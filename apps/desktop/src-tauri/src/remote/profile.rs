//! Remote profiles (ADR-0034 point 7.10): the import of an enrolment bundle, the files of a
//! profile, and the pinned transport built from them.
//!
//! A profile is `<data_dir>/remote/<enrolment id>/` (mode `0700`) with `cert.pem`, `key.pem` and
//! `ca.pem` (each `0600`), and an entry without the key in `desktop-prefs.json`.
//!
//! An import is staged first in `<data_dir>/remote/pending/<enrolment id>/` and becomes a profile
//! only when the person connects after comparing the pin ([`commit`]); a cancel removes the stage
//! ([`discard`]) and leaves a stored profile of the same enrolment as it was (DEC-RM-26).

use std::path::{Path, PathBuf};

use cerberus_admin::bundle::AdminBundle;
use cerberus_admin::clients::EnrolmentId;
use cerberus_admin::dto::{RemoteProfileView, ts};
use cerberus_admin::error::{IpcError, IpcResult};
use cerberus_client::{PinnedHttps, Trust};
use jiff::Timestamp;

use super::CALL_TIMEOUT;
use crate::prefs::{AppPaths, RemoteProfile, write_private};

/// The client certificate of a profile.
pub const CERT_FILE: &str = "cert.pem";
/// The client key of a profile (PKCS#8 PEM).
pub const KEY_FILE: &str = "key.pem";
/// The server CA certificate of a profile.
pub const CA_FILE: &str = "ca.pem";

/// The folder of the profile `id`. The ID must be an enrolment ID, so it can never name another
/// folder.
///
/// # Errors
/// `validation_failed` when `id` is not an enrolment ID.
pub fn profile_dir(paths: &AppPaths, id: &str) -> IpcResult<PathBuf> {
    let id: EnrolmentId = id
        .parse()
        .map_err(|_| IpcError::invalid("profile", "is not a remote profile ID"))?;
    Ok(paths.remote_root().join(id.to_string()))
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700);
        builder.create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        builder.create(path)
    }
}

/// The folder of staged imports. Its name is not an enrolment ID, so it never is a profile.
fn pending_root(paths: &AppPaths) -> PathBuf {
    paths.remote_root().join("pending")
}

/// The staged files of the import of `id`.
///
/// # Errors
/// As [`profile_dir`].
pub fn pending_dir(paths: &AppPaths, id: &str) -> IpcResult<PathBuf> {
    let dir = profile_dir(paths, id)?;
    let name = dir.file_name().map(ToOwned::to_owned).unwrap_or_default();
    Ok(pending_root(paths).join(name))
}

/// Reads and checks the bundle at `path` (see [`AdminBundle::read`]) and stages its files. A
/// stored profile of the same enrolment is not touched; an earlier staged import is dropped. The
/// bundle file itself is not changed: the person deletes it after the import.
///
/// # Errors
/// `invalid_bundle` when the file is not a valid bundle (the text never quotes the file),
/// `internal` when the files cannot be written.
pub fn stage(paths: &AppPaths, path: &Path, now: Timestamp) -> IpcResult<RemoteProfile> {
    let bundle = AdminBundle::read(path, now)
        .map_err(|error| IpcError::new("invalid_bundle", &error.to_string()))?;
    stage_bundle(paths, &bundle)
}

/// Stages a bundle that is already checked, as [`stage`] does for a file. An earlier staged import is dropped.
///
/// # Errors
/// `invalid_bundle` when the CA certificate does not parse, `internal` when the files cannot be
/// written.
pub fn stage_bundle(paths: &AppPaths, bundle: &AdminBundle) -> IpcResult<RemoteProfile> {
    let profile = profile_of(bundle)?;
    discard(paths)?;
    let dir = pending_dir(paths, &profile.id)?;
    private_dir(&paths.remote_root())?;
    private_dir(&pending_root(paths))?;
    write_files(&dir, bundle)?;
    tracing::info!(profile = %profile.id, url = %bundle.url, "remote bundle staged");
    Ok(profile)
}

/// Stores a bundle that is already checked straight as a profile, for the first-time setup of a
/// server: the bundle comes from memory, so there is nothing to compare, and a staged import of
/// the person is not touched. The files are written next to the profile and moved in, so a
/// failure leaves no half profile. A profile of the same enrolment (a retry) is replaced.
///
/// # Errors
/// `invalid_bundle` when the CA certificate does not parse, `internal` when the files cannot be
/// written or moved.
pub fn store_bundle(paths: &AppPaths, bundle: &AdminBundle) -> IpcResult<RemoteProfile> {
    let profile = profile_of(bundle)?;
    let dir = profile_dir(paths, &profile.id)?;
    let building = paths.remote_root().join(format!("setup-{}", profile.id));
    private_dir(&paths.remote_root())?;
    if building.exists() {
        std::fs::remove_dir_all(&building)?;
    }
    private_dir(&building)?;
    let moved = write_files(&building, bundle).and_then(|()| {
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::rename(&building, &dir).map_err(IpcError::from)
    });
    if let Err(error) = moved {
        drop(std::fs::remove_dir_all(&building));
        return Err(error);
    }
    tracing::info!(profile = %profile.id, url = %bundle.url, "remote profile stored from a setup");
    Ok(profile)
}

fn profile_of(bundle: &AdminBundle) -> IpcResult<RemoteProfile> {
    let ca_sha256 = bundle
        .ca_sha256_hex()
        .map_err(|error| IpcError::new("invalid_bundle", &error.to_string()))?;
    Ok(RemoteProfile {
        id: bundle.id.to_string(),
        label: bundle.label.clone(),
        url: bundle.url.clone(),
        ca_pin: bundle.ca_pin.clone(),
        ca_sha256,
        operator_id: bundle.operator_id.to_string(),
        not_after: bundle.not_after,
    })
}

/// Writes the three files of a profile into the private folder `dir`.
fn write_files(dir: &Path, bundle: &AdminBundle) -> IpcResult<()> {
    private_dir(dir)?;
    write_private(&dir.join(CERT_FILE), bundle.client_cert_pem.as_bytes())?;
    write_private(
        &dir.join(KEY_FILE),
        bundle.client_key_pem.expose().as_bytes(),
    )?;
    write_private(&dir.join(CA_FILE), bundle.ca_cert_pem.as_bytes())?;
    Ok(())
}

/// Makes the staged import of `id` the stored profile, in place of an older one of the same
/// enrolment: the old folder is moved aside, the stage moved in, then the old folder removed.
///
/// # Errors
/// `not_found` when nothing is staged for `id`, `internal` when a move fails (the old profile is
/// put back).
pub fn commit(paths: &AppPaths, id: &str) -> IpcResult<()> {
    let staged = pending_dir(paths, id)?;
    if !staged.is_dir() {
        return Err(IpcError::new(
            "not_found",
            "no staged import for this profile",
        ));
    }
    let dir = profile_dir(paths, id)?;
    let aside = paths.remote_root().join(format!("replaced-{id}"));
    if aside.exists() {
        std::fs::remove_dir_all(&aside)?;
    }
    let had_old = dir.exists();
    if had_old {
        std::fs::rename(&dir, &aside)?;
    }
    if let Err(error) = std::fs::rename(&staged, &dir) {
        if had_old {
            std::fs::rename(&aside, &dir)?;
        }
        return Err(error.into());
    }
    if had_old {
        std::fs::remove_dir_all(&aside)?;
    }
    discard(paths)?;
    tracing::info!(profile = %id, "remote profile stored");
    Ok(())
}

/// Removes every staged import.
///
/// # Errors
/// `internal` when the folder cannot be removed.
pub fn discard(paths: &AppPaths) -> IpcResult<()> {
    match std::fs::remove_dir_all(pending_root(paths)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// True when a file is readable by others than its owner.
#[cfg(unix)]
fn too_open(path: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o077 != 0)
}

#[cfg(not(unix))]
fn too_open(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

/// The pinned transport of a profile: TLS 1.3, the CA file and its pin, the client certificate.
///
/// # Errors
/// `unavailable` when a file of the profile is missing or the key file is readable by others;
/// `invalid_bundle` when the files or the URL are not usable.
pub fn transport(paths: &AppPaths, profile: &RemoteProfile) -> IpcResult<PinnedHttps> {
    transport_in(&profile_dir(paths, &profile.id)?, profile)
}

/// As [`transport`], from the files in `dir` (a stored profile or a staged import).
///
/// # Errors
/// As [`transport`].
pub fn transport_in(dir: &Path, profile: &RemoteProfile) -> IpcResult<PinnedHttps> {
    let (cert, key, ca) = (dir.join(CERT_FILE), dir.join(KEY_FILE), dir.join(CA_FILE));
    for file in [&cert, &key, &ca] {
        if !file.is_file() {
            return Err(IpcError::unavailable(
                "a file of the remote profile is missing; import the bundle again",
            ));
        }
    }
    if too_open(&key)? {
        return Err(IpcError::unavailable(
            "the key file of the remote profile is readable by other users; import the bundle again",
        ));
    }
    let trust = Trust::CaFileAndPin {
        ca,
        pin: profile.ca_pin.clone(),
    };
    PinnedHttps::with_client_cert(&profile.url, &trust, (cert, key), CALL_TIMEOUT)
        .map_err(|error| IpcError::new("invalid_bundle", &error.to_string()))
}

/// Removes the files of the profile `id` (only its own folder).
///
/// # Errors
/// `validation_failed` for a bad ID, `internal` when the folder cannot be removed.
pub fn forget(paths: &AppPaths, id: &str) -> IpcResult<()> {
    let dir = profile_dir(paths, id)?;
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// The IPC view of a profile.
#[must_use]
pub fn view(profile: &RemoteProfile, active: bool) -> RemoteProfileView {
    RemoteProfileView {
        id: profile.id.clone(),
        label: profile.label.clone(),
        url: profile.url.clone(),
        ca_pin: profile.ca_pin.clone(),
        ca_sha256: profile.ca_sha256.clone(),
        operator_id: profile.operator_id.clone(),
        not_after: ts(profile.not_after),
        active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_folder_is_named_by_an_enrolment_id_only() {
        let paths = AppPaths::new(PathBuf::from("/data"));
        let id = EnrolmentId::generate().to_string();
        assert_eq!(
            profile_dir(&paths, &id).expect("dir"),
            PathBuf::from("/data/remote").join(&id)
        );
        for bad in ["..", "../vault.cerberus", "", "x/y"] {
            assert_eq!(
                profile_dir(&paths, bad).expect_err(bad).code,
                "validation_failed"
            );
        }
    }

    #[test]
    fn a_missing_profile_has_no_transport_and_forget_is_quiet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = AppPaths::new(dir.path().to_path_buf());
        let profile = RemoteProfile {
            id: EnrolmentId::generate().to_string(),
            label: "laptop".to_owned(),
            url: "https://localhost:8443".to_owned(),
            ca_pin: "sha256/AAAA".to_owned(),
            ca_sha256: "00".repeat(32),
            operator_id: "op".to_owned(),
            not_after: Timestamp::UNIX_EPOCH,
        };
        assert_eq!(
            transport(&paths, &profile).expect_err("no files").code,
            "unavailable"
        );
        forget(&paths, &profile.id).expect("nothing to forget");
    }
}
