//! Remote profiles (ADR-0034 point 7.10): the import of an enrolment bundle, the files of a
//! profile, and the pinned transport built from them.
//!
//! A profile is `<data_dir>/remote/<enrolment id>/` (mode `0700`) with `cert.pem`, `key.pem` and
//! `ca.pem` (each `0600`), and an entry without the key in `desktop-prefs.json`.

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

/// Reads and checks the bundle at `path` (see [`AdminBundle::read`]) and stores its files. A
/// profile with the same enrolment ID is replaced. The bundle file itself is not changed: the
/// person deletes it after the import.
///
/// # Errors
/// `invalid_bundle` when the file is not a valid bundle (the text never quotes the file),
/// `internal` when the profile files cannot be written.
pub fn import(paths: &AppPaths, path: &Path, now: Timestamp) -> IpcResult<RemoteProfile> {
    let bundle = AdminBundle::read(path, now)
        .map_err(|error| IpcError::new("invalid_bundle", &error.to_string()))?;
    let ca_sha256 = bundle
        .ca_sha256_hex()
        .map_err(|error| IpcError::new("invalid_bundle", &error.to_string()))?;
    let id = bundle.id.to_string();
    let dir = profile_dir(paths, &id)?;
    private_dir(&paths.remote_root())?;
    private_dir(&dir)?;
    write_private(&dir.join(CERT_FILE), bundle.client_cert_pem.as_bytes())?;
    write_private(
        &dir.join(KEY_FILE),
        bundle.client_key_pem.expose().as_bytes(),
    )?;
    write_private(&dir.join(CA_FILE), bundle.ca_cert_pem.as_bytes())?;
    tracing::info!(profile = %id, url = %bundle.url, "remote profile imported");
    Ok(RemoteProfile {
        id,
        label: bundle.label.clone(),
        url: bundle.url.clone(),
        ca_pin: bundle.ca_pin.clone(),
        ca_sha256,
        operator_id: bundle.operator_id.to_string(),
        not_after: bundle.not_after,
    })
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
    let dir = profile_dir(paths, &profile.id)?;
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
