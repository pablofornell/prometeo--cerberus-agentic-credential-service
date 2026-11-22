//! `cerberusd backup`: a consistent copy of the vault file while the daemon runs (ADR-0031).
//!
//! Copying `vault.cerberus` with `cp` or `rsync` while the daemon writes is not safe: the vault runs in WAL mode,
//! so the newest commits are in `vault.cerberus-wal`, and a copy of the files at different moments does not open.
//! This command makes the copy with SQLite itself (`VACUUM INTO`, one read transaction, see
//! `Store::backup_vault_file`). The daemon keeps writing, and the copy is a snapshot of one moment. It needs no
//! passphrase: the file holds the same encrypted rows as the vault.
//!
//! The file is written under a temporary name, checked, synced and then linked to its final name, so a reader of the
//! folder sees a whole backup or none. No audit event is written: `backup.create` is part of the encrypted audit
//! chain, and this command has no key (the chain is sealed with the vault key).

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use cerberus_store::{Store, StoreError};
use cerberus_types::{Clock, RequestId};

use crate::config::Config;
use crate::daemon::VAULT_FILE;

/// The file name ending of a backup.
pub const BACKUP_SUFFIX: &str = ".cerberus-backup";
/// The file name start of a backup that this command makes.
const NAME_PREFIX: &str = "cerberus-";
/// The time part of a backup name, in UTC. The text order of it is the time order.
const STAMP_FORMAT: &str = "%Y%m%dT%H%M%SZ";
/// Characters of the vault ID in a backup name.
const SHORT_ID_LEN: usize = 8;
/// Length of the time part: `20260101T000000Z`.
const STAMP_LEN: usize = 16;
/// The start of the name that a backup has while it is written.
const PARTIAL_PREFIX: &str = ".cerberus-";
/// The ending of the name that a backup has while it is written.
const PARTIAL_SUFFIX: &str = ".partial";
/// A partial file older than this is the rest of a run that was killed. The next run removes it.
const STALE_PARTIAL_SECONDS: i64 = 24 * 60 * 60;

/// Why a backup failed.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The vault file is not in the data folder.
    #[error("no vault file at {0}")]
    NoVault(PathBuf),
    /// `--keep` needs a folder to prune.
    #[error("--keep needs a folder for --out, not the file name {0}")]
    KeepWithFile(PathBuf),
    /// `--keep` must be at least 1.
    #[error("--keep must be at least 1")]
    KeepZero,
    /// The vault copy failed.
    #[error("cannot copy the vault: {0}")]
    Store(StoreError),
    /// The copy is not a valid backup. It was removed.
    #[error("the new backup failed its check and was removed: {0}")]
    Check(StoreError),
    /// A file or folder step failed.
    #[error("{action} {path}: {source}")]
    Io {
        /// What was tried.
        action: &'static str,
        /// The path.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
}

fn io_error(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> BackupError {
    let path = path.to_path_buf();
    move |source| BackupError::Io {
        action,
        path,
        source,
    }
}

/// What a backup run did.
#[derive(Debug, PartialEq, Eq)]
pub struct BackupReport {
    /// The new backup file.
    pub path: PathBuf,
    /// The older backups that `--keep` removed, oldest first.
    pub pruned: Vec<PathBuf>,
}

/// Makes a backup of the vault of `config` and, when `keep` is set, removes the older ones of the same vault.
///
/// `out` is a backup file name (it ends in `.cerberus-backup`) or a folder. A folder is made (mode 0700) when it is
/// missing. In a folder, the name is `cerberus-<8 characters of the vault ID>-<UTC time>.cerberus-backup`. The new
/// file has mode 0600 and never replaces a file. `keep` removes only files of this naming scheme and of this vault
/// that are in `out`: never another name, a folder or a link. It runs after the new backup is checked and in place.
/// It keeps the new file and the `keep - 1` newest of the others, so the new file is never removed, also when an
/// older file has a time in the future.
///
/// A run first removes the `.cerberus-*.partial` files in `out` that are older than 24 hours (regular files only, not
/// links): a run that was killed leaves them.
///
/// # Errors
/// [`BackupError`]. After an error, no partial file is left and nothing is pruned.
pub async fn run(
    config: &Config,
    out: &Path,
    keep: Option<u32>,
    clock: &dyn Clock,
) -> Result<BackupReport, BackupError> {
    if keep == Some(0) {
        return Err(BackupError::KeepZero);
    }
    let vault = config.data_dir.join(VAULT_FILE);
    if !vault.is_file() {
        return Err(BackupError::NoVault(vault));
    }
    let named = !out.is_dir() && out.to_string_lossy().ends_with(BACKUP_SUFFIX);
    if named && keep.is_some() {
        return Err(BackupError::KeepWithFile(out.to_path_buf()));
    }
    let dir = if named {
        out.parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    } else {
        out
    };
    make_folder(dir)?;
    remove_stale_partials(dir, clock);
    // A random part in the name: two runs at once must not write the same file, also when the process IDs are the
    // same (separate containers). `RequestId` is a random UUID, so no new dependency is needed.
    let partial = dir.join(format!(
        "{PARTIAL_PREFIX}{}{PARTIAL_SUFFIX}",
        RequestId::generate()
    ));
    let info = match write_checked(&vault, &partial).await {
        Ok(info) => info,
        Err(error) => {
            // The partial file is ours (made by this run), so removing it is safe.
            drop(std::fs::remove_file(&partial));
            return Err(error);
        }
    };
    let short = short_id(&info.vault_id.to_string());
    let path = if named {
        out.to_path_buf()
    } else {
        let stamp = clock.now().strftime(STAMP_FORMAT).to_string();
        dir.join(format!("{NAME_PREFIX}{short}-{stamp}{BACKUP_SUFFIX}"))
    };
    let placed = place(&partial, &path).map_err(io_error("cannot place the backup at", &path));
    drop(std::fs::remove_file(&partial));
    placed?;
    sync_folder(dir)?;
    let pruned = match keep {
        Some(keep) => prune(dir, &short, keep as usize, &path)?,
        None => Vec::new(),
    };
    Ok(BackupReport { path, pruned })
}

/// Gives `partial` its final name `path`, and never replaces a file. A hard link fails when the name exists. A file
/// system without hard links gets a copy to a new file instead.
fn place(partial: &Path, path: &Path) -> io::Result<()> {
    place_with(partial, path, |from, to| std::fs::hard_link(from, to))
}

/// [`place`] with the link step as a parameter, so a test can run the copy step.
fn place_with(
    partial: &Path,
    path: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    match link(partial, path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(_) => copy_new(partial, path),
        Ok(()) => Ok(()),
    }
}

/// Copies `source` to the new file `path` (mode 0600). `create_new` fails when the name exists, so a file is never
/// replaced and never cut to zero. The data is synced before the function returns. When any step fails, the new file
/// is removed, so no torn file stays under the final name. The caller syncs the folder.
fn copy_new(source: &Path, path: &Path) -> io::Result<()> {
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let copied = std::fs::File::open(source)
        .and_then(|mut from| io::copy(&mut from, &mut target))
        .and_then(|_| target.flush())
        .and_then(|()| target.sync_all());
    if copied.is_err() {
        // The file is ours (`create_new` made it), so removing it is safe.
        drop(std::fs::remove_file(path));
    }
    copied
}

/// Removes the `.cerberus-*.partial` regular files in `dir` that are older than 24 hours. It is best effort: a file
/// that cannot be read or removed stays, and the backup goes on. A link is never followed or removed.
fn remove_stale_partials(dir: &Path, clock: &dyn Clock) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = clock.now().as_second();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with(PARTIAL_PREFIX) && name.ends_with(PARTIAL_SUFFIX)) {
            continue;
        }
        // `file_type` and `symlink_metadata` do not follow links.
        let stale = entry.file_type().is_ok_and(|kind| kind.is_file())
            && entry
                .path()
                .symlink_metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|time| jiff::Timestamp::try_from(time).ok())
                .is_some_and(|modified| now - modified.as_second() > STALE_PARTIAL_SECONDS);
        if stale {
            drop(std::fs::remove_file(entry.path()));
        }
    }
}

/// Copies the vault to `partial`, syncs it to disk and checks it as a backup.
async fn write_checked(
    vault: &Path,
    partial: &Path,
) -> Result<cerberus_store::BackupInfo, BackupError> {
    Store::backup_vault_file(vault, partial)
        .await
        .map_err(BackupError::Store)?;
    std::fs::File::open(partial)
        .and_then(|file| file.sync_all())
        .map_err(io_error("cannot sync", partial))?;
    Store::inspect_backup(partial)
        .await
        .map_err(BackupError::Check)
}

/// Makes `dir` with mode 0700 when it is missing.
fn make_folder(dir: &Path) -> Result<(), BackupError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(dir)
        .map_err(io_error("cannot make the folder", dir))
}

/// Syncs the folder entry, so the new name survives a power loss.
fn sync_folder(dir: &Path) -> Result<(), BackupError> {
    std::fs::File::open(dir)
        .and_then(|folder| folder.sync_all())
        .map_err(io_error("cannot sync the folder", dir))
}

/// The first characters of a vault ID text (the part before the first `-` of a hyphenated UUID is 8 characters).
fn short_id(vault_id: &str) -> String {
    vault_id.chars().take(SHORT_ID_LEN).collect()
}

/// The time part of `name` when it is `cerberus-<short>-<time>.cerberus-backup` of this vault, else `None`.
fn stamp_of<'a>(name: &'a str, short: &str) -> Option<&'a str> {
    let stamp = name
        .strip_prefix(NAME_PREFIX)?
        .strip_prefix(short)?
        .strip_prefix('-')?
        .strip_suffix(BACKUP_SUFFIX)?;
    let bytes = stamp.as_bytes();
    let fits = bytes.len() == STAMP_LEN
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            8 => *byte == b'T',
            15 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        });
    fits.then_some(stamp)
}

/// Removes the regular files of this scheme and of this vault in `dir`, except `new` and the `keep - 1` newest others.
/// `new` is never removed: its time can be older than the time of other files (a clock that was wrong). Returns the
/// removed paths, oldest first.
fn prune(dir: &Path, short: &str, keep: usize, new: &Path) -> Result<Vec<PathBuf>, BackupError> {
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io_error("cannot read the folder", dir))? {
        let entry = entry.map_err(io_error("cannot read the folder", dir))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stamp) = stamp_of(&name, short) else {
            continue;
        };
        // `file_type` does not follow links: a link or a folder with a backup name is left alone.
        let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
        if is_file && entry.path() != new {
            found.push((stamp.to_owned(), entry.path()));
        }
    }
    found.sort();
    let surplus = found.len().saturating_sub(keep.saturating_sub(1));
    let mut pruned = Vec::new();
    for (_, path) in found.into_iter().take(surplus) {
        std::fs::remove_file(&path).map_err(io_error("cannot remove the old backup", &path))?;
        pruned.push(path);
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

    use super::*;

    const SHORT: &str = "0a1b2c3d";

    /// The fallback for a file system without hard links: it never replaces a file and it never leaves a torn one.
    #[test]
    fn the_copy_fallback_never_replaces_and_leaves_no_torn_file() {
        let dir = tempfile::tempdir().unwrap();
        let (partial, path) = (dir.path().join("partial"), dir.path().join("final"));
        std::fs::write(&partial, b"backup bytes").unwrap();
        let no_link = |_: &Path, _: &Path| Err(io::Error::from(io::ErrorKind::Unsupported));

        place_with(&partial, &path, no_link).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"backup bytes");
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &std::fs::metadata(&path).unwrap().permissions()
            ) & 0o777,
            0o600
        );

        // A file at the final name is never cut or replaced.
        std::fs::write(&partial, b"other bytes").unwrap();
        let error = place_with(&partial, &path, no_link).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"backup bytes");

        // A copy that fails after the new file was made removes it. A folder cannot be read as a file.
        std::fs::remove_file(&path).unwrap();
        let folder = dir.path().join("folder");
        std::fs::create_dir(&folder).unwrap();
        assert!(place_with(&folder, &path, no_link).is_err());
        assert!(!path.exists(), "a torn file stayed under the final name");
        let missing = dir.path().join("missing");
        assert!(place_with(&missing, &path, no_link).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn only_the_scheme_of_this_vault_has_a_stamp() {
        let name = |text: &str| stamp_of(text, SHORT).map(str::to_owned);
        assert_eq!(
            name("cerberus-0a1b2c3d-20260101T000000Z.cerberus-backup").as_deref(),
            Some("20260101T000000Z")
        );
        for other in [
            "cerberus-ffffffff-20260101T000000Z.cerberus-backup",
            "cerberus-0a1b2c3d-20260101T000000Z.cerberus-backup.partial",
            "cerberus-0a1b2c3d-20260101.cerberus-backup",
            "cerberus-0a1b2c3d-2026010AT000000Z.cerberus-backup",
            "cerberus-0a1b2c3d-20260101T000000Z.cerb",
            "my-cerberus-0a1b2c3d-20260101T000000Z.cerberus-backup",
            "vault.cerberus",
        ] {
            assert_eq!(name(other), None, "{other}");
        }
    }
}
