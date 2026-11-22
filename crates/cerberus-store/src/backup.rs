//! Backup and restore (ADR-0031).

use std::path::{Path, PathBuf};
use std::time::Duration;

use cerberus_types::Clock;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::fsutil::{create_private_file, wal_is_plausible, with_suffix};
use crate::rows::{BackupInfo, HeaderRow, KeySlotRow};
use crate::store::{APPLICATION_ID, not_a_database};
use crate::{Store, StoreError};

impl Store {
    /// Writes a consistent copy of the whole vault with `VACUUM INTO`: header, key slots, every encrypted row,
    /// the audit chain and `audit_pending`. Works while locked. The file gets mode 0600 and must not exist.
    ///
    /// # Errors
    /// [`StoreError::Io`] when `dest` exists or cannot be made, or an engine error. A failed backup leaves no file.
    pub async fn backup_to(&self, dest: &Path) -> Result<(), StoreError> {
        vacuum_into(&self.pool, dest).await
    }

    /// [`Self::backup_to`] for a vault file that another process may have open, for example a running daemon
    /// (ADR-0031 point 1, `cerberusd backup`). It opens its own read-only connection and needs no key. The vault
    /// runs in WAL mode (`connect_options`, no exclusive locking), so this read does not block the writer and the
    /// writer does not block this read: the copy is one read transaction, a snapshot of one moment. The schema is
    /// not migrated. The file gets mode 0600 and must not exist.
    ///
    /// The connection is read-only, so it never writes a page of the vault and never folds the `-wal` file into it
    /// when it closes. Before it opens, it runs the same `-wal` check as [`Store::open`] (AUD-10). A `-wal` file
    /// that fails the check is refused, because SQLite would ignore it and the copy would miss the commits in it.
    ///
    /// # Errors
    /// [`StoreError::Io`] when `vault_path` is missing or `dest` exists or cannot be made,
    /// [`StoreError::Corrupt`] when the `-wal` file fails the check,
    /// [`StoreError::NotAVault`] when the file is not a Cerberus vault, or an engine error (for example a
    /// busy database after 30 s). A failed backup leaves no file.
    pub async fn backup_vault_file(vault_path: &Path, dest: &Path) -> Result<(), StoreError> {
        if !vault_path.is_file() {
            return Err(StoreError::Io(std::io::ErrorKind::NotFound.into()));
        }
        if !wal_is_plausible(vault_path)? {
            return Err(StoreError::Corrupt);
        }
        // Read-only, and not `immutable`: a running daemon may write. No `create_if_missing`, no journal mode and no
        // other pragma.
        let options = SqliteConnectOptions::new()
            .filename(vault_path)
            .read_only(true)
            .create_if_missing(false)
            .busy_timeout(BACKUP_BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(not_a_database)?;
        let result = async {
            let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
                .fetch_one(&pool)
                .await
                .map_err(not_a_database)?;
            if application_id != APPLICATION_ID {
                return Err(StoreError::NotAVault);
            }
            vacuum_into(&pool, dest).await
        }
        .await;
        pool.close().await;
        result
    }

    /// Reads what a backup file says about itself, without any key (ADR-0031 step 1): application ID, schema
    /// version, header and key slots. Also runs `PRAGMA quick_check`. The file is opened once, read-only and
    /// `immutable`, so SQLite reads only this one file and never a `-wal` or `-shm` file next to it. A backup
    /// with a sibling `-wal` file is still refused, as a second guard (RUSTSEC-2026-0459, see `deny.toml`).
    ///
    /// # Errors
    /// [`StoreError::NotAVault`], [`StoreError::TooNew`], or [`StoreError::Corrupt`] when the quick check fails.
    pub async fn inspect_backup(path: &Path) -> Result<BackupInfo, StoreError> {
        if with_suffix(path, "-wal").exists() {
            return Err(StoreError::NotAVault);
        }
        read_backup_file(path).await
    }
}

/// How long [`Store::backup_vault_file`] waits for a lock. A long write (a migration) can hold the database.
const BACKUP_BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// `VACUUM INTO dest` on `pool`. The new file gets mode 0600 and a failure removes it.
async fn vacuum_into(pool: &sqlx::SqlitePool, dest: &Path) -> Result<(), StoreError> {
    let text = dest
        .to_str()
        .ok_or_else(|| StoreError::Io(std::io::ErrorKind::InvalidInput.into()))?;
    // `VACUUM INTO` accepts an empty existing file. Making it first gives it mode 0600 from the start.
    create_private_file(dest)?;
    let result = sqlx::query("VACUUM INTO ?1").bind(text).execute(pool).await;
    if let Err(error) = result {
        // The file is ours and holds no complete backup, so removing it is safe.
        drop(std::fs::remove_file(dest));
        return Err(error.into());
    }
    Ok(())
}

/// [`Store::inspect_backup`] without the sibling check: one `immutable` read-only connection.
pub(crate) async fn read_backup_file(path: &Path) -> Result<BackupInfo, StoreError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .immutable(true)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(not_a_database)?;
    let result = read_backup(&pool).await;
    pool.close().await;
    result
}

async fn read_backup(pool: &sqlx::SqlitePool) -> Result<BackupInfo, StoreError> {
    let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(pool)
        .await
        .map_err(not_a_database)?;
    let schema_version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
        .map_err(not_a_database)?;
    if application_id != APPLICATION_ID || schema_version == 0 {
        return Err(StoreError::NotAVault);
    }
    let supported = crate::store::schema_version();
    if schema_version > supported {
        return Err(StoreError::TooNew {
            found: schema_version,
            supported,
        });
    }
    let check: String = sqlx::query_scalar("PRAGMA quick_check(1)")
        .fetch_one(pool)
        .await?;
    if check != "ok" {
        return Err(StoreError::Corrupt);
    }
    let header_row = sqlx::query("SELECT * FROM vault_header WHERE id = 1")
        .fetch_one(pool)
        .await?;
    let header = HeaderRow::from_sql(&header_row)?;
    let slot_rows = sqlx::query("SELECT * FROM key_slots ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(BackupInfo {
        vault_id: header.vault_id,
        format_version: header.format_version,
        schema_version,
        created_at: header.created_at,
        slots: slot_rows
            .iter()
            .map(KeySlotRow::from_sql)
            .collect::<Result<_, _>>()?,
    })
}

/// Puts a backup in place of the vault file (ADR-0031 step 3, parts 1, 4 and the file swap).
///
/// 1. Copies the backup once to `<vault>.restore-tmp` (a new file, mode 0600). The backup path is not
///    opened again after this read.
/// 2. Checks that copy with [`Store::inspect_backup`], so the file that is installed is the file that
///    was checked (AUD-10).
/// 3. Moves the current vault file (and its `-wal` and `-shm`) to `<vault>.pre-restore-<UTC time>`
///    (with `-2`, `-3` ... when that name is taken). It is not deleted.
/// 4. Renames the copy to the vault path. When a rename fails, the moved files are moved back first.
///
/// A vault path that is a symbolic link (or whose `-wal` or `-shm` is one) is refused before
/// anything is read or moved: the swap would move the link, not the vault it points to (NEW-11).
/// When the restore is complete, the caller renames the moved file with [`retire_replaced`], so a
/// `.pre-restore-*` name always means a restore that did not finish (NEW-12).
///
/// The vault must be closed first, with [`Store::close`] awaited (a closing connection removes the
/// `-wal` and `-shm` files by name, NEW-10). The caller must have verified the phrase against a slot
/// in the backup (use `inspect_backup` for the slots), and after the next open it revokes leases and
/// cancels pending requests (`Tx::revoke_all_leases`, `Tx::cancel_pending_requests`). Returns the
/// path of the moved file, or `None` when nothing was moved (no vault file existed).
///
/// # Errors
/// As [`Store::inspect_backup`], or [`StoreError::Io`] (`InvalidInput` for a linked vault path, see
/// [`linked_vault_file`]). The current vault is untouched until the checked
/// copy is complete; a copy that fails the check is removed. A failed swap moves the old files back,
/// so after any error other than [`StoreError::RestoreStranded`] the old vault is the vault file.
/// `RestoreStranded` says where the old vault file is when it could not be moved back.
pub async fn restore_backup(
    backup: &Path,
    vault_path: &Path,
    clock: &dyn Clock,
) -> Result<Option<PathBuf>, StoreError> {
    if linked_vault_file(vault_path).is_some() {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the vault file is a symbolic link",
        )));
    }
    let stamp = clock.now().strftime("%Y%m%dT%H%M%SZ").to_string();
    let tmp = with_suffix(vault_path, ".restore-tmp");
    let copy = {
        let (backup, tmp) = (backup.to_path_buf(), tmp.clone());
        move || copy_to_tmp(&backup, &tmp)
    };
    blocking(copy).await?;
    if let Err(error) = Store::inspect_backup(&tmp).await {
        // The copy is ours and failed the check, so removing it is safe.
        drop(std::fs::remove_file(&tmp));
        return Err(error);
    }
    let vault = vault_path.to_path_buf();
    blocking(move || swap_files(&tmp, &vault, &stamp)).await
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| StoreError::Io(std::io::ErrorKind::Other.into()))?
}

/// Copies `backup` to `tmp`, a new private file. An old `tmp` (from a crash) is removed first.
fn copy_to_tmp(backup: &Path, tmp: &Path) -> Result<(), StoreError> {
    for path in [
        tmp.to_path_buf(),
        with_suffix(tmp, "-wal"),
        with_suffix(tmp, "-shm"),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut copy = create_private_file(tmp)?;
    let mut source = std::fs::File::open(backup)?;
    let done = std::io::copy(&mut source, &mut copy).and_then(|_| copy.sync_all());
    drop(copy);
    if let Err(error) = done {
        drop(std::fs::remove_file(tmp));
        return Err(error.into());
    }
    Ok(())
}

/// The three files of a vault: the main file, its `-wal` and its `-shm`.
const VAULT_FILES: [&str; 3] = ["", "-wal", "-shm"];
/// The name part of the old vault file while a restore runs or after it failed.
const PRE_RESTORE: &str = ".pre-restore-";
/// The name part of the old vault file after a restore that went through (NEW-12).
const REPLACED: &str = ".replaced-";

/// The first of the vault file, its `-wal` and its `-shm` that is a symbolic link, if any. A
/// restore refuses such a vault path: it would rename the link and leave the real file where the
/// link pointed, so the next start could not find it (NEW-11). A missing file is not a link.
#[must_use]
pub fn linked_vault_file(vault_path: &Path) -> Option<PathBuf> {
    VAULT_FILES
        .iter()
        .map(|suffix| with_suffix(vault_path, suffix))
        .find(|path| {
            path.symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_symlink())
        })
}

/// Moves the current vault aside and renames the checked copy `tmp` to the vault path.
///
/// It never stops half way (NEW-10). A `-wal` or `-shm` that is gone when it is renamed was never
/// there or was just removed by the last connection of a closing store: there is nothing to move.
/// When any rename fails, every file moved so far is moved back, so the old vault is the vault
/// file again and the error is returned. If a file cannot be moved back, the error is
/// [`StoreError::RestoreStranded`] with the path where the old vault now is.
fn swap_files(tmp: &Path, vault: &Path, stamp: &str) -> Result<Option<PathBuf>, StoreError> {
    let target = free_name(vault, PRE_RESTORE, stamp);
    let mut moved: Vec<&str> = Vec::new();
    let mut failure = None;
    for suffix in VAULT_FILES {
        match std::fs::rename(with_suffix(vault, suffix), with_suffix(&target, suffix)) {
            Ok(()) => moved.push(suffix),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    if failure.is_none()
        && let Err(error) = std::fs::rename(tmp, vault)
    {
        failure = Some(error);
    }
    let Some(error) = failure else {
        return Ok((!moved.is_empty()).then_some(target));
    };
    // The copy is ours; the old files go back in the reverse order.
    drop(std::fs::remove_file(tmp));
    let mut stranded = false;
    for suffix in moved.iter().rev() {
        if let Err(back) = std::fs::rename(with_suffix(&target, suffix), with_suffix(vault, suffix))
        {
            tracing::error!(error = %back, "could not move the old vault file back");
            stranded = true;
        }
    }
    if stranded {
        return Err(StoreError::RestoreStranded { moved: target });
    }
    Err(error.into())
}

/// `<vault><kind><stamp>` (`kind` is [`PRE_RESTORE`], [`REPLACED`] or the pre-migrate prefix of
/// `Store::migrate`), or with `-2`, `-3` ... added when a file of that name exists (two restores in
/// the same second must not overwrite the first old vault; a second migration from the same
/// version must not overwrite the first copy, DEC-RD-5).
pub(crate) fn free_name(vault: &Path, kind: &str, stamp: &str) -> PathBuf {
    let taken = |path: &Path| {
        VAULT_FILES
            .iter()
            .any(|suffix| with_suffix(path, suffix).symlink_metadata().is_ok())
    };
    let first = with_suffix(vault, &format!("{kind}{stamp}"));
    if !taken(&first) {
        return first;
    }
    let mut n: u32 = 2;
    loop {
        let next = with_suffix(vault, &format!("{kind}{stamp}-{n}"));
        if !taken(&next) || n == u32::MAX {
            return next;
        }
        n = n.saturating_add(1);
    }
}

/// After a restore that went through: renames the old vault file that the swap moved to `moved`
/// (`<vault>.pre-restore-<stamp>`), with its `-wal` and `-shm`, to `<vault>.replaced-<stamp>`, so
/// [`stranded_vaults`] never lists it (NEW-12). The file is kept, as before. It never replaces a
/// file: the new name gets `-2`, `-3` ... when taken. The side files move first and the main file
/// last; when a rename fails, the side files moved so far go back, so the old file keeps its
/// `.pre-restore-*` name whole. Returns the new path.
///
/// # Errors
/// [`StoreError::Io`]: `InvalidInput` when `moved` is not a `.pre-restore-*` name of `vault_path`,
/// or the failed rename.
pub fn retire_replaced(vault_path: &Path, moved: &Path) -> Result<PathBuf, StoreError> {
    let invalid = || StoreError::Io(std::io::ErrorKind::InvalidInput.into());
    let name = vault_path
        .file_name()
        .ok_or_else(invalid)?
        .to_string_lossy();
    let moved_name = moved.file_name().ok_or_else(invalid)?.to_string_lossy();
    let stamp = moved_name
        .strip_prefix(&format!("{name}{PRE_RESTORE}"))
        .filter(|stamp| !stamp.is_empty())
        .ok_or_else(invalid)?;
    if moved.parent() != vault_path.parent() {
        return Err(invalid());
    }
    let target = free_name(vault_path, REPLACED, stamp);
    let mut done: Vec<&str> = Vec::new();
    for suffix in ["-wal", "-shm", ""] {
        match std::fs::rename(with_suffix(moved, suffix), with_suffix(&target, suffix)) {
            Ok(()) => done.push(suffix),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {}
            Err(error) => {
                for back in done.iter().rev() {
                    if let Err(undo) =
                        std::fs::rename(with_suffix(&target, back), with_suffix(moved, back))
                    {
                        tracing::error!(error = %undo, "could not undo a partial rename of the replaced vault");
                    }
                }
                return Err(error.into());
            }
        }
    }
    Ok(target)
}

/// The old vault files that a failed restore left next to `vault_path`: the main files named
/// `<vault file name>.pre-restore-<stamp>` (and `-2`, `-3` ... , see [`free_name`]), newest first.
/// A `-wal` or `-shm` side file is not listed: it travels with its main file. Regular files and
/// symbolic links count (an older version moved a linked vault path as the link, NEW-11), folders
/// do not. A missing directory is not an error, it just holds none (T27-G). The old file of a
/// restore that went through is named `.replaced-*` ([`retire_replaced`]) and is not listed (NEW-12).
///
/// The desktop uses it at start: when the vault file is gone and this list is not empty, the real
/// vault is stranded and a new empty vault must not be made.
///
/// # Errors
/// [`StoreError::Io`] when the directory cannot be read.
pub fn stranded_vaults(vault_path: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let (Some(dir), Some(name)) = (vault_path.parent(), vault_path.file_name()) else {
        return Ok(Vec::new());
    };
    let prefix = format!("{}{PRE_RESTORE}", name.to_string_lossy());
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    // Sort key: the stamp (fixed width, so text order is time order), then the `-N` of `free_name`.
    let mut found: Vec<((String, u32), PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = file_name.strip_prefix(&prefix) else {
            continue;
        };
        if rest.ends_with("-wal") || rest.ends_with("-shm") {
            continue;
        }
        let kind = entry.file_type()?;
        if !kind.is_file() && !kind.is_symlink() {
            continue;
        }
        let key = rest.split_once('-').map_or_else(
            || (rest.to_owned(), 1),
            |(stamp, n)| (stamp.to_owned(), n.parse().unwrap_or(1)),
        );
        found.push((key, entry.path()));
    }
    found.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

    use std::sync::Arc;

    use cerberus_types::{ManualClock, t0};

    use super::*;
    use crate::OpenOptions;

    fn files_at(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// NEW-10: the swap fails after the old vault file was moved (here the checked copy is gone).
    /// Every moved file comes back, unchanged, and the old vault opens.
    #[tokio::test]
    async fn a_swap_that_fails_after_the_move_puts_the_old_vault_back() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.cerberus");
        let clock = Arc::new(ManualClock::new(t0()));
        let options = |create| OpenOptions {
            path: vault.clone(),
            create,
        };
        let store = Store::open(options(true), clock.clone()).await.unwrap();
        let schema: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        store.close().await;
        let main = std::fs::read(&vault).unwrap();
        // A `-wal` and `-shm` that a crash left behind: they must come back too.
        std::fs::write(with_suffix(&vault, "-wal"), b"").unwrap();
        std::fs::write(with_suffix(&vault, "-shm"), b"shm").unwrap();
        let before = files_at(dir.path());
        let missing = dir.path().join("vault.cerberus.restore-tmp");
        let result = swap_files(&missing, &vault, "20260101T000000Z");
        assert!(matches!(result, Err(StoreError::Io(_))), "{result:?}");
        assert_eq!(files_at(dir.path()), before, "no file is left moved");
        assert_eq!(
            std::fs::read(&vault).unwrap(),
            main,
            "the old file is unchanged"
        );
        assert_eq!(std::fs::read(with_suffix(&vault, "-shm")).unwrap(), b"shm");
        std::fs::remove_file(with_suffix(&vault, "-shm")).unwrap();
        let store = Store::open(options(false), clock).await.unwrap();
        let again: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(again, schema, "the old vault opens");
        store.close().await;
    }

    /// T27-G: the old files of failed restores are listed newest first, by stamp and then by the
    /// `-N` of the name; side files, other names and a missing folder are not listed.
    #[test]
    fn stranded_vaults_lists_main_files_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.cerberus");
        assert!(
            stranded_vaults(&dir.path().join("missing").join("v"))
                .unwrap()
                .is_empty()
        );
        assert!(stranded_vaults(&vault).unwrap().is_empty());
        for name in [
            "vault.cerberus.pre-restore-20260101T000000Z",
            "vault.cerberus.pre-restore-20260101T000000Z-wal",
            "vault.cerberus.pre-restore-20260101T000000Z-2",
            "vault.cerberus.pre-restore-20260101T000000Z-10",
            "vault.cerberus.pre-restore-20260102T000000Z-shm",
            "vault.cerberus.pre-restore-20251231T000000Z",
            "vault.cerberus.restore-tmp",
            "other.cerberus.pre-restore-20270101T000000Z",
        ] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        std::fs::create_dir(
            dir.path()
                .join("vault.cerberus.pre-restore-20280101T000000Z"),
        )
        .unwrap();
        let names: Vec<String> = stranded_vaults(&vault)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "vault.cerberus.pre-restore-20260101T000000Z-10",
                "vault.cerberus.pre-restore-20260101T000000Z-2",
                "vault.cerberus.pre-restore-20260101T000000Z",
                "vault.cerberus.pre-restore-20251231T000000Z",
            ]
        );
    }

    /// NEW-10: a `-wal` or `-shm` that is not there (a closing connection may just have removed
    /// it) does not stop the swap.
    #[test]
    fn missing_side_files_do_not_stop_the_swap() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.cerberus");
        let tmp = dir.path().join("vault.cerberus.restore-tmp");
        std::fs::write(&vault, b"old").unwrap();
        std::fs::write(with_suffix(&vault, "-shm"), b"shm").unwrap();
        std::fs::write(&tmp, b"new").unwrap();
        let moved = swap_files(&tmp, &vault, "20260101T000000Z")
            .unwrap()
            .expect("the old file was moved");
        assert_eq!(std::fs::read(&vault).unwrap(), b"new");
        assert_eq!(std::fs::read(&moved).unwrap(), b"old");
        assert_eq!(std::fs::read(with_suffix(&moved, "-shm")).unwrap(), b"shm");
        assert!(!with_suffix(&vault, "-shm").exists());
    }

    /// Two restores in the same second keep both old vault files.
    #[test]
    fn a_second_restore_in_the_same_second_keeps_the_first_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.cerberus");
        let tmp = dir.path().join("vault.cerberus.restore-tmp");
        let mut moved = Vec::new();
        for text in ["one", "two", "three"] {
            std::fs::write(&vault, text).unwrap();
            std::fs::write(&tmp, b"next").unwrap();
            moved.push(
                swap_files(&tmp, &vault, "20260101T000000Z")
                    .unwrap()
                    .unwrap(),
            );
        }
        let texts: Vec<Vec<u8>> = moved.iter().map(|p| std::fs::read(p).unwrap()).collect();
        assert_eq!(texts, [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);
        assert!(moved[1].to_string_lossy().ends_with("-2"));
    }

    /// NEW-12: the old file of a restore that went through is renamed to `.replaced-*` with its
    /// side files, so it is never listed as stranded; a second one of the same stamp gets `-2`.
    #[test]
    fn t27h_a_replaced_vault_is_not_listed_as_stranded() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.cerberus");
        let tmp = dir.path().join("vault.cerberus.restore-tmp");
        let mut kept = Vec::new();
        for text in ["one", "two"] {
            std::fs::write(&vault, text).unwrap();
            std::fs::write(with_suffix(&vault, "-wal"), b"wal").unwrap();
            std::fs::write(&tmp, b"next").unwrap();
            let moved = swap_files(&tmp, &vault, "20260101T000000Z")
                .unwrap()
                .unwrap();
            assert_eq!(
                stranded_vaults(&vault).unwrap(),
                std::slice::from_ref(&moved)
            );
            kept.push(retire_replaced(&vault, &moved).unwrap());
            assert!(stranded_vaults(&vault).unwrap().is_empty());
        }
        let names: Vec<String> = kept
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "vault.cerberus.replaced-20260101T000000Z",
                "vault.cerberus.replaced-20260101T000000Z-2",
            ]
        );
        assert_eq!(std::fs::read(&kept[1]).unwrap(), b"two");
        assert_eq!(
            std::fs::read(with_suffix(&kept[1], "-wal")).unwrap(),
            b"wal"
        );
        assert!(
            !files_at(dir.path())
                .iter()
                .any(|name| name.contains(".pre-restore-")),
            "no .pre-restore-* file is left"
        );
        assert!(
            retire_replaced(&vault, &vault).is_err(),
            "not a .pre-restore-* name"
        );
    }

    /// NEW-11: a `.pre-restore-*` main file that is a symbolic link (an older version moved a
    /// linked vault path as the link) counts as stranded, so the start makes no new vault.
    #[cfg(unix)]
    #[test]
    fn t27h_a_linked_old_vault_file_is_listed_as_stranded() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.cerberus");
        let real = dir.path().join("real.cerberus");
        std::fs::write(&real, b"x").unwrap();
        let old = dir
            .path()
            .join("vault.cerberus.pre-restore-20260101T000000Z");
        std::os::unix::fs::symlink(&real, &old).unwrap();
        assert_eq!(stranded_vaults(&vault).unwrap(), [old]);
    }
}
