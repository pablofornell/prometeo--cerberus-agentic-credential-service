//! `backup_restore` (ADR-0031): check the backup, prove the credential against it, swap the file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_api::{LocalCaIssuer, TlsPaths};
use cerberus_core::{CoreConfig, KeyCustody, VaultService};
use cerberus_crypto::{RecoveryKey, SecretString};
use cerberus_store::{
    OpenOptions, Store, StoreError, linked_vault_file, restore_backup, retire_replaced,
    stranded_vaults,
};
use cerberus_types::{Clock, LockReason, OperatorId, SystemClock, VaultStateKind};
use zeroize::Zeroizing;

use super::files;
use crate::dto::{RestoreUnlockInput, id};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

/// Largest backup file accepted.
const MAX_BACKUP_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The credential of the backup, kept as plain zeroizing text so it can be used twice.
enum Credential {
    Phrase(OperatorId, Zeroizing<String>),
    Recovery(Zeroizing<String>),
}

impl Credential {
    fn from_input(input: RestoreUnlockInput) -> IpcResult<Self> {
        match input {
            RestoreUnlockInput::Phrase {
                operator_id,
                phrase,
            } => Ok(Self::Phrase(
                id("operator_id", &operator_id)?,
                Zeroizing::new(phrase.into_core().expose_secret().to_owned()),
            )),
            RestoreUnlockInput::Recovery { recovery_key } => Ok(Self::Recovery(Zeroizing::new(
                recovery_key.into_core().expose_secret().to_owned(),
            ))),
        }
    }

    async fn unlock(&self, core: &VaultService) -> IpcResult<()> {
        match self {
            Self::Phrase(operator, phrase) => {
                core.unlock_with_phrase(*operator, SecretString::new(phrase.to_string()))
                    .await?;
            }
            Self::Recovery(text) => {
                let key = RecoveryKey::parse(text).map_err(|_| {
                    IpcError::invalid("recovery_key", "is not a valid recovery key")
                })?;
                core.unlock_with_recovery(key).await?;
            }
        }
        Ok(())
    }
}

/// The backup, copied once into a private folder (mode 0700) inside the data directory. The
/// copy is the only thing that is opened from here on: it is checked, the credential is proved on
/// a copy of it, and it is the file that is installed (AUD-10). The folder is removed at the end.
struct Staged {
    dir: PathBuf,
    candidate: PathBuf,
}

impl Staged {
    /// Reads `backup` once and checks the copy. The caller's path is not opened again.
    async fn copy(state: &DesktopState, backup: &Path) -> IpcResult<Self> {
        let dir = state.inner.paths.data_dir.join(format!(
            "restore-check-{}",
            cerberus_types::RequestId::generate()
        ));
        create_private_dir(&dir)?;
        let staged = Self {
            candidate: dir.join("candidate.cerberus"),
            dir,
        };
        files::copy_new_private(backup, &staged.candidate, MAX_BACKUP_BYTES)?;
        Store::inspect_backup(&staged.candidate).await?;
        Ok(staged)
    }

    /// Proves the credential on a throwaway copy of the staged file, opened as a second service,
    /// so nothing of the live vault changes and the staged file itself is never opened for writing.
    async fn prove(&self, clock: &Arc<dyn Clock>, credential: &Credential) -> IpcResult<()> {
        let probe_dir = self.dir.join("probe");
        create_private_dir(&probe_dir)?;
        let file = probe_dir.join("vault.cerberus");
        files::copy_new_private(&self.candidate, &file, MAX_BACKUP_BYTES)?;
        let store = Store::open(
            OpenOptions {
                path: file,
                create: false,
            },
            Arc::clone(clock),
        )
        .await?;
        let issuer = LocalCaIssuer::new(TlsPaths::in_data_dir(&probe_dir), Vec::new());
        let config = CoreConfig::desktop(probe_dir.clone(), Arc::new(issuer));
        let service = VaultService::open(store, Arc::clone(clock), config).await?;
        let proved = report_chain(&service, credential).await;
        // Closed before its folder goes, so no connection of it is left (NEW-10).
        service.close_store().await;
        drop(service);
        proved?;
        if let Err(error) = std::fs::remove_dir_all(&probe_dir) {
            tracing::warn!(%error, "could not remove the restore probe folder");
        }
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // The folder is one this call made inside the data directory.
        if let Err(error) = std::fs::remove_dir_all(&self.dir) {
            tracing::warn!(%error, "could not remove the restore check folder");
        }
    }
}

fn create_private_dir(path: &Path) -> IpcResult<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

/// `backup_restore`: owner, or no vault yet. Copies the backup once into a private folder, proves
/// the credential against that copy, moves the current file to `vault.cerberus.pre-restore-<time>`,
/// installs the same copy, opens it, then revokes all leases and cancels pending requests by one
/// unlock and lock (ADR-0031 step 3.5). The old store is closed, and every task that uses it has
/// ended, before any file moves (NEW-10). When the swap or a step after it fails, the old vault file
/// is put back (AUD-10) and opened again; a restore never makes a new vault in its place. One
/// restore runs at a time. The vault is locked afterwards: the person unlocks it.
///
/// A vault path that is a symbolic link is refused before anything changes (NEW-11). When the
/// restore went through, the old file is renamed from `.pre-restore-*` to `.replaced-*`, so only
/// a restore that did not finish leaves a `.pre-restore-*` file (NEW-12).
pub async fn backup_restore(
    state: &DesktopState,
    window: &str,
    src: String,
    unlock: RestoreUnlockInput,
) -> IpcResult<()> {
    check(window, "backup_restore")?;
    let _gate = state
        .inner
        .restore_gate
        .try_lock()
        .map_err(|_| IpcError::new("conflict", "a restore is already running"))?;
    let core = state.core()?;
    let ctx = if core.state() == VaultStateKind::NoVault {
        None
    } else {
        Some(state.operator().await?.1)
    };
    core.authorize_restore(ctx.as_ref()).await?;
    // The swap would rename the link, not the vault it points to, and the next start would not
    // find the real file (NEW-11). Refused before anything is read, locked or moved.
    if let Some(link) = linked_vault_file(&state.inner.paths.vault_file()) {
        tracing::warn!(link = %link.display(), "restore refused: the vault path is a symbolic link");
        return Err(IpcError::unavailable(
            "the vault file is a symbolic link; put the real file at the vault path, then restore",
        ));
    }
    let backup = files::picked_file(state, "src", &src, MAX_BACKUP_BYTES)?;
    let credential = Credential::from_input(unlock)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let staged = Staged::copy(state, &backup).await?;
    staged.prove(&clock, &credential).await?;

    // Lock the old vault first (DEC-FIX8-4): the lock closes the SSH bridge sockets, cancels
    // pending requests and drops the keys. Only then the server and the tasks stop.
    if core.state() == VaultStateKind::Unlocked {
        core.lock(LockReason::Restore).await?;
    }
    drop(core);
    close_service(state).await;
    let paths = state.inner.paths.clone();
    let tls = TlsPaths::in_data_dir(&paths.data_dir);
    // The leaf belongs to the old CA. The backup keeps the CA, so the next unlock makes a new leaf.
    for leaf in [&tls.leaf_cert_der, &tls.leaf_key_der, &tls.ca_cert_der] {
        if let Err(error) = std::fs::remove_file(leaf)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "could not remove the old TLS leaf");
        }
    }
    let vault = paths.vault_file();
    let had_vault = vault.exists();
    let moved = match swap(state, &staged.candidate, &vault, &*clock).await {
        Ok(moved) => moved,
        Err(error) => {
            reopen_after_failed_swap(state, &vault, had_vault, &error).await;
            return Err(error.into());
        }
    };
    // From here the restored file is installed, so every failure puts the old one back (AUD-10),
    // including the failure to open the restored file.
    let finished = match state.reopen_service().await {
        Ok(()) => finish_restore(state, &credential).await,
        Err(error) => Err(error),
    };
    if let Err(error) = finished {
        roll_back(state, &paths.vault_file(), moved.as_deref()).await;
        return Err(error);
    }
    // The restore went through: the old file is no longer a vault to put back (NEW-12).
    if let Some(moved) = moved.as_deref() {
        match retire_replaced(&vault, moved) {
            Ok(kept) => tracing::info!(kept = %kept.display(), "the replaced vault file is kept"),
            Err(error) => tracing::warn!(
                %error,
                moved = %moved.display(),
                "could not rename the replaced vault file; it keeps its .pre-restore name"
            ),
        }
    }
    Ok(())
}

/// `vault_recover_stranded` (T27-G): puts the newest old vault of a failed restore back at the
/// vault path. It works only while the app found the vault stranded at start (or after a failed
/// restore): the vault file is missing and one or more `<vault>.pre-restore-*` files are next to it.
/// The newest one, with its `-wal` and `-shm`, is renamed to the vault path and never replaces a
/// file that is there. If the file does not open, it is moved back and the error is returned. The
/// vault is sealed afterwards, and `backup.recover` is written to the pending audit list, so it
/// joins the chain at the next unlock. That row also makes the core revoke every agent key and
/// lease of the vault at that unlock, before it serves a call (T27-H, NEW-12): the file may be
/// the vault a restore replaced. When the row cannot be written, the file is moved back too. No
/// unlock can run in between: `vault_unlock` waits for the restore gate that this call holds.
pub async fn vault_recover_stranded(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "vault_recover_stranded")?;
    let _gate = state
        .inner
        .restore_gate
        .try_lock()
        .map_err(|_| IpcError::new("conflict", "a restore is already running"))?;
    let vault = state.inner.paths.vault_file();
    if ["", "-wal", "-shm"]
        .iter()
        .any(|suffix| suffixed(&vault, suffix).symlink_metadata().is_ok())
        || state.core().is_ok()
    {
        return Err(IpcError::new(
            "conflict",
            "a vault file already exists; nothing was moved",
        ));
    }
    let Some(old) = stranded_vaults(&vault)?.into_iter().next() else {
        state.clear_stranded();
        return Err(IpcError::new("not_found", "no old vault file was found"));
    };
    move_files(&old, &vault).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            IpcError::new("conflict", "a vault file already exists; nothing was moved")
        } else {
            IpcError::internal(&error)
        }
    })?;
    let recovered = match state.reopen_service().await {
        Ok(()) => match state.core() {
            Ok(core) => core
                .record_stranded_recovery()
                .await
                .map_err(IpcError::from),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    if let Err(error) = recovered {
        // Not a vault the app can open, or its revoke marker cannot be written: leave the state
        // as it was found.
        tracing::error!(%error, old = %old.display(), "the old vault file is not put back; it stays at its old name");
        close_service(state).await;
        if let Err(back) = move_files(&vault, &old) {
            tracing::error!(%back, "could not move the old vault file back to its old name");
        }
        state.note_stranded();
        return Err(error);
    }
    state.clear_stranded();
    tracing::warn!(old = %old.display(), "an old vault file of a failed restore was put back in place; its agent keys and leases are revoked at the next unlock");
    Ok(())
}

/// Stops the server and every task of the current service, takes the service out of the state
/// and closes its store, and waits for all of it (NEW-10). A closing SQLite connection removes the
/// `-wal` and `-shm` files by name, so none may still be open when a vault file moves.
async fn close_service(state: &DesktopState) {
    state.clear_held();
    state.stop_all().await;
    let old = state.take_core();
    state.clear_held();
    if let Some(old) = old {
        old.close_store().await;
    }
}

/// The file swap of the store, or in tests what the swap hook says.
async fn swap(
    state: &DesktopState,
    candidate: &Path,
    vault: &Path,
    clock: &dyn Clock,
) -> Result<Option<PathBuf>, StoreError> {
    #[cfg(test)]
    if let Some(hook) = state.take_swap_hook()
        && let Some(result) = hook(vault)
    {
        return result;
    }
    #[cfg(not(test))]
    let _ = state;
    restore_backup(candidate, vault, clock).await
}

/// The swap failed. The store has moved the old files back, except when it says
/// `RestoreStranded`; then one more try is made here. The old vault is opened again and never
/// made new: only when there was no vault file before the restore may an empty one be made.
async fn reopen_after_failed_swap(
    state: &DesktopState,
    vault: &Path,
    had_vault: bool,
    error: &StoreError,
) {
    if let StoreError::RestoreStranded { moved } = error
        && let Err(back_error) = put_back(vault, moved)
    {
        tracing::error!(%back_error, moved = %moved.display(), "the old vault file is not back in place");
    }
    let reopened = if had_vault {
        state.reopen_service().await
    } else {
        state.open_service().await
    };
    if let Err(open_error) = reopened {
        tracing::error!(%open_error, "could not open the vault after a failed restore");
        // The vault file is gone and the old one is at `.pre-restore-*`: say so (T27-G).
        state.note_stranded();
    }
}

/// Puts the old vault file back after a restore failed past the swap, and opens it again.
async fn roll_back(state: &DesktopState, vault: &Path, moved: Option<&Path>) {
    if let Ok(core) = state.core() {
        drop(core.lock(LockReason::Restore).await);
    }
    close_service(state).await;
    if let Err(error) = undo_swap(vault, moved) {
        tracing::error!(%error, "could not put the old vault file back");
    }
    // With no old file (there was no vault) an empty vault is the state before the restore.
    let reopened = if moved.is_some() {
        state.reopen_service().await
    } else {
        state.open_service().await
    };
    if let Err(error) = reopened {
        tracing::error!(%error, "could not open the vault after a failed restore");
        state.note_stranded();
    }
}

/// Renames the files at `moved` back to the vault path, but never over a file that is there.
fn put_back(vault: &Path, moved: &Path) -> std::io::Result<()> {
    move_files(moved, vault)
}

/// Renames `from`, `from-wal` and `from-shm` (the ones that exist) to `to`, `to-wal` and `to-shm`.
/// It never replaces a file: when any target is there, nothing is moved and the error is
/// `AlreadyExists`. When a rename fails, the files moved so far go back and the error is returned.
fn move_files(from: &Path, to: &Path) -> std::io::Result<()> {
    let present: Vec<&str> = ["", "-wal", "-shm"]
        .into_iter()
        .filter(|suffix| suffixed(from, suffix).exists())
        .collect();
    if present
        .iter()
        .any(|suffix| suffixed(to, suffix).symlink_metadata().is_ok())
    {
        return Err(std::io::ErrorKind::AlreadyExists.into());
    }
    let mut done: Vec<&str> = Vec::new();
    for suffix in present {
        if let Err(error) = std::fs::rename(suffixed(from, suffix), suffixed(to, suffix)) {
            for moved in done.iter().rev() {
                if let Err(back) = std::fs::rename(suffixed(to, moved), suffixed(from, moved)) {
                    tracing::error!(%back, "could not undo a partial move of the vault files");
                }
            }
            return Err(error);
        }
        done.push(suffix);
    }
    Ok(())
}

/// Removes the installed vault file (and its `-wal` and `-shm`) and renames the moved file back.
/// With no moved file (there was no vault before) the installed file is only removed.
fn undo_swap(vault: &Path, moved: Option<&Path>) -> std::io::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        match std::fs::remove_file(suffixed(vault, suffix)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if let Some(moved) = moved {
        for suffix in ["", "-wal", "-shm"] {
            let from = suffixed(moved, suffix);
            if from.exists() {
                std::fs::rename(&from, suffixed(vault, suffix))?;
            }
        }
    }
    Ok(())
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Unlocks the staged service with the credential and warns when its audit chain is broken.
async fn report_chain(service: &VaultService, credential: &Credential) -> IpcResult<()> {
    credential.unlock(service).await?;
    let status = service.status().await;
    if let Some(session) = status.session {
        let ctx = cerberus_core::OperatorContext {
            operator_id: session.operator_id,
            role: session.role,
            request_id: cerberus_types::RequestId::generate(),
        };
        if let Ok(report) = service.audit_verify(&ctx).await
            && matches!(report, cerberus_core::audit::ChainReport::Broken { .. })
        {
            tracing::warn!("the audit chain of the backup is broken; restoring anyway");
        }
    }
    drop(service.lock(LockReason::Restore).await);
    Ok(())
}

/// Unlocks the restored vault, revokes every lease, and locks it again.
async fn finish_restore(state: &DesktopState, credential: &Credential) -> IpcResult<()> {
    let core = state.core()?;
    credential.unlock(&core).await?;
    let (core, ctx) = state.operator().await?;
    let revoked = core.revoke_all_leases(&ctx).await;
    let recorded = core.record_restore(&ctx).await;
    core.lock(LockReason::Restore).await?;
    let count = revoked?;
    recorded?;
    tracing::info!(count, "backup restored; leases revoked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Secret;
    use crate::error::IpcResult;
    use crate::prefs::{AppPaths, Prefs};
    use crate::state::{Shell, StateOptions};
    use cerberus_core::NewVault;
    use serde_json::json;

    const PHRASE: &str = "correct horse battery staple jumbo violet";

    struct NoShell;

    impl Shell for NoShell {
        fn clipboard_write(&self, _text: &str) -> IpcResult<()> {
            Ok(())
        }
        fn clipboard_read(&self) -> Option<String> {
            None
        }
        fn clipboard_clear(&self) {}
        fn set_autostart(&self, _enabled: bool) -> IpcResult<()> {
            Ok(())
        }
        fn set_content_protection(&self, _enabled: bool) {}
    }

    async fn state_with_vault() -> (DesktopState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let app = dir.path().join("app");
        std::fs::create_dir_all(&app).expect("app dir");
        let paths = AppPaths::new(app);
        Prefs {
            port: 0,
            ..Prefs::default()
        }
        .save(&paths)
        .expect("prefs");
        let state = DesktopState::open(paths, Arc::new(NoShell), StateOptions::default())
            .await
            .expect("open");
        state
            .core()
            .expect("core")
            .create_vault(NewVault {
                owner_label: "owner".to_owned(),
                phrase: SecretString::new(PHRASE.to_owned()),
                kdf: cerberus_crypto::KdfParams::new(19_456, 1, 1).expect("kdf"),
                host_names: Vec::new(),
            })
            .await
            .expect("create vault");
        (state, dir)
    }

    async fn add_note(state: &DesktopState, title: &str) {
        let ws = crate::ops::workspace_put(
            state,
            "main",
            None,
            serde_json::from_value(
                json!({ "slug": title, "name": title, "description": "", "aliases": [] }),
            )
            .expect("workspace"),
        )
        .await
        .expect("workspace")
        .id;
        let input = serde_json::from_value(json!({
            "workspace_id": ws, "title": title, "description": "", "role_label": null,
            "category": "Note", "tags": [], "environment": "dev", "target": null, "custom": {},
            "expires_at": null, "max_uses": null,
            "payload": { "kind": "note", "text": "fake" }
        }))
        .expect("input");
        crate::ops::item_create(state, "main", input)
            .await
            .expect("item");
    }

    /// AUD-10: the backup is read once. What is checked and installed is the private copy, so a
    /// change of the original after the copy has no effect.
    #[tokio::test]
    async fn the_staged_copy_does_not_follow_the_original() {
        let (state, dir) = state_with_vault().await;
        let backup = dir.path().join("b.cerberus-backup");
        crate::ops::backup_create(&state, "main", backup.display().to_string())
            .await
            .expect("backup");
        let original = std::fs::read(&backup).expect("read");
        let staged = Staged::copy(&state, &backup).await.expect("stage");
        // The attacker swaps the file in the synced folder after the copy.
        std::fs::write(&backup, b"not a vault").expect("swap");
        assert_eq!(std::fs::read(&staged.candidate).expect("read"), original);
        Store::inspect_backup(&staged.candidate)
            .await
            .expect("the staged copy is still the proved vault");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode(&staged.dir), 0o700);
            assert_eq!(mode(&staged.candidate), 0o600);
        }
        let folder = staged.dir.clone();
        drop(staged);
        assert!(!folder.exists(), "the staging folder is removed");
    }

    /// AUD-10: a garbage file is refused when it is staged, before anything of the live vault changes.
    #[tokio::test]
    async fn a_file_that_is_not_a_backup_is_refused_at_staging() {
        let (state, dir) = state_with_vault().await;
        let junk = dir.path().join("junk");
        std::fs::write(&junk, b"not a vault").expect("junk");
        assert!(Staged::copy(&state, &junk).await.is_err());
        let leftovers = std::fs::read_dir(&state.inner.paths.data_dir)
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("restore-check-")
            })
            .count();
        assert_eq!(leftovers, 0, "no staging folder is left behind");
    }

    /// AUD-10: when a step after the swap fails, the old vault file comes back and opens.
    #[tokio::test]
    async fn a_failed_restore_puts_the_old_vault_back() {
        let (state, dir) = state_with_vault().await;
        let backup = dir.path().join("b.cerberus-backup");
        crate::ops::backup_create(&state, "main", backup.display().to_string())
            .await
            .expect("backup");
        add_note(&state, "only-in-the-old-vault").await;
        let vault = state.inner.paths.vault_file();
        // The swap part of a restore, then the failure of a later step.
        let core = state.core().expect("core");
        core.lock(LockReason::Restore).await.expect("lock");
        drop(core);
        close_service(&state).await;
        let moved = restore_backup(&backup, &vault, &SystemClock)
            .await
            .expect("swap")
            .expect("the old file was moved");
        state
            .reopen_service()
            .await
            .expect("open the restored file");
        roll_back(&state, &vault, Some(&moved)).await;
        assert!(!moved.exists(), "the moved file is back in place");
        let operators = crate::ops::vault_list_operators(&state, "main")
            .await
            .expect("operators");
        crate::ops::vault_unlock(
            &state,
            "main",
            operators[0].id.clone(),
            Secret::new(PHRASE.into()),
        )
        .await
        .expect("unlock the old vault");
        let items = crate::ops::item_list(&state, "main", Default::default())
            .await
            .expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "only-in-the-old-vault");
    }

    fn phrase_input(operator_id: String) -> RestoreUnlockInput {
        serde_json::from_value(json!({
            "kind": "phrase", "operator_id": operator_id, "phrase": PHRASE
        }))
        .expect("input")
    }

    /// AUD-10: when the restored file cannot be opened (a step after the swap, before the lock and
    /// revoke part), the old vault file still comes back, opens, and nothing is stranded.
    #[tokio::test]
    async fn a_restored_file_that_does_not_open_is_rolled_back() {
        let (state, dir) = state_with_vault().await;
        let backup = dir.path().join("b.cerberus-backup");
        crate::ops::backup_create(&state, "main", backup.display().to_string())
            .await
            .expect("backup");
        add_note(&state, "only-in-the-old-vault").await;
        let operator = crate::ops::vault_list_operators(&state, "main")
            .await
            .expect("operators")[0]
            .id
            .clone();
        state.note_dropped(std::slice::from_ref(&backup));
        // The first open after the swap fails; the open of the roll back works.
        state
            .inner
            .fail_next_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let error = backup_restore(
            &state,
            "main",
            backup.display().to_string(),
            phrase_input(operator.clone()),
        )
        .await
        .expect_err("the restore fails");
        assert_eq!(error.code, "internal");
        let data_dir = &state.inner.paths.data_dir;
        let stranded = std::fs::read_dir(data_dir)
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".pre-restore-"))
            .count();
        assert_eq!(stranded, 0, "the old file is not left as .pre-restore-*");
        crate::ops::vault_unlock(&state, "main", operator, Secret::new(PHRASE.into()))
            .await
            .expect("unlock the original vault");
        let items = crate::ops::item_list(&state, "main", Default::default())
            .await
            .expect("items");
        assert_eq!(items.len(), 1, "the original vault is back and usable");
        assert_eq!(items[0].title, "only-in-the-old-vault");
    }

    /// AUD-10: a restore that starts while another one holds the gate is refused, without a race:
    /// the gate is held by the test, so the second call must observe the first one in progress.
    #[tokio::test]
    async fn a_second_restore_is_refused_while_the_gate_is_held() {
        let (state, dir) = state_with_vault().await;
        let backup = dir.path().join("b.cerberus-backup");
        crate::ops::backup_create(&state, "main", backup.display().to_string())
            .await
            .expect("backup");
        let operator = crate::ops::vault_list_operators(&state, "main")
            .await
            .expect("operators")[0]
            .id
            .clone();
        state.note_dropped(std::slice::from_ref(&backup));
        let src = backup.display().to_string();
        let running = state
            .inner
            .restore_gate
            .try_lock()
            .expect("the gate is free");
        let refused = backup_restore(&state, "main", src.clone(), phrase_input(operator.clone()))
            .await
            .expect_err("refused");
        assert_eq!(refused.code, "conflict");
        drop(running);
        // With the gate free the same call goes through.
        backup_restore(&state, "main", src, phrase_input(operator))
            .await
            .expect("the restore runs once the gate is free");
    }

    /// A vault with one note, its backup (dropped on the window, so it may be read) and the owner.
    async fn restorable() -> (DesktopState, tempfile::TempDir, PathBuf, String) {
        let (state, dir) = state_with_vault().await;
        let backup = dir.path().join("b.cerberus-backup");
        crate::ops::backup_create(&state, "main", backup.display().to_string())
            .await
            .expect("backup");
        add_note(&state, "only-in-the-old-vault").await;
        let operator = crate::ops::vault_list_operators(&state, "main")
            .await
            .expect("operators")[0]
            .id
            .clone();
        state.note_dropped(std::slice::from_ref(&backup));
        (state, dir, backup, operator)
    }

    fn set_swap_hook(state: &DesktopState, hook: crate::state::SwapHook) {
        *state
            .inner
            .swap_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    fn pre_restore_files(state: &DesktopState) -> Vec<PathBuf> {
        std::fs::read_dir(&state.inner.paths.data_dir)
            .expect("dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".pre-restore-"))
            .map(|e| e.path())
            .collect()
    }

    /// Moves the vault file and its `-wal` and `-shm` to `<vault>.pre-restore-test`.
    fn move_vault_away(vault: &Path) -> PathBuf {
        let moved = suffixed(vault, ".pre-restore-test");
        for suffix in ["", "-wal", "-shm"] {
            let from = suffixed(vault, suffix);
            if from.exists() {
                std::fs::rename(&from, suffixed(&moved, suffix)).expect("move");
            }
        }
        moved
    }

    /// NEW-10: the old store is closed, with its `-wal` folded in and removed, before the swap
    /// moves any file. The hook sees the state right before the swap.
    #[tokio::test]
    async fn new10_the_old_store_is_closed_before_the_swap() {
        let (state, _dir, backup, operator) = restorable().await;
        let old = state.core().expect("core").store().clone();
        let seen = Arc::new(std::sync::Mutex::new(None));
        let record = Arc::clone(&seen);
        set_swap_hook(
            &state,
            Box::new(move |vault: &Path| {
                *record.lock().expect("seen") =
                    Some((old.is_closed(), suffixed(vault, "-wal").exists()));
                None
            }),
        );
        backup_restore(
            &state,
            "main",
            backup.display().to_string(),
            phrase_input(operator),
        )
        .await
        .expect("restore");
        let seen = *seen.lock().expect("seen");
        assert_eq!(
            seen,
            Some((true, false)),
            "(old store closed, -wal left) right before the swap"
        );
    }

    /// NEW-10: the store could not move the old file back (`RestoreStranded`). The desktop puts it
    /// back and opens it; it never opens the vault path with `create`, which made a new empty vault.
    #[tokio::test]
    async fn new10_a_stranded_old_vault_is_put_back_not_replaced_by_an_empty_one() {
        let (state, _dir, backup, operator) = restorable().await;
        set_swap_hook(
            &state,
            Box::new(|vault: &Path| {
                let moved = move_vault_away(vault);
                Some(Err(StoreError::RestoreStranded { moved }))
            }),
        );
        let error = backup_restore(
            &state,
            "main",
            backup.display().to_string(),
            phrase_input(operator.clone()),
        )
        .await
        .expect_err("the swap fails");
        assert_eq!(error.code, "internal");
        assert!(pre_restore_files(&state).is_empty(), "the old file is back");
        crate::ops::vault_unlock(&state, "main", operator, Secret::new(PHRASE.into()))
            .await
            .expect("the original vault unlocks");
        let items = crate::ops::item_list(&state, "main", Default::default())
            .await
            .expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "only-in-the-old-vault");
    }

    /// NEW-10: when the vault file is gone after a failed swap and cannot be found, the vault path
    /// stays empty: no new vault is made there, and the old file is untouched.
    #[tokio::test]
    async fn new10_a_failed_swap_never_makes_a_new_vault() {
        let (state, _dir, backup, operator) = restorable().await;
        let vault = state.inner.paths.vault_file();
        let kept = Arc::new(std::sync::Mutex::new(None));
        let record = Arc::clone(&kept);
        set_swap_hook(
            &state,
            Box::new(move |vault: &Path| {
                *record.lock().expect("kept") = Some(move_vault_away(vault));
                Some(Err(StoreError::Io(std::io::ErrorKind::NotFound.into())))
            }),
        );
        backup_restore(
            &state,
            "main",
            backup.display().to_string(),
            phrase_input(operator),
        )
        .await
        .expect_err("the swap fails");
        assert!(!vault.exists(), "no new vault file at the vault path");
        let kept = kept.lock().expect("kept").clone().expect("moved");
        Store::inspect_backup(&kept)
            .await
            .expect("the old vault file is intact where it is");
        assert_eq!(
            state.core().expect_err("no service").code,
            "stranded_restore",
            "no service runs on an empty vault, and the old file is reported (T27-G)"
        );
        let status = crate::ops::vault_status(&state, "main")
            .await
            .expect("status");
        assert_eq!(status.stranded_restore, [kept.display().to_string()]);
    }

    /// T27-G: a vault whose service is closed, its file moved to `.pre-restore-test` (a failed
    /// restore that left only the old file), and a new app state started on the same folder.
    async fn stranded_start() -> (DesktopState, tempfile::TempDir, PathBuf, String) {
        let (state, dir, _backup, operator) = restorable().await;
        let paths = state.inner.paths.clone();
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        close_service(&state).await;
        let kept = move_vault_away(&paths.vault_file());
        drop(state);
        let restarted = DesktopState::open(paths, Arc::new(NoShell), StateOptions::default())
            .await
            .expect("open");
        (restarted, dir, kept, operator)
    }

    /// T27-G: the vault file is gone and an old one waits at `.pre-restore-*`. The start makes no
    /// new vault; it reports the old file, and creating a vault is refused.
    #[tokio::test]
    async fn t27g_start_with_only_a_pre_restore_file_makes_no_vault() {
        let (state, _dir, kept, _operator) = stranded_start().await;
        let vault = state.inner.paths.vault_file();
        assert!(!vault.exists(), "no new vault file at the vault path");
        assert_eq!(state.stranded_restore(), std::slice::from_ref(&kept));
        assert_eq!(
            state.core().expect_err("no service").code,
            "stranded_restore"
        );
        let status = crate::ops::vault_status(&state, "main")
            .await
            .expect("status");
        assert_eq!(status.state, crate::dto::VaultState::NoVault);
        assert_eq!(status.stranded_restore, [kept.display().to_string()]);
        let refused = crate::ops::vault_create(
            &state,
            "main",
            "owner".to_owned(),
            Secret::new(PHRASE.into()),
            serde_json::from_value(json!({ "m_cost_kib": 19_456, "t_cost": 1, "p_cost": 1 }))
                .expect("kdf"),
            Vec::new(),
        )
        .await
        .expect_err("no new vault while the old one waits");
        assert_eq!(refused.code, "stranded_restore");
        assert!(!vault.exists());
        assert!(kept.exists(), "the old file is untouched");
    }

    /// T27-G: the recover command puts the newest old file back; the vault then unlocks with its data
    /// and the recovery is in the audit chain.
    #[tokio::test]
    async fn t27g_recover_puts_the_stranded_vault_back() {
        let (state, _dir, kept, operator) = stranded_start().await;
        let vault = state.inner.paths.vault_file();
        vault_recover_stranded(&state, "main")
            .await
            .expect("recover");
        assert!(vault.exists() && !kept.exists(), "the file moved back");
        assert!(state.stranded_restore().is_empty());
        let status = crate::ops::vault_status(&state, "main")
            .await
            .expect("status");
        assert_eq!(status.state, crate::dto::VaultState::Sealed);
        assert!(status.stranded_restore.is_empty());
        crate::ops::vault_unlock(&state, "main", operator, Secret::new(PHRASE.into()))
            .await
            .expect("the original vault unlocks");
        let items = crate::ops::item_list(&state, "main", Default::default())
            .await
            .expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "only-in-the-old-vault");
        let rows = crate::ops::audit_query(
            &state,
            "main",
            serde_json::from_value(json!({
                "from": null, "to": null, "event_type": "backup.recover", "agent_id": null,
                "item_id": null, "before_seq": null, "limit": 10
            }))
            .expect("query"),
        )
        .await
        .expect("audit");
        assert_eq!(rows.len(), 1, "one backup.recover event");
    }

    /// T27-G: the recover command never replaces a file at the vault path.
    #[tokio::test]
    async fn t27g_recover_refuses_when_a_vault_file_exists() {
        let (state, _dir, kept, _operator) = stranded_start().await;
        let vault = state.inner.paths.vault_file();
        std::fs::write(&vault, b"already here").expect("file");
        let refused = vault_recover_stranded(&state, "main")
            .await
            .expect_err("refused");
        assert_eq!(refused.code, "conflict");
        assert_eq!(std::fs::read(&vault).expect("read"), b"already here");
        assert!(kept.exists(), "the old file did not move");
    }

    /// T27-G: the files move together, and never over a file that is there.
    #[test]
    fn move_files_takes_the_side_files_and_never_replaces() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("vault.cerberus.pre-restore-1");
        let to = dir.path().join("vault.cerberus");
        for suffix in ["", "-wal", "-shm"] {
            std::fs::write(suffixed(&from, suffix), format!("old{suffix}")).expect("write");
        }
        std::fs::write(suffixed(&to, "-wal"), b"orphan").expect("orphan");
        let error = move_files(&from, &to).expect_err("a target is there");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(from.exists() && !to.exists(), "nothing moved");
        std::fs::remove_file(suffixed(&to, "-wal")).expect("remove");
        move_files(&from, &to).expect("move");
        for suffix in ["", "-wal", "-shm"] {
            assert_eq!(
                std::fs::read_to_string(suffixed(&to, suffix)).expect("read"),
                format!("old{suffix}")
            );
            assert!(!suffixed(&from, suffix).exists());
        }
    }

    /// Names in the data folder that contain `part`.
    fn files_named(state: &DesktopState, part: &str) -> Vec<String> {
        std::fs::read_dir(&state.inner.paths.data_dir)
            .expect("dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(part))
            .collect()
    }

    /// Locks the vault, closes its service and starts a new app state on the same folder.
    async fn restart(state: DesktopState) -> DesktopState {
        let paths = state.inner.paths.clone();
        if let Ok(core) = state.core() {
            core.lock(LockReason::Manual).await.expect("lock");
        }
        close_service(&state).await;
        drop(state);
        DesktopState::open(paths, Arc::new(NoShell), StateOptions::default())
            .await
            .expect("open")
    }

    /// NEW-12: a restore that went through leaves its old file as `.replaced-*`, not as
    /// `.pre-restore-*`. When the vault file is gone later, the start is a normal start with no
    /// vault, not the stranded state that offers to put the replaced vault back.
    #[tokio::test]
    async fn t27h_a_successful_restore_leaves_no_stranded_file() {
        let (state, _dir, backup, operator) = restorable().await;
        backup_restore(
            &state,
            "main",
            backup.display().to_string(),
            phrase_input(operator),
        )
        .await
        .expect("restore");
        assert!(
            pre_restore_files(&state).is_empty(),
            "no .pre-restore-* file"
        );
        assert_eq!(
            files_named(&state, ".replaced-").len(),
            1,
            "the old file is kept"
        );
        let vault = state.inner.paths.vault_file();
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        close_service(&state).await;
        // The person deletes the vault file to start over.
        std::fs::remove_file(&vault).expect("remove the vault file");
        let state = restart(state).await;
        assert!(state.stranded_restore().is_empty(), "nothing is stranded");
        let status = crate::ops::vault_status(&state, "main")
            .await
            .expect("status");
        assert_eq!(status.state, crate::dto::VaultState::NoVault);
        assert!(status.stranded_restore.is_empty());
    }

    /// NEW-12: a vault put back by `vault_recover_stranded` may be one that a restore replaced
    /// because its agent tokens leaked. At its first unlock every agent key is revoked before the
    /// vault serves a call, and `backup.recover_revoke` is in the chain.
    #[tokio::test]
    async fn t27h_a_recovered_vault_loses_its_agent_keys_at_unlock() {
        let (state, _dir, _backup, operator) = restorable().await;
        let agent = crate::ops::agent_create(
            &state,
            "main",
            serde_json::from_value(json!({ "name": "bot", "description": "" })).expect("agent"),
            serde_json::from_value(json!({
                "scopes": ["catalog:read"], "lifetime_days": 30, "ip_allowlist": []
            }))
            .expect("key"),
        )
        .await
        .expect("agent");
        assert!(agent.agent.keys.iter().all(|key| key.revoked_at.is_none()));
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        close_service(&state).await;
        let kept = move_vault_away(&state.inner.paths.vault_file());
        let state = restart(state).await;
        assert_eq!(state.stranded_restore(), [kept]);
        vault_recover_stranded(&state, "main")
            .await
            .expect("recover");
        crate::ops::vault_unlock(&state, "main", operator, Secret::new(PHRASE.into()))
            .await
            .expect("unlock");
        let agents = crate::ops::agent_list(&state, "main")
            .await
            .expect("agents");
        assert_eq!(agents.len(), 1);
        assert!(!agents[0].keys.is_empty());
        assert!(
            agents[0].keys.iter().all(|key| key.revoked_at.is_some()),
            "every agent key of the recovered vault is revoked"
        );
        let rows = crate::ops::audit_query(
            &state,
            "main",
            serde_json::from_value(json!({
                "from": null, "to": null, "event_type": "backup.recover_revoke", "agent_id": null,
                "item_id": null, "before_seq": null, "limit": 10
            }))
            .expect("query"),
        )
        .await
        .expect("audit");
        assert_eq!(rows.len(), 1, "one backup.recover_revoke event");
        // The marker was drained: the next unlock revokes nothing again.
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        let operator = crate::ops::vault_list_operators(&state, "main")
            .await
            .expect("operators")[0]
            .id
            .clone();
        crate::ops::vault_unlock(&state, "main", operator, Secret::new(PHRASE.into()))
            .await
            .expect("unlock again");
        let rows = crate::ops::audit_query(
            &state,
            "main",
            serde_json::from_value(json!({
                "from": null, "to": null, "event_type": "backup.recover_revoke", "agent_id": null,
                "item_id": null, "before_seq": null, "limit": 10
            }))
            .expect("query"),
        )
        .await
        .expect("audit");
        assert_eq!(rows.len(), 1, "the revoke ran once");
    }

    /// NEW-11: a restore over a vault path that is a symbolic link is refused with a clear error,
    /// before the vault is locked or any file moves; the link and the vault stay as they are.
    #[cfg(unix)]
    #[tokio::test]
    async fn t27h_a_restore_over_a_linked_vault_path_is_refused() {
        let (state, dir, backup, operator) = restorable().await;
        let vault = state.inner.paths.vault_file();
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        close_service(&state).await;
        let real = dir.path().join("vault.cerberus");
        std::fs::rename(&vault, &real).expect("move the vault out");
        std::os::unix::fs::symlink(&real, &vault).expect("link");
        state.reopen_service().await.expect("open through the link");
        crate::ops::vault_unlock(&state, "main", operator.clone(), Secret::new(PHRASE.into()))
            .await
            .expect("unlock");
        // The close above forgot the dropped files; the backup may be read again.
        state.note_dropped(std::slice::from_ref(&backup));
        let error = backup_restore(
            &state,
            "main",
            backup.display().to_string(),
            phrase_input(operator),
        )
        .await
        .expect_err("refused");
        assert_eq!(error.code, "unavailable", "{error:?}");
        assert!(
            vault
                .symlink_metadata()
                .expect("link")
                .file_type()
                .is_symlink()
        );
        assert!(pre_restore_files(&state).is_empty(), "nothing moved");
        assert_eq!(
            state.core().expect("core").state(),
            VaultStateKind::Unlocked,
            "refused before the vault was locked"
        );
    }

    /// NEW-11: the vault file is missing and the data folder cannot be listed. The start fails
    /// closed: no vault is made, no service runs, and the commands get `unavailable`.
    #[cfg(unix)]
    #[tokio::test]
    async fn t27h_a_folder_read_error_at_start_makes_no_vault() {
        use std::os::unix::fs::PermissionsExt;
        let (state, _dir, _backup, _operator) = restorable().await;
        let paths = state.inner.paths.clone();
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        close_service(&state).await;
        drop(state);
        let kept = move_vault_away(&paths.vault_file());
        let set_mode = |mode| {
            std::fs::set_permissions(&paths.data_dir, std::fs::Permissions::from_mode(mode))
                .expect("chmod");
        };
        // Write and search, but no read: `read_dir` fails, a file can still be made.
        set_mode(0o300);
        if std::fs::read_dir(&paths.data_dir).is_ok() {
            set_mode(0o700);
            eprintln!("skipped: the folder mode is not enforced for this user");
            return;
        }
        let opened =
            DesktopState::open(paths.clone(), Arc::new(NoShell), StateOptions::default()).await;
        let vault_made = paths.vault_file().exists();
        set_mode(0o700);
        let state = opened.expect("open");
        assert!(!vault_made, "no new vault file at the vault path");
        assert!(!paths.vault_file().exists());
        assert_eq!(state.core().expect_err("no service").code, "unavailable");
        let refused = crate::ops::vault_create(
            &state,
            "main",
            "owner".to_owned(),
            Secret::new(PHRASE.into()),
            serde_json::from_value(json!({ "m_cost_kib": 19_456, "t_cost": 1, "p_cost": 1 }))
                .expect("kdf"),
            Vec::new(),
        )
        .await
        .expect_err("no new vault while the folder cannot be checked");
        assert_eq!(refused.code, "unavailable");
        assert!(!paths.vault_file().exists());
        assert!(kept.exists(), "the old file is untouched");
        // Once the folder reads again, the recovery finds the old file.
        vault_recover_stranded(&state, "main")
            .await
            .expect("recover");
        assert!(paths.vault_file().exists());
    }

    /// NEW-14: when the vault service does not open after the store did, the store is closed and
    /// waited for before the caller moves any file.
    #[tokio::test]
    async fn t27h_a_store_whose_service_does_not_open_is_closed() {
        let (state, _dir) = state_with_vault().await;
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        close_service(&state).await;
        state
            .inner
            .fail_next_service_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
        state.reopen_service().await.expect_err("injected failure");
        let store = state
            .inner
            .failed_store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .expect("the store of the failed open");
        assert!(store.is_closed(), "the store is closed");
        assert!(state.core().is_err(), "no service runs");
    }

    /// NEW-14: an unlock waits while a restore (or a recovery) holds the gate, so it cannot unlock
    /// the old vault between the restore's lock and the swap; it runs once the gate is free.
    #[tokio::test]
    async fn t27h_an_unlock_waits_for_the_restore_gate() {
        let (state, _dir) = state_with_vault().await;
        let core = state.core().expect("core");
        core.lock(LockReason::Manual).await.expect("lock");
        drop(core);
        let operator = crate::ops::vault_list_operators(&state, "main")
            .await
            .expect("operators")[0]
            .id
            .clone();
        let running = state
            .inner
            .restore_gate
            .try_lock()
            .expect("the gate is free");
        let waited = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            crate::ops::vault_unlock(&state, "main", operator.clone(), Secret::new(PHRASE.into())),
        )
        .await;
        assert!(waited.is_err(), "the unlock waits for the gate");
        assert_eq!(state.core().expect("core").state(), VaultStateKind::Sealed);
        drop(running);
        crate::ops::vault_unlock(&state, "main", operator, Secret::new(PHRASE.into()))
            .await
            .expect("the unlock runs once the gate is free");
        assert_eq!(
            state.core().expect("core").state(),
            VaultStateKind::Unlocked
        );
    }

    #[test]
    fn undoing_a_swap_with_no_old_file_only_removes_the_new_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = dir.path().join("vault.cerberus");
        std::fs::write(&vault, b"new").expect("write");
        std::fs::write(suffixed(&vault, "-wal"), b"wal").expect("wal");
        undo_swap(&vault, None).expect("undo");
        assert!(!vault.exists() && !suffixed(&vault, "-wal").exists());
    }
}
