//! The state of the desktop app: the one vault service, the HTTPS server, the secrets that stay in
//! the backend (SSH drafts, one-time values) and the clipboard timer (D1, ADR-0001).
//!
//! In remote mode (ADR-0034) the state holds a [`RemoteBackend`] instead: no store, no service
//! and no server are opened, and [`DesktopState::core`] answers `remote_unsupported`.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use cerberus_api::{LocalCaIssuer, RunningServer, TlsPaths};
use cerberus_core::items::Payload;
use cerberus_core::{
    CoreConfig, CoreError, KeyCustody, OperatorContext, OsLockEvents, VaultService,
};
use cerberus_crypto::sha256;
use cerberus_store::{OpenOptions, Store, stranded_vaults};
use cerberus_types::{Clock, LockReason, RequestId, SystemClock, VaultStateKind};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::dto::OneTimeKind;
use crate::error::{IpcError, IpcResult};
use crate::prefs::{AppPaths, Prefs};
use crate::remote::{self, CLOSE_WAIT, RemoteBackend};

/// How long a copied secret stays on the clipboard (plan section 4.7).
pub const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
/// Most SSH drafts kept in the backend at once. The oldest goes first.
const MAX_DRAFTS: usize = 8;
/// Most paths from the native file dialog that the backend remembers. The oldest goes first.
const MAX_PICKED: usize = 16;
/// `ui_activity` counts at most once in this time (interfaces.md section 9).
const ACTIVITY_MIN_GAP_MS: i64 = 1000;

/// What the app needs from the desktop shell. The real one is [`crate::shell::TauriShell`]; tests
/// use a fake, so the command layer runs without a window.
pub trait Shell: Send + Sync {
    /// Puts text on the clipboard.
    ///
    /// # Errors
    /// `unavailable` when the clipboard cannot be written.
    fn clipboard_write(&self, text: &str) -> IpcResult<()>;
    /// The text now on the clipboard, if it holds text.
    fn clipboard_read(&self) -> Option<String>;
    /// Empties the clipboard.
    fn clipboard_clear(&self);
    /// Turns the start-at-login option on or off.
    ///
    /// # Errors
    /// `unavailable` when the OS refuses.
    fn set_autostart(&self, enabled: bool) -> IpcResult<()>;
    /// Turns content protection (no screenshots of the window) on or off.
    fn set_content_protection(&self, enabled: bool);
    /// Opens the native dialog for one file and waits for the person. `None` when the person
    /// cancels or the system has no dialog. Only a path that comes from here may be read by the
    /// backend (AUD-11).
    fn pick_file(&self, _title: Option<&str>, _extensions: &[String]) -> Option<PathBuf> {
        None
    }
    /// Starts `program` with `args`: no shell, no wait, the arguments as they are. The desktop app
    /// uses it to open the RustDesk client (DEC-RD-3). The default starts nothing, so a shell
    /// that does not say otherwise (every test shell) never runs a program.
    ///
    /// # Errors
    /// `unavailable` when the program cannot be started.
    fn launch(&self, _program: &Path, _args: &[String]) -> IpcResult<()> {
        Err(IpcError::unavailable("this shell cannot start programs"))
    }
}

/// What stays in the backend and never goes to the UI as a plain value.
#[derive(Default)]
struct Held {
    drafts: VecDeque<(String, HeldTag, Payload)>,
    one_time: HashMap<&'static str, (HeldTag, Zeroizing<String>)>,
}

/// What a first-time setup of a server gave and the desktop must not lose: the recovery key, which
/// the server shows only once, and the admin bundle (JSON), until it is stored as a profile. It
/// has its own lifetime: no lock, idle lock or event lag clears it (`clear_held` does not touch
/// it), because it belongs to the server and not to a local unlock. It ends when the person
/// finishes the recovery step (`remote_setup_finish`), at a panic wipe, or at a restart.
pub(crate) struct SetupHold {
    pub(crate) recovery_key: Zeroizing<String>,
    pub(crate) bundle: Zeroizing<Vec<u8>>,
}

/// Who may use a held value: the operator of the unlock that was current when it was stored, and
/// the unlock time (the unlock epoch). A new unlock, even by the same operator, makes it stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldTag {
    operator: cerberus_types::OperatorId,
    unlocked_at_ms: i64,
}

/// The server and the tasks that belong to the current vault service.
#[derive(Default)]
pub(crate) struct Services {
    pub(crate) server: Option<RunningServer>,
    /// The leaf renewal task of the running server.
    pub(crate) renewal: Option<JoinHandle<()>>,
    /// The core background tasks (idle lock, sweeper).
    pub(crate) tasks: Vec<JoinHandle<()>>,
    pub(crate) extra_names: Vec<String>,
}

pub(crate) struct Inner {
    pub(crate) paths: AppPaths,
    pub(crate) shell: Arc<dyn Shell>,
    core: RwLock<Option<VaultService>>,
    pub(crate) services: AsyncMutex<Services>,
    prefs: Mutex<Prefs>,
    held: Mutex<Held>,
    clip_generation: AtomicU64,
    /// SHA-256 of the last text we copied, while we may still need to clear it.
    last_copy: Mutex<Option<[u8; 32]>>,
    /// Files the person chose in the native dialog (AUD-11). Cleared at every lock.
    picked: Mutex<VecDeque<PathBuf>>,
    clipboard_ttl: Duration,
    /// Held by a running restore: two restores must not run at once (AUD-10). The stranded-vault
    /// recovery holds it too, and an unlock waits for it (NEW-14).
    pub(crate) restore_gate: AsyncMutex<()>,
    clock: Arc<dyn Clock>,
    last_activity_ms: AtomicI64,
    pending: AtomicU32,
    pub(crate) listen_error: Mutex<Option<String>>,
    /// Old vault files (`<vault>.pre-restore-*`) found while the vault file itself is missing: a
    /// failed restore stranded the real vault. While it is not empty no service runs, and no new
    /// vault is made (T27-G). Newest first.
    stranded: Mutex<Vec<PathBuf>>,
    /// True when the last look for stranded files failed while the vault file was missing (a
    /// folder read error). The check fails closed: no service runs and no vault is made, as if a
    /// stranded file had been found (T27-H, NEW-11).
    stranded_check_failed: AtomicBool,
    /// Grows each time a new vault service is opened (start, restore). The event pump follows it.
    generation: watch::Sender<u64>,
    os_source: Mutex<Option<Arc<dyn OsLockEvents>>>,
    /// The remote server, in remote mode. Set at start and never changed: a mode switch restarts
    /// the app (DEC-RM-9).
    remote: Option<Arc<RemoteBackend>>,
    /// In remote mode: whether the OS sleep and screen-lock hook works (it ends the session).
    remote_os_hook_ok: AtomicBool,
    /// A bundle import that waits for the person to compare the pin and connect (DEC-RM-26). Its
    /// files are staged; nothing of a stored profile changes until `remote_activate`.
    pending_import: Mutex<Option<crate::prefs::RemoteProfile>>,
    /// The result of a first-time server setup, until the person finishes the recovery step.
    setup_hold: Mutex<Option<SetupHold>>,
    /// Test only: the next `open_service` fails, as if the file could not be opened.
    #[cfg(test)]
    pub(crate) fail_next_open: std::sync::atomic::AtomicBool,
    /// Test only: runs right before the file swap of a restore. A result it returns stands in
    /// for the swap.
    #[cfg(test)]
    pub(crate) swap_hook: Mutex<Option<SwapHook>>,
    /// Test only: the next `VaultService::open` in `open_service_with` fails after the store
    /// opened, and the store is kept in `failed_store` so a test can see that it was closed.
    #[cfg(test)]
    pub(crate) fail_next_service_open: AtomicBool,
    #[cfg(test)]
    pub(crate) failed_store: Mutex<Option<Store>>,
}

/// Test only: see `Inner::swap_hook`. Gets the vault path.
#[cfg(test)]
pub(crate) type SwapHook =
    Box<dyn FnOnce(&Path) -> Option<Result<Option<PathBuf>, cerberus_store::StoreError>> + Send>;

/// The state that Tauri manages. Cheap to clone.
#[derive(Clone)]
pub struct DesktopState {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for DesktopState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopState").finish_non_exhaustive()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Options that tests change. The app uses the defaults.
#[derive(Clone)]
pub struct StateOptions {
    /// Time before the clipboard is cleared.
    pub clipboard_ttl: Duration,
    /// The vault clock. `None` means the system clock. Tests give a manual clock for time rules
    /// such as the unlock back-off.
    pub clock: Option<Arc<dyn Clock>>,
}

impl std::fmt::Debug for StateOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateOptions")
            .field("clipboard_ttl", &self.clipboard_ttl)
            .field("clock", &self.clock.as_ref().map(|_| "custom"))
            .finish()
    }
}

impl Default for StateOptions {
    fn default() -> Self {
        Self {
            clipboard_ttl: CLIPBOARD_CLEAR_AFTER,
            clock: None,
        }
    }
}

impl DesktopState {
    /// Opens the vault file in `paths.data_dir` (made when missing) and starts the service, its
    /// background tasks and, when a vault exists, the HTTPS server. Call it inside the Tokio runtime
    /// that will keep running: the service keeps a handle to it.
    ///
    /// When the vault file is missing but an old one from a failed restore waits at
    /// `<vault>.pre-restore-*`, no vault is made and no service runs: [`Self::stranded_restore`]
    /// lists the old files and `vault_recover_stranded` puts the newest back (T27-G).
    ///
    /// # Errors
    /// `internal` when the file cannot be opened, `unavailable` when it is not a Cerberus vault.
    pub async fn open(
        paths: AppPaths,
        shell: Arc<dyn Shell>,
        options: StateOptions,
    ) -> IpcResult<Self> {
        let mut prefs = Prefs::load(&paths);
        // An import staged by an earlier run was never confirmed.
        if let Err(error) = remote::profile::discard(&paths) {
            tracing::warn!(code = %error.code, "could not remove a staged remote import");
        }
        let clock = options.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let remote = remote_backend(&paths, &mut prefs, &clock);
        let state = Self {
            inner: Arc::new(Inner {
                paths,
                shell,
                core: RwLock::new(None),
                services: AsyncMutex::new(Services::default()),
                prefs: Mutex::new(prefs),
                held: Mutex::new(Held::default()),
                clip_generation: AtomicU64::new(0),
                last_copy: Mutex::new(None),
                picked: Mutex::new(VecDeque::new()),
                clipboard_ttl: options.clipboard_ttl,
                restore_gate: AsyncMutex::new(()),
                clock,
                last_activity_ms: AtomicI64::new(0),
                pending: AtomicU32::new(0),
                listen_error: Mutex::new(None),
                stranded: Mutex::new(Vec::new()),
                stranded_check_failed: AtomicBool::new(false),
                generation: watch::channel(0).0,
                os_source: Mutex::new(None),
                remote,
                remote_os_hook_ok: AtomicBool::new(false),
                pending_import: Mutex::new(None),
                setup_hold: Mutex::new(None),
                #[cfg(test)]
                fail_next_open: AtomicBool::new(false),
                #[cfg(test)]
                swap_hook: Mutex::new(None),
                #[cfg(test)]
                fail_next_service_open: AtomicBool::new(false),
                #[cfg(test)]
                failed_store: Mutex::new(None),
            }),
        };
        // Remote mode: no store, no service, no server (ADR-0034 point 1.2).
        if let Some(remote) = &state.inner.remote {
            tracing::info!(profile = %remote.profile().id, "remote mode: no local vault is opened");
            return Ok(state);
        }
        // A vault file that is gone while an old one waits at `.pre-restore-*` is a restore that
        // failed badly. A new empty vault would look like lost data, so none is made (T27-G).
        // When the folder cannot be read, none is made either (T27-H).
        if state.note_stranded() {
            return Ok(state);
        }
        state.open_service().await?;
        Ok(state)
    }

    /// Looks for stranded old vault files and remembers them. True when the vault file is missing
    /// and at least one old file was found, or when the look failed (the folder or the vault path
    /// cannot be read): then no vault may be made or opened (fail closed, T27-H, NEW-11). The list
    /// and the failure are cleared otherwise.
    pub(crate) fn note_stranded(&self) -> bool {
        let vault = self.inner.paths.vault_file();
        let looked = match vault.symlink_metadata() {
            Ok(_) => Ok(Vec::new()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => stranded_vaults(&vault),
            Err(error) => Err(error.into()),
        };
        let failed = looked.is_err();
        let found = looked.unwrap_or_else(|error| {
            tracing::error!(
                %error,
                vault = %vault.display(),
                "could not look for old vault files of a failed restore; no vault is opened or made"
            );
            Vec::new()
        });
        if !found.is_empty() {
            tracing::error!(
                vault = %vault.display(),
                stranded = ?found,
                "the vault file is missing but an old one from a failed restore was found; no new vault is made"
            );
        }
        let stranded = !found.is_empty();
        *locked(&self.inner.stranded) = found;
        self.inner
            .stranded_check_failed
            .store(failed, Ordering::SeqCst);
        stranded || failed
    }

    /// True while no service runs on purpose: a stranded vault waits, or the look for one failed.
    fn held_back(&self) -> bool {
        !locked(&self.inner.stranded).is_empty()
            || self.inner.stranded_check_failed.load(Ordering::SeqCst)
    }

    /// The old vault files of a failed restore, newest first, while the vault file is missing.
    /// Empty in every normal run.
    #[must_use]
    pub fn stranded_restore(&self) -> Vec<PathBuf> {
        locked(&self.inner.stranded).clone()
    }

    /// Forgets the stranded files after they were put back, and a failed look for them.
    pub(crate) fn clear_stranded(&self) {
        locked(&self.inner.stranded).clear();
        self.inner
            .stranded_check_failed
            .store(false, Ordering::SeqCst);
    }

    /// Opens the store and the service, and starts the background tasks and the server. The vault
    /// file is made when it is missing (first start).
    pub(crate) async fn open_service(&self) -> IpcResult<()> {
        self.open_service_with(true).await
    }

    /// As [`Self::open_service`], but the vault file must exist: it is never made. A restore uses
    /// it, so a failure can never leave a new empty vault in place of the real one (NEW-10).
    pub(crate) async fn reopen_service(&self) -> IpcResult<()> {
        self.open_service_with(false).await
    }

    async fn open_service_with(&self, create: bool) -> IpcResult<()> {
        #[cfg(test)]
        if self.inner.fail_next_open.swap(false, Ordering::SeqCst) {
            return Err(IpcError::new("internal", "injected open failure"));
        }
        let data_dir = self.inner.paths.data_dir.clone();
        let clock = Arc::clone(&self.inner.clock);
        let store = Store::open(
            OpenOptions {
                path: self.inner.paths.vault_file(),
                create,
            },
            Arc::clone(&clock),
        )
        .await?;
        let issuer = LocalCaIssuer::new(TlsPaths::in_data_dir(&data_dir), Vec::new());
        let config = CoreConfig::desktop(data_dir, Arc::new(issuer));
        let opened = VaultService::open(store.clone(), clock, config).await;
        #[cfg(test)]
        let opened = if self
            .inner
            .fail_next_service_open
            .swap(false, Ordering::SeqCst)
        {
            *locked(&self.inner.failed_store) = Some(store.clone());
            Err(CoreError::Corrupt)
        } else {
            opened
        };
        let core = match opened {
            Ok(core) => core,
            Err(error) => {
                // Closed and waited for: the caller may move the vault files right away (a
                // recovery or a roll back), and a closing connection removes the `-wal` and
                // `-shm` by name (NEW-14).
                store.close().await;
                return Err(error.into());
            }
        };
        let tasks = core.spawn_background();
        *self
            .inner
            .core
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(core.clone());
        self.inner.services.lock().await.tasks = tasks;
        let source = locked(&self.inner.os_source).clone();
        if let Some(source) = source {
            core.attach_os_events(&*source);
        }
        self.inner
            .generation
            .send_modify(|generation| *generation += 1);
        self.start_server_if_ready(&core).await;
        Ok(())
    }

    /// The wipe for the panic hook (ADR-0026): the keys, the held values and our clipboard text.
    /// It never waits: a state that is busy is skipped.
    pub fn emergency_wipe(&self) {
        if let Some(remote) = &self.inner.remote {
            remote.wipe();
        }
        if let Ok(guard) = self.inner.core.try_read()
            && let Some(core) = guard.as_ref()
        {
            core.emergency_wipe();
        }
        if let Ok(mut held) = self.inner.held.try_lock() {
            held.drafts.clear();
            held.one_time.clear();
        }
        if let Ok(mut hold) = self.inner.setup_hold.try_lock() {
            *hold = None;
        }
        if let Ok(mut picked) = self.inner.picked.try_lock() {
            picked.clear();
        }
        self.clear_clipboard_if_ours();
    }

    /// Quit: locks the vault (reason `quit`), clears the clipboard if it holds a copied secret,
    /// and stops the server and the background tasks. In remote mode it closes the admin session
    /// (at most [`CLOSE_WAIT`]); the server vault stays as it is (DEC-RM-8).
    pub async fn shutdown(&self) {
        if let Some(remote) = &self.inner.remote {
            if tokio::time::timeout(CLOSE_WAIT, remote.close_session())
                .await
                .is_err()
            {
                tracing::info!("the remote session close at quit took too long");
            }
            self.clear_held();
            return;
        }
        if let Ok(core) = self.core()
            && let Err(error) = core.lock(LockReason::Quit).await
        {
            tracing::warn!(%error, "lock at quit failed");
        }
        self.clear_held();
        self.stop_all().await;
    }

    /// The vault service.
    ///
    /// # Errors
    /// `stranded_restore` when a failed restore left the vault only as an old file (T27-G),
    /// `unavailable` while a restore swaps the vault file, or when the look for such an old file
    /// failed at start (T27-H).
    pub fn core(&self) -> IpcResult<VaultService> {
        self.inner
            .core
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                if self.inner.remote.is_some() {
                    remote::unsupported()
                } else if !locked(&self.inner.stranded).is_empty() {
                    IpcError::new(
                        "stranded_restore",
                        "a vault left by a failed restore was found; put it back first",
                    )
                } else if self.inner.stranded_check_failed.load(Ordering::SeqCst) {
                    IpcError::unavailable(
                        "the data folder could not be read, so no vault was opened or made; restart Cerberus",
                    )
                } else {
                    IpcError::unavailable("the vault is being replaced")
                }
            })
    }

    /// The remote server, in remote mode.
    #[must_use]
    pub fn remote(&self) -> Option<&Arc<RemoteBackend>> {
        self.inner.remote.as_ref()
    }

    /// In remote mode, attaches the OS sleep and screen-lock watcher: each event ends this
    /// desktop's admin session (ADR-0034 point 7.5, DEC-RM-8). Returns false when the OS gives no
    /// such events, or in local mode.
    pub fn attach_remote_os_events(&self, source: &dyn crate::os_hooks::OsWatcher) -> bool {
        let Some(remote) = self.inner.remote.clone() else {
            return false;
        };
        let ok = source.watch(Arc::new(move |event| {
            tracing::info!(?event, "OS sleep or screen lock: the remote session ends");
            let remote = Arc::clone(&remote);
            drop(tauri::async_runtime::spawn(async move {
                remote.close_session().await;
            }));
        }));
        self.inner.remote_os_hook_ok.store(ok, Ordering::SeqCst);
        ok
    }

    /// The time of the vault clock.
    pub(crate) fn now(&self) -> jiff::Timestamp {
        self.inner.clock.now()
    }

    /// The staged bundle import, if one waits for the person.
    pub(crate) fn pending_import(&self) -> Option<crate::prefs::RemoteProfile> {
        locked(&self.inner.pending_import).clone()
    }

    /// Replaces the staged bundle import.
    pub(crate) fn set_pending_import(&self, profile: Option<crate::prefs::RemoteProfile>) {
        *locked(&self.inner.pending_import) = profile;
    }

    /// Whether the OS hook of remote mode works.
    pub(crate) fn remote_os_hook_ok(&self) -> bool {
        self.inner.remote_os_hook_ok.load(Ordering::SeqCst)
    }

    /// Test only: takes the swap hook of the next restore.
    #[cfg(test)]
    pub(crate) fn take_swap_hook(&self) -> Option<SwapHook> {
        locked(&self.inner.swap_hook).take()
    }

    /// Removes the service from the state (a restore does it before it swaps the file).
    pub(crate) fn take_core(&self) -> Option<VaultService> {
        self.inner
            .core
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// The service and a context for the unlocked session. The operator and the role come from the
    /// session, never from an argument of the UI (threat T-7). The call counts as operator activity.
    ///
    /// # Errors
    /// `vault_locked`, or `no_vault` before a vault exists.
    pub async fn operator(&self) -> IpcResult<(VaultService, OperatorContext)> {
        let (core, ctx) = self.session().await?;
        core.note_operator_activity();
        Ok((core, ctx))
    }

    /// As [`Self::operator`] but it does not count as operator activity. Background work of the
    /// shell (the pending count) uses it, so it cannot keep the vault unlocked.
    pub(crate) async fn session(&self) -> IpcResult<(VaultService, OperatorContext)> {
        let core = self.core()?;
        let status = core.status().await;
        let Some(session) = status.session else {
            return Err(match status.state {
                VaultStateKind::NoVault => CoreError::NoVault,
                _ => CoreError::Locked,
            }
            .into());
        };
        Ok((
            core,
            OperatorContext {
                operator_id: session.operator_id,
                role: session.role,
                request_id: RequestId::generate(),
            },
        ))
    }

    /// Attaches the OS sleep and screen-lock watcher, now and to every later vault service (a
    /// restore opens a new one). Returns false when the OS gives no such events.
    ///
    /// While the vault is stranded (T27-G) there is no service yet: the source is kept, and the
    /// service that the recovery opens gets it.
    ///
    /// # Errors
    /// `unavailable` while a restore swaps the vault file.
    pub fn attach_os_events(&self, source: Arc<dyn OsLockEvents>) -> IpcResult<bool> {
        let ok = match self.core() {
            Ok(core) => core.attach_os_events(&*source),
            Err(_) if self.held_back() => true,
            Err(error) => return Err(error),
        };
        *locked(&self.inner.os_source) = Some(source);
        Ok(ok)
    }

    /// A receiver that changes each time a new vault service is opened.
    #[must_use]
    pub fn generations(&self) -> watch::Receiver<u64> {
        self.inner.generation.subscribe()
    }

    /// The preferences.
    #[must_use]
    pub fn prefs(&self) -> Prefs {
        locked(&self.inner.prefs).clone()
    }

    /// Replaces and saves the preferences.
    ///
    /// # Errors
    /// `internal` when the file cannot be written.
    pub fn set_prefs(&self, prefs: Prefs) -> IpcResult<()> {
        prefs
            .save(&self.inner.paths)
            .map_err(|e| IpcError::internal(&e))?;
        *locked(&self.inner.prefs) = prefs;
        Ok(())
    }

    /// Counts a sign of life of the UI, at most once a second. In remote mode it is the session
    /// keep-alive, sent at most every 30 s.
    pub fn ui_activity(&self) -> IpcResult<()> {
        if let Some(remote) = &self.inner.remote {
            remote.keepalive();
            return Ok(());
        }
        let core = self.core()?;
        let now = core.clock().now().as_millisecond();
        let last = self.inner.last_activity_ms.load(Ordering::SeqCst);
        if now.saturating_sub(last) >= ACTIVITY_MIN_GAP_MS
            && self
                .inner
                .last_activity_ms
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            cerberus_admin::handlers::ui_activity(&core);
        }
        Ok(())
    }

    /// Number of requests that wait for a person, as the event pump last counted.
    #[must_use]
    pub fn pending_count(&self) -> u32 {
        self.inner.pending.load(Ordering::SeqCst)
    }

    pub(crate) fn set_pending_count(&self, count: u32) {
        self.inner.pending.store(count, Ordering::SeqCst);
    }

    // ---- values that stay in the backend -------------------------------------------------------

    /// The tag of the current unlock, or `None` when the vault is locked.
    async fn held_tag(&self) -> Option<HeldTag> {
        let session = self.core().ok()?.status().await.session?;
        Some(HeldTag {
            operator: session.operator_id,
            unlocked_at_ms: session.unlocked_at.as_millisecond(),
        })
    }

    /// The tag now, or `not_found` after dropping every held value that belongs to another unlock
    /// (DEC-FIX8-6). A lagged event pump cannot leave a stale value usable.
    async fn live_tag(&self) -> IpcResult<HeldTag> {
        let Some(tag) = self.held_tag().await else {
            self.clear_held();
            return Err(IpcError::new("not_found", "not found"));
        };
        let mut held = locked(&self.inner.held);
        held.drafts.retain(|(_, owner, _)| *owner == tag);
        held.one_time.retain(|_, (owner, _)| *owner == tag);
        Ok(tag)
    }

    /// Keeps an SSH payload in the backend and returns its draft ID.
    ///
    /// # Errors
    /// `locked` when no one is unlocked.
    pub async fn put_draft(&self, payload: Payload) -> IpcResult<String> {
        let tag = self.held_tag().await.ok_or(CoreError::Locked)?;
        let id = RequestId::generate().to_string();
        let mut held = locked(&self.inner.held);
        held.drafts.push_back((id.clone(), tag, payload));
        while held.drafts.len() > MAX_DRAFTS {
            held.drafts.pop_front();
        }
        Ok(id)
    }

    /// A copy of a draft payload. The draft stays until [`Self::discard_draft`], so a failed
    /// `item_create` does not lose the key.
    ///
    /// # Errors
    /// `not_found` when the draft does not exist (never made, used, dropped at lock, or made in
    /// another unlock).
    pub async fn draft(&self, id: &str) -> IpcResult<Payload> {
        let tag = self.live_tag().await?;
        locked(&self.inner.held)
            .drafts
            .iter()
            .find(|(draft, owner, _)| draft == id && *owner == tag)
            .map(|(_, _, payload)| payload.clone())
            .ok_or_else(|| IpcError::new("not_found", "not found"))
    }

    /// Drops a draft after it was saved.
    pub fn discard_draft(&self, id: &str) {
        locked(&self.inner.held)
            .drafts
            .retain(|(draft, _, _)| draft != id);
    }

    /// Keeps the last one-time value of a kind (a recovery key or a token) for the clipboard.
    /// With no unlocked session the value is not kept.
    pub async fn set_one_time(&self, kind: OneTimeKind, text: &str) {
        let Some(tag) = self.held_tag().await else {
            return;
        };
        locked(&self.inner.held)
            .one_time
            .insert(one_time_key(kind), (tag, Zeroizing::new(text.to_owned())));
    }

    /// Keeps the result of a first-time server setup (see [`SetupHold`]).
    pub(crate) fn set_setup_hold(&self, hold: Option<SetupHold>) {
        *locked(&self.inner.setup_hold) = hold;
    }

    /// A copy of the held admin bundle (JSON) of the last setup, if it is still held.
    pub(crate) fn setup_bundle(&self) -> Option<Zeroizing<Vec<u8>>> {
        locked(&self.inner.setup_hold)
            .as_ref()
            .map(|hold| hold.bundle.clone())
    }

    /// A copy of the held recovery key of the last setup, if it is still held.
    pub(crate) fn setup_recovery_key(&self) -> Option<Zeroizing<String>> {
        locked(&self.inner.setup_hold)
            .as_ref()
            .map(|hold| hold.recovery_key.clone())
    }

    /// A copy of the last one-time value of a kind, if it belongs to the current unlock.
    pub async fn one_time(&self, kind: OneTimeKind) -> Option<Zeroizing<String>> {
        let tag = self.live_tag().await.ok()?;
        locked(&self.inner.held)
            .one_time
            .get(one_time_key(kind))
            .filter(|(owner, _)| *owner == tag)
            .map(|(_, text)| text.clone())
    }

    /// Drops every draft and one-time value, forgets the picked files, and clears the clipboard
    /// when it still holds what we copied (AUD-14). Every lock path calls it, and the pump on lag.
    pub fn clear_held(&self) {
        {
            let mut held = locked(&self.inner.held);
            held.drafts.clear();
            held.one_time.clear();
        }
        locked(&self.inner.picked).clear();
        self.clear_clipboard_if_ours();
    }

    // ---- files chosen by the person ----------------------------------------------------------

    /// Asks the native dialog for one file and remembers the answer, so the backend may read it
    /// (AUD-11). The path text of the webview is never trusted by itself.
    pub async fn pick_file(
        &self,
        title: Option<String>,
        extensions: Vec<String>,
    ) -> Option<String> {
        let shell = Arc::clone(&self.inner.shell);
        let picked =
            tokio::task::spawn_blocking(move || shell.pick_file(title.as_deref(), &extensions))
                .await
                .ok()
                .flatten()?;
        let text = picked.to_str()?.to_owned();
        let resolved = picked.canonicalize().unwrap_or(picked);
        let mut list = locked(&self.inner.picked);
        list.retain(|known| *known != resolved);
        list.push_back(resolved);
        while list.len() > MAX_PICKED {
            list.pop_front();
        }
        Some(text)
    }

    /// Remembers files that the OS reported as dropped on the main window (AUD-11).
    pub fn note_dropped(&self, paths: &[PathBuf]) {
        let mut list = locked(&self.inner.picked);
        for path in paths {
            let resolved = path.canonicalize().unwrap_or_else(|_| path.clone());
            list.retain(|known| *known != resolved);
            list.push_back(resolved);
        }
        while list.len() > MAX_PICKED {
            list.pop_front();
        }
    }

    /// True when `path` is a file that the native dialog returned in this unlock.
    pub(crate) fn is_picked(&self, path: &Path) -> bool {
        let Ok(resolved) = path.canonicalize() else {
            return false;
        };
        locked(&self.inner.picked).contains(&resolved)
    }

    // ---- clipboard -----------------------------------------------------------------------------

    /// Copies `text` and clears the clipboard after 30 seconds, but only when it still holds
    /// this text (the person may have copied something else since).
    ///
    /// # Errors
    /// `unavailable` when the clipboard cannot be written.
    pub fn copy_and_clear(&self, text: &str) -> IpcResult<()> {
        self.inner.shell.clipboard_write(text)?;
        let digest = sha256(&[text.as_bytes()]);
        *locked(&self.inner.last_copy) = Some(digest);
        let generation = self.inner.clip_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let inner = Arc::clone(&self.inner);
        drop(tauri::async_runtime::spawn(async move {
            tokio::time::sleep(inner.clipboard_ttl).await;
            if inner.clip_generation.load(Ordering::SeqCst) != generation {
                return;
            }
            let same = inner
                .shell
                .clipboard_read()
                .is_some_and(|now| sha256(&[now.as_bytes()]) == digest);
            if same {
                inner.shell.clipboard_clear();
            }
            let mut last = locked(&inner.last_copy);
            if *last == Some(digest) {
                *last = None;
            }
        }));
        Ok(())
    }

    /// Clears the clipboard when it still holds the last text we copied (AUD-14). Lock, panic,
    /// quit and the panic hook call it. A text the person copied since is left alone. It never
    /// waits for a lock that is busy.
    fn clear_clipboard_if_ours(&self) {
        let digest = match self.inner.last_copy.try_lock() {
            Ok(mut last) => last.take(),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner().take(),
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        let Some(digest) = digest else {
            return;
        };
        // The timer of this copy has nothing left to do.
        self.inner.clip_generation.fetch_add(1, Ordering::SeqCst);
        if self
            .inner
            .shell
            .clipboard_read()
            .is_some_and(|now| sha256(&[now.as_bytes()]) == digest)
        {
            self.inner.shell.clipboard_clear();
        }
    }
}

/// The backend of the active remote profile. A profile that cannot be used (gone from the
/// preferences, files missing) is logged and the app starts in local mode with `remote.active`
/// cleared: local mode is the safe default (ADR-0034 point 1.1).
fn remote_backend(
    paths: &AppPaths,
    prefs: &mut Prefs,
    clock: &Arc<dyn Clock>,
) -> Option<Arc<RemoteBackend>> {
    let id = prefs.remote.active.clone()?;
    let built = prefs
        .remote
        .profile(&id)
        .cloned()
        .ok_or_else(|| IpcError::unavailable("the active remote profile is not stored"))
        .and_then(|profile| {
            let http = remote::profile::transport(paths, &profile)?;
            Ok((profile, http))
        });
    match built {
        Ok((profile, http)) => Some(Arc::new(RemoteBackend::new(
            profile,
            http,
            Arc::clone(clock),
        ))),
        Err(error) => {
            tracing::error!(
                profile = %id,
                code = %error.code,
                reason = %error.message,
                "the remote profile cannot be used; starting in local mode"
            );
            prefs.remote.active = None;
            if let Err(error) = prefs.save(paths) {
                tracing::warn!(%error, "could not save the switch back to local mode");
            }
            None
        }
    }
}

const fn one_time_key(kind: OneTimeKind) -> &'static str {
    match kind {
        OneTimeKind::RecoveryKey => "recovery_key",
        OneTimeKind::AgentToken => "agent_token",
    }
}
