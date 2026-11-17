//! The bridge: one signing socket per lease, opened by `ssh-prepare` and closed when the lease
//! ends, is released or revoked, when the vault locks, and when the bridge is dropped.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, Weak};
#[cfg(unix)]
use std::time::Duration;

use cerberus_core::agent_api::PendingResult;
use cerberus_core::agent_api::ssh::{SshPrepareInput, SshPrepareOutcome, SshTicket};
use cerberus_core::items::SshMeta;
use cerberus_core::leases::LeaseView;
use cerberus_core::{AgentApi, AgentContext, CoreError, VaultService};
use cerberus_types::{ItemId, LeaseId, RequestId};
use jiff::Timestamp;

/// Signing sockets one bridge keeps open at a time.
pub const MAX_SOCKETS: usize = 32;
/// Signing sockets one agent may have open at a time.
pub const MAX_SOCKETS_PER_AGENT: usize = 8;
/// Longest socket path, in bytes. `sun_path` holds 108 bytes on Linux and 104 on macOS,
/// with the final zero byte.
pub const MAX_SOCKET_PATH_BYTES: usize = 100;
/// How often the bridge closes sockets past their end and checks their leases again.
#[cfg(unix)]
const TICK: Duration = Duration::from_secs(1);
/// Every this many ticks, every lease is checked again (a missed event cannot keep a socket).
#[cfg(unix)]
const FULL_CHECK_TICKS: u32 = 5;

/// Why `prepare` failed.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The Agent API refused the call (scope, policy, lease, lock, validation).
    #[error(transparent)]
    Core(#[from] CoreError),
    /// Too many sockets are open (for the bridge or for this agent).
    #[error("too many ssh-agent sockets are open")]
    Full,
    /// This platform has no Unix sockets.
    #[error("the ssh-agent bridge needs Unix sockets")]
    Unsupported,
    /// The socket path does not fit in a Unix socket address.
    #[error("the ssh-agent socket path is too long")]
    PathTooLong,
    /// The socket or its directory could not be made.
    #[error("ssh-agent socket error: {0}")]
    Io(#[from] std::io::Error),
}

/// Where the bridge puts its sockets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeConfig {
    /// Base directory; each bridge makes its own 0700 directory in it.
    pub runtime_dir: PathBuf,
}

impl BridgeConfig {
    /// `$XDG_RUNTIME_DIR/cerberus-ssh` when that variable names an absolute directory, else
    /// `<data dir>/run/cerberus-ssh` of the vault service.
    #[must_use]
    pub fn for_service(core: &VaultService) -> Self {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_dir());
        let base = runtime.unwrap_or_else(|| core.config().data_dir.join("run"));
        Self {
            runtime_dir: base.join("cerberus-ssh"),
        }
    }
}

/// A ready signing socket. Nothing here is secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshReady {
    /// The request ID of the call.
    pub request_id: RequestId,
    /// Set `SSH_AUTH_SOCK` to this path.
    pub socket_path: PathBuf,
    /// The SSH key item.
    pub item_id: ItemId,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// Host, port and user from the item metadata.
    pub ssh: SshMeta,
    /// End of the socket.
    pub expires_at: Timestamp,
    /// The lease that covers the socket.
    pub lease: LeaseView,
}

/// The answer of [`SshBridge::prepare`].
#[derive(Debug)]
pub enum PrepareOutcome {
    /// The socket is ready.
    Ready(Box<SshReady>),
    /// A person must approve first.
    Pending(PendingResult),
}

/// The ssh-agent bridge of one vault service. Cheap to clone; the last clone to drop closes
/// every socket and removes its directory.
#[derive(Clone)]
pub struct SshBridge {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SshBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshBridge")
            .field("runtime_dir", &self.inner.config.runtime_dir)
            .finish_non_exhaustive()
    }
}

struct Inner {
    api: AgentApi,
    config: BridgeConfig,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    #[cfg(unix)]
    dir: Option<crate::dirs::BridgeDir>,
    #[cfg(unix)]
    sockets: HashMap<LeaseId, crate::socket::Socket>,
    #[cfg(unix)]
    watcher: Option<Watcher>,
    #[cfg(not(unix))]
    sockets: HashMap<LeaseId, ()>,
}

#[cfg(unix)]
struct Watcher {
    task: tokio::task::JoinHandle<()>,
    check: tokio::sync::mpsc::UnboundedSender<LeaseId>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        #[cfg(unix)]
        if let Some(watcher) = state.watcher.take() {
            watcher.task.abort();
        }
        // Sockets first (each removes its file), then the directory.
        state.sockets.clear();
        #[cfg(unix)]
        {
            state.dir = None;
        }
    }
}

/// The shared bridges, one per vault service (see [`SshBridge::shared`]). Weak: the holders of
/// a bridge (the API state) decide how long it lives.
static SHARED: Mutex<Vec<Weak<Inner>>> = Mutex::new(Vec::new());

impl SshBridge {
    /// A bridge for `core`. Opens nothing until the first `prepare`. It is not shared: use
    /// [`Self::shared`] for the bridge that REST and MCP use.
    #[must_use]
    pub fn new(core: VaultService, config: BridgeConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                api: core.agent_api(),
                config,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// The one shared bridge of `core` (made with [`BridgeConfig::for_service`] when no live one
    /// exists). One bridge per service keeps the rule "one socket per lease" for REST and MCP.
    /// Keep a clone (the API state does): a bridge with no holder closes its sockets.
    #[must_use]
    pub fn shared(core: &VaultService) -> Self {
        let mut list = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
        list.retain(|weak| weak.strong_count() > 0);
        // Clones of one service share one `CoreConfig`, so its address names the service.
        let found = list
            .iter()
            .filter_map(Weak::upgrade)
            .find(|inner| std::ptr::eq(inner.api.service().config(), core.config()));
        if let Some(inner) = found {
            return Self { inner };
        }
        let bridge = Self::new(core.clone(), BridgeConfig::for_service(core));
        list.push(Arc::downgrade(&bridge.inner));
        bridge
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of open sockets.
    #[must_use]
    pub fn socket_count(&self) -> usize {
        self.state().sockets.len()
    }

    /// The socket path of a lease, while its socket is open.
    #[must_use]
    pub fn socket_path(&self, lease: LeaseId) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            self.state()
                .sockets
                .get(&lease)
                .map(|socket| socket.path().to_path_buf())
        }
        #[cfg(not(unix))]
        {
            let _ = lease;
            None
        }
    }

    /// Closes every socket (graceful shutdown of the host).
    pub fn close_all(&self) {
        let closed = std::mem::take(&mut self.state().sockets);
        drop(closed);
    }

    /// `POST /v1/credentials/{id}/ssh-prepare`, MCP `ssh_prepare`: runs
    /// [`AgentApi::ssh_prepare`], then opens (or reuses) the socket of the lease.
    ///
    /// # Errors
    /// [`BridgeError::Core`] for every refusal of the Agent API, [`BridgeError::Full`],
    /// [`BridgeError::PathTooLong`], [`BridgeError::Io`], or [`BridgeError::Unsupported`]
    /// on a platform without Unix sockets.
    pub async fn prepare(
        &self,
        ctx: &AgentContext,
        item: ItemId,
        input: SshPrepareInput,
    ) -> Result<PrepareOutcome, BridgeError> {
        if cfg!(not(unix)) {
            return Err(BridgeError::Unsupported);
        }
        // Check room before the lease use is spent. `install` checks again under the lock.
        self.room_for(ctx, input.lease_id)?;
        match self.inner.api.ssh_prepare(ctx, item, input).await? {
            SshPrepareOutcome::Pending(pending) => Ok(PrepareOutcome::Pending(pending)),
            SshPrepareOutcome::Ready(grant) => {
                let grant = *grant;
                let socket_path = self.install(grant.ticket)?;
                Ok(PrepareOutcome::Ready(Box::new(SshReady {
                    request_id: grant.request_id,
                    socket_path,
                    item_id: grant.item.id,
                    public_key: grant.public_key,
                    fingerprint: grant.fingerprint,
                    ssh: grant.ssh,
                    expires_at: grant.expires_at,
                    lease: grant.lease,
                })))
            }
        }
    }

    fn room_for(&self, ctx: &AgentContext, lease: Option<LeaseId>) -> Result<(), BridgeError> {
        let state = self.state();
        if lease.is_some_and(|id| state.sockets.contains_key(&id)) {
            return Ok(());
        }
        Self::room_in(&state, ctx.agent_id)
    }

    #[cfg(unix)]
    fn room_in(state: &State, agent: cerberus_types::AgentId) -> Result<(), BridgeError> {
        let of_agent = state
            .sockets
            .values()
            .filter(|socket| socket.ticket().agent_id() == agent)
            .count();
        if state.sockets.len() >= MAX_SOCKETS || of_agent >= MAX_SOCKETS_PER_AGENT {
            return Err(BridgeError::Full);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn room_in(_state: &State, _agent: cerberus_types::AgentId) -> Result<(), BridgeError> {
        Err(BridgeError::Unsupported)
    }

    /// Opens the socket of the ticket lease, or gives the ticket to the socket that is open.
    #[cfg(unix)]
    fn install(&self, ticket: SshTicket) -> Result<PathBuf, BridgeError> {
        let lease = ticket.lease_id();
        let mut state = self.state();
        if let Some(socket) = state.sockets.get(&lease) {
            socket.replace_ticket(ticket);
            return Ok(socket.path().to_path_buf());
        }
        Self::room_in(&state, ticket.agent_id())?;
        if state.dir.is_none() {
            state.dir = Some(crate::dirs::BridgeDir::create(
                &self.inner.config.runtime_dir,
            )?);
        }
        let Some(dir) = state.dir.as_ref() else {
            return Err(BridgeError::Io(std::io::Error::other(
                "no socket directory",
            )));
        };
        let path = dir
            .path()
            .join(format!("{}.sock", lease.as_uuid().simple()));
        if path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(BridgeError::PathTooLong);
        }
        let check = self.watcher_in(&mut state);
        let socket =
            crate::socket::Socket::open(path.clone(), self.inner.api.clone(), ticket, check)?;
        state.sockets.insert(lease, socket);
        Ok(path)
    }

    #[cfg(not(unix))]
    fn install(&self, _ticket: SshTicket) -> Result<PathBuf, BridgeError> {
        Err(BridgeError::Unsupported)
    }

    /// The check channel of the watcher task; starts the task when it does not run.
    #[cfg(unix)]
    fn watcher_in(&self, state: &mut State) -> tokio::sync::mpsc::UnboundedSender<LeaseId> {
        if let Some(watcher) = state.watcher.as_ref().filter(|w| !w.task.is_finished()) {
            return watcher.check.clone();
        }
        let (check, rx) = tokio::sync::mpsc::unbounded_channel();
        let events = self.inner.api.service().subscribe();
        let task = tokio::spawn(watch(Arc::downgrade(&self.inner), events, rx));
        state.watcher = Some(Watcher {
            task,
            check: check.clone(),
        });
        check
    }
}

/// The sockets to check: every one, or the one of `lease`.
#[cfg(unix)]
fn tickets(inner: &Inner, lease: Option<LeaseId>) -> Vec<SshTicket> {
    let state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
    state
        .sockets
        .iter()
        .filter(|(id, _)| lease.is_none_or(|wanted| **id == wanted))
        .map(|(_, socket)| socket.ticket())
        .collect()
}

/// Closes the sockets whose ticket is no longer open.
#[cfg(unix)]
async fn recheck(inner: &Inner, lease: Option<LeaseId>) {
    let mut ended = Vec::new();
    for ticket in tickets(inner, lease) {
        if !inner.api.ssh_ticket_open(&ticket).await {
            ended.push(ticket.lease_id());
        }
    }
    close(inner, &ended);
}

#[cfg(unix)]
fn close(inner: &Inner, leases: &[LeaseId]) {
    if leases.is_empty() {
        return;
    }
    let removed: Vec<_> = {
        let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
        leases
            .iter()
            .filter_map(|id| state.sockets.remove(id))
            .collect()
    };
    tracing::info!(count = removed.len(), "ssh-agent sockets closed");
    drop(removed);
}

#[cfg(unix)]
fn close_every(inner: &Inner) {
    let all: Vec<LeaseId> = {
        let state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.sockets.keys().copied().collect()
    };
    close(inner, &all);
}

/// Closes sockets on core events (lock, lease changes), on the ticket end, and when a sign was
/// refused. Holds the bridge weakly: it ends when the bridge is gone.
#[cfg(unix)]
async fn watch(
    inner: Weak<Inner>,
    mut events: tokio::sync::broadcast::Receiver<cerberus_core::CoreEvent>,
    mut checks: tokio::sync::mpsc::UnboundedReceiver<LeaseId>,
) {
    use cerberus_core::CoreEvent;
    use cerberus_types::VaultStateKind;
    use tokio::sync::broadcast::error::RecvError;

    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ticks: u32 = 0;
    loop {
        enum Step {
            Event(Result<CoreEvent, RecvError>),
            Check(Option<LeaseId>),
            Tick,
        }
        let step = tokio::select! {
            event = events.recv() => Step::Event(event),
            lease = checks.recv() => Step::Check(lease),
            _ = tick.tick() => Step::Tick,
        };
        let Some(inner) = inner.upgrade() else {
            return;
        };
        match step {
            Step::Event(Ok(CoreEvent::StateChanged(kind))) if kind != VaultStateKind::Unlocked => {
                close_every(&inner);
            }
            Step::Event(Ok(CoreEvent::LeaseChanged(id))) => recheck(&inner, Some(id)).await,
            Step::Event(Ok(_)) => {}
            Step::Event(Err(RecvError::Lagged(_))) => recheck(&inner, None).await,
            Step::Event(Err(RecvError::Closed)) | Step::Check(None) => {
                close_every(&inner);
                return;
            }
            Step::Check(Some(id)) => recheck(&inner, Some(id)).await,
            Step::Tick => {
                ticks = ticks.wrapping_add(1);
                let now = inner.api.service().clock().now();
                if ticks.is_multiple_of(FULL_CHECK_TICKS) {
                    recheck(&inner, None).await;
                } else {
                    let ended: Vec<LeaseId> = tickets(&inner, None)
                        .iter()
                        .filter(|ticket| now >= ticket.expires_at())
                        .map(SshTicket::lease_id)
                        .collect();
                    close(&inner, &ended);
                }
            }
        }
    }
}
