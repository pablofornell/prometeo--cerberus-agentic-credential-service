//! The admin API of `cerberusd` under `/admin/v1` (ADR-0034, DEC-RM-2 to DEC-RM-6, threat model
//! TB-10). It exists only when the host puts an [`AdminConfig`] in
//! [`crate::ApiConfig::admin`]; without one no `/admin` route is mounted and every `/admin` path
//! is `404 route_not_found` (invariant 8). The desktop app never mounts it.
//!
//! Two factors on every call (invariant 9):
//! 1. **Device**: the TLS client certificate verified against the vault CA, and its SHA-256 a live
//!    entry of the admin client registry, checked on every request (`403 admin_cert_required`).
//! 2. **Person**: an admin session opened with the bound operator's passphrase (`cas_` token,
//!    `401 admin_session_required`). Only `hello`, `vault_status` and `vault_list_operators` need
//!    the device alone.
//!
//! Agent tokens (`cvt_`) are never sessions, and `cas_` tokens never pass the agent token check
//! of `/v1` and `/mcp`. Closing a session never locks the vault; a lock, a new unlock or a revoke
//! ends every session it touches (invariant 10).

mod errors;
mod layers;
mod routes;
mod session;

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Duration;

use cerberus_admin::clients::{AdminClient, AdminClients, ClientsError, EnrolmentId};
use cerberus_core::{AdminAudit, AdminEventKind, CoreEvent, VaultService};
use cerberus_types::VaultStateKind;
use jiff::Timestamp;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use crate::config::AppState;

pub use errors::status_of;
pub(crate) use routes::router;
pub use session::SessionId;
use session::{Closed, NewSession, Refusal, Session, SessionTable};

/// How often the sweeper ends sessions that are past a limit, when no vault state change wakes it.
const SWEEP_EVERY: Duration = Duration::from_secs(15);

/// The limits of the admin API (ADR-0034 points 3.3, 6.2, 6.4, 6.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminLimits {
    /// A session ends after this many seconds without a call that counts as activity: 900.
    pub session_idle_seconds: u32,
    /// A session ends this many seconds after it opened: 43 200 (12 h).
    pub session_max_seconds: u32,
    /// Live sessions of the daemon: 4.
    pub max_sessions: usize,
    /// Live sessions of one enrolment: 2.
    pub max_sessions_per_enrolment: usize,
    /// Event streams of one session: 2.
    pub max_streams_per_session: usize,
    /// Failed session opens of one enrolment within `failure_window_seconds` before it is
    /// refused: 5.
    pub failures_allowed: u32,
    /// The window of `failures_allowed`: 900 s.
    pub failure_window_seconds: u32,
    /// How long an enrolment is refused after `failures_allowed` failures, before any KDF: 900 s.
    pub failure_block_seconds: u32,
}

impl Default for AdminLimits {
    fn default() -> Self {
        Self {
            session_idle_seconds: 900,
            session_max_seconds: 43_200,
            max_sessions: 4,
            max_sessions_per_enrolment: 2,
            max_streams_per_session: 2,
            failures_allowed: 5,
            failure_window_seconds: 900,
            failure_block_seconds: 900,
        }
    }
}

/// The failed session opens of each enrolment (ADR-0034 point 6.3). Only enrolled devices reach
/// it, so it holds at most one entry per registry entry.
#[derive(Debug, Default)]
struct Failures {
    by_enrolment: std::collections::HashMap<EnrolmentId, FailureEntry>,
    /// Enrolments with a session open running now. One at a time per enrolment, so parallel
    /// tries cannot all pass the check before the first failure is counted.
    in_flight: std::collections::HashSet<EnrolmentId>,
}

/// Why a session open is refused before its body is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptRefusal {
    /// The enrolment had too many failures: wait this many seconds.
    Blocked(u32),
    /// Another session open of the enrolment runs now.
    Busy,
}

/// A session open that runs. Dropping it lets the next one of the enrolment start.
pub(crate) struct Attempt<'a> {
    admin: &'a AdminState,
    enrolment: EnrolmentId,
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        self.admin.failures().in_flight.remove(&self.enrolment);
    }
}

#[derive(Debug, Default)]
struct FailureEntry {
    /// Times (ms) of the failures in the window.
    recent: Vec<i64>,
    /// Refused until this time (ms).
    blocked_until: Option<i64>,
}

impl Failures {
    /// `Err(seconds)` while the enrolment is refused.
    fn check(&self, enrolment: EnrolmentId, now_ms: i64) -> Result<(), u32> {
        match self
            .by_enrolment
            .get(&enrolment)
            .and_then(|e| e.blocked_until)
        {
            Some(until) if until > now_ms => {
                let seconds = (until - now_ms).saturating_add(999) / 1000;
                Err(u32::try_from(seconds).unwrap_or(u32::MAX))
            }
            _ => Ok(()),
        }
    }

    fn failed(&mut self, enrolment: EnrolmentId, now_ms: i64, limits: &AdminLimits) {
        let window = i64::from(limits.failure_window_seconds).saturating_mul(1000);
        let entry = self.by_enrolment.entry(enrolment).or_default();
        if entry.blocked_until.is_some_and(|until| until <= now_ms) {
            entry.blocked_until = None;
        }
        entry
            .recent
            .retain(|at| now_ms.saturating_sub(*at) < window);
        entry.recent.push(now_ms);
        if entry.recent.len() >= usize::try_from(limits.failures_allowed.max(1)).unwrap_or(1) {
            let block = i64::from(limits.failure_block_seconds).saturating_mul(1000);
            entry.blocked_until = Some(now_ms.saturating_add(block));
            entry.recent.clear();
        }
    }

    fn succeeded(&mut self, enrolment: EnrolmentId) {
        self.by_enrolment.remove(&enrolment);
    }
}

/// The admin state of one daemon: the client registry, the sessions and the failure limit. The
/// host makes it once and shares the `Arc` between the server ([`AdminConfig`]) and its own
/// enrolment and revoke handling (the unlock socket of `cerberusd`).
pub struct AdminState {
    clients: RwLock<AdminClients>,
    registry: Option<PathBuf>,
    sessions: Mutex<SessionTable>,
    failures: Mutex<Failures>,
    limits: AdminLimits,
    /// Grows whenever sessions end, so event streams stop at once.
    changed: watch::Sender<u64>,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("registry", &self.registry)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// The admin API part of [`crate::ApiConfig`]. `None` there means no admin route.
#[derive(Clone, Debug)]
pub struct AdminConfig {
    /// The shared admin state.
    pub state: std::sync::Arc<AdminState>,
}

/// The lock epoch while the vault is unlocked, else `None`.
fn live_epoch(core: &VaultService) -> Option<u64> {
    (core.state() == VaultStateKind::Unlocked).then(|| core.lock_epoch())
}

impl AdminState {
    /// The state for a registry and limits. The registry is not saved anywhere; see
    /// [`Self::with_registry_file`].
    #[must_use]
    pub fn new(clients: AdminClients, limits: AdminLimits) -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            clients: RwLock::new(clients),
            registry: None,
            sessions: Mutex::new(SessionTable::default()),
            failures: Mutex::new(Failures::default()),
            limits,
            changed,
        }
    }

    /// Saves every registry change to `path` (`<data_dir>/admin-clients.json`), and
    /// [`Self::reload_clients`] reads it.
    #[must_use]
    pub fn with_registry_file(mut self, path: PathBuf) -> Self {
        self.registry = Some(path);
        self
    }

    /// The limits.
    #[must_use]
    pub fn limits(&self) -> &AdminLimits {
        &self.limits
    }

    fn clients_read(&self) -> std::sync::RwLockReadGuard<'_, AdminClients> {
        self.clients.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn clients_write(&self) -> std::sync::RwLockWriteGuard<'_, AdminClients> {
        self.clients.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn sessions(&self) -> MutexGuard<'_, SessionTable> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn failures(&self) -> MutexGuard<'_, Failures> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A copy of the registry.
    #[must_use]
    pub fn clients(&self) -> AdminClients {
        self.clients_read().clone()
    }

    /// The live enrolment of a client certificate hash, if any.
    #[must_use]
    pub fn find_live(&self, cert_sha256: &[u8; 32], now: Timestamp) -> Option<AdminClient> {
        self.clients_read().find_live(cert_sha256, now).cloned()
    }

    /// Adds an enrolment and saves the registry (when it has a file). Nothing changes when the
    /// save fails.
    ///
    /// # Errors
    /// [`ClientsError::Duplicate`], or the save error.
    pub fn enroll(&self, client: AdminClient) -> Result<(), ClientsError> {
        let mut clients = self.clients_write();
        let mut next = clients.clone();
        next.add(client)?;
        if let Some(path) = &self.registry {
            next.save(path)?;
        }
        *clients = next;
        Ok(())
    }

    /// Revokes an enrolment: it can no longer pass the device check, its sessions end (their
    /// connections close within about 1 s), and `admin.session_close` (`revoked`) and
    /// `admin.client_revoke` are audited. Returns false when there is no such enrolment or it
    /// was revoked already.
    ///
    /// # Errors
    /// The save error of the registry file. The revoke is in effect in memory anyway, until the
    /// daemon restarts.
    pub async fn revoke(&self, core: &VaultService, id: EnrolmentId) -> Result<bool, ClientsError> {
        let now = core.clock().now();
        let (entry, saved) = {
            let mut clients = self.clients_write();
            if !clients.revoke(id, now) {
                return Ok(false);
            }
            let saved = match &self.registry {
                Some(path) => clients.save(path),
                None => Ok(()),
            };
            (clients.get(id).cloned(), saved)
        };
        let closed = self.sessions().drop_enrolment(id);
        self.bump();
        audit_closed(core, closed).await;
        let mut event = AdminAudit::new(AdminEventKind::ClientRevoke);
        event.enrolment = Some(id.to_string());
        if let Some(entry) = entry {
            event.label = Some(entry.label);
            event.operator = Some(entry.operator_id);
        }
        if let Err(error) = core.record_admin_event(None, event).await {
            tracing::warn!(%error, "admin.client_revoke was not audited");
        }
        saved.map(|()| true)
    }

    /// Reads the registry file again (an offline `cerberusd admin revoke` edited it). Sessions of
    /// enrolments that are no longer live end (`revoked`). Without a file this does nothing.
    ///
    /// # Errors
    /// The load error. The registry in memory stays as it was.
    pub async fn reload_clients(&self, core: &VaultService) -> Result<(), ClientsError> {
        let Some(path) = &self.registry else {
            return Ok(());
        };
        let fresh = AdminClients::load(path)?;
        let now = core.clock().now();
        let gone: Vec<EnrolmentId> = {
            let mut clients = self.clients_write();
            *clients = fresh;
            clients
                .list()
                .iter()
                .filter(|c| !c.is_live(now))
                .map(|c| c.id)
                .collect()
        };
        let closed: Vec<Closed> = {
            let mut sessions = self.sessions();
            gone.into_iter()
                .flat_map(|id| sessions.drop_enrolment(id))
                .collect()
        };
        if !closed.is_empty() {
            self.bump();
        }
        audit_closed(core, closed).await;
        Ok(())
    }

    /// Number of sessions in the table (an ended one may count until the next sweep).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions().len()
    }

    /// True when the session exists, has not ended (idle, absolute limit, lock) and its
    /// enrolment is still live (not revoked, certificate not expired).
    #[must_use]
    pub fn session_live(&self, core: &VaultService, id: SessionId) -> bool {
        let now = core.clock().now();
        let enrolment = {
            let sessions = self.sessions();
            if !sessions.is_live(id, now, live_epoch(core), &self.limits) {
                return false;
            }
            sessions.enrolment_of(id)
        };
        enrolment.is_some_and(|e| self.clients_read().get(e).is_some_and(|c| c.is_live(now)))
    }

    /// Ends every session that is past a limit or older than the last lock, and audits them.
    pub async fn sweep(&self, core: &VaultService) {
        let closed = self
            .sessions()
            .sweep(core.clock().now(), live_epoch(core), &self.limits);
        if !closed.is_empty() {
            self.bump();
        }
        audit_closed(core, closed).await;
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    pub(crate) fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Starts a session open of `enrolment`: refused while the enrolment is blocked or another
    /// open of it runs.
    pub(crate) fn begin_attempt(
        &self,
        enrolment: EnrolmentId,
        now: Timestamp,
    ) -> Result<Attempt<'_>, AttemptRefusal> {
        let mut failures = self.failures();
        failures
            .check(enrolment, now.as_millisecond())
            .map_err(AttemptRefusal::Blocked)?;
        if !failures.in_flight.insert(enrolment) {
            return Err(AttemptRefusal::Busy);
        }
        Ok(Attempt {
            admin: self,
            enrolment,
        })
    }

    pub(crate) fn failure_record(&self, enrolment: EnrolmentId, now: Timestamp) {
        self.failures()
            .failed(enrolment, now.as_millisecond(), &self.limits);
    }

    pub(crate) fn failure_clear(&self, enrolment: EnrolmentId) {
        self.failures().succeeded(enrolment);
    }

    pub(crate) fn open_session(
        &self,
        new: NewSession,
        now: Timestamp,
    ) -> Result<
        (SessionId, cerberus_types::wire::WireSecret, Vec<Closed>),
        cerberus_crypto::CryptoError,
    > {
        let opened = self.sessions().open(new, now, &self.limits)?;
        if !opened.2.is_empty() {
            self.bump();
        }
        Ok(opened)
    }

    pub(crate) fn check_session(
        &self,
        core: &VaultService,
        token: &str,
        cert_sha256: &[u8; 32],
    ) -> Result<Session, Refusal> {
        let result = self.sessions().check(
            token,
            cert_sha256,
            core.clock().now(),
            live_epoch(core),
            &self.limits,
        );
        if matches!(result, Err(Refusal::Ended(_))) {
            self.bump();
        }
        result
    }

    pub(crate) fn touch(&self, id: SessionId, now: Timestamp) {
        self.sessions().touch(id, now);
    }

    pub(crate) fn close_session(&self, id: SessionId) -> Option<Closed> {
        let closed = self
            .sessions()
            .close(id, cerberus_core::SessionCloseReason::Closed);
        self.bump();
        closed
    }

    pub(crate) fn stream_acquire(&self, id: SessionId) -> bool {
        self.sessions()
            .stream_acquire(id, self.limits.max_streams_per_session)
    }

    pub(crate) fn stream_release(&self, id: SessionId) {
        self.sessions().stream_release(id);
    }
}

/// Audits ended sessions (`admin.session_close`). While sealed they go to `audit_pending`.
async fn audit_closed(core: &VaultService, closed: Vec<Closed>) {
    for session in closed {
        let mut event = AdminAudit::new(AdminEventKind::SessionClose);
        event.enrolment = Some(session.enrolment.to_string());
        event.label = Some(session.label);
        event.operator = Some(session.ctx.operator_id);
        event.reason = Some(session.reason);
        if let Err(error) = core.record_admin_event(Some(&session.ctx), event).await {
            tracing::warn!(%error, "admin.session_close was not audited");
        }
    }
}

/// Ends sessions at every vault state change (a lock voids them all) and every
/// [`SWEEP_EVERY`]. The server starts it with the listener and stops it at shutdown.
pub(crate) fn spawn_sweeper(state: AppState) -> Option<JoinHandle<()>> {
    let admin = state.admin()?.clone();
    let core = state.core().clone();
    let mut events = core.subscribe();
    Some(tokio::spawn(async move {
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Ok(CoreEvent::StateChanged(_)) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                () = tokio::time::sleep(SWEEP_EVERY) => {}
            }
            admin.sweep(&core).await;
        }
    }))
}

#[cfg(test)]
mod tests {
    use cerberus_types::t0;

    use super::*;

    #[test]
    fn five_failures_in_the_window_refuse_the_enrolment_for_the_block_time() {
        let limits = AdminLimits::default();
        let mut failures = Failures::default();
        let e = EnrolmentId::generate();
        let base = t0().as_millisecond();
        for n in 0..4 {
            failures.failed(e, base + n * 1000, &limits);
            assert!(failures.check(e, base + n * 1000).is_ok());
        }
        failures.failed(e, base + 4000, &limits);
        assert_eq!(failures.check(e, base + 4000), Err(900));
        assert!(failures.check(e, base + 4000 + 900_000).is_ok());
        // Another enrolment is not touched; a success clears the count.
        assert!(failures.check(EnrolmentId::generate(), base).is_ok());
        failures.succeeded(e);
        assert!(failures.check(e, base + 4000).is_ok());
    }

    #[test]
    fn one_session_open_per_enrolment_runs_at_a_time() {
        let admin = AdminState::new(AdminClients::default(), AdminLimits::default());
        let (e, other) = (EnrolmentId::generate(), EnrolmentId::generate());
        let first = admin.begin_attempt(e, t0()).expect("first");
        assert_eq!(
            admin.begin_attempt(e, t0()).err(),
            Some(AttemptRefusal::Busy)
        );
        let parallel = admin.begin_attempt(other, t0()).expect("another enrolment");
        drop(first);
        drop(parallel);
        let again = admin.begin_attempt(e, t0()).expect("after the first ended");
        for _ in 0..5 {
            admin.failure_record(e, t0());
        }
        drop(again);
        assert_eq!(
            admin.begin_attempt(e, t0()).err(),
            Some(AttemptRefusal::Blocked(900))
        );
    }

    #[test]
    fn failures_outside_the_window_do_not_add_up() {
        let limits = AdminLimits::default();
        let mut failures = Failures::default();
        let e = EnrolmentId::generate();
        let base = t0().as_millisecond();
        for n in 0..10 {
            failures.failed(e, base + n * 300_000, &limits);
            assert!(failures.check(e, base + n * 300_000).is_ok(), "{n}");
        }
    }
}
