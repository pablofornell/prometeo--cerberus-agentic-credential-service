//! The vault service: key custody, the state machine and the lock triggers (ADR-0026).
//!
//! The state is one `tokio::sync::RwLock<VaultState>`. Keys and the index live only in the
//! `Unlocked` variant. Every read of keys or metadata goes through [`VaultService::unlocked`] (or
//! the role-checked [`VaultService::authorize`]), which refuses while the vault is not unlocked.
//!
//! Lock order: a lock request first sets the state kind to `Locking` (new calls get `Locked` at
//! once), then waits for the write lock. `tokio`'s `RwLock` is fair, so calls that queue after the
//! request wait behind it and then see `Sealed`. In-flight calls hold a read guard; the lock waits
//! for them, so no call can still read keys once `lock` returns.
//!
//! The erase runs in a task on the service runtime (DEC-FIX5-1). A caller that gives up (timeout,
//! `select!`) or an OS hook on a thread without a runtime cannot leave the vault at `Locking`.

mod authlog;
mod autolock;
mod backoff;
mod ca;
mod checks;
mod custody;
mod events;
mod integration;
mod operators;
mod state;

#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};

use cerberus_crypto::{CryptoError, KdfParams, SlotKdf};
use cerberus_store::{Store, StoreError};
use cerberus_types::{
    AccessRequestStatus, Clock, LockReason, OperatorId, OperatorRole, VaultStateKind,
};
use jiff::Timestamp;
use tokio::sync::{
    Mutex, RwLock, RwLockMappedWriteGuard, RwLockReadGuard, RwLockWriteGuard, broadcast,
};

pub use autolock::{
    AUTO_LOCK_PERIOD, DEFAULT_IDLE_SECONDS, DEFAULT_MAX_UNLOCKED_SECONDS, IDLE_LOCK_RANGE,
    LockSettings, MAX_UNLOCKED_RANGE, SWEEP_PERIOD, keys as setting_keys,
};
pub use backoff::{
    FREE_UNLOCK_FAILURES, MAX_UNLOCK_WAIT_SECONDS, seconds_until_retry, unlock_wait_seconds,
};
pub use ca::{CaIssuer, IssuedCa, TLS_CUSTOM_SETTING, TlsCaMaterial, TlsCustomMaterial};
pub use custody::{CreatedVault, KeyCustody, NewVault, OperatorInfo};
pub use events::{CoreConfig, CoreEvent, OsEvent, OsEventSink, OsLockEvents};
pub use state::Session;

pub(crate) use integration::by_operator;
pub(crate) use state::Unlocked;
use state::VaultState;

use crate::audit::{Actor, AuditEvent, EventType};
use crate::auth::{AuthLimits, AuthTable};
use crate::context::OperatorContext;
use crate::error::CoreError;

const KIND_NO_VAULT: u8 = 0;
const KIND_SEALED: u8 = 1;
const KIND_UNLOCKED: u8 = 2;
const KIND_LOCKING: u8 = 3;

const fn kind_of(value: u8) -> VaultStateKind {
    match value {
        KIND_NO_VAULT => VaultStateKind::NoVault,
        KIND_UNLOCKED => VaultStateKind::Unlocked,
        KIND_LOCKING => VaultStateKind::Locking,
        _ => VaultStateKind::Sealed,
    }
}

/// Capacity of the event channel. A slow receiver misses old events (`Lagged`), never blocks.
const EVENT_CAPACITY: usize = 256;

/// Lock bookkeeping that sync code (OS hook, panic button during a pending lock) reads.
#[derive(Debug, Default)]
struct LockSide {
    /// The reason of the first lock request since the last unlock.
    pending_reason: Option<LockReason>,
    /// The reason of the latest lock that dropped the keys in this run (DEC-INT10-9).
    last_reason: Option<LockReason>,
    /// The operator of the current session, so a panic can join a pending lock.
    session_operator: Option<OperatorId>,
    /// A panic that the next erase must honor (it revokes all leases).
    panic_request: Option<OperatorId>,
    /// A panic whose lease revoke failed. The next unlock revokes all leases first.
    revoke_at_unlock: Option<String>,
}

pub(crate) struct Inner {
    store: Store,
    clock: Arc<dyn Clock>,
    config: CoreConfig,
    state: RwLock<VaultState>,
    /// Mirror of the state for sync readers. `Locking` is only here.
    kind: AtomicU8,
    /// Grows at each lock request. An unlock that started before a lock request does not install.
    epoch: AtomicU64,
    /// Serializes create, unlock and key slot changes.
    gate: Mutex<()>,
    events: broadcast::Sender<CoreEvent>,
    last_activity_ms: AtomicI64,
    lock_settings: autolock::LockSettingsCell,
    os_hook_ok: AtomicBool,
    /// Agent status and key hashes (plain columns), for token checks also while sealed.
    auth: AuthTable,
    /// The runtime the service was opened on. Lock tasks run here, also when the OS hook calls
    /// from a thread without a runtime.
    runtime: tokio::runtime::Handle,
    side: std::sync::Mutex<LockSide>,
    /// Policy engine state (read limits, gates, settings cache). See [`crate::policy::PolicyEngine`].
    policy: crate::policy::engine::EngineState,
    /// Rate limit of `auth.failed` events by source IP (DEC-FIX7-11).
    auth_failures: std::sync::Mutex<authlog::AuthFailureLog>,
}

/// The vault service. Owns key custody and the index. Cheap to clone (one `Arc` inside).
#[derive(Clone)]
pub struct VaultService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for VaultService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultService")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// What the UI shows about the vault (IPC `vault_status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStatus {
    /// The state.
    pub state: VaultStateKind,
    /// The session, while unlocked.
    pub session: Option<Session>,
    /// Seconds until the idle lock, while unlocked and when the idle lock is on.
    pub idle_seconds_left: Option<u64>,
    /// Time of the hard lock, while unlocked and when the hard limit is on.
    pub hard_lock_at: Option<Timestamp>,
    /// False when the header MAC failed at the last unlock.
    pub header_ok: bool,
    /// True when an OS hook is attached and works.
    pub os_hook_ok: bool,
    /// True when every key page could be locked in RAM (ADR-0012).
    pub memlock_ok: bool,
    /// Argon2id cost of the passphrase slot of the session operator. `None` while sealed and for a
    /// recovery session (that slot has no passphrase KDF). DEC-INT10-8.
    pub kdf: Option<KdfParams>,
    /// Why the latest lock in this run happened. `None` when the vault was not locked yet in this
    /// run. A panic lock and a process panic both read as [`LockReason::PanicButton`] or
    /// [`LockReason::Panic`]. DEC-INT10-9.
    pub last_lock_reason: Option<LockReason>,
    /// Failed unlocks in a row (kept in the header, so a restart keeps it). DEC-INT10-10.
    pub failed_unlocks: u32,
    /// Unlock tries left before the back-off starts (`FREE_UNLOCK_FAILURES` minus the failures).
    pub free_unlock_tries_left: u32,
    /// Seconds until the next unlock try is allowed. 0 when no back-off runs.
    pub retry_after_seconds: u32,
}

impl VaultService {
    /// Opens the service on an open store. The state is `NoVault` when the file has no header,
    /// else `Sealed`. Lock tasks run on the tokio runtime of this call.
    ///
    /// # Errors
    /// A storage error.
    pub async fn open(
        store: Store,
        clock: Arc<dyn Clock>,
        config: CoreConfig,
    ) -> Result<Self, CoreError> {
        let (state, kind) = match store.header().await {
            Ok(_) => (VaultState::Sealed, KIND_SEALED),
            Err(StoreError::NotFound) => (VaultState::NoVault, KIND_NO_VAULT),
            Err(error) => return Err(error.into()),
        };
        let lock_settings = autolock::LockSettingsCell::new(LockSettings::defaults(&config));
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let now = clock.now();
        let service = Self {
            inner: Arc::new(Inner {
                store,
                clock,
                config,
                state: RwLock::new(state),
                kind: AtomicU8::new(kind),
                epoch: AtomicU64::new(0),
                gate: Mutex::new(()),
                events,
                last_activity_ms: AtomicI64::new(0),
                lock_settings,
                os_hook_ok: AtomicBool::new(false),
                auth: AuthTable::new(AuthLimits::default()),
                runtime: tokio::runtime::Handle::current(),
                side: std::sync::Mutex::new(LockSide::default()),
                policy: crate::policy::engine::EngineState::default(),
                auth_failures: std::sync::Mutex::default(),
            }),
        };
        service.rebuild_auth_unverified(now).await?;
        Ok(service)
    }

    /// The token table (ADR-0016). It works while sealed; see [`AuthTable`].
    #[must_use]
    pub fn auth(&self) -> &AuthTable {
        &self.inner.auth
    }

    /// The current state. Sync; reads the mirror flag.
    #[must_use]
    pub fn state(&self) -> VaultStateKind {
        kind_of(self.inner.kind.load(Ordering::SeqCst))
    }

    /// Events for the UI and SSE.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<CoreEvent> {
        self.inner.events.subscribe()
    }

    /// The policy, lease and approval engine of this service (cheap; shares one state).
    #[must_use]
    pub fn policy(&self) -> crate::policy::PolicyEngine {
        crate::policy::PolicyEngine::new(self.clone())
    }

    pub(crate) fn policy_state(&self) -> &crate::policy::engine::EngineState {
        &self.inner.policy
    }

    /// The store of this service.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// Closes the store of this service and waits until every connection is closed
    /// ([`Store::close`]). Every clone of the service shares the store, so after this every store
    /// call of any clone fails. A restore calls it, after the lock and after the tasks that hold
    /// the service stopped, before it moves the vault file (NEW-10). Takes no vault guard.
    pub async fn close_store(&self) {
        self.inner.store.clone().close().await;
    }

    /// The clock of this service.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &CoreConfig {
        &self.inner.config
    }

    pub(crate) fn emit(&self, event: CoreEvent) {
        // No receiver is not an error: the UI may not listen yet.
        drop(self.inner.events.send(event));
    }

    fn not_unlocked_error(&self) -> CoreError {
        match self.inner.kind.load(Ordering::SeqCst) {
            KIND_NO_VAULT => CoreError::NoVault,
            _ => CoreError::Locked,
        }
    }

    /// Read access to the unlocked state. Hold the guard only for the call: a lock waits for it.
    ///
    /// # Errors
    /// [`CoreError::Locked`] (or [`CoreError::NoVault`]) when the vault is not unlocked.
    pub(crate) async fn unlocked(&self) -> Result<RwLockReadGuard<'_, Unlocked>, CoreError> {
        if self.inner.kind.load(Ordering::SeqCst) != KIND_UNLOCKED {
            return Err(self.not_unlocked_error());
        }
        let guard = self.inner.state.read().await;
        RwLockReadGuard::try_map(guard, |state| match state {
            VaultState::Unlocked(unlocked) => Some(&**unlocked),
            VaultState::NoVault | VaultState::Sealed => None,
        })
        .map_err(|_| self.not_unlocked_error())
    }

    /// Write access to the unlocked state (index updates: DB first, then the index, ADR-0006).
    ///
    /// # Errors
    /// [`CoreError::Locked`] (or [`CoreError::NoVault`]) when the vault is not unlocked.
    pub(crate) async fn unlocked_mut(
        &self,
    ) -> Result<RwLockMappedWriteGuard<'_, Unlocked>, CoreError> {
        if self.inner.kind.load(Ordering::SeqCst) != KIND_UNLOCKED {
            return Err(self.not_unlocked_error());
        }
        let guard = self.inner.state.write().await;
        RwLockWriteGuard::try_map(guard, |state| match state {
            VaultState::Unlocked(unlocked) => Some(&mut **unlocked),
            VaultState::NoVault | VaultState::Sealed => None,
        })
        .map_err(|_| self.not_unlocked_error())
    }

    /// [`Self::unlocked`] plus the role check of ADR-0009 for `ctx`. Every operator method uses it.
    ///
    /// # Errors
    /// [`CoreError::Locked`], [`CoreError::Forbidden`] (context of another session) or
    /// [`CoreError::RoleNotAllowed`].
    pub(crate) async fn authorize(
        &self,
        ctx: &OperatorContext,
        min: OperatorRole,
    ) -> Result<RwLockReadGuard<'_, Unlocked>, CoreError> {
        let guard = self.unlocked().await?;
        guard.session.authorize(ctx, min)?;
        Ok(guard)
    }

    /// The status view.
    pub async fn status(&self) -> VaultStatus {
        let now = self.inner.clock.now();
        let (session, header_ok) = match self.unlocked().await {
            Ok(guard) => (Some(guard.session), guard.header_ok),
            Err(_) => (None, true),
        };
        let (idle_left, hard_left) =
            session.map_or((None, None), |s| self.auto_lock_times(s.unlocked_at, now));
        let hard_lock_at = hard_left.and_then(|ms| {
            Timestamp::from_millisecond(now.as_millisecond().saturating_add(ms)).ok()
        });
        let (failed_unlocks, retry_after_seconds) = match self.inner.store.header().await {
            Ok(header) => (header.failed_unlocks, seconds_until_retry(&header, now)),
            Err(_) => (0, 0),
        };
        let kdf = match session {
            Some(s) => self.slot_kdf(s.operator_id).await,
            None => None,
        };
        VaultStatus {
            state: self.state(),
            session,
            idle_seconds_left: idle_left.map(|ms| u64::try_from(ms.max(0) / 1000).unwrap_or(0)),
            hard_lock_at,
            header_ok,
            os_hook_ok: self.inner.os_hook_ok.load(Ordering::SeqCst),
            memlock_ok: !cerberus_crypto::memlock::lock_failed(),
            kdf,
            last_lock_reason: self.side().last_reason,
            failed_unlocks,
            free_unlock_tries_left: FREE_UNLOCK_FAILURES.saturating_sub(failed_unlocks),
            retry_after_seconds,
        }
    }

    /// The Argon2id cost of the passphrase slot `operator`, or `None` for another slot kind or a
    /// slot that cannot be read.
    async fn slot_kdf(&self, operator: OperatorId) -> Option<KdfParams> {
        let rows = self.inner.store.key_slots().await.ok()?;
        rows.into_iter()
            .find(|row| row.id == operator)
            .and_then(|row| match row.material.kdf {
                SlotKdf::Argon2id(params) => Some(params),
                SlotKdf::HkdfSha256 => None,
            })
    }

    fn side(&self) -> MutexGuard<'_, LockSide> {
        self.inner
            .side
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Bumps the epoch and moves `Unlocked` to `Locking`. No lock taken, no allocation.
    fn mark_locking(&self) -> bool {
        self.inner.epoch.fetch_add(1, Ordering::SeqCst);
        self.inner
            .kind
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |k| {
                (k == KIND_UNLOCKED || k == KIND_LOCKING).then_some(KIND_LOCKING)
            })
            .is_ok()
    }

    /// Marks a lock request: new calls are refused from now on, and an unlock in progress will not
    /// install. Returns true when the vault was unlocked (or already locking).
    fn begin_lock(&self, reason: LockReason) -> bool {
        let locking = self.mark_locking();
        if locking {
            let mut side = self.side();
            if side.pending_reason.is_none() {
                side.pending_reason = Some(reason);
            }
        }
        locking
    }

    /// The reason of a lock that was requested but has not dropped the keys yet.
    pub(super) fn pending_lock_reason(&self) -> Option<LockReason> {
        if self.inner.kind.load(Ordering::SeqCst) != KIND_LOCKING {
            return None;
        }
        Some(self.side().pending_reason.unwrap_or(LockReason::Manual))
    }

    /// Requests a lock from sync code. The full lock runs in a task on the service runtime, so it
    /// works from any thread.
    pub(super) fn spawn_lock(&self, reason: LockReason) {
        if !self.begin_lock(reason) {
            return;
        }
        let service = self.clone();
        drop(self.inner.runtime.spawn(async move {
            service.lock_for(reason).await;
        }));
    }

    /// Locks for `reason` and logs a failure of the clean-up steps. Returns true when keys were
    /// dropped. The keys are always dropped, also when a clean-up step fails.
    pub(crate) async fn lock_for(&self, reason: LockReason) -> bool {
        match self.lock_inner(reason, None).await {
            Ok(dropped) => dropped,
            Err(error) => {
                tracing::warn!(%error, "lock clean-up failed; keys were dropped");
                true
            }
        }
    }

    /// The lock. With `panic_by`, all leases are revoked first (panic button, ADR-0019).
    /// Pending access requests are always cancelled (ADR-0018). Then the `Unlocked` state is
    /// dropped. Returns `Ok(false)` when the vault was not unlocked.
    ///
    /// The erase runs in a detached task: when the caller is cancelled, it still finishes.
    async fn lock_inner(
        &self,
        reason: LockReason,
        panic_by: Option<OperatorId>,
    ) -> Result<bool, CoreError> {
        if !self.begin_lock(reason) {
            return match panic_by {
                Some(_) => self.panic_outcome(),
                None => Ok(false),
            };
        }
        let service = self.clone();
        let task = self
            .inner
            .runtime
            .spawn(async move { service.erase(reason, panic_by).await });
        // A join error means the task panicked or the runtime stops. The idle loop finishes a
        // lock that is left at `Locking`.
        task.await
            .map_err(|_| CoreError::Crypto(CryptoError::Kdf))?
    }

    /// Takes the write lock and drops the keys. A panic request made while this lock was
    /// pending is honored here.
    async fn erase(
        &self,
        reason: LockReason,
        panic_by: Option<OperatorId>,
    ) -> Result<bool, CoreError> {
        let mut guard = self.inner.state.write().await;
        let VaultState::Unlocked(unlocked) = &*guard else {
            drop(guard);
            // Another lock dropped the keys first.
            let _already_sealed = self.inner.kind.compare_exchange(
                KIND_LOCKING,
                KIND_SEALED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            return match panic_by {
                Some(_) => self.panic_outcome(),
                None => Ok(false),
            };
        };
        let panic = {
            let mut side = self.side();
            side.pending_reason = None;
            side.session_operator = None;
            side.panic_request.take()
        }
        .or(panic_by);
        let reason = if panic.is_some() {
            LockReason::PanicButton
        } else {
            reason
        };
        self.side().last_reason = Some(reason);
        let cleanup = self.before_erase(unlocked, reason, panic).await;
        // Drop the keys and the index: `Vmk`, `Key32` and the `Zeroizing` text zeroize on drop.
        *guard = VaultState::Sealed;
        self.inner.kind.store(KIND_SEALED, Ordering::SeqCst);
        drop(guard);
        self.emit(CoreEvent::StateChanged(VaultStateKind::Sealed));
        cleanup.map(|()| true)
    }

    /// The result of a panic whose lock found the vault sealed: `Ok` when an earlier lock took
    /// the panic request (and revoked the leases), else `Locked`.
    fn panic_outcome(&self) -> Result<bool, CoreError> {
        match self.side().panic_request.take() {
            None => Ok(true),
            Some(_) => Err(self.not_unlocked_error()),
        }
    }

    /// Marks a panic by `operator`: the next erase revokes all leases, also when a lock is
    /// already pending.
    pub(super) fn request_panic(&self, operator: OperatorId) {
        self.side().panic_request = Some(operator);
    }

    /// The operator of the session while a lock is pending, for the panic button.
    pub(super) fn locking_session_operator(&self) -> Option<OperatorId> {
        if self.inner.kind.load(Ordering::SeqCst) != KIND_LOCKING {
            return None;
        }
        self.side().session_operator
    }

    /// Remembers a panic whose lease revoke failed, in memory and (best effort) in a sealed
    /// setting, so the next unlock revokes all leases before the vault serves calls.
    async fn defer_panic_revoke(&self, unlocked: &Unlocked, by: OperatorId) {
        let by = by.to_string();
        self.side().revoke_at_unlock = Some(by.clone());
        if let Err(error) = self.put_panic_setting(unlocked, Some(&by)).await {
            tracing::warn!(%error, "could not save the pending panic revoke");
        }
    }

    /// Takes the in-memory pending panic revoke.
    pub(super) fn take_revoke_at_unlock(&self) -> Option<String> {
        self.side().revoke_at_unlock.take()
    }

    /// Puts back a pending panic revoke that the unlock could not do.
    pub(super) fn keep_revoke_at_unlock(&self, by: String) {
        self.side().revoke_at_unlock = Some(by);
    }

    /// Store work that needs the row MAC key, done just before the keys go.
    async fn before_erase(
        &self,
        unlocked: &Unlocked,
        reason: LockReason,
        panic_by: Option<OperatorId>,
    ) -> Result<(), CoreError> {
        let now = self.inner.clock.now();
        let macs = unlocked.row_macs();
        let work = async {
            let mut tx = self.inner.store.begin().await?;
            let revoked = match panic_by {
                Some(by) => tx.revoke_all_leases(now, &by.to_string(), &macs).await?,
                None => cerberus_store::RevokeReport::default(),
            };
            let cancelled = tx.cancel_pending_requests(now, &macs).await?;
            tx.commit().await?;
            Ok::<_, CoreError>((revoked, cancelled))
        };
        let (revoked, cancelled) = match work.await {
            Ok(counts) => counts,
            Err(error) => {
                if let Some(by) = panic_by {
                    self.defer_panic_revoke(unlocked, by).await;
                }
                return Err(error);
            }
        };
        self.report_bad_macs(unlocked, &revoked, &cancelled).await;
        let revoked = revoked.revoked;
        let cancelled = cancelled.cancelled;
        // Waiters (SSE, MCP `request_access`) get a terminal event for each cancelled request
        // (ADR-0026 "send a final SSE event").
        for id in &cancelled {
            self.emit(CoreEvent::AccessRequestResolved {
                id: *id,
                status: AccessRequestStatus::Cancelled,
            });
        }
        let cancelled = cancelled.len();
        let reason_text = serde_json::to_value(reason).unwrap_or(serde_json::Value::Null);
        let event = match panic_by {
            Some(by) => AuditEvent::new(EventType::VaultPanic, Actor::operator(by.to_string()))
                .detail("leases_revoked", revoked),
            None => AuditEvent::new(EventType::VaultLock, Actor::system()),
        };
        let event = event
            .detail("reason", reason_text)
            .detail("requests_cancelled", cancelled);
        self.audit(unlocked, event).await;
        tracing::info!(reason = ?reason, "vault locked");
        Ok(())
    }

    /// Sync, allocation-free key wipe for the process panic hook only (ADR-0026). It takes the
    /// state only when no call holds it; the process aborts right after, so a held state goes
    /// with the process. Other sync callers use the OS hook path, which runs the full lock.
    pub fn emergency_wipe(&self) {
        self.mark_locking();
        if let Ok(mut guard) = self.inner.state.try_write() {
            if matches!(&*guard, VaultState::Unlocked(_)) {
                *guard = VaultState::Sealed;
            }
            if !matches!(&*guard, VaultState::NoVault) {
                self.inner.kind.store(KIND_SEALED, Ordering::SeqCst);
            }
        }
    }

    /// Puts a new unlocked state in place, unless a lock was requested since `epoch`.
    ///
    /// # Errors
    /// [`CoreError::Locked`] when a lock request came in during the unlock (or the create). The
    /// new keys are dropped and the vault is `Sealed`.
    async fn install(&self, unlocked: Unlocked, epoch: u64) -> Result<(), CoreError> {
        let mut guard = self.inner.state.write().await;
        let refuse = |state: &mut VaultState| {
            *state = VaultState::Sealed;
            self.inner.kind.store(KIND_SEALED, Ordering::SeqCst);
        };
        if self.inner.epoch.load(Ordering::SeqCst) != epoch {
            refuse(&mut guard);
            return Err(CoreError::Locked);
        }
        let now_ms = unlocked.session.unlocked_at.as_millisecond();
        let header_ok = unlocked.header_ok;
        let operator = unlocked.session.operator_id;
        {
            let mut side = self.side();
            side.pending_reason = None;
            side.panic_request = None;
            side.session_operator = Some(operator);
        }
        *guard = VaultState::Unlocked(Box::new(unlocked));
        self.inner.last_activity_ms.store(now_ms, Ordering::SeqCst);
        self.inner.kind.store(KIND_UNLOCKED, Ordering::SeqCst);
        // A lock request between the first check and the store above saw `Sealed` and did
        // nothing. Check again, and drop the keys at once if one came in.
        if self.inner.epoch.load(Ordering::SeqCst) != epoch {
            self.side().session_operator = None;
            refuse(&mut guard);
            return Err(CoreError::Locked);
        }
        drop(guard);
        self.emit(CoreEvent::StateChanged(VaultStateKind::Unlocked));
        if !header_ok {
            self.emit(CoreEvent::HeaderMismatch);
        }
        Ok(())
    }
}
