//! Lock triggers (ADR-0026): idle time, the hard limit after unlock, OS events, and the
//! background loops.

use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use cerberus_store::{SettingRow, StoreError, SweepReport, Sweeper};
use cerberus_types::{LockReason, OperatorRole};
use jiff::Timestamp;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::events::{CoreConfig, CoreEvent, OsEvent, OsEventSink, OsLockEvents};
use super::state::Unlocked;
use super::{KIND_UNLOCKED, VaultService};
use crate::context::{AgentContext, OperatorContext};
use crate::error::CoreError;
use cerberus_types::FieldProblem;

/// Default idle lock time (30 minutes).
pub const DEFAULT_IDLE_SECONDS: u64 = 1_800;
/// Default hard limit after unlock (12 hours).
pub const DEFAULT_MAX_UNLOCKED_SECONDS: u32 = 43_200;
/// Allowed idle lock times.
pub const IDLE_LOCK_RANGE: RangeInclusive<u32> = 60..=86_400;
/// Allowed hard limits.
pub const MAX_UNLOCKED_RANGE: RangeInclusive<u32> = 900..=604_800;
/// How often the idle loop checks (ADR-0022 point 4).
pub const AUTO_LOCK_PERIOD: Duration = Duration::from_secs(5);
/// How often the expiry sweeper runs (ADR-0027).
pub const SWEEP_PERIOD: Duration = Duration::from_secs(60);

/// Setting keys in the `settings` table. The value is JSON: a number or `null` (off), or a bool.
pub mod keys {
    /// Idle lock time in seconds, or `null` for off.
    pub const IDLE_LOCK_SECONDS: &str = "idle_lock_seconds";
    /// Hard limit after unlock in seconds, or `null` for off.
    pub const MAX_UNLOCKED_SECONDS: &str = "max_unlocked_seconds";
    /// Lock on OS sleep and screen lock.
    pub const LOCK_ON_OS_LOCK: &str = "lock_on_os_lock";
    /// A successful agent call counts as activity for the idle timer.
    pub const AGENT_ACTIVITY_KEEPS_UNLOCKED: &str = "agent_activity_keeps_unlocked";
}

/// The lock trigger settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockSettings {
    /// Idle lock time in seconds (60..=86400), or `None` for off.
    pub idle_lock_seconds: Option<u32>,
    /// Hard limit after unlock in seconds (900..=604800), or `None` for off.
    pub max_unlocked_seconds: Option<u32>,
    /// Lock on OS sleep and screen lock.
    pub lock_on_os_lock: bool,
    /// A successful agent call counts as activity.
    pub agent_activity_keeps_unlocked: bool,
}

impl LockSettings {
    /// The values used when the vault has no setting rows.
    #[must_use]
    pub fn defaults(config: &CoreConfig) -> Self {
        Self {
            idle_lock_seconds: config
                .idle_lock_default
                .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX)),
            max_unlocked_seconds: Some(DEFAULT_MAX_UNLOCKED_SECONDS),
            lock_on_os_lock: true,
            agent_activity_keeps_unlocked: true,
        }
    }

    /// Checks the ranges of ADR-0026.
    ///
    /// # Errors
    /// [`CoreError::Validation`] with one problem per bad field.
    pub fn validate(&self) -> Result<(), CoreError> {
        let mut problems = Vec::new();
        if self
            .idle_lock_seconds
            .is_some_and(|s| !IDLE_LOCK_RANGE.contains(&s))
        {
            problems.push(FieldProblem {
                field: keys::IDLE_LOCK_SECONDS.to_owned(),
                problem: "must be 60..86400 or off".to_owned(),
            });
        }
        if self
            .max_unlocked_seconds
            .is_some_and(|s| !MAX_UNLOCKED_RANGE.contains(&s))
        {
            problems.push(FieldProblem {
                field: keys::MAX_UNLOCKED_SECONDS.to_owned(),
                problem: "must be 900..604800 or off".to_owned(),
            });
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(CoreError::Validation(problems))
        }
    }
}

/// The settings as atomics, so the sync hooks (`note_agent_activity`, `on_os_event`) can read them.
/// 0 means off for the two times.
#[derive(Debug)]
pub(super) struct LockSettingsCell {
    idle: AtomicU32,
    max: AtomicU32,
    os: AtomicBool,
    agent: AtomicBool,
}

impl LockSettingsCell {
    pub(super) fn new(value: LockSettings) -> Self {
        let cell = Self {
            idle: AtomicU32::new(0),
            max: AtomicU32::new(0),
            os: AtomicBool::new(false),
            agent: AtomicBool::new(false),
        };
        cell.set(value);
        cell
    }

    pub(super) fn set(&self, value: LockSettings) {
        self.idle
            .store(value.idle_lock_seconds.unwrap_or(0), Ordering::SeqCst);
        self.max
            .store(value.max_unlocked_seconds.unwrap_or(0), Ordering::SeqCst);
        self.os.store(value.lock_on_os_lock, Ordering::SeqCst);
        self.agent
            .store(value.agent_activity_keeps_unlocked, Ordering::SeqCst);
    }

    pub(super) fn get(&self) -> LockSettings {
        let some = |v: u32| (v != 0).then_some(v);
        LockSettings {
            idle_lock_seconds: some(self.idle.load(Ordering::SeqCst)),
            max_unlocked_seconds: some(self.max.load(Ordering::SeqCst)),
            lock_on_os_lock: self.os.load(Ordering::SeqCst),
            agent_activity_keeps_unlocked: self.agent.load(Ordering::SeqCst),
        }
    }
}

impl VaultService {
    /// Reads one sealed setting. A missing row gives `None`; a row that fails to open or parse also
    /// gives `None` (the default applies), an integrity alert and a chain event.
    pub(super) async fn read_setting<T: serde::de::DeserializeOwned>(
        &self,
        unlocked: &Unlocked,
        row: Result<SettingRow, StoreError>,
        key: &'static str,
    ) -> Result<Option<T>, CoreError> {
        let row = match row {
            Ok(row) => row,
            Err(StoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let parsed = unlocked
            .blobs()
            .open_setting(key, &row.value_ct)
            .ok()
            .and_then(|plain| serde_json::from_slice(plain.expose_secret()).ok());
        if parsed.is_none() {
            tracing::warn!(key, "sealed setting failed to open");
            self.integrity_issue(unlocked, "settings", key.to_owned())
                .await;
        }
        Ok(parsed)
    }

    /// Loads the lock settings of the vault into the service. Missing rows keep the defaults.
    pub(super) async fn load_lock_settings(&self, unlocked: &Unlocked) -> Result<(), CoreError> {
        let store = &self.inner.store;
        let defaults = LockSettings::defaults(&self.inner.config);
        let idle: Option<Option<u32>> = self
            .read_setting(
                unlocked,
                store.setting(keys::IDLE_LOCK_SECONDS).await,
                keys::IDLE_LOCK_SECONDS,
            )
            .await?;
        let max: Option<Option<u32>> = self
            .read_setting(
                unlocked,
                store.setting(keys::MAX_UNLOCKED_SECONDS).await,
                keys::MAX_UNLOCKED_SECONDS,
            )
            .await?;
        let os: Option<bool> = self
            .read_setting(
                unlocked,
                store.setting(keys::LOCK_ON_OS_LOCK).await,
                keys::LOCK_ON_OS_LOCK,
            )
            .await?;
        let agent: Option<bool> = self
            .read_setting(
                unlocked,
                store.setting(keys::AGENT_ACTIVITY_KEEPS_UNLOCKED).await,
                keys::AGENT_ACTIVITY_KEEPS_UNLOCKED,
            )
            .await?;
        let value = LockSettings {
            idle_lock_seconds: idle.unwrap_or(defaults.idle_lock_seconds),
            max_unlocked_seconds: max.unwrap_or(defaults.max_unlocked_seconds),
            lock_on_os_lock: os.unwrap_or(defaults.lock_on_os_lock),
            agent_activity_keeps_unlocked: agent.unwrap_or(defaults.agent_activity_keeps_unlocked),
        };
        // A stored value out of range (an edited file cannot forge one, but a bug could) falls
        // back to the defaults.
        let value = if value.validate().is_ok() {
            value
        } else {
            defaults
        };
        self.inner.lock_settings.set(value);
        Ok(())
    }

    /// The lock trigger settings. Any role.
    ///
    /// # Errors
    /// [`CoreError::Locked`], or the errors of the role check.
    pub async fn lock_settings(&self, ctx: &OperatorContext) -> Result<LockSettings, CoreError> {
        let _guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        Ok(self.inner.lock_settings.get())
    }

    /// Saves the lock trigger settings. Role operator or owner.
    ///
    /// # Errors
    /// [`CoreError::Validation`] for out-of-range values, [`CoreError::Locked`], the role check,
    /// or a storage error.
    pub async fn set_lock_settings(
        &self,
        ctx: &OperatorContext,
        value: LockSettings,
    ) -> Result<(), CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        value.validate()?;
        let now = self.inner.clock.now();
        let blobs = guard.blobs();
        let entries: [(&str, serde_json::Value); 4] = [
            (keys::IDLE_LOCK_SECONDS, value.idle_lock_seconds.into()),
            (
                keys::MAX_UNLOCKED_SECONDS,
                value.max_unlocked_seconds.into(),
            ),
            (keys::LOCK_ON_OS_LOCK, value.lock_on_os_lock.into()),
            (
                keys::AGENT_ACTIVITY_KEEPS_UNLOCKED,
                value.agent_activity_keeps_unlocked.into(),
            ),
        ];
        let mut tx = self.inner.store.begin().await?;
        for (key, json) in entries {
            let plain = serde_json::to_vec(&json).map_err(|_| CoreError::Corrupt)?;
            let row = SettingRow {
                key: key.to_owned(),
                updated_at: now,
                value_ct: blobs.seal_setting(key, &plain)?,
            };
            tx.put_setting(&row).await?;
        }
        tx.commit().await?;
        self.inner.lock_settings.set(value);
        let event = super::integration::by_operator(crate::audit::EventType::SettingsChange, ctx)
            .detail(
                "keys",
                serde_json::json!([
                    keys::IDLE_LOCK_SECONDS,
                    keys::MAX_UNLOCKED_SECONDS,
                    keys::LOCK_ON_OS_LOCK,
                    keys::AGENT_ACTIVITY_KEEPS_UNLOCKED
                ]),
            );
        self.audit(&guard, event).await;
        Ok(())
    }

    /// Called by the API layer after each authenticated agent call (ADR-0026). Counts as activity
    /// when `agent_activity_keeps_unlocked` is on. Sync and cheap.
    pub fn note_agent_activity(&self, _ctx: &AgentContext) {
        if self.inner.lock_settings.get().agent_activity_keeps_unlocked {
            self.touch_activity();
        }
    }

    /// Operator input in the UI (IPC `ui_activity`). Resets the idle timer.
    pub fn note_operator_activity(&self) {
        self.touch_activity();
    }

    fn touch_activity(&self) {
        if self.inner.kind.load(Ordering::SeqCst) == KIND_UNLOCKED {
            let now = self.inner.clock.now().as_millisecond();
            self.inner.last_activity_ms.fetch_max(now, Ordering::SeqCst);
        }
    }

    /// Seconds until the idle lock and the time of the hard lock, for the status view.
    pub(super) fn auto_lock_times(
        &self,
        unlocked_at: Timestamp,
        now: Timestamp,
    ) -> (Option<i64>, Option<i64>) {
        let settings = self.inner.lock_settings.get();
        let now_ms = now.as_millisecond();
        let idle_left = settings.idle_lock_seconds.map(|secs| {
            let last = self.inner.last_activity_ms.load(Ordering::SeqCst);
            last.saturating_add(i64::from(secs) * 1000)
                .saturating_sub(now_ms)
        });
        let hard_left = settings.max_unlocked_seconds.map(|secs| {
            unlocked_at
                .as_millisecond()
                .saturating_add(i64::from(secs) * 1000)
                .saturating_sub(now_ms)
        });
        (idle_left, hard_left)
    }

    /// One run of the idle-lock loop (ADR-0022 point 4). Locks when the hard limit or the idle
    /// time is reached and returns the reason. Otherwise sends an `AutoLockTick`. A lock that was
    /// requested but did not finish (state `Locking`) is finished here, with its own reason.
    pub async fn run_auto_lock_once(&self, now: Timestamp) -> Option<LockReason> {
        if let Some(reason) = self.pending_lock_reason() {
            return self.lock_for(reason).await.then_some(reason);
        }
        let unlocked_at = {
            let guard = self.unlocked().await.ok()?;
            guard.session.unlocked_at
        };
        let (idle_left, hard_left) = self.auto_lock_times(unlocked_at, now);
        let reason = if hard_left.is_some_and(|ms| ms <= 0) {
            Some(LockReason::MaxUnlocked)
        } else if idle_left.is_some_and(|ms| ms <= 0) {
            Some(LockReason::Idle)
        } else {
            None
        };
        match reason {
            Some(reason) => {
                self.lock_for(reason).await;
                Some(reason)
            }
            None => {
                let left = [idle_left, hard_left].into_iter().flatten().min();
                if let Some(ms) = left {
                    self.emit(CoreEvent::AutoLockTick {
                        seconds_left: u64::try_from(ms / 1000).unwrap_or(0),
                    });
                }
                None
            }
        }
    }

    /// Sync OS hook entry (ADR-0026). Works from any thread. New calls are refused at once; the
    /// full lock (cancel requests, audit, `StateChanged`) runs in a task on the service runtime.
    /// The setting is read once here, so turning it off later cannot stop a lock that started.
    pub fn on_os_event(&self, _event: OsEvent) {
        if !self.inner.lock_settings.get().lock_on_os_lock {
            return;
        }
        self.spawn_lock(LockReason::OsLock);
    }

    /// Async OS hook entry. Locks with reason `os_lock` when `lock_on_os_lock` is on. Returns true
    /// when it locked.
    pub async fn handle_os_event(&self, _event: OsEvent) -> bool {
        if !self.inner.lock_settings.get().lock_on_os_lock {
            return false;
        }
        self.lock_for(LockReason::OsLock).await
    }

    /// A handle for an OS hook.
    #[must_use]
    pub fn os_event_sink(&self) -> OsEventSink {
        OsEventSink::new(&self.inner)
    }

    /// Starts an OS hook. The result shows in the status view (`os_hook_ok`).
    pub fn attach_os_events(&self, source: &dyn OsLockEvents) -> bool {
        let ok = source.start(self.os_event_sink());
        self.inner.os_hook_ok.store(ok, Ordering::SeqCst);
        ok
    }

    /// Work after each sweep: removes the items that the sweeper deleted from the index, then
    /// deletes the items whose sealed expiry has passed, which the sweeper cannot see (AUD-8).
    pub async fn apply_sweep_report(&self, report: &SweepReport) {
        if !report.expired_items.is_empty()
            && let Ok(mut guard) = self.unlocked_mut().await
        {
            for id in &report.expired_items {
                guard.index.remove_item(id);
            }
        }
        self.delete_sealed_expired(self.inner.clock.now()).await;
    }

    /// Starts the background loops of this service: the idle-lock check every 5 s, the expiry
    /// sweeper every 60 s (its reports update the index), and the approval and lease expiry loop
    /// every 1 s (`PolicyEngine::spawn_expiry_loop`). Abort the handles to stop.
    pub fn spawn_background(&self) -> Vec<JoinHandle<()>> {
        let idle = {
            let service = self.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(AUTO_LOCK_PERIOD);
                loop {
                    tick.tick().await;
                    let now = service.inner.clock.now();
                    service.run_auto_lock_once(now).await;
                }
            })
        };
        // The sweeper sends every report, also an empty one: the pass over the sealed expiry in
        // `apply_sweep_report` needs no plain row to be due (AUD-8).
        let (reports_tx, mut reports_rx) = mpsc::channel(16);
        let sweeper = Sweeper::new(self.inner.store.clone()).spawn(
            SWEEP_PERIOD,
            self.inner.clock.clone(),
            reports_tx,
        );
        let reports = {
            let service = self.clone();
            tokio::spawn(async move {
                while let Some(report) = reports_rx.recv().await {
                    service.apply_sweep_report(&report).await;
                }
            })
        };
        vec![idle, sweeper, reports, self.policy().spawn_expiry_loop()]
    }
}
