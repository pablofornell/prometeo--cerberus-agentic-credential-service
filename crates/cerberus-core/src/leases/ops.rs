//! Lease operations: list, revoke, revoke all, release, and expiry events (ADR-0019).
//!
//! Every change reads the row again inside one write transaction and checks its MAC there, so a
//! revoke can never be undone by a stale copy and a tampered row is never signed again.

use cerberus_store::{LeaseRow, LeaseSource, SettingRow, StoreError};
use cerberus_types::{AccessRequestId, AgentId, LeaseId, OperatorRole};
use jiff::Timestamp;

use super::{LeaseView, is_active};
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::{AgentContext, OperatorContext};
use crate::error::CoreError;
use crate::policy::PolicyEngine;
use crate::policy::engine::{by_agent, whole_ms};
use crate::vault::{CoreEvent, Unlocked};

/// Sealed setting that holds the end of the last lease expiry scan that wrote events (Unix ms).
pub const LEASE_EXPIRY_MARK_KEY: &str = "lease_expiry_mark";

/// A lease as the Leases screen shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseDetail {
    /// What the agent sees.
    pub view: LeaseView,
    /// The agent.
    pub agent_id: AgentId,
    /// `auto` or `approval`.
    pub source: LeaseSource,
    /// The request that made it, for an approval lease.
    pub request_id: Option<AccessRequestId>,
    /// Uses so far.
    pub uses: u32,
    /// Creation time (the item was exposed to the agent from then).
    pub created_at: Timestamp,
}

/// The answer to a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseOutcome {
    /// The lease.
    pub lease_id: LeaseId,
    /// Release time.
    pub released_at: Timestamp,
}

/// What a change does to a row that is still active.
enum Change {
    Revoke(String),
    Release,
}

impl PolicyEngine {
    /// Active leases, soonest end first. Any role. Rows with a bad MAC are left out (alert).
    ///
    /// # Errors
    /// `Locked`, the role check, or a storage error.
    pub async fn list_leases(&self, ctx: &OperatorContext) -> Result<Vec<LeaseDetail>, CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Viewer).await?;
        let unlocked: &Unlocked = &guard;
        let now = self.now();
        let macs = unlocked.row_macs();
        let mut out = Vec::new();
        for row in self.service.store().live_leases(now).await? {
            if !macs.verify_lease(&row)? {
                self.mac_alert(unlocked, "leases", row.id.to_string()).await;
                continue;
            }
            if is_active(&row, now) {
                out.push(LeaseDetail {
                    view: LeaseView::of(&row),
                    agent_id: row.agent_id,
                    source: row.source,
                    request_id: row.request_id,
                    uses: row.uses,
                    created_at: row.created_at,
                });
            }
        }
        Ok(out)
    }

    /// Reads a lease inside a write transaction, checks MAC and state, applies `change`, signs
    /// and commits. `owner` limits the change to the leases of one agent (release).
    async fn change_lease(
        &self,
        unlocked: &Unlocked,
        id: LeaseId,
        owner: Option<AgentId>,
        change: Change,
        now: Timestamp,
    ) -> Result<LeaseRow, CoreError> {
        let macs = unlocked.row_macs();
        let _gate = self.state().lease_gate.lock().await;
        let mut tx = self.service.store().begin().await?;
        let mut row = match tx.lease(id).await {
            Ok(row) => row,
            Err(StoreError::NotFound) => return Err(CoreError::NotFound),
            Err(error) => return Err(error.into()),
        };
        if owner.is_some_and(|agent| agent != row.agent_id) {
            return Err(CoreError::NotFound);
        }
        if !macs.verify_lease(&row)? {
            drop(tx);
            self.mac_alert(unlocked, "leases", id.to_string()).await;
            return Err(CoreError::Corrupt);
        }
        if !is_active(&row, now) {
            return Err(CoreError::Conflict);
        }
        match change {
            Change::Revoke(by) => {
                row.revoked_at = Some(whole_ms(now));
                row.revoked_by = Some(by);
            }
            Change::Release => row.released_at = Some(whole_ms(now)),
        }
        macs.sign_lease(&mut row)?;
        tx.put_lease(&row).await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Revokes one lease. Any role (ADR-0009: a viewer may revoke leases). The next check fails
    /// at once. For an auto lease it
    /// also blocks new auto leases for that agent and item until the old end (ADR-0019 point 7).
    ///
    /// # Errors
    /// `NotFound`, `Conflict` (not active), `Corrupt` (bad MAC), `Locked`, the role check, or a
    /// storage error.
    pub async fn revoke_lease(&self, ctx: &OperatorContext, id: LeaseId) -> Result<(), CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Viewer).await?;
        let unlocked: &Unlocked = &guard;
        let now = self.now();
        let by = format!("operator:{}", ctx.operator_id);
        let row = self
            .change_lease(unlocked, id, None, Change::Revoke(by), now)
            .await?;
        let event = AuditEvent::new(
            EventType::LeaseRevoke,
            Actor::operator(ctx.operator_id.to_string()),
        )
        .request_id(ctx.request_id)
        .target("lease", id.to_string())
        .detail("agent_id", row.agent_id.to_string())
        .detail("item_id", row.item_id.to_string());
        self.service.audit(unlocked, event).await;
        self.service.emit(CoreEvent::LeaseChanged(id));
        Ok(())
    }

    /// Revokes every lease that is not released or revoked, without locking (the Leases screen).
    /// Any role (ADR-0009).
    /// The panic button is `KeyCustody::panic_lock`, which also cancels requests and locks.
    /// Returns the number of rows changed: every lease not released or revoked, also ended ones.
    ///
    /// # Errors
    /// `Locked`, the role check, or a storage error.
    pub async fn revoke_all_leases(&self, ctx: &OperatorContext) -> Result<u64, CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Viewer).await?;
        let unlocked: &Unlocked = &guard;
        let now = self.now();
        let _gate = self.state().lease_gate.lock().await;
        // Only for the change events: a row that cannot be read must not stop the revoke (NEW-3).
        let live: Vec<LeaseId> = match self.service.store().live_leases(now).await {
            Ok(rows) => rows.iter().map(|row| row.id).collect(),
            Err(error) => {
                tracing::warn!(%error, "could not list the live leases before revoke-all");
                Vec::new()
            }
        };
        let by = format!("operator:{}", ctx.operator_id);
        let mut tx = self.service.store().begin().await?;
        let report = tx
            .revoke_all_leases(whole_ms(now), &by, &unlocked.row_macs())
            .await?;
        tx.commit().await?;
        let count = report.revoked;
        for id in report.bad_mac {
            self.service
                .integrity_issue(unlocked, "leases", id.to_string())
                .await;
        }
        self.service
            .unreadable_rows(unlocked, "leases", report.malformed)
            .await;
        let event = AuditEvent::new(
            EventType::LeaseRevoke,
            Actor::operator(ctx.operator_id.to_string()),
        )
        .request_id(ctx.request_id)
        .detail("all", true)
        .detail("count", count);
        self.service.audit(unlocked, event).await;
        for id in live {
            self.service.emit(CoreEvent::LeaseChanged(id));
        }
        Ok(count)
    }

    /// `POST /v1/leases/{id}/release` (agent). A lease of another agent is `NotFound`.
    ///
    /// # Errors
    /// `NotFound`, `Conflict` (not active), `Locked`, or a storage error. A bad MAC is `NotFound`.
    pub async fn release_lease(
        &self,
        ctx: &AgentContext,
        id: LeaseId,
    ) -> Result<ReleaseOutcome, CoreError> {
        let guard = self.service.unlocked().await?;
        let unlocked: &Unlocked = &guard;
        let now = self.now();
        let row = match self
            .change_lease(unlocked, id, Some(ctx.agent_id), Change::Release, now)
            .await
        {
            Err(CoreError::Corrupt) => return Err(CoreError::NotFound),
            other => other?,
        };
        let released_at = row.released_at.unwrap_or(now);
        let event = by_agent(EventType::LeaseRelease, ctx)
            .target("lease", id.to_string())
            .detail("item_id", row.item_id.to_string());
        self.service.audit(unlocked, event).await;
        self.service.emit(CoreEvent::LeaseChanged(id));
        Ok(ReleaseOutcome {
            lease_id: id,
            released_at,
        })
    }

    /// Writes `lease.expire` for leases whose end passed since the last scan. The scan mark is
    /// kept in memory and, after a scan that wrote events, in the sealed setting
    /// [`LEASE_EXPIRY_MARK_KEY`]. So the first scan of a new process (at unlock) starts where the
    /// last process stopped, and leases that ended while the process was down are reported too
    /// (DEC-WIRE6-6). Without a stored mark the scan starts at the Unix epoch.
    pub(crate) async fn report_lease_expiry(
        &self,
        unlocked: &Unlocked,
        now: Timestamp,
    ) -> Result<u64, CoreError> {
        // One scan at a time, so two runs never report the same range twice.
        let _gate = self.state().lease_gate.lock().await;
        let known = *self.mark();
        let from = match known {
            Some(mark) => mark,
            None => self.stored_expiry_mark(unlocked).await?,
        };
        *self.mark() = Some(now.max(from));
        if from >= now {
            return Ok(0);
        }
        let macs = unlocked.row_macs();
        let mut count = 0u64;
        for row in self
            .service
            .store()
            .leases_expired_between(from, now)
            .await?
        {
            if !macs.verify_lease(&row)? {
                self.mac_alert(unlocked, "leases", row.id.to_string()).await;
                continue;
            }
            let event = AuditEvent::new(EventType::LeaseExpire, Actor::system())
                .target("lease", row.id.to_string())
                .detail("agent_id", row.agent_id.to_string())
                .detail("item_id", row.item_id.to_string())
                .detail("uses", row.uses);
            self.service.audit(unlocked, event).await;
            self.service.emit(CoreEvent::LeaseChanged(row.id));
            count += 1;
        }
        if count > 0 {
            // Only a scan that wrote events moves the stored mark: a range without ended leases
            // can never get one later (a new lease always ends after its creation), so an older
            // stored mark only costs an empty rescan.
            self.store_expiry_mark(unlocked, now).await?;
        }
        Ok(count)
    }

    fn mark(&self) -> std::sync::MutexGuard<'_, Option<Timestamp>> {
        self.state()
            .expiry_mark
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The stored scan mark, or the Unix epoch. A row that does not open is an integrity issue;
    /// the scan then starts at the epoch (events may repeat, none is lost).
    async fn stored_expiry_mark(&self, unlocked: &Unlocked) -> Result<Timestamp, CoreError> {
        let row = match self.service.store().setting(LEASE_EXPIRY_MARK_KEY).await {
            Ok(row) => row,
            Err(StoreError::NotFound) => return Ok(Timestamp::UNIX_EPOCH),
            Err(error) => return Err(error.into()),
        };
        let parsed = unlocked
            .blobs()
            .open_setting(LEASE_EXPIRY_MARK_KEY, &row.value_ct)
            .ok()
            .and_then(|plain| serde_json::from_slice::<i64>(plain.expose_secret()).ok())
            .and_then(|ms| Timestamp::from_millisecond(ms).ok());
        if let Some(mark) = parsed {
            return Ok(mark);
        }
        self.mac_alert(unlocked, "settings", LEASE_EXPIRY_MARK_KEY.to_owned())
            .await;
        Ok(Timestamp::UNIX_EPOCH)
    }

    async fn store_expiry_mark(
        &self,
        unlocked: &Unlocked,
        mark: Timestamp,
    ) -> Result<(), CoreError> {
        let plain = serde_json::to_vec(&mark.as_millisecond()).map_err(|_| CoreError::Corrupt)?;
        let row = SettingRow {
            key: LEASE_EXPIRY_MARK_KEY.to_owned(),
            updated_at: whole_ms(mark),
            value_ct: unlocked
                .blobs()
                .seal_setting(LEASE_EXPIRY_MARK_KEY, &plain)?,
        };
        let mut tx = self.service.store().begin().await?;
        tx.put_setting(&row).await?;
        tx.commit().await?;
        Ok(())
    }
}
