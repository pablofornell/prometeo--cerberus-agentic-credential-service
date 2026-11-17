//! Agent side of the queue: create, dedupe, read, wait, and the timeout sweep.

use std::time::Duration;

use cerberus_store::{AccessRequestRow, StoreError};
use cerberus_types::{AccessRequestId, AccessRequestStatus, FieldProblem, OperatorId, Permission};
use jiff::{SignedDuration, Timestamp};

use super::{AccessRequestView, CreateAccess, clean_reason, is_terminal, status_text};
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::index::ItemMeta;
use crate::leases::{self, LeaseCheck, LeaseView};
use crate::policy::engine::{
    agent_grants, by_agent, decision_error, item_live, permission_text, whole_ms,
};
use crate::policy::{Decision, EvalInput, PolicyEngine, PolicyItem, PolicySettings, evaluate};
use crate::vault::{CoreEvent, Unlocked};

/// What one run of [`PolicyEngine::expire_due`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExpiryReport {
    /// Pending requests set to `expired`.
    pub requests_expired: u64,
    /// Leases whose end time passed since the last run (`lease.expire` written).
    pub leases_expired: u64,
}

/// How often a waiting call checks the row again, besides the events.
const WAIT_TICK: Duration = Duration::from_secs(1);
/// How often the background loop runs the timeout sweep (ADR-0022 point 4).
pub const EXPIRY_PERIOD: Duration = Duration::from_secs(1);

fn ttl_problem() -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: "ttl_seconds".to_owned(),
        problem: "must be 60 to 86400".to_owned(),
    }])
}

impl PolicyEngine {
    /// Reads one request row and checks its MAC. A bad MAC gives an alert and `Corrupt`: the
    /// request then counts as not approved (ADR-0033 point 5).
    pub(crate) async fn verified_request(
        &self,
        unlocked: &Unlocked,
        id: AccessRequestId,
    ) -> Result<AccessRequestRow, CoreError> {
        let row = self.service.store().access_request(id).await?;
        if unlocked.row_macs().verify_access_request(&row)? {
            Ok(row)
        } else {
            self.mac_alert(unlocked, "access_requests", id.to_string())
                .await;
            Err(CoreError::Corrupt)
        }
    }

    /// MAC-checked pending rows (bad rows are dropped with an alert).
    pub(crate) async fn verified_pending(
        &self,
        unlocked: &Unlocked,
    ) -> Result<Vec<AccessRequestRow>, CoreError> {
        let rows = self.service.store().pending_access_requests().await?;
        let macs = unlocked.row_macs();
        let mut good = Vec::with_capacity(rows.len());
        for row in rows {
            if macs.verify_access_request(&row)? {
                good.push(row);
            } else {
                self.mac_alert(unlocked, "access_requests", row.id.to_string())
                    .await;
            }
        }
        Ok(good)
    }

    /// Moves a pending request to a terminal state (not `approved`, see `approve_request`).
    ///
    /// The row is read again inside one write transaction, its MAC checked, and it must still be
    /// `pending`; so a deny, an expiry and a lock cancel can never undo each other.
    ///
    /// # Errors
    /// [`CoreError::Conflict`] when the request is no longer pending, `Corrupt` for a bad MAC.
    pub(crate) async fn finish_request(
        &self,
        unlocked: &Unlocked,
        id: AccessRequestId,
        status: AccessRequestStatus,
        now: Timestamp,
        by: Option<OperatorId>,
    ) -> Result<AccessRequestRow, CoreError> {
        let macs = unlocked.row_macs();
        let mut tx = self.service.store().begin().await?;
        let mut row = tx.access_request(id).await?;
        if !macs.verify_access_request(&row)? {
            drop(tx);
            self.mac_alert(unlocked, "access_requests", id.to_string())
                .await;
            return Err(CoreError::Corrupt);
        }
        if row.status != AccessRequestStatus::Pending {
            return Err(CoreError::Conflict);
        }
        row.status = status;
        row.decided_at = Some(whole_ms(now));
        row.decided_by = by;
        macs.sign_access_request(&mut row)?;
        tx.put_access_request(&row).await?;
        tx.commit().await?;
        let event_type = match status {
            AccessRequestStatus::Expired => EventType::RequestExpire,
            AccessRequestStatus::Denied => EventType::RequestDeny,
            AccessRequestStatus::Approved => EventType::RequestApprove,
            AccessRequestStatus::Cancelled | AccessRequestStatus::Pending => {
                EventType::RequestCancel
            }
        };
        let actor = by.map_or_else(Actor::system, |op| Actor::operator(op.to_string()));
        let event = AuditEvent::new(event_type, actor)
            .target("request", row.id.to_string())
            .detail("agent_id", row.agent_id.to_string())
            .detail("item_id", row.item_id.to_string())
            .detail("status", status_text(status));
        self.service.audit(unlocked, event).await;
        self.service
            .emit(CoreEvent::AccessRequestResolved { id: row.id, status });
        Ok(row)
    }

    /// Sets a pending request to `expired`. Returns false when another change won the race (the
    /// request was decided or cancelled first); that is not an error.
    pub(crate) async fn expire_quietly(
        &self,
        unlocked: &Unlocked,
        id: AccessRequestId,
        now: Timestamp,
    ) -> Result<bool, CoreError> {
        match self
            .finish_request(unlocked, id, AccessRequestStatus::Expired, now, None)
            .await
        {
            Ok(_) => Ok(true),
            Err(CoreError::Conflict) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The view of a row; for an approved row it adds the lease when its MAC is good.
    pub(crate) async fn view_of(
        &self,
        unlocked: &Unlocked,
        row: &AccessRequestRow,
    ) -> Result<AccessRequestView, CoreError> {
        let lease = match row.lease_id {
            Some(id) if row.status == AccessRequestStatus::Approved => {
                match self.service.store().lease(id).await {
                    Ok(lease) if unlocked.row_macs().verify_lease(&lease)? => {
                        Some(LeaseView::of(&lease))
                    }
                    Ok(_) => {
                        self.mac_alert(unlocked, "leases", id.to_string()).await;
                        None
                    }
                    Err(StoreError::NotFound) => None,
                    Err(error) => return Err(error.into()),
                }
            }
            _ => None,
        };
        Ok(AccessRequestView::of(row, lease))
    }

    /// Creates a request (or returns the pending one) after the policy said "ask". The caller
    /// holds the guard, has checked policy, and holds `request_gate` since before its lease
    /// check, so an approval cannot land between the lease check and the pending check
    /// (AUD-22, DEC-T24-5).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_request(
        &self,
        _request_gate: &tokio::sync::MutexGuard<'_, ()>,
        unlocked: &Unlocked,
        ctx: &AgentContext,
        meta: &ItemMeta,
        permission: Permission,
        reason: Option<&str>,
        ttl_seconds: Option<u32>,
        settings: &PolicySettings,
        now: Timestamp,
    ) -> Result<AccessRequestView, CoreError> {
        let item_id = meta.id;
        if ttl_seconds.is_some_and(|ttl| !(60..=86_400).contains(&ttl)) {
            return Err(ttl_problem());
        }
        if !self.service.config().approvals_available {
            let error = CoreError::ApprovalUnavailable;
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    item_id,
                    permission,
                    "approval_unavailable",
                    None,
                    error,
                )
                .await);
        }
        // Deny cool-down (ADR-0018 rule 3).
        let cooldown = SignedDuration::from_secs(i64::from(settings.deny_cooldown_seconds));
        let history = self
            .service
            .store()
            .access_requests_for(ctx.agent_id, item_id)
            .await?;
        let macs = unlocked.row_macs();
        for row in &history {
            let recent_deny = row.status == AccessRequestStatus::Denied
                && row
                    .decided_at
                    .is_some_and(|at| now < at.saturating_add(cooldown).unwrap_or(at));
            if recent_deny {
                if macs.verify_access_request(row)? {
                    let error = CoreError::ApprovalDenied(Some(row.id));
                    return Err(self
                        .refuse(
                            unlocked,
                            ctx,
                            item_id,
                            permission,
                            "deny_cooldown",
                            None,
                            error,
                        )
                        .await);
                }
                self.mac_alert(unlocked, "access_requests", row.id.to_string())
                    .await;
            }
        }
        // Lazy timeout of old pending rows, then dedupe and the cap (rules 1 and 2).
        let mut live = Vec::new();
        for row in self.verified_pending(unlocked).await? {
            if row.expires_at <= now {
                self.expire_quietly(unlocked, row.id, now).await?;
            } else if row.agent_id == ctx.agent_id {
                live.push(row);
            }
        }
        if let Some(row) = live
            .iter()
            .find(|r| r.item_id == item_id && r.permission == permission)
        {
            return self.view_of(unlocked, row).await;
        }
        let max_pending = usize::try_from(settings.max_pending_per_agent).unwrap_or(usize::MAX);
        if live.len() >= max_pending {
            let soonest = live.iter().map(|r| r.expires_at).min().unwrap_or(now);
            let wait = soonest.duration_since(now).as_secs().max(1);
            let error = CoreError::RateLimited {
                retry_after_seconds: u32::try_from(wait).unwrap_or(u32::MAX),
            };
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    item_id,
                    permission,
                    "pending_cap",
                    None,
                    error,
                )
                .await);
        }
        if let Err(retry_after_seconds) =
            self.state()
                .limiter
                .record_request(&ctx.agent_id, now, settings)
        {
            let error = CoreError::RateLimited {
                retry_after_seconds,
            };
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    item_id,
                    permission,
                    "request_rate",
                    None,
                    error,
                )
                .await);
        }
        let id = AccessRequestId::generate();
        let reason_ct = match reason.map(clean_reason).filter(|r| !r.is_empty()) {
            Some(text) => Some(unlocked.blobs().seal_request_reason(&id, text.as_bytes())?),
            None => None,
        };
        let timeout = SignedDuration::from_secs(i64::from(settings.approval_timeout_seconds));
        let mut row = AccessRequestRow {
            id,
            agent_id: ctx.agent_id,
            item_id,
            permission,
            status: AccessRequestStatus::Pending,
            requested_ttl_seconds: ttl_seconds,
            created_at: whole_ms(now),
            expires_at: whole_ms(now.saturating_add(timeout).unwrap_or(now)),
            decided_at: None,
            decided_by: None,
            approval_option: None,
            lease_id: None,
            request_id: ctx.request_id,
            reason_ct,
            row_mac: [0; 32],
        };
        macs.sign_access_request(&mut row)?;
        let mut tx = self.service.store().begin().await?;
        tx.put_access_request(&row).await?;
        tx.commit().await?;
        let event = by_agent(EventType::RequestCreate, ctx)
            .target("request", id.to_string())
            .detail("item_id", item_id.to_string())
            .detail("permission", permission_text(permission))
            .detail(
                "environment",
                serde_json::to_value(meta.environment).unwrap_or_default(),
            )
            .detail("expires_at_ms", row.expires_at.as_millisecond());
        self.service.audit(unlocked, event).await;
        self.service.emit(CoreEvent::AccessRequestCreated(id));
        Ok(AccessRequestView::of(&row, None))
    }

    /// `POST /v1/requests`: ask before the secret is needed (ADR-0018).
    ///
    /// # Errors
    /// As [`Self::authorize_secret`], plus [`CoreError::Conflict`] when no approval is needed
    /// (mode `auto`, or an approved lease is active): the agent calls the secret route.
    pub async fn request_access(
        &self,
        ctx: &AgentContext,
        req: CreateAccess,
    ) -> Result<AccessRequestView, CoreError> {
        let guard = self.service.unlocked().await?;
        let unlocked: &Unlocked = &guard;
        let now = self.now();
        let permission = req.permission;
        if !crate::policy::is_secret_permission(permission) {
            return Err(CoreError::Validation(vec![FieldProblem {
                field: "permission".to_owned(),
                problem: "must be read or use_ssh".to_owned(),
            }]));
        }
        let settings = self.settings_in(unlocked).await;
        let grants = agent_grants(&unlocked.index, &ctx.agent_id);
        let Some(meta) = unlocked
            .index
            .item(&req.item_id)
            .filter(|m| item_live(m, now))
        else {
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    req.item_id,
                    permission,
                    "not_found",
                    None,
                    CoreError::NotFound,
                )
                .await);
        };
        let item = PolicyItem::of(meta);
        let peek = crate::policy::limits::Peek(&self.state().limiter);
        let find = evaluate(
            &EvalInput {
                grants: &grants,
                item,
                permission: Permission::Find,
                reason: None,
                now,
            },
            &ctx.agent_id,
            &peek,
        );
        if !find.is_allow() {
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    req.item_id,
                    permission,
                    find.as_str(),
                    find.grant_id(),
                    CoreError::NotFound,
                )
                .await);
        }
        let decision = evaluate(
            &EvalInput {
                grants: &grants,
                item,
                permission,
                reason: Some(&req.reason),
                now,
            },
            &ctx.agent_id,
            &peek,
        );
        let Decision::Allow { mode, .. } = decision else {
            let error = decision_error(&decision);
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    req.item_id,
                    permission,
                    decision.as_str(),
                    decision.grant_id(),
                    error,
                )
                .await);
        };
        // The gate is held from the lease check to the pending check: an approval takes it too,
        // so it lands before the lease check or after the request is looked up (AUD-22).
        let gate = self.state().request_gate.lock().await;
        let rows = self
            .verified_leases(unlocked, ctx.agent_id, req.item_id)
            .await?;
        // The same lease view as the read path: a session approval of an earlier unlock is over.
        let rows = self.drop_old_session_leases(unlocked, rows, now).await?;
        match leases::check(&rows, mode, permission, now, None) {
            LeaseCheck::NeedApproval => {}
            LeaseCheck::Active(_) | LeaseCheck::NewAuto => return Err(CoreError::Conflict),
            LeaseCheck::Blocked { .. } => {
                return Err(self
                    .refuse(
                        unlocked,
                        ctx,
                        req.item_id,
                        permission,
                        "lease_revoked",
                        None,
                        CoreError::Forbidden,
                    )
                    .await);
            }
        }
        self.open_request(
            &gate,
            unlocked,
            ctx,
            meta,
            permission,
            Some(&req.reason),
            req.ttl_seconds,
            &settings,
            now,
        )
        .await
    }

    /// `GET /v1/requests/{id}`. A request of another agent is `NotFound`. A pending request past
    /// its time is set to `expired` here, so the result never depends on the background loop.
    ///
    /// # Errors
    /// `NotFound`, `Corrupt` (bad row MAC), `Locked`, or a storage error.
    pub async fn get_access_request(
        &self,
        ctx: &AgentContext,
        id: AccessRequestId,
    ) -> Result<AccessRequestView, CoreError> {
        let guard = self.service.unlocked().await?;
        let unlocked: &Unlocked = &guard;
        let row = match self.verified_request(unlocked, id).await {
            Ok(row) if row.agent_id == ctx.agent_id => row,
            Ok(_) | Err(CoreError::Store(StoreError::NotFound)) => return Err(CoreError::NotFound),
            Err(error) => return Err(error),
        };
        let now = self.now();
        let row = if row.status == AccessRequestStatus::Pending && row.expires_at <= now {
            let _gate = self.state().request_gate.lock().await;
            self.expire_quietly(unlocked, row.id, now).await?;
            self.verified_request(unlocked, id).await?
        } else {
            row
        };
        self.view_of(unlocked, &row).await
    }

    /// Waits up to `max_wait` (capped at 120 s) for the request to reach a terminal state, then
    /// returns its view (still `pending` when the wait ran out). The vault guard is held only
    /// while the row is read, never while waiting.
    ///
    /// A lock cancels pending requests and sends `AccessRequestResolved` for each before the keys
    /// go. When the row can no longer be read (sealed), the wait returns the last view with that
    /// terminal status, so an SSE stream ends with a final `cancelled` event (ADR-0026).
    ///
    /// # Errors
    /// As [`Self::get_access_request`]; `Locked` when the vault locks during the wait and no
    /// terminal event for this request arrived.
    pub async fn wait_access_request(
        &self,
        ctx: &AgentContext,
        id: AccessRequestId,
        max_wait: Duration,
    ) -> Result<AccessRequestView, CoreError> {
        let max_wait = max_wait.min(Duration::from_secs(super::MAX_WAIT_SECONDS));
        let mut events = self.service.subscribe();
        let mut last = self.get_access_request(ctx, id).await?;
        let wait = async {
            loop {
                if is_terminal(last.status) {
                    return Ok(last.clone());
                }
                // Wake on any event (a decision, a lock) or after one tick, then read again.
                let resolved = match tokio::time::timeout(WAIT_TICK, events.recv()).await {
                    Ok(Ok(CoreEvent::AccessRequestResolved { id: got, status })) if got == id => {
                        Some(status)
                    }
                    Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                        return Err(CoreError::Locked);
                    }
                    _ => None,
                };
                match self.get_access_request(ctx, id).await {
                    Ok(view) => last = view,
                    Err(CoreError::Locked) => {
                        let Some(status) = resolved.filter(|s| is_terminal(*s)) else {
                            return Err(CoreError::Locked);
                        };
                        last.status = status;
                        last.decided_at = Some(whole_ms(self.now()));
                        return Ok(last.clone());
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        match tokio::time::timeout(max_wait, wait).await {
            Ok(result) => result,
            Err(_) => self.get_access_request(ctx, id).await,
        }
    }

    /// One run of the timeout sweep (ADR-0022 point 4): pending requests past their time become
    /// `expired`, and leases whose end passed since the last run get `lease.expire`. Does nothing
    /// while locked.
    ///
    /// # Errors
    /// A storage error. `Locked` is not an error here: it gives an empty report.
    pub async fn expire_due(&self, now: Timestamp) -> Result<ExpiryReport, CoreError> {
        let Ok(guard) = self.service.unlocked().await else {
            return Ok(ExpiryReport::default());
        };
        let unlocked: &Unlocked = &guard;
        let mut report = ExpiryReport::default();
        {
            let _gate = self.state().request_gate.lock().await;
            for row in self.verified_pending(unlocked).await? {
                if row.expires_at <= now && self.expire_quietly(unlocked, row.id, now).await? {
                    report.requests_expired += 1;
                }
            }
        }
        report.leases_expired = self.report_lease_expiry(unlocked, now).await?;
        Ok(report)
    }

    /// Starts the background loop that runs [`Self::expire_due`] every second.
    #[must_use]
    pub fn spawn_expiry_loop(&self) -> tokio::task::JoinHandle<()> {
        let engine = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(EXPIRY_PERIOD);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let now = engine.now();
                if let Err(error) = engine.expire_due(now).await {
                    tracing::warn!(%error, "approval expiry sweep failed");
                }
            }
        })
    }
}
