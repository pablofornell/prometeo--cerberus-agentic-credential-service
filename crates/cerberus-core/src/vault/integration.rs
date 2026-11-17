//! Calls from the vault service into the audit log (T08) and the token table (T09).
//!
//! The audit writer lives inside [`Unlocked`] and holds a share of its key tree, so the lock that
//! drops `Unlocked` drops the writer and its `audit_key` with it. The token table lives in the
//! service: it is rebuilt without MAC checks at open (it only picks 401 or 423 while sealed) and
//! with MAC checks at unlock (ADR-0033 point 5).

use cerberus_store::{AUDIT_PENDING_CAP, AuditPendingRow};
use cerberus_types::ErrorCode;
use jiff::Timestamp;

use super::VaultService;
use super::events::CoreEvent;
use super::state::Unlocked;
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::{AgentContext, OperatorContext};
use crate::error::CoreError;

/// An event by the operator of `ctx`.
pub(crate) fn by_operator(event: EventType, ctx: &OperatorContext) -> AuditEvent {
    AuditEvent::new(event, Actor::operator(ctx.operator_id.to_string())).request_id(ctx.request_id)
}

impl VaultService {
    /// Appends one event to the chain and fails when the write fails. Secret reads use it: no
    /// secret leaves the vault without its audit event (ADR-0025).
    ///
    /// # Errors
    /// The audit write error.
    pub(crate) async fn audit_strict(
        &self,
        unlocked: &Unlocked,
        event: AuditEvent,
    ) -> Result<(), CoreError> {
        let result = unlocked.audit.append(&event).await.map(|_| ());
        self.report_audit_break(unlocked);
        result
    }

    /// Appends one event to the chain. A failure is logged and the action goes on: only a secret
    /// read must fail with its audit write (ADR-0025).
    pub(crate) async fn audit(&self, unlocked: &Unlocked, event: AuditEvent) {
        if let Err(error) = unlocked.audit.append(&event).await {
            tracing::warn!(%error, event = %event.event_type, "audit write failed");
        }
        self.report_audit_break(unlocked);
    }

    /// Raises the integrity alert when the writer found a changed audit head or a cut log and
    /// chained a break mark (AUD-1). The mark itself is the `integrity.row_mac_mismatch` event.
    pub(crate) fn report_audit_break(&self, unlocked: &Unlocked) {
        if let Some(seq) = unlocked.audit.take_break() {
            self.emit(CoreEvent::IntegrityAlert {
                table: "audit_head",
                row_id: seq.to_string(),
            });
        }
    }

    /// Writes a minimal event to `audit_pending` (no key needed). It joins the chain at the next unlock.
    pub(super) async fn audit_pending(
        &self,
        event: EventType,
        agent: Option<&AgentContext>,
        target_id: Option<String>,
        code: ErrorCode,
        route: Option<&'static str>,
    ) {
        let row = AuditPendingRow {
            occurred_at: self.inner.clock.now(),
            event_type: event.as_str().to_owned(),
            agent_id: agent.map(|ctx| ctx.agent_id),
            target_id,
            result_code: code.as_str().to_owned(),
            route: route.map(str::to_owned),
            request_id: agent.map(|ctx| ctx.request_id),
        };
        if let Err(error) = self
            .inner
            .store
            .push_audit_pending(&row, AUDIT_PENDING_CAP)
            .await
        {
            tracing::warn!(%error, "pending audit write failed");
        }
    }

    /// Writes `backup.recover` to `audit_pending` (no key needed) after the desktop put a vault
    /// file left by a failed restore back in place (T27-G). The vault is sealed at that moment, so
    /// the event joins the chain at the next unlock. It holds no path and no secret.
    ///
    /// The row is also the marker for the revoke at that unlock: every agent key and lease of the
    /// vault is revoked before it serves a call (T27-H, NEW-12). So it is written even when the
    /// pending list is full (the cap does not apply to it), and a failed write is returned: the
    /// caller must then not leave the vault in place.
    ///
    /// # Errors
    /// A storage error.
    pub async fn record_stranded_recovery(&self) -> Result<(), CoreError> {
        let row = AuditPendingRow {
            occurred_at: self.inner.clock.now(),
            event_type: EventType::BackupRecover.as_str().to_owned(),
            agent_id: None,
            target_id: None,
            result_code: "ok".to_owned(),
            route: None,
            request_id: None,
        };
        self.inner.store.push_audit_pending(&row, u32::MAX).await?;
        Ok(())
    }

    /// Records a refused agent call (ADR-0008 point 5): in `audit_pending` while locked, in the
    /// chain while unlocked.
    pub async fn audit_locked_call(
        &self,
        ctx: Option<&AgentContext>,
        route: &'static str,
        code: ErrorCode,
    ) {
        if let Ok(guard) = self.unlocked().await {
            let actor = ctx.map_or_else(Actor::system, |c| Actor::agent(c.agent_id.to_string()));
            let mut event = AuditEvent::new(EventType::ApiLockedCall, actor)
                .result(code.as_str())
                .detail("route", route);
            if let Some(c) = ctx {
                event = event.request_id(c.request_id);
            }
            self.audit(&guard, event).await;
            return;
        }
        self.audit_pending(EventType::ApiLockedCall, ctx, None, code, Some(route))
            .await;
    }

    /// Rebuilds the token table from the DB without MAC checks (no key while sealed).
    pub(super) async fn rebuild_auth_unverified(&self, now: Timestamp) -> Result<(), CoreError> {
        let (agents, keys) = self.inner.store.load_auth_rows().await?;
        self.inner.auth.rebuild(&agents, &keys, None, now)?;
        Ok(())
    }

    /// Rebuilds the token table with row MAC checks. A row with a bad MAC counts as revoked, raises an
    /// integrity alert and writes `integrity.row_mac_mismatch` to the chain (ADR-0033 point 5).
    pub(super) async fn rebuild_auth_verified(
        &self,
        unlocked: &Unlocked,
        now: Timestamp,
    ) -> Result<(), CoreError> {
        let (agents, keys) = self.inner.store.load_auth_rows().await?;
        let issues = self
            .inner
            .auth
            .rebuild(&agents, &keys, Some(&unlocked.row_macs()), now)?;
        for issue in issues {
            tracing::warn!(table = issue.table, row_id = %issue.row_id, "row MAC mismatch");
            self.integrity_issue(unlocked, issue.table, issue.row_id)
                .await;
        }
        Ok(())
    }

    /// A row that failed its MAC or whose sealed blob failed to open: writes
    /// `integrity.row_mac_mismatch` to the chain and raises the UI alert (ADR-0033).
    pub(crate) async fn integrity_issue(
        &self,
        unlocked: &Unlocked,
        table: &'static str,
        row_id: String,
    ) {
        let event = AuditEvent::new(EventType::IntegrityRowMacMismatch, Actor::system())
            .target(table, row_id.clone())
            .result("vault_corrupt");
        self.audit(unlocked, event).await;
        self.emit(CoreEvent::IntegrityAlert { table, row_id });
    }
}
