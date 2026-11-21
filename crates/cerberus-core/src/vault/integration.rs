//! Calls from the vault service into the audit log (T08) and the token table (T09).
//!
//! The audit writer lives inside [`Unlocked`] and holds a share of its key tree, so the lock that
//! drops `Unlocked` drops the writer and its `audit_key` with it. The token table lives in the
//! service: it is rebuilt without MAC checks at open (it only picks 401 or 423 while sealed) and
//! with MAC checks at unlock (ADR-0033 point 5).

use cerberus_store::{AUDIT_PENDING_CAP, AuditPendingRow};
use cerberus_types::{ErrorCode, OperatorId};
use jiff::Timestamp;

use super::VaultService;
use super::events::CoreEvent;
use super::state::Unlocked;
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::{AgentContext, OperatorContext};
use crate::error::CoreError;

/// The kind of an admin API event of `cerberusd` (ADR-0034).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminEventKind {
    /// The daemon started with the admin API on (`admin.api_start`).
    ApiStart,
    /// An enrolled desktop opened a session (`admin.session_open`).
    SessionOpen,
    /// A session ended (`admin.session_close`).
    SessionClose,
    /// A desktop was enrolled (`admin.client_enroll`).
    ClientEnroll,
    /// An enrolment was revoked (`admin.client_revoke`).
    ClientRevoke,
}

impl AdminEventKind {
    /// The audit event type.
    #[must_use]
    pub const fn event_type(self) -> EventType {
        match self {
            Self::ApiStart => EventType::AdminApiStart,
            Self::SessionOpen => EventType::AdminSessionOpen,
            Self::SessionClose => EventType::AdminSessionClose,
            Self::ClientEnroll => EventType::AdminClientEnroll,
            Self::ClientRevoke => EventType::AdminClientRevoke,
        }
    }

    /// True for the kinds that can happen while the vault is sealed. They go to `audit_pending`
    /// then and join the chain at the next unlock.
    #[must_use]
    pub const fn written_while_sealed(self) -> bool {
        matches!(
            self,
            Self::ApiStart | Self::SessionClose | Self::ClientRevoke
        )
    }
}

/// Why an admin session ended (ADR-0034 point 6.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionCloseReason {
    /// The desktop closed it.
    Closed,
    /// Past its idle limit.
    Idle,
    /// Past its absolute limit.
    Max,
    /// The vault was locked or unlocked again.
    Lock,
    /// Its enrolment was revoked.
    Revoked,
}

impl SessionCloseReason {
    /// The text in `details.reason`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Idle => "idle",
            Self::Max => "max",
            Self::Lock => "lock",
            Self::Revoked => "revoked",
        }
    }
}

/// One admin API event for the audit log. It holds IDs and labels only: never a phrase, a token,
/// a certificate or a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminAudit {
    /// What happened.
    pub kind: AdminEventKind,
    /// The enrolment ID (the target, kind `admin_client`).
    pub enrolment: Option<String>,
    /// The enrolment label.
    pub label: Option<String>,
    /// The operator the enrolment is bound to.
    pub operator: Option<OperatorId>,
    /// Why a session ended.
    pub reason: Option<SessionCloseReason>,
    /// For a session open: true when it unlocked a sealed vault.
    pub unlocked: Option<bool>,
}

impl AdminAudit {
    /// An event of `kind` with no target and no details.
    #[must_use]
    pub const fn new(kind: AdminEventKind) -> Self {
        Self {
            kind,
            enrolment: None,
            label: None,
            operator: None,
            reason: None,
            unlocked: None,
        }
    }

    fn into_event(self, ctx: Option<&OperatorContext>) -> AuditEvent {
        let kind = self.kind.event_type();
        let mut event = match ctx {
            Some(ctx) => by_operator(kind, ctx),
            None => AuditEvent::new(kind, Actor::system()),
        };
        if let Some(enrolment) = self.enrolment {
            event = event.target("admin_client", enrolment);
        }
        if let Some(label) = self.label {
            event = event.detail("label", label);
        }
        if let Some(operator) = self.operator {
            event = event.detail("operator", operator.to_string());
        }
        if let Some(reason) = self.reason {
            event = event.detail("reason", reason.as_str());
        }
        if let Some(unlocked) = self.unlocked {
            event = event.detail("unlocked", unlocked);
        }
        event
    }
}

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

    /// Records an admin API event (ADR-0034): in the chain while unlocked, with the operator of
    /// `ctx` as the actor (else `system`). While sealed, the kinds of
    /// [`AdminEventKind::written_while_sealed`] go to `audit_pending` with the enrolment as the
    /// target; their details are not kept there (the pending row has no room for them).
    ///
    /// # Errors
    /// [`CoreError::Locked`] for another kind while sealed, or the storage error of the pending
    /// write. A failed chain write is logged and not returned, as for other operator actions.
    pub async fn record_admin_event(
        &self,
        ctx: Option<&OperatorContext>,
        event: AdminAudit,
    ) -> Result<(), CoreError> {
        if let Ok(guard) = self.unlocked().await {
            self.audit(&guard, event.into_event(ctx)).await;
            return Ok(());
        }
        if !event.kind.written_while_sealed() {
            return Err(CoreError::Locked);
        }
        let row = AuditPendingRow {
            occurred_at: self.inner.clock.now(),
            event_type: event.kind.event_type().as_str().to_owned(),
            agent_id: None,
            target_id: event.enrolment,
            result_code: "ok".to_owned(),
            route: None,
            request_id: ctx.map(|ctx| ctx.request_id),
        };
        self.inner
            .store
            .push_audit_pending(&row, AUDIT_PENDING_CAP)
            .await?;
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
