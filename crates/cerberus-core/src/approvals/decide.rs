//! Operator side of the queue: the pending list, approve and deny (ADR-0018, ADR-0009).

use std::collections::HashMap;

use cerberus_store::{LeaseRow, LeaseSource};
use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, ApprovalOption, LeaseId, OperatorRole,
};
use jiff::SignedDuration;
use serde::Deserialize;

use super::{AccessRequestDetail, AccessRequestView, BURST_WARNING_ABOVE, clean_reason};
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::leases::{self, LeaseView};
use crate::policy::engine::{agent_grants, permission_text, whole_ms};
use crate::policy::limits::Peek;
use crate::policy::{Decision, EvalInput, PolicyEngine, PolicyItem, evaluate, reason_present};
use crate::vault::{CoreEvent, Unlocked};

/// Upper bound of an "approve for the session" lease (ADR-0018: 8 h). The item setting
/// `session_ttl_max_seconds` can make it shorter.
pub const SESSION_APPROVAL_CAP_SECONDS: u32 = 8 * 3600;

/// The part of the agent metadata the window needs. Other fields are ignored.
#[derive(Deserialize)]
struct AgentName {
    name: String,
}

fn approval_text(option: ApprovalOption) -> &'static str {
    match option {
        ApprovalOption::Once => "once",
        ApprovalOption::Minutes15 => "minutes_15",
        ApprovalOption::Session => "session",
    }
}

impl PolicyEngine {
    /// Agent names by ID (decrypted agent metadata). A row that does not open shows its ID.
    pub(crate) async fn agent_names(
        &self,
        unlocked: &Unlocked,
    ) -> Result<HashMap<AgentId, String>, CoreError> {
        let (agents, _) = self.service.store().load_auth_rows().await?;
        let blobs = unlocked.blobs();
        Ok(agents
            .iter()
            .map(|row| {
                let name = blobs
                    .open_agent_meta(&row.id, &row.meta_ct)
                    .ok()
                    .and_then(|plain| {
                        serde_json::from_slice::<AgentName>(plain.expose_secret()).ok()
                    })
                    .map_or_else(|| row.id.to_string(), |meta| meta.name);
                (row.id, name)
            })
            .collect())
    }

    /// The reason text of a request, cleaned. Empty when there is none or it does not open.
    fn reason_text(unlocked: &Unlocked, id: &AccessRequestId, ct: Option<&[u8]>) -> String {
        ct.and_then(|ct| unlocked.blobs().open_request_reason(id, ct).ok())
            .and_then(|plain| {
                std::str::from_utf8(plain.expose_secret())
                    .ok()
                    .map(clean_reason)
            })
            .unwrap_or_default()
    }

    /// The pending requests for the approval window, oldest first. Any role may read the list.
    ///
    /// # Errors
    /// `Locked`, the role check, or a storage error.
    pub async fn pending_requests(
        &self,
        ctx: &OperatorContext,
    ) -> Result<Vec<AccessRequestDetail>, CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Viewer).await?;
        let unlocked: &Unlocked = &guard;
        let now = self.now();
        let names = self.agent_names(unlocked).await?;
        let mut out = Vec::new();
        for row in self.verified_pending(unlocked).await? {
            if row.expires_at <= now {
                continue;
            }
            let Some(meta) = unlocked.index.item(&row.item_id) else {
                continue;
            };
            let workspace_name = unlocked
                .index
                .workspace(&meta.workspace_id)
                .map(|w| w.name.to_string())
                .unwrap_or_default();
            out.push(AccessRequestDetail {
                view: AccessRequestView::of(&row, None),
                agent_id: row.agent_id,
                agent_name: names
                    .get(&row.agent_id)
                    .cloned()
                    .unwrap_or_else(|| row.agent_id.to_string()),
                item_title: meta.title.to_string(),
                item_kind: meta.kind,
                role_label: meta.role_label.as_ref().map(|r| r.to_string()),
                workspace_name,
                environment: meta.environment,
                reason: Self::reason_text(unlocked, &row.id, row.reason_ct.as_deref()),
                burst_warning: self.state().limiter.recent_requests(&row.agent_id, now)
                    > BURST_WARNING_ABOVE,
            });
        }
        Ok(out)
    }

    /// Approves a pending request and makes its lease (ADR-0018 options, ADR-0019 point 5).
    /// Role operator or owner, from the unlocked session.
    ///
    /// Policy is checked again first: a grant that was removed or turned to `deny` since the
    /// request was made stops the approval. The request row is read again inside the write
    /// transaction and must still be `pending`, so approve, deny, timeout and a lock cancel
    /// cannot undo each other.
    ///
    /// # Errors
    /// `Conflict` (not pending any more, timed out, or policy no longer allows), `NotFound`,
    /// `Corrupt` (bad MAC), `Locked`, the role check, or a storage error.
    pub async fn approve_request(
        &self,
        ctx: &OperatorContext,
        id: AccessRequestId,
        option: ApprovalOption,
    ) -> Result<LeaseView, CoreError> {
        // Read the hard lock time before the guard: `status` takes the guard itself.
        let hard_lock_at = self.service.status().await.hard_lock_at;
        let guard = self.service.authorize(ctx, OperatorRole::Operator).await?;
        let unlocked: &Unlocked = &guard;
        let _gate = self.state().request_gate.lock().await;
        let now = self.now();
        let pre = self.verified_request(unlocked, id).await?;
        if pre.status != AccessRequestStatus::Pending {
            return Err(CoreError::Conflict);
        }
        if pre.expires_at <= now {
            self.expire_quietly(unlocked, id, now).await?;
            return Err(CoreError::Conflict);
        }
        let Some(meta) = unlocked.index.item(&pre.item_id) else {
            return Err(CoreError::NotFound);
        };
        let reason = Self::reason_text(unlocked, &pre.id, pre.reason_ct.as_deref());
        let grants = agent_grants(&unlocked.index, &pre.agent_id);
        let decision = evaluate(
            &EvalInput {
                grants: &grants,
                item: PolicyItem::of(meta),
                permission: pre.permission,
                reason: reason_present(Some(&reason)).then_some(reason.as_str()),
                now,
            },
            &pre.agent_id,
            &Peek(&self.state().limiter),
        );
        let Decision::Allow { mode, grant_id } = decision else {
            return Err(CoreError::Conflict);
        };
        let item_settings = self.service.load_item_settings(unlocked).await?;
        let session_max = SignedDuration::from_secs(i64::from(
            SESSION_APPROVAL_CAP_SECONDS.min(item_settings.session_ttl_max_seconds),
        ));
        let terms = leases::ttl_for(
            option,
            mode,
            session_max,
            meta.expires_at,
            now,
            hard_lock_at,
            pre.requested_ttl_seconds,
        );
        let macs = unlocked.row_macs();
        let mut tx = self.service.store().begin().await?;
        let mut row = tx.access_request(id).await?;
        if !macs.verify_access_request(&row)? {
            drop(tx);
            self.mac_alert(unlocked, "access_requests", id.to_string())
                .await;
            return Err(CoreError::Corrupt);
        }
        if row.status != AccessRequestStatus::Pending || row.expires_at <= now {
            return Err(CoreError::Conflict);
        }
        let mut lease = LeaseRow {
            id: LeaseId::generate(),
            agent_id: row.agent_id,
            item_id: row.item_id,
            permission: row.permission,
            source: LeaseSource::Approval,
            request_id: Some(row.id),
            created_at: whole_ms(now),
            expires_at: whole_ms(terms.expires_at),
            max_uses: terms.max_uses,
            uses: 0,
            released_at: None,
            revoked_at: None,
            revoked_by: None,
            row_mac: [0; 32],
        };
        macs.sign_lease(&mut lease)?;
        row.status = AccessRequestStatus::Approved;
        row.decided_at = Some(whole_ms(now));
        row.decided_by = Some(ctx.operator_id);
        row.approval_option = Some(option);
        row.lease_id = Some(lease.id);
        macs.sign_access_request(&mut row)?;
        tx.put_lease(&lease).await?;
        tx.put_access_request(&row).await?;
        tx.commit().await?;

        let actor = || Actor::operator(ctx.operator_id.to_string());
        let approve = AuditEvent::new(EventType::RequestApprove, actor())
            .request_id(ctx.request_id)
            .target("request", id.to_string())
            .detail("agent_id", row.agent_id.to_string())
            .detail("item_id", row.item_id.to_string())
            .detail("option", approval_text(option))
            .detail("grant_id", grant_id.to_string())
            .detail("lease_id", lease.id.to_string());
        self.service.audit(unlocked, approve).await;
        let mut create = AuditEvent::new(EventType::LeaseCreate, actor())
            .request_id(ctx.request_id)
            .target("lease", lease.id.to_string())
            .detail("agent_id", lease.agent_id.to_string())
            .detail("item_id", lease.item_id.to_string())
            .detail("source", "approval")
            .detail("permission", permission_text(lease.permission))
            .detail("expires_at_ms", lease.expires_at.as_millisecond());
        if let Some(max) = lease.max_uses {
            create = create.detail("max_uses", max);
        }
        self.service.audit(unlocked, create).await;
        self.service.emit(CoreEvent::AccessRequestResolved {
            id,
            status: AccessRequestStatus::Approved,
        });
        self.service.emit(CoreEvent::LeaseChanged(lease.id));
        Ok(LeaseView::of(&lease))
    }

    /// Denies a pending request and starts the deny cool-down. Role operator or owner.
    ///
    /// # Errors
    /// `Conflict` (not pending any more), `NotFound`, `Corrupt`, `Locked`, the role check, or a
    /// storage error.
    pub async fn deny_request(
        &self,
        ctx: &OperatorContext,
        id: AccessRequestId,
    ) -> Result<(), CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Operator).await?;
        let unlocked: &Unlocked = &guard;
        let _gate = self.state().request_gate.lock().await;
        let now = self.now();
        self.finish_request(
            unlocked,
            id,
            AccessRequestStatus::Denied,
            now,
            Some(ctx.operator_id),
        )
        .await
        .map_err(|error| match error {
            CoreError::Store(cerberus_store::StoreError::NotFound) => CoreError::NotFound,
            other => other,
        })?;
        Ok(())
    }
}
