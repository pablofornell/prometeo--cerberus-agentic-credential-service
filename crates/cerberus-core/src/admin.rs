//! Operator calls for the Tauri IPC commands (ADR-0003, `docs/interfaces.md` section 9) that had
//! no `VaultService` method yet, and thin `VaultService` methods over the policy engine, so the
//! desktop layer calls exactly one service method per command.
//!
//! Every method checks the role of the unlocked session (`VaultService::authorize` or
//! `Session::authorize`), never `OperatorContext.role` (DEC-T05-5).

mod audit_ops;
mod settings;
mod workspaces;

#[cfg(test)]
mod tests;

use cerberus_types::{
    AccessRequestId, AgentId, ApprovalOption, GrantId, ItemId, LeaseId, OperatorRole,
};

use crate::approvals::AccessRequestDetail;
use crate::audit::EventType;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::items::{RevealedItem, TotpCode};
use crate::leases::{LeaseDetail, LeaseView};
use crate::policy::{Grant, GrantInput, PolicySettings, SimulationRow};
use crate::vault::VaultService;

pub use audit_ops::{AuditEntry, AuditOutcome, AuditQuery, MAX_AUDIT_QUERY_LIMIT};
pub use settings::SettingsView;
pub use workspaces::{WorkspaceInput, WorkspaceView};

impl VaultService {
    /// The role check alone, for IPC commands that read no vault data but need a role
    /// (`password_generate`, `ssh_key_generate`, `ssh_key_import`, `agent_snippets`,
    /// `network_*`, `tls_*`, `csv_*`): it uses the session role.
    ///
    /// # Errors
    /// `Locked`, `Forbidden` (context of another session) or `RoleNotAllowed`.
    pub async fn authorize_role(
        &self,
        ctx: &OperatorContext,
        min: OperatorRole,
    ) -> Result<(), CoreError> {
        self.authorize(ctx, min).await.map(|_| ())
    }

    /// IPC `item_reveal` and `clipboard_copy_secret`: the payload for the operator, not counted
    /// as a use (ADR-0027). Role operator. Writes `item.reveal` with the operator as actor; the
    /// payload is returned only when that event is in the chain.
    ///
    /// # Errors
    /// `NotFound`, `Corrupt`, `Locked`, the role check, or the audit or storage error.
    pub async fn reveal_item(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
    ) -> Result<RevealedItem, CoreError> {
        let mut guard = self.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Operator)?;
        let revealed = self.read_payload_in(&mut guard, id, false).await?;
        let event = crate::vault::by_operator(EventType::ItemReveal, ctx)
            .target("item", id.to_string())
            .detail("surface", "ipc");
        self.audit_strict(&guard, event).await?;
        Ok(revealed)
    }

    /// IPC `item_totp_preview`: the current code. Role operator. Writes `item.totp`.
    ///
    /// # Errors
    /// `NotFound` (no item or no seed), `Locked`, the role check, or the audit error.
    pub async fn totp_preview(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
    ) -> Result<TotpCode, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let code = self.totp_code_in(&guard, id).await?;
        let event = crate::vault::by_operator(EventType::ItemTotp, ctx)
            .target("item", id.to_string())
            .detail("surface", "ipc");
        self.audit_strict(&guard, event).await?;
        Ok(code)
    }

    /// IPC `grant_list`. Any role.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::list_grants`].
    pub async fn list_grants(
        &self,
        ctx: &OperatorContext,
        agent: Option<AgentId>,
    ) -> Result<Vec<Grant>, CoreError> {
        self.policy().list_grants(ctx, agent).await
    }

    /// IPC `grant_put`. Operator; `allow_prod_auto` needs the owner.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::put_grant`].
    pub async fn put_grant(
        &self,
        ctx: &OperatorContext,
        input: GrantInput,
    ) -> Result<Grant, CoreError> {
        self.policy().put_grant(ctx, input).await
    }

    /// IPC `grant_delete`. Operator; a grant with `allow_prod_auto` needs the owner.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::delete_grant`].
    pub async fn delete_grant(&self, ctx: &OperatorContext, id: GrantId) -> Result<(), CoreError> {
        self.policy().delete_grant(ctx, id).await
    }

    /// IPC `policy_simulate`. Any role.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::simulate`].
    pub async fn simulate(
        &self,
        ctx: &OperatorContext,
        agent: AgentId,
    ) -> Result<Vec<SimulationRow>, CoreError> {
        self.policy().simulate(ctx, agent).await
    }

    /// IPC `request_list_pending`. Any role.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::pending_requests`].
    pub async fn pending_requests(
        &self,
        ctx: &OperatorContext,
    ) -> Result<Vec<AccessRequestDetail>, CoreError> {
        self.policy().pending_requests(ctx).await
    }

    /// IPC `request_approve`. Operator.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::approve_request`].
    pub async fn approve_request(
        &self,
        ctx: &OperatorContext,
        id: AccessRequestId,
        option: ApprovalOption,
    ) -> Result<LeaseView, CoreError> {
        self.policy().approve_request(ctx, id, option).await
    }

    /// IPC `request_deny`. Operator.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::deny_request`].
    pub async fn deny_request(
        &self,
        ctx: &OperatorContext,
        id: AccessRequestId,
    ) -> Result<(), CoreError> {
        self.policy().deny_request(ctx, id).await
    }

    /// IPC `lease_list`. Any role.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::list_leases`].
    pub async fn list_leases(&self, ctx: &OperatorContext) -> Result<Vec<LeaseDetail>, CoreError> {
        self.policy().list_leases(ctx).await
    }

    /// IPC `lease_revoke`. Any role (ADR-0009).
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::revoke_lease`].
    pub async fn revoke_lease(&self, ctx: &OperatorContext, id: LeaseId) -> Result<(), CoreError> {
        self.policy().revoke_lease(ctx, id).await
    }

    /// IPC `lease_revoke_all`. Any role (ADR-0009).
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::revoke_all_leases`].
    pub async fn revoke_all_leases(&self, ctx: &OperatorContext) -> Result<u64, CoreError> {
        self.policy().revoke_all_leases(ctx).await
    }

    /// The policy settings. Any role. `settings_get` includes them.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::policy_settings`].
    pub async fn policy_settings(
        &self,
        ctx: &OperatorContext,
    ) -> Result<PolicySettings, CoreError> {
        self.policy().policy_settings(ctx).await
    }

    /// Saves the policy settings. Owner.
    ///
    /// # Errors
    /// As [`crate::policy::PolicyEngine::set_policy_settings`].
    pub async fn set_policy_settings(
        &self,
        ctx: &OperatorContext,
        value: PolicySettings,
    ) -> Result<(), CoreError> {
        self.policy().set_policy_settings(ctx, value).await
    }
}
