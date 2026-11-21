//! Handlers of grants, access requests and leases.

use cerberus_core::{OperatorContext, VaultService};

use crate::dto::{
    AccessRequestView, ApprovalOption, GrantInputView, GrantView, LeaseDetailView, LeaseView, id,
    opt_id,
};
use crate::error::IpcResult;

/// `grant_list`, of one agent or of all.
///
/// # Errors
/// `validation_failed` for a bad agent ID, or a core error.
pub async fn grant_list(
    core: &VaultService,
    ctx: &OperatorContext,
    agent_id: Option<String>,
) -> IpcResult<Vec<GrantView>> {
    let agent = opt_id("agent_id", agent_id.as_deref())?;
    Ok(core
        .list_grants(ctx, agent)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// `grant_put`: operator; `allow_prod_auto` needs the owner (the core checks it).
///
/// # Errors
/// `validation_failed` for a bad input, or a core error.
pub async fn grant_put(
    core: &VaultService,
    ctx: &OperatorContext,
    input: GrantInputView,
) -> IpcResult<GrantView> {
    Ok(core.put_grant(ctx, input.into_core()?).await?.into())
}

/// `grant_delete`: operator.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn grant_delete(
    core: &VaultService,
    ctx: &OperatorContext,
    grant: String,
) -> IpcResult<()> {
    core.delete_grant(ctx, id("id", &grant)?).await?;
    Ok(())
}

/// `request_list_pending`.
///
/// # Errors
/// A core error (role, state, storage).
pub async fn request_list_pending(
    core: &VaultService,
    ctx: &OperatorContext,
) -> IpcResult<Vec<AccessRequestView>> {
    Ok(core
        .pending_requests(ctx)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// `request_approve`: operator.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn request_approve(
    core: &VaultService,
    ctx: &OperatorContext,
    request: String,
    option: ApprovalOption,
) -> IpcResult<LeaseView> {
    Ok(core
        .approve_request(ctx, id("id", &request)?, option.into())
        .await?
        .into())
}

/// `request_deny`: operator.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn request_deny(
    core: &VaultService,
    ctx: &OperatorContext,
    request: String,
) -> IpcResult<()> {
    core.deny_request(ctx, id("id", &request)?).await?;
    Ok(())
}

/// `lease_list`.
///
/// # Errors
/// A core error (role, state, storage).
pub async fn lease_list(
    core: &VaultService,
    ctx: &OperatorContext,
) -> IpcResult<Vec<LeaseDetailView>> {
    Ok(core
        .list_leases(ctx)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// `lease_revoke`: any role (DEC-WIRE6-11).
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn lease_revoke(
    core: &VaultService,
    ctx: &OperatorContext,
    lease: String,
) -> IpcResult<()> {
    core.revoke_lease(ctx, id("id", &lease)?).await?;
    Ok(())
}
