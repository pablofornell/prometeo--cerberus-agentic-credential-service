//! Commands of grants, the simulator, access requests and leases.

use cerberus_admin::handlers;

use crate::dto::{
    AccessRequestView, ApprovalOption, GrantInputView, GrantView, LeaseDetailView, LeaseView,
    SimulationRow, id,
};
use crate::error::IpcResult;
use crate::guard::check;
use crate::state::DesktopState;

/// `grant_list`.
pub async fn grant_list(
    state: &DesktopState,
    window: &str,
    agent_id: Option<String>,
) -> IpcResult<Vec<GrantView>> {
    check(window, "grant_list")?;
    let (core, ctx) = state.operator().await?;
    handlers::grant_list(&core, &ctx, agent_id).await
}

/// `grant_put`: operator; `allow_prod_auto` needs the owner (the core checks it).
pub async fn grant_put(
    state: &DesktopState,
    window: &str,
    input: GrantInputView,
) -> IpcResult<GrantView> {
    check(window, "grant_put")?;
    let (core, ctx) = state.operator().await?;
    handlers::grant_put(&core, &ctx, input).await
}

/// `grant_delete`: operator.
pub async fn grant_delete(state: &DesktopState, window: &str, grant: String) -> IpcResult<()> {
    check(window, "grant_delete")?;
    let (core, ctx) = state.operator().await?;
    handlers::grant_delete(&core, &ctx, grant).await
}

/// `policy_simulate`.
pub async fn policy_simulate(
    state: &DesktopState,
    window: &str,
    agent_id: String,
) -> IpcResult<Vec<SimulationRow>> {
    check(window, "policy_simulate")?;
    let (core, ctx) = state.operator().await?;
    let rows = core.simulate(&ctx, id("agent_id", &agent_id)?).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// `request_list_pending`: main and approval windows.
pub async fn request_list_pending(
    state: &DesktopState,
    window: &str,
) -> IpcResult<Vec<AccessRequestView>> {
    check(window, "request_list_pending")?;
    let (core, ctx) = state.operator().await?;
    handlers::request_list_pending(&core, &ctx).await
}

/// `request_approve`: operator.
pub async fn request_approve(
    state: &DesktopState,
    window: &str,
    request: String,
    option: ApprovalOption,
) -> IpcResult<LeaseView> {
    check(window, "request_approve")?;
    let (core, ctx) = state.operator().await?;
    handlers::request_approve(&core, &ctx, request, option).await
}

/// `request_deny`: operator.
pub async fn request_deny(state: &DesktopState, window: &str, request: String) -> IpcResult<()> {
    check(window, "request_deny")?;
    let (core, ctx) = state.operator().await?;
    handlers::request_deny(&core, &ctx, request).await
}

/// `lease_list`.
pub async fn lease_list(state: &DesktopState, window: &str) -> IpcResult<Vec<LeaseDetailView>> {
    check(window, "lease_list")?;
    let (core, ctx) = state.operator().await?;
    handlers::lease_list(&core, &ctx).await
}

/// `lease_revoke`: any role (DEC-WIRE6-11).
pub async fn lease_revoke(state: &DesktopState, window: &str, lease: String) -> IpcResult<()> {
    check(window, "lease_revoke")?;
    let (core, ctx) = state.operator().await?;
    handlers::lease_revoke(&core, &ctx, lease).await
}

/// `lease_revoke_all`: any role. Returns how many leases ended.
pub async fn lease_revoke_all(state: &DesktopState, window: &str) -> IpcResult<u64> {
    check(window, "lease_revoke_all")?;
    let (core, ctx) = state.operator().await?;
    Ok(core.revoke_all_leases(&ctx).await?)
}
