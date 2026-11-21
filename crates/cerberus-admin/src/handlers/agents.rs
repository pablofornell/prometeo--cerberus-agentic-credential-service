//! Handlers of the agent commands.

use cerberus_core::{OperatorContext, VaultService};

use crate::dto::AgentView;
use crate::error::IpcResult;

/// `agent_list`.
///
/// # Errors
/// A core error (role, state, storage).
pub async fn agent_list(core: &VaultService, ctx: &OperatorContext) -> IpcResult<Vec<AgentView>> {
    Ok(core
        .list_agents(ctx)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}
