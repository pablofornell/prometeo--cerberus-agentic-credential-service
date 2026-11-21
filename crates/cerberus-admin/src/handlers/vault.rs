//! Handlers of the vault state commands.

use cerberus_core::{KeyCustody, OperatorContext, VaultService};
use cerberus_types::LockReason;

use crate::dto::{OperatorPublic, VaultStatusView};
use crate::error::IpcResult;

/// `vault_status`. Needs no session.
pub async fn vault_status(core: &VaultService) -> VaultStatusView {
    core.status().await.into()
}

/// `vault_list_operators`. Needs no session: it works while sealed.
///
/// # Errors
/// `no_vault`, or a storage error.
pub async fn vault_list_operators(core: &VaultService) -> IpcResult<Vec<OperatorPublic>> {
    let operators = core.list_operators().await?;
    Ok(operators.into_iter().map(Into::into).collect())
}

/// `vault_lock`. Locking a vault that is already locked is not an error.
///
/// # Errors
/// A core error of the lock.
pub async fn vault_lock(core: &VaultService) -> IpcResult<()> {
    core.lock(LockReason::Manual).await?;
    Ok(())
}

/// `vault_panic`: revokes all leases, cancels all requests, locks.
///
/// # Errors
/// A core error (role, state, storage).
pub async fn vault_panic(core: &VaultService, ctx: &OperatorContext) -> IpcResult<()> {
    core.panic_lock(ctx).await?;
    Ok(())
}

/// `ui_activity`: a person is at work. Resets the idle lock timer of the vault. The caller limits
/// how often it runs.
pub fn ui_activity(core: &VaultService) {
    core.note_operator_activity();
}
