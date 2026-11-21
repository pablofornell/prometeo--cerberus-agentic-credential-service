//! Handlers of the audit commands.

use cerberus_core::{OperatorContext, VaultService};

use crate::dto::{AuditEntryView, AuditQueryView};
use crate::error::IpcResult;

/// `audit_query`.
///
/// # Errors
/// `validation_failed` for a bad time or ID, or a core error.
pub async fn audit_query(
    core: &VaultService,
    ctx: &OperatorContext,
    query: AuditQueryView,
) -> IpcResult<Vec<AuditEntryView>> {
    let rows = core.audit_query(ctx, query.into_core()?).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}
