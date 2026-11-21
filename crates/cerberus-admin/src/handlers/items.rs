//! Handlers of workspaces and items.
//!
//! `item_create` and `item_update` take a resolved payload: the caller turns the
//! [`PayloadView`] of the input into a [`Payload`] or a [`PayloadChange`] first. The desktop
//! resolves an SSH key draft it holds; the admin API refuses drafts (ADR-0034 point 5.6).

use cerberus_core::items::{Payload, PayloadChange};
use cerberus_core::{OperatorContext, VaultService};

use crate::dto::{
    ItemDetailView, ItemFilterView, ItemInputView, ItemSummaryView, PayloadView,
    RevealedSecretView, TotpView, WorkspaceInputView, WorkspaceView, id, opt_id,
};
use crate::error::{IpcError, IpcResult};

/// Takes the payload out of an input. A placeholder that holds no secret stays behind; the
/// handlers never read it.
pub fn take_payload(input: &mut ItemInputView) -> PayloadView {
    std::mem::replace(
        &mut input.payload,
        PayloadView::SshKeyDraft {
            draft_id: String::new(),
        },
    )
}

/// The payload of a new item. A new item has no stored secret to keep.
///
/// # Errors
/// `validation_failed` for [`PayloadChange::Keep`].
pub fn payload_for_create(change: PayloadChange) -> IpcResult<Payload> {
    match change {
        PayloadChange::Replace(payload) => Ok(payload),
        PayloadChange::Keep => Err(IpcError::invalid(
            "payload",
            "cannot be kept when an item is created",
        )),
    }
}

/// `workspace_list`.
///
/// # Errors
/// A core error (role, state, storage).
pub async fn workspace_list(
    core: &VaultService,
    ctx: &OperatorContext,
) -> IpcResult<Vec<WorkspaceView>> {
    Ok(core
        .list_workspaces(ctx)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// `workspace_put`: operator. `workspace = None` makes a new workspace.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn workspace_put(
    core: &VaultService,
    ctx: &OperatorContext,
    workspace: Option<String>,
    input: WorkspaceInputView,
) -> IpcResult<WorkspaceView> {
    let workspace = opt_id("id", workspace.as_deref())?;
    Ok(core
        .put_workspace(ctx, workspace, input.into())
        .await?
        .into())
}

/// `item_list`.
///
/// # Errors
/// `validation_failed` for a bad workspace ID, or a core error.
pub async fn item_list(
    core: &VaultService,
    ctx: &OperatorContext,
    filter: ItemFilterView,
) -> IpcResult<Vec<ItemSummaryView>> {
    let items = core.list_items(ctx, filter.into_core()?).await?;
    Ok(items.into_iter().map(Into::into).collect())
}

/// `item_get`.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn item_get(
    core: &VaultService,
    ctx: &OperatorContext,
    item: String,
) -> IpcResult<ItemDetailView> {
    Ok(core.get_item(ctx, id("id", &item)?).await?.into())
}

/// `item_create`: operator. The `payload` field of `input` is not read: `payload` is the
/// resolved secret part.
///
/// # Errors
/// `validation_failed` for a bad ID or time, or a core error.
pub async fn item_create(
    core: &VaultService,
    ctx: &OperatorContext,
    input: ItemInputView,
    payload: Payload,
) -> IpcResult<ItemDetailView> {
    Ok(core
        .create_item_as_operator(ctx, input.into_core(payload)?)
        .await?
        .into())
}

/// `item_update`: operator. [`PayloadChange::Keep`] changes the metadata only: the stored secret
/// stays, the version number stays, and no reveal is audited. The `payload` field of `input` is
/// not read.
///
/// # Errors
/// `validation_failed` for a bad ID or time, or a core error.
pub async fn item_update(
    core: &VaultService,
    ctx: &OperatorContext,
    item: String,
    input: ItemInputView,
    change: PayloadChange,
) -> IpcResult<ItemDetailView> {
    let item = id("id", &item)?;
    Ok(core
        .update_item(ctx, item, input.into_core(change)?)
        .await?
        .into())
}

/// `item_delete`: operator.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn item_delete(
    core: &VaultService,
    ctx: &OperatorContext,
    item: String,
) -> IpcResult<()> {
    core.delete_item_as_operator(ctx, id("id", &item)?).await?;
    Ok(())
}

/// `item_reveal`: operator. The only answer that holds an item secret; the core audits it as
/// `item.reveal`.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn item_reveal(
    core: &VaultService,
    ctx: &OperatorContext,
    item: String,
) -> IpcResult<RevealedSecretView> {
    Ok(core.reveal_item(ctx, id("id", &item)?).await?.into())
}

/// `item_totp_preview`: operator.
///
/// # Errors
/// `validation_failed` for a bad ID, or a core error.
pub async fn item_totp_preview(
    core: &VaultService,
    ctx: &OperatorContext,
    item: String,
) -> IpcResult<TotpView> {
    Ok(core.totp_preview(ctx, id("id", &item)?).await?.into())
}
