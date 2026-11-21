//! Commands of workspaces, items and secrets.

use cerberus_admin::handlers;
use cerberus_core::items::{Payload, PayloadChange, generate_ed25519, import_private_key};
use cerberus_types::OperatorRole as CoreRole;

use super::files;
use super::generate::{self, CharClass};
use crate::dto::{
    ItemDetailView, ItemFilterView, ItemInputView, ItemSummaryView, ItemVersionView, OneTimeKind,
    PayloadSource, PayloadView, RevealedSecretView, Secret, SshKeyDraft, TotpView,
    WorkspaceInputView, WorkspaceView, id,
};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

/// Largest SSH key file `ssh_key_import` reads.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// `workspace_list`.
pub async fn workspace_list(state: &DesktopState, window: &str) -> IpcResult<Vec<WorkspaceView>> {
    check(window, "workspace_list")?;
    let (core, ctx) = state.operator().await?;
    handlers::workspace_list(&core, &ctx).await
}

/// `workspace_put`: operator. `id = null` makes a new workspace.
pub async fn workspace_put(
    state: &DesktopState,
    window: &str,
    workspace: Option<String>,
    input: WorkspaceInputView,
) -> IpcResult<WorkspaceView> {
    check(window, "workspace_put")?;
    let (core, ctx) = state.operator().await?;
    handlers::workspace_put(&core, &ctx, workspace, input).await
}

/// `workspace_delete`: operator; `conflict` when the workspace has items.
pub async fn workspace_delete(
    state: &DesktopState,
    window: &str,
    workspace: String,
) -> IpcResult<()> {
    check(window, "workspace_delete")?;
    let (core, ctx) = state.operator().await?;
    core.delete_workspace(&ctx, id("id", &workspace)?).await?;
    Ok(())
}

/// `item_list`.
pub async fn item_list(
    state: &DesktopState,
    window: &str,
    filter: ItemFilterView,
) -> IpcResult<Vec<ItemSummaryView>> {
    check(window, "item_list")?;
    let (core, ctx) = state.operator().await?;
    handlers::item_list(&core, &ctx, filter).await
}

/// `item_get`.
pub async fn item_get(
    state: &DesktopState,
    window: &str,
    item: String,
) -> IpcResult<ItemDetailView> {
    check(window, "item_get")?;
    let (core, ctx) = state.operator().await?;
    handlers::item_get(&core, &ctx, item).await
}

/// What an input does with the secret, and the draft to drop after the save.
async fn resolve_payload(
    state: &DesktopState,
    view: PayloadView,
) -> IpcResult<(PayloadChange, Option<String>)> {
    match view.into_source() {
        PayloadSource::Payload(payload) => Ok((PayloadChange::Replace(payload), None)),
        PayloadSource::Draft(draft) => Ok((
            PayloadChange::Replace(state.draft(&draft).await?),
            Some(draft),
        )),
        PayloadSource::Keep => Ok((PayloadChange::Keep, None)),
    }
}

/// `item_create`: operator.
pub async fn item_create(
    state: &DesktopState,
    window: &str,
    mut input: ItemInputView,
) -> IpcResult<ItemDetailView> {
    check(window, "item_create")?;
    let (core, ctx) = state.operator().await?;
    let view = handlers::take_payload(&mut input);
    let (change, draft) = resolve_payload(state, view).await?;
    let payload = handlers::payload_for_create(change)?;
    let detail = handlers::item_create(&core, &ctx, input, payload).await?;
    if let Some(draft) = draft {
        state.discard_draft(&draft);
    }
    Ok(detail)
}

/// `item_update`: operator. A payload of kind `keep` changes the metadata only: the stored
/// secret stays, the version number stays, and no reveal is audited.
pub async fn item_update(
    state: &DesktopState,
    window: &str,
    item: String,
    mut input: ItemInputView,
) -> IpcResult<ItemDetailView> {
    check(window, "item_update")?;
    let (core, ctx) = state.operator().await?;
    // A bad ID is refused before the draft is looked up.
    id::<cerberus_types::ItemId>("id", &item)?;
    let view = handlers::take_payload(&mut input);
    let (change, draft) = resolve_payload(state, view).await?;
    let detail = handlers::item_update(&core, &ctx, item, input, change).await?;
    if let Some(draft) = draft {
        state.discard_draft(&draft);
    }
    Ok(detail)
}

/// `item_delete`: operator.
pub async fn item_delete(state: &DesktopState, window: &str, item: String) -> IpcResult<()> {
    check(window, "item_delete")?;
    let (core, ctx) = state.operator().await?;
    handlers::item_delete(&core, &ctx, item).await
}

/// `item_reveal`: operator. The only answer that holds an item secret. It goes to the main window
/// only, and the call is audited as `item.reveal` by the core.
pub async fn item_reveal(
    state: &DesktopState,
    window: &str,
    item: String,
) -> IpcResult<RevealedSecretView> {
    check(window, "item_reveal")?;
    let (core, ctx) = state.operator().await?;
    handlers::item_reveal(&core, &ctx, item).await
}

/// `item_versions`.
pub async fn item_versions(
    state: &DesktopState,
    window: &str,
    item: String,
) -> IpcResult<Vec<ItemVersionView>> {
    check(window, "item_versions")?;
    let (core, ctx) = state.operator().await?;
    let versions = core.item_versions(&ctx, id("id", &item)?).await?;
    Ok(versions.into_iter().map(Into::into).collect())
}

/// `item_restore_version`: operator.
pub async fn item_restore_version(
    state: &DesktopState,
    window: &str,
    item: String,
    version: u32,
) -> IpcResult<ItemDetailView> {
    check(window, "item_restore_version")?;
    let (core, ctx) = state.operator().await?;
    Ok(core
        .restore_item_version(&ctx, id("id", &item)?, version)
        .await?
        .into())
}

/// `item_totp_preview`: operator.
pub async fn item_totp_preview(
    state: &DesktopState,
    window: &str,
    item: String,
) -> IpcResult<TotpView> {
    check(window, "item_totp_preview")?;
    let (core, ctx) = state.operator().await?;
    handlers::item_totp_preview(&core, &ctx, item).await
}

/// The text of one secret field of a payload. `None` when the kind has no such field.
fn field_text(payload: &Payload, field: &str) -> Option<String> {
    let text = |s: &cerberus_crypto::SecretString| Some(s.expose_secret().to_owned());
    let opt = |s: &Option<cerberus_crypto::SecretString>| s.as_ref().and_then(text);
    match (payload, field) {
        (Payload::WebLogin { username, .. }, "username") => text(username),
        (Payload::WebLogin { password, .. }, "password" | "secret") => text(password),
        (Payload::ApiKey { key, .. }, "key" | "secret") => text(key),
        (Payload::SshKey { private_key, .. }, "private_key" | "secret") => text(private_key),
        (Payload::SshKey { passphrase, .. }, "passphrase") => opt(passphrase),
        (Payload::SessionToken { token, .. }, "token" | "secret") => text(token),
        (Payload::BrowserSession { storage_state, .. }, "storage_state" | "secret") => {
            text(storage_state)
        }
        (Payload::Database { url, .. }, "url") => opt(url),
        (Payload::Database { username, .. }, "username") => opt(username),
        (Payload::Database { password, .. }, "password" | "secret") => opt(password),
        (Payload::Cloud { access_key_id, .. }, "access_key_id") => opt(access_key_id),
        (
            Payload::Cloud {
                secret_access_key, ..
            },
            "secret_access_key" | "secret",
        ) => opt(secret_access_key),
        (Payload::Cloud { session_token, .. }, "session_token") => opt(session_token),
        (Payload::Certificate { key_pem, .. }, "key_pem" | "secret") => opt(key_pem),
        (Payload::EnvBundle { vars }, name) => vars.get(name).and_then(text),
        (Payload::Note { text: note }, "text" | "secret") => text(note),
        (Payload::Rustdesk { password }, "password" | "secret") => opt(password),
        _ => None,
    }
}

/// `clipboard_copy_secret`: operator. Copies one field of the item and clears the clipboard after
/// 30 seconds if it still holds the value. `field` is a payload field name, `secret` (the main
/// secret of the kind) or `totp` (the current code). The read is audited like `item_reveal`.
pub async fn clipboard_copy_secret(
    state: &DesktopState,
    window: &str,
    item: String,
    field: String,
) -> IpcResult<()> {
    check(window, "clipboard_copy_secret")?;
    let (core, ctx) = state.operator().await?;
    let item = id("item_id", &item)?;
    let text = if field == "totp" {
        let code = core.totp_preview(&ctx, item).await?;
        zeroize::Zeroizing::new(code.code.expose_secret().to_owned())
    } else {
        let revealed = core.reveal_item(&ctx, item).await?;
        let text = field_text(&revealed.payload, &field)
            .ok_or_else(|| IpcError::invalid("field", "this item has no such secret field"))?;
        zeroize::Zeroizing::new(text)
    };
    state.copy_and_clear(&text)
}

/// `clipboard_copy_once`: copies the last one-time value the backend holds (DEC-036).
pub async fn clipboard_copy_once(
    state: &DesktopState,
    window: &str,
    kind: OneTimeKind,
) -> IpcResult<()> {
    check(window, "clipboard_copy_once")?;
    state.operator().await?;
    let text = state
        .one_time(kind)
        .await
        .ok_or_else(|| IpcError::new("not_found", "there is no such value to copy"))?;
    state.copy_and_clear(&text)
}

/// `password_generate`: operator.
pub async fn password_generate(
    state: &DesktopState,
    window: &str,
    length: u32,
    classes: Vec<CharClass>,
) -> IpcResult<Secret> {
    check(window, "password_generate")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Operator).await?;
    let text = generate::password(length, &classes)?;
    Ok(Secret::new(text.to_string()))
}

async fn draft_of(state: &DesktopState, payload: Payload) -> IpcResult<SshKeyDraft> {
    let Payload::SshKey {
        public_key,
        fingerprint,
        ..
    } = &payload
    else {
        return Err(IpcError::invalid("key", "is not an SSH key"));
    };
    let (public_key, fingerprint) = (public_key.clone(), fingerprint.clone());
    Ok(SshKeyDraft {
        draft_id: state.put_draft(payload).await?,
        public_key,
        fingerprint,
    })
}

/// `ssh_key_generate`: operator. The private key stays in a backend draft.
pub async fn ssh_key_generate(
    state: &DesktopState,
    window: &str,
    comment: String,
) -> IpcResult<SshKeyDraft> {
    check(window, "ssh_key_generate")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Operator).await?;
    draft_of(state, generate_ed25519(&comment)?).await
}

/// Where `ssh_key_import` reads the key from.
#[derive(Debug, serde::Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SshKeySource {
    /// A file on this machine (a regular file of at most 64 KiB).
    Path {
        /// Absolute path.
        path: String,
    },
    /// The key text.
    Pem {
        /// OpenSSH private key text.
        pem: Secret,
    },
}

/// `ssh_key_import`: operator. The private key stays in a backend draft.
pub async fn ssh_key_import(
    state: &DesktopState,
    window: &str,
    source: SshKeySource,
    passphrase: Option<Secret>,
) -> IpcResult<SshKeyDraft> {
    check(window, "ssh_key_import")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Operator).await?;
    let text = match source {
        SshKeySource::Pem { pem } => pem.into_core(),
        SshKeySource::Path { path } => {
            let file = files::picked_file(state, "path", &path, MAX_KEY_FILE_BYTES)?;
            let bytes = zeroize::Zeroizing::new(std::fs::read(file)?);
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| IpcError::invalid("path", "is not a text key file"))?;
            cerberus_crypto::SecretString::new(text.to_owned())
        }
    };
    let payload = import_private_key(text.expose_secret(), passphrase.map(Secret::into_core))?;
    draft_of(state, payload).await
}
