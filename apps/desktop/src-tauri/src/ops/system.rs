//! Commands of the audit log, settings, network, backup, import and activity.

use std::net::IpAddr;

use cerberus_api::tls::{CustomCertError, store_custom_cert};
use cerberus_store::AgentStatus as StoreAgentStatus;
use cerberus_types::OperatorRole as CoreRole;
use serde_json::Value;

use super::files;
use super::rustdesk::{RUSTDESK_PATH_KEY, parse_path_setting};
use crate::dto::{AuditEntryView, AuditQueryView, ChainReportView, NetworkView, SettingsView};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

/// Settings keys the desktop shell keeps itself (they are not in the vault).
pub const AUTOSTART_KEY: &str = "autostart";
/// Content protection key.
pub const CONTENT_PROTECTION_KEY: &str = "content_protection";

/// `audit_query`.
pub async fn audit_query(
    state: &DesktopState,
    window: &str,
    query: AuditQueryView,
) -> IpcResult<Vec<AuditEntryView>> {
    check(window, "audit_query")?;
    let (core, ctx) = state.operator().await?;
    let rows = core.audit_query(&ctx, query.into_core()?).await?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// `audit_verify`.
pub async fn audit_verify(state: &DesktopState, window: &str) -> IpcResult<ChainReportView> {
    check(window, "audit_verify")?;
    let (core, ctx) = state.operator().await?;
    Ok(core.audit_verify(&ctx).await?.into())
}

/// `audit_export`: writes a new file. Returns the number of rows.
pub async fn audit_export(state: &DesktopState, window: &str, dest: String) -> IpcResult<u64> {
    check(window, "audit_export")?;
    let (core, ctx) = state.operator().await?;
    let dest = files::new_file("dest", &dest)?;
    Ok(core.audit_export(&ctx, &dest).await?)
}

/// `settings_get`: the vault settings and the desktop settings.
pub async fn settings_get(state: &DesktopState, window: &str) -> IpcResult<SettingsView> {
    check(window, "settings_get")?;
    settings_view(state).await
}

async fn settings_view(state: &DesktopState) -> IpcResult<SettingsView> {
    let (core, ctx) = state.operator().await?;
    let mut view: SettingsView = core.settings_get(&ctx).await?.into();
    let prefs = state.prefs();
    view.values
        .insert(AUTOSTART_KEY.to_owned(), Value::Bool(prefs.autostart));
    view.values.insert(
        CONTENT_PROTECTION_KEY.to_owned(),
        Value::Bool(prefs.content_protection),
    );
    view.values.insert(
        RUSTDESK_PATH_KEY.to_owned(),
        prefs.rustdesk_path.map_or(Value::Null, |path| {
            Value::String(path.display().to_string())
        }),
    );
    Ok(view)
}

/// `settings_set`: one key at a time. `autostart`, `content_protection` and `rustdesk_path` are
/// desktop settings (operator role); every other key goes to the vault, which checks the role of
/// its group.
pub async fn settings_set(
    state: &DesktopState,
    window: &str,
    key: String,
    value: Value,
) -> IpcResult<SettingsView> {
    check(window, "settings_set")?;
    if key != AUTOSTART_KEY && key != CONTENT_PROTECTION_KEY && key != RUSTDESK_PATH_KEY {
        let (core, ctx) = state.operator().await?;
        return Ok(core.settings_set(&ctx, &key, value).await?.into());
    }
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Operator).await?;
    if key == RUSTDESK_PATH_KEY {
        let mut prefs = state.prefs();
        prefs.rustdesk_path = parse_path_setting(&value)?;
        state.set_prefs(prefs)?;
        return settings_view(state).await;
    }
    let on = value
        .as_bool()
        .ok_or_else(|| IpcError::invalid(&key, "must be true or false"))?;
    let mut prefs = state.prefs();
    if key == AUTOSTART_KEY {
        state.inner.shell.set_autostart(on)?;
        prefs.autostart = on;
    } else {
        state.inner.shell.set_content_protection(on);
        prefs.content_protection = on;
    }
    state.set_prefs(prefs)?;
    settings_view(state).await
}

/// `network_status`: any role.
pub async fn network_status(state: &DesktopState, window: &str) -> IpcResult<NetworkView> {
    check(window, "network_status")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Viewer).await?;
    state.network_view(&core).await
}

fn parse_bind(addrs: &[String]) -> IpcResult<Vec<IpAddr>> {
    if addrs.is_empty() {
        return Err(IpcError::invalid("addrs", "needs at least one address"));
    }
    addrs
        .iter()
        .map(|text| {
            text.parse::<IpAddr>()
                .map_err(|_| IpcError::invalid("addrs", "holds a bad IP address"))
        })
        .collect()
}

/// `network_set_bind`: owner. A LAN address needs a client certificate on every active key
/// (ADR-0023 point 2, threat E-10). The server restarts with the new bind; when it cannot start,
/// the old bind is restored.
pub async fn network_set_bind(
    state: &DesktopState,
    window: &str,
    addrs: Vec<String>,
    port: u16,
) -> IpcResult<NetworkView> {
    check(window, "network_set_bind")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Owner).await?;
    let bind = parse_bind(&addrs)?;
    if port < 1024 {
        return Err(IpcError::invalid("port", "must be 1024 to 65535"));
    }
    if bind.iter().any(|ip| !ip.is_loopback()) {
        let agents = core.list_agents(&ctx).await?;
        let open_key = agents
            .iter()
            .filter(|agent| agent.status != StoreAgentStatus::Revoked)
            .flat_map(|agent| agent.keys.iter())
            .any(|key| key.revoked_at.is_none() && !key.require_mtls);
        if open_key {
            return Err(IpcError::invalid(
                "addrs",
                "a LAN address needs a client certificate on every active key",
            ));
        }
    }
    let before = state.prefs();
    let mut after = before.clone();
    after.bind = bind;
    after.port = port;
    state.set_prefs(after)?;
    if let Err(error) = state.restart_server().await {
        state.set_prefs(before)?;
        if let Err(back) = state.restart_server().await {
            tracing::error!(error = %back, "the old bind did not start again");
        }
        return Err(error);
    }
    state.network_view(&core).await
}

/// `tls_export_ca`: any role. Writes the CA certificate (PEM) as a new file.
pub async fn tls_export_ca(state: &DesktopState, window: &str, dest: String) -> IpcResult<()> {
    check(window, "tls_export_ca")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Viewer).await?;
    let dest = files::new_file("dest", &dest)?;
    let active = cerberus_api::tls::active_tls(&core)
        .await
        .map_err(|e| IpcError::internal(&e))?;
    files::write_new_private(&dest, active.anchor.pem.as_bytes())
}

/// The biggest PEM file we read for a custom certificate.
const MAX_PEM_BYTES: u64 = 1024 * 1024;

fn custom_error(error: CustomCertError) -> IpcError {
    match error {
        CustomCertError::Core(error) => error.into(),
        CustomCertError::Invalid(problem) => IpcError::invalid("certificate", &problem),
    }
}

/// `tls_load_custom`: owner. Loads the PEM chain (server certificate first) and the PEM private
/// key of the owner, checks them, seals them in the vault and serves them with no restart
/// (ADR-0023 point 8). Clients that pin the local CA no longer match: the pin and the fingerprint
/// in the returned view are those of the new chain. Only the picked file names go to the log,
/// never the content or the folders.
pub async fn tls_load_custom(
    state: &DesktopState,
    window: &str,
    chain_path: String,
    key_path: String,
) -> IpcResult<NetworkView> {
    check(window, "tls_load_custom")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Owner).await?;
    let chain_file = files::picked_file(state, "chain_path", &chain_path, MAX_PEM_BYTES)?;
    let key_file = files::picked_file(state, "key_path", &key_path, MAX_PEM_BYTES)?;
    let chain = std::fs::read(&chain_file)?;
    let key = zeroize::Zeroizing::new(std::fs::read(&key_file)?);
    let cert = store_custom_cert(&core, &ctx, &chain, &key, &[])
        .await
        .map_err(custom_error)?;
    tracing::info!(
        chain_file = ?chain_file.file_name(),
        key_file = ?key_file.file_name(),
        not_after = %cert.not_after(),
        "custom TLS certificate loaded"
    );
    state.apply_tls(&core).await?;
    state.network_view(&core).await
}

/// `tls_use_local_ca`: owner. Removes the custom certificate and its key from the vault and serves
/// the local CA chain again. Clients that pin the local CA match again.
pub async fn tls_use_local_ca(state: &DesktopState, window: &str) -> IpcResult<NetworkView> {
    check(window, "tls_use_local_ca")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Owner).await?;
    core.tls_custom_clear(&ctx).await?;
    state.apply_tls(&core).await?;
    state.network_view(&core).await
}

/// `backup_create`: operator. Writes a new file.
pub async fn backup_create(state: &DesktopState, window: &str, dest: String) -> IpcResult<()> {
    check(window, "backup_create")?;
    let (core, ctx) = state.operator().await?;
    let dest = files::new_file("dest", &dest)?;
    core.backup_create(&ctx, &dest).await?;
    Ok(())
}

/// `file_pick_open`: opens the native dialog for one file to read. The backend remembers the
/// answer, and only such a file may be read by `csv_preview`, `csv_import`, `ssh_key_import`,
/// `tls_load_custom` and `backup_restore` (AUD-11). `None` when the person cancels.
pub async fn file_pick_open(
    state: &DesktopState,
    window: &str,
    title: Option<String>,
    extensions: Vec<String>,
) -> IpcResult<Option<String>> {
    check(window, "file_pick_open")?;
    Ok(state.pick_file(title, extensions).await)
}

/// `ui_activity`: the UI saw a person at work. Resets the idle timer, at most once a second.
pub fn ui_activity(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "ui_activity")?;
    state.ui_activity()
}
