//! Commands of agents, their keys and their client certificates.

use cerberus_api::LocalCa;
use cerberus_core::agents::NewAgentKey;
use cerberus_types::{AgentKeyId, OperatorRole as CoreRole};

use super::files;
use crate::dto::{
    AgentCreated, AgentInputView, AgentKeyCreated, AgentKeyInputView, AgentStatus, AgentView,
    IssuedClientCert, OneTimeKind, Secret, Snippets, id,
};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

/// `agent_list`.
pub async fn agent_list(state: &DesktopState, window: &str) -> IpcResult<Vec<AgentView>> {
    check(window, "agent_list")?;
    let (core, ctx) = state.operator().await?;
    Ok(core
        .list_agents(&ctx)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

/// AUD-13: on a LAN bind every active key needs a client certificate (ADR-0023 point 2). A new key
/// has none until `agent_issue_client_cert` runs, and the certificate needs the key ID, so the
/// key cannot be made first. The person switches to loopback, makes the key, issues its
/// certificate, and then binds to the LAN again (`network_set_bind` checks every key).
fn refuse_unbound_key_on_lan(state: &DesktopState) -> IpcResult<()> {
    if state.prefs().is_lan() {
        return Err(IpcError::invalid(
            "bind",
            "a new key has no client certificate: make it while the server listens on loopback only",
        ));
    }
    Ok(())
}

async fn token_secret(state: &DesktopState, key: &NewAgentKey) -> Secret {
    let text = key.token.expose_secret();
    state.set_one_time(OneTimeKind::AgentToken, text).await;
    Secret::new(text.to_owned())
}

/// `agent_create`: operator. The token is shown one time.
pub async fn agent_create(
    state: &DesktopState,
    window: &str,
    input: AgentInputView,
    key: AgentKeyInputView,
) -> IpcResult<AgentCreated> {
    check(window, "agent_create")?;
    let (core, ctx) = state.operator().await?;
    refuse_unbound_key_on_lan(state)?;
    let (agent, new_key) = core
        .create_agent(&ctx, input.into(), key.into_core()?)
        .await?;
    let token = token_secret(state, &new_key).await;
    Ok(AgentCreated {
        agent: agent.into(),
        token,
    })
}

/// `agent_update`: operator.
pub async fn agent_update(
    state: &DesktopState,
    window: &str,
    agent: String,
    input: AgentInputView,
) -> IpcResult<AgentView> {
    check(window, "agent_update")?;
    let (core, ctx) = state.operator().await?;
    Ok(core
        .update_agent(&ctx, id("id", &agent)?, input.into())
        .await?
        .into())
}

/// `agent_set_status`: operator.
pub async fn agent_set_status(
    state: &DesktopState,
    window: &str,
    agent: String,
    status: AgentStatus,
) -> IpcResult<AgentView> {
    check(window, "agent_set_status")?;
    let (core, ctx) = state.operator().await?;
    Ok(core
        .set_agent_status(&ctx, id("id", &agent)?, status.into())
        .await?
        .into())
}

/// `agent_key_create`: operator. The token is shown one time.
pub async fn agent_key_create(
    state: &DesktopState,
    window: &str,
    agent_id: String,
    key: AgentKeyInputView,
) -> IpcResult<AgentKeyCreated> {
    check(window, "agent_key_create")?;
    let (core, ctx) = state.operator().await?;
    refuse_unbound_key_on_lan(state)?;
    let new_key = core
        .create_agent_key(&ctx, id("agent_id", &agent_id)?, key.into_core()?)
        .await?;
    let token = token_secret(state, &new_key).await;
    Ok(AgentKeyCreated {
        key: new_key.key.into(),
        token,
    })
}

/// `agent_key_rotate`: operator. The old key keeps working for `overlap_seconds`.
pub async fn agent_key_rotate(
    state: &DesktopState,
    window: &str,
    key_id: String,
    overlap_seconds: u32,
) -> IpcResult<AgentKeyCreated> {
    check(window, "agent_key_rotate")?;
    let (core, ctx) = state.operator().await?;
    let key_id_parsed: AgentKeyId = id("key_id", &key_id)?;
    if state.prefs().is_lan() {
        // The new key keeps the binding of the old one. A key without one must not be copied.
        let bound = core
            .list_agents(&ctx)
            .await?
            .iter()
            .flat_map(|agent| agent.keys.iter())
            .any(|key| key.id == key_id_parsed && key.require_mtls);
        if !bound {
            refuse_unbound_key_on_lan(state)?;
        }
    }
    let new_key = core
        .rotate_agent_key(
            &ctx,
            key_id_parsed,
            std::time::Duration::from_secs(u64::from(overlap_seconds)),
        )
        .await?;
    let token = token_secret(state, &new_key).await;
    Ok(AgentKeyCreated {
        key: new_key.key.into(),
        token,
    })
}

/// `agent_key_revoke`: operator.
pub async fn agent_key_revoke(state: &DesktopState, window: &str, key_id: String) -> IpcResult<()> {
    check(window, "agent_key_revoke")?;
    let (core, ctx) = state.operator().await?;
    core.revoke_agent_key(&ctx, id("key_id", &key_id)?).await?;
    Ok(())
}

/// `agent_issue_client_cert`: owner. Signs a client certificate with the local CA, writes the
/// certificate and the key (mode 0600) as new files in `dest_dir`, and binds the key to it. A
/// key that is bound needs the certificate on every call (mTLS).
pub async fn agent_issue_client_cert(
    state: &DesktopState,
    window: &str,
    key_id: String,
    dest_dir: String,
) -> IpcResult<IssuedClientCert> {
    check(window, "agent_issue_client_cert")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Owner).await?;
    let key_id: AgentKeyId = id("key_id", &key_id)?;
    let dir = files::existing_dir("dest_dir", &dest_dir)?;
    let agent = core
        .list_agents(&ctx)
        .await?
        .into_iter()
        .find(|agent| agent.keys.iter().any(|key| key.id == key_id))
        .ok_or(cerberus_core::CoreError::NotFound)?;
    let material = core.tls_ca_material().await?;
    let ca = LocalCa::from_parts(&material.cert_der, &material.key_der)
        .map_err(|e| IpcError::internal(&e))?;
    let issued = ca
        .issue_client(agent.id, core.clock().now())
        .map_err(|e| IpcError::internal(&e))?;
    let cert_path = files::new_file(
        "dest_dir",
        &path_text(&dir, &format!("cerberus-agent-{key_id}.crt")),
    )?;
    let key_path = files::new_file(
        "dest_dir",
        &path_text(&dir, &format!("cerberus-agent-{key_id}.key")),
    )?;
    files::write_new_private(&cert_path, issued.cert_pem().as_bytes())?;
    let key_pem = zeroize::Zeroizing::new(issued.key_pem());
    if let Err(error) = files::write_new_private(&key_path, key_pem.as_bytes()) {
        remove_ours(&cert_path);
        return Err(error);
    }
    let sha256 = issued.sha256();
    if let Err(error) = core.bind_client_cert(&ctx, key_id, sha256).await {
        remove_ours(&cert_path);
        remove_ours(&key_path);
        return Err(error.into());
    }
    Ok(IssuedClientCert {
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
        sha256: sha256.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

fn path_text(dir: &std::path::Path, name: &str) -> String {
    dir.join(name).display().to_string()
}

/// Removes a file this call made, after a later step failed. A failure is only logged.
fn remove_ours(path: &std::path::Path) {
    if let Err(error) = std::fs::remove_file(path) {
        tracing::warn!(%error, "could not remove a certificate file after a failed bind");
    }
}

/// `agent_snippets`: connection examples for an agent. They name `$CERBERUS_TOKEN` and never hold
/// a token. Any role.
pub async fn agent_snippets(
    state: &DesktopState,
    window: &str,
    agent_id: String,
) -> IpcResult<Snippets> {
    check(window, "agent_snippets")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Viewer).await?;
    let agent_id: cerberus_types::AgentId = id("agent_id", &agent_id)?;
    core.list_agents(&ctx)
        .await?
        .into_iter()
        .find(|agent| agent.id == agent_id)
        .ok_or(cerberus_core::CoreError::NotFound)?;
    let base = format!("https://localhost:{}", state.prefs().port);
    Ok(Snippets {
        mcp_json: format!(
            "{{\n  \"mcpServers\": {{\n    \"cerberus\": {{\n      \"url\": \"{base}/mcp\",\n      \"headers\": {{ \"Authorization\": \"Bearer ${{CERBERUS_TOKEN}}\" }}\n    }}\n  }}\n}}\n"
        ),
        curl: format!(
            "curl --cacert cerberus-ca.pem -H \"Authorization: Bearer $CERBERUS_TOKEN\" {base}/v1/status\n"
        ),
        env: format!(
            "export CERBERUS_URL={base}\nexport CERBERUS_AGENT_ID={agent_id}\nexport CERBERUS_TOKEN=<paste the token here>\nexport NODE_EXTRA_CA_CERTS=/path/to/cerberus-ca.pem\n"
        ),
    })
}
