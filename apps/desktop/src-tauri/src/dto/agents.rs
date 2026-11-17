//! Types of the agent and key commands.

use cerberus_core::agents::{
    AgentInput, AgentKeyInput, AgentKeyView as CoreKey, AgentView as CoreAgent,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use specta::Type;

use super::{AgentStatus, Scope, Secret, opt_ts};
use crate::error::{IpcError, IpcResult};

/// Name and description of an agent.
#[derive(Clone, Debug, Deserialize, Type)]
pub struct AgentInputView {
    /// A short name.
    pub name: String,
    /// Free text.
    pub description: String,
}

impl From<AgentInputView> for AgentInput {
    fn from(value: AgentInputView) -> Self {
        Self {
            name: value.name,
            description: value.description,
        }
    }
}

/// What the operator chooses for a new key.
#[derive(Clone, Debug, Deserialize, Type)]
pub struct AgentKeyInputView {
    /// Scopes. Empty means the default scopes.
    pub scopes: Vec<Scope>,
    /// Lifetime in days (1 to 365). `null` means no expiry and needs the owner role.
    pub lifetime_days: Option<u32>,
    /// IP allowlist in CIDR text. Empty means any address.
    pub ip_allowlist: Vec<String>,
}

impl AgentKeyInputView {
    /// The core input. `require_mtls` is always false here: a key becomes mTLS-bound through
    /// `agent_issue_client_cert` (DEC-T09-5).
    ///
    /// # Errors
    /// `validation_failed` for a bad CIDR.
    pub fn into_core(self) -> IpcResult<AgentKeyInput> {
        let ip_allowlist = self
            .ip_allowlist
            .iter()
            .map(|text| {
                text.parse::<IpNet>()
                    .map_err(|_| IpcError::invalid("ip_allowlist", "holds a bad CIDR address"))
            })
            .collect::<IpcResult<Vec<_>>>()?;
        Ok(AgentKeyInput {
            scopes: self.scopes.into_iter().map(Into::into).collect(),
            lifetime_days: self.lifetime_days,
            ip_allowlist,
            require_mtls: false,
        })
    }
}

/// A key of an agent. It never holds the secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct AgentKeyView {
    /// Key ID.
    pub id: String,
    /// Last 4 characters of the secret.
    pub hint: String,
    /// Scopes.
    pub scopes: Vec<Scope>,
    /// IP allowlist.
    pub ip_allowlist: Vec<String>,
    /// Expiry.
    pub expires_at: Option<String>,
    /// Revoke time.
    pub revoked_at: Option<String>,
    /// Last use.
    pub last_used_at: Option<String>,
    /// True when the key needs a client certificate.
    pub require_mtls: bool,
}

impl From<CoreKey> for AgentKeyView {
    fn from(value: CoreKey) -> Self {
        Self {
            id: value.id.to_string(),
            hint: value.hint,
            scopes: value.scopes.into_iter().map(Into::into).collect(),
            ip_allowlist: value.ip_allowlist.iter().map(ToString::to_string).collect(),
            expires_at: opt_ts(value.expires_at),
            revoked_at: opt_ts(value.revoked_at),
            last_used_at: opt_ts(value.last_used_at),
            require_mtls: value.require_mtls,
        }
    }
}

/// An agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct AgentView {
    /// Agent ID.
    pub id: String,
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Status.
    pub status: AgentStatus,
    /// Keys, newest first.
    pub keys: Vec<AgentKeyView>,
    /// Latest use of any key.
    pub last_seen_at: Option<String>,
}

impl From<CoreAgent> for AgentView {
    fn from(value: CoreAgent) -> Self {
        Self {
            id: value.id.to_string(),
            name: value.name,
            description: value.description,
            status: value.status.into(),
            keys: value.keys.into_iter().map(Into::into).collect(),
            last_seen_at: opt_ts(value.last_seen_at),
        }
    }
}

/// Result of `agent_create`. The token is shown one time.
#[derive(Debug, Serialize, Type)]
pub struct AgentCreated {
    /// The agent.
    pub agent: AgentView,
    /// The token text.
    pub token: Secret,
}

/// Result of `agent_key_create` and `agent_key_rotate`. The token is shown one time.
#[derive(Debug, Serialize, Type)]
pub struct AgentKeyCreated {
    /// The key.
    pub key: AgentKeyView,
    /// The token text.
    pub token: Secret,
}

/// Result of `agent_issue_client_cert`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct IssuedClientCert {
    /// Path of the certificate file.
    pub cert_path: String,
    /// Path of the private key file (mode 0600).
    pub key_path: String,
    /// SHA-256 of the certificate, in hex.
    pub sha256: String,
}

/// Result of `agent_snippets`. Nothing here holds a token: the snippets name `$CERBERUS_TOKEN`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct Snippets {
    /// MCP client configuration (JSON text).
    pub mcp_json: String,
    /// A curl example.
    pub curl: String,
    /// Shell environment lines.
    pub env: String,
}
