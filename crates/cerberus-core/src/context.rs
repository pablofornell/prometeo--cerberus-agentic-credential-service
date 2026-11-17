//! Caller contexts: who makes a call. The transport layer sets them.

use std::collections::BTreeSet;
use std::net::IpAddr;

use cerberus_types::ids::{AgentId, AgentKeyId, OperatorId, RequestId};
use cerberus_types::{OperatorRole, Scope};

/// Set by the auth middleware after a token check (ADR-0016).
#[derive(Clone, Debug)]
pub struct AgentContext {
    /// The agent that made the call.
    pub agent_id: AgentId,
    /// The key the agent used.
    pub key_id: AgentKeyId,
    /// The scopes of that key.
    pub scopes: BTreeSet<Scope>,
    /// The ID of this request.
    pub request_id: RequestId,
    /// The IP address of the caller.
    pub source_ip: IpAddr,
    /// The surface the call came in on.
    pub surface: Surface,
}

/// The network surface an agent call came in on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// The REST API under `/v1`.
    Rest,
    /// The MCP endpoint at `/mcp`.
    Mcp,
}

/// Set by the Tauri layer for every IPC command.
#[derive(Clone, Debug)]
pub struct OperatorContext {
    /// The operator (key slot) that made the call.
    pub operator_id: OperatorId,
    /// The role of that operator.
    pub role: OperatorRole,
    /// The ID of this request.
    pub request_id: RequestId,
}
