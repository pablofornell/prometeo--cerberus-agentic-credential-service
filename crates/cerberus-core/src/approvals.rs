//! The approval queue (ADR-0018): access requests, the person's decision, timeouts, and waits.
//!
//! An agent learns the result by polling [`PolicyEngine::get_access_request`] or by waiting with
//! [`PolicyEngine::wait_access_request`]. A wait never holds the vault guard: it reads the row
//! under a short guard, then sleeps on the event channel with the guard released, so a lock is
//! never blocked by a waiting agent.

mod decide;
mod queue;

#[cfg(test)]
mod tests;

use cerberus_store::AccessRequestRow;
use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, Environment, ItemId, ItemKind, Permission,
};
use jiff::Timestamp;

use crate::leases::LeaseView;

pub use decide::SESSION_APPROVAL_CAP_SECONDS;
pub use queue::ExpiryReport;

/// Longest reason text kept, in characters (ADR-0018).
pub const MAX_REASON_CHARS: usize = 500;
/// Longest wait of one MCP call (ADR-0018).
pub const MAX_WAIT_SECONDS: u64 = 120;
/// Requests per agent in 60 s above which the window shows a warning (ADR-0018).
pub const BURST_WARNING_ABOVE: usize = 3;

/// A request as the agent sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequestView {
    /// Request ID.
    pub id: AccessRequestId,
    /// The item.
    pub item_id: ItemId,
    /// `read` or `use_ssh`.
    pub permission: Permission,
    /// State.
    pub status: AccessRequestStatus,
    /// TTL the agent asked for.
    pub requested_ttl_seconds: Option<u32>,
    /// Creation time.
    pub created_at: Timestamp,
    /// Time the request times out.
    pub expires_at: Timestamp,
    /// Time of the decision, expiry or cancel.
    pub decided_at: Option<Timestamp>,
    /// The lease, when approved.
    pub lease: Option<LeaseView>,
}

impl AccessRequestView {
    pub(crate) fn of(row: &AccessRequestRow, lease: Option<LeaseView>) -> Self {
        Self {
            id: row.id,
            item_id: row.item_id,
            permission: row.permission,
            status: row.status,
            requested_ttl_seconds: row.requested_ttl_seconds,
            created_at: row.created_at,
            expires_at: row.expires_at,
            decided_at: row.decided_at,
            lease,
        }
    }
}

/// A pending request as the approval window shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequestDetail {
    /// The request.
    pub view: AccessRequestView,
    /// The agent, from the token (never from the request text).
    pub agent_id: AgentId,
    /// The agent name.
    pub agent_name: String,
    /// Item title.
    pub item_title: String,
    /// Item kind (metadata).
    pub item_kind: ItemKind,
    /// Item role label, for example `admin` (metadata).
    pub role_label: Option<String>,
    /// Workspace name.
    pub workspace_name: String,
    /// Item environment (`prod` gets a red badge).
    pub environment: Environment,
    /// Untrusted. Control and format characters removed. At most 500 characters.
    pub reason: String,
    /// True when the agent made more than 3 requests in the last 60 s.
    pub burst_warning: bool,
}

/// What the agent sends to ask ahead (`POST /v1/requests`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateAccess {
    /// The item.
    pub item_id: ItemId,
    /// `read` or `use_ssh`.
    pub permission: Permission,
    /// Untrusted reason text.
    pub reason: String,
    /// TTL asked for, 60 to 86400 s.
    pub ttl_seconds: Option<u32>,
}

/// Removes control characters and hidden format characters (bidi controls, zero-width and tag
/// characters, AUD-24) and cuts to [`MAX_REASON_CHARS`] characters.
#[must_use]
pub fn clean_reason(text: &str) -> String {
    text.chars()
        .filter(|c| !cerberus_types::text::is_hidden_char(*c))
        .take(MAX_REASON_CHARS)
        .collect()
}

/// True for a state that never changes again.
#[must_use]
pub const fn is_terminal(status: AccessRequestStatus) -> bool {
    !matches!(status, AccessRequestStatus::Pending)
}

/// The stable text name of a status, for audit details.
pub(crate) const fn status_text(status: AccessRequestStatus) -> &'static str {
    match status {
        AccessRequestStatus::Pending => "pending",
        AccessRequestStatus::Approved => "approved",
        AccessRequestStatus::Denied => "denied",
        AccessRequestStatus::Expired => "expired",
        AccessRequestStatus::Cancelled => "cancelled",
    }
}
