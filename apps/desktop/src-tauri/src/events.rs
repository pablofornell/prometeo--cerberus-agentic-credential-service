//! Backend to UI events (`tauri-specta` typed events). They hold IDs and metadata only, never a
//! secret value or an item title (threat I-19).

use serde::{Deserialize, Serialize};
use specta::Type;
use tauri_specta::Event;

use crate::dto::{RequestStatus, VaultState};

/// The vault state changed.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct VaultStateChanged {
    /// The new state.
    pub state: VaultState,
}

/// An agent asked for access.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct AccessRequestCreated {
    /// Request ID.
    pub id: String,
}

/// A request was decided, expired or cancelled.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct AccessRequestResolved {
    /// Request ID.
    pub id: String,
    /// The new state.
    pub status: RequestStatus,
}

/// An agent call that the dashboard shows.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct AgentActivity {
    /// Agent ID.
    pub agent_id: String,
    /// Audit event type.
    pub event_type: String,
    /// Item ID, when the call was about one.
    pub item_id: Option<String>,
    /// Time.
    pub at: String,
}

/// A lease was made, used up, released or revoked.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct LeaseChanged {
    /// Lease ID.
    pub id: String,
}

/// Seconds left before the next automatic lock.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct AutolockTick {
    /// Seconds until the lock.
    pub seconds_left: u32,
}

/// An agent read many different items in one hour.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct MassReadAlert {
    /// Agent ID.
    pub agent_id: String,
    /// Distinct items read.
    pub distinct_items: u32,
}

/// The header check failed at unlock.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct HeaderMismatch {}

/// A row check failed. Table name and row ID only.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct IntegrityAlert {
    /// Table name.
    pub table: String,
    /// Row ID.
    pub row_id: String,
}

/// Number of access requests that wait for a person. The tray badge and the approval window use it.
#[derive(Clone, Debug, Serialize, Deserialize, Type, Event)]
pub struct PendingCountChanged {
    /// Pending requests.
    pub count: u32,
}
