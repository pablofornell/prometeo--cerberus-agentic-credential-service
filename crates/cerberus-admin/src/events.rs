//! The live events of the admin API (`GET /admin/v1/events`, ADR-0034 point 5). They are the
//! typed UI events of the desktop, with the same fields, so a remote desktop emits the same Tauri
//! events as the local event pump. They hold IDs and metadata only, never a secret value or an
//! item title (threat I-19).

use cerberus_core::CoreEvent;
use serde::{Deserialize, Serialize};

use crate::dto::{RequestStatus, VaultState};

/// One UI event. The JSON form names the event in the field `event`, for example
/// `{"event":"LeaseChanged","id":"..."}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum WireEvent {
    /// The vault state changed.
    VaultStateChanged {
        /// The new state.
        state: VaultState,
    },
    /// An agent asked for access.
    AccessRequestCreated {
        /// Request ID.
        id: String,
    },
    /// A request was decided, expired or cancelled.
    AccessRequestResolved {
        /// Request ID.
        id: String,
        /// The new state.
        status: RequestStatus,
    },
    /// An agent call that the dashboard shows.
    AgentActivity {
        /// Agent ID.
        agent_id: String,
        /// Audit event type.
        event_type: String,
        /// Item ID, when the call was about one.
        item_id: Option<String>,
        /// Time.
        at: String,
    },
    /// A lease was made, used up, released or revoked.
    LeaseChanged {
        /// Lease ID.
        id: String,
    },
    /// Seconds left before the next automatic lock.
    AutolockTick {
        /// Seconds until the lock.
        seconds_left: u32,
    },
    /// An agent read many different items in one hour.
    MassReadAlert {
        /// Agent ID.
        agent_id: String,
        /// Distinct items read.
        distinct_items: u32,
    },
    /// The header check failed at unlock.
    HeaderMismatch,
    /// A row check failed. Table name and row ID only.
    IntegrityAlert {
        /// Table name.
        table: String,
        /// Row ID.
        row_id: String,
    },
    /// Number of access requests that wait for a person. The core has no such event: the host
    /// counts the pending requests after a request event.
    PendingCountChanged {
        /// Pending requests.
        count: u32,
    },
}

impl WireEvent {
    /// The event name: the value of the `event` field.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::VaultStateChanged { .. } => "VaultStateChanged",
            Self::AccessRequestCreated { .. } => "AccessRequestCreated",
            Self::AccessRequestResolved { .. } => "AccessRequestResolved",
            Self::AgentActivity { .. } => "AgentActivity",
            Self::LeaseChanged { .. } => "LeaseChanged",
            Self::AutolockTick { .. } => "AutolockTick",
            Self::MassReadAlert { .. } => "MassReadAlert",
            Self::HeaderMismatch => "HeaderMismatch",
            Self::IntegrityAlert { .. } => "IntegrityAlert",
            Self::PendingCountChanged { .. } => "PendingCountChanged",
        }
    }
}

/// The UI event of a core event.
#[must_use]
pub fn from_core(event: CoreEvent) -> WireEvent {
    match event {
        CoreEvent::StateChanged(kind) => WireEvent::VaultStateChanged {
            state: VaultState::from(kind),
        },
        CoreEvent::AccessRequestCreated(id) => {
            WireEvent::AccessRequestCreated { id: id.to_string() }
        }
        CoreEvent::AccessRequestResolved { id, status } => WireEvent::AccessRequestResolved {
            id: id.to_string(),
            status: RequestStatus::from(status),
        },
        CoreEvent::AgentActivity {
            agent_id,
            event_type,
            item_id,
            at,
        } => WireEvent::AgentActivity {
            agent_id: agent_id.to_string(),
            event_type: event_type.to_owned(),
            item_id: item_id.map(|i| i.to_string()),
            at: at.to_string(),
        },
        CoreEvent::LeaseChanged(id) => WireEvent::LeaseChanged { id: id.to_string() },
        CoreEvent::AutoLockTick { seconds_left } => WireEvent::AutolockTick {
            seconds_left: u32::try_from(seconds_left).unwrap_or(u32::MAX),
        },
        CoreEvent::MassReadAlert {
            agent_id,
            distinct_items,
        } => WireEvent::MassReadAlert {
            agent_id: agent_id.to_string(),
            distinct_items,
        },
        CoreEvent::HeaderMismatch => WireEvent::HeaderMismatch,
        CoreEvent::IntegrityAlert { table, row_id } => WireEvent::IntegrityAlert {
            table: table.to_owned(),
            row_id,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use cerberus_types::{
        AccessRequestId, AccessRequestStatus, AgentId, ItemId, LeaseId, VaultStateKind, t0,
    };
    use serde_json::json;

    use super::*;

    /// Every core event, once.
    fn every_core_event() -> Vec<CoreEvent> {
        vec![
            CoreEvent::StateChanged(VaultStateKind::Unlocked),
            CoreEvent::AccessRequestCreated(AccessRequestId::generate()),
            CoreEvent::AccessRequestResolved {
                id: AccessRequestId::generate(),
                status: AccessRequestStatus::Approved,
            },
            CoreEvent::AgentActivity {
                agent_id: AgentId::generate(),
                event_type: "secret.reveal",
                item_id: Some(ItemId::generate()),
                at: t0(),
            },
            CoreEvent::LeaseChanged(LeaseId::generate()),
            CoreEvent::AutoLockTick { seconds_left: 30 },
            CoreEvent::MassReadAlert {
                agent_id: AgentId::generate(),
                distinct_items: 12,
            },
            CoreEvent::HeaderMismatch,
            CoreEvent::IntegrityAlert {
                table: "items",
                row_id: "row-1".to_owned(),
            },
        ]
    }

    #[test]
    fn every_core_event_maps_and_round_trips() {
        let events = every_core_event();
        let mut names: Vec<&str> = Vec::new();
        for event in events {
            let wire = from_core(event);
            let text = serde_json::to_value(&wire).unwrap();
            assert_eq!(text["event"], wire.name());
            let back: WireEvent = serde_json::from_value(text).unwrap();
            assert_eq!(back, wire);
            names.push(wire.name());
        }
        names.dedup();
        assert_eq!(names.len(), 9, "one wire event per core event");
    }

    #[test]
    fn fields_are_those_of_the_desktop_events() {
        let id = LeaseId::generate();
        assert_eq!(
            serde_json::to_value(from_core(CoreEvent::LeaseChanged(id))).unwrap(),
            json!({ "event": "LeaseChanged", "id": id.to_string() })
        );
        assert_eq!(
            serde_json::to_value(from_core(CoreEvent::StateChanged(VaultStateKind::Sealed)))
                .unwrap(),
            json!({ "event": "VaultStateChanged", "state": "sealed" })
        );
        assert_eq!(
            serde_json::to_value(from_core(CoreEvent::HeaderMismatch)).unwrap(),
            json!({ "event": "HeaderMismatch" })
        );
        assert_eq!(
            serde_json::to_value(from_core(CoreEvent::AutoLockTick {
                seconds_left: u64::MAX
            }))
            .unwrap(),
            json!({ "event": "AutolockTick", "seconds_left": u32::MAX })
        );
        let pending = WireEvent::PendingCountChanged { count: 3 };
        assert_eq!(
            serde_json::to_value(&pending).unwrap(),
            json!({ "event": "PendingCountChanged", "count": 3 })
        );
    }
}
