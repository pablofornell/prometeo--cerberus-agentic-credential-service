//! The audit log: an append-only, HMAC-chained record of every call (ADR-0025).
//!
//! - [`AuditWriter`] appends events, drains the events written while locked, prunes by retention
//!   and exports JSON lines. The vault service builds one at unlock and drops it at lock.
//! - [`verify_chain`] walks the chain and names the first broken `seq` ([`ChainReport`]).
//! - [`EventType`] is the catalog of event types.
//!
//! An [`AuditEvent`] holds only plain data. The crypto secret types do not implement `Serialize`,
//! so no secret value can be put in a body.

mod catalog;
mod chain;
mod export;
mod verify;
mod writer;

#[cfg(test)]
mod tests;

use cerberus_types::RequestId;
use serde::{Deserialize, Serialize};

pub use catalog::{EventType, UnknownEventType};
pub use chain::{entry_hash, genesis_prev_hash};
pub(crate) use verify::ChainWalk;
pub(crate) use verify::open_body as open_audit_body;
pub use verify::{BreakKind, ChainReport, verify_chain};
pub use writer::AuditWriter;

/// Longest text kept in a body field. Longer text is cut (ADR-0025).
pub const MAX_TEXT_CHARS: usize = 500;

/// Who did it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The kind of actor.
    pub kind: ActorKind,
    /// The agent or operator ID. `None` for the system.
    pub id: Option<String>,
}

impl Actor {
    /// The vault itself (sweeper, retention, startup).
    #[must_use]
    pub const fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: None,
        }
    }

    /// An agent, by ID text.
    #[must_use]
    pub fn agent(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Agent,
            id: Some(id.into()),
        }
    }

    /// An operator, by ID text.
    #[must_use]
    pub fn operator(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Operator,
            id: Some(id.into()),
        }
    }
}

/// The kind of actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// An agent with a token.
    Agent,
    /// A person using the desktop app.
    Operator,
    /// The vault itself.
    System,
}

/// What the event is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Kind of object, for example `item`.
    pub kind: String,
    /// ID of the object.
    pub id: String,
}

/// The body sealed inside `audit_events.body_ct`. It has no field that can hold a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event type name (see [`EventType`]).
    #[serde(rename = "type")]
    pub event_type: String,
    /// Who did it.
    pub actor: Actor,
    /// What it was done to.
    pub target: Option<Target>,
    /// `ok` or an error code.
    pub result: String,
    /// The request this event belongs to.
    pub request_id: Option<RequestId>,
    /// Extra metadata. Never a secret value.
    pub details: serde_json::Map<String, serde_json::Value>,
}

impl AuditEvent {
    /// A successful event of `event_type` done by `actor`.
    #[must_use]
    pub fn new(event_type: EventType, actor: Actor) -> Self {
        Self {
            event_type: event_type.as_str().to_owned(),
            actor,
            target: None,
            result: "ok".to_owned(),
            request_id: None,
            details: serde_json::Map::new(),
        }
    }

    /// Sets the target.
    #[must_use]
    pub fn target(mut self, kind: impl Into<String>, id: impl Into<String>) -> Self {
        self.target = Some(Target {
            kind: kind.into(),
            id: id.into(),
        });
        self
    }

    /// Sets the result (`ok` or an error code).
    #[must_use]
    pub fn result(mut self, code: impl Into<String>) -> Self {
        self.result = code.into();
        self
    }

    /// Sets the request ID.
    #[must_use]
    pub const fn request_id(mut self, id: RequestId) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Adds one detail. Every text inside the value is cut to [`MAX_TEXT_CHARS`].
    #[must_use]
    pub fn detail(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        let mut value = value.into();
        cut_text(&mut value);
        self.details.insert(key.to_owned(), value);
        self
    }
}

fn cut_text(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if let Some((end, _)) = text.char_indices().nth(MAX_TEXT_CHARS) {
                text.truncate(end);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(cut_text),
        serde_json::Value::Object(map) => map.values_mut().for_each(cut_text),
        _ => {}
    }
}
