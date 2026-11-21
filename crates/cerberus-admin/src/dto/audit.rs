//! Types of the audit commands.

use cerberus_core::admin::{AuditEntry, AuditOutcome, AuditQuery};
use cerberus_core::audit::ChainReport;
use serde::{Deserialize, Serialize};
use specta::Type;

use super::{opt_id, opt_parse_ts, ts};
use crate::error::IpcResult;

/// Outcome of an audit event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcomeView {
    /// The result is `ok`.
    Ok,
    /// The result is an error code.
    Failed,
}

impl From<AuditOutcomeView> for AuditOutcome {
    fn from(value: AuditOutcomeView) -> Self {
        match value {
            AuditOutcomeView::Ok => Self::Ok,
            AuditOutcomeView::Failed => Self::Failed,
        }
    }
}

/// Filter of `audit_query`.
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct AuditQueryView {
    /// Events at or after this time.
    pub from: Option<String>,
    /// Events before this time.
    pub to: Option<String>,
    /// Event type name.
    pub event_type: Option<String>,
    /// Events by or about this agent.
    pub agent_id: Option<String>,
    /// Events about this item.
    pub item_id: Option<String>,
    /// Only events with this outcome. `null` or no key: all events.
    #[serde(default)]
    pub outcome: Option<AuditOutcomeView>,
    /// Only rows with a lower sequence number (the next page).
    pub before_seq: Option<u64>,
    /// Page size, 1 to 1000.
    pub limit: u32,
    /// Free text, 1 to 200 characters, no case. It matches the event type, the target, the
    /// actor ID, agent names and item titles (metadata only). `null` or no key: no text filter.
    #[serde(default)]
    pub text: Option<String>,
}

impl AuditQueryView {
    /// The core query.
    ///
    /// # Errors
    /// `validation_failed` for a bad time or ID.
    pub fn into_core(self) -> IpcResult<AuditQuery> {
        Ok(AuditQuery {
            from: opt_parse_ts("from", self.from.as_deref())?,
            to: opt_parse_ts("to", self.to.as_deref())?,
            event_type: self.event_type,
            agent_id: opt_id("agent_id", self.agent_id.as_deref())?,
            item_id: opt_id("item_id", self.item_id.as_deref())?,
            outcome: self.outcome.map(Into::into),
            before_seq: self.before_seq,
            limit: self.limit,
            text: self.text,
        })
    }
}

/// One audit row. `details` holds metadata only, never a secret.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Type)]
pub struct AuditEntryView {
    /// Position in the chain.
    pub seq: u64,
    /// Time of the event.
    pub occurred_at: String,
    /// Event type, for example `item.reveal`.
    pub event_type: String,
    /// `agent`, `operator` or `system`.
    pub actor_kind: String,
    /// Agent or operator ID.
    pub actor_id: Option<String>,
    /// Kind of the object the event is about.
    pub target_kind: Option<String>,
    /// ID of that object.
    pub target_id: Option<String>,
    /// `ok` or an error code.
    pub result: String,
    /// Request ID.
    pub request_id: Option<String>,
    /// Metadata.
    pub details: serde_json::Value,
}

impl From<AuditEntry> for AuditEntryView {
    fn from(value: AuditEntry) -> Self {
        let event = value.event;
        let actor_kind = match event.actor.kind {
            cerberus_core::audit::ActorKind::Agent => "agent",
            cerberus_core::audit::ActorKind::Operator => "operator",
            cerberus_core::audit::ActorKind::System => "system",
        };
        let (target_kind, target_id) = match event.target {
            Some(target) => (Some(target.kind), Some(target.id)),
            None => (None, None),
        };
        Self {
            seq: value.seq,
            occurred_at: ts(value.occurred_at),
            event_type: event.event_type,
            actor_kind: actor_kind.to_owned(),
            actor_id: event.actor.id,
            target_kind,
            target_id,
            result: event.result,
            request_id: event.request_id.map(|r| r.to_string()),
            details: serde_json::Value::Object(event.details),
        }
    }
}

/// Result of `audit_verify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ChainReportView {
    /// True when every row is good.
    pub ok: bool,
    /// Rows checked (when ok).
    pub count: u64,
    /// First sequence number checked (when ok).
    pub first_seq: u64,
    /// Last sequence number checked (when ok).
    pub last_seq: u64,
    /// The first broken sequence number (when not ok).
    pub broken_seq: Option<u64>,
    /// What is wrong there (when not ok).
    pub break_kind: Option<String>,
}

impl From<ChainReport> for ChainReportView {
    fn from(value: ChainReport) -> Self {
        match value {
            ChainReport::Ok {
                count,
                first_seq,
                last_seq,
            } => Self {
                ok: true,
                count,
                first_seq,
                last_seq,
                broken_seq: None,
                break_kind: None,
            },
            ChainReport::Broken { seq, kind } => Self {
                ok: false,
                count: 0,
                first_seq: 0,
                last_seq: 0,
                broken_seq: Some(seq),
                break_kind: Some(format!("{kind:?}")),
            },
        }
    }
}
