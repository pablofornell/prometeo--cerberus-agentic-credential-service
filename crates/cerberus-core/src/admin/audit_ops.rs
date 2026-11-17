//! Audit and backup commands (IPC `audit_query`, `audit_verify`, `audit_export`,
//! `backup_create`, and the role check of `backup_restore`).

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use cerberus_types::{AgentId, ItemId, OperatorRole, VaultStateKind};
use jiff::Timestamp;

use crate::audit::{Actor, AuditEvent, BreakKind, ChainReport, EventType};
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::Index;
use crate::vault::{VaultService, by_operator};

/// Largest page of [`VaultService::audit_query`].
pub const MAX_AUDIT_QUERY_LIMIT: u32 = 1000;
/// Rows read from the store at a time.
const PAGE: u32 = 500;
/// The `result` of a good event (`AuditEvent::new`).
const OK_RESULT: &str = "ok";
/// Longest text of the [`AuditQuery::text`] filter, in characters.
pub const MAX_AUDIT_TEXT_CHARS: usize = 200;

/// The result part of an event: `ok`, or an error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The event has the result `ok`.
    Ok,
    /// The event has an error code as result.
    Failed,
}

/// A filter for the audit screen. All parts are optional except `limit`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditQuery {
    /// Events at or after this time.
    pub from: Option<Timestamp>,
    /// Events before this time.
    pub to: Option<Timestamp>,
    /// Event type name, for example `item.reveal`.
    pub event_type: Option<String>,
    /// Events by this agent, or about it (`details.agent_id`).
    pub agent_id: Option<AgentId>,
    /// Events about this item (target or `details.item_id`).
    pub item_id: Option<ItemId>,
    /// Only events with this outcome (DEC-INT10-11).
    pub outcome: Option<AuditOutcome>,
    /// Only rows with a lower `seq` (the next page of a newest-first list).
    pub before_seq: Option<u64>,
    /// Page size, 1..=1000.
    pub limit: u32,
    /// Free text, 1..=200 characters, no case. It matches metadata only: the event type, the
    /// target kind and ID, the actor ID, the agent name of the actor, target or
    /// `details.agent_id`, and the item title of the target or `details.item_id`. It never
    /// looks at other detail values (DEC-T27-A2-8).
    pub text: Option<String>,
}

/// The names that the text filter can match, read once per query.
struct TextFilter<'a> {
    needle: String,
    agent_names: HashMap<String, String>,
    index: &'a Index,
}

impl TextFilter<'_> {
    fn hit(&self, text: &str) -> bool {
        text.to_lowercase().contains(&self.needle)
    }

    fn matches(&self, event: &AuditEvent) -> bool {
        let detail = |key: &str| event.details.get(key).and_then(serde_json::Value::as_str);
        let target = event.target.as_ref();
        let target_of = |kind: &str| target.filter(|t| t.kind == kind).map(|t| t.id.as_str());
        let agents = [
            event.actor.id.as_deref(),
            detail("agent_id"),
            target_of("agent"),
        ];
        let items = [target_of("item"), detail("item_id")];
        self.hit(&event.event_type)
            || target.is_some_and(|t| self.hit(&t.kind) || self.hit(&t.id))
            || event.actor.id.as_deref().is_some_and(|id| self.hit(id))
            || agents
                .into_iter()
                .flatten()
                .filter_map(|id| self.agent_names.get(id))
                .any(|name| self.hit(name))
            || items
                .into_iter()
                .flatten()
                .filter_map(|id| id.parse::<ItemId>().ok())
                .filter_map(|id| self.index.item(&id))
                .any(|meta| self.hit(&meta.title))
    }
}

/// One audit row as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// Position in the chain.
    pub seq: u64,
    /// Time of the event.
    pub occurred_at: Timestamp,
    /// The opened body.
    pub event: AuditEvent,
}

fn matches(query: &AuditQuery, occurred_at: Timestamp, event: &AuditEvent) -> bool {
    let detail_is = |key: &str, id: &str| {
        event
            .details
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| value == id)
    };
    let target_is = |kind: &str, id: &str| {
        event
            .target
            .as_ref()
            .is_some_and(|t| t.kind == kind && t.id == id)
    };
    let agent_ok = query.agent_id.is_none_or(|agent| {
        let id = agent.to_string();
        event.actor.id.as_deref() == Some(id.as_str())
            || detail_is("agent_id", &id)
            || target_is("agent", &id)
    });
    let item_ok = query.item_id.is_none_or(|item| {
        let id = item.to_string();
        target_is("item", &id) || detail_is("item_id", &id)
    });
    query.from.is_none_or(|from| occurred_at >= from)
        && query.to.is_none_or(|to| occurred_at < to)
        && query
            .event_type
            .as_deref()
            .is_none_or(|t| event.event_type == t)
        && query.outcome.is_none_or(|outcome| {
            let ok = event.result == OK_RESULT;
            ok == (outcome == AuditOutcome::Ok)
        })
        && agent_ok
        && item_ok
}

const fn break_text(kind: BreakKind) -> &'static str {
    match kind {
        BreakKind::HmacMismatch => "hmac_mismatch",
        BreakKind::PrevHashMismatch => "prev_hash_mismatch",
        BreakKind::MissingRow => "missing_row",
        BreakKind::HeadMismatch => "head_mismatch",
        BreakKind::UnreadableBody => "unreadable_body",
    }
}

/// Makes `dest` as a new file with mode 0600 (it must not exist).
fn new_private_file(dest: &Path) -> Result<std::fs::File, CoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(dest)
        .map_err(|error| CoreError::Store(cerberus_store::StoreError::Io(error)))
}

impl VaultService {
    /// IPC `audit_query`: matching rows, newest first, at most `limit`. Any role. Rows whose
    /// body does not open are skipped (`audit_verify` names them).
    ///
    /// # Errors
    /// `Validation` (limit), `Locked`, the role check, or a storage error.
    pub async fn audit_query(
        &self,
        ctx: &OperatorContext,
        query: AuditQuery,
    ) -> Result<Vec<AuditEntry>, CoreError> {
        if !(1..=MAX_AUDIT_QUERY_LIMIT).contains(&query.limit) {
            return Err(CoreError::Validation(vec![cerberus_types::FieldProblem {
                field: "limit".to_owned(),
                problem: "must be 1..1000".to_owned(),
            }]));
        }
        let needle = query
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase);
        if needle
            .as_ref()
            .is_some_and(|t| t.chars().count() > MAX_AUDIT_TEXT_CHARS)
        {
            return Err(CoreError::Validation(vec![cerberus_types::FieldProblem {
                field: "text".to_owned(),
                problem: "must be at most 200 characters".to_owned(),
            }]));
        }
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let filter = match needle {
            Some(needle) => Some(TextFilter {
                needle,
                agent_names: self
                    .policy()
                    .agent_names(&guard)
                    .await?
                    .into_iter()
                    .map(|(id, name)| (id.to_string(), name))
                    .collect(),
                index: &guard.index,
            }),
            None => None,
        };
        let Some(head) = self.store().audit_head().await? else {
            return Ok(Vec::new());
        };
        let blobs = guard.blobs();
        let limit = usize::try_from(query.limit).unwrap_or(usize::MAX);
        let mut out = Vec::new();
        let mut end = query
            .before_seq
            .map_or(head.last_seq, |before| before.saturating_sub(1))
            .min(head.last_seq);
        while end >= head.anchor_seq && end > 0 && out.len() < limit {
            let start = end.saturating_sub(u64::from(PAGE) - 1).max(head.anchor_seq);
            let count = u32::try_from(end - start + 1).unwrap_or(PAGE);
            let rows = self.store().audit_range(start, count).await?;
            for row in rows.iter().rev() {
                let Ok(event) = crate::audit::open_audit_body(&blobs, row) else {
                    continue;
                };
                if matches(&query, row.occurred_at, &event)
                    && filter.as_ref().is_none_or(|f| f.matches(&event))
                {
                    out.push(AuditEntry {
                        seq: row.seq,
                        occurred_at: row.occurred_at,
                        event,
                    });
                    if out.len() == limit {
                        break;
                    }
                }
            }
            end = start.saturating_sub(1);
        }
        Ok(out)
    }

    /// IPC `audit_verify`: walks the chain (ADR-0025) and writes `audit.verify` with the result.
    /// Any role.
    ///
    /// # Errors
    /// `Locked`, the role check, or a storage error.
    pub async fn audit_verify(&self, ctx: &OperatorContext) -> Result<ChainReport, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let report = guard.audit.verify().await?;
        let event =
            by_operator(EventType::AuditVerify, ctx).target("vault", guard.vault_id.to_string());
        let event = match report {
            ChainReport::Ok { count, .. } => event.detail("chain", "ok").detail("count", count),
            ChainReport::Broken { seq, kind } => event
                .result(crate::error::CoreError::Corrupt.code().as_str())
                .detail("chain", "broken")
                .detail("seq", seq)
                .detail("kind", break_text(kind)),
        };
        self.audit(&guard, event).await;
        Ok(report)
    }

    /// IPC `audit_export`: JSON Lines to `dest`, a new file with mode 0600 (the export holds
    /// titles, ADR-0025). Writes `audit.export`. Any role. Returns the number of lines. A failed
    /// export removes its file.
    ///
    /// # Errors
    /// `Store(Io)` when `dest` exists or cannot be written, `Locked`, the role check, or a
    /// storage error.
    pub async fn audit_export(&self, ctx: &OperatorContext, dest: &Path) -> Result<u64, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let file = new_private_file(dest)?;
        let mut out = std::io::BufWriter::new(file);
        let actor = Actor::operator(ctx.operator_id.to_string());
        let written = match guard.audit.export_jsonl(actor, &mut out).await {
            Ok(count) => out
                .flush()
                .map(|()| count)
                .map_err(|error| CoreError::Store(cerberus_store::StoreError::Io(error))),
            Err(error) => Err(error),
        };
        if written.is_err() {
            drop(out);
            // The file is ours and holds no complete export.
            drop(std::fs::remove_file(dest));
        }
        written
    }

    /// IPC `backup_create`: a copy of the encrypted vault at `dest` (ADR-0031). Role operator.
    /// The role is checked first; the copy runs without the vault guard (it may take a while and
    /// needs no key), then `backup.create` is written.
    ///
    /// # Errors
    /// `Store(Io)` when `dest` exists, `Locked`, the role check, or a storage error.
    pub async fn backup_create(&self, ctx: &OperatorContext, dest: &Path) -> Result<(), CoreError> {
        self.authorize_role(ctx, OperatorRole::Operator).await?;
        self.store().backup_to(dest).await?;
        match self.unlocked().await {
            Ok(guard) => {
                let event = by_operator(EventType::BackupCreate, ctx)
                    .target("vault", guard.vault_id.to_string());
                self.audit(&guard, event).await;
            }
            Err(_) => tracing::warn!("vault locked during backup; backup.create not written"),
        }
        Ok(())
    }

    /// Writes `backup.restore` after the desktop swapped the vault file and unlocked the
    /// restored vault (DEC-FIX8-2). The event is part of the restored chain. The role comes from
    /// the session of the restored vault (any role: that session was proved by the credential).
    /// The event holds no path and no secret.
    ///
    /// # Errors
    /// `Locked`, `Forbidden` (wrong session), or the audit write error.
    pub async fn record_restore(&self, ctx: &OperatorContext) -> Result<(), CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let event =
            by_operator(EventType::BackupRestore, ctx).target("vault", guard.vault_id.to_string());
        self.audit_strict(&guard, event).await
    }

    /// The role check of IPC `backup_restore` (ADR-0031): allowed in state `NoVault` without a
    /// context, else only for an owner session. The desktop layer then locks, closes the store,
    /// calls `cerberus_store::restore_backup`, opens a new service and unlocks it.
    ///
    /// # Errors
    /// `Locked` (sealed: unlock first), `Forbidden` (no context), or the role check.
    pub async fn authorize_restore(&self, ctx: Option<&OperatorContext>) -> Result<(), CoreError> {
        if self.state() == VaultStateKind::NoVault {
            return Ok(());
        }
        let ctx = ctx.ok_or(CoreError::Forbidden)?;
        self.authorize_role(ctx, OperatorRole::Owner).await
    }
}
