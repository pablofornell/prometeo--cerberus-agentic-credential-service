//! Grant CRUD (IPC `grant_list`, `grant_put`, `grant_delete`). Roles come from the unlocked
//! session (DEC-T05-5): any role lists; operator or owner changes; `allow_prod_auto` needs the
//! owner (ADR-0017 consequences).
//!
//! A change writes the DB first, then the index, both under the vault write guard, so a decision
//! never sees a grant the DB does not have.

use cerberus_crypto::SecretBytes;
use cerberus_store::{AgentStatus, GrantRow, StoreError};
use cerberus_types::{AgentId, FieldProblem, GrantId, GrantMode, OperatorRole};

use super::body::encode_grant;
use super::engine::{agent_grants, permission_text, whole_ms};
use super::{Grant, GrantInput, PolicyEngine, specificity};
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::{Index, grant_entry};

/// Most entries in one selector field.
pub const MAX_SELECTOR_ENTRIES: usize = 64;
/// Longest text entry (category, tag, role label), in characters.
pub const MAX_TEXT_CHARS: usize = 80;
/// Highest `max_reads_per_hour`.
const MAX_READS_PER_HOUR: u32 = 10_000;

fn problem(field: &str, text: &str) -> FieldProblem {
    FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }
}

fn check_texts(field: &str, list: &[String], problems: &mut Vec<FieldProblem>) {
    if list.len() > MAX_SELECTOR_ENTRIES {
        problems.push(problem(field, "too many entries"));
    }
    if list
        .iter()
        .any(|t| t.trim().is_empty() || t.chars().count() > MAX_TEXT_CHARS)
    {
        problems.push(problem(field, "entries must be 1 to 80 characters"));
    }
}

/// Checks a grant input. `now` is the time of the change.
///
/// # Errors
/// [`CoreError::Validation`] with every problem found.
pub fn validate(input: &GrantInput, now: jiff::Timestamp) -> Result<(), CoreError> {
    let mut problems = Vec::new();
    let s = &input.selector;
    let too_many = |len: usize| len > MAX_SELECTOR_ENTRIES;
    if too_many(s.workspace_ids.len())
        || too_many(s.environments.len())
        || too_many(s.kinds.len())
        || too_many(s.item_ids.len())
    {
        problems.push(problem("selector", "too many entries"));
    }
    check_texts("selector.categories", &s.categories, &mut problems);
    check_texts("selector.tags", &s.tags, &mut problems);
    check_texts("selector.role_labels", &s.role_labels, &mut problems);
    if input.permissions.is_empty() && input.mode != GrantMode::Deny {
        problems.push(problem("permissions", "must not be empty"));
    }
    let c = &input.conditions;
    if let Some(window) = &c.time_window {
        if window.days.is_empty() {
            problems.push(problem("conditions.time_window.days", "must not be empty"));
        }
        let whole_minute = |t: jiff::civil::Time| t.second() == 0 && t.subsec_nanosecond() == 0;
        if window.start == window.end || !whole_minute(window.start) || !whole_minute(window.end) {
            problems.push(problem(
                "conditions.time_window",
                "start and end must differ and be whole minutes",
            ));
        }
        if jiff::tz::TimeZone::get(&window.tz).is_err() {
            problems.push(problem("conditions.time_window.tz", "unknown time zone"));
        }
    }
    if c.max_reads_per_hour
        .is_some_and(|n| n == 0 || n > MAX_READS_PER_HOUR)
    {
        problems.push(problem(
            "conditions.max_reads_per_hour",
            "must be 1 to 10000",
        ));
    }
    if c.expires_at.is_some_and(|end| end <= now) {
        problems.push(problem("conditions.expires_at", "must be in the future"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(CoreError::Validation(problems))
    }
}

/// Finds a grant in the index by ID (any agent).
fn find_grant(index: &Index, agents: &[AgentId], id: &GrantId) -> Option<Grant> {
    agents
        .iter()
        .flat_map(|agent| agent_grants(index, agent))
        .find(|g| g.id == *id)
}

fn grant_event(event: EventType, ctx: &OperatorContext, grant: &Grant) -> AuditEvent {
    let permissions: Vec<&str> = grant
        .permissions
        .iter()
        .map(|p| permission_text(*p))
        .collect();
    AuditEvent::new(event, Actor::operator(ctx.operator_id.to_string()))
        .request_id(ctx.request_id)
        .target("grant", grant.id.to_string())
        .detail("agent_id", grant.agent_id.to_string())
        .detail("mode", serde_json::to_value(grant.mode).unwrap_or_default())
        .detail("permissions", serde_json::json!(permissions))
        .detail("specificity", specificity(&grant.selector))
        .detail("allow_prod_auto", grant.allow_prod_auto)
}

impl PolicyEngine {
    /// All grants, or the grants of one agent. Any role.
    ///
    /// # Errors
    /// `Locked`, the role check, or a storage error.
    pub async fn list_grants(
        &self,
        ctx: &OperatorContext,
        agent: Option<AgentId>,
    ) -> Result<Vec<Grant>, CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Viewer).await?;
        let agents = match agent {
            Some(id) => vec![id],
            None => {
                let (rows, _) = self.service.store().load_auth_rows().await?;
                rows.iter().map(|row| row.id).collect()
            }
        };
        let mut out: Vec<Grant> = agents
            .iter()
            .flat_map(|id| agent_grants(&guard.index, id))
            .collect();
        out.sort_by_key(|g| (g.created_at, g.id.0));
        Ok(out)
    }

    /// Creates or changes a grant. Operator or owner; `allow_prod_auto` (new, or on the grant
    /// being changed) needs the owner.
    ///
    /// # Errors
    /// `Validation`, `NotFound` (unknown grant ID or agent), `Conflict` (revoked agent),
    /// `RoleNotAllowed`, `Locked`, or a storage error.
    pub async fn put_grant(
        &self,
        ctx: &OperatorContext,
        input: GrantInput,
    ) -> Result<Grant, CoreError> {
        let mut guard = self.service.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Operator)?;
        let now = whole_ms(self.now());
        validate(&input, now)?;
        let (agents, _) = self.service.store().load_auth_rows().await?;
        match agents.iter().find(|row| row.id == input.agent_id) {
            None => return Err(CoreError::NotFound),
            Some(row) if row.status == AgentStatus::Revoked => return Err(CoreError::Conflict),
            Some(_) => {}
        }
        let agent_ids: Vec<AgentId> = agents.iter().map(|row| row.id).collect();
        let old = match input.id {
            Some(id) => Some(find_grant(&guard.index, &agent_ids, &id).ok_or(CoreError::NotFound)?),
            None => None,
        };
        if input.allow_prod_auto || old.as_ref().is_some_and(|g| g.allow_prod_auto) {
            guard.session.authorize(ctx, OperatorRole::Owner)?;
        }
        let grant = Grant {
            id: input.id.unwrap_or_else(GrantId::generate),
            agent_id: input.agent_id,
            selector: input.selector,
            permissions: input.permissions,
            mode: input.mode,
            conditions: super::Conditions {
                expires_at: input.conditions.expires_at.map(whole_ms),
                ..input.conditions
            },
            allow_prod_auto: input.allow_prod_auto,
            created_at: old.as_ref().map_or(now, |g| g.created_at),
            updated_at: now,
        };
        let json = encode_grant(&grant).map_err(|_| CoreError::Corrupt)?;
        let row = GrantRow {
            id: grant.id,
            agent_id: grant.agent_id,
            created_at: grant.created_at,
            updated_at: now,
            expires_at: grant.conditions.expires_at,
            body_ct: guard.blobs().seal_grant_body(&grant.id, &json)?,
        };
        let mut tx = self.service.store().begin().await?;
        tx.put_grant(&row).await?;
        tx.commit().await?;
        guard
            .index
            .upsert_grant(grant_entry(&row, SecretBytes::new(json.to_vec())));
        let event = if old.is_some() {
            EventType::GrantUpdate
        } else {
            EventType::GrantCreate
        };
        self.service
            .audit(&guard, grant_event(event, ctx, &grant))
            .await;
        Ok(grant)
    }

    /// Deletes a grant. Operator or owner; a grant with `allow_prod_auto` needs the owner.
    ///
    /// # Errors
    /// `NotFound`, `RoleNotAllowed`, `Locked`, or a storage error.
    pub async fn delete_grant(&self, ctx: &OperatorContext, id: GrantId) -> Result<(), CoreError> {
        let mut guard = self.service.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Operator)?;
        let (agents, _) = self.service.store().load_auth_rows().await?;
        let agent_ids: Vec<AgentId> = agents.iter().map(|row| row.id).collect();
        let old = find_grant(&guard.index, &agent_ids, &id);
        if old.as_ref().is_some_and(|g| g.allow_prod_auto) {
            guard.session.authorize(ctx, OperatorRole::Owner)?;
        }
        let mut tx = self.service.store().begin().await?;
        match tx.delete_grant(id).await {
            Ok(()) => {}
            Err(StoreError::NotFound) => return Err(CoreError::NotFound),
            Err(error) => return Err(error.into()),
        }
        tx.commit().await?;
        guard.index.remove_grant(&id);
        let mut event = AuditEvent::new(
            EventType::GrantDelete,
            Actor::operator(ctx.operator_id.to_string()),
        )
        .request_id(ctx.request_id)
        .target("grant", id.to_string());
        if let Some(g) = &old {
            event = event.detail("agent_id", g.agent_id.to_string());
        }
        self.service.audit(&guard, event).await;
        Ok(())
    }
}
