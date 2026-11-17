//! The simulator: "what can agent X see?" (plan screen 7, ADR-0017 rules). It runs the same
//! [`evaluate`] for every item and permission, with the reason absent and a read counter that
//! only checks, so a simulation never uses a read.

use cerberus_types::{AgentId, ItemId, OperatorRole, Permission};
use jiff::Timestamp;

use super::engine::{agent_grants, item_live};
use super::limits::Peek;
use super::{
    ALL_PERMISSIONS, Decision, EvalInput, Grant, PolicyEngine, PolicyItem, ReadCounter, evaluate,
};
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::ItemMeta;

/// One row of the simulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationRow {
    /// The item.
    pub item_id: ItemId,
    /// Its title.
    pub title: String,
    /// The permission.
    pub permission: Permission,
    /// What [`evaluate`] says (reason absent).
    pub decision: Decision,
}

/// Rows for every live item and every permission, sorted by item ID then permission.
#[must_use]
pub fn simulate_rows<'a>(
    grants: &[Grant],
    items: impl Iterator<Item = &'a ItemMeta>,
    agent: &AgentId,
    now: Timestamp,
    counter: &dyn ReadCounter,
) -> Vec<SimulationRow> {
    let mut rows = Vec::new();
    for meta in items.filter(|m| item_live(m, now)) {
        for permission in ALL_PERMISSIONS {
            let input = EvalInput {
                grants,
                item: PolicyItem::of(meta),
                permission,
                reason: None,
                now,
            };
            rows.push(SimulationRow {
                item_id: meta.id,
                title: meta.title.to_string(),
                permission,
                decision: evaluate(&input, agent, counter),
            });
        }
    }
    rows.sort_by_key(|row| (row.item_id.0, row.permission));
    rows
}

impl PolicyEngine {
    /// The simulator for one agent. Any role.
    ///
    /// # Errors
    /// `Locked` or the role check.
    pub async fn simulate(
        &self,
        ctx: &OperatorContext,
        agent: AgentId,
    ) -> Result<Vec<SimulationRow>, CoreError> {
        let guard = self.service.authorize(ctx, OperatorRole::Viewer).await?;
        let grants = agent_grants(&guard.index, &agent);
        Ok(simulate_rows(
            &grants,
            guard.index.iter_items(),
            &agent,
            self.now(),
            &Peek(&self.state().limiter),
        ))
    }
}
