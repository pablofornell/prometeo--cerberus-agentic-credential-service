//! The policy view that resolve uses (`crate::resolve::ResolvePolicy`, T06).
//!
//! Resolve runs under its own vault guard and asks policy synchronously. So the engine first
//! takes a snapshot for one agent (grants, its active approval leases, the time),
//! drops its guard, and resolve then asks the snapshot. The snapshot only answers "would this
//! read be allowed now or need a person". It hands out nothing: the secret itself goes only
//! through [`PolicyEngine::authorize_secret`], which counts the read, uses or makes the lease and
//! opens the request.

use std::collections::HashMap;

use cerberus_store::{LeaseRow, LeaseSource};
use cerberus_types::{AgentId, GrantMode, ItemId, Permission};
use jiff::Timestamp;

use super::engine::{agent_grants, decision_error, item_live};
use super::limits::Peek;
use super::{Decision, EvalInput, Grant, PolicyEngine, PolicyItem, can_find, evaluate};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::index::ItemMeta;
use crate::leases::{is_active, serves};
use crate::resolve::{ReadAccess, ResolvePolicy};

/// Policy for one resolve call of one agent.
#[derive(Debug)]
pub struct ResolveSnapshot<'a> {
    engine: &'a PolicyEngine,
    agent: AgentId,
    grants: Vec<Grant>,
    reason_present: bool,
    /// Active approval read leases by item. Which of them serves a read depends on the mode.
    approved: HashMap<ItemId, Vec<LeaseRow>>,
    approvals_available: bool,
    now: Timestamp,
}

impl PolicyEngine {
    /// A [`ResolveSnapshot`] for the agent of `ctx`. `purpose` is checked for presence only.
    /// Takes the vault guard for this call and releases it before it returns.
    ///
    /// # Errors
    /// `Locked`, or a storage error.
    pub async fn resolve_policy(
        &self,
        ctx: &AgentContext,
        purpose: Option<&str>,
    ) -> Result<ResolveSnapshot<'_>, CoreError> {
        let guard = self.service.unlocked().await?;
        let now = self.now();
        let macs = guard.row_macs();
        let mut approved: HashMap<ItemId, Vec<LeaseRow>> = HashMap::new();
        for row in self.service.store().live_leases(now).await? {
            if row.agent_id != ctx.agent_id || row.permission != Permission::Read {
                continue;
            }
            if !macs.verify_lease(&row)? {
                self.mac_alert(&guard, "leases", row.id.to_string()).await;
                continue;
            }
            if row.source == LeaseSource::Approval && is_active(&row, now) {
                approved.entry(row.item_id).or_default().push(row);
            }
        }
        Ok(ResolveSnapshot {
            engine: self,
            agent: ctx.agent_id,
            grants: agent_grants(&guard.index, &ctx.agent_id),
            reason_present: super::reason_present(purpose),
            approved,
            approvals_available: self.service.config().approvals_available,
            now,
        })
    }
}

impl ResolvePolicy for ResolveSnapshot<'_> {
    fn can_find(&self, item: &ItemMeta) -> bool {
        item_live(item, self.now) && can_find(&self.grants, &self.agent, item, self.now)
    }

    fn read_access(&self, item: &ItemMeta) -> Result<ReadAccess, CoreError> {
        // Presence is all policy may see of the purpose; a fixed stand-in keeps the words out.
        let reason = self.reason_present.then_some("reason given");
        let decision = evaluate(
            &EvalInput {
                grants: &self.grants,
                item: PolicyItem::of(item),
                permission: Permission::Read,
                reason,
                now: self.now,
            },
            &self.agent,
            &Peek(&self.engine.state().limiter),
        );
        match decision {
            Decision::Allow {
                mode: GrantMode::Auto,
                ..
            } => Ok(ReadAccess::Granted),
            // The same lease rule as the read path: `ask_always` needs a one-use approval lease.
            Decision::Allow { mode, .. }
                if self.approved.get(&item.id).is_some_and(|rows| {
                    rows.iter()
                        .any(|row| serves(row, mode, Permission::Read, self.now))
                }) =>
            {
                Ok(ReadAccess::Granted)
            }
            Decision::Allow { .. } if self.approvals_available => Ok(ReadAccess::NeedsApproval),
            Decision::Allow { .. } => Err(CoreError::ApprovalUnavailable),
            other => Err(decision_error(&other)),
        }
    }
}
