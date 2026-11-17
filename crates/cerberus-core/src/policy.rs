//! Grants and policy evaluation (ADR-0017).
//!
//! [`evaluate`] is the one decision function: deny wins, then the most specific grant, then its
//! conditions, then the `prod` rule. It is pure apart from the [`ReadCounter`]. It uses only the
//! agent identity, grant data and item metadata. The reason text is checked for presence only.
//!
//! [`PolicyEngine`] holds the in-memory state around it (read limits, request rate, settings) and
//! runs the grant CRUD, the simulator, leases (`crate::leases`) and approvals (`crate::approvals`).

mod body;
pub(crate) mod engine;
mod grants;
pub(crate) mod limits;
mod resolve_policy;
mod settings;
mod simulate;

#[cfg(test)]
pub(crate) mod testkit;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use cerberus_types::{AgentId, Environment, GrantId, GrantMode, ItemId, ItemKind, Permission};
use jiff::Timestamp;

use crate::index::{ItemMeta, normalize};

pub use body::{GrantParseError, decode_grant, encode_grant};
pub use engine::{PolicyEngine, SecretAccess, SecretAsk, agent_grants};
pub use grants::{MAX_SELECTOR_ENTRIES, MAX_TEXT_CHARS};
pub use limits::{LimitHit, ReadLimiter};
pub use resolve_policy::ResolveSnapshot;
pub use settings::{POLICY_SETTINGS_KEY, PolicySettings};
pub use simulate::{SimulationRow, simulate_rows};

/// Shortest reason text that counts as present for `reason_required` (ADR-0017 step 5).
pub const MIN_REASON_CHARS: usize = 8;

/// The permissions in a fixed order (the simulator shows one row for each).
pub const ALL_PERMISSIONS: [Permission; 5] = [
    Permission::Find,
    Permission::Read,
    Permission::CreateSession,
    Permission::Write,
    Permission::UseSsh,
];

/// Which items a grant covers. An empty field matches every item (ADR-0017 match rules).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selector {
    /// Workspaces.
    pub workspace_ids: Vec<cerberus_types::WorkspaceId>,
    /// Environments.
    pub environments: Vec<Environment>,
    /// Categories (normalized compare).
    pub categories: Vec<String>,
    /// Tags: the item matches when it has at least one of them (normalized compare).
    pub tags: Vec<String>,
    /// Item kinds.
    pub kinds: Vec<ItemKind>,
    /// Role labels (normalized compare).
    pub role_labels: Vec<String>,
    /// Single items.
    pub item_ids: Vec<ItemId>,
}

/// Days and hours in which a grant works. `start > end` means a window over midnight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeWindow {
    /// Days of the week (in `tz`) on which the window opens.
    pub days: Vec<jiff::civil::Weekday>,
    /// Start time, inclusive.
    pub start: jiff::civil::Time,
    /// End time, exclusive.
    pub end: jiff::civil::Time,
    /// IANA time zone name, for example `Europe/Madrid`.
    pub tz: String,
}

/// Extra checks of a grant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conditions {
    /// The grant works only inside this window.
    pub time_window: Option<TimeWindow>,
    /// Most secret reads per hour for this grant and agent.
    pub max_reads_per_hour: Option<u32>,
    /// The grant ends at this time.
    pub expires_at: Option<Timestamp>,
    /// The call must give a reason of at least [`MIN_REASON_CHARS`] characters.
    pub reason_required: bool,
}

/// One grant: an agent, a selector, permissions, a mode and conditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Grant ID.
    pub id: GrantId,
    /// The agent.
    pub agent_id: AgentId,
    /// Which items.
    pub selector: Selector,
    /// What the agent may do. Empty is allowed only for a `deny` grant (it then denies all).
    pub permissions: BTreeSet<Permission>,
    /// How reads are approved.
    pub mode: GrantMode,
    /// Extra checks.
    pub conditions: Conditions,
    /// `prod` reads may use this mode without the forced `ask_always` (owner only).
    pub allow_prod_auto: bool,
    /// Creation time (the tie-break uses it).
    pub created_at: Timestamp,
    /// Last change.
    pub updated_at: Timestamp,
}

/// A grant as the operator enters it. `id = None` makes a new grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantInput {
    /// The grant to change, or `None` for a new one.
    pub id: Option<GrantId>,
    /// The agent.
    pub agent_id: AgentId,
    /// Which items.
    pub selector: Selector,
    /// What the agent may do.
    pub permissions: BTreeSet<Permission>,
    /// How reads are approved.
    pub mode: GrantMode,
    /// Extra checks.
    pub conditions: Conditions,
    /// `prod` reads may skip the forced `ask_always`. Needs the owner role.
    pub allow_prod_auto: bool,
}

/// What an item looks like to policy. For create checks it is the proposed metadata.
#[derive(Clone, Copy, Debug)]
pub struct PolicyItem<'a> {
    /// Workspace.
    pub workspace_id: &'a cerberus_types::WorkspaceId,
    /// Environment.
    pub environment: Environment,
    /// Category.
    pub category: &'a str,
    /// Tags.
    pub tags: &'a [zeroize::Zeroizing<String>],
    /// Kind.
    pub kind: ItemKind,
    /// Role label.
    pub role_label: Option<&'a str>,
    /// Item ID; `None` for an item that does not exist yet.
    pub item_id: Option<&'a ItemId>,
}

impl<'a> PolicyItem<'a> {
    /// The policy view of an indexed item.
    #[must_use]
    pub fn of(meta: &'a ItemMeta) -> Self {
        Self {
            workspace_id: &meta.workspace_id,
            environment: meta.environment,
            category: meta.category.as_str(),
            tags: &meta.tags,
            kind: meta.kind,
            role_label: meta.role_label.as_deref().map(String::as_str),
            item_id: Some(&meta.id),
        }
    }
}

/// The result of [`evaluate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Allowed. `mode` is `Auto`, `AskOnce` or `AskAlways`; it is always `Auto` for `find`,
    /// `write` and `create_session` (ADR-0017 step 8).
    Allow {
        /// The effective mode (after the `prod` rule).
        mode: GrantMode,
        /// The chosen grant.
        grant_id: GrantId,
    },
    /// A `deny` grant matches.
    Deny {
        /// The deny grant.
        grant_id: GrantId,
    },
    /// No grant gives this permission.
    NoGrant,
    /// The chosen grant has a time window and now is outside it.
    ConditionFailed {
        /// The chosen grant.
        grant_id: GrantId,
    },
    /// The chosen grant needs a reason and the call gave none.
    ReasonRequired {
        /// The chosen grant.
        grant_id: GrantId,
    },
    /// The read limit of the chosen grant is used up.
    GrantRateLimited {
        /// The chosen grant.
        grant_id: GrantId,
        /// Seconds until the next read can work.
        retry_after_seconds: u32,
    },
}

impl Decision {
    /// True for [`Decision::Allow`].
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// The stable text name, for audit details.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "allow",
            Self::Deny { .. } => "deny",
            Self::NoGrant => "no_grant",
            Self::ConditionFailed { .. } => "condition_failed",
            Self::ReasonRequired { .. } => "reason_required",
            Self::GrantRateLimited { .. } => "grant_rate_limited",
        }
    }

    /// The grant the decision came from, if any.
    #[must_use]
    pub const fn grant_id(&self) -> Option<GrantId> {
        match self {
            Self::Allow { grant_id, .. }
            | Self::Deny { grant_id }
            | Self::ConditionFailed { grant_id }
            | Self::ReasonRequired { grant_id }
            | Self::GrantRateLimited { grant_id, .. } => Some(*grant_id),
            Self::NoGrant => None,
        }
    }
}

/// The input of one decision.
#[derive(Clone, Copy, Debug)]
pub struct EvalInput<'a> {
    /// The grants of the agent (other agents' grants are ignored).
    pub grants: &'a [Grant],
    /// The item.
    pub item: PolicyItem<'a>,
    /// The permission asked for.
    pub permission: Permission,
    /// The reason or purpose text. Only its presence is checked.
    pub reason: Option<&'a str>,
    /// The time of the call.
    pub now: Timestamp,
}

/// Counts secret reads per (grant, agent) over a sliding hour.
pub trait ReadCounter: Send + Sync {
    /// Checks the limit and, when under it, counts one read. `Err` holds the seconds to wait.
    ///
    /// # Errors
    /// The seconds until a read is free again.
    fn check_and_record(
        &self,
        grant: &GrantId,
        agent: &AgentId,
        limit: u32,
        now: Timestamp,
    ) -> Result<(), u32>;
}

/// True when `permission` uses the grant mode (secret reads).
#[must_use]
pub const fn is_secret_permission(permission: Permission) -> bool {
    matches!(permission, Permission::Read | Permission::UseSsh)
}

/// Permission implication (ADR-0017 match rule 4): `read` and `use_ssh` imply `find`.
fn grant_gives(grant: &Grant, permission: Permission) -> bool {
    if grant.mode == GrantMode::Deny && grant.permissions.is_empty() {
        return true;
    }
    grant.permissions.contains(&permission)
        || (permission == Permission::Find
            && (grant.permissions.contains(&Permission::Read)
                || grant.permissions.contains(&Permission::UseSsh)))
}

fn text_in(list: &[String], value: &str) -> bool {
    let value = normalize(value);
    list.iter()
        .any(|entry| normalize(entry).as_str() == value.as_str())
}

/// True when every non-empty selector field matches the item (ADR-0017 match rules 1 to 3).
#[must_use]
pub fn selector_matches(selector: &Selector, item: &PolicyItem<'_>) -> bool {
    let ids = selector.item_ids.is_empty()
        || item
            .item_id
            .is_some_and(|id| selector.item_ids.contains(id));
    let workspaces =
        selector.workspace_ids.is_empty() || selector.workspace_ids.contains(item.workspace_id);
    let envs =
        selector.environments.is_empty() || selector.environments.contains(&item.environment);
    let categories = selector.categories.is_empty() || text_in(&selector.categories, item.category);
    let tags = selector.tags.is_empty() || item.tags.iter().any(|t| text_in(&selector.tags, t));
    let kinds = selector.kinds.is_empty() || selector.kinds.contains(&item.kind);
    let roles = selector.role_labels.is_empty()
        || item
            .role_label
            .is_some_and(|r| text_in(&selector.role_labels, r));
    ids && workspaces && envs && categories && tags && kinds && roles
}

/// Specificity: the sum of the weights of the non-empty selector fields (ADR-0017 step 4).
#[must_use]
pub fn specificity(selector: &Selector) -> u32 {
    let weight = |empty: bool, w: u32| if empty { 0 } else { w };
    weight(selector.item_ids.is_empty(), 64)
        + weight(selector.workspace_ids.is_empty(), 16)
        + weight(selector.environments.is_empty(), 8)
        + weight(selector.role_labels.is_empty(), 4)
        + weight(selector.kinds.is_empty(), 2)
        + weight(selector.categories.is_empty(), 2)
        + weight(selector.tags.is_empty(), 1)
}

/// Strictness of a mode for the tie-break: `ask_always` > `ask_once` > `auto`.
const fn strictness(mode: GrantMode) -> u8 {
    match mode {
        GrantMode::Deny => 3,
        GrantMode::AskAlways => 2,
        GrantMode::AskOnce => 1,
        GrantMode::Auto => 0,
    }
}

/// The ordering key: a smaller key wins. Higher specificity, then stricter mode, then older
/// `created_at`, then the smaller ID.
fn rank_key(
    grant: &Grant,
) -> (
    std::cmp::Reverse<u32>,
    std::cmp::Reverse<u8>,
    Timestamp,
    [u8; 16],
) {
    (
        std::cmp::Reverse(specificity(&grant.selector)),
        std::cmp::Reverse(strictness(grant.mode)),
        grant.created_at,
        *grant.id.0.as_bytes(),
    )
}

/// True when the grant has not ended at `now`.
#[must_use]
pub fn grant_live(grant: &Grant, now: Timestamp) -> bool {
    grant.conditions.expires_at.is_none_or(|end| now < end)
}

/// True when `now` is inside the window. An unknown time zone counts as outside (fail closed).
#[must_use]
pub fn in_window(window: &TimeWindow, now: Timestamp) -> bool {
    let Ok(tz) = jiff::tz::TimeZone::get(&window.tz) else {
        return false;
    };
    let local = now.to_zoned_datetime(tz);
    let time = local.time();
    let day = local.weekday();
    if window.start <= window.end {
        window.days.contains(&day) && window.start <= time && time < window.end
    } else if time >= window.start {
        // Over midnight: the part after the start belongs to the day the window opened.
        window.days.contains(&day)
    } else {
        time < window.end && window.days.contains(&day.previous())
    }
}

/// True when a reason of at least [`MIN_REASON_CHARS`] characters is present. Only presence and
/// length count; the words never change a decision (plan section 4.6).
#[must_use]
pub fn reason_present(reason: Option<&str>) -> bool {
    reason.is_some_and(|text| text.trim().chars().count() >= MIN_REASON_CHARS)
}

/// The policy decision for (agent, item, permission), ADR-0017 steps 1 to 8.
///
/// Rules this function adds where the ADR leaves room (DEC-T07-2):
/// - The reason check runs before the read counter, so a refused call does not use a read.
/// - `reason_required` applies to every permission except `find`.
/// - The time window applies to every permission (outside it the grant does not exist).
/// - `max_reads_per_hour` counts only `read` and `use_ssh`.
pub fn evaluate(input: &EvalInput<'_>, agent: &AgentId, counter: &dyn ReadCounter) -> Decision {
    let mut matching: Vec<&Grant> = input
        .grants
        .iter()
        .filter(|g| g.agent_id == *agent)
        .filter(|g| grant_live(g, input.now))
        .filter(|g| grant_gives(g, input.permission))
        .filter(|g| selector_matches(&g.selector, &input.item))
        .collect();
    matching.sort_by_key(|g| rank_key(g));
    if let Some(deny) = matching.iter().find(|g| g.mode == GrantMode::Deny) {
        return Decision::Deny { grant_id: deny.id };
    }
    let Some(chosen) = matching.first() else {
        return Decision::NoGrant;
    };
    let grant_id = chosen.id;
    if let Some(window) = &chosen.conditions.time_window
        && !in_window(window, input.now)
    {
        return Decision::ConditionFailed { grant_id };
    }
    if input.permission != Permission::Find
        && chosen.conditions.reason_required
        && !reason_present(input.reason)
    {
        return Decision::ReasonRequired { grant_id };
    }
    if !is_secret_permission(input.permission) {
        return Decision::Allow {
            mode: GrantMode::Auto,
            grant_id,
        };
    }
    if let Some(limit) = chosen.conditions.max_reads_per_hour
        && let Err(retry_after_seconds) =
            counter.check_and_record(&grant_id, agent, limit, input.now)
    {
        return Decision::GrantRateLimited {
            grant_id,
            retry_after_seconds,
        };
    }
    let mode = if input.item.environment == Environment::Prod && !chosen.allow_prod_auto {
        GrantMode::AskAlways
    } else {
        chosen.mode
    };
    Decision::Allow { mode, grant_id }
}

/// True when policy gives `find` on the item: the filter for resolve and catalog. Uses no read
/// counter (`find` never counts reads).
#[must_use]
pub fn can_find(grants: &[Grant], agent: &AgentId, meta: &ItemMeta, now: Timestamp) -> bool {
    let input = EvalInput {
        grants,
        item: PolicyItem::of(meta),
        permission: Permission::Find,
        reason: None,
        now,
    };
    evaluate(&input, agent, &NoCount).is_allow()
}

/// A counter that never counts: for `find` and for checks that must not use a read.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCount;

impl ReadCounter for NoCount {
    fn check_and_record(&self, _: &GrantId, _: &AgentId, _: u32, _: Timestamp) -> Result<(), u32> {
        Ok(())
    }
}
