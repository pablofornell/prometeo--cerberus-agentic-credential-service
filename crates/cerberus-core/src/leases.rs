//! Lease semantics (ADR-0019): when a lease is active, which lease a read may use, and how long an
//! approved lease lives. The functions here are pure; the operations that read and write lease
//! rows are on [`crate::policy::PolicyEngine`] (`ops`).

mod ops;

#[cfg(test)]
mod tests;

use cerberus_store::{LeaseRow, LeaseSource};
use cerberus_types::{ApprovalOption, GrantMode, ItemId, LeaseId, Permission};
use jiff::{SignedDuration, Timestamp};

pub use ops::{LEASE_EXPIRY_MARK_KEY, LeaseDetail, ReleaseOutcome};

/// TTL of "approve once" (ADR-0018).
pub const ONCE_TTL: SignedDuration = SignedDuration::from_secs(300);
/// TTL of "approve for 15 minutes" (ADR-0018).
pub const MINUTES_15_TTL: SignedDuration = SignedDuration::from_secs(900);

/// What the lease rows say about one read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseCheck {
    /// This active lease covers the read.
    Active(LeaseRow),
    /// Mode `auto` and no usable lease: make a new auto lease.
    NewAuto,
    /// The mode needs a person and no approved lease is active.
    NeedApproval,
    /// Mode `auto`, but an operator revoked an auto lease for this agent and item. New auto leases
    /// are refused until the old lease would have ended (ADR-0019 point 7).
    Blocked {
        /// End of the block.
        until: Timestamp,
    },
}

/// What the agent sees of a lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseView {
    /// Lease ID.
    pub id: LeaseId,
    /// The item.
    pub item_id: ItemId,
    /// `read` or `use_ssh`.
    pub permission: Permission,
    /// End time.
    pub expires_at: Timestamp,
    /// Uses left, or `None` for no use limit.
    pub uses_left: Option<u32>,
}

impl LeaseView {
    /// The view of a row.
    #[must_use]
    pub fn of(row: &LeaseRow) -> Self {
        Self {
            id: row.id,
            item_id: row.item_id,
            permission: row.permission,
            expires_at: row.expires_at,
            uses_left: row.max_uses.map(|max| max.saturating_sub(row.uses)),
        }
    }
}

/// Lease end time and use limit for an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseTerms {
    /// End time.
    pub expires_at: Timestamp,
    /// Use limit.
    pub max_uses: Option<u32>,
}

/// ADR-0019 point 3: `now < expires_at`, not released, not revoked, and uses left.
#[must_use]
pub fn is_active(row: &LeaseRow, now: Timestamp) -> bool {
    now < row.expires_at
        && row.released_at.is_none()
        && row.revoked_at.is_none()
        && row.max_uses.is_none_or(|max| row.uses < max)
}

/// True when this lease may serve a read in effective `mode` (ADR-0017 step 6, ADR-0019 point 5).
///
/// - `auto`: any lease.
/// - `ask_once`: only an approval lease, so a grant changed from `auto` to an ask mode takes
///   effect at once.
/// - `ask_always` (also the `prod` default): only a one-use approval lease made by an approval of
///   a request. So a session or 15-minute approval given under `ask_once` does not serve a grant
///   that was tightened, or an item that moved to `prod`: each read needs its own approval.
/// - `deny`: none.
fn source_fits(row: &LeaseRow, mode: GrantMode) -> bool {
    match mode {
        GrantMode::Auto => true,
        GrantMode::AskOnce => row.source == LeaseSource::Approval,
        GrantMode::AskAlways => {
            row.source == LeaseSource::Approval
                && row.request_id.is_some()
                && row.max_uses == Some(1)
        }
        GrantMode::Deny => false,
    }
}

/// True when `row` is active and may serve a read of `permission` in effective `mode`.
#[must_use]
pub fn serves(row: &LeaseRow, mode: GrantMode, permission: Permission, now: Timestamp) -> bool {
    row.permission == permission && source_fits(row, mode) && is_active(row, now)
}

/// Picks the lease for a read of `permission` in effective `mode`.
///
/// `leases` are the MAC-checked rows of one agent and one item. `wanted` is the lease the agent
/// asked for; when it cannot serve, the normal choice applies. Else the usable lease that ends
/// first is used.
#[must_use]
pub fn check(
    leases: &[LeaseRow],
    mode: GrantMode,
    permission: Permission,
    now: Timestamp,
    wanted: Option<&LeaseId>,
) -> LeaseCheck {
    let usable = |row: &&LeaseRow| serves(row, mode, permission, now);
    if let Some(id) = wanted
        && let Some(row) = leases.iter().filter(usable).find(|row| row.id == *id)
    {
        return LeaseCheck::Active(row.clone());
    }
    if let Some(row) = leases
        .iter()
        .filter(usable)
        .min_by_key(|row| (row.expires_at, row.id.0))
    {
        return LeaseCheck::Active(row.clone());
    }
    match mode {
        GrantMode::Auto => {
            let block = leases
                .iter()
                .filter(|row| {
                    row.permission == permission
                        && row.source == LeaseSource::Auto
                        && row.revoked_at.is_some()
                        && now < row.expires_at
                })
                .map(|row| row.expires_at)
                .max();
            block.map_or(LeaseCheck::NewAuto, |until| LeaseCheck::Blocked { until })
        }
        GrantMode::AskOnce | GrantMode::AskAlways | GrantMode::Deny => LeaseCheck::NeedApproval,
    }
}

/// End time and use limit of a lease made by an approval (ADR-0018 options, ADR-0019 point 5).
///
/// - Once: 300 s and one use. 15 minutes: 900 s. Session: `session_max`, and not past the next
///   hard lock.
/// - `ask_always` always gives one use.
/// - A TTL the agent asked for can only make it shorter.
/// - Never past the item expiry (ADR-0019 point 4).
#[must_use]
pub fn ttl_for(
    option: ApprovalOption,
    mode: GrantMode,
    session_max: SignedDuration,
    item_expires_at: Option<Timestamp>,
    now: Timestamp,
    next_hard_lock_at: Option<Timestamp>,
    requested_ttl_seconds: Option<u32>,
) -> LeaseTerms {
    let (ttl, mut max_uses) = match option {
        ApprovalOption::Once => (ONCE_TTL, Some(1)),
        ApprovalOption::Minutes15 => (MINUTES_15_TTL, None),
        ApprovalOption::Session => (session_max, None),
    };
    if mode == GrantMode::AskAlways {
        max_uses = Some(1);
    }
    let ttl = requested_ttl_seconds
        .map(|s| SignedDuration::from_secs(i64::from(s)))
        .map_or(ttl, |asked| ttl.min(asked));
    let mut end = now.saturating_add(ttl).unwrap_or(now);
    if option == ApprovalOption::Session
        && let Some(lock_at) = next_hard_lock_at
    {
        end = end.min(lock_at);
    }
    if let Some(item_end) = item_expires_at {
        end = end.min(item_end);
    }
    LeaseTerms {
        expires_at: end,
        max_uses,
    }
}

/// End time of a new auto lease: `ttl` from now, not past the item expiry.
#[must_use]
pub fn auto_expiry(
    ttl: SignedDuration,
    item_expires_at: Option<Timestamp>,
    now: Timestamp,
) -> Timestamp {
    let end = now.saturating_add(ttl).unwrap_or(now);
    item_expires_at.map_or(end, |item_end| end.min(item_end))
}
