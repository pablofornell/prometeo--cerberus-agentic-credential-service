//! Types of the grant, request, lease and settings commands.

use std::collections::{BTreeMap, BTreeSet};

use cerberus_core::admin::SettingsView as CoreSettings;
use cerberus_core::approvals::AccessRequestDetail;
use cerberus_core::leases::{LeaseDetail, LeaseView as CoreLease};
use cerberus_core::policy::{
    Conditions, Decision, Grant, GrantInput, Selector, SimulationRow as CoreRow, TimeWindow,
};
use jiff::civil::{Time, Weekday};
use serde::{Deserialize, Serialize};
use specta::Type;

use super::{
    Environment, GrantMode, ItemKind, LeaseSource, Permission, RequestStatus, id, opt_id,
    opt_parse_ts, opt_ts, ts,
};
use crate::error::{IpcError, IpcResult};

/// Which items a grant covers. An empty list matches everything.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct SelectorView {
    /// Workspace IDs.
    pub workspace_ids: Vec<String>,
    /// Environments.
    pub environments: Vec<Environment>,
    /// Categories.
    pub categories: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Kinds.
    pub kinds: Vec<ItemKind>,
    /// Role labels.
    pub role_labels: Vec<String>,
    /// Single item IDs.
    pub item_ids: Vec<String>,
}

fn ids<T: std::str::FromStr<Err = cerberus_types::IdParseError>>(
    field: &str,
    list: &[String],
) -> IpcResult<Vec<T>> {
    list.iter().map(|text| id(field, text)).collect()
}

impl SelectorView {
    fn into_core(self) -> IpcResult<Selector> {
        Ok(Selector {
            workspace_ids: ids("selector.workspace_ids", &self.workspace_ids)?,
            environments: self.environments.into_iter().map(Into::into).collect(),
            categories: self.categories,
            tags: self.tags,
            kinds: self.kinds.into_iter().map(Into::into).collect(),
            role_labels: self.role_labels,
            item_ids: ids("selector.item_ids", &self.item_ids)?,
        })
    }

    fn of(selector: Selector) -> Self {
        Self {
            workspace_ids: selector
                .workspace_ids
                .iter()
                .map(ToString::to_string)
                .collect(),
            environments: selector.environments.into_iter().map(Into::into).collect(),
            categories: selector.categories,
            tags: selector.tags,
            kinds: selector.kinds.into_iter().map(Into::into).collect(),
            role_labels: selector.role_labels,
            item_ids: selector.item_ids.iter().map(ToString::to_string).collect(),
        }
    }
}

/// A day of the week.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum DayOfWeek {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl From<Weekday> for DayOfWeek {
    fn from(value: Weekday) -> Self {
        match value {
            Weekday::Monday => Self::Monday,
            Weekday::Tuesday => Self::Tuesday,
            Weekday::Wednesday => Self::Wednesday,
            Weekday::Thursday => Self::Thursday,
            Weekday::Friday => Self::Friday,
            Weekday::Saturday => Self::Saturday,
            Weekday::Sunday => Self::Sunday,
        }
    }
}

impl From<DayOfWeek> for Weekday {
    fn from(value: DayOfWeek) -> Self {
        match value {
            DayOfWeek::Monday => Self::Monday,
            DayOfWeek::Tuesday => Self::Tuesday,
            DayOfWeek::Wednesday => Self::Wednesday,
            DayOfWeek::Thursday => Self::Thursday,
            DayOfWeek::Friday => Self::Friday,
            DayOfWeek::Saturday => Self::Saturday,
            DayOfWeek::Sunday => Self::Sunday,
        }
    }
}

/// Days and hours in which a grant works.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct TimeWindowView {
    /// Days of the week.
    pub days: Vec<DayOfWeek>,
    /// Start time `HH:MM:SS`, inclusive.
    pub start: String,
    /// End time `HH:MM:SS`, exclusive.
    pub end: String,
    /// IANA time zone name.
    pub tz: String,
}

fn time(field: &str, text: &str) -> IpcResult<Time> {
    text.parse()
        .map_err(|_| IpcError::invalid(field, "is not a time of day (HH:MM:SS)"))
}

impl TimeWindowView {
    fn into_core(self) -> IpcResult<TimeWindow> {
        Ok(TimeWindow {
            days: self.days.into_iter().map(Into::into).collect(),
            start: time("conditions.time_window.start", &self.start)?,
            end: time("conditions.time_window.end", &self.end)?,
            tz: self.tz,
        })
    }

    fn of(window: TimeWindow) -> Self {
        Self {
            days: window.days.into_iter().map(Into::into).collect(),
            start: window.start.to_string(),
            end: window.end.to_string(),
            tz: window.tz,
        }
    }
}

/// Extra checks of a grant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ConditionsView {
    /// The grant works only inside this window.
    pub time_window: Option<TimeWindowView>,
    /// Most secret reads per hour.
    pub max_reads_per_hour: Option<u32>,
    /// The grant ends at this time.
    pub expires_at: Option<String>,
    /// The call must give a reason.
    pub reason_required: bool,
}

impl ConditionsView {
    fn into_core(self) -> IpcResult<Conditions> {
        Ok(Conditions {
            time_window: self
                .time_window
                .map(TimeWindowView::into_core)
                .transpose()?,
            max_reads_per_hour: self.max_reads_per_hour,
            expires_at: opt_parse_ts("conditions.expires_at", self.expires_at.as_deref())?,
            reason_required: self.reason_required,
        })
    }

    fn of(conditions: Conditions) -> Self {
        Self {
            time_window: conditions.time_window.map(TimeWindowView::of),
            max_reads_per_hour: conditions.max_reads_per_hour,
            expires_at: opt_ts(conditions.expires_at),
            reason_required: conditions.reason_required,
        }
    }
}

/// Input of `grant_put`. `id = null` makes a new grant.
#[derive(Clone, Debug, Deserialize, Type)]
pub struct GrantInputView {
    /// The grant to change.
    pub id: Option<String>,
    /// The agent.
    pub agent_id: String,
    /// Which items.
    pub selector: SelectorView,
    /// What the agent may do.
    pub permissions: Vec<Permission>,
    /// How reads are approved.
    pub mode: GrantMode,
    /// Extra checks.
    pub conditions: ConditionsView,
    /// `prod` reads may skip the forced approval. The owner only.
    pub allow_prod_auto: bool,
}

impl GrantInputView {
    /// The core input.
    ///
    /// # Errors
    /// `validation_failed` for a bad ID, time or time zone field.
    pub fn into_core(self) -> IpcResult<GrantInput> {
        Ok(GrantInput {
            id: opt_id("id", self.id.as_deref())?,
            agent_id: id("agent_id", &self.agent_id)?,
            selector: self.selector.into_core()?,
            permissions: self
                .permissions
                .into_iter()
                .map(Into::into)
                .collect::<BTreeSet<_>>(),
            mode: self.mode.into(),
            conditions: self.conditions.into_core()?,
            allow_prod_auto: self.allow_prod_auto,
        })
    }
}

/// A grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct GrantView {
    /// Grant ID.
    pub id: String,
    /// The agent.
    pub agent_id: String,
    /// Which items.
    pub selector: SelectorView,
    /// What the agent may do.
    pub permissions: Vec<Permission>,
    /// How reads are approved.
    pub mode: GrantMode,
    /// Extra checks.
    pub conditions: ConditionsView,
    /// `prod` reads may skip the forced approval.
    pub allow_prod_auto: bool,
    /// Creation time.
    pub created_at: String,
    /// Last change.
    pub updated_at: String,
}

impl From<Grant> for GrantView {
    fn from(value: Grant) -> Self {
        Self {
            id: value.id.to_string(),
            agent_id: value.agent_id.to_string(),
            selector: SelectorView::of(value.selector),
            permissions: value.permissions.into_iter().map(Into::into).collect(),
            mode: value.mode.into(),
            conditions: ConditionsView::of(value.conditions),
            allow_prod_auto: value.allow_prod_auto,
            created_at: ts(value.created_at),
            updated_at: ts(value.updated_at),
        }
    }
}

/// What policy decides for one item and permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct DecisionView {
    /// `allow`, `deny`, `no_grant`, `condition_failed`, `reason_required` or `grant_rate_limited`.
    pub outcome: String,
    /// The effective mode, for `allow`.
    pub mode: Option<GrantMode>,
    /// The grant the decision came from.
    pub grant_id: Option<String>,
    /// Seconds to wait, for `grant_rate_limited`.
    pub retry_after_seconds: Option<u32>,
}

impl From<Decision> for DecisionView {
    fn from(value: Decision) -> Self {
        let mode = match &value {
            Decision::Allow { mode, .. } => Some((*mode).into()),
            _ => None,
        };
        let retry_after_seconds = match &value {
            Decision::GrantRateLimited {
                retry_after_seconds,
                ..
            } => Some(*retry_after_seconds),
            _ => None,
        };
        Self {
            outcome: value.as_str().to_owned(),
            mode,
            grant_id: value.grant_id().map(|g| g.to_string()),
            retry_after_seconds,
        }
    }
}

/// One row of the policy simulator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct SimulationRow {
    /// Item ID.
    pub item_id: String,
    /// Item title.
    pub title: String,
    /// The permission.
    pub permission: Permission,
    /// The decision.
    pub decision: DecisionView,
}

impl From<CoreRow> for SimulationRow {
    fn from(value: CoreRow) -> Self {
        Self {
            item_id: value.item_id.to_string(),
            title: value.title,
            permission: value.permission.into(),
            decision: value.decision.into(),
        }
    }
}

/// What an agent sees of a lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct LeaseView {
    /// Lease ID.
    pub id: String,
    /// The item.
    pub item_id: String,
    /// The permission.
    pub permission: Permission,
    /// End time.
    pub expires_at: String,
    /// Uses left.
    pub uses_left: Option<u32>,
}

impl From<CoreLease> for LeaseView {
    fn from(value: CoreLease) -> Self {
        Self {
            id: value.id.to_string(),
            item_id: value.item_id.to_string(),
            permission: value.permission.into(),
            expires_at: ts(value.expires_at),
            uses_left: value.uses_left,
        }
    }
}

/// A lease as the Leases screen shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct LeaseDetailView {
    /// What the agent sees.
    pub view: LeaseView,
    /// The agent.
    pub agent_id: String,
    /// How the lease was made.
    pub source: LeaseSource,
    /// The request that made it.
    pub request_id: Option<String>,
    /// Uses so far.
    pub uses: u32,
    /// Creation time.
    pub created_at: String,
}

impl From<LeaseDetail> for LeaseDetailView {
    fn from(value: LeaseDetail) -> Self {
        Self {
            view: value.view.into(),
            agent_id: value.agent_id.to_string(),
            source: value.source.into(),
            request_id: value.request_id.map(|r| r.to_string()),
            uses: value.uses,
            created_at: ts(value.created_at),
        }
    }
}

/// A pending request as the approval window shows it. `reason` is untrusted text: show it as text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct AccessRequestView {
    /// Request ID.
    pub id: String,
    /// The item.
    pub item_id: String,
    /// The permission.
    pub permission: Permission,
    /// State.
    pub status: RequestStatus,
    /// TTL the agent asked for.
    pub requested_ttl_seconds: Option<u32>,
    /// Creation time.
    pub created_at: String,
    /// Time the request times out.
    pub expires_at: String,
    /// The agent, from its token.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Item title.
    pub item_title: String,
    /// Item kind (metadata only).
    pub item_kind: ItemKind,
    /// Item role label, for example `admin` (metadata only).
    pub role_label: Option<String>,
    /// Workspace name.
    pub workspace_name: String,
    /// Item environment.
    pub environment: Environment,
    /// Untrusted reason text.
    pub reason: String,
    /// True when the agent made more than 3 requests in the last 60 s.
    pub burst_warning: bool,
}

impl From<AccessRequestDetail> for AccessRequestView {
    fn from(value: AccessRequestDetail) -> Self {
        Self {
            id: value.view.id.to_string(),
            item_id: value.view.item_id.to_string(),
            permission: value.view.permission.into(),
            status: value.view.status.into(),
            requested_ttl_seconds: value.view.requested_ttl_seconds,
            created_at: ts(value.view.created_at),
            expires_at: ts(value.view.expires_at),
            agent_id: value.agent_id.to_string(),
            agent_name: value.agent_name,
            item_title: value.item_title,
            item_kind: value.item_kind.into(),
            role_label: value.role_label,
            workspace_name: value.workspace_name,
            environment: value.environment.into(),
            reason: value.reason,
            burst_warning: value.burst_warning,
        }
    }
}

/// All settings by key. A value is a number, a flag or `null` (off).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Type)]
pub struct SettingsView {
    /// Key to value.
    pub values: BTreeMap<String, serde_json::Value>,
}

impl From<CoreSettings> for SettingsView {
    fn from(value: CoreSettings) -> Self {
        Self {
            values: value.values,
        }
    }
}
