//! The JSON form of a grant inside `grants.body_ct` (ADR-0017: the whole body is encrypted).
//!
//! Times are Unix milliseconds. Week days are 1 (Monday) to 7 (Sunday). Times of day are minutes
//! after midnight. Unknown fields are refused, so a body of another shape never loads half-read.

use std::collections::BTreeSet;

use cerberus_types::WorkspaceId;
use cerberus_types::{AgentId, Environment, GrantMode, ItemId, ItemKind, Permission};
use jiff::Timestamp;
use jiff::civil::{Time, Weekday};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{Conditions, Grant, Selector, TimeWindow};
use crate::index::GrantEntry;

/// The body could not be read. The engine then denies everything for that agent (fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("grant body is not readable")]
pub struct GrantParseError;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorJson {
    workspace_ids: Vec<WorkspaceId>,
    environments: Vec<Environment>,
    categories: Vec<String>,
    tags: Vec<String>,
    kinds: Vec<ItemKind>,
    role_labels: Vec<String>,
    item_ids: Vec<ItemId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowJson {
    days: Vec<u8>,
    start_minute: u16,
    end_minute: u16,
    tz: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionsJson {
    time_window: Option<WindowJson>,
    max_reads_per_hour: Option<u32>,
    expires_at_ms: Option<i64>,
    reason_required: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantJson {
    v: u8,
    agent_id: AgentId,
    selector: SelectorJson,
    permissions: BTreeSet<Permission>,
    mode: GrantMode,
    conditions: ConditionsJson,
    allow_prod_auto: bool,
    created_at_ms: i64,
    updated_at_ms: i64,
}

const BODY_VERSION: u8 = 1;

fn minute_of(time: Time) -> u16 {
    let minutes = i32::from(time.hour()) * 60 + i32::from(time.minute());
    u16::try_from(minutes).unwrap_or(0)
}

fn time_of(minute: u16) -> Result<Time, GrantParseError> {
    if minute >= 24 * 60 {
        return Err(GrantParseError);
    }
    let hour = i8::try_from(minute / 60).map_err(|_| GrantParseError)?;
    let min = i8::try_from(minute % 60).map_err(|_| GrantParseError)?;
    Time::new(hour, min, 0, 0).map_err(|_| GrantParseError)
}

fn day_number(day: Weekday) -> u8 {
    u8::try_from(day.to_monday_one_offset()).unwrap_or(1)
}

fn day_of(number: u8) -> Result<Weekday, GrantParseError> {
    let offset = i8::try_from(number).map_err(|_| GrantParseError)?;
    Weekday::from_monday_one_offset(offset).map_err(|_| GrantParseError)
}

fn ms(ts: Timestamp) -> i64 {
    ts.as_millisecond()
}

fn ts(ms: i64) -> Result<Timestamp, GrantParseError> {
    Timestamp::from_millisecond(ms).map_err(|_| GrantParseError)
}

/// The JSON for `grants.body_ct` (seal it with `Blobs::seal_grant_body`). Times are cut to whole
/// milliseconds.
///
/// # Errors
/// [`GrantParseError`] when the JSON cannot be written (it cannot for these types).
pub fn encode_grant(grant: &Grant) -> Result<Zeroizing<Vec<u8>>, GrantParseError> {
    let s = &grant.selector;
    let c = &grant.conditions;
    let body = GrantJson {
        v: BODY_VERSION,
        agent_id: grant.agent_id,
        selector: SelectorJson {
            workspace_ids: s.workspace_ids.clone(),
            environments: s.environments.clone(),
            categories: s.categories.clone(),
            tags: s.tags.clone(),
            kinds: s.kinds.clone(),
            role_labels: s.role_labels.clone(),
            item_ids: s.item_ids.clone(),
        },
        permissions: grant.permissions.clone(),
        mode: grant.mode,
        conditions: ConditionsJson {
            time_window: c.time_window.as_ref().map(|w| WindowJson {
                days: w.days.iter().copied().map(day_number).collect(),
                start_minute: minute_of(w.start),
                end_minute: minute_of(w.end),
                tz: w.tz.clone(),
            }),
            max_reads_per_hour: c.max_reads_per_hour,
            expires_at_ms: c.expires_at.map(ms),
            reason_required: c.reason_required,
        },
        allow_prod_auto: grant.allow_prod_auto,
        created_at_ms: ms(grant.created_at),
        updated_at_ms: ms(grant.updated_at),
    };
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    serde_json::to_writer(&mut *out, &body).map_err(|_| GrantParseError)?;
    Ok(out)
}

/// Parses an opened grant entry of the index.
///
/// The effective expiry is the earlier of the plain copy and the sealed value (ADR-0033 point 6).
/// The sealed `agent_id` must equal the plain column, so a row moved to another agent in the file
/// does not load.
///
/// # Errors
/// [`GrantParseError`] for a body of the wrong shape, a bad time, or an agent mismatch.
pub fn decode_grant(entry: &GrantEntry) -> Result<Grant, GrantParseError> {
    let body: GrantJson =
        serde_json::from_slice(entry.body.expose_secret()).map_err(|_| GrantParseError)?;
    if body.v != BODY_VERSION || body.agent_id != entry.agent_id {
        return Err(GrantParseError);
    }
    let window = body
        .conditions
        .time_window
        .map(|w| -> Result<TimeWindow, GrantParseError> {
            Ok(TimeWindow {
                days: w.days.into_iter().map(day_of).collect::<Result<_, _>>()?,
                start: time_of(w.start_minute)?,
                end: time_of(w.end_minute)?,
                tz: w.tz,
            })
        })
        .transpose()?;
    let sealed_expiry = body.conditions.expires_at_ms.map(ts).transpose()?;
    let expires_at = match (sealed_expiry, entry.expires_at) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    };
    Ok(Grant {
        id: entry.id,
        agent_id: body.agent_id,
        selector: Selector {
            workspace_ids: body.selector.workspace_ids,
            environments: body.selector.environments,
            categories: body.selector.categories,
            tags: body.selector.tags,
            kinds: body.selector.kinds,
            role_labels: body.selector.role_labels,
            item_ids: body.selector.item_ids,
        },
        permissions: body.permissions,
        mode: body.mode,
        conditions: Conditions {
            time_window: window,
            max_reads_per_hour: body.conditions.max_reads_per_hour,
            expires_at,
            reason_required: body.conditions.reason_required,
        },
        allow_prod_auto: body.allow_prod_auto,
        created_at: ts(body.created_at_ms)?,
        updated_at: ts(body.updated_at_ms)?,
    })
}
