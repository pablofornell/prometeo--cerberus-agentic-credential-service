//! Read and request limits of ADR-0030 that need policy context: grant `max_reads_per_hour`,
//! secret reads per agent per minute, distinct items per agent per hour, and access requests per
//! agent. The per-IP and per-agent call limits and the auth lockout are in `crate::auth`.
//!
//! Sliding windows in memory. Time comes from the caller's `now` (the `Clock`), so tests never
//! sleep. A restart resets them, as ADR-0030 accepts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};

use cerberus_types::{AgentId, GrantId, ItemId};
use jiff::Timestamp;

use super::ReadCounter;
use super::settings::PolicySettings;

const HOUR_MS: i64 = 3_600_000;
const MINUTE_MS: i64 = 60_000;
/// Window of the request burst warning in the approval window (ADR-0018).
const BURST_WINDOW_MS: i64 = 60_000;
/// Maps above this size drop their empty entries on the next insert.
const PRUNE_ABOVE: usize = 4096;

/// Which limit refused a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitHit {
    /// The grant's `max_reads_per_hour` (`429 grant_rate_limited`).
    Grant {
        /// Seconds to wait.
        retry_after_seconds: u32,
    },
    /// Secret reads per agent per minute (`429 rate_limited`).
    SecretReads {
        /// Seconds to wait.
        retry_after_seconds: u32,
    },
    /// Distinct items per agent per hour (`429 rate_limited` and a dashboard alert).
    DistinctItems {
        /// Seconds to wait.
        retry_after_seconds: u32,
        /// Distinct items read in the hour.
        distinct: u32,
    },
}

fn wait_seconds(wait_ms: i64) -> u32 {
    let ms = u64::try_from(wait_ms.max(0)).unwrap_or(0);
    u32::try_from(ms.div_ceil(1000).max(1)).unwrap_or(u32::MAX)
}

fn trim<T>(queue: &mut VecDeque<(i64, T)>, now_ms: i64, window_ms: i64) {
    while queue
        .front()
        .is_some_and(|(at, _)| now_ms - at >= window_ms)
    {
        queue.pop_front();
    }
}

/// Checks a sliding-window count. `Err` holds the seconds until the oldest entry leaves.
fn window_check<T>(
    queue: &VecDeque<(i64, T)>,
    limit: u32,
    now_ms: i64,
    window_ms: i64,
) -> Result<(), u32> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let live = queue
        .iter()
        .filter(|(at, _)| now_ms - at < window_ms)
        .count();
    if live < limit {
        return Ok(());
    }
    // The entry that must leave before one more fits.
    let index = live.saturating_sub(limit);
    let oldest = queue
        .iter()
        .filter(|(at, _)| now_ms - at < window_ms)
        .nth(index)
        .map_or(now_ms, |(at, _)| *at);
    Err(wait_seconds(oldest + window_ms - now_ms))
}

fn prune<K: Hash + Eq, T>(map: &mut HashMap<K, VecDeque<(i64, T)>>, now_ms: i64, window_ms: i64) {
    if map.len() > PRUNE_ABOVE {
        map.retain(|_, queue| {
            trim(queue, now_ms, window_ms);
            !queue.is_empty()
        });
    }
}

#[derive(Debug, Default)]
struct State {
    grant_reads: HashMap<(GrantId, AgentId), VecDeque<(i64, ())>>,
    secret_reads: HashMap<AgentId, VecDeque<(i64, ())>>,
    item_reads: HashMap<AgentId, VecDeque<(i64, ItemId)>>,
    requests: HashMap<AgentId, VecDeque<(i64, ())>>,
    /// Last mass-read alert per agent, so the dashboard gets one alert per hour.
    alerted_ms: HashMap<AgentId, i64>,
}

/// The policy limiters. One per engine; cheap to share by reference.
#[derive(Debug, Default)]
pub struct ReadLimiter {
    state: Mutex<State>,
}

/// The outcome of a counted read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadRecorded {
    /// Distinct items read by the agent in the last hour, after this read.
    pub distinct: u32,
}

impl ReadLimiter {
    /// A limiter with empty windows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Checks the grant limit without counting (the simulator and the pre-check of a read).
    ///
    /// # Errors
    /// The seconds until a read is free.
    pub fn peek_grant(
        &self,
        grant: &GrantId,
        agent: &AgentId,
        limit: u32,
        now: Timestamp,
    ) -> Result<(), u32> {
        let state = self.lock();
        let now_ms = now.as_millisecond();
        state
            .grant_reads
            .get(&(*grant, *agent))
            .map_or(Ok(()), |q| window_check(q, limit, now_ms, HOUR_MS))
    }

    /// Checks every read limit and, when all pass, counts one secret read of `item` in all of them
    /// at once. `grant` is the chosen grant and its `max_reads_per_hour`, if it has one.
    ///
    /// # Errors
    /// The first [`LimitHit`]; then nothing is counted.
    pub(crate) fn record_read(
        &self,
        agent: &AgentId,
        item: &ItemId,
        grant: Option<(GrantId, u32)>,
        now: Timestamp,
        settings: &PolicySettings,
    ) -> Result<ReadRecorded, LimitHit> {
        let now_ms = now.as_millisecond();
        let mut state = self.lock();
        prune(&mut state.grant_reads, now_ms, HOUR_MS);
        prune(&mut state.secret_reads, now_ms, MINUTE_MS);
        prune(&mut state.item_reads, now_ms, HOUR_MS);
        if let Some((id, limit)) = grant {
            let queue = state.grant_reads.entry((id, *agent)).or_default();
            trim(queue, now_ms, HOUR_MS);
            window_check(queue, limit, now_ms, HOUR_MS).map_err(|retry_after_seconds| {
                LimitHit::Grant {
                    retry_after_seconds,
                }
            })?;
        }
        let reads = state.secret_reads.entry(*agent).or_default();
        trim(reads, now_ms, MINUTE_MS);
        window_check(reads, settings.secret_reads_per_minute, now_ms, MINUTE_MS).map_err(
            |retry_after_seconds| LimitHit::SecretReads {
                retry_after_seconds,
            },
        )?;
        let items = state.item_reads.entry(*agent).or_default();
        trim(items, now_ms, HOUR_MS);
        let mut distinct: HashSet<ItemId> = items.iter().map(|(_, id)| *id).collect();
        if !distinct.contains(item)
            && distinct.len()
                >= usize::try_from(settings.distinct_items_per_hour).unwrap_or(usize::MAX)
        {
            // The window frees a slot when the oldest item has no read left in it.
            let retry = items
                .front()
                .map_or(1, |(at, _)| wait_seconds(at + HOUR_MS - now_ms));
            return Err(LimitHit::DistinctItems {
                retry_after_seconds: retry,
                distinct: u32::try_from(distinct.len()).unwrap_or(u32::MAX),
            });
        }
        items.push_back((now_ms, *item));
        distinct.insert(*item);
        if let Some(reads) = state.secret_reads.get_mut(agent) {
            reads.push_back((now_ms, ()));
        }
        if let Some((id, _)) = grant
            && let Some(queue) = state.grant_reads.get_mut(&(id, *agent))
        {
            queue.push_back((now_ms, ()));
        }
        Ok(ReadRecorded {
            distinct: u32::try_from(distinct.len()).unwrap_or(u32::MAX),
        })
    }

    /// True when a mass-read alert for `agent` should be sent now (at most one per hour).
    pub(crate) fn take_alert(&self, agent: &AgentId, now: Timestamp) -> bool {
        let now_ms = now.as_millisecond();
        let mut state = self.lock();
        match state.alerted_ms.get(agent) {
            Some(at) if now_ms - at < HOUR_MS => false,
            _ => {
                state.alerted_ms.insert(*agent, now_ms);
                true
            }
        }
    }

    /// Checks the access request rate and counts one request when under it.
    ///
    /// # Errors
    /// The seconds to wait.
    pub(crate) fn record_request(
        &self,
        agent: &AgentId,
        now: Timestamp,
        settings: &PolicySettings,
    ) -> Result<(), u32> {
        let now_ms = now.as_millisecond();
        let window_ms = i64::from(settings.requests_window_seconds) * 1000;
        let mut state = self.lock();
        prune(&mut state.requests, now_ms, window_ms.max(BURST_WINDOW_MS));
        let queue = state.requests.entry(*agent).or_default();
        trim(queue, now_ms, window_ms.max(BURST_WINDOW_MS));
        window_check(queue, settings.requests_per_window, now_ms, window_ms)?;
        queue.push_back((now_ms, ()));
        Ok(())
    }

    /// Requests made by `agent` in the last 60 s (the burst warning of ADR-0018).
    pub(crate) fn recent_requests(&self, agent: &AgentId, now: Timestamp) -> usize {
        let now_ms = now.as_millisecond();
        self.lock().requests.get(agent).map_or(0, |q| {
            q.iter()
                .filter(|(at, _)| now_ms - at < BURST_WINDOW_MS)
                .count()
        })
    }
}

/// A [`ReadCounter`] that checks the grant limit and never counts. The engine counts only when a
/// secret is really handed out ([`ReadLimiter::record_read`]), so a call that ends in an approval
/// prompt or an error uses no read.
#[derive(Debug)]
pub(crate) struct Peek<'a>(pub(crate) &'a ReadLimiter);

impl ReadCounter for Peek<'_> {
    fn check_and_record(
        &self,
        grant: &GrantId,
        agent: &AgentId,
        limit: u32,
        now: Timestamp,
    ) -> Result<(), u32> {
        self.0.peek_grant(grant, agent, limit, now)
    }
}
