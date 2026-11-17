//! Rate limits and the short lockout after repeated failures (ADR-0030).
//!
//! The limiters are plain token buckets in memory. They read time from the `now` the caller passes
//! in (which comes from the `Clock`, ADR-0022), so tests move time without sleeping. A restart
//! resets them, as ADR-0030 accepts.
//!
//! The source limits (the bucket per IP and the failure lockout) only ever see failed token
//! checks. On loopback every agent shares one source with any local user, so a source limit on
//! good tokens would be a lockout tool (NEW-5, DEC-T27-E-1). Memory is bounded: past
//! [`MAX_SOURCES`] tracked sources, new sources share one entry.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};

/// One token costs this many milli-tokens. Refill is `per_second` milli-tokens per millisecond.
const TOKEN: i64 = 1000;

/// Maps above this size drop their idle entries on the next insert.
const PRUNE_ABOVE: usize = 4096;

/// Most sources tracked one by one. Past it (after the idle ones are dropped), a new source shares
/// the entry of [`OVERFLOW`], so many sources cannot grow the maps without bound.
pub(super) const MAX_SOURCES: usize = PRUNE_ABOVE;

/// The shared entry of the sources past [`MAX_SOURCES`].
const OVERFLOW: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// Settings for the auth limits. Defaults are the ADR-0030 values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthLimits {
    /// Failed token checks per second per source IP. A good token never takes from it (NEW-5).
    pub ip_per_second: u32,
    /// Burst size per source IP (failed checks only).
    pub ip_burst: u32,
    /// Requests per second per agent.
    pub agent_per_second: u32,
    /// Burst size per agent.
    pub agent_burst: u32,
    /// Auth failures from one IP inside the window that start a lockout of the failing checks of
    /// that IP. A good token from a locked IP still passes (NEW-5).
    pub failure_max: u32,
    /// Auth failures from all sources together inside the window that start a lockout of every
    /// failing check, from any source. A good token still passes (NEW-5).
    pub global_failure_max: u32,
    /// Length of the failure window in seconds.
    pub failure_window_seconds: u32,
    /// Length of the lockout in seconds.
    pub lockout_seconds: u32,
}

impl Default for AuthLimits {
    fn default() -> Self {
        Self {
            ip_per_second: 30,
            ip_burst: 60,
            agent_per_second: 20,
            agent_burst: 40,
            failure_max: 10,
            global_failure_max: 100,
            failure_window_seconds: 300,
            lockout_seconds: 300,
        }
    }
}

/// Seconds to wait, rounded up and at least one, for a wait given in milliseconds.
fn wait_seconds(wait_ms: i64) -> u32 {
    let ms = u64::try_from(wait_ms).unwrap_or(0);
    u32::try_from(ms.div_ceil(1000).max(1)).unwrap_or(u32::MAX)
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    millitokens: i64,
    last_ms: i64,
}

impl Bucket {
    fn capacity(burst: u32) -> i64 {
        i64::from(burst.max(1)) * TOKEN
    }

    fn refill(&mut self, now_ms: i64, per_second: u32, burst: u32) {
        let elapsed = now_ms.saturating_sub(self.last_ms).max(0);
        let added = elapsed.saturating_mul(i64::from(per_second.max(1)));
        self.millitokens = self
            .millitokens
            .saturating_add(added)
            .min(Self::capacity(burst));
        self.last_ms = now_ms;
    }
}

/// A set of token buckets, one per key.
#[derive(Debug)]
pub(super) struct KeyedBuckets<K> {
    map: Mutex<HashMap<K, Bucket>>,
}

impl<K: Hash + Eq + Copy> KeyedBuckets<K> {
    pub(super) fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one token. `Err` holds the seconds until a token is free.
    pub(super) fn take(&self, key: K, now_ms: i64, per_second: u32, burst: u32) -> Result<(), u32> {
        self.take_bounded(key, None, now_ms, per_second, burst)
    }

    /// As [`Self::take`], but past [`MAX_SOURCES`] keys a new key uses `overflow` instead.
    pub(super) fn take_bounded(
        &self,
        key: K,
        overflow: Option<K>,
        now_ms: i64,
        per_second: u32,
        burst: u32,
    ) -> Result<(), u32> {
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() > PRUNE_ABOVE {
            map.retain(|_, bucket| {
                let mut probe = *bucket;
                probe.refill(now_ms, per_second, burst);
                probe.millitokens < Bucket::capacity(burst)
            });
        }
        let key = match overflow {
            Some(shared) if !map.contains_key(&key) && map.len() >= MAX_SOURCES => shared,
            _ => key,
        };
        let bucket = map.entry(key).or_insert(Bucket {
            millitokens: Bucket::capacity(burst),
            last_ms: now_ms,
        });
        bucket.refill(now_ms, per_second, burst);
        if bucket.millitokens >= TOKEN {
            bucket.millitokens -= TOKEN;
            return Ok(());
        }
        let missing = u64::try_from(TOKEN - bucket.millitokens).unwrap_or(1);
        let wait_ms = missing.div_ceil(u64::from(per_second.max(1)));
        Err(wait_seconds(i64::try_from(wait_ms).unwrap_or(i64::MAX)))
    }

    /// Keys held now (for the bound tests).
    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[derive(Debug, Default)]
struct FailureState {
    recent_ms: VecDeque<i64>,
    locked_until_ms: i64,
}

impl FailureState {
    fn locked_for(&self, now_ms: i64) -> Option<u32> {
        (self.locked_until_ms > now_ms).then(|| wait_seconds(self.locked_until_ms - now_ms))
    }

    fn live(&self, now_ms: i64, window_ms: i64) -> bool {
        self.locked_until_ms > now_ms || self.recent_ms.iter().any(|at| now_ms - at < window_ms)
    }

    /// Records one failure. Starts a lockout when `max` failures fall in the window. The queue
    /// never holds more than `max` entries.
    fn record(&mut self, now_ms: i64, max: u32, limits: &AuthLimits) {
        let window_ms = i64::from(limits.failure_window_seconds) * 1000;
        while self
            .recent_ms
            .front()
            .is_some_and(|at| now_ms - at >= window_ms)
        {
            self.recent_ms.pop_front();
        }
        self.recent_ms.push_back(now_ms);
        let max = usize::try_from(max.max(1)).unwrap_or(usize::MAX);
        if self.recent_ms.len() >= max {
            self.recent_ms.clear();
            self.locked_until_ms = now_ms + i64::from(limits.lockout_seconds) * 1000;
        }
    }
}

/// Counts auth failures per source IP and from all sources together, and locks out further
/// failing checks for a short time. It is only asked about checks that failed (NEW-5).
#[derive(Debug)]
pub(super) struct FailureTracker {
    map: Mutex<HashMap<IpAddr, FailureState>>,
    global: Mutex<FailureState>,
}

/// An IPv6 client can pick any address in its /64, so all of them share one key.
pub(super) fn ip_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
        v4 => v4,
    }
}

/// The overflow key, for [`KeyedBuckets::take_bounded`].
pub(super) const fn overflow_key() -> IpAddr {
    OVERFLOW
}

impl FailureTracker {
    pub(super) fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            global: Mutex::new(FailureState::default()),
        }
    }

    /// Seconds left of the lockout of this source, or of the global one, or `None`.
    pub(super) fn locked_for(&self, ip: IpAddr, now_ms: i64) -> Option<u32> {
        let source = {
            let map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
            let state = match map.get(&ip) {
                Some(state) => Some(state),
                None if map.len() >= MAX_SOURCES => map.get(&OVERFLOW),
                None => None,
            };
            state.and_then(|state| state.locked_for(now_ms))
        };
        source.or_else(|| {
            self.global
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .locked_for(now_ms)
        })
    }

    /// Records one failure of `ip` and one of all sources. Starts a lockout when a limit is reached.
    pub(super) fn record(&self, ip: IpAddr, now_ms: i64, limits: &AuthLimits) {
        let window_ms = i64::from(limits.failure_window_seconds) * 1000;
        {
            let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
            if map.len() > PRUNE_ABOVE {
                map.retain(|_, state| state.live(now_ms, window_ms));
            }
            let key = if map.contains_key(&ip) || map.len() < MAX_SOURCES {
                ip
            } else {
                OVERFLOW
            };
            map.entry(key)
                .or_default()
                .record(now_ms, limits.failure_max, limits);
        }
        self.global
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(now_ms, limits.global_failure_max, limits);
    }

    /// Sources held now (for the bound tests).
    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}
