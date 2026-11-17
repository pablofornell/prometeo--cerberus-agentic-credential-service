//! Audit of refused token checks (DEC-FIX7-11, NEW-8). A token check has no agent context, so
//! the transport layer reports the failure here.
//!
//! At most one event per source and class per minute is written; the failures in between are
//! counted and the next event carries the count (`suppressed_before`). A source is the IP as the
//! API maps it (`idle::source_of`): all of loopback (`127.0.0.0/8`, `::1`, IPv4-mapped forms) is one
//! source, an IPv6 address counts by its `/64`. The class keeps a token that matched a real key
//! (revoked, expired ...) apart from guesses, so a flood of bad tokens cannot hide it. Over all
//! sources at most [`GLOBAL_PER_WINDOW`] events per class are written per minute; failures past
//! that are counted and the next event of the class carries them (`suppressed_other`). So a flood
//! cannot grow the chain by more than a fixed number of rows a minute.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cerberus_types::RequestId;

use super::VaultService;
use crate::audit::{Actor, AuditEvent, EventType};
use crate::auth::Refusal;
use crate::context::Surface;

/// One event per source and class in this time.
const WINDOW_MS: i64 = 60_000;
/// Most sources tracked. Past this, sources share one bucket (`0.0.0.0`), so memory stays bounded.
const MAX_TRACKED: usize = 4096;
/// Most events per class from all sources together in one window (NEW-8).
pub(crate) const GLOBAL_PER_WINDOW: u32 = 10;

/// The source of a failure for the throttle: loopback is one source, IPv6 counts by its `/64`.
/// The same mapping as the API's connection sources (DEC-T27-D2-2).
fn audit_source(ip: IpAddr) -> IpAddr {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return IpAddr::V4(Ipv4Addr::LOCALHOST);
    }
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
    }
}

/// An event is due: the failures of this source and class not written since its last event,
/// and the failures of the class that the global cap (or the table bound) kept out of any event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Due {
    pub(crate) suppressed_before: u64,
    pub(crate) suppressed_other: u64,
}

/// The global budget of one class: start of its window, events written in it, failures not written.
#[derive(Debug, Default)]
struct Budget {
    start: Option<i64>,
    written: u32,
    suppressed: u64,
}

/// Per source and class (`true` = the token matched a real key): start of the current window and
/// failures not written since the last event. Plus the two global budgets.
#[derive(Debug, Default)]
pub(crate) struct AuthFailureLog {
    by_source: HashMap<(IpAddr, bool), (i64, u64)>,
    budgets: [Budget; 2],
}

impl AuthFailureLog {
    /// `Some` when an event is due for a failure from `ip` now, else counts the failure.
    pub(crate) fn take(&mut self, ip: IpAddr, matched_key: bool, now_ms: i64) -> Option<Due> {
        let wanted = (audit_source(ip), matched_key);
        if !self.by_source.contains_key(&wanted) && self.by_source.len() >= MAX_TRACKED {
            // Counts of dropped entries move to their class, so no failure goes uncounted.
            let budgets = &mut self.budgets;
            self.by_source.retain(|(_, matched), (start, suppressed)| {
                let keep = now_ms.saturating_sub(*start) < WINDOW_MS;
                if !keep {
                    let budget = &mut budgets[usize::from(*matched)];
                    budget.suppressed = budget.suppressed.saturating_add(*suppressed);
                }
                keep
            });
        }
        let key = if self.by_source.contains_key(&wanted) || self.by_source.len() < MAX_TRACKED {
            wanted
        } else {
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), matched_key)
        };
        if let Some((start, suppressed)) = self.by_source.get_mut(&key)
            && now_ms.saturating_sub(*start) < WINDOW_MS
        {
            *suppressed = suppressed.saturating_add(1);
            return None;
        }
        let budget = &mut self.budgets[usize::from(matched_key)];
        if budget
            .start
            .is_none_or(|start| now_ms.saturating_sub(start) >= WINDOW_MS)
        {
            budget.start = Some(now_ms);
            budget.written = 0;
        }
        if budget.written >= GLOBAL_PER_WINDOW {
            budget.suppressed = budget.suppressed.saturating_add(1);
            return None;
        }
        budget.written = budget.written.saturating_add(1);
        let suppressed_other = std::mem::take(&mut budget.suppressed);
        let suppressed_before = self
            .by_source
            .insert(key, (now_ms, 0))
            .map_or(0, |(_, before)| before);
        Some(Due {
            suppressed_before,
            suppressed_other,
        })
    }
}

const fn surface_text(surface: Surface) -> &'static str {
    match surface {
        Surface::Rest => "rest",
        Surface::Mcp => "mcp",
    }
}

impl VaultService {
    /// Audits a refused token check (`auth.failed`), at most once per source and class per minute
    /// and at most [`GLOBAL_PER_WINDOW`] times per class per minute in all (NEW-8). `reason` is the
    /// credential failure (`key_revoked` also when a lockout refused the check), `result` is what
    /// the caller got, and `limit` names the limit when one refused it. While unlocked the event
    /// goes to the chain with the reason, the IP, the surface and the counts of failures not
    /// written. While locked it goes to `audit_pending` (IP as target and the outward error code;
    /// that table has no details).
    pub async fn audit_auth_failure(
        &self,
        source_ip: IpAddr,
        refusal: impl Into<Refusal>,
        request_id: RequestId,
        surface: Surface,
    ) {
        let Refusal { failure, cause } = refusal.into();
        let now_ms = self.clock().now().as_millisecond();
        let due = self
            .inner
            .auth_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take(source_ip, cause.matched_a_key(), now_ms);
        let Some(due) = due else {
            return;
        };
        let code = failure.outward().code();
        if let Ok(guard) = self.unlocked().await {
            let mut event = AuditEvent::new(EventType::AuthFailed, Actor::system())
                .request_id(request_id)
                .result(code.as_str())
                .detail("reason", cause.reason())
                .detail("source_ip", source_ip.to_string())
                .detail("surface", surface_text(surface))
                .detail("suppressed_before", due.suppressed_before)
                .detail("suppressed_other", due.suppressed_other);
            if failure != cause {
                event = event.detail("limit", failure.reason());
            }
            self.audit(&guard, event).await;
            return;
        }
        self.audit_pending(
            EventType::AuthFailed,
            None,
            Some(source_ip.to_string()),
            code,
            None,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn due(before: u64, other: u64) -> Option<Due> {
        Some(Due {
            suppressed_before: before,
            suppressed_other: other,
        })
    }

    #[test]
    fn one_event_per_ip_per_minute_with_the_count() {
        let mut log = AuthFailureLog::default();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(log.take(ip, false, 0), due(0, 0));
        assert_eq!(log.take(ip, false, 1_000), None);
        assert_eq!(log.take(ip, false, 59_999), None);
        assert_eq!(log.take(other, false, 10), due(0, 0));
        assert_eq!(log.take(ip, false, 60_000), due(2, 0));
        assert_eq!(log.take(ip, false, 60_001), None);
    }

    #[test]
    fn many_ips_share_one_bucket_past_the_cap() {
        let mut log = AuthFailureLog::default();
        for n in 0..u32::try_from(MAX_TRACKED).unwrap_or(u32::MAX) {
            log.take(IpAddr::V4(Ipv4Addr::from(n + 1)), false, 0);
        }
        assert!(log.by_source.len() <= MAX_TRACKED);
        log.take(IpAddr::V4(Ipv4Addr::new(200, 0, 0, 1)), false, 1);
        log.take(IpAddr::V4(Ipv4Addr::new(200, 0, 0, 2)), false, 2);
        assert!(log.by_source.len() <= MAX_TRACKED + 1);
    }

    /// NEW-8: every loopback address, `::1` and the IPv4-mapped forms are one source, and the
    /// addresses of one IPv6 `/64` are one source.
    #[test]
    fn new8_loopback_is_one_source_and_ipv6_counts_by_its_64() {
        let mut log = AuthFailureLog::default();
        assert_eq!(log.take("127.0.0.1".parse().unwrap(), false, 0), due(0, 0));
        for (n, ip) in ["127.0.0.2", "127.9.8.7", "::1", "::ffff:127.0.0.5"]
            .iter()
            .enumerate()
        {
            assert_eq!(log.take(ip.parse().unwrap(), false, 1), None, "{n}: {ip}");
        }
        assert_eq!(
            log.take("127.3.3.3".parse().unwrap(), false, 60_000),
            due(4, 0)
        );
        assert_eq!(
            log.take("2001:db8::1".parse().unwrap(), false, 0),
            due(0, 0)
        );
        assert_eq!(
            log.take("2001:db8::ffff:2".parse().unwrap(), false, 1),
            None
        );
        assert_eq!(
            log.take("2001:db8:0:1::1".parse().unwrap(), false, 2),
            due(0, 0),
            "another /64"
        );
        assert_eq!(
            log.take("::ffff:10.0.0.1".parse().unwrap(), false, 3),
            due(0, 0)
        );
        assert_eq!(log.take("10.0.0.1".parse().unwrap(), false, 4), None);
    }

    /// NEW-8: over all sources at most `GLOBAL_PER_WINDOW` events per class are due per minute;
    /// the rest is counted and given to the next event of the class.
    #[test]
    fn new8_a_flood_from_many_sources_is_capped_and_counted() {
        let mut log = AuthFailureLog::default();
        let mut written = 0;
        for n in 0..1000_u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
            if log.take(ip, false, 0).is_some() {
                written += 1;
            }
        }
        assert_eq!(written, GLOBAL_PER_WINDOW);
        // A token that matched a real key has its own budget.
        assert_eq!(log.take(Ipv4Addr::LOCALHOST.into(), true, 1), due(0, 0));
        // The next minute: the first event of the class carries everything not written.
        let next = log.take(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), false, 60_000);
        assert_eq!(next, due(0, u64::from(1000 - GLOBAL_PER_WINDOW)));
    }

    /// NEW-8: a real key's failure from a source whose bad-token flood was just written still
    /// gets its own event.
    #[test]
    fn new8_a_matched_key_is_not_hidden_by_a_guess_flood() {
        let mut log = AuthFailureLog::default();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(log.take(local, false, 0), due(0, 0));
        assert_eq!(log.take(local, false, 1), None);
        assert_eq!(log.take(local, true, 2), due(0, 0));
        assert_eq!(log.take("127.0.0.9".parse().unwrap(), true, 3), None);
    }
}
