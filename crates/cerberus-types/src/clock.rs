//! Clock abstraction (ADR-0022).
//!
//! Code reads wall time only through [`Clock`], and measures durations only through
//! [`Stopwatch`]. `clippy.toml` bans the direct calls everywhere else.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use jiff::{SignedDuration, Timestamp};

/// Source of wall-clock time.
pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// The real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "the one allowed wall-clock read (ADR-0022)"
    )]
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// A clock that tests move by hand. Clones share the same time.
#[derive(Debug, Clone)]
pub struct ManualClock {
    inner: Arc<Mutex<Timestamp>>,
}

impl ManualClock {
    /// A clock that starts at `start`.
    #[must_use]
    pub fn new(start: Timestamp) -> Self {
        Self {
            inner: Arc::new(Mutex::new(start)),
        }
    }

    /// Moves the time by `by` (may be negative). Saturates at the limits of `Timestamp`.
    pub fn advance(&self, by: SignedDuration) {
        let mut now = self.guard();
        if let Ok(next) = now.saturating_add(by) {
            *now = next;
        }
    }

    /// Sets the time to `to`.
    pub fn set(&self, to: Timestamp) {
        *self.guard() = to;
    }

    // A panic in another test thread must not hide the time, so a poisoned lock is still used.
    fn guard(&self) -> MutexGuard<'_, Timestamp> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        *self.guard()
    }
}

/// Shared test start time `2026-01-01T00:00:00Z` (ADR-0022 point 7).
pub const T0: Timestamp = Timestamp::constant(1_767_225_600, 0);

/// Shared test start time `2026-01-01T00:00:00Z` (ADR-0022 point 7).
#[must_use]
pub const fn t0() -> Timestamp {
    T0
}

/// Measures elapsed time with the monotonic clock (for example the KDF cost test).
///
/// It is not wall time, so it cannot be stored or compared with a [`Clock`] value.
#[derive(Debug, Clone, Copy)]
pub struct Stopwatch {
    start: Instant,
}

impl Stopwatch {
    /// Starts a measurement.
    #[allow(
        clippy::disallowed_methods,
        reason = "the one allowed monotonic read (ADR-0022)"
    )]
    #[must_use]
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Time since [`Stopwatch::start`].
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t0_is_2026_new_year() {
        assert_eq!(t0().to_string(), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn manual_clock_moves_only_by_hand() {
        let clock = ManualClock::new(t0());
        assert_eq!(clock.now(), t0());
        clock.advance(SignedDuration::from_secs(3600));
        assert_eq!(clock.now().to_string(), "2026-01-01T01:00:00Z");
        clock.advance(SignedDuration::from_secs(-7200));
        assert_eq!(clock.now().to_string(), "2025-12-31T23:00:00Z");
        clock.set(t0());
        assert_eq!(clock.now(), t0());
    }

    #[test]
    fn manual_clock_clones_share_time() {
        let clock = ManualClock::new(t0());
        let shared: Arc<dyn Clock> = Arc::new(clock.clone());
        clock.advance(SignedDuration::from_secs(60));
        assert_eq!(shared.now(), clock.now());
    }

    #[test]
    fn manual_clock_saturates() {
        let clock = ManualClock::new(Timestamp::MAX);
        clock.advance(SignedDuration::MAX);
        assert_eq!(clock.now(), Timestamp::MAX);
    }

    #[test]
    fn system_clock_is_after_t0() {
        assert!(SystemClock.now() > t0());
    }

    #[test]
    fn stopwatch_does_not_go_back() {
        let watch = Stopwatch::start();
        let first = watch.elapsed();
        assert!(watch.elapsed() >= first);
    }
}
