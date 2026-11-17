# ADR-0022: Clock abstraction for TTL and time tests

- Status: Accepted
- Date: 2026-11-16
- Plan reference: A3 ("after 3600 s (test clock)"), 4.2 (idle lock), T07 (leases)
- Related: ADR-0007, ADR-0019, ADR-0026, ADR-0027, ADR-0030

## Context

TTL, leases, approvals, idle lock and token expiry depend on time. Tests must not sleep. Hermes uses a `ManualClock`
(T00, section 6).

## Decision

1. `cerberus-types` defines:
   ```rust
   pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
       fn now(&self) -> jiff::Timestamp;
   }
   pub struct SystemClock;
   pub struct ManualClock { /* Arc<Mutex<Timestamp>> */ }
   impl ManualClock { pub fn new(start: Timestamp) -> Self; pub fn advance(&self, by: jiff::SignedDuration); pub fn set(&self, to: Timestamp); }
   ```
2. Every component that reads wall time takes `Arc<dyn Clock>` at construction: store sweeper, vault service,
   policy, lease engine, approval queue, token checks, audit writer, TLS renewal.
3. `clippy.toml` `disallowed-methods` bans `std::time::SystemTime::now`, `jiff::Timestamp::now` and
   `chrono::Utc::now` in all crates. Only `SystemClock::now` has an `#[allow]`.
4. Timers: background loops (sweeper every 60 s, idle-lock check every 5 s, approval expiry check every 1 s) use
   `tokio::time::interval`. Each loop body is a public `run_once(now)` function, so tests call it with the manual clock
   and do not need the timer.
5. Rate limiters use `governor` with its own monotonic clock. Tests use `governor::clock::FakeRelativeClock`.
6. Storage: all times are `INTEGER` Unix milliseconds, UTC. Conversion is in `cerberus-store` only.
7. Shared test helper `t0()` = `2026-01-01T00:00:00Z`.

## Consequences

- A3 test: create with `ttl_seconds: 3600`, `clock.advance(3600 s)`, item is not visible, `sweeper.run_once()` deletes it.
- A clock jump backwards on the host can extend TTLs. This is an accepted risk (threat model T-6): the local user
  who can change the system clock already controls the host.

## Alternatives considered

- **`tokio::time::pause()` only.** Rejected. It controls tokio timers, not wall-clock timestamps in the DB.
