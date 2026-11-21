//! Connection deadlines and the slots of connections that have not authenticated (AUD-4, NEW-1).
//!
//! Progress means a request, never bytes: a byte trickle, a slow HTTP/2 preface or HTTP/2 PING
//! frames do not keep a connection. Rules (DEC-T27-D2-1):
//! - The first request head must be complete within `header_timeout` after the TLS handshake.
//! - A connection that has had no authenticated request is closed `auth_timeout` after accept,
//!   even while a request runs (no route without a token takes long).
//! - After an authenticated request, the connection is closed when no authenticated request has
//!   run for `idle_timeout`. A response that is still being sent (an SSE stream) counts as running.
//!
//! - A response that hyper has not pulled more of for `send_timeout` closes the connection, so a
//!   client that never reads (or keeps an HTTP/2 window of 0) cannot hold it. A stream that waits
//!   for its own next event does not count (NEW-6).
//! - An authenticated connection is closed when the key of its first authenticated request is
//!   revoked or expires, or its agent is no longer active (NEW-6). A connection of an admin
//!   session (ADR-0034) is closed when that session ends: closed elsewhere, expired, voided by a
//!   lock, or its enrolment revoked.
//!
//! [`Pending`] holds the connections that have not authenticated. When their budget or the whole
//! server is full, a new connection evicts the oldest one of the busiest source, so silent or
//! trickling clients never lock an agent out, and authenticated connections are never evicted
//! (DEC-T27-D2-2). [`Owners`] caps the authenticated connections of one agent, so one token
//! cannot take every authenticated slot (NEW-6, DEC-T27-E-2).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::response::Response;
use cerberus_types::{AgentId, AgentKeyId, Stopwatch};
use hyper::body::{Frame, SizeHint};
use tokio::sync::Notify;

use crate::admin::SessionId;
use crate::config::ApiLimits;

/// Who an authenticated connection belongs to. [`watch`] closes it when the owner is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnOwner {
    /// The agent and key of its first authenticated agent request (NEW-6).
    Agent(AgentId, AgentKeyId),
    /// The admin session of its last admin request with a session (ADR-0034).
    Admin(SessionId),
}

const UNAUTHENTICATED: u8 = 0;
const AUTHENTICATED: u8 = 1;
const EVICTED: u8 = 2;

/// The shortest sleep of [`watch`], in milliseconds. Every limit is at least this long in effect,
/// so a tiny limit can never make the sleep bounds cross (NEW-7).
const MIN_WAIT_MS: u64 = 5;

/// How often [`watch`] wakes at least, and so asks whether the key of an authenticated connection
/// is still live.
const OWNER_CHECK_MS: u64 = 1_000;

/// Responses of one connection that hyper has been handed but has not pulled further, by ID,
/// with the time (ms since accept) they started to wait.
#[derive(Debug, Default)]
struct Sends {
    next_id: u64,
    waiting: HashMap<u64, u64>,
}

/// What happened on one connection, shared by the accept loop, the service, the token check and
/// the watcher.
#[derive(Debug)]
pub(crate) struct Activity {
    /// Started at accept.
    start: Stopwatch,
    /// `UNAUTHENTICATED`, `AUTHENTICATED` or `EVICTED`. Authenticated and evicted are final.
    state: AtomicU8,
    /// Milliseconds since `start` when the TLS handshake ended.
    handshake_ms: AtomicU64,
    /// True after the first complete request head.
    requested: AtomicBool,
    /// Authenticated requests that run now (their response is not fully sent yet).
    authed_inflight: AtomicUsize,
    /// Milliseconds since `start` of the last start or end of an authenticated request.
    authed_ms: AtomicU64,
    /// Milliseconds since `start` when the connection got its slot. It is 0 unless the connection
    /// had to wait for one; the `auth_timeout` counts from here (NEW-7).
    admitted_ms: AtomicU64,
    /// Woken when the connection is evicted.
    evict: Notify,
    /// The owner, set by [`Owners::bind`] (the agent of the first authenticated agent request)
    /// or [`Owners::bind_admin`].
    owner: Mutex<Option<ConnOwner>>,
    /// True once the connection has ended (it no longer counts for [`Owners`]).
    closed: AtomicBool,
    /// Responses that wait for hyper to pull more of them (NEW-6).
    sends: Mutex<Sends>,
}

impl Activity {
    /// A connection that has just been accepted.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Stopwatch::start(),
            state: AtomicU8::new(UNAUTHENTICATED),
            handshake_ms: AtomicU64::new(0),
            requested: AtomicBool::new(false),
            authed_inflight: AtomicUsize::new(0),
            authed_ms: AtomicU64::new(0),
            admitted_ms: AtomicU64::new(0),
            evict: Notify::new(),
            owner: Mutex::new(None),
            closed: AtomicBool::new(false),
            sends: Mutex::new(Sends::default()),
        })
    }

    /// The connection got its slot after a wait: the unauthenticated lifetime starts now, not at
    /// accept, so a long wait does not close it before its first request (NEW-7).
    pub fn admitted(&self) {
        self.admitted_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    /// The connection has ended. Called by the accept loop when its task finishes.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn owner(&self) -> Option<ConnOwner> {
        *self.owner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sends(&self) -> std::sync::MutexGuard<'_, Sends> {
        self.sends.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A response was handed to hyper: it waits for hyper from now on.
    fn send_begin(&self) -> u64 {
        let now = self.now_ms();
        let mut sends = self.sends();
        let id = sends.next_id;
        sends.next_id = sends.next_id.wrapping_add(1);
        sends.waiting.insert(id, now);
        id
    }

    /// hyper pulls the response (progress), or the response is done: it no longer waits.
    fn send_pulled(&self, id: u64) {
        self.sends().waiting.remove(&id);
    }

    /// The response gave hyper a frame: it waits for hyper again from now on.
    fn send_ready(&self, id: u64) {
        let now = self.now_ms();
        self.sends().waiting.insert(id, now);
    }

    /// Since when (ms since accept) the response that has waited longest for hyper waits.
    fn oldest_send(&self) -> Option<u64> {
        self.sends().waiting.values().copied().min()
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    fn is_unauthenticated(&self) -> bool {
        self.state() == UNAUTHENTICATED
    }

    /// The TLS handshake ended: the first-request time starts now.
    pub fn handshake_done(&self) {
        self.handshake_ms.store(self.now_ms(), Ordering::Relaxed);
    }

    /// A complete request head arrived (the service was called).
    pub fn request_started(&self) {
        self.requested.store(true, Ordering::Relaxed);
    }

    /// A request on this connection passed the token check. From now on the connection is never
    /// evicted. The guard keeps the connection busy until the response is fully sent.
    #[must_use]
    pub fn authenticated(self: &Arc<Self>) -> AuthedRequest {
        // An evicted connection stays evicted (the exchange fails); it is closed anyway.
        let _already_final = self.state.compare_exchange(
            UNAUTHENTICATED,
            AUTHENTICATED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.authed_inflight.fetch_add(1, Ordering::Relaxed);
        self.authed_ms.store(self.now_ms(), Ordering::Relaxed);
        AuthedRequest(Arc::clone(self))
    }

    /// Marks an unauthenticated connection as evicted and wakes it. False when it already
    /// authenticated (or was evicted before).
    fn evict(&self) -> bool {
        let evicted = self
            .state
            .compare_exchange(
                UNAUTHENTICATED,
                EVICTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if evicted {
            self.evict.notify_one();
        }
        evicted
    }

    /// Ends when the connection is evicted for a newer one.
    pub async fn evicted(&self) {
        loop {
            if self.state() == EVICTED {
                return;
            }
            self.evict.notified().await;
        }
    }
}

/// The request extension that lets the token check reach its connection.
#[derive(Clone, Debug)]
pub(crate) struct ConnActivity(pub Arc<Activity>);

/// An authenticated request that runs. While one exists, the connection is not idle.
#[derive(Debug)]
pub(crate) struct AuthedRequest(Arc<Activity>);

impl Drop for AuthedRequest {
    fn drop(&mut self) {
        self.0.authed_inflight.fetch_sub(1, Ordering::Relaxed);
        self.0.authed_ms.store(self.0.now_ms(), Ordering::Relaxed);
    }
}

/// Keeps `guard` until hyper has sent the whole body of `response` (or dropped it), so a long
/// stream counts as a running request. It also records when hyper last pulled the body, for the
/// `send_timeout` (NEW-6).
pub(crate) fn hold_until_sent(response: Response, guard: AuthedRequest) -> Response {
    let sending = Sending {
        id: guard.0.send_begin(),
        activity: Arc::clone(&guard.0),
    };
    response.map(|body| {
        Body::new(Held {
            inner: body,
            sending,
            _guard: guard,
        })
    })
}

/// One response in [`Activity::sends`]. Leaves it on drop.
struct Sending {
    activity: Arc<Activity>,
    id: u64,
}

impl Drop for Sending {
    fn drop(&mut self) {
        self.activity.send_pulled(self.id);
    }
}

/// A response body that holds an [`AuthedRequest`].
struct Held {
    inner: Body,
    sending: Sending,
    _guard: AuthedRequest,
}

impl hyper::body::Body for Held {
    type Data = <Body as hyper::body::Body>::Data;
    type Error = <Body as hyper::body::Body>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // hyper pulls: progress. If the body has a frame now, the response waits for hyper again;
        // if the body itself waits (an SSE stream between events), nothing waits for the client.
        self.sending.activity.send_pulled(self.sending.id);
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(poll, Poll::Ready(Some(Ok(_)))) {
            self.sending.activity.send_ready(self.sending.id);
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Why [`watch`] ended a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Closed {
    /// No complete request head within `header_timeout` after the handshake.
    NoRequest,
    /// No authenticated request within `auth_timeout` after accept.
    NotAuthenticated,
    /// No authenticated request ran for `idle_timeout`.
    Idle,
    /// A response waited `send_timeout` for the client (NEW-6).
    SendStalled,
    /// The key of the connection was revoked or expired, or its agent is not active (NEW-6).
    OwnerGone,
}

/// Ends when a deadline of the module rules passes. Bytes and HTTP/2 control frames never move a
/// deadline; only requests do. `owner_live` says whether the owner of the connection is still
/// there: a key of an agent can still pass a token check, or an admin session is still live.
pub(crate) async fn watch(
    activity: Arc<Activity>,
    limits: &ApiLimits,
    owner_live: &(dyn Fn(ConnOwner) -> bool + Send + Sync),
) -> Closed {
    let header = millis(limits.header_timeout);
    let auth = millis(limits.auth_timeout);
    let idle = millis(limits.idle_timeout);
    let send = millis(limits.send_timeout);
    // The state can change at any time, so never sleep longer than the shortest limit. The floor
    // keeps `step >= MIN_WAIT_MS`, so the clamp below cannot panic (NEW-7).
    let step = header.min(auth).min(idle).min(send).max(MIN_WAIT_MS);
    loop {
        let now = activity.now_ms();
        let wait = if activity.state() == AUTHENTICATED {
            if let Some(owner) = activity.owner()
                && !owner_live(owner)
            {
                return Closed::OwnerGone;
            }
            if activity.authed_inflight.load(Ordering::Relaxed) > 0 {
                match activity.oldest_send() {
                    Some(since) => {
                        let waited = now.saturating_sub(since);
                        if waited >= send {
                            return Closed::SendStalled;
                        }
                        send - waited
                    }
                    None => step,
                }
            } else {
                let since = now.saturating_sub(activity.authed_ms.load(Ordering::Relaxed));
                if since >= idle {
                    return Closed::Idle;
                }
                idle - since
            }
        } else {
            let deadline = activity
                .admitted_ms
                .load(Ordering::Relaxed)
                .saturating_add(auth);
            if now >= deadline {
                return Closed::NotAuthenticated;
            }
            let mut wait = deadline - now;
            if !activity.requested.load(Ordering::Relaxed) {
                let first = activity
                    .handshake_ms
                    .load(Ordering::Relaxed)
                    .saturating_add(header);
                if now >= first {
                    return Closed::NoRequest;
                }
                wait = wait.min(first - now);
            }
            wait
        };
        // Also wake each `OWNER_CHECK_MS`: a connection that authenticates during a long sleep
        // must see a revoke of its key soon after.
        let wait = wait.clamp(MIN_WAIT_MS, step).min(OWNER_CHECK_MS);
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The source of a connection for the eviction order. All of loopback (`127.0.0.0/8`, `::1`, and
/// their IPv4-mapped forms) is one source, since every local agent and every local attacker share
/// it. An IPv6 address counts by its `/64`, which one host can fill with addresses.
#[must_use]
pub(crate) fn source_of(ip: IpAddr) -> IpAddr {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return IpAddr::V4(Ipv4Addr::LOCALHOST);
    }
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !u128::from(u64::MAX);
            IpAddr::V6(Ipv6Addr::from(bits))
        }
    }
}

struct Entry {
    id: u64,
    source: IpAddr,
    activity: Arc<Activity>,
}

#[derive(Default)]
struct Table {
    next_id: u64,
    /// In accept order: the oldest first. Holds only live connections; ones that authenticated or
    /// were evicted are pruned at the next admission.
    entries: Vec<Entry>,
}

/// The connections that have not authenticated yet (DEC-T27-D2-2).
pub(crate) struct Pending {
    max: usize,
    table: Mutex<Table>,
}

/// The place of one connection in [`Pending`]. Given back on drop.
pub(crate) struct PendingSlot {
    owner: Arc<Pending>,
    id: u64,
}

impl Pending {
    /// At most `max` unauthenticated connections at one time (at least one).
    #[must_use]
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max: max.max(1),
            table: Mutex::new(Table::default()),
        })
    }

    /// Adds a new connection from `ip`. When the budget is full, or `server_full` (no free
    /// connection slot), the oldest connection of the source with the most unauthenticated
    /// connections is evicted first. The flag is true when one was evicted.
    pub fn admit(
        this: &Arc<Self>,
        ip: IpAddr,
        activity: &Arc<Activity>,
        server_full: bool,
    ) -> (PendingSlot, bool) {
        let mut table = this.table.lock().unwrap_or_else(PoisonError::into_inner);
        table
            .entries
            .retain(|entry| entry.activity.is_unauthenticated());
        let mut evicted = false;
        if server_full || table.entries.len() >= this.max {
            evicted = evict_any(&mut table.entries);
        }
        let id = table.next_id;
        table.next_id = table.next_id.wrapping_add(1);
        table.entries.push(Entry {
            id,
            source: source_of(ip),
            activity: Arc::clone(activity),
        });
        let slot = PendingSlot {
            owner: Arc::clone(this),
            id,
        };
        (slot, evicted)
    }
}

/// Evicts one connection, see [`evict_one`]. A victim that authenticated after the prune is not
/// evicted (it only leaves the table); then the next one is tried, so a full server still frees a
/// slot this round (NEW-7). Each try removes an entry, so this ends.
fn evict_any(entries: &mut Vec<Entry>) -> bool {
    while !entries.is_empty() {
        if evict_one(entries) {
            return true;
        }
    }
    false
}

/// Evicts the oldest connection of the source that holds the most entries (ties: the source
/// with the oldest connection). A flood from one source only cycles its own connections.
fn evict_one(entries: &mut Vec<Entry>) -> bool {
    let mut counts: HashMap<IpAddr, usize> = HashMap::new();
    for entry in entries.iter() {
        *counts.entry(entry.source).or_insert(0) += 1;
    }
    let Some(most) = counts.values().copied().max() else {
        return false;
    };
    let victim = entries
        .iter()
        .position(|entry| counts.get(&entry.source).copied() == Some(most));
    match victim {
        Some(index) => {
            let entry = entries.remove(index);
            entry.activity.evict()
        }
        None => false,
    }
}

/// The authenticated connections of each agent (NEW-6, DEC-T27-E-2). A connection belongs to the
/// agent and key of its first authenticated request.
pub(crate) struct Owners {
    max: usize,
    by_agent: Mutex<HashMap<AgentId, Vec<Weak<Activity>>>>,
}

impl Owners {
    /// At most `max` open authenticated connections per agent (at least one).
    #[must_use]
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max: max.max(1),
            by_agent: Mutex::new(HashMap::new()),
        })
    }

    /// Binds the connection to `agent` and `key` unless it is bound already. False when the agent
    /// already has `max` open connections; the connection is then not bound and must not be
    /// marked authenticated.
    pub fn bind(&self, activity: &Arc<Activity>, agent: AgentId, key: AgentKeyId) -> bool {
        let mut by_agent = self.by_agent.lock().unwrap_or_else(PoisonError::into_inner);
        let mut owner = activity
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if owner.is_some() {
            return true;
        }
        let list = by_agent.entry(agent).or_default();
        list.retain(|weak| weak.upgrade().is_some_and(|conn| !conn.is_closed()));
        if list.len() >= self.max {
            return false;
        }
        list.push(Arc::downgrade(activity));
        *owner = Some(ConnOwner::Agent(agent, key));
        true
    }

    /// Binds the connection to an admin session, so it closes when the session ends. It does not
    /// count against an agent's connections. A connection that an agent owns stays the agent's;
    /// one of an earlier admin session moves to the new session.
    pub fn bind_admin(&self, activity: &Arc<Activity>, session: SessionId) {
        let mut owner = activity
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !matches!(*owner, Some(ConnOwner::Agent(..))) {
            *owner = Some(ConnOwner::Admin(session));
        }
    }

    /// Unbinds the connection from an admin session that the client closed itself, so the
    /// connection is not cut under the answer of that close. It keeps the normal idle deadline.
    pub fn unbind_admin(&self, activity: &Arc<Activity>, session: SessionId) {
        let mut owner = activity
            .owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *owner == Some(ConnOwner::Admin(session)) {
            *owner = None;
        }
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        let mut table = self
            .owner
            .table
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        table.entries.retain(|entry| entry.id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    #[test]
    fn every_loopback_address_is_one_source() {
        let loopback = source_of(ip("127.0.0.1"));
        for other in ["127.0.0.2", "127.255.0.9", "::1", "::ffff:127.0.0.9"] {
            assert_eq!(source_of(ip(other)), loopback, "{other}");
        }
        assert_ne!(source_of(ip("192.0.2.1")), loopback);
        assert_eq!(source_of(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
    }

    #[test]
    fn an_ipv6_source_is_its_64_prefix() {
        assert_eq!(source_of(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(
            source_of(ip("2001:db8:1:2:bbbb::7")),
            source_of(ip("2001:db8:1:2:aaaa::1"))
        );
        assert_ne!(
            source_of(ip("2001:db8:1:3::1")),
            source_of(ip("2001:db8:1:2::1"))
        );
    }

    #[test]
    fn a_full_budget_evicts_the_oldest_of_the_busiest_source() {
        let pending = Pending::new(3);
        let lone = Activity::new();
        let flood: Vec<_> = (0..2).map(|_| Activity::new()).collect();
        let (_lone, _) = Pending::admit(&pending, ip("192.0.2.1"), &lone, false);
        let _flood: Vec<_> = flood
            .iter()
            .map(|activity| Pending::admit(&pending, ip("192.0.2.9"), activity, false))
            .collect();
        // The fourth connection: the busiest source loses its oldest one, the lone one stays.
        let newer = Activity::new();
        let (_newer, evicted) = Pending::admit(&pending, ip("192.0.2.9"), &newer, false);
        assert!(evicted);
        assert!(lone.is_unauthenticated());
        assert_eq!(flood[0].state(), EVICTED);
        assert!(flood[1].is_unauthenticated());
    }

    #[test]
    fn an_authenticated_connection_is_never_evicted() {
        let pending = Pending::new(1);
        let agent = Activity::new();
        let (_agent, _) = Pending::admit(&pending, ip("127.0.0.1"), &agent, false);
        let running = agent.authenticated();
        let other = Activity::new();
        let (_other, evicted) = Pending::admit(&pending, ip("127.0.0.1"), &other, true);
        // Only the new connection is unauthenticated, and it is not evicted for itself.
        assert!(!evicted);
        assert_eq!(agent.state(), AUTHENTICATED);
        drop(running);
        let third = Activity::new();
        let (_third, evicted) = Pending::admit(&pending, ip("127.0.0.1"), &third, false);
        assert!(evicted);
        assert_eq!(other.state(), EVICTED);
        assert_eq!(agent.state(), AUTHENTICATED);
    }

    #[test]
    fn an_evicted_connection_does_not_become_authenticated() {
        let activity = Activity::new();
        assert!(activity.evict());
        drop(activity.authenticated());
        assert_eq!(activity.state(), EVICTED);
        assert!(!activity.evict());
    }

    fn limits_of(ms: u64) -> ApiLimits {
        ApiLimits {
            header_timeout: Duration::from_millis(ms),
            auth_timeout: Duration::from_millis(ms),
            idle_timeout: Duration::from_millis(ms),
            send_timeout: Duration::from_millis(ms),
            ..ApiLimits::default()
        }
    }

    /// NEW-7: limits under the 5 ms floor of the sleep do not panic (`clamp` with min > max did).
    #[tokio::test]
    async fn tiny_limits_do_not_panic() {
        for ms in [0, 1, 4] {
            let closed = tokio::time::timeout(
                Duration::from_secs(2),
                watch(Activity::new(), &limits_of(ms), &|_| true),
            )
            .await
            .expect("watch ends");
            assert!(
                matches!(closed, Closed::NoRequest | Closed::NotAuthenticated),
                "{ms} ms: {closed:?}"
            );
        }
    }

    /// NEW-7: a connection that waited for a slot gets its whole `auth_timeout` from the moment it
    /// got the slot, not from accept.
    #[tokio::test]
    async fn the_auth_time_starts_when_the_slot_is_free() {
        let limits = ApiLimits {
            header_timeout: Duration::from_secs(30),
            auth_timeout: Duration::from_millis(200),
            ..ApiLimits::default()
        };
        let activity = Activity::new();
        tokio::time::sleep(Duration::from_millis(300)).await;
        activity.admitted();
        activity.handshake_done();
        let early = tokio::time::timeout(
            Duration::from_millis(100),
            watch(Arc::clone(&activity), &limits, &|_| true),
        )
        .await;
        assert!(early.is_err(), "closed right after the wait: {early:?}");
        let closed =
            tokio::time::timeout(Duration::from_secs(2), watch(activity, &limits, &|_| true))
                .await
                .expect("closed at the deadline");
        assert_eq!(closed, Closed::NotAuthenticated);
    }

    /// NEW-7: when the chosen victim authenticated after the prune, the next one is evicted.
    #[test]
    fn a_victim_that_authenticated_does_not_stop_the_eviction() {
        let busy = Activity::new();
        let next = Activity::new();
        let mut entries = vec![
            Entry {
                id: 0,
                source: ip("192.0.2.9"),
                activity: Arc::clone(&busy),
            },
            Entry {
                id: 1,
                source: ip("192.0.2.9"),
                activity: Arc::clone(&next),
            },
        ];
        let _running = busy.authenticated();
        assert!(evict_any(&mut entries));
        assert_eq!(busy.state(), AUTHENTICATED);
        assert_eq!(next.state(), EVICTED);
        assert!(entries.is_empty());
        assert!(!evict_any(&mut entries));
    }

    /// NEW-6: an agent binds at most `max` open connections; a closed one frees its place, and a
    /// bound connection stays bound to its first key.
    #[test]
    fn one_agent_binds_at_most_max_connections() {
        let owners = Owners::new(2);
        let agent = AgentId::generate();
        let key = AgentKeyId::generate();
        let conns: Vec<_> = (0..3).map(|_| Activity::new()).collect();
        assert!(owners.bind(&conns[0], agent, key));
        assert!(owners.bind(&conns[1], agent, key));
        assert!(!owners.bind(&conns[2], agent, key));
        assert_eq!(conns[2].owner(), None);
        // Another agent is not affected; a bound connection is not counted twice.
        assert!(owners.bind(&conns[0], AgentId::generate(), AgentKeyId::generate()));
        assert_eq!(conns[0].owner(), Some(ConnOwner::Agent(agent, key)));
        assert!(owners.bind(&Activity::new(), AgentId::generate(), key));
        conns[0].close();
        assert!(owners.bind(&conns[2], agent, key));
    }

    /// ADR-0034: an admin session owns a connection outside the agent cap; a newer session takes
    /// it over, an agent's connection stays the agent's, and only its own session unbinds it.
    #[tokio::test]
    async fn an_admin_session_owns_its_connection_until_it_ends() {
        let owners = Owners::new(1);
        let (first, second) = (SessionId::generate(), SessionId::generate());
        let conn = Activity::new();
        owners.bind_admin(&conn, first);
        assert_eq!(conn.owner(), Some(ConnOwner::Admin(first)));
        owners.bind_admin(&conn, second);
        assert_eq!(conn.owner(), Some(ConnOwner::Admin(second)));
        owners.unbind_admin(&conn, first);
        assert_eq!(conn.owner(), Some(ConnOwner::Admin(second)));
        let agent_conn = Activity::new();
        assert!(owners.bind(&agent_conn, AgentId::generate(), AgentKeyId::generate()));
        owners.bind_admin(&agent_conn, first);
        assert!(matches!(agent_conn.owner(), Some(ConnOwner::Agent(..))));
        // The watcher closes the connection once its session is gone.
        let _running = conn.authenticated();
        let closed = tokio::time::timeout(
            Duration::from_secs(5),
            watch(Arc::clone(&conn), &limits_of(60_000), &|owner| {
                owner != ConnOwner::Admin(second)
            }),
        )
        .await
        .expect("closed");
        assert_eq!(closed, Closed::OwnerGone);
        owners.unbind_admin(&conn, second);
        assert_eq!(conn.owner(), None);
    }

    /// NEW-6: a response waits for hyper from when it is handed over until hyper pulls it, and
    /// again after each frame; a body that waits for itself is not waiting for the client.
    #[test]
    fn a_response_waits_for_the_client_only_between_frames() {
        let activity = Activity::new();
        assert_eq!(activity.oldest_send(), None);
        let id = activity.send_begin();
        assert!(activity.oldest_send().is_some());
        activity.send_pulled(id);
        assert_eq!(activity.oldest_send(), None);
        activity.send_ready(id);
        assert!(activity.oldest_send().is_some());
        drop(Sending {
            activity: Arc::clone(&activity),
            id,
        });
        assert_eq!(activity.oldest_send(), None);
    }

    #[test]
    fn a_freed_slot_leaves_the_table() {
        let pending = Pending::new(1);
        let first = Activity::new();
        let (slot, _) = Pending::admit(&pending, ip("127.0.0.1"), &first, false);
        drop(slot);
        let second = Activity::new();
        let (_second, evicted) = Pending::admit(&pending, ip("127.0.0.1"), &second, false);
        assert!(!evicted);
        assert!(first.is_unauthenticated());
    }
}
