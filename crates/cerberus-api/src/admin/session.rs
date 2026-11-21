//! The admin session table (ADR-0034 point 6, DEC-RM-5). In memory only: no session survives a
//! restart.
//!
//! A token is `cas_<session id>.<secret>`: a UUIDv7 and 32 random bytes in base64url. The table
//! keeps the SHA-256 of the secret, never the secret. A session is bound to the enrolment and the
//! client certificate that opened it, to the operator, and to the lock epoch of the vault, so a
//! lock or a new unlock voids it. It ends after its idle or its absolute limit.

use std::collections::HashMap;

use cerberus_admin::clients::EnrolmentId;
use cerberus_admin::wire::SESSION_TOKEN_PREFIX;
use cerberus_core::{OperatorContext, SessionCloseReason};
use cerberus_crypto::{CryptoError, Key32, ct_eq, sha256};
use cerberus_types::wire::WireSecret;
use data_encoding::BASE64URL_NOPAD;
use jiff::Timestamp;
use zeroize::Zeroizing;

use super::AdminLimits;

cerberus_types::uuid_id!(
    /// ID of one admin session (UUIDv7). It is the visible part of the token.
    SessionId
);

/// Domain label of the token hash.
const HASH_LABEL: &[u8] = b"cerberus/v1/admin-session";
/// Length of the session ID text.
const ID_CHARS: usize = 36;
/// Length of the base64url secret (32 bytes, no padding).
const SECRET_CHARS: usize = 43;

/// One live session.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    /// Session ID.
    pub id: SessionId,
    /// The enrolment that opened it.
    pub enrolment: EnrolmentId,
    /// The label of that enrolment (for the audit).
    pub label: String,
    /// SHA-256 of the client certificate of the connection that opened it.
    pub cert_sha256: [u8; 32],
    /// The operator context of the vault session (its request ID is replaced per call).
    pub ctx: OperatorContext,
    /// The lock epoch of the vault when the session opened.
    pub epoch: u64,
    /// Open time.
    pub opened_at: Timestamp,
    /// Last call that counts as activity.
    pub last_used: Timestamp,
    /// SHA-256 of the domain label, the ID and the secret.
    hash: [u8; 32],
    /// Event streams that run now.
    streams: usize,
}

/// A session that ended, for the audit (`admin.session_close`).
#[derive(Debug)]
pub(crate) struct Closed {
    /// The enrolment of the session.
    pub enrolment: EnrolmentId,
    /// Its label.
    pub label: String,
    /// The operator context of the session.
    pub ctx: OperatorContext,
    /// Why it ended.
    pub reason: SessionCloseReason,
}

impl Closed {
    fn of(session: Session, reason: SessionCloseReason) -> Self {
        Self {
            enrolment: session.enrolment,
            label: session.label,
            ctx: session.ctx,
            reason,
        }
    }
}

/// Why a token does not pass. Every reason is the same `401 admin_session_required` outside.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// Not a `cas_` token of the right form.
    Malformed,
    /// No such session, or the secret does not match.
    Unknown,
    /// The token came over a connection with another client certificate.
    OtherDevice,
    /// The session was past a limit or the vault was locked; it is removed now.
    Ended(Closed),
}

/// What a new session is bound to.
pub(crate) struct NewSession {
    /// The enrolment.
    pub enrolment: EnrolmentId,
    /// Its label.
    pub label: String,
    /// The client certificate of the connection.
    pub cert_sha256: [u8; 32],
    /// The operator context the phrase check gave.
    pub ctx: OperatorContext,
    /// The lock epoch read before the phrase check.
    pub epoch: u64,
}

fn token_hash(id: SessionId, secret: &[u8; 32]) -> [u8; 32] {
    sha256(&[HASH_LABEL, id.as_bytes(), secret])
}

fn millis_since(now: Timestamp, then: Timestamp) -> i64 {
    now.as_millisecond().saturating_sub(then.as_millisecond())
}

fn seconds_ms(seconds: u32) -> i64 {
    i64::from(seconds).saturating_mul(1000)
}

/// Parses `cas_<uuid>.<43 chars>`. Strict: the canonical lower-case ID and a canonical secret.
fn parse(token: &str) -> Option<(SessionId, Zeroizing<[u8; 32]>)> {
    let rest = token.strip_prefix(SESSION_TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('.')?;
    if id.len() != ID_CHARS || secret.len() != SECRET_CHARS {
        return None;
    }
    let id: SessionId = id.parse().ok()?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    if BASE64URL_NOPAD.decode_len(secret.len()).ok()? != bytes.len() {
        return None;
    }
    BASE64URL_NOPAD
        .decode_mut(secret.as_bytes(), &mut bytes[..])
        .ok()?;
    Some((id, bytes))
}

/// The live sessions of the daemon.
#[derive(Debug, Default)]
pub(crate) struct SessionTable {
    sessions: HashMap<SessionId, Session>,
}

impl SessionTable {
    /// Why `session` has ended at `now`, if it has. `live_epoch` is the lock epoch while the vault
    /// is unlocked, else `None`.
    fn ended(
        session: &Session,
        now: Timestamp,
        live_epoch: Option<u64>,
        limits: &AdminLimits,
    ) -> Option<SessionCloseReason> {
        if live_epoch != Some(session.epoch) {
            return Some(SessionCloseReason::Lock);
        }
        if millis_since(now, session.opened_at) >= seconds_ms(limits.session_max_seconds) {
            return Some(SessionCloseReason::Max);
        }
        if millis_since(now, session.last_used) >= seconds_ms(limits.session_idle_seconds) {
            return Some(SessionCloseReason::Idle);
        }
        None
    }

    /// Number of sessions in the table (ended ones may be counted until the next sweep).
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Opens a session and returns its ID, its token and the sessions it pushed out: at most
    /// `max_sessions_per_enrolment` per enrolment and `max_sessions` in all, the oldest of the
    /// same enrolment first, then the oldest of all.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the OS random generator fails.
    pub fn open(
        &mut self,
        new: NewSession,
        now: Timestamp,
        limits: &AdminLimits,
    ) -> Result<(SessionId, WireSecret, Vec<Closed>), CryptoError> {
        let secret = Key32::random()?;
        let id = SessionId::generate();
        let hash = token_hash(id, secret.expose_secret());
        let mut text = Zeroizing::new([0u8; SECRET_CHARS]);
        BASE64URL_NOPAD.encode_mut(secret.expose_secret(), &mut text[..]);
        let mut token =
            String::with_capacity(SESSION_TOKEN_PREFIX.len() + ID_CHARS + 1 + SECRET_CHARS);
        token.push_str(SESSION_TOKEN_PREFIX);
        token.push_str(&id.to_string());
        token.push('.');
        token.extend(text.iter().map(|b| char::from(*b)));

        let mut closed = Vec::new();
        let per_enrolment = limits.max_sessions_per_enrolment.max(1);
        while self.count_of(new.enrolment) >= per_enrolment {
            match self.oldest(Some(new.enrolment)) {
                Some(old) => closed.extend(self.close(old, SessionCloseReason::Closed)),
                None => break,
            }
        }
        while self.sessions.len() >= limits.max_sessions.max(1) {
            match self.oldest(None) {
                Some(old) => closed.extend(self.close(old, SessionCloseReason::Closed)),
                None => break,
            }
        }
        self.sessions.insert(
            id,
            Session {
                id,
                enrolment: new.enrolment,
                label: new.label,
                cert_sha256: new.cert_sha256,
                ctx: new.ctx,
                epoch: new.epoch,
                opened_at: now,
                last_used: now,
                hash,
                streams: 0,
            },
        );
        Ok((id, WireSecret::new(token), closed))
    }

    fn count_of(&self, enrolment: EnrolmentId) -> usize {
        self.sessions
            .values()
            .filter(|s| s.enrolment == enrolment)
            .count()
    }

    fn oldest(&self, enrolment: Option<EnrolmentId>) -> Option<SessionId> {
        self.sessions
            .values()
            .filter(|s| enrolment.is_none_or(|e| s.enrolment == e))
            .min_by_key(|s| (s.opened_at, s.id))
            .map(|s| s.id)
    }

    /// Checks a token that came over a connection with the client certificate `cert_sha256`. An
    /// ended session is removed and given back in [`Refusal::Ended`] for the audit.
    pub fn check(
        &mut self,
        token: &str,
        cert_sha256: &[u8; 32],
        now: Timestamp,
        live_epoch: Option<u64>,
        limits: &AdminLimits,
    ) -> Result<Session, Refusal> {
        let (id, secret) = parse(token).ok_or(Refusal::Malformed)?;
        let session = self.sessions.get(&id).ok_or(Refusal::Unknown)?;
        if !ct_eq(&token_hash(id, &secret), &session.hash) {
            return Err(Refusal::Unknown);
        }
        if !ct_eq(cert_sha256, &session.cert_sha256) {
            return Err(Refusal::OtherDevice);
        }
        if let Some(reason) = Self::ended(session, now, live_epoch, limits) {
            let closed = self.close(id, reason).ok_or(Refusal::Unknown)?;
            return Err(Refusal::Ended(closed));
        }
        Ok(session.clone())
    }

    /// True when the session exists and has not ended at `now`.
    pub fn is_live(
        &self,
        id: SessionId,
        now: Timestamp,
        live_epoch: Option<u64>,
        limits: &AdminLimits,
    ) -> bool {
        self.sessions
            .get(&id)
            .is_some_and(|s| Self::ended(s, now, live_epoch, limits).is_none())
    }

    /// The enrolment of a session.
    pub fn enrolment_of(&self, id: SessionId) -> Option<EnrolmentId> {
        self.sessions.get(&id).map(|s| s.enrolment)
    }

    /// Resets the idle limit of the session.
    pub fn touch(&mut self, id: SessionId, now: Timestamp) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.last_used = session.last_used.max(now);
        }
    }

    /// Removes the session.
    pub fn close(&mut self, id: SessionId, reason: SessionCloseReason) -> Option<Closed> {
        self.sessions
            .remove(&id)
            .map(|session| Closed::of(session, reason))
    }

    /// Removes every session of the enrolment (it was revoked).
    pub fn drop_enrolment(&mut self, enrolment: EnrolmentId) -> Vec<Closed> {
        let ids: Vec<SessionId> = self
            .sessions
            .values()
            .filter(|s| s.enrolment == enrolment)
            .map(|s| s.id)
            .collect();
        ids.into_iter()
            .filter_map(|id| self.close(id, SessionCloseReason::Revoked))
            .collect()
    }

    /// Removes every session that has ended at `now`.
    pub fn sweep(
        &mut self,
        now: Timestamp,
        live_epoch: Option<u64>,
        limits: &AdminLimits,
    ) -> Vec<Closed> {
        let ended: Vec<(SessionId, SessionCloseReason)> = self
            .sessions
            .values()
            .filter_map(|s| Self::ended(s, now, live_epoch, limits).map(|reason| (s.id, reason)))
            .collect();
        ended
            .into_iter()
            .filter_map(|(id, reason)| self.close(id, reason))
            .collect()
    }

    /// Takes one event stream slot of the session. False when it has `max` already or is gone.
    pub fn stream_acquire(&mut self, id: SessionId, max: usize) -> bool {
        match self.sessions.get_mut(&id) {
            Some(session) if session.streams < max => {
                session.streams += 1;
                true
            }
            _ => false,
        }
    }

    /// Gives back an event stream slot.
    pub fn stream_release(&mut self, id: SessionId) {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.streams = session.streams.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use cerberus_types::{OperatorId, OperatorRole, RequestId, t0};
    use jiff::SignedDuration;

    use super::*;

    fn ctx() -> OperatorContext {
        OperatorContext {
            operator_id: OperatorId::generate(),
            role: OperatorRole::Owner,
            request_id: RequestId::generate(),
        }
    }

    fn new(enrolment: EnrolmentId, cert: u8) -> NewSession {
        NewSession {
            enrolment,
            label: "laptop".to_owned(),
            cert_sha256: [cert; 32],
            ctx: ctx(),
            epoch: 3,
        }
    }

    #[test]
    fn a_token_passes_only_with_its_secret_and_its_certificate() {
        let limits = AdminLimits::default();
        let mut table = SessionTable::default();
        let e = EnrolmentId::generate();
        let (id, token, closed) = table.open(new(e, 1), t0(), &limits).unwrap();
        assert!(closed.is_empty());
        let text = token.expose();
        assert!(text.starts_with("cas_"));
        assert_eq!(text.len(), 4 + 36 + 1 + 43);
        assert_eq!(
            table
                .check(text, &[1; 32], t0(), Some(3), &limits)
                .unwrap()
                .id,
            id
        );
        assert!(matches!(
            table.check(text, &[2; 32], t0(), Some(3), &limits),
            Err(Refusal::OtherDevice)
        ));
        let mut wrong = text.to_owned();
        wrong.replace_range(text.len() - 2.., "AA");
        assert!(matches!(
            table.check(&wrong, &[1; 32], t0(), Some(3), &limits),
            Err(Refusal::Unknown)
        ));
        for bad in ["", "cas_", "cvt_x.y", &text[..text.len() - 1]] {
            assert!(matches!(
                table.check(bad, &[1; 32], t0(), Some(3), &limits),
                Err(Refusal::Malformed)
            ));
        }
    }

    #[test]
    fn idle_max_and_lock_end_a_session() {
        let limits = AdminLimits::default();
        let mut table = SessionTable::default();
        let e = EnrolmentId::generate();
        let (_, token, _) = table.open(new(e, 1), t0(), &limits).unwrap();
        let idle = t0() + SignedDuration::from_secs(900);
        match table.check(token.expose(), &[1; 32], idle, Some(3), &limits) {
            Err(Refusal::Ended(closed)) => assert_eq!(closed.reason, SessionCloseReason::Idle),
            other => panic!("{other:?}"),
        }
        let (id, token, _) = table.open(new(e, 1), t0(), &limits).unwrap();
        let mut at = t0();
        for _ in 0..50 {
            at += SignedDuration::from_secs(890);
            table.touch(id, at);
        }
        match table.check(token.expose(), &[1; 32], at, Some(3), &limits) {
            Err(Refusal::Ended(closed)) => assert_eq!(closed.reason, SessionCloseReason::Max),
            other => panic!("{other:?}"),
        }
        let (_, token, _) = table.open(new(e, 1), t0(), &limits).unwrap();
        match table.check(token.expose(), &[1; 32], t0(), Some(4), &limits) {
            Err(Refusal::Ended(closed)) => assert_eq!(closed.reason, SessionCloseReason::Lock),
            other => panic!("{other:?}"),
        }
        let (_, _, _) = table.open(new(e, 1), t0(), &limits).unwrap();
        assert_eq!(table.sweep(t0(), None, &limits).len(), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn caps_push_out_the_oldest_of_the_enrolment_then_the_oldest_of_all() {
        let limits = AdminLimits::default();
        let mut table = SessionTable::default();
        let (a, b, c) = (
            EnrolmentId::generate(),
            EnrolmentId::generate(),
            EnrolmentId::generate(),
        );
        let at = |s: i64| t0() + SignedDuration::from_secs(s);
        let (a1, ..) = table.open(new(a, 1), at(0), &limits).unwrap();
        let (_a2, ..) = table.open(new(a, 1), at(1), &limits).unwrap();
        let (_, _, closed) = table.open(new(a, 1), at(2), &limits).unwrap();
        assert_eq!(closed.len(), 1);
        assert!(!table.is_live(a1, at(2), Some(3), &limits));
        let (b1, ..) = table.open(new(b, 2), at(3), &limits).unwrap();
        let (_b2, ..) = table.open(new(b, 2), at(4), &limits).unwrap();
        assert_eq!(table.len(), 4);
        let (_, _, closed) = table.open(new(c, 3), at(5), &limits).unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].enrolment, a);
        assert_eq!(table.len(), 4);
        assert!(table.is_live(b1, at(5), Some(3), &limits));
        assert_eq!(table.drop_enrolment(b).len(), 2);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn a_session_has_at_most_max_streams() {
        let limits = AdminLimits::default();
        let mut table = SessionTable::default();
        let (id, ..) = table
            .open(new(EnrolmentId::generate(), 1), t0(), &limits)
            .unwrap();
        assert!(table.stream_acquire(id, 2));
        assert!(table.stream_acquire(id, 2));
        assert!(!table.stream_acquire(id, 2));
        table.stream_release(id);
        assert!(table.stream_acquire(id, 2));
        assert!(!table.stream_acquire(SessionId::generate(), 2));
    }
}
