//! Agent token checks (ADR-0016) with rate limits and lockouts (ADR-0030).
//!
//! [`AuthTable`] is an in-memory copy of the plain agent and key columns. It works while the
//! vault is locked: the caller decides between `401` and `423` after [`AuthTable::check`] says the
//! token is good. The table changes in the same call as the DB write (see `crate::agents`), so a
//! revoke is effective at once. There is no result cache.

mod limits;

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{PoisonError, RwLock};

use cerberus_crypto::{ct_eq, parse_token, token_hash};
use cerberus_store::{AgentKeyRow, AgentRow, AgentStatus, RowMacs};
use cerberus_types::Scope;
use cerberus_types::ids::{AgentId, AgentKeyId, RequestId};
use jiff::Timestamp;

use crate::{AgentContext, CoreError, Surface};
pub use limits::AuthLimits;
use limits::{FailureTracker, KeyedBuckets, ip_key, overflow_key};

/// Most keys one agent can have that are neither revoked nor expired (ADR-0016).
pub const MAX_LIVE_KEYS: usize = 5;

/// Every check compares the token hash against exactly this many key slots. Unused slots hold a
/// dummy hash, so an unknown agent costs the same as a known one. It is `MAX_LIVE_KEYS` plus room
/// for dead keys, which are kept so the audit log can say "revoked" or "expired".
pub const KEY_SLOTS: usize = 2 * MAX_LIVE_KEYS;

/// A hash that no token has (it would need a SHA-256 preimage). Fills the unused slots.
const DUMMY_HASH: [u8; 32] = [0; 32];

/// Why a token check failed. The caller sees one `401` for the first eight; the audit keeps the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// The token text is not valid.
    Malformed,
    /// No agent has this ID.
    UnknownAgent,
    /// The agent exists but no key matches the secret.
    NoKeyMatch,
    /// The key is past its expiry.
    KeyExpired,
    /// The key is revoked, or its row failed the MAC check.
    KeyRevoked,
    /// The agent is suspended or revoked.
    AgentInactive,
    /// The source IP is not in the key's allowlist.
    IpNotAllowed,
    /// The key needs a client certificate that was not presented or does not match.
    MtlsMismatch,
    /// Too many requests from this agent, or too many failed checks from this IP
    /// (`429 rate_limited`).
    RateLimited {
        /// Seconds until a retry can work.
        retry_after_seconds: u32,
    },
    /// Too many failed checks from this IP, or from all sources (`429 too_many_failures`). Only a
    /// check that failed gets it; a good token is never locked out (NEW-5).
    LockedOut {
        /// Seconds until the lockout ends.
        retry_after_seconds: u32,
    },
}

impl AuthFailure {
    /// A stable short name for the audit event.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnknownAgent => "unknown_agent",
            Self::NoKeyMatch => "no_key_match",
            Self::KeyExpired => "key_expired",
            Self::KeyRevoked => "key_revoked",
            Self::AgentInactive => "agent_inactive",
            Self::IpNotAllowed => "ip_not_allowed",
            Self::MtlsMismatch => "mtls_mismatch",
            Self::RateLimited { .. } => "rate_limited",
            Self::LockedOut { .. } => "locked_out",
        }
    }

    /// The error the caller sees. Every credential failure is the same `401` (DEC-014); only the
    /// two limits differ, because they carry `retry_after_seconds`. A lockout uses
    /// `CoreError::UnlockBackoff`, which maps to the `too_many_failures` wire code.
    #[must_use]
    pub const fn outward(self) -> CoreError {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => CoreError::RateLimited {
                retry_after_seconds,
            },
            Self::LockedOut {
                retry_after_seconds,
            } => CoreError::UnlockBackoff {
                retry_after_seconds,
            },
            _ => CoreError::BadCredentials,
        }
    }

    /// True when the secret matched a real key and a rule refused it (expired or revoked key,
    /// inactive agent, IP or mTLS rule): someone holds a real token. False for a guess
    /// (malformed, unknown agent, no key match) and for the limits.
    #[must_use]
    pub const fn matched_a_key(self) -> bool {
        matches!(
            self,
            Self::KeyExpired
                | Self::KeyRevoked
                | Self::AgentInactive
                | Self::IpNotAllowed
                | Self::MtlsMismatch
        )
    }
}

/// A refused token check: what the caller is told (`failure`), and the credential failure under it
/// (`cause`). They differ only when a limit refused a failed check: `failure` is then
/// `LockedOut` or `RateLimited`, and `cause` still says, for example, `KeyRevoked` (NEW-8). For a
/// good token past the per-agent limit both are `RateLimited`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// The answer to the caller ([`AuthFailure::outward`]).
    pub failure: AuthFailure,
    /// The reason under it, for the audit.
    pub cause: AuthFailure,
}

impl From<AuthFailure> for Refusal {
    fn from(failure: AuthFailure) -> Self {
        Self {
            failure,
            cause: failure,
        }
    }
}

/// What the transport layer knows about one request. `Debug` hides the token.
pub struct TokenCheckInput<'a> {
    /// The token from the `Authorization: Bearer` header (without the scheme).
    pub raw_token: &'a str,
    /// The IP address of the caller.
    pub source_ip: IpAddr,
    /// SHA-256 of the client certificate, if one was presented.
    pub client_cert_sha256: Option<[u8; 32]>,
    /// The ID the server made for this request.
    pub request_id: RequestId,
    /// The surface the request came in on.
    pub surface: Surface,
}

impl std::fmt::Debug for TokenCheckInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCheckInput")
            .field("raw_token", &"[REDACTED]")
            .field("source_ip", &self.source_ip)
            .field("client_cert_sha256", &self.client_cert_sha256.is_some())
            .field("request_id", &self.request_id)
            .field("surface", &self.surface)
            .finish()
    }
}

/// A row that failed its MAC check (ADR-0033). The UI shows a red alert and the audit gets an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityIssue {
    /// `agents` or `agent_keys`.
    pub table: &'static str,
    /// The row ID.
    pub row_id: String,
}

#[derive(Debug, Clone)]
struct KeyAuth {
    id: AgentKeyId,
    hash: [u8; 32],
    scopes: BTreeSet<Scope>,
    ip_allowlist: Vec<ipnet::IpNet>,
    require_mtls: bool,
    client_cert_sha256: Option<[u8; 32]>,
    created_at: Timestamp,
    expires_at: Option<Timestamp>,
    revoked: bool,
}

impl KeyAuth {
    fn from_row(row: &AgentKeyRow) -> Self {
        Self {
            id: row.id,
            hash: row.secret_hash,
            scopes: row.scopes.iter().copied().collect(),
            ip_allowlist: row.ip_allowlist.clone(),
            require_mtls: row.require_mtls,
            client_cert_sha256: row.client_cert_sha256,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked: row.revoked_at.is_some(),
        }
    }

    fn expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|at| at <= now)
    }

    fn dead(&self, now: Timestamp) -> bool {
        self.revoked || self.expired(now)
    }
}

#[derive(Debug, Clone)]
struct AgentAuth {
    status: AgentStatus,
    keys: Vec<KeyAuth>,
}

impl AgentAuth {
    /// Keeps at most `KEY_SLOTS` keys: dead ones go first, oldest first, then the oldest live ones.
    fn trim(&mut self, now: Timestamp) {
        while self.keys.len() > KEY_SLOTS {
            let drop = self
                .keys
                .iter()
                .enumerate()
                .min_by_key(|(_, key)| (!key.dead(now), key.created_at))
                .map(|(index, _)| index);
            match drop {
                Some(index) => {
                    self.keys.remove(index);
                }
                None => break,
            }
        }
    }
}

/// In-memory copy of agent status and key hashes (plain columns).
///
/// Updated in the same call as the DB write. Rebuilt at unlock with row-MAC checks (ADR-0033);
/// rows with a bad MAC count as revoked.
#[derive(Debug)]
pub struct AuthTable {
    agents: RwLock<HashMap<AgentId, AgentAuth>>,
    limits: AuthLimits,
    ip_rate: KeyedBuckets<IpAddr>,
    agent_rate: KeyedBuckets<AgentId>,
    failures: FailureTracker,
    /// Serializes agent and key changes (read, DB write, table update), so a stale row of one
    /// change can never undo another (DEC-FIX5-2).
    writes: tokio::sync::Mutex<()>,
}

impl AuthTable {
    /// An empty table with these limits.
    #[must_use]
    pub fn new(limits: AuthLimits) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            limits,
            ip_rate: KeyedBuckets::new(),
            agent_rate: KeyedBuckets::new(),
            failures: FailureTracker::new(),
            writes: tokio::sync::Mutex::new(()),
        }
    }

    /// Holds off other agent and key changes until the guard drops. `crate::agents` takes it for
    /// each change.
    pub(crate) async fn lock_writes(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.writes.lock().await
    }

    /// Replaces the content with these rows. Limiter state is kept.
    ///
    /// With `macs`, rows with a bad MAC are loaded as revoked and listed in the result. Without
    /// `macs` (the vault is sealed, no key) the rows are used as stored; they only decide between
    /// `401` and `423` (ADR-0033 item 5).
    ///
    /// # Errors
    /// `CoreError::Store` if a MAC cannot be computed.
    pub fn rebuild(
        &self,
        agents: &[AgentRow],
        keys: &[AgentKeyRow],
        macs: Option<&RowMacs<'_>>,
        now: Timestamp,
    ) -> Result<Vec<IntegrityIssue>, CoreError> {
        let (agents, keys, issues) = match macs {
            Some(macs) => verify_rows(agents, keys, macs)?,
            None => (agents.to_vec(), keys.to_vec(), Vec::new()),
        };
        let mut table: HashMap<AgentId, AgentAuth> = agents
            .iter()
            .map(|row| {
                (
                    row.id,
                    AgentAuth {
                        status: row.status,
                        keys: Vec::new(),
                    },
                )
            })
            .collect();
        for row in &keys {
            if let Some(agent) = table.get_mut(&row.agent_id) {
                agent.keys.push(KeyAuth::from_row(row));
            }
        }
        for agent in table.values_mut() {
            agent.trim(now);
        }
        *self.agents.write().unwrap_or_else(PoisonError::into_inner) = table;
        Ok(issues)
    }

    /// Adds or updates one agent after a DB write. Keeps its keys.
    pub fn apply_agent(&self, row: &AgentRow) {
        let mut agents = self.agents.write().unwrap_or_else(PoisonError::into_inner);
        agents
            .entry(row.id)
            .and_modify(|agent| agent.status = row.status)
            .or_insert_with(|| AgentAuth {
                status: row.status,
                keys: Vec::new(),
            });
    }

    /// Adds or updates one key after a DB write. Call `apply_agent` first for a new agent;
    /// a key of an unknown agent is ignored (the DB refuses it too).
    pub fn apply_key(&self, row: &AgentKeyRow, now: Timestamp) {
        let mut agents = self.agents.write().unwrap_or_else(PoisonError::into_inner);
        let Some(agent) = agents.get_mut(&row.agent_id) else {
            return;
        };
        let key = KeyAuth::from_row(row);
        match agent.keys.iter_mut().find(|existing| existing.id == row.id) {
            Some(existing) => *existing = key,
            None => agent.keys.push(key),
        }
        agent.trim(now);
    }

    /// The expiry of one key of one agent: `None` when the key is unknown, `Some(None)` for a
    /// key without expiry (the status view of the Agent API).
    #[must_use]
    pub fn key_expires_at(&self, agent: &AgentId, key: &AgentKeyId) -> Option<Option<Timestamp>> {
        let agents = self.agents.read().unwrap_or_else(PoisonError::into_inner);
        agents
            .get(agent)?
            .keys
            .iter()
            .find(|k| k.id == *key)
            .map(|k| k.expires_at)
    }

    /// True while this key of this agent could still pass a check: the agent is active and the key
    /// is known, not revoked and not expired. The API closes the connections of a key when this
    /// turns false (NEW-6, DEC-T27-E-2).
    #[must_use]
    pub fn key_active(&self, agent: &AgentId, key: &AgentKeyId, now: Timestamp) -> bool {
        let agents = self.agents.read().unwrap_or_else(PoisonError::into_inner);
        agents.get(agent).is_some_and(|found| {
            found.status == AgentStatus::Active
                && found.keys.iter().any(|k| k.id == *key && !k.dead(now))
        })
    }

    /// Checks a bearer token: the credential first, then the limits (ADR-0016, ADR-0030).
    ///
    /// A good token is limited per agent only. The source limits apply to failed checks only: a
    /// failure from a locked-out source (or while all sources are locked out) is
    /// `LockedOut`, past the source bucket it is `RateLimited`, else it counts toward both lockouts
    /// and keeps its reason. So a local user who floods bad tokens from `127.0.0.1` can never lock
    /// out the agents that share that address (NEW-5, DEC-T27-E-1). Guessing stays impractical
    /// because of the 256-bit secret, not because of the lockout. The caller maps the result:
    /// `Ok` and the vault is locked gives `423`.
    ///
    /// # Errors
    /// The [`AuthFailure`] reason. Show the caller `AuthFailure::outward`.
    pub fn check(
        &self,
        input: &TokenCheckInput<'_>,
        now: Timestamp,
    ) -> Result<AgentContext, AuthFailure> {
        self.check_refusal(input, now)
            .map_err(|refusal| refusal.failure)
    }

    /// [`Self::check`], and on a refusal also the credential failure under a limit, for the
    /// audit (`VaultService::audit_auth_failure`).
    ///
    /// # Errors
    /// The [`Refusal`]. Show the caller `refusal.failure.outward()`.
    pub fn check_refusal(
        &self,
        input: &TokenCheckInput<'_>,
        now: Timestamp,
    ) -> Result<AgentContext, Refusal> {
        self.check_with(input, now, &mut |a, b| ct_eq(a, b))
    }

    /// `check` with the comparison passed in, so a test can count the comparisons.
    fn check_with(
        &self,
        input: &TokenCheckInput<'_>,
        now: Timestamp,
        eq: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<AgentContext, Refusal> {
        let now_ms = now.as_millisecond();
        match self.verify(input, now, eq) {
            Ok(context) => {
                self.agent_rate
                    .take(
                        context.agent_id,
                        now_ms,
                        self.limits.agent_per_second,
                        self.limits.agent_burst,
                    )
                    .map_err(|retry_after_seconds| AuthFailure::RateLimited {
                        retry_after_seconds,
                    })?;
                Ok(context)
            }
            Err(cause) => Err(Refusal {
                failure: self.failed(ip_key(input.source_ip), now_ms, cause),
                cause,
            }),
        }
    }

    /// The answer to a failed check from `ip`: a lockout or the source bucket refuses it,
    /// else it is counted and keeps its reason.
    fn failed(&self, ip: IpAddr, now_ms: i64, failure: AuthFailure) -> AuthFailure {
        if let Some(retry_after_seconds) = self.failures.locked_for(ip, now_ms) {
            return AuthFailure::LockedOut {
                retry_after_seconds,
            };
        }
        if let Err(retry_after_seconds) = self.ip_rate.take_bounded(
            ip,
            Some(overflow_key()),
            now_ms,
            self.limits.ip_per_second,
            self.limits.ip_burst,
        ) {
            return AuthFailure::RateLimited {
                retry_after_seconds,
            };
        }
        self.failures.record(ip, now_ms, &self.limits);
        failure
    }

    /// The credential check. The token is hashed and compared with `KEY_SLOTS` slots with no
    /// early exit, whether or not the agent exists. Only then are the rules applied.
    fn verify(
        &self,
        input: &TokenCheckInput<'_>,
        now: Timestamp,
        eq: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<AgentContext, AuthFailure> {
        let parsed = parse_token(input.raw_token).map_err(|_| AuthFailure::Malformed)?;
        let candidate = token_hash(&parsed.agent_id, &parsed.secret);
        let agents = self.agents.read().unwrap_or_else(PoisonError::into_inner);
        let agent = agents.get(&parsed.agent_id);
        let keys: &[KeyAuth] = agent.map_or(&[], |found| found.keys.as_slice());
        let mut hit: Option<&KeyAuth> = None;
        for slot in 0..KEY_SLOTS {
            let key = keys.get(slot);
            let stored = key.map_or(&DUMMY_HASH, |found| &found.hash);
            let matched = eq(&candidate, stored);
            hit = hit.or_else(|| key.filter(|_| matched));
        }
        let agent = agent.ok_or(AuthFailure::UnknownAgent)?;
        let key = hit.ok_or(AuthFailure::NoKeyMatch)?;
        if key.revoked {
            return Err(AuthFailure::KeyRevoked);
        }
        if key.expired(now) {
            return Err(AuthFailure::KeyExpired);
        }
        if agent.status != AgentStatus::Active {
            return Err(AuthFailure::AgentInactive);
        }
        let ip = input.source_ip.to_canonical();
        if !key.ip_allowlist.is_empty() && !key.ip_allowlist.iter().any(|net| net.contains(&ip)) {
            return Err(AuthFailure::IpNotAllowed);
        }
        if key.require_mtls {
            let presented = input.client_cert_sha256.is_some_and(|cert| {
                key.client_cert_sha256
                    .is_some_and(|bound| ct_eq(&cert, &bound))
            });
            if !presented {
                return Err(AuthFailure::MtlsMismatch);
            }
        }
        Ok(AgentContext {
            agent_id: parsed.agent_id,
            key_id: key.id,
            scopes: key.scopes.clone(),
            request_id: input.request_id,
            source_ip: input.source_ip,
            surface: input.surface,
        })
    }
}

/// Agent rows, key rows and the rows that failed their MAC.
type CheckedRows = (Vec<AgentRow>, Vec<AgentKeyRow>, Vec<IntegrityIssue>);

/// Checks the row MACs (ADR-0033). A bad agent row comes back as `Revoked`; a bad key row comes
/// back revoked (its `revoked_at` is set to its `created_at` if it had none). Good rows are unchanged.
///
/// # Errors
/// `CoreError::Store` if a MAC cannot be computed.
pub fn verify_rows(
    agents: &[AgentRow],
    keys: &[AgentKeyRow],
    macs: &RowMacs<'_>,
) -> Result<CheckedRows, CoreError> {
    let mut issues = Vec::new();
    let mut checked_agents = Vec::with_capacity(agents.len());
    for row in agents {
        let mut row = row.clone();
        if !macs.verify_agent(&row)? {
            row.status = AgentStatus::Revoked;
            issues.push(IntegrityIssue {
                table: "agents",
                row_id: row.id.to_string(),
            });
        }
        checked_agents.push(row);
    }
    let mut checked_keys = Vec::with_capacity(keys.len());
    for row in keys {
        let mut row = row.clone();
        if !macs.verify_agent_key(&row)? {
            row.revoked_at = Some(row.revoked_at.unwrap_or(row.created_at));
            issues.push(IntegrityIssue {
                table: "agent_keys",
                row_id: row.id.to_string(),
            });
        }
        checked_keys.push(row);
    }
    Ok((checked_agents, checked_keys, issues))
}

#[cfg(test)]
mod tests;
