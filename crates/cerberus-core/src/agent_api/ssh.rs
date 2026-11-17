//! The SSH signing path of the Agent API (T22). The ssh-agent bridge (`cerberus-ssh-agent`)
//! calls only this module; the private key never leaves core.
//!
//! - [`AgentApi::ssh_prepare`] runs the normal secret path with the permission `use_ssh`
//!   (scope `ssh:use`, policy, lease or approval, ADR-0017/0018/0019). It reads the key once to
//!   get the public key, writes `ssh.prepare` and gives an [`SshTicket`]. The ticket holds IDs
//!   and the public key only.
//! - [`AgentApi::ssh_sign`] signs one ssh-agent `SIGN_REQUEST` for a ticket. Every sign checks
//!   the vault state, the agent key, the grant, the lease and the item again, adds one use to
//!   the lease, and writes `ssh.sign` (strict) before the signature exists. The private key is
//!   opened for that one signature and dropped (zeroized) at once.
//! - [`AgentApi::ssh_ticket_open`] tells the bridge when to close the socket of a ticket.
//!
//! Only ed25519 keys sign (DEC-T22-2). Only two kinds of data are signed: an SSH user
//! authentication request for this key, and an `SSHSIG` blob (DEC-T22-4) for a namespace that
//! the item setting `sshsig_namespaces` allows (AUD-21, DEC-T27-A2-6).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use cerberus_crypto::SecretString;
use cerberus_store::{AgentStatus, LeaseRow, StoreError};
use cerberus_types::{
    AgentId, ErrorCode, GrantId, ItemId, ItemKind, LeaseId, Permission, RequestId, Scope,
};
use jiff::{SignedDuration, Timestamp};
use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature, SigningKey};

use super::{AgentApi, PendingResult, audit_purpose, check_purpose, problem};
use crate::audit::{AuditEvent, EventType};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::items::{
    ItemSummary, KDF_ROUNDS_PROBLEM, KEY_SSHSIG_NAMESPACES, Payload, SshMeta, allows_sshsig,
    kdf_cost_ok,
};
use crate::leases::{self, LeaseView};
use crate::policy::engine::{agent_grants, item_live};
use crate::policy::{
    Decision, EvalInput, NoCount, PolicyEngine, PolicyItem, SecretAccess, SecretAsk, evaluate,
};
use crate::vault::{CoreEvent, Unlocked};

/// Route names for audit events of the SSH path.
pub mod routes {
    /// Open a signing socket.
    pub const PREPARE: &str = "POST /v1/credentials/{id}/ssh-prepare";
    /// One `SIGN_REQUEST` on a signing socket.
    pub const SIGN: &str = "ssh-agent SIGN_REQUEST";
}

/// Shortest socket TTL an agent can ask for, in seconds.
pub const SSH_TTL_MIN_SECONDS: u32 = 60;
/// Longest socket TTL an agent can ask for, in seconds.
pub const SSH_TTL_MAX_SECONDS: u32 = 86_400;
/// Largest data a `SIGN_REQUEST` may carry, in bytes. The ssh-agent frame limit is the same.
pub const MAX_SIGN_DATA_BYTES: usize = 256 * 1024;
/// Signatures one ticket may make in one minute.
pub const SIGNS_PER_MINUTE: usize = 60;

/// SSH message number of a user authentication request (RFC 4252).
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// Magic text at the start of the data of an `SSHSIG` signature.
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
/// Longest user name kept in the `ssh.sign` audit details, in characters.
const AUDIT_USER_CHARS: usize = 64;

/// `POST /v1/credentials/{id}/ssh-prepare` body (MCP `ssh_prepare`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshPrepareInput {
    /// Why the agent needs the key, 1..500 characters (audit only).
    pub purpose: String,
    /// A lease to use.
    pub lease_id: Option<LeaseId>,
    /// Socket TTL, 60..86400 s. It can only shorten the lease; it is also the TTL asked for
    /// when an approval is needed.
    pub ttl_seconds: Option<u32>,
}

/// A prepared SSH key: what the agent may see, and the ticket for the bridge.
#[derive(Debug)]
pub struct SshGrant {
    /// The request ID of the call.
    pub request_id: RequestId,
    /// Item metadata.
    pub item: ItemSummary,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// Machine, host, port and user from the item metadata.
    pub ssh: SshMeta,
    /// End of the socket: the lease end, or earlier when the agent asked for a shorter TTL.
    pub expires_at: Timestamp,
    /// The lease that covers the socket.
    pub lease: LeaseView,
    /// The signing ticket. Give it to the bridge only; it is not shown to the agent.
    pub ticket: SshTicket,
}

/// The answer of [`AgentApi::ssh_prepare`].
#[derive(Debug)]
pub enum SshPrepareOutcome {
    /// The key is ready for a signing socket.
    Ready(Box<SshGrant>),
    /// An approval is needed.
    Pending(PendingResult),
}

/// The right of one signing socket to ask core for signatures. Only core makes it. It holds IDs
/// and the public key, never private key material. Cheap to clone; clones share the sign count.
#[derive(Clone)]
pub struct SshTicket {
    inner: Arc<Ticket>,
}

struct Ticket {
    agent: AgentContext,
    item_id: ItemId,
    lease_id: LeaseId,
    grant_id: GrantId,
    /// SSH wire form of the public key (the ssh-agent key blob).
    key_blob: Vec<u8>,
    public_key: String,
    fingerprint: String,
    expires_at: Timestamp,
    /// The purpose of the prepare call: grants with a reason rule see it at each sign.
    purpose: String,
    /// The unlock this ticket belongs to. A lock ends the ticket.
    unlocked_at: Timestamp,
    /// Signatures allowed in total, or `None` for no limit (DEC-T22-3).
    sign_budget: Option<u32>,
    signs: Mutex<SignCount>,
}

#[derive(Default)]
struct SignCount {
    total: u32,
    recent: VecDeque<Timestamp>,
}

impl std::fmt::Debug for SshTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTicket")
            .field("lease_id", &self.inner.lease_id)
            .field("item_id", &self.inner.item_id)
            .field("expires_at", &self.inner.expires_at)
            .finish_non_exhaustive()
    }
}

impl SshTicket {
    /// The lease of this ticket.
    #[must_use]
    pub fn lease_id(&self) -> LeaseId {
        self.inner.lease_id
    }

    /// The SSH key item.
    #[must_use]
    pub fn item_id(&self) -> ItemId {
        self.inner.item_id
    }

    /// The agent the ticket was made for.
    #[must_use]
    pub fn agent_id(&self) -> AgentId {
        self.inner.agent.agent_id
    }

    /// The public key in SSH wire form (the key blob of `IDENTITIES_ANSWER`).
    #[must_use]
    pub fn key_blob(&self) -> &[u8] {
        &self.inner.key_blob
    }

    /// The OpenSSH public key line.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.inner.public_key
    }

    /// The `SHA256:...` fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.inner.fingerprint
    }

    /// End of the ticket.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.inner.expires_at
    }

    /// Signatures left, or `None` for no limit.
    #[must_use]
    pub fn signs_left(&self) -> Option<u32> {
        let total = self.count().total;
        self.inner
            .sign_budget
            .map(|budget| budget.saturating_sub(total))
    }

    /// True when the budget is used up or the end time passed.
    fn spent(&self, now: Timestamp) -> bool {
        now >= self.inner.expires_at || self.signs_left() == Some(0)
    }

    fn count(&self) -> std::sync::MutexGuard<'_, SignCount> {
        self.inner
            .signs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the per-minute window of `previous` (the ticket this one replaces on the same
    /// lease) count for this ticket too, so a second prepare does not reset the rate limit
    /// (DEC-FIX8-7). The total budget is not carried: the new prepare spent a new lease use.
    pub fn carry_rate_window(&self, previous: &Self) {
        if Arc::ptr_eq(&self.inner, &previous.inner) {
            return;
        }
        let recent = previous.count().recent.clone();
        self.count().recent = recent;
    }

    /// Takes one signature from the budget and the per-minute window. A refused sign takes
    /// nothing; a taken sign stays taken when a later step fails (fail closed).
    fn take_sign(&self, now: Timestamp) -> Result<(), CoreError> {
        let mut count = self.count();
        let window_start = now - SignedDuration::from_secs(60);
        while count.recent.front().is_some_and(|at| *at <= window_start) {
            count.recent.pop_front();
        }
        if self
            .inner
            .sign_budget
            .is_some_and(|budget| count.total >= budget)
        {
            return Err(CoreError::Forbidden);
        }
        if count.recent.len() >= SIGNS_PER_MINUTE {
            let oldest = count.recent.front().copied().unwrap_or(now);
            let wait = (oldest + SignedDuration::from_secs(60))
                .duration_since(now)
                .as_secs()
                .max(1);
            return Err(CoreError::RateLimited {
                retry_after_seconds: u32::try_from(wait).unwrap_or(60),
            });
        }
        count.total = count.total.saturating_add(1);
        count.recent.push_back(now);
        Ok(())
    }
}

/// What a `SIGN_REQUEST` asks to sign (DEC-T22-4).
#[derive(Debug, PartialEq, Eq)]
enum SignData {
    /// An SSH user authentication request for the ticket key.
    UserAuth {
        /// The user name in the request (cut for the audit body).
        user: String,
    },
    /// An `SSHSIG` blob (`ssh-keygen -Y sign`, git commit signing).
    SshSig {
        /// The namespace in the blob, for example `git`.
        namespace: String,
    },
}

/// A reader of SSH wire data (RFC 4251): `byte`, `boolean` and `string`.
struct Wire<'a>(&'a [u8]);

impl<'a> Wire<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let (len, rest) = self.0.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if rest.len() < len {
            return None;
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Some(value)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Reads the kind of the data to sign. `None` means the data is neither a user authentication
/// request for `key_blob` nor an `SSHSIG` blob, so it is not signed.
fn sign_data_kind(data: &[u8], key_blob: &[u8]) -> Option<SignData> {
    if let Some(rest) = data.strip_prefix(SSHSIG_MAGIC) {
        return sshsig_namespace(rest).map(|namespace| SignData::SshSig { namespace });
    }
    let mut wire = Wire(data);
    let session_id = wire.string()?;
    if session_id.is_empty() || session_id.len() > 64 {
        return None;
    }
    if wire.byte()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = wire.string()?;
    if wire.string()? != b"ssh-connection" {
        return None;
    }
    let method = wire.string()?;
    let hostbound = match method {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return None,
    };
    if wire.byte()? != 1 {
        return None;
    }
    let _algorithm = wire.string()?;
    if wire.string()? != key_blob {
        return None;
    }
    if hostbound {
        let _host_key = wire.string()?;
    }
    if !wire.is_empty() {
        return None;
    }
    let user = String::from_utf8_lossy(user)
        .chars()
        .filter(|c| !cerberus_types::text::is_hidden_char(*c))
        .take(AUDIT_USER_CHARS)
        .collect();
    Some(SignData::UserAuth { user })
}

/// Reads the signed data of an `SSHSIG` blob after the magic text (PROTOCOL.sshsig): `string
/// namespace`, `string reserved` (empty), `string hash_algorithm` (`sha256` or `sha512`) and
/// `string H(message)` of that length, and nothing else. Gives the namespace.
fn sshsig_namespace(rest: &[u8]) -> Option<String> {
    let mut wire = Wire(rest);
    let namespace = wire.string()?;
    let reserved = wire.string()?;
    let hash_alg = wire.string()?;
    let hash = wire.string()?;
    let hash_ok = matches!((hash_alg, hash.len()), (b"sha256", 32) | (b"sha512", 64));
    if namespace.is_empty() || !reserved.is_empty() || !hash_ok || !wire.is_empty() {
        return None;
    }
    std::str::from_utf8(namespace).ok().map(str::to_owned)
}

/// The namespace of an `SSHSIG` blob as the `ssh.sign` event keeps it: cleaned and cut.
fn audit_namespace(data: &[u8]) -> Option<String> {
    if data.len() > MAX_SIGN_DATA_BYTES {
        return None;
    }
    let namespace = sshsig_namespace(data.strip_prefix(SSHSIG_MAGIC)?)?;
    Some(
        namespace
            .chars()
            .filter(|c| !cerberus_types::text::is_hidden_char(*c))
            .take(AUDIT_USER_CHARS)
            .collect(),
    )
}

/// Reads the key text. An encrypted key stays encrypted: its public part is readable, so this is
/// cheap and may run on the vault guard.
fn parse_key(private_key: &SecretString) -> Result<PrivateKey, CoreError> {
    PrivateKey::from_openssh(private_key.expose_secret().trim()).map_err(|_| CoreError::Corrupt)
}

/// The cheap checks of a parsed key, before any decrypt: ed25519, a passphrase when it is
/// encrypted, and a KDF cost in the limit (AUD-3). Safe on the vault guard.
fn check_key(key: &PrivateKey, passphrase: Option<&SecretString>) -> Result<(), CoreError> {
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(problem(
            "payload.private_key",
            "only ed25519 keys can sign through the ssh-agent bridge",
        ));
    }
    if key.is_encrypted() && passphrase.is_none() {
        return Err(problem(
            "payload.passphrase",
            "is needed to open the encrypted SSH key",
        ));
    }
    if !kdf_cost_ok(key) {
        return Err(problem("payload.private_key", KDF_ROUNDS_PROBLEM));
    }
    Ok(())
}

/// Opens an encrypted key (bcrypt-pbkdf: slow, never run it on the vault guard) and checks that
/// it is ed25519.
fn open_key(key: PrivateKey, passphrase: Option<&SecretString>) -> Result<PrivateKey, CoreError> {
    let key = if key.is_encrypted() {
        let phrase = passphrase.ok_or_else(|| {
            problem(
                "payload.passphrase",
                "is needed to open the encrypted SSH key",
            )
        })?;
        key.decrypt(phrase.expose_secret().as_bytes())
            .map_err(|_| problem("payload.passphrase", "does not open the SSH key"))?
    } else {
        key
    };
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(problem(
            "payload.private_key",
            "only ed25519 keys can sign through the ssh-agent bridge",
        ));
    }
    Ok(key)
}

/// Signs `data` and returns the SSH signature blob (`string algorithm`, `string signature`).
fn sign_blob<K: SigningKey>(key: &K, data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let signature: Signature = key.try_sign(data).map_err(|_| CoreError::Corrupt)?;
    Vec::<u8>::try_from(signature).map_err(|_| CoreError::Corrupt)
}

/// What `ssh_sign` and `ssh_prepare` need to open the key after the vault guard is dropped
/// (DEC-FIX8-5, DEC-T27-A2-3). The key may still be encrypted. Both parts zeroize on drop.
struct SignJob {
    key: PrivateKey,
    passphrase: Option<SecretString>,
}

impl SignJob {
    /// Opens the key. Slow for an encrypted key: run it on a blocking thread.
    fn open(self) -> Result<PrivateKey, CoreError> {
        open_key(self.key, self.passphrase.as_ref())
    }

    /// Opens the key and signs. Slow for an encrypted key: run it on a blocking thread.
    fn run(self, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        sign_blob(&self.open()?, data)
    }
}

/// Runs `job` on a blocking thread, with no guard held.
async fn open_off_guard(job: SignJob) -> Result<(), CoreError> {
    tokio::task::spawn_blocking(move || job.open().map(drop))
        .await
        .map_err(|_| CoreError::Corrupt)
        .and_then(|result| result)
}

/// The public facts of an SSH payload: the key blob, the OpenSSH line and the fingerprint.
struct PublicFacts {
    key_blob: Vec<u8>,
    public_key: String,
    fingerprint: String,
}

fn public_facts(key: &PrivateKey) -> Result<PublicFacts, CoreError> {
    let public: &PublicKey = key.public_key();
    Ok(PublicFacts {
        key_blob: public.to_bytes().map_err(|_| CoreError::Corrupt)?,
        public_key: public.to_openssh().map_err(|_| CoreError::Corrupt)?,
        fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    })
}

/// The SSH key parts of a payload, or `Validation` for another kind.
fn ssh_parts(payload: &Payload) -> Result<(&SecretString, Option<&SecretString>), CoreError> {
    match payload {
        Payload::SshKey {
            private_key,
            passphrase,
            ..
        } => Ok((private_key, passphrase.as_ref())),
        _ => Err(problem("item_id", "is not an ssh_key item")),
    }
}

impl AgentApi {
    /// `POST /v1/credentials/{id}/ssh-prepare`, MCP `ssh_prepare`. Scope `ssh:use`, policy
    /// `use_ssh`. The call spends one lease use like a reveal (or opens an access request); it
    /// does not count as a reveal for the item `max_uses` (DEC-T22-3). Writes `ssh.prepare`
    /// (strict: no ticket without its event).
    ///
    /// # Errors
    /// `Validation` (purpose, TTL, not an SSH key, not ed25519, a passphrase that does not open
    /// the key), `NotFound`, `Forbidden`, `ReasonRequired`, `ConditionFailed`,
    /// `GrantRateLimited`, `RateLimited`, `ApprovalUnavailable`, `Locked`, `InsufficientScope`,
    /// or a storage error.
    pub async fn ssh_prepare(
        &self,
        ctx: &AgentContext,
        id: ItemId,
        input: SshPrepareInput,
    ) -> Result<SshPrepareOutcome, CoreError> {
        self.ready(ctx, Scope::SshUse, routes::PREPARE).await?;
        check_purpose(&input.purpose)?;
        if input
            .ttl_seconds
            .is_some_and(|ttl| !(SSH_TTL_MIN_SECONDS..=SSH_TTL_MAX_SECONDS).contains(&ttl))
        {
            return Err(problem("ttl_seconds", "must be 60..86400"));
        }
        // A visible item of another kind is a clear validation error. An item the agent cannot
        // see goes on to the policy check, which gives the same `NotFound` (and audit) as for a
        // missing item, so the kind of a hidden item never leaks.
        let wrong_kind = {
            let guard = self.service.unlocked().await?;
            let now = self.service.clock().now();
            let visible = PolicyEngine::find_filter(&guard.index, ctx.agent_id, now);
            guard
                .index
                .item(&id)
                .is_some_and(|meta| visible(meta) && meta.kind != ItemKind::SshKey)
        };
        if wrong_kind {
            return Err(problem("item_id", "is not an ssh_key item"));
        }
        let ask = SecretAsk {
            item_id: id,
            permission: Permission::UseSsh,
            reason: Some(&input.purpose),
            lease_id: input.lease_id,
            requested_ttl_seconds: input.ttl_seconds,
        };
        // Check, key read and the strict `ssh.prepare` event on one write guard, as in
        // `read_secret` (DEC-FIX7-2). The bcrypt decrypt of an encrypted key runs after the guard
        // is dropped, so a lock or the panic button never waits for it (AUD-3, DEC-T27-A2-3).
        let mut guard = self.service.unlocked_mut().await?;
        let (lease, grant_id) = match self.engine().authorize_secret_in(&guard, ctx, ask).await? {
            SecretAccess::Pending(view) => {
                return Ok(SshPrepareOutcome::Pending(PendingResult {
                    request_id: ctx.request_id,
                    access_request: view,
                }));
            }
            SecretAccess::Granted { lease, grant_id } => (lease, grant_id),
        };
        let event = Self::event(ctx, EventType::SshPrepare, routes::PREPARE)
            .target("item", id.to_string())
            .detail("lease_id", lease.id.to_string())
            .detail("grant_id", grant_id.to_string())
            .detail("purpose", audit_purpose(&input.purpose));
        let opened = async {
            let revealed = self.service.read_payload_in(&mut guard, id, false).await?;
            let (private_key, passphrase) = ssh_parts(&revealed.payload)?;
            let key = parse_key(private_key)?;
            check_key(&key, passphrase)?;
            let facts = public_facts(&key)?;
            let job = key.is_encrypted().then(|| SignJob {
                key,
                passphrase: passphrase.cloned(),
            });
            Ok::<_, CoreError>((
                revealed.summary,
                revealed.ssh.unwrap_or_default(),
                facts,
                job,
            ))
        }
        .await;
        let (summary, ssh, facts, job) = match opened {
            Ok(parts) => parts,
            Err(error) => {
                self.service
                    .audit(&guard, event.result(error.code().as_str()))
                    .await;
                return Err(error);
            }
        };
        let now = self.service.clock().now();
        let expires_at = input
            .ttl_seconds
            .map(|ttl| now + SignedDuration::from_secs(i64::from(ttl)))
            .map_or(lease.expires_at, |end| end.min(lease.expires_at));
        // A lease with a use limit served this prepare with its last use; the socket then makes
        // one signature (one SSH login) and closes (DEC-T22-3).
        let sign_budget = lease.uses_left.map(|_| 1);
        let mut event = event
            .detail("fingerprint", facts.fingerprint.clone())
            .detail("expires_at_ms", expires_at.as_millisecond());
        if let Some(budget) = sign_budget {
            event = event.detail("sign_budget", budget);
        }
        self.service.audit_strict(&guard, event.clone()).await?;
        let unlocked_at = guard.session.unlocked_at;
        drop(guard);
        if let Some(job) = job {
            // The passphrase must open the key, so a bad item fails here and not at the first
            // signature. No guard is held while bcrypt runs.
            if let Err(error) = open_off_guard(job).await {
                if let Ok(guard) = self.service.unlocked().await {
                    let event = event
                        .result(error.code().as_str())
                        .detail("decision", "key_open");
                    self.service.audit(&guard, event).await;
                }
                return Err(error);
            }
            // Take the guard again: a lock (or a lock and a new unlock) during the decrypt ends
            // the prepare, so no ticket of an ended session is given out. Every sign checks the
            // grant, the lease and the key again.
            let guard = self.service.unlocked().await?;
            if guard.session.unlocked_at != unlocked_at {
                return Err(CoreError::Locked);
            }
        }
        let ticket = SshTicket {
            inner: Arc::new(Ticket {
                agent: ctx.clone(),
                item_id: id,
                lease_id: lease.id,
                grant_id,
                key_blob: facts.key_blob,
                public_key: facts.public_key.clone(),
                fingerprint: facts.fingerprint.clone(),
                expires_at,
                purpose: input.purpose,
                unlocked_at,
                sign_budget,
                signs: Mutex::new(SignCount::default()),
            }),
        };
        Ok(SshPrepareOutcome::Ready(Box::new(SshGrant {
            request_id: ctx.request_id,
            item: summary,
            public_key: facts.public_key,
            fingerprint: facts.fingerprint,
            ssh,
            expires_at,
            lease,
            ticket,
        })))
    }

    /// True while the socket of `ticket` may stay open: the vault is unlocked in the same session,
    /// the ticket end has not passed, its budget is not used up, the agent key is still usable,
    /// and its lease row (MAC checked) is not released, revoked or past its end. Policy is
    /// checked again at each sign.
    pub async fn ssh_ticket_open(&self, ticket: &SshTicket) -> bool {
        let Ok(guard) = self.service.unlocked().await else {
            return false;
        };
        let now = self.service.clock().now();
        if guard.session.unlocked_at != ticket.inner.unlocked_at || ticket.spent(now) {
            return false;
        }
        if self
            .agent_key_usable(&guard, &ticket.inner.agent, now)
            .await
            .is_err()
        {
            return false;
        }
        match self.service.store().lease(ticket.lease_id()).await {
            Ok(row) => {
                guard.row_macs().verify_lease(&row).unwrap_or(false)
                    && lease_open(&row, ticket, now)
            }
            Err(_) => false,
        }
    }

    /// Signs one ssh-agent `SIGN_REQUEST` for `ticket`. `flags` are the request flags; ed25519
    /// has no flags, so they are only audited. The answer is the SSH signature blob.
    ///
    /// Steps on one vault write guard (the key is opened and the signature made after the guard
    /// is dropped, on a blocking thread, DEC-FIX8-5): the session of the ticket, the agent and its key
    /// (active, not revoked or expired, scope `ssh:use`), policy `use_ssh` (any allow mode; the
    /// lease must still fit it), the lease row (one more use), the item key (same public key),
    /// the data kind, then `ssh.sign` (strict) and the signature.
    ///
    /// # Errors
    /// `Locked`, `Forbidden` (ticket ended, budget used, agent key, policy, lease or key
    /// changed), `NotFound` (item gone), `RateLimited`, `Validation` (data too long or not a
    /// kind that is signed), or a storage error.
    pub async fn ssh_sign(
        &self,
        ticket: &SshTicket,
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>, CoreError> {
        let inner = &ticket.inner;
        let ctx = AgentContext {
            request_id: RequestId::generate(),
            ..inner.agent.clone()
        };
        if self.service.state() != cerberus_types::VaultStateKind::Unlocked {
            self.service
                .audit_locked_call(Some(&ctx), routes::SIGN, ErrorCode::VaultLocked)
                .await;
            return Err(CoreError::Locked);
        }
        let base = Self::event(&ctx, EventType::SshSign, routes::SIGN)
            .target("item", inner.item_id.to_string())
            .detail("lease_id", inner.lease_id.to_string())
            .detail("fingerprint", inner.fingerprint.clone())
            .detail("data_bytes", data.len())
            .detail("flags", flags);
        let base = match audit_namespace(data) {
            Some(namespace) => base.detail("namespace", namespace),
            None => base,
        };
        let mut guard = self.service.unlocked_mut().await?;
        match self
            .sign_in(&mut guard, ticket, &ctx, data, base.clone())
            .await
        {
            Ok(job) => {
                // The checks and the `ssh.sign` event are done. Drop the guard before the slow
                // key opening (DEC-FIX8-5): one agent must not stall every other call.
                drop(guard);
                let data = data.to_vec();
                let signed = tokio::task::spawn_blocking(move || job.run(&data))
                    .await
                    .map_err(|_| CoreError::Corrupt)
                    .and_then(|result| result);
                match signed {
                    Ok(signature) => {
                        self.service.emit(CoreEvent::LeaseChanged(inner.lease_id));
                        Ok(signature)
                    }
                    Err(error) => {
                        if let Ok(guard) = self.service.unlocked().await {
                            let event = base
                                .result(error.code().as_str())
                                .detail("decision", "sign");
                            self.service.audit(&guard, event).await;
                        }
                        Err(error)
                    }
                }
            }
            Err((error, decision)) => {
                let event = base
                    .result(error.code().as_str())
                    .detail("decision", decision);
                self.service.audit(&guard, event).await;
                Err(error)
            }
        }
    }

    /// The body of [`Self::ssh_sign`] on the write guard. A refusal gives the error and the
    /// `decision` text for its audit event.
    async fn sign_in(
        &self,
        guard: &mut Unlocked,
        ticket: &SshTicket,
        ctx: &AgentContext,
        data: &[u8],
        event: AuditEvent,
    ) -> Result<SignJob, (CoreError, &'static str)> {
        let inner = &ticket.inner;
        let now = self.service.clock().now();
        if guard.session.unlocked_at != inner.unlocked_at {
            return Err((CoreError::Forbidden, "session_ended"));
        }
        if now >= inner.expires_at {
            return Err((CoreError::Forbidden, "ticket_expired"));
        }
        if data.len() > MAX_SIGN_DATA_BYTES {
            return Err((problem("data", "is too long"), "data_too_long"));
        }
        let Some(kind) = sign_data_kind(data, &inner.key_blob) else {
            return Err((
                problem("data", "is not an SSH user authentication or SSHSIG blob"),
                "data_kind",
            ));
        };
        if let SignData::SshSig { namespace } = &kind {
            // Checked before a sign is taken from the budget, so a refused namespace costs the
            // ticket nothing. A missing item is refused by the policy step below.
            if let Some(meta) = guard.index.item(&inner.item_id) {
                let setting = meta.custom.get(KEY_SSHSIG_NAMESPACES).map(|t| t.as_str());
                if !allows_sshsig(setting, namespace) {
                    return Err((CoreError::Forbidden, "sshsig_namespace"));
                }
            }
        }
        ticket.take_sign(now).map_err(|error| {
            let decision = if matches!(error, CoreError::RateLimited { .. }) {
                "sign_rate_limit"
            } else {
                "sign_budget_used"
            };
            (error, decision)
        })?;
        self.agent_key_usable(guard, ctx, now)
            .await
            .map_err(|error| (error, "agent_key_inactive"))?;
        let mode = {
            let grants = agent_grants(&guard.index, &ctx.agent_id);
            let Some(meta) = guard
                .index
                .item(&inner.item_id)
                .filter(|m| item_live(m, now))
            else {
                return Err((CoreError::NotFound, "not_found"));
            };
            let input = |permission| EvalInput {
                grants: &grants,
                item: PolicyItem::of(meta),
                permission,
                reason: Some(inner.purpose.as_str()),
                now,
            };
            if !evaluate(&input(Permission::Find), &ctx.agent_id, &NoCount).is_allow() {
                return Err((CoreError::NotFound, "not_visible"));
            }
            match evaluate(&input(Permission::UseSsh), &ctx.agent_id, &NoCount) {
                Decision::Allow { mode, .. } => mode,
                other => {
                    return Err((
                        crate::policy::engine::decision_error(&other),
                        other.as_str(),
                    ));
                }
            }
        };
        let uses = self
            .use_ssh_lease(guard, ticket, mode, now)
            .await
            .map_err(|error| (error, "lease_ended"))?;
        let revealed = self
            .service
            .read_payload_in(guard, inner.item_id, false)
            .await
            .map_err(|error| (error, "key_read"))?;
        let (private_key, passphrase) =
            ssh_parts(&revealed.payload).map_err(|e| (e, "key_kind"))?;
        let key = parse_key(private_key).map_err(|e| (e, "key_open"))?;
        check_key(&key, passphrase).map_err(|e| (e, "key_open"))?;
        let facts = public_facts(&key).map_err(|e| (e, "key_open"))?;
        if facts.key_blob != inner.key_blob {
            return Err((CoreError::Forbidden, "key_changed"));
        }
        let mut event = event
            .detail("grant_id", inner.grant_id.to_string())
            .detail("uses", uses);
        event = match kind {
            SignData::UserAuth { user } => {
                event.detail("data_kind", "userauth").detail("user", user)
            }
            SignData::SshSig { .. } => event.detail("data_kind", "sshsig"),
        };
        // The signature exists only after its event is in the chain (ADR-0025).
        self.service
            .audit_strict(guard, event)
            .await
            .map_err(|error| (error, "audit"))?;
        let job = SignJob {
            key,
            passphrase: passphrase.cloned(),
        };
        drop(revealed);
        Ok(job)
    }

    /// The agent and the key of the ticket are still usable: agent active, key not revoked or
    /// expired, scope `ssh:use`. Rows are MAC checked; a bad row counts as revoked.
    async fn agent_key_usable(
        &self,
        guard: &Unlocked,
        ctx: &AgentContext,
        now: Timestamp,
    ) -> Result<(), CoreError> {
        let (agents, keys) = self.service.store().load_auth_rows().await?;
        let (agents, keys, _) = crate::auth::verify_rows(&agents, &keys, &guard.row_macs())?;
        let agent_ok = agents
            .iter()
            .any(|row| row.id == ctx.agent_id && row.status == AgentStatus::Active);
        let key_ok = keys.iter().any(|row| {
            row.id == ctx.key_id
                && row.agent_id == ctx.agent_id
                && row.revoked_at.is_none()
                && row.expires_at.is_none_or(|end| now < end)
                && row.scopes.contains(&Scope::SshUse)
        });
        if agent_ok && key_ok {
            Ok(())
        } else {
            Err(CoreError::Forbidden)
        }
    }

    /// Adds one use to the ticket lease, read again inside one transaction under the lease gate
    /// (DEC-T07-7). Returns the new use count.
    async fn use_ssh_lease(
        &self,
        guard: &Unlocked,
        ticket: &SshTicket,
        mode: cerberus_types::GrantMode,
        now: Timestamp,
    ) -> Result<u32, CoreError> {
        let macs = guard.row_macs();
        let _gate = self.service.policy_state().lease_gate.lock().await;
        let mut tx = self.service.store().begin().await?;
        let mut row = match tx.lease(ticket.lease_id()).await {
            Ok(row) => row,
            Err(StoreError::NotFound) => return Err(CoreError::Forbidden),
            Err(error) => return Err(error.into()),
        };
        if !macs.verify_lease(&row)? {
            drop(tx);
            self.service
                .integrity_issue(guard, "leases", row.id.to_string())
                .await;
            return Err(CoreError::Forbidden);
        }
        if !lease_open(&row, ticket, now) || !lease_fits(&row, mode, now) {
            return Err(CoreError::Forbidden);
        }
        row.uses = row.uses.saturating_add(1);
        macs.sign_lease(&mut row)?;
        tx.put_lease(&row).await?;
        tx.commit().await?;
        Ok(row.uses)
    }
}

/// The lease row belongs to the ticket and is open: not released, not revoked, before its end.
/// The use limit is not checked here: the ticket budget covers it (DEC-T22-3).
fn lease_open(row: &LeaseRow, ticket: &SshTicket, now: Timestamp) -> bool {
    row.id == ticket.lease_id()
        && row.agent_id == ticket.agent_id()
        && row.item_id == ticket.item_id()
        && row.permission == Permission::UseSsh
        && row.released_at.is_none()
        && row.revoked_at.is_none()
        && now < row.expires_at
}

/// The lease still fits the effective mode of the grant (ADR-0019 point 5, DEC-FIX7-1): a grant
/// tightened from `auto` to an ask mode stops an auto lease at once. The use count is left out.
fn lease_fits(row: &LeaseRow, mode: cerberus_types::GrantMode, now: Timestamp) -> bool {
    let probe = LeaseRow {
        uses: 0,
        ..row.clone()
    };
    leases::serves(&probe, mode, Permission::UseSsh, now)
}

#[cfg(test)]
mod tests;
