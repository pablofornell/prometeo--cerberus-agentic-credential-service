//! Agent and agent key management (ADR-0016): create, list, rename, suspend, delete, issue,
//! rotate and revoke keys.
//!
//! Every call that changes data writes the DB in one transaction, signs the rows (ADR-0033), and
//! then updates the [`AuthTable`] before it returns, so a revoke or a suspend is effective at once.
//! These calls need the unlocked keys (encrypted agent metadata and row MACs), so the vault
//! service builds an `AgentService` from them for each call. The IPC layer calls the
//! [`VaultService`] methods here: they check the context against the session and use the session
//! role. Changes are serialized by the write lock of the [`AuthTable`], and every row update is a
//! compare and set, so a stale row never undoes a revoke or a suspend (DEC-FIX5-2).

use std::time::Duration;

use cerberus_crypto::{SecretString, TokenSecret, token_hash};
use cerberus_store::{AgentKeyRow, AgentRow, AgentStatus, Blobs, RowMacs, Store};
use cerberus_types::ids::{AgentId, AgentKeyId};
use cerberus_types::{Clock, FieldProblem, OperatorRole, Scope};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::audit::{Actor, AuditEvent, EventType};
use crate::auth::{AuthTable, MAX_LIVE_KEYS, verify_rows};
use crate::vault::{Unlocked, VaultService};
use crate::{CoreError, OperatorContext};

/// Longest agent name, in characters.
pub const MAX_NAME_CHARS: usize = 80;
/// Longest agent description, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 500;
/// Most entries in one IP allowlist.
pub const MAX_ALLOWLIST_ENTRIES: usize = 32;
/// Longest key lifetime in days.
pub const MAX_LIFETIME_DAYS: u32 = 365;
/// Longest rotation overlap (7 days).
pub const MAX_OVERLAP: Duration = Duration::from_secs(7 * 86_400);

/// The scopes a new key gets when the input has none (ADR-0016).
pub const DEFAULT_SCOPES: [Scope; 4] = [
    Scope::StatusRead,
    Scope::CatalogRead,
    Scope::SecretsRead,
    Scope::Requests,
];

/// Name and description of an agent. Stored encrypted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInput {
    /// A short name, 1 to 80 characters.
    pub name: String,
    /// Free text, up to 500 characters.
    pub description: String,
}

/// An agent as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentView {
    /// The agent ID.
    pub id: AgentId,
    /// The name.
    pub name: String,
    /// The description.
    pub description: String,
    /// Active, suspended or revoked (deleted).
    pub status: AgentStatus,
    /// All keys, newest first.
    pub keys: Vec<AgentKeyView>,
    /// The latest `last_used_at` of its keys.
    pub last_seen_at: Option<Timestamp>,
}

/// A key as the UI shows it. Never holds the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentKeyView {
    /// The key ID.
    pub id: AgentKeyId,
    /// The last 4 characters of the secret.
    pub hint: String,
    /// The scopes.
    pub scopes: Vec<Scope>,
    /// The IP allowlist. Empty means any address.
    pub ip_allowlist: Vec<ipnet::IpNet>,
    /// The expiry, or `None` for no expiry.
    pub expires_at: Option<Timestamp>,
    /// When the key was revoked.
    pub revoked_at: Option<Timestamp>,
    /// When the key last passed a check.
    pub last_used_at: Option<Timestamp>,
    /// True if the key needs a client certificate.
    pub require_mtls: bool,
}

/// What the operator chooses for a new key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentKeyInput {
    /// The scopes. Empty means [`DEFAULT_SCOPES`].
    pub scopes: Vec<Scope>,
    /// Lifetime in days (1 to 365). `None` is no expiry and needs the owner role.
    pub lifetime_days: Option<u32>,
    /// The IP allowlist. Empty means any address.
    pub ip_allowlist: Vec<ipnet::IpNet>,
    /// Must be false. The schema allows `require_mtls` only with a certificate fingerprint, so a
    /// key becomes mTLS-bound through [`VaultService::bind_client_cert`] (DEC-T09-5).
    pub require_mtls: bool,
}

/// A new key and its token. The token text exists only here: show it one time.
#[derive(Debug)]
pub struct NewAgentKey {
    /// The key as stored.
    pub key: AgentKeyView,
    /// `cvt_<agent_id>.<secret>`.
    pub token: SecretString,
}

#[derive(Serialize, Deserialize)]
struct AgentMeta {
    name: String,
    description: String,
}

/// Agent and key operations on one open vault. Built by [`VaultService`] for each call, after the
/// role check of the session (DEC-T05-5). `role` is the session role, never a caller's claim.
pub(crate) struct AgentService<'a> {
    store: &'a Store,
    auth: &'a AuthTable,
    blobs: Blobs<'a>,
    macs: RowMacs<'a>,
    clock: &'a dyn Clock,
    role: OperatorRole,
}

fn problem(field: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }])
}

fn validate_input(input: &AgentInput) -> Result<AgentInput, CoreError> {
    // Agent names show inline next to agent text, so hidden format characters (bidi controls,
    // zero-width) are removed first (AUD-24).
    let name = cerberus_types::text::strip_format(&input.name);
    let name = name.trim();
    let name_chars = name.chars().count();
    if name_chars == 0 || name_chars > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(problem("name", "1 to 80 characters, no control characters"));
    }
    let description = cerberus_types::text::strip_format(&input.description);
    let description = description.trim();
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(problem("description", "at most 500 characters"));
    }
    Ok(AgentInput {
        name: name.to_owned(),
        description: description.to_owned(),
    })
}

fn key_view(row: &AgentKeyRow) -> AgentKeyView {
    AgentKeyView {
        id: row.id,
        hint: row.hint.clone(),
        scopes: row.scopes.clone(),
        ip_allowlist: row.ip_allowlist.clone(),
        expires_at: row.expires_at,
        revoked_at: row.revoked_at,
        last_used_at: row.last_used_at,
        require_mtls: row.require_mtls,
    }
}

fn is_live(row: &AgentKeyRow, now: Timestamp) -> bool {
    row.revoked_at.is_none() && row.expires_at.is_none_or(|at| at > now)
}

impl<'a> AgentService<'a> {
    /// Uses the unlocked keys of one vault. `auth` is the table the token checks read. `role` is
    /// the role of the unlocked session.
    pub(crate) const fn new(
        store: &'a Store,
        auth: &'a AuthTable,
        blobs: Blobs<'a>,
        macs: RowMacs<'a>,
        clock: &'a dyn Clock,
        role: OperatorRole,
    ) -> Self {
        Self {
            store,
            auth,
            blobs,
            macs,
            clock,
            role,
        }
    }

    fn require_operator(&self) -> Result<(), CoreError> {
        match self.role {
            OperatorRole::Owner | OperatorRole::Operator => Ok(()),
            OperatorRole::Viewer => Err(CoreError::RoleNotAllowed),
        }
    }

    fn open_meta(&self, row: &AgentRow) -> Result<AgentMeta, CoreError> {
        let plain = self.blobs.open_agent_meta(&row.id, &row.meta_ct)?;
        serde_json::from_slice(plain.expose_secret()).map_err(|_| CoreError::Corrupt)
    }

    fn seal_meta(&self, id: &AgentId, input: &AgentInput) -> Result<Vec<u8>, CoreError> {
        let meta = AgentMeta {
            name: input.name.clone(),
            description: input.description.clone(),
        };
        let json = serde_json::to_vec(&meta).map_err(|_| CoreError::Corrupt)?;
        Ok(self.blobs.seal_agent_meta(id, &json)?)
    }

    fn view(&self, agent: &AgentRow, keys: &[AgentKeyRow]) -> Result<AgentView, CoreError> {
        let meta = self.open_meta(agent)?;
        let mut keys: Vec<&AgentKeyRow> = keys.iter().filter(|k| k.agent_id == agent.id).collect();
        keys.sort_by_key(|key| std::cmp::Reverse(key.created_at));
        Ok(AgentView {
            id: agent.id,
            name: meta.name,
            description: meta.description,
            status: agent.status,
            last_seen_at: keys.iter().filter_map(|key| key.last_used_at).max(),
            keys: keys.into_iter().map(key_view).collect(),
        })
    }

    /// The rows of one agent. A row with a bad MAC is `Corrupt`: it is not changed or re-signed.
    /// Callers that change rows hold the write lock of the table, so the rows stay current.
    async fn agent_rows(&self, id: AgentId) -> Result<(AgentRow, Vec<AgentKeyRow>), CoreError> {
        let (agents, keys) = self.store.load_auth_rows().await?;
        let agent = agents
            .into_iter()
            .find(|row| row.id == id)
            .ok_or(CoreError::NotFound)?;
        let keys: Vec<AgentKeyRow> = keys.into_iter().filter(|k| k.agent_id == id).collect();
        let (_, _, issues) = verify_rows(std::slice::from_ref(&agent), &keys, &self.macs)?;
        if !issues.is_empty() {
            return Err(CoreError::Corrupt);
        }
        Ok((agent, keys))
    }

    /// The rows of the agent that owns `key`, and that key.
    async fn key_rows(
        &self,
        key: AgentKeyId,
    ) -> Result<(AgentRow, Vec<AgentKeyRow>, AgentKeyRow), CoreError> {
        let (_, keys) = self.store.load_auth_rows().await?;
        let agent_id = keys
            .iter()
            .find(|row| row.id == key)
            .map(|row| row.agent_id)
            .ok_or(CoreError::NotFound)?;
        let (agent, keys) = self.agent_rows(agent_id).await?;
        let row = keys
            .iter()
            .find(|row| row.id == key)
            .cloned()
            .ok_or(CoreError::NotFound)?;
        Ok((agent, keys, row))
    }

    /// Checks the input and builds a signed key row and its token.
    fn new_key(
        &self,
        agent: AgentId,
        input: &AgentKeyInput,
        now: Timestamp,
    ) -> Result<(AgentKeyRow, SecretString), CoreError> {
        let expires_at = match input.lifetime_days {
            None if self.role == OperatorRole::Owner => None,
            None => return Err(CoreError::RoleNotAllowed),
            Some(days @ 1..=MAX_LIFETIME_DAYS) => Some(
                now.checked_add(SignedDuration::from_secs(i64::from(days) * 86_400))
                    .map_err(|_| problem("lifetime_days", "out of range"))?,
            ),
            Some(_) => return Err(problem("lifetime_days", "1 to 365, or none")),
        };
        self.key_row(agent, input, now, expires_at, None)
    }

    fn key_row(
        &self,
        agent: AgentId,
        input: &AgentKeyInput,
        now: Timestamp,
        expires_at: Option<Timestamp>,
        client_cert_sha256: Option<[u8; 32]>,
    ) -> Result<(AgentKeyRow, SecretString), CoreError> {
        if input.require_mtls && client_cert_sha256.is_none() {
            return Err(problem(
                "require_mtls",
                "set it by binding a client certificate",
            ));
        }
        if input.ip_allowlist.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(problem("ip_allowlist", "at most 32 entries"));
        }
        let mut scopes = input.scopes.clone();
        if scopes.is_empty() {
            scopes = DEFAULT_SCOPES.to_vec();
        }
        scopes.sort();
        scopes.dedup();
        let secret = TokenSecret::generate()?;
        let mut row = AgentKeyRow {
            id: AgentKeyId::generate(),
            agent_id: agent,
            secret_hash: token_hash(&agent, &secret),
            hint: secret.hint(),
            scopes,
            ip_allowlist: input.ip_allowlist.clone(),
            require_mtls: input.require_mtls,
            client_cert_sha256,
            created_at: now,
            expires_at,
            revoked_at: None,
            last_used_at: None,
            row_mac: [0; 32],
        };
        self.macs.sign_agent_key(&mut row)?;
        Ok((row, secret.to_token_string(&agent)))
    }

    /// All agents, for any role. Rows with a bad MAC show as revoked (ADR-0033).
    ///
    /// # Errors
    /// `Store`, `Crypto` or `Corrupt` if stored data cannot be read.
    pub(crate) async fn list_agents(&self) -> Result<Vec<AgentView>, CoreError> {
        let (agents, keys) = self.store.load_auth_rows().await?;
        let (agents, keys, _) = verify_rows(&agents, &keys, &self.macs)?;
        let mut views = agents
            .iter()
            .map(|agent| self.view(agent, &keys))
            .collect::<Result<Vec<_>, _>>()?;
        views.sort_by_key(|view| view.name.to_lowercase());
        Ok(views)
    }

    /// Makes an agent with its first key. The token in the result is shown one time.
    ///
    /// # Errors
    /// `RoleNotAllowed` for a viewer, or for "no expiry" without the owner role; `Validation`
    /// for bad input; `Store` or `Crypto`.
    pub(crate) async fn create_agent(
        &self,
        input: AgentInput,
        key: AgentKeyInput,
    ) -> Result<(AgentView, NewAgentKey), CoreError> {
        self.require_operator()?;
        let input = validate_input(&input)?;
        let _writes = self.auth.lock_writes().await;
        let now = self.clock.now();
        let id = AgentId::generate();
        let (key_row, token) = self.new_key(id, &key, now)?;
        let mut agent = AgentRow {
            id,
            status: AgentStatus::Active,
            created_at: now,
            updated_at: now,
            meta_ct: self.seal_meta(&id, &input)?,
            row_mac: [0; 32],
        };
        self.macs.sign_agent(&mut agent)?;
        let mut tx = self.store.begin().await?;
        tx.put_agent(&agent).await?;
        tx.put_agent_key(&key_row).await?;
        tx.commit().await?;
        self.auth.apply_agent(&agent);
        self.auth.apply_key(&key_row, now);
        let view = self.view(&agent, std::slice::from_ref(&key_row))?;
        Ok((
            view,
            NewAgentKey {
                key: key_view(&key_row),
                token,
            },
        ))
    }

    /// Renames an agent or changes its description. Only `meta_ct` and `updated_at` change; the
    /// status is never written back (a suspend or delete at the same time stays).
    ///
    /// # Errors
    /// `RoleNotAllowed`, `Validation`, `NotFound`, `Conflict` for a deleted agent, `Corrupt` for a
    /// row with a bad MAC.
    pub(crate) async fn update_agent(
        &self,
        id: AgentId,
        input: AgentInput,
    ) -> Result<AgentView, CoreError> {
        self.require_operator()?;
        let input = validate_input(&input)?;
        let _writes = self.auth.lock_writes().await;
        let (mut agent, keys) = self.agent_rows(id).await?;
        if agent.status == AgentStatus::Revoked {
            return Err(CoreError::Conflict);
        }
        let status = agent.status;
        agent.meta_ct = self.seal_meta(&id, &input)?;
        agent.updated_at = self.clock.now();
        self.macs.sign_agent(&mut agent)?;
        let mut tx = self.store.begin().await?;
        if !tx.update_agent_if_status(&agent, status).await? {
            return Err(CoreError::Conflict);
        }
        tx.commit().await?;
        self.view(&agent, &keys)
    }

    /// Suspends, re-activates or deletes an agent. `Revoked` is the delete: it is final and
    /// revokes every key of the agent in the same transaction (the store has no row delete, so
    /// the encrypted name stays for the audit trail). The table changes before this returns.
    ///
    /// # Errors
    /// `RoleNotAllowed`, `NotFound`, `Conflict` if the agent is already deleted, `Corrupt`.
    pub(crate) async fn set_agent_status(
        &self,
        id: AgentId,
        status: AgentStatus,
    ) -> Result<AgentView, CoreError> {
        self.require_operator()?;
        let _writes = self.auth.lock_writes().await;
        let (mut agent, mut keys) = self.agent_rows(id).await?;
        if agent.status == AgentStatus::Revoked {
            return Err(CoreError::Conflict);
        }
        let before = agent.status;
        let now = self.clock.now();
        agent.status = status;
        agent.updated_at = now;
        self.macs.sign_agent(&mut agent)?;
        let mut tx = self.store.begin().await?;
        if !tx.update_agent_if_status(&agent, before).await? {
            return Err(CoreError::Conflict);
        }
        if status == AgentStatus::Revoked {
            for key in keys.iter_mut().filter(|k| k.revoked_at.is_none()) {
                key.revoked_at = Some(now);
                self.macs.sign_agent_key(key)?;
                // False: the key was revoked already; it stays revoked either way.
                tx.update_live_agent_key(key).await?;
            }
        }
        tx.commit().await?;
        self.auth.apply_agent(&agent);
        for key in &keys {
            self.auth.apply_key(key, now);
        }
        self.view(&agent, &keys)
    }

    /// Adds a key to an agent. At most 5 keys can be live (not revoked, not expired).
    ///
    /// # Errors
    /// `RoleNotAllowed`, `Validation`, `NotFound`, `Conflict` (agent deleted, or 5 live keys),
    /// `Corrupt`.
    pub(crate) async fn create_agent_key(
        &self,
        agent: AgentId,
        input: AgentKeyInput,
    ) -> Result<NewAgentKey, CoreError> {
        self.require_operator()?;
        let _writes = self.auth.lock_writes().await;
        let now = self.clock.now();
        let (agent_row, keys) = self.agent_rows(agent).await?;
        if agent_row.status == AgentStatus::Revoked
            || keys.iter().filter(|k| is_live(k, now)).count() >= MAX_LIVE_KEYS
        {
            return Err(CoreError::Conflict);
        }
        let (row, token) = self.new_key(agent, &input, now)?;
        let mut tx = self.store.begin().await?;
        tx.put_agent_key(&row).await?;
        tx.commit().await?;
        self.auth.apply_key(&row, now);
        Ok(NewAgentKey {
            key: key_view(&row),
            token,
        })
    }

    /// Makes a new key with the same settings and lifetime, and ends the old key after `overlap`
    /// (at most 7 days; 0 ends it now). The old expiry is never made later. A revoke of the old
    /// key is never undone: the old key is changed only while it is not revoked.
    ///
    /// # Errors
    /// `RoleNotAllowed` (also for a key without expiry unless owner), `Validation`, `NotFound`,
    /// `Conflict` (old key not live, agent deleted, or 5 live keys), `Corrupt`.
    pub(crate) async fn rotate_agent_key(
        &self,
        key: AgentKeyId,
        overlap: Duration,
    ) -> Result<NewAgentKey, CoreError> {
        self.require_operator()?;
        if overlap > MAX_OVERLAP {
            return Err(problem("overlap", "at most 7 days"));
        }
        let overlap =
            SignedDuration::try_from(overlap).map_err(|_| problem("overlap", "out of range"))?;
        let _writes = self.auth.lock_writes().await;
        let now = self.clock.now();
        let (agent, keys, mut old) = self.key_rows(key).await?;
        if agent.status == AgentStatus::Revoked
            || !is_live(&old, now)
            || keys.iter().filter(|k| is_live(k, now)).count() >= MAX_LIVE_KEYS
        {
            return Err(CoreError::Conflict);
        }
        let expires_at = match old.expires_at {
            Some(at) => Some(
                now.checked_add(at - old.created_at)
                    .map_err(|_| problem("lifetime_days", "out of range"))?,
            ),
            None if self.role == OperatorRole::Owner => None,
            None => return Err(CoreError::RoleNotAllowed),
        };
        let params = AgentKeyInput {
            scopes: old.scopes.clone(),
            lifetime_days: None,
            ip_allowlist: old.ip_allowlist.clone(),
            require_mtls: old.require_mtls,
        };
        let (new_row, token) =
            self.key_row(agent.id, &params, now, expires_at, old.client_cert_sha256)?;
        let old_end = now
            .checked_add(overlap)
            .map_err(|_| problem("overlap", "out of range"))?;
        old.expires_at = Some(old.expires_at.map_or(old_end, |at| at.min(old_end)));
        self.macs.sign_agent_key(&mut old)?;
        let mut tx = self.store.begin().await?;
        if !tx.update_live_agent_key(&old).await? {
            return Err(CoreError::Conflict);
        }
        tx.put_agent_key(&new_row).await?;
        tx.commit().await?;
        self.auth.apply_key(&old, now);
        self.auth.apply_key(&new_row, now);
        Ok(NewAgentKey {
            key: key_view(&new_row),
            token,
        })
    }

    /// Revokes a key at once. A key that is already revoked stays as it is. Returns the agent.
    ///
    /// # Errors
    /// `RoleNotAllowed`, `NotFound`, `Corrupt`.
    pub(crate) async fn revoke_agent_key(&self, key: AgentKeyId) -> Result<AgentId, CoreError> {
        self.require_operator()?;
        let _writes = self.auth.lock_writes().await;
        let (agent, _, mut row) = self.key_rows(key).await?;
        if row.revoked_at.is_some() {
            return Ok(agent.id);
        }
        let now = self.clock.now();
        row.revoked_at = Some(now);
        self.macs.sign_agent_key(&mut row)?;
        let mut tx = self.store.begin().await?;
        if tx.update_live_agent_key(&row).await? {
            tx.commit().await?;
            self.auth.apply_key(&row, now);
        }
        Ok(agent.id)
    }

    /// Binds a live key to the SHA-256 of its client certificate and sets `require_mtls`.
    /// Use it after issuing the certificate. Binding again replaces the old fingerprint.
    ///
    /// # Errors
    /// `RoleNotAllowed`, `NotFound`, `Conflict` if the key is not live, `Corrupt`.
    pub(crate) async fn bind_client_cert(
        &self,
        key: AgentKeyId,
        sha256: [u8; 32],
    ) -> Result<AgentKeyView, CoreError> {
        self.require_operator()?;
        let _writes = self.auth.lock_writes().await;
        let now = self.clock.now();
        let (_, _, mut row) = self.key_rows(key).await?;
        if !is_live(&row, now) {
            return Err(CoreError::Conflict);
        }
        row.require_mtls = true;
        row.client_cert_sha256 = Some(sha256);
        self.macs.sign_agent_key(&mut row)?;
        let mut tx = self.store.begin().await?;
        if !tx.update_live_agent_key(&row).await? {
            return Err(CoreError::Conflict);
        }
        tx.commit().await?;
        self.auth.apply_key(&row, now);
        Ok(key_view(&row))
    }
}

/// An audit event by the operator of `ctx` about an agent or a key.
fn agent_event(
    event: EventType,
    ctx: &OperatorContext,
    kind: &str,
    id: impl ToString,
) -> AuditEvent {
    AuditEvent::new(event, Actor::operator(ctx.operator_id.to_string()))
        .request_id(ctx.request_id)
        .target(kind, id.to_string())
}

/// The agent calls of the IPC layer. Each call checks `ctx` against the unlocked session and
/// takes the role from the session, not from `ctx` (DEC-T05-5, DEC-FIX5-3). It holds the state
/// read guard only for the short DB work of the call.
impl VaultService {
    fn agent_service<'a>(&'a self, unlocked: &'a Unlocked) -> AgentService<'a> {
        AgentService::new(
            self.store(),
            self.auth(),
            unlocked.blobs(),
            unlocked.row_macs(),
            self.clock().as_ref(),
            unlocked.session.role,
        )
    }

    /// All agents. Any role.
    ///
    /// # Errors
    /// `Locked`, `Forbidden` (context of another session), `Store`, `Corrupt`.
    pub async fn list_agents(&self, ctx: &OperatorContext) -> Result<Vec<AgentView>, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        self.agent_service(&guard).list_agents().await
    }

    /// Makes an agent with its first key. Role operator or owner; "no expiry" needs owner.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `Validation`, `Store`, `Crypto`.
    pub async fn create_agent(
        &self,
        ctx: &OperatorContext,
        input: AgentInput,
        key: AgentKeyInput,
    ) -> Result<(AgentView, NewAgentKey), CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let (view, new_key) = self.agent_service(&guard).create_agent(input, key).await?;
        let event = agent_event(EventType::AgentCreate, ctx, "agent", view.id)
            .detail("key_id", new_key.key.id.to_string());
        self.audit(&guard, event).await;
        Ok((view, new_key))
    }

    /// Renames an agent or changes its description. Role operator or owner.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `Validation`, `NotFound`, `Conflict`, `Corrupt`.
    pub async fn update_agent(
        &self,
        ctx: &OperatorContext,
        id: AgentId,
        input: AgentInput,
    ) -> Result<AgentView, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let view = self.agent_service(&guard).update_agent(id, input).await?;
        self.audit(
            &guard,
            agent_event(EventType::AgentUpdate, ctx, "agent", id),
        )
        .await;
        Ok(view)
    }

    /// Suspends, resumes or deletes (`Revoked`) an agent. Role operator or owner.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `NotFound`, `Conflict`, `Corrupt`.
    pub async fn set_agent_status(
        &self,
        ctx: &OperatorContext,
        id: AgentId,
        status: AgentStatus,
    ) -> Result<AgentView, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let view = self
            .agent_service(&guard)
            .set_agent_status(id, status)
            .await?;
        let kind = match status {
            AgentStatus::Active => EventType::AgentResume,
            AgentStatus::Suspended => EventType::AgentSuspend,
            AgentStatus::Revoked => EventType::AgentRevoke,
        };
        self.audit(&guard, agent_event(kind, ctx, "agent", id))
            .await;
        Ok(view)
    }

    /// Deletes an agent: [`Self::set_agent_status`] with `Revoked`.
    ///
    /// # Errors
    /// As [`Self::set_agent_status`].
    pub async fn delete_agent(&self, ctx: &OperatorContext, id: AgentId) -> Result<(), CoreError> {
        self.set_agent_status(ctx, id, AgentStatus::Revoked)
            .await
            .map(drop)
    }

    /// Adds a key to an agent. Role operator or owner.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `Validation`, `NotFound`, `Conflict`, `Corrupt`.
    pub async fn create_agent_key(
        &self,
        ctx: &OperatorContext,
        agent: AgentId,
        input: AgentKeyInput,
    ) -> Result<NewAgentKey, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let new_key = self
            .agent_service(&guard)
            .create_agent_key(agent, input)
            .await?;
        let event = agent_event(EventType::AgentKeyCreate, ctx, "agent_key", new_key.key.id)
            .detail("agent_id", agent.to_string());
        self.audit(&guard, event).await;
        Ok(new_key)
    }

    /// Rotates a key (new key, old key ends after `overlap`). Role operator or owner.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `Validation`, `NotFound`, `Conflict`, `Corrupt`.
    pub async fn rotate_agent_key(
        &self,
        ctx: &OperatorContext,
        key: AgentKeyId,
        overlap: Duration,
    ) -> Result<NewAgentKey, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let new_key = self
            .agent_service(&guard)
            .rotate_agent_key(key, overlap)
            .await?;
        let event = agent_event(EventType::AgentKeyRotate, ctx, "agent_key", key)
            .detail("new_key_id", new_key.key.id.to_string())
            .detail("overlap_seconds", overlap.as_secs());
        self.audit(&guard, event).await;
        Ok(new_key)
    }

    /// Revokes a key at once. Role operator or owner.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `NotFound`, `Corrupt`.
    pub async fn revoke_agent_key(
        &self,
        ctx: &OperatorContext,
        key: AgentKeyId,
    ) -> Result<(), CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        let agent = self.agent_service(&guard).revoke_agent_key(key).await?;
        let event = agent_event(EventType::AgentKeyRevoke, ctx, "agent_key", key)
            .detail("agent_id", agent.to_string());
        self.audit(&guard, event).await;
        Ok(())
    }

    /// Binds a live key to its client certificate (SHA-256) and sets `require_mtls`. Owner only:
    /// it is the core half of IPC `agent_issue_client_cert`, whose role is owner
    /// (`docs/interfaces.md` section 9, DEC-WIRE6-13).
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `NotFound`, `Conflict`, `Corrupt`.
    pub async fn bind_client_cert(
        &self,
        ctx: &OperatorContext,
        key: AgentKeyId,
        sha256: [u8; 32],
    ) -> Result<AgentKeyView, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        let view = self
            .agent_service(&guard)
            .bind_client_cert(key, sha256)
            .await?;
        let event =
            agent_event(EventType::AgentUpdate, ctx, "agent_key", key).detail("require_mtls", true);
        self.audit(&guard, event).await;
        Ok(view)
    }
}

#[cfg(test)]
mod tests;
