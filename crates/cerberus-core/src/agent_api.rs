//! The Agent API: the one entry point for agent calls. REST (T10) and MCP (T11) call only this
//! (ADR-0004). Get it with [`VaultService::agent_api`].
//!
//! Every method runs the same steps, once:
//! 1. The vault must be unlocked. Else `Locked` (HTTP 423, ADR-0008) and `api.locked_call` with
//!    the route name (`audit_pending` while sealed). No data is read.
//! 2. The token scope of the route (ADR-0016). Else `InsufficientScope` and `auth.failed`.
//! 3. Policy (ADR-0017), leases and approvals (ADR-0018, ADR-0019) through the
//!    [`PolicyEngine`], then the item service.
//! 4. Audit events. A secret leaves the vault only when its `item.reveal` (or `item.totp`) event
//!    is in the chain (ADR-0025). No event holds a secret value.
//!
//! No method holds the vault guard while it calls an engine method that takes its own guard, or
//! while it waits. A secret read runs the policy check and the payload read on one write guard
//! (DEC-FIX7-2), so no grant change, revoke, edit or lock can land between them.
//! Results that carry a secret have `handling` = [`HANDLING_SECRET`] (ADR-0028); T10 and T11
//! copy it into the response body and convert the [`Payload`] to the wire form.

#[cfg(test)]
mod hardening;
#[cfg(test)]
mod regressions;
pub mod ssh;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::BTreeMap;
use std::time::Duration;

use cerberus_crypto::SecretString;
use cerberus_types::{
    AccessRequestId, AgentId, AgentKeyId, Environment, ErrorCode, FieldProblem, GrantId,
    HANDLING_SECRET, ItemId, ItemKind, LeaseId, Permission, RequestId, Scope, VaultStateKind,
};
use jiff::Timestamp;

use crate::approvals::{AccessRequestView, CreateAccess};
use crate::audit::{AuditEvent, EventType};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::index::{Index, ItemMeta, normalize, words};
use crate::items::{ItemInput, ItemSummary, Payload, SshMeta, agent_payload_problems};
use crate::leases::{LeaseView, ReleaseOutcome};
use crate::policy::engine::{agent_grants, by_agent, decision_error, item_live};
use crate::policy::{
    Decision, EvalInput, NoCount, PolicyEngine, PolicyItem, SecretAccess, SecretAsk, evaluate,
};
use crate::resolve::{Candidate, Resolution, ResolveMode, ResolveRequest};
use crate::vault::VaultService;

/// Route names for audit events (`details.route`). MCP tools use the route of the same call.
pub mod routes {
    /// Agent status.
    pub const STATUS: &str = "GET /v1/status";
    /// Resolve by app, environment and role.
    pub const RESOLVE: &str = "POST /v1/credentials/resolve";
    /// The catalog (metadata only).
    pub const CATALOG: &str = "GET /v1/credentials";
    /// Reveal by item ID.
    pub const REVEAL: &str = "POST /v1/credentials/{id}/reveal";
    /// Current TOTP code.
    pub const TOTP: &str = "POST /v1/credentials/{id}/totp";
    /// Agent creates an item.
    pub const CREATE_ITEM: &str = "POST /v1/credentials";
    /// Agent stores a session.
    pub const CREATE_SESSION: &str = "POST /v1/sessions";
    /// Agent deletes an item it created.
    pub const DELETE_ITEM: &str = "DELETE /v1/credentials/{id}";
    /// Ask for access ahead.
    pub const REQUEST_ACCESS: &str = "POST /v1/requests";
    /// Poll an access request.
    pub const GET_REQUEST: &str = "GET /v1/requests/{id}";
    /// Wait for an access request (SSE).
    pub const WAIT_REQUEST: &str = "GET /v1/requests/{id}/events";
    /// Give back a lease.
    pub const RELEASE_LEASE: &str = "POST /v1/leases/{id}/release";
}

/// Default page size of the catalog.
pub const CATALOG_DEFAULT_LIMIT: u32 = 100;
/// Largest page size of the catalog.
pub const CATALOG_MAX_LIMIT: u32 = 500;
/// Longest `purpose` text, in characters (ADR-0020).
pub const MAX_PURPOSE_CHARS: usize = 500;

/// The agent's own view of its key (`GET /v1/status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSelf {
    /// Agent ID.
    pub id: AgentId,
    /// Agent name (empty when the row does not open).
    pub name: String,
    /// The key of this call.
    pub key_id: AgentKeyId,
    /// The scopes of that key.
    pub scopes: Vec<Scope>,
    /// Expiry of that key.
    pub key_expires_at: Option<Timestamp>,
}

/// `GET /v1/status`, MCP `vault_status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentStatusView {
    /// Vault state (always `unlocked` here: a sealed vault gives `Locked`).
    pub vault: VaultStateKind,
    /// The caller.
    pub agent: AgentSelf,
    /// Time of the vault clock.
    pub server_time: Timestamp,
}

/// A secret for the agent (ADR-0028). Metadata in `item`, the value in `secret`, the lease in
/// `lease`. Convert it to the response and drop it; `Debug` shows no secret value.
#[derive(Debug)]
pub struct SecretResult {
    /// Always [`HANDLING_SECRET`]. The response body carries it at the top level.
    pub handling: &'static str,
    /// The request ID of the call.
    pub request_id: RequestId,
    /// Item metadata.
    pub item: ItemSummary,
    /// The secret value. The TOTP seed is removed (ADR-0027).
    pub secret: Payload,
    /// Machine, host, port and user of an SSH key (from the metadata).
    pub ssh: Option<SshMeta>,
    /// The lease that covered the read.
    pub lease: LeaseView,
}

/// A person must decide first (`202`, ADR-0018).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingResult {
    /// The request ID of the call.
    pub request_id: RequestId,
    /// The access request to poll or wait on.
    pub access_request: AccessRequestView,
}

/// The answer of [`AgentApi::reveal`].
#[derive(Debug)]
pub enum RevealOutcome {
    /// The secret.
    Secret(Box<SecretResult>),
    /// An approval is needed.
    Pending(PendingResult),
}

/// The answer of [`AgentApi::resolve`] (wire `outcome`).
#[derive(Debug)]
pub enum ResolveResult {
    /// `best`, one confident match, read allowed: the secret.
    Secret(Box<SecretResult>),
    /// `best`, one confident match, an approval is needed.
    Pending(PendingResult),
    /// `candidates` mode. Metadata only.
    Candidates(Vec<Candidate>),
    /// `best` mode without a clear winner. Metadata only.
    Ambiguous(Vec<Candidate>),
}

/// A TOTP code for the agent. The seed stays in the vault.
#[derive(Debug)]
pub struct TotpResult {
    /// Always [`HANDLING_SECRET`].
    pub handling: &'static str,
    /// The request ID of the call.
    pub request_id: RequestId,
    /// The item.
    pub item_id: ItemId,
    /// The code.
    pub code: SecretString,
    /// Step length in seconds.
    pub period: u32,
    /// Seconds until the code changes.
    pub expires_in_seconds: u32,
    /// The lease that covered the read.
    pub lease: LeaseView,
}

/// The answer of [`AgentApi::totp`].
#[derive(Debug)]
pub enum TotpOutcome {
    /// The code.
    Code(Box<TotpResult>),
    /// An approval is needed.
    Pending(PendingResult),
}

/// `POST /v1/credentials/{id}/reveal` body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevealInput {
    /// Why the agent reads the secret, 1..500 characters (audit only).
    pub purpose: String,
    /// A lease to use.
    pub lease_id: Option<LeaseId>,
    /// TTL to ask for when an approval is needed (60..86400 s).
    pub ttl_seconds: Option<u32>,
}

/// `POST /v1/credentials/{id}/totp` body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TotpInput {
    /// Why the agent needs the code, 1..500 characters (audit only).
    pub purpose: String,
    /// A lease to use.
    pub lease_id: Option<LeaseId>,
}

/// `GET /v1/credentials` query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogQuery {
    /// Workspace slug or alias. An unknown one gives an empty page.
    pub workspace: Option<String>,
    /// Environment.
    pub environment: Option<Environment>,
    /// Kind.
    pub kind: Option<ItemKind>,
    /// Tag (normalized compare).
    pub tag: Option<String>,
    /// Free text: every word must be in title, description, role label, tags or target.
    pub q: Option<String>,
    /// Page size, 1..=500 (default 100).
    pub limit: Option<u32>,
    /// `next_cursor` of the previous page.
    pub cursor: Option<String>,
}

/// One catalog page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogPage {
    /// Items the agent may find, sorted by title.
    pub items: Vec<ItemSummary>,
    /// Cursor of the next page, when there is one.
    pub next_cursor: Option<String>,
}

/// `POST /v1/credentials` body (MCP `store_secret`). The TOTP seed of a web login is inside the
/// payload.
#[derive(Debug)]
pub struct AgentItemInput {
    /// Workspace slug or alias.
    pub workspace: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Environment.
    pub environment: Environment,
    /// Role label.
    pub role_label: Option<String>,
    /// Category; the kind name when missing.
    pub category: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Target: URL, host or app name.
    pub target: Option<String>,
    /// Extra facts (SSH: `machine`, `host`, `port`, `user`).
    pub custom: BTreeMap<String, String>,
    /// Lifetime in seconds (ADR-0007). Session kinds get the default TTL when it is missing.
    pub ttl_seconds: Option<u32>,
    /// Reveals after which the item is deleted.
    pub max_uses: Option<u32>,
    /// The secret.
    pub payload: Payload,
}

/// `POST /v1/sessions` body. The payload must be a session token or a browser session.
#[derive(Debug)]
pub struct AgentSessionInput {
    /// Workspace slug or alias.
    pub workspace: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Environment.
    pub environment: Environment,
    /// Role label.
    pub role_label: Option<String>,
    /// Target: URL, host or app name.
    pub target: Option<String>,
    /// Lifetime in seconds: default `session_ttl_default_seconds` (3600), at most
    /// `session_ttl_max_seconds` (item settings, ADR-0007).
    pub ttl_seconds: Option<u32>,
    /// `SessionToken` or `BrowserSession`.
    pub payload: Payload,
}

/// An item the agent made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedItem {
    /// Its metadata.
    pub item: ItemSummary,
}

/// The Agent API on one vault service. Cheap to clone.
#[derive(Clone, Debug)]
pub struct AgentApi {
    service: VaultService,
}

impl VaultService {
    /// The Agent API of this service.
    #[must_use]
    pub fn agent_api(&self) -> AgentApi {
        AgentApi {
            service: self.clone(),
        }
    }
}

/// Removes hidden format characters (bidi controls, zero-width and tag characters) from every
/// metadata text an agent writes (AUD-24). Other agents and people read these texts inline,
/// where such characters can change the display order or hide words. Control characters stay,
/// so item validation still refuses them.
fn strip_agent_text(mut input: AgentItemInput) -> AgentItemInput {
    use cerberus_types::text::strip_format;
    let strip_opt = |text: Option<String>| text.map(|t| strip_format(&t));
    input.title = strip_format(&input.title);
    input.description = strip_opt(input.description);
    input.role_label = strip_opt(input.role_label);
    input.category = strip_opt(input.category);
    input.target = strip_opt(input.target);
    input.tags = input.tags.iter().map(|t| strip_format(t)).collect();
    input.custom = std::mem::take(&mut input.custom)
        .into_iter()
        .map(|(k, v)| (strip_format(&k), strip_format(&v)))
        .collect();
    input
}

const fn is_session_kind(kind: ItemKind) -> bool {
    matches!(kind, ItemKind::SessionToken | ItemKind::BrowserSession)
}

/// The category of an agent item without one.
const fn default_category(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::WebLogin => "Web login",
        ItemKind::ApiKey => "API key",
        ItemKind::SshKey => "SSH key",
        ItemKind::SessionToken => "Session token",
        ItemKind::BrowserSession => "Browser session",
        ItemKind::Database => "Database",
        ItemKind::Cloud => "Cloud",
        ItemKind::Certificate => "Certificate",
        ItemKind::EnvBundle => "Environment",
        ItemKind::Note => "Note",
    }
}

fn problem(field: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }])
}

fn check_purpose(purpose: &str) -> Result<(), CoreError> {
    let len = purpose.trim().chars().count();
    if (1..=MAX_PURPOSE_CHARS).contains(&len) {
        Ok(())
    } else {
        Err(problem("purpose", "must be 1..500 characters"))
    }
}

/// The purpose as audit bodies keep it: trimmed and cut to [`MAX_PURPOSE_CHARS`] characters.
/// A call can fail its length check and still be audited, so this cut never relies on it.
pub(crate) fn audit_purpose(purpose: &str) -> String {
    purpose.trim().chars().take(MAX_PURPOSE_CHARS).collect()
}

/// The text form of a resolve outcome, for `api.resolve`.
const fn mode_text(mode: ResolveMode) -> &'static str {
    match mode {
        ResolveMode::Best => "best",
        ResolveMode::Candidates => "candidates",
    }
}

/// The text form of a scope, for audit details.
fn scope_text(scope: Scope) -> serde_json::Value {
    serde_json::to_value(scope).unwrap_or(serde_json::Value::Null)
}

impl AgentApi {
    /// The vault service.
    #[must_use]
    pub const fn service(&self) -> &VaultService {
        &self.service
    }

    fn engine(&self) -> PolicyEngine {
        self.service.policy()
    }

    /// Steps 1 and 2 of every call: unlocked, then the scope.
    async fn ready(
        &self,
        ctx: &AgentContext,
        scope: Scope,
        route: &'static str,
    ) -> Result<(), CoreError> {
        self.unlocked_or_audit(ctx, route).await?;
        if ctx.scopes.contains(&scope) {
            return Ok(());
        }
        self.scope_refused(ctx, scope, route).await
    }

    /// Step 1 only. A sealed vault (or none) is `Locked` for agents, with `api.locked_call`.
    async fn unlocked_or_audit(
        &self,
        ctx: &AgentContext,
        route: &'static str,
    ) -> Result<(), CoreError> {
        if self.service.state() == VaultStateKind::Unlocked {
            return Ok(());
        }
        self.service
            .audit_locked_call(Some(ctx), route, ErrorCode::VaultLocked)
            .await;
        Err(CoreError::Locked)
    }

    /// Writes `auth.failed` (reason `insufficient_scope`) and returns the error.
    async fn scope_refused(
        &self,
        ctx: &AgentContext,
        scope: Scope,
        route: &'static str,
    ) -> Result<(), CoreError> {
        let error = CoreError::InsufficientScope(scope);
        let guard = self.service.unlocked().await?;
        let event = by_agent(EventType::AuthFailed, ctx)
            .result(error.code().as_str())
            .detail("reason", "insufficient_scope")
            .detail("scope", scope_text(scope))
            .detail("route", route);
        self.service.audit(&guard, event).await;
        Err(error)
    }

    /// An event of this agent with the route detail.
    fn event(ctx: &AgentContext, event: EventType, route: &'static str) -> AuditEvent {
        by_agent(event, ctx).detail("route", route)
    }

    /// Writes a non-secret event (a failure is logged, ADR-0025).
    async fn audit(&self, event: AuditEvent) {
        if let Ok(guard) = self.service.unlocked().await {
            self.service.audit(&guard, event).await;
        }
    }

    /// `GET /v1/status`, MCP `vault_status`. Scope `status:read`.
    ///
    /// # Errors
    /// `Locked`, `InsufficientScope`, or a storage error.
    pub async fn status(&self, ctx: &AgentContext) -> Result<AgentStatusView, CoreError> {
        self.ready(ctx, Scope::StatusRead, routes::STATUS).await?;
        let name = {
            let guard = self.service.unlocked().await?;
            let names = self.engine().agent_names(&guard).await?;
            names.get(&ctx.agent_id).cloned().unwrap_or_default()
        };
        Ok(AgentStatusView {
            vault: VaultStateKind::Unlocked,
            agent: AgentSelf {
                id: ctx.agent_id,
                name,
                key_id: ctx.key_id,
                scopes: ctx.scopes.iter().copied().collect(),
                key_expires_at: self
                    .service
                    .auth()
                    .key_expires_at(&ctx.agent_id, &ctx.key_id)
                    .flatten(),
            },
            server_time: self.service.clock().now(),
        })
    }

    /// `POST /v1/credentials/resolve`, MCP `find_credentials` (mode `candidates`) and
    /// `get_credential` (mode `best`). Scope `secrets:read` for `best`, `catalog:read` for
    /// `candidates` (ADR-0016).
    ///
    /// Policy is asked first (a snapshot, no guard kept), then the index is scored. The `read`
    /// answer of the snapshot is only advisory: the read itself goes through
    /// [`PolicyEngine::authorize_secret`], which counts it, uses or makes the lease, or opens the
    /// access request. Writes `api.resolve` (with the purpose) and, for a secret, `item.reveal`.
    ///
    /// # Errors
    /// `Validation`, `NoMatch` (with hints), `NotFound`, `Forbidden`, `ReasonRequired`,
    /// `ConditionFailed`, `GrantRateLimited`, `RateLimited`, `ApprovalDenied`,
    /// `ApprovalUnavailable`, `Locked`, `InsufficientScope`, or a storage error.
    pub async fn resolve(
        &self,
        ctx: &AgentContext,
        req: ResolveRequest,
    ) -> Result<ResolveResult, CoreError> {
        let scope = match req.mode {
            ResolveMode::Best => Scope::SecretsRead,
            ResolveMode::Candidates => Scope::CatalogRead,
        };
        self.ready(ctx, scope, routes::RESOLVE).await?;
        let engine = self.engine();
        let scored = async {
            req.validate()?;
            let snapshot = engine.resolve_policy(ctx, Some(&req.purpose)).await?;
            self.service.resolve(&req, &snapshot).await
        }
        .await;
        let base = Self::event(ctx, EventType::ApiResolve, routes::RESOLVE)
            .detail("mode", mode_text(req.mode))
            .detail("purpose", audit_purpose(&req.purpose));
        let result = match scored {
            Err(error) => Err(error),
            Ok(Resolution::Candidates(list)) => Ok(ResolveResult::Candidates(list)),
            Ok(Resolution::Ambiguous(list)) => Ok(ResolveResult::Ambiguous(list)),
            Ok(Resolution::Best { item, .. }) => self
                .read_secret(
                    ctx,
                    item.id,
                    Some(&req.purpose),
                    None,
                    None,
                    routes::RESOLVE,
                )
                .await
                .map(|outcome| match outcome {
                    RevealOutcome::Secret(secret) => ResolveResult::Secret(secret),
                    RevealOutcome::Pending(pending) => ResolveResult::Pending(pending),
                }),
        };
        let event = match &result {
            Err(error) => base.result(error.code().as_str()),
            Ok(ResolveResult::Candidates(list)) => base
                .detail("outcome", "candidates")
                .detail("count", list.len()),
            Ok(ResolveResult::Ambiguous(list)) => base
                .detail("outcome", "ambiguous")
                .detail("count", list.len()),
            Ok(ResolveResult::Secret(secret)) => base
                .target("item", secret.item.id.to_string())
                .detail("outcome", "secret"),
            Ok(ResolveResult::Pending(pending)) => base
                .target("item", pending.access_request.item_id.to_string())
                .detail("outcome", "pending")
                .detail("access_request", pending.access_request.id.to_string()),
        };
        self.audit(event).await;
        result
    }

    /// The secret read of `resolve` and `reveal`: policy, lease or approval, then the payload
    /// and `item.reveal` on one write guard. The secret is returned only after its event is in
    /// the chain.
    async fn read_secret(
        &self,
        ctx: &AgentContext,
        id: ItemId,
        purpose: Option<&str>,
        lease_id: Option<LeaseId>,
        ttl_seconds: Option<u32>,
        route: &'static str,
    ) -> Result<RevealOutcome, CoreError> {
        let ask = SecretAsk {
            item_id: id,
            permission: Permission::Read,
            reason: purpose,
            lease_id,
            requested_ttl_seconds: ttl_seconds,
        };
        // One write guard for the check and the read: a deny, revoke, edit or lock waits for
        // the whole read, so it either lands before the check or after the secret is audited.
        // A lock cannot burn a one-use lease between the two either.
        let mut guard = self.service.unlocked_mut().await?;
        let access = self.engine().authorize_secret_in(&guard, ctx, ask).await?;
        let (lease, grant_id) = match access {
            SecretAccess::Pending(view) => {
                return Ok(RevealOutcome::Pending(PendingResult {
                    request_id: ctx.request_id,
                    access_request: view,
                }));
            }
            SecretAccess::Granted { lease, grant_id } => (lease, grant_id),
        };
        let event = Self::reveal_event(ctx, id, &lease, grant_id, purpose, route);
        let revealed = self
            .service
            .reveal_payload_in(&mut guard, id, event)
            .await?;
        drop(guard);
        Ok(RevealOutcome::Secret(Box::new(SecretResult {
            handling: HANDLING_SECRET,
            request_id: ctx.request_id,
            item: revealed.summary,
            secret: revealed.payload.without_totp(),
            ssh: revealed.ssh,
            lease,
        })))
    }

    fn reveal_event(
        ctx: &AgentContext,
        id: ItemId,
        lease: &LeaseView,
        grant_id: GrantId,
        purpose: Option<&str>,
        route: &'static str,
    ) -> AuditEvent {
        let mut event = Self::event(ctx, EventType::ItemReveal, route)
            .target("item", id.to_string())
            .detail("lease_id", lease.id.to_string())
            .detail("grant_id", grant_id.to_string());
        if let Some(text) = purpose {
            event = event.detail("purpose", audit_purpose(text));
        }
        event
    }

    /// `GET /v1/credentials`, MCP resource `cerberus://catalog`. Metadata of the items the agent
    /// may find (policy `find`), sorted by title, in pages. Scope `catalog:read`. Writes
    /// `api.catalog`.
    ///
    /// # Errors
    /// `Validation` (limit or cursor), `Locked`, or `InsufficientScope`.
    pub async fn catalog(
        &self,
        ctx: &AgentContext,
        query: CatalogQuery,
    ) -> Result<CatalogPage, CoreError> {
        self.ready(ctx, Scope::CatalogRead, routes::CATALOG).await?;
        let limit = query.limit.unwrap_or(CATALOG_DEFAULT_LIMIT);
        if !(1..=CATALOG_MAX_LIMIT).contains(&limit) {
            return Err(problem("limit", "must be 1..500"));
        }
        let offset = match query.cursor.as_deref() {
            None => 0,
            Some(text) => text
                .parse::<usize>()
                .map_err(|_| problem("cursor", "is not a cursor of this catalog"))?,
        };
        let page = {
            let guard = self.service.unlocked().await?;
            let now = self.service.clock().now();
            let mut items = catalog_items(&guard.index, ctx.agent_id, &query, now);
            let total = items.len();
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let end = offset.saturating_add(limit).min(total);
            let next_cursor = (end < total).then(|| end.to_string());
            let items = if offset < total {
                items.drain(offset..end).collect()
            } else {
                Vec::new()
            };
            let event = Self::event(ctx, EventType::ApiCatalog, routes::CATALOG)
                .detail("count", items_len(&items))
                .detail("offset", offset);
            self.service.audit(&guard, event).await;
            CatalogPage { items, next_cursor }
        };
        Ok(page)
    }

    /// `POST /v1/credentials/{id}/reveal`, MCP `get_credential` by ID. Scope `secrets:read`.
    /// Writes `item.reveal` (and the lease events of the engine).
    ///
    /// # Errors
    /// As [`Self::resolve`] for a confident match, plus `Validation` for the purpose.
    pub async fn reveal(
        &self,
        ctx: &AgentContext,
        id: ItemId,
        req: RevealInput,
    ) -> Result<RevealOutcome, CoreError> {
        self.ready(ctx, Scope::SecretsRead, routes::REVEAL).await?;
        check_purpose(&req.purpose)?;
        self.read_secret(
            ctx,
            id,
            Some(&req.purpose),
            req.lease_id,
            req.ttl_seconds,
            routes::REVEAL,
        )
        .await
    }

    /// `POST /v1/credentials/{id}/totp`, MCP `get_totp`. The code needs the same `read` policy
    /// and lease as a reveal; the seed never leaves the vault and the code does not count as a
    /// reveal for `max_uses` (DEC-T06-5). Scope `secrets:read`. Writes `item.totp`.
    ///
    /// # Errors
    /// As [`Self::reveal`]; `NotFound` also for an item without a TOTP seed.
    pub async fn totp(
        &self,
        ctx: &AgentContext,
        id: ItemId,
        req: TotpInput,
    ) -> Result<TotpOutcome, CoreError> {
        self.ready(ctx, Scope::SecretsRead, routes::TOTP).await?;
        check_purpose(&req.purpose)?;
        let no_seed = {
            let guard = self.service.unlocked().await?;
            guard.index.item(&id).is_some_and(|meta| !meta.has_totp)
        };
        if no_seed {
            return Err(CoreError::NotFound);
        }
        let ask = SecretAsk {
            item_id: id,
            permission: Permission::Read,
            reason: Some(&req.purpose),
            lease_id: req.lease_id,
            requested_ttl_seconds: None,
        };
        // Check and code on one guard, as in `read_secret`. The code changes nothing, so the
        // read guard is enough: a writer still waits for both steps.
        let guard = self.service.unlocked().await?;
        let access = self.engine().authorize_secret_in(&guard, ctx, ask).await?;
        let (lease, grant_id) = match access {
            SecretAccess::Pending(view) => {
                return Ok(TotpOutcome::Pending(PendingResult {
                    request_id: ctx.request_id,
                    access_request: view,
                }));
            }
            SecretAccess::Granted { lease, grant_id } => (lease, grant_id),
        };
        let event = Self::event(ctx, EventType::ItemTotp, routes::TOTP)
            .target("item", id.to_string())
            .detail("lease_id", lease.id.to_string())
            .detail("grant_id", grant_id.to_string())
            .detail("purpose", audit_purpose(&req.purpose));
        let code = match self.service.totp_code_in(&guard, id).await {
            Ok(code) => code,
            Err(error) => {
                self.service
                    .audit(&guard, event.result(error.code().as_str()))
                    .await;
                return Err(error);
            }
        };
        self.service.audit_strict(&guard, event).await?;
        drop(guard);
        Ok(TotpOutcome::Code(Box::new(TotpResult {
            handling: HANDLING_SECRET,
            request_id: ctx.request_id,
            item_id: id,
            code: code.code,
            period: code.period,
            expires_in_seconds: code.expires_in_seconds,
            lease,
        })))
    }

    /// `POST /v1/credentials`, MCP `store_secret`. The kind of the payload decides the scope and
    /// the policy permission: session kinds need `sessions:write` and `create_session`, other
    /// kinds `secrets:write` and `write` (ADR-0016, ADR-0017 rule 5). Writes `item.create`
    /// (also for a refusal).
    ///
    /// # Errors
    /// `Forbidden` (no grant or unknown workspace, A11), `InsufficientScope`, `Validation`,
    /// `Conflict` (title used by an item the agent can find), `Locked`, or a storage error.
    pub async fn create_item(
        &self,
        ctx: &AgentContext,
        input: AgentItemInput,
    ) -> Result<CreatedItem, CoreError> {
        let kind = input.payload.kind();
        let (scope, permission) = if is_session_kind(kind) {
            (Scope::SessionsWrite, Permission::CreateSession)
        } else {
            (Scope::SecretsWrite, Permission::Write)
        };
        self.ready(ctx, scope, routes::CREATE_ITEM).await?;
        self.create(ctx, input, permission).await
    }

    /// `POST /v1/sessions`: store a session token or browser session with a TTL (default 3600 s,
    /// at most `session_ttl_max_seconds`, ADR-0007). Scope `sessions:write`, policy
    /// `create_session`.
    ///
    /// # Errors
    /// As [`Self::create_item`]; `Validation` when the payload is not a session kind.
    pub async fn create_session(
        &self,
        ctx: &AgentContext,
        input: AgentSessionInput,
    ) -> Result<CreatedItem, CoreError> {
        self.ready(ctx, Scope::SessionsWrite, routes::CREATE_SESSION)
            .await?;
        let kind = input.payload.kind();
        if !is_session_kind(kind) {
            return Err(problem(
                "payload",
                "must be a session_token or a browser_session",
            ));
        }
        let item = AgentItemInput {
            workspace: input.workspace,
            title: input.title,
            description: input.description,
            environment: input.environment,
            role_label: input.role_label,
            category: None,
            tags: Vec::new(),
            target: input.target,
            custom: BTreeMap::new(),
            ttl_seconds: input.ttl_seconds,
            max_uses: None,
            payload: input.payload,
        };
        self.create(ctx, item, Permission::CreateSession).await
    }

    async fn create(
        &self,
        ctx: &AgentContext,
        input: AgentItemInput,
        permission: Permission,
    ) -> Result<CreatedItem, CoreError> {
        let input = strip_agent_text(input);
        let kind = input.payload.kind();
        let env_problems = agent_payload_problems(&input.payload);
        if !env_problems.is_empty() {
            let error = CoreError::Validation(env_problems);
            let event = by_agent(EventType::ItemCreate, ctx)
                .result(error.code().as_str())
                .detail("kind", serde_json::to_value(kind).unwrap_or_default())
                .detail("decision", "forbidden_env_name");
            self.audit(event).await;
            return Err(error);
        }
        let workspace_id = {
            let guard = self.service.unlocked().await?;
            guard.index.workspace_by_slug(&input.workspace)
        };
        // An unknown workspace is the same `Forbidden` as no grant, so a create never tells an
        // agent which workspaces exist (DEC-FIX7-3).
        let Some(workspace_id) = workspace_id else {
            let error = CoreError::Forbidden;
            let event = by_agent(EventType::ItemCreate, ctx)
                .result(error.code().as_str())
                .detail("kind", serde_json::to_value(kind).unwrap_or_default())
                .detail("decision", "unknown_workspace");
            self.audit(event).await;
            return Err(error);
        };
        let expires_at = self
            .service
            .expiry_from_ttl(kind, input.ttl_seconds.map(u64::from))
            .await?;
        let item = ItemInput {
            workspace_id,
            title: input.title,
            description: input.description.unwrap_or_default(),
            role_label: input.role_label,
            category: input
                .category
                .unwrap_or_else(|| default_category(kind).to_owned()),
            tags: input.tags,
            environment: input.environment,
            target: input.target,
            custom: input.custom,
            expires_at,
            max_uses: input.max_uses,
            payload: input.payload,
        };
        let agent = ctx.agent_id;
        let now = self.service.clock().now();
        let check = move |index: &Index, meta: &ItemMeta| {
            let grants = agent_grants(index, &agent);
            let item = PolicyItem {
                item_id: None,
                ..PolicyItem::of(meta)
            };
            let decision = evaluate(
                &EvalInput {
                    grants: &grants,
                    item,
                    permission,
                    reason: None,
                    now,
                },
                &agent,
                &NoCount,
            );
            match decision {
                Decision::Allow { .. } => Ok(()),
                other => Err((decision_error(&other), other.as_str())),
            }
        };
        let detail = self.service.create_item_as_agent(ctx, item, &check).await?;
        Ok(CreatedItem {
            item: detail.summary,
        })
    }

    /// `DELETE /v1/credentials/{id}`: delete an item this agent created. Scope `secrets:write`,
    /// or `sessions:write` for session kinds. An item the agent can neither find nor created is
    /// `NotFound`; a visible item of someone else is `Forbidden` (ADR-0021). Writes
    /// `item.delete` (also for a refusal).
    ///
    /// # Errors
    /// `NotFound`, `Forbidden`, `InsufficientScope`, `Locked`, or a storage error.
    pub async fn delete_item(&self, ctx: &AgentContext, id: ItemId) -> Result<(), CoreError> {
        self.unlocked_or_audit(ctx, routes::DELETE_ITEM).await?;
        let any_write =
            ctx.scopes.contains(&Scope::SecretsWrite) || ctx.scopes.contains(&Scope::SessionsWrite);
        if !any_write {
            return self
                .scope_refused(ctx, Scope::SecretsWrite, routes::DELETE_ITEM)
                .await;
        }
        let (kind, own) = {
            let guard = self.service.unlocked().await?;
            let now = self.service.clock().now();
            let Some(meta) = guard.index.item(&id).filter(|m| item_live(m, now)) else {
                return Err(CoreError::NotFound);
            };
            let own = meta.created_by == crate::index::CreatedBy::Agent(ctx.agent_id);
            let grants = agent_grants(&guard.index, &ctx.agent_id);
            if !own && !crate::policy::can_find(&grants, &ctx.agent_id, meta, now) {
                return Err(CoreError::NotFound);
            }
            (meta.kind, own)
        };
        let scope = if is_session_kind(kind) {
            Scope::SessionsWrite
        } else {
            Scope::SecretsWrite
        };
        if !ctx.scopes.contains(&scope) {
            return self.scope_refused(ctx, scope, routes::DELETE_ITEM).await;
        }
        if !own {
            let error = CoreError::Forbidden;
            let event = Self::event(ctx, EventType::ItemDelete, routes::DELETE_ITEM)
                .target("item", id.to_string())
                .result(error.code().as_str())
                .detail("decision", "not_creator");
            self.audit(event).await;
            return Err(error);
        }
        self.service.delete_item_as_agent(ctx, id).await
    }

    /// `POST /v1/requests`, MCP `request_access`: ask a person ahead. Scope `requests`. Writes
    /// `request.create`.
    ///
    /// # Errors
    /// As [`PolicyEngine::request_access`], plus `Locked` and `InsufficientScope`.
    pub async fn request_access(
        &self,
        ctx: &AgentContext,
        req: CreateAccess,
    ) -> Result<AccessRequestView, CoreError> {
        self.ready(ctx, Scope::Requests, routes::REQUEST_ACCESS)
            .await?;
        self.engine().request_access(ctx, req).await
    }

    /// `GET /v1/requests/{id}`. Scope `requests`.
    ///
    /// # Errors
    /// As [`PolicyEngine::get_access_request`], plus `Locked` and `InsufficientScope`.
    pub async fn get_access_request(
        &self,
        ctx: &AgentContext,
        id: AccessRequestId,
    ) -> Result<AccessRequestView, CoreError> {
        self.ready(ctx, Scope::Requests, routes::GET_REQUEST)
            .await?;
        self.engine().get_access_request(ctx, id).await
    }

    /// `GET /v1/requests/{id}/events` (SSE) and the MCP waits: waits up to `max_wait` (capped
    /// at 120 s) for a terminal state, with no guard held. A lock ends it with a `cancelled`
    /// view (or `Locked`). SSE sends the first state with [`Self::get_access_request`], then
    /// calls this until a terminal state or `expires_at`. Scope `requests`.
    ///
    /// # Errors
    /// As [`PolicyEngine::wait_access_request`], plus `InsufficientScope`.
    pub async fn wait_access_request(
        &self,
        ctx: &AgentContext,
        id: AccessRequestId,
        max_wait: Duration,
    ) -> Result<AccessRequestView, CoreError> {
        self.ready(ctx, Scope::Requests, routes::WAIT_REQUEST)
            .await?;
        self.engine().wait_access_request(ctx, id, max_wait).await
    }

    /// `POST /v1/leases/{id}/release`, MCP `release_credential`. Scope `requests`. Writes
    /// `lease.release`.
    ///
    /// # Errors
    /// `NotFound` (also a lease of another agent), `Conflict` (not active), `Locked`,
    /// `InsufficientScope`, or a storage error.
    pub async fn release_lease(
        &self,
        ctx: &AgentContext,
        id: LeaseId,
    ) -> Result<ReleaseOutcome, CoreError> {
        self.ready(ctx, Scope::Requests, routes::RELEASE_LEASE)
            .await?;
        self.engine().release_lease(ctx, id).await
    }
}

fn items_len(items: &[ItemSummary]) -> u64 {
    u64::try_from(items.len()).unwrap_or(u64::MAX)
}

/// The catalog rows of `agent` for `query`, sorted by normalized title then ID.
fn catalog_items(
    index: &Index,
    agent: AgentId,
    query: &CatalogQuery,
    now: Timestamp,
) -> Vec<ItemSummary> {
    let visible = PolicyEngine::find_filter(index, agent, now);
    let workspace = match query.workspace.as_deref() {
        Some(name) => match index.workspace_by_slug(name) {
            Some(id) => Some(id),
            None => return Vec::new(),
        },
        None => None,
    };
    let tag = query.tag.as_deref().map(normalize);
    let q_words = query.q.as_deref().map(words).unwrap_or_default();
    let mut rows: Vec<&ItemMeta> = index
        .iter_items()
        .filter(|m| visible(m))
        .filter(|m| workspace.is_none_or(|w| w == m.workspace_id))
        .filter(|m| query.environment.is_none_or(|e| e == m.environment))
        .filter(|m| query.kind.is_none_or(|k| k == m.kind))
        .filter(|m| {
            tag.as_ref()
                .is_none_or(|t| m.tags.iter().any(|x| normalize(x) == *t))
        })
        .filter(|m| {
            q_words.iter().all(|w| {
                index
                    .items_with_word(w)
                    .is_some_and(|ids| ids.contains(&m.id))
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        normalize(&a.title)
            .cmp(&normalize(&b.title))
            .then(a.id.cmp(&b.id))
    });
    rows.into_iter()
        .map(|meta| ItemSummary::of(meta, index))
        .collect()
}
