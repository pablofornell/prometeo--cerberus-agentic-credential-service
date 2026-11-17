//! The policy engine: the state around [`super::evaluate`] and the secret read path.
//!
//! Locking rules:
//! - Each call takes the vault read guard once, for the call only, and never takes it twice (a
//!   second read while a lock waits would deadlock on the fair `RwLock`).
//! - No call holds the guard across a long wait. Approval waits release it between checks
//!   (`crate::approvals`).
//! - `lease_gate` serializes the read-change-write of lease rows, so two reads cannot both use the
//!   last use of a lease. `request_gate` does the same for request dedupe and the pending cap.

use std::sync::{Mutex, PoisonError};

use cerberus_crypto::SecretBytes;
use cerberus_store::{LeaseRow, LeaseSource, StoreError};
use cerberus_types::{AgentId, ApprovalOption, GrantId, GrantMode, ItemId, LeaseId, Permission};
use jiff::{SignedDuration, Timestamp};

use super::body::decode_grant;
use super::limits::{LimitHit, Peek, ReadLimiter};
use super::settings::{POLICY_SETTINGS_KEY, PolicySettings};
use super::{Decision, EvalInput, Grant, PolicyItem, Selector, evaluate};
use crate::approvals::AccessRequestView;
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::index::{Index, ItemMeta};
use crate::leases::{self, LeaseCheck, LeaseView};
use crate::vault::{CoreEvent, Unlocked, VaultService};

/// The result of a secret read check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretAccess {
    /// The read may go ahead now. The lease use is already counted and audited; the caller reads
    /// the secret and writes `item.reveal` (or `ssh.prepare`).
    Granted {
        /// The lease that covers the read.
        lease: LeaseView,
        /// The grant that allowed it.
        grant_id: GrantId,
    },
    /// A person must decide first (`202`). The agent polls or waits on the request.
    Pending(AccessRequestView),
}

/// What the agent asks for on a secret route.
#[derive(Clone, Copy, Debug)]
pub struct SecretAsk<'a> {
    /// The item.
    pub item_id: ItemId,
    /// `read` or `use_ssh`.
    pub permission: Permission,
    /// The reason or purpose text (untrusted; presence only for policy).
    pub reason: Option<&'a str>,
    /// A lease the agent wants to use.
    pub lease_id: Option<LeaseId>,
    /// TTL the agent asks for when an approval is needed (60 to 86400 s).
    pub requested_ttl_seconds: Option<u32>,
}

/// The in-memory state of the engine. It lives in the vault service (one per service), so every
/// [`PolicyEngine`] of a service shares it and the service can reach the engine without an `Arc`
/// cycle.
#[derive(Debug, Default)]
pub(crate) struct EngineState {
    pub(crate) limiter: ReadLimiter,
    /// Settings cache (see [`SettingsCache`]).
    pub(crate) settings: Mutex<SettingsCache>,
    pub(crate) lease_gate: tokio::sync::Mutex<()>,
    pub(crate) request_gate: tokio::sync::Mutex<()>,
    /// End of the last lease expiry scan (`lease.expire` events). `None` until the first scan of
    /// this process, which reads the stored mark.
    pub(crate) expiry_mark: Mutex<Option<Timestamp>>,
}

/// The policy settings cache. `generation` grows on every save, so a load that read the row
/// before a save never puts its stale value over the saved one (DEC-FIX7-7).
#[derive(Debug, Default)]
pub(crate) struct SettingsCache {
    /// Unlock time of the session the value belongs to, and the value.
    value: Option<(Timestamp, PolicySettings)>,
    /// Number of saves so far.
    generation: u64,
}

/// Policy, lease and approval engine on one vault service. Cheap to clone (it is the service).
/// Get it with [`VaultService::policy`]; every engine of one service shares one state.
#[derive(Clone)]
pub struct PolicyEngine {
    pub(crate) service: VaultService,
}

impl std::fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyEngine").finish_non_exhaustive()
    }
}

/// The audit event type for a refused or granted secret read of `permission`.
pub(crate) const fn read_event(permission: Permission) -> EventType {
    match permission {
        Permission::UseSsh => EventType::SshPrepare,
        Permission::Find | Permission::Read | Permission::CreateSession | Permission::Write => {
            EventType::ItemReveal
        }
    }
}

/// An event by the agent of `ctx`.
pub(crate) fn by_agent(event: EventType, ctx: &AgentContext) -> AuditEvent {
    AuditEvent::new(event, Actor::agent(ctx.agent_id.to_string())).request_id(ctx.request_id)
}

/// The error for a refused decision. `NoGrant` is `403` here: the caller checked `find` first.
pub(crate) fn decision_error(decision: &Decision) -> CoreError {
    match decision {
        Decision::Deny { .. } | Decision::NoGrant | Decision::Allow { .. } => CoreError::Forbidden,
        Decision::ConditionFailed { .. } => CoreError::ConditionFailed,
        Decision::ReasonRequired { .. } => CoreError::ReasonRequired,
        Decision::GrantRateLimited {
            retry_after_seconds,
            ..
        } => CoreError::GrantRateLimited {
            retry_after_seconds: *retry_after_seconds,
        },
    }
}

/// A grant that denies everything: used when a grant of the agent cannot be read (fail closed).
fn deny_all(id: GrantId, agent: AgentId) -> Grant {
    Grant {
        id,
        agent_id: agent,
        selector: Selector::default(),
        permissions: std::collections::BTreeSet::new(),
        mode: GrantMode::Deny,
        conditions: super::Conditions::default(),
        allow_prod_auto: false,
        created_at: Timestamp::UNIX_EPOCH,
        updated_at: Timestamp::UNIX_EPOCH,
    }
}

/// The parsed grants of `agent`. A body that does not parse becomes a deny-all grant, so a broken
/// deny grant can never turn into access (DEC-T07-3).
#[must_use]
pub fn agent_grants(index: &Index, agent: &AgentId) -> Vec<Grant> {
    index
        .grants_for(agent)
        .iter()
        .map(|entry| decode_grant(entry).unwrap_or_else(|_| deny_all(entry.id, *agent)))
        .collect()
}

/// True when the item has not passed its own expiry.
pub(crate) fn item_live(meta: &ItemMeta, now: Timestamp) -> bool {
    meta.expires_at.is_none_or(|end| now < end)
}

impl PolicyEngine {
    /// The engine of `service` (the same as [`VaultService::policy`]).
    #[must_use]
    pub fn new(service: VaultService) -> Self {
        Self { service }
    }

    /// The vault service.
    #[must_use]
    pub fn service(&self) -> &VaultService {
        &self.service
    }

    pub(crate) fn state(&self) -> &EngineState {
        self.service.policy_state()
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.service.clock().now()
    }

    /// The settings of the current session. Loads the sealed row once per unlock. A missing row
    /// gives the defaults; a row that does not open or parse gives the defaults and an alert.
    pub(crate) async fn settings_in(&self, unlocked: &Unlocked) -> PolicySettings {
        let key = unlocked.session.unlocked_at;
        let generation = {
            let cache = self.lock_settings();
            if let Some((at, value)) = cache.value
                && at == key
            {
                return value;
            }
            cache.generation
        };
        let value = match self.service.store().setting(POLICY_SETTINGS_KEY).await {
            Ok(row) => {
                let parsed = unlocked
                    .blobs()
                    .open_setting(POLICY_SETTINGS_KEY, &row.value_ct)
                    .ok()
                    .and_then(|plain| {
                        serde_json::from_slice::<PolicySettings>(plain.expose_secret()).ok()
                    })
                    .filter(|s| s.validate().is_ok());
                match parsed {
                    Some(value) => value,
                    None => {
                        // ADR-0033 point 5: the UI alert and the chain event, then the defaults.
                        self.mac_alert(unlocked, "settings", POLICY_SETTINGS_KEY.to_owned())
                            .await;
                        PolicySettings::default()
                    }
                }
            }
            Err(_) => PolicySettings::default(),
        };
        self.store_loaded_settings(key, generation, value)
    }

    /// Puts a loaded value in the cache unless a save came after the load started. Returns the
    /// value to use: the saved one when a save won.
    pub(crate) fn store_loaded_settings(
        &self,
        key: Timestamp,
        generation: u64,
        value: PolicySettings,
    ) -> PolicySettings {
        let mut cache = self.lock_settings();
        if cache.generation == generation {
            cache.value = Some((key, value));
            return value;
        }
        match cache.value {
            Some((at, saved)) if at == key => saved,
            _ => value,
        }
    }

    /// The save counter of the settings cache (tests).
    #[cfg(test)]
    pub(crate) fn settings_generation(&self) -> u64 {
        self.lock_settings().generation
    }

    fn lock_settings(&self) -> std::sync::MutexGuard<'_, SettingsCache> {
        self.state()
            .settings
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Called after a save committed: the saved value wins over any load still running.
    pub(crate) fn cache_settings(&self, unlocked: &Unlocked, value: PolicySettings) {
        let mut cache = self.lock_settings();
        cache.generation = cache.generation.wrapping_add(1);
        cache.value = Some((unlocked.session.unlocked_at, value));
    }

    /// Raises an integrity alert and writes `integrity.row_mac_mismatch` (ADR-0033 point 5).
    pub(crate) async fn mac_alert(&self, unlocked: &Unlocked, table: &'static str, row_id: String) {
        tracing::warn!(table, row_id = %row_id, "row MAC mismatch");
        self.service.integrity_issue(unlocked, table, row_id).await;
    }

    /// The lease rows of (agent, item) whose MAC is good. Bad rows are dropped with an alert.
    pub(crate) async fn verified_leases(
        &self,
        unlocked: &Unlocked,
        agent: AgentId,
        item: ItemId,
    ) -> Result<Vec<LeaseRow>, CoreError> {
        let rows = self.service.store().leases_for(agent, item).await?;
        let macs = unlocked.row_macs();
        let mut good = Vec::with_capacity(rows.len());
        for row in rows {
            if macs.verify_lease(&row)? {
                good.push(row);
            } else {
                self.mac_alert(unlocked, "leases", row.id.to_string()).await;
            }
        }
        Ok(good)
    }

    /// Drops approval leases from "approve for the session" that were made before the current
    /// unlock: such a lease ends at the next lock (ADR-0018). When the request row is missing or
    /// bad, the lease is dropped too (fail closed).
    pub(crate) async fn drop_old_session_leases(
        &self,
        unlocked: &Unlocked,
        rows: Vec<LeaseRow>,
        now: Timestamp,
    ) -> Result<Vec<LeaseRow>, CoreError> {
        let started = unlocked.session.unlocked_at;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let needs_check = row.source == LeaseSource::Approval
                && row.created_at < started
                && leases::is_active(&row, now);
            if !needs_check {
                out.push(row);
                continue;
            }
            let Some(request_id) = row.request_id else {
                continue;
            };
            let option = match self.service.store().access_request(request_id).await {
                Ok(req) if unlocked.row_macs().verify_access_request(&req)? => req.approval_option,
                Ok(_) => {
                    self.mac_alert(unlocked, "access_requests", request_id.to_string())
                        .await;
                    None
                }
                Err(StoreError::NotFound) => None,
                Err(error) => return Err(error.into()),
            };
            if matches!(
                option,
                Some(ApprovalOption::Once | ApprovalOption::Minutes15)
            ) {
                out.push(row);
            }
        }
        Ok(out)
    }

    /// Writes a refused secret read to the audit chain and returns `error`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn refuse(
        &self,
        unlocked: &Unlocked,
        ctx: &AgentContext,
        item: ItemId,
        permission: Permission,
        decision: &str,
        grant: Option<GrantId>,
        error: CoreError,
    ) -> CoreError {
        let mut event = by_agent(read_event(permission), ctx)
            .target("item", item.to_string())
            .result(error.code().as_str())
            .detail("permission", permission_text(permission))
            .detail("decision", decision);
        if let Some(id) = grant {
            event = event.detail("grant_id", id.to_string());
        }
        self.service.audit(unlocked, event).await;
        error
    }

    /// The secret read path for `reveal`, `totp`, `ssh-prepare` and `resolve` with a value
    /// (ADR-0017, ADR-0018, ADR-0019, ADR-0030). Takes the vault guard for this call only.
    ///
    /// # Errors
    /// `NotFound` (item missing or not visible), `Forbidden`, `ConditionFailed`,
    /// `ReasonRequired`, `GrantRateLimited`, `RateLimited`, `ApprovalDenied`,
    /// `ApprovalUnavailable`, `Validation` (bad TTL), `Locked`, or a storage error.
    pub async fn authorize_secret(
        &self,
        ctx: &AgentContext,
        ask: SecretAsk<'_>,
    ) -> Result<SecretAccess, CoreError> {
        let guard = self.service.unlocked().await?;
        self.authorize_secret_in(&guard, ctx, ask).await
    }

    /// [`Self::authorize_secret`] for a caller that already holds the vault guard.
    ///
    /// # Errors
    /// As [`Self::authorize_secret`].
    pub(crate) async fn authorize_secret_in(
        &self,
        unlocked: &Unlocked,
        ctx: &AgentContext,
        ask: SecretAsk<'_>,
    ) -> Result<SecretAccess, CoreError> {
        let now = self.now();
        let item_id = ask.item_id;
        let permission = ask.permission;
        if !super::is_secret_permission(permission) {
            return Err(CoreError::Validation(vec![cerberus_types::FieldProblem {
                field: "permission".to_owned(),
                problem: "must be read or use_ssh".to_owned(),
            }]));
        }
        let settings = self.settings_in(unlocked).await;
        let grants = agent_grants(&unlocked.index, &ctx.agent_id);
        let Some(meta) = unlocked.index.item(&item_id).filter(|m| item_live(m, now)) else {
            let error = CoreError::NotFound;
            return Err(self
                .refuse(unlocked, ctx, item_id, permission, "not_found", None, error)
                .await);
        };
        let item = PolicyItem::of(meta);
        let peek = Peek(&self.state().limiter);
        let find = evaluate(
            &EvalInput {
                grants: &grants,
                item,
                permission: Permission::Find,
                reason: None,
                now,
            },
            &ctx.agent_id,
            &peek,
        );
        if !find.is_allow() {
            let error = CoreError::NotFound;
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    item_id,
                    permission,
                    find.as_str(),
                    find.grant_id(),
                    error,
                )
                .await);
        }
        let decision = evaluate(
            &EvalInput {
                grants: &grants,
                item,
                permission,
                reason: ask.reason,
                now,
            },
            &ctx.agent_id,
            &peek,
        );
        let Decision::Allow { mode, grant_id } = decision else {
            let error = decision_error(&decision);
            return Err(self
                .refuse(
                    unlocked,
                    ctx,
                    item_id,
                    permission,
                    decision.as_str(),
                    decision.grant_id(),
                    error,
                )
                .await);
        };
        let grant_limit = grants
            .iter()
            .find(|g| g.id == grant_id)
            .and_then(|g| g.conditions.max_reads_per_hour)
            .map(|limit| (grant_id, limit));

        // Gate order: `request_gate`, then `lease_gate`. The request gate is held from the lease
        // check to the pending check of an approval, so an approval cannot land between them and
        // open a second request (AUD-22, DEC-T24-5).
        let request_gate = self.state().request_gate.lock().await;
        let gate = self.state().lease_gate.lock().await;
        let rows = self
            .verified_leases(unlocked, ctx.agent_id, item_id)
            .await?;
        let rows = self.drop_old_session_leases(unlocked, rows, now).await?;
        let outcome = match leases::check(&rows, mode, permission, now, ask.lease_id.as_ref()) {
            LeaseCheck::Active(row) => {
                self.count_read(
                    unlocked,
                    ctx,
                    meta,
                    permission,
                    grant_id,
                    grant_limit,
                    &settings,
                    now,
                )
                .await?;
                let lease = self.use_lease(unlocked, ctx, row).await?;
                SecretAccess::Granted { lease, grant_id }
            }
            LeaseCheck::NewAuto => {
                self.count_read(
                    unlocked,
                    ctx,
                    meta,
                    permission,
                    grant_id,
                    grant_limit,
                    &settings,
                    now,
                )
                .await?;
                let lease = self
                    .new_auto_lease(unlocked, ctx, meta, permission, grant_id, &settings, now)
                    .await?;
                SecretAccess::Granted { lease, grant_id }
            }
            LeaseCheck::Blocked { until } => {
                drop(gate);
                let error = CoreError::Forbidden;
                let mut event = by_agent(read_event(permission), ctx)
                    .target("item", item_id.to_string())
                    .result(error.code().as_str())
                    .detail("decision", "lease_revoked")
                    .detail("grant_id", grant_id.to_string());
                event = event.detail("blocked_until_ms", until.as_millisecond());
                self.service.audit(unlocked, event).await;
                return Err(error);
            }
            LeaseCheck::NeedApproval => {
                drop(gate);
                let view = self
                    .open_request(
                        &request_gate,
                        unlocked,
                        ctx,
                        meta,
                        permission,
                        ask.reason,
                        ask.requested_ttl_seconds,
                        &settings,
                        now,
                    )
                    .await?;
                return Ok(SecretAccess::Pending(view));
            }
        };
        drop(gate);
        Ok(outcome)
    }

    /// Counts one read in every limit, or refuses it (audited). Sends the mass-read alert.
    #[allow(clippy::too_many_arguments)]
    async fn count_read(
        &self,
        unlocked: &Unlocked,
        ctx: &AgentContext,
        meta: &ItemMeta,
        permission: Permission,
        grant_id: GrantId,
        grant_limit: Option<(GrantId, u32)>,
        settings: &PolicySettings,
        now: Timestamp,
    ) -> Result<(), CoreError> {
        let hit = match self.state().limiter.record_read(
            &ctx.agent_id,
            &meta.id,
            grant_limit,
            now,
            settings,
        ) {
            Ok(_) => return Ok(()),
            Err(hit) => hit,
        };
        let (error, decision) = match hit {
            LimitHit::Grant {
                retry_after_seconds,
            } => (
                CoreError::GrantRateLimited {
                    retry_after_seconds,
                },
                "grant_rate_limited",
            ),
            LimitHit::SecretReads {
                retry_after_seconds,
            } => (
                CoreError::RateLimited {
                    retry_after_seconds,
                },
                "secret_read_limit",
            ),
            LimitHit::DistinctItems {
                retry_after_seconds,
                distinct,
            } => {
                if self.state().limiter.take_alert(&ctx.agent_id, now) {
                    self.service.emit(CoreEvent::MassReadAlert {
                        agent_id: ctx.agent_id,
                        distinct_items: distinct,
                    });
                }
                (
                    CoreError::RateLimited {
                        retry_after_seconds,
                    },
                    "distinct_items_limit",
                )
            }
        };
        Err(self
            .refuse(
                unlocked,
                ctx,
                meta.id,
                permission,
                decision,
                Some(grant_id),
                error,
            )
            .await)
    }

    /// Adds one use to an active lease (new row MAC) and audits `lease.use`.
    async fn use_lease(
        &self,
        unlocked: &Unlocked,
        ctx: &AgentContext,
        chosen: LeaseRow,
    ) -> Result<LeaseView, CoreError> {
        // Read the row again inside the write transaction: a revoke or release that landed after
        // the check must win, and must never be overwritten by the older copy.
        let macs = unlocked.row_macs();
        let now = self.now();
        let mut tx = self.service.store().begin().await?;
        let mut row = tx.lease(chosen.id).await?;
        if !macs.verify_lease(&row)? {
            drop(tx);
            self.mac_alert(unlocked, "leases", chosen.id.to_string())
                .await;
            return Err(CoreError::Forbidden);
        }
        if !leases::is_active(&row, now) {
            return Err(CoreError::Forbidden);
        }
        row.uses = row.uses.saturating_add(1);
        macs.sign_lease(&mut row)?;
        tx.put_lease(&row).await?;
        tx.commit().await?;
        let view = LeaseView::of(&row);
        let mut event = by_agent(EventType::LeaseUse, ctx)
            .target("lease", row.id.to_string())
            .detail("item_id", row.item_id.to_string())
            .detail("uses", row.uses);
        if let Some(left) = view.uses_left {
            event = event.detail("uses_left", left);
        }
        self.service.audit(unlocked, event).await;
        self.service.emit(CoreEvent::LeaseChanged(row.id));
        Ok(view)
    }

    /// Makes a new auto lease that already counts this read (DEC-018, ADR-0019 point 5).
    #[allow(clippy::too_many_arguments)]
    async fn new_auto_lease(
        &self,
        unlocked: &Unlocked,
        ctx: &AgentContext,
        meta: &ItemMeta,
        permission: Permission,
        grant_id: GrantId,
        settings: &PolicySettings,
        now: Timestamp,
    ) -> Result<LeaseView, CoreError> {
        let ttl = SignedDuration::from_secs(i64::from(settings.lease_ttl_auto_seconds));
        let mut row = LeaseRow {
            id: LeaseId::generate(),
            agent_id: ctx.agent_id,
            item_id: meta.id,
            permission,
            source: LeaseSource::Auto,
            request_id: None,
            created_at: whole_ms(now),
            expires_at: whole_ms(leases::auto_expiry(ttl, meta.expires_at, now)),
            max_uses: None,
            uses: 1,
            released_at: None,
            revoked_at: None,
            revoked_by: None,
            row_mac: [0; 32],
        };
        unlocked.row_macs().sign_lease(&mut row)?;
        let mut tx = self.service.store().begin().await?;
        tx.put_lease(&row).await?;
        tx.commit().await?;
        let create = by_agent(EventType::LeaseCreate, ctx)
            .target("lease", row.id.to_string())
            .detail("item_id", meta.id.to_string())
            .detail("source", "auto")
            .detail("permission", permission_text(permission))
            .detail("grant_id", grant_id.to_string())
            .detail("expires_at_ms", row.expires_at.as_millisecond());
        self.service.audit(unlocked, create).await;
        let used = by_agent(EventType::LeaseUse, ctx)
            .target("lease", row.id.to_string())
            .detail("item_id", meta.id.to_string())
            .detail("uses", row.uses);
        self.service.audit(unlocked, used).await;
        self.service.emit(CoreEvent::LeaseChanged(row.id));
        Ok(LeaseView::of(&row))
    }

    /// The parsed grants of `agent` in the current index (fail closed, see [`agent_grants`]).
    ///
    /// # Errors
    /// [`CoreError::Locked`].
    pub async fn grants_of(&self, agent: &AgentId) -> Result<Vec<Grant>, CoreError> {
        let guard = self.service.unlocked().await?;
        Ok(agent_grants(&guard.index, agent))
    }

    /// A visibility filter for resolve and catalog: true when policy gives `find` on the item.
    /// Build it from a guard the caller holds; it takes no lock itself.
    pub fn find_filter(
        index: &Index,
        agent: AgentId,
        now: Timestamp,
    ) -> impl Fn(&ItemMeta) -> bool {
        let grants = agent_grants(index, &agent);
        move |meta: &ItemMeta| item_live(meta, now) && super::can_find(&grants, &agent, meta, now)
    }

    /// The policy decision on an existing or proposed item, for `find`, `write` and
    /// `create_session` checks. It never counts a read (the grant read limit is only checked).
    /// Refusals are audited by the caller with its own event (`item.create`); this writes nothing.
    /// Secret reads must use [`Self::authorize_secret`].
    #[must_use]
    pub fn decide(
        &self,
        index: &Index,
        agent: &AgentId,
        item: PolicyItem<'_>,
        permission: Permission,
        reason: Option<&str>,
        now: Timestamp,
    ) -> Decision {
        let grants = agent_grants(index, agent);
        evaluate(
            &EvalInput {
                grants: &grants,
                item,
                permission,
                reason,
                now,
            },
            agent,
            &Peek(&self.state().limiter),
        )
    }
}

/// The text form of a permission, for audit details.
pub(crate) fn permission_text(permission: Permission) -> &'static str {
    match permission {
        Permission::Find => "find",
        Permission::Read => "read",
        Permission::CreateSession => "create_session",
        Permission::Write => "write",
        Permission::UseSsh => "use_ssh",
    }
}

/// `ts` cut to whole milliseconds, as the store keeps it (so views match stored rows).
pub(crate) fn whole_ms(ts: Timestamp) -> Timestamp {
    Timestamp::from_millisecond(ts.as_millisecond()).unwrap_or(ts)
}

/// Opens a sealed setting value the engine wrote (test and settings helpers).
pub(crate) fn settings_json(value: &PolicySettings) -> Result<SecretBytes, CoreError> {
    serde_json::to_vec(value)
        .map(SecretBytes::new)
        .map_err(|_| CoreError::Corrupt)
}
