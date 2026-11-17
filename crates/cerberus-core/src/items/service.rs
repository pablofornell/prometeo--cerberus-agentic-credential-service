//! Item create, change, delete, versions, reveal and TOTP on the vault service (ADR-0027).
//!
//! Every write goes to the database first and then to the index (ADR-0006). A write holds the
//! write guard of the unlocked state for its whole run, so two calls cannot interleave. The
//! methods here do no policy check: the caller (Agent API) runs policy first. Operator methods
//! check the role (ADR-0009). Items an agent creates carry `created_by = agent:<id>`.

use std::collections::BTreeMap;

use cerberus_store::{
    ItemRow, ItemVersionRow, LeaseRow, LeaseSource, SealedPayload, SettingRow, StoreError,
};
use cerberus_types::{
    AgentId, Environment, FieldProblem, ItemId, ItemKind, LeaseId, OperatorRole, WorkspaceId,
};
use jiff::Timestamp;
use zeroize::Zeroizing;

use super::payload::Payload;
use super::settings::{ItemSettings, setting_keys};
use super::ssh::SshMeta;
use super::summary::ItemSummary;
use super::totp::{TotpCode, totp_now};
use super::validate::{normalize_input, validate_fields, validate_item, validate_payload};
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::{AgentContext, OperatorContext};
use crate::error::CoreError;
use crate::index::{CreatedBy, Index, ItemMeta, decode_item_meta, encode_item_meta, normalize};
use crate::policy::engine::whole_ms;
use crate::vault::Unlocked;
use crate::vault::VaultService;

/// Input for creating or replacing an item. The kind is the kind of `payload`. `P` is
/// [`Payload`] for a create and [`PayloadChange`] for an update ([`ItemUpdate`]).
#[derive(Debug)]
pub struct ItemInput<P = Payload> {
    /// Workspace of the item. It must exist.
    pub workspace_id: WorkspaceId,
    /// Title, 1..200 characters. Unique per workspace (normalized).
    pub title: String,
    /// Description, 0..2000 characters.
    pub description: String,
    /// Role label, for example `admin`.
    pub role_label: Option<String>,
    /// Category, for example `Web login`.
    pub category: String,
    /// Tags, at most 20.
    pub tags: Vec<String>,
    /// Environment.
    pub environment: Environment,
    /// Target: URL, host, machine name or app name.
    pub target: Option<String>,
    /// Extra facts by name (at most 20). SSH keys use `machine`, `host`, `port`, `user`.
    pub custom: BTreeMap<String, String>,
    /// End of life. Session kinds get the default TTL when it is `None`.
    pub expires_at: Option<Timestamp>,
    /// Number of reveals after which the item is deleted.
    pub max_uses: Option<u32>,
    /// The secret part.
    pub payload: P,
}

impl ItemInput {
    /// The kind of the item.
    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        self.payload.kind()
    }
}

/// What an update does with the secret part of an item.
#[derive(Debug)]
pub enum PayloadChange {
    /// Leave the stored secret as it is: a metadata-only update (DEC-INT10-6).
    Keep,
    /// Seal this payload as a new version. It must have the kind of the item.
    Replace(Payload),
}

/// Input of [`VaultService::update_item`].
pub type ItemUpdate = ItemInput<PayloadChange>;

impl From<ItemInput> for ItemUpdate {
    fn from(input: ItemInput) -> Self {
        Self {
            workspace_id: input.workspace_id,
            title: input.title,
            description: input.description,
            role_label: input.role_label,
            category: input.category,
            tags: input.tags,
            environment: input.environment,
            target: input.target,
            custom: input.custom,
            expires_at: input.expires_at,
            max_uses: input.max_uses,
            payload: PayloadChange::Replace(input.payload),
        }
    }
}

/// An item as the admin UI sees it: metadata and counters, no payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemDetail {
    /// The metadata.
    pub summary: ItemSummary,
    /// Current version number.
    pub version: u32,
    /// Reveals so far.
    pub use_count: u32,
    /// Reveal limit.
    pub max_uses: Option<u32>,
    /// Agents the secret was exposed to, with the time of the latest exposure, newest first
    /// (ADR-0019 point 10). An agent is listed when it has a lease on the item that is active
    /// (it can read now) or that was used at least once. Revoke does not remove it: the value
    /// may still be with the agent, so the UI suggests a rotation.
    pub exposed_to: Vec<(AgentId, Timestamp)>,
}

/// A policy check for an agent create, run under the write guard on the proposed metadata
/// (ADR-0017 rule 5). It returns the refusal and the policy decision name for the audit event.
pub(crate) type CreateCheck<'a> =
    &'a (dyn Fn(&Index, &ItemMeta) -> Result<(), (CoreError, &'static str)> + Sync);

/// One entry of the version history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemVersionInfo {
    /// Version number.
    pub version: u32,
    /// When the version was made.
    pub created_at: Timestamp,
    /// Title at that version.
    pub title: String,
}

/// Filter for [`VaultService::list_items`].
#[derive(Clone, Debug, Default)]
pub struct ItemFilter {
    /// Only this workspace.
    pub workspace_id: Option<WorkspaceId>,
    /// Only this environment.
    pub environment: Option<Environment>,
    /// Only this kind.
    pub kind: Option<ItemKind>,
    /// Only items with this tag (normalized compare).
    pub tag: Option<String>,
    /// Free text: every word must appear in title, description, role label, tags or target.
    pub q: Option<String>,
}

/// The secret of an item, after a counted or an uncounted read.
#[derive(Debug)]
pub struct RevealedItem {
    /// The metadata.
    pub summary: ItemSummary,
    /// The payload. Convert it to a response before it is dropped.
    pub payload: Payload,
    /// Reveals so far, including this one when it was counted.
    pub use_count: u32,
    /// True when this read used the last allowed reveal and the item is now deleted.
    pub exhausted: bool,
    /// Machine, host, port and user of an SSH key item (from the metadata); `None` for other
    /// kinds.
    pub ssh: Option<SshMeta>,
}

/// Leases a version change ended, and lease rows it left alone for a bad MAC.
#[derive(Default)]
struct EndedLeases {
    revoked: Vec<LeaseRow>,
    bad_mac: Vec<LeaseId>,
}

/// How a change reaches the database.
enum Commit<'a> {
    /// A new version row. Only the newest `keep` versions stay.
    NewVersion {
        row: &'a ItemRow,
        version: &'a ItemVersionRow,
        keep: u32,
    },
    /// The current version stays. The metadata blobs of the item row and of that version are
    /// replaced (`snapshot_ct` is the new snapshot).
    InPlace {
        row: &'a ItemRow,
        snapshot_ct: Vec<u8>,
    },
}

impl Commit<'_> {
    const fn row(&self) -> &ItemRow {
        match self {
            Self::NewVersion { row, .. } | Self::InPlace { row, .. } => row,
        }
    }
}

#[derive(Clone, Copy)]
enum Who<'a> {
    Operator(&'a OperatorContext),
    Agent(&'a AgentContext),
}

impl Who<'_> {
    fn created_by(self) -> CreatedBy {
        match self {
            Self::Operator(ctx) => CreatedBy::Operator(ctx.operator_id),
            Self::Agent(ctx) => CreatedBy::Agent(ctx.agent_id),
        }
    }

    fn event(self, event: EventType, item: ItemId) -> AuditEvent {
        let (actor, request_id) = match self {
            Self::Operator(ctx) => (Actor::operator(ctx.operator_id.to_string()), ctx.request_id),
            Self::Agent(ctx) => (Actor::agent(ctx.agent_id.to_string()), ctx.request_id),
        };
        AuditEvent::new(event, actor)
            .request_id(request_id)
            .target("item", item.to_string())
    }
}

fn field(name: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: name.to_owned(),
        problem: text.to_owned(),
    }])
}

/// A row that is gone (deleted or expired between the index check and the read) is `NotFound`.
fn from_store(error: StoreError) -> CoreError {
    match error {
        StoreError::NotFound => CoreError::NotFound,
        other => other.into(),
    }
}

fn problems_to_result(problems: Vec<FieldProblem>) -> Result<(), CoreError> {
    if problems.is_empty() {
        Ok(())
    } else {
        Err(CoreError::Validation(problems))
    }
}

fn kind_json(kind: ItemKind) -> serde_json::Value {
    serde_json::to_value(kind).unwrap_or(serde_json::Value::Null)
}

fn expired(meta: &ItemMeta, now: Timestamp) -> bool {
    meta.expires_at.is_some_and(|at| now >= at)
}

/// The other live items of `workspace` with the same normalized title.
fn clashing_titles<'a>(
    index: &'a Index,
    workspace: &WorkspaceId,
    title: &str,
    except: Option<&'a ItemId>,
    now: Timestamp,
) -> impl Iterator<Item = &'a ItemMeta> {
    let wanted = normalize(title);
    index
        .items_in_workspace(workspace)
        .into_iter()
        .flatten()
        .filter(move |id| Some(*id) != except)
        .filter_map(|id| index.item(id))
        .filter(move |m| !expired(m, now) && normalize(&m.title) == wanted)
}

/// True when another live item of `workspace` has the same normalized title.
pub(super) fn title_taken(
    index: &Index,
    workspace: &WorkspaceId,
    title: &str,
    except: Option<&ItemId>,
    now: Timestamp,
) -> bool {
    clashing_titles(index, workspace, title, except, now)
        .next()
        .is_some()
}

/// True when an operator change moves the item to a title in use. Keeping the title and the
/// workspace is always fine: an agent may have made a twin it could not see (DEC-FIX7-3).
fn moves_to_used_title(
    index: &Index,
    old: &ItemMeta,
    workspace: &WorkspaceId,
    title: &str,
    now: Timestamp,
) -> bool {
    let same = old.workspace_id == *workspace && normalize(&old.title) == normalize(title);
    !same && title_taken(index, workspace, title, Some(&old.id), now)
}

/// `shape` is the kind and the TOTP flag of the payload the item has after the change.
fn build_meta<P>(
    id: ItemId,
    input: &ItemInput<P>,
    shape: (ItemKind, bool),
    created_by: CreatedBy,
    use_count: u32,
    expires_at: Option<Timestamp>,
    now: Timestamp,
) -> ItemMeta {
    let zs = |s: &str| Zeroizing::new(s.to_owned());
    ItemMeta {
        id,
        kind: shape.0,
        workspace_id: input.workspace_id,
        title: zs(&input.title),
        description: zs(&input.description),
        role_label: input.role_label.as_deref().map(zs),
        category: zs(&input.category),
        tags: input.tags.iter().map(|t| zs(t)).collect(),
        environment: input.environment,
        target: input.target.as_deref().map(zs),
        created_by,
        max_uses: input.max_uses,
        use_count,
        expires_at,
        updated_at: now,
        has_totp: shape.1,
        custom: input
            .custom
            .iter()
            .map(|(k, v)| (k.clone(), zs(v)))
            .collect(),
    }
}

/// Seals metadata and payload as `version` of the item.
pub(super) fn seal_version(
    unlocked: &Unlocked,
    meta: &ItemMeta,
    payload: &Payload,
    version: u32,
    created_at: Timestamp,
) -> Result<(ItemRow, ItemVersionRow), CoreError> {
    let blobs = unlocked.blobs();
    let meta_json = encode_item_meta(meta)?;
    let payload_json = payload.to_json()?;
    let sealed = blobs.seal_payload(&meta.id, version, &payload_json)?;
    let row = ItemRow {
        id: meta.id,
        kind: meta.kind,
        expires_at: meta.expires_at,
        created_at,
        updated_at: meta.updated_at,
        current_version: version,
        meta_ct: blobs.seal_item_meta(&meta.id, version, &meta_json)?,
    };
    let version_row = ItemVersionRow {
        item_id: meta.id,
        version,
        created_at: meta.updated_at,
        wrapped_dek: sealed.wrapped_dek,
        payload_ct: sealed.payload_ct,
        meta_ct: blobs.seal_item_snapshot(&meta.id, version, &meta_json)?,
    };
    Ok((row, version_row))
}

impl VaultService {
    async fn read_setting_u32(
        &self,
        unlocked: &Unlocked,
        key: &str,
    ) -> Result<Option<u32>, CoreError> {
        let row = match self.store().setting(key).await {
            Ok(row) => row,
            Err(StoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let parsed = unlocked
            .blobs()
            .open_setting(key, &row.value_ct)
            .ok()
            .and_then(|plain| serde_json::from_slice::<u32>(plain.expose_secret()).ok());
        if parsed.is_none() {
            // ADR-0033 point 5: the UI alert and `integrity.row_mac_mismatch` in the chain.
            self.integrity_issue(unlocked, "settings", key.to_owned())
                .await;
        }
        Ok(parsed)
    }

    /// Item settings with defaults for missing rows. A stored set out of range gives the defaults.
    pub(crate) async fn load_item_settings(
        &self,
        unlocked: &Unlocked,
    ) -> Result<ItemSettings, CoreError> {
        let d = ItemSettings::default();
        let value = ItemSettings {
            session_ttl_default_seconds: self
                .read_setting_u32(unlocked, setting_keys::SESSION_TTL_DEFAULT_SECONDS)
                .await?
                .unwrap_or(d.session_ttl_default_seconds),
            session_ttl_max_seconds: self
                .read_setting_u32(unlocked, setting_keys::SESSION_TTL_MAX_SECONDS)
                .await?
                .unwrap_or(d.session_ttl_max_seconds),
            versions_keep: self
                .read_setting_u32(unlocked, setting_keys::ITEM_VERSIONS_KEEP)
                .await?
                .unwrap_or(d.versions_keep),
        };
        Ok(if value.validate().is_ok() { value } else { d })
    }

    /// The item settings. Any role.
    ///
    /// # Errors
    /// [`CoreError::Locked`], the role check, or a storage error.
    pub async fn item_settings(&self, ctx: &OperatorContext) -> Result<ItemSettings, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        self.load_item_settings(&guard).await
    }

    /// Saves the item settings. Owner only (ADR-0009).
    ///
    /// # Errors
    /// [`CoreError::Validation`] for out-of-range values, [`CoreError::Locked`], the role check,
    /// or a storage error.
    pub async fn set_item_settings(
        &self,
        ctx: &OperatorContext,
        value: ItemSettings,
    ) -> Result<(), CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        value.validate()?;
        let now = self.clock().now();
        let blobs = guard.blobs();
        let entries = [
            (
                setting_keys::SESSION_TTL_DEFAULT_SECONDS,
                value.session_ttl_default_seconds,
            ),
            (
                setting_keys::SESSION_TTL_MAX_SECONDS,
                value.session_ttl_max_seconds,
            ),
            (setting_keys::ITEM_VERSIONS_KEEP, value.versions_keep),
        ];
        let mut tx = self.store().begin().await?;
        for (key, number) in entries {
            let plain = serde_json::to_vec(&number).map_err(|_| CoreError::Corrupt)?;
            tx.put_setting(&SettingRow {
                key: key.to_owned(),
                updated_at: now,
                value_ct: blobs.seal_setting(key, &plain)?,
            })
            .await?;
        }
        tx.commit().await?;
        let event = AuditEvent::new(
            EventType::SettingsChange,
            Actor::operator(ctx.operator_id.to_string()),
        )
        .request_id(ctx.request_id)
        .target("settings", "items");
        self.audit(&guard, event).await;
        Ok(())
    }

    /// The expiry for an agent call with `ttl_seconds` (ADR-0007). Put the result in
    /// [`ItemInput::expires_at`].
    ///
    /// # Errors
    /// [`CoreError::Validation`] (field `ttl_seconds`), [`CoreError::Locked`], or a storage error.
    pub async fn expiry_from_ttl(
        &self,
        kind: ItemKind,
        ttl_seconds: Option<u64>,
    ) -> Result<Option<Timestamp>, CoreError> {
        let guard = self.unlocked().await?;
        let settings = self.load_item_settings(&guard).await?;
        settings
            .expiry_from_ttl(kind, ttl_seconds, self.clock().now())
            .map_err(CoreError::Validation)
    }

    /// Creates an item as an operator. Role operator or owner.
    ///
    /// # Errors
    /// [`CoreError::Validation`], [`CoreError::Conflict`] (title already used in the workspace),
    /// [`CoreError::Locked`], the role check, or a storage error.
    pub async fn create_item_as_operator(
        &self,
        ctx: &OperatorContext,
        input: ItemInput,
    ) -> Result<ItemDetail, CoreError> {
        self.create(Who::Operator(ctx), input, None).await
    }

    /// Creates an item for an agent. `check` is the policy check (`write` or `create_session`)
    /// of the Agent API; it runs under the write guard, and a refusal writes `item.create` with
    /// the error code.
    ///
    /// # Errors
    /// As [`Self::create_item_as_operator`] without the role check, plus the refusal of `check`.
    pub(crate) async fn create_item_as_agent(
        &self,
        ctx: &AgentContext,
        input: ItemInput,
        check: CreateCheck<'_>,
    ) -> Result<ItemDetail, CoreError> {
        self.create(Who::Agent(ctx), input, Some(check)).await
    }

    async fn write_guard(
        &self,
        who: Who<'_>,
    ) -> Result<tokio::sync::RwLockMappedWriteGuard<'_, Unlocked>, CoreError> {
        let guard = self.unlocked_mut().await?;
        if let Who::Operator(ctx) = who {
            guard.session.authorize(ctx, OperatorRole::Operator)?;
        }
        Ok(guard)
    }

    async fn create(
        &self,
        who: Who<'_>,
        input: ItemInput,
        check: Option<CreateCheck<'_>>,
    ) -> Result<ItemDetail, CoreError> {
        let input = normalize_input(input);
        validate_item(&input).map_err(CoreError::Validation)?;
        let mut guard = self.write_guard(who).await?;
        let now = self.clock().now();
        let settings = self.load_item_settings(&guard).await?;
        let expires_at = settings
            .expiry(input.kind(), input.expires_at, now)
            .map_err(CoreError::Validation)?;
        let id = ItemId::generate();
        let shape = (input.kind(), input.payload.has_totp());
        let meta = build_meta(id, &input, shape, who.created_by(), 0, expires_at, now);
        // An agent create runs policy first, and then never tells it a fact about items or
        // workspaces it cannot see (DEC-FIX7-3): an unknown workspace is the same `Forbidden` as
        // no grant, and a title clash counts only with items the agent can find.
        if let Who::Agent(ctx) = who {
            let refusal = match check.map(|check| check(&guard.index, &meta)) {
                Some(Err(refusal)) => Some(refusal),
                _ if guard.index.workspace(&input.workspace_id).is_none() => {
                    Some((CoreError::Forbidden, "unknown_workspace"))
                }
                _ => None,
            };
            if let Some((error, decision)) = refusal {
                let event = AuditEvent::new(
                    EventType::ItemCreate,
                    Actor::agent(ctx.agent_id.to_string()),
                )
                .request_id(ctx.request_id)
                .result(error.code().as_str())
                .detail("kind", kind_json(meta.kind))
                .detail("decision", decision);
                self.audit(&guard, event).await;
                return Err(error);
            }
            let sees = crate::policy::PolicyEngine::find_filter(&guard.index, ctx.agent_id, now);
            let clash = clashing_titles(&guard.index, &input.workspace_id, &input.title, None, now)
                .any(sees);
            if clash {
                return Err(CoreError::Conflict);
            }
        } else {
            if guard.index.workspace(&input.workspace_id).is_none() {
                return Err(field("workspace_id", "is not a known workspace"));
            }
            if title_taken(&guard.index, &input.workspace_id, &input.title, None, now) {
                return Err(CoreError::Conflict);
            }
        }
        let (row, version) = seal_version(&guard, &meta, &input.payload, 1, now)?;
        let mut tx = self.store().begin().await?;
        tx.insert_item(&row, &version).await?;
        tx.commit().await?;
        guard.index.upsert_item_at(meta.clone(), 1);
        let event = who
            .event(EventType::ItemCreate, id)
            .detail("kind", kind_json(meta.kind));
        self.audit(&guard, event).await;
        Ok(detail_of(&guard.index, &meta, 1, Vec::new()))
    }

    /// Changes an item (role operator or owner). With [`PayloadChange::Replace`] the content
    /// becomes a new version. With [`PayloadChange::Keep`] only the metadata changes: the stored
    /// secret, its ciphertext and the version number stay, the metadata blobs of the current
    /// version are replaced, and no reveal is audited (DEC-INT10-6). The kind cannot change.
    /// `use_count` stays.
    ///
    /// # Errors
    /// [`CoreError::NotFound`], [`CoreError::Validation`], [`CoreError::Conflict`],
    /// [`CoreError::Locked`], the role check, or a storage error.
    pub async fn update_item(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
        input: impl Into<ItemUpdate>,
    ) -> Result<ItemDetail, CoreError> {
        let who = Who::Operator(ctx);
        let input = normalize_input(input.into());
        let replace = matches!(input.payload, PayloadChange::Replace(_));
        if let PayloadChange::Replace(payload) = &input.payload {
            let mut problems = validate_fields(&input, payload.kind());
            problems.extend(validate_payload(payload));
            problems_to_result(problems)?;
        }
        let mut guard = self.write_guard(who).await?;
        let now = self.clock().now();
        let (old, current) = self.checked_item(&guard, id).await?;
        let kind = match &input.payload {
            PayloadChange::Replace(payload) => payload.kind(),
            PayloadChange::Keep => old.kind,
        };
        if old.kind != kind {
            return Err(field("payload", "the kind of an item cannot change"));
        }
        if !replace {
            problems_to_result(validate_fields(&input, kind))?;
        }
        if guard.index.workspace(&input.workspace_id).is_none() {
            return Err(field("workspace_id", "is not a known workspace"));
        }
        if moves_to_used_title(&guard.index, &old, &input.workspace_id, &input.title, now) {
            return Err(CoreError::Conflict);
        }
        if input.max_uses.is_some_and(|m| old.use_count >= m) {
            return Err(field("max_uses", "must be above the uses so far"));
        }
        let settings = self.load_item_settings(&guard).await?;
        let expires_at = settings
            .expiry(kind, input.expires_at, now)
            .map_err(CoreError::Validation)?;
        let has_totp = match &input.payload {
            PayloadChange::Replace(payload) => payload.has_totp(),
            PayloadChange::Keep => old.has_totp,
        };
        let meta = build_meta(
            id,
            &input,
            (kind, has_totp),
            old.created_by,
            old.use_count,
            expires_at,
            now,
        );
        let (version, ended) = match &input.payload {
            PayloadChange::Replace(payload) => {
                let version = current.current_version + 1;
                let (mut row, version_row) = seal_version(&guard, &meta, payload, version, now)?;
                row.created_at = current.created_at;
                let write = Commit::NewVersion {
                    row: &row,
                    version: &version_row,
                    keep: settings.keep_for(meta.kind),
                };
                (
                    version,
                    self.commit(&guard, ctx, (&old, &meta), &current, write)
                        .await?,
                )
            }
            PayloadChange::Keep => {
                let version = current.current_version;
                let blobs = guard.blobs();
                let json = encode_item_meta(&meta)?;
                let row = ItemRow {
                    id,
                    kind: meta.kind,
                    expires_at: meta.expires_at,
                    created_at: current.created_at,
                    updated_at: now,
                    current_version: version,
                    meta_ct: blobs.seal_item_meta(&id, version, &json)?,
                };
                let write = Commit::InPlace {
                    row: &row,
                    snapshot_ct: blobs.seal_item_snapshot(&id, version, &json)?,
                };
                (
                    version,
                    self.commit(&guard, ctx, (&old, &meta), &current, write)
                        .await?,
                )
            }
        };
        guard.index.upsert_item_at(meta.clone(), version);
        let event = change_details(
            who.event(EventType::ItemUpdate, id)
                .detail("version", version),
            &old,
            &meta,
        );
        let event = if replace {
            event
        } else {
            event.detail("payload", "kept")
        };
        self.audit(&guard, event).await;
        self.report_ended_leases(&guard, ctx, ended).await;
        let exposed = self.exposure(&guard, id).await?;
        Ok(detail_of(&guard.index, &meta, version, exposed))
    }

    /// Writes a change of an item. When the change moves the item to another environment or
    /// workspace, the same transaction ends (revokes) its live approval leases: a person approved
    /// the read of the item as it was (DEC-FIX7-1). Auto leases stay; they serve only `auto`, and
    /// the read path checks the mode at each use. The write guard keeps every other lease writer
    /// out, so the rows read here cannot change before the transaction.
    ///
    /// `current` is the checked item row before the change: the write is refused when the stored
    /// row is no longer that row. Returns the ended leases and the IDs of rows with a bad MAC
    /// (left as they are).
    async fn commit(
        &self,
        unlocked: &Unlocked,
        ctx: &OperatorContext,
        (old, new): (&ItemMeta, &ItemMeta),
        current: &ItemRow,
        write: Commit<'_>,
    ) -> Result<EndedLeases, CoreError> {
        let row = write.row();
        let moved = old.environment != new.environment || old.workspace_id != new.workspace_id;
        let candidates = if moved {
            self.store().leases_of_item(row.id).await?
        } else {
            Vec::new()
        };
        let macs = unlocked.row_macs();
        let now = self.clock().now();
        let mut ended = EndedLeases::default();
        let mut tx = self.store().begin().await?;
        // The row was checked against the index; it must be the same row inside the write.
        if tx.item(row.id).await.map_err(from_store)? != *current {
            return Err(CoreError::Corrupt);
        }
        match write {
            Commit::NewVersion { row, version, keep } => {
                tx.add_item_version(row, version, keep).await?;
            }
            Commit::InPlace { row, snapshot_ct } => {
                tx.update_item_meta(row).await?;
                tx.update_version_meta(row.id, row.current_version, &snapshot_ct)
                    .await?;
            }
        }
        for candidate in candidates {
            if candidate.source != LeaseSource::Approval {
                continue;
            }
            let mut lease = match tx.lease(candidate.id).await {
                Ok(lease) => lease,
                Err(StoreError::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            if !macs.verify_lease(&lease)? {
                ended.bad_mac.push(lease.id);
                continue;
            }
            if !crate::leases::is_active(&lease, now) {
                continue;
            }
            lease.revoked_at = Some(whole_ms(now));
            lease.revoked_by = Some(format!("operator:{}", ctx.operator_id));
            macs.sign_lease(&mut lease)?;
            tx.put_lease(&lease).await?;
            ended.revoked.push(lease);
        }
        tx.commit().await?;
        Ok(ended)
    }

    /// Audits the leases [`Self::commit`] ended (after its commit).
    async fn report_ended_leases(
        &self,
        unlocked: &Unlocked,
        ctx: &OperatorContext,
        ended: EndedLeases,
    ) {
        for id in ended.bad_mac {
            self.integrity_issue(unlocked, "leases", id.to_string())
                .await;
        }
        for lease in ended.revoked {
            let event = AuditEvent::new(
                EventType::LeaseRevoke,
                Actor::operator(ctx.operator_id.to_string()),
            )
            .request_id(ctx.request_id)
            .target("lease", lease.id.to_string())
            .detail("agent_id", lease.agent_id.to_string())
            .detail("item_id", lease.item_id.to_string())
            .detail("reason", "item_moved");
            self.audit(unlocked, event).await;
            self.emit(crate::vault::CoreEvent::LeaseChanged(lease.id));
        }
    }

    /// Makes version `version` the newest content as a new version (role operator or owner).
    /// Limits (`use_count`, `max_uses`) and the expiry stay as they are now.
    ///
    /// # Errors
    /// [`CoreError::NotFound`] (unknown item or version), [`CoreError::Validation`] (workspace
    /// is gone), [`CoreError::Conflict`] (title is used now), [`CoreError::Locked`], the role
    /// check, or a storage error.
    pub async fn restore_item_version(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
        version: u32,
    ) -> Result<ItemDetail, CoreError> {
        let who = Who::Operator(ctx);
        let mut guard = self.write_guard(who).await?;
        let now = self.clock().now();
        let (current_meta, current) = self.checked_item(&guard, id).await?;
        let old = self
            .store()
            .item_version(id, version)
            .await
            .map_err(from_store)?;
        let blobs = guard.blobs();
        let snapshot = blobs.open_item_snapshot(&id, version, &old.meta_ct)?;
        // A snapshot written before T27 has no sealed kind; the kind of an item never changes,
        // so the checked current kind is used, and the restored payload must have it (AUD-2).
        let (mut meta, _) = decode_item_meta(&current, &snapshot)?;
        meta.kind = current_meta.kind;
        meta.expires_at = current_meta.expires_at;
        meta.use_count = current_meta.use_count;
        meta.max_uses = current_meta.max_uses;
        meta.updated_at = now;
        let plain = blobs.open_payload(
            &id,
            version,
            &SealedPayload {
                wrapped_dek: old.wrapped_dek,
                payload_ct: old.payload_ct,
            },
        )?;
        let payload = Payload::from_json(plain.expose_secret())?;
        if payload.kind() != meta.kind {
            self.integrity_issue(&guard, "item_versions", id.to_string())
                .await;
            return Err(CoreError::Corrupt);
        }
        if guard.index.workspace(&meta.workspace_id).is_none() {
            return Err(field("workspace_id", "is not a known workspace"));
        }
        if moves_to_used_title(
            &guard.index,
            &current_meta,
            &meta.workspace_id,
            &meta.title,
            now,
        ) {
            return Err(CoreError::Conflict);
        }
        let settings = self.load_item_settings(&guard).await?;
        let new_version = current.current_version + 1;
        let (mut row, version_row) = seal_version(&guard, &meta, &payload, new_version, now)?;
        row.created_at = current.created_at;
        let write = Commit::NewVersion {
            row: &row,
            version: &version_row,
            keep: settings.keep_for(meta.kind),
        };
        let ended = self
            .commit(&guard, ctx, (&current_meta, &meta), &current, write)
            .await?;
        guard.index.upsert_item_at(meta.clone(), new_version);
        self.audit(
            &guard,
            who.event(EventType::ItemVersionRestore, id)
                .detail("restored_version", version)
                .detail("version", new_version),
        )
        .await;
        self.report_ended_leases(&guard, ctx, ended).await;
        let exposed = self.exposure(&guard, id).await?;
        Ok(detail_of(&guard.index, &meta, new_version, exposed))
    }

    /// The version history, newest first. Any role.
    ///
    /// # Errors
    /// [`CoreError::NotFound`], [`CoreError::Locked`], the role check, or a storage error.
    pub async fn item_versions(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
    ) -> Result<Vec<ItemVersionInfo>, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let (_, current_row) = self.checked_item(&guard, id).await?;
        let current = current_row.current_version;
        let blobs = guard.blobs();
        let mut out = Vec::new();
        for version in (1..=current).rev() {
            let row = match self.store().item_version(id, version).await {
                Ok(row) => row,
                Err(StoreError::NotFound) => break,
                Err(error) => return Err(error.into()),
            };
            let snapshot = blobs.open_item_snapshot(&id, version, &row.meta_ct)?;
            let (meta, _) = decode_item_meta(&current_row, &snapshot)?;
            out.push(ItemVersionInfo {
                version,
                created_at: row.created_at,
                title: meta.title.to_string(),
            });
        }
        Ok(out)
    }

    /// Deletes an item as an operator (hard delete, ADR-0027). Role operator or owner.
    ///
    /// # Errors
    /// [`CoreError::NotFound`], [`CoreError::Locked`], the role check, or a storage error.
    pub async fn delete_item_as_operator(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
    ) -> Result<(), CoreError> {
        self.delete(Who::Operator(ctx), id).await
    }

    /// Deletes an item the agent created. Policy is checked by the caller.
    ///
    /// # Errors
    /// [`CoreError::NotFound`], [`CoreError::Forbidden`] (the agent did not create the item),
    /// [`CoreError::Locked`], or a storage error.
    pub(crate) async fn delete_item_as_agent(
        &self,
        ctx: &AgentContext,
        id: ItemId,
    ) -> Result<(), CoreError> {
        self.delete(Who::Agent(ctx), id).await
    }

    async fn delete(&self, who: Who<'_>, id: ItemId) -> Result<(), CoreError> {
        let mut guard = self.write_guard(who).await?;
        let now = self.clock().now();
        let meta = live_meta(&guard.index, &id, now)?;
        if matches!(who, Who::Agent(_)) && meta.created_by != who.created_by() {
            return Err(CoreError::Forbidden);
        }
        let mut tx = self.store().begin().await?;
        tx.delete_item(id).await?;
        tx.commit().await?;
        guard.index.remove_item(&id);
        self.audit(&guard, who.event(EventType::ItemDelete, id))
            .await;
        Ok(())
    }

    /// One item. Any role.
    ///
    /// # Errors
    /// [`CoreError::NotFound`], [`CoreError::Locked`], the role check, or a storage error.
    pub async fn get_item(
        &self,
        ctx: &OperatorContext,
        id: ItemId,
    ) -> Result<ItemDetail, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let (meta, row) = self.checked_item(&guard, id).await?;
        let exposed = self.exposure(&guard, id).await?;
        Ok(detail_of(&guard.index, &meta, row.current_version, exposed))
    }

    /// The exposure list of an item (see [`ItemDetail::exposed_to`]). Lease rows with a bad MAC
    /// are left out with an integrity alert.
    async fn exposure(
        &self,
        unlocked: &Unlocked,
        id: ItemId,
    ) -> Result<Vec<(AgentId, Timestamp)>, CoreError> {
        let now = self.clock().now();
        let macs = unlocked.row_macs();
        let mut latest: BTreeMap<AgentId, Timestamp> = BTreeMap::new();
        for row in self.store().leases_of_item(id).await? {
            if !macs.verify_lease(&row)? {
                self.integrity_issue(unlocked, "leases", row.id.to_string())
                    .await;
                continue;
            }
            if row.uses == 0 && !crate::leases::is_active(&row, now) {
                continue;
            }
            let at = latest.entry(row.agent_id).or_insert(row.created_at);
            *at = (*at).max(row.created_at);
        }
        let mut out: Vec<(AgentId, Timestamp)> = latest.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Ok(out)
    }

    /// Items that match `filter`, sorted by title. Expired items are left out. Any role.
    ///
    /// # Errors
    /// [`CoreError::Locked`] or the role check.
    pub async fn list_items(
        &self,
        ctx: &OperatorContext,
        filter: ItemFilter,
    ) -> Result<Vec<ItemSummary>, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let now = self.clock().now();
        let tag = filter.tag.as_deref().map(normalize);
        let q_words: Vec<_> = filter
            .q
            .as_deref()
            .map(crate::index::words)
            .unwrap_or_default();
        let mut out: Vec<ItemSummary> = guard
            .index
            .iter_items()
            .filter(|m| !expired(m, now))
            .filter(|m| filter.workspace_id.is_none_or(|w| w == m.workspace_id))
            .filter(|m| filter.environment.is_none_or(|e| e == m.environment))
            .filter(|m| filter.kind.is_none_or(|k| k == m.kind))
            .filter(|m| {
                tag.as_ref()
                    .is_none_or(|t| m.tags.iter().any(|x| normalize(x) == *t))
            })
            .filter(|m| {
                q_words.iter().all(|w| {
                    guard
                        .index
                        .items_with_word(w)
                        .is_some_and(|ids| ids.contains(&m.id))
                })
            })
            .map(|m| ItemSummary::of(m, &guard.index))
            .collect();
        out.sort_by(|a, b| {
            normalize(&a.title)
                .cmp(&normalize(&b.title))
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// Opens the payload of an item (test helper; the Agent API and the operator reveal use
    /// [`Self::read_payload_in`] on the guard they hold).
    ///
    /// With `count_use` the read counts as a reveal (ADR-0027): `use_count` grows, and when it
    /// reaches `max_uses` the item is deleted in the same transaction. Nothing is returned when
    /// that transaction fails. Without it (an operator looking at the secret in the UI) nothing
    /// changes. The caller has run policy and, for agents, audit.
    ///
    /// # Errors
    /// [`CoreError::NotFound`] (also for an expired item), [`CoreError::Corrupt`] when a blob
    /// fails its check, [`CoreError::Locked`], or a storage error.
    #[cfg(test)]
    pub(crate) async fn read_payload(
        &self,
        id: ItemId,
        count_use: bool,
    ) -> Result<RevealedItem, CoreError> {
        let mut guard = self.unlocked_mut().await?;
        self.read_payload_in(&mut guard, id, count_use).await
    }

    /// [`Self::read_payload`] for a caller that holds the write guard (the operator reveal,
    /// which checks the session role on the same guard).
    ///
    /// # Errors
    /// As [`Self::read_payload`].
    pub(crate) async fn read_payload_in(
        &self,
        guard: &mut Unlocked,
        id: ItemId,
        count_use: bool,
    ) -> Result<RevealedItem, CoreError> {
        let (meta, row, payload) = self.open_current(guard, id).await?;
        if !count_use {
            let summary = ItemSummary::of(&meta, &guard.index);
            let ssh = ssh_of(&meta);
            return Ok(RevealedItem {
                summary,
                payload,
                use_count: meta.use_count,
                exhausted: false,
                ssh,
            });
        }
        self.count_reveal(guard, meta, row, payload, None).await
    }

    /// The counted agent reveal on the write guard the caller also used for the policy check.
    ///
    /// `event` (`item.reveal`) gets `use_count` and `exhausted` and is written strictly *before*
    /// the use is counted: so when the audit write fails nothing changes, and the last allowed
    /// reveal never deletes the item without its event in the chain (DEC-FIX7-8). A failed read
    /// writes `event` with the error code (not strict) and returns the error.
    ///
    /// # Errors
    /// As [`Self::read_payload`], or the audit error.
    pub(crate) async fn reveal_payload_in(
        &self,
        guard: &mut Unlocked,
        id: ItemId,
        event: AuditEvent,
    ) -> Result<RevealedItem, CoreError> {
        let (meta, row, payload) = match self.open_current(guard, id).await {
            Ok(parts) => parts,
            Err(error) => {
                self.audit(guard, event.result(error.code().as_str())).await;
                return Err(error);
            }
        };
        self.count_reveal(guard, meta, row, payload, Some(event))
            .await
    }

    /// The live metadata, the item row and the opened payload of the current version.
    async fn open_current(
        &self,
        guard: &Unlocked,
        id: ItemId,
    ) -> Result<(ItemMeta, ItemRow, Payload), CoreError> {
        let (meta, row) = self.checked_item(guard, id).await?;
        let version = self
            .store()
            .item_version(id, row.current_version)
            .await
            .map_err(from_store)?;
        let plain = guard.blobs().open_payload(
            &id,
            row.current_version,
            &SealedPayload {
                wrapped_dek: version.wrapped_dek,
                payload_ct: version.payload_ct,
            },
        )?;
        let payload = Payload::from_json(plain.expose_secret())?;
        if payload.kind() != meta.kind {
            self.integrity_issue(guard, "item_versions", id.to_string())
                .await;
            return Err(CoreError::Corrupt);
        }
        Ok((meta, row, payload))
    }

    /// The live metadata and the plain row of an item, after the row was checked against the
    /// index: the same kind (the index has the sealed kind, AUD-2) and the same current version
    /// (the version whose sealed metadata opened, AUD-6). A row that a file edit changed is
    /// [`CoreError::Corrupt`] with an integrity alert.
    async fn checked_item(
        &self,
        guard: &Unlocked,
        id: ItemId,
    ) -> Result<(ItemMeta, ItemRow), CoreError> {
        let meta = live_meta(&guard.index, &id, self.clock().now())?.clone();
        let row = self.store().item(id).await.map_err(from_store)?;
        if row.kind != meta.kind || guard.index.item_version(&id) != Some(row.current_version) {
            tracing::warn!(row_id = %id, "item row does not match the index");
            self.integrity_issue(guard, "items", id.to_string()).await;
            return Err(CoreError::Corrupt);
        }
        Ok((meta, row))
    }

    /// Counts one reveal (ADR-0027): `use_count` grows, and when it reaches `max_uses` the item
    /// is deleted in the same transaction. Nothing is returned when that transaction fails. With
    /// `event`, that event is written strictly before the transaction.
    async fn count_reveal(
        &self,
        guard: &mut Unlocked,
        meta: ItemMeta,
        row: ItemRow,
        payload: Payload,
        event: Option<AuditEvent>,
    ) -> Result<RevealedItem, CoreError> {
        let id = meta.id;
        let summary = ItemSummary::of(&meta, &guard.index);
        let ssh = ssh_of(&meta);
        let use_count = meta.use_count.saturating_add(1);
        let exhausted = meta.max_uses.is_some_and(|max| use_count >= max);
        let checked = row.clone();
        let mut updated = meta;
        let next = if exhausted {
            None
        } else {
            updated.use_count = use_count;
            let json = encode_item_meta(&updated)?;
            let mut next = row;
            next.meta_ct = guard
                .blobs()
                .seal_item_meta(&id, next.current_version, &json)?;
            Some(next)
        };
        let event = event.map(|e| {
            e.detail("use_count", use_count)
                .detail("exhausted", exhausted)
        });
        if let Some(event) = &event {
            self.audit_strict(guard, event.clone()).await?;
        }
        let committed = async {
            let mut tx = self.store().begin().await?;
            // The checked row must be the stored row inside the write (no change since the check).
            if tx.item(id).await.map_err(from_store)? != checked {
                return Err(CoreError::Corrupt);
            }
            match &next {
                None => {
                    tx.delete_item(id).await?;
                }
                Some(next) => tx.update_item_meta(next).await?,
            }
            tx.commit().await?;
            Ok::<(), CoreError>(())
        }
        .await;
        if let Err(error) = committed {
            if let Some(event) = event {
                // The chain already holds the reveal; say that it did not go through.
                let failed = event
                    .result(error.code().as_str())
                    .detail("stage", "count_use");
                self.audit(guard, failed).await;
            }
            return Err(error);
        }
        if exhausted {
            guard.index.remove_item(&id);
            let event = AuditEvent::new(EventType::ItemDelete, Actor::system())
                .target("item", id.to_string())
                .detail("reason", "max_uses");
            self.audit(guard, event).await;
        } else {
            guard.index.upsert_item(updated);
        }
        Ok(RevealedItem {
            summary,
            payload,
            use_count,
            exhausted,
            ssh,
        })
    }

    /// Test helper: the current TOTP code of a web login and the seconds left. The seed stays inside. It does
    /// not count as a reveal (ADR-0027 counts reveals only). The caller runs policy and audit.
    ///
    /// # Errors
    /// [`CoreError::NotFound`] (no such item, expired, or no TOTP seed), [`CoreError::Locked`],
    /// [`CoreError::Corrupt`], or a storage error.
    #[cfg(test)]
    pub(crate) async fn totp_code(&self, id: ItemId) -> Result<TotpCode, CoreError> {
        let guard = self.unlocked().await?;
        self.totp_code_in(&guard, id).await
    }

    /// [`Self::totp_code`] for a caller that holds the guard.
    ///
    /// # Errors
    /// As [`Self::totp_code`].
    pub(crate) async fn totp_code_in(
        &self,
        guard: &Unlocked,
        id: ItemId,
    ) -> Result<TotpCode, CoreError> {
        let now = self.clock().now();
        let (meta, row) = self.checked_item(guard, id).await?;
        if !meta.has_totp {
            return Err(CoreError::NotFound);
        }
        let version = self
            .store()
            .item_version(id, row.current_version)
            .await
            .map_err(from_store)?;
        let plain = guard.blobs().open_payload(
            &id,
            row.current_version,
            &SealedPayload {
                wrapped_dek: version.wrapped_dek,
                payload_ct: version.payload_ct,
            },
        )?;
        let payload = Payload::from_json(plain.expose_secret())?;
        totp_now(payload.totp().ok_or(CoreError::NotFound)?, now)
    }
}

/// Machine, host, port and user of an SSH key item; `None` for other kinds.
fn ssh_of(meta: &ItemMeta) -> Option<SshMeta> {
    (meta.kind == ItemKind::SshKey)
        .then(|| SshMeta::from_custom(|key| meta.custom.get(key).map(|v| v.as_str())))
}

/// The metadata of a live item: `NotFound` when unknown or expired.
fn live_meta<'a>(index: &'a Index, id: &ItemId, now: Timestamp) -> Result<&'a ItemMeta, CoreError> {
    index
        .item(id)
        .filter(|m| !expired(m, now))
        .ok_or(CoreError::NotFound)
}

/// Adds to `item.update` the names of the changed fields (never their values) and the old and new
/// environment and workspace (AUD-27).
fn change_details(event: AuditEvent, old: &ItemMeta, new: &ItemMeta) -> AuditEvent {
    let changed: Vec<&str> = [
        ("workspace_id", old.workspace_id != new.workspace_id),
        ("title", old.title != new.title),
        ("description", old.description != new.description),
        ("role_label", old.role_label != new.role_label),
        ("category", old.category != new.category),
        ("tags", old.tags != new.tags),
        ("environment", old.environment != new.environment),
        ("target", old.target != new.target),
        ("custom", old.custom != new.custom),
        ("expires_at", old.expires_at != new.expires_at),
        ("max_uses", old.max_uses != new.max_uses),
    ]
    .into_iter()
    .filter_map(|(name, differs)| differs.then_some(name))
    .collect();
    let env = |e: Environment| serde_json::to_value(e).unwrap_or(serde_json::Value::Null);
    event
        .detail("changed", changed)
        .detail("old_environment", env(old.environment))
        .detail("new_environment", env(new.environment))
        .detail("old_workspace_id", old.workspace_id.to_string())
        .detail("new_workspace_id", new.workspace_id.to_string())
}

fn detail_of(
    index: &Index,
    meta: &ItemMeta,
    version: u32,
    exposed_to: Vec<(AgentId, Timestamp)>,
) -> ItemDetail {
    ItemDetail {
        summary: ItemSummary::of(meta, index),
        version,
        use_count: meta.use_count,
        max_uses: meta.max_uses,
        exposed_to,
    }
}
