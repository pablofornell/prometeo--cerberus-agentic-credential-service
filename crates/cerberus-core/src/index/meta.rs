//! Decrypted metadata held by the index, and the JSON form inside the sealed columns.
//!
//! Text fields are `Zeroizing<String>`, so dropping the index erases them (ADR-0006 point 4).
//! `Debug` shows IDs only: titles and tags are protected metadata and never go to a log (ADR-0032).
//! Times inside the JSON are Unix milliseconds, like the plain columns (ADR-0022 point 6).

use std::collections::BTreeMap;
use std::fmt;

use cerberus_crypto::SecretBytes;
use cerberus_store::{GrantRow, ItemRow, WorkspaceRow};
use cerberus_types::{AgentId, Environment, GrantId, ItemId, ItemKind, OperatorId, WorkspaceId};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CoreError;

/// Who made an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatedBy {
    /// A person, by operator ID.
    Operator(OperatorId),
    /// An agent.
    Agent(AgentId),
}

/// Metadata of one item (the opened `items.meta_ct` and the plain times). The kind is sealed in
/// `meta_ct` too and checked against the plain column (AUD-2).
#[derive(Clone)]
pub struct ItemMeta {
    /// Item ID.
    pub id: ItemId,
    /// Item kind.
    pub kind: ItemKind,
    /// Workspace of the item.
    pub workspace_id: WorkspaceId,
    /// Title.
    pub title: Zeroizing<String>,
    /// Description.
    pub description: Zeroizing<String>,
    /// Role label, for example "admin".
    pub role_label: Option<Zeroizing<String>>,
    /// Category.
    pub category: Zeroizing<String>,
    /// Tags.
    pub tags: Vec<Zeroizing<String>>,
    /// Environment.
    pub environment: Environment,
    /// Target URL, host or app name.
    pub target: Option<Zeroizing<String>>,
    /// Who made the item.
    pub created_by: CreatedBy,
    /// Use limit.
    pub max_uses: Option<u32>,
    /// Uses so far.
    pub use_count: u32,
    /// Effective expiry: the earlier of the plain and the sealed value (ADR-0033 point 6).
    pub expires_at: Option<Timestamp>,
    /// Last change.
    pub updated_at: Timestamp,
    /// True when the payload has a TOTP seed.
    pub has_totp: bool,
    /// Extra facts by name, for example `host` and `user` of an SSH key (ADR-0027).
    pub custom: BTreeMap<String, Zeroizing<String>>,
}

impl fmt::Debug for ItemMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemMeta")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("workspace_id", &self.workspace_id)
            .finish_non_exhaustive()
    }
}

/// Metadata of one workspace (opened `workspaces.meta_ct`).
#[derive(Clone)]
pub struct WorkspaceMeta {
    /// Workspace ID.
    pub id: WorkspaceId,
    /// Slug, for example "shop-frontend".
    pub slug: Zeroizing<String>,
    /// Display name.
    pub name: Zeroizing<String>,
    /// Description.
    pub description: Zeroizing<String>,
    /// Other names that resolve to this workspace.
    pub aliases: Vec<Zeroizing<String>>,
    /// Last change.
    pub updated_at: Timestamp,
}

impl fmt::Debug for WorkspaceMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspaceMeta")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// One grant: plain columns and the opened `grants.body_ct`. The policy engine (T07) parses the body.
#[derive(Clone, Debug)]
pub struct GrantEntry {
    /// Grant ID.
    pub id: GrantId,
    /// Agent of the grant.
    pub agent_id: AgentId,
    /// Plain expiry copy (the sweeper uses it while locked).
    pub expires_at: Option<Timestamp>,
    /// Last change.
    pub updated_at: Timestamp,
    /// The opened JSON body. Zeroized on drop; `Debug` is redacted.
    pub body: SecretBytes,
}

#[derive(Serialize)]
struct ItemBodyOut<'a> {
    kind: ItemKind,
    workspace_id: &'a WorkspaceId,
    title: &'a str,
    description: &'a str,
    role_label: Option<&'a str>,
    category: &'a str,
    tags: Vec<&'a str>,
    environment: Environment,
    target: Option<&'a str>,
    created_by: CreatedBy,
    max_uses: Option<u32>,
    use_count: u32,
    expires_at_ms: Option<i64>,
    has_totp: bool,
    custom: BTreeMap<&'a str, &'a str>,
}

/// A decoded text field that zeroizes on drop, also when decoding fails half way (DEC-FIX5-8).
/// serde_json's scratch buffer for strings with escapes is not zeroized.
struct ZText(Zeroizing<String>);

impl<'de> Deserialize<'de> for ZText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemBodyIn {
    /// Missing in metadata written before T27 (DEC-T27-A1-2).
    #[serde(default)]
    kind: Option<ItemKind>,
    workspace_id: WorkspaceId,
    title: ZText,
    description: ZText,
    role_label: Option<ZText>,
    category: ZText,
    tags: Vec<ZText>,
    environment: Environment,
    target: Option<ZText>,
    created_by: CreatedBy,
    max_uses: Option<u32>,
    use_count: u32,
    expires_at_ms: Option<i64>,
    has_totp: bool,
    #[serde(default)]
    custom: BTreeMap<String, ZText>,
}

#[derive(Serialize)]
struct WorkspaceBodyOut<'a> {
    slug: &'a str,
    name: &'a str,
    description: &'a str,
    aliases: Vec<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceBodyIn {
    slug: ZText,
    name: ZText,
    description: ZText,
    aliases: Vec<ZText>,
}

fn to_json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    serde_json::to_writer(&mut *out, value).map_err(|_| CoreError::Corrupt)?;
    Ok(out)
}

fn earlier(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

fn zs(text: ZText) -> Zeroizing<String> {
    text.0
}

/// The JSON for `items.meta_ct` (seal it with `Blobs::seal_item_meta`).
///
/// # Errors
/// [`CoreError::Corrupt`] when the JSON cannot be written (it cannot for these types).
pub fn encode_item_meta(meta: &ItemMeta) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    to_json(&ItemBodyOut {
        kind: meta.kind,
        workspace_id: &meta.workspace_id,
        title: &meta.title,
        description: &meta.description,
        role_label: meta.role_label.as_deref().map(String::as_str),
        category: &meta.category,
        tags: meta.tags.iter().map(|t| t.as_str()).collect(),
        environment: meta.environment,
        target: meta.target.as_deref().map(String::as_str),
        created_by: meta.created_by,
        max_uses: meta.max_uses,
        use_count: meta.use_count,
        expires_at_ms: meta.expires_at.map(Timestamp::as_millisecond),
        has_totp: meta.has_totp,
        custom: meta
            .custom
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect(),
    })
}

/// Where the kind of a decoded item comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KindSource {
    /// The sealed metadata holds the kind, and it is the kind of the plain column.
    Sealed,
    /// The metadata was written before the kind was sealed (before T27). The kind is the plain
    /// column, which a file edit can change, so the caller must check it against the kind of the
    /// authenticated payload before it trusts it (AUD-2, DEC-T27-A1-2).
    Plain,
}

/// Builds the metadata of `row` from its opened `meta_ct` (or a version snapshot).
///
/// The kind is the sealed kind. A sealed kind that differs from the plain `items.kind` column is
/// [`CoreError::Corrupt`] (AUD-2). Metadata without a sealed kind gives [`KindSource::Plain`].
///
/// # Errors
/// [`CoreError::Corrupt`] for JSON of the wrong shape, a bad time, or a kind mismatch.
pub fn decode_item_meta(
    row: &ItemRow,
    plain: &SecretBytes,
) -> Result<(ItemMeta, KindSource), CoreError> {
    let body: ItemBodyIn =
        serde_json::from_slice(plain.expose_secret()).map_err(|_| CoreError::Corrupt)?;
    let source = match body.kind {
        Some(kind) if kind == row.kind => KindSource::Sealed,
        Some(_) => return Err(CoreError::Corrupt),
        None => KindSource::Plain,
    };
    let sealed_expiry = body
        .expires_at_ms
        .map(Timestamp::from_millisecond)
        .transpose()
        .map_err(|_| CoreError::Corrupt)?;
    let meta = ItemMeta {
        id: row.id,
        kind: row.kind,
        workspace_id: body.workspace_id,
        title: zs(body.title),
        description: zs(body.description),
        role_label: body.role_label.map(zs),
        category: zs(body.category),
        tags: body.tags.into_iter().map(zs).collect(),
        environment: body.environment,
        target: body.target.map(zs),
        created_by: body.created_by,
        max_uses: body.max_uses,
        use_count: body.use_count,
        expires_at: earlier(row.expires_at, sealed_expiry),
        updated_at: row.updated_at,
        has_totp: body.has_totp,
        custom: body.custom.into_iter().map(|(k, v)| (k, zs(v))).collect(),
    };
    Ok((meta, source))
}

/// The JSON for `workspaces.meta_ct` (seal it with `Blobs::seal_workspace_meta`).
///
/// # Errors
/// [`CoreError::Corrupt`] when the JSON cannot be written (it cannot for these types).
pub fn encode_workspace_meta(meta: &WorkspaceMeta) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    to_json(&WorkspaceBodyOut {
        slug: &meta.slug,
        name: &meta.name,
        description: &meta.description,
        aliases: meta.aliases.iter().map(|a| a.as_str()).collect(),
    })
}

/// Builds the metadata of `row` from its opened `meta_ct`.
///
/// # Errors
/// [`CoreError::Corrupt`] for JSON of the wrong shape.
pub fn decode_workspace_meta(
    row: &WorkspaceRow,
    plain: &SecretBytes,
) -> Result<WorkspaceMeta, CoreError> {
    let body: WorkspaceBodyIn =
        serde_json::from_slice(plain.expose_secret()).map_err(|_| CoreError::Corrupt)?;
    Ok(WorkspaceMeta {
        id: row.id,
        slug: zs(body.slug),
        name: zs(body.name),
        description: zs(body.description),
        aliases: body.aliases.into_iter().map(zs).collect(),
        updated_at: row.updated_at,
    })
}

/// A grant entry from `row` and its opened body.
#[must_use]
pub fn grant_entry(row: &GrantRow, body: SecretBytes) -> GrantEntry {
    GrantEntry {
        id: row.id,
        agent_id: row.agent_id,
        expires_at: row.expires_at,
        updated_at: row.updated_at,
        body,
    }
}
