//! What an agent or a list may see of an item: metadata only.
//!
//! The type holds plain `String`s and IDs. It has no field that can carry a payload, so a secret
//! cannot be put into a catalog row or a resolve candidate.

use std::collections::BTreeMap;

use cerberus_types::{Environment, ItemId, ItemKind};
use jiff::Timestamp;
use serde::Serialize;

use crate::index::{CreatedBy, Index, ItemMeta};

/// Metadata of one item for catalogs, candidates and answers (ADR-0020).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ItemSummary {
    /// Item ID.
    pub id: ItemId,
    /// Kind.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Role label.
    pub role_label: Option<String>,
    /// Category.
    pub category: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Environment.
    pub environment: Environment,
    /// Slug of the workspace (empty when the workspace is gone).
    pub workspace: String,
    /// Target: URL, host or app name.
    pub target: Option<String>,
    /// `operator:<id>` or `agent:<id>`.
    pub created_by: String,
    /// Expiry.
    pub expires_at: Option<Timestamp>,
    /// Last change.
    pub updated_at: Timestamp,
    /// True when the item has a TOTP seed (the seed itself is never listed).
    pub has_totp: bool,
    /// Extra facts by name (metadata, never a secret). The operator views show them; the agent
    /// wire types do not copy this field (DEC-INT10-7).
    #[serde(skip)]
    pub custom: BTreeMap<String, String>,
}

impl ItemSummary {
    /// The summary of `meta`, with the workspace slug from `index`.
    #[must_use]
    pub fn of(meta: &ItemMeta, index: &Index) -> Self {
        Self {
            id: meta.id,
            kind: meta.kind,
            title: meta.title.as_str().to_owned(),
            description: meta.description.as_str().to_owned(),
            role_label: meta.role_label.as_ref().map(|s| s.as_str().to_owned()),
            category: meta.category.as_str().to_owned(),
            tags: meta.tags.iter().map(|t| t.as_str().to_owned()).collect(),
            environment: meta.environment,
            workspace: index
                .workspace(&meta.workspace_id)
                .map(|w| w.slug.as_str().to_owned())
                .unwrap_or_default(),
            target: meta.target.as_ref().map(|s| s.as_str().to_owned()),
            created_by: match meta.created_by {
                CreatedBy::Operator(id) => format!("operator:{id}"),
                CreatedBy::Agent(id) => format!("agent:{id}"),
            },
            expires_at: meta.expires_at,
            updated_at: meta.updated_at,
            has_totp: meta.has_totp,
            custom: meta
                .custom
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().to_owned()))
                .collect(),
        }
    }
}
