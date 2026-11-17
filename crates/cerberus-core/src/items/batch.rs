//! Many new items in one transaction (the CSV import, DEC-T23-4).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use cerberus_types::{ItemId, WorkspaceId};
use jiff::Timestamp;
use zeroize::Zeroizing;

use super::service::{ItemInput, seal_version, title_taken};
use super::validate::validate_item;
use crate::error::CoreError;
use crate::index::{CreatedBy, Index, ItemMeta, normalize};
use crate::vault::{Unlocked, VaultService};

/// Normalized titles of the live items of `workspace`.
pub(crate) fn live_titles(
    index: &Index,
    workspace: &WorkspaceId,
    now: Timestamp,
) -> BTreeSet<String> {
    index
        .items_in_workspace(workspace)
        .into_iter()
        .flatten()
        .filter_map(|id| index.item(id))
        .filter(|m| m.expires_at.is_none_or(|at| now < at))
        .map(|m| normalize(&m.title).to_string())
        .collect()
}

fn meta_of(
    id: ItemId,
    input: &ItemInput,
    created_by: CreatedBy,
    expires_at: Option<Timestamp>,
    now: Timestamp,
) -> ItemMeta {
    let zs = |s: &str| Zeroizing::new(s.to_owned());
    ItemMeta {
        id,
        kind: input.kind(),
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
        use_count: 0,
        expires_at,
        updated_at: now,
        has_totp: input.payload.has_totp(),
        custom: BTreeMap::new(),
    }
}

impl VaultService {
    /// Creates every item of `inputs` or none: one database transaction, and the index changes
    /// only after the commit. Each input is validated again. A title that is already used in the
    /// workspace, or used twice in `inputs`, is a `Conflict` and nothing is written. The caller
    /// holds the write guard and has checked the role.
    ///
    /// # Errors
    /// `Validation`, `Conflict`, or a storage error.
    pub(crate) async fn insert_items_batch(
        &self,
        guard: &mut Unlocked,
        inputs: Vec<ItemInput>,
        created_by: CreatedBy,
    ) -> Result<usize, CoreError> {
        let now = self.clock().now();
        let settings = self.load_item_settings(guard).await?;
        let mut sealed = Vec::with_capacity(inputs.len());
        let mut metas = Vec::with_capacity(inputs.len());
        let mut used: BTreeSet<(WorkspaceId, String)> = BTreeSet::new();
        for input in &inputs {
            validate_item(input).map_err(CoreError::Validation)?;
            if guard.index.workspace(&input.workspace_id).is_none() {
                return Err(CoreError::Validation(vec![cerberus_types::FieldProblem {
                    field: "workspace_id".to_owned(),
                    problem: "is not a known workspace".to_owned(),
                }]));
            }
            let key = (input.workspace_id, normalize(&input.title).to_string());
            if !used.insert(key)
                || title_taken(&guard.index, &input.workspace_id, &input.title, None, now)
            {
                return Err(CoreError::Conflict);
            }
            let expires_at = settings
                .expiry(input.kind(), input.expires_at, now)
                .map_err(CoreError::Validation)?;
            let meta = meta_of(ItemId::generate(), input, created_by, expires_at, now);
            sealed.push(seal_version(guard, &meta, &input.payload, 1, now)?);
            metas.push(meta);
        }
        let mut tx = self.store().begin().await?;
        for (row, version) in &sealed {
            tx.insert_item(row, version).await?;
        }
        tx.commit().await?;
        let count = metas.len();
        for meta in metas {
            guard.index.upsert_item_at(meta, 1);
        }
        Ok(count)
    }
}
