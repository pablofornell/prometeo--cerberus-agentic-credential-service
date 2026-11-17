//! Workspaces (IPC `workspace_list`, `workspace_put`, `workspace_delete`). A workspace is the
//! "app" of resolve (ADR-0020): its slug, name and aliases are sealed in `workspaces.meta_ct`.

use cerberus_store::{StoreError, WorkspaceRow};
use cerberus_types::{FieldProblem, OperatorRole, WorkspaceId};
use zeroize::Zeroizing;

use crate::audit::EventType;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::{Index, WorkspaceMeta, encode_workspace_meta, normalize};
use crate::vault::{VaultService, by_operator};

/// Most aliases of one workspace.
const MAX_ALIASES: usize = 20;

/// What the operator enters for a workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceInput {
    /// Lower case letters, digits and `-`, 1..64 characters, for example `shop-frontend`.
    pub slug: String,
    /// Display name, 1..100 characters.
    pub name: String,
    /// Description, 0..500 characters.
    pub description: String,
    /// Other names that resolve to this workspace, at most 20, each 1..64 characters.
    pub aliases: Vec<String>,
}

/// A workspace as the UI shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceView {
    /// Workspace ID.
    pub id: WorkspaceId,
    /// Slug.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Aliases.
    pub aliases: Vec<String>,
    /// Items in the workspace (also expired ones the sweeper has not deleted yet).
    pub item_count: u32,
}

fn view(meta: &WorkspaceMeta, index: &Index) -> WorkspaceView {
    WorkspaceView {
        id: meta.id,
        slug: meta.slug.to_string(),
        name: meta.name.to_string(),
        description: meta.description.to_string(),
        aliases: meta.aliases.iter().map(|a| a.to_string()).collect(),
        item_count: index
            .items_in_workspace(&meta.id)
            .map_or(0, |ids| u32::try_from(ids.len()).unwrap_or(u32::MAX)),
    }
}

fn problem(problems: &mut Vec<FieldProblem>, field: &str, text: &str) {
    problems.push(FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    });
}

fn chars_in(text: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&text.chars().count())
}

/// Trims the text fields and checks the rules of [`WorkspaceInput`].
fn validate(input: WorkspaceInput) -> Result<WorkspaceInput, CoreError> {
    let input = WorkspaceInput {
        slug: input.slug.trim().to_owned(),
        name: input.name.trim().to_owned(),
        description: input.description.trim().to_owned(),
        aliases: input.aliases.iter().map(|a| a.trim().to_owned()).collect(),
    };
    let mut problems = Vec::new();
    let slug_ok = chars_in(&input.slug, 1, 64)
        && input
            .slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !slug_ok {
        problem(&mut problems, "slug", "must be 1..64 of a-z, 0-9 and -");
    }
    if !chars_in(&input.name, 1, 100) {
        problem(&mut problems, "name", "must be 1..100 characters");
    }
    if !chars_in(&input.description, 0, 500) {
        problem(&mut problems, "description", "must be 0..500 characters");
    }
    if input.aliases.len() > MAX_ALIASES {
        problem(&mut problems, "aliases", "at most 20");
    }
    if input.aliases.iter().any(|a| !chars_in(a, 1, 64)) {
        problem(&mut problems, "aliases", "each must be 1..64 characters");
    }
    if problems.is_empty() {
        Ok(input)
    } else {
        Err(CoreError::Validation(problems))
    }
}

impl VaultService {
    /// IPC `workspace_list`: every workspace, sorted by name. Any role.
    ///
    /// # Errors
    /// `Locked` or the role check.
    pub async fn list_workspaces(
        &self,
        ctx: &OperatorContext,
    ) -> Result<Vec<WorkspaceView>, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        let mut out: Vec<WorkspaceView> = guard
            .index
            .iter_workspaces()
            .map(|meta| view(meta, &guard.index))
            .collect();
        out.sort_by(|a, b| {
            normalize(&a.name)
                .cmp(&normalize(&b.name))
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// IPC `workspace_put`: creates a workspace (`id = None`) or changes one. Role operator.
    /// The slug and every alias must not be a slug or alias of another workspace (normalized).
    /// Writes `workspace.create` or `workspace.update`.
    ///
    /// # Errors
    /// `Validation`, `Conflict` (name used by another workspace), `NotFound` (unknown ID),
    /// `Locked`, the role check, or a storage error.
    pub async fn put_workspace(
        &self,
        ctx: &OperatorContext,
        id: Option<WorkspaceId>,
        input: WorkspaceInput,
    ) -> Result<WorkspaceView, CoreError> {
        let input = validate(input)?;
        let mut guard = self.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Operator)?;
        let now = self.clock().now();
        let old = match id {
            Some(id) => Some(guard.index.workspace(&id).ok_or(CoreError::NotFound)?.id),
            None => None,
        };
        let id = old.unwrap_or_else(WorkspaceId::generate);
        let taken = std::iter::once(&input.slug)
            .chain(input.aliases.iter())
            .filter_map(|name| guard.index.workspace_by_slug(name))
            .any(|owner| owner != id);
        if taken {
            return Err(CoreError::Conflict);
        }
        let zs = |s: &str| Zeroizing::new(s.to_owned());
        let meta = WorkspaceMeta {
            id,
            slug: zs(&input.slug),
            name: zs(&input.name),
            description: zs(&input.description),
            aliases: input.aliases.iter().map(|a| zs(a)).collect(),
            updated_at: now,
        };
        let json = encode_workspace_meta(&meta)?;
        // The store keeps `created_at` of an existing row on update.
        let row = WorkspaceRow {
            id,
            created_at: now,
            updated_at: now,
            meta_ct: guard.blobs().seal_workspace_meta(&id, &json)?,
        };
        let mut tx = self.store().begin().await?;
        tx.put_workspace(&row).await?;
        tx.commit().await?;
        guard.index.upsert_workspace(meta);
        let event_type = if old.is_some() {
            EventType::WorkspaceUpdate
        } else {
            EventType::WorkspaceCreate
        };
        self.audit(
            &guard,
            by_operator(event_type, ctx).target("workspace", id.to_string()),
        )
        .await;
        let meta = guard.index.workspace(&id).ok_or(CoreError::NotFound)?;
        Ok(view(meta, &guard.index))
    }

    /// IPC `workspace_delete`. Role operator. A workspace with items gives `Conflict` (409).
    /// Writes `workspace.delete`.
    ///
    /// # Errors
    /// `NotFound`, `Conflict`, `Locked`, the role check, or a storage error.
    pub async fn delete_workspace(
        &self,
        ctx: &OperatorContext,
        id: WorkspaceId,
    ) -> Result<(), CoreError> {
        let mut guard = self.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Operator)?;
        if guard.index.workspace(&id).is_none() {
            return Err(CoreError::NotFound);
        }
        if guard
            .index
            .items_in_workspace(&id)
            .is_some_and(|ids| !ids.is_empty())
        {
            return Err(CoreError::Conflict);
        }
        let mut tx = self.store().begin().await?;
        match tx.delete_workspace(id).await {
            Ok(()) => {}
            Err(StoreError::NotFound) => return Err(CoreError::NotFound),
            Err(error) => return Err(error.into()),
        }
        tx.commit().await?;
        guard.index.remove_workspace(&id);
        self.audit(
            &guard,
            by_operator(EventType::WorkspaceDelete, ctx).target("workspace", id.to_string()),
        )
        .await;
        Ok(())
    }
}
