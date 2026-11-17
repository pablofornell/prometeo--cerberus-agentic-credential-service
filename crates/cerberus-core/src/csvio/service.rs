//! The service methods of the CSV import and export.

use cerberus_types::{FieldProblem, OperatorRole, WorkspaceId};
use zeroize::Zeroizing;

use super::export::write_csv;
use super::plan::{ImportOptions, ImportPreview, ImportReport, make_plan, preview_bytes};
use super::table::{CsvError, parse_table};
use crate::audit::EventType;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::CreatedBy;
use crate::items::batch::live_titles;
use crate::vault::{VaultService, by_operator};

/// A finished export: the CSV bytes (zeroized on drop) and the number of items in it.
#[derive(Debug)]
pub struct CsvExport {
    /// The file content. It holds every secret in plain text.
    pub bytes: Zeroizing<Vec<u8>>,
    /// Items written.
    pub count: u64,
}

fn problem(field: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }])
}

impl From<CsvError> for CoreError {
    fn from(error: CsvError) -> Self {
        problem("file", &error.to_string())
    }
}

impl VaultService {
    /// IPC `csv_preview`: reads `bytes` and says what an import would do. Nothing is written and
    /// the answer holds no secret value. Role operator.
    ///
    /// # Errors
    /// `Validation` (bad file, unknown workspace, bad mapping), `Locked`, or the role check.
    pub async fn csv_preview(
        &self,
        ctx: &OperatorContext,
        bytes: &[u8],
        options: &ImportOptions,
    ) -> Result<ImportPreview, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Operator).await?;
        if guard.index.workspace(&options.workspace_id).is_none() {
            return Err(problem("workspace_id", "is not a known workspace"));
        }
        let existing = live_titles(&guard.index, &options.workspace_id, self.clock().now());
        preview_bytes(bytes, options, &existing)
    }

    /// IPC `csv_import`: makes every importable row an item, all in one transaction. The audit
    /// event `items.import` holds counts only. Role operator.
    ///
    /// # Errors
    /// As [`Self::csv_preview`], `Validation` (field `file`) when no row can be imported, or a
    /// storage error. After an error nothing was imported.
    pub async fn csv_import(
        &self,
        ctx: &OperatorContext,
        bytes: &[u8],
        options: &ImportOptions,
    ) -> Result<ImportReport, CoreError> {
        let mut guard = self.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Operator)?;
        if guard.index.workspace(&options.workspace_id).is_none() {
            return Err(problem("workspace_id", "is not a known workspace"));
        }
        let table = parse_table(bytes)?;
        let existing = live_titles(&guard.index, &options.workspace_id, self.clock().now());
        let plan = make_plan(&table, options, &existing)?;
        let Some(source) = plan.preview.source else {
            return Err(problem(
                "source",
                "is not known: choose Generic and map the columns",
            ));
        };
        if plan.items.is_empty() {
            return Err(problem("file", "has no row that can be imported"));
        }
        let preview = plan.preview;
        let imported = self
            .insert_items_batch(&mut guard, plan.items, CreatedBy::Operator(ctx.operator_id))
            .await?;
        let report = ImportReport {
            imported: u32::try_from(imported).unwrap_or(u32::MAX),
            skipped_problems: preview.problem_count,
            skipped_duplicates: preview.duplicate_count.saturating_sub(preview.renamed),
            renamed: preview.renamed,
            notes_dropped: preview.notes_dropped,
        };
        let event = by_operator(EventType::ItemsImport, ctx)
            .target("workspace", options.workspace_id.to_string())
            .detail("source", source.name())
            .detail("imported", report.imported)
            .detail("skipped_problems", report.skipped_problems)
            .detail("skipped_duplicates", report.skipped_duplicates)
            .detail("renamed", report.renamed);
        self.audit(&guard, event).await;
        Ok(report)
    }

    /// IPC `csv_export`: every live item (or those of one workspace) as CSV with the secrets in
    /// plain text. Role owner, taken from the session. The event `items.export` is written
    /// strictly before the bytes are returned, and holds the count only.
    ///
    /// # Errors
    /// `Validation` (unknown workspace), `Corrupt` when an item does not open, `Locked`, the role
    /// check, or the audit error.
    pub async fn csv_export(
        &self,
        ctx: &OperatorContext,
        workspace: Option<WorkspaceId>,
    ) -> Result<CsvExport, CoreError> {
        let mut guard = self.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Owner)?;
        if let Some(id) = workspace
            && guard.index.workspace(&id).is_none()
        {
            return Err(problem("workspace_id", "is not a known workspace"));
        }
        let now = self.clock().now();
        let mut wanted: Vec<(String, String, cerberus_types::ItemId)> = guard
            .index
            .iter_items()
            .filter(|m| m.expires_at.is_none_or(|at| now < at))
            .filter(|m| workspace.is_none_or(|w| w == m.workspace_id))
            .map(|m| {
                let ws = guard
                    .index
                    .workspace(&m.workspace_id)
                    .map(|w| w.name.as_str().to_owned())
                    .unwrap_or_default();
                (ws, crate::index::normalize(&m.title).to_string(), m.id)
            })
            .collect();
        wanted.sort();
        let mut items = Vec::with_capacity(wanted.len());
        for (name, _, id) in wanted {
            items.push((name, self.read_payload_in(&mut guard, id, false).await?));
        }
        let bytes = write_csv(&items)?;
        let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let mut event = by_operator(EventType::ItemsExport, ctx).detail("count", count);
        if let Some(id) = workspace {
            event = event.detail("workspace_id", id.to_string());
        }
        self.audit_strict(&guard, event).await?;
        Ok(CsvExport { bytes, count })
    }
}
