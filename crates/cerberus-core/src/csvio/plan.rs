//! From a table to a plan: which rows become items, which are left out and why. The plan holds
//! no cell text except the item inputs; the preview and the report hold counts, row numbers and
//! titles (metadata, never secrets).

use std::collections::{BTreeMap, BTreeSet};

use cerberus_types::{Environment, ItemKind, WorkspaceId};
use serde::{Deserialize, Serialize};

use super::rows::{Targets, build_row};
use super::source::{Columns, CsvSource, Field};
use super::table::{Table, parse_table};
use crate::error::CoreError;
use crate::index::normalize;
use crate::items::ItemInput;

/// Most problem rows and duplicate rows a preview lists. The counts are always complete.
pub const LIST_LIMIT: usize = 200;

/// What to do with a row whose title is already used in the target workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicatePolicy {
    /// Leave the row out. A second import of the same file adds nothing.
    Skip,
    /// Import the row with a number added to the title: `Title (2)`.
    Rename,
}

/// What the user chose for an import.
#[derive(Clone, Debug)]
pub struct ImportOptions {
    /// The flavour, or `Auto`.
    pub source: CsvSource,
    /// Target workspace.
    pub workspace_id: WorkspaceId,
    /// Environment of every row that has none of its own.
    pub environment: Environment,
    /// Role label of every row that has none of its own.
    pub role_label: Option<String>,
    /// Field to column name. Overrides the preset of the flavour.
    pub mapping: BTreeMap<Field, String>,
    /// Rows whose title is already in the workspace.
    pub duplicates: DuplicatePolicy,
}

/// Why a row is left out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemCode {
    /// The row has more cells than the header has columns.
    ColumnCount,
    /// The kind is not one Cerberus imports (cards, identities, keys, ...).
    UnsupportedKind,
    /// Every cell is empty.
    EmptyRow,
    /// No title and no URL to take one from.
    MissingTitle,
    /// A kind that needs a secret has none.
    MissingSecret,
    /// A value is not valid. `field` names it.
    InvalidValue,
}

/// A row that cannot be imported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RowProblem {
    /// 1-based data row (the header is not counted).
    pub row: u32,
    /// The reason.
    pub code: ProblemCode,
    /// The item field at fault, when the reason is `InvalidValue`.
    pub field: Option<String>,
}

/// A row whose title is already used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DuplicateRow {
    /// 1-based data row.
    pub row: u32,
    /// The title as in the file.
    pub title: String,
    /// True when the other item comes from the same file, false when it is already in the vault.
    pub in_file: bool,
    /// True when the row is imported under a new title, false when it is left out.
    pub renamed: bool,
}

/// The dry run: what an import would do. It holds no secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportPreview {
    /// The flavour used (the detected one for `Auto`). `None` when the header is not known: the
    /// user must choose `Generic` and map the columns.
    pub source: Option<CsvSource>,
    /// The flavour the header looks like, whatever the user chose.
    pub detected: Option<CsvSource>,
    /// Header names (at most 64, each cut to 80 characters), for the mapping step.
    pub columns: Vec<String>,
    /// Data rows in the file.
    pub total_rows: u32,
    /// Rows that become items (renamed ones included).
    pub importable: u32,
    /// Importable rows by kind.
    pub by_kind: Vec<(ItemKind, u32)>,
    /// Rows that cannot be imported, first [`LIST_LIMIT`].
    pub problems: Vec<RowProblem>,
    /// All rows that cannot be imported.
    pub problem_count: u32,
    /// Rows with a used title, first [`LIST_LIMIT`].
    pub duplicates: Vec<DuplicateRow>,
    /// All rows with a used title.
    pub duplicate_count: u32,
    /// Rows imported under a new title.
    pub renamed: u32,
    /// Logins whose notes are left out (a login has no notes field, DEC-T23-3).
    pub notes_dropped: u32,
}

/// The result of an import.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    /// Items made.
    pub imported: u32,
    /// Rows left out because of a problem.
    pub skipped_problems: u32,
    /// Rows left out because the title was in use.
    pub skipped_duplicates: u32,
    /// Items made under a new title.
    pub renamed: u32,
    /// Logins whose notes are left out.
    pub notes_dropped: u32,
}

pub(crate) struct Plan {
    pub items: Vec<ItemInput>,
    pub preview: ImportPreview,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn column_name(name: &str) -> String {
    name.chars().take(80).collect()
}

/// A free title: `Title (2)`, `Title (3)`, ... under the 200 character limit.
fn numbered(title: &str, taken: impl Fn(&str) -> bool) -> Option<String> {
    (2_u32..10_000).find_map(|n| {
        let suffix = format!(" ({n})");
        let keep = 200_usize.saturating_sub(suffix.chars().count());
        let candidate: String = title.chars().take(keep).collect::<String>() + &suffix;
        (!taken(&candidate)).then_some(candidate)
    })
}

/// Reads `table` against the titles that are already in the workspace.
pub(crate) fn make_plan(
    table: &Table,
    options: &ImportOptions,
    existing: &BTreeSet<String>,
) -> Result<Plan, CoreError> {
    let detected = CsvSource::detect(&table.headers);
    let source = match options.source {
        CsvSource::Auto => detected,
        other => Some(other),
    };
    let columns = table
        .headers
        .iter()
        .take(64)
        .map(|h| column_name(h))
        .collect();
    let mut preview = ImportPreview {
        source,
        detected,
        columns,
        total_rows: count(table.rows.len()),
        importable: 0,
        by_kind: Vec::new(),
        problems: Vec::new(),
        problem_count: 0,
        duplicates: Vec::new(),
        duplicate_count: 0,
        renamed: 0,
        notes_dropped: 0,
    };
    let Some(source) = source else {
        return Ok(Plan {
            items: Vec::new(),
            preview,
        });
    };
    let cols = Columns::resolve(&table.headers, source, &options.mapping).map_err(|bad| {
        CoreError::Validation(vec![cerberus_types::FieldProblem {
            field: format!("mapping.{}", bad.0.name()),
            problem: "names a column that is not in the file".to_owned(),
        }])
    })?;
    let targets = Targets {
        workspace_id: options.workspace_id,
        environment: options.environment,
        role_label: options.role_label.as_deref(),
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut items = Vec::new();
    let mut by_kind: BTreeMap<String, (ItemKind, u32)> = BTreeMap::new();
    let note_problem = |preview: &mut ImportPreview, row: u32, code, field| {
        preview.problem_count = preview.problem_count.saturating_add(1);
        if preview.problems.len() < LIST_LIMIT {
            preview.problems.push(RowProblem { row, code, field });
        }
    };
    for row in &table.rows {
        if row.cells.len() > table.headers.len() {
            note_problem(&mut preview, row.number, ProblemCode::ColumnCount, None);
            continue;
        }
        let built = match build_row(&cols, source, row, &targets) {
            Ok(built) => built,
            Err((code, field)) => {
                note_problem(&mut preview, row.number, code, field);
                continue;
            }
        };
        let mut input = built.input;
        let key = normalize(&input.title).to_string();
        let in_file = seen.contains(&key);
        let in_vault = existing.contains(&key);
        let mut renamed = false;
        if in_file || in_vault {
            let skip = in_vault && !in_file && options.duplicates == DuplicatePolicy::Skip;
            let title = input.title.clone();
            let mut left_out = skip;
            if !skip {
                let policy = options.duplicates;
                let fresh = numbered(&input.title, |t| {
                    let k = normalize(t).to_string();
                    seen.contains(&k)
                        || (existing.contains(&k) && policy == DuplicatePolicy::Rename)
                });
                match fresh {
                    // A renumbered title that the vault has (an earlier import) means this row
                    // was imported before: with `Skip` it is left out.
                    Some(t)
                        if policy == DuplicatePolicy::Skip
                            && existing.contains(&*normalize(&t)) =>
                    {
                        left_out = true;
                    }
                    Some(t) => {
                        input.title = t;
                        renamed = true;
                    }
                    None => left_out = true,
                }
            }
            preview.duplicate_count = preview.duplicate_count.saturating_add(1);
            if preview.duplicates.len() < LIST_LIMIT {
                preview.duplicates.push(DuplicateRow {
                    row: row.number,
                    title,
                    in_file,
                    renamed: !left_out && renamed,
                });
            }
            if left_out {
                continue;
            }
        }
        seen.insert(normalize(&input.title).to_string());
        if renamed {
            preview.renamed = preview.renamed.saturating_add(1);
        }
        if built.notes_dropped {
            preview.notes_dropped = preview.notes_dropped.saturating_add(1);
        }
        let name = serde_json::to_string(&input.kind()).unwrap_or_default();
        by_kind.entry(name).or_insert((input.kind(), 0)).1 += 1;
        items.push(input);
    }
    preview.importable = count(items.len());
    preview.by_kind = by_kind.into_values().collect();
    Ok(Plan { items, preview })
}

/// The dry run on raw bytes: parse and plan, no vault needed. `existing` holds the normalized
/// titles already in the workspace. The service uses it, and so does the fuzz target.
///
/// # Errors
/// `Validation` for a bad file or a mapping that names a missing column.
pub fn preview_bytes(
    bytes: &[u8],
    options: &ImportOptions,
    existing: &BTreeSet<String>,
) -> Result<ImportPreview, CoreError> {
    let table = parse_table(bytes)?;
    Ok(make_plan(&table, options, existing)?.preview)
}
