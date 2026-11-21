//! Types of the CSV import and export commands (T23).

use std::collections::BTreeMap;

use cerberus_core::csvio;
use serde::{Deserialize, Serialize};
use specta::Type;

use super::{Environment, ItemKind};

/// Where a CSV file came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum CsvSource {
    /// Find the flavour from the header row.
    Auto,
    /// Bitwarden.
    Bitwarden,
    /// 1Password.
    #[serde(rename = "onepassword")]
    OnePassword,
    /// KeePassXC.
    #[serde(rename = "keepassxc")]
    KeePassXc,
    /// Chrome, Edge, Brave.
    Chrome,
    /// Firefox.
    Firefox,
    /// A Cerberus export, or any file with a column mapping.
    Generic,
}

impl From<csvio::CsvSource> for CsvSource {
    fn from(value: csvio::CsvSource) -> Self {
        match value {
            csvio::CsvSource::Auto => Self::Auto,
            csvio::CsvSource::Bitwarden => Self::Bitwarden,
            csvio::CsvSource::OnePassword => Self::OnePassword,
            csvio::CsvSource::KeePassXc => Self::KeePassXc,
            csvio::CsvSource::Chrome => Self::Chrome,
            csvio::CsvSource::Firefox => Self::Firefox,
            csvio::CsvSource::Generic => Self::Generic,
        }
    }
}

impl From<CsvSource> for csvio::CsvSource {
    fn from(value: CsvSource) -> Self {
        match value {
            CsvSource::Auto => Self::Auto,
            CsvSource::Bitwarden => Self::Bitwarden,
            CsvSource::OnePassword => Self::OnePassword,
            CsvSource::KeePassXc => Self::KeePassXc,
            CsvSource::Chrome => Self::Chrome,
            CsvSource::Firefox => Self::Firefox,
            CsvSource::Generic => Self::Generic,
        }
    }
}

mirror_enum! {
    /// What to do with a row whose title is already in the workspace.
    DuplicatePolicy (csvio::DuplicatePolicy) { Skip, Rename }
}

mirror_enum! {
    /// Why a row cannot be imported.
    ProblemCode (csvio::ProblemCode) {
        ColumnCount, UnsupportedKind, EmptyRow, MissingTitle, MissingSecret, InvalidValue
    }
}

/// Column mapping of `csv_preview` and `csv_import`: item field name to CSV column name. The
/// field names are `title`, `kind`, `url`, `username`, `password`, `secret`, `totp`, `notes`,
/// `tags`, `description`, `role`, `category` and `environment`. An empty column name removes
/// the preset column of that field.
#[derive(Clone, Debug, Default, Deserialize, Type)]
pub struct CsvMapping {
    /// Item field to CSV column.
    pub columns: BTreeMap<String, String>,
}

/// The arguments of `csv_preview` and `csv_import`.
#[derive(Clone, Debug, Deserialize, Type)]
pub struct CsvImportRequest {
    /// Absolute path of the CSV file.
    pub path: String,
    /// Target workspace ID.
    pub workspace_id: String,
    /// The flavour, or `auto`.
    pub source: CsvSource,
    /// Environment of every row that has none.
    pub environment: Environment,
    /// Role label of every row that has none.
    pub role_label: Option<String>,
    /// Column mapping (needed for an unknown header, optional otherwise).
    pub mapping: CsvMapping,
    /// What to do with a title that is already in the workspace.
    pub duplicates: DuplicatePolicy,
}

/// A row that cannot be imported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct RowProblemView {
    /// 1-based data row (the header is not counted).
    pub row: u32,
    /// The reason.
    pub code: ProblemCode,
    /// The item field at fault, for `invalid_value`.
    pub field: Option<String>,
}

/// A row whose title is already used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct DuplicateRowView {
    /// 1-based data row.
    pub row: u32,
    /// The title as in the file.
    pub title: String,
    /// True when the other item is in the same file.
    pub in_file: bool,
    /// True when the row is imported under a new title.
    pub renamed: bool,
}

/// Rows of one kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct KindCountView {
    /// The kind.
    pub kind: ItemKind,
    /// How many rows.
    pub count: u32,
}

/// Result of `csv_preview`: counts, row numbers and titles. No secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct ImportPreviewView {
    /// The flavour used. `null` when the header is unknown: choose `generic` and map the columns.
    pub source: Option<CsvSource>,
    /// The flavour the header looks like.
    pub detected: Option<CsvSource>,
    /// Header names, for the mapping step.
    pub columns: Vec<String>,
    /// Data rows in the file.
    pub total_rows: u32,
    /// Rows that become items.
    pub importable: u32,
    /// Importable rows by kind.
    pub by_kind: Vec<KindCountView>,
    /// Rows that cannot be imported (the first 200).
    pub problems: Vec<RowProblemView>,
    /// All rows that cannot be imported.
    pub problem_count: u32,
    /// Rows with a used title (the first 200).
    pub duplicates: Vec<DuplicateRowView>,
    /// All rows with a used title.
    pub duplicate_count: u32,
    /// Rows imported under a new title.
    pub renamed: u32,
    /// Logins whose notes are left out.
    pub notes_dropped: u32,
}

impl From<csvio::ImportPreview> for ImportPreviewView {
    fn from(p: csvio::ImportPreview) -> Self {
        Self {
            source: p.source.map(Into::into),
            detected: p.detected.map(Into::into),
            columns: p.columns,
            total_rows: p.total_rows,
            importable: p.importable,
            by_kind: p
                .by_kind
                .into_iter()
                .map(|(kind, count)| KindCountView {
                    kind: kind.into(),
                    count,
                })
                .collect(),
            problems: p
                .problems
                .into_iter()
                .map(|r| RowProblemView {
                    row: r.row,
                    code: r.code.into(),
                    field: r.field,
                })
                .collect(),
            problem_count: p.problem_count,
            duplicates: p
                .duplicates
                .into_iter()
                .map(|d| DuplicateRowView {
                    row: d.row,
                    title: d.title,
                    in_file: d.in_file,
                    renamed: d.renamed,
                })
                .collect(),
            duplicate_count: p.duplicate_count,
            renamed: p.renamed,
            notes_dropped: p.notes_dropped,
        }
    }
}

/// Result of `csv_import`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
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

impl From<csvio::ImportReport> for ImportReport {
    fn from(r: csvio::ImportReport) -> Self {
        Self {
            imported: r.imported,
            skipped_problems: r.skipped_problems,
            skipped_duplicates: r.skipped_duplicates,
            renamed: r.renamed,
            notes_dropped: r.notes_dropped,
        }
    }
}
