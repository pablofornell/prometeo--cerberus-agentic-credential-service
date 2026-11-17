//! CSV import and export (T23, DEC-T23-*).
//!
//! The parser works on bytes in memory and never touches the disk: the desktop layer reads the
//! file, calls the service and zeroizes the bytes. A preview (`csv_preview`) reads the file and
//! answers with counts and row numbers only. An import (`csv_import`) reads it again, plans the
//! same rows and writes all new items in one transaction. Nothing here puts a cell value into a
//! log, an error or an audit event.

mod export;
mod guard;
mod plan;
mod rows;
mod service;
mod source;
mod table;
mod totp_text;

#[cfg(test)]
mod tests;

pub use export::EXPORT_COLUMNS;
pub use guard::{guard_cell, unguard_cell};
pub use plan::{
    DuplicatePolicy, DuplicateRow, ImportOptions, ImportPreview, ImportReport, ProblemCode,
    RowProblem, preview_bytes,
};
pub use service::CsvExport;
pub use source::{CsvSource, Field};
pub use table::{
    CsvError, MAX_CELL_BYTES, MAX_COLUMNS, MAX_FILE_BYTES, MAX_ROWS, Table, parse_table,
};
