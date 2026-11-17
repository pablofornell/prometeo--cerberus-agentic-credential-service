//! Bytes to a table of cells. No semantics: that is `rows`.

use zeroize::Zeroizing;

/// Largest file the importer reads (8 MiB). The desktop layer checks the size before it reads.
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Most data rows (the header is not counted).
pub const MAX_ROWS: usize = 20_000;
/// Most columns.
pub const MAX_COLUMNS: usize = 64;
/// Largest cell in bytes. Larger than any payload limit, so the payload check gives the reason.
pub const MAX_CELL_BYTES: usize = 128 * 1024;

/// Why a file cannot be read as CSV. The text never holds a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CsvError {
    /// More than [`MAX_FILE_BYTES`].
    #[error("the file is larger than 8 MiB")]
    TooLarge,
    /// The bytes are not UTF-8 text.
    #[error("the file is not UTF-8 text; save it as CSV UTF-8 and try again")]
    NotUtf8,
    /// The file is a UTF-16 text (it starts with a UTF-16 byte order mark).
    #[error("the file is UTF-16 text; save it as CSV UTF-8 and try again")]
    Utf16,
    /// No header row.
    #[error("the file has no header row")]
    Empty,
    /// More than [`MAX_ROWS`] data rows.
    #[error("the file has more than 20000 rows")]
    TooManyRows,
    /// More than [`MAX_COLUMNS`] columns in the header.
    #[error("the file has more than 64 columns")]
    TooManyColumns,
    /// A cell is larger than [`MAX_CELL_BYTES`].
    #[error("a cell is larger than 128 KiB")]
    CellTooLarge,
}

/// A data row: its 1-based number among the data rows and its cells.
#[derive(Debug)]
pub struct Row {
    /// 1-based position among the data rows. The header is not counted.
    pub number: u32,
    /// The cells. The count can differ from the header count (a ragged row).
    pub cells: Vec<Zeroizing<String>>,
}

/// A parsed file.
#[derive(Debug)]
pub struct Table {
    /// Header cells, trimmed.
    pub headers: Vec<String>,
    /// Data rows.
    pub rows: Vec<Row>,
}

fn delimiter(first_line: &str) -> u8 {
    let count = |c: char| first_line.chars().filter(|x| *x == c).count();
    let (comma, semi, tab) = (count(','), count(';'), count('\t'));
    if semi > comma && semi >= tab {
        b';'
    } else if tab > comma && tab > semi {
        b'\t'
    } else {
        b','
    }
}

/// Reads CSV text from bytes. Handles a UTF-8 byte order mark, CRLF or LF line ends, quoted
/// separators, quoted new lines and doubled quotes. The delimiter (comma, semicolon or tab) comes
/// from the header line. Empty lines are skipped.
///
/// # Errors
/// [`CsvError`] for a file that is too large, not UTF-8, empty or over a limit.
pub fn parse_table(bytes: &[u8]) -> Result<Table, CsvError> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(CsvError::TooLarge);
    }
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        return Err(CsvError::Utf16);
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|_| CsvError::NotUtf8)?;
    let first_line = text.lines().next().unwrap_or("");
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(delimiter(first_line))
        .from_reader(text.as_bytes());
    let mut record = csv::StringRecord::new();
    let mut headers: Option<Vec<String>> = None;
    let mut rows: Vec<Row> = Vec::new();
    // A broken record (it cannot happen on valid UTF-8 text with `flexible`) ends the read; what
    // was read stays. The record is reused, so only one row of plain text lives outside `rows`.
    while reader.read_record(&mut record).unwrap_or(false) {
        if record.iter().any(|cell| cell.len() > MAX_CELL_BYTES) {
            return Err(CsvError::CellTooLarge);
        }
        if headers.is_none() {
            if record.len() > MAX_COLUMNS {
                return Err(CsvError::TooManyColumns);
            }
            headers = Some(record.iter().map(|c| c.trim().to_owned()).collect());
            continue;
        }
        if rows.len() >= MAX_ROWS {
            return Err(CsvError::TooManyRows);
        }
        let number = u32::try_from(rows.len().saturating_add(1)).unwrap_or(u32::MAX);
        rows.push(Row {
            number,
            cells: record
                .iter()
                .map(|c| Zeroizing::new(c.to_owned()))
                .collect(),
        });
    }
    let headers = headers.ok_or(CsvError::Empty)?;
    if headers.iter().all(String::is_empty) {
        return Err(CsvError::Empty);
    }
    Ok(Table { headers, rows })
}
