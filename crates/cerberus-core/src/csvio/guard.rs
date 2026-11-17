//! Spreadsheet formula injection guard (OWASP "CSV Injection"). A cell that starts with `=`, `+`,
//! `-`, `@`, a tab or a carriage return can run as a formula when the file opens in a
//! spreadsheet. The export puts one `'` in front of such a cell. A cell that starts with `'`
//! followed by such a character gets one more `'`, so [`unguard_cell`] undoes the guard exactly.

const TRIGGERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

fn needs_guard(cell: &str) -> bool {
    cell.trim_start_matches('\'')
        .chars()
        .next()
        .is_some_and(|c| TRIGGERS.contains(&c))
}

/// The cell as it is written to the export file.
#[must_use]
pub fn guard_cell(cell: &str) -> String {
    if needs_guard(cell) {
        format!("'{cell}")
    } else {
        cell.to_owned()
    }
}

/// Undoes [`guard_cell`] for a file the export wrote.
#[must_use]
pub fn unguard_cell(cell: &str) -> &str {
    match cell.strip_prefix('\'') {
        Some(rest) if needs_guard(rest) => rest,
        _ => cell,
    }
}
