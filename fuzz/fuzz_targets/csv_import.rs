//! CSV import (T23): arbitrary bytes through the parser and the row mapping of every source, and the
//! formula guard on arbitrary text. The dry run must not panic and its counts must add up.
#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use cerberus_core::csvio::{
    CsvSource, DuplicatePolicy, ImportOptions, guard_cell, preview_bytes, unguard_cell,
};
use cerberus_types::{Environment, WorkspaceId};
use libfuzzer_sys::fuzz_target;

const SOURCES: [CsvSource; 7] = [
    CsvSource::Auto,
    CsvSource::Bitwarden,
    CsvSource::OnePassword,
    CsvSource::KeePassXc,
    CsvSource::Chrome,
    CsvSource::Firefox,
    CsvSource::Generic,
];

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    let source = SOURCES[usize::from(*first) % SOURCES.len()];
    let options = ImportOptions {
        source,
        workspace_id: WorkspaceId::generate(),
        environment: Environment::Dev,
        role_label: None,
        mapping: BTreeMap::new(),
        duplicates: if first & 0x80 == 0 {
            DuplicatePolicy::Skip
        } else {
            DuplicatePolicy::Rename
        },
    };
    let existing: BTreeSet<String> = ["existing title".to_owned()].into();
    if let Ok(preview) = preview_bytes(rest, &options, &existing) {
        // An unknown header (no source) plans no row, so the counts only add up with a source.
        if preview.source.is_some() {
            let left_out = preview.duplicate_count.saturating_sub(preview.renamed);
            assert_eq!(
                preview.importable + preview.problem_count + left_out,
                preview.total_rows
            );
        }
    }
    if let Ok(text) = std::str::from_utf8(rest) {
        assert_eq!(unguard_cell(&guard_cell(text)), text);
    }
});
