//! JSON Lines export: metadata only, one event per line.

use std::io::Write;

use cerberus_store::{AuditRow, Blobs, Store};
use serde::Serialize;

use super::AuditEvent;
use super::verify::open_body;
use crate::CoreError;

const PAGE: u32 = 500;

#[derive(Serialize)]
struct Line<'a> {
    seq: u64,
    occurred_at: i64,
    prev_hash: String,
    hmac: String,
    body: &'a AuditEvent,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Writes every row from the anchor on as one JSON line. Returns the number of lines.
pub(crate) async fn export_lines(
    store: &Store,
    blobs: &Blobs<'_>,
    out: &mut (dyn Write + Send),
) -> Result<u64, CoreError> {
    let from = match store.audit_head().await? {
        Some(head) => head.anchor_seq,
        None => return Ok(0),
    };
    let mut next = from;
    let mut count = 0_u64;
    loop {
        let page = store.audit_range(next, PAGE).await?;
        let Some(last) = page.last() else { break };
        next = last.seq.saturating_add(1);
        for row in &page {
            write_line(blobs, row, out)?;
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn write_line(
    blobs: &Blobs<'_>,
    row: &AuditRow,
    out: &mut (dyn Write + Send),
) -> Result<(), CoreError> {
    let body = open_body(blobs, row)?;
    let line = Line {
        seq: row.seq,
        occurred_at: row.occurred_at.as_millisecond(),
        prev_hash: hex(&row.prev_hash),
        hmac: hex(&row.hmac),
        body: &body,
    };
    serde_json::to_writer(&mut *out, &line).map_err(|_| CoreError::Corrupt)?;
    out.write_all(b"\n")
        .map_err(|error| CoreError::Store(error.into()))
}
