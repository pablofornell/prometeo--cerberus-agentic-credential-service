//! Chain verification: finds the first broken `seq`.

use cerberus_crypto::{KeyTree, ct_eq};
use cerberus_store::{AuditHeadRow, AuditRow, Blobs, Store};
use cerberus_types::VaultId;

use super::chain::{entry_hash, head_hmac, row_hmac};
use super::{AuditEvent, EventType};
use crate::CoreError;

const PAGE: u32 = 500;

/// What is wrong at the reported `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakKind {
    /// The row HMAC does not match its content (a changed body, time, `seq` or HMAC).
    HmacMismatch,
    /// `prev_hash` is not the hash of the row before.
    PrevHashMismatch,
    /// A row is missing (a gap in `seq`).
    MissingRow,
    /// The head disagrees with the rows (cut tail, extra rows, or a changed head).
    HeadMismatch,
    /// The body does not decrypt or is not an audit event.
    UnreadableBody,
}

impl BreakKind {
    /// The stable text name, for example `head_mismatch`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacMismatch => "hmac_mismatch",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::MissingRow => "missing_row",
            Self::HeadMismatch => "head_mismatch",
            Self::UnreadableBody => "unreadable_body",
        }
    }
}

/// Result of [`verify_chain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainReport {
    /// Every row is good. An empty log gives `count = 0` and zeros.
    Ok {
        /// Rows checked.
        count: u64,
        /// First `seq` checked (the anchor).
        first_seq: u64,
        /// Last `seq` checked.
        last_seq: u64,
    },
    /// The first problem that is not a break mark; when the marks are the only problem, the
    /// first mark (`HeadMismatch` at its `seq`).
    Broken {
        /// Position of the problem.
        seq: u64,
        /// The reason.
        kind: BreakKind,
    },
}

const fn broken(seq: u64, kind: BreakKind) -> ChainReport {
    ChainReport::Broken { seq, kind }
}

/// Walks the chain from the anchor to the end and reports the first problem, or `Ok`.
///
/// Order of checks: the head HMAC, then each row (gap, `prev_hash`, HMAC, body), then the head
/// against the last row. A break mark that the writer chained after it found a changed head or a
/// cut log (AUD-1) is reported as `HeadMismatch` at its `seq`; a gap in `seq` that ends at a good
/// mark is the cut that the mark reports, and stays `MissingRow` at the first missing `seq`. The
/// walk goes on past a mark (it is a good, chained row), so a later break is still found and
/// reported instead of the mark: marks are permanent, and without this one mark would hide every
/// later edit (NEW-2, DEC-T27-D1-4).
///
/// # Errors
/// A storage error, not a chain problem.
pub async fn verify_chain(
    store: &Store,
    keys: &KeyTree,
    vault_id: &VaultId,
) -> Result<ChainReport, CoreError> {
    let mut walk = ChainWalk::start(store, keys, true).await?;
    loop {
        if let Some(report) = walk.step(store, keys, vault_id).await? {
            return Ok(report);
        }
    }
}

/// A chain walk one page at a time, so a caller can let go of its locks between pages.
pub(crate) struct ChainWalk {
    head: Option<AuditHeadRow>,
    next_seq: u64,
    prev: [u8; 32],
    count: u64,
    /// Walk past `head.last_seq` and report rows there as a head mismatch. Without it the walk
    /// ends at the head that was read at the start (rows appended since then are not checked).
    strict_end: bool,
    /// The report for the first break mark seen (the mark, or the gap that ends at it). It is the
    /// report when nothing after it is wrong.
    first_mark: Option<ChainReport>,
    done: Option<ChainReport>,
}

impl ChainWalk {
    /// Reads the head and checks its HMAC.
    ///
    /// # Errors
    /// A storage error.
    pub(crate) async fn start(
        store: &Store,
        keys: &KeyTree,
        strict_end: bool,
    ) -> Result<Self, CoreError> {
        let head = store.audit_head().await?;
        let mut walk = Self {
            next_seq: head.as_ref().map_or(0, |h| h.anchor_seq),
            prev: head.as_ref().map_or([0; 32], |h| h.anchor_prev_hash),
            head,
            count: 0,
            strict_end,
            first_mark: None,
            done: None,
        };
        match &walk.head {
            None => {
                walk.done = Some(match store.audit_range(0, 1).await?.first() {
                    Some(row) => broken(row.seq, BreakKind::HeadMismatch),
                    None => ChainReport::Ok {
                        count: 0,
                        first_seq: 0,
                        last_seq: 0,
                    },
                });
            }
            Some(head) => {
                let expected = head_hmac(
                    &keys.audit_key,
                    head.last_seq,
                    &head.last_entry_hash,
                    head.anchor_seq,
                    &head.anchor_prev_hash,
                );
                if !ct_eq(&expected, &head.head_hmac) {
                    walk.done = Some(broken(head.last_seq, BreakKind::HeadMismatch));
                }
            }
        }
        Ok(walk)
    }

    /// The anchor of the head read at the start (a prune moves it).
    pub(crate) fn anchor(&self) -> Option<u64> {
        self.head.as_ref().map(|h| h.anchor_seq)
    }

    /// Checks the next page. Returns the report when the walk is over.
    ///
    /// # Errors
    /// A storage error.
    pub(crate) async fn step(
        &mut self,
        store: &Store,
        keys: &KeyTree,
        vault_id: &VaultId,
    ) -> Result<Option<ChainReport>, CoreError> {
        if let Some(done) = self.done {
            return Ok(Some(done));
        }
        let Some(head) = self.head.clone() else {
            return Ok(self.done);
        };
        let page = store.audit_range(self.next_seq, PAGE).await?;
        let blobs = Blobs::new(vault_id, keys);
        let mut end = page.is_empty();
        for row in &page {
            if !self.strict_end && row.seq > head.last_seq {
                end = true;
                break;
            }
            let check = check_row(row, &self.prev, keys, &blobs);
            if row.seq != self.next_seq {
                let gap = broken(self.next_seq, BreakKind::MissingRow);
                // The writer chains a mark after a cut tail at the old head `seq` + 1, so a gap
                // that ends at a good mark is that cut; the walk goes on (NEW-2).
                if row.seq < self.next_seq || !matches!(check, Ok(RowCheck::Mark)) {
                    return Ok(self.finish(gap));
                }
                self.first_mark.get_or_insert(gap);
            }
            match check {
                Ok(RowCheck::Event) => {}
                Ok(RowCheck::Mark) => {
                    self.first_mark
                        .get_or_insert(broken(row.seq, BreakKind::HeadMismatch));
                }
                Err(kind) => return Ok(self.finish(broken(row.seq, kind))),
            }
            self.prev = entry_hash(
                row.seq,
                row.occurred_at.as_millisecond(),
                &row.prev_hash,
                &row.body_ct,
            );
            self.next_seq = row.seq.saturating_add(1);
            self.count = self.count.saturating_add(1);
        }
        if !self.strict_end && self.next_seq > head.last_seq {
            end = true;
        }
        if !end {
            return Ok(None);
        }
        let last_checked = self.next_seq.saturating_sub(1);
        let report = if last_checked != head.last_seq {
            let at = last_checked.min(head.last_seq).saturating_add(1);
            broken(at, BreakKind::HeadMismatch)
        } else if !ct_eq(&self.prev, &head.last_entry_hash) {
            broken(head.last_seq, BreakKind::HeadMismatch)
        } else if let Some(mark) = self.first_mark {
            mark
        } else {
            ChainReport::Ok {
                count: self.count,
                first_seq: head.anchor_seq,
                last_seq: head.last_seq,
            }
        };
        Ok(self.finish(report))
    }

    fn finish(&mut self, report: ChainReport) -> Option<ChainReport> {
        self.done = Some(report);
        self.done
    }
}

/// A row that passed its checks.
enum RowCheck {
    /// An ordinary event.
    Event,
    /// A break mark (AUD-1): a good row that reports an earlier break.
    Mark,
}

fn check_row(
    row: &AuditRow,
    expected_prev: &[u8; 32],
    keys: &KeyTree,
    blobs: &Blobs<'_>,
) -> Result<RowCheck, BreakKind> {
    if !ct_eq(&row.prev_hash, expected_prev) {
        return Err(BreakKind::PrevHashMismatch);
    }
    let hash = entry_hash(
        row.seq,
        row.occurred_at.as_millisecond(),
        &row.prev_hash,
        &row.body_ct,
    );
    if !ct_eq(&row_hmac(&keys.audit_key, &hash), &row.hmac) {
        return Err(BreakKind::HmacMismatch);
    }
    match open_body(blobs, row) {
        Err(_) => Err(BreakKind::UnreadableBody),
        Ok(event) if is_break_mark(&event) => Ok(RowCheck::Mark),
        Ok(_) => Ok(RowCheck::Event),
    }
}

/// True for the mark the writer chains after it found a changed head or a cut log (AUD-1).
pub(crate) fn is_break_mark(event: &AuditEvent) -> bool {
    event.event_type == EventType::IntegrityRowMacMismatch.as_str()
        && event
            .target
            .as_ref()
            .is_some_and(|target| target.kind == "audit_head")
}

/// Opens and parses the body of one row.
pub(crate) fn open_body(blobs: &Blobs<'_>, row: &AuditRow) -> Result<AuditEvent, CoreError> {
    let plain = blobs.open_audit_body(row.seq, &row.body_ct)?;
    serde_json::from_slice(plain.expose_secret()).map_err(|_| CoreError::Corrupt)
}
