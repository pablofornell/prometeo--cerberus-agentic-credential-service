//! The audit writer: serialized appends, pending drain, prune, export.

use std::io::Write;
use std::sync::Arc;

use cerberus_crypto::{KeyTree, ct_eq};
use cerberus_store::{AuditHeadRow, AuditPendingRow, AuditRow, Blobs, Store, Tx};
use cerberus_types::{Clock, VaultId};
use jiff::{SignedDuration, Timestamp};

use super::chain::{entry_hash, genesis_prev_hash, head_hmac, make_head, row_hmac};
use super::export::export_lines;
use super::verify::{ChainReport, verify_chain};
use super::{Actor, ActorKind, AuditEvent, EventType, Target};
use crate::CoreError;

const PAGE: u32 = 500;

/// Appends to the audit chain. One writer exists while the vault is unlocked.
///
/// The vault service builds it at unlock from the open store, the key tree (it needs `audit_key`
/// for the chain and `meta_key` for the sealed bodies), the vault ID and the clock. Dropping the
/// writer drops its share of the key tree; the keys are erased when the last share is gone, so the
/// service must not keep other shares past lock.
///
/// All appends go through one lock, so the chain has no forks and `seq` has no gaps.
pub struct AuditWriter {
    store: Store,
    keys: Arc<KeyTree>,
    vault_id: VaultId,
    clock: Arc<dyn Clock>,
    gate: tokio::sync::Mutex<()>,
    /// The `seq` of a break mark written and not yet reported (AUD-1).
    break_seen: std::sync::Mutex<Option<u64>>,
    /// The vault already has a log (a writer made at unlock), so a log with no head and no row
    /// was wiped, not new (AUD-1, DEC-T27-A1-1).
    log_expected: bool,
}

impl AuditWriter {
    /// A writer for the vault `vault_id`.
    #[must_use]
    pub fn new(store: Store, keys: Arc<KeyTree>, vault_id: VaultId, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            keys,
            vault_id,
            clock,
            gate: tokio::sync::Mutex::new(()),
            break_seen: std::sync::Mutex::new(None),
            log_expected: false,
        }
    }

    /// The same writer for a vault that already has a log: an empty log (no head, no row) is then
    /// a cut, and the first append chains a break mark before it (AUD-1). A writer made at vault
    /// create must not use this, because its log is empty until `vault.create` is written.
    #[must_use]
    pub(crate) fn expecting_log(mut self) -> Self {
        self.log_expected = true;
        self
    }

    /// Appends one event stamped with the clock. Returns its `seq`.
    ///
    /// The caller decides what a failure means: a secret read must fail with it, other actions
    /// log it and go on (ADR-0025).
    ///
    /// # Errors
    /// A storage or crypto error.
    pub async fn append(&self, event: &AuditEvent) -> Result<u64, CoreError> {
        let _gate = self.gate.lock().await;
        let at = self.clock.now();
        let seqs = self.write_batch(&[(at, event.clone())]).await?;
        seqs.last().copied().ok_or(CoreError::Corrupt)
    }

    /// Moves the events written while locked into the chain, oldest first, each marked
    /// `details.recorded_while_locked = true`. Returns the number of events written, not counting
    /// the overflow note.
    ///
    /// The pending rows are taken and the events chained in one transaction. If anything fails or
    /// the process dies before the commit, the rows stay pending and the chain is unchanged
    /// (DEC-WIRE-1).
    ///
    /// # Errors
    /// A storage or crypto error.
    pub async fn drain_pending(&self) -> Result<u64, CoreError> {
        let _gate = self.gate.lock().await;
        let mut tx = self.store.begin().await?;
        let take = tx.take_audit_pending().await?;
        let mut malformed = take.malformed;
        let mut events: Vec<(Timestamp, AuditEvent)> = Vec::with_capacity(take.rows.len() + 1);
        for row in &take.rows {
            // The rows are not authenticated (AR-6). Only the types that code writes while
            // locked are accepted; any other row is counted with the unreadable ones (AUD-9).
            if LOCKED_TYPES.iter().any(|t| t.as_str() == row.event_type) {
                events.push(pending_event(row));
            } else {
                malformed = malformed.saturating_add(1);
            }
        }
        let written = events.len() as u64;
        if take.overflow > 0 || malformed > 0 {
            let note = AuditEvent::new(EventType::AuditPendingOverflow, Actor::system())
                .detail("dropped", take.overflow)
                .detail("malformed", malformed)
                .detail("recorded_while_locked", true);
            events.push((self.clock.now(), note));
        }
        self.chain_events(&mut tx, &events).await?;
        tx.commit().await?;
        Ok(written)
    }

    /// The `seq` of the newest break mark this writer wrote, if one was written since the last
    /// call (AUD-1). The vault service raises the integrity alert for it.
    pub(crate) fn take_break(&self) -> Option<u64> {
        self.break_seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Checks the whole chain. See [`verify_chain`].
    ///
    /// # Errors
    /// A storage error.
    pub async fn verify(&self) -> Result<ChainReport, CoreError> {
        let _gate = self.gate.lock().await;
        verify_chain(&self.store, &self.keys, &self.vault_id).await
    }

    /// Deletes rows older than `retention_days`, always keeping the newest row, and writes
    /// `audit.prune`. The chain is verified first; a broken chain is not pruned
    /// ([`CoreError::Corrupt`]), so pruning cannot hide a break. Returns the rows deleted.
    ///
    /// # Errors
    /// [`CoreError::Corrupt`] for a broken chain, or a storage error.
    pub async fn prune(&self, retention_days: u32, actor: Actor) -> Result<u64, CoreError> {
        let _gate = self.gate.lock().await;
        let now = self.clock.now();
        if !matches!(
            verify_chain(&self.store, &self.keys, &self.vault_id).await?,
            ChainReport::Ok { .. }
        ) {
            return Err(CoreError::Corrupt);
        }
        let Some(head) = self.store.audit_head().await? else {
            return Ok(0);
        };
        let age = SignedDuration::from_hours(24_i64.saturating_mul(i64::from(retention_days)));
        let cutoff = now.checked_sub(age).map_err(|_| CoreError::Corrupt)?;
        let Some(keep) = self
            .first_kept(head.anchor_seq, head.last_seq, cutoff)
            .await?
        else {
            return Ok(0);
        };
        if keep.seq <= head.anchor_seq {
            return Ok(0);
        }
        let new_head = make_head(
            &self.keys.audit_key,
            head.last_seq,
            head.last_entry_hash,
            keep.seq,
            keep.prev_hash,
        );
        let mut tx = self.store.begin().await?;
        // The head was checked by the walk above; it must be the same head inside the write.
        if tx.audit_head().await?.as_ref() != Some(&head) {
            return Err(CoreError::Conflict);
        }
        let deleted = tx.prune_audit(keep.seq, &new_head).await?;
        tx.commit().await?;
        let event = AuditEvent::new(EventType::AuditPrune, actor)
            .target("vault", self.vault_id.to_string())
            .detail("deleted", deleted)
            .detail("first_kept_seq", keep.seq);
        self.write_batch(&[(now, event)]).await?;
        Ok(deleted)
    }

    /// Writes every row as one JSON line (`seq`, `occurred_at`, hex `prev_hash` and `hmac`, and the
    /// opened body), then records `audit.export`. Returns the number of lines.
    ///
    /// # Errors
    /// A storage, crypto or write error.
    pub async fn export_jsonl(
        &self,
        actor: Actor,
        out: &mut (dyn Write + Send),
    ) -> Result<u64, CoreError> {
        let _gate = self.gate.lock().await;
        let blobs = Blobs::new(&self.vault_id, &self.keys);
        let count = export_lines(&self.store, &blobs, out).await?;
        let event = AuditEvent::new(EventType::AuditExport, actor)
            .target("vault", self.vault_id.to_string())
            .detail("rows", count);
        self.write_batch(&[(self.clock.now(), event)]).await?;
        Ok(count)
    }

    /// The first row to keep: the first with `occurred_at >= cutoff`, or the last row.
    async fn first_kept(
        &self,
        from: u64,
        last_seq: u64,
        cutoff: Timestamp,
    ) -> Result<Option<AuditRow>, CoreError> {
        let mut next = from;
        let mut newest = None;
        loop {
            let page = self.store.audit_range(next, PAGE).await?;
            let Some(last) = page.last() else { break };
            next = last.seq.saturating_add(1);
            for row in page {
                if row.occurred_at >= cutoff || row.seq == last_seq {
                    return Ok(Some(row));
                }
                newest = Some(row);
            }
        }
        Ok(newest)
    }

    /// Chains and writes `events` in one transaction. The caller holds the gate.
    async fn write_batch(&self, events: &[(Timestamp, AuditEvent)]) -> Result<Vec<u64>, CoreError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.store.begin().await?;
        let written = self.chain_events(&mut tx, events).await?;
        tx.commit().await?;
        Ok(written)
    }

    /// Where the next row goes, read and checked inside `tx` (AUD-1).
    ///
    /// The head is used only when its HMAC is good and the newest row agrees with it (same
    /// `last_seq`, same entry hash), and a log without a head is used only when it has no row and
    /// the writer does not expect a log ([`Self::expecting_log`]). Otherwise the head was changed or the log was cut: a break mark
    /// ([`EventType::IntegrityRowMacMismatch`] on target `audit_head`) is chained after the newest
    /// row that is there. [`verify_chain`] reports that mark as `HeadMismatch` for good, so a cut
    /// can never read as "chain OK" again, and appends go on (a secret read is never blocked).
    async fn chain_position(
        &self,
        tx: &mut Tx<'_>,
    ) -> Result<(Position, Option<AuditEvent>), CoreError> {
        let genesis = genesis_prev_hash(&self.vault_id);
        let head = tx.audit_head().await?;
        let last = tx.audit_end(true).await?;
        let problem = match (&head, &last) {
            (None, None) if self.log_expected => "log_missing",
            (None, None) => {
                return Ok((
                    Position {
                        seq: 0,
                        prev: genesis,
                        anchor_seq: 1,
                        anchor_prev: genesis,
                    },
                    None,
                ));
            }
            (None, Some(_)) => "head_missing",
            (Some(h), _) if !head_is_signed(&self.keys.audit_key, h) => "head_hmac",
            (Some(h), Some(row))
                if row.seq == h.last_seq && ct_eq(&row_hash(row), &h.last_entry_hash) =>
            {
                return Ok((
                    Position {
                        seq: h.last_seq,
                        prev: h.last_entry_hash,
                        anchor_seq: h.anchor_seq,
                        anchor_prev: h.anchor_prev_hash,
                    },
                    None,
                ));
            }
            (Some(_), _) => "tail",
        };
        // A break. Chain after the newest row there is; keep a signed anchor, else start the walk
        // at the oldest row there is.
        let signed = head
            .as_ref()
            .filter(|h| head_is_signed(&self.keys.audit_key, h));
        let (seq, prev) = match &last {
            Some(row) => (row.seq.max(signed.map_or(0, |h| h.last_seq)), row_hash(row)),
            None => (signed.map_or(0, |h| h.last_seq), genesis),
        };
        let (anchor_seq, anchor_prev) = match (signed, tx.audit_end(false).await?) {
            (Some(h), _) => (h.anchor_seq, h.anchor_prev_hash),
            (None, Some(first)) => (first.seq, first.prev_hash),
            (None, None) => (seq.saturating_add(1), prev),
        };
        let mark = AuditEvent::new(EventType::IntegrityRowMacMismatch, Actor::system())
            .target("audit_head", "1")
            .result("vault_corrupt")
            .detail("chain", "head_mismatch")
            .detail("problem", problem)
            .detail("head_last_seq", head.as_ref().map(|h| h.last_seq))
            .detail("found_last_seq", last.as_ref().map(|row| row.seq));
        Ok((
            Position {
                seq,
                prev,
                anchor_seq,
                anchor_prev,
            },
            Some(mark),
        ))
    }

    /// Chains `events` after the checked head and appends them in `tx`, which the caller commits.
    /// The caller holds the gate.
    async fn chain_events(
        &self,
        tx: &mut Tx<'_>,
        events: &[(Timestamp, AuditEvent)],
    ) -> Result<Vec<u64>, CoreError> {
        let (position, mark) = self.chain_position(tx).await?;
        let Position {
            mut seq,
            mut prev,
            anchor_seq,
            anchor_prev,
        } = position;
        let marked = mark.map(|event| (self.clock.now(), event));
        let blobs = Blobs::new(&self.vault_id, &self.keys);
        let mut written = Vec::with_capacity(events.len());
        let mut mark_seq = None;
        for (index, (at, event)) in marked.iter().chain(events).enumerate() {
            seq = seq.saturating_add(1);
            let at =
                Timestamp::from_millisecond(at.as_millisecond()).map_err(|_| CoreError::Corrupt)?;
            let body = serde_json::to_vec(event).map_err(|_| CoreError::Corrupt)?;
            let body_ct = blobs.seal_audit_body(seq, &body)?;
            let hash = entry_hash(seq, at.as_millisecond(), &prev, &body_ct);
            let row = AuditRow {
                seq,
                occurred_at: at,
                prev_hash: prev,
                hmac: row_hmac(&self.keys.audit_key, &hash),
                body_ct,
            };
            let new_head = make_head(&self.keys.audit_key, seq, hash, anchor_seq, anchor_prev);
            tx.append_audit(&row, &new_head).await?;
            prev = hash;
            if marked.is_some() && index == 0 {
                mark_seq = Some(seq);
            } else {
                written.push(seq);
            }
        }
        if let Some(at) = mark_seq {
            tracing::warn!(seq = at, "audit head did not match the log; break marked");
            *self
                .break_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(at);
        }
        Ok(written)
    }
}

/// The next free place in the chain.
struct Position {
    seq: u64,
    prev: [u8; 32],
    anchor_seq: u64,
    anchor_prev: [u8; 32],
}

/// Event types that the code writes to `audit_pending` while locked (ADR-0025).
const LOCKED_TYPES: &[EventType] = &[
    EventType::VaultUnlockFailed,
    EventType::ApiLockedCall,
    EventType::AuthFailed,
    EventType::ItemExpire,
    EventType::BackupRecover,
];

fn row_hash(row: &AuditRow) -> [u8; 32] {
    entry_hash(
        row.seq,
        row.occurred_at.as_millisecond(),
        &row.prev_hash,
        &row.body_ct,
    )
}

fn head_is_signed(audit_key: &cerberus_crypto::Key32, head: &AuditHeadRow) -> bool {
    ct_eq(
        &head_hmac(
            audit_key,
            head.last_seq,
            &head.last_entry_hash,
            head.anchor_seq,
            &head.anchor_prev_hash,
        ),
        &head.head_hmac,
    )
}

/// A pending row as a chain event (ADR-0025).
fn pending_event(row: &AuditPendingRow) -> (Timestamp, AuditEvent) {
    let actor = row
        .agent_id
        .as_ref()
        .map_or_else(Actor::system, |id| Actor {
            kind: ActorKind::Agent,
            id: Some(id.to_string()),
        });
    let kind = row
        .event_type
        .parse::<EventType>()
        .ok()
        .and_then(EventType::target_kind)
        .unwrap_or("unknown");
    let mut event = AuditEvent {
        event_type: row.event_type.clone(),
        actor,
        target: row.target_id.as_ref().map(|id| Target {
            kind: kind.to_owned(),
            id: id.clone(),
        }),
        result: row.result_code.clone(),
        request_id: row.request_id,
        details: serde_json::Map::new(),
    };
    event = event.detail("recorded_while_locked", true);
    if let Some(route) = &row.route {
        event = event.detail("route", route.as_str());
    }
    (row.occurred_at, event)
}
