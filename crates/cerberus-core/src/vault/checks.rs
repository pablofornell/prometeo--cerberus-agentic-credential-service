//! Integrity checks of stored data at and after unlock (T27): the sealed kind of each item and
//! the upgrade of items written before it was sealed, items whose sealed expiry has passed, rows
//! with a bad MAC that a bulk change left alone, and one walk of the audit chain per unlock.

use cerberus_store::{CancelReport, ItemRow, RevokeReport, SealedPayload};
use cerberus_types::{ItemId, ItemKind};
use jiff::Timestamp;

use super::VaultService;
use super::events::CoreEvent;
use super::state::Unlocked;
use crate::audit::{Actor, AuditEvent, ChainReport, ChainWalk, EventType};
use crate::error::CoreError;
use crate::index::{ItemMeta, KindSource, decode_item_meta, encode_item_meta};
use crate::items::Payload;

/// An item that the index takes, at its current version.
type Indexed = (ItemMeta, u32);
/// A row that is left out of the index, for the alert: table name and row ID.
type BadRow = (&'static str, String);

impl VaultService {
    /// Opens every item row for the index (ADR-0006).
    ///
    /// - The metadata must open under the row's `current_version` (the AAD holds it), and its
    ///   sealed kind must be the plain `items.kind` (AUD-2).
    /// - Metadata written before T27 has no sealed kind. Its plain kind is taken only when the
    ///   authenticated payload of the current version has the same kind; then the metadata is
    ///   sealed again with the kind in it, so the upgrade happens once (DEC-T27-A1-2).
    ///
    /// A row that fails is left out and returned, so the caller raises the integrity alert.
    pub(super) async fn index_items(
        &self,
        unlocked: &Unlocked,
        rows: &[ItemRow],
    ) -> (Vec<Indexed>, Vec<BadRow>) {
        let blobs = unlocked.blobs();
        let mut good = Vec::with_capacity(rows.len());
        let mut bad = Vec::new();
        let mut upgrade = Vec::new();
        for row in rows {
            let decoded = blobs
                .open_item_meta(&row.id, row.current_version, &row.meta_ct)
                .map_err(CoreError::from)
                .and_then(|plain| decode_item_meta(row, &plain));
            let meta = match decoded {
                Ok((meta, KindSource::Sealed)) => meta,
                Ok((meta, KindSource::Plain)) => match self.payload_kind(unlocked, row).await {
                    Ok(kind) if kind == row.kind => {
                        upgrade.push((row, meta.clone()));
                        meta
                    }
                    _ => {
                        tracing::warn!(row_id = %row.id, "item kind does not match its payload");
                        bad.push(("items", row.id.to_string()));
                        continue;
                    }
                },
                Err(_) => {
                    tracing::warn!(table = "items", row_id = %row.id, "sealed metadata failed to open");
                    bad.push(("items", row.id.to_string()));
                    continue;
                }
            };
            good.push((meta, row.current_version));
        }
        if !upgrade.is_empty()
            && let Err(error) = self.seal_kinds(unlocked, &upgrade).await
        {
            // The rows stay as they are and are checked the same way at the next unlock.
            tracing::warn!(%error, "item kinds not sealed yet");
        }
        (good, bad)
    }

    /// The kind of the opened payload of the current version of `row`.
    async fn payload_kind(
        &self,
        unlocked: &Unlocked,
        row: &ItemRow,
    ) -> Result<ItemKind, CoreError> {
        let version = self
            .inner
            .store
            .item_version(row.id, row.current_version)
            .await?;
        let plain = unlocked.blobs().open_payload(
            &row.id,
            row.current_version,
            &SealedPayload {
                wrapped_dek: version.wrapped_dek,
                payload_ct: version.payload_ct,
            },
        )?;
        Ok(Payload::from_json(plain.expose_secret())?.kind())
    }

    /// Seals the metadata of pre-T27 rows again, now with the kind, in one transaction. Each row
    /// is changed only while it is still the row that was checked (a compare and set).
    async fn seal_kinds(
        &self,
        unlocked: &Unlocked,
        rows: &[(&ItemRow, ItemMeta)],
    ) -> Result<(), CoreError> {
        let blobs = unlocked.blobs();
        let mut tx = self.inner.store.begin().await?;
        let mut sealed = 0_usize;
        for (row, meta) in rows {
            let json = encode_item_meta(meta)?;
            let meta_ct = blobs.seal_item_meta(&row.id, row.current_version, &json)?;
            if tx
                .replace_item_meta_if(
                    row.id,
                    row.kind,
                    row.current_version,
                    &row.meta_ct,
                    &meta_ct,
                )
                .await?
            {
                sealed += 1;
            }
        }
        tx.commit().await?;
        tracing::info!(sealed, "sealed the kind of items written before T27");
        Ok(())
    }

    /// Raises the alert for each lease and request that a bulk change left alone because its
    /// row MAC is bad (AUD-7), and once per table for rows it could not read (NEW-3).
    pub(super) async fn report_bad_macs(
        &self,
        unlocked: &Unlocked,
        revoked: &RevokeReport,
        cancelled: &CancelReport,
    ) {
        for id in &revoked.bad_mac {
            self.integrity_issue(unlocked, "leases", id.to_string())
                .await;
        }
        for id in &cancelled.bad_mac {
            self.integrity_issue(unlocked, "access_requests", id.to_string())
                .await;
        }
        self.unreadable_rows(unlocked, "leases", revoked.malformed)
            .await;
        self.unreadable_rows(unlocked, "access_requests", cancelled.malformed)
            .await;
    }

    /// Rows of `table` that a bulk change skipped because they cannot be read (NEW-3): writes
    /// `integrity.row_mac_mismatch` with the count (`malformed`) and raises the alert with no row
    /// ID (the ID itself may be what is broken). Does nothing for a count of 0.
    pub(crate) async fn unreadable_rows(
        &self,
        unlocked: &Unlocked,
        table: &'static str,
        count: u64,
    ) {
        if count == 0 {
            return;
        }
        tracing::warn!(
            table,
            count,
            "rows that cannot be read were left as they are"
        );
        let event = AuditEvent::new(EventType::IntegrityRowMacMismatch, Actor::system())
            .target(table, "")
            .result("vault_corrupt")
            .detail("malformed", count);
        self.audit(unlocked, event).await;
        self.emit(CoreEvent::IntegrityAlert {
            table,
            row_id: String::new(),
        });
    }

    /// Deletes the items whose effective expiry (the earlier of the plain and the sealed value,
    /// ADR-0033 point 6) has passed. The store sweeper sees only the plain column, so an item whose
    /// plain `expires_at` was cleared or moved later is deleted here (AUD-8). Each delete writes
    /// `item.expire`. Runs after unlock and after each sweep; does nothing while locked.
    pub(crate) async fn delete_sealed_expired(&self, now: Timestamp) {
        let Ok(mut guard) = self.unlocked_mut().await else {
            return;
        };
        let due: Vec<ItemId> = guard
            .index
            .iter_items()
            .filter(|meta| meta.expires_at.is_some_and(|at| now >= at))
            .map(|meta| meta.id)
            .collect();
        if due.is_empty() {
            return;
        }
        let store = &self.inner.store;
        let work = async {
            let mut tx = store.begin().await?;
            let mut deleted = Vec::with_capacity(due.len());
            for id in &due {
                if tx.delete_item(*id).await? {
                    deleted.push(*id);
                }
            }
            tx.commit().await?;
            Ok::<_, CoreError>(deleted)
        };
        let deleted = match work.await {
            Ok(deleted) => deleted,
            Err(error) => {
                tracing::warn!(%error, "delete of expired items failed");
                return;
            }
        };
        // An item the sweeper deleted first has its own pending `item.expire` already.
        for id in &due {
            guard.index.remove_item(id);
        }
        for id in &deleted {
            let event = AuditEvent::new(EventType::ItemExpire, Actor::system())
                .target("item", id.to_string())
                .detail("reason", "sealed_expiry");
            self.audit(&guard, event).await;
        }
        // The checkpoint can take a while; a lock must not wait for it.
        drop(guard);
        if !deleted.is_empty()
            && let Err(error) = store.truncate_wal().await
        {
            tracing::warn!(%error, "WAL checkpoint after the delete failed");
        }
    }

    /// Starts one walk of the audit chain in the background (AUD-1). A break raises the integrity
    /// alert (`audit_events`, with the `seq`) and writes `audit.verify` with the result.
    pub(super) fn spawn_chain_check(&self) {
        let service = self.clone();
        tokio::spawn(async move { service.check_chain().await });
    }

    async fn check_chain(&self) {
        let report = match self.walk_chain().await {
            Ok(Some(report)) => report,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "audit chain check after unlock failed");
                return;
            }
        };
        let ChainReport::Broken { seq, kind } = report else {
            return;
        };
        tracing::warn!(seq, kind = kind.as_str(), "audit chain is broken");
        if let Ok(guard) = self.unlocked().await {
            let event = AuditEvent::new(EventType::AuditVerify, Actor::system())
                .target("vault", guard.vault_id.to_string())
                .result(CoreError::Corrupt.code().as_str())
                .detail("chain", "broken")
                .detail("seq", seq)
                .detail("kind", kind.as_str());
            self.audit(&guard, event).await;
        }
        self.emit(CoreEvent::IntegrityAlert {
            table: "audit_events",
            row_id: seq.to_string(),
        });
    }

    /// Walks the chain up to the head read at the start, one page per read guard, so a lock never
    /// waits for the whole walk. `None` when the vault locked during the walk. A prune that moved
    /// the anchor during the walk starts it once more.
    async fn walk_chain(&self) -> Result<Option<ChainReport>, CoreError> {
        let store = self.inner.store.clone();
        let mut restarted = false;
        let mut walk = {
            let guard = self.unlocked().await?;
            ChainWalk::start(&store, &guard.keys, false).await?
        };
        loop {
            let step = {
                let Ok(guard) = self.unlocked().await else {
                    return Ok(None);
                };
                walk.step(&store, &guard.keys, &guard.vault_id).await?
            };
            match step {
                None => {}
                Some(ChainReport::Broken { .. })
                    if !restarted
                        && store.audit_head().await?.map(|h| h.anchor_seq) != walk.anchor() =>
                {
                    restarted = true;
                    let guard = self.unlocked().await?;
                    walk = ChainWalk::start(&store, &guard.keys, false).await?;
                }
                Some(report) => return Ok(Some(report)),
            }
        }
    }
}
