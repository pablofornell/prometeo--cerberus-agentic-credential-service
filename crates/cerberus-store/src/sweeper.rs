//! The expiry sweeper (ADR-0027). It needs no key, so it runs while the vault is locked.
//!
//! It deletes by the plain `expires_at` columns only, with `secure_delete = ON`, then shrinks the file.
//! The sealed expiry copy (ADR-0033 point 6) needs keys, so the vault service deletes by it after each
//! sweep while unlocked (AUD-8).
//! Each expired item is also written to `audit_pending` as an `item.expire` event in the same
//! transaction, so no event is lost. The vault service folds those rows into the audit chain at the
//! next unlock, or while unlocked (ADR-0025).

use std::sync::Arc;
use std::time::Duration;

use cerberus_types::{Clock, ItemId};
use jiff::{SignedDuration, Timestamp};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::rows::AuditPendingRow;
use crate::{Store, StoreError};

/// Most rows that wait in `audit_pending` (ADR-0025). More events only raise the overflow counter.
pub const AUDIT_PENDING_CAP: u32 = 10_000;

/// A lease that has been inactive this long is deleted. A revoked auto lease counts as inactive
/// only from its old end, not from the revoke (ADR-0019 point 7).
const LEASE_GRACE: SignedDuration = SignedDuration::from_hours(1);
/// A finished access request is kept this long.
const REQUEST_KEEP: SignedDuration = SignedDuration::from_hours(7 * 24);
/// Full `VACUUM` at most once in this time.
const FULL_VACUUM_EVERY: SignedDuration = SignedDuration::from_hours(24);
/// `incremental_vacuum` runs after more rows than this were deleted in one sweep.
const INCREMENTAL_VACUUM_ROWS: u64 = 100;

/// What one sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Items deleted because `expires_at` passed.
    pub expired_items: Vec<ItemId>,
    /// Inactive leases deleted.
    pub leases_deleted: u64,
    /// Old access requests deleted.
    pub requests_deleted: u64,
    /// A full `VACUUM` ran.
    pub vacuumed: bool,
}

/// Deletes expired rows and keeps the file small.
#[derive(Debug)]
pub struct Sweeper {
    store: Store,
    last_full_vacuum: Option<Timestamp>,
    deleted_since_vacuum: bool,
}

fn before(now: Timestamp, span: SignedDuration) -> Result<Timestamp, StoreError> {
    now.checked_sub(span).map_err(|_| StoreError::Corrupt)
}

impl Sweeper {
    /// A sweeper for this store.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            last_full_vacuum: None,
            deleted_since_vacuum: false,
        }
    }

    /// One sweep at time `now`:
    /// 1. delete items with `expires_at <= now` (versions, leases and requests of the item go with them);
    /// 2. delete leases inactive for over 1 hour (a revoked auto lease from its old end) and access
    ///    requests finished over 7 days ago;
    /// 3. after any delete, `wal_checkpoint(TRUNCATE)`, so removed bytes leave the WAL file;
    /// 4. `incremental_vacuum` after over 100 deleted rows;
    /// 5. a full `VACUUM` at most once in 24 hours, when something was deleted since the last one.
    ///
    /// # Errors
    /// An engine error. Nothing is deleted then, except what an earlier step already committed.
    pub async fn run_once(&mut self, now: Timestamp) -> Result<SweepReport, StoreError> {
        let mut tx = self.store.begin().await?;
        let (expired_items, leases_deleted, requests_deleted) = tx
            .sweep(now, before(now, LEASE_GRACE)?, before(now, REQUEST_KEEP)?)
            .await?;
        for id in &expired_items {
            let event = AuditPendingRow {
                occurred_at: now,
                event_type: "item.expire".to_owned(),
                agent_id: None,
                target_id: Some(id.to_string()),
                result_code: "ok".to_owned(),
                route: None,
                request_id: None,
            };
            tx.push_audit_pending(&event, AUDIT_PENDING_CAP).await?;
        }
        tx.commit().await?;

        let deleted = u64::try_from(expired_items.len()).unwrap_or(u64::MAX)
            + leases_deleted
            + requests_deleted;
        let mut vacuumed = false;
        if deleted > 0 {
            self.deleted_since_vacuum = true;
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&self.store.pool)
                .await?;
            if deleted > INCREMENTAL_VACUUM_ROWS {
                sqlx::query("PRAGMA incremental_vacuum")
                    .execute(&self.store.pool)
                    .await?;
            }
        }
        let due = match self.last_full_vacuum {
            None => true,
            Some(last) => now >= last.checked_add(FULL_VACUUM_EVERY).unwrap_or(last),
        };
        if self.deleted_since_vacuum && due {
            sqlx::query("VACUUM").execute(&self.store.pool).await?;
            self.last_full_vacuum = Some(now);
            self.deleted_since_vacuum = false;
            vacuumed = true;
        }
        Ok(SweepReport {
            expired_items,
            leases_deleted,
            requests_deleted,
            vacuumed,
        })
    }

    /// Runs `run_once` every `period`, with the time from `clock`. Every report is sent on `on_report`, also
    /// one that did nothing, so the receiver can run its own work after each sweep (the vault service
    /// deletes items by their sealed expiry then, AUD-8). A failed sweep is logged and tried again. The task
    /// ends when the receiver is dropped; abort the handle to stop it earlier.
    #[must_use]
    pub fn spawn(
        mut self,
        period: Duration,
        clock: Arc<dyn Clock>,
        on_report: mpsc::Sender<SweepReport>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                match self.run_once(clock.now()).await {
                    Ok(report) => {
                        if on_report.send(report).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => tracing::warn!(%error, "expiry sweep failed"),
                }
            }
        })
    }
}
