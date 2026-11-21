//! The store: open, migrate, and the read side of every repository.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cerberus_types::{AccessRequestId, AgentId, Clock, ItemId, LeaseId};
use jiff::Timestamp;
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};

use crate::StoreError;
use crate::convert::{from_u64, to_ms};
use crate::fsutil::{create_private_dir, create_private_file, wal_is_plausible};
use crate::rows::{
    AccessRequestRow, AgentKeyRow, AgentRow, AuditHeadRow, AuditPendingRow, AuditRow, GrantRow,
    HeaderRow, IndexRows, ItemRow, ItemVersionRow, KeySlotRow, LeaseRow, SettingRow, TlsCaRow,
    WorkspaceRow,
};
use crate::tx::Tx;

/// `PRAGMA application_id` of a Cerberus vault: "CBRV" (ADR-0013).
pub const APPLICATION_ID: i64 = 0x4342_5256;

/// Migrations, embedded in the binary. Each file sets `PRAGMA user_version` to its own number.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// How long a writer waits for the database lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

fn latest_version(migrator: &Migrator) -> i64 {
    migrator.iter().map(|m| m.version).max().unwrap_or(0)
}

/// The newest schema version this build knows.
#[must_use]
pub fn schema_version() -> i64 {
    latest_version(&MIGRATOR)
}

/// Where and how to open the vault file.
#[derive(Clone, Debug)]
pub struct OpenOptions {
    /// Path of the vault file (`vault.cerberus`).
    pub path: PathBuf,
    /// Make the file (mode 0600) and its directory (mode 0700) when they are missing.
    pub create: bool,
}

/// The vault database. Cheap to clone: clones share one connection pool.
#[derive(Clone, Debug)]
pub struct Store {
    pub(crate) pool: SqlitePool,
    pub(crate) clock: Arc<dyn Clock>,
}

/// What a file says before we open it for writing.
pub(crate) struct Probe {
    pub(crate) application_id: i64,
    pub(crate) user_version: i64,
    pub(crate) has_tables: bool,
}

/// Reads the application ID and schema version through a read-only connection, so a file that is
/// not ours is never changed (no WAL switch, no pragma writes). A WAL left by a crash counts, so
/// call it only after [`wal_is_plausible`]. Backups are read by `immutable` connections instead.
async fn probe(path: &Path) -> Result<Probe, StoreError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(BUSY_TIMEOUT);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(not_a_database)?;
    let result = async {
        let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&pool)
            .await?;
        let user_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&pool)
            .await?;
        let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master")
            .fetch_one(&pool)
            .await?;
        Ok::<_, sqlx::Error>(Probe {
            application_id,
            user_version,
            has_tables: tables > 0,
        })
    }
    .await;
    pool.close().await;
    result.map_err(not_a_database)
}

/// SQLite error 26 (`SQLITE_NOTADB`) means the file is not a database at all.
pub(crate) fn not_a_database(error: sqlx::Error) -> StoreError {
    match &error {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("26") => StoreError::NotAVault,
        _ => StoreError::from(error),
    }
}

fn connect_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        // `auto_vacuum` only has an effect before the first table exists (ADR-0013 point 2).
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(BUSY_TIMEOUT)
        .pragma("secure_delete", "ON")
        .pragma("trusted_schema", "OFF")
}

impl Store {
    /// Opens the vault file, checks it and brings the schema up to date.
    ///
    /// - A missing file is made when `create` is set (mode 0600, directory mode 0700).
    /// - An empty file is made into a new vault when `create` is set.
    /// - A file that is not a Cerberus vault is refused and never written.
    /// - A `-wal` file whose header does not fit the file (another page size, a bad checksum) is
    ///   refused with `Corrupt` before SQLite reads it (AUD-10).
    /// - A schema newer than this build is refused (`TooNew`).
    /// - An older schema is migrated. A copy `<file>.pre-migrate-v<N>` is written first (ADR-0013).
    ///
    /// Migrations only change structure, so no key is needed.
    ///
    /// # Errors
    /// [`StoreError::NotAVault`], [`StoreError::TooNew`], [`StoreError::Corrupt`] (a bad `-wal`
    /// file), [`StoreError::Io`] (missing file without `create`), or an engine or migration error.
    pub async fn open(opts: OpenOptions, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        Self::open_with(opts, clock, &MIGRATOR).await
    }

    /// `open` with a given migration set. Tests use it to run a newer schema than this build has.
    pub(crate) async fn open_with(
        opts: OpenOptions,
        clock: Arc<dyn Clock>,
        migrator: &Migrator,
    ) -> Result<Self, StoreError> {
        let latest = latest_version(migrator);
        if !opts.path.exists() {
            if !opts.create {
                return Err(StoreError::Io(std::io::ErrorKind::NotFound.into()));
            }
            if let Some(dir) = opts.path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                create_private_dir(dir)?;
            }
            create_private_file(&opts.path)?;
        }
        if !wal_is_plausible(&opts.path)? {
            return Err(StoreError::Corrupt);
        }
        let probe = probe(&opts.path).await?;
        let from_version = if probe.application_id == APPLICATION_ID {
            if probe.user_version > latest {
                return Err(StoreError::TooNew {
                    found: probe.user_version,
                    supported: latest,
                });
            }
            if probe.user_version == 0 {
                return Err(StoreError::NotAVault);
            }
            Some(probe.user_version)
        } else if probe.application_id == 0 && !probe.has_tables && opts.create {
            None
        } else {
            return Err(StoreError::NotAVault);
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(connect_options(&opts.path))
            .await?;
        let store = Self { pool, clock };
        if let Err(error) = store
            .migrate(&opts.path, from_version, latest, migrator)
            .await
        {
            // A store that did not open is closed and waited for, so none of its connections can
            // still remove the `-wal` or `-shm` by name when the caller moves the file (NEW-14).
            store.pool.close().await;
            return Err(error);
        }
        Ok(store)
    }

    /// The part of [`Self::open_with`] after the pool exists: the pre-migrate backup, the
    /// migrations and the version check.
    async fn migrate(
        &self,
        path: &Path,
        from_version: Option<i64>,
        latest: i64,
        migrator: &Migrator,
    ) -> Result<(), StoreError> {
        if let Some(version) = from_version.filter(|version| *version < latest) {
            let mut name = path.as_os_str().to_owned();
            name.push(format!(".pre-migrate-v{version}"));
            self.backup_to(Path::new(&name)).await?;
        }
        migrator.run(&self.pool).await?;
        let after: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&self.pool)
            .await?;
        if after != latest {
            return Err(StoreError::Corrupt);
        }
        Ok(())
    }

    /// Writes the header, the key slots and the CA in one transaction. Only for a new vault.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when a header exists already, or when a row breaks a schema rule.
    pub async fn initialize(
        &self,
        header: &HeaderRow,
        slots: &[KeySlotRow],
        ca: &TlsCaRow,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        tx.insert_header(header).await?;
        for slot in slots {
            tx.upsert_slot(slot).await?;
        }
        tx.put_tls_ca(ca).await?;
        tx.commit().await
    }

    /// Starts a write transaction (`BEGIN IMMEDIATE`, so a later write never fails with a lock upgrade error).
    ///
    /// # Errors
    /// An engine error.
    pub async fn begin(&self) -> Result<Tx<'_>, StoreError> {
        Ok(Tx::new(self.pool.begin_with("BEGIN IMMEDIATE").await?))
    }

    /// The vault header.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] before `initialize`.
    pub async fn header(&self) -> Result<HeaderRow, StoreError> {
        let row = sqlx::query("SELECT * FROM vault_header WHERE id = 1")
            .fetch_one(&self.pool)
            .await?;
        HeaderRow::from_sql(&row)
    }

    /// Adds one to the failed unlock counter and returns the new count. Works while locked.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when there is no header.
    pub async fn record_unlock_failure(&self, at: Timestamp) -> Result<u32, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "UPDATE vault_header SET failed_unlocks = failed_unlocks + 1, last_failed_unlock_at = ?1 \
             WHERE id = 1 RETURNING failed_unlocks",
        )
        .bind(to_ms(at))
        .fetch_one(&self.pool)
        .await?;
        crate::convert::to_u32(count)
    }

    /// Sets the failed unlock counter to zero.
    ///
    /// # Errors
    /// An engine error.
    pub async fn reset_unlock_failures(&self) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE vault_header SET failed_unlocks = 0, last_failed_unlock_at = NULL WHERE id = 1",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All key slots, in ID order.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for a slot with out-of-range KDF costs.
    pub async fn key_slots(&self) -> Result<Vec<KeySlotRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM key_slots ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(KeySlotRow::from_sql).collect()
    }

    /// Agents and their keys, for the token table. Works while locked. The caller checks every row MAC
    /// once the vault is unlocked (ADR-0033 point 5).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn load_auth_rows(&self) -> Result<(Vec<AgentRow>, Vec<AgentKeyRow>), StoreError> {
        let agents = sqlx::query("SELECT * FROM agents ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let keys = sqlx::query("SELECT * FROM agent_keys ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok((
            agents
                .iter()
                .map(AgentRow::from_sql)
                .collect::<Result<_, _>>()?,
            keys.iter()
                .map(AgentKeyRow::from_sql)
                .collect::<Result<_, _>>()?,
        ))
    }

    /// Workspaces, items, agents and grants for the in-memory index. Items and grants that are
    /// expired by their plain `expires_at` are left out (ADR-0027: invisible at once).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn load_all_for_index(&self) -> Result<IndexRows, StoreError> {
        let now = to_ms(self.clock.now());
        let workspaces = sqlx::query("SELECT * FROM workspaces ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let items = sqlx::query(
            "SELECT * FROM items WHERE expires_at IS NULL OR expires_at > ?1 ORDER BY id",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let agents = sqlx::query("SELECT * FROM agents ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let grants = sqlx::query(
            "SELECT * FROM grants WHERE expires_at IS NULL OR expires_at > ?1 ORDER BY id",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(IndexRows {
            workspaces: workspaces
                .iter()
                .map(WorkspaceRow::from_sql)
                .collect::<Result<_, _>>()?,
            items: items
                .iter()
                .map(ItemRow::from_sql)
                .collect::<Result<_, _>>()?,
            agents: agents
                .iter()
                .map(AgentRow::from_sql)
                .collect::<Result<_, _>>()?,
            grants: grants
                .iter()
                .map(GrantRow::from_sql)
                .collect::<Result<_, _>>()?,
        })
    }

    /// One item row. An expired item is `NotFound`.
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn item(&self, id: ItemId) -> Result<ItemRow, StoreError> {
        let row = sqlx::query(
            "SELECT * FROM items WHERE id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
        )
        .bind(id.to_string())
        .bind(to_ms(self.clock.now()))
        .fetch_one(&self.pool)
        .await?;
        ItemRow::from_sql(&row)
    }

    /// One version of an item. The item of an expired item is `NotFound`.
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn item_version(
        &self,
        item: ItemId,
        version: u32,
    ) -> Result<ItemVersionRow, StoreError> {
        let row = sqlx::query(
            "SELECT v.* FROM item_versions v JOIN items i ON i.id = v.item_id \
             WHERE v.item_id = ?1 AND v.version = ?2 AND (i.expires_at IS NULL OR i.expires_at > ?3)",
        )
        .bind(item.to_string())
        .bind(i64::from(version))
        .bind(to_ms(self.clock.now()))
        .fetch_one(&self.pool)
        .await?;
        ItemVersionRow::from_sql(&row)
    }

    /// One lease row. The caller checks its MAC before it trusts the row (ADR-0033 point 5).
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn lease(&self, id: LeaseId) -> Result<LeaseRow, StoreError> {
        let row = sqlx::query("SELECT * FROM leases WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(&self.pool)
            .await?;
        LeaseRow::from_sql(&row)
    }

    /// Leases of one agent for one item that are not released, not revoked and not expired at `now`.
    /// The caller checks each MAC.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn active_leases(
        &self,
        agent: AgentId,
        item: ItemId,
        now: Timestamp,
    ) -> Result<Vec<LeaseRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM leases WHERE agent_id = ?1 AND item_id = ?2 \
             AND released_at IS NULL AND revoked_at IS NULL AND expires_at > ?3 ORDER BY expires_at",
        )
        .bind(agent.to_string())
        .bind(item.to_string())
        .bind(to_ms(now))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(LeaseRow::from_sql).collect()
    }

    /// One access request. The caller checks its MAC.
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn access_request(
        &self,
        id: AccessRequestId,
    ) -> Result<AccessRequestRow, StoreError> {
        let row = sqlx::query("SELECT * FROM access_requests WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(&self.pool)
            .await?;
        AccessRequestRow::from_sql(&row)
    }

    /// Requests in state `pending`, oldest first. The caller checks each MAC.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn pending_access_requests(&self) -> Result<Vec<AccessRequestRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM access_requests WHERE status = 'pending' ORDER BY created_at, id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(AccessRequestRow::from_sql).collect()
    }

    /// Every access request of one agent for one item, any state, newest first. The caller checks
    /// each MAC (deny cool-down, ADR-0018).
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn access_requests_for(
        &self,
        agent: AgentId,
        item: ItemId,
    ) -> Result<Vec<AccessRequestRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM access_requests WHERE agent_id = ?1 AND item_id = ?2 \
             ORDER BY created_at DESC, id",
        )
        .bind(agent.to_string())
        .bind(item.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(AccessRequestRow::from_sql).collect()
    }

    /// Every lease row of one agent for one item, also released, revoked and expired ones (the
    /// revoke block of ADR-0019 point 7). The caller checks each MAC.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn leases_for(
        &self,
        agent: AgentId,
        item: ItemId,
    ) -> Result<Vec<LeaseRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM leases WHERE agent_id = ?1 AND item_id = ?2 ORDER BY expires_at, id",
        )
        .bind(agent.to_string())
        .bind(item.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(LeaseRow::from_sql).collect()
    }

    /// Every lease row of one item, any agent and any state, newest first (exposure view,
    /// ADR-0019 point 10). The caller checks each MAC.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn leases_of_item(&self, item: ItemId) -> Result<Vec<LeaseRow>, StoreError> {
        let rows =
            sqlx::query("SELECT * FROM leases WHERE item_id = ?1 ORDER BY created_at DESC, id")
                .bind(item.to_string())
                .fetch_all(&self.pool)
                .await?;
        rows.iter().map(LeaseRow::from_sql).collect()
    }

    /// Leases that are not released, not revoked and not expired at `now`, soonest end first.
    /// `max_uses` is not checked here. The caller checks each MAC.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn live_leases(&self, now: Timestamp) -> Result<Vec<LeaseRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM leases WHERE released_at IS NULL AND revoked_at IS NULL \
             AND expires_at > ?1 ORDER BY expires_at, id",
        )
        .bind(to_ms(now))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(LeaseRow::from_sql).collect()
    }

    /// Leases not released and not revoked whose `expires_at` is in `(after, until]` (lease expiry
    /// audit events, ADR-0019 point 12). The caller checks each MAC.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn leases_expired_between(
        &self,
        after: Timestamp,
        until: Timestamp,
    ) -> Result<Vec<LeaseRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT * FROM leases WHERE released_at IS NULL AND revoked_at IS NULL \
             AND expires_at > ?1 AND expires_at <= ?2 ORDER BY expires_at, id",
        )
        .bind(to_ms(after))
        .bind(to_ms(until))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(LeaseRow::from_sql).collect()
    }

    /// One setting row (the value is sealed).
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn setting(&self, key: &str) -> Result<SettingRow, StoreError> {
        let row = sqlx::query("SELECT * FROM settings WHERE key = ?1")
            .bind(key)
            .fetch_one(&self.pool)
            .await?;
        SettingRow::from_sql(&row)
    }

    /// All setting rows, by key.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn settings(&self) -> Result<Vec<SettingRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM settings ORDER BY key")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(SettingRow::from_sql).collect()
    }

    /// The local CA row.
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn tls_ca(&self) -> Result<TlsCaRow, StoreError> {
        let row = sqlx::query("SELECT * FROM tls_ca WHERE id = 1")
            .fetch_one(&self.pool)
            .await?;
        TlsCaRow::from_sql(&row)
    }

    /// Audit rows with `seq >= from_seq`, in order, at most `limit`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn audit_range(
        &self,
        from_seq: u64,
        limit: u32,
    ) -> Result<Vec<AuditRow>, StoreError> {
        let rows = sqlx::query("SELECT * FROM audit_events WHERE seq >= ?1 ORDER BY seq LIMIT ?2")
            .bind(from_u64(from_seq)?)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(AuditRow::from_sql).collect()
    }

    /// The audit head, or `None` before the first event.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn audit_head(&self) -> Result<Option<AuditHeadRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM audit_head WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(AuditHeadRow::from_sql).transpose()
    }

    /// Adds an event written while locked. When `cap` rows wait already, only the overflow counter grows (ADR-0025).
    ///
    /// # Errors
    /// An engine error.
    pub async fn push_audit_pending(
        &self,
        row: &AuditPendingRow,
        cap: u32,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        tx.push_audit_pending(row, cap).await?;
        tx.commit().await
    }

    /// True when an event of `event_type` waits in `audit_pending`. It reads only; the rows stay.
    ///
    /// # Errors
    /// An engine error.
    pub async fn has_audit_pending(&self, event_type: &str) -> Result<bool, StoreError> {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM audit_pending WHERE event_type = ?1 LIMIT 1")
                .bind(event_type)
                .fetch_optional(&self.pool)
                .await?;
        Ok(found.is_some())
    }

    /// Takes all pending events (oldest first), the overflow count and the count of unreadable
    /// rows, and clears them, in a transaction of its own. A caller that must not lose the events
    /// on a crash uses [`Tx::take_audit_pending`] in the transaction that stores them instead.
    ///
    /// # Errors
    /// An engine error.
    pub async fn take_audit_pending(&self) -> Result<crate::tx::PendingTake, StoreError> {
        let mut tx = self.begin().await?;
        let take = tx.take_audit_pending().await?;
        tx.commit().await?;
        Ok(take)
    }

    /// Folds the WAL into the main file and empties it, so rows deleted with `secure_delete` are
    /// gone from both files (the sweeper does the same after a delete).
    ///
    /// # Errors
    /// An engine error.
    pub async fn truncate_wal(&self) -> Result<(), StoreError> {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Closes all connections, of this store and of every clone (they share one pool), and waits
    /// until each one is closed; a connection in use is closed when its query ends. SQLite then
    /// folds the WAL into the main file and removes the `-wal` and `-shm` files. Every later call
    /// on any clone fails. Call it before the vault file is moved (restore, NEW-10).
    pub async fn close(self) {
        self.pool.close().await;
    }

    /// True once [`Self::close`] was called on this store or a clone.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use cerberus_types::{ManualClock, t0};

    use super::*;

    fn options(path: &Path, create: bool) -> OpenOptions {
        OpenOptions {
            path: path.to_path_buf(),
            create,
        }
    }

    #[tokio::test]
    async fn every_pooled_connection_has_the_safety_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let store = Store::open(options(&path, true), Arc::new(ManualClock::new(t0())))
            .await
            .unwrap();
        // Hold several connections at once, so the pool opens more than one.
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(store.pool.acquire().await.unwrap());
        }
        for conn in &mut held {
            for (pragma, expected) in [
                ("secure_delete", 1_i64),
                ("foreign_keys", 1),
                ("synchronous", 2),
                ("trusted_schema", 0),
            ] {
                let sql = sqlx::AssertSqlSafe(format!("PRAGMA {pragma}"));
                let value: i64 = sqlx::query_scalar(sql)
                    .fetch_one(&mut **conn)
                    .await
                    .unwrap();
                assert_eq!(value, expected, "{pragma}");
            }
        }
    }

    /// A directory with the migrations of this build up to `version`, and `extra` as the next one.
    fn migrations_dir(version: i64, extra: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        for entry in std::fs::read_dir(&source).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let number: i64 = name.split('_').next().unwrap().parse().unwrap();
            if number <= version {
                std::fs::copy(&path, dir.path().join(&name)).unwrap();
            }
        }
        if let Some(sql) = extra {
            let next = version + 1;
            std::fs::write(dir.path().join(format!("{next:04}_extra.sql")), sql).unwrap();
        }
        dir
    }

    #[tokio::test]
    async fn older_schema_is_migrated_after_a_pre_migrate_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let clock = Arc::new(ManualClock::new(t0()));
        let ours = schema_version();
        Store::open(options(&path, true), clock.clone())
            .await
            .unwrap()
            .close()
            .await;

        let next = ours + 1;
        let extra = format!(
            "CREATE TABLE extra (id INTEGER PRIMARY KEY) STRICT;\nPRAGMA user_version = {next};"
        );
        let migrations = migrations_dir(ours, Some(&extra));
        let newer = Migrator::new(migrations.path()).await.unwrap();
        let store = Store::open_with(options(&path, false), clock.clone(), &newer)
            .await
            .unwrap();
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(version, next);
        store.close().await;

        let copy = path.with_file_name(format!("vault.cerberus.pre-migrate-v{ours}"));
        assert_eq!(
            probe(&copy).await.unwrap().user_version,
            ours,
            "the copy keeps the old schema"
        );

        // This build now refuses the newer file.
        let error = Store::open(options(&path, false), clock).await.unwrap_err();
        assert!(
            matches!(error, StoreError::TooNew { found, supported } if found == next && supported == ours),
            "{error:?}"
        );
    }

    async fn count(pool: &SqlitePool, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    /// DEC-RD-2: migration 0002 rebuilds `items` to allow the kind `rustdesk`. Every item row (with
    /// its rowid) and every row that points at one stays, foreign keys work again afterwards, and a
    /// second run of the file changes nothing.
    #[tokio::test]
    async fn migration_0002_allows_rustdesk_and_keeps_every_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let clock = Arc::new(ManualClock::new(t0()));
        let first = migrations_dir(1, None);
        let v1 = Migrator::new(first.path()).await.unwrap();
        let store = Store::open_with(options(&path, true), clock.clone(), &v1)
            .await
            .unwrap();
        for (rowid, id, kind, expires) in [
            (7_i64, "item-a", "web_login", None),
            (9, "item-b", "session_token", Some(5_000_i64)),
        ] {
            sqlx::query(
                "INSERT INTO items (rowid, id, kind, expires_at, created_at, updated_at, \
                 current_version, meta_ct) VALUES (?, ?, ?, ?, 1, 2, 1, x'0102')",
            )
            .bind(rowid)
            .bind(id)
            .bind(kind)
            .bind(expires)
            .execute(&store.pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO item_versions (item_id, version, created_at, wrapped_dek, \
                 payload_ct, meta_ct) VALUES (?, 1, 1, x'aa', x'bb', x'cc')",
            )
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
        }
        let refused = sqlx::query(
            "INSERT INTO items (id, kind, created_at, updated_at, current_version, meta_ct) \
             VALUES ('item-c', 'rustdesk', 1, 1, 1, x'00')",
        )
        .execute(&store.pool)
        .await;
        assert!(refused.is_err(), "version 1 has no rustdesk kind");
        store.close().await;

        let store = Store::open(options(&path, false), clock).await.unwrap();
        let pool = &store.pool;
        assert_eq!(count(pool, "PRAGMA user_version").await, 2);
        assert_eq!(count(pool, "PRAGMA foreign_keys").await, 1);
        assert_eq!(count(pool, "SELECT count(*) FROM item_versions").await, 2);
        assert_eq!(
            count(
                pool,
                "SELECT count(*) FROM items WHERE (rowid, id, kind) IN \
                 (VALUES (7, 'item-a', 'web_login'), (9, 'item-b', 'session_token'))"
            )
            .await,
            2
        );
        assert_eq!(
            count(
                pool,
                "SELECT count(*) FROM sqlite_master WHERE type = 'index' \
                 AND name = 'items_expires_at' AND tbl_name = 'items'"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                pool,
                "SELECT count(*) FROM sqlite_master WHERE name = 'items_new'"
            )
            .await,
            0
        );
        assert!(
            path.with_file_name("vault.cerberus.pre-migrate-v1")
                .exists(),
            "the copy of version 1 is written first"
        );

        sqlx::query(
            "INSERT INTO items (id, kind, created_at, updated_at, current_version, meta_ct) \
             VALUES ('item-c', 'rustdesk', 1, 1, 1, x'00')",
        )
        .execute(pool)
        .await
        .unwrap();
        let bogus = sqlx::query(
            "INSERT INTO items (id, kind, created_at, updated_at, current_version, meta_ct) \
             VALUES ('item-d', 'bogus', 1, 1, 1, x'00')",
        )
        .execute(pool)
        .await;
        assert!(bogus.is_err(), "the kind is still checked");
        let orphan = sqlx::query(
            "INSERT INTO item_versions (item_id, version, created_at, wrapped_dek, payload_ct, \
             meta_ct) VALUES ('no-such-item', 1, 1, x'aa', x'bb', x'cc')",
        )
        .execute(pool)
        .await;
        assert!(orphan.is_err(), "foreign keys are enforced again");
        sqlx::query("DELETE FROM items WHERE id = 'item-a'")
            .execute(pool)
            .await
            .unwrap();
        assert_eq!(
            count(pool, "SELECT count(*) FROM item_versions").await,
            1,
            "the cascade points at the new table"
        );

        // A second run (a crash before the bookkeeping row) keeps the data as it is.
        let again = MIGRATOR.iter().find(|m| m.version == 2).unwrap();
        let mut conn = pool.acquire().await.unwrap();
        sqlx::raw_sql(again.sql.clone())
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        assert_eq!(count(pool, "SELECT count(*) FROM items").await, 2);
        assert_eq!(count(pool, "SELECT count(*) FROM item_versions").await, 1);
        store.close().await;
    }

    /// AUD-10: the check of a backup reads only the main file. A `-wal` file that appears next to
    /// it (after the sibling check) is never read, so the file that is checked is one file.
    #[tokio::test]
    async fn the_backup_check_never_reads_a_sibling_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let clock = Arc::new(ManualClock::new(t0()));
        let store = Store::open(options(&path, true), clock).await.unwrap();
        let mut tx = store.begin().await.unwrap();
        tx.insert_header(&HeaderRow {
            format_version: crate::FORMAT_VERSION,
            vault_id: cerberus_types::VaultId::generate(),
            created_at: t0(),
            failed_unlocks: 0,
            last_failed_unlock_at: None,
            header_mac: [0; 32],
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA wal_autocheckpoint = 0")
            .execute(&mut *conn)
            .await
            .unwrap();
        // This change lives in the `-wal` file only while the connection is open.
        sqlx::query("PRAGMA user_version = 9")
            .execute(&mut *conn)
            .await
            .unwrap();
        let seen = crate::backup::read_backup_file(&path).await.unwrap();
        assert_eq!(
            seen.schema_version,
            schema_version(),
            "the check must not read the -wal file"
        );
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "PRAGMA user_version = {}",
            schema_version()
        )))
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    #[test]
    fn every_migration_sets_its_own_user_version() {
        for migration in MIGRATOR.iter() {
            let needle = format!("PRAGMA user_version = {};", migration.version);
            assert!(
                migration.sql.as_str().contains(&needle),
                "migration {}",
                migration.version
            );
        }
    }
}
