//! The write side: one transaction type for every table.

use cerberus_crypto::SlotKdf;
use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, AgentKeyId, GrantId, ItemId, ItemKind,
    KeySlotId, LeaseId, WorkspaceId,
};
use jiff::Timestamp;
use sqlx::sqlite::Sqlite;
use sqlx::{SqliteConnection, Transaction};

use crate::StoreError;
use crate::convert::{enum_text, from_u64, nets_text, opt_to_ms, scopes_text, to_ms, to_u64};
use crate::macs::RowMacs;
use crate::rows::{
    AccessRequestRow, AgentKeyRow, AgentRow, AuditHeadRow, AuditPendingRow, AuditRow, GrantRow,
    HeaderRow, ItemRow, ItemVersionRow, KeySlotRow, LeaseRow, MAGIC, SettingRow, SlotKind,
    TlsCaRow, WorkspaceRow,
};

/// What [`Tx::revoke_all_leases`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevokeReport {
    /// Leases revoked and signed again.
    pub revoked: u64,
    /// Leases left as they are because their row MAC is bad (AUD-7). The caller raises the
    /// integrity alert for each.
    pub bad_mac: Vec<LeaseId>,
    /// Rows left as they are because they cannot be read (a bad ID, time or enum text). They are
    /// only counted, so one bad row never stops the revoke of the others (NEW-3). The caller
    /// raises the integrity alert.
    pub malformed: u64,
}

/// What [`Tx::cancel_pending_requests`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CancelReport {
    /// Requests set to `cancelled`, so the caller can tell their waiters.
    pub cancelled: Vec<AccessRequestId>,
    /// Requests left as they are because their row MAC is bad (AUD-7).
    pub bad_mac: Vec<AccessRequestId>,
    /// Rows left as they are because they cannot be read; only counted (NEW-3).
    pub malformed: u64,
}

/// What [`Tx::take_audit_pending`] took.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingTake {
    /// The readable rows, oldest first.
    pub rows: Vec<AuditPendingRow>,
    /// Events not stored because the list was full.
    pub overflow: u64,
    /// Rows that could not be read (a bad ID or time). They are deleted with the others and only
    /// counted (AUD-9), so one bad row never blocks the rest.
    pub malformed: u64,
}

/// A write transaction. Commit is explicit; drop rolls back.
#[derive(Debug)]
pub struct Tx<'a> {
    tx: Transaction<'a, Sqlite>,
}

impl<'a> Tx<'a> {
    pub(crate) fn new(tx: Transaction<'a, Sqlite>) -> Self {
        Self { tx }
    }

    fn conn(&mut self) -> &mut SqliteConnection {
        &mut self.tx
    }

    /// Makes every change of this transaction permanent.
    ///
    /// # Errors
    /// An engine error. The transaction is rolled back then.
    pub async fn commit(self) -> Result<(), StoreError> {
        Ok(self.tx.commit().await?)
    }

    pub(crate) async fn insert_header(&mut self, row: &HeaderRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO vault_header (id, magic, format_version, vault_id, created_at, failed_unlocks, \
             last_failed_unlock_at, header_mac) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(MAGIC)
        .bind(i64::from(row.format_version))
        .bind(row.vault_id.as_bytes().as_slice())
        .bind(to_ms(row.created_at))
        .bind(i64::from(row.failed_unlocks))
        .bind(opt_to_ms(row.last_failed_unlock_at))
        .bind(row.header_mac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Inserts or replaces a key slot.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when the slot breaks a schema rule (for example a second recovery slot).
    pub async fn upsert_slot(&mut self, row: &KeySlotRow) -> Result<(), StoreError> {
        let (kdf_alg, version, m, t, p) = match &row.material.kdf {
            SlotKdf::Argon2id(params) => (
                "argon2id",
                Some(i64::from(cerberus_crypto::ARGON2_VERSION)),
                Some(i64::from(params.m_cost_kib())),
                Some(i64::from(params.t_cost())),
                Some(i64::from(params.p_cost())),
            ),
            SlotKdf::HkdfSha256 => ("hkdf-sha256", None, None, None, None),
        };
        let kind = enum_text(&row.kind)?;
        if (row.kind == SlotKind::Recovery) != (row.material.kdf == SlotKdf::HkdfSha256) {
            return Err(StoreError::Conflict);
        }
        sqlx::query(
            "INSERT INTO key_slots (id, kind, label, role, kdf_alg, argon2_version, m_cost_kib, t_cost, \
             p_cost, salt, wrapped_vmk, created_at, updated_at, last_unlock_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, label = excluded.label, \
             role = excluded.role, kdf_alg = excluded.kdf_alg, argon2_version = excluded.argon2_version, \
             m_cost_kib = excluded.m_cost_kib, t_cost = excluded.t_cost, p_cost = excluded.p_cost, \
             salt = excluded.salt, wrapped_vmk = excluded.wrapped_vmk, updated_at = excluded.updated_at, \
             last_unlock_at = excluded.last_unlock_at",
        )
        .bind(row.id.to_string())
        .bind(kind)
        .bind(&row.label)
        .bind(row.role.as_str())
        .bind(kdf_alg)
        .bind(version)
        .bind(m)
        .bind(t)
        .bind(p)
        .bind(row.material.salt.as_slice())
        .bind(row.material.wrapped_vmk.as_slice())
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.updated_at))
        .bind(opt_to_ms(row.last_unlock_at))
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Deletes a key slot.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the slot does not exist.
    pub async fn delete_slot(&mut self, id: KeySlotId) -> Result<(), StoreError> {
        let done = sqlx::query("DELETE FROM key_slots WHERE id = ?1")
            .bind(id.to_string())
            .execute(self.conn())
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Sets the header MAC (after a slot change).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when there is no header.
    pub async fn set_header_mac(&mut self, mac: &[u8; 32]) -> Result<(), StoreError> {
        let done = sqlx::query("UPDATE vault_header SET header_mac = ?1 WHERE id = 1")
            .bind(mac.as_slice())
            .execute(self.conn())
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Inserts or replaces a setting.
    ///
    /// # Errors
    /// An engine error.
    pub async fn put_setting(&mut self, row: &SettingRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO settings (key, updated_at, value_ct) VALUES (?1, ?2, ?3) \
             ON CONFLICT(key) DO UPDATE SET updated_at = excluded.updated_at, value_ct = excluded.value_ct",
        )
        .bind(&row.key)
        .bind(to_ms(row.updated_at))
        .bind(row.value_ct.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Deletes a setting. Returns true when a row existed.
    ///
    /// # Errors
    /// An engine error.
    pub async fn delete_setting(&mut self, key: &str) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM settings WHERE key = ?1")
            .bind(key)
            .execute(self.conn())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Inserts or replaces the single local CA row.
    ///
    /// # Errors
    /// An engine error.
    pub async fn put_tls_ca(&mut self, row: &TlsCaRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO tls_ca (id, ca_cert_der, ca_key_ct, created_at, not_after) \
             VALUES (1, ?1, ?2, ?3, ?4) ON CONFLICT(id) DO UPDATE SET ca_cert_der = excluded.ca_cert_der, \
             ca_key_ct = excluded.ca_key_ct, created_at = excluded.created_at, not_after = excluded.not_after",
        )
        .bind(row.ca_cert_der.as_slice())
        .bind(row.ca_key_ct.as_slice())
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.not_after))
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Inserts or replaces a workspace.
    ///
    /// # Errors
    /// An engine error.
    pub async fn put_workspace(&mut self, row: &WorkspaceRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO workspaces (id, created_at, updated_at, meta_ct) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, meta_ct = excluded.meta_ct",
        )
        .bind(row.id.to_string())
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.updated_at))
        .bind(row.meta_ct.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Deletes a workspace row. Items link to it only inside their sealed metadata, so the caller
    /// decides what happens to them.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the workspace does not exist.
    pub async fn delete_workspace(&mut self, id: WorkspaceId) -> Result<(), StoreError> {
        let done = sqlx::query("DELETE FROM workspaces WHERE id = ?1")
            .bind(id.to_string())
            .execute(self.conn())
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn write_item(&mut self, item: &ItemRow, insert: bool) -> Result<(), StoreError> {
        let kind = enum_text(&item.kind)?;
        let sql = if insert {
            "INSERT INTO items (id, kind, expires_at, created_at, updated_at, current_version, meta_ct) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
        } else {
            "UPDATE items SET kind = ?2, expires_at = ?3, created_at = ?4, updated_at = ?5, \
             current_version = ?6, meta_ct = ?7 WHERE id = ?1"
        };
        let done = sqlx::query(sql)
            .bind(item.id.to_string())
            .bind(kind)
            .bind(opt_to_ms(item.expires_at))
            .bind(to_ms(item.created_at))
            .bind(to_ms(item.updated_at))
            .bind(i64::from(item.current_version))
            .bind(item.meta_ct.as_slice())
            .execute(self.conn())
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn insert_version(&mut self, row: &ItemVersionRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO item_versions (item_id, version, created_at, wrapped_dek, payload_ct, meta_ct) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(row.item_id.to_string())
        .bind(i64::from(row.version))
        .bind(to_ms(row.created_at))
        .bind(row.wrapped_dek.as_slice())
        .bind(row.payload_ct.as_slice())
        .bind(row.meta_ct.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Inserts a new item and its first version.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when the ID exists, or when `first` is not version `item.current_version` of this item.
    pub async fn insert_item(
        &mut self,
        item: &ItemRow,
        first: &ItemVersionRow,
    ) -> Result<(), StoreError> {
        if first.item_id != item.id || first.version != item.current_version {
            return Err(StoreError::Conflict);
        }
        self.write_item(item, true).await?;
        self.insert_version(first).await
    }

    /// Updates the item row to `version` (its `current_version`), adds the version row and deletes
    /// versions older than the newest `keep` (ADR-0027).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown item. [`StoreError::Conflict`] when `version` does not
    /// match `item`, the version exists already, or `keep` is zero.
    pub async fn add_item_version(
        &mut self,
        item: &ItemRow,
        version: &ItemVersionRow,
        keep: u32,
    ) -> Result<(), StoreError> {
        if version.item_id != item.id || version.version != item.current_version || keep == 0 {
            return Err(StoreError::Conflict);
        }
        self.write_item(item, false).await?;
        self.insert_version(version).await?;
        sqlx::query("DELETE FROM item_versions WHERE item_id = ?1 AND version <= ?2")
            .bind(item.id.to_string())
            .bind(i64::from(version.version) - i64::from(keep))
            .execute(self.conn())
            .await?;
        Ok(())
    }

    /// Replaces the item row without a new version (for a change that makes no version).
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown item.
    pub async fn update_item_meta(&mut self, item: &ItemRow) -> Result<(), StoreError> {
        self.write_item(item, false).await
    }

    /// Replaces the metadata snapshot (`item_versions.meta_ct`) of one version, for a metadata
    /// change that makes no new version.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown version.
    pub async fn update_version_meta(
        &mut self,
        item: ItemId,
        version: u32,
        meta_ct: &[u8],
    ) -> Result<(), StoreError> {
        let done = sqlx::query(
            "UPDATE item_versions SET meta_ct = ?3 WHERE item_id = ?1 AND version = ?2",
        )
        .bind(item.to_string())
        .bind(i64::from(version))
        .bind(meta_ct)
        .execute(self.conn())
        .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Hard-deletes an item with its versions, leases and access requests (cascade, ADR-0027).
    /// Returns false when the item did not exist.
    ///
    /// # Errors
    /// An engine error.
    pub async fn delete_item(&mut self, id: ItemId) -> Result<bool, StoreError> {
        let done = sqlx::query("DELETE FROM items WHERE id = ?1")
            .bind(id.to_string())
            .execute(self.conn())
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// One item row, read inside this transaction, also when it has expired (the caller checks it
    /// against the index before it changes the row).
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn item(&mut self, id: ItemId) -> Result<ItemRow, StoreError> {
        let row = sqlx::query("SELECT * FROM items WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(self.conn())
            .await?;
        ItemRow::from_sql(&row)
    }

    /// Replaces `meta_ct` of an item only while the row still has `kind`, `version` and the
    /// metadata blob `old_meta_ct` (a compare and set, for the upgrade of rows written before the
    /// kind was sealed, DEC-T27-A1-2). Returns false when the row changed or is gone.
    ///
    /// # Errors
    /// An engine error.
    pub async fn replace_item_meta_if(
        &mut self,
        id: ItemId,
        kind: ItemKind,
        version: u32,
        old_meta_ct: &[u8],
        new_meta_ct: &[u8],
    ) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE items SET meta_ct = ?5 WHERE id = ?1 AND kind = ?2 AND current_version = ?3 \
             AND meta_ct = ?4",
        )
        .bind(id.to_string())
        .bind(enum_text(&kind)?)
        .bind(i64::from(version))
        .bind(old_meta_ct)
        .bind(new_meta_ct)
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Inserts or replaces an agent. Replacing keeps the agent's keys, grants, leases and requests.
    ///
    /// # Errors
    /// An engine error.
    pub async fn put_agent(&mut self, row: &AgentRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO agents (id, status, created_at, updated_at, meta_ct, row_mac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(id) DO UPDATE SET status = excluded.status, \
             created_at = excluded.created_at, updated_at = excluded.updated_at, \
             meta_ct = excluded.meta_ct, row_mac = excluded.row_mac",
        )
        .bind(row.id.to_string())
        .bind(enum_text(&row.status)?)
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.updated_at))
        .bind(row.meta_ct.as_slice())
        .bind(row.row_mac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Inserts or replaces an agent key.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] for a duplicate `secret_hash` or an unknown agent.
    pub async fn put_agent_key(&mut self, row: &AgentKeyRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO agent_keys (id, agent_id, secret_hash, hint, scopes, ip_allowlist, require_mtls, \
             client_cert_sha256, created_at, expires_at, revoked_at, last_used_at, row_mac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT(id) DO UPDATE SET agent_id = excluded.agent_id, secret_hash = excluded.secret_hash, \
             hint = excluded.hint, scopes = excluded.scopes, ip_allowlist = excluded.ip_allowlist, \
             require_mtls = excluded.require_mtls, client_cert_sha256 = excluded.client_cert_sha256, \
             created_at = excluded.created_at, expires_at = excluded.expires_at, \
             revoked_at = excluded.revoked_at, last_used_at = excluded.last_used_at, \
             row_mac = excluded.row_mac",
        )
        .bind(row.id.to_string())
        .bind(row.agent_id.to_string())
        .bind(row.secret_hash.as_slice())
        .bind(&row.hint)
        .bind(scopes_text(&row.scopes)?)
        .bind(nets_text(&row.ip_allowlist))
        .bind(i64::from(row.require_mtls))
        .bind(row.client_cert_sha256.as_ref().map(<[u8; 32]>::as_slice))
        .bind(to_ms(row.created_at))
        .bind(opt_to_ms(row.expires_at))
        .bind(opt_to_ms(row.revoked_at))
        .bind(opt_to_ms(row.last_used_at))
        .bind(row.row_mac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Updates an agent row only when its stored status is still `expected` (a compare and set).
    /// Returns false when the status changed (or the agent is gone); nothing is written then.
    /// `created_at` is never changed.
    ///
    /// # Errors
    /// An engine error.
    pub async fn update_agent_if_status(
        &mut self,
        row: &AgentRow,
        expected: crate::rows::AgentStatus,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE agents SET status = ?2, updated_at = ?3, meta_ct = ?4, row_mac = ?5 \
             WHERE id = ?1 AND status = ?6",
        )
        .bind(row.id.to_string())
        .bind(enum_text(&row.status)?)
        .bind(to_ms(row.updated_at))
        .bind(row.meta_ct.as_slice())
        .bind(row.row_mac.as_slice())
        .bind(enum_text(&expected)?)
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Updates the changeable columns of a key (`require_mtls`, `client_cert_sha256`,
    /// `expires_at`, `revoked_at`, `row_mac`) only while the stored key is not revoked. Returns
    /// false when it is revoked (or gone); nothing is written then, so a stale row can never undo
    /// a revoke. `last_used_at` is not touched.
    ///
    /// # Errors
    /// An engine error.
    pub async fn update_live_agent_key(&mut self, row: &AgentKeyRow) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE agent_keys SET require_mtls = ?2, client_cert_sha256 = ?3, expires_at = ?4, \
             revoked_at = ?5, row_mac = ?6 WHERE id = ?1 AND revoked_at IS NULL",
        )
        .bind(row.id.to_string())
        .bind(i64::from(row.require_mtls))
        .bind(row.client_cert_sha256.as_ref().map(<[u8; 32]>::as_slice))
        .bind(opt_to_ms(row.expires_at))
        .bind(opt_to_ms(row.revoked_at))
        .bind(row.row_mac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Sets `last_used_at` of a key. It is not in the row MAC (ADR-0033), so this works while locked.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown key.
    pub async fn touch_agent_key(
        &mut self,
        id: AgentKeyId,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let done = sqlx::query("UPDATE agent_keys SET last_used_at = ?2 WHERE id = ?1")
            .bind(id.to_string())
            .bind(to_ms(at))
            .execute(self.conn())
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Inserts or replaces a grant.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] for an unknown agent.
    pub async fn put_grant(&mut self, row: &GrantRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO grants (id, agent_id, created_at, updated_at, expires_at, body_ct) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(id) DO UPDATE SET agent_id = excluded.agent_id, \
             updated_at = excluded.updated_at, expires_at = excluded.expires_at, body_ct = excluded.body_ct",
        )
        .bind(row.id.to_string())
        .bind(row.agent_id.to_string())
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.updated_at))
        .bind(opt_to_ms(row.expires_at))
        .bind(row.body_ct.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Deletes a grant.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown grant.
    pub async fn delete_grant(&mut self, id: GrantId) -> Result<(), StoreError> {
        let done = sqlx::query("DELETE FROM grants WHERE id = ?1")
            .bind(id.to_string())
            .execute(self.conn())
            .await?;
        if done.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// One lease row, read inside this transaction. The write lock is held from `begin`, so no
    /// other writer can change the row before this transaction ends. The caller checks the MAC.
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn lease(&mut self, id: cerberus_types::LeaseId) -> Result<LeaseRow, StoreError> {
        let row = sqlx::query("SELECT * FROM leases WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(self.conn())
            .await?;
        LeaseRow::from_sql(&row)
    }

    /// One access request row, read inside this transaction (see [`Self::lease`]). The caller
    /// checks the MAC.
    ///
    /// # Errors
    /// [`StoreError::NotFound`].
    pub async fn access_request(
        &mut self,
        id: cerberus_types::AccessRequestId,
    ) -> Result<AccessRequestRow, StoreError> {
        let row = sqlx::query("SELECT * FROM access_requests WHERE id = ?1")
            .bind(id.to_string())
            .fetch_one(self.conn())
            .await?;
        AccessRequestRow::from_sql(&row)
    }

    /// Inserts or replaces a lease.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] for an unknown agent or item.
    pub async fn put_lease(&mut self, row: &LeaseRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO leases (id, agent_id, item_id, permission, source, request_id, created_at, \
             expires_at, max_uses, uses, released_at, revoked_at, revoked_by, row_mac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
             ON CONFLICT(id) DO UPDATE SET agent_id = excluded.agent_id, item_id = excluded.item_id, \
             permission = excluded.permission, source = excluded.source, request_id = excluded.request_id, \
             created_at = excluded.created_at, expires_at = excluded.expires_at, \
             max_uses = excluded.max_uses, uses = excluded.uses, released_at = excluded.released_at, \
             revoked_at = excluded.revoked_at, revoked_by = excluded.revoked_by, row_mac = excluded.row_mac",
        )
        .bind(row.id.to_string())
        .bind(row.agent_id.to_string())
        .bind(row.item_id.to_string())
        .bind(enum_text(&row.permission)?)
        .bind(enum_text(&row.source)?)
        .bind(row.request_id.map(|id| id.to_string()))
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.expires_at))
        .bind(row.max_uses.map(i64::from))
        .bind(i64::from(row.uses))
        .bind(opt_to_ms(row.released_at))
        .bind(opt_to_ms(row.revoked_at))
        .bind(row.revoked_by.as_deref())
        .bind(row.row_mac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Revokes every lease that is not released and not revoked: sets `revoked_at` and `revoked_by`
    /// and makes a new row MAC for each (the panic button and restore, ADR-0031 and ADR-0019).
    /// A row whose MAC is bad is left as it is and reported, so a forged row never gets a good MAC
    /// (DEC-T07-7, AUD-7). A row that cannot be read is left as it is and counted in
    /// [`RevokeReport::malformed`], and the other rows are still revoked (NEW-3). The write sets
    /// only the revoke columns and the MAC, never `agent_id` or `item_id`, so a lease whose parent
    /// row was deleted behind the store is revoked too (DEC-T27-E-4).
    ///
    /// # Errors
    /// An engine error, or a MAC or write failure.
    pub async fn revoke_all_leases(
        &mut self,
        at: Timestamp,
        by: &str,
        macs: &RowMacs<'_>,
    ) -> Result<RevokeReport, StoreError> {
        let rows =
            sqlx::query("SELECT * FROM leases WHERE released_at IS NULL AND revoked_at IS NULL")
                .fetch_all(self.conn())
                .await?;
        let mut report = RevokeReport::default();
        for sql_row in &rows {
            let Ok(mut lease) = LeaseRow::from_sql(sql_row) else {
                report.malformed += 1;
                continue;
            };
            if !macs.verify_lease(&lease)? {
                report.bad_mac.push(lease.id);
                continue;
            }
            lease.revoked_at = Some(at);
            lease.revoked_by = Some(by.to_owned());
            macs.sign_lease(&mut lease)?;
            let done = sqlx::query(
                "UPDATE leases SET revoked_at = ?1, revoked_by = ?2, row_mac = ?3 WHERE id = ?4",
            )
            .bind(opt_to_ms(lease.revoked_at))
            .bind(lease.revoked_by.as_deref())
            .bind(lease.row_mac.as_slice())
            .bind(stored_id(sql_row)?)
            .execute(self.conn())
            .await?;
            if done.rows_affected() == 1 {
                report.revoked += 1;
            } else {
                report.malformed += 1;
            }
        }
        Ok(report)
    }

    /// Inserts or replaces an access request.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] for an unknown agent or item.
    pub async fn put_access_request(&mut self, row: &AccessRequestRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO access_requests (id, agent_id, item_id, permission, status, requested_ttl_seconds, \
             created_at, expires_at, decided_at, decided_by, approval_option, lease_id, request_id, \
             reason_ct, row_mac) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
             ON CONFLICT(id) DO UPDATE SET agent_id = excluded.agent_id, item_id = excluded.item_id, \
             permission = excluded.permission, status = excluded.status, \
             requested_ttl_seconds = excluded.requested_ttl_seconds, created_at = excluded.created_at, \
             expires_at = excluded.expires_at, decided_at = excluded.decided_at, \
             decided_by = excluded.decided_by, approval_option = excluded.approval_option, \
             lease_id = excluded.lease_id, request_id = excluded.request_id, \
             reason_ct = excluded.reason_ct, row_mac = excluded.row_mac",
        )
        .bind(row.id.to_string())
        .bind(row.agent_id.to_string())
        .bind(row.item_id.to_string())
        .bind(enum_text(&row.permission)?)
        .bind(enum_text(&row.status)?)
        .bind(row.requested_ttl_seconds.map(i64::from))
        .bind(to_ms(row.created_at))
        .bind(to_ms(row.expires_at))
        .bind(opt_to_ms(row.decided_at))
        .bind(row.decided_by.map(|id| id.to_string()))
        .bind(row.approval_option.as_ref().map(enum_text).transpose()?)
        .bind(row.lease_id.map(|id| id.to_string()))
        .bind(row.request_id.to_string())
        .bind(row.reason_ct.as_deref())
        .bind(row.row_mac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Sets every `pending` request to `cancelled` (decided at `at`) and makes new row MACs. A row
    /// whose MAC is bad is left as it is and reported (AUD-7). A row that cannot be read is left as
    /// it is and counted in [`CancelReport::malformed`] (NEW-3). As for leases, the write never sets
    /// `agent_id` or `item_id`, so a lost parent row does not stop it (DEC-T27-E-4).
    ///
    /// # Errors
    /// An engine error, or a MAC or write failure.
    pub async fn cancel_pending_requests(
        &mut self,
        at: Timestamp,
        macs: &RowMacs<'_>,
    ) -> Result<CancelReport, StoreError> {
        let rows = sqlx::query("SELECT * FROM access_requests WHERE status = 'pending'")
            .fetch_all(self.conn())
            .await?;
        let mut report = CancelReport::default();
        for sql_row in &rows {
            let Ok(mut request) = AccessRequestRow::from_sql(sql_row) else {
                report.malformed += 1;
                continue;
            };
            if !macs.verify_access_request(&request)? {
                report.bad_mac.push(request.id);
                continue;
            }
            request.status = AccessRequestStatus::Cancelled;
            request.decided_at = Some(at);
            macs.sign_access_request(&mut request)?;
            let done = sqlx::query(
                "UPDATE access_requests SET status = ?1, decided_at = ?2, row_mac = ?3 WHERE id = ?4",
            )
            .bind(enum_text(&request.status)?)
            .bind(opt_to_ms(request.decided_at))
            .bind(request.row_mac.as_slice())
            .bind(stored_id(sql_row)?)
            .execute(self.conn())
            .await?;
            if done.rows_affected() == 1 {
                report.cancelled.push(request.id);
            } else {
                report.malformed += 1;
            }
        }
        Ok(report)
    }

    /// The audit head, read inside this transaction, or `None` when there is no head row.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn audit_head(&mut self) -> Result<Option<AuditHeadRow>, StoreError> {
        let row = sqlx::query("SELECT * FROM audit_head WHERE id = 1")
            .fetch_optional(self.conn())
            .await?;
        row.as_ref().map(AuditHeadRow::from_sql).transpose()
    }

    /// The audit row with the highest `seq` (`last = true`) or the lowest, read inside this
    /// transaction. `None` for an empty log.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unreadable row.
    pub async fn audit_end(&mut self, last: bool) -> Result<Option<AuditRow>, StoreError> {
        let sql = if last {
            "SELECT * FROM audit_events ORDER BY seq DESC LIMIT 1"
        } else {
            "SELECT * FROM audit_events ORDER BY seq LIMIT 1"
        };
        let row = sqlx::query(sql).fetch_optional(self.conn()).await?;
        row.as_ref().map(AuditRow::from_sql).transpose()
    }

    async fn upsert_audit_head(&mut self, head: &AuditHeadRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO audit_head (id, last_seq, last_entry_hash, anchor_seq, anchor_prev_hash, head_hmac) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5) ON CONFLICT(id) DO UPDATE SET last_seq = excluded.last_seq, \
             last_entry_hash = excluded.last_entry_hash, anchor_seq = excluded.anchor_seq, \
             anchor_prev_hash = excluded.anchor_prev_hash, head_hmac = excluded.head_hmac",
        )
        .bind(from_u64(head.last_seq)?)
        .bind(head.last_entry_hash.as_slice())
        .bind(from_u64(head.anchor_seq)?)
        .bind(head.anchor_prev_hash.as_slice())
        .bind(head.head_hmac.as_slice())
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Appends one audit row and moves the head in the same transaction (ADR-0025).
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when `head.last_seq` is not `row.seq`, or `seq` exists already.
    pub async fn append_audit(
        &mut self,
        row: &AuditRow,
        head: &AuditHeadRow,
    ) -> Result<(), StoreError> {
        if head.last_seq != row.seq {
            return Err(StoreError::Conflict);
        }
        sqlx::query(
            "INSERT INTO audit_events (seq, occurred_at, prev_hash, hmac, body_ct) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(from_u64(row.seq)?)
        .bind(to_ms(row.occurred_at))
        .bind(row.prev_hash.as_slice())
        .bind(row.hmac.as_slice())
        .bind(row.body_ct.as_slice())
        .execute(self.conn())
        .await?;
        self.upsert_audit_head(head).await
    }

    /// Deletes audit rows with `seq < before_seq` and stores the new head. This is the only way to delete
    /// audit rows: it opens the prune guard for this statement only (ADR-0025). Returns the rows deleted.
    ///
    /// # Errors
    /// An engine error.
    pub async fn prune_audit(
        &mut self,
        before_seq: u64,
        head: &AuditHeadRow,
    ) -> Result<u64, StoreError> {
        sqlx::query("UPDATE audit_prune_guard SET active = 1 WHERE id = 1")
            .execute(self.conn())
            .await?;
        let done = sqlx::query("DELETE FROM audit_events WHERE seq < ?1")
            .bind(from_u64(before_seq)?)
            .execute(self.conn())
            .await?;
        sqlx::query("UPDATE audit_prune_guard SET active = 0 WHERE id = 1")
            .execute(self.conn())
            .await?;
        self.upsert_audit_head(head).await?;
        Ok(done.rows_affected())
    }

    /// Adds an event written while locked, or counts it as overflow when `cap` rows wait already.
    pub(crate) async fn push_audit_pending(
        &mut self,
        row: &AuditPendingRow,
        cap: u32,
    ) -> Result<(), StoreError> {
        let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_pending")
            .fetch_one(self.conn())
            .await?;
        if waiting >= i64::from(cap) {
            sqlx::query("UPDATE audit_pending_overflow SET count = count + 1 WHERE id = 1")
                .execute(self.conn())
                .await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO audit_pending (occurred_at, event_type, agent_id, target_id, result_code, route, request_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(to_ms(row.occurred_at))
        .bind(&row.event_type)
        .bind(row.agent_id.as_ref().map(AgentId::to_string))
        .bind(row.target_id.as_deref())
        .bind(&row.result_code)
        .bind(row.route.as_deref())
        .bind(row.request_id.map(|id| id.to_string()))
        .execute(self.conn())
        .await?;
        Ok(())
    }

    /// Reads and clears the pending events and the overflow counter, inside this transaction. The
    /// rows are gone for good only when the transaction commits, so a caller that chains them in the
    /// same transaction loses none on a crash or an error (DEC-WIRE-1). A row that cannot be read
    /// is deleted and counted in [`PendingTake::malformed`] (AUD-9).
    ///
    /// # Errors
    /// An engine error.
    pub async fn take_audit_pending(&mut self) -> Result<PendingTake, StoreError> {
        let rows = sqlx::query("SELECT * FROM audit_pending ORDER BY id")
            .fetch_all(self.conn())
            .await?;
        let overflow: i64 =
            sqlx::query_scalar("SELECT count FROM audit_pending_overflow WHERE id = 1")
                .fetch_one(self.conn())
                .await?;
        sqlx::query("DELETE FROM audit_pending")
            .execute(self.conn())
            .await?;
        sqlx::query("UPDATE audit_pending_overflow SET count = 0 WHERE id = 1")
            .execute(self.conn())
            .await?;
        let mut take = PendingTake {
            rows: Vec::with_capacity(rows.len()),
            overflow: to_u64(overflow)?,
            malformed: 0,
        };
        for row in &rows {
            match AuditPendingRow::from_sql(row) {
                Ok(pending) => take.rows.push(pending),
                Err(_) => take.malformed += 1,
            }
        }
        Ok(take)
    }

    /// Sweeper step: deletes expired items (cascade), old leases and old requests. Returns the IDs of the
    /// items deleted and the counts of leases and requests deleted.
    pub(crate) async fn sweep(
        &mut self,
        now: Timestamp,
        lease_cutoff: Timestamp,
        request_cutoff: Timestamp,
    ) -> Result<(Vec<ItemId>, u64, u64), StoreError> {
        let expired: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM items WHERE expires_at IS NOT NULL AND expires_at <= ?1 ORDER BY id",
        )
        .bind(to_ms(now))
        .fetch_all(self.conn())
        .await?;
        let ids = expired
            .iter()
            .map(|text| crate::convert::parse_id(text))
            .collect::<Result<Vec<ItemId>, _>>()?;
        sqlx::query("DELETE FROM items WHERE expires_at IS NOT NULL AND expires_at <= ?1")
            .bind(to_ms(now))
            .execute(self.conn())
            .await?;
        let lease_ms = to_ms(lease_cutoff);
        // A revoked auto lease blocks new auto leases until its old end (ADR-0019 point 7), so
        // it stays until `expires_at` is past the grace time like an ended lease.
        let leases = sqlx::query(
            "DELETE FROM leases WHERE expires_at <= ?1 OR released_at <= ?1 \
             OR (revoked_at <= ?1 AND source != 'auto')",
        )
        .bind(lease_ms)
        .execute(self.conn())
        .await?;
        let requests = sqlx::query(
            "DELETE FROM access_requests WHERE COALESCE(decided_at, expires_at) <= ?1 AND status != 'pending' \
             OR status = 'pending' AND expires_at <= ?1",
        )
        .bind(to_ms(request_cutoff))
        .execute(self.conn())
        .await?;
        Ok((ids, leases.rows_affected(), requests.rows_affected()))
    }
}

/// The `id` text exactly as stored, so an in-place update finds the row it read.
fn stored_id(row: &sqlx::sqlite::SqliteRow) -> Result<String, StoreError> {
    Ok(sqlx::Row::try_get::<String, _>(row, "id")?)
}
