//! Row types: the plain columns as typed values, and the `*_ct` columns as sealed bytes (ADR-0005).
//!
//! Fields mirror the columns of `migrations/0001_initial.sql`. A `row_mac` is made by
//! [`crate::RowMacs`] and checked by the caller before it trusts the row (ADR-0033).

#![allow(missing_docs, reason = "fields mirror the schema columns")]

use cerberus_crypto::{KdfParams, KeySlot, SlotKdf, SlotMaterial};
use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, AgentKeyId, ApprovalOption, GrantId, ItemId,
    ItemKind, KeySlotId, LeaseId, OperatorId, OperatorRole, Permission, RequestId, Scope, VaultId,
    WorkspaceId,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::SqliteRow;

use crate::StoreError;
use crate::convert::{
    bytes32, from_ms, opt_bytes32, opt_from_ms, opt_parse_enum, opt_parse_id, opt_to_u32,
    parse_enum, parse_id, parse_nets, parse_scopes, to_u32, to_u64,
};

/// `vault_header.magic` (ADR-0013).
pub const MAGIC: &str = "CERBERUS-VAULT";
/// Crypto format version 1 (ADR-0013, ADR-0014).
pub const FORMAT_VERSION: u32 = 1;

/// The one `vault_header` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRow {
    pub format_version: u32,
    pub vault_id: VaultId,
    pub created_at: Timestamp,
    pub failed_unlocks: u32,
    pub last_failed_unlock_at: Option<Timestamp>,
    pub header_mac: [u8; 32],
}

/// Kind of a key slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotKind {
    Passphrase,
    Recovery,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlotRow {
    pub id: KeySlotId,
    pub kind: SlotKind,
    pub label: String,
    pub role: OperatorRole,
    pub material: SlotMaterial,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub last_unlock_at: Option<Timestamp>,
}

impl KeySlotRow {
    /// The slot as the crypto crate sees it (for the header MAC and for unlock).
    #[must_use]
    pub fn to_key_slot(&self) -> KeySlot {
        KeySlot {
            id: self.id,
            role: self.role,
            material: self.material.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingRow {
    pub key: String,
    pub updated_at: Timestamp,
    pub value_ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCaRow {
    pub ca_cert_der: Vec<u8>,
    pub ca_key_ct: Vec<u8>,
    pub created_at: Timestamp,
    pub not_after: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRow {
    pub id: WorkspaceId,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub meta_ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemRow {
    pub id: ItemId,
    pub kind: ItemKind,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub current_version: u32,
    pub meta_ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemVersionRow {
    pub item_id: ItemId,
    pub version: u32,
    pub created_at: Timestamp,
    pub wrapped_dek: Vec<u8>,
    pub payload_ct: Vec<u8>,
    pub meta_ct: Vec<u8>,
}

/// Status of an agent. Plain, because token checks run while locked (ADR-0016).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRow {
    pub id: AgentId,
    pub status: AgentStatus,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub meta_ct: Vec<u8>,
    pub row_mac: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentKeyRow {
    pub id: AgentKeyId,
    pub agent_id: AgentId,
    pub secret_hash: [u8; 32],
    pub hint: String,
    pub scopes: Vec<Scope>,
    pub ip_allowlist: Vec<ipnet::IpNet>,
    pub require_mtls: bool,
    pub client_cert_sha256: Option<[u8; 32]>,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
    pub last_used_at: Option<Timestamp>,
    pub row_mac: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    pub id: GrantId,
    pub agent_id: AgentId,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub body_ct: Vec<u8>,
}

/// How a lease came to exist (ADR-0019).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseSource {
    Auto,
    Approval,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseRow {
    pub id: LeaseId,
    pub agent_id: AgentId,
    pub item_id: ItemId,
    pub permission: Permission,
    pub source: LeaseSource,
    pub request_id: Option<AccessRequestId>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub released_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
    pub revoked_by: Option<String>,
    pub row_mac: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessRequestRow {
    pub id: AccessRequestId,
    pub agent_id: AgentId,
    pub item_id: ItemId,
    pub permission: Permission,
    pub status: AccessRequestStatus,
    pub requested_ttl_seconds: Option<u32>,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub decided_at: Option<Timestamp>,
    pub decided_by: Option<OperatorId>,
    pub approval_option: Option<ApprovalOption>,
    pub lease_id: Option<LeaseId>,
    pub request_id: RequestId,
    pub reason_ct: Option<Vec<u8>>,
    pub row_mac: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    pub seq: u64,
    pub occurred_at: Timestamp,
    pub prev_hash: [u8; 32],
    pub hmac: [u8; 32],
    pub body_ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditHeadRow {
    pub last_seq: u64,
    pub last_entry_hash: [u8; 32],
    pub anchor_seq: u64,
    pub anchor_prev_hash: [u8; 32],
    pub head_hmac: [u8; 32],
}

/// An event written while the vault is locked (ADR-0025). Plain on purpose: IDs, codes and routes only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPendingRow {
    pub occurred_at: Timestamp,
    pub event_type: String,
    pub agent_id: Option<AgentId>,
    pub target_id: Option<String>,
    pub result_code: String,
    pub route: Option<String>,
    pub request_id: Option<RequestId>,
}

/// Everything the in-memory index needs at unlock (ADR-0006). Expired items and grants are left out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexRows {
    pub workspaces: Vec<WorkspaceRow>,
    pub items: Vec<ItemRow>,
    pub agents: Vec<AgentRow>,
    pub grants: Vec<GrantRow>,
}

/// What a backup file says about itself, read without any key (ADR-0031 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupInfo {
    pub vault_id: VaultId,
    pub format_version: u32,
    pub schema_version: i64,
    pub created_at: Timestamp,
    pub slots: Vec<KeySlotRow>,
}

// ---- readers (queries use `SELECT *`; every reader reads its columns by name) ----------------------

fn vault_id_from(bytes: &[u8]) -> Result<VaultId, StoreError> {
    let array: [u8; 16] = bytes.try_into().map_err(|_| StoreError::Corrupt)?;
    Ok(VaultId(array))
}

impl HeaderRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        let vault_id: Vec<u8> = row.try_get("vault_id")?;
        Ok(Self {
            format_version: to_u32(row.try_get("format_version")?)?,
            vault_id: vault_id_from(&vault_id)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            failed_unlocks: to_u32(row.try_get("failed_unlocks")?)?,
            last_failed_unlock_at: opt_from_ms(row.try_get("last_failed_unlock_at")?)?,
            header_mac: bytes32(&row.try_get::<Vec<u8>, _>("header_mac")?)?,
        })
    }
}

impl KeySlotRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        let kind: SlotKind = parse_enum(&row.try_get::<String, _>("kind")?)?;
        let kdf_alg: String = row.try_get("kdf_alg")?;
        let kdf = match (kind, kdf_alg.as_str()) {
            (SlotKind::Passphrase, "argon2id") => {
                let m = to_u32(row.try_get::<i64, _>("m_cost_kib")?)?;
                let t = to_u32(row.try_get::<i64, _>("t_cost")?)?;
                let p = to_u32(row.try_get::<i64, _>("p_cost")?)?;
                SlotKdf::Argon2id(KdfParams::new(m, t, p).map_err(|_| StoreError::Corrupt)?)
            }
            (SlotKind::Recovery, "hkdf-sha256") => SlotKdf::HkdfSha256,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            kind,
            label: row.try_get("label")?,
            role: parse_enum(&row.try_get::<String, _>("role")?)?,
            material: SlotMaterial {
                kdf,
                salt: bytes32(&row.try_get::<Vec<u8>, _>("salt")?)?,
                wrapped_vmk: row.try_get("wrapped_vmk")?,
            },
            created_at: from_ms(row.try_get("created_at")?)?,
            updated_at: from_ms(row.try_get("updated_at")?)?,
            last_unlock_at: opt_from_ms(row.try_get("last_unlock_at")?)?,
        })
    }
}

impl SettingRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            key: row.try_get("key")?,
            updated_at: from_ms(row.try_get("updated_at")?)?,
            value_ct: row.try_get("value_ct")?,
        })
    }
}

impl TlsCaRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            ca_cert_der: row.try_get("ca_cert_der")?,
            ca_key_ct: row.try_get("ca_key_ct")?,
            created_at: from_ms(row.try_get("created_at")?)?,
            not_after: from_ms(row.try_get("not_after")?)?,
        })
    }
}

impl WorkspaceRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            updated_at: from_ms(row.try_get("updated_at")?)?,
            meta_ct: row.try_get("meta_ct")?,
        })
    }
}

impl ItemRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            kind: parse_enum(&row.try_get::<String, _>("kind")?)?,
            expires_at: opt_from_ms(row.try_get("expires_at")?)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            updated_at: from_ms(row.try_get("updated_at")?)?,
            current_version: to_u32(row.try_get("current_version")?)?,
            meta_ct: row.try_get("meta_ct")?,
        })
    }
}

impl ItemVersionRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            item_id: parse_id(&row.try_get::<String, _>("item_id")?)?,
            version: to_u32(row.try_get("version")?)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            wrapped_dek: row.try_get("wrapped_dek")?,
            payload_ct: row.try_get("payload_ct")?,
            meta_ct: row.try_get("meta_ct")?,
        })
    }
}

impl AgentRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            status: parse_enum(&row.try_get::<String, _>("status")?)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            updated_at: from_ms(row.try_get("updated_at")?)?,
            meta_ct: row.try_get("meta_ct")?,
            row_mac: bytes32(&row.try_get::<Vec<u8>, _>("row_mac")?)?,
        })
    }
}

impl AgentKeyRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        let cert: Option<Vec<u8>> = row.try_get("client_cert_sha256")?;
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
            secret_hash: bytes32(&row.try_get::<Vec<u8>, _>("secret_hash")?)?,
            hint: row.try_get("hint")?,
            scopes: parse_scopes(&row.try_get::<String, _>("scopes")?)?,
            ip_allowlist: parse_nets(&row.try_get::<String, _>("ip_allowlist")?)?,
            require_mtls: row.try_get::<i64, _>("require_mtls")? != 0,
            client_cert_sha256: opt_bytes32(cert.as_deref())?,
            created_at: from_ms(row.try_get("created_at")?)?,
            expires_at: opt_from_ms(row.try_get("expires_at")?)?,
            revoked_at: opt_from_ms(row.try_get("revoked_at")?)?,
            last_used_at: opt_from_ms(row.try_get("last_used_at")?)?,
            row_mac: bytes32(&row.try_get::<Vec<u8>, _>("row_mac")?)?,
        })
    }
}

impl GrantRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            updated_at: from_ms(row.try_get("updated_at")?)?,
            expires_at: opt_from_ms(row.try_get("expires_at")?)?,
            body_ct: row.try_get("body_ct")?,
        })
    }
}

impl LeaseRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
            item_id: parse_id(&row.try_get::<String, _>("item_id")?)?,
            permission: parse_enum(&row.try_get::<String, _>("permission")?)?,
            source: parse_enum(&row.try_get::<String, _>("source")?)?,
            request_id: opt_parse_id(row.try_get::<Option<String>, _>("request_id")?.as_deref())?,
            created_at: from_ms(row.try_get("created_at")?)?,
            expires_at: from_ms(row.try_get("expires_at")?)?,
            max_uses: opt_to_u32(row.try_get("max_uses")?)?,
            uses: to_u32(row.try_get("uses")?)?,
            released_at: opt_from_ms(row.try_get("released_at")?)?,
            revoked_at: opt_from_ms(row.try_get("revoked_at")?)?,
            revoked_by: row.try_get("revoked_by")?,
            row_mac: bytes32(&row.try_get::<Vec<u8>, _>("row_mac")?)?,
        })
    }
}

impl AccessRequestRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            id: parse_id(&row.try_get::<String, _>("id")?)?,
            agent_id: parse_id(&row.try_get::<String, _>("agent_id")?)?,
            item_id: parse_id(&row.try_get::<String, _>("item_id")?)?,
            permission: parse_enum(&row.try_get::<String, _>("permission")?)?,
            status: parse_enum(&row.try_get::<String, _>("status")?)?,
            requested_ttl_seconds: opt_to_u32(row.try_get("requested_ttl_seconds")?)?,
            created_at: from_ms(row.try_get("created_at")?)?,
            expires_at: from_ms(row.try_get("expires_at")?)?,
            decided_at: opt_from_ms(row.try_get("decided_at")?)?,
            decided_by: opt_parse_id(row.try_get::<Option<String>, _>("decided_by")?.as_deref())?,
            approval_option: opt_parse_enum(
                row.try_get::<Option<String>, _>("approval_option")?
                    .as_deref(),
            )?,
            lease_id: opt_parse_id(row.try_get::<Option<String>, _>("lease_id")?.as_deref())?,
            request_id: parse_id(&row.try_get::<String, _>("request_id")?)?,
            reason_ct: row.try_get("reason_ct")?,
            row_mac: bytes32(&row.try_get::<Vec<u8>, _>("row_mac")?)?,
        })
    }
}

impl AuditRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            seq: to_u64(row.try_get("seq")?)?,
            occurred_at: from_ms(row.try_get("occurred_at")?)?,
            prev_hash: bytes32(&row.try_get::<Vec<u8>, _>("prev_hash")?)?,
            hmac: bytes32(&row.try_get::<Vec<u8>, _>("hmac")?)?,
            body_ct: row.try_get("body_ct")?,
        })
    }
}

impl AuditHeadRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            last_seq: to_u64(row.try_get("last_seq")?)?,
            last_entry_hash: bytes32(&row.try_get::<Vec<u8>, _>("last_entry_hash")?)?,
            anchor_seq: to_u64(row.try_get("anchor_seq")?)?,
            anchor_prev_hash: bytes32(&row.try_get::<Vec<u8>, _>("anchor_prev_hash")?)?,
            head_hmac: bytes32(&row.try_get::<Vec<u8>, _>("head_hmac")?)?,
        })
    }
}

impl AuditPendingRow {
    pub(crate) fn from_sql(row: &SqliteRow) -> Result<Self, StoreError> {
        Ok(Self {
            occurred_at: from_ms(row.try_get("occurred_at")?)?,
            event_type: row.try_get("event_type")?,
            agent_id: opt_parse_id(row.try_get::<Option<String>, _>("agent_id")?.as_deref())?,
            target_id: row.try_get("target_id")?,
            result_code: row.try_get("result_code")?,
            route: row.try_get("route")?,
            request_id: opt_parse_id(row.try_get::<Option<String>, _>("request_id")?.as_deref())?,
        })
    }
}
