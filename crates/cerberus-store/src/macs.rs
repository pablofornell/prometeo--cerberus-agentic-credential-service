//! Row MACs (ADR-0033) and the header MAC (ADR-0013), computed with the crypto crate.
//!
//! The store never keeps a key. The caller passes `row_mac_key` or `header_key` in.

use cerberus_crypto::{
    HeaderMacInput, Key32, MacField, ct_eq, header_mac as crypto_header_mac, row_mac,
};
use cerberus_types::VaultId;

use crate::StoreError;
use crate::convert::{enum_text, nets_text, scopes_text, to_ms};
use crate::rows::{
    AccessRequestRow, AgentKeyRow, AgentRow, HeaderRow, KeySlotRow, LeaseRow, MAGIC,
};

fn int(value: i64) -> MacField<'static> {
    MacField::Int(value)
}

fn opt_int(value: Option<i64>) -> MacField<'static> {
    value.map_or(MacField::Null, MacField::Int)
}

fn opt_text(value: Option<&str>) -> MacField<'_> {
    value.map_or(MacField::Null, MacField::Text)
}

/// Makes and checks the `row_mac` of `agents`, `agent_keys`, `leases` and `access_requests`.
///
/// `row_mac_key` is the key from the key tree, so this exists only while the vault is unlocked.
#[derive(Clone, Copy)]
pub struct RowMacs<'a> {
    key: &'a Key32,
    vault_id: &'a VaultId,
}

impl<'a> RowMacs<'a> {
    /// Uses `row_mac_key` for the vault `vault_id`.
    #[must_use]
    pub const fn new(row_mac_key: &'a Key32, vault_id: &'a VaultId) -> Self {
        Self {
            key: row_mac_key,
            vault_id,
        }
    }

    fn mac(&self, table: &str, fields: &[MacField<'_>]) -> [u8; 32] {
        row_mac(self.key, self.vault_id, table, fields)
    }

    /// MAC of an agent row: `id`, `status`, `created_at`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] if the status has no text form (cannot happen for the known values).
    pub fn agent(&self, row: &AgentRow) -> Result<[u8; 32], StoreError> {
        let id = row.id.to_string();
        let status = enum_text(&row.status)?;
        Ok(self.mac(
            "agents",
            &[
                MacField::Text(&id),
                MacField::Text(&status),
                int(to_ms(row.created_at)),
            ],
        ))
    }

    /// MAC of an agent key row: every column except `last_used_at` and `row_mac`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] if a scope has no text form (cannot happen for the known values).
    pub fn agent_key(&self, row: &AgentKeyRow) -> Result<[u8; 32], StoreError> {
        let id = row.id.to_string();
        let agent_id = row.agent_id.to_string();
        let scopes = scopes_text(&row.scopes)?;
        let nets = nets_text(&row.ip_allowlist);
        Ok(self.mac(
            "agent_keys",
            &[
                MacField::Text(&id),
                MacField::Text(&agent_id),
                MacField::Bytes(&row.secret_hash),
                MacField::Text(&row.hint),
                MacField::Text(&scopes),
                MacField::Text(&nets),
                int(i64::from(row.require_mtls)),
                row.client_cert_sha256
                    .as_ref()
                    .map_or(MacField::Null, |hash| MacField::Bytes(hash)),
                int(to_ms(row.created_at)),
                opt_int(row.expires_at.map(to_ms)),
                opt_int(row.revoked_at.map(to_ms)),
            ],
        ))
    }

    /// MAC of a lease row: every column except `row_mac`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] if an enum has no text form (cannot happen for the known values).
    pub fn lease(&self, row: &LeaseRow) -> Result<[u8; 32], StoreError> {
        let id = row.id.to_string();
        let agent_id = row.agent_id.to_string();
        let item_id = row.item_id.to_string();
        let permission = enum_text(&row.permission)?;
        let source = enum_text(&row.source)?;
        let request_id = row.request_id.map(|id| id.to_string());
        Ok(self.mac(
            "leases",
            &[
                MacField::Text(&id),
                MacField::Text(&agent_id),
                MacField::Text(&item_id),
                MacField::Text(&permission),
                MacField::Text(&source),
                opt_text(request_id.as_deref()),
                int(to_ms(row.created_at)),
                int(to_ms(row.expires_at)),
                opt_int(row.max_uses.map(i64::from)),
                int(i64::from(row.uses)),
                opt_int(row.released_at.map(to_ms)),
                opt_int(row.revoked_at.map(to_ms)),
                opt_text(row.revoked_by.as_deref()),
            ],
        ))
    }

    /// MAC of an access request row: every column except `reason_ct` and `row_mac`.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] if an enum has no text form (cannot happen for the known values).
    pub fn access_request(&self, row: &AccessRequestRow) -> Result<[u8; 32], StoreError> {
        let id = row.id.to_string();
        let agent_id = row.agent_id.to_string();
        let item_id = row.item_id.to_string();
        let permission = enum_text(&row.permission)?;
        let status = enum_text(&row.status)?;
        let decided_by = row.decided_by.map(|id| id.to_string());
        let option = row.approval_option.as_ref().map(enum_text).transpose()?;
        let lease_id = row.lease_id.map(|id| id.to_string());
        let request_id = row.request_id.to_string();
        Ok(self.mac(
            "access_requests",
            &[
                MacField::Text(&id),
                MacField::Text(&agent_id),
                MacField::Text(&item_id),
                MacField::Text(&permission),
                MacField::Text(&status),
                opt_int(row.requested_ttl_seconds.map(i64::from)),
                int(to_ms(row.created_at)),
                int(to_ms(row.expires_at)),
                opt_int(row.decided_at.map(to_ms)),
                opt_text(decided_by.as_deref()),
                opt_text(option.as_deref()),
                opt_text(lease_id.as_deref()),
                MacField::Text(&request_id),
            ],
        ))
    }

    /// Sets `row.row_mac` for an agent row.
    ///
    /// # Errors
    /// As [`Self::agent`].
    pub fn sign_agent(&self, row: &mut AgentRow) -> Result<(), StoreError> {
        row.row_mac = self.agent(row)?;
        Ok(())
    }

    /// Sets `row.row_mac` for an agent key row.
    ///
    /// # Errors
    /// As [`Self::agent_key`].
    pub fn sign_agent_key(&self, row: &mut AgentKeyRow) -> Result<(), StoreError> {
        row.row_mac = self.agent_key(row)?;
        Ok(())
    }

    /// Sets `row.row_mac` for a lease row.
    ///
    /// # Errors
    /// As [`Self::lease`].
    pub fn sign_lease(&self, row: &mut LeaseRow) -> Result<(), StoreError> {
        row.row_mac = self.lease(row)?;
        Ok(())
    }

    /// Sets `row.row_mac` for an access request row.
    ///
    /// # Errors
    /// As [`Self::access_request`].
    pub fn sign_access_request(&self, row: &mut AccessRequestRow) -> Result<(), StoreError> {
        row.row_mac = self.access_request(row)?;
        Ok(())
    }

    /// True when the stored MAC of an agent row is right (constant-time compare).
    ///
    /// # Errors
    /// As [`Self::agent`].
    pub fn verify_agent(&self, row: &AgentRow) -> Result<bool, StoreError> {
        Ok(ct_eq(&self.agent(row)?, &row.row_mac))
    }

    /// True when the stored MAC of an agent key row is right.
    ///
    /// # Errors
    /// As [`Self::agent_key`].
    pub fn verify_agent_key(&self, row: &AgentKeyRow) -> Result<bool, StoreError> {
        Ok(ct_eq(&self.agent_key(row)?, &row.row_mac))
    }

    /// True when the stored MAC of a lease row is right.
    ///
    /// # Errors
    /// As [`Self::lease`].
    pub fn verify_lease(&self, row: &LeaseRow) -> Result<bool, StoreError> {
        Ok(ct_eq(&self.lease(row)?, &row.row_mac))
    }

    /// True when the stored MAC of an access request row is right.
    ///
    /// # Errors
    /// As [`Self::access_request`].
    pub fn verify_access_request(&self, row: &AccessRequestRow) -> Result<bool, StoreError> {
        Ok(ct_eq(&self.access_request(row)?, &row.row_mac))
    }
}

/// The header MAC over the header row and its key slots (ADR-0013). `header_key` comes from the key tree.
#[must_use]
pub fn header_mac(header_key: &Key32, header: &HeaderRow, slots: &[KeySlotRow]) -> [u8; 32] {
    let key_slots: Vec<_> = slots.iter().map(KeySlotRow::to_key_slot).collect();
    crypto_header_mac(
        header_key,
        &HeaderMacInput {
            magic: MAGIC,
            format_version: header.format_version,
            vault_id: &header.vault_id,
            created_at_ms: to_ms(header.created_at),
            slots: key_slots
                .iter()
                .map(cerberus_crypto::KeySlot::mac_input)
                .collect(),
        },
    )
}

/// True when `header.header_mac` is right for this header and these slots.
#[must_use]
pub fn verify_header_mac(header_key: &Key32, header: &HeaderRow, slots: &[KeySlotRow]) -> bool {
    ct_eq(&header_mac(header_key, header, slots), &header.header_mac)
}
