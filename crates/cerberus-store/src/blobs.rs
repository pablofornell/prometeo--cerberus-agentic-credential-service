//! Sealing and opening of the encrypted columns, through `cerberus-crypto` (ADR-0014).
//!
//! One method pair per purpose label, so the AAD (purpose, vault, record ID, version) is built in
//! one place. A ciphertext moved to another row, column, version or vault fails to open.
//! Plaintext is padded and sealed by the crypto crate. This module does not touch key bytes.

use cerberus_crypto::{
    Aad, KeyTree, Purpose, SecretBytes, new_dek, open, seal, unwrap_dek, wrap_dek,
};
use cerberus_types::{AccessRequestId, AgentId, GrantId, ItemId, VaultId, WorkspaceId};

use crate::StoreError;

/// Record ID of the single `tls_ca` row in the `ca.key` AAD.
const CA_RECORD_ID: &[u8] = b"tls_ca";

/// The two sealed columns of one item version (`item_versions.wrapped_dek`, `item_versions.payload_ct`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPayload {
    /// The DEK of this version, sealed with `item_kek`.
    pub wrapped_dek: Vec<u8>,
    /// The payload, sealed with that DEK.
    pub payload_ct: Vec<u8>,
}

/// Seals and opens the encrypted columns of one vault with the keys of an unlocked key tree.
#[derive(Clone, Copy)]
pub struct Blobs<'a> {
    vault_id: &'a VaultId,
    keys: &'a KeyTree,
}

impl<'a> Blobs<'a> {
    /// Uses the key tree of the vault `vault_id`.
    #[must_use]
    pub const fn new(vault_id: &'a VaultId, keys: &'a KeyTree) -> Self {
        Self { vault_id, keys }
    }

    fn aad<'b>(&'b self, purpose: Purpose, record_id: &'b [u8], version: u32) -> Aad<'b> {
        Aad {
            purpose,
            vault_id: self.vault_id,
            record_id,
            version,
        }
    }

    fn seal_meta(
        &self,
        purpose: Purpose,
        record_id: &[u8],
        version: u32,
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        Ok(seal(
            &self.keys.meta_key,
            &self.aad(purpose, record_id, version),
            plain,
        )?)
    }

    fn open_meta(
        &self,
        purpose: Purpose,
        record_id: &[u8],
        version: u32,
        ct: &[u8],
    ) -> Result<SecretBytes, StoreError> {
        Ok(open(
            &self.keys.meta_key,
            &self.aad(purpose, record_id, version),
            ct,
        )?)
    }

    /// Seals `items.meta_ct`. `version` is `items.current_version`.
    ///
    /// # Errors
    /// [`StoreError::Crypto`] when the random generator fails or the plaintext is too long.
    pub fn seal_item_meta(
        &self,
        item: &ItemId,
        version: u32,
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::ItemMeta, item.as_bytes(), version, plain)
    }

    /// Opens `items.meta_ct`.
    ///
    /// # Errors
    /// [`StoreError::Crypto`] (`Integrity`) when the blob is changed or belongs to another row or version.
    pub fn open_item_meta(
        &self,
        item: &ItemId,
        version: u32,
        ct: &[u8],
    ) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::ItemMeta, item.as_bytes(), version, ct)
    }

    /// Seals `item_versions.meta_ct`, the metadata snapshot of one version.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_item_snapshot(
        &self,
        item: &ItemId,
        version: u32,
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::ItemMetaSnapshot, item.as_bytes(), version, plain)
    }

    /// Opens `item_versions.meta_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_item_snapshot(
        &self,
        item: &ItemId,
        version: u32,
        ct: &[u8],
    ) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::ItemMetaSnapshot, item.as_bytes(), version, ct)
    }

    /// Makes a new DEK for `version`, seals the payload with it and wraps the DEK with `item_kek`.
    ///
    /// # Errors
    /// [`StoreError::Crypto`] when the random generator fails.
    pub fn seal_payload(
        &self,
        item: &ItemId,
        version: u32,
        payload: &[u8],
    ) -> Result<SealedPayload, StoreError> {
        let dek = new_dek()?;
        let wrapped_dek = wrap_dek(
            &self.keys.item_kek,
            &self.aad(Purpose::ItemDek, item.as_bytes(), version),
            &dek,
        )?;
        let payload_ct = seal(
            &dek,
            &self.aad(Purpose::ItemPayload, item.as_bytes(), version),
            payload,
        )?;
        Ok(SealedPayload {
            wrapped_dek,
            payload_ct,
        })
    }

    /// Unwraps the DEK and opens the payload of one version.
    ///
    /// # Errors
    /// [`StoreError::Crypto`] (`Integrity`) when a blob is changed or moved to another item or version.
    pub fn open_payload(
        &self,
        item: &ItemId,
        version: u32,
        sealed: &SealedPayload,
    ) -> Result<SecretBytes, StoreError> {
        let dek = unwrap_dek(
            &self.keys.item_kek,
            &self.aad(Purpose::ItemDek, item.as_bytes(), version),
            &sealed.wrapped_dek,
        )?;
        Ok(open(
            &dek,
            &self.aad(Purpose::ItemPayload, item.as_bytes(), version),
            &sealed.payload_ct,
        )?)
    }

    /// Seals `workspaces.meta_ct`.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_workspace_meta(
        &self,
        id: &WorkspaceId,
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::WorkspaceMeta, id.as_bytes(), 0, plain)
    }

    /// Opens `workspaces.meta_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_workspace_meta(
        &self,
        id: &WorkspaceId,
        ct: &[u8],
    ) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::WorkspaceMeta, id.as_bytes(), 0, ct)
    }

    /// Seals `agents.meta_ct`.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_agent_meta(&self, id: &AgentId, plain: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::AgentMeta, id.as_bytes(), 0, plain)
    }

    /// Opens `agents.meta_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_agent_meta(&self, id: &AgentId, ct: &[u8]) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::AgentMeta, id.as_bytes(), 0, ct)
    }

    /// Seals `grants.body_ct`.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_grant_body(&self, id: &GrantId, plain: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::GrantBody, id.as_bytes(), 0, plain)
    }

    /// Opens `grants.body_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_grant_body(&self, id: &GrantId, ct: &[u8]) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::GrantBody, id.as_bytes(), 0, ct)
    }

    /// Seals `access_requests.reason_ct`.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_request_reason(
        &self,
        id: &AccessRequestId,
        plain: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::RequestReason, id.as_bytes(), 0, plain)
    }

    /// Opens `access_requests.reason_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_request_reason(
        &self,
        id: &AccessRequestId,
        ct: &[u8],
    ) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::RequestReason, id.as_bytes(), 0, ct)
    }

    /// Seals `audit_events.body_ct`. The record ID is `seq` as u64 big-endian (ADR-0025).
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_audit_body(&self, seq: u64, plain: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::AuditBody, &seq.to_be_bytes(), 0, plain)
    }

    /// Opens `audit_events.body_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_audit_body(&self, seq: u64, ct: &[u8]) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::AuditBody, &seq.to_be_bytes(), 0, ct)
    }

    /// Seals `settings.value_ct`. The record ID is the key name.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_setting(&self, key: &str, plain: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.seal_meta(Purpose::SettingsValue, key.as_bytes(), 0, plain)
    }

    /// Opens `settings.value_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_setting(&self, key: &str, ct: &[u8]) -> Result<SecretBytes, StoreError> {
        self.open_meta(Purpose::SettingsValue, key.as_bytes(), 0, ct)
    }

    /// Seals `tls_ca.ca_key_ct` with `ca_key`.
    ///
    /// # Errors
    /// As [`Self::seal_item_meta`].
    pub fn seal_ca_key(&self, plain: &[u8]) -> Result<Vec<u8>, StoreError> {
        Ok(seal(
            &self.keys.ca_key,
            &self.aad(Purpose::CaKey, CA_RECORD_ID, 0),
            plain,
        )?)
    }

    /// Opens `tls_ca.ca_key_ct`.
    ///
    /// # Errors
    /// As [`Self::open_item_meta`].
    pub fn open_ca_key(&self, ct: &[u8]) -> Result<SecretBytes, StoreError> {
        Ok(open(
            &self.keys.ca_key,
            &self.aad(Purpose::CaKey, CA_RECORD_ID, 0),
            ct,
        )?)
    }
}
