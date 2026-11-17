//! The local CA is made at vault creation (ADR-0023). Certificate code lives in the API layer, so
//! the vault service takes it as a trait. The service seals the CA key with `ca_key`.

use cerberus_crypto::SecretBytes;
use cerberus_store::{SettingRow, StoreError};
use cerberus_types::{OperatorRole, VaultId};
use jiff::Timestamp;

use super::VaultService;
use super::custody::HOST_NAMES_SETTING;
use super::integration::by_operator;
use crate::audit::EventType;
use crate::context::OperatorContext;
use crate::error::CoreError;

/// The setting that holds the owner custom certificate (ADR-0023 point 8). Sealed like every
/// setting, so the key is protected by the vault keys and a locked vault cannot serve it.
pub const TLS_CUSTOM_SETTING: &str = "tls_custom";
/// The most certificates in a custom chain.
const MAX_CUSTOM_CHAIN: usize = 8;

/// The owner custom certificate: the chain (leaf first) and the leaf private key.
pub struct TlsCustomMaterial {
    /// The certificate chain, DER, leaf first.
    pub chain_der: Vec<Vec<u8>>,
    /// The leaf private key (PKCS#8 DER). Zeroized on drop.
    pub key_der: SecretBytes,
}

impl std::fmt::Debug for TlsCustomMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCustomMaterial")
            .field("chain_len", &self.chain_der.len())
            .field("key_der", &"[REDACTED]")
            .finish()
    }
}

fn push_part(out: &mut Vec<u8>, part: &[u8]) -> Result<(), CoreError> {
    let len = u32::try_from(part.len()).map_err(|_| CoreError::Corrupt)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(part);
    Ok(())
}

/// Frames the material as `count, (len, cert)*, len, key`, all lengths u32 big endian.
fn encode_custom(chain: &[Vec<u8>], key: &[u8]) -> Result<Vec<u8>, CoreError> {
    let count = u32::try_from(chain.len()).map_err(|_| CoreError::Corrupt)?;
    let mut out = count.to_be_bytes().to_vec();
    for cert in chain {
        push_part(&mut out, cert)?;
    }
    push_part(&mut out, key)?;
    Ok(out)
}

fn take_part<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], CoreError> {
    let (head, tail) = rest.split_at_checked(4).ok_or(CoreError::Corrupt)?;
    let len = u32::from_be_bytes(head.try_into().map_err(|_| CoreError::Corrupt)?);
    let len = usize::try_from(len).map_err(|_| CoreError::Corrupt)?;
    let (part, tail) = tail.split_at_checked(len).ok_or(CoreError::Corrupt)?;
    *rest = tail;
    Ok(part)
}

fn decode_custom(plain: &[u8]) -> Result<TlsCustomMaterial, CoreError> {
    let (head, mut rest) = plain.split_at_checked(4).ok_or(CoreError::Corrupt)?;
    let count = u32::from_be_bytes(head.try_into().map_err(|_| CoreError::Corrupt)?);
    let count = usize::try_from(count).map_err(|_| CoreError::Corrupt)?;
    if count == 0 || count > MAX_CUSTOM_CHAIN {
        return Err(CoreError::Corrupt);
    }
    let mut chain_der = Vec::with_capacity(count);
    for _ in 0..count {
        chain_der.push(take_part(&mut rest)?.to_vec());
    }
    let key_der = SecretBytes::new(take_part(&mut rest)?.to_vec());
    if !rest.is_empty() {
        return Err(CoreError::Corrupt);
    }
    Ok(TlsCustomMaterial { chain_der, key_der })
}

/// A new local CA.
#[derive(Debug)]
pub struct IssuedCa {
    /// The self-signed CA certificate (DER). Stored plain in `tls_ca.ca_cert_der`.
    pub cert_der: Vec<u8>,
    /// The CA private key (DER). The service seals it and drops it.
    pub key_der: SecretBytes,
    /// End of validity.
    pub not_after: Timestamp,
    /// Pin text `sha256/<base64>` of the CA SubjectPublicKeyInfo (ADR-0023 point 6).
    pub pin: String,
}

/// Makes the local CA (ECDSA P-256, 10 years, ADR-0023). `cerberus-api` implements it with `rcgen`.
pub trait CaIssuer: Send + Sync + std::fmt::Debug {
    /// Makes a new CA for the vault `vault_id` at time `now`.
    ///
    /// # Errors
    /// Any error makes `create_vault` fail before a file is written.
    fn issue_ca(&self, vault_id: &VaultId, now: Timestamp) -> Result<IssuedCa, CoreError>;
}

/// The local CA for the TLS layer of the same process: renew the server leaf, issue agent client
/// certificates (DEC-FIX7-10). Not reachable from the Agent API. `Debug` hides the key.
pub struct TlsCaMaterial {
    /// The CA certificate (DER).
    pub cert_der: Vec<u8>,
    /// The CA private key (DER). Zeroized on drop.
    pub key_der: SecretBytes,
    /// The host names given at vault creation (leaf SAN names).
    pub host_names: Vec<String>,
}

impl std::fmt::Debug for TlsCaMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCaMaterial")
            .field("cert_der_len", &self.cert_der.len())
            .field("key_der", &"[REDACTED]")
            .field("host_names", &self.host_names)
            .finish()
    }
}

/// A missing `tls_ca` row means there is no vault yet.
fn ca_row_error(error: StoreError) -> CoreError {
    match error {
        StoreError::NotFound => CoreError::NoVault,
        other => other.into(),
    }
}

impl VaultService {
    /// The CA certificate (DER). It is stored plain, so this works while locked (CA export).
    ///
    /// # Errors
    /// [`CoreError::NoVault`] before a vault exists, or a storage error.
    pub async fn tls_ca_cert(&self) -> Result<Vec<u8>, CoreError> {
        Ok(self
            .store()
            .tls_ca()
            .await
            .map_err(ca_row_error)?
            .ca_cert_der)
    }

    /// The CA certificate, its private key and the host names. Unlocked only: the key is sealed
    /// with `ca_key`. For the TLS layer of this process only; never send it to an agent or a UI.
    ///
    /// # Errors
    /// [`CoreError::Locked`] (or `NoVault`), [`CoreError::Corrupt`] when the key does not open,
    /// or a storage error.
    pub async fn tls_ca_material(&self) -> Result<TlsCaMaterial, CoreError> {
        let guard = self.unlocked().await?;
        let row = self.store().tls_ca().await.map_err(ca_row_error)?;
        let key_der = guard.blobs().open_ca_key(&row.ca_key_ct)?;
        let host_names = match self.store().setting(HOST_NAMES_SETTING).await {
            Ok(setting) => guard
                .blobs()
                .open_setting(HOST_NAMES_SETTING, &setting.value_ct)
                .ok()
                .and_then(|plain| serde_json::from_slice::<Vec<String>>(plain.expose_secret()).ok())
                .ok_or(CoreError::Corrupt)?,
            Err(StoreError::NotFound) => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(TlsCaMaterial {
            cert_der: row.ca_cert_der,
            key_der,
            host_names,
        })
    }

    /// The owner custom certificate, or `None` when the local CA is in use. Unlocked only: it is
    /// sealed. For the TLS layer of this process only; never send the key to an agent or a UI.
    ///
    /// # Errors
    /// [`CoreError::Locked`] (or `NoVault`), [`CoreError::Corrupt`] when it does not open, or a
    /// storage error.
    pub async fn tls_custom_material(&self) -> Result<Option<TlsCustomMaterial>, CoreError> {
        let guard = self.unlocked().await?;
        let row = match self.store().setting(TLS_CUSTOM_SETTING).await {
            Ok(row) => row,
            Err(StoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let plain = guard
            .blobs()
            .open_setting(TLS_CUSTOM_SETTING, &row.value_ct)
            .map_err(|_| CoreError::Corrupt)?;
        decode_custom(plain.expose_secret()).map(Some)
    }

    /// Stores the custom certificate (already validated by the TLS layer): the chain and the key
    /// are sealed in one setting, then `tls.custom_load` is written. Owner only; the role comes from
    /// the session.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, `Validation` for an empty or too long chain, or a
    /// storage error.
    pub async fn tls_custom_store(
        &self,
        ctx: &OperatorContext,
        chain_der: &[Vec<u8>],
        key_der: &SecretBytes,
    ) -> Result<(), CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        if chain_der.is_empty() || chain_der.len() > MAX_CUSTOM_CHAIN {
            return Err(CoreError::Corrupt);
        }
        let plain = SecretBytes::new(encode_custom(chain_der, key_der.expose_secret())?);
        let row = SettingRow {
            key: TLS_CUSTOM_SETTING.to_owned(),
            updated_at: self.inner.clock.now(),
            value_ct: guard
                .blobs()
                .seal_setting(TLS_CUSTOM_SETTING, plain.expose_secret())?,
        };
        let mut tx = self.inner.store.begin().await?;
        tx.put_setting(&row).await?;
        tx.commit().await?;
        let event = by_operator(EventType::TlsCustomLoad, ctx)
            .target("settings", "tls")
            .detail("chain_len", chain_der.len());
        self.audit(&guard, event).await;
        Ok(())
    }

    /// Removes the custom certificate and its key, then writes `tls.custom_revert`. Returns false
    /// (and writes nothing) when there was none. Owner only; the role comes from the session.
    ///
    /// # Errors
    /// `Locked`, `Forbidden`, `RoleNotAllowed`, or a storage error.
    pub async fn tls_custom_clear(&self, ctx: &OperatorContext) -> Result<bool, CoreError> {
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        let mut tx = self.inner.store.begin().await?;
        let existed = tx.delete_setting(TLS_CUSTOM_SETTING).await?;
        tx.commit().await?;
        if existed {
            let event = by_operator(EventType::TlsCustomRevert, ctx).target("settings", "tls");
            self.audit(&guard, event).await;
        }
        Ok(existed)
    }
}
