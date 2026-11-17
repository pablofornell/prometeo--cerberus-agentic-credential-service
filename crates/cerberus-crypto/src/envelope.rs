//! AEAD envelope and AAD (ADR-0014).
//!
//! Envelope: `0x01 || nonce (24 bytes) || ciphertext || tag (16 bytes)`, XChaCha20-Poly1305.
//! Plaintext inside: `u32 BE length || data || zero padding` to a multiple of 64 bytes.

use cerberus_types::VaultId;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::mac::length_prefixed;
use crate::random;
use crate::secret::{Key32, SecretBytes};

/// Envelope format version byte.
pub const ENVELOPE_VERSION: u8 = 0x01;
/// First AAD field of format version 1.
pub const AAD_CONTEXT: &[u8] = b"cerberus/v1";
/// Nonce length of XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// The padded plaintext is a multiple of this.
pub const PAD_BLOCK: usize = 64;
const HEADER_LEN: usize = 1 + NONCE_LEN;
const LEN_PREFIX: usize = 4;

/// What a sealed blob is for. The label is the second AAD field (ADR-0014 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Purpose {
    SlotVmk,
    ItemDek,
    ItemPayload,
    ItemMeta,
    ItemMetaSnapshot,
    WorkspaceMeta,
    AgentMeta,
    GrantBody,
    RequestReason,
    AuditBody,
    SettingsValue,
    CaKey,
}

impl Purpose {
    /// Every purpose.
    pub const ALL: [Self; 12] = [
        Self::SlotVmk,
        Self::ItemDek,
        Self::ItemPayload,
        Self::ItemMeta,
        Self::ItemMetaSnapshot,
        Self::WorkspaceMeta,
        Self::AgentMeta,
        Self::GrantBody,
        Self::RequestReason,
        Self::AuditBody,
        Self::SettingsValue,
        Self::CaKey,
    ];

    /// The ASCII label of ADR-0014.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SlotVmk => "slot.vmk",
            Self::ItemDek => "item.dek",
            Self::ItemPayload => "item.payload",
            Self::ItemMeta => "item.meta",
            Self::ItemMetaSnapshot => "item.meta_snapshot",
            Self::WorkspaceMeta => "workspace.meta",
            Self::AgentMeta => "agent.meta",
            Self::GrantBody => "grant.body",
            Self::RequestReason => "request.reason",
            Self::AuditBody => "audit.body",
            Self::SettingsValue => "settings.value",
            Self::CaKey => "ca.key",
        }
    }
}

/// Additional data that binds a blob to its place (ADR-0014).
#[derive(Clone, Copy, Debug)]
pub struct Aad<'a> {
    /// Purpose (column).
    pub purpose: Purpose,
    /// Vault.
    pub vault_id: &'a VaultId,
    /// Record ID bytes: a UUID (16 bytes), an audit sequence (u64 BE) or a settings key name.
    pub record_id: &'a [u8],
    /// Record version, 0 when the record has no versions.
    pub version: u32,
}

impl Aad<'_> {
    /// `lp("cerberus/v1") || lp(label) || lp(vault_id) || lp(record_id) || lp(version u32 BE)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        length_prefixed(&[
            AAD_CONTEXT,
            self.purpose.label().as_bytes(),
            self.vault_id.as_bytes(),
            self.record_id,
            &self.version.to_be_bytes(),
        ])
    }
}

/// Length of the padded plaintext for `data_len` bytes of data.
fn padded_len(data_len: usize) -> Result<usize, CryptoError> {
    let raw = data_len
        .checked_add(LEN_PREFIX)
        .ok_or(CryptoError::Encoding)?;
    raw.checked_next_multiple_of(PAD_BLOCK)
        .ok_or(CryptoError::Encoding)
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    let key: &Key = key.expose_secret().into();
    XChaCha20Poly1305::new(key)
}

/// Seals `plaintext` with a new random nonce.
///
/// # Errors
/// [`CryptoError::Rng`] when the OS random generator fails, [`CryptoError::Encoding`] when the
/// plaintext is longer than 4 GiB.
pub fn seal(key: &Key32, aad: &Aad<'_>, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    random::fill(&mut nonce)?;
    seal_with_nonce(key, aad, plaintext, &nonce)
}

/// Seal with a given nonce. Only [`seal`] (random nonce) and fixed test vectors use it.
pub(crate) fn seal_with_nonce(
    key: &Key32,
    aad: &Aad<'_>,
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let data_len = u32::try_from(plaintext.len()).map_err(|_| CryptoError::Encoding)?;
    let body_len = padded_len(plaintext.len())?;
    let total = HEADER_LEN + body_len + TAG_LEN;
    // Full capacity up front: the buffer never moves, so no plaintext copy is left behind.
    // It is zeroized if anything fails before encryption ends.
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.push(ENVELOPE_VERSION);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&data_len.to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(HEADER_LEN + body_len, 0);
    let tag = cipher(key)
        .encrypt_inout_detached(
            nonce.into(),
            &aad.to_bytes(),
            (&mut out[HEADER_LEN..]).into(),
        )
        .map_err(|_| CryptoError::Encoding)?;
    out.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *out))
}

/// Opens an envelope and removes the padding.
///
/// # Errors
/// [`CryptoError::EnvelopeVersion`] for an unknown version byte, [`CryptoError::Integrity`] for
/// a wrong key, wrong AAD, changed bytes, a wrong length or bad padding.
pub fn open(key: &Key32, aad: &Aad<'_>, envelope: &[u8]) -> Result<SecretBytes, CryptoError> {
    let (&version, rest) = envelope.split_first().ok_or(CryptoError::Integrity)?;
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::EnvelopeVersion);
    }
    if rest.len() < NONCE_LEN + PAD_BLOCK + TAG_LEN {
        return Err(CryptoError::Integrity);
    }
    let (nonce, rest) = rest.split_at(NONCE_LEN);
    let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
    if body.len() % PAD_BLOCK != 0 {
        return Err(CryptoError::Integrity);
    }
    let nonce = <&XNonce>::try_from(nonce).map_err(|_| CryptoError::Integrity)?;
    let tag = <&Tag>::try_from(tag).map_err(|_| CryptoError::Integrity)?;
    let mut buf = Zeroizing::new(body.to_vec());
    cipher(key)
        .decrypt_inout_detached(nonce, &aad.to_bytes(), (&mut buf[..]).into(), tag)
        .map_err(|_| CryptoError::Integrity)?;
    unpad(buf)
}

/// Checks the length prefix and the zero padding, then keeps only the data in place.
fn unpad(mut buf: Zeroizing<Vec<u8>>) -> Result<SecretBytes, CryptoError> {
    let (prefix, rest) = buf.split_at(LEN_PREFIX);
    let mut len_bytes = [0u8; LEN_PREFIX];
    len_bytes.copy_from_slice(prefix);
    let data_len =
        usize::try_from(u32::from_be_bytes(len_bytes)).map_err(|_| CryptoError::Integrity)?;
    if data_len > rest.len() || padded_len(data_len)? != buf.len() {
        return Err(CryptoError::Integrity);
    }
    if rest[data_len..].iter().any(|b| *b != 0) {
        return Err(CryptoError::Integrity);
    }
    // Shift the data to the front in the same buffer, then cut. Zeroize on drop clears the
    // whole capacity, so the cut tail is erased later too.
    buf.copy_within(LEN_PREFIX..LEN_PREFIX + data_len, 0);
    buf.truncate(data_len);
    Ok(SecretBytes::new(std::mem::take(&mut *buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn labels_match_adr_0014() {
        let labels: Vec<&str> = Purpose::ALL.iter().map(|p| p.label()).collect();
        assert_eq!(
            labels,
            [
                "slot.vmk",
                "item.dek",
                "item.payload",
                "item.meta",
                "item.meta_snapshot",
                "workspace.meta",
                "agent.meta",
                "grant.body",
                "request.reason",
                "audit.body",
                "settings.value",
                "ca.key",
            ]
        );
    }

    #[test]
    fn aad_layout() {
        let vault = VaultId([0x11; 16]);
        let aad = Aad {
            purpose: Purpose::ItemPayload,
            vault_id: &vault,
            record_id: &[0x22; 16],
            version: 7,
        };
        let mut expected = vec![0, 11];
        expected.extend_from_slice(b"cerberus/v1");
        expected.extend_from_slice(&[0, 12]);
        expected.extend_from_slice(b"item.payload");
        expected.extend_from_slice(&[0, 16]);
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&[0, 16]);
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&[0, 4, 0, 0, 0, 7]);
        assert_eq!(aad.to_bytes(), expected);
    }

    #[test]
    fn padding_hides_exact_length() {
        let key = Key32::random().unwrap();
        let vault = VaultId([1; 16]);
        let aad = Aad {
            purpose: Purpose::ItemPayload,
            vault_id: &vault,
            record_id: b"r",
            version: 0,
        };
        let lens: Vec<usize> = [0usize, 1, 59, 60, 61, 124, 125]
            .iter()
            .map(|n| seal(&key, &aad, &vec![0xAB; *n]).unwrap().len())
            .collect();
        // 1 + 24 + padded + 16; padded = (n + 4) rounded up to 64.
        assert_eq!(lens, [105, 105, 105, 105, 169, 169, 233]);
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = Key32::random().unwrap();
        let vault = VaultId([1; 16]);
        let aad = Aad {
            purpose: Purpose::SettingsValue,
            vault_id: &vault,
            record_id: b"k",
            version: 0,
        };
        let env = seal(&key, &aad, b"").unwrap();
        assert!(open(&key, &aad, &env).unwrap().is_empty());
    }

    #[test]
    fn unknown_version_and_short_input() {
        let key = Key32::random().unwrap();
        let vault = VaultId([1; 16]);
        let aad = Aad {
            purpose: Purpose::ItemMeta,
            vault_id: &vault,
            record_id: b"r",
            version: 1,
        };
        let mut env = seal(&key, &aad, b"fake").unwrap();
        env[0] = 0x02;
        assert_eq!(
            open(&key, &aad, &env).err(),
            Some(CryptoError::EnvelopeVersion)
        );
        assert_eq!(open(&key, &aad, &[]).err(), Some(CryptoError::Integrity));
        assert_eq!(
            open(&key, &aad, &[ENVELOPE_VERSION; 40]).err(),
            Some(CryptoError::Integrity)
        );
        let env = seal(&key, &aad, b"fake").unwrap();
        assert_eq!(
            open(&key, &aad, &env[..env.len() - 1]).err(),
            Some(CryptoError::Integrity)
        );
    }

    /// Seals a hand-made padded body with the raw cipher (for padding checks after decryption).
    fn raw_envelope(key: &Key32, aad: &Aad<'_>, body: &[u8]) -> Vec<u8> {
        let nonce = [9u8; NONCE_LEN];
        let mut buf = body.to_vec();
        let tag = cipher(key)
            .encrypt_inout_detached((&nonce).into(), &aad.to_bytes(), (&mut buf[..]).into())
            .unwrap();
        let mut out = vec![ENVELOPE_VERSION];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        out
    }

    #[test]
    fn bad_padding_inside_a_valid_ciphertext_is_refused() {
        let key = Key32::random().unwrap();
        let vault = VaultId([1; 16]);
        let aad = Aad {
            purpose: Purpose::ItemMeta,
            vault_id: &vault,
            record_id: b"r",
            version: 1,
        };
        let mut good = vec![0u8; 64];
        good[3] = 2;
        good[4..6].copy_from_slice(b"ok");
        assert_eq!(
            open(&key, &aad, &raw_envelope(&key, &aad, &good))
                .unwrap()
                .expose_secret(),
            b"ok"
        );
        let mut nonzero_pad = good.clone();
        nonzero_pad[63] = 1;
        let mut too_long = good.clone();
        too_long[3] = 61;
        let mut extra_block = good.clone();
        extra_block.extend_from_slice(&[0u8; 64]);
        for body in [nonzero_pad, too_long, extra_block] {
            assert_eq!(
                open(&key, &aad, &raw_envelope(&key, &aad, &body)).err(),
                Some(CryptoError::Integrity)
            );
        }
    }

    #[test]
    fn fixed_nonce_vector() {
        // Regression vector for T25. Recomputed independently in Python (cryptography's
        // ChaCha20Poly1305 + HChaCha20 from RFC draft-irtf-cfrg-xchacha-03).
        let key = Key32::from_bytes(core::array::from_fn(|i| i as u8));
        let vault = VaultId([0xA5; 16]);
        let aad = Aad {
            purpose: Purpose::ItemPayload,
            vault_id: &vault,
            record_id: &[0x5A; 16],
            version: 1,
        };
        let env = seal_with_nonce(&key, &aad, b"fake-secret", &[0x24; NONCE_LEN]).unwrap();
        assert_eq!(hex(&env), FIXED_VECTOR);
        assert_eq!(
            open(&key, &aad, &env).unwrap().expose_secret(),
            b"fake-secret"
        );
    }

    const FIXED_VECTOR: &str = concat!(
        "01242424242424242424242424242424242424242424242424abc55875f7cc06015931f7947111f2aaebf547fd8e",
        "7aa2c892ed07f231ba975e46d940cd6c26a42696042ab4ecd44e08fe40cca53d0bc4fe0fe5cba5e886883346289565",
        "bba9a05d738a0d4bf0d0b3f2"
    );
}
