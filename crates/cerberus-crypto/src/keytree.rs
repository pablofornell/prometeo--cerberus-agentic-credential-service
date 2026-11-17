//! Key tree from the VMK, and per-version DEKs (ADR-0014).

use cerberus_types::VaultId;

use crate::envelope::{Aad, Purpose, open, seal};
use crate::error::CryptoError;
use crate::kdf::hkdf_sha256;
use crate::secret::{Key32, Vmk};

/// HKDF `info` labels of the key tree (ADR-0014).
pub mod labels {
    /// Wraps item-version DEKs.
    pub const ITEM_KEK: &[u8] = b"cerberus/v1/item-kek";
    /// Seals metadata blobs.
    pub const META_KEY: &[u8] = b"cerberus/v1/meta-key";
    /// Audit chain HMAC.
    pub const AUDIT_KEY: &[u8] = b"cerberus/v1/audit-key";
    /// Seals the local CA key.
    pub const CA_KEY: &[u8] = b"cerberus/v1/ca-key";
    /// Header MAC.
    pub const HEADER_KEY: &[u8] = b"cerberus/v1/header-key";
    /// Row MACs of plain security columns (ADR-0033).
    pub const ROW_MAC_KEY: &[u8] = b"cerberus/v1/row-mac-key";
}

/// Keys derived from the VMK with HKDF-SHA256(ikm = VMK, salt = vault ID).
#[derive(Debug)]
pub struct KeyTree {
    /// Wraps each item-version DEK.
    pub item_kek: Key32,
    /// Seals metadata (`item.meta`, `workspace.meta`, …).
    pub meta_key: Key32,
    /// Audit chain HMAC key.
    pub audit_key: Key32,
    /// Seals the CA private key.
    pub ca_key: Key32,
    /// Header MAC key.
    pub header_key: Key32,
    /// Row MAC key.
    pub row_mac_key: Key32,
}

impl KeyTree {
    /// Derives all six keys.
    ///
    /// # Errors
    /// [`CryptoError::Kdf`] when HKDF fails (it does not for 32-byte outputs).
    pub fn derive(vmk: &Vmk, vault_id: &VaultId) -> Result<Self, CryptoError> {
        let ikm = vmk.0.expose_secret();
        let salt = vault_id.as_bytes();
        Ok(Self {
            item_kek: hkdf_sha256(salt, ikm, labels::ITEM_KEK)?,
            meta_key: hkdf_sha256(salt, ikm, labels::META_KEY)?,
            audit_key: hkdf_sha256(salt, ikm, labels::AUDIT_KEY)?,
            ca_key: hkdf_sha256(salt, ikm, labels::CA_KEY)?,
            header_key: hkdf_sha256(salt, ikm, labels::HEADER_KEY)?,
            row_mac_key: hkdf_sha256(salt, ikm, labels::ROW_MAC_KEY)?,
        })
    }
}

/// A new random DEK for one item version.
///
/// # Errors
/// [`CryptoError::Rng`] when the OS random generator fails.
pub fn new_dek() -> Result<Key32, CryptoError> {
    Key32::random()
}

/// Seals `dek` with `item_kek`. `aad.purpose` must be [`Purpose::ItemDek`].
///
/// # Errors
/// [`CryptoError::Encoding`] for another purpose, or the errors of [`seal`].
pub fn wrap_dek(item_kek: &Key32, aad: &Aad<'_>, dek: &Key32) -> Result<Vec<u8>, CryptoError> {
    if aad.purpose != Purpose::ItemDek {
        return Err(CryptoError::Encoding);
    }
    seal(item_kek, aad, dek.expose_secret())
}

/// Opens a wrapped DEK into locked memory.
///
/// # Errors
/// [`CryptoError::Integrity`] for a wrong key, wrong AAD, changed bytes or a wrong length.
pub fn unwrap_dek(item_kek: &Key32, aad: &Aad<'_>, wrapped: &[u8]) -> Result<Key32, CryptoError> {
    if aad.purpose != Purpose::ItemDek {
        return Err(CryptoError::Encoding);
    }
    let plain = open(item_kek, aad, wrapped)?;
    key_from_plain(plain.expose_secret())
}

/// Copies 32 opened bytes into a locked key.
pub(crate) fn key_from_plain(bytes: &[u8]) -> Result<Key32, CryptoError> {
    if bytes.len() != 32 {
        return Err(CryptoError::Integrity);
    }
    Key32::try_fill(|out| {
        out.copy_from_slice(bytes);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_tree_for_a_fixed_vmk() {
        // Vectors computed with Python `hmac`/`hashlib` (RFC 5869 HKDF), VMK = 00..1f,
        // vault ID = 0xa5 * 16.
        let vmk = Vmk(Key32::from_bytes(core::array::from_fn(|i| i as u8)));
        let tree = KeyTree::derive(&vmk, &VaultId([0xA5; 16])).unwrap();
        let got = [
            hex(tree.item_kek.expose_secret()),
            hex(tree.meta_key.expose_secret()),
            hex(tree.audit_key.expose_secret()),
            hex(tree.ca_key.expose_secret()),
            hex(tree.header_key.expose_secret()),
            hex(tree.row_mac_key.expose_secret()),
        ];
        assert_eq!(got, TREE_VECTOR);
    }

    const TREE_VECTOR: [&str; 6] = [
        "dd0d0b5bee8e22514ad4ef231c87da98bb01e375090ebc677abdc888ef83a288",
        "0436f15b8a97a50b5f86d7b80816a235822b2fb0e3a2f7749a8ab5ff1545d3d8",
        "72d5b9c8a0b6984a9b25c8058aef968eacd41e3c02158f5e39454bebbd75775c",
        "4d3f5ee314ff4ec58bf0354ecbeb3e7fd8781e8bfe70e684483c61b6bf38dfef",
        "1f0f7beec1444c88cb4123619abbcdbc284ca322323e0e3d593195b20635445d",
        "f2b5c1ac90cce32251df88192653e61d1f1dd305ce472d64a11b21d886f04ccc",
    ];

    #[test]
    fn keys_differ_by_label_and_vault() {
        let vmk = Vmk::generate().unwrap();
        let a = KeyTree::derive(&vmk, &VaultId([1; 16])).unwrap();
        let b = KeyTree::derive(&vmk, &VaultId([2; 16])).unwrap();
        let keys = [
            &a.item_kek,
            &a.meta_key,
            &a.audit_key,
            &a.ca_key,
            &a.header_key,
            &a.row_mac_key,
        ];
        for (i, x) in keys.iter().enumerate() {
            for y in &keys[i + 1..] {
                assert_ne!(x.expose_secret(), y.expose_secret());
            }
        }
        assert_ne!(a.item_kek.expose_secret(), b.item_kek.expose_secret());
    }

    #[test]
    fn dek_wrap_roundtrip_and_binding() {
        let kek = Key32::random().unwrap();
        let vault = VaultId([1; 16]);
        let item = [7u8; 16];
        let aad = Aad {
            purpose: Purpose::ItemDek,
            vault_id: &vault,
            record_id: &item,
            version: 1,
        };
        let dek = new_dek().unwrap();
        let wrapped = wrap_dek(&kek, &aad, &dek).unwrap();
        let back = unwrap_dek(&kek, &aad, &wrapped).unwrap();
        assert_eq!(back.expose_secret(), dek.expose_secret());
        let v2 = Aad { version: 2, ..aad };
        assert_eq!(
            unwrap_dek(&kek, &v2, &wrapped).err(),
            Some(CryptoError::Integrity)
        );
        let other_item = Aad {
            record_id: &[8u8; 16],
            ..aad
        };
        assert_eq!(
            unwrap_dek(&kek, &other_item, &wrapped).err(),
            Some(CryptoError::Integrity)
        );
        let wrong_purpose = Aad {
            purpose: Purpose::ItemPayload,
            ..aad
        };
        assert_eq!(
            wrap_dek(&kek, &wrong_purpose, &dek).err(),
            Some(CryptoError::Encoding)
        );
        assert_eq!(
            unwrap_dek(&kek, &wrong_purpose, &wrapped).err(),
            Some(CryptoError::Encoding)
        );
    }

    #[test]
    fn unwrap_refuses_a_wrong_length_key() {
        let kek = Key32::random().unwrap();
        let vault = VaultId([1; 16]);
        let aad = Aad {
            purpose: Purpose::ItemDek,
            vault_id: &vault,
            record_id: &[7u8; 16],
            version: 1,
        };
        let short = seal(&kek, &aad, &[1u8; 31]).unwrap();
        assert_eq!(
            unwrap_dek(&kek, &aad, &short).err(),
            Some(CryptoError::Integrity)
        );
    }
}
