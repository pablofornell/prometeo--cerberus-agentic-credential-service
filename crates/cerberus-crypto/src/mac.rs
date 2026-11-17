//! Hashes, MACs, length-prefixed encoding and constant-time comparison.

use cerberus_types::{KeySlotId, VaultId};
use hkdf::HmacImpl;
use hmac::Hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::kdf::KdfParams;
use crate::secret::Key32;

/// Marker for a part of 65535 bytes or more in [`length_prefixed`].
const LONG_MARKER: u16 = u16::MAX;

/// Encodes parts as `u16 BE length || bytes` each (ADR-0014, ADR-0025).
///
/// A part of 65535 bytes or more gets `0xFFFF || u64 BE length || bytes`. The ADRs do not define
/// that case; this keeps the encoding unambiguous instead of cutting the length. No input of
/// version 1 is that long.
#[must_use]
pub fn length_prefixed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 2).sum());
    for part in parts {
        append_lp(&mut out, part);
    }
    out
}

fn append_lp(out: &mut Vec<u8>, part: &[u8]) {
    match u16::try_from(part.len()) {
        Ok(len) if len != LONG_MARKER => out.extend_from_slice(&len.to_be_bytes()),
        _ => {
            out.extend_from_slice(&LONG_MARKER.to_be_bytes());
            out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(part);
}

/// SHA-256 of the concatenation of `parts`.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// HMAC-SHA256 with `key` over the concatenation of `parts`.
#[must_use]
pub fn hmac_sha256(key: &Key32, parts: &[&[u8]]) -> [u8; 32] {
    hmac_raw(key.expose_secret(), parts)
}

fn hmac_raw(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as HmacImpl>::new_from_slice(key);
    for part in parts {
        HmacImpl::update(&mut mac, part);
    }
    HmacImpl::finalize(mac).into()
}

/// Checks an HMAC-SHA256 tag in constant time.
#[must_use]
pub fn verify_hmac_sha256(key: &Key32, parts: &[&[u8]], tag: &[u8; 32]) -> bool {
    ct_eq(&hmac_sha256(key, parts), tag)
}

/// Constant-time equality. Different lengths give false (the length is not secret).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Header MAC input (ADR-0013).
#[derive(Debug)]
pub struct HeaderMacInput<'a> {
    /// Always `CERBERUS-VAULT`.
    pub magic: &'a str,
    /// Crypto format version.
    pub format_version: u32,
    /// Vault ID.
    pub vault_id: &'a VaultId,
    /// Creation time, Unix ms.
    pub created_at_ms: i64,
    /// All key slots. [`header_mac`] sorts them by ID.
    pub slots: Vec<SlotMacInput<'a>>,
}

/// One key slot in the header MAC.
#[derive(Debug)]
pub struct SlotMacInput<'a> {
    /// Slot ID.
    pub id: &'a KeySlotId,
    /// `passphrase` or `recovery`.
    pub kind: &'a str,
    /// `owner`, `operator` or `viewer`.
    pub role: &'a str,
    /// `argon2id` or `hkdf-sha256`.
    pub kdf_alg: &'a str,
    /// Argon2id costs, `None` for the recovery slot.
    pub kdf: Option<KdfParams>,
    /// Slot salt.
    pub salt: &'a [u8; 32],
    /// The wrapped VMK envelope.
    pub wrapped_vmk: &'a [u8],
}

/// HMAC-SHA256 with `header_key` over the canonical header (ADR-0013).
///
/// Every field is length-prefixed. Numbers are big-endian. Slots are in ID order. For each slot
/// the KDF numbers are one field `0x00` when absent, or `0x01` followed by three fields
/// `m_cost_kib`, `t_cost`, `p_cost` (u32 BE each).
#[must_use]
pub fn header_mac(header_key: &Key32, input: &HeaderMacInput<'_>) -> [u8; 32] {
    let mut data = Vec::new();
    append_lp(&mut data, input.magic.as_bytes());
    append_lp(&mut data, &input.format_version.to_be_bytes());
    append_lp(&mut data, input.vault_id.as_bytes());
    append_lp(&mut data, &input.created_at_ms.to_be_bytes());
    let mut slots: Vec<&SlotMacInput<'_>> = input.slots.iter().collect();
    slots.sort_by_key(|slot| *slot.id);
    for slot in slots {
        append_lp(&mut data, slot.id.as_bytes());
        append_lp(&mut data, slot.kind.as_bytes());
        append_lp(&mut data, slot.role.as_bytes());
        append_lp(&mut data, slot.kdf_alg.as_bytes());
        match slot.kdf {
            None => append_lp(&mut data, &[0x00]),
            Some(params) => {
                append_lp(&mut data, &[0x01]);
                append_lp(&mut data, &params.m_cost_kib().to_be_bytes());
                append_lp(&mut data, &params.t_cost().to_be_bytes());
                append_lp(&mut data, &params.p_cost().to_be_bytes());
            }
        }
        append_lp(&mut data, slot.salt);
        append_lp(&mut data, slot.wrapped_vmk);
    }
    hmac_sha256(header_key, &[&data])
}

/// One column value for a row MAC (ADR-0033). `Null` = SQL NULL.
#[derive(Clone, Copy, Debug)]
pub enum MacField<'a> {
    /// SQL NULL.
    Null,
    /// BLOB.
    Bytes(&'a [u8]),
    /// INTEGER (encoded as i64 BE).
    Int(i64),
    /// TEXT (UTF-8 bytes).
    Text(&'a str),
}

/// Label at the start of every row MAC input (ADR-0033).
pub const ROW_MAC_LABEL: &[u8] = b"cerberus/v1/row";

fn row_mac_input(vault_id: &VaultId, table: &str, fields: &[MacField<'_>]) -> Vec<u8> {
    let mut data = Vec::new();
    append_lp(&mut data, ROW_MAC_LABEL);
    append_lp(&mut data, table.as_bytes());
    append_lp(&mut data, vault_id.as_bytes());
    for field in fields {
        // Marker 0x00 = NULL (then an empty field), 0x01 = a value.
        match field {
            MacField::Null => {
                data.push(0x00);
                append_lp(&mut data, &[]);
            }
            MacField::Bytes(bytes) => {
                data.push(0x01);
                append_lp(&mut data, bytes);
            }
            MacField::Int(value) => {
                data.push(0x01);
                append_lp(&mut data, &value.to_be_bytes());
            }
            MacField::Text(text) => {
                data.push(0x01);
                append_lp(&mut data, text.as_bytes());
            }
        }
    }
    data
}

/// Row MAC: HMAC-SHA256(row_mac_key, lp(label) || lp(table) || lp(vault_id) || fields) (ADR-0033).
///
/// Each field is a marker byte (`0x00` NULL, `0x01` value) and then the length-prefixed value
/// (empty for NULL). The caller passes the columns in the fixed order of the table.
#[must_use]
pub fn row_mac(
    row_mac_key: &Key32,
    vault_id: &VaultId,
    table: &str,
    fields: &[MacField<'_>],
) -> [u8; 32] {
    hmac_sha256(row_mac_key, &[&row_mac_input(vault_id, table, fields)])
}

/// Checks a row MAC in constant time.
#[must_use]
pub fn verify_row_mac(
    row_mac_key: &Key32,
    vault_id: &VaultId,
    table: &str,
    fields: &[MacField<'_>],
    tag: &[u8; 32],
) -> bool {
    ct_eq(&row_mac(row_mac_key, vault_id, table, fields), tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn length_prefix_layout() {
        assert_eq!(
            length_prefixed(&[b"ab", b"", b"c"]),
            vec![0, 2, b'a', b'b', 0, 0, 0, 1, b'c']
        );
        let long = vec![7u8; 70_000];
        let out = length_prefixed(&[&long]);
        assert_eq!(&out[..10], &[0xFF, 0xFF, 0, 0, 0, 0, 0, 0x01, 0x11, 0x70]);
        assert_eq!(out.len(), 10 + 70_000);
        // Exactly 65535 bytes also uses the long form, so 0xFFFF is never a plain length.
        let edge = vec![1u8; 65_535];
        assert_eq!(&length_prefixed(&[&edge])[..2], &[0xFF, 0xFF]);
        assert_eq!(&length_prefixed(&[&edge[..65_534]])[..2], &[0xFF, 0xFE]);
    }

    #[test]
    fn length_prefix_is_unambiguous() {
        assert_ne!(
            length_prefixed(&[b"ab", b"c"]),
            length_prefixed(&[b"a", b"bc"])
        );
    }

    #[test]
    fn sha256_known_answer() {
        // FIPS 180-2 example "abc", split in parts.
        assert_eq!(
            hex(&sha256(&[b"a", b"bc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_rfc4231_case_2() {
        assert_eq!(
            hex(&hmac_raw(b"Jefe", &[b"what do ya want ", b"for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_with_a_32_byte_key() {
        // Vector computed with Python `hmac` (key 0x0b * 32, data "Hi There").
        let key = Key32::from_bytes([0x0b; 32]);
        assert_eq!(
            hex(&hmac_sha256(&key, &[b"Hi ", b"There"])),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
    }

    #[test]
    fn verify_hmac_detects_changes() {
        let key = Key32::random().unwrap();
        let tag = hmac_sha256(&key, &[b"data"]);
        assert!(verify_hmac_sha256(&key, &[b"data"], &tag));
        assert!(!verify_hmac_sha256(&key, &[b"datA"], &tag));
        let mut bad = tag;
        bad[31] ^= 1;
        assert!(!verify_hmac_sha256(&key, &[b"data"], &bad));
        let other = Key32::random().unwrap();
        assert!(!verify_hmac_sha256(&other, &[b"data"], &tag));
    }

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    /// Owned copy of one slot, so a test can change a single field.
    #[derive(Clone)]
    struct SlotFixture {
        id: KeySlotId,
        kind: &'static str,
        role: &'static str,
        kdf_alg: &'static str,
        kdf: Option<KdfParams>,
        salt: [u8; 32],
        wrapped_vmk: Vec<u8>,
    }

    /// Owned copy of the whole header MAC input.
    #[derive(Clone)]
    struct HeaderFixture {
        magic: &'static str,
        format_version: u32,
        vault_id: VaultId,
        created_at_ms: i64,
        slots: Vec<SlotFixture>,
    }

    impl HeaderFixture {
        fn base() -> Self {
            let slot = |id: u8, kdf: Option<KdfParams>| SlotFixture {
                id: KeySlotId::from_bytes([id; 16]),
                kind: if kdf.is_some() {
                    "passphrase"
                } else {
                    "recovery"
                },
                role: "owner",
                kdf_alg: if kdf.is_some() {
                    "argon2id"
                } else {
                    "hkdf-sha256"
                },
                kdf,
                salt: [id + 8; 32],
                wrapped_vmk: vec![id; 5],
            };
            Self {
                magic: "CERBERUS-VAULT",
                format_version: 1,
                vault_id: VaultId([3; 16]),
                created_at_ms: 1,
                slots: vec![
                    slot(1, Some(KdfParams::new(65_536, 3, 4).unwrap())),
                    slot(2, None),
                ],
            }
        }

        fn mac(&self, key: &Key32) -> [u8; 32] {
            let slots = self
                .slots
                .iter()
                .map(|s| SlotMacInput {
                    id: &s.id,
                    kind: s.kind,
                    role: s.role,
                    kdf_alg: s.kdf_alg,
                    kdf: s.kdf,
                    salt: &s.salt,
                    wrapped_vmk: &s.wrapped_vmk,
                })
                .collect();
            header_mac(
                key,
                &HeaderMacInput {
                    magic: self.magic,
                    format_version: self.format_version,
                    vault_id: &self.vault_id,
                    created_at_ms: self.created_at_ms,
                    slots,
                },
            )
        }
    }

    #[test]
    fn header_mac_sorts_slots() {
        let key = Key32::random().unwrap();
        let base = HeaderFixture::base();
        let mut reversed = base.clone();
        reversed.slots.reverse();
        assert_eq!(base.mac(&key), reversed.mac(&key));
        // A different key gives a different tag.
        assert_ne!(base.mac(&key), base.mac(&Key32::random().unwrap()));
    }

    #[test]
    fn header_mac_covers_every_field() {
        let key = Key32::random().unwrap();
        let base = HeaderFixture::base();
        let tag = base.mac(&key);
        assert_eq!(tag, base.clone().mac(&key), "same input, same tag");

        // Each case changes exactly one field of the header; the tag must change every time.
        let mut cases: Vec<(String, HeaderFixture)> = Vec::new();
        let mut add = |name: &str, change: &dyn Fn(&mut HeaderFixture)| {
            let mut changed = base.clone();
            change(&mut changed);
            cases.push((name.to_owned(), changed));
        };
        add("magic", &|h| h.magic = "CERBERUS-VAULT2");
        add("format_version", &|h| h.format_version = 2);
        add("vault_id", &|h| h.vault_id = VaultId([4; 16]));
        add("created_at_ms", &|h| h.created_at_ms = 2);
        add("slot added", &|h| {
            let mut extra = h.slots[1].clone();
            extra.id = KeySlotId::from_bytes([7; 16]);
            h.slots.push(extra);
        });
        add("slot removed", &|h| {
            h.slots.pop();
        });
        for i in 0..2 {
            add(&format!("slot {i} id"), &|h| {
                h.slots[i].id = KeySlotId::from_bytes([9; 16]);
            });
            add(&format!("slot {i} kind"), &|h| h.slots[i].kind = "other");
            add(&format!("slot {i} role"), &|h| h.slots[i].role = "viewer");
            add(&format!("slot {i} kdf_alg"), &|h| {
                h.slots[i].kdf_alg = "other";
            });
            add(&format!("slot {i} salt"), &|h| h.slots[i].salt[31] ^= 1);
            add(&format!("slot {i} wrapped_vmk"), &|h| {
                h.slots[i].wrapped_vmk[0] ^= 1;
            });
            add(&format!("slot {i} wrapped_vmk longer"), &|h| {
                h.slots[i].wrapped_vmk.push(0);
            });
        }
        // KDF numbers: only slot 0 has them; slot 1 can gain them.
        let params = KdfParams::new(65_536, 3, 4).unwrap();
        assert_eq!(base.slots[0].kdf, Some(params));
        add("slot 0 kdf m_cost", &|h| {
            h.slots[0].kdf = Some(KdfParams::new(65_537, 3, 4).unwrap());
        });
        add("slot 0 kdf t_cost", &|h| {
            h.slots[0].kdf = Some(KdfParams::new(65_536, 4, 4).unwrap());
        });
        add("slot 0 kdf p_cost", &|h| {
            h.slots[0].kdf = Some(KdfParams::new(65_536, 3, 5).unwrap());
        });
        add("slot 0 kdf removed", &|h| h.slots[0].kdf = None);
        add("slot 1 kdf added", &|h| h.slots[1].kdf = Some(params));

        for (name, changed) in &cases {
            assert_ne!(tag, changed.mac(&key), "header MAC ignores: {name}");
        }
    }

    #[test]
    fn row_mac_null_differs_from_empty_and_fields_are_bound() {
        let key = Key32::random().unwrap();
        let vault = VaultId([4; 16]);
        let null = row_mac(&key, &vault, "leases", &[MacField::Null]);
        let empty = row_mac(&key, &vault, "leases", &[MacField::Text("")]);
        assert_ne!(null, empty);
        let tag = row_mac(
            &key,
            &vault,
            "agents",
            &[MacField::Text("active"), MacField::Int(5)],
        );
        assert!(verify_row_mac(
            &key,
            &vault,
            "agents",
            &[MacField::Text("active"), MacField::Int(5)],
            &tag
        ));
        assert!(!verify_row_mac(
            &key,
            &vault,
            "agents",
            &[MacField::Text("active"), MacField::Int(6)],
            &tag
        ));
        assert!(!verify_row_mac(
            &key,
            &vault,
            "agent_keys",
            &[MacField::Text("active"), MacField::Int(5)],
            &tag
        ));
        assert!(!verify_row_mac(
            &key,
            &VaultId([5; 16]),
            "agents",
            &[MacField::Text("active"), MacField::Int(5)],
            &tag
        ));
    }

    #[test]
    fn row_mac_input_layout() {
        let vault = VaultId([0xAA; 16]);
        let data = row_mac_input(
            &vault,
            "t",
            &[MacField::Null, MacField::Int(1), MacField::Bytes(&[7])],
        );
        let mut expected = length_prefixed(&[ROW_MAC_LABEL, b"t", &[0xAA; 16]]);
        expected.extend_from_slice(&[0x00, 0, 0]);
        expected.extend_from_slice(&[0x01, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&[0x01, 0, 1, 7]);
        assert_eq!(data, expected);
    }
}
