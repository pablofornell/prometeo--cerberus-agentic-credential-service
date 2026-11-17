//! Golden vectors of the Cerberus formats (ADR-0013, ADR-0014, ADR-0033), version 1.
//!
//! `vectors/format_v1.txt` was made once with the code of this task (T25). Every value in it is a
//! fake test value: the phrase, the recovery key and the payload protect nothing. The test decodes
//! each stored blob and checks each stored MAC. A change in the key slot, header MAC, envelope or
//! row MAC format breaks it. Do not regenerate the file to make a test pass: a format change needs
//! a new format version and a migration (ADR-0013).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::HashMap;

use cerberus_crypto::{
    Aad, HeaderMacInput, KdfParams, KeySlot, KeySlotSet, KeyTree, MacField, Purpose, RecoveryKey,
    SecretString, SlotKdf, SlotMacInput, SlotMaterial, Vmk, header_mac, open, open_passphrase_slot,
    open_recovery_slot, row_mac, unwrap_dek,
};
use cerberus_types::{ItemId, KeySlotId, OperatorRole, VaultId};

const FILE: &str = include_str!("vectors/format_v1.txt");

struct Vectors(HashMap<&'static str, &'static str>);

impl Vectors {
    fn load() -> Self {
        Self(
            FILE.lines()
                .filter_map(|line| line.split_once(" = "))
                .collect(),
        )
    }

    fn text(&self, name: &str) -> &'static str {
        self.0.get(name).copied().expect("vector exists")
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        let hex = self.text(name);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        self.bytes(name).try_into().expect("length")
    }
}

struct Golden {
    v: Vectors,
    vault: VaultId,
    passphrase_slot: KeySlotId,
    recovery_slot: KeySlotId,
    passphrase_material: SlotMaterial,
    recovery_material: SlotMaterial,
}

fn golden() -> Golden {
    let v = Vectors::load();
    let params = KdfParams::new(19_456, 1, 1).expect("params");
    let passphrase_material = SlotMaterial {
        kdf: SlotKdf::Argon2id(params),
        salt: v.array("passphrase_slot_salt"),
        wrapped_vmk: v.bytes("passphrase_slot_wrapped_vmk"),
    };
    let recovery_material = SlotMaterial {
        kdf: SlotKdf::HkdfSha256,
        salt: v.array("recovery_slot_salt"),
        wrapped_vmk: v.bytes("recovery_slot_wrapped_vmk"),
    };
    Golden {
        vault: VaultId(v.array("vault_id")),
        passphrase_slot: KeySlotId::from_bytes(v.array("passphrase_slot_id")),
        recovery_slot: KeySlotId::from_bytes(v.array("recovery_slot_id")),
        passphrase_material,
        recovery_material,
        v,
    }
}

fn open_vmk_with_passphrase(g: &Golden) -> Vmk {
    let phrase = SecretString::new(g.v.text("passphrase").to_owned());
    open_passphrase_slot(
        &g.vault,
        &g.passphrase_slot,
        &phrase,
        &g.passphrase_material,
    )
    .expect("golden passphrase slot opens")
}

#[test]
fn key_slots_open_to_the_same_vmk() {
    let g = golden();
    let from_phrase = open_vmk_with_passphrase(&g);
    let recovery = RecoveryKey::parse(g.v.text("recovery_key")).expect("golden recovery key");
    let from_recovery =
        open_recovery_slot(&g.vault, &g.recovery_slot, &recovery, &g.recovery_material)
            .expect("golden recovery slot opens");
    assert!(from_phrase.same_key(&from_recovery));
    // The recovery key prints back in the same canonical text.
    assert_eq!(
        recovery.to_display().expose_secret(),
        g.v.text("recovery_key")
    );
    // The slots satisfy the slot rules of ADR-0009.
    let slots = vec![
        KeySlot {
            id: g.passphrase_slot,
            role: OperatorRole::Owner,
            material: g.passphrase_material.clone(),
        },
        KeySlot {
            id: g.recovery_slot,
            role: OperatorRole::Owner,
            material: g.recovery_material.clone(),
        },
    ];
    assert!(KeySlotSet::from_slots(g.vault, slots).is_ok());
}

#[test]
fn key_tree_keys_match() {
    let g = golden();
    let tree = KeyTree::derive(&open_vmk_with_passphrase(&g), &g.vault).expect("tree");
    assert_eq!(
        tree.header_key.expose_secret(),
        &g.v.array::<32>("header_key")
    );
    assert_eq!(tree.item_kek.expose_secret(), &g.v.array::<32>("item_kek"));
    assert_eq!(
        tree.row_mac_key.expose_secret(),
        &g.v.array::<32>("row_mac_key")
    );
    assert_eq!(
        tree.audit_key.expose_secret(),
        &g.v.array::<32>("audit_key")
    );
}

#[test]
fn header_mac_matches() {
    let g = golden();
    let tree = KeyTree::derive(&open_vmk_with_passphrase(&g), &g.vault).expect("tree");
    let SlotKdf::Argon2id(params) = g.passphrase_material.kdf else {
        panic!("passphrase slot uses Argon2id");
    };
    let input = HeaderMacInput {
        magic: "CERBERUS-VAULT",
        format_version: 1,
        vault_id: &g.vault,
        created_at_ms: g.v.text("header_created_at_ms").parse().expect("number"),
        slots: vec![
            SlotMacInput {
                id: &g.passphrase_slot,
                kind: "passphrase",
                role: "owner",
                kdf_alg: "argon2id",
                kdf: Some(params),
                salt: &g.passphrase_material.salt,
                wrapped_vmk: &g.passphrase_material.wrapped_vmk,
            },
            SlotMacInput {
                id: &g.recovery_slot,
                kind: "recovery",
                role: "owner",
                kdf_alg: "hkdf-sha256",
                kdf: None,
                salt: &g.recovery_material.salt,
                wrapped_vmk: &g.recovery_material.wrapped_vmk,
            },
        ],
    };
    assert_eq!(
        header_mac(&tree.header_key, &input),
        g.v.array::<32>("header_mac")
    );
}

#[test]
fn blob_envelope_decodes() {
    let g = golden();
    let tree = KeyTree::derive(&open_vmk_with_passphrase(&g), &g.vault).expect("tree");
    let item = ItemId::from_bytes(g.v.array("item_id"));
    let version: u32 = g.v.text("item_version").parse().expect("number");
    let dek_aad = Aad {
        purpose: Purpose::ItemDek,
        vault_id: &g.vault,
        record_id: item.as_bytes(),
        version,
    };
    let dek = unwrap_dek(&tree.item_kek, &dek_aad, &g.v.bytes("item_dek_wrapped"))
        .expect("golden DEK unwraps");
    let payload_aad = Aad {
        purpose: Purpose::ItemPayload,
        ..dek_aad
    };
    let plain = open(&dek, &payload_aad, &g.v.bytes("item_payload_envelope"))
        .expect("golden envelope opens");
    assert_eq!(
        plain.expose_secret(),
        g.v.text("item_payload_plaintext").as_bytes()
    );
    // The AAD binds the blob to its place: another purpose or version fails.
    let other = Aad {
        version: version + 1,
        ..payload_aad
    };
    assert!(open(&dek, &other, &g.v.bytes("item_payload_envelope")).is_err());
}

#[test]
fn row_mac_matches() {
    let g = golden();
    let tree = KeyTree::derive(&open_vmk_with_passphrase(&g), &g.vault).expect("tree");
    let fields = [
        MacField::Text("a"),
        MacField::Int(7),
        MacField::Null,
        MacField::Bytes(&[1, 2, 3]),
    ];
    let mac = row_mac(
        &tree.row_mac_key,
        &g.vault,
        g.v.text("row_mac_table"),
        &fields,
    );
    assert_eq!(mac, g.v.array::<32>("row_mac"));
}
