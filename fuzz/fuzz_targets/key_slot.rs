//! Key slot and vault header parse: KDF params from stored numbers, slot sets, header MAC input,
//! recovery slot open with arbitrary slot material (ADR-0009, ADR-0013).
#![no_main]

use arbitrary::Arbitrary;
use cerberus_crypto::{
    HeaderMacInput, Key32, KdfParams, KeySlot, KeySlotSet, RecoveryKey, SecretString, SlotKdf,
    SlotMaterial, header_mac, open_passphrase_slot, open_recovery_slot,
};
use cerberus_types::{KeySlotId, OperatorRole, VaultId};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct SlotInput {
    id: [u8; 16],
    role: u8,
    recovery: bool,
    m: u32,
    t: u32,
    p: u32,
    salt: [u8; 32],
    wrapped: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    vault: [u8; 16],
    format_version: u32,
    created_at_ms: i64,
    slots: Vec<SlotInput>,
    open_passphrase: bool,
}

thread_local! {
    static KEY: Key32 = Key32::from_bytes([9u8; 32]);
}

fuzz_target!(|input: Input| {
    let vault = VaultId(input.vault);
    let mut slots = Vec::new();
    for s in input.slots.iter().take(8) {
        let kdf = if s.recovery {
            SlotKdf::HkdfSha256
        } else {
            match KdfParams::new(s.m, s.t, s.p) {
                Ok(params) => SlotKdf::Argon2id(params),
                Err(_) => continue,
            }
        };
        let role = match s.role % 3 {
            0 => OperatorRole::Owner,
            1 => OperatorRole::Operator,
            _ => OperatorRole::Viewer,
        };
        slots.push(KeySlot {
            id: KeySlotId::from_bytes(s.id),
            role,
            material: SlotMaterial {
                kdf,
                salt: s.salt,
                wrapped_vmk: s.wrapped.clone(),
            },
        });
    }
    // The Argon2id derivation is slow: open a passphrase slot only for the cheapest costs.
    let cheap = KdfParams::new(KdfParams::MIN_M_COST_KIB, 1, 1).ok();
    let recovery = RecoveryKey::generate().ok();
    for slot in &slots {
        match (&slot.material.kdf, &recovery) {
            (SlotKdf::HkdfSha256, Some(key)) => {
                let _ = open_recovery_slot(&vault, &slot.id, key, &slot.material);
            }
            (SlotKdf::Argon2id(params), _)
                if input.open_passphrase && Some(*params) == cheap =>
            {
                let phrase = SecretString::new("fuzz phrase fuzz phrase".to_owned());
                let _ = open_passphrase_slot(&vault, &slot.id, &phrase, &slot.material);
            }
            _ => {}
        }
    }
    let inputs: Vec<_> = slots.iter().map(KeySlot::mac_input).collect();
    KEY.with(|key| {
        let mac = header_mac(
            key,
            &HeaderMacInput {
                magic: "CERBERUS-VAULT",
                format_version: input.format_version,
                vault_id: &vault,
                created_at_ms: input.created_at_ms,
                slots: inputs,
            },
        );
        std::hint::black_box(mac);
    });
    let _ = KeySlotSet::from_slots(vault, slots);
});
