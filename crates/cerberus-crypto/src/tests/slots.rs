//! Key slot tests: create, add, remove, rewrap, roles, recovery, tamper cases.

use cerberus_types::{KeySlotId, OperatorRole, VaultId};

use crate::{
    CryptoError, HeaderMacInput, KdfParams, KeySlot, KeySlotSet, KeyTree, RecoveryKey,
    SecretString, SlotKdf, Vmk, create_passphrase_slot, create_recovery_slot, diceware, header_mac,
    open_passphrase_slot, open_recovery_slot,
};

fn fast() -> KdfParams {
    KdfParams::insecure_fast_for_tests()
}

fn strong() -> SecretString {
    diceware(7).unwrap()
}

struct Fixture {
    vault: VaultId,
    vmk: Vmk,
    owner: KeySlotId,
    owner_phrase: SecretString,
    set: KeySlotSet,
}

fn fixture() -> Fixture {
    let vault = VaultId::generate();
    let vmk = Vmk::generate().unwrap();
    let owner = KeySlotId::generate();
    let owner_phrase = strong();
    let set = KeySlotSet::create(vault, &vmk, owner, &owner_phrase, fast()).unwrap();
    Fixture {
        vault,
        vmk,
        owner,
        owner_phrase,
        set,
    }
}

#[test]
fn owner_unlocks_and_wrong_phrase_fails() {
    let f = fixture();
    let (vmk, role) = f.set.unlock_passphrase(&f.owner, &f.owner_phrase).unwrap();
    assert!(vmk.same_key(&f.vmk));
    assert_eq!(role, OperatorRole::Owner);
    let wrong = SecretString::new(format!("{}x", f.owner_phrase.expose_secret()));
    assert_eq!(
        f.set.unlock_passphrase(&f.owner, &wrong).err(),
        Some(CryptoError::Integrity)
    );
    assert_eq!(
        f.set
            .unlock_passphrase(&KeySlotId::generate(), &f.owner_phrase)
            .err(),
        Some(CryptoError::SlotRule)
    );
}

#[test]
fn equivalent_unicode_forms_unlock() {
    let vault = VaultId::generate();
    let vmk = Vmk::generate().unwrap();
    let id = KeySlotId::generate();
    let composed = SecretString::new("caf\u{00E9} orbit velvet cactus lantern".to_owned());
    let set = KeySlotSet::create(vault, &vmk, id, &composed, fast()).unwrap();
    let decomposed = SecretString::new("cafe\u{0301} orbit velvet cactus lantern".to_owned());
    assert!(set.unlock_passphrase(&id, &decomposed).is_ok());
    // No trim: a trailing space is a different phrase.
    let spaced = SecretString::new("caf\u{00E9} orbit velvet cactus lantern ".to_owned());
    assert_eq!(
        set.unlock_passphrase(&id, &spaced).err(),
        Some(CryptoError::Integrity)
    );
}

#[test]
fn weak_phrase_cannot_make_a_slot() {
    let vault = VaultId::generate();
    let vmk = Vmk::generate().unwrap();
    for weak in ["short", "password1234", "aaaaaaaaaaaaaaaa"] {
        let phrase = SecretString::new(weak.to_owned());
        let result = create_passphrase_slot(&vmk, &vault, &KeySlotId::generate(), &phrase, fast());
        assert_eq!(result.err(), Some(CryptoError::WeakPhrase), "{weak}");
    }
}

#[test]
fn operators_have_own_phrases_and_roles() {
    let mut f = fixture();
    let operator = KeySlotId::generate();
    let viewer = KeySlotId::generate();
    let (op_phrase, viewer_phrase) = (strong(), strong());
    f.set
        .add_passphrase(&f.vmk, operator, OperatorRole::Operator, &op_phrase, fast())
        .unwrap();
    f.set
        .add_passphrase(&f.vmk, viewer, OperatorRole::Viewer, &viewer_phrase, fast())
        .unwrap();
    let (vmk, role) = f.set.unlock_passphrase(&operator, &op_phrase).unwrap();
    assert!(vmk.same_key(&f.vmk));
    assert_eq!(role, OperatorRole::Operator);
    let (vmk, role) = f.set.unlock_passphrase(&viewer, &viewer_phrase).unwrap();
    assert!(vmk.same_key(&f.vmk));
    assert_eq!(role, OperatorRole::Viewer);
    // One phrase opens only its own slot (ADR-0009: no "try all slots").
    assert_eq!(
        f.set.unlock_passphrase(&viewer, &op_phrase).err(),
        Some(CryptoError::Integrity)
    );
    // Duplicate ID is refused.
    assert_eq!(
        f.set
            .add_passphrase(&f.vmk, viewer, OperatorRole::Viewer, &strong(), fast())
            .err(),
        Some(CryptoError::SlotRule)
    );
}

#[test]
fn removed_slot_cannot_unlock() {
    let mut f = fixture();
    let operator = KeySlotId::generate();
    let phrase = strong();
    f.set
        .add_passphrase(&f.vmk, operator, OperatorRole::Operator, &phrase, fast())
        .unwrap();
    assert!(f.set.unlock_passphrase(&operator, &phrase).is_ok());
    let removed = f.set.remove(&operator).unwrap();
    assert_eq!(removed.id, operator);
    assert!(f.set.get(&operator).is_none());
    assert_eq!(
        f.set.unlock_passphrase(&operator, &phrase).err(),
        Some(CryptoError::SlotRule)
    );
    assert_eq!(f.set.remove(&operator).err(), Some(CryptoError::SlotRule));
}

#[test]
fn last_owner_cannot_be_removed_or_demoted() {
    let mut f = fixture();
    assert_eq!(f.set.remove(&f.owner).err(), Some(CryptoError::SlotRule));
    assert_eq!(
        f.set.set_role(&f.owner, OperatorRole::Viewer).err(),
        Some(CryptoError::SlotRule)
    );
    assert_eq!(
        f.set.get(&f.owner).map(|s| s.role),
        Some(OperatorRole::Owner)
    );
    // With a second owner, the first can go.
    let second = KeySlotId::generate();
    f.set
        .add_passphrase(&f.vmk, second, OperatorRole::Operator, &strong(), fast())
        .unwrap();
    f.set.set_role(&second, OperatorRole::Owner).unwrap();
    f.set.set_role(&f.owner, OperatorRole::Viewer).unwrap();
    assert_eq!(f.set.remove(&second).err(), Some(CryptoError::SlotRule));
    f.set.set_role(&f.owner, OperatorRole::Owner).unwrap();
    f.set.remove(&second).unwrap();
    // The recovery slot does not count as an owner and cannot change role.
    let recovery_id = KeySlotId::generate();
    f.set
        .set_recovery(&f.vmk, recovery_id, &RecoveryKey::generate().unwrap())
        .unwrap();
    assert_eq!(f.set.remove(&f.owner).err(), Some(CryptoError::SlotRule));
    assert_eq!(
        f.set.set_role(&recovery_id, OperatorRole::Viewer).err(),
        Some(CryptoError::SlotRule)
    );
}

#[test]
fn rewrap_keeps_the_vmk() {
    let mut f = fixture();
    let before = f.set.get(&f.owner).unwrap().material.clone();
    let new_phrase = strong();
    f.set
        .change_phrase(&f.owner, &f.owner_phrase, &new_phrase, fast())
        .unwrap();
    let after = f.set.get(&f.owner).unwrap().material.clone();
    assert_ne!(before.salt, after.salt, "rewrap uses a new salt");
    assert_ne!(before.wrapped_vmk, after.wrapped_vmk);
    let (vmk, _) = f.set.unlock_passphrase(&f.owner, &new_phrase).unwrap();
    assert!(
        vmk.same_key(&f.vmk),
        "VMK is the same, so no item needs new encryption"
    );
    assert_eq!(
        f.set.unlock_passphrase(&f.owner, &f.owner_phrase).err(),
        Some(CryptoError::Integrity)
    );
    // A wrong current phrase changes nothing.
    let other = strong();
    assert_eq!(
        f.set
            .change_phrase(&f.owner, &f.owner_phrase, &other, fast())
            .err(),
        Some(CryptoError::Integrity)
    );
    assert!(f.set.unlock_passphrase(&f.owner, &new_phrase).is_ok());
    // Data sealed under the old tree still opens with the tree of the same VMK.
    let tree = KeyTree::derive(&vmk, &f.vault).unwrap();
    let old_tree = KeyTree::derive(&f.vmk, &f.vault).unwrap();
    assert_eq!(
        tree.meta_key.expose_secret(),
        old_tree.meta_key.expose_secret()
    );
}

#[test]
fn rewrap_with_new_costs() {
    let mut f = fixture();
    let params = KdfParams::new(19_456, 1, 1).unwrap();
    let phrase = strong();
    f.set.rewrap(&f.vmk, &f.owner, &phrase, params).unwrap();
    assert_eq!(
        f.set.get(&f.owner).unwrap().material.kdf,
        SlotKdf::Argon2id(params)
    );
    assert!(
        f.set
            .unlock_passphrase(&f.owner, &phrase)
            .unwrap()
            .0
            .same_key(&f.vmk)
    );
}

#[test]
fn recovery_key_unlocks_as_owner_and_rotation_retires_the_old_key() {
    let mut f = fixture();
    let first = RecoveryKey::generate().unwrap();
    let id = KeySlotId::generate();
    assert_eq!(
        f.set.unlock_recovery(&first).err(),
        Some(CryptoError::SlotRule)
    );
    f.set.set_recovery(&f.vmk, id, &first).unwrap();
    // Through the text form, as the person types it.
    let typed = RecoveryKey::parse(first.to_display().expose_secret()).unwrap();
    let (vmk, role) = f.set.unlock_recovery(&typed).unwrap();
    assert!(vmk.same_key(&f.vmk));
    assert_eq!(role, OperatorRole::Owner);
    let wrong = RecoveryKey::generate().unwrap();
    assert_eq!(
        f.set.unlock_recovery(&wrong).err(),
        Some(CryptoError::Integrity)
    );

    let second = RecoveryKey::generate().unwrap();
    let new_id = KeySlotId::generate();
    f.set.set_recovery(&f.vmk, new_id, &second).unwrap();
    assert_eq!(f.set.slots().iter().filter(|s| s.is_recovery()).count(), 1);
    assert_eq!(
        f.set.unlock_recovery(&first).err(),
        Some(CryptoError::Integrity)
    );
    assert!(f.set.unlock_recovery(&second).unwrap().0.same_key(&f.vmk));
    // A passphrase slot ID cannot become the recovery slot.
    assert_eq!(
        f.set.set_recovery(&f.vmk, f.owner, &second).err(),
        Some(CryptoError::SlotRule)
    );
    // The recovery slot cannot be rewrapped with a phrase.
    assert_eq!(
        f.set.rewrap(&f.vmk, &new_id, &strong(), fast()).err(),
        Some(CryptoError::SlotRule)
    );
}

#[test]
fn slot_kinds_cannot_be_mixed() {
    let f = fixture();
    let recovery = RecoveryKey::generate().unwrap();
    let rid = KeySlotId::generate();
    let rslot = create_recovery_slot(&f.vmk, &f.vault, &rid, &recovery).unwrap();
    let pslot = &f.set.get(&f.owner).unwrap().material;
    assert_eq!(
        open_passphrase_slot(&f.vault, &rid, &f.owner_phrase, &rslot).err(),
        Some(CryptoError::SlotRule)
    );
    assert_eq!(
        open_recovery_slot(&f.vault, &f.owner, &recovery, pslot).err(),
        Some(CryptoError::SlotRule)
    );
}

#[test]
fn slot_material_is_bound_to_slot_and_vault() {
    let f = fixture();
    let material = f.set.get(&f.owner).unwrap().material.clone();
    // Copy the wrapped VMK to another slot ID.
    assert_eq!(
        open_passphrase_slot(&f.vault, &KeySlotId::generate(), &f.owner_phrase, &material).err(),
        Some(CryptoError::Integrity)
    );
    // Copy it to another vault.
    assert_eq!(
        open_passphrase_slot(&VaultId::generate(), &f.owner, &f.owner_phrase, &material).err(),
        Some(CryptoError::Integrity)
    );
    // Another salt gives another KEK.
    let mut salted = material.clone();
    salted.salt[0] ^= 1;
    assert_eq!(
        open_passphrase_slot(&f.vault, &f.owner, &f.owner_phrase, &salted).err(),
        Some(CryptoError::Integrity)
    );
}

#[test]
fn changed_kdf_costs_cannot_open_the_slot() {
    // Threat model T-2: a lower (or other) cost from a changed header gives another KEK.
    let vault = VaultId::generate();
    let vmk = Vmk::generate().unwrap();
    let id = KeySlotId::generate();
    let phrase = strong();
    let real = KdfParams::new(19_456, 2, 1).unwrap();
    let mut material = create_passphrase_slot(&vmk, &vault, &id, &phrase, real).unwrap();
    material.kdf = SlotKdf::Argon2id(KdfParams::new(19_456, 1, 1).unwrap());
    assert_eq!(
        open_passphrase_slot(&vault, &id, &phrase, &material).err(),
        Some(CryptoError::Integrity)
    );
}

#[test]
fn file_values_below_the_floor_are_refused() {
    // A store reads the numbers and must build them with `KdfParams::new`.
    // (64, 1, 1) is the fast test value: `new` refuses it in test builds too.
    for (m, t, p) in [
        (64, 1, 1),
        (19_455, 3, 4),
        (65_536, 0, 4),
        (65_536, 3, 17),
        (4_194_305, 1, 1),
        (65_536, 21, 1),
    ] {
        assert_eq!(
            KdfParams::new(m, t, p).err(),
            Some(CryptoError::InvalidKdfParams),
            "{m} {t} {p}"
        );
    }
    assert!(KdfParams::insecure_fast_for_tests().validate().is_ok());
}

#[test]
fn from_slots_checks_the_rules() {
    let f = fixture();
    let owner_slot = f.set.get(&f.owner).unwrap().clone();
    assert!(KeySlotSet::from_slots(f.vault, vec![owner_slot.clone()]).is_ok());
    assert_eq!(
        KeySlotSet::from_slots(f.vault, vec![]).err(),
        Some(CryptoError::SlotRule)
    );
    let viewer_only = KeySlot {
        role: OperatorRole::Viewer,
        ..owner_slot.clone()
    };
    assert_eq!(
        KeySlotSet::from_slots(f.vault, vec![viewer_only]).err(),
        Some(CryptoError::SlotRule)
    );
    assert_eq!(
        KeySlotSet::from_slots(f.vault, vec![owner_slot.clone(), owner_slot.clone()]).err(),
        Some(CryptoError::SlotRule)
    );
    let rk = RecoveryKey::generate().unwrap();
    let material = create_recovery_slot(&f.vmk, &f.vault, &KeySlotId::generate(), &rk).unwrap();
    let r1 = KeySlot {
        id: KeySlotId::generate(),
        role: OperatorRole::Owner,
        material: material.clone(),
    };
    let r2 = KeySlot {
        id: KeySlotId::generate(),
        role: OperatorRole::Owner,
        material: material.clone(),
    };
    assert_eq!(
        KeySlotSet::from_slots(f.vault, vec![owner_slot.clone(), r1.clone(), r2]).err(),
        Some(CryptoError::SlotRule)
    );
    let viewer_recovery = KeySlot {
        role: OperatorRole::Viewer,
        ..r1.clone()
    };
    assert_eq!(
        KeySlotSet::from_slots(f.vault, vec![owner_slot.clone(), viewer_recovery]).err(),
        Some(CryptoError::SlotRule)
    );
    let set = KeySlotSet::from_slots(f.vault, vec![owner_slot, r1]).unwrap();
    assert_eq!(set.vault_id(), &f.vault);
    assert!(set.unlock_passphrase(&f.owner, &f.owner_phrase).is_ok());
}

#[test]
fn header_mac_changes_when_a_slot_changes() {
    let mut f = fixture();
    let tree = KeyTree::derive(&f.vmk, &f.vault).unwrap();
    let mac_of = |set: &KeySlotSet| {
        header_mac(
            &tree.header_key,
            &HeaderMacInput {
                magic: "CERBERUS-VAULT",
                format_version: 1,
                vault_id: set.vault_id(),
                created_at_ms: 1_767_225_600_000,
                slots: set.slots().iter().map(KeySlot::mac_input).collect(),
            },
        )
    };
    let before = mac_of(&f.set);
    assert_eq!(before, mac_of(&f.set));
    f.set
        .set_recovery(
            &f.vmk,
            KeySlotId::generate(),
            &RecoveryKey::generate().unwrap(),
        )
        .unwrap();
    let with_recovery = mac_of(&f.set);
    assert_ne!(before, with_recovery);
    let phrase = strong();
    f.set.rewrap(&f.vmk, &f.owner, &phrase, fast()).unwrap();
    assert_ne!(with_recovery, mac_of(&f.set));
    let input = f.set.get(&f.owner).unwrap().mac_input();
    assert_eq!(
        (input.kind, input.kdf_alg, input.role),
        ("passphrase", "argon2id", "owner")
    );
    let recovery = f.set.recovery().unwrap().mac_input();
    assert_eq!(
        (recovery.kind, recovery.kdf_alg, recovery.kdf),
        ("recovery", "hkdf-sha256", None)
    );
}
