//! Property tests (proptest).

use std::sync::OnceLock;

use cerberus_types::{ItemId, KeySlotId, VaultId};
use proptest::prelude::*;

use crate::{
    Aad, CryptoError, KdfParams, Key32, KeySlotSet, KeyTree, Purpose, RecoveryKey, SecretString,
    Vmk, new_dek, open, seal, unwrap_dek, wrap_dek,
};

/// One shared key (making keys is cheap, but a fixed key keeps failures reproducible per case).
fn key() -> &'static Key32 {
    static KEY: OnceLock<Key32> = OnceLock::new();
    KEY.get_or_init(|| Key32::random().unwrap())
}

fn purpose() -> impl Strategy<Value = Purpose> {
    prop::sample::select(Purpose::ALL.to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn seal_open_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0..1500),
        vault in any::<[u8; 16]>(),
        record in prop::collection::vec(any::<u8>(), 0..40),
        version in any::<u32>(),
        purpose in purpose(),
    ) {
        let vault = VaultId(vault);
        let aad = Aad { purpose, vault_id: &vault, record_id: &record, version };
        let env = seal(key(), &aad, &data).unwrap();
        // 1 version byte + 24 nonce + 16 tag around a body of whole 64-byte blocks.
        prop_assert_eq!((env.len() - 41) % 64, 0);
        let back = open(key(), &aad, &env).unwrap();
        prop_assert_eq!(back.expose_secret(), data.as_slice());
    }

    #[test]
    fn any_single_byte_change_in_the_envelope_fails(
        data in prop::collection::vec(any::<u8>(), 0..300),
        index in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let vault = VaultId([7; 16]);
        let aad = Aad { purpose: Purpose::ItemPayload, vault_id: &vault, record_id: &[1; 16], version: 1 };
        let mut env = seal(key(), &aad, &data).unwrap();
        // Covers the version byte, every nonce byte, the ciphertext and the tag.
        let i = index.index(env.len());
        env[i] ^= mask;
        let result = open(key(), &aad, &env);
        if i == 0 {
            prop_assert_eq!(result.err(), Some(CryptoError::EnvelopeVersion));
        } else {
            prop_assert_eq!(result.err(), Some(CryptoError::Integrity));
        }
    }

    #[test]
    fn any_change_in_the_aad_fails(
        data in prop::collection::vec(any::<u8>(), 0..200),
        record in prop::collection::vec(any::<u8>(), 1..32),
        vault in any::<[u8; 16]>(),
        version in any::<u32>(),
        index in any::<prop::sample::Index>(),
        mask in 1u8..=255,
        other_version in any::<u32>(),
        other_purpose in purpose(),
    ) {
        let vault_id = VaultId(vault);
        let aad = Aad { purpose: Purpose::ItemMeta, vault_id: &vault_id, record_id: &record, version };
        let env = seal(key(), &aad, &data).unwrap();

        let mut changed_record = record.clone();
        let i = index.index(changed_record.len());
        changed_record[i] ^= mask;
        let bad = Aad { record_id: &changed_record, ..aad };
        prop_assert_eq!(open(key(), &bad, &env).err(), Some(CryptoError::Integrity));

        let mut changed_vault = vault;
        changed_vault[index.index(16)] ^= mask;
        let other_vault = VaultId(changed_vault);
        let bad = Aad { vault_id: &other_vault, ..aad };
        prop_assert_eq!(open(key(), &bad, &env).err(), Some(CryptoError::Integrity));

        if other_version != version {
            let bad = Aad { version: other_version, ..aad };
            prop_assert_eq!(open(key(), &bad, &env).err(), Some(CryptoError::Integrity));
        }
        if other_purpose != Purpose::ItemMeta {
            let bad = Aad { purpose: other_purpose, ..aad };
            prop_assert_eq!(open(key(), &bad, &env).err(), Some(CryptoError::Integrity));
        }
        // Extra or missing record bytes: length prefixes keep the fields apart.
        let mut longer = record.clone();
        longer.push(0);
        let bad = Aad { record_id: &longer, ..aad };
        prop_assert_eq!(open(key(), &bad, &env).err(), Some(CryptoError::Integrity));
    }

    #[test]
    fn wrong_key_fails(data in prop::collection::vec(any::<u8>(), 0..200)) {
        let vault = VaultId([1; 16]);
        let aad = Aad { purpose: Purpose::GrantBody, vault_id: &vault, record_id: b"g", version: 0 };
        let env = seal(key(), &aad, &data).unwrap();
        let other = Key32::random().unwrap();
        prop_assert_eq!(open(&other, &aad, &env).err(), Some(CryptoError::Integrity));
    }

    #[test]
    fn truncated_or_extended_envelopes_fail(
        data in prop::collection::vec(any::<u8>(), 0..200),
        cut in 1usize..80,
        extra in prop::collection::vec(any::<u8>(), 1..80),
    ) {
        let vault = VaultId([1; 16]);
        let aad = Aad { purpose: Purpose::AuditBody, vault_id: &vault, record_id: &5u64.to_be_bytes(), version: 0 };
        let env = seal(key(), &aad, &data).unwrap();
        let cut = cut.min(env.len());
        prop_assert!(open(key(), &aad, &env[..env.len() - cut]).is_err());
        let mut longer = env.clone();
        longer.extend_from_slice(&extra);
        prop_assert!(open(key(), &aad, &longer).is_err());
    }

    #[test]
    fn item_ciphertext_cannot_move_to_another_item(
        payload in prop::collection::vec(any::<u8>(), 1..300),
        version in 1u32..1000,
    ) {
        // Full item path: DEK wrapped by item_kek, payload sealed by the DEK. Both bound to item and version.
        let vault = VaultId::generate();
        let tree = KeyTree::derive(&Vmk::generate().unwrap(), &vault).unwrap();
        let (item, other) = (ItemId::generate(), ItemId::generate());
        let dek = new_dek().unwrap();
        let dek_aad = Aad { purpose: Purpose::ItemDek, vault_id: &vault, record_id: item.as_bytes(), version };
        let pay_aad = Aad { purpose: Purpose::ItemPayload, ..dek_aad };
        let wrapped = wrap_dek(&tree.item_kek, &dek_aad, &dek).unwrap();
        let sealed = seal(&dek, &pay_aad, &payload).unwrap();

        let opened_dek = unwrap_dek(&tree.item_kek, &dek_aad, &wrapped).unwrap();
        let opened = open(&opened_dek, &pay_aad, &sealed).unwrap();
        prop_assert_eq!(opened.expose_secret(), payload.as_slice());

        let moved_dek = Aad { record_id: other.as_bytes(), ..dek_aad };
        let moved_pay = Aad { record_id: other.as_bytes(), ..pay_aad };
        prop_assert_eq!(unwrap_dek(&tree.item_kek, &moved_dek, &wrapped).err(), Some(CryptoError::Integrity));
        prop_assert_eq!(open(&dek, &moved_pay, &sealed).err(), Some(CryptoError::Integrity));
        // Another version of the same item, or the payload column read as the meta column.
        let other_version = Aad { version: version + 1, ..pay_aad };
        prop_assert_eq!(open(&dek, &other_version, &sealed).err(), Some(CryptoError::Integrity));
        let as_meta = Aad { purpose: Purpose::ItemMetaSnapshot, ..pay_aad };
        prop_assert_eq!(open(&dek, &as_meta, &sealed).err(), Some(CryptoError::Integrity));
        // The payload key is the DEK, not item_kek or meta_key.
        prop_assert_eq!(open(&tree.item_kek, &pay_aad, &sealed).err(), Some(CryptoError::Integrity));
        prop_assert_eq!(open(&tree.meta_key, &pay_aad, &sealed).err(), Some(CryptoError::Integrity));
    }
}

proptest! {
    // Each case runs Argon2id (fast test costs), so fewer cases.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn wrong_phrase_fails(guess in ".{0,40}") {
        let vault = VaultId([2; 16]);
        let id = KeySlotId::from_bytes([3; 16]);
        let phrase = SecretString::new("fake-orbit velvet cactus lantern harbor".to_owned());
        let vmk = Vmk::generate().unwrap();
        let set = KeySlotSet::create(vault, &vmk, id, &phrase, KdfParams::insecure_fast_for_tests()).unwrap();
        prop_assume!(crate::normalize_phrase(&guess).expose_secret() != phrase.expose_secret());
        let guess = SecretString::new(guess);
        prop_assert_eq!(set.unlock_passphrase(&id, &guess).err(), Some(CryptoError::Integrity));
        prop_assert!(set.unlock_passphrase(&id, &phrase).unwrap().0.same_key(&vmk));
    }

    #[test]
    fn single_changed_character_of_the_phrase_fails(index in any::<prop::sample::Index>(), c in any::<char>()) {
        let vault = VaultId([2; 16]);
        let id = KeySlotId::from_bytes([4; 16]);
        let text = "fake-orbit velvet cactus lantern harbor";
        let phrase = SecretString::new(text.to_owned());
        let set = KeySlotSet::create(vault, &Vmk::generate().unwrap(), id, &phrase, KdfParams::insecure_fast_for_tests()).unwrap();
        let mut chars: Vec<char> = text.chars().collect();
        let i = index.index(chars.len());
        prop_assume!(chars[i] != c);
        chars[i] = c;
        let changed: String = chars.into_iter().collect();
        prop_assume!(crate::normalize_phrase(&changed).expose_secret() != text);
        prop_assert_eq!(set.unlock_passphrase(&id, &SecretString::new(changed)).err(), Some(CryptoError::Integrity));
    }

    #[test]
    fn rewrap_keeps_vmk_and_retires_old_phrase(round in 1usize..4) {
        let vault = VaultId::generate();
        let id = KeySlotId::generate();
        let vmk = Vmk::generate().unwrap();
        let mut phrase = crate::diceware(7).unwrap();
        let mut set = KeySlotSet::create(vault, &vmk, id, &phrase, KdfParams::insecure_fast_for_tests()).unwrap();
        for _ in 0..round {
            let next = crate::diceware(7).unwrap();
            set.change_phrase(&id, &phrase, &next, KdfParams::insecure_fast_for_tests()).unwrap();
            prop_assert_eq!(set.unlock_passphrase(&id, &phrase).err(), Some(CryptoError::Integrity));
            phrase = next;
            prop_assert!(set.unlock_passphrase(&id, &phrase).unwrap().0.same_key(&vmk));
        }
    }

    #[test]
    fn recovery_key_unlocks_and_others_do_not(_case in 0u8..4) {
        let vault = VaultId::generate();
        let vmk = Vmk::generate().unwrap();
        let mut set = KeySlotSet::create(vault, &vmk, KeySlotId::generate(), &crate::diceware(7).unwrap(), KdfParams::insecure_fast_for_tests()).unwrap();
        let recovery = RecoveryKey::generate().unwrap();
        set.set_recovery(&vmk, KeySlotId::generate(), &recovery).unwrap();
        let typed = RecoveryKey::parse(&recovery.to_display().expose_secret().to_lowercase()).unwrap();
        prop_assert!(set.unlock_recovery(&typed).unwrap().0.same_key(&vmk));
        prop_assert_eq!(set.unlock_recovery(&RecoveryKey::generate().unwrap()).err(), Some(CryptoError::Integrity));
    }
}
