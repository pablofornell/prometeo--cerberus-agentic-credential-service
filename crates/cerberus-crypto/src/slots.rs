//! Key slots: each slot wraps the same VMK with its own KEK (ADR-0009, ADR-0013, ADR-0014).

use cerberus_types::{KeySlotId, OperatorRole, VaultId};

use crate::envelope::{Aad, Purpose, open, seal};
use crate::error::CryptoError;
use crate::kdf::{KdfParams, derive_passphrase_kek, derive_recovery_kek, normalize_phrase};
use crate::keytree::key_from_plain;
use crate::mac::SlotMacInput;
use crate::phrase::meets_phrase_policy;
use crate::random;
use crate::recovery::RecoveryKey;
use crate::secret::{SecretString, Vmk};

/// `key_slots.kind` of a passphrase slot.
pub const KIND_PASSPHRASE: &str = "passphrase";
/// `key_slots.kind` of the recovery slot.
pub const KIND_RECOVERY: &str = "recovery";
/// `key_slots.kdf_alg` of a passphrase slot.
pub const KDF_ARGON2ID: &str = "argon2id";
/// `key_slots.kdf_alg` of the recovery slot.
pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";

/// KDF of a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotKdf {
    /// Passphrase slot.
    Argon2id(KdfParams),
    /// Recovery slot.
    HkdfSha256,
}

/// The stored crypto part of a slot. None of it is secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotMaterial {
    /// KDF and its costs.
    pub kdf: SlotKdf,
    /// 32 random bytes, new for each wrap.
    pub salt: [u8; 32],
    /// Envelope of the VMK (purpose `slot.vmk`, record ID = slot ID, version 0).
    pub wrapped_vmk: Vec<u8>,
}

fn slot_aad<'a>(vault_id: &'a VaultId, slot_id: &'a KeySlotId) -> Aad<'a> {
    Aad {
        purpose: Purpose::SlotVmk,
        vault_id,
        record_id: slot_id.as_bytes(),
        version: 0,
    }
}

fn new_salt() -> Result<[u8; 32], CryptoError> {
    let mut salt = [0u8; 32];
    random::fill(&mut salt)?;
    Ok(salt)
}

/// Wraps the VMK under a phrase. A new random salt is used.
///
/// # Errors
/// [`CryptoError::WeakPhrase`] when the phrase fails the policy (12 characters, zxcvbn >= 3),
/// [`CryptoError::InvalidKdfParams`], [`CryptoError::Kdf`] or [`CryptoError::Rng`].
pub fn create_passphrase_slot(
    vmk: &Vmk,
    vault_id: &VaultId,
    slot_id: &KeySlotId,
    phrase: &SecretString,
    params: KdfParams,
) -> Result<SlotMaterial, CryptoError> {
    if !meets_phrase_policy(&normalize_phrase(phrase.expose_secret()), &[]) {
        return Err(CryptoError::WeakPhrase);
    }
    params.validate()?;
    let salt = new_salt()?;
    let kek = derive_passphrase_kek(phrase, &salt, &params)?;
    let wrapped_vmk = seal(&kek, &slot_aad(vault_id, slot_id), vmk.0.expose_secret())?;
    Ok(SlotMaterial {
        kdf: SlotKdf::Argon2id(params),
        salt,
        wrapped_vmk,
    })
}

/// Opens a passphrase slot.
///
/// # Errors
/// [`CryptoError::Integrity`] for a wrong phrase or changed slot data, [`CryptoError::SlotRule`]
/// for a recovery slot, [`CryptoError::InvalidKdfParams`] for out-of-range costs.
pub fn open_passphrase_slot(
    vault_id: &VaultId,
    slot_id: &KeySlotId,
    phrase: &SecretString,
    slot: &SlotMaterial,
) -> Result<Vmk, CryptoError> {
    let SlotKdf::Argon2id(params) = &slot.kdf else {
        return Err(CryptoError::SlotRule);
    };
    let kek = derive_passphrase_kek(phrase, &slot.salt, params)?;
    let plain = open(&kek, &slot_aad(vault_id, slot_id), &slot.wrapped_vmk)?;
    key_from_plain(plain.expose_secret()).map(Vmk)
}

/// Wraps the VMK under a recovery key. A new random salt is used.
///
/// # Errors
/// [`CryptoError::Rng`] or [`CryptoError::Kdf`].
pub fn create_recovery_slot(
    vmk: &Vmk,
    vault_id: &VaultId,
    slot_id: &KeySlotId,
    recovery: &RecoveryKey,
) -> Result<SlotMaterial, CryptoError> {
    let salt = new_salt()?;
    let kek = derive_recovery_kek(recovery, &salt)?;
    let wrapped_vmk = seal(&kek, &slot_aad(vault_id, slot_id), vmk.0.expose_secret())?;
    Ok(SlotMaterial {
        kdf: SlotKdf::HkdfSha256,
        salt,
        wrapped_vmk,
    })
}

/// Opens the recovery slot.
///
/// # Errors
/// [`CryptoError::Integrity`] for a wrong key or changed slot data, [`CryptoError::SlotRule`]
/// for a passphrase slot.
pub fn open_recovery_slot(
    vault_id: &VaultId,
    slot_id: &KeySlotId,
    recovery: &RecoveryKey,
    slot: &SlotMaterial,
) -> Result<Vmk, CryptoError> {
    if slot.kdf != SlotKdf::HkdfSha256 {
        return Err(CryptoError::SlotRule);
    }
    let kek = derive_recovery_kek(recovery, &slot.salt)?;
    let plain = open(&kek, &slot_aad(vault_id, slot_id), &slot.wrapped_vmk)?;
    key_from_plain(plain.expose_secret()).map(Vmk)
}

/// One key slot: ID, role and crypto material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
    /// Slot ID. For a passphrase slot it is also the operator ID (DEC-007).
    pub id: KeySlotId,
    /// Role. The recovery slot always has role owner (ADR-0009 point 4).
    pub role: OperatorRole,
    /// KDF, salt and wrapped VMK.
    pub material: SlotMaterial,
}

impl KeySlot {
    /// True for the recovery slot.
    #[must_use]
    pub fn is_recovery(&self) -> bool {
        self.material.kdf == SlotKdf::HkdfSha256
    }

    /// `passphrase` or `recovery`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        if self.is_recovery() {
            KIND_RECOVERY
        } else {
            KIND_PASSPHRASE
        }
    }

    /// This slot as a header MAC input (ADR-0013).
    #[must_use]
    pub fn mac_input(&self) -> SlotMacInput<'_> {
        let (kdf_alg, kdf) = match &self.material.kdf {
            SlotKdf::Argon2id(params) => (KDF_ARGON2ID, Some(*params)),
            SlotKdf::HkdfSha256 => (KDF_HKDF_SHA256, None),
        };
        SlotMacInput {
            id: &self.id,
            kind: self.kind(),
            role: self.role.as_str(),
            kdf_alg,
            kdf,
            salt: &self.material.salt,
            wrapped_vmk: &self.material.wrapped_vmk,
        }
    }

    fn is_owner_passphrase(&self) -> bool {
        !self.is_recovery() && self.role == OperatorRole::Owner
    }
}

/// All key slots of one vault, with the slot rules of ADR-0009:
/// at least one owner passphrase slot, at most one recovery slot, the recovery slot is owner.
#[derive(Clone, Debug)]
pub struct KeySlotSet {
    vault_id: VaultId,
    slots: Vec<KeySlot>,
}

impl KeySlotSet {
    /// A new set with the first owner slot.
    ///
    /// # Errors
    /// The errors of [`create_passphrase_slot`].
    pub fn create(
        vault_id: VaultId,
        vmk: &Vmk,
        owner: KeySlotId,
        phrase: &SecretString,
        params: KdfParams,
    ) -> Result<Self, CryptoError> {
        let material = create_passphrase_slot(vmk, &vault_id, &owner, phrase, params)?;
        Ok(Self {
            vault_id,
            slots: vec![KeySlot {
                id: owner,
                role: OperatorRole::Owner,
                material,
            }],
        })
    }

    /// Rebuilds a set from stored slots and checks the slot rules.
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] when a rule fails or an ID is used twice.
    pub fn from_slots(vault_id: VaultId, slots: Vec<KeySlot>) -> Result<Self, CryptoError> {
        let set = Self { vault_id, slots };
        set.check_rules()?;
        Ok(set)
    }

    fn check_rules(&self) -> Result<(), CryptoError> {
        let owners = self
            .slots
            .iter()
            .filter(|s| s.is_owner_passphrase())
            .count();
        let recovery: Vec<&KeySlot> = self.slots.iter().filter(|s| s.is_recovery()).collect();
        let mut ids: Vec<KeySlotId> = self.slots.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        let ok = owners >= 1
            && recovery.len() <= 1
            && recovery.iter().all(|s| s.role == OperatorRole::Owner)
            && ids.len() == self.slots.len();
        if ok {
            Ok(())
        } else {
            Err(CryptoError::SlotRule)
        }
    }

    /// Vault ID of the set.
    #[must_use]
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// All slots.
    #[must_use]
    pub fn slots(&self) -> &[KeySlot] {
        &self.slots
    }

    /// The slot with `id`.
    #[must_use]
    pub fn get(&self, id: &KeySlotId) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.id == *id)
    }

    /// The recovery slot, if one exists.
    #[must_use]
    pub fn recovery(&self) -> Option<&KeySlot> {
        self.slots.iter().find(|s| s.is_recovery())
    }

    fn position(&self, id: &KeySlotId) -> Result<usize, CryptoError> {
        self.slots
            .iter()
            .position(|s| s.id == *id)
            .ok_or(CryptoError::SlotRule)
    }

    /// Adds an operator slot.
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] when `id` is used already, or the errors of [`create_passphrase_slot`].
    pub fn add_passphrase(
        &mut self,
        vmk: &Vmk,
        id: KeySlotId,
        role: OperatorRole,
        phrase: &SecretString,
        params: KdfParams,
    ) -> Result<(), CryptoError> {
        if self.get(&id).is_some() {
            return Err(CryptoError::SlotRule);
        }
        let material = create_passphrase_slot(vmk, &self.vault_id, &id, phrase, params)?;
        self.slots.push(KeySlot { id, role, material });
        Ok(())
    }

    /// Sets the one recovery slot. An old recovery slot is replaced (key rotation).
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] when `id` belongs to a passphrase slot, or the errors of
    /// [`create_recovery_slot`].
    pub fn set_recovery(
        &mut self,
        vmk: &Vmk,
        id: KeySlotId,
        recovery: &RecoveryKey,
    ) -> Result<(), CryptoError> {
        if self.get(&id).is_some_and(|s| !s.is_recovery()) {
            return Err(CryptoError::SlotRule);
        }
        let material = create_recovery_slot(vmk, &self.vault_id, &id, recovery)?;
        self.slots.retain(|s| !s.is_recovery());
        self.slots.push(KeySlot {
            id,
            role: OperatorRole::Owner,
            material,
        });
        Ok(())
    }

    /// Removes a slot. The last owner passphrase slot cannot be removed.
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] for an unknown ID or the last owner.
    pub fn remove(&mut self, id: &KeySlotId) -> Result<KeySlot, CryptoError> {
        let index = self.position(id)?;
        let removed = self.slots.remove(index);
        if let Err(err) = self.check_rules() {
            self.slots.insert(index, removed);
            return Err(err);
        }
        Ok(removed)
    }

    /// Changes the role of a passphrase slot. The last owner cannot be demoted.
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] for an unknown ID, the recovery slot, or the last owner.
    pub fn set_role(&mut self, id: &KeySlotId, role: OperatorRole) -> Result<(), CryptoError> {
        let index = self.position(id)?;
        let Some(slot) = self.slots.get_mut(index) else {
            return Err(CryptoError::SlotRule);
        };
        if slot.is_recovery() {
            return Err(CryptoError::SlotRule);
        }
        let old = std::mem::replace(&mut slot.role, role);
        if let Err(err) = self.check_rules() {
            if let Some(slot) = self.slots.get_mut(index) {
                slot.role = old;
            }
            return Err(err);
        }
        Ok(())
    }

    /// Wraps the VMK again in one passphrase slot with a new phrase, new salt and new costs.
    /// No item is encrypted again (ADR-0014).
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] for an unknown ID or the recovery slot, or the errors of
    /// [`create_passphrase_slot`].
    pub fn rewrap(
        &mut self,
        vmk: &Vmk,
        id: &KeySlotId,
        new_phrase: &SecretString,
        params: KdfParams,
    ) -> Result<(), CryptoError> {
        let index = self.position(id)?;
        if self.slots.get(index).is_none_or(KeySlot::is_recovery) {
            return Err(CryptoError::SlotRule);
        }
        let material = create_passphrase_slot(vmk, &self.vault_id, id, new_phrase, params)?;
        if let Some(slot) = self.slots.get_mut(index) {
            slot.material = material;
        }
        Ok(())
    }

    /// Changes the phrase of a slot. The current phrase must open it first.
    ///
    /// # Errors
    /// [`CryptoError::Integrity`] for a wrong current phrase, or the errors of [`KeySlotSet::rewrap`].
    pub fn change_phrase(
        &mut self,
        id: &KeySlotId,
        current: &SecretString,
        new_phrase: &SecretString,
        params: KdfParams,
    ) -> Result<(), CryptoError> {
        let (vmk, _) = self.unlock_passphrase(id, current)?;
        self.rewrap(&vmk, id, new_phrase, params)
    }

    /// Opens the VMK with the phrase of slot `id`. Returns the VMK and the role of the slot.
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] for an unknown or recovery slot, [`CryptoError::Integrity`] for a
    /// wrong phrase.
    pub fn unlock_passphrase(
        &self,
        id: &KeySlotId,
        phrase: &SecretString,
    ) -> Result<(Vmk, OperatorRole), CryptoError> {
        let slot = self.get(id).ok_or(CryptoError::SlotRule)?;
        let vmk = open_passphrase_slot(&self.vault_id, &slot.id, phrase, &slot.material)?;
        Ok((vmk, slot.role))
    }

    /// Opens the VMK with the recovery key. The role is always owner (ADR-0009 point 4).
    ///
    /// # Errors
    /// [`CryptoError::SlotRule`] when there is no recovery slot, [`CryptoError::Integrity`] for a
    /// wrong key.
    pub fn unlock_recovery(
        &self,
        recovery: &RecoveryKey,
    ) -> Result<(Vmk, OperatorRole), CryptoError> {
        let slot = self.recovery().ok_or(CryptoError::SlotRule)?;
        let vmk = open_recovery_slot(&self.vault_id, &slot.id, recovery, &slot.material)?;
        Ok((vmk, OperatorRole::Owner))
    }
}
