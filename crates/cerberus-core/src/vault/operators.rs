//! Operator slots and roles (ADR-0009), phrase change and recovery key rotation (ADR-0014).
//!
//! Every slot change runs under the service gate, writes the slot rows and a new header MAC in one
//! transaction, and never encrypts an item again.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use cerberus_crypto::{CryptoError, KdfParams, RecoveryKey, SecretString, SlotKdf};
use cerberus_store::{KeySlotRow, SlotKind, header_mac, verify_header_mac};
use cerberus_types::{KeySlotId, OperatorId, OperatorRole};

use super::custody::{
    OperatorInfo, RECOVERY_LABEL, blocking_raw, check_label, map_new_phrase_error, slot_set,
};
use super::events::CoreEvent;
use super::integration::by_operator;
use super::state::{Session, Unlocked};
use super::{KIND_NO_VAULT, VaultService};
use crate::audit::{Actor, AuditEvent, EventType};
use crate::context::OperatorContext;
use crate::error::CoreError;
use cerberus_types::FieldProblem;

fn kdf_of(row: &KeySlotRow) -> Option<KdfParams> {
    match &row.material.kdf {
        SlotKdf::Argon2id(params) => Some(*params),
        SlotKdf::HkdfSha256 => None,
    }
}

/// KDF cost for a new slot: the cost of the caller's own slot, or (after a recovery unlock) the
/// cost of the first owner slot.
fn cost_for_new_slot(session: &Session, rows: &[KeySlotRow]) -> Result<KdfParams, CoreError> {
    rows.iter()
        .find(|row| row.id == session.operator_id)
        .and_then(kdf_of)
        .or_else(|| {
            rows.iter()
                .filter(|row| row.role == OperatorRole::Owner)
                .find_map(kdf_of)
        })
        .ok_or(CoreError::Corrupt)
}

fn find_operator(rows: &[KeySlotRow], id: &OperatorId) -> Result<KeySlotRow, CoreError> {
    rows.iter()
        .find(|row| row.id == *id && row.kind == SlotKind::Passphrase)
        .cloned()
        .ok_or(CoreError::NotFound)
}

impl VaultService {
    /// Writes changed slots and the new header MAC in one transaction. Refuses with `Corrupt`
    /// when the stored header MAC does not match the stored slots: a new MAC would hide an edit
    /// of the file (DEC-FIX5-4). The caller holds the gate, so the slots cannot change between
    /// this check and the write.
    async fn save_slots(
        &self,
        unlocked: &Unlocked,
        rows_after: &[KeySlotRow],
        upsert: &[&KeySlotRow],
        delete: &[KeySlotId],
    ) -> Result<(), CoreError> {
        let header = self.inner.store.header().await?;
        let stored = self.inner.store.key_slots().await?;
        if !unlocked.header_ok || !verify_header_mac(&unlocked.keys.header_key, &header, &stored) {
            tracing::warn!("slot change refused: the stored header MAC does not match");
            let event = AuditEvent::new(EventType::VaultHeaderMismatch, Actor::system())
                .target("vault", unlocked.vault_id.to_string())
                .result("vault_corrupt");
            self.audit(unlocked, event).await;
            self.emit(CoreEvent::HeaderMismatch);
            return Err(CoreError::Corrupt);
        }
        let mac = header_mac(&unlocked.keys.header_key, &header, rows_after);
        let mut tx = self.inner.store.begin().await?;
        for id in delete {
            tx.delete_slot(*id).await?;
        }
        for row in upsert {
            tx.upsert_slot(row).await?;
        }
        tx.set_header_mac(&mac).await?;
        tx.commit().await?;
        Ok(())
    }

    pub(super) async fn list_operators_impl(&self) -> Result<Vec<OperatorInfo>, CoreError> {
        if self.inner.kind.load(Ordering::SeqCst) == KIND_NO_VAULT {
            return Err(CoreError::NoVault);
        }
        let rows = self.inner.store.key_slots().await?;
        Ok(rows
            .into_iter()
            .filter(|row| row.kind == SlotKind::Passphrase)
            .map(|row| OperatorInfo {
                id: row.id,
                label: row.label,
                role: row.role,
                last_unlock_at: row.last_unlock_at,
            })
            .collect())
    }

    pub(super) async fn add_operator_impl(
        &self,
        ctx: &OperatorContext,
        label: String,
        role: OperatorRole,
        phrase: SecretString,
    ) -> Result<OperatorId, CoreError> {
        let _gate = self.inner.gate.lock().await;
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        check_label(&label)?;
        let rows = self.inner.store.key_slots().await?;
        if rows
            .iter()
            .any(|row| row.kind == SlotKind::Passphrase && row.label == label)
        {
            return Err(CoreError::Validation(vec![FieldProblem {
                field: "label".to_owned(),
                problem: "another operator has this label".to_owned(),
            }]));
        }
        let params = cost_for_new_slot(&guard.session, &rows)?;
        let mut set = slot_set(guard.vault_id, &rows)?;
        let id = KeySlotId::generate();
        let vmk = Arc::clone(&guard.vmk);
        let set = blocking_raw(move || {
            set.add_passphrase(&vmk, id, role, &phrase, params)?;
            Ok(set)
        })
        .await?
        .map_err(map_new_phrase_error)?;
        let material = set
            .get(&id)
            .map(|slot| slot.material.clone())
            .ok_or(CoreError::Corrupt)?;
        let now = self.inner.clock.now();
        let row = KeySlotRow {
            id,
            kind: SlotKind::Passphrase,
            label,
            role,
            material,
            created_at: now,
            updated_at: now,
            last_unlock_at: None,
        };
        let mut rows_after = rows;
        rows_after.push(row.clone());
        self.save_slots(&guard, &rows_after, &[&row], &[]).await?;
        let event = by_operator(EventType::OperatorAdd, ctx)
            .target("operator", id.to_string())
            .detail("role", role.as_str());
        self.audit(&guard, event).await;
        Ok(id)
    }

    pub(super) async fn remove_operator_impl(
        &self,
        ctx: &OperatorContext,
        id: OperatorId,
    ) -> Result<(), CoreError> {
        let _gate = self.inner.gate.lock().await;
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        if id == guard.session.operator_id {
            return Err(CoreError::Conflict);
        }
        let rows = self.inner.store.key_slots().await?;
        find_operator(&rows, &id)?;
        let mut set = slot_set(guard.vault_id, &rows)?;
        set.remove(&id).map_err(|_| CoreError::Conflict)?;
        let rows_after: Vec<KeySlotRow> = rows.into_iter().filter(|row| row.id != id).collect();
        self.save_slots(&guard, &rows_after, &[], &[id]).await?;
        let event = by_operator(EventType::OperatorRemove, ctx).target("operator", id.to_string());
        self.audit(&guard, event).await;
        Ok(())
    }

    pub(super) async fn set_operator_role_impl(
        &self,
        ctx: &OperatorContext,
        id: OperatorId,
        role: OperatorRole,
    ) -> Result<(), CoreError> {
        let _gate = self.inner.gate.lock().await;
        let mut guard = self.unlocked_mut().await?;
        guard.session.authorize(ctx, OperatorRole::Owner)?;
        let rows = self.inner.store.key_slots().await?;
        let mut row = find_operator(&rows, &id)?;
        let mut set = slot_set(guard.vault_id, &rows)?;
        set.set_role(&id, role).map_err(|_| CoreError::Conflict)?;
        row.role = role;
        row.updated_at = self.inner.clock.now();
        let rows_after: Vec<KeySlotRow> = rows
            .into_iter()
            .map(|r| if r.id == id { row.clone() } else { r })
            .collect();
        self.save_slots(&guard, &rows_after, &[&row], &[]).await?;
        if guard.session.operator_id == id {
            guard.session.role = role;
        }
        let event = by_operator(EventType::OperatorRoleChange, ctx)
            .target("operator", id.to_string())
            .detail("role", role.as_str());
        self.audit(&guard, event).await;
        Ok(())
    }

    /// Changes the caller's own phrase. `kdf` sets a new cost (for example after a new cost test);
    /// `None` keeps the slot's cost. The current phrase must open the slot and give the VMK that is
    /// in memory. Only the slot is wrapped again (ADR-0014).
    ///
    /// # Errors
    /// [`CoreError::BadCredentials`] for a wrong current phrase (it does not count as a failed
    /// unlock), [`CoreError::Validation`] for a weak new phrase, [`CoreError::UnsupportedKdfCost`],
    /// [`CoreError::Conflict`] after a recovery unlock (that slot has no phrase), or the role check.
    pub async fn change_phrase_with_kdf(
        &self,
        ctx: &OperatorContext,
        current: SecretString,
        new: SecretString,
        kdf: Option<KdfParams>,
    ) -> Result<(), CoreError> {
        let _gate = self.inner.gate.lock().await;
        let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
        if guard.session.via_recovery {
            return Err(CoreError::Conflict);
        }
        let id = guard.session.operator_id;
        let rows = self.inner.store.key_slots().await?;
        let mut row = find_operator(&rows, &id)?;
        let params = match kdf.or_else(|| kdf_of(&row)) {
            Some(params) => params,
            None => return Err(CoreError::Corrupt),
        };
        let mut set = slot_set(guard.vault_id, &rows)?;
        let vmk = Arc::clone(&guard.vmk);
        let result = blocking_raw(move || {
            let (opened, _) = set.unlock_passphrase(&id, &current)?;
            if !opened.same_key(&vmk) {
                return Err(CryptoError::SlotRule);
            }
            set.rewrap(&vmk, &id, &new, params)?;
            Ok(set)
        })
        .await?;
        let set = match result {
            Ok(set) => set,
            Err(CryptoError::Integrity) => return Err(CoreError::BadCredentials),
            Err(CryptoError::SlotRule) => return Err(CoreError::Corrupt),
            Err(other) => return Err(map_new_phrase_error(other)),
        };
        row.material = set
            .get(&id)
            .map(|slot| slot.material.clone())
            .ok_or(CoreError::Corrupt)?;
        row.updated_at = self.inner.clock.now();
        let rows_after: Vec<KeySlotRow> = rows
            .into_iter()
            .map(|r| if r.id == id { row.clone() } else { r })
            .collect();
        self.save_slots(&guard, &rows_after, &[&row], &[]).await?;
        let event = by_operator(EventType::OperatorPhraseChange, ctx)
            .target("operator", id.to_string())
            .detail("kdf_changed", kdf.is_some());
        self.audit(&guard, event).await;
        Ok(())
    }

    /// Sets a new phrase for an operator after a recovery unlock (ADR-0009 point 4: the person
    /// lost the phrase, so no current phrase is asked). Only in a recovery session, which has role
    /// owner. The slot is wrapped again with the VMK in memory.
    ///
    /// # Errors
    /// [`CoreError::Conflict`] outside a recovery session, [`CoreError::NotFound`] for an unknown
    /// operator, [`CoreError::Validation`] for a weak phrase, [`CoreError::UnsupportedKdfCost`].
    pub async fn reset_phrase_after_recovery(
        &self,
        ctx: &OperatorContext,
        operator: OperatorId,
        new: SecretString,
        kdf: Option<KdfParams>,
    ) -> Result<(), CoreError> {
        let _gate = self.inner.gate.lock().await;
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        if !guard.session.via_recovery {
            return Err(CoreError::Conflict);
        }
        let rows = self.inner.store.key_slots().await?;
        let mut row = find_operator(&rows, &operator)?;
        let Some(params) = kdf.or_else(|| kdf_of(&row)) else {
            return Err(CoreError::Corrupt);
        };
        let mut set = slot_set(guard.vault_id, &rows)?;
        let vmk = Arc::clone(&guard.vmk);
        let set = blocking_raw(move || {
            set.rewrap(&vmk, &operator, &new, params)?;
            Ok(set)
        })
        .await?
        .map_err(map_new_phrase_error)?;
        row.material = set
            .get(&operator)
            .map(|slot| slot.material.clone())
            .ok_or(CoreError::Corrupt)?;
        row.updated_at = self.inner.clock.now();
        let rows_after: Vec<KeySlotRow> = rows
            .into_iter()
            .map(|r| if r.id == operator { row.clone() } else { r })
            .collect();
        self.save_slots(&guard, &rows_after, &[&row], &[]).await?;
        let event = by_operator(EventType::OperatorPhraseChange, ctx)
            .target("operator", operator.to_string())
            .detail("via_recovery", true);
        self.audit(&guard, event).await;
        Ok(())
    }

    pub(super) async fn rotate_recovery_key_impl(
        &self,
        ctx: &OperatorContext,
    ) -> Result<SecretString, CoreError> {
        let _gate = self.inner.gate.lock().await;
        let guard = self.authorize(ctx, OperatorRole::Owner).await?;
        let rows = self.inner.store.key_slots().await?;
        let mut set = slot_set(guard.vault_id, &rows)?;
        let old = set.recovery().map(|slot| slot.id);
        let recovery = RecoveryKey::generate()?;
        let id = KeySlotId::generate();
        set.set_recovery(&guard.vmk, id, &recovery)?;
        let material = set
            .get(&id)
            .map(|slot| slot.material.clone())
            .ok_or(CoreError::Corrupt)?;
        let now = self.inner.clock.now();
        let row = KeySlotRow {
            id,
            kind: SlotKind::Recovery,
            label: RECOVERY_LABEL.to_owned(),
            role: OperatorRole::Owner,
            material,
            created_at: now,
            updated_at: now,
            last_unlock_at: None,
        };
        let mut rows_after: Vec<KeySlotRow> =
            rows.into_iter().filter(|r| Some(r.id) != old).collect();
        rows_after.push(row.clone());
        let delete: Vec<KeySlotId> = old.into_iter().collect();
        self.save_slots(&guard, &rows_after, &[&row], &delete)
            .await?;
        let event =
            by_operator(EventType::RecoveryRotate, ctx).target("vault", guard.vault_id.to_string());
        self.audit(&guard, event).await;
        Ok(recovery.to_display())
    }
}
