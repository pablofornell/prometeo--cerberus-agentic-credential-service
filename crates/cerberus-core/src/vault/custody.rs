//! Create, unlock and lock (ADR-0009, ADR-0013, ADR-0014, ADR-0026).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use cerberus_crypto::{
    CryptoError, KdfParams, KeySlotSet, KeyTree, RecoveryKey, SecretString, Vmk,
};
use cerberus_store::{
    CancelReport, FORMAT_VERSION, HeaderRow, IndexRows, KeySlotRow, RevokeReport, SettingRow,
    SlotKind, TlsCaRow, header_mac, verify_header_mac,
};
use cerberus_types::{
    AccessRequestStatus, ErrorCode, FieldProblem, KeySlotId, LockReason, OperatorId, OperatorRole,
    RequestId, VaultId,
};
use jiff::Timestamp;

use super::events::CoreEvent;
use super::state::{Session, Unlocked};
use super::{KIND_NO_VAULT, KIND_SEALED, LockSettings, VaultService, backoff};
use crate::audit::{Actor, AuditEvent, AuditWriter, EventType};
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::{self, Index};

/// Label of the recovery slot in `key_slots.label`.
pub(super) const RECOVERY_LABEL: &str = "Recovery key";
/// Longest operator label (`key_slots.label` CHECK).
pub(super) const MAX_LABEL_CHARS: usize = 64;
/// Setting key for the extra TLS host names given at creation (ADR-0023 point 3).
pub const HOST_NAMES_SETTING: &str = "tls_host_names";
/// Setting key for a panic whose lease revoke failed: the operator ID, or `null` (DEC-FIX5-5).
pub(super) const PANIC_REVOKE_SETTING: &str = "panic_revoke_pending";

/// What the revoke after a stranded-vault recovery did (T27-H, NEW-12).
struct RecoveryRevoke {
    agent_keys: u64,
    leases: RevokeReport,
    requests: CancelReport,
}

/// Input of [`KeyCustody::create_vault`].
#[derive(Debug)]
pub struct NewVault {
    /// Label of the first owner, shown on the unlock screen.
    pub owner_label: String,
    /// The owner's master phrase.
    pub phrase: SecretString,
    /// KDF cost from the cost test (ADR-0013).
    pub kdf: KdfParams,
    /// Extra host names for the TLS leaf.
    pub host_names: Vec<String>,
}

/// Result of [`KeyCustody::create_vault`].
#[derive(Debug)]
pub struct CreatedVault {
    /// The first owner (its key slot ID).
    pub owner_id: OperatorId,
    /// The recovery key text. Show it one time, then drop it.
    pub recovery_key: SecretString,
    /// The CA pin (ADR-0023 point 6).
    pub ca_pin: String,
}

/// One operator as the unlock screen lists it. Plain data (accepted leak I-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorInfo {
    /// Operator ID (= key slot ID).
    pub id: OperatorId,
    /// Label.
    pub label: String,
    /// Role.
    pub role: OperatorRole,
    /// Last successful unlock.
    pub last_unlock_at: Option<Timestamp>,
}

/// Key custody (docs/interfaces.md section 4). [`VaultService`] implements it.
pub trait KeyCustody: Send + Sync {
    /// Makes a new vault and unlocks it as its owner. Only in state `NoVault`.
    fn create_vault(
        &self,
        new: NewVault,
    ) -> impl Future<Output = Result<CreatedVault, CoreError>> + Send;
    /// Unlocks with the phrase of one operator.
    fn unlock_with_phrase(
        &self,
        operator: OperatorId,
        phrase: SecretString,
    ) -> impl Future<Output = Result<OperatorContext, CoreError>> + Send;
    /// Unlocks with the recovery key (role owner).
    fn unlock_with_recovery(
        &self,
        recovery: RecoveryKey,
    ) -> impl Future<Output = Result<OperatorContext, CoreError>> + Send;
    /// Locks. Does nothing when the vault is not unlocked.
    fn lock(&self, reason: LockReason) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Revoke all leases, cancel all requests, then lock (panic button).
    fn panic_lock(
        &self,
        ctx: &OperatorContext,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// The operators (passphrase slots). Works while sealed.
    fn list_operators(&self) -> impl Future<Output = Result<Vec<OperatorInfo>, CoreError>> + Send;
    /// Adds an operator slot. Owner only.
    fn add_operator(
        &self,
        ctx: &OperatorContext,
        label: String,
        role: OperatorRole,
        phrase: SecretString,
    ) -> impl Future<Output = Result<OperatorId, CoreError>> + Send;
    /// Removes an operator slot. Owner only; not the last owner, not the caller's own slot.
    fn remove_operator(
        &self,
        ctx: &OperatorContext,
        id: OperatorId,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Changes the role of an operator. Owner only; the last owner cannot be demoted.
    fn set_operator_role(
        &self,
        ctx: &OperatorContext,
        id: OperatorId,
        role: OperatorRole,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Changes the caller's own phrase (rewrap only, ADR-0014). Any role.
    fn change_phrase(
        &self,
        ctx: &OperatorContext,
        current: SecretString,
        new: SecretString,
    ) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Replaces the recovery key and returns the new text (shown once). Owner only.
    fn rotate_recovery_key(
        &self,
        ctx: &OperatorContext,
    ) -> impl Future<Output = Result<SecretString, CoreError>> + Send;
}

/// What opens the VMK.
enum Credential {
    Phrase(OperatorId, SecretString),
    Recovery(RecoveryKey),
}

fn problem(field: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }])
}

/// Checks a label against the `key_slots.label` rule.
pub(super) fn check_label(label: &str) -> Result<(), CoreError> {
    let chars = label.chars().count();
    if chars == 0 || chars > MAX_LABEL_CHARS || label.trim().is_empty() {
        return Err(problem("label", "must be 1..64 characters"));
    }
    Ok(())
}

/// Maps a crypto error of a slot change with a new phrase.
pub(super) fn map_new_phrase_error(error: CryptoError) -> CoreError {
    match error {
        CryptoError::WeakPhrase => problem(
            "phrase",
            "needs 12 characters or more and a strength score of 3 or more",
        ),
        // Derive refused the cost on this machine (DEC-073), or the cost is out of range.
        CryptoError::InvalidKdfParams => CoreError::UnsupportedKdfCost,
        other => CoreError::Crypto(other),
    }
}

/// The slot rows as the crypto crate sees them, with the slot rules checked.
pub(super) fn slot_set(vault_id: VaultId, rows: &[KeySlotRow]) -> Result<KeySlotSet, CoreError> {
    KeySlotSet::from_slots(vault_id, rows.iter().map(KeySlotRow::to_key_slot).collect())
        .map_err(|_| CoreError::Corrupt)
}

impl VaultService {
    async fn create_vault_impl(&self, new: NewVault) -> Result<CreatedVault, CoreError> {
        let _gate = self.inner.gate.lock().await;
        if self.inner.kind.load(Ordering::SeqCst) != KIND_NO_VAULT {
            return Err(CoreError::Conflict);
        }
        // A screen lock during create bumps the epoch; the new vault then stays sealed.
        let epoch = self.inner.epoch.load(Ordering::SeqCst);
        check_label(&new.owner_label)?;
        let now = self.inner.clock.now();
        let vault_id = VaultId::generate();
        let owner_id = KeySlotId::generate();
        let recovery_id = KeySlotId::generate();
        let NewVault {
            owner_label,
            phrase,
            kdf,
            host_names,
        } = new;
        let (vmk, set, recovery) = tokio::task::spawn_blocking(move || {
            let vmk = Vmk::generate()?;
            let mut set = KeySlotSet::create(vault_id, &vmk, owner_id, &phrase, kdf)?;
            let recovery = RecoveryKey::generate()?;
            set.set_recovery(&vmk, recovery_id, &recovery)?;
            Ok::<_, CryptoError>((vmk, set, recovery))
        })
        .await
        .map_err(|_| CoreError::Crypto(CryptoError::Kdf))?
        .map_err(map_new_phrase_error)?;
        let keys = KeyTree::derive(&vmk, &vault_id)?;

        let rows: Vec<KeySlotRow> = set
            .slots()
            .iter()
            .map(|slot| KeySlotRow {
                id: slot.id,
                kind: if slot.is_recovery() {
                    SlotKind::Recovery
                } else {
                    SlotKind::Passphrase
                },
                label: if slot.is_recovery() {
                    RECOVERY_LABEL.to_owned()
                } else {
                    owner_label.clone()
                },
                role: slot.role,
                material: slot.material.clone(),
                created_at: now,
                updated_at: now,
                last_unlock_at: (slot.id == owner_id).then_some(now),
            })
            .collect();
        let mut header = HeaderRow {
            format_version: FORMAT_VERSION,
            vault_id,
            created_at: now,
            failed_unlocks: 0,
            last_failed_unlock_at: None,
            header_mac: [0; 32],
        };
        header.header_mac = header_mac(&keys.header_key, &header, &rows);

        let ca = self.inner.config.ca_issuer.issue_ca(&vault_id, now)?;
        let keys = Arc::new(keys);
        let unlocked = Unlocked {
            session: Session {
                operator_id: owner_id,
                role: OperatorRole::Owner,
                unlocked_at: now,
                via_recovery: false,
            },
            vault_id,
            vmk: Arc::new(vmk),
            audit: self.audit_writer(&keys, vault_id),
            keys,
            index: Index::default(),
            header_ok: true,
        };
        let blobs = unlocked.blobs();
        let ca_row = TlsCaRow {
            ca_cert_der: ca.cert_der,
            ca_key_ct: blobs.seal_ca_key(ca.key_der.expose_secret())?,
            created_at: now,
            not_after: ca.not_after,
        };
        let hosts = serde_json::to_vec(&host_names).map_err(|_| CoreError::Corrupt)?;
        let hosts_row = SettingRow {
            key: HOST_NAMES_SETTING.to_owned(),
            updated_at: now,
            value_ct: blobs.seal_setting(HOST_NAMES_SETTING, &hosts)?,
        };
        self.inner.store.initialize(&header, &rows, &ca_row).await?;
        // From here the file is a vault. Later steps must not fail, or the recovery key is lost.
        let mut tx = self.inner.store.begin().await?;
        tx.put_setting(&hosts_row).await?;
        if let Err(error) = tx.commit().await {
            tracing::warn!(%error, "could not save the TLS host names");
        }
        self.inner
            .lock_settings
            .set(LockSettings::defaults(&self.inner.config));
        let event = AuditEvent::new(
            EventType::VaultCreate,
            Actor::operator(owner_id.to_string()),
        )
        .target("vault", vault_id.to_string());
        self.audit(&unlocked, event).await;
        match self.install(unlocked, epoch).await {
            // A lock came in during create: the vault is sealed, and the recovery key must still
            // reach the person (DEC-FIX5-6).
            Ok(()) | Err(CoreError::Locked) => {}
            Err(error) => return Err(error),
        }
        Ok(CreatedVault {
            owner_id,
            recovery_key: recovery.to_display(),
            ca_pin: ca.pin,
        })
    }

    async fn unlock_impl(&self, credential: Credential) -> Result<OperatorContext, CoreError> {
        let _gate = self.inner.gate.lock().await;
        match self.inner.kind.load(Ordering::SeqCst) {
            KIND_SEALED => {}
            KIND_NO_VAULT => return Err(CoreError::NoVault),
            _ => return Err(CoreError::Conflict),
        }
        let epoch = self.inner.epoch.load(Ordering::SeqCst);
        let now = self.inner.clock.now();
        let store = &self.inner.store;
        let header = store.header().await?;
        backoff::check(&header, now)?;
        let rows = store.key_slots().await?;
        let set = slot_set(header.vault_id, &rows)?;

        let via_recovery = matches!(credential, Credential::Recovery(_));
        let attempted = match &credential {
            Credential::Phrase(operator, _) => operator.to_string(),
            Credential::Recovery(_) => "recovery".to_owned(),
        };
        let opened = match credential {
            Credential::Phrase(operator, phrase) => {
                if set.get(&operator).is_none_or(|slot| slot.is_recovery()) {
                    // Unknown or removed operator: a failed unlock, without running the KDF.
                    Err(CryptoError::Integrity)
                } else {
                    blocking_raw(move || {
                        set.unlock_passphrase(&operator, &phrase)
                            .map(|(v, _)| (v, operator))
                    })
                    .await?
                }
            }
            Credential::Recovery(recovery) => {
                let id = set.recovery().map(|slot| slot.id);
                match id {
                    Some(id) => {
                        blocking_raw(move || set.unlock_recovery(&recovery).map(|(v, _)| (v, id)))
                            .await?
                    }
                    None => Err(CryptoError::Integrity),
                }
            }
        };
        let (vmk, slot_id) = match opened {
            Ok(found) => found,
            Err(CryptoError::Integrity | CryptoError::SlotRule) => {
                store.record_unlock_failure(now).await?;
                self.audit_pending(
                    EventType::VaultUnlockFailed,
                    None,
                    Some(attempted),
                    ErrorCode::Unauthenticated,
                    None,
                )
                .await;
                return Err(CoreError::BadCredentials);
            }
            Err(CryptoError::InvalidKdfParams) => return Err(CoreError::UnsupportedKdfCost),
            Err(other) => return Err(CoreError::Crypto(other)),
        };
        store.reset_unlock_failures().await?;
        let stored_role = rows
            .iter()
            .find(|row| row.id == slot_id)
            .map(|row| row.role)
            .ok_or(CoreError::Corrupt)?;

        let keys = Arc::new(KeyTree::derive(&vmk, &header.vault_id)?);
        let header_ok = verify_header_mac(&keys.header_key, &header, &rows);
        // The role column is covered only by the header MAC. When the MAC fails, the stored role
        // cannot be trusted: the session gets viewer rights, and slot changes are refused
        // (DEC-FIX5-4).
        let role = if header_ok {
            stored_role
        } else {
            OperatorRole::Viewer
        };
        let mut unlocked = Unlocked {
            session: Session {
                operator_id: slot_id,
                role,
                unlocked_at: now,
                via_recovery,
            },
            vault_id: header.vault_id,
            vmk: Arc::new(vmk),
            audit: self.audit_writer(&keys, header.vault_id).expecting_log(),
            keys,
            index: Index::default(),
            header_ok,
        };
        if !header_ok {
            tracing::warn!("vault header MAC mismatch at unlock");
        }
        let index_rows = store.load_all_for_index().await?;
        let (index, bad_rows) = self.build_index(&unlocked, index_rows).await;
        unlocked.index = index;
        if let Some(row) = rows.iter().find(|row| row.id == slot_id) {
            let mut row = row.clone();
            row.last_unlock_at = Some(now);
            let mut tx = store.begin().await?;
            tx.upsert_slot(&row).await?;
            tx.commit().await?;
        }
        // Before anything of this vault can serve a call: a vault put back from an old restore
        // file loses its agent keys and leases (T27-H, NEW-12). A failure fails the unlock.
        let recovery = self.revoke_after_recovery(&unlocked, now).await?;
        // Events recorded while locked happened first, so they join the chain first. A failed
        // drain is an integrity alert, not only a log line (AUD-9).
        if let Err(error) = unlocked.audit.drain_pending().await {
            tracing::warn!(%error, "pending audit events not moved into the chain");
            self.emit(CoreEvent::IntegrityAlert {
                table: "audit_pending",
                row_id: String::new(),
            });
        }
        if let Some(done) = recovery {
            self.report_recovery_revoke(&unlocked, done).await;
        }
        self.report_audit_break(&unlocked);
        for (table, row_id) in bad_rows {
            self.integrity_issue(&unlocked, table, row_id).await;
        }
        self.load_lock_settings(&unlocked).await?;
        self.rebuild_auth_verified(&unlocked, now).await?;
        self.finish_deferred_panic(&unlocked, now).await;
        let kind = if via_recovery {
            EventType::VaultUnlockRecovery
        } else {
            EventType::VaultUnlock
        };
        let event = AuditEvent::new(kind, Actor::operator(slot_id.to_string()))
            .target("vault", header.vault_id.to_string());
        self.audit(&unlocked, event).await;
        if !header_ok {
            let event = AuditEvent::new(EventType::VaultHeaderMismatch, Actor::system())
                .target("vault", header.vault_id.to_string())
                .result("vault_corrupt");
            self.audit(&unlocked, event).await;
        }
        self.install(unlocked, epoch).await?;
        Ok(OperatorContext {
            operator_id: slot_id,
            role,
            request_id: RequestId::generate(),
        })
    }

    /// Work right after an unlock, with no guard held: the approval timeouts and the
    /// `lease.expire` events for leases that ended while the vault was sealed or the process was
    /// down (DEC-WIRE6-6). A failure is logged; the expiry loop tries again.
    async fn after_unlock(&self) {
        let now = self.inner.clock.now();
        if let Err(error) = self.policy().expire_due(now).await {
            tracing::warn!(%error, "expiry run after unlock failed");
        }
        self.delete_sealed_expired(now).await;
        self.spawn_chain_check();
    }

    /// A chain writer for the vault, sharing `keys`.
    fn audit_writer(&self, keys: &Arc<KeyTree>, vault_id: VaultId) -> AuditWriter {
        AuditWriter::new(
            self.inner.store.clone(),
            Arc::clone(keys),
            vault_id,
            Arc::clone(&self.inner.clock),
        )
    }

    /// Opens all metadata rows into the index. A row that fails to open or parse is left out and
    /// returned, so the caller raises an integrity alert and writes it to the chain (ADR-0014: an
    /// open failure is corruption).
    async fn build_index(
        &self,
        unlocked: &Unlocked,
        rows: IndexRows,
    ) -> (Index, Vec<(&'static str, String)>) {
        let blobs = unlocked.blobs();
        let mut bad = Vec::new();
        let mut alert = |table: &'static str, id: String| {
            tracing::warn!(table, row_id = %id, "sealed metadata failed to open");
            bad.push((table, id));
        };
        let mut workspaces = Vec::with_capacity(rows.workspaces.len());
        for row in &rows.workspaces {
            match blobs
                .open_workspace_meta(&row.id, &row.meta_ct)
                .map_err(CoreError::from)
                .and_then(|plain| index::decode_workspace_meta(row, &plain))
            {
                Ok(meta) => workspaces.push(meta),
                Err(_) => alert("workspaces", row.id.to_string()),
            }
        }
        let mut grants = Vec::with_capacity(rows.grants.len());
        for row in &rows.grants {
            match blobs.open_grant_body(&row.id, &row.body_ct) {
                Ok(body) => grants.push(index::grant_entry(row, body)),
                Err(_) => alert("grants", row.id.to_string()),
            }
        }
        let (items, bad_items) = self.index_items(unlocked, &rows.items).await;
        bad.extend(bad_items);
        let mut index = Index::build(Vec::new(), workspaces, grants);
        for (meta, version) in items {
            index.upsert_item_at(meta, version);
        }
        (index, bad)
    }

    /// Revokes all leases when a panic could not do it before the last lock (DEC-FIX5-5). Runs at
    /// unlock, before the vault serves calls. On failure the request is kept for the next unlock.
    async fn finish_deferred_panic(&self, unlocked: &Unlocked, now: Timestamp) {
        let in_memory = self.take_revoke_at_unlock();
        let stored = match self.panic_setting(unlocked).await {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(%error, "could not read the pending panic revoke");
                None
            }
        };
        let Some(by) = in_memory.or(stored) else {
            return;
        };
        let macs = unlocked.row_macs();
        let work = async {
            let mut tx = self.inner.store.begin().await?;
            let revoked = tx.revoke_all_leases(now, &by, &macs).await?;
            let cancelled = tx.cancel_pending_requests(now, &macs).await?;
            tx.put_setting(&self.panic_setting_row(unlocked, None, now)?)
                .await?;
            tx.commit().await?;
            Ok::<_, CoreError>((revoked, cancelled))
        };
        match work.await {
            Ok((revoked, cancelled)) => {
                self.report_bad_macs(unlocked, &revoked, &cancelled).await;
                let revoked = revoked.revoked;
                let cancelled = cancelled.cancelled;
                for id in &cancelled {
                    self.emit(CoreEvent::AccessRequestResolved {
                        id: *id,
                        status: AccessRequestStatus::Cancelled,
                    });
                }
                let cancelled = cancelled.len();
                let event = AuditEvent::new(EventType::VaultPanic, Actor::operator(by))
                    .detail("deferred", true)
                    .detail("leases_revoked", revoked)
                    .detail("requests_cancelled", cancelled);
                self.audit(unlocked, event).await;
            }
            Err(error) => {
                tracing::warn!(%error, "pending panic revoke failed; kept for the next unlock");
                self.keep_revoke_at_unlock(by);
            }
        }
    }

    /// A vault file left by a restore was put back in place (`vault_recover_stranded`), and its
    /// `backup.recover` event still waits in `audit_pending` (T27-H, NEW-12). That file may be the
    /// vault a restore replaced, whose agent tokens the owner meant to stop, so every live agent
    /// key and lease is revoked and every pending request cancelled, in one transaction, before
    /// the vault serves any call. The pending row is the marker: it is drained into the chain only
    /// after this commit, so a crash in between runs the revoke again at the next unlock (a revoked
    /// key stays revoked). A key or lease whose row MAC is bad is left as it is: the token table
    /// treats such a key as revoked, and the alert is raised. `None` when no recovery waits.
    ///
    /// # Errors
    /// A storage or MAC error. The unlock then fails, so the old keys are never served.
    async fn revoke_after_recovery(
        &self,
        unlocked: &Unlocked,
        now: Timestamp,
    ) -> Result<Option<RecoveryRevoke>, CoreError> {
        let store = &self.inner.store;
        if !store
            .has_audit_pending(EventType::BackupRecover.as_str())
            .await?
        {
            return Ok(None);
        }
        let macs = unlocked.row_macs();
        let by = unlocked.session.operator_id.to_string();
        let (_, keys) = store.load_auth_rows().await?;
        let mut tx = store.begin().await?;
        let mut agent_keys: u64 = 0;
        for mut key in keys.into_iter().filter(|key| key.revoked_at.is_none()) {
            if !macs.verify_agent_key(&key)? {
                continue;
            }
            key.revoked_at = Some(now);
            macs.sign_agent_key(&mut key)?;
            if tx.update_live_agent_key(&key).await? {
                agent_keys = agent_keys.saturating_add(1);
            }
        }
        let leases = tx.revoke_all_leases(now, &by, &macs).await?;
        let requests = tx.cancel_pending_requests(now, &macs).await?;
        tx.commit().await?;
        Ok(Some(RecoveryRevoke {
            agent_keys,
            leases,
            requests,
        }))
    }

    /// Tells the waiters of the cancelled requests, raises the alerts for rows left out, and
    /// writes `backup.recover_revoke` after the drained `backup.recover` (T27-H).
    async fn report_recovery_revoke(&self, unlocked: &Unlocked, done: RecoveryRevoke) {
        self.report_bad_macs(unlocked, &done.leases, &done.requests)
            .await;
        for id in &done.requests.cancelled {
            self.emit(CoreEvent::AccessRequestResolved {
                id: *id,
                status: AccessRequestStatus::Cancelled,
            });
        }
        tracing::warn!(
            agent_keys = done.agent_keys,
            leases = done.leases.revoked,
            "a vault put back from an old restore file: its agent keys and leases were revoked"
        );
        let event = AuditEvent::new(
            EventType::BackupRecoverRevoke,
            Actor::operator(unlocked.session.operator_id.to_string()),
        )
        .target("vault", unlocked.vault_id.to_string())
        .detail("agent_keys_revoked", done.agent_keys)
        .detail("leases_revoked", done.leases.revoked)
        .detail("requests_cancelled", done.requests.cancelled.len());
        self.audit(unlocked, event).await;
    }

    /// The operator of a pending panic revoke in the sealed setting, if any.
    async fn panic_setting(&self, unlocked: &Unlocked) -> Result<Option<String>, CoreError> {
        let row = self.inner.store.setting(PANIC_REVOKE_SETTING).await;
        let value: Option<Option<String>> = self
            .read_setting(unlocked, row, PANIC_REVOKE_SETTING)
            .await?;
        Ok(value.flatten())
    }

    fn panic_setting_row(
        &self,
        unlocked: &Unlocked,
        by: Option<&str>,
        now: Timestamp,
    ) -> Result<SettingRow, CoreError> {
        let plain = serde_json::to_vec(&by).map_err(|_| CoreError::Corrupt)?;
        Ok(SettingRow {
            key: PANIC_REVOKE_SETTING.to_owned(),
            updated_at: now,
            value_ct: unlocked
                .blobs()
                .seal_setting(PANIC_REVOKE_SETTING, &plain)?,
        })
    }

    /// Saves (or clears, with `None`) the pending panic revoke.
    pub(super) async fn put_panic_setting(
        &self,
        unlocked: &Unlocked,
        by: Option<&str>,
    ) -> Result<(), CoreError> {
        let row = self.panic_setting_row(unlocked, by, self.inner.clock.now())?;
        let mut tx = self.inner.store.begin().await?;
        tx.put_setting(&row).await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Runs slot work (Argon2id, about 0.7 s) on the blocking pool. The crypto error stays for the
/// caller to map.
pub(super) async fn blocking_raw<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, CryptoError> + Send + 'static,
) -> Result<Result<T, CryptoError>, CoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| CoreError::Crypto(CryptoError::Kdf))
}

impl KeyCustody for VaultService {
    async fn create_vault(&self, new: NewVault) -> Result<CreatedVault, CoreError> {
        self.create_vault_impl(new).await
    }

    async fn unlock_with_phrase(
        &self,
        operator: OperatorId,
        phrase: SecretString,
    ) -> Result<OperatorContext, CoreError> {
        let ctx = self
            .unlock_impl(Credential::Phrase(operator, phrase))
            .await?;
        self.after_unlock().await;
        Ok(ctx)
    }

    async fn unlock_with_recovery(
        &self,
        recovery: RecoveryKey,
    ) -> Result<OperatorContext, CoreError> {
        let ctx = self.unlock_impl(Credential::Recovery(recovery)).await?;
        self.after_unlock().await;
        Ok(ctx)
    }

    async fn lock(&self, reason: LockReason) -> Result<(), CoreError> {
        self.lock_inner(reason, None).await.map(|_| ())
    }

    async fn panic_lock(&self, ctx: &OperatorContext) -> Result<(), CoreError> {
        // During a pending lock the panic joins it: the erase that runs first revokes the leases.
        let operator = match self.locking_session_operator() {
            Some(id) if id == ctx.operator_id => id,
            Some(_) => return Err(CoreError::Forbidden),
            None => {
                let guard = self.authorize(ctx, OperatorRole::Viewer).await?;
                guard.session.operator_id
            }
        };
        self.request_panic(operator);
        self.lock_inner(LockReason::PanicButton, Some(operator))
            .await
            .map(|_| ())
    }

    async fn list_operators(&self) -> Result<Vec<OperatorInfo>, CoreError> {
        self.list_operators_impl().await
    }

    async fn add_operator(
        &self,
        ctx: &OperatorContext,
        label: String,
        role: OperatorRole,
        phrase: SecretString,
    ) -> Result<OperatorId, CoreError> {
        self.add_operator_impl(ctx, label, role, phrase).await
    }

    async fn remove_operator(
        &self,
        ctx: &OperatorContext,
        id: OperatorId,
    ) -> Result<(), CoreError> {
        self.remove_operator_impl(ctx, id).await
    }

    async fn set_operator_role(
        &self,
        ctx: &OperatorContext,
        id: OperatorId,
        role: OperatorRole,
    ) -> Result<(), CoreError> {
        self.set_operator_role_impl(ctx, id, role).await
    }

    async fn change_phrase(
        &self,
        ctx: &OperatorContext,
        current: SecretString,
        new: SecretString,
    ) -> Result<(), CoreError> {
        self.change_phrase_with_kdf(ctx, current, new, None).await
    }

    async fn rotate_recovery_key(&self, ctx: &OperatorContext) -> Result<SecretString, CoreError> {
        self.rotate_recovery_key_impl(ctx).await
    }
}
