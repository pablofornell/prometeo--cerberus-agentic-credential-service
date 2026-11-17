//! Create, unlock, lock, back-off, recovery and key erasure.

use std::sync::Arc;

use cerberus_crypto::{KdfParams, Key32, KeyTree, RecoveryKey, Vmk};
use cerberus_types::{LockReason, OperatorRole, VaultStateKind};
use zeroize::ZeroizeOnDrop;

use super::fixture::*;
use crate::error::CoreError;
use crate::vault::state::VaultState;
use crate::vault::{CoreEvent, KeyCustody, LockSettings, NewVault};

async fn unlock_owner(fixture: &Fixture, owner: cerberus_types::OperatorId) {
    fixture
        .service
        .unlock_with_phrase(owner, phrase(OWNER_PHRASE))
        .await
        .unwrap();
}

#[tokio::test]
async fn no_vault_state_allows_only_create() {
    let fixture = Fixture::empty().await;
    let service = &fixture.service;
    assert_eq!(service.state(), VaultStateKind::NoVault);
    let some_id = cerberus_types::KeySlotId::generate();
    assert!(matches!(
        service
            .unlock_with_phrase(some_id, phrase(OWNER_PHRASE))
            .await,
        Err(CoreError::NoVault)
    ));
    assert!(matches!(
        service.list_operators().await,
        Err(CoreError::NoVault)
    ));
    assert!(matches!(service.unlocked().await, Err(CoreError::NoVault)));
    service.lock(LockReason::Manual).await.unwrap();
}

#[tokio::test]
async fn create_unlocks_as_owner_and_cannot_run_twice() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert_eq!(service.state(), VaultStateKind::Unlocked);
    let status = service.status().await;
    let session = status.session.unwrap();
    assert_eq!(session.operator_id, created.owner_id);
    assert_eq!(session.role, OperatorRole::Owner);
    assert!(status.header_ok);
    assert_eq!(created.ca_pin, "sha256/fake-pin");
    assert!(created.recovery_key.expose_secret().starts_with("CRK1-"));
    let operators = service.list_operators().await.unwrap();
    assert_eq!(operators.len(), 1, "the recovery slot is not an operator");
    assert_eq!(operators[0].label, "Owner");
    assert_eq!(
        service.lock_settings(&ctx).await.unwrap(),
        LockSettings::defaults(&config())
    );
    let again = service
        .create_vault(NewVault {
            owner_label: "Other".to_owned(),
            phrase: phrase(SECOND_PHRASE),
            kdf: kdf(),
            host_names: Vec::new(),
        })
        .await;
    assert!(matches!(again, Err(CoreError::Conflict)));
}

#[tokio::test]
async fn create_refuses_a_weak_phrase_a_bad_label_and_a_capped_cost() {
    let fixture = Fixture::empty().await;
    let new = |label: &str, text: &str, kdf: KdfParams| NewVault {
        owner_label: label.to_owned(),
        phrase: phrase(text),
        kdf,
        host_names: Vec::new(),
    };
    let weak = fixture
        .service
        .create_vault(new("Owner", "short", kdf()))
        .await;
    assert!(matches!(weak, Err(CoreError::Validation(p)) if p[0].field == "phrase"));
    let label = fixture
        .service
        .create_vault(new("", OWNER_PHRASE, kdf()))
        .await;
    assert!(matches!(label, Err(CoreError::Validation(p)) if p[0].field == "label"));
    // t = 11 is inside the file range but above the derive cap of 10 (DEC-073).
    let capped = KdfParams::new(19_456, 11, 1).unwrap();
    let cost = fixture
        .service
        .create_vault(new("Owner", OWNER_PHRASE, capped))
        .await;
    assert!(matches!(cost, Err(CoreError::UnsupportedKdfCost)));
    assert_eq!(fixture.service.state(), VaultStateKind::NoVault);
}

#[tokio::test]
async fn wrong_phrase_fails_and_counts() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    service.lock(LockReason::Manual).await.unwrap();
    let wrong = service
        .unlock_with_phrase(created.owner_id, phrase(WRONG_PHRASE))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    assert_eq!(service.store().header().await.unwrap().failed_unlocks, 1);
    assert_eq!(service.state(), VaultStateKind::Sealed);
    let unknown = service
        .unlock_with_phrase(cerberus_types::KeySlotId::generate(), phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(unknown, Err(CoreError::BadCredentials)));
    assert_eq!(service.store().header().await.unwrap().failed_unlocks, 2);
    unlock_owner(&fixture, created.owner_id).await;
    assert_eq!(service.store().header().await.unwrap().failed_unlocks, 0);
    let twice = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(twice, Err(CoreError::Conflict)));
}

#[tokio::test]
async fn recovery_key_unlocks_as_owner_and_cannot_change_a_phrase() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    service.lock(LockReason::Manual).await.unwrap();
    let key = RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    let ctx = service.unlock_with_recovery(key).await.unwrap();
    assert_eq!(ctx.role, OperatorRole::Owner);
    assert!(service.status().await.session.unwrap().via_recovery);
    let change = service
        .change_phrase(&ctx, phrase(OWNER_PHRASE), phrase(NEW_PHRASE))
        .await;
    assert!(matches!(change, Err(CoreError::Conflict)));
    service.lock(LockReason::Manual).await.unwrap();
    let other = RecoveryKey::generate().unwrap();
    assert!(matches!(
        service.unlock_with_recovery(other).await,
        Err(CoreError::BadCredentials)
    ));
}

#[tokio::test]
async fn back_off_grows_and_survives_a_restart() {
    let (fixture, created, _ctx) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let try_with = |text: &'static str| {
        let service = fixture.service.clone();
        let owner = created.owner_id;
        async move { service.unlock_with_phrase(owner, phrase(text)).await }
    };
    for _ in 0..5 {
        assert!(matches!(
            try_with(WRONG_PHRASE).await,
            Err(CoreError::BadCredentials)
        ));
    }
    // After 5 failures: wait 1 s. The right phrase is refused too, and the KDF does not run.
    assert!(matches!(
        try_with(OWNER_PHRASE).await,
        Err(CoreError::UnlockBackoff {
            retry_after_seconds: 1
        })
    ));
    fixture.advance(1);
    assert!(matches!(
        try_with(WRONG_PHRASE).await,
        Err(CoreError::BadCredentials)
    ));
    assert!(matches!(
        try_with(WRONG_PHRASE).await,
        Err(CoreError::UnlockBackoff {
            retry_after_seconds: 2
        })
    ));

    // A restart keeps the counter (it is in the header).
    let restarted = fixture.reopen().await;
    assert_eq!(restarted.state(), VaultStateKind::Sealed);
    let refused = restarted
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(
        refused,
        Err(CoreError::UnlockBackoff {
            retry_after_seconds: 2
        })
    ));
    fixture.advance(2);
    restarted
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert_eq!(restarted.store().header().await.unwrap().failed_unlocks, 0);
}

#[tokio::test]
async fn too_high_kdf_cost_in_the_file_is_not_a_wrong_phrase() {
    let (fixture, created, _ctx) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE key_slots SET t_cost = 11 WHERE kind = 'passphrase'")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    let result = fixture
        .service
        .unlock_with_phrase(created.owner_id, phrase(WRONG_PHRASE))
        .await;
    assert!(matches!(result, Err(CoreError::UnsupportedKdfCost)));
    assert_eq!(
        fixture
            .service
            .store()
            .header()
            .await
            .unwrap()
            .failed_unlocks,
        0,
        "not counted"
    );
    // The recovery slot has no Argon2 cost and still opens the vault.
    let key = RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    fixture.service.unlock_with_recovery(key).await.unwrap();
}

#[test]
fn key_types_zeroize_on_drop() {
    fn zeroizes<T: ZeroizeOnDrop>() {}
    zeroizes::<Vmk>();
    zeroizes::<Key32>();
    zeroizes::<RecoveryKey>();
    // `KeyTree` is six `Key32` fields; its drop drops each of them.
    let _fields = |tree: KeyTree| -> [Key32; 6] {
        [
            tree.item_kek,
            tree.meta_key,
            tree.audit_key,
            tree.ca_key,
            tree.header_key,
            tree.row_mac_key,
        ]
    };
}

#[tokio::test]
async fn lock_drops_every_key_and_the_index() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    fixture.add_item("Fake Item").await;
    service.lock(LockReason::Manual).await.unwrap();
    unlock_owner(&fixture, created.owner_id).await;
    let (keys, vmk) = {
        let guard = service.unlocked().await.unwrap();
        assert_eq!(guard.index.item_count(), 1, "index built from sealed rows");
        (Arc::downgrade(&guard.keys), Arc::downgrade(&guard.vmk))
    };
    let mut events = service.subscribe();
    service.lock(LockReason::Manual).await.unwrap();
    assert!(keys.upgrade().is_none(), "key tree dropped");
    assert!(vmk.upgrade().is_none(), "VMK dropped");
    assert!(matches!(
        &*service.inner.state.read().await,
        VaultState::Sealed
    ));
    assert_eq!(service.state(), VaultStateKind::Sealed);
    assert!(matches!(
        events.try_recv(),
        Ok(CoreEvent::StateChanged(VaultStateKind::Sealed))
    ));
}

#[tokio::test]
async fn emergency_wipe_drops_keys_without_await() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let keys = {
        let guard = fixture.service.unlocked().await.unwrap();
        Arc::downgrade(&guard.keys)
    };
    fixture.service.emergency_wipe();
    assert!(keys.upgrade().is_none());
    assert_eq!(fixture.service.state(), VaultStateKind::Sealed);
}

#[tokio::test]
async fn every_call_is_refused_while_sealed() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    service.lock(LockReason::Manual).await.unwrap();
    let locked = |r: Result<(), CoreError>| matches!(r, Err(CoreError::Locked));
    assert!(locked(
        service
            .add_operator(
                &ctx,
                "Second".to_owned(),
                OperatorRole::Viewer,
                phrase(SECOND_PHRASE)
            )
            .await
            .map(|_| ())
    ));
    assert!(locked(
        service.remove_operator(&ctx, created.owner_id).await
    ));
    assert!(locked(
        service
            .set_operator_role(&ctx, created.owner_id, OperatorRole::Viewer)
            .await
    ));
    assert!(locked(
        service
            .change_phrase(&ctx, phrase(OWNER_PHRASE), phrase(NEW_PHRASE))
            .await
    ));
    assert!(locked(service.rotate_recovery_key(&ctx).await.map(|_| ())));
    assert!(locked(service.panic_lock(&ctx).await));
    assert!(locked(service.lock_settings(&ctx).await.map(|_| ())));
    assert!(locked(
        service
            .set_lock_settings(&ctx, LockSettings::defaults(&config()))
            .await
    ));
    assert!(locked(service.unlocked().await.map(|_| ())));
    assert!(locked(service.unlocked_mut().await.map(|_| ())));
    assert!(service.status().await.session.is_none());
    assert_eq!(service.run_auto_lock_once(fixture.clock_now()).await, None);
    // Lock and the operator list still work.
    service.lock(LockReason::Manual).await.unwrap();
    assert_eq!(service.list_operators().await.unwrap().len(), 1);
}

#[tokio::test]
async fn lock_cancels_requests_and_panic_also_revokes_leases() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let item = fixture.add_item("Leased").await;
    let (lease, request) = fixture.add_lease_and_request(item).await;
    service.lock(LockReason::Manual).await.unwrap();
    let store = service.store();
    assert_eq!(
        store.access_request(request).await.unwrap().status,
        cerberus_types::AccessRequestStatus::Cancelled
    );
    assert!(
        store.lease(lease).await.unwrap().revoked_at.is_none(),
        "lock keeps leases"
    );

    let ctx = {
        unlock_owner(&fixture, created.owner_id).await;
        ctx_for(ctx.operator_id, OperatorRole::Owner)
    };
    let (lease2, _) = fixture.add_lease_and_request(item).await;
    service.panic_lock(&ctx).await.unwrap();
    assert_eq!(service.state(), VaultStateKind::Sealed);
    for id in [lease, lease2] {
        let row = store.lease(id).await.unwrap();
        assert!(row.revoked_at.is_some());
        assert_eq!(
            row.revoked_by.as_deref(),
            Some(created.owner_id.to_string().as_str())
        );
    }
    // The new row MACs are valid.
    unlock_owner(&fixture, created.owner_id).await;
    let guard = service.unlocked().await.unwrap();
    let macs = guard.row_macs();
    assert!(
        macs.verify_lease(&store.lease(lease).await.unwrap())
            .unwrap()
    );
    assert!(
        macs.verify_access_request(&store.access_request(request).await.unwrap())
            .unwrap()
    );
}

#[tokio::test]
async fn a_changed_header_opens_with_an_alert() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let second = service
        .add_operator(
            &ctx,
            "Second".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE key_slots SET role = 'owner' WHERE id = ?1")
        .bind(second.to_string())
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    let mut events = service.subscribe();
    unlock_owner(&fixture, created.owner_id).await;
    assert!(!service.status().await.header_ok);
    let mut seen = false;
    while let Ok(event) = events.try_recv() {
        seen |= matches!(event, CoreEvent::HeaderMismatch);
    }
    assert!(seen);
}

#[tokio::test]
async fn a_changed_item_blob_is_left_out_of_the_index() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let good = fixture.add_item("Good").await;
    let bad = fixture.add_item("Bad").await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    // Move the good item's sealed metadata into the bad row: the AAD binds the item ID.
    sqlx::query(
        "UPDATE items SET meta_ct = (SELECT meta_ct FROM items WHERE id = ?1) WHERE id = ?2",
    )
    .bind(good.to_string())
    .bind(bad.to_string())
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;
    let mut events = fixture.service.subscribe();
    unlock_owner(&fixture, created.owner_id).await;
    let guard = fixture.service.unlocked().await.unwrap();
    assert!(guard.index.item(&good).is_some());
    assert!(guard.index.item(&bad).is_none());
    let mut alert = false;
    while let Ok(event) = events.try_recv() {
        alert |= matches!(event, CoreEvent::IntegrityAlert { table: "items", ref row_id } if *row_id == bad.to_string());
    }
    assert!(alert);
}

#[tokio::test]
async fn custody_futures_are_send() {
    fn send<T: Send>(_: &T) {}
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    send(&service.unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE)));
    send(&service.lock(LockReason::Manual));
    send(&service.panic_lock(&ctx));
    send(&service.change_phrase(&ctx, phrase(OWNER_PHRASE), phrase(NEW_PHRASE)));
    send(&service.rotate_recovery_key(&ctx));
}

#[tokio::test]
async fn after_a_recovery_unlock_the_owner_sets_a_new_phrase() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let normal = service
        .reset_phrase_after_recovery(&ctx, created.owner_id, phrase(NEW_PHRASE), None)
        .await;
    assert!(
        matches!(normal, Err(CoreError::Conflict)),
        "needs a recovery session"
    );
    service.lock(LockReason::Manual).await.unwrap();
    let key = RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    let rctx = service.unlock_with_recovery(key).await.unwrap();
    service
        .reset_phrase_after_recovery(&rctx, created.owner_id, phrase(NEW_PHRASE), None)
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    service
        .unlock_with_phrase(created.owner_id, phrase(NEW_PHRASE))
        .await
        .unwrap();
    assert!(service.status().await.header_ok);
}
