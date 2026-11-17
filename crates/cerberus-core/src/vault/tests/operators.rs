//! Operator slots, roles, phrase change and recovery key rotation.

use cerberus_crypto::{KdfParams, RecoveryKey};
use cerberus_types::{KeySlotId, LockReason, OperatorRole};

use super::fixture::*;
use crate::error::CoreError;
use crate::vault::KeyCustody;

#[tokio::test]
async fn change_phrase_keeps_data_and_old_phrase_stops_working() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let item = fixture.add_item("Kept Item").await;
    let wrong = service
        .change_phrase(&ctx, phrase(WRONG_PHRASE), phrase(NEW_PHRASE))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    assert_eq!(
        service.store().header().await.unwrap().failed_unlocks,
        0,
        "a wrong current phrase is not a failed unlock"
    );
    let weak = service
        .change_phrase(&ctx, phrase(OWNER_PHRASE), phrase("short"))
        .await;
    assert!(matches!(weak, Err(CoreError::Validation(_))));
    service
        .change_phrase(&ctx, phrase(OWNER_PHRASE), phrase(NEW_PHRASE))
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    assert!(matches!(
        service
            .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
            .await,
        Err(CoreError::BadCredentials)
    ));
    service
        .unlock_with_phrase(created.owner_id, phrase(NEW_PHRASE))
        .await
        .unwrap();
    {
        let guard = service.unlocked().await.unwrap();
        assert_eq!(
            guard.index.item(&item).map(|m| m.title.as_str()),
            Some("Kept Item")
        );
    }
    assert!(service.status().await.header_ok, "header MAC was updated");
    service.lock(LockReason::Manual).await.unwrap();
    let key = RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    service.unlock_with_recovery(key).await.unwrap();
}

#[tokio::test]
async fn change_phrase_can_set_a_new_cost() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let stronger = KdfParams::new(19_456, 2, 1).unwrap();
    service
        .change_phrase_with_kdf(
            &ctx,
            phrase(OWNER_PHRASE),
            phrase(NEW_PHRASE),
            Some(stronger),
        )
        .await
        .unwrap();
    let rows = service.store().key_slots().await.unwrap();
    let owner = rows.iter().find(|r| r.id == created.owner_id).unwrap();
    assert_eq!(
        owner.material.kdf,
        cerberus_crypto::SlotKdf::Argon2id(stronger)
    );
}

#[tokio::test]
async fn removed_operator_cannot_unlock() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let second = service
        .add_operator(
            &ctx,
            "Second".to_owned(),
            OperatorRole::Operator,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let second_ctx = service
        .unlock_with_phrase(second, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    assert_eq!(second_ctx.role, OperatorRole::Operator);
    service.lock(LockReason::Manual).await.unwrap();
    let ctx = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    service.remove_operator(&ctx, second).await.unwrap();
    assert_eq!(service.list_operators().await.unwrap().len(), 1);
    assert!(service.status().await.header_ok);
    service.lock(LockReason::Manual).await.unwrap();
    assert!(matches!(
        service
            .unlock_with_phrase(second, phrase(SECOND_PHRASE))
            .await,
        Err(CoreError::BadCredentials)
    ));
}

#[tokio::test]
async fn viewer_cannot_do_owner_or_operator_actions() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let viewer = service
        .add_operator(
            &ctx,
            "Viewer".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let vctx = service
        .unlock_with_phrase(viewer, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    let denied = |r: Result<(), CoreError>| matches!(r, Err(CoreError::RoleNotAllowed));
    assert!(denied(
        service
            .add_operator(
                &vctx,
                "X".to_owned(),
                OperatorRole::Owner,
                phrase(NEW_PHRASE)
            )
            .await
            .map(|_| ())
    ));
    assert!(denied(
        service.remove_operator(&vctx, created.owner_id).await
    ));
    assert!(denied(
        service
            .set_operator_role(&vctx, viewer, OperatorRole::Owner)
            .await
    ));
    assert!(denied(service.rotate_recovery_key(&vctx).await.map(|_| ())));
    // A viewer may change its own phrase, and may lock or press panic.
    service
        .change_phrase(&vctx, phrase(SECOND_PHRASE), phrase(NEW_PHRASE))
        .await
        .unwrap();
    service.panic_lock(&vctx).await.unwrap();
    service
        .unlock_with_phrase(viewer, phrase(NEW_PHRASE))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_context_of_another_session_is_refused() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let other = ctx_for(KeySlotId::generate(), OperatorRole::Owner);
    assert!(matches!(
        fixture.service.rotate_recovery_key(&other).await,
        Err(CoreError::Forbidden)
    ));
    // The role in the context is not trusted: the session role counts.
    let viewer = fixture
        .service
        .add_operator(
            &ctx,
            "Viewer".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    fixture.service.lock(LockReason::Manual).await.unwrap();
    fixture
        .service
        .unlock_with_phrase(viewer, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    let forged = ctx_for(viewer, OperatorRole::Owner);
    assert!(matches!(
        fixture.service.rotate_recovery_key(&forged).await,
        Err(CoreError::RoleNotAllowed)
    ));
}

#[tokio::test]
async fn last_owner_and_own_slot_are_protected() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert!(matches!(
        service
            .set_operator_role(&ctx, created.owner_id, OperatorRole::Viewer)
            .await,
        Err(CoreError::Conflict)
    ));
    assert!(matches!(
        service.remove_operator(&ctx, created.owner_id).await,
        Err(CoreError::Conflict)
    ));
    assert!(matches!(
        service.remove_operator(&ctx, KeySlotId::generate()).await,
        Err(CoreError::NotFound)
    ));
    let recovery = service
        .store()
        .key_slots()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.kind == cerberus_store::SlotKind::Recovery)
        .unwrap();
    assert!(matches!(
        service.remove_operator(&ctx, recovery.id).await,
        Err(CoreError::NotFound)
    ));
    // With a second owner, the first can step down; the session role follows.
    service
        .add_operator(
            &ctx,
            "Owner Two".to_owned(),
            OperatorRole::Owner,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service
        .set_operator_role(&ctx, created.owner_id, OperatorRole::Operator)
        .await
        .unwrap();
    assert_eq!(
        service.status().await.session.unwrap().role,
        OperatorRole::Operator
    );
    assert!(matches!(
        service.rotate_recovery_key(&ctx).await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        service
            .add_operator(
                &ctx,
                "Owner Two".to_owned(),
                OperatorRole::Viewer,
                phrase(NEW_PHRASE)
            )
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
}

#[tokio::test]
async fn duplicate_label_is_refused() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let result = fixture
        .service
        .add_operator(
            &ctx,
            "Owner".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await;
    assert!(matches!(result, Err(CoreError::Validation(p)) if p[0].field == "label"));
}

#[tokio::test]
async fn rotate_recovery_key_replaces_the_old_key() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let new_text = service.rotate_recovery_key(&ctx).await.unwrap();
    assert_ne!(
        new_text.expose_secret(),
        created.recovery_key.expose_secret()
    );
    let slots = service.store().key_slots().await.unwrap();
    assert_eq!(
        slots
            .iter()
            .filter(|r| r.kind == cerberus_store::SlotKind::Recovery)
            .count(),
        1
    );
    assert!(service.status().await.header_ok);
    service.lock(LockReason::Manual).await.unwrap();
    let old = RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    assert!(matches!(
        service.unlock_with_recovery(old).await,
        Err(CoreError::BadCredentials)
    ));
    let new = RecoveryKey::parse(new_text.expose_secret()).unwrap();
    service.unlock_with_recovery(new).await.unwrap();
    assert!(service.status().await.header_ok);
}
