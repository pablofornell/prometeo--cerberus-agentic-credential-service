//! The status view: KDF cost, last lock reason and the failed unlock count (DEC-INT10-8 to 10).

use cerberus_crypto::RecoveryKey;
use cerberus_types::{LockReason, VaultStateKind};

use super::fixture::*;
use crate::error::CoreError;
use crate::vault::{FREE_UNLOCK_FAILURES, KeyCustody, OsEvent};

#[tokio::test]
async fn status_shows_the_kdf_cost_of_the_session_slot() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert_eq!(service.status().await.kdf, Some(kdf()));

    service.lock(LockReason::Manual).await.unwrap();
    assert_eq!(service.status().await.kdf, None, "sealed: no session");

    let key = RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    service.unlock_with_recovery(key).await.unwrap();
    assert_eq!(
        service.status().await.kdf,
        None,
        "the recovery slot has no passphrase KDF"
    );
}

#[tokio::test]
async fn status_shows_the_reason_of_the_latest_lock() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert_eq!(service.status().await.last_lock_reason, None);

    service.lock(LockReason::Manual).await.unwrap();
    let status = service.status().await;
    assert_eq!(status.state, VaultStateKind::Sealed);
    assert_eq!(status.last_lock_reason, Some(LockReason::Manual));

    let unlock = || service.unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE));
    unlock().await.unwrap();
    fixture.advance(1_801);
    assert_eq!(
        service.run_auto_lock_once(fixture.clock_now()).await,
        Some(LockReason::Idle)
    );
    assert_eq!(
        service.status().await.last_lock_reason,
        Some(LockReason::Idle)
    );

    unlock().await.unwrap();
    assert!(service.handle_os_event(OsEvent::Sleep).await);
    assert_eq!(
        service.status().await.last_lock_reason,
        Some(LockReason::OsLock)
    );

    let ctx = unlock().await.unwrap();
    service.panic_lock(&ctx).await.unwrap();
    assert_eq!(
        service.status().await.last_lock_reason,
        Some(LockReason::PanicButton)
    );
}

#[tokio::test]
async fn status_counts_failed_unlocks_and_the_back_off() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    let fresh = service.status().await;
    assert_eq!(
        (
            fresh.failed_unlocks,
            fresh.free_unlock_tries_left,
            fresh.retry_after_seconds
        ),
        (0, FREE_UNLOCK_FAILURES, 0)
    );

    service.lock(LockReason::Manual).await.unwrap();
    for done in 1..FREE_UNLOCK_FAILURES {
        let wrong = service
            .unlock_with_phrase(created.owner_id, phrase(WRONG_PHRASE))
            .await;
        assert!(matches!(wrong, Err(CoreError::BadCredentials)));
        let status = service.status().await;
        assert_eq!(status.failed_unlocks, done);
        assert_eq!(status.free_unlock_tries_left, FREE_UNLOCK_FAILURES - done);
        assert_eq!(status.retry_after_seconds, 0);
    }

    // The fifth failure starts the back-off: 1 second, then 2.
    let wrong = service
        .unlock_with_phrase(created.owner_id, phrase(WRONG_PHRASE))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    let status = service.status().await;
    assert_eq!(status.failed_unlocks, FREE_UNLOCK_FAILURES);
    assert_eq!(status.free_unlock_tries_left, 0);
    assert_eq!(status.retry_after_seconds, 1);
    let refused = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(
        refused,
        Err(CoreError::UnlockBackoff {
            retry_after_seconds: 1
        })
    ));

    fixture.advance(1);
    assert_eq!(service.status().await.retry_after_seconds, 0);
    assert_eq!(
        service.status().await.failed_unlocks,
        FREE_UNLOCK_FAILURES,
        "the count stays until a good unlock"
    );

    // The count is in the header: a restart keeps it.
    let restarted = fixture.reopen().await;
    assert_eq!(
        restarted.status().await.failed_unlocks,
        FREE_UNLOCK_FAILURES
    );

    service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let status = service.status().await;
    assert_eq!(
        (status.failed_unlocks, status.free_unlock_tries_left),
        (0, FREE_UNLOCK_FAILURES)
    );
}
