//! Many tasks read while the vault locks. No read may see keys or metadata once `lock` returned.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use cerberus_types::{LockReason, VaultStateKind};

use super::fixture::*;
use crate::error::CoreError;
use crate::vault::KeyCustody;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_never_see_data_after_lock_returns() {
    let (fixture, created, _ctx) = Fixture::created().await;
    for n in 0..20 {
        fixture.add_item(&format!("Item {n}")).await;
    }
    fixture.service.lock(LockReason::Manual).await.unwrap();
    for round in 0..5 {
        let ctx = fixture
            .service
            .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
            .await
            .unwrap();
        let lock_done = Arc::new(AtomicBool::new(false));
        let reads_ok = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for task in 0..64 {
            let service = fixture.service.clone();
            let lock_done = lock_done.clone();
            let reads_ok = reads_ok.clone();
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let started_after_lock = lock_done.load(Ordering::SeqCst);
                    let result = if task % 2 == 0 {
                        service.unlocked().await.map(|guard| {
                            // Still holding the guard: the lock cannot have returned.
                            assert!(!lock_done.load(Ordering::SeqCst), "read during lock");
                            assert_eq!(guard.index.item_count(), 20);
                            guard.keys.meta_key.expose_secret()[0]
                        })
                    } else {
                        service.lock_settings(&ctx).await.map(|_| 0)
                    };
                    match result {
                        Ok(_) => {
                            assert!(!started_after_lock, "data after lock returned");
                            reads_ok.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(CoreError::Locked) => {
                            if lock_done.load(Ordering::SeqCst) {
                                return;
                            }
                        }
                        Err(other) => panic!("unexpected error {other:?}"),
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }
        tokio::time::sleep(Duration::from_millis(5 + round * 3)).await;
        fixture.service.lock(LockReason::Manual).await.unwrap();
        lock_done.store(true, Ordering::SeqCst);
        assert_eq!(fixture.service.state(), VaultStateKind::Sealed);
        for task in tasks {
            task.await.unwrap();
        }
        assert!(
            reads_ok.load(Ordering::SeqCst) > 0,
            "reads ran before the lock"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_lock_requests_at_once_all_end_sealed() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let keys = {
        let guard = fixture.service.unlocked().await.unwrap();
        Arc::downgrade(&guard.keys)
    };
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let service = fixture.service.clone();
        tasks.push(tokio::spawn(async move {
            service.lock(LockReason::Manual).await.unwrap();
            assert_eq!(service.state(), VaultStateKind::Sealed);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert!(keys.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_during_an_unlock_leaves_the_vault_sealed() {
    let (fixture, created, _ctx) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let unlocking = {
        let service = fixture.service.clone();
        tokio::spawn(async move {
            service
                .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
                .await
        })
    };
    // The KDF of the unlock takes far longer than this.
    tokio::time::sleep(Duration::from_millis(20)).await;
    fixture.service.lock(LockReason::OsLock).await.unwrap();
    let result = unlocking.await.unwrap();
    if result.is_ok() {
        // The unlock finished first; the lock ran after it and then sealed the vault.
        assert_eq!(fixture.service.state(), VaultStateKind::Sealed);
    } else {
        assert!(matches!(result, Err(CoreError::Locked)));
    }
    assert_eq!(fixture.service.state(), VaultStateKind::Sealed);
    assert!(matches!(
        fixture.service.unlocked().await,
        Err(CoreError::Locked)
    ));
}
