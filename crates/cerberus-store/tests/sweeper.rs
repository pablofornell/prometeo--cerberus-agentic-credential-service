//! The expiry sweeper works while locked: it uses the clock and plain columns only, never a key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use cerberus_store::{StoreError, Sweeper};
use cerberus_types::{AccessRequestStatus, ItemKind};
use common::{Fixture, at, file_contains};
use jiff::SignedDuration;
use tokio::sync::mpsc;

#[tokio::test]
async fn sweeper_deletes_expired_rows_while_locked_with_a_manual_clock() {
    let fx = Fixture::new().await;
    // Everything below is written with keys. After this block the test holds no key use: the vault is "locked".
    let (token, token_v) = fx.item(ItemKind::SessionToken, Some(at(3600)), "tok");
    let (soon, soon_v) = fx.item(ItemKind::ApiKey, Some(at(60)), "soon");
    let (keeper, keeper_v) = fx.item(ItemKind::ApiKey, None, "keep");
    let (later, later_v) = fx.item(ItemKind::ApiKey, Some(at(100_000)), "later");
    let agent = fx.agent("s");
    let old_lease = fx.lease(&agent, &keeper, at(100));
    let live_lease = fx.lease(&agent, &keeper, at(90_000));
    let old_request = fx.request(&agent, &keeper, AccessRequestStatus::Denied, at(100), "old");
    let new_request = fx.request(
        &agent,
        &keeper,
        AccessRequestStatus::Pending,
        at(90_000),
        "new",
    );
    let mut tx = fx.store.begin().await.unwrap();
    for (item, version) in [
        (&token, &token_v),
        (&soon, &soon_v),
        (&keeper, &keeper_v),
        (&later, &later_v),
    ] {
        tx.insert_item(item, version).await.unwrap();
    }
    tx.put_agent(&agent).await.unwrap();
    tx.put_lease(&old_lease).await.unwrap();
    tx.put_lease(&live_lease).await.unwrap();
    tx.put_access_request(&old_request).await.unwrap();
    tx.put_access_request(&new_request).await.unwrap();
    tx.commit().await.unwrap();

    let mut sweeper = Sweeper::new(fx.store.clone());

    // Nothing is due yet.
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert!(report.expired_items.is_empty());
    assert_eq!(
        (
            report.leases_deleted,
            report.requests_deleted,
            report.vacuumed
        ),
        (0, 0, false)
    );

    // 61 s later: only `soon` has expired.
    fx.clock.advance(SignedDuration::from_secs(61));
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(report.expired_items, vec![soon.id]);
    assert!(
        report.vacuumed,
        "first delete triggers the first full VACUUM"
    );
    assert!(matches!(
        fx.store.item(soon.id).await,
        Err(StoreError::NotFound)
    ));

    // One hour later (3661 s): the session token has expired as well. Old lease and request are older than the grace times? No:
    // the lease is 1 h past expiry only after 3700 s, the request is kept 7 days.
    fx.clock.advance(SignedDuration::from_secs(3600));
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(report.expired_items, vec![token.id]);
    assert_eq!(report.leases_deleted, 0);
    assert!(!report.vacuumed, "a second full VACUUM waits 24 h");

    fx.clock.advance(SignedDuration::from_secs(100));
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(report.leases_deleted, 1, "old lease: 1 h past its expiry");
    assert_eq!(report.requests_deleted, 0);

    // 8 days later: the finished request is deleted too, and `later` has expired.
    fx.clock.advance(SignedDuration::from_hours(8 * 24));
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(report.expired_items, vec![later.id]);
    assert_eq!(
        report.requests_deleted, 2,
        "the denied one, and the pending one that expired 7 days ago"
    );
    assert_eq!(report.leases_deleted, 1);
    assert!(report.vacuumed, "more than 24 h since the last full VACUUM");

    // Only the item without expiry is left.
    let rows = fx.store.load_all_for_index().await.unwrap();
    assert_eq!(
        rows.items.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![keeper.id]
    );
    // The versions of the deleted items went with them.
    assert!(matches!(
        fx.store.item_version(token.id, 1).await,
        Err(StoreError::NotFound)
    ));

    // Each expiry left an `item.expire` event for the audit chain.
    let take = fx.store.take_audit_pending().await.unwrap();
    let (events, overflow) = (take.rows, take.overflow);
    assert_eq!(overflow, 0);
    let expired: Vec<_> = events
        .iter()
        .map(|event| event.target_id.clone().unwrap())
        .collect();
    assert_eq!(
        expired,
        vec![
            soon.id.to_string(),
            token.id.to_string(),
            later.id.to_string()
        ]
    );
    assert!(
        events
            .iter()
            .all(|event| event.event_type == "item.expire" && event.result_code == "ok")
    );
}

#[tokio::test]
async fn deleted_rows_leave_no_bytes_in_the_file_or_wal() {
    // `secure_delete` and the WAL checkpoint: raw marker bytes in a deleted row must be gone.
    // The store does not look inside blobs, so a recognizable raw value stands in for a sealed one.
    let fx = Fixture::new().await;
    let (mut item, version) = fx.item(ItemKind::SessionToken, Some(at(60)), "gone");
    item.meta_ct = b"RAW-DELETED-ROW-MARKER-0123456789".to_vec();
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.commit().await.unwrap();
    assert!(
        file_contains(&fx.path, "RAW-DELETED-ROW-MARKER"),
        "the marker is stored before the sweep"
    );

    fx.clock.advance(SignedDuration::from_secs(61));
    let mut sweeper = Sweeper::new(fx.store.clone());
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(report.expired_items, vec![item.id]);
    assert!(
        !file_contains(&fx.path, "RAW-DELETED-ROW-MARKER"),
        "the marker survived the sweep"
    );
}

#[tokio::test]
async fn spawned_sweeper_reports_work_and_ends_with_its_receiver() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::SessionToken, Some(at(60)), "sp");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.commit().await.unwrap();
    fx.clock.advance(SignedDuration::from_secs(61));

    let (sender, mut receiver) = mpsc::channel(4);
    let handle = Sweeper::new(fx.store.clone()).spawn(
        Duration::from_millis(20),
        Arc::new(fx.clock.clone()),
        sender,
    );
    let report = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.expired_items, vec![item.id]);
    drop(receiver);
    // Every sweep sends its report, so the next sweep finds the closed channel and the task ends.
    let (extra, extra_v) = fx.item(ItemKind::SessionToken, Some(at(70)), "sp2");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&extra, &extra_v).await.unwrap();
    tx.commit().await.unwrap();
    fx.clock.advance(SignedDuration::from_secs(20));
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .unwrap()
        .unwrap();
}

/// ADR-0019 point 7: a revoked auto lease blocks new auto leases until its old end, so the
/// sweeper keeps it until then. Other revoked or released leases go 1 h after that.
#[tokio::test]
async fn sweeper_keeps_revoked_auto_leases_until_their_end() {
    let fx = Fixture::new().await;
    let (keeper, keeper_v) = fx.item(ItemKind::ApiKey, None, "keep");
    let agent = fx.agent("s");
    let sign = |mut row: cerberus_store::LeaseRow| {
        fx.macs().sign_lease(&mut row).unwrap();
        row
    };
    let mut revoked_auto = fx.lease(&agent, &keeper, at(86_400));
    revoked_auto.revoked_at = Some(at(10));
    revoked_auto.revoked_by = Some("operator:x".to_owned());
    let revoked_auto = sign(revoked_auto);
    let mut revoked_approval = fx.lease(&agent, &keeper, at(86_400));
    revoked_approval.source = cerberus_store::LeaseSource::Approval;
    revoked_approval.revoked_at = Some(at(10));
    revoked_approval.revoked_by = Some("operator:x".to_owned());
    let revoked_approval = sign(revoked_approval);
    let mut released_auto = fx.lease(&agent, &keeper, at(86_400));
    released_auto.released_at = Some(at(10));
    let released_auto = sign(released_auto);
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&keeper, &keeper_v).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    for row in [&revoked_auto, &revoked_approval, &released_auto] {
        tx.put_lease(row).await.unwrap();
    }
    tx.commit().await.unwrap();

    let mut sweeper = Sweeper::new(fx.store.clone());
    fx.clock.advance(SignedDuration::from_secs(3700));
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(report.leases_deleted, 2, "approval and released rows go");
    assert!(fx.store.lease(revoked_auto.id).await.is_ok());

    fx.clock.advance(SignedDuration::from_secs(86_400));
    let report = sweeper.run_once(fx.clock_now()).await.unwrap();
    assert_eq!(
        report.leases_deleted, 1,
        "after its old end the revoked auto row goes"
    );
    assert!(matches!(
        fx.store.lease(revoked_auto.id).await,
        Err(StoreError::NotFound)
    ));
}
