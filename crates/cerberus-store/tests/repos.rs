//! Repositories: items and versions, agents and keys, leases, requests, row MACs, audit, pending events.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use cerberus_store::{
    AgentStatus, AuditHeadRow, AuditPendingRow, AuditRow, GrantRow, SettingRow, StoreError,
    WorkspaceRow,
};
use cerberus_types::{AccessRequestStatus, GrantId, ItemId, ItemKind, Permission, WorkspaceId, t0};
use common::{Fixture, at, raw};

#[tokio::test]
async fn item_with_versions_round_trips_and_old_versions_are_cut() {
    let fx = Fixture::new().await;
    let blobs = fx.blobs();
    let (mut item, first) = fx.item(ItemKind::ApiKey, None, "v1");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &first).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(fx.store.item(item.id).await.unwrap(), item);
    assert_eq!(fx.store.item_version(item.id, 1).await.unwrap(), first);

    for number in 2..=4_u32 {
        let sealed = blobs
            .seal_payload(&item.id, number, format!("payload {number}").as_bytes())
            .unwrap();
        item.current_version = number;
        item.updated_at = at(i64::from(number));
        item.meta_ct = blobs.seal_item_meta(&item.id, number, b"meta").unwrap();
        let version = cerberus_store::ItemVersionRow {
            item_id: item.id,
            version: number,
            created_at: at(i64::from(number)),
            wrapped_dek: sealed.wrapped_dek,
            payload_ct: sealed.payload_ct,
            meta_ct: blobs.seal_item_snapshot(&item.id, number, b"meta").unwrap(),
        };
        let mut tx = fx.store.begin().await.unwrap();
        tx.add_item_version(&item, &version, 2).await.unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(fx.store.item(item.id).await.unwrap().current_version, 4);
    assert!(matches!(
        fx.store.item_version(item.id, 1).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fx.store.item_version(item.id, 2).await,
        Err(StoreError::NotFound)
    ));
    fx.store.item_version(item.id, 3).await.unwrap();
    let last = fx.store.item_version(item.id, 4).await.unwrap();
    let last_again = last.clone();
    let opened = blobs
        .open_payload(
            &item.id,
            4,
            &cerberus_store::SealedPayload {
                wrapped_dek: last.wrapped_dek,
                payload_ct: last.payload_ct,
            },
        )
        .unwrap();
    assert_eq!(opened.expose_secret(), b"payload 4");

    // A version that does not match the item row is refused.
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.add_item_version(&item, &last_again, 2).await,
        Err(StoreError::Conflict)
    ));
}

#[tokio::test]
async fn version_snapshot_can_be_replaced_without_touching_the_payload() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::Note, None, "s");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.commit().await.unwrap();
    let blobs = fx.blobs();
    let snapshot = blobs
        .seal_item_snapshot(&item.id, 1, b"changed meta")
        .unwrap();
    let mut tx = fx.store.begin().await.unwrap();
    tx.update_version_meta(item.id, 1, &snapshot).await.unwrap();
    assert!(matches!(
        tx.update_version_meta(item.id, 2, &snapshot).await,
        Err(StoreError::NotFound)
    ));
    tx.commit().await.unwrap();
    let row = fx.store.item_version(item.id, 1).await.unwrap();
    assert_eq!(row.meta_ct, snapshot);
    assert_eq!(row.payload_ct, version.payload_ct);
    assert_eq!(row.wrapped_dek, version.wrapped_dek);
}

#[tokio::test]
async fn expired_items_are_invisible_at_once() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::SessionToken, Some(at(100)), "e");
    let (keeper, keeper_version) = fx.item(ItemKind::Note, None, "k");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.insert_item(&keeper, &keeper_version).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(fx.store.load_all_for_index().await.unwrap().items.len(), 2);
    fx.clock.set(at(100));
    assert!(matches!(
        fx.store.item(item.id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fx.store.item_version(item.id, 1).await,
        Err(StoreError::NotFound)
    ));
    let rows = fx.store.load_all_for_index().await.unwrap();
    assert_eq!(
        rows.items.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![keeper.id]
    );
}

#[tokio::test]
async fn delete_item_removes_versions_leases_and_requests() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::Note, None, "d");
    let agent = fx.agent("d");
    let lease = fx.lease(&agent, &item, at(500));
    let request = fx.request(&agent, &item, AccessRequestStatus::Pending, at(500), "d");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_lease(&lease).await.unwrap();
    tx.put_access_request(&request).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = fx.store.begin().await.unwrap();
    assert!(tx.delete_item(item.id).await.unwrap());
    assert!(
        !tx.delete_item(item.id).await.unwrap(),
        "second delete finds nothing"
    );
    tx.commit().await.unwrap();
    let db = raw(&fx.path).await;
    for table in ["item_versions", "leases", "access_requests"] {
        let count: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[tokio::test]
async fn a_dropped_transaction_rolls_back() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::Note, None, "r");
    {
        let mut tx = fx.store.begin().await.unwrap();
        tx.insert_item(&item, &version).await.unwrap();
    }
    assert!(matches!(
        fx.store.item(item.id).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn schema_constraints_surface_as_conflict() {
    let fx = Fixture::new().await;
    // A session token must have an expiry.
    let (no_expiry, version) = fx.item(ItemKind::SessionToken, None, "c");
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.insert_item(&no_expiry, &version).await,
        Err(StoreError::Conflict)
    ));
    drop(tx);

    // Duplicate secret hash, key for an unknown agent.
    let agent = fx.agent("c");
    let one = fx.agent_key(&agent, 7);
    let two = fx.agent_key(&agent, 7);
    let mut tx = fx.store.begin().await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_agent_key(&one).await.unwrap();
    assert!(matches!(
        tx.put_agent_key(&two).await,
        Err(StoreError::Conflict)
    ));
    drop(tx);
    let stranger = fx.agent("stranger");
    let orphan = fx.agent_key(&stranger, 8);
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.put_agent_key(&orphan).await,
        Err(StoreError::Conflict)
    ));
    drop(tx);

    // Missing rows.
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.delete_grant(GrantId::generate()).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        tx.delete_workspace(WorkspaceId::generate()).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        tx.update_item_meta(&no_expiry).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn only_one_recovery_slot_and_kind_must_match_the_kdf() {
    let fx = Fixture::new().await;
    let mut slots = fx.store.key_slots().await.unwrap();
    let mut recovery = slots.remove(0);
    recovery.id = cerberus_types::KeySlotId::generate();
    // A passphrase slot marked as a recovery slot.
    recovery.kind = cerberus_store::SlotKind::Recovery;
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.upsert_slot(&recovery).await,
        Err(StoreError::Conflict)
    ));
    drop(tx);
    // Deleting the owner slot works at this layer (the slot rules belong to cerberus-crypto).
    let mut tx = fx.store.begin().await.unwrap();
    tx.delete_slot(fx.owner).await.unwrap();
    assert!(matches!(
        tx.delete_slot(fx.owner).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn auth_rows_load_while_locked_and_row_macs_catch_changes() {
    let fx = Fixture::new().await;
    let agent = fx.agent("m");
    let key = fx.agent_key(&agent, 9);
    let (item, version) = fx.item(ItemKind::ApiKey, None, "m");
    let lease = fx.lease(&agent, &item, at(600));
    let request = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "m");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_agent_key(&key).await.unwrap();
    tx.put_lease(&lease).await.unwrap();
    tx.put_access_request(&request).await.unwrap();
    tx.commit().await.unwrap();

    let macs = fx.macs();
    let (agents, keys) = fx.store.load_auth_rows().await.unwrap();
    assert_eq!((agents.len(), keys.len()), (1, 1));
    assert_eq!(keys[0], key);
    assert!(macs.verify_agent(&agents[0]).unwrap());
    assert!(macs.verify_agent_key(&keys[0]).unwrap());
    let leases = fx
        .store
        .active_leases(agent.id, item.id, at(1))
        .await
        .unwrap();
    assert_eq!(leases, vec![lease.clone()]);
    assert!(macs.verify_lease(&leases[0]).unwrap());
    let stored_request = fx.store.access_request(request.id).await.unwrap();
    assert!(macs.verify_access_request(&stored_request).unwrap());

    // Touching `last_used_at` is allowed while locked and does not break the MAC.
    let mut tx = fx.store.begin().await.unwrap();
    tx.touch_agent_key(key.id, at(5)).await.unwrap();
    tx.commit().await.unwrap();
    let (_, keys) = fx.store.load_auth_rows().await.unwrap();
    assert_eq!(keys[0].last_used_at, Some(at(5)));
    assert!(macs.verify_agent_key(&keys[0]).unwrap());

    // Each forgery below is made with raw SQL, as someone with the file and no key would.
    let db = raw(&fx.path).await;
    sqlx::query("UPDATE agent_keys SET scopes = 'secrets:read secrets:write'")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("UPDATE agents SET status = 'suspended'")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("UPDATE leases SET expires_at = expires_at + 86400000")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("UPDATE access_requests SET status = 'approved'")
        .execute(&db)
        .await
        .unwrap();
    let (agents, keys) = fx.store.load_auth_rows().await.unwrap();
    assert!(!macs.verify_agent(&agents[0]).unwrap());
    assert!(!macs.verify_agent_key(&keys[0]).unwrap());
    assert!(
        !macs
            .verify_lease(&fx.store.lease(lease.id).await.unwrap())
            .unwrap()
    );
    assert!(
        !macs
            .verify_access_request(&fx.store.access_request(request.id).await.unwrap())
            .unwrap()
    );
    // Each of the other columns is covered too: clearing a revoke, a new key hash, the TTL, the uses.
    let mut forged = keys[0].clone();
    forged.revoked_at = Some(at(1));
    assert!(!macs.verify_agent_key(&forged).unwrap());
}

#[tokio::test]
async fn a_row_mac_made_with_another_key_or_vault_does_not_verify() {
    let fx = Fixture::new().await;
    let agent = fx.agent("k");
    let other_key = cerberus_crypto::Key32::random().unwrap();
    let other = cerberus_store::RowMacs::new(&other_key, &fx.vault_id);
    assert!(!other.verify_agent(&agent).unwrap());
    let other_vault = cerberus_types::VaultId::generate();
    let moved = cerberus_store::RowMacs::new(&fx.keys.row_mac_key, &other_vault);
    assert!(!moved.verify_agent(&agent).unwrap());
    // The MAC binds the table: an agent MAC is not a key MAC even for the same bytes.
    assert!(fx.macs().verify_agent(&agent).unwrap());
}

#[tokio::test]
async fn revoke_all_leases_and_cancel_pending_keep_valid_macs() {
    let fx = Fixture::new().await;
    let agent = fx.agent("p");
    let (item, version) = fx.item(ItemKind::ApiKey, None, "p");
    let live = fx.lease(&agent, &item, at(600));
    let mut released = fx.lease(&agent, &item, at(600));
    released.released_at = Some(at(10));
    fx.macs().sign_lease(&mut released).unwrap();
    let pending = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "p");
    let denied = fx.request(&agent, &item, AccessRequestStatus::Denied, at(600), "p2");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_lease(&live).await.unwrap();
    tx.put_lease(&released).await.unwrap();
    tx.put_access_request(&pending).await.unwrap();
    tx.put_access_request(&denied).await.unwrap();
    tx.commit().await.unwrap();

    let macs = fx.macs();
    let mut tx = fx.store.begin().await.unwrap();
    assert_eq!(
        tx.revoke_all_leases(at(20), "panic", &macs)
            .await
            .unwrap()
            .revoked,
        1
    );
    assert_eq!(
        tx.cancel_pending_requests(at(20), &macs)
            .await
            .unwrap()
            .cancelled,
        vec![pending.id]
    );
    tx.commit().await.unwrap();

    let live_after = fx.store.lease(live.id).await.unwrap();
    assert_eq!(
        (live_after.revoked_at, live_after.revoked_by.as_deref()),
        (Some(at(20)), Some("panic"))
    );
    assert!(macs.verify_lease(&live_after).unwrap());
    let released_after = fx.store.lease(released.id).await.unwrap();
    assert_eq!(released_after, released, "a released lease is left alone");
    assert!(
        fx.store
            .active_leases(agent.id, item.id, at(21))
            .await
            .unwrap()
            .is_empty()
    );
    let cancelled = fx.store.access_request(pending.id).await.unwrap();
    assert_eq!(cancelled.status, AccessRequestStatus::Cancelled);
    assert!(macs.verify_access_request(&cancelled).unwrap());
    assert_eq!(fx.store.access_request(denied.id).await.unwrap(), denied);
    assert!(fx.store.pending_access_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn workspaces_settings_grants_and_agents_round_trip() {
    let fx = Fixture::new().await;
    let blobs = fx.blobs();
    let workspace_id = WorkspaceId::generate();
    let workspace = WorkspaceRow {
        id: workspace_id,
        created_at: t0(),
        updated_at: t0(),
        meta_ct: blobs.seal_workspace_meta(&workspace_id, b"name").unwrap(),
    };
    let mut agent = fx.agent("g");
    let grant_id = GrantId::generate();
    let grant = GrantRow {
        id: grant_id,
        agent_id: agent.id,
        created_at: t0(),
        updated_at: t0(),
        expires_at: Some(at(50)),
        body_ct: blobs.seal_grant_body(&grant_id, b"body").unwrap(),
    };
    let setting = SettingRow {
        key: "idle_lock_seconds".to_owned(),
        updated_at: t0(),
        value_ct: blobs.seal_setting("idle_lock_seconds", b"900").unwrap(),
    };
    let mut tx = fx.store.begin().await.unwrap();
    tx.put_workspace(&workspace).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_grant(&grant).await.unwrap();
    tx.put_setting(&setting).await.unwrap();
    tx.commit().await.unwrap();

    let rows = fx.store.load_all_for_index().await.unwrap();
    assert_eq!(rows.workspaces, vec![workspace.clone()]);
    assert_eq!(rows.agents, vec![agent.clone()]);
    assert_eq!(rows.grants, vec![grant.clone()]);
    assert_eq!(
        fx.store.setting("idle_lock_seconds").await.unwrap(),
        setting
    );
    assert_eq!(fx.store.settings().await.unwrap(), vec![setting.clone()]);
    assert!(matches!(
        fx.store.setting("nope").await,
        Err(StoreError::NotFound)
    ));

    // An expired grant leaves the index.
    fx.clock.set(at(50));
    assert!(
        fx.store
            .load_all_for_index()
            .await
            .unwrap()
            .grants
            .is_empty()
    );

    // Replace an agent, delete a grant and a workspace.
    agent.status = AgentStatus::Revoked;
    fx.macs().sign_agent(&mut agent).unwrap();
    let mut tx = fx.store.begin().await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.delete_grant(grant_id).await.unwrap();
    tx.delete_workspace(workspace_id).await.unwrap();
    tx.commit().await.unwrap();
    let rows = fx.store.load_all_for_index().await.unwrap();
    assert_eq!(rows.agents, vec![agent]);
    assert!(rows.grants.is_empty() && rows.workspaces.is_empty());
}

fn audit(seq: u64) -> (AuditRow, AuditHeadRow) {
    (
        AuditRow {
            seq,
            occurred_at: at(i64::try_from(seq).unwrap()),
            prev_hash: [1; 32],
            hmac: [2; 32],
            body_ct: vec![3; 40],
        },
        AuditHeadRow {
            last_seq: seq,
            last_entry_hash: [4; 32],
            anchor_seq: 1,
            anchor_prev_hash: [1; 32],
            head_hmac: [5; 32],
        },
    )
}

#[tokio::test]
async fn audit_log_is_append_only_and_prunes_only_through_the_guard() {
    let fx = Fixture::new().await;
    assert!(fx.store.audit_head().await.unwrap().is_none());
    for seq in 1..=5 {
        let (row, head) = audit(seq);
        let mut tx = fx.store.begin().await.unwrap();
        tx.append_audit(&row, &head).await.unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(fx.store.audit_head().await.unwrap().unwrap().last_seq, 5);
    let rows = fx.store.audit_range(2, 3).await.unwrap();
    assert_eq!(
        rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![2, 3, 4]
    );

    // A head that does not match the row is refused, and a repeated seq is a conflict.
    let (row, mut head) = audit(6);
    head.last_seq = 9;
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.append_audit(&row, &head).await,
        Err(StoreError::Conflict)
    ));
    drop(tx);
    let (again, again_head) = audit(5);
    let mut tx = fx.store.begin().await.unwrap();
    assert!(matches!(
        tx.append_audit(&again, &again_head).await,
        Err(StoreError::Conflict)
    ));
    drop(tx);

    // Raw UPDATE and DELETE are stopped by the triggers.
    let db = raw(&fx.path).await;
    assert!(
        sqlx::query("UPDATE audit_events SET hmac = zeroblob(32) WHERE seq = 3")
            .execute(&db)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM audit_events WHERE seq = 3")
            .execute(&db)
            .await
            .is_err()
    );

    // Prune through the store works and closes the guard again.
    let mut head = audit(5).1;
    head.anchor_seq = 3;
    let mut tx = fx.store.begin().await.unwrap();
    assert_eq!(tx.prune_audit(3, &head).await.unwrap(), 2);
    tx.commit().await.unwrap();
    let rows = fx.store.audit_range(0, 100).await.unwrap();
    assert_eq!(
        rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    assert_eq!(fx.store.audit_head().await.unwrap().unwrap().anchor_seq, 3);
    assert!(
        sqlx::query("DELETE FROM audit_events WHERE seq = 3")
            .execute(&db)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pending_audit_events_cap_overflow_and_drain() {
    let fx = Fixture::new().await;
    let event = |n: i64| AuditPendingRow {
        occurred_at: at(n),
        event_type: "api.locked_call".to_owned(),
        agent_id: None,
        target_id: None,
        result_code: "vault_locked".to_owned(),
        route: Some("/v1/credentials/{id}/reveal".to_owned()),
        request_id: Some(cerberus_types::RequestId::generate()),
    };
    for n in 0..5 {
        fx.store.push_audit_pending(&event(n), 3).await.unwrap();
    }
    let take = fx.store.take_audit_pending().await.unwrap();
    let (rows, overflow) = (take.rows, take.overflow);
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows.iter().map(|row| row.occurred_at).collect::<Vec<_>>(),
        vec![at(0), at(1), at(2)]
    );
    assert_eq!(overflow, 2);
    let take = fx.store.take_audit_pending().await.unwrap();
    let (rows, overflow) = (take.rows, take.overflow);
    assert!(rows.is_empty());
    assert_eq!(overflow, 0);
}

#[tokio::test]
async fn pending_audit_events_taken_in_a_transaction_survive_a_rollback() {
    let fx = Fixture::new().await;
    let event = |n: i64| AuditPendingRow {
        occurred_at: at(n),
        event_type: "api.locked_call".to_owned(),
        agent_id: None,
        target_id: None,
        result_code: "vault_locked".to_owned(),
        route: None,
        request_id: None,
    };
    for n in 0..3 {
        fx.store.push_audit_pending(&event(n), 2).await.unwrap();
    }
    // Take, then drop the transaction without a commit (a failure or a crash before the append).
    let mut tx = fx.store.begin().await.unwrap();
    let take = tx.take_audit_pending().await.unwrap();
    let (rows, overflow) = (take.rows, take.overflow);
    assert_eq!((rows.len(), overflow), (2, 1));
    drop(tx);
    let take = fx.store.take_audit_pending().await.unwrap();
    let (rows, overflow) = (take.rows, take.overflow);
    assert_eq!(
        rows.iter().map(|row| row.occurred_at).collect::<Vec<_>>(),
        vec![at(0), at(1)]
    );
    assert_eq!(overflow, 1);

    // Committed, the take is final.
    for n in 0..2 {
        fx.store.push_audit_pending(&event(n), 2).await.unwrap();
    }
    let mut tx = fx.store.begin().await.unwrap();
    tx.take_audit_pending().await.unwrap();
    tx.commit().await.unwrap();
    let take = fx.store.take_audit_pending().await.unwrap();
    let (rows, overflow) = (take.rows, take.overflow);
    assert!(rows.is_empty());
    assert_eq!(overflow, 0);
}

#[tokio::test]
async fn permission_and_enum_values_survive_a_round_trip() {
    let fx = Fixture::new().await;
    let agent = fx.agent("u");
    let (item, version) = fx.item(ItemKind::Certificate, None, "u");
    let mut lease = fx.lease(&agent, &item, at(60));
    lease.permission = Permission::UseSsh;
    lease.source = cerberus_store::LeaseSource::Approval;
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_lease(&lease).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(fx.store.lease(lease.id).await.unwrap(), lease);
    let _ = ItemId::generate();
}

/// AUD-7: a forged lease row (bad MAC) is not signed again by revoke-all.
#[tokio::test]
async fn revoke_all_leases_never_signs_a_forged_row() {
    let fx = Fixture::new().await;
    let agent = fx.agent("f");
    let (item, version) = fx.item(ItemKind::ApiKey, None, "f");
    let good = fx.lease(&agent, &item, at(600));
    let mut forged = fx.lease(&agent, &item, at(9_000));
    forged.row_mac = [7; 32];
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_lease(&good).await.unwrap();
    tx.put_lease(&forged).await.unwrap();
    tx.commit().await.unwrap();

    let macs = fx.macs();
    let mut tx = fx.store.begin().await.unwrap();
    let report = tx.revoke_all_leases(at(20), "panic", &macs).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(report.revoked, 1);
    assert_eq!(report.bad_mac, vec![forged.id]);
    let forged_after = fx.store.lease(forged.id).await.unwrap();
    assert_eq!(forged_after, forged, "the forged row is left as it was");
    assert!(!macs.verify_lease(&forged_after).unwrap());
    assert!(
        macs.verify_lease(&fx.store.lease(good.id).await.unwrap())
            .unwrap()
    );
}

/// AUD-7: a forged pending request (bad MAC) is not signed again by cancel-pending.
#[tokio::test]
async fn cancel_pending_requests_never_signs_a_forged_row() {
    let fx = Fixture::new().await;
    let agent = fx.agent("g");
    let (item, version) = fx.item(ItemKind::ApiKey, None, "g");
    let good = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "g1");
    let mut forged = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "g2");
    forged.row_mac = [9; 32];
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_access_request(&good).await.unwrap();
    tx.put_access_request(&forged).await.unwrap();
    tx.commit().await.unwrap();

    let macs = fx.macs();
    let mut tx = fx.store.begin().await.unwrap();
    let report = tx.cancel_pending_requests(at(20), &macs).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(report.cancelled, vec![good.id]);
    assert_eq!(report.bad_mac, vec![forged.id]);
    let forged_after = fx.store.access_request(forged.id).await.unwrap();
    assert_eq!(forged_after.status, AccessRequestStatus::Pending);
    assert!(!macs.verify_access_request(&forged_after).unwrap());
}

/// NEW-3: a lease or request row that cannot be read (a bad ID) is counted and left alone; the
/// other rows are still revoked and cancelled, so one bad row cannot block the panic revoke.
#[tokio::test]
async fn an_unreadable_row_does_not_stop_revoke_all_or_cancel_pending() {
    let fx = Fixture::new().await;
    let agent = fx.agent("n");
    let (item, version) = fx.item(ItemKind::ApiKey, None, "n");
    let good = fx.lease(&agent, &item, at(600));
    let pending = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "n1");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_lease(&good).await.unwrap();
    tx.put_access_request(&pending).await.unwrap();
    tx.commit().await.unwrap();
    let pool = raw(&fx.path).await;
    let mut conn = pool.acquire().await.unwrap();
    for (copy, insert, id) in [
        (
            "CREATE TEMP TABLE copy AS SELECT * FROM leases WHERE id = ?1",
            "INSERT INTO leases SELECT * FROM copy",
            good.id.to_string(),
        ),
        (
            "CREATE TEMP TABLE copy AS SELECT * FROM access_requests WHERE id = ?1",
            "INSERT INTO access_requests SELECT * FROM copy",
            pending.id.to_string(),
        ),
    ] {
        sqlx::query(copy)
            .bind(&id)
            .execute(&mut *conn)
            .await
            .unwrap();
        for sql in [
            "UPDATE copy SET id = 'not-a-uuid'",
            insert,
            "DROP TABLE copy",
        ] {
            sqlx::query(sql).execute(&mut *conn).await.unwrap();
        }
    }
    drop(conn);
    pool.close().await;

    let macs = fx.macs();
    let mut tx = fx.store.begin().await.unwrap();
    let revoked = tx.revoke_all_leases(at(20), "panic", &macs).await.unwrap();
    let cancelled = tx.cancel_pending_requests(at(20), &macs).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!((revoked.revoked, revoked.malformed), (1, 1));
    assert!(revoked.bad_mac.is_empty());
    assert_eq!(cancelled.cancelled, vec![pending.id]);
    assert_eq!(cancelled.malformed, 1);
    let after = fx.store.lease(good.id).await.unwrap();
    assert_eq!(after.revoked_by.as_deref(), Some("panic"));
    assert!(macs.verify_lease(&after).unwrap());
    assert_eq!(
        fx.store.access_request(pending.id).await.unwrap().status,
        AccessRequestStatus::Cancelled
    );
}

/// NEW-3 (rest, T27-E): a file attacker deletes the `items` or `agents` row that a live lease or a
/// pending request points to, with a SQLite tool where foreign keys are off. The row still parses
/// and its MAC is good, so it is revoked or cancelled like the others, and no write of the
/// revoke-all touches the parent columns (an UPSERT would fail with `FOREIGN KEY constraint failed`).
#[tokio::test]
async fn a_lease_whose_parent_row_is_gone_is_still_revoked() {
    let fx = Fixture::new().await;
    let agent = fx.agent("o");
    let other_agent = fx.agent("p");
    let (gone_item, gone_version) = fx.item(ItemKind::ApiKey, None, "o");
    let (item, version) = fx.item(ItemKind::ApiKey, None, "p");
    let item_gone = fx.lease(&agent, &gone_item, at(600));
    let agent_gone = fx.lease(&other_agent, &item, at(600));
    let fine = fx.lease(&agent, &item, at(600));
    let request_gone = fx.request(
        &agent,
        &gone_item,
        AccessRequestStatus::Pending,
        at(600),
        "o1",
    );
    let request_fine = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "o2");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&gone_item, &gone_version).await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_agent(&other_agent).await.unwrap();
    for lease in [&item_gone, &agent_gone, &fine] {
        tx.put_lease(lease).await.unwrap();
    }
    tx.put_access_request(&request_gone).await.unwrap();
    tx.put_access_request(&request_fine).await.unwrap();
    tx.commit().await.unwrap();
    let pool = raw(&fx.path).await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("DELETE FROM items WHERE id = ?1")
        .bind(gone_item.id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("DELETE FROM agents WHERE id = ?1")
        .bind(other_agent.id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    pool.close().await;

    let macs = fx.macs();
    let mut tx = fx.store.begin().await.unwrap();
    let revoked = tx.revoke_all_leases(at(20), "panic", &macs).await.unwrap();
    let cancelled = tx.cancel_pending_requests(at(20), &macs).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!((revoked.revoked, revoked.malformed), (3, 0));
    assert!(revoked.bad_mac.is_empty());
    let mut ids = cancelled.cancelled.clone();
    ids.sort();
    let mut want = vec![request_gone.id, request_fine.id];
    want.sort();
    assert_eq!(ids, want);
    for lease in [&item_gone, &agent_gone, &fine] {
        let after = fx.store.lease(lease.id).await.unwrap();
        assert_eq!(after.revoked_by.as_deref(), Some("panic"));
        assert_eq!(
            (after.agent_id, after.item_id),
            (lease.agent_id, lease.item_id)
        );
        assert!(macs.verify_lease(&after).unwrap());
    }
    let after = fx.store.access_request(request_gone.id).await.unwrap();
    assert_eq!(after.status, AccessRequestStatus::Cancelled);
    assert!(macs.verify_access_request(&after).unwrap());
}

/// AUD-9: one malformed pending row is skipped and counted; the others are taken.
#[tokio::test]
async fn a_malformed_pending_row_is_skipped_and_counted() {
    let fx = Fixture::new().await;
    let event = |n: i64| AuditPendingRow {
        occurred_at: at(n),
        event_type: "api.locked_call".to_owned(),
        agent_id: None,
        target_id: None,
        result_code: "vault_locked".to_owned(),
        route: None,
        request_id: None,
    };
    fx.store.push_audit_pending(&event(1), 10).await.unwrap();
    let pool = raw(&fx.path).await;
    sqlx::query(
        "INSERT INTO audit_pending (occurred_at, event_type, agent_id, result_code) \
         VALUES (2, 'auth.failed', 'not-a-uuid', 'unauthenticated')",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    fx.store.push_audit_pending(&event(3), 10).await.unwrap();
    let taken = fx.store.take_audit_pending().await.unwrap();
    assert_eq!(
        taken
            .rows
            .iter()
            .map(|row| row.occurred_at)
            .collect::<Vec<_>>(),
        vec![at(1), at(3)]
    );
    assert_eq!((taken.overflow, taken.malformed), (0, 1));
    let again = fx.store.take_audit_pending().await.unwrap();
    assert!(again.rows.is_empty());
    assert_eq!(again.malformed, 0);
}
