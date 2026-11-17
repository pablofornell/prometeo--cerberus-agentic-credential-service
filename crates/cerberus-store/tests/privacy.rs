//! A7: the vault file shows no secret and no metadata. AAD: a sealed blob cannot move to another place.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use cerberus_crypto::CryptoError;
use cerberus_store::{AuditHeadRow, AuditRow, GrantRow, SettingRow, StoreError, WorkspaceRow};
use cerberus_types::{AccessRequestStatus, AgentId, GrantId, ItemId, ItemKind, WorkspaceId, t0};
use common::{Fixture, at, file_contains, raw};

const MARKERS: [&str; 12] = [
    "SECRET-m1",
    "TITLE-m1",
    "DESCRIPTION-m1",
    "ROLE-m1",
    "TAG-m1",
    "TARGET-m1",
    "AGENT-NAME-m1",
    "GRANT-BODY-m1",
    "REASON-m1",
    "SETTING-m1",
    "AUDIT-BODY-m1",
    "WORKSPACE-NAME-m1",
];

fn is_integrity(error: &StoreError) -> bool {
    matches!(error, StoreError::Crypto(CryptoError::Integrity))
}

#[tokio::test]
async fn no_marker_appears_in_the_vault_file_or_its_wal() {
    let fx = Fixture::new().await;
    let blobs = fx.blobs();

    let workspace_id = WorkspaceId::generate();
    let (item, version) = fx.item(ItemKind::WebLogin, None, "m1");
    let agent = fx.agent("m1");
    let grant_id = GrantId::generate();
    let request = fx.request(&agent, &item, AccessRequestStatus::Pending, at(900), "m1");

    let mut tx = fx.store.begin().await.unwrap();
    tx.put_workspace(&WorkspaceRow {
        id: workspace_id,
        created_at: t0(),
        updated_at: t0(),
        meta_ct: blobs
            .seal_workspace_meta(&workspace_id, b"WORKSPACE-NAME-m1")
            .unwrap(),
    })
    .await
    .unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_grant(&GrantRow {
        id: grant_id,
        agent_id: agent.id,
        created_at: t0(),
        updated_at: t0(),
        expires_at: None,
        body_ct: blobs.seal_grant_body(&grant_id, b"GRANT-BODY-m1").unwrap(),
    })
    .await
    .unwrap();
    tx.put_access_request(&request).await.unwrap();
    tx.put_setting(&SettingRow {
        key: "idle_lock_seconds".to_owned(),
        updated_at: t0(),
        value_ct: blobs
            .seal_setting("idle_lock_seconds", b"SETTING-m1")
            .unwrap(),
    })
    .await
    .unwrap();
    tx.append_audit(
        &AuditRow {
            seq: 1,
            occurred_at: t0(),
            prev_hash: [1; 32],
            hmac: [2; 32],
            body_ct: blobs.seal_audit_body(1, b"AUDIT-BODY-m1").unwrap(),
        },
        &AuditHeadRow {
            last_seq: 1,
            last_entry_hash: [3; 32],
            anchor_seq: 1,
            anchor_prev_hash: [1; 32],
            head_hmac: [4; 32],
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // The control: the scan can see plain text that is really there.
    assert!(
        file_contains(&fx.path, "vault_header"),
        "the scan must see the schema text"
    );
    assert!(file_contains(&fx.path, "CERBERUS-VAULT"));
    for marker in MARKERS.iter().chain(&["FAKE-CA-PRIVATE-KEY-MARKER"]) {
        assert!(
            !file_contains(&fx.path, marker),
            "{marker} found with the WAL present"
        );
    }

    // The data is really there: it opens with the keys.
    let rows = fx.store.load_all_for_index().await.unwrap();
    let meta = blobs
        .open_item_meta(&item.id, 1, &rows.items[0].meta_ct)
        .unwrap();
    assert!(String::from_utf8_lossy(meta.expose_secret()).contains("TITLE-m1"));

    // After a checkpoint (close) the WAL is folded into the main file. Check again.
    let path = fx.path.clone();
    fx.store.close().await;
    for marker in MARKERS.iter().chain(&["FAKE-CA-PRIVATE-KEY-MARKER"]) {
        assert!(!file_contains(&path, marker), "{marker} found after close");
    }
}

#[tokio::test]
async fn a_blob_moved_to_another_row_fails_to_open() {
    let fx = Fixture::new().await;
    let blobs = fx.blobs();
    let (item_a, version_a) = fx.item(ItemKind::ApiKey, None, "a");
    let (item_b, version_b) = fx.item(ItemKind::ApiKey, None, "b");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item_a, &version_a).await.unwrap();
    tx.insert_item(&item_b, &version_b).await.unwrap();
    tx.commit().await.unwrap();

    // Copy B's sealed metadata and payload into A's rows, behind the store's back.
    let db = raw(&fx.path).await;
    sqlx::query("UPDATE items SET meta_ct = ?1 WHERE id = ?2")
        .bind(item_b.meta_ct.as_slice())
        .bind(item_a.id.to_string())
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("UPDATE item_versions SET wrapped_dek = ?1, payload_ct = ?2 WHERE item_id = ?3")
        .bind(version_b.wrapped_dek.as_slice())
        .bind(version_b.payload_ct.as_slice())
        .bind(item_a.id.to_string())
        .execute(&db)
        .await
        .unwrap();

    let moved = fx.store.item(item_a.id).await.unwrap();
    let error = blobs
        .open_item_meta(&item_a.id, 1, &moved.meta_ct)
        .unwrap_err();
    assert!(is_integrity(&error), "{error:?}");
    let moved_version = fx.store.item_version(item_a.id, 1).await.unwrap();
    let sealed = cerberus_store::SealedPayload {
        wrapped_dek: moved_version.wrapped_dek,
        payload_ct: moved_version.payload_ct,
    };
    let error = blobs.open_payload(&item_a.id, 1, &sealed).unwrap_err();
    assert!(is_integrity(&error), "{error:?}");

    // B itself still opens.
    let own = fx.store.item_version(item_b.id, 1).await.unwrap();
    let opened = blobs
        .open_payload(
            &item_b.id,
            1,
            &cerberus_store::SealedPayload {
                wrapped_dek: own.wrapped_dek,
                payload_ct: own.payload_ct,
            },
        )
        .unwrap();
    assert!(String::from_utf8_lossy(opened.expose_secret()).contains("SECRET-b"));
}

#[tokio::test]
async fn a_blob_moved_to_another_version_column_or_vault_fails_to_open() {
    let fx = Fixture::new().await;
    let blobs = fx.blobs();
    let id = ItemId::generate();
    let sealed = blobs.seal_payload(&id, 1, b"fake payload").unwrap();
    // Another version number.
    assert!(is_integrity(
        &blobs.open_payload(&id, 2, &sealed).unwrap_err()
    ));
    // The same bytes read as another purpose: a workspace and an agent that share the ID bytes.
    let workspace = WorkspaceId::from_bytes(*id.as_bytes());
    let agent = AgentId::from_bytes(*id.as_bytes());
    let ct = blobs.seal_workspace_meta(&workspace, b"fake name").unwrap();
    assert!(is_integrity(
        &blobs.open_agent_meta(&agent, &ct).unwrap_err()
    ));
    // The meta and the snapshot of one item are different purposes.
    let meta = blobs.seal_item_meta(&id, 1, b"fake").unwrap();
    assert!(is_integrity(
        &blobs.open_item_snapshot(&id, 1, &meta).unwrap_err()
    ));
    // A setting moved to another key name; an audit body moved to another seq.
    let setting = blobs.seal_setting("a", b"fake").unwrap();
    assert!(is_integrity(
        &blobs.open_setting("b", &setting).unwrap_err()
    ));
    let body = blobs.seal_audit_body(1, b"fake").unwrap();
    assert!(is_integrity(&blobs.open_audit_body(2, &body).unwrap_err()));
    // Another vault, even with the same keys.
    let other_vault = cerberus_types::VaultId::generate();
    let other = cerberus_store::Blobs::new(&other_vault, &fx.keys);
    assert!(is_integrity(
        &other.open_item_meta(&id, 1, &meta).unwrap_err()
    ));
    // The right place works.
    assert_eq!(
        blobs.open_item_meta(&id, 1, &meta).unwrap().expose_secret(),
        b"fake"
    );
}

#[tokio::test]
async fn a_changed_byte_in_a_blob_fails_to_open() {
    let fx = Fixture::new().await;
    let blobs = fx.blobs();
    let id = ItemId::generate();
    let mut ct = blobs.seal_item_meta(&id, 1, b"fake").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(is_integrity(
        &blobs.open_item_meta(&id, 1, &ct).unwrap_err()
    ));
}
