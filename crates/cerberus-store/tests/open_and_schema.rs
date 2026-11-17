//! Open, migrate, refuse wrong or newer files, header and key slots.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::sync::Arc;

use cerberus_store::{OpenOptions, Store, StoreError, schema_version, verify_header_mac};
use cerberus_types::{ManualClock, t0};
use common::{Fixture, at, raw};

#[tokio::test]
async fn migration_up_from_empty_sets_the_schema() {
    let fx = Fixture::new().await;
    let db = raw(&fx.path).await;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&db)
        .await
        .unwrap();
    let app_id: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&db)
        .await
        .unwrap();
    let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
        .fetch_one(&db)
        .await
        .unwrap();
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(version, schema_version());
    assert_eq!(version, 1);
    assert_eq!(app_id, 0x4342_5256);
    assert_eq!(auto_vacuum, 2, "INCREMENTAL");
    assert_eq!(journal, "wal");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(&db)
    .await
    .unwrap();
    for table in [
        "access_requests",
        "agent_keys",
        "agents",
        "audit_events",
        "audit_head",
        "audit_pending",
        "audit_pending_overflow",
        "audit_prune_guard",
        "grants",
        "item_versions",
        "items",
        "key_slots",
        "leases",
        "settings",
        "tls_ca",
        "vault_header",
        "workspaces",
    ] {
        assert!(
            tables.iter().any(|name| name == table),
            "missing table {table}"
        );
    }
}

#[tokio::test]
async fn open_refuses_a_newer_schema() {
    let fx = Fixture::new().await;
    let path = fx.path.clone();
    let clock = fx.clock.clone();
    let db = raw(&path).await;
    sqlx::query("PRAGMA user_version = 99")
        .execute(&db)
        .await
        .unwrap();
    db.close().await;
    fx.store.close().await;
    let error = Store::open(
        OpenOptions {
            path,
            create: false,
        },
        Arc::new(clock),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            StoreError::TooNew {
                found: 99,
                supported: 1
            }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn open_refuses_files_that_are_not_vaults_and_does_not_change_them() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(t0()));
    let open = |path: std::path::PathBuf, create: bool| {
        let clock = clock.clone();
        async move { Store::open(OpenOptions { path, create }, clock).await }
    };

    let text = dir.path().join("text.db");
    std::fs::write(
        &text,
        b"this is not a database, it is only a long enough line of text".repeat(100),
    )
    .unwrap();
    assert!(matches!(
        open(text.clone(), true).await,
        Err(StoreError::NotAVault)
    ));

    let other = dir.path().join("other.db");
    let db = raw(&other).await;
    sqlx::query("CREATE TABLE notes (a TEXT)")
        .execute(&db)
        .await
        .unwrap();
    db.close().await;
    let before = std::fs::read(&other).unwrap();
    assert!(matches!(
        open(other.clone(), true).await,
        Err(StoreError::NotAVault)
    ));
    assert_eq!(
        std::fs::read(&other).unwrap(),
        before,
        "a foreign file must stay as it was"
    );
    assert!(!dir.path().join("other.db-wal").exists());

    let empty = dir.path().join("empty.db");
    std::fs::write(&empty, b"").unwrap();
    assert!(matches!(
        open(empty, false).await,
        Err(StoreError::NotAVault)
    ));

    let missing = dir.path().join("missing.db");
    assert!(matches!(
        open(missing.clone(), false).await,
        Err(StoreError::Io(_))
    ));
    assert!(!missing.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn new_vault_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new().await;
    let file = std::fs::metadata(&fx.path).unwrap().permissions().mode() & 0o777;
    let dir = std::fs::metadata(fx.path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file, 0o600);
    assert_eq!(dir, 0o700);
}

#[tokio::test]
async fn header_and_slots_round_trip_and_the_mac_checks() {
    let fx = Fixture::new().await;
    let header = fx.store.header().await.unwrap();
    let slots = fx.store.key_slots().await.unwrap();
    assert_eq!(header.vault_id, fx.vault_id);
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].id, fx.owner);
    assert!(verify_header_mac(&fx.keys.header_key, &header, &slots));

    // A changed slot (as an attacker with the file would do) breaks the header MAC.
    let db = raw(&fx.path).await;
    sqlx::query("UPDATE key_slots SET role = 'viewer'")
        .execute(&db)
        .await
        .unwrap();
    let changed = fx.store.key_slots().await.unwrap();
    assert!(!verify_header_mac(&fx.keys.header_key, &header, &changed));
}

#[tokio::test]
async fn initialize_twice_is_a_conflict_and_changes_nothing() {
    let fx = Fixture::new().await;
    let header = fx.store.header().await.unwrap();
    let slots = fx.store.key_slots().await.unwrap();
    let ca = fx.store.tls_ca().await.unwrap();
    let error = fx.store.initialize(&header, &slots, &ca).await.unwrap_err();
    assert!(matches!(error, StoreError::Conflict), "{error:?}");
    assert_eq!(fx.store.key_slots().await.unwrap(), slots);
}

#[tokio::test]
async fn unlock_failures_count_and_reset_while_locked() {
    let fx = Fixture::new().await;
    assert_eq!(fx.store.record_unlock_failure(at(1)).await.unwrap(), 1);
    assert_eq!(fx.store.record_unlock_failure(at(2)).await.unwrap(), 2);
    let header = fx.store.header().await.unwrap();
    assert_eq!(
        (header.failed_unlocks, header.last_failed_unlock_at),
        (2, Some(at(2)))
    );
    fx.store.reset_unlock_failures().await.unwrap();
    let header = fx.store.header().await.unwrap();
    assert_eq!(
        (header.failed_unlocks, header.last_failed_unlock_at),
        (0, None)
    );
}

#[tokio::test]
async fn schema_rules_are_enforced_by_the_database() {
    let fx = Fixture::new().await;
    let db = raw(&fx.path).await;
    // KDF cost below the ADR-0013 floor.
    let low = sqlx::query(
        "INSERT INTO key_slots (id, kind, label, role, kdf_alg, argon2_version, m_cost_kib, t_cost, p_cost, \
         salt, wrapped_vmk, created_at, updated_at) VALUES ('a', 'passphrase', 'x', 'owner', 'argon2id', 19, \
         1024, 1, 1, zeroblob(32), x'00', 0, 0)",
    )
    .execute(&db)
    .await;
    assert!(low.is_err());
    // A second header row.
    let second = sqlx::query(
        "INSERT INTO vault_header (id, magic, format_version, vault_id, created_at, header_mac) \
         VALUES (2, 'CERBERUS-VAULT', 1, zeroblob(16), 0, zeroblob(32))",
    )
    .execute(&db)
    .await;
    assert!(second.is_err());
}

/// A 32-byte WAL header (big-endian magic) with a correct checksum for `page_size`.
fn wal_header(page_size: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for word in [
        0x377f_0683_u32,
        3_007_000,
        page_size,
        0,
        0x1234_5678,
        0x0abc_def0,
    ] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    let (mut s0, mut s1) = (0_u32, 0_u32);
    for pair in out.chunks(8) {
        let x0 = u32::from_be_bytes([pair[0], pair[1], pair[2], pair[3]]);
        let x1 = u32::from_be_bytes([pair[4], pair[5], pair[6], pair[7]]);
        s0 = s0.wrapping_add(x0).wrapping_add(s1);
        s1 = s1.wrapping_add(x1).wrapping_add(s0);
    }
    out.extend_from_slice(&s0.to_be_bytes());
    out.extend_from_slice(&s1.to_be_bytes());
    out
}

/// AUD-10 (RUSTSEC-2026-0459): a `-wal` file next to the live vault whose page size is not the
/// page size of the vault is refused before SQLite reads it, and it is not changed.
#[tokio::test]
async fn open_refuses_a_wal_file_of_another_page_size() {
    let fx = Fixture::new().await;
    let path = fx.path.clone();
    let clock = fx.clock.clone();
    fx.store.close().await;
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let wal = std::path::PathBuf::from(wal);
    let crafted = wal_header(1024);
    std::fs::write(&wal, &crafted).unwrap();
    let opened = Store::open(
        OpenOptions {
            path: path.clone(),
            create: false,
        },
        Arc::new(clock.clone()),
    )
    .await;
    assert!(matches!(opened, Err(StoreError::Corrupt)), "{opened:?}");
    assert_eq!(std::fs::read(&wal).unwrap(), crafted);

    // A header with the right page size (a WAL left by a crash) still opens.
    std::fs::write(&wal, wal_header(4096)).unwrap();
    Fixture::reopen(&path, &clock).await.close().await;
}
