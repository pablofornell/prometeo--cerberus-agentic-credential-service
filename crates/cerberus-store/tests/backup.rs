//! Backup and restore (ADR-0031).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use cerberus_store::{Store, StoreError, linked_vault_file, restore_backup};
use cerberus_types::{AccessRequestStatus, ItemKind};
use common::{Fixture, at, file_contains};

#[tokio::test]
async fn backup_then_restore_gives_an_equal_vault() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::WebLogin, None, "bk");
    let agent = fx.agent("bk");
    let key = fx.agent_key(&agent, 3);
    let lease = fx.lease(&agent, &item, at(600));
    let request = fx.request(&agent, &item, AccessRequestStatus::Pending, at(600), "bk");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.put_agent(&agent).await.unwrap();
    tx.put_agent_key(&key).await.unwrap();
    tx.put_lease(&lease).await.unwrap();
    tx.put_access_request(&request).await.unwrap();
    tx.commit().await.unwrap();

    let backup = fx.dir.path().join("vault.cerberus-backup");
    fx.store.backup_to(&backup).await.unwrap();
    // A backup never overwrites a file.
    assert!(matches!(
        fx.store.backup_to(&backup).await,
        Err(StoreError::Io(_))
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!file_contains(&backup, "SECRET-bk"));
    assert!(!file_contains(&backup, "TITLE-bk"));

    let info = Store::inspect_backup(&backup).await.unwrap();
    assert_eq!(info.vault_id, fx.vault_id);
    assert_eq!(info.schema_version, cerberus_store::schema_version());
    assert_eq!(info.slots, fx.store.key_slots().await.unwrap());

    // Change the live vault after the backup, then restore over it.
    let mut tx = fx.store.begin().await.unwrap();
    tx.delete_item(item.id).await.unwrap();
    tx.commit().await.unwrap();
    let path = fx.path.clone();
    let clock = fx.clock.clone();
    let header = fx.store.header().await.unwrap();
    fx.store.close().await;

    let moved = restore_backup(&backup, &path, &clock)
        .await
        .unwrap()
        .unwrap();
    assert!(moved.exists());
    assert!(moved.to_string_lossy().contains(".pre-restore-"));
    let restored = Fixture::reopen(&path, &clock).await;
    assert_eq!(restored.header().await.unwrap(), header);
    let rows = restored.load_all_for_index().await.unwrap();
    assert_eq!(rows.items, vec![item.clone()]);
    assert_eq!(restored.item_version(item.id, 1).await.unwrap(), version);
    let (agents, keys) = restored.load_auth_rows().await.unwrap();
    assert_eq!((agents, keys), (vec![agent.clone()], vec![key.clone()]));
    assert_eq!(restored.lease(lease.id).await.unwrap(), lease);
    assert_eq!(restored.access_request(request.id).await.unwrap(), request);
    // The old vault is still readable at its new name.
    let old = Store::inspect_backup(&moved).await.unwrap();
    assert_eq!(old.vault_id, fx.vault_id);
}

/// NEW-11: a restore refuses a vault path that is a symbolic link, before anything is copied or
/// moved. Before, the swap renamed the link to `.pre-restore-*` and left the real file where the
/// link pointed, out of reach of the stranded check at the next start.
#[cfg(unix)]
#[tokio::test]
async fn t27h_a_linked_vault_path_is_not_restored() {
    let fx = Fixture::new().await;
    let backup = fx.dir.path().join("b.cerberus-backup");
    fx.store.backup_to(&backup).await.unwrap();
    let path = fx.path.clone();
    let clock = fx.clock.clone();
    fx.store.close().await;
    let real = fx.dir.path().join("synced").join("vault.cerberus");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    std::fs::rename(&path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &path).unwrap();
    assert_eq!(linked_vault_file(&path), Some(path.clone()));
    let before = std::fs::read(&real).unwrap();
    let error = restore_backup(&backup, &path, &clock)
        .await
        .expect_err("a linked vault path is refused");
    assert!(
        matches!(&error, StoreError::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "{error:?}"
    );
    assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the link still reaches the vault"
    );
    let mut names: Vec<String> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["vault.cerberus"], "nothing was moved or copied");
}

#[tokio::test]
async fn restore_into_a_directory_without_a_vault_moves_nothing() {
    let fx = Fixture::new().await;
    let backup = fx.dir.path().join("b.cerberus-backup");
    fx.store.backup_to(&backup).await.unwrap();
    let target = fx.dir.path().join("fresh").join("vault.cerberus");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    assert!(
        restore_backup(&backup, &target, &fx.clock)
            .await
            .unwrap()
            .is_none()
    );
    let store = Fixture::reopen(&target, &fx.clock).await;
    assert_eq!(store.header().await.unwrap().vault_id, fx.vault_id);
}

#[tokio::test]
async fn bad_backups_are_refused_and_the_vault_is_left_alone() {
    let fx = Fixture::new().await;
    let junk = fx.dir.path().join("junk");
    std::fs::write(&junk, b"not a backup at all, only some text".repeat(50)).unwrap();
    assert!(matches!(
        Store::inspect_backup(&junk).await,
        Err(StoreError::NotAVault)
    ));
    let before = fx.store.header().await.unwrap();
    assert!(matches!(
        restore_backup(&junk, &fx.path, &fx.clock).await,
        Err(StoreError::NotAVault)
    ));
    assert_eq!(fx.store.header().await.unwrap(), before);

    // A backup from a newer version is refused.
    let backup = fx.dir.path().join("newer");
    fx.store.backup_to(&backup).await.unwrap();
    let db = common::raw(&backup).await;
    sqlx::query("PRAGMA user_version = 7")
        .execute(&db)
        .await
        .unwrap();
    db.close().await;
    assert!(matches!(
        Store::inspect_backup(&backup).await,
        Err(StoreError::TooNew {
            found: 7,
            supported: 2
        })
    ));
}

#[tokio::test]
async fn a_backup_with_a_sibling_wal_file_is_refused() {
    let fx = Fixture::new().await;
    let backup = fx.dir.path().join("with-wal");
    fx.store.backup_to(&backup).await.unwrap();
    std::fs::write(fx.dir.path().join("with-wal-wal"), b"x").unwrap();
    assert!(matches!(
        Store::inspect_backup(&backup).await,
        Err(StoreError::NotAVault)
    ));
}
