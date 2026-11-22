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

/// `backup_vault_file` reads the vault file through its own connection while the store keeps writing (the case
/// of `cerberusd backup` next to a running daemon). Every copy passes `integrity_check`, is a valid backup, and
/// holds whole transactions only: an item and its version always come together.
#[tokio::test]
async fn a_backup_made_while_another_connection_writes_is_consistent() {
    let fx = Fixture::new().await;
    let rows: Vec<_> = (0..120)
        .map(|n| fx.item(ItemKind::WebLogin, None, &format!("w{n}")))
        .collect();
    let total = rows.len();
    let store = fx.store.clone();
    let writer = tokio::spawn(async move {
        for (item, version) in rows {
            let mut tx = store.begin().await.unwrap();
            tx.insert_item(&item, &version).await.unwrap();
            tx.commit().await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    let mut counts = Vec::new();
    for n in 0..6 {
        let backup = fx.dir.path().join(format!("live-{n}.cerberus-backup"));
        Store::backup_vault_file(&fx.path, &backup).await.unwrap();
        let info = Store::inspect_backup(&backup).await.unwrap();
        assert_eq!(info.vault_id, fx.vault_id);
        let db = common::raw(&backup).await;
        let check: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(check, "ok");
        let items: i64 = sqlx::query_scalar("SELECT count(*) FROM items")
            .fetch_one(&db)
            .await
            .unwrap();
        let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM item_versions")
            .fetch_one(&db)
            .await
            .unwrap();
        db.close().await;
        assert_eq!(items, versions, "a copy holds whole transactions only");
        counts.push(items);
        tokio::task::yield_now().await;
    }
    writer.await.unwrap();
    assert!(
        counts.windows(2).all(|pair| pair[0] <= pair[1]),
        "{counts:?}"
    );
    // The writer ran during the copies: the first copy holds fewer items than the last.
    assert!(counts.first() < counts.last(), "{counts:?}");
    let final_items = fx.store.load_all_for_index().await.unwrap().items.len();
    assert_eq!(final_items, total);
}

#[tokio::test]
async fn backup_vault_file_refuses_a_missing_file_a_foreign_file_and_an_existing_target() {
    let fx = Fixture::new().await;
    let dest = fx.dir.path().join("out.cerberus-backup");
    assert!(matches!(
        Store::backup_vault_file(&fx.dir.path().join("none"), &dest).await,
        Err(StoreError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(!dest.exists());
    let junk = fx.dir.path().join("junk");
    std::fs::write(&junk, b"not a database, only some text".repeat(50)).unwrap();
    assert!(matches!(
        Store::backup_vault_file(&junk, &dest).await,
        Err(StoreError::NotAVault)
    ));
    assert!(!dest.exists(), "a refused source leaves no file");
    Store::backup_vault_file(&fx.path, &dest).await.unwrap();
    assert!(matches!(
        Store::backup_vault_file(&fx.path, &dest).await,
        Err(StoreError::Io(_))
    ));
}

/// With no other connection (the daemon is stopped), `backup_vault_file` works on a vault with no `-wal` and
/// `-shm` file. The vault file does not change and the vault stays openable.
#[tokio::test]
async fn backup_vault_file_works_when_no_other_connection_is_open() {
    let fx = Fixture::new().await;
    let (item, version) = fx.item(ItemKind::WebLogin, None, "stopped");
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.commit().await.unwrap();
    fx.store.close().await;
    assert!(!wal_path(&fx.path).exists() && !shm_path(&fx.path).exists());
    let before = std::fs::read(&fx.path).unwrap();
    let first = fx.dir.path().join("first.cerberus-backup");
    Store::backup_vault_file(&fx.path, &first).await.unwrap();
    assert_eq!(std::fs::read(&fx.path).unwrap(), before);
    // A read-only connection cannot remove the files that it makes. The `-wal` file stays empty.
    assert_eq!(
        std::fs::metadata(wal_path(&fx.path)).map_or(0, |m| m.len()),
        0
    );
    assert_eq!(
        Store::inspect_backup(&first).await.unwrap().vault_id,
        fx.vault_id
    );
    let store = Fixture::reopen(&fx.path, &fx.clock).await;
    assert_eq!(store.load_all_for_index().await.unwrap().items, [item]);
}

fn wal_path(vault: &std::path::Path) -> std::path::PathBuf {
    let mut name = vault.as_os_str().to_owned();
    name.push("-wal");
    name.into()
}

fn shm_path(vault: &std::path::Path) -> std::path::PathBuf {
    let mut name = vault.as_os_str().to_owned();
    name.push("-shm");
    name.into()
}

/// Makes the state a crash leaves: a vault file, a valid `-wal` file with commits in it and a `-shm` file, and no
/// connection to them. The files are copied while the fixture store still has them open.
async fn crashed_copy(fx: &Fixture, tag: &str) -> std::path::PathBuf {
    let (item, version) = fx.item(ItemKind::WebLogin, None, tag);
    let mut tx = fx.store.begin().await.unwrap();
    tx.insert_item(&item, &version).await.unwrap();
    tx.commit().await.unwrap();
    let dir = fx.dir.path().join(format!("crashed-{tag}"));
    std::fs::create_dir(&dir).unwrap();
    let vault = dir.join("vault.cerberus");
    std::fs::copy(&fx.path, &vault).unwrap();
    std::fs::copy(wal_path(&fx.path), wal_path(&vault)).unwrap();
    std::fs::copy(shm_path(&fx.path), shm_path(&vault)).unwrap();
    assert!(
        std::fs::metadata(wal_path(&vault)).unwrap().len() > 32,
        "the commit must be in the -wal file"
    );
    vault
}

/// The vault must not be changed by a backup: with a valid `-wal` file and no other connection, a read-write
/// connection would fold the `-wal` file into the vault and delete it when it closes.
#[tokio::test]
async fn backup_vault_file_changes_no_vault_file_and_keeps_the_wal() {
    let fx = Fixture::new().await;
    let vault = crashed_copy(&fx, "wal").await;
    let (vault_before, wal_before) = (
        std::fs::read(&vault).unwrap(),
        std::fs::read(wal_path(&vault)).unwrap(),
    );

    let dest = fx.dir.path().join("wal.cerberus-backup");
    Store::backup_vault_file(&vault, &dest).await.unwrap();

    assert_eq!(std::fs::read(&vault).unwrap(), vault_before);
    assert_eq!(std::fs::read(wal_path(&vault)).unwrap(), wal_before);
    assert!(shm_path(&vault).exists());
    // The copy holds the commit that was only in the `-wal` file.
    let db = common::raw(&dest).await;
    let items: i64 = sqlx::query_scalar("SELECT count(*) FROM items")
        .fetch_one(&db)
        .await
        .unwrap();
    db.close().await;
    assert_eq!(items, 1);
}

/// A `-wal` file that fails the `Store::open` check (AUD-10) is refused: SQLite would ignore it, the copy would
/// miss its commits and nothing may delete it.
#[tokio::test]
async fn backup_vault_file_refuses_a_wal_with_a_bad_checksum() {
    let fx = Fixture::new().await;
    let vault = crashed_copy(&fx, "bad").await;
    let mut wal = std::fs::read(wal_path(&vault)).unwrap();
    wal[24] ^= 0xff; // The first checksum word of the `-wal` header.
    std::fs::write(wal_path(&vault), &wal).unwrap();
    let vault_before = std::fs::read(&vault).unwrap();

    let dest = fx.dir.path().join("bad.cerberus-backup");
    assert!(matches!(
        Store::backup_vault_file(&vault, &dest).await,
        Err(StoreError::Corrupt)
    ));
    assert!(!dest.exists(), "a refused source leaves no file");
    assert_eq!(std::fs::read(&vault).unwrap(), vault_before);
    assert_eq!(std::fs::read(wal_path(&vault)).unwrap(), wal);
    // `Store::open` refuses the same file, so both agree.
    let opened = Store::open(
        cerberus_store::OpenOptions {
            path: vault,
            create: false,
        },
        std::sync::Arc::new(fx.clock.clone()),
    )
    .await;
    assert!(matches!(opened, Err(StoreError::Corrupt)));
}
