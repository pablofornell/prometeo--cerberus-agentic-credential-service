//! Tests of `cerberusd backup` (ADR-0031): a real vault made with the core API in a temp dir, a writer that keeps
//! adding items while the backups run, and the real `cerberusd` binary for the command line. Every secret here is a
//! fake test value.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use cerberus_api::tls::{LocalCaIssuer, TlsPaths};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::items::{ItemInput, Payload};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreConfig, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{Clock, Environment, OperatorRole, RequestId, SystemClock, WorkspaceId};
use cerberusd::backup::{self, BACKUP_SUFFIX, BackupError};
use cerberusd::config::{self, Config};
use cerberusd::daemon::VAULT_FILE;

const PHRASE: &str = "orbit velvet canyon mosaic 7";

fn no_env(_: &str) -> Option<String> {
    None
}

/// The settings of a data folder: only `data_dir` is set.
fn config_for(data_dir: &Path) -> Config {
    let path = data_dir.join("cerberusd.toml");
    std::fs::write(
        &path,
        format!("data_dir = {:?}\n", data_dir.display().to_string()),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    config::load(Some(&path), &no_env).expect("config")
}

fn login(workspace: WorkspaceId, n: usize) -> ItemInput {
    ItemInput {
        workspace_id: workspace,
        title: format!("Shop admin {n}"),
        description: "Shop admin login".to_owned(),
        role_label: Some("admin".to_owned()),
        category: "Web login".to_owned(),
        tags: vec!["shop".to_owned()],
        environment: Environment::Dev,
        target: Some("https://shop.example.test/login".to_owned()),
        custom: BTreeMap::new(),
        expires_at: None,
        max_uses: None,
        payload: Payload::WebLogin {
            username: SecretString::new("canary-user-5d20be41".to_owned()),
            password: SecretString::new("canary-pw-7f3a91c2".to_owned()),
            url: None,
            totp: None,
        },
    }
}

/// A vault in `data_dir`, still open and unlocked, as a running daemon holds it.
async fn open_vault(data_dir: &Path) -> (VaultService, OperatorContext, WorkspaceId) {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = Store::open(
        OpenOptions {
            path: data_dir.join(VAULT_FILE),
            create: true,
        },
        Arc::clone(&clock),
    )
    .await
    .expect("store");
    let core = VaultService::open(
        store,
        clock,
        CoreConfig {
            approvals_available: false,
            idle_lock_default: None,
            max_unlocked_default: None,
            data_dir: data_dir.to_path_buf(),
            ca_issuer: Arc::new(LocalCaIssuer::new(
                TlsPaths::in_data_dir(data_dir),
                Vec::new(),
            )),
        },
    )
    .await
    .expect("open");
    let created = core
        .create_vault(NewVault {
            owner_label: "owner".to_owned(),
            phrase: SecretString::new(PHRASE.to_owned()),
            kdf: KdfParams::new(19_456, 1, 1).expect("kdf"),
            host_names: vec![],
        })
        .await
        .expect("create vault");
    let owner = OperatorContext {
        operator_id: created.owner_id,
        role: OperatorRole::Owner,
        request_id: RequestId::generate(),
    };
    let workspace = core
        .put_workspace(
            &owner,
            None,
            WorkspaceInput {
                slug: "shop-frontend".to_owned(),
                name: "Shop frontend".to_owned(),
                description: String::new(),
                aliases: vec![],
            },
        )
        .await
        .expect("workspace");
    (core, owner, workspace.id)
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn binary(data_dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cerberusd"))
        .arg("--config")
        .arg(data_dir.join("cerberusd.toml"))
        .args(args)
        .env_remove("CERBERUSD_DATA_DIR")
        .output()
        .expect("run cerberusd")
}

/// The case of the deploy pipeline: the vault is open and written by one process, and `cerberusd backup` runs in
/// another. Every backup opens as a valid backup of the same vault, has mode 0600 and leaves no partial file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backups_made_while_the_vault_is_written_are_valid() {
    let data = tempfile::tempdir().unwrap();
    let (core, owner, workspace) = open_vault(data.path()).await;
    let config = config_for(data.path());
    let out = data.path().join("backups");
    let writer = tokio::spawn(async move {
        for n in 0..40 {
            core.create_item_as_operator(&owner, login(workspace, n))
                .await
                .expect("item");
        }
    });
    let mut made = Vec::new();
    // Three runs of the library, then one of the real binary, all while the writer runs.
    for n in 0..3 {
        let named = out.join(format!("run-{n}{BACKUP_SUFFIX}"));
        let report = backup::run(&config, &named, None, &SystemClock)
            .await
            .expect("backup");
        assert_eq!(report.path, named);
        made.push(report.path);
    }
    let result = binary(data.path(), &["backup", "--out", out.to_str().unwrap()]);
    assert!(result.status.success(), "{result:?}");
    let printed = String::from_utf8(result.stdout).unwrap();
    made.push(PathBuf::from(printed.trim()));
    writer.await.unwrap();
    for path in &made {
        let info = Store::inspect_backup(path).await.expect("a valid backup");
        assert_eq!(info.schema_version, cerberus_store::schema_version());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let default_name = made[3].file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        default_name.starts_with("cerberus-") && default_name.ends_with(BACKUP_SUFFIX),
        "{default_name}"
    );
    assert!(
        names(&out).iter().all(|name| name.ends_with(BACKUP_SUFFIX)),
        "no partial file is left: {:?}",
        names(&out)
    );
}

/// `--keep` removes only older backups of this vault in the naming scheme. Everything else stays.
#[tokio::test]
async fn keep_prunes_only_older_backups_of_this_vault() {
    let data = tempfile::tempdir().unwrap();
    let (_core, _owner, _workspace) = open_vault(data.path()).await;
    let config = config_for(data.path());
    let out = data.path().join("backups");
    let first = backup::run(&config, &out, None, &SystemClock)
        .await
        .expect("first backup");
    let first_name = first
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    // `cerberus-<8 characters of the vault ID>-<time>.cerberus-backup`.
    let short = first_name["cerberus-".len()..][..8].to_owned();
    std::fs::remove_file(&first.path).unwrap();
    let mine = |stamp: &str| format!("cerberus-{short}-{stamp}{BACKUP_SUFFIX}");
    let old_mine = [
        mine("20200101T000000Z"),
        mine("20200102T000000Z"),
        mine("20200103T000000Z"),
        mine("20200104T000000Z"),
    ];
    let others = [
        // Another vault, a different tool, a partial file, a note and a name that only looks like ours.
        format!("cerberus-ffffffff-20200101T000000Z{BACKUP_SUFFIX}"),
        "vault.cerberus".to_owned(),
        "notes.txt".to_owned(),
        format!("{}.partial", mine("20200101T000000Z")),
        format!("my-{}", mine("20200101T000000Z")),
        mine("2020"),
    ];
    for name in old_mine.iter().chain(&others) {
        std::fs::write(out.join(name), b"x").unwrap();
    }
    // A folder and a link with a backup name are not files of ours.
    let folder = mine("20190101T000000Z");
    std::fs::create_dir(out.join(&folder)).unwrap();
    let outside = data.path().join("outside.txt");
    std::fs::write(&outside, b"keep me").unwrap();
    let link = mine("20190102T000000Z");
    std::os::unix::fs::symlink(&outside, out.join(&link)).unwrap();

    let report = backup::run(&config, &out, Some(3), &SystemClock)
        .await
        .expect("backup with keep");
    // The new backup and the two newest old ones stay: 3 in all. The two oldest go.
    assert_eq!(
        report
            .pruned
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [old_mine[0].clone(), old_mine[1].clone()]
    );
    let left = names(&out);
    for gone in &old_mine[..2] {
        assert!(!left.contains(gone), "{gone} was kept");
    }
    for stay in old_mine[2..].iter().chain(&others).chain([&folder, &link]) {
        assert!(left.contains(stay), "{stay} was removed");
    }
    assert!(
        left.contains(
            &report
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        )
    );
    assert!(out.join(&folder).is_dir());
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep me");
    assert!(Store::inspect_backup(&report.path).await.is_ok());
}

/// A wrong clock can leave files with a time in the future. `--keep` must still keep the new backup, and the
/// other `keep - 1` newest files, and remove the rest.
#[tokio::test]
async fn keep_never_removes_the_new_backup_when_older_files_are_dated_in_the_future() {
    let data = tempfile::tempdir().unwrap();
    let (_core, _owner, _workspace) = open_vault(data.path()).await;
    let config = config_for(data.path());
    let out = data.path().join("backups");
    let first = backup::run(&config, &out, None, &SystemClock)
        .await
        .expect("first backup");
    let first_name = first.path.file_name().unwrap().to_string_lossy();
    let short = first_name["cerberus-".len()..][..8].to_owned();
    std::fs::remove_file(&first.path).unwrap();
    let mine = |stamp: &str| format!("cerberus-{short}-{stamp}{BACKUP_SUFFIX}");
    let future = [
        mine("20990101T000000Z"),
        mine("20990102T000000Z"),
        mine("20990103T000000Z"),
    ];
    for name in &future {
        std::fs::write(out.join(name), b"x").unwrap();
    }

    let report = backup::run(&config, &out, Some(2), &SystemClock)
        .await
        .expect("backup with keep");
    assert!(
        report.path.is_file(),
        "the new backup was removed: {:?}",
        names(&out)
    );
    assert!(Store::inspect_backup(&report.path).await.is_ok());
    // The new file and the newest other file stay.
    assert_eq!(
        report
            .pruned
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        [future[0].clone(), future[1].clone()]
    );
    let new_name = report
        .path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mut expected = [future[2].clone(), new_name];
    expected.sort();
    assert_eq!(names(&out), expected);
    // `--keep 1` keeps the new file alone.
    let alone = data.path().join("alone");
    std::fs::create_dir(&alone).unwrap();
    std::fs::write(alone.join(&future[2]), b"x").unwrap();
    let report = backup::run(&config, &alone, Some(1), &SystemClock)
        .await
        .expect("backup with keep 1");
    assert_eq!(names(&alone).len(), 1, "{:?}", names(&alone));
    assert!(report.path.is_file());
}

/// Two runs in one process (or two containers with the same process ID) must not write the same partial file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runs_at_the_same_time_use_different_partial_files() {
    let data = tempfile::tempdir().unwrap();
    let (_core, _owner, _workspace) = open_vault(data.path()).await;
    let config = config_for(data.path());
    let out = data.path().join("backups");
    let (one, two, three) = (
        out.join(format!("one{BACKUP_SUFFIX}")),
        out.join(format!("two{BACKUP_SUFFIX}")),
        out.join(format!("three{BACKUP_SUFFIX}")),
    );
    let (a, b, c) = tokio::join!(
        backup::run(&config, &one, None, &SystemClock),
        backup::run(&config, &two, None, &SystemClock),
        backup::run(&config, &three, None, &SystemClock),
    );
    a.expect("run one");
    b.expect("run two");
    c.expect("run three");
    for path in [&one, &two, &three] {
        assert!(Store::inspect_backup(path).await.is_ok());
    }
    assert_eq!(names(&out).len(), 3, "{:?}", names(&out));
}

/// A run removes the old `.cerberus-*.partial` regular files that a killed run left. A new one, a link, a folder and
/// other names stay.
#[tokio::test]
async fn a_run_removes_only_stale_partial_files() {
    let data = tempfile::tempdir().unwrap();
    let (_core, _owner, _workspace) = open_vault(data.path()).await;
    let config = config_for(data.path());
    let out = data.path().join("backups");
    std::fs::create_dir(&out).unwrap();
    let age = |name: &str, hours: u64| {
        let file = std::fs::File::options()
            .write(true)
            .open(out.join(name))
            .unwrap();
        let seconds = u64::try_from(SystemClock.now().as_second()).unwrap() - hours * 3600;
        file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
            .unwrap();
    };
    for name in [
        ".cerberus-4242.partial",
        ".cerberus-0f3a9c.partial",
        ".cerberus-fresh.partial",
        ".other-4242.partial",
        ".cerberus-4242.keep",
    ] {
        std::fs::write(out.join(name), b"x").unwrap();
    }
    age(".cerberus-4242.partial", 48);
    age(".cerberus-0f3a9c.partial", 25);
    age(".cerberus-fresh.partial", 1);
    age(".other-4242.partial", 48);
    age(".cerberus-4242.keep", 48);
    // A link and a folder with a partial name are not files of ours, however old.
    let outside = data.path().join("outside.txt");
    std::fs::write(&outside, b"keep me").unwrap();
    std::os::unix::fs::symlink(&outside, out.join(".cerberus-link.partial")).unwrap();
    std::fs::create_dir(out.join(".cerberus-folder.partial")).unwrap();

    let report = backup::run(&config, &out, None, &SystemClock)
        .await
        .expect("backup");
    let left = names(&out);
    for gone in [".cerberus-4242.partial", ".cerberus-0f3a9c.partial"] {
        assert!(!left.iter().any(|name| name == gone), "{gone} stayed");
    }
    for stay in [
        ".cerberus-fresh.partial",
        ".other-4242.partial",
        ".cerberus-4242.keep",
        ".cerberus-link.partial",
        ".cerberus-folder.partial",
    ] {
        assert!(left.iter().any(|name| name == stay), "{stay} was removed");
    }
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep me");
    assert!(report.path.is_file());
    // The run's own partial file is gone: the four that stay are the only ones.
    assert_eq!(
        left.iter()
            .filter(|name| name.ends_with(".partial"))
            .count(),
        4,
        "{left:?}"
    );
}

#[tokio::test]
async fn bad_requests_fail_and_change_nothing() {
    let data = tempfile::tempdir().unwrap();
    let config = config_for(data.path());
    let out = data.path().join("backups");
    // No vault file: the folder is not made.
    let error = backup::run(&config, &out, None, &SystemClock)
        .await
        .expect_err("no vault");
    assert!(matches!(error, BackupError::NoVault(_)), "{error}");
    assert!(!out.exists());
    let (_core, _owner, _workspace) = open_vault(data.path()).await;
    let file = out.join(format!("one{BACKUP_SUFFIX}"));
    let error = backup::run(&config, &file, Some(2), &SystemClock)
        .await
        .expect_err("keep with a file");
    assert!(matches!(error, BackupError::KeepWithFile(_)), "{error}");
    let error = backup::run(&config, &out, Some(0), &SystemClock)
        .await
        .expect_err("keep 0");
    assert!(matches!(error, BackupError::KeepZero), "{error}");
    assert!(!out.exists(), "a refused request makes no folder");
    // A named file is made once and never replaced.
    backup::run(&config, &file, None, &SystemClock)
        .await
        .expect("named backup");
    std::fs::write(&file, b"precious").unwrap();
    assert!(
        backup::run(&config, &file, None, &SystemClock)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"precious");
    assert_eq!(names(&out), [format!("one{BACKUP_SUFFIX}")]);
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn the_command_exits_non_zero_without_a_vault() {
    let data = tempfile::tempdir().unwrap();
    config_for(data.path());
    let out = data.path().join("backups");
    let result = binary(data.path(), &["backup", "--out", out.to_str().unwrap()]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no vault file"));
    assert!(result.stdout.is_empty());
    let result = binary(
        data.path(),
        &["backup", "--out", out.to_str().unwrap(), "--keep", "0"],
    );
    assert!(!result.status.success());
}
