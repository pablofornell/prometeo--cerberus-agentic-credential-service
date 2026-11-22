//! Tests of `cerberusd init`: the library with an injected passphrase prompt (a small KDF cost, so no cost test runs),
//! and the real `cerberusd` binary for the checks that run before any passphrase is asked. Every secret here is a fake
//! test value.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::cell::Cell;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use cerberus_core::vault::KeyCustody;
use cerberus_crypto::{KdfParams, RecoveryKey, SecretString};
use cerberus_types::{OperatorRole, VaultStateKind};
use cerberusd::config::{self, Config};
use cerberusd::daemon::{self, VAULT_FILE};
use cerberusd::init::{
    DEFAULT_OWNER, InitError, InitRequest, RecoveryOutput, RecoveryTarget, init_with,
};

const PHRASE: &str = "orbit velvet canyon mosaic 7";

fn no_env(_: &str) -> Option<String> {
    None
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The settings of a data folder. The config file is kept next to the data folder, not in it.
fn config_for(data_dir: &Path, extra: &str) -> (Config, PathBuf) {
    let path = data_dir.parent().unwrap().join("cerberusd.toml");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\nbind = [\"127.0.0.1\"]\nport = {}\n{extra}",
            data_dir.display().to_string(),
            free_port()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (config::load(Some(&path), &no_env).expect("config"), path)
}

fn kdf() -> Option<KdfParams> {
    Some(KdfParams::new(19_456, 1, 1).expect("kdf"))
}

fn request(recovery: RecoveryTarget) -> InitRequest {
    InitRequest {
        owner_label: "alpha".to_owned(),
        recovery,
        kdf: kdf(),
    }
}

/// A prompt that gives `phrase` both times and counts its calls.
fn typed<'a>(
    phrase: &'a str,
    calls: &'a Cell<u32>,
) -> impl FnMut(&str) -> std::io::Result<String> + 'a {
    move |_prompt| {
        calls.set(calls.get() + 1);
        Ok(phrase.to_owned())
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The whole path: init makes a vault that `serve` opens sealed, the phrase unlocks it, and the recovery key in the
/// file opens it too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_makes_a_vault_that_serve_opens_and_the_phrase_and_the_recovery_key_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    let calls = Cell::new(0);

    let report = init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        typed(PHRASE, &calls),
    )
    .await
    .expect("init");
    assert_eq!(calls.get(), 2, "the phrase and its repeat");
    assert!(!report.interrupted);
    assert_eq!(report.vault_path, data.join(VAULT_FILE));
    assert!(report.ca_pin.starts_with("sha256/"), "{}", report.ca_pin);
    assert!(
        matches!(&report.recovery, RecoveryOutput::Written(path) if *path == key_file),
        "{:?}",
        report.recovery
    );
    assert_eq!(mode(&report.vault_path), 0o600);
    assert_eq!(mode(&data), 0o700);
    assert_eq!(mode(&key_file), 0o600);
    // The vault and the TLS folder (CA certificate and leaf), as a vault made on the desktop has. No SQLite side files:
    // nothing holds the vault open any more.
    assert_eq!(names(&data), ["tls".to_owned(), VAULT_FILE.to_owned()]);
    let key_text = std::fs::read_to_string(&key_file).unwrap();
    assert!(key_text.starts_with("CRK1-"), "{key_text}");

    // `serve` finds the vault and starts sealed.
    let core = daemon::serve(&config, std::future::ready(()), |_| {})
        .await
        .expect("serve");
    assert_eq!(core.state(), VaultStateKind::Sealed);
    let operators = core.list_operators().await.expect("operators");
    assert_eq!(operators.len(), 1);
    assert_eq!(operators[0].label, "alpha");
    assert_eq!(operators[0].role, OperatorRole::Owner);
    assert_eq!(operators[0].id, report.owner_id);

    let wrong = core
        .unlock_with_phrase(
            report.owner_id,
            SecretString::new("not the phrase 123".into()),
        )
        .await;
    assert!(wrong.is_err());
    core.unlock_with_phrase(report.owner_id, SecretString::new(PHRASE.to_owned()))
        .await
        .expect("the phrase unlocks");
    assert_eq!(core.state(), VaultStateKind::Unlocked);
    core.lock(cerberus_types::LockReason::Manual).await.unwrap();
    let recovery = RecoveryKey::parse(key_text.trim()).expect("a recovery key");
    core.unlock_with_recovery(recovery)
        .await
        .expect("the recovery key unlocks");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_terminal_target_hands_the_key_back_and_writes_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let calls = Cell::new(0);
    let mut asked = request(RecoveryTarget::Terminal);
    asked.owner_label = DEFAULT_OWNER.to_owned();
    let report = init_with(&config, asked, typed(PHRASE, &calls))
        .await
        .expect("init");
    let RecoveryOutput::Show(key) = report.recovery else {
        panic!("expected the key to show");
    };
    RecoveryKey::parse(key.expose_secret()).expect("a recovery key");
    assert_eq!(names(&data), ["tls".to_owned(), VAULT_FILE.to_owned()]);
    assert_eq!(names(dir.path()), ["cerberusd.toml", "data"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_refuses_when_the_vault_exists_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (config, _) = config_for(&data, "");
    std::fs::write(data.join(VAULT_FILE), b"an existing vault").unwrap();
    let key_file = dir.path().join("recovery.txt");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    assert!(matches!(error, InitError::VaultExists { .. }), "{error}");
    assert_eq!(calls.get(), 0, "no passphrase is asked");
    assert_eq!(
        std::fs::read(data.join(VAULT_FILE)).unwrap(),
        b"an existing vault"
    );
    assert!(!key_file.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passphrases_that_differ_make_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        |_prompt| {
            calls.set(calls.get() + 1);
            Ok(format!("{PHRASE} {}", calls.get()))
        },
    )
    .await
    .expect_err("refused");
    assert!(matches!(error, InitError::Mismatch), "{error}");
    assert!(!data.exists(), "no data folder was made");
    assert!(!key_file.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_weak_passphrase_is_refused_and_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        typed("password1234", &calls),
    )
    .await
    .expect_err("refused");
    match &error {
        InitError::Invalid(text) => assert!(text.contains("12 characters"), "{text}"),
        other => panic!("expected a validation error, got {other}"),
    }
    assert!(!key_file.exists(), "the empty key file was removed");
    assert!(
        !data.exists(),
        "nothing was made: the policy is checked first"
    );
    // A second try with a good phrase works: the first left nothing in the way.
    init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        typed(PHRASE, &calls),
    )
    .await
    .expect("init after a refusal");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_file_that_exists_stops_before_anything_is_asked() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    std::fs::write(&key_file, b"mine").unwrap();
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(error, InitError::RecoveryFileExists { .. }),
        "{error}"
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(std::fs::read(&key_file).unwrap(), b"mine");
    assert!(!data.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_data_folder_open_to_others_is_refused_before_the_vault_is_made() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (config, _) = config_for(&data, "");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::Terminal),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(error, InitError::Daemon(daemon::DaemonError::Mode { .. })),
        "{error}"
    );
    assert!(names(&data).is_empty());
}

/// The TLS names are the `host_names` of the config only, so the certificate and the Host check of `serve` agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_config_host_names_are_the_tls_names() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "host_names = [\"vault.example.test\"]\n");
    let calls = Cell::new(0);
    init_with(
        &config,
        request(RecoveryTarget::Terminal),
        typed(PHRASE, &calls),
    )
    .await
    .expect("init");
    let leaf = std::fs::read(data.join("tls/leaf-cert.der")).unwrap();
    let text = String::from_utf8_lossy(&leaf);
    assert!(
        text.contains("vault.example.test"),
        "the leaf names the config host"
    );
}

/// A vault file that appears after the first check (here: while the passphrase is typed) is never touched: the
/// exclusive create fails and nothing of it is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vault_that_appears_after_the_check_survives() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (config, _) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    let other = data.join(VAULT_FILE);
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(key_file.clone())),
        |_prompt| {
            calls.set(calls.get() + 1);
            if !other.exists() {
                std::fs::write(&other, b"another vault").unwrap();
                std::fs::write(data.join("vault.cerberus-wal"), b"its wal").unwrap();
            }
            Ok(PHRASE.to_owned())
        },
    )
    .await
    .expect_err("refused");
    assert!(matches!(error, InitError::VaultExists { .. }), "{error}");
    assert_eq!(std::fs::read(&other).unwrap(), b"another vault");
    assert_eq!(
        std::fs::read(data.join("vault.cerberus-wal")).unwrap(),
        b"its wal"
    );
    assert!(!key_file.exists(), "the key file of this run was removed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_side_files_are_refused_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (config, _) = config_for(&data, "");
    for side in ["vault.cerberus-wal", "vault.cerberus-shm"] {
        std::fs::write(data.join(side), b"old").unwrap();
        let calls = Cell::new(0);
        let error = init_with(
            &config,
            request(RecoveryTarget::Terminal),
            typed(PHRASE, &calls),
        )
        .await
        .expect_err("refused");
        assert!(
            matches!(&error, InitError::VaultExists { path } if path.ends_with(side)),
            "{error}"
        );
        assert!(error.to_string().contains("-wal / -shm"), "{error}");
        assert_eq!(calls.get(), 0);
        assert_eq!(std::fs::read(data.join(side)).unwrap(), b"old");
        std::fs::remove_file(data.join(side)).unwrap();
    }
}

/// The recovery key file must not be in the data folder, however the path is written. Nothing is asked or made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_file_in_the_data_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(data.join("sub")).unwrap();
    let link = dir.path().join("link-to-data");
    std::os::unix::fs::symlink(&data, &link).unwrap();
    let (config, _) = config_for(&data, "");
    let inside = [
        data.join("recovery.txt"),
        data.join("sub").join("recovery.txt"),
        data.join("..").join("data").join("recovery.txt"),
        link.join("recovery.txt"),
        // The names of the vault files themselves.
        data.join("vault.cerberus-wal"),
    ];
    for path in inside {
        let calls = Cell::new(0);
        let error = init_with(
            &config,
            request(RecoveryTarget::File(path.clone())),
            typed(PHRASE, &calls),
        )
        .await
        .expect_err("refused");
        assert!(
            matches!(error, InitError::RecoveryInDataDir { .. }),
            "{path:?}: {error}"
        );
        assert_eq!(calls.get(), 0, "{path:?}");
    }
    assert_eq!(names(&data), ["sub"], "nothing was made");
}

/// A missing folder for the recovery file shows before the passphrase is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_folder_that_does_not_exist_is_refused_before_the_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(
            dir.path().join("missing").join("key.txt"),
        )),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    assert!(matches!(error, InitError::RecoveryFolder { .. }), "{error}");
    assert_eq!(calls.get(), 0);
    assert!(!data.exists());
}

/// A create that fails after the CA and the leaf were written removes what this run made: the TLS folder, the vault
/// file, the key file and the data folder. The slow-KDF-free cost of the tests is below the stored range, so the
/// vault cannot be saved, which is a failure after `issue_ca`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_that_fails_late_removes_only_what_this_run_made() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    let calls = Cell::new(0);
    let mut late = request(RecoveryTarget::File(key_file.clone()));
    late.kdf = Some(KdfParams::insecure_fast_for_tests());
    let error = init_with(&config, late.clone(), typed(PHRASE, &calls))
        .await
        .expect_err("the vault cannot be saved");
    assert!(
        !matches!(error, InitError::VaultExists { .. }),
        "the failure is the late one: {error}"
    );
    assert!(!data.exists(), "the data folder this run made is gone");
    assert!(!key_file.exists());

    // A data folder that was there before stays, with what it held. A TLS folder that was there stays too.
    std::fs::create_dir_all(data.join("tls")).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(data.join("notes.txt"), b"mine").unwrap();
    std::fs::write(data.join("tls").join("keep.txt"), b"mine too").unwrap();
    init_with(&config, late.clone(), typed(PHRASE, &calls))
        .await
        .expect_err("the vault cannot be saved");
    assert_eq!(names(&data), ["notes.txt", "tls"]);
    assert_eq!(names(&data.join("tls")), ["keep.txt"]);

    // Without a TLS folder before the run, the leaf files of this run are removed, and the folder with them.
    std::fs::remove_dir_all(data.join("tls")).unwrap();
    init_with(&config, late, typed(PHRASE, &calls))
        .await
        .expect_err("the vault cannot be saved");
    assert_eq!(names(&data), ["notes.txt"]);
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// A folder that this user cannot write in is refused before the passphrase is asked, not after the vault is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_folder_that_cannot_be_written_is_refused_before_the_prompts() {
    if is_root() {
        return; // root can write anywhere
    }
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let folder = dir.path().join("readonly");
    std::fs::create_dir(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(folder.join("key.txt"))),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        matches!(error, InitError::RecoveryFolderNotWritable { .. }),
        "{error}"
    );
    assert_eq!(calls.get(), 0);
    assert!(!data.exists());
    assert!(names(&folder).is_empty(), "the probe file is gone");
}

/// The recovery file named like a data folder that does not exist yet is the inside-data-dir error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_file_named_like_the_new_data_folder_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (config, _) = config_for(&data, "");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::File(data.clone())),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    assert!(
        matches!(error, InitError::RecoveryInDataDir { .. }),
        "{error}"
    );
    assert_eq!(calls.get(), 0);
    assert!(!data.exists());
}

/// A data folder of another user is refused before the prompts, with the hint to run as the service user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_data_folder_of_another_user_is_refused_before_the_prompts() {
    if is_root() {
        return; // root owns the folder
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cerberusd.toml");
    std::fs::write(&path, "data_dir = \"/tmp\"\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = config::load(Some(&path), &no_env).expect("config");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::Terminal),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("refused");
    assert!(matches!(error, InitError::DataDirOwner { .. }), "{error}");
    assert!(error.to_string().contains("sudo -u cerberus"), "{error}");
    assert_eq!(calls.get(), 0);
}

/// Folders that this run made on the way to a new data folder go with it, and nothing else does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_create_removes_the_parent_folders_it_made() {
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("srv");
    std::fs::create_dir(&existing).unwrap();
    let data = existing.join("a").join("b").join("data");
    // The config file sits in the folder that exists; `config_for` puts it next to the data folder.
    let path = dir.path().join("cerberusd.toml");
    std::fs::write(
        &path,
        format!("data_dir = {:?}\n", data.display().to_string()),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = config::load(Some(&path), &no_env).expect("config");
    let calls = Cell::new(0);
    let mut late = request(RecoveryTarget::Terminal);
    late.kdf = Some(KdfParams::insecure_fast_for_tests());
    init_with(&config, late, typed(PHRASE, &calls))
        .await
        .expect_err("the vault cannot be saved");
    assert!(names(&existing).is_empty(), "{:?}", names(&existing));
    assert_eq!(names(dir.path()), ["cerberusd.toml", "srv"]);
}

/// A TLS write that fails leaves its `.tmp` file. This run removes it, and only it: a folder in the way of the rename
/// stays, as does the data folder that existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_tls_write_leaves_no_tmp_file() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(data.join("tls").join("leaf-key.der")).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(data.join("tls").join("leaf-key.der").join("x"), b"x").unwrap();
    let (config, _) = config_for(&data, "");
    let calls = Cell::new(0);
    let error = init_with(
        &config,
        request(RecoveryTarget::Terminal),
        typed(PHRASE, &calls),
    )
    .await
    .expect_err("the key cannot be renamed over a folder");
    assert!(!matches!(error, InitError::VaultExists { .. }), "{error}");
    assert_eq!(names(&data), ["tls"]);
    assert_eq!(names(&data.join("tls")), ["leaf-key.der"]);
}

#[test]
fn a_key_without_a_file_or_a_terminal_has_no_safe_place() {
    assert!(matches!(
        RecoveryTarget::choose(None, false),
        Err(InitError::NoRecoveryTarget)
    ));
    assert_eq!(
        RecoveryTarget::choose(None, true).unwrap(),
        RecoveryTarget::Terminal
    );
    let file = PathBuf::from("/tmp/key.txt");
    for terminal in [false, true] {
        assert_eq!(
            RecoveryTarget::choose(Some(file.clone()), terminal).unwrap(),
            RecoveryTarget::File(file.clone())
        );
    }
}

fn binary(config: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cerberusd"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("CERBERUSD_DATA_DIR")
        .output()
        .expect("run cerberusd")
}

/// The test captures stdout, so it is not a terminal: the key has no safe place and nothing may be made.
#[test]
fn the_binary_refuses_without_a_terminal_or_a_recovery_file_and_makes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (_config, path) = config_for(&data, "");
    let result = binary(&path, &["init"]);
    assert!(!result.status.success(), "{result:?}");
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("--recovery-out"), "{stderr}");
    assert!(!data.exists(), "no data folder: {:?}", names(dir.path()));
}

#[test]
fn the_binary_refuses_when_the_vault_exists() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_config, path) = config_for(&data, "");
    std::fs::write(data.join(VAULT_FILE), b"an existing vault").unwrap();
    let key_file = dir.path().join("recovery.txt");
    let result = binary(
        &path,
        &["init", "--recovery-out", key_file.to_str().unwrap()],
    );
    assert!(!result.status.success(), "{result:?}");
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("exists"), "{stderr}");
    assert_eq!(
        std::fs::read(data.join(VAULT_FILE)).unwrap(),
        b"an existing vault"
    );
    assert!(!key_file.exists());
}

#[test]
fn the_binary_refuses_a_recovery_file_that_exists() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (_config, path) = config_for(&data, "");
    let key_file = dir.path().join("recovery.txt");
    std::fs::write(&key_file, b"mine").unwrap();
    let result = binary(
        &path,
        &["init", "--recovery-out", key_file.to_str().unwrap()],
    );
    assert!(!result.status.success(), "{result:?}");
    assert_eq!(std::fs::read(&key_file).unwrap(), b"mine");
    assert!(!data.exists());
}
