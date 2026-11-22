//! First-time setup of a server from the desktop (ADR-0034, DEC-SRV-3): a real `cerberusd` serve loop on an empty data
//! directory, the `remote_setup_check` and `remote_setup` commands as the first client, the stored profile, and then
//! the desktop in remote mode against the server that it made. Own test binary: the log capture is the global
//! subscriber of the process. Every secret here is a fake test value.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerberus_core::VaultService;
use cerberus_crypto::KdfParams;
use cerberus_desktop::commands::Dispatch;
use cerberus_desktop::dto::{BackendMode, OneTimeKind, Secret, VaultState, WorkspaceView};
use cerberus_desktop::error::IpcError;
use cerberus_desktop::remote::setup::SetupState;
use cerberus_desktop::{AppPaths, DesktopState, Prefs, StateOptions, ops};
use cerberus_types::{Clock, ManualClock, SystemClock};
use cerberusd::config::{self, Config};
use cerberusd::daemon::{self, DaemonError, ServeOptions};
use cerberusd::setup::read_setup_code;
use common::{FakeShell, MAIN, PHRASE};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, IpcError>) -> String {
    result.expect_err("an error").code
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// A `cerberusd` on a data directory that does not exist yet, with the admin API on and a small setup cost.
struct Server {
    config: Config,
    stop: Option<oneshot::Sender<()>>,
    run: Option<JoinHandle<Result<Option<VaultService>, DaemonError>>>,
    _dir: tempfile::TempDir,
}

impl Server {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cerberusd.toml");
        std::fs::write(
            &path,
            format!(
                "data_dir = {:?}\nbind = [\"127.0.0.1\"]\nport = {}\n[admin]\nenabled = true\n",
                dir.path().join("data").display().to_string(),
                free_port()
            ),
        )
        .expect("write config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let config = config::load(Some(&path), &|_| None).expect("config");
        let (stop, stop_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = oneshot::channel();
        let serve_config = config.clone();
        let options = ServeOptions {
            setup_kdf: Some(KdfParams::new(19_456, 1, 1).expect("kdf")),
            ..ServeOptions::default()
        };
        let run = tokio::spawn(async move {
            daemon::serve_with(
                &serve_config,
                &options,
                async { drop(stop_rx.await) },
                |ready| drop(ready_tx.send(ready.clone())),
            )
            .await
        });
        ready_rx.await.expect("the server is ready");
        Self {
            config,
            stop: Some(stop),
            run: Some(run),
            _dir: dir,
        }
    }

    /// What `cerberusd setup-code` prints.
    fn setup_code(&self) -> String {
        read_setup_code(&self.config)
            .expect("setup code")
            .as_str()
            .trim()
            .to_owned()
    }

    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.run
            .take()
            .expect("running")
            .await
            .expect("join")
            .expect("serve");
    }
}

/// A desktop data folder with no local vault, in local mode.
async fn local_desktop(dir: &Path) -> (DesktopState, Arc<FakeShell>) {
    local_desktop_with(dir, StateOptions::default()).await
}

/// As [`local_desktop`], with state options (a clock that is not the system clock).
async fn local_desktop_with(dir: &Path, options: StateOptions) -> (DesktopState, Arc<FakeShell>) {
    let paths = AppPaths::new(dir.to_path_buf());
    Prefs {
        port: 0,
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(FakeShell::default());
    let state = DesktopState::open(paths, shell.clone(), options)
        .await
        .expect("open");
    (state, shell)
}

/// base64url without padding.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The setup code of the server with another token or another pin.
fn changed_code(original: &str, token: Option<&str>, pin: Option<&str>) -> String {
    let code = cerberus_client::setup::SetupCode::parse(original).expect("a setup code");
    let json = serde_json::json!({
        "url": code.url,
        "token": token.unwrap_or_else(|| code.token.expose()),
        "pin": pin.unwrap_or(&code.pin),
    });
    format!(
        "{}{}",
        cerberus_client::setup::SETUP_CODE_PREFIX,
        b64url(json.to_string().as_bytes())
    )
}

fn private_mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

/// The whole path: a server with no vault, the check, the setup, the stored profile, the recovery key, the switch to
/// remote mode, and a session on the vault that the first client made. No secret is logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_client_sets_up_a_server_and_connects_in_remote_mode() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .init();
    let server = Server::start().await;
    let setup_code = server.setup_code();
    let token = cerberus_client::setup::SetupCode::parse(&setup_code)
        .expect("a setup code")
        .token
        .expose()
        .to_owned();
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, shell) = local_desktop(dir.path()).await;

    // The label check comes first.
    assert_eq!(
        code(ops::remote_setup_check(&state, "evil", Secret::new(setup_code.clone()), None).await),
        "window_not_allowed"
    );
    // The check tells that the server waits, and stores nothing.
    let waiting =
        ops::remote_setup_check(&state, MAIN, Secret::new(format!("  {setup_code}\n")), None)
            .await
            .expect("check");
    assert_eq!(waiting.state, SetupState::Pending);
    assert!(waiting.url.starts_with("https://"), "{}", waiting.url);
    assert!(state.prefs().remote.profiles.is_empty());

    let created = ops::remote_setup(
        &state,
        MAIN,
        Secret::new(setup_code.clone()),
        "  alpha ".to_owned(),
        Secret::new(PHRASE.to_owned()),
        Some("laptop".to_owned()),
        None,
    )
    .await
    .expect("setup");

    // The profile is stored and not the active one; the bundle never was a file of its own.
    assert!(created.store_error.is_none());
    let profile = created.profile.as_ref().expect("the profile is stored");
    assert_eq!(profile.label, "laptop");
    assert_eq!(profile.url, waiting.url);
    assert!(!profile.active);
    assert_eq!(state.prefs().remote.profiles.len(), 1);
    assert_eq!(state.prefs().remote.active, None);
    let stored = dir.path().join("remote").join(&profile.id);
    assert_eq!(
        private_mode(&stored.join(cerberus_desktop::remote::profile::KEY_FILE)),
        0o600
    );
    assert_eq!(private_mode(&stored), 0o700);
    assert!(!dir.path().join("remote").join("pending").exists());
    let overview = ops::remote_status(&state, MAIN).await.expect("overview");
    assert_eq!(overview.mode, BackendMode::Local);
    assert_eq!(overview.profiles.len(), 1);

    // The recovery key is shown once, and can be copied although no local operator is unlocked.
    let key = format!("{:?}", created.recovery_key);
    assert_eq!(key, "[REDACTED]");
    // The key has its own lifetime: a lock or a lagged pump clears the values of an unlock, not this.
    state.clear_held();
    ops::remote_setup_copy_key(&state, MAIN)
        .await
        .expect("copy the recovery key");
    let recovery_key = shell.clipboard.lock().unwrap().clone().expect("copied");
    assert!(recovery_key.starts_with("CRK1-"), "{recovery_key}");

    // A second setup finds a server that is not waiting any more. The listener stops once the answer has left, so
    // the first check may still hit it: wait for it to go.
    let mut gone = None;
    for _ in 0..100 {
        match ops::remote_setup_check(&state, MAIN, Secret::new(setup_code.clone()), None).await {
            Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(error) => {
                gone = Some(error.code);
                break;
            }
        }
    }
    assert!(
        matches!(
            gone.as_deref(),
            Some("setup_wrong_server" | "remote_unreachable")
        ),
        "the setup listener is gone: {gone:?}"
    );

    // Connect, restart (a new state on the same folder), unlock, and work on the server vault.
    assert!(
        ops::remote_activate(&state, MAIN, Some(profile.id.clone()), false)
            .await
            .expect("connect"),
        "the switch needs a restart"
    );
    state.shutdown().await;
    drop(state);
    let remote = DesktopState::open(
        AppPaths::new(dir.path().to_path_buf()),
        Arc::new(FakeShell::default()),
        StateOptions::default(),
    )
    .await
    .expect("open in remote mode");
    assert!(remote.remote().is_some(), "remote mode");
    let mut reachable = false;
    for _ in 0..100 {
        let status = ops::vault_status(&remote, MAIN).await.expect("status");
        if status.remote.is_some_and(|link| link.reachable) {
            reachable = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(reachable, "the server serves its vault after the setup");
    let status = ops::vault_status(&remote, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed, "no session yet");
    let session = ops::vault_unlock(
        &remote,
        MAIN,
        profile.operator_id.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock with the passphrase of the first owner");
    assert_eq!(session.operator_id, profile.operator_id);
    let workspaces: Vec<WorkspaceView> = Dispatch::workspace_list(&remote, MAIN)
        .await
        .expect("a remote call works");
    assert!(workspaces.is_empty());
    remote.shutdown().await;
    server.stop().await;

    // No log line holds the code, the token, the passphrase or the recovery key.
    let log = String::from_utf8_lossy(&capture.0.lock().unwrap()).into_owned();
    for secret in [
        setup_code.as_str(),
        token.as_str(),
        PHRASE,
        recovery_key.as_str(),
        "PRIVATE KEY",
    ] {
        assert!(!log.contains(secret), "the log holds a secret");
    }
}

/// A refused setup changes nothing on the desktop, and the server waits for the next try.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_setup_stores_nothing_and_the_server_keeps_waiting() {
    let server = Server::start().await;
    let setup_code = server.setup_code();
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, _shell) = local_desktop(dir.path()).await;
    let setup = |text: String, owner: &str, phrase: &str, url: Option<&str>| {
        ops::remote_setup(
            &state,
            MAIN,
            Secret::new(text),
            owner.to_owned(),
            Secret::new(phrase.to_owned()),
            None,
            url.map(ToOwned::to_owned),
        )
    };

    // Not a code, and not quoted back.
    let error = ops::remote_setup_check(&state, MAIN, Secret::new("canary-text".to_owned()), None)
        .await
        .expect_err("not a code");
    assert_eq!(error.code, "validation_failed");
    assert_eq!(error.fields[0].field, "code");
    assert!(!format!("{error:?}").contains("canary-text"));
    // A bad address.
    assert_eq!(
        code(
            ops::remote_setup_check(
                &state,
                MAIN,
                Secret::new(setup_code.clone()),
                Some("http://127.0.0.1:1".to_owned())
            )
            .await
        ),
        "validation_failed"
    );
    // An address that nothing listens on.
    assert_eq!(
        code(
            ops::remote_setup_check(
                &state,
                MAIN,
                Secret::new(setup_code.clone()),
                Some(format!("https://127.0.0.1:{}", free_port()))
            )
            .await
        ),
        "remote_unreachable"
    );
    // The right address with the pin of another server.
    let other_pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    assert_eq!(
        code(
            ops::remote_setup_check(
                &state,
                MAIN,
                Secret::new(changed_code(&setup_code, None, Some(other_pin))),
                None
            )
            .await
        ),
        "setup_wrong_server"
    );
    // A wrong token.
    assert_eq!(
        code(
            setup(
                changed_code(&setup_code, Some("wrong"), None),
                "alpha",
                PHRASE,
                None
            )
            .await
        ),
        "unauthenticated"
    );
    // A weak passphrase and an empty name: the fields come back.
    let weak = setup(setup_code.clone(), "alpha", "password1234", None)
        .await
        .expect_err("weak");
    assert_eq!(weak.code, "validation_failed");
    assert!(weak.fields.iter().any(|f| f.field == "passphrase"));
    let nameless = setup(setup_code.clone(), "  ", PHRASE, None)
        .await
        .expect_err("no name");
    assert!(nameless.fields.iter().any(|f| f.field == "owner_label"));
    // An address that is not a name of the server.
    let elsewhere = setup(
        setup_code.clone(),
        "alpha",
        PHRASE,
        Some("https://not-this-server.example.test:7373"),
    )
    .await
    .expect_err("another host");
    assert!(
        matches!(
            elsewhere.code.as_str(),
            "validation_failed" | "remote_unreachable"
        ),
        "{elsewhere:?}"
    );

    // Nothing was stored, and the server still waits.
    assert!(state.prefs().remote.profiles.is_empty());
    assert!(!dir.path().join("remote").exists());
    let waiting = ops::remote_setup_check(&state, MAIN, Secret::new(setup_code), None)
        .await
        .expect("still waiting");
    assert_eq!(waiting.state, SetupState::Pending);
    state.shutdown().await;
    server.stop().await;
}

/// A manual clock `seconds` away from the system clock.
fn clock_at(seconds: i64) -> StateOptions {
    let now = SystemClock.now().as_second() + seconds;
    StateOptions {
        clock: Some(Arc::new(ManualClock::new(
            jiff::Timestamp::from_second(now).expect("a time"),
        ))),
        ..StateOptions::default()
    }
}

async fn set_up(
    state: &DesktopState,
    server: &Server,
) -> cerberus_desktop::remote::setup::RemoteSetupView {
    ops::remote_setup(
        state,
        MAIN,
        Secret::new(server.setup_code()),
        "alpha".to_owned(),
        Secret::new(PHRASE.to_owned()),
        None,
        None,
    )
    .await
    .expect("the server is set up")
}

/// The server back-dates its client certificate by a few minutes. A desktop clock that is behind must still store the
/// bundle, a staged import of the person must stay, and a clock past the end of the certificate must not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clock_that_is_behind_still_stores_the_bundle_and_a_stage_stays() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    // Two days behind: the certificate does not exist yet for this clock.
    let (state, _shell) = local_desktop_with(dir.path(), clock_at(-2 * 86_400)).await;
    let stage = dir.path().join("remote").join("pending").join("keep");
    std::fs::create_dir_all(&stage).expect("a staged import");
    let created = set_up(&state, &server).await;
    assert!(created.store_error.is_none(), "{:?}", created.store_error);
    assert!(created.profile.is_some());
    assert!(
        stage.is_dir(),
        "a staged import of the person is not touched"
    );
    state.shutdown().await;
    server.stop().await;

    // A clock after the end of the certificate: refused, but the key and the bundle are held.
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, shell) = local_desktop_with(dir.path(), clock_at(1_000 * 86_400)).await;
    let created = set_up(&state, &server).await;
    assert!(created.profile.is_none());
    assert_eq!(
        created.store_error.as_ref().map(|e| e.code.as_str()),
        Some("invalid_bundle")
    );
    assert!(state.prefs().remote.profiles.is_empty());
    ops::remote_setup_copy_key(&state, MAIN)
        .await
        .expect("the key is held");
    assert!(
        shell
            .clipboard
            .lock()
            .unwrap()
            .clone()
            .expect("copied")
            .starts_with("CRK1-")
    );
    assert_eq!(
        code(ops::remote_setup_save(&state, MAIN).await),
        "invalid_bundle"
    );
    state.shutdown().await;
    server.stop().await;
}

/// The vault exists on the server, but this desktop cannot keep the profile: the key still comes back, and "Save the
/// connection" works from the held bundle once the problem is gone. The held values end with `remote_setup_finish`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_store_keeps_the_key_and_the_bundle_until_the_person_is_done() {
    let server = Server::start().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (state, shell) = local_desktop(dir.path()).await;
    // A file where the folder of the profiles must be.
    let blocker = dir.path().join("remote");
    std::fs::write(&blocker, b"in the way").expect("blocker");

    let created = set_up(&state, &server).await;
    assert!(created.profile.is_none());
    assert_eq!(
        created.store_error.as_ref().map(|e| e.code.as_str()),
        Some("internal")
    );
    assert!(state.prefs().remote.profiles.is_empty());
    assert!(!format!("{created:?}").contains("CRK1-"));
    // The label check comes first on the three new commands.
    assert_eq!(
        code(ops::remote_setup_save(&state, "evil").await),
        "window_not_allowed"
    );
    assert_eq!(
        code(ops::remote_setup_copy_key(&state, "evil").await),
        "window_not_allowed"
    );
    assert_eq!(
        code(ops::remote_setup_finish(&state, "evil").await),
        "window_not_allowed"
    );
    // Another one-time kind never gives the server key, and a lock does not drop it.
    state.clear_held();
    assert_eq!(
        code(ops::clipboard_copy_once(&state, MAIN, OneTimeKind::RecoveryKey).await),
        "no_vault"
    );
    ops::remote_setup_copy_key(&state, MAIN)
        .await
        .expect("copy");
    assert!(
        shell
            .clipboard
            .lock()
            .unwrap()
            .clone()
            .expect("copied")
            .starts_with("CRK1-")
    );

    // Save again while the problem stays, then after it is gone.
    assert_eq!(code(ops::remote_setup_save(&state, MAIN).await), "internal");
    std::fs::remove_file(&blocker).expect("remove the blocker");
    let profile = ops::remote_setup_save(&state, MAIN).await.expect("save");
    assert!(!profile.active);
    assert_eq!(state.prefs().remote.profiles.len(), 1);
    assert_eq!(state.prefs().remote.profiles[0].id, profile.id);
    assert!(
        dir.path()
            .join("remote")
            .join(&profile.id)
            .join(cerberus_desktop::remote::profile::KEY_FILE)
            .is_file()
    );
    // A second save replaces the same profile.
    ops::remote_setup_save(&state, MAIN)
        .await
        .expect("save again");
    assert_eq!(state.prefs().remote.profiles.len(), 1);
    assert!(
        ops::remote_activate(&state, MAIN, Some(profile.id.clone()), false)
            .await
            .expect("connect")
    );

    ops::remote_setup_finish(&state, MAIN)
        .await
        .expect("finish");
    ops::remote_setup_finish(&state, MAIN)
        .await
        .expect("finish again");
    assert_eq!(
        code(ops::remote_setup_copy_key(&state, MAIN).await),
        "not_found"
    );
    assert_eq!(
        code(ops::remote_setup_save(&state, MAIN).await),
        "not_found"
    );
    assert_eq!(state.prefs().remote.profiles.len(), 1, "the profile stays");
    state.shutdown().await;
    server.stop().await;
}

#[test]
fn the_helper_encodes_base64url() {
    assert_eq!(b64url(b"{}"), "e30");
    assert_eq!(b64url(b"abc"), "YWJj");
    assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
}
