//! Tests of the first-time setup (DEC-SRV-3): a real `cerberusd` serve loop on an empty data directory, the real setup
//! listener over TLS 1.3, and the client library of `cerberus-client` as the first client. The key-derivation cost is
//! fixed and small, so no cost test runs. Every secret here is a fake test value.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use cerberus_admin::bundle::AdminBundle;
use cerberus_admin::clients::AdminClients;
use cerberus_api::tls::CaExport;
use cerberus_client::setup::{SetupCode, SetupRequest, health, setup};
use cerberus_client::{ClientError, PinnedHttps, WireSecret};
use cerberus_core::VaultService;
use cerberus_crypto::KdfParams;
use cerberus_types::{Clock, ErrorCode, SystemClock, VaultStateKind};
use cerberusd::config::{self, Config};
use cerberusd::daemon::{self, DaemonError, Ready, ServeOptions, VAULT_FILE};
use cerberusd::https;
use cerberusd::setup::{FREE_ATTEMPTS, SETUP_CODE_FILE, SetupCodeError, read_setup_code};
use cerberusd::unlock::registry_path;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const PHRASE: &str = "orbit velvet canyon mosaic 7";

type Run = JoinHandle<Result<Option<VaultService>, DaemonError>>;

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

/// The settings of a data directory that does not exist yet. The config file is kept next to it.
fn config_for(dir: &Path, admin: bool, extra: &str) -> (Config, PathBuf) {
    let data = dir.join("data");
    let path = dir.join("cerberusd.toml");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\nbind = [\"127.0.0.1\"]\nport = {}\n{extra}\n[admin]\nenabled = {admin}\n",
            data.display().to_string(),
            free_port()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (config::load(Some(&path), &no_env).expect("config"), path)
}

fn start(config: &Config) -> (oneshot::Sender<()>, Run, oneshot::Receiver<Ready>) {
    start_paused(config, None)
}

/// As [`start`], with a pause inside the setup (after the vault file is made, before the client is enrolled).
fn start_paused(
    config: &Config,
    pause: Option<std::time::Duration>,
) -> (oneshot::Sender<()>, Run, oneshot::Receiver<Ready>) {
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let (ready_tx, ready_rx) = oneshot::channel::<Ready>();
    let config = config.clone();
    let options = ServeOptions {
        setup_kdf: Some(KdfParams::new(19_456, 1, 1).expect("kdf")),
        setup_pause: pause,
    };
    let run = tokio::spawn(async move {
        daemon::serve_with(&config, &options, async { drop(stop_rx.await) }, |ready| {
            drop(ready_tx.send(ready.clone()));
        })
        .await
    });
    (stop_tx, run, ready_rx)
}

/// Waits until the daemon went on with the new vault (its unlock socket exists). The unlock of the new vault runs after the
/// answer has left, so a stop that comes at once would end the daemon while it still waited for its first client.
async fn wait_served(config: &Config) {
    for _ in 0..200 {
        if config.data_dir.join("cerberusd.sock").exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the daemon did not go on with the vault");
}

fn code_of(config: &Config) -> SetupCode {
    SetupCode::parse(read_setup_code(config).expect("setup code").as_str()).expect("a setup code")
}

fn request(passphrase: &str) -> SetupRequest {
    SetupRequest::new("alpha", WireSecret::new(passphrase.to_owned()))
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

fn api_code(error: &ClientError) -> Option<ErrorCode> {
    error.code()
}

fn with_token(code: &SetupCode, token: &str) -> SetupCode {
    SetupCode {
        url: code.url.clone(),
        token: WireSecret::new(token.to_owned()),
        pin: code.pin.clone(),
    }
}

/// The client certificate and key of a bundle, DER.
fn identity(bundle: &AdminBundle) -> (Vec<u8>, Vec<u8>) {
    let cert = CertificateDer::from_pem_slice(bundle.client_cert_pem.as_bytes()).expect("cert");
    let key =
        PrivatePkcs8KeyDer::from_pem_slice(bundle.client_key_pem.expose().as_bytes()).expect("key");
    (cert.as_ref().to_vec(), key.secret_pkcs8_der().to_vec())
}

/// The whole path: an empty data directory, the daemon starts and waits, the first client makes the vault, and the
/// daemon serves it with the new CA and the vault unlocked, with no restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_client_creates_the_vault_and_the_daemon_serves_it_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let data = config.data_dir.clone();
    let (stop, run, ready) = start(&config);
    let ready = ready.await.expect("ready");
    assert_eq!(ready.addrs.len(), 1, "the setup listener is up");
    assert!(!ready.socket.exists(), "no unlock socket before the vault");
    assert_eq!(mode(&data), 0o700, "the daemon made the data directory");
    assert_eq!(
        mode(&data.join(SETUP_CODE_FILE)),
        0o600,
        "the code is private"
    );
    assert_eq!(names(&data), [SETUP_CODE_FILE.to_owned()]);

    // The waiting server says so, and refuses every other route.
    let code = code_of(&config);
    let state = health(&code).await.expect("health");
    assert_eq!(state.vault, "no_vault");
    assert_eq!(state.setup.as_deref(), Some("pending"));
    let http = PinnedHttps::for_setup(&code.url, &code.pin, std::time::Duration::from_secs(20))
        .expect("transport");
    for path in ["/v1/status", "/admin/v1/hello", "/mcp"] {
        let answer = http.get(path).await.expect("answer");
        assert_eq!(answer.status(), 503, "{path}");
    }

    // A wrong token, a refused passphrase and a bad URL change nothing.
    let wrong = setup(&with_token(&code, "not-the-token"), &request(PHRASE))
        .await
        .expect_err("wrong token");
    assert_eq!(
        api_code(&wrong),
        Some(ErrorCode::Unauthenticated),
        "{wrong}"
    );
    let weak = setup(&code, &request("password1234"))
        .await
        .expect_err("weak passphrase");
    assert_eq!(api_code(&weak), Some(ErrorCode::ValidationFailed), "{weak}");
    let mut elsewhere = request(PHRASE);
    elsewhere.url = Some("https://evil.example.test:7373".to_owned());
    let refused = setup(&code, &elsewhere).await.expect_err("foreign host");
    assert_eq!(
        api_code(&refused),
        Some(ErrorCode::ValidationFailed),
        "{refused}"
    );
    let mut unnamed = request(PHRASE);
    unnamed.device_label = Some(String::new());
    let refused = setup(&code, &unnamed).await.expect_err("empty label");
    assert_eq!(
        api_code(&refused),
        Some(ErrorCode::ValidationFailed),
        "{refused}"
    );
    assert_eq!(
        names(&data),
        [SETUP_CODE_FILE.to_owned()],
        "nothing was made"
    );

    // The real one.
    let mut asked = request(PHRASE);
    asked.device_label = Some("laptop".to_owned());
    let outcome = setup(&code, &asked).await.expect("setup");
    assert!(
        outcome.recovery_key.expose().starts_with("CRK1-"),
        "a recovery key"
    );
    assert!(outcome.ca_pin.starts_with("sha256/"));
    assert!(!format!("{outcome:?}").contains("CRK1-"));
    let body = outcome.bundle.to_json().expect("bundle json");
    let bundle: AdminBundle = serde_json::from_slice(&body).expect("an admin bundle");
    bundle.check(SystemClock.now()).expect("a valid bundle");
    assert_eq!(bundle.ca_pin, outcome.ca_pin);
    assert_eq!(bundle.label, "laptop");
    assert_eq!(bundle.url, code.url);
    assert_eq!(bundle.operator_id.to_string(), outcome.owner_id);

    // The files: the vault, the TLS folder, the CA file, the registry, the unlock socket. The code is gone.
    assert!(!data.join(SETUP_CODE_FILE).exists(), "the code is used up");
    assert_eq!(mode(&data.join(VAULT_FILE)), 0o600);
    assert!(data.join("tls/leaf-cert.der").is_file());
    let registry = AdminClients::load(&registry_path(&data)).expect("registry");
    assert_eq!(registry.list().len(), 1);
    assert_eq!(registry.list()[0].label, "laptop");
    assert_eq!(registry.list()[0].id, bundle.id);

    // The same port now serves the vault: the CA of the bundle verifies it, the bootstrap pin no longer matches, and
    // the vault is unlocked, as `create_vault` leaves it.
    let ca = bundle.ca_cert_der().expect("ca");
    assert_eq!(CaExport::from_der(&ca).expect("export").pin, outcome.ca_pin);
    let addr = ready.addrs[0];
    // The daemon goes on with the vault right after the answer left: the listener changes within moments.
    let mut open = None;
    for _ in 0..100 {
        if let Ok(reply) = https::request(addr, &ca, "GET", "/v1/health", None, None).await {
            open = Some(reply);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let open = open.expect("health of the vault");
    assert_eq!(open.status, 200);
    assert!(ready.socket.exists(), "the unlock socket is up now");
    assert!(data.join(daemon::CA_PEM_FILE).is_file());
    let json: serde_json::Value = serde_json::from_slice(&open.body).expect("json");
    assert_eq!(json["vault"], "unlocked");
    let again = setup(&code, &request(PHRASE))
        .await
        .expect_err("second setup");
    assert!(matches!(again, ClientError::PinMismatch), "{again}");

    // The bundle works: the admin gate opens with its certificate.
    let (cert, key) = identity(&bundle);
    let hello = https::request_as(
        addr,
        &ca,
        Some((cert.as_slice(), key.as_slice())),
        "GET",
        "/admin/v1/hello",
        None,
        None,
    )
    .await
    .expect("hello");
    assert_eq!(hello.status, 200);

    stop.send(()).expect("stop");
    let core = run
        .await
        .expect("join")
        .expect("serve")
        .expect("a vault was made");
    assert_eq!(core.state(), VaultStateKind::Sealed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_starts_without_a_vault_and_stops_with_no_service_and_no_code_file() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    let ready = ready.await.expect("ready");
    assert!(!ready.addrs.is_empty());
    let first = code_of(&config);
    stop.send(()).expect("stop");
    let stopped = run.await.expect("join").expect("serve");
    assert!(stopped.is_none(), "no vault was made");
    assert!(
        !config.data_dir.join(SETUP_CODE_FILE).exists(),
        "the code goes with the listener"
    );
    assert!(!config.data_dir.join(VAULT_FILE).exists());

    // A new start makes a new code; the old one is not accepted.
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let second = code_of(&config);
    assert_ne!(first.token.expose(), second.token.expose());
    assert_ne!(first.pin, second.pin, "a new setup certificate");
    let old = setup(&first, &request(PHRASE)).await.expect_err("old code");
    assert!(matches!(old, ClientError::PinMismatch), "{old}");
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

/// Wrong tokens make their address wait longer (no permanent lockout: a flood must not lock the owner out until a
/// restart). The health says `locked_out` for the waiting address, and the right token works after the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_tokens_make_the_address_wait_and_the_right_token_works_after_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let code = code_of(&config);
    let wrong = with_token(&code, "not-the-token");
    // The free attempts, and the one that starts the wait, are plain refusals.
    for _ in 0..=FREE_ATTEMPTS {
        let error = setup(&wrong, &request(PHRASE)).await.expect_err("wrong");
        assert_eq!(
            api_code(&error),
            Some(ErrorCode::Unauthenticated),
            "{error}"
        );
    }
    // Now the address has to wait, also with the right token, and it is told how long.
    let waiting = setup(&code, &request(PHRASE)).await.expect_err("waiting");
    assert_eq!(
        api_code(&waiting),
        Some(ErrorCode::TooManyFailures),
        "{waiting}"
    );
    let api = waiting.api().expect("api error");
    assert!(api.retryable);
    assert!(
        api.retry_after_seconds()
            .is_some_and(|s| (1..=3).contains(&s))
    );
    assert_eq!(
        health(&code).await.expect("health").setup.as_deref(),
        Some("locked_out")
    );
    assert!(!config.data_dir.join(VAULT_FILE).exists());
    // After the wait nothing is locked: no restart is needed.
    tokio::time::sleep(std::time::Duration::from_millis(2300)).await;
    assert_eq!(
        health(&code).await.expect("health").setup.as_deref(),
        Some("pending")
    );
    setup(&code, &request(PHRASE))
        .await
        .expect("setup after the wait");
    wait_served(&config).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_one_of_several_simultaneous_setups_makes_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let code = code_of(&config);
    let asked = request(PHRASE);
    let (a, b, c) = tokio::join!(
        setup(&code, &asked),
        setup(&code, &asked),
        setup(&code, &asked)
    );
    let results = [a, b, c];
    let made = results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(made, 1, "{results:?}");
    for failed in results.iter().filter_map(|result| result.as_ref().err()) {
        // Either the second call met the running one (conflict), or the listener had closed already.
        assert!(
            matches!(
                failed,
                ClientError::PinMismatch
                    | ClientError::Connect(_)
                    | ClientError::Transport(_)
                    | ClientError::Tls(_)
            ) || api_code(failed) == Some(ErrorCode::Conflict),
            "{failed}"
        );
    }
    wait_served(&config).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_some());
}

/// A vault file that appears while the daemon waits (a backup copied in) is never replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vault_file_that_appears_while_waiting_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let code = code_of(&config);
    std::fs::write(config.data_dir.join(VAULT_FILE), b"an existing vault").unwrap();
    let error = setup(&code, &request(PHRASE)).await.expect_err("refused");
    assert_eq!(api_code(&error), Some(ErrorCode::Conflict), "{error}");
    assert_eq!(
        std::fs::read(config.data_dir.join(VAULT_FILE)).unwrap(),
        b"an existing vault"
    );
    // `setup-code` knows there is nothing to set up.
    assert!(matches!(
        read_setup_code(&config),
        Err(SetupCodeError::VaultExists { .. })
    ));
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

/// A setup that fails after the vault was made removes everything it made, so the same code can be used again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_that_fails_late_removes_what_it_made_and_can_be_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let data = config.data_dir.clone();
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let code = code_of(&config);
    // The registry cannot be saved: a folder sits where its file goes.
    std::fs::create_dir(registry_path(&data)).unwrap();
    let error = setup(&code, &request(PHRASE)).await.expect_err("fails");
    assert_eq!(api_code(&error), Some(ErrorCode::Internal), "{error}");
    assert_eq!(
        names(&data),
        [
            registry_path(&data)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            SETUP_CODE_FILE.to_owned()
        ],
        "no vault file, no TLS files"
    );
    std::fs::remove_dir(registry_path(&data)).unwrap();
    let outcome = setup(&code, &request(PHRASE)).await.expect("second try");
    assert!(outcome.recovery_key.expose().starts_with("CRK1-"));
    wait_served(&config).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_some());
}

/// Without the admin API there is no bundle to give, so the daemon waits and serves nothing, and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_admin_api_the_daemon_waits_and_serves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), false, "");
    let (stop, run, ready) = start(&config);
    let ready = ready.await.expect("ready");
    assert!(ready.addrs.is_empty());
    assert!(matches!(
        read_setup_code(&config),
        Err(SetupCodeError::NotPending { .. })
    ));
    assert!(std::net::TcpStream::connect(("127.0.0.1", config.port)).is_err());
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

#[test]
fn a_code_file_that_nobody_serves_is_stale() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    std::fs::create_dir(&config.data_dir).unwrap();
    std::fs::write(
        config.data_dir.join(SETUP_CODE_FILE),
        "cerberus-setup:1:x\n",
    )
    .unwrap();
    assert!(matches!(
        read_setup_code(&config),
        Err(SetupCodeError::NotListening { .. })
    ));
}

fn binary(config: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cerberusd"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run cerberusd")
}

/// `cerberusd setup-code` and `cerberusd status`, as the operator runs them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_setup_code_and_status_commands() {
    let dir = tempfile::tempdir().unwrap();
    let (config, path) = config_for(dir.path(), true, "");
    let run_binary = |args: &'static [&'static str]| {
        let path = path.clone();
        tokio::task::spawn_blocking(move || binary(&path, args))
    };

    // Nothing waits yet.
    let none = run_binary(&["setup-code"]).await.unwrap();
    assert!(!none.status.success());
    assert!(String::from_utf8_lossy(&none.stderr).contains("no setup is pending"));
    let status = run_binary(&["status"]).await.unwrap();
    assert!(status.status.success());
    let said = String::from_utf8_lossy(&status.stdout);
    assert!(said.contains("no vault yet"), "{said}");
    assert!(
        said.contains("no cerberusd waits"),
        "it must not say that a daemon waits when none runs: {said}"
    );

    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let status = run_binary(&["status"]).await.unwrap();
    assert!(String::from_utf8_lossy(&status.stdout).contains("waits for its first client"));
    let shown = run_binary(&["setup-code"]).await.unwrap();
    assert!(
        shown.status.success(),
        "{}",
        String::from_utf8_lossy(&shown.stderr)
    );
    let text = String::from_utf8(shown.stdout).unwrap();
    let code = SetupCode::parse(&text).expect("a setup code");
    assert_eq!(
        text.trim(),
        std::fs::read_to_string(config.data_dir.join(SETUP_CODE_FILE))
            .unwrap()
            .trim()
    );
    setup(&code, &request(PHRASE))
        .await
        .expect("setup with the printed code");

    // The vault exists now.
    let gone = run_binary(&["setup-code"]).await.unwrap();
    assert!(!gone.status.success());
    assert!(String::from_utf8_lossy(&gone.stderr).contains("has a vault already"));
    wait_served(&config).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_some());
}

/// The real binary, the real cost test: `cerberusd serve` on an empty folder, a client makes the vault, and the log of
/// the daemon has the pin and the code file path but none of the secrets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_real_binary_measures_the_cost_and_never_logs_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (config, path) = config_for(dir.path(), true, "");
    let log = dir.path().join("daemon.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cerberusd"))
        .arg("--config")
        .arg(&path)
        .arg("serve")
        .stderr(std::fs::File::create(&log).unwrap())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn cerberusd");
    let mut code = None;
    for _ in 0..200 {
        if let Ok(text) = read_setup_code(&config) {
            code = Some(SetupCode::parse(text.as_str()).expect("a setup code"));
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let code = code.expect("the daemon waits for its first client");
    let secret = "orbit velvet canyon mosaic 7";
    let outcome = setup(&code, &request(secret)).await;
    // Wait for the vault to be served before the daemon is stopped.
    let served = {
        let mut served = false;
        for _ in 0..200 {
            if config.data_dir.join("cerberusd.sock").exists() {
                served = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        served
    };
    child.kill().expect("stop cerberusd");
    child.wait().expect("wait");
    let outcome = outcome.expect("setup with the measured cost");
    assert!(served, "the daemon went on with the vault");
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.contains(&code.pin), "the pin is logged:\n{logged}");
    assert!(
        logged.contains("setup-code"),
        "the code file path is logged"
    );
    for secret in [
        code.token.expose(),
        secret,
        outcome.recovery_key.expose(),
        outcome.bundle.client_key_pem.expose(),
    ] {
        assert!(!logged.contains(secret), "a secret is in the log");
    }
}

/// DEC-SRV-3: the admin API is on when the config does not say otherwise, so a fresh default install waits for the first
/// client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_config_without_the_admin_table_waits_for_the_first_client() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cerberusd.toml");
    let data = dir.path().join("data");
    std::fs::write(
        &path,
        format!(
            "data_dir = {:?}\nbind = [\"127.0.0.1\"]\nport = {}\n",
            data.display().to_string(),
            free_port()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = config::load(Some(&path), &no_env).expect("config");
    assert!(config.admin.enabled);
    let (stop, run, ready) = start(&config);
    assert_eq!(ready.await.expect("ready").addrs.len(), 1);
    let code = code_of(&config);
    assert_eq!(health(&code).await.expect("health").vault, "no_vault");
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

/// A TLS client that accepts any certificate (the tests need a raw connection that the client library cannot give).
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type RawTls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

async fn raw_connect(addr: std::net::SocketAddr) -> RawTls {
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAny))
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            tcp,
        )
        .await
        .unwrap()
}

/// Reads one HTTP/1.1 answer: the status and the body.
async fn raw_answer(stream: &mut RawTls) -> (u16, String) {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some(head_end) = text.find("\r\n\r\n") {
            let length = text[..head_end]
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if buf.len() >= head_end + 4 + length {
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
    (status, body)
}

fn raw_setup_request(token: &str) -> String {
    let body = format!(
        "{{\"setup_token\":\"{token}\",\"owner_label\":\"alpha\",\"passphrase\":\"{PHRASE}\"}}"
    );
    format!(
        "POST /v1/setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

fn temp_vault_names(data: &Path) -> Vec<String> {
    names(data)
        .into_iter()
        .filter(|name| name.starts_with("vault.cerberus.setup-"))
        .filter(|name| !name.ends_with("-wal") && !name.ends_with("-shm"))
        .collect()
}

/// HIGH regression: a client that ends its connection while the vault is being made must not leave a half vault. Before
/// the fix the creation ran inside the connection's future, so it was dropped half way: `vault.cerberus` stayed, every
/// later setup got `409`, and a restart could not start. Now the setup runs in a task of its own, builds the vault under a
/// temporary name, and removes everything (and revokes the enrolment) when nobody is left to receive the recovery key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_leaves_during_the_setup_leaves_no_vault_and_the_setup_can_be_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let data = config.data_dir.clone();
    let (stop, run, ready) = start_paused(&config, Some(std::time::Duration::from_millis(1500)));
    drop(ready.await.expect("ready"));
    let code = code_of(&config);

    // The client gives up after 300 ms, while the server is in the middle of the setup.
    let gave_up = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        setup(&code, &request(PHRASE)),
    )
    .await;
    assert!(gave_up.is_err(), "the client left before the answer");
    // Mid-setup: the vault has only its temporary name.
    assert!(!data.join(VAULT_FILE).exists(), "no vault.cerberus yet");
    assert_eq!(temp_vault_names(&data).len(), 1, "{:?}", names(&data));

    // The setup ends by itself and takes its files with it.
    let mut gone = false;
    for _ in 0..100 {
        if temp_vault_names(&data).is_empty() && !data.join("tls").exists() {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        gone,
        "the files of the setup are removed: {:?}",
        names(&data)
    );
    assert!(!data.join(VAULT_FILE).exists());
    let registry = AdminClients::load(&registry_path(&data)).expect("registry");
    assert!(
        registry
            .list()
            .iter()
            .all(|client| client.revoked_at.is_some()),
        "no live enrolment of a vault that is gone"
    );

    // The same code can be used again, and now it works.
    let outcome = setup(&code, &request(PHRASE)).await.expect("second try");
    assert!(outcome.recovery_key.expose().starts_with("CRK1-"));
    assert!(data.join(VAULT_FILE).is_file());
    assert!(temp_vault_names(&data).is_empty(), "{:?}", names(&data));
    wait_served(&config).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_some());
}

/// The temporary files of a setup that was killed are not the vault: they do not block a new start or a new setup, and
/// the daemon removes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn temporary_files_of_a_killed_setup_do_not_block_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let data = config.data_dir.clone();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "vault.cerberus.setup-0123456789ab",
        "vault.cerberus.setup-0123456789ab-wal",
        "vault.cerberus.setup-0123456789ab-shm",
    ] {
        std::fs::write(data.join(name), b"half a vault").unwrap();
    }
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("the daemon starts"));
    assert!(temp_vault_names(&data).is_empty(), "{:?}", names(&data));
    let outcome = setup(&code_of(&config), &request(PHRASE))
        .await
        .expect("setup");
    assert!(outcome.recovery_key.expose().starts_with("CRK1-"));
    wait_served(&config).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_some());
}

/// MEDIUM regression: a stop that comes while a setup runs must let the answer with the recovery key leave. Before the
/// fix the stop branch locked and closed the vault, `serve` returned, and the runtime tore the connection down while the
/// body was written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_during_a_setup_still_delivers_the_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let data = config.data_dir.clone();
    let (stop, run, ready) = start_paused(&config, Some(std::time::Duration::from_millis(1000)));
    drop(ready.await.expect("ready"));
    let code = code_of(&config);
    let client = tokio::spawn(async move { setup(&code, &request(PHRASE)).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    stop.send(()).expect("stop");
    let outcome = client
        .await
        .expect("join")
        .expect("the answer was delivered");
    assert!(outcome.recovery_key.expose().starts_with("CRK1-"));
    let stopped = run.await.expect("join").expect("serve");
    assert!(stopped.is_none(), "the daemon stopped while it waited");
    assert!(data.join(VAULT_FILE).is_file(), "the vault exists, locked");
    assert!(!data.join(SETUP_CODE_FILE).exists());
    assert!(temp_vault_names(&data).is_empty());
}

/// MEDIUM regression: a request that is half sent when the daemon stops must not be able to start a setup when it is
/// finished (the stop sets the phase to closing under the lock).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_that_is_half_sent_at_the_stop_cannot_start_a_setup() {
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    let ready = ready.await.expect("ready");
    let code = code_of(&config);
    let request = raw_setup_request(code.token.expose());
    let (first, rest) = request.split_at(request.len() - 20);
    let mut stream = raw_connect(ready.addrs[0]).await;
    stream.write_all(first.as_bytes()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
    stream.write_all(rest.as_bytes()).await.unwrap();
    let (status, body) = raw_answer(&mut stream).await;
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("unavailable"), "{body}");
    assert!(!config.data_dir.join(VAULT_FILE).exists());
}

/// LOW regression: the setup listener serves one request per connection, so idle keep-alive connections cannot hold its
/// few slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_closes_after_its_answer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    let ready = ready.await.expect("ready");
    let mut stream = raw_connect(ready.addrs[0]).await;
    stream
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let (status, _) = raw_answer(&mut stream).await;
    assert_eq!(status, 200);
    // The server ends the connection: a read gives the end of the stream, not a wait.
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut rest),
    )
    .await;
    assert!(closed.is_ok(), "the server closed the connection");
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

/// LOW regression: a client that sends the head and then no body is cut after the body timeout (10 s), not after the
/// 120 s of the whole connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_that_does_not_arrive_is_refused_after_the_body_timeout() {
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    let ready = ready.await.expect("ready");
    let mut stream = raw_connect(ready.addrs[0]).await;
    stream
        .write_all(b"POST /v1/setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"setup")
        .await
        .unwrap();
    let started = cerberus_types::Stopwatch::start();
    let answered =
        tokio::time::timeout(std::time::Duration::from_secs(15), raw_answer(&mut stream))
            .await
            .expect("the server answered within 15 s");
    assert_eq!(answered.0, 400, "{}", answered.1);
    assert!(started.elapsed() < std::time::Duration::from_secs(14));
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

/// Nit: a bind that fails leaves no code file behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_that_fails_leaves_no_code_file() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let taken = TcpListener::bind(("127.0.0.1", config.port)).unwrap();
    let (_stop, run, _ready) = start(&config);
    let result = run.await.expect("join");
    assert!(result.is_err(), "the port is taken");
    assert!(
        !config.data_dir.join(SETUP_CODE_FILE).exists(),
        "{:?}",
        names(&config.data_dir)
    );
    drop(taken);
}

/// A setup that was killed leaves the TLS files that `create_vault` wrote. With no vault they belong to a dead CA, so
/// the next start removes them (known names only).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tls_files_of_a_killed_setup_are_removed_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let data = config.data_dir.clone();
    std::fs::create_dir_all(data.join("tls")).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "leaf-cert.der",
        "leaf-key.der",
        "ca-cert.der",
        "leaf-key.tmp",
    ] {
        std::fs::write(data.join("tls").join(name), b"dead CA").unwrap();
    }
    std::fs::write(data.join("tls").join("mine.txt"), b"not ours").unwrap();
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    assert_eq!(names(&data.join("tls")), ["mine.txt".to_owned()]);
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}

/// Side files with no vault file are leftovers, not a vault: the answer says to remove them, not to restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn side_files_without_a_vault_file_get_their_own_message() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _) = config_for(dir.path(), true, "");
    let (stop, run, ready) = start(&config);
    drop(ready.await.expect("ready"));
    let code = code_of(&config);
    std::fs::write(config.data_dir.join("vault.cerberus-wal"), b"left over").unwrap();
    let error = setup(&code, &request(PHRASE)).await.expect_err("refused");
    assert_eq!(api_code(&error), Some(ErrorCode::Conflict), "{error}");
    let text = error.to_string();
    assert!(text.contains("remove"), "{text}");
    assert!(!text.contains("restart cerberusd"), "{text}");
    assert!(std::fs::read(config.data_dir.join("vault.cerberus-wal")).is_ok());
    stop.send(()).expect("stop");
    assert!(run.await.expect("join").expect("serve").is_none());
}
