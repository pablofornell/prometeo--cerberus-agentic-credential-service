//! Integration tests of `cerberusd`: a real vault made with the core API, the real serve loop, the real unlock
//! socket and the real TLS listener, all in a temp dir. Every secret here is a fake test value.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_admin::bundle::AdminBundle;
use cerberus_admin::clients::AdminClients;
use cerberus_api::tls::{LocalCaIssuer, TlsPaths};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::items::{ItemInput, Payload};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreConfig, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    Clock, Environment, GrantMode, ItemId, OperatorRole, Permission, RequestId, Scope, SystemClock,
    VaultStateKind, WorkspaceId,
};
use cerberusd::admin::{self, AdminCliError, EnrollRequest, Source};
use cerberusd::config::{self, Config, ConfigError};
use cerberusd::daemon::{self, DaemonError, Ready};
use cerberusd::https;
use cerberusd::status;
use cerberusd::unlock::{self, UnlockError};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const PHRASE: &str = "orbit velvet canyon mosaic 7";
const PASSWORD: &str = "canary-pw-7f3a91c2";

fn no_env(_: &str) -> Option<String> {
    None
}

fn web_login(workspace: WorkspaceId) -> ItemInput {
    ItemInput {
        workspace_id: workspace,
        title: "Shop admin".to_owned(),
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
            password: SecretString::new(PASSWORD.to_owned()),
            url: None,
            totp: None,
        },
    }
}

/// What the vault seed gives the tests: an agent token and an item the agent may read.
struct Seed {
    token: String,
    item: ItemId,
}

/// Makes a vault in `data_dir` with the core API, then closes it. The daemon opens it next. The agent's
/// grant on the item has `mode` (an approval mode: cerberusd has no approver unless the admin API is on).
async fn make_vault(data_dir: &Path) -> Seed {
    make_vault_with(data_dir, GrantMode::AskAlways).await
}

async fn make_vault_with(data_dir: &Path, mode: GrantMode) -> Seed {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tls = TlsPaths::in_data_dir(data_dir);
    let store = Store::open(
        OpenOptions {
            path: data_dir.join(daemon::VAULT_FILE),
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
            ca_issuer: Arc::new(LocalCaIssuer::new(tls, Vec::new())),
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
    let ws = core
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
    let (agent, key) = core
        .create_agent(
            &owner,
            AgentInput {
                name: "qa-agent".to_owned(),
                description: String::new(),
            },
            AgentKeyInput {
                scopes: vec![Scope::StatusRead, Scope::CatalogRead, Scope::SecretsRead],
                lifetime_days: Some(30),
                ip_allowlist: vec![],
                require_mtls: false,
            },
        )
        .await
        .expect("agent");
    let mut permissions = BTreeSet::new();
    permissions.extend([Permission::Find, Permission::Read]);
    // `ask_always`: every read needs an approval, and cerberusd has no one to approve.
    core.put_grant(
        &owner,
        GrantInput {
            id: None,
            agent_id: agent.id,
            selector: Selector {
                workspace_ids: vec![ws.id],
                environments: vec![Environment::Dev],
                categories: vec![],
                tags: vec![],
                kinds: vec![],
                role_labels: vec![],
                item_ids: vec![],
            },
            permissions,
            mode,
            conditions: Conditions::default(),
            allow_prod_auto: false,
        },
    )
    .await
    .expect("grant");
    let item = core
        .create_item_as_operator(&owner, web_login(ws.id))
        .await
        .expect("item");
    let seed = Seed {
        token: key.token.expose_secret().to_owned(),
        item: item.summary.id,
    };
    drop(core);
    seed
}

/// Writes a config file with the given mode and extra lines.
fn write_config(path: &Path, data_dir: &Path, extra: &str, mode: u32) {
    let text = format!("data_dir = {:?}\n{extra}", data_dir.display().to_string());
    std::fs::write(path, text).expect("write config");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// The running daemon task: it gives the service when it stops, or `None` when no vault was made.
type Run = JoinHandle<Result<Option<VaultService>, DaemonError>>;

/// Starts the daemon in a task. The stop signal is a oneshot, the same kind of future the signal handler gives.
fn start_daemon(config: Config) -> (oneshot::Sender<()>, Run, oneshot::Receiver<Ready>) {
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let (ready_tx, ready_rx) = oneshot::channel::<Ready>();
    let run = tokio::spawn(async move {
        daemon::serve(&config, async { drop(stop_rx.await) }, |ready| {
            drop(ready_tx.send(ready.clone()));
        })
        .await
    });
    (stop_tx, run, ready_rx)
}

fn ca_der(data_dir: &Path) -> Vec<u8> {
    let pem = std::fs::read(daemon::ca_pem_path(data_dir)).expect("CA pem");
    CertificateDer::from_pem_slice(&pem)
        .expect("CA is PEM")
        .as_ref()
        .to_vec()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_unlocks_serves_ask_grants_as_403_and_stops_locked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let seed = make_vault(&data).await;
    let path = dir.path().join("cerberusd.toml");
    let port = free_port();
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {port}\n[admin]\nenabled = false\n"),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    // The admin API is on by default (DEC-SRV-3); approvals are off only with an explicit `enabled = false`.
    assert!(!config.admin.enabled);
    let (stop, run, ready_rx) = start_daemon(config.clone());
    let ready = ready_rx.await.expect("ready");
    let addr = ready.addrs[0];
    let ca = ca_der(&data);

    let health = status::check(&config).await.expect("status while sealed");
    assert_eq!(health.vault, "locked");
    assert_eq!(health.address, addr);

    // A wrong phrase is refused, and the vault stays sealed.
    let wrong = unlock::unlock_with(&ready.socket, None, |_| {
        Ok("wrong words for this test".to_owned())
    })
    .await;
    assert!(
        matches!(wrong, Err(UnlockError::Refused { .. })),
        "{wrong:?}"
    );

    // The phrase goes through the same prompt the terminal uses. The prompt text is the only thing asked.
    let label = unlock::unlock_with(&ready.socket, None, |prompt| {
        assert_eq!(prompt, "Passphrase: ");
        Ok(PHRASE.to_owned())
    })
    .await
    .expect("unlock");
    assert_eq!(label, "owner");
    assert_eq!(
        status::check(&config).await.expect("status").vault,
        "unlocked"
    );

    // An `ask_always` read gets 403 approval_unavailable (ADR-0002 point 4).
    let reveal = https::request(
        addr,
        &ca,
        "POST",
        &format!("/v1/credentials/{}/reveal", seed.item),
        Some(&seed.token),
        Some(r#"{"purpose":"integration test read"}"#),
    )
    .await
    .expect("reveal");
    assert_eq!(reveal.status, 403);
    let body: serde_json::Value = serde_json::from_slice(&reveal.body).expect("json");
    assert_eq!(body["error"]["code"], "approval_unavailable");
    assert!(!String::from_utf8_lossy(&reveal.body).contains(PASSWORD));

    // `/mcp` is mounted: without a token it is refused with 401, not 404.
    let mcp = https::request(addr, &ca, "POST", "/mcp", None, Some("{}"))
        .await
        .expect("mcp");
    assert_eq!(mcp.status, 401);

    // The admin API is off by default: no admin route, and no enrolment (ADR-0034 invariant 8).
    let hello = https::request(addr, &ca, "GET", "/admin/v1/hello", None, None)
        .await
        .expect("hello");
    assert_eq!(hello.status, 404);
    let body: serde_json::Value = serde_json::from_slice(&hello.body).expect("json");
    assert_eq!(body["error"]["code"], "route_not_found");
    let enroll = admin::enroll_with(&ready.socket, &enroll_request(addr.port()), |_| {
        Ok(PHRASE.to_owned())
    })
    .await;
    assert!(
        matches!(&enroll, Err(AdminCliError::Socket(UnlockError::Refused { code, .. })) if code == "unavailable"),
        "{enroll:?}"
    );
    assert_eq!(
        status::admin_summary(&config).to_string(),
        "admin API: off, 0 enrolled clients"
    );

    // Stop through the same channel a signal uses. The vault must be locked and the listener closed.
    stop.send(()).expect("stop");
    let core = run
        .await
        .expect("join")
        .expect("serve")
        .expect("a vault was served");
    assert_eq!(core.state(), VaultStateKind::Sealed);
    assert!(!ready.socket.exists(), "unlock socket removed");
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "listener is closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_tls_leaf_yet_means_https_starts_at_the_first_unlock() {
    // A backup copied from the desktop has no leaf (ADR-0031 point 2). The CA key is sealed, so the
    // daemon makes the leaf at the first unlock and only then listens for HTTPS.
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    make_vault(&data).await;
    let tls = TlsPaths::in_data_dir(&data);
    std::fs::remove_file(&tls.leaf_cert_der).expect("remove leaf");
    std::fs::remove_file(&tls.leaf_key_der).expect("remove leaf key");
    let port = free_port();
    let path = dir.path().join("cerberusd.toml");
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {port}\n"),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    let (stop, run, ready_rx) = start_daemon(config.clone());
    let ready = ready_rx.await.expect("ready");
    assert!(
        ready.addrs.is_empty(),
        "no listener before the first unlock"
    );
    assert!(status::check(&config).await.is_err());

    unlock::unlock_with(&ready.socket, None, |_| Ok(PHRASE.to_owned()))
        .await
        .expect("unlock");
    // The unlock reply comes before the listener is up, so poll for a few seconds.
    let mut health = None;
    for _ in 0..100 {
        if let Ok(found) = status::check(&config).await {
            health = Some(found);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(health.expect("listener after unlock").vault, "unlocked");
    assert!(tls.leaf_cert_der.is_file(), "leaf made at unlock");

    stop.send(()).expect("stop");
    let core = run
        .await
        .expect("join")
        .expect("serve")
        .expect("a vault was served");
    assert_eq!(core.state(), VaultStateKind::Sealed);
}

/// DEC-SRV-3: a data directory with no vault is not an error. The daemon starts, tells that it is ready, and waits for
/// the first client (the setup itself is tested in `tests/setup.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_starts_without_a_vault_and_waits_for_the_first_client() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("empty");
    std::fs::create_dir(&data).expect("mkdir");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let path = dir.path().join("cerberusd.toml");
    let port = free_port();
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {port}\n[admin]\nenabled = true\n"),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    let (stop, run, ready_rx) = start_daemon(config.clone());
    let ready = ready_rx
        .await
        .expect("ready: the daemon starts with no vault");
    assert_eq!(ready.addrs.len(), 1);
    let code = cerberusd::setup::read_setup_code(&config).expect("setup code");
    let code = cerberus_client::setup::SetupCode::parse(code.as_str()).expect("a setup code");
    let health = cerberus_client::setup::health(&code).await.expect("health");
    assert_eq!(health.vault, "no_vault");
    assert_eq!(health.setup.as_deref(), Some("pending"));
    assert!(!data.join(daemon::VAULT_FILE).exists());
    stop.send(()).expect("stop");
    let stopped = run.await.expect("join").expect("serve");
    assert!(stopped.is_none(), "no vault, so no service");
}

#[test]
fn config_with_mode_0644_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cerberusd.toml");
    write_config(&path, &PathBuf::from("/srv/cerberus"), "", 0o644);
    let error = config::load(Some(&path), &no_env).expect_err("refused");
    assert!(
        matches!(error, ConfigError::Mode { mode: 0o644, .. }),
        "{error}"
    );
}

#[test]
fn config_with_an_unknown_key_names_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("cerberusd.toml");
    write_config(&path, &PathBuf::from("/srv/cerberus"), "prot = 1\n", 0o600);
    let error = config::load(Some(&path), &no_env).expect_err("refused");
    assert!(error.to_string().contains("prot"), "{error}");
}

#[test]
fn explicit_config_path_must_exist() {
    let dir = tempfile::tempdir().expect("tempdir");
    let error = config::load(Some(&dir.path().join("missing.toml")), &no_env).expect_err("refused");
    assert!(matches!(error, ConfigError::Read { .. }), "{error}");
}

#[test]
fn log_filter_carries_the_mcp_directive() {
    // rmcp logs message bodies, which can hold secrets, at debug level (ADR-0029 item 9).
    let text = cerberusd::logging::directives();
    assert!(text.split(',').any(|item| item == "rmcp=warn"), "{text}");
    assert!(
        tracing_subscriber::EnvFilter::try_new(&text).is_ok(),
        "{text}"
    );
}

/// AUD-30: a manual run checks the modes of the data directory and the vault file. systemd sets them,
/// but a person who starts the binary by hand may not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aud30_a_vault_file_or_data_dir_open_to_others_stops_the_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    make_vault(&data).await;
    let path = dir.path().join("cerberusd.toml");
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {}\n", free_port()),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    let vault = data.join(daemon::VAULT_FILE);

    std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let result = daemon::serve(&config, std::future::ready(()), |_| {}).await;
    assert!(
        matches!(result, Err(DaemonError::Mode { .. })),
        "vault file mode 0644: {result:?}"
    );

    std::fs::set_permissions(&vault, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let result = daemon::serve(&config, std::future::ready(()), |_| {}).await;
    assert!(
        matches!(result, Err(DaemonError::Mode { .. })),
        "data dir mode 0755: {result:?}"
    );

    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let result = daemon::serve(&config, std::future::ready(()), |_| {}).await;
    assert!(result.is_ok(), "private modes start: {result:?}");
}

fn enroll_request(port: u16) -> EnrollRequest {
    EnrollRequest {
        owner: None,
        operator: None,
        label: "laptop".to_owned(),
        url: format!("https://localhost:{port}"),
    }
}

/// The client certificate and key of a bundle, DER.
fn identity(bundle: &AdminBundle) -> (Vec<u8>, Vec<u8>) {
    let cert = CertificateDer::from_pem_slice(bundle.client_cert_pem.as_bytes()).expect("cert");
    let key =
        PrivatePkcs8KeyDer::from_pem_slice(bundle.client_key_pem.expose().as_bytes()).expect("key");
    (cert.as_ref().to_vec(), key.secret_pkcs8_der().to_vec())
}

/// Sends one raw line to the unlock socket and returns the reply line.
async fn raw_socket_line(socket: &Path, line: &str) -> serde_json::Value {
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .expect("connect");
    stream.write_all(line.as_bytes()).await.expect("write");
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.expect("read");
    serde_json::from_slice(&reply).expect("reply json")
}

/// ADR-0034 points 2 and 3 end to end on the real daemon: config on, enrolment over the socket (sealed,
/// wrong phrase, good), the bundle the desktop will read, the device and session gates, approvals on,
/// online and offline revoke, and the old unlock line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_api_enrolment_approvals_and_revoke() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let seed = make_vault_with(&data, GrantMode::AskOnce).await;
    let port = free_port();
    let path = dir.path().join("cerberusd.toml");
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {port}\n[admin]\nenabled = true\n"),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    assert!(config.admin.enabled);
    let (stop, run, ready_rx) = start_daemon(config.clone());
    let ready = ready_rx.await.expect("ready");
    let addr = ready.addrs[0];
    let ca = ca_der(&data);
    assert_eq!(
        status::admin_summary(&config).to_string(),
        "admin API: on, 0 enrolled clients"
    );

    // Sealed: the CA key is sealed, so no enrolment.
    let sealed = admin::enroll_with(&ready.socket, &enroll_request(port), |prompt| {
        assert_eq!(prompt, "Owner passphrase: ");
        Ok(PHRASE.to_owned())
    })
    .await;
    assert!(
        matches!(&sealed, Err(AdminCliError::Socket(UnlockError::Refused { code, .. })) if code == "vault_locked"),
        "{sealed:?}"
    );
    // An old unlock line, without `op`, still unlocks.
    let reply = raw_socket_line(
        &ready.socket,
        &format!("{{\"operator\":null,\"phrase\":\"{PHRASE}\"}}\n"),
    )
    .await;
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["operator"], "owner");

    // A wrong owner phrase, then the right one.
    let wrong = admin::enroll_with(&ready.socket, &enroll_request(port), |_| {
        Ok("wrong words for this test".to_owned())
    })
    .await;
    assert!(
        matches!(&wrong, Err(AdminCliError::Socket(UnlockError::Refused { code, .. })) if code == "bad_credentials"),
        "{wrong:?}"
    );
    let bundle = admin::enroll_with(&ready.socket, &enroll_request(port), |_| {
        Ok(PHRASE.to_owned())
    })
    .await
    .expect("enroll");
    let bad_url = EnrollRequest {
        url: "http://localhost:1".to_owned(),
        ..enroll_request(port)
    };
    let refused = admin::enroll_with(&ready.socket, &bad_url, |_| Ok(PHRASE.to_owned())).await;
    assert!(
        matches!(&refused, Err(AdminCliError::Socket(UnlockError::Refused { code, .. })) if code == "invalid_request"),
        "{refused:?}"
    );
    // The bundle is what the desktop accepts, and its CA matches `cerberusd status`.
    let bundle_path = dir.path().join("laptop.cerberus-admin");
    bundle.write_new(&bundle_path).expect("write bundle");
    let mode = std::fs::metadata(&bundle_path)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    assert!(bundle.write_new(&bundle_path).is_err(), "never over a file");
    let read = AdminBundle::read(&bundle_path, SystemClock.now()).expect("the desktop reads it");
    assert_eq!(read.id, bundle.id);
    assert_eq!(read.url, format!("https://localhost:{port}"));
    assert_eq!(
        status::ca_fingerprints(&config).expect("ca").pin,
        bundle.ca_pin
    );
    // The registry has the entry, mode 0600; `list` shows it.
    let registry = data.join("admin-clients.json");
    let mode = std::fs::metadata(&registry)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let clients = AdminClients::load(&registry).expect("registry");
    assert_eq!(clients.list().len(), 1);
    assert_eq!(clients.list()[0].id, bundle.id);
    let (listed, source) = admin::list_with(&ready.socket, &data).await.expect("list");
    assert_eq!(source, Source::Daemon);
    assert_eq!(listed.len(), 1);
    assert_eq!(
        status::admin_summary(&config).to_string(),
        "admin API: on, 1 enrolled clients"
    );

    // The device gate: with the new certificate `hello` answers; without one it is refused.
    let (cert, key) = identity(&bundle);
    let id = Some((cert.as_slice(), key.as_slice()));
    let hello = https::request_as(addr, &ca, id, "GET", "/admin/v1/hello", None, None)
        .await
        .expect("hello");
    assert_eq!(hello.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&hello.body).expect("json");
    assert_eq!(body["admin_protocol"], 1);
    assert_eq!(body["vault_state"], "unlocked");
    let bare = https::request(addr, &ca, "GET", "/admin/v1/hello", None, None)
        .await
        .expect("bare");
    assert_eq!(bare.status, 403);
    // Agents without a client certificate still work on the loopback bind.
    let status_reply = https::request(addr, &ca, "GET", "/v1/status", Some(&seed.token), None)
        .await
        .expect("status");
    assert_eq!(status_reply.status, 200);

    // A session, and approvals: an `ask_once` read is a pending request, not `403 approval_unavailable`.
    let open =
        serde_json::json!({ "operator_id": bundle.operator_id.to_string(), "phrase": PHRASE });
    let session = https::request_as(
        addr,
        &ca,
        id,
        "POST",
        "/admin/v1/session",
        None,
        Some(&open.to_string()),
    )
    .await
    .expect("session");
    assert_eq!(
        session.status,
        200,
        "{}",
        String::from_utf8_lossy(&session.body)
    );
    let token = serde_json::from_slice::<serde_json::Value>(&session.body).expect("json")["token"]
        .as_str()
        .expect("token")
        .to_owned();
    // A session token is never an agent token: refused on `/v1` and on `/mcp` (ADR-0034 point 4.3).
    for (method, route, body) in [("GET", "/v1/status", None), ("POST", "/mcp", Some("{}"))] {
        let refused = https::request_as(addr, &ca, id, method, route, Some(&token), body)
            .await
            .expect("agent route");
        assert_eq!(refused.status, 401, "{method} {route}");
    }
    let reveal_path = format!("/v1/credentials/{}/reveal", seed.item);
    let purpose = r#"{"purpose":"integration test read"}"#;
    let pending = https::request(
        addr,
        &ca,
        "POST",
        &reveal_path,
        Some(&seed.token),
        Some(purpose),
    )
    .await
    .expect("reveal");
    assert_eq!(
        pending.status,
        202,
        "{}",
        String::from_utf8_lossy(&pending.body)
    );
    let request_id =
        serde_json::from_slice::<serde_json::Value>(&pending.body).expect("json")["access_request"]
            ["id"]
            .as_str()
            .expect("id")
            .to_owned();
    let approve = serde_json::json!({ "request": request_id, "option": "once" }).to_string();
    let approved = https::request_as(
        addr,
        &ca,
        id,
        "POST",
        "/admin/v1/rpc/request_approve",
        Some(&token),
        Some(&approve),
    )
    .await
    .expect("approve");
    assert_eq!(
        approved.status,
        200,
        "{}",
        String::from_utf8_lossy(&approved.body)
    );
    let revealed = https::request(
        addr,
        &ca,
        "POST",
        &reveal_path,
        Some(&seed.token),
        Some(purpose),
    )
    .await
    .expect("reveal");
    assert_eq!(revealed.status, 200);
    assert!(String::from_utf8_lossy(&revealed.body).contains(PASSWORD));

    // A second enrolment for the offline revoke below.
    let second = admin::enroll_with(
        &ready.socket,
        &EnrollRequest {
            label: "second".to_owned(),
            ..enroll_request(port)
        },
        |_| Ok(PHRASE.to_owned()),
    )
    .await
    .expect("second enrolment");

    // Online revoke: the device is refused at once, its session with it.
    let source = admin::revoke_with(&ready.socket, &data, &bundle.id.to_string())
        .await
        .expect("revoke");
    assert_eq!(source, Source::Daemon);
    let after = https::request_as(
        addr,
        &ca,
        id,
        "POST",
        "/admin/v1/rpc/item_list",
        Some(&token),
        Some(r#"{"filter":{}}"#),
    )
    .await
    .expect("after revoke");
    assert_eq!(after.status, 403);
    let again = admin::revoke_with(&ready.socket, &data, &bundle.id.to_string()).await;
    assert!(
        matches!(again, Err(AdminCliError::NotFound(_))),
        "{again:?}"
    );
    // The revoke removed power only: the vault is still unlocked for agents.
    let status_reply = https::request(addr, &ca, "GET", "/v1/status", Some(&seed.token), None)
        .await
        .expect("status");
    assert_eq!(status_reply.status, 200);

    stop.send(()).expect("stop");
    let core = run
        .await
        .expect("join")
        .expect("serve")
        .expect("a vault was served");
    assert_eq!(core.state(), VaultStateKind::Sealed);

    // Offline revoke: no daemon answers, so the file is edited.
    let source = admin::revoke_with(&ready.socket, &data, &second.id.to_string())
        .await
        .expect("offline revoke");
    assert_eq!(source, Source::File);
    let clients = AdminClients::load(&registry).expect("registry");
    assert!(clients.list().iter().all(|c| c.revoked_at.is_some()));
    let (listed, source) = admin::list_with(&ready.socket, &data).await.expect("list");
    assert_eq!(source, Source::File);
    assert_eq!(listed.len(), 2);
}

/// ADR-0034 point 3.5: with the admin API on, a registry open to others stops the start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_registry_with_a_wide_mode_stops_the_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    make_vault(&data).await;
    let path = dir.path().join("cerberusd.toml");
    write_config(
        &path,
        &data,
        &format!(
            "bind = [\"127.0.0.1\"]\nport = {}\n[admin]\nenabled = true\n",
            free_port()
        ),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    let registry = data.join("admin-clients.json");
    AdminClients::default().save(&registry).expect("save");
    std::fs::set_permissions(&registry, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let result = daemon::serve(&config, std::future::ready(()), |_| {}).await;
    assert!(
        matches!(&result, Err(DaemonError::Mode { mode: 0o644, .. })),
        "{result:?}"
    );
    // With the admin API off the file is not read.
    let mut off = config.clone();
    off.admin.enabled = false;
    let result = daemon::serve(&off, std::future::ready(()), |_| {}).await;
    assert!(result.is_ok(), "{result:?}");
}

/// Pre-existing defect: when the HTTPS listener cannot start (a port collision) after the unlock socket was bound, the
/// socket task stayed alive in the process, and a second start in the same process (a retry) failed with "already
/// running for this data directory".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_https_start_leaves_no_unlock_socket_behind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    make_vault(&data).await;
    let path = dir.path().join("cerberusd.toml");
    let port = free_port();
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {port}\n"),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    let taken = std::net::TcpListener::bind(("127.0.0.1", port)).expect("take the port");
    let first = daemon::serve(&config, std::future::pending::<()>(), |_| {}).await;
    assert!(
        matches!(first, Err(DaemonError::Server(_))),
        "the port is taken: {first:?}"
    );
    drop(taken);
    let (stop, run, ready) = start_daemon(config);
    let ready = ready
        .await
        .expect("the second start is not refused as already running");
    assert!(!ready.addrs.is_empty());
    stop.send(()).expect("stop");
    run.await.expect("join").expect("serve");
}

/// A leaf of another CA in the data folder (left by a setup that was killed, then a backup copied in) is not served: the
/// listener starts at the first unlock with a leaf of the vault CA, so `status` (which trusts that CA) works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leaf_of_a_dead_ca_is_not_served() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    make_vault(&data).await;
    let tls = TlsPaths::in_data_dir(&data);
    let now = SystemClock.now();
    let dead = cerberus_api::tls::LocalCa::create(&cerberus_types::VaultId::generate(), now)
        .expect("dead ca");
    let stale = dead
        .issue_leaf(&cerberus_api::tls::leaf_names(&[]), now)
        .expect("leaf");
    cerberus_api::tls::write_leaf(&tls, &stale).expect("write the stale leaf");
    let port = free_port();
    let path = dir.path().join("cerberusd.toml");
    write_config(
        &path,
        &data,
        &format!("bind = [\"127.0.0.1\"]\nport = {port}\n"),
        0o600,
    );
    let config = config::load(Some(&path), &no_env).expect("config");
    let (stop, run, ready_rx) = start_daemon(config.clone());
    let ready = ready_rx.await.expect("ready");
    assert!(
        ready.addrs.is_empty(),
        "the leaf of a dead CA is not served while sealed"
    );
    unlock::unlock_with(&ready.socket, None, |_| Ok(PHRASE.to_owned()))
        .await
        .expect("unlock");
    let mut health = None;
    for _ in 0..100 {
        if let Ok(found) = status::check(&config).await {
            health = Some(found);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(health.expect("listener after unlock").vault, "unlocked");
    assert_ne!(
        std::fs::read(&tls.leaf_cert_der).expect("leaf"),
        stale.cert_der,
        "the leaf was renewed"
    );
    stop.send(()).expect("stop");
    run.await.expect("join").expect("serve");
}
