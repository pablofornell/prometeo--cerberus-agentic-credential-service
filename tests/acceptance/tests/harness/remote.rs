//! Fixture of A13 (ADR-0034): a vault made with the core API in a private folder, then the real `cerberusd`
//! serve loop on it in this process (unlock socket, TLS listener, the admin API when asked), the terminal unlock and
//! `cerberusd admin enroll` through the socket, and an HTTPS client that can present a client certificate. Every
//! secret is a fake test value.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_admin::bundle::AdminBundle;
use cerberus_api::tls::{LocalCa, LocalCaIssuer, TlsPaths};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::{CoreConfig, KeyCustody, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    Clock, Environment, GrantMode, ItemId, OperatorId, OperatorRole, Permission, RequestId, Scope,
    SystemClock, WorkspaceId,
};
use cerberusd::admin::{self as daemon_admin, EnrollRequest};
use cerberusd::config::{self, Config};
use cerberusd::daemon::{self, DaemonError, Ready};
use cerberusd::unlock;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{PASSWORD, PHRASE, USERNAME, web_login};

/// What the vault seed gives A13: an agent with an `ask_once` grant on one `prod` item, and an agent client
/// certificate signed by the vault CA (it must not pass the admin routes).
pub struct Seed {
    pub token: String,
    pub prod_item: ItemId,
    pub workspace: WorkspaceId,
    pub owner: OperatorId,
    /// (certificate DER, PKCS#8 key DER) of the agent's client certificate.
    pub agent_identity: (Vec<u8>, Vec<u8>),
}

async fn make_vault(data_dir: &Path) -> Seed {
    std::fs::create_dir_all(data_dir).expect("data dir");
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
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
        Arc::clone(&clock),
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
    core.put_grant(
        &owner,
        GrantInput {
            id: None,
            agent_id: agent.id,
            selector: Selector {
                workspace_ids: vec![ws.id],
                environments: vec![Environment::Prod],
                categories: vec![],
                tags: vec![],
                kinds: vec![],
                role_labels: vec![],
                item_ids: vec![],
            },
            permissions,
            mode: GrantMode::AskOnce,
            conditions: Conditions::default(),
            allow_prod_auto: false,
        },
    )
    .await
    .expect("grant");
    let item = core
        .create_item_as_operator(
            &owner,
            web_login(
                ws.id,
                "Shop admin",
                Environment::Prod,
                ("Shop admin login", USERNAME, PASSWORD),
            ),
        )
        .await
        .expect("item");
    // An agent client certificate from the same CA: CA-signed, but no enrolment.
    let material = core.tls_ca_material().await.expect("ca material");
    let ca = LocalCa::from_parts(&material.cert_der, &material.key_der).expect("ca");
    let issued = ca
        .issue_client(agent.id, clock.now())
        .expect("agent client cert");
    let seed = Seed {
        token: key.token.expose_secret().to_owned(),
        prod_item: item.summary.id,
        workspace: ws.id,
        owner: created.owner_id,
        agent_identity: (issued.cert_der, issued.key_der.expose_secret().to_vec()),
    };
    drop(core);
    seed
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// A running `cerberusd` on loopback, unlocked once at the terminal (its TLS leaf exists then).
pub struct Daemon {
    pub dir: tempfile::TempDir,
    pub data: PathBuf,
    pub config: Config,
    pub ready: Ready,
    pub seed: Seed,
    pub ca_der: Vec<u8>,
    pub port: u16,
    stop: Option<oneshot::Sender<()>>,
    run: Option<JoinHandle<Result<Option<VaultService>, DaemonError>>>,
}

impl Daemon {
    /// Makes a vault and starts `cerberusd` on it with `[admin] enabled = admin`, then unlocks it through the socket.
    pub async fn start(admin: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        let seed = make_vault(&data).await;
        let path = dir.path().join("cerberusd.toml");
        // A free port can be taken by another test between the probe and the bind: try again.
        let mut attempt = 0;
        let (port, config, stop, run, ready) = loop {
            attempt += 1;
            let port = free_port();
            let text = format!(
                "data_dir = {:?}\nbind = [\"127.0.0.1\"]\nport = {port}\n[admin]\nenabled = {admin}\n",
                data.display().to_string()
            );
            std::fs::write(&path, text).expect("config file");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            let config = config::load(Some(&path), &|_| None).expect("config");
            let (stop, stop_rx) = oneshot::channel::<()>();
            let (ready_tx, ready_rx) = oneshot::channel::<Ready>();
            let serve_config = config.clone();
            let run = tokio::spawn(async move {
                daemon::serve(&serve_config, async { drop(stop_rx.await) }, |ready| {
                    drop(ready_tx.send(ready.clone()));
                })
                .await
            });
            match ready_rx.await {
                Ok(ready) => break (port, config, stop, run, ready),
                Err(_) => {
                    let error = match run.await.expect("join") {
                        Ok(_) => "it stopped before it was ready".to_owned(),
                        Err(error) => error.to_string(),
                    };
                    assert!(attempt < 3, "cerberusd did not start: {error}");
                }
            }
        };
        unlock::unlock_with(&ready.socket, None, |_| Ok(PHRASE.to_owned()))
            .await
            .expect("terminal unlock");
        let pem = std::fs::read(daemon::ca_pem_path(&data)).expect("CA pem");
        let ca_der = CertificateDer::from_pem_slice(&pem)
            .expect("CA is PEM")
            .as_ref()
            .to_vec();
        Self {
            dir,
            data,
            config,
            ready,
            seed,
            ca_der,
            port,
            stop: Some(stop),
            run: Some(run),
        }
    }

    /// `cerberusd admin enroll --label <label> --url https://localhost:<port>` with the owner phrase.
    pub async fn enroll(&self, label: &str) -> AdminBundle {
        daemon_admin::enroll_with(
            &self.ready.socket,
            &EnrollRequest {
                owner: None,
                operator: None,
                label: label.to_owned(),
                url: format!("https://localhost:{}", self.port),
            },
            |_| Ok(PHRASE.to_owned()),
        )
        .await
        .expect("enroll")
    }

    /// `cerberusd admin revoke <id>` through the socket.
    pub async fn revoke(&self, bundle: &AdminBundle) {
        daemon_admin::revoke_with(&self.ready.socket, &self.data, &bundle.id.to_string())
            .await
            .expect("revoke");
    }

    /// An HTTPS client of this daemon, with a client certificate when `identity` is set.
    pub fn client(&self, identity: Option<(&[u8], &[u8])>) -> Https {
        Https::new(&self.ca_der, identity, self.port)
    }

    /// Stops the daemon and returns its service (locked).
    pub async fn stop(mut self) -> VaultService {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.run
            .take()
            .expect("running")
            .await
            .expect("join")
            .expect("serve")
            .expect("a vault was served")
    }
}

/// The client identity of a bundle as DER: (certificate, PKCS#8 key).
pub fn bundle_identity(bundle: &AdminBundle) -> (Vec<u8>, Vec<u8>) {
    let cert = CertificateDer::from_pem_slice(bundle.client_cert_pem.as_bytes()).expect("cert");
    let key =
        PrivatePkcs8KeyDer::from_pem_slice(bundle.client_key_pem.expose().as_bytes()).expect("key");
    (cert.as_ref().to_vec(), key.secret_pkcs8_der().to_vec())
}

pub struct Reply {
    pub status: u16,
    pub json: Value,
}

/// An HTTPS client (reqwest, TLS 1.3, the vault CA) with an optional client certificate.
pub struct Https {
    http: reqwest::Client,
    base: String,
}

impl Https {
    pub fn new(ca_der: &[u8], identity: Option<(&[u8], &[u8])>, port: u16) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der.to_vec()))
            .expect("root");
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_root_certificates(roots);
        let tls = match identity {
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(cert.to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
                )
                .expect("client identity"),
            None => builder.with_no_client_auth(),
        };
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .expect("http client");
        Self {
            http,
            base: format!("https://localhost:{port}"),
        }
    }

    pub async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Reply {
        let method = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
        let mut request = self.http.request(method, format!("{}{path}", self.base));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.expect("request");
        let status = response.status().as_u16();
        let bytes = response.bytes().await.expect("body");
        Reply {
            status,
            json: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        }
    }

    /// The status code of an agent's `GET /v1/status`.
    pub async fn get_status(&self, token: &str) -> u16 {
        self.send("GET", "/v1/status", Some(token), None)
            .await
            .status
    }

    /// `POST /admin/v1/rpc/{command}` with `args`.
    pub async fn rpc(&self, command: &str, token: Option<&str>, args: &Value) -> Reply {
        self.send(
            "POST",
            &format!("/admin/v1/rpc/{command}"),
            token,
            Some(args),
        )
        .await
    }
}
