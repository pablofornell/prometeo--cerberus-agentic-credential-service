//! Fixture of the acceptance suite: a real vault in a temporary directory with a manual clock, the real TLS
//! server with `/mcp` mounted on an ephemeral port, an HTTPS client, an MCP client, and the `cerberus` binary.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use cerberus_api::tls::{CaExport, TlsPaths};
use cerberus_api::{ApiConfig, AppState, LocalCaIssuer, RunningServer, start};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::items::{ItemInput, Payload, generate_ed25519};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::{CoreConfig, KeyCustody, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    AccessRequestId, AgentId, AgentKeyId, Clock, Environment, GrantMode, ItemId, ManualClock,
    OperatorId, OperatorRole, Permission, RequestId, Scope, WorkspaceId,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, Implementation,
};
use rmcp::service::RunningService;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use serde_json::Value;

pub const PHRASE: &str = "orbit velvet canyon mosaic 7";
pub const ALT_PHRASE: &str = "wrong marble lantern copper 3";
pub const PASSWORD: &str = "canary-pw-7f3a91c2";
pub const USERNAME: &str = "canary-user-5d20be41";

pub type McpClient = RunningService<RoleClient, ClientConfig>;

pub fn op_ctx(owner: &OperatorContext) -> OperatorContext {
    OperatorContext {
        request_id: RequestId::generate(),
        ..owner.clone()
    }
}

/// A web login item. `fake` is (description, username, password).
pub fn web_login(
    workspace: WorkspaceId,
    title: &str,
    environment: Environment,
    fake: (&str, &str, &str),
) -> ItemInput {
    ItemInput {
        workspace_id: workspace,
        title: title.to_owned(),
        description: fake.0.to_owned(),
        role_label: Some("admin".to_owned()),
        category: "Web login".to_owned(),
        tags: vec!["shop".to_owned()],
        environment,
        target: Some("https://shop.example.test/login".to_owned()),
        custom: BTreeMap::new(),
        expires_at: None,
        max_uses: None,
        payload: Payload::WebLogin {
            username: SecretString::new(fake.1.to_owned()),
            password: SecretString::new(fake.2.to_owned()),
            url: None,
            totp: None,
        },
    }
}

pub fn client_config(
    ca_der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .expect("root");
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub struct Reply {
    pub status: u16,
    pub json: Value,
}

/// An HTTPS client that trusts the vault CA.
pub struct Rest {
    http: reqwest::Client,
    base: String,
}

impl Rest {
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

    pub async fn get(&self, path: &str, token: Option<&str>) -> Reply {
        self.send("GET", path, token, None).await
    }

    pub async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> Reply {
        self.send("POST", path, token, Some(body)).await
    }
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub clock: ManualClock,
    pub core: VaultService,
    pub owner: OperatorContext,
    pub owner_id: OperatorId,
    pub recovery_key: SecretString,
    pub server: Option<RunningServer>,
    pub addr: SocketAddr,
    pub ca_der: Vec<u8>,
    pub ca_file: PathBuf,
    pub ca_pin: String,
    pub workspace: WorkspaceId,
    pub agent: AgentId,
    pub token: String,
    pub key_id: AgentKeyId,
    pub rest: Rest,
    pub ssh_item: ItemId,
}

fn tls_config(ca_der: &[u8]) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))
        .expect("root");
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

impl Env {
    /// A vault with one workspace (`shop-frontend`, alias `shop`), one agent that may find, read and
    /// create sessions (not write), and one staging login.
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir: PathBuf = dir.path().to_path_buf();
        let tls = TlsPaths::in_data_dir(&data_dir);
        let clock = ManualClock::new(Clock::now(&cerberus_types::SystemClock));
        let shared: Arc<dyn Clock> = Arc::new(clock.clone());
        let store = Store::open(
            OpenOptions {
                path: data_dir.join("vault.cerberus"),
                create: true,
            },
            Arc::clone(&shared),
        )
        .await
        .expect("store");
        let core = VaultService::open(
            store,
            Arc::clone(&shared),
            CoreConfig {
                approvals_available: true,
                idle_lock_default: None,
                data_dir: data_dir.clone(),
                ca_issuer: Arc::new(LocalCaIssuer::new(tls.clone(), vec![])),
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
                    aliases: vec!["shop".to_owned()],
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
                    scopes: vec![
                        Scope::StatusRead,
                        Scope::CatalogRead,
                        Scope::SecretsRead,
                        Scope::SecretsWrite,
                        Scope::SessionsWrite,
                        Scope::Requests,
                    ],
                    lifetime_days: Some(30),
                    ip_allowlist: vec![],
                    require_mtls: false,
                },
            )
            .await
            .expect("agent");
        core.put_grant(
            &owner,
            GrantInput {
                id: None,
                agent_id: agent.id,
                selector: Selector {
                    workspace_ids: vec![ws.id],
                    environments: vec![Environment::Staging, Environment::Prod, Environment::Dev],
                    categories: vec![],
                    tags: vec![],
                    kinds: vec![],
                    role_labels: vec![],
                    item_ids: vec![],
                },
                permissions: BTreeSet::from([
                    Permission::Find,
                    Permission::Read,
                    Permission::CreateSession,
                ]),
                mode: GrantMode::Auto,
                conditions: Conditions::default(),
                allow_prod_auto: false,
            },
        )
        .await
        .expect("grant");
        core.create_item_as_operator(
            &owner,
            web_login(
                ws.id,
                "Shop admin",
                Environment::Staging,
                ("Shop admin login", USERNAME, PASSWORD),
            ),
        )
        .await
        .expect("item");
        let mut config = ApiConfig::loopback(tls);
        config.bind = vec!["127.0.0.1:0".parse().expect("addr")];
        let ca_der = core.tls_ca_cert().await.expect("tls_ca_cert");
        let export = CaExport::from_der(&ca_der).expect("ca export");
        let ca_file = data_dir.join("ca.pem");
        std::fs::write(&ca_file, &export.pem).expect("ca file");
        let state = AppState::new(core.clone(), &config);
        let app = cerberus_api::app(&state, cerberus_mcp::mcp_router(&state));
        let server = start(&config, state, app).await.expect("start");
        let addr = server.local_addrs()[0];
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config(&ca_der))
            .build()
            .expect("http client");
        Self {
            dir,
            clock,
            core,
            owner_id: created.owner_id,
            owner,
            recovery_key: created.recovery_key,
            server: Some(server),
            addr,
            ca_der,
            ca_file,
            ca_pin: export.pin,
            workspace: ws.id,
            agent: agent.id,
            token: key.token.expose_secret().to_owned(),
            key_id: key.key.id,
            rest: Rest {
                http,
                base: format!("https://localhost:{}", addr.port()),
            },
            ssh_item: ItemId::generate(),
        }
    }

    pub async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }

    /// A prod item: reading it needs a person to approve.
    pub async fn prod_item(&self, title: &str) -> ItemId {
        self.core
            .create_item_as_operator(
                &op_ctx(&self.owner),
                web_login(
                    self.workspace,
                    title,
                    Environment::Prod,
                    ("Shop admin login", USERNAME, PASSWORD),
                ),
            )
            .await
            .expect("prod item")
            .summary
            .id
    }

    /// Adds an SSH key item for `machine` and a grant for `use_ssh`. Returns lines of the private key,
    /// so a test can check they never show.
    pub async fn add_ssh_machine(&mut self, machine: &str) -> Vec<String> {
        let payload = generate_ed25519("fake-acceptance-key").expect("key");
        let Payload::SshKey { private_key, .. } = &payload else {
            panic!("ssh payload");
        };
        let markers = private_key
            .expose_secret()
            .lines()
            .filter(|line| !line.starts_with("-----") && line.len() > 16)
            .map(str::to_owned)
            .collect();
        let custom = BTreeMap::from([
            ("host".to_owned(), "127.0.0.1".to_owned()),
            ("port".to_owned(), "2222".to_owned()),
            ("user".to_owned(), "ci".to_owned()),
        ]);
        let item = self
            .core
            .create_item_as_operator(
                &op_ctx(&self.owner),
                ItemInput {
                    workspace_id: self.workspace,
                    title: "Build key".to_owned(),
                    description: "fake test key".to_owned(),
                    role_label: None,
                    category: "SSH key".to_owned(),
                    tags: vec![],
                    environment: Environment::Dev,
                    target: Some(machine.to_owned()),
                    custom,
                    expires_at: None,
                    max_uses: None,
                    payload,
                },
            )
            .await
            .expect("ssh item");
        self.ssh_item = item.summary.id;
        self.core
            .put_grant(
                &op_ctx(&self.owner),
                GrantInput {
                    id: None,
                    agent_id: self.agent,
                    selector: Selector::default(),
                    permissions: BTreeSet::from([Permission::UseSsh, Permission::Find]),
                    mode: GrantMode::Auto,
                    conditions: Conditions::default(),
                    allow_prod_auto: false,
                },
            )
            .await
            .expect("ssh grant");
        markers
    }

    /// A new key of the test agent with exactly these scopes.
    pub async fn agent_token(&self, scopes: &[Scope]) -> String {
        self.core
            .create_agent_key(
                &op_ctx(&self.owner),
                self.agent,
                AgentKeyInput {
                    scopes: scopes.to_vec(),
                    lifetime_days: Some(30),
                    ip_allowlist: vec![],
                    require_mtls: false,
                },
            )
            .await
            .expect("key")
            .token
            .expose_secret()
            .to_owned()
    }

    /// The id of the first pending access request. Polls the approval list, with a deadline.
    pub async fn wait_for_pending(&self) -> AccessRequestId {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let pending = self
                .core
                .pending_requests(&op_ctx(&self.owner))
                .await
                .expect("pending");
            if let Some(first) = pending.first() {
                return first.view.id;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no pending request appeared"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn try_mcp(&self, token: &str) -> Result<McpClient, String> {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config(&self.ca_der))
            .build()
            .expect("http client");
        let uri = format!("https://localhost:{}/mcp", self.addr.port());
        let config = StreamableHttpClientTransportConfig::with_uri(uri).auth_header(token);
        let transport = StreamableHttpClientTransport::with_client(http, config);
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("cerberus-acceptance", "0.0.0"),
        )
        .serve(transport)
        .await
        .map_err(|error| error.to_string())
    }

    pub async fn mcp_with(&self, token: &str) -> McpClient {
        self.try_mcp(token).await.expect("mcp initialize")
    }

    pub async fn mcp(&self) -> McpClient {
        self.mcp_with(&self.token).await
    }

    /// Changes one audit row in the database file (the attacker drops the append-only triggers first).
    pub async fn tamper_audit_row(&self, seq: u64) {
        use sqlx::Connection;
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(self.dir.path().join("vault.cerberus"));
        let mut conn = sqlx::SqliteConnection::connect_with(&options)
            .await
            .expect("raw connection");
        for sql in [
            "DROP TRIGGER audit_events_no_update",
            "DROP TRIGGER audit_events_no_delete",
        ] {
            sqlx::query(sql)
                .execute(&mut conn)
                .await
                .expect("drop trigger");
        }
        let changed =
            sqlx::query("UPDATE audit_events SET occurred_at = occurred_at + 1 WHERE seq = ?1")
                .bind(i64::try_from(seq).expect("seq"))
                .execute(&mut conn)
                .await
                .expect("tamper");
        assert_eq!(changed.rows_affected(), 1);
    }

    /// Runs the `cerberus` binary with the agent environment, to the end, on a blocking thread.
    pub async fn cli(&self, args: &[&str]) -> Output {
        let mut cmd = std::process::Command::new(cerberus_binary());
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env(
                "CERBERUS_URL",
                format!("https://127.0.0.1:{}", self.addr.port()),
            )
            .env("CERBERUS_TOKEN", &self.token)
            .env("CERBERUS_CA_FILE", &self.ca_file)
            .env("CERBERUS_CA_PIN", &self.ca_pin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        tokio::task::spawn_blocking(move || cmd.output().expect("run cerberus"))
            .await
            .expect("join")
    }
}

/// The path of the `cerberus` binary. It is built on first use, because Cargo gives `CARGO_BIN_EXE_*` only to the
/// package that owns the binary. The path comes from the JSON messages of `cargo build`, so it is right for any
/// target directory layout (DEC-T24-2).
fn cerberus_binary() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let mut build = std::process::Command::new(
                std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
            );
            build
                .args([
                    "build",
                    "--quiet",
                    "--package",
                    "cerberus-client",
                    "--bin",
                    "cerberus",
                    "--message-format=json-render-diagnostics",
                ])
                .stderr(Stdio::inherit());
            if !cfg!(debug_assertions) {
                build.arg("--release");
            }
            let out = build.output().expect("cargo build");
            assert!(out.status.success(), "building the cerberus binary failed");
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|msg| {
                    msg["reason"] == "compiler-artifact" && msg["target"]["name"] == "cerberus"
                })
                .find_map(|msg| msg["executable"].as_str().map(PathBuf::from))
                .expect("cargo reported no cerberus executable")
        })
        .clone()
}

/// Calls a tool with a JSON object of arguments.
pub async fn mcp_call(
    client: &rmcp::Peer<RoleClient>,
    name: &'static str,
    args: Value,
) -> CallToolResult {
    let Value::Object(map) = args else {
        panic!("arguments must be an object");
    };
    client
        .call_tool(CallToolRequestParams::new(name).with_arguments(map))
        .await
        .expect("tool call")
}

pub fn mcp_data(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("structured content")
}

pub fn error_code(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "expected an error: {result:?}");
    mcp_data(result)["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}
