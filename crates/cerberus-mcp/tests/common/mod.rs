//! Test harness: a real vault, the real TLS server on an ephemeral port with `/mcp` mounted, and an
//! rmcp client over TLS. All secret values here are fake test values.
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
use std::sync::Arc;

use cerberus_api::tls::TlsPaths;
use cerberus_api::{ApiConfig, AppState, RunningServer, start};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::items::{ItemInput, Payload};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreConfig, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    AgentId, Environment, GrantMode, ItemId, LockReason, OperatorRole, Permission, RequestId,
    Scope, SystemClock, WorkspaceId,
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
pub const PASSWORD: &str = "canary-pw-7f3a91c2";
pub const USERNAME: &str = "canary-user-5d20be41";
pub const SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

pub type Client = RunningService<RoleClient, ClientConfig>;

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub core: VaultService,
    pub owner: OperatorContext,
    pub owner_id: cerberus_types::OperatorId,
    pub server: Option<RunningServer>,
    pub addr: SocketAddr,
    pub ca_der: Vec<u8>,
    pub workspace: WorkspaceId,
    pub agent: AgentId,
    pub token: String,
    pub item: ItemId,
    pub state: AppState,
}

pub fn op_ctx(owner: &OperatorContext) -> OperatorContext {
    OperatorContext {
        request_id: RequestId::generate(),
        ..owner.clone()
    }
}

pub fn web_login(workspace: WorkspaceId, title: &str, env: Environment) -> ItemInput {
    ItemInput {
        workspace_id: workspace,
        title: title.to_owned(),
        description: "Shop admin login".to_owned(),
        role_label: Some("admin".to_owned()),
        category: "Web login".to_owned(),
        tags: vec!["shop".to_owned()],
        environment: env,
        target: Some("https://shop.example.test/login".to_owned()),
        custom: BTreeMap::new(),
        expires_at: None,
        max_uses: None,
        payload: Payload::WebLogin {
            username: SecretString::new(USERNAME.to_owned()),
            password: SecretString::new(PASSWORD.to_owned()),
            url: None,
            totp: None,
        },
    }
}

impl Fixture {
    pub async fn new() -> Self {
        Self::with_scopes(&[
            Scope::StatusRead,
            Scope::CatalogRead,
            Scope::SecretsRead,
            Scope::SecretsWrite,
            Scope::SessionsWrite,
            Scope::Requests,
        ])
        .await
    }

    /// The agent has these scopes; the grant allows `find`, `read` and `create_session` (not `write`).
    pub async fn with_scopes(scopes: &[Scope]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir: PathBuf = dir.path().to_path_buf();
        let tls = TlsPaths::in_data_dir(&data_dir);
        let clock: Arc<dyn cerberus_types::Clock> = Arc::new(SystemClock);
        let store = Store::open(
            OpenOptions {
                path: data_dir.join("vault.cerberus"),
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
                approvals_available: true,
                idle_lock_default: None,
                data_dir: data_dir.clone(),
                ca_issuer: Arc::new(cerberus_api::LocalCaIssuer::new(tls.clone(), vec![])),
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
        let (agent_view, new_key) = core
            .create_agent(
                &owner,
                AgentInput {
                    name: "qa-agent".to_owned(),
                    description: String::new(),
                },
                AgentKeyInput {
                    scopes: scopes.to_vec(),
                    lifetime_days: Some(30),
                    ip_allowlist: vec![],
                    require_mtls: false,
                },
            )
            .await
            .expect("agent");
        let mut permissions = BTreeSet::new();
        permissions.extend([
            Permission::Find,
            Permission::Read,
            Permission::CreateSession,
        ]);
        core.put_grant(
            &owner,
            GrantInput {
                id: None,
                agent_id: agent_view.id,
                selector: Selector {
                    workspace_ids: vec![ws.id],
                    environments: vec![Environment::Staging, Environment::Prod, Environment::Dev],
                    categories: vec![],
                    tags: vec![],
                    kinds: vec![],
                    role_labels: vec![],
                    item_ids: vec![],
                },
                permissions,
                mode: GrantMode::Auto,
                conditions: Conditions::default(),
                allow_prod_auto: false,
            },
        )
        .await
        .expect("grant");
        let item = core
            .create_item_as_operator(&owner, web_login(ws.id, "Shop admin", Environment::Staging))
            .await
            .expect("item");
        let mut config = ApiConfig::loopback(tls);
        config.bind = vec!["127.0.0.1:0".parse().expect("addr")];
        let ca_der = core.tls_ca_cert().await.expect("tls_ca_cert");
        let state = AppState::new(core.clone(), &config);
        let app = cerberus_api::app(&state, cerberus_mcp::mcp_router(&state));
        let server = start(&config, state.clone(), app).await.expect("start");
        let addr = server.local_addrs()[0];
        let token = new_key.token.expose_secret().to_owned();
        Self {
            dir,
            core,
            owner_id: created.owner_id,
            owner,
            server: Some(server),
            addr,
            ca_der,
            workspace: ws.id,
            agent: agent_view.id,
            token,
            item: item.summary.id,
            state,
        }
    }

    pub async fn prod_item(&self, title: &str) -> ItemId {
        self.core
            .create_item_as_operator(
                &op_ctx(&self.owner),
                web_login(self.workspace, title, Environment::Prod),
            )
            .await
            .expect("prod item")
            .summary
            .id
    }

    pub fn url(&self) -> String {
        format!("https://localhost:{}/mcp", self.addr.port())
    }

    /// The rustls config of a client that trusts the vault CA.
    pub fn tls_config(&self) -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(self.ca_der.clone()))
            .expect("root");
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// An rmcp client that sends `token` and trusts the vault CA.
    pub async fn client_with(&self, token: &str) -> Client {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(self.tls_config())
            .build()
            .expect("http client");
        let config = StreamableHttpClientTransportConfig::with_uri(self.url()).auth_header(token);
        let transport = StreamableHttpClientTransport::with_client(http, config);
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("cerberus-test-client", "0.0.0"),
        )
        .serve(transport)
        .await
        .expect("mcp initialize")
    }

    pub async fn client(&self) -> Client {
        self.client_with(&self.token).await
    }

    pub async fn lock(&self) {
        self.core.lock(LockReason::Manual).await.expect("lock");
    }

    pub async fn unlock(&self) {
        self.core
            .unlock_with_phrase(self.owner_id, SecretString::new(PHRASE.to_owned()))
            .await
            .expect("unlock");
    }

    pub async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }
}

/// Calls a tool with a JSON object of arguments.
pub async fn call(client: &Client, name: &'static str, args: Value) -> CallToolResult {
    let Value::Object(map) = args else {
        panic!("arguments must be an object");
    };
    client
        .call_tool(CallToolRequestParams::new(name).with_arguments(map))
        .await
        .expect("tool call")
}

/// The structured content of a result.
pub fn data(result: &CallToolResult) -> Value {
    result
        .structured_content
        .clone()
        .expect("structured content")
}

/// The text content of a result.
pub fn text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn error_code(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "expected an error: {result:?}");
    data(result)["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}
