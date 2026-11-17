//! A real vault, a real TLS server on an ephemeral port, one agent token and one item.
//! All secret values are fake test values.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use cerberus_api::tls::{CaExport, TlsPaths};
use cerberus_api::{ApiConfig, AppState, LocalCaIssuer, RunningServer, start};
use cerberus_client::{Client, ClientConfig, Trust};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::items::{ItemInput, Payload};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::{CoreConfig, KeyCustody, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::wire::WireSecret;
use cerberus_types::{
    AccessRequestId, ApprovalOption, Environment, GrantMode, ItemId, LockReason, OperatorRole,
    Permission, RequestId, Scope, SystemClock, WorkspaceId,
};

pub const PHRASE: &str = "orbit velvet canyon mosaic 7";
/// Fake secret values. The tests search every output for these.
pub const PASSWORD: &str = "canary-pw-7f3a91c2";
pub const USERNAME: &str = "canary-user-5d20be41";

fn web_login(workspace_id: WorkspaceId, title: &str, environment: Environment) -> ItemInput {
    ItemInput {
        workspace_id,
        title: title.to_owned(),
        description: "Shop admin login".to_owned(),
        role_label: Some("admin".to_owned()),
        category: "Web login".to_owned(),
        tags: vec!["shop".to_owned()],
        environment,
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

pub struct Real {
    pub dir: tempfile::TempDir,
    pub core: VaultService,
    pub owner: OperatorContext,
    pub owner_id: cerberus_types::OperatorId,
    pub server: Option<RunningServer>,
    pub addr: SocketAddr,
    pub export: CaExport,
    pub ca_file: PathBuf,
    pub token: String,
    pub item: ItemId,
    /// A prod item: reading it needs a person to approve (ADR-0017).
    pub prod_item: ItemId,
}

impl Real {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
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
        .unwrap();
        let core = VaultService::open(
            store,
            Arc::clone(&clock),
            CoreConfig {
                approvals_available: true,
                idle_lock_default: None,
                data_dir: data_dir.clone(),
                ca_issuer: Arc::new(LocalCaIssuer::new(tls.clone(), vec![])),
            },
        )
        .await
        .unwrap();
        let created = core
            .create_vault(NewVault {
                owner_label: "owner".to_owned(),
                phrase: SecretString::new(PHRASE.to_owned()),
                kdf: KdfParams::new(19_456, 1, 1).unwrap(),
                host_names: vec![],
            })
            .await
            .unwrap();
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
                    slug: "shop".to_owned(),
                    name: "Shop".to_owned(),
                    description: String::new(),
                    aliases: vec![],
                },
            )
            .await
            .unwrap();
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
            .unwrap();
        let mut permissions = BTreeSet::new();
        permissions.extend([
            Permission::Find,
            Permission::Read,
            Permission::CreateSession,
            Permission::Write,
        ]);
        core.put_grant(
            &owner,
            GrantInput {
                id: None,
                agent_id: agent.id,
                selector: Selector {
                    workspace_ids: vec![ws.id],
                    environments: vec![Environment::Staging, Environment::Dev, Environment::Prod],
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
        .unwrap();
        let item = core
            .create_item_as_operator(&owner, web_login(ws.id, "Shop admin", Environment::Staging))
            .await
            .unwrap();
        let prod_item = core
            .create_item_as_operator(
                &owner,
                web_login(ws.id, "Shop prod admin", Environment::Prod),
            )
            .await
            .unwrap();
        let mut config = ApiConfig::loopback(tls.clone());
        config.bind = vec!["127.0.0.1:0".parse().unwrap()];
        let ca_der = core.tls_ca_cert().await.unwrap();
        let export = CaExport::from_der(&ca_der).unwrap();
        let ca_file = data_dir.join("ca.pem");
        std::fs::write(&ca_file, &export.pem).unwrap();
        let state = AppState::new(core.clone(), &config);
        let server = start(&config, state.clone(), cerberus_api::router(&state))
            .await
            .unwrap();
        let addr = server.local_addrs()[0];
        Self {
            dir,
            core,
            owner,
            owner_id: created.owner_id,
            server: Some(server),
            addr,
            export,
            ca_file,
            token: key.token.expose_secret().to_owned(),
            item: item.summary.id,
            prod_item: prod_item.summary.id,
        }
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub fn config(&self) -> ClientConfig {
        ClientConfig {
            base_url: url::Url::parse(&self.url()).unwrap(),
            token: WireSecret::new(self.token.clone()),
            trust: Trust::CaFileAndPin {
                ca: self.ca_file.clone(),
                pin: self.export.pin.clone(),
            },
            client_cert: None,
            timeout: std::time::Duration::from_secs(10),
        }
    }

    pub fn client(&self) -> Client {
        Client::new(&self.config()).unwrap()
    }

    /// The owner approves a request once.
    pub async fn approve(&self, id: AccessRequestId) {
        let owner = OperatorContext {
            request_id: RequestId::generate(),
            ..self.owner.clone()
        };
        self.core
            .approve_request(&owner, id, ApprovalOption::Once)
            .await
            .unwrap();
    }

    pub async fn lock(&self) {
        self.core.lock(LockReason::Manual).await.unwrap();
    }

    pub async fn unlock(&self) {
        self.core
            .unlock_with_phrase(self.owner_id, SecretString::new(PHRASE.to_owned()))
            .await
            .unwrap();
    }

    pub async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }
}
