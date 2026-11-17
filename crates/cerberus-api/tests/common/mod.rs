//! Test harness: a real vault, a real TLS server on an ephemeral port, and a small HTTPS client.
//! All secret values here are fake test values.
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
use std::time::Duration;

use cerberus_api::tls::{LocalCa, TlsPaths, leaf_names, write_leaf};
use cerberus_api::{ApiConfig, AppState, RunningServer, start};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::items::{ItemInput, Payload};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{
    CaIssuer, CoreConfig, CoreError, IssuedCa, NewVault, OperatorContext, VaultService,
};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    AgentId, Environment, GrantMode, ItemId, ItemKind, LockReason, OperatorRole, Permission,
    RequestId, Scope, SystemClock, VaultId, WorkspaceId,
};
use http_body_util_lite::collect;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use jiff::Timestamp;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const PHRASE: &str = "orbit velvet canyon mosaic 7";
pub const PASSWORD: &str = "canary-pw-7f3a91c2";
pub const USERNAME: &str = "canary-user-5d20be41";

/// Makes the CA and the first leaf from a CA the test keeps, so the test can sign client certs.
#[derive(Debug)]
pub struct FixedIssuer {
    pub ca: Arc<LocalCa>,
    pub tls: TlsPaths,
}

impl CaIssuer for FixedIssuer {
    fn issue_ca(&self, _vault_id: &VaultId, now: Timestamp) -> Result<IssuedCa, CoreError> {
        let leaf = self.ca.issue_leaf(&leaf_names(&[]), now).expect("leaf");
        write_leaf(&self.tls, &leaf).expect("write leaf");
        Ok(self.ca.to_issued().expect("issued"))
    }
}

#[derive(Default)]
pub struct Options {
    /// Use a CA the test keeps (needed to issue client certificates).
    pub keep_ca: bool,
    /// Require a client certificate for every connection.
    pub require_client_cert: bool,
    /// Verify client certificates when sent.
    pub client_ca: bool,
    pub bind_lan: bool,
    /// Run the vault on a clock that only the test moves (`Fixture::clock`). Tests that depend on
    /// elapsed time (rate limits, expiry) use it, so a loaded machine cannot change the outcome.
    pub manual_clock: bool,
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub core: VaultService,
    pub owner: OperatorContext,
    pub owner_label_id: cerberus_types::OperatorId,
    pub server: Option<RunningServer>,
    pub addr: SocketAddr,
    pub tls: TlsPaths,
    pub ca_der: Vec<u8>,
    pub ca: Option<Arc<LocalCa>>,
    pub workspace: WorkspaceId,
    pub agent: AgentId,
    pub token: String,
    pub key_id: cerberus_types::AgentKeyId,
    pub item: ItemId,
    pub state: AppState,
    /// Set when `Options::manual_clock` is on.
    pub clock: Option<cerberus_types::ManualClock>,
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
        Self::with(Options::default()).await
    }

    pub async fn with(opts: Options) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir: PathBuf = dir.path().to_path_buf();
        let tls = TlsPaths::in_data_dir(&data_dir);
        let manual = opts
            .manual_clock
            .then(|| cerberus_types::ManualClock::new(cerberus_types::Clock::now(&SystemClock)));
        let clock: Arc<dyn cerberus_types::Clock> = match &manual {
            Some(manual) => Arc::new(manual.clone()),
            None => Arc::new(SystemClock),
        };
        let (issuer, ca): (Arc<dyn CaIssuer>, Option<Arc<LocalCa>>) = if opts.keep_ca {
            let ca = Arc::new(LocalCa::create(&VaultId::generate(), clock.now()).expect("ca"));
            (
                Arc::new(FixedIssuer {
                    ca: Arc::clone(&ca),
                    tls: tls.clone(),
                }),
                Some(ca),
            )
        } else {
            (
                Arc::new(cerberus_api::LocalCaIssuer::new(tls.clone(), vec![])),
                None,
            )
        };
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
                ca_issuer: issuer,
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
        let mut config = ApiConfig::loopback(tls.clone());
        config.bind = if opts.bind_lan {
            vec!["0.0.0.0:0".parse().expect("addr")]
        } else {
            vec!["127.0.0.1:0".parse().expect("addr")]
        };
        let ca_der = core.tls_ca_cert().await.expect("tls_ca_cert");
        if opts.client_ca {
            config.client_ca_der = Some(ca_der.clone());
        }
        config.require_client_cert = opts.require_client_cert;
        let state = AppState::new(core.clone(), &config);
        let server = start(&config, state.clone(), cerberus_api::router(&state))
            .await
            .expect("start");
        let addr = server.local_addrs()[0];
        let token = new_key.token.expose_secret().to_owned();
        Self {
            dir,
            core,
            owner_label_id: created.owner_id,
            owner,
            server: Some(server),
            addr,
            tls,
            ca_der,
            ca,
            workspace: ws.id,
            agent: agent_view.id,
            token,
            key_id: new_key.key.id,
            item: item.summary.id,
            state,
            clock: manual,
        }
    }

    pub fn client(&self) -> Client {
        Client::new(self.addr, &self.ca_der, None)
    }

    pub async fn lock(&self) {
        self.core.lock(LockReason::Manual).await.expect("lock");
    }

    pub async fn unlock(&self) {
        self.core
            .unlock_with_phrase(self.owner_label_id, SecretString::new(PHRASE.to_owned()))
            .await
            .expect("unlock");
    }

    pub async fn stop(mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }
}

pub struct Resp {
    pub status: u16,
    pub headers: hyper::HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    pub fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

pub fn client_config(
    ca_der: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
    identity: Option<(Vec<u8>, Vec<u8>)>,
) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("root");
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(roots);
    let config = match identity {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .expect("client auth"),
    };
    Arc::new(config)
}

#[derive(Clone)]
pub struct Client {
    pub addr: SocketAddr,
    pub config: Arc<rustls::ClientConfig>,
}

impl Client {
    pub fn new(addr: SocketAddr, ca_der: &[u8], identity: Option<(Vec<u8>, Vec<u8>)>) -> Self {
        Self {
            addr,
            config: client_config(ca_der, &[&rustls::version::TLS13], identity),
        }
    }

    pub fn with_config(addr: SocketAddr, config: Arc<rustls::ClientConfig>) -> Self {
        Self { addr, config }
    }

    pub async fn connect(
        &self,
    ) -> Result<hyper::client::conn::http1::SendRequest<http_body_util_lite::Full>, std::io::Error>
    {
        let tcp = TcpStream::connect(self.addr).await?;
        let tls = TlsConnector::from(Arc::clone(&self.config))
            .connect(ServerName::try_from("localhost").expect("name"), tcp)
            .await?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(std::io::Error::other)?;
        tokio::spawn(async move {
            drop(conn.await);
        });
        Ok(sender)
    }

    pub async fn send(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<&str>,
    ) -> Resp {
        let (status, headers, incoming) = self.send_stream(method, path, token, extra, body).await;
        let body = collect(incoming).await;
        Resp {
            status,
            headers,
            body,
        }
    }

    pub async fn send_stream(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: Option<&str>,
    ) -> (u16, hyper::HeaderMap, Incoming) {
        let mut sender = self.connect().await.expect("connect");
        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", format!("localhost:{}", self.addr.port()));
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let has_body = body.is_some();
        if has_body && !extra.iter().any(|(name, _)| *name == "content-type") {
            builder = builder.header("content-type", "application/json");
        }
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        let request = builder
            .body(http_body_util_lite::Full::new(body.unwrap_or("")))
            .expect("request");
        let response = sender.send_request(request).await.expect("send");
        let (parts, incoming) = response.into_parts();
        (parts.status.as_u16(), parts.headers, incoming)
    }

    pub async fn get(&self, path: &str, token: &str) -> Resp {
        self.send("GET", path, Some(token), &[], None).await
    }

    pub async fn post(&self, path: &str, token: &str, body: &str) -> Resp {
        self.send("POST", path, Some(token), &[], Some(body)).await
    }
}

/// Reads SSE events (`event`, `data`) from a body until `stop` says so or the stream ends.
pub async fn read_events(
    mut body: Incoming,
    max: usize,
    wait: Duration,
) -> Vec<(String, serde_json::Value)> {
    use http_body_util_lite::next_frame_bytes;
    let mut out = Vec::new();
    let mut buffer = String::new();
    let deadline = tokio::time::Instant::now() + wait;
    while out.len() < max {
        let chunk = tokio::time::timeout_at(deadline, next_frame_bytes(&mut body)).await;
        let Ok(Some(bytes)) = chunk else { break };
        buffer.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(end) = buffer.find("\n\n") {
            let block: String = buffer.drain(..end + 2).collect();
            let mut name = String::new();
            let mut data = String::new();
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    name = v.trim().to_owned();
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push_str(v.trim());
                }
            }
            if !name.is_empty() {
                out.push((name, serde_json::from_str(&data).unwrap_or_default()));
            }
        }
    }
    out
}

/// Tiny body helpers over `hyper::body`, so the tests need no extra crate.
pub mod http_body_util_lite {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use hyper::body::{Body, Frame, Incoming};

    /// A request body from a string.
    pub struct Full {
        data: Option<Bytes>,
    }

    impl Full {
        pub fn new(text: &str) -> Self {
            Self {
                data: Some(Bytes::copy_from_slice(text.as_bytes())).filter(|b| !b.is_empty()),
            }
        }
    }

    impl Body for Full {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.data.take().map(|b| Ok(Frame::data(b))))
        }
    }

    pub async fn next_frame_bytes(body: &mut Incoming) -> Option<Bytes> {
        loop {
            let frame = std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await?;
            if let Ok(frame) = frame
                && let Ok(data) = frame.into_data()
            {
                return Some(data);
            }
            if body.is_end_stream() {
                return None;
            }
        }
    }

    pub async fn collect(mut body: Incoming) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = next_frame_bytes(&mut body).await {
            out.extend_from_slice(&chunk);
        }
        out
    }
}

pub fn token_with_secret(token: &str, secret: &str) -> String {
    let (head, _) = token.split_once('.').expect("token shape");
    format!("{head}.{secret}")
}

pub fn assert_error_shape(resp: &Resp, status: u16, code: &str) {
    assert_eq!(
        resp.status,
        status,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let json = resp.json();
    let error = &json["error"];
    assert_eq!(error["code"], code);
    assert!(error["message"].is_string());
    assert!(error["retryable"].is_boolean());
    assert_eq!(
        error["request_id"].as_str(),
        resp.header("x-request-id").as_deref(),
        "request id in body and header"
    );
    assert_eq!(json.as_object().map(serde_json::Map::len), Some(1));
}

pub const ITEM_KIND_WEB: ItemKind = ItemKind::WebLogin;
