//! Test harness: a real vault in a temp dir, one agent with `ssh:use`, an ed25519 key item made
//! at run time, a bridge with its runtime directory in the temp dir, and a raw ssh-agent client.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agent_api::ssh::SshPrepareInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::auth::TokenCheckInput;
use cerberus_core::items::{ItemInput, Payload, generate_ed25519};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{
    AgentContext, CaIssuer, CoreConfig, CoreError, IssuedCa, NewVault, OperatorContext, Surface,
    VaultService,
};
use cerberus_crypto::{KdfParams, SecretBytes, SecretString};
use cerberus_ssh_agent::{BridgeConfig, PrepareOutcome, SshBridge, SshReady};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    Environment, GrantMode, ItemId, LockReason, OperatorRole, Permission, RequestId, Scope,
    SystemClock, VaultId, WorkspaceId,
};
use jiff::{SignedDuration, Timestamp};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const PHRASE: &str = "orbit velvet canyon mosaic 7";

#[derive(Debug)]
struct FakeCa;

impl CaIssuer for FakeCa {
    fn issue_ca(&self, _vault_id: &VaultId, now: Timestamp) -> Result<IssuedCa, CoreError> {
        Ok(IssuedCa {
            cert_der: b"fake-ca-cert".to_vec(),
            key_der: SecretBytes::new(b"fake-ca-key".to_vec()),
            not_after: now + SignedDuration::from_hours(24 * 3650),
            pin: "sha256/fake-pin".to_owned(),
        })
    }
}

pub struct Fx {
    pub dir: tempfile::TempDir,
    pub core: VaultService,
    pub owner: OperatorContext,
    pub workspace: WorkspaceId,
    pub agent: AgentContext,
    pub item: ItemId,
    /// Text forms of the private key that must never leave core.
    pub markers: Vec<String>,
    pub bridge: SshBridge,
}

pub fn runtime_dir(dir: &Path) -> PathBuf {
    dir.join("run").join("cerberus-ssh")
}

/// The Base64 lines of the OpenSSH private key text and the hex of the ed25519 seed.
pub fn key_markers(payload: &Payload) -> Vec<String> {
    let Payload::SshKey { private_key, .. } = payload else {
        panic!("ssh payload expected");
    };
    let text = private_key.expose_secret();
    let mut out: Vec<String> = text
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
        .map(str::to_owned)
        .collect();
    let key = PrivateKey::from_openssh(text).unwrap();
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    out.push(seed.iter().map(|b| format!("{b:02x}")).collect());
    out
}

pub fn ssh_item(
    ws: WorkspaceId,
    title: &str,
    payload: Payload,
    port: u16,
    user: &str,
) -> ItemInput {
    let mut custom = BTreeMap::new();
    custom.insert("machine".to_owned(), "build-01".to_owned());
    custom.insert("host".to_owned(), "127.0.0.1".to_owned());
    custom.insert("port".to_owned(), port.to_string());
    custom.insert("user".to_owned(), user.to_owned());
    ItemInput {
        workspace_id: ws,
        title: title.to_owned(),
        description: "fake test key".to_owned(),
        role_label: None,
        category: "SSH key".to_owned(),
        tags: Vec::new(),
        environment: Environment::Dev,
        target: Some("build-01".to_owned()),
        custom,
        expires_at: None,
        max_uses: None,
        payload,
    }
}

pub fn input() -> SshPrepareInput {
    SshPrepareInput {
        purpose: "deploy the build".to_owned(),
        ..SshPrepareInput::default()
    }
}

impl Fx {
    pub async fn new() -> Self {
        Self::with(2222, "ci", GrantMode::Auto).await
    }

    pub async fn with(port: u16, user: &str, mode: GrantMode) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock: Arc<dyn cerberus_types::Clock> = Arc::new(SystemClock);
        let store = Store::open(
            OpenOptions {
                path: dir.path().join("vault.cerberus"),
                create: true,
            },
            Arc::clone(&clock),
        )
        .await
        .unwrap();
        let core = VaultService::open(
            store,
            clock,
            CoreConfig {
                approvals_available: true,
                idle_lock_default: None,
                data_dir: dir.path().to_path_buf(),
                ca_issuer: Arc::new(FakeCa),
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
                    slug: "infra".to_owned(),
                    name: "Infra".to_owned(),
                    description: String::new(),
                    aliases: vec![],
                },
            )
            .await
            .unwrap();
        let (agent_view, key) = core
            .create_agent(
                &owner,
                AgentInput {
                    name: "deploy-agent".to_owned(),
                    description: String::new(),
                },
                AgentKeyInput {
                    scopes: vec![Scope::SshUse, Scope::Requests, Scope::SecretsRead],
                    lifetime_days: Some(30),
                    ip_allowlist: vec![],
                    require_mtls: false,
                },
            )
            .await
            .unwrap();
        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::UseSsh);
        core.put_grant(
            &owner,
            GrantInput {
                id: None,
                agent_id: agent_view.id,
                selector: Selector::default(),
                permissions,
                mode,
                conditions: Conditions::default(),
                allow_prod_auto: false,
            },
        )
        .await
        .unwrap();
        let payload = generate_ed25519("fake-build-01").unwrap();
        let markers = key_markers(&payload);
        let item = core
            .create_item_as_operator(&owner, ssh_item(ws.id, "Build key", payload, port, user))
            .await
            .unwrap()
            .summary
            .id;
        let agent = core
            .auth()
            .check(
                &TokenCheckInput {
                    raw_token: key.token.expose_secret(),
                    source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    client_cert_sha256: None,
                    request_id: RequestId::generate(),
                    surface: Surface::Rest,
                },
                core.clock().now(),
            )
            .unwrap();
        let bridge = SshBridge::new(
            core.clone(),
            BridgeConfig {
                runtime_dir: runtime_dir(dir.path()),
            },
        );
        Self {
            dir,
            core,
            owner,
            workspace: ws.id,
            agent,
            item,
            markers,
            bridge,
        }
    }

    pub async fn prepare(&self) -> SshReady {
        self.prepare_item(self.item).await
    }

    pub async fn prepare_item(&self, item: ItemId) -> SshReady {
        match self
            .bridge
            .prepare(&self.agent, item, input())
            .await
            .unwrap()
        {
            PrepareOutcome::Ready(ready) => *ready,
            PrepareOutcome::Pending(p) => panic!("expected ready, got {p:?}"),
        }
    }

    pub async fn lock(&self) {
        self.core.lock(LockReason::Manual).await.unwrap();
    }

    pub async fn unlock(&self) {
        let operator = self.owner.operator_id;
        self.core
            .unlock_with_phrase(operator, SecretString::new(PHRASE.to_owned()))
            .await
            .unwrap();
    }

    pub async fn audit_export_text(&self) -> String {
        let dest = self
            .dir
            .path()
            .join(format!("audit-{}.jsonl", RequestId::generate()));
        self.core.audit_export(&self.owner, &dest).await.unwrap();
        std::fs::read_to_string(&dest).unwrap()
    }
}

/// Waits up to 5 s for `path` to be gone.
pub async fn gone(path: &Path) -> bool {
    for _ in 0..100 {
        if !path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
}

/// The data an SSH client signs for a public key login.
pub fn userauth(blob: &[u8], user: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, &[9; 32]);
    out.push(50);
    put_string(&mut out, user.as_bytes());
    put_string(&mut out, b"ssh-connection");
    put_string(&mut out, b"publickey");
    out.push(1);
    put_string(&mut out, b"ssh-ed25519");
    put_string(&mut out, blob);
    out
}

/// A raw ssh-agent client.
pub struct AgentClient {
    stream: UnixStream,
}

impl AgentClient {
    pub async fn connect(path: &Path) -> Self {
        Self {
            stream: UnixStream::connect(path).await.unwrap(),
        }
    }

    /// Sends one message body (type and contents) and reads one answer body.
    pub async fn call(&mut self, body: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(body);
        self.stream.write_all(&frame).await.unwrap();
        self.read().await.expect("an answer")
    }

    /// Writes raw bytes. False when the bridge already closed the connection.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> bool {
        self.stream.write_all(bytes).await.is_ok()
    }

    /// One answer body, or `None` when the bridge closed the connection.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        let mut head = [0_u8; 4];
        self.stream.read_exact(&mut head).await.ok()?;
        let mut body = vec![0; usize::try_from(u32::from_be_bytes(head)).unwrap()];
        self.stream.read_exact(&mut body).await.ok()?;
        Some(body)
    }

    /// The key blobs of `REQUEST_IDENTITIES`.
    pub async fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
        let answer = self.call(&[11]).await;
        assert_eq!(answer[0], 12, "IDENTITIES_ANSWER");
        let mut rest = &answer[1..];
        let count = take_u32(&mut rest);
        let mut out = Vec::new();
        for _ in 0..count {
            let blob = take_string(&mut rest).to_vec();
            let comment = String::from_utf8(take_string(&mut rest).to_vec()).unwrap();
            out.push((blob, comment));
        }
        assert!(rest.is_empty());
        out
    }

    /// The signature blob of a `SIGN_REQUEST`, or `None` for `SSH_AGENT_FAILURE`.
    pub async fn sign(&mut self, blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let mut body = vec![13];
        put_string(&mut body, blob);
        put_string(&mut body, data);
        body.extend_from_slice(&0_u32.to_be_bytes());
        let answer = self.call(&body).await;
        match answer[0] {
            14 => {
                let mut rest = &answer[1..];
                let sig = take_string(&mut rest).to_vec();
                assert!(rest.is_empty());
                Some(sig)
            }
            5 => {
                assert_eq!(answer.len(), 1);
                None
            }
            other => panic!("unexpected answer type {other}"),
        }
    }
}

fn take_u32(input: &mut &[u8]) -> u32 {
    let (head, rest) = input.split_at(4);
    *input = rest;
    u32::from_be_bytes(head.try_into().unwrap())
}

fn take_string<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let len = usize::try_from(take_u32(input)).unwrap();
    let (value, rest) = input.split_at(len);
    *input = rest;
    value
}
