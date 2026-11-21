//! Shared harness of the remote mode tests: a real `cerberusd` with the admin API on (the serve
//! loop, the unlock socket and the TLS listener of the daemon crate, in this process, on a free
//! loopback port), an enrolment bundle from `cerberusd admin enroll`, and a desktop state in
//! remote mode. Every secret here is a fake test value.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerberus_admin::bundle::AdminBundle;
use cerberus_api::tls::{LocalCaIssuer, TlsPaths};
use cerberus_core::admin::WorkspaceInput;
use cerberus_core::agents::{AgentInput, AgentKeyInput};
use cerberus_core::items::{ItemInput, Payload};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreConfig, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_desktop::error::IpcResult;
use cerberus_desktop::{AppPaths, DesktopState, Prefs, RemotePrefs, Shell, StateOptions, remote};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{
    Clock, Environment, GrantMode, ItemId, OperatorRole, Permission, RequestId, Scope, SystemClock,
    WorkspaceId,
};
use cerberusd::admin::{self as daemon_admin, EnrollRequest};
use cerberusd::config::{self, Config};
use cerberusd::daemon::{self, DaemonError, Ready};
use cerberusd::https;
use cerberusd::unlock;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub const PHRASE: &str = "orbit velvet canyon mosaic 7";
pub const PASSWORD: &str = "canary-pw-7f3a91c2";
pub const MAIN: &str = "main";

/// A shell with a fake file dialog and clipboard.
#[derive(Default)]
pub struct FakeShell {
    pub clipboard: Mutex<Option<String>>,
    pub pick: Mutex<Option<PathBuf>>,
}

impl Shell for FakeShell {
    fn pick_file(&self, _title: Option<&str>, _extensions: &[String]) -> Option<PathBuf> {
        self.pick.lock().unwrap().clone()
    }
    fn clipboard_write(&self, text: &str) -> IpcResult<()> {
        *self.clipboard.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }
    fn clipboard_read(&self) -> Option<String> {
        self.clipboard.lock().unwrap().clone()
    }
    fn clipboard_clear(&self) {
        *self.clipboard.lock().unwrap() = None;
    }
    fn set_autostart(&self, _enabled: bool) -> IpcResult<()> {
        Ok(())
    }
    fn set_content_protection(&self, _enabled: bool) {}
}

/// What the vault seed gives the tests: an agent token, the agent's `ask_once` item, the workspace
/// and the owner.
pub struct Seed {
    pub token: String,
    pub item: ItemId,
    pub workspace: WorkspaceId,
    pub owner: cerberus_types::OperatorId,
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

/// Makes a vault in `data_dir` with the core API (an owner, a workspace, an agent with an
/// `ask_once` grant on one item), then closes it. The daemon opens it next.
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
        clock,
        CoreConfig {
            approvals_available: false,
            idle_lock_default: None,
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
                environments: vec![Environment::Dev],
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
        .create_item_as_operator(&owner, web_login(ws.id))
        .await
        .expect("item");
    let seed = Seed {
        token: key.token.expose_secret().to_owned(),
        item: item.summary.id,
        workspace: ws.id,
        owner: created.owner_id,
    };
    drop(core);
    seed
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("addr").port()
}

/// A running `cerberusd`, unlocked once at the terminal (its TLS leaf exists then).
pub struct Daemon {
    pub dir: tempfile::TempDir,
    pub data: PathBuf,
    pub config: Config,
    pub ready: Ready,
    pub seed: Seed,
    pub ca_der: Vec<u8>,
    pub port: u16,
    stop: Option<oneshot::Sender<()>>,
    run: Option<JoinHandle<Result<VaultService, DaemonError>>>,
}

impl Daemon {
    /// Makes a vault, starts the daemon (`[admin] enabled = admin`) and unlocks it through the
    /// socket, as `cerberusd unlock` does.
    pub async fn start(admin: bool) -> Self {
        Self::start_with(admin, "").await
    }

    /// As [`Self::start`], with extra lines in the `[admin]` table (session limits).
    pub async fn start_with(admin: bool, admin_extra: &str) -> Self {
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
                "data_dir = {:?}\nbind = [\"127.0.0.1\"]\nport = {port}\n[admin]\nenabled = {admin}\n{admin_extra}",
                data.display().to_string()
            );
            std::fs::write(&path, text).expect("write config");
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
                    eprintln!("cerberusd did not start ({error}); trying another port");
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
        // The listener comes up with the leaf; wait until it answers.
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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

    pub fn addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], self.port))
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

    /// Writes `bundle` as a new file next to the data folder and returns the path.
    pub fn bundle_file(&self, bundle: &AdminBundle, name: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        bundle.write_new(&path).expect("write bundle");
        path
    }

    /// `cerberusd unlock` again (after a remote lock).
    pub async fn unlock(&self) {
        unlock::unlock_with(&self.ready.socket, None, |_| Ok(PHRASE.to_owned()))
            .await
            .expect("terminal unlock");
    }

    /// `cerberusd admin revoke <id>`.
    pub async fn revoke(&self, bundle: &AdminBundle) {
        daemon_admin::revoke_with(&self.ready.socket, &self.data, &bundle.id.to_string())
            .await
            .expect("revoke");
    }

    /// An agent call with the seed token.
    pub async fn agent(&self, method: &str, path: &str, body: Option<&str>) -> https::Reply {
        https::request(
            self.addr(),
            &self.ca_der,
            method,
            path,
            Some(&self.seed.token),
            body,
        )
        .await
        .expect("agent call")
    }

    /// An admin call with the bundle's client certificate, outside the desktop.
    pub async fn admin_call(
        &self,
        bundle: &AdminBundle,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> https::Reply {
        let cert = CertificateDer::from_pem_slice(bundle.client_cert_pem.as_bytes()).expect("cert");
        let key = PrivatePkcs8KeyDer::from_pem_slice(bundle.client_key_pem.expose().as_bytes())
            .expect("key");
        let identity = (cert.as_ref().to_vec(), key.secret_pkcs8_der().to_vec());
        https::request_as(
            self.addr(),
            &self.ca_der,
            Some((identity.0.as_slice(), identity.1.as_slice())),
            method,
            path,
            token,
            body,
        )
        .await
        .expect("admin call")
    }

    /// Opens a second admin session with the bundle, outside the desktop. Returns the token.
    pub async fn open_session(&self, bundle: &AdminBundle) -> String {
        let open =
            serde_json::json!({ "operator_id": bundle.operator_id.to_string(), "phrase": PHRASE });
        let reply = self
            .admin_call(
                bundle,
                "POST",
                "/admin/v1/session",
                None,
                Some(&open.to_string()),
            )
            .await;
        assert_eq!(
            reply.status,
            200,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        serde_json::from_slice::<serde_json::Value>(&reply.body).expect("json")["token"]
            .as_str()
            .expect("token")
            .to_owned()
    }

    /// Stops the daemon and returns its (locked) service.
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
    }
}

/// A desktop data folder with `bundle` imported as the active profile (the files and the
/// preferences that `remote_import_bundle` and `remote_activate` write), and the state opened on
/// it: remote mode.
pub async fn remote_desktop(
    bundle_path: &Path,
) -> (DesktopState, tempfile::TempDir, Arc<FakeShell>) {
    remote_desktop_with(bundle_path, StateOptions::default()).await
}

/// As [`remote_desktop`], with state options (a manual clock).
pub async fn remote_desktop_with(
    bundle_path: &Path,
    options: StateOptions,
) -> (DesktopState, tempfile::TempDir, Arc<FakeShell>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().to_path_buf());
    let profile =
        remote::profile::stage(&paths, bundle_path, SystemClock.now()).expect("stage bundle");
    remote::profile::commit(&paths, &profile.id).expect("store profile");
    Prefs {
        port: 0,
        remote: RemotePrefs {
            active: Some(profile.id.clone()),
            profiles: vec![profile],
        },
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(FakeShell::default());
    let state = DesktopState::open(paths, shell.clone(), options)
        .await
        .expect("open in remote mode");
    (state, dir, shell)
}

/// The JSON input of a new web login in `workspace`.
pub fn web_login_input(workspace: &str, title: &str) -> serde_json::Value {
    serde_json::json!({
        "workspace_id": workspace, "title": title, "description": "", "role_label": null,
        "category": "Web login", "tags": [], "environment": "dev", "target": null, "custom": {},
        "expires_at": null, "max_uses": null,
        "payload": { "kind": "web_login", "username": "remote-user", "password": PASSWORD,
                     "url": null, "totp": null }
    })
}
