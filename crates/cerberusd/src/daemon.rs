//! The daemon: opens the vault, serves the Agent API over TLS, takes unlock requests on a local socket, and on stop
//! locks the vault before it stops the server (ADR-0002, ADR-0023, ADR-0026).
//!
//! The daemon starts sealed. If the vault has no TLS leaf yet (a backup copied from the desktop has none, ADR-0031
//! point 2), the listener starts after the first unlock, because the CA key is sealed until then.

use std::future::Future;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_api::tls::{
    CaExport, LocalCa, LocalCaIssuer, TlsPaths, leaf_names, renew_leaf_if_needed,
};
use cerberus_api::{ApiConfig, AppState, RunningServer, ServerError, start};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreConfig, CoreError, VaultService};
use cerberus_store::{OpenOptions, Store, StoreError};
use cerberus_types::{Clock, LockReason, SystemClock, VaultStateKind};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::unlock;

/// The vault file in the data directory.
pub const VAULT_FILE: &str = "vault.cerberus";
/// The CA certificate in PEM, in the TLS directory. It is public: agents trust it (ADR-0023 point 7).
pub const CA_PEM_FILE: &str = "tls/ca-cert.pem";

/// What the daemon reports once it is ready to take requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ready {
    /// Addresses the HTTPS listener is bound to. Empty until the first unlock when there is no TLS leaf yet.
    pub addrs: Vec<std::net::SocketAddr>,
    /// The unlock socket.
    pub socket: PathBuf,
}

/// Why the daemon cannot run.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// The vault file is not in the data directory.
    #[error(
        "no vault file at {path}. Make a backup in the desktop app, copy it to this path as {VAULT_FILE} with mode 0600, then start again."
    )]
    NoVault {
        /// The expected path.
        path: PathBuf,
    },
    /// The vault file cannot be opened.
    #[error("cannot open the vault file: {0}")]
    Store(#[from] StoreError),
    /// The vault service failed.
    #[error("vault error: {0}")]
    Core(#[from] CoreError),
    /// The HTTPS server cannot start.
    #[error("HTTPS server: {0}")]
    Server(#[from] ServerError),
    /// A file or socket error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The data directory or the vault file can be used by other users.
    #[error("{path} has mode {mode:o}; it must not be open to group or others (chmod {fix} {path})", path = .path.display())]
    Mode {
        /// The path.
        path: PathBuf,
        /// The mode found, permission bits only.
        mode: u32,
        /// The mode to set.
        fix: &'static str,
    },
    /// Another daemon listens on the unlock socket.
    #[error("cerberusd is already running for this data directory (socket {0})")]
    AlreadyRunning(PathBuf),
}

/// Refuses a path that group or others can use. systemd sets the modes, but a manual run does not
/// (AUD-30).
fn check_private(path: &Path, fix: &'static str) -> Result<(), DaemonError> {
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(DaemonError::Mode {
            path: path.to_path_buf(),
            mode,
            fix,
        });
    }
    Ok(())
}

/// The HTTPS listener and the task that renews its leaf.
struct Http {
    server: RunningServer,
    renewal: JoinHandle<()>,
}

/// Runs the daemon until `stop` completes. Then it locks the vault and stops the listener.
///
/// `on_ready` runs once the unlock socket is up. The caller uses it to tell systemd the daemon is ready.
/// The returned service is locked: a test or a caller can check it.
///
/// # Errors
/// [`DaemonError`] when the vault cannot be opened or the listener cannot start.
pub async fn serve<S>(
    config: &Config,
    stop: S,
    on_ready: impl FnOnce(&Ready),
) -> Result<VaultService, DaemonError>
where
    S: Future<Output = ()> + Send,
{
    let vault_path = config.data_dir.join(VAULT_FILE);
    if !vault_path.is_file() {
        return Err(DaemonError::NoVault { path: vault_path });
    }
    check_private(&config.data_dir, "0700")?;
    check_private(&vault_path, "0600")?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tls = TlsPaths::in_data_dir(&config.data_dir);
    let store = Store::open(
        OpenOptions {
            path: vault_path,
            create: false,
        },
        Arc::clone(&clock),
    )
    .await?;
    let core = VaultService::open(
        store,
        clock,
        CoreConfig {
            approvals_available: false,
            idle_lock_default: config.idle_lock(),
            data_dir: config.data_dir.clone(),
            ca_issuer: Arc::new(LocalCaIssuer::new(tls.clone(), config.host_names.clone())),
        },
    )
    .await?;
    write_ca_pem(&core, &config.data_dir).await?;
    let tasks = core.spawn_background();
    let listener = unlock::bind(&config.data_dir).await?;
    let socket_task = tokio::spawn(unlock::accept_loop(listener, core.clone()));
    let socket = unlock::socket_path(&config.data_dir);

    let mut http = if leaf_present(&tls) {
        Some(start_http(&core, config, &tls).await?)
    } else {
        None
    };
    let addrs = http
        .as_ref()
        .map(|h| h.server.local_addrs().to_vec())
        .unwrap_or_default();
    on_ready(&Ready {
        addrs,
        socket: socket.clone(),
    });
    tracing::info!(socket = %socket.display(), sealed = http.is_none(), "cerberusd ready");

    tokio::pin!(stop);
    if http.is_none() {
        tokio::select! {
            () = &mut stop => {}
            () = wait_unlocked(&core) => {
                renew_leaf_now(&core, config, &tls).await?;
                http = Some(start_http(&core, config, &tls).await?);
            }
        }
    }
    if http.is_some() {
        stop.await;
    }
    shutdown(&core, http, tasks, socket_task, &socket).await;
    Ok(core)
}

/// Stop the unlock socket, lock, then stop the server. A request during the stop gets `423`, and the keys are
/// gone before the listener closes. The socket stops first, so no unlock can start after the lock.
async fn shutdown(
    core: &VaultService,
    http: Option<Http>,
    tasks: Vec<JoinHandle<()>>,
    socket_task: JoinHandle<()>,
    socket: &Path,
) {
    socket_task.abort();
    if let Err(error) = core.lock(LockReason::Quit).await {
        tracing::error!(%error, "lock on stop failed");
    }
    for task in tasks {
        task.abort();
    }
    if let Some(http) = http {
        http.renewal.abort();
        http.server.shutdown().await;
    }
    if let Err(error) = std::fs::remove_file(socket) {
        tracing::warn!(%error, "could not remove the unlock socket");
    }
    tracing::info!("cerberusd stopped; the vault is locked");
}

fn leaf_present(tls: &TlsPaths) -> bool {
    tls.leaf_cert_der.is_file() && tls.leaf_key_der.is_file()
}

/// Returns when the vault is unlocked. It subscribes before it checks, so no change is missed.
async fn wait_unlocked(core: &VaultService) {
    let mut events = core.subscribe();
    loop {
        if core.state() == VaultStateKind::Unlocked {
            return;
        }
        match events.recv().await {
            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Makes the TLS leaf when there is none. The CA key is needed, so this runs only while unlocked.
async fn renew_leaf_now(
    core: &VaultService,
    config: &Config,
    tls: &TlsPaths,
) -> Result<(), DaemonError> {
    let material = core.tls_ca_material().await?;
    let ca = LocalCa::from_parts(&material.cert_der, &material.key_der)?;
    let mut names = material.host_names;
    names.extend(config.host_names.iter().cloned());
    renew_leaf_if_needed(&ca, tls, &leaf_names(&names), core.clock().now())?;
    Ok(())
}

async fn start_http(
    core: &VaultService,
    config: &Config,
    tls: &TlsPaths,
) -> Result<Http, DaemonError> {
    let mut api = ApiConfig::loopback(tls.clone());
    api.bind = config.listen_addrs();
    api.allowed_hosts = leaf_names(&config.host_names);
    if config.require_mtls {
        api.client_ca_der = Some(core.tls_ca_cert().await?);
        api.require_client_cert = true;
    }
    let state = AppState::new(core.clone(), &api);
    // `/mcp` is mounted next to `/v1`. Its router already has the token check (ADR-0029).
    let app = cerberus_api::app(&state, cerberus_mcp::mcp_router(&state));
    let server = start(&api, state.clone(), app).await?;
    let renewal = server.spawn_leaf_renewal(core.clone(), tls.clone(), config.host_names.clone());
    Ok(Http { server, renewal })
}

/// Writes the CA certificate (public) to `tls/ca-cert.pem`, atomically. It works while sealed.
async fn write_ca_pem(core: &VaultService, data_dir: &Path) -> Result<(), DaemonError> {
    let der = core.tls_ca_cert().await?;
    let export = CaExport::from_der(&der)?;
    let path = data_dir.join(CA_PEM_FILE);
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let tmp = data_dir.join(format!("{CA_PEM_FILE}.tmp"));
    std::fs::write(&tmp, export.pem.as_bytes())?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, &path)?;
    tracing::info!(
        path = %path.display(),
        pin = %export.pin,
        sha256 = %export.cert_sha256_hex,
        "CA certificate written; agents trust it through NODE_EXTRA_CA_CERTS or the pin"
    );
    Ok(())
}

/// Path of the CA certificate for a data directory.
#[must_use]
pub fn ca_pem_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CA_PEM_FILE)
}
