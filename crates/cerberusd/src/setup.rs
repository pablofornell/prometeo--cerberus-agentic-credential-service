//! First-time setup of a server that has no vault (ADR-0034, DEC-SRV-3). The daemon is the custodian of the vault, so
//! nobody types a passphrase on the server: the first client creates the vault over the network.
//!
//! With no vault file `cerberusd serve` does not stop. It tells systemd it is ready and runs a **setup listener** on the
//! configured addresses. Its TLS certificate is self-signed, is not a CA, is made in memory at each start and is
//! never stored in a vault. It serves two routes only: `GET /v1/health` and `POST /v1/setup`. Every other route
//! answers `503 unavailable` ("no vault yet").
//!
//! The listener starts only when the admin API is on (`[admin] enabled`, true by default), because the client that makes the vault must come out of
//! the setup with an admin bundle (ADR-0034) and there is no other way to manage the vault from a desktop. Without the
//! admin API the daemon waits, logs why, and serves nothing.
//!
//! **The setup code.** At each start the daemon makes a random 32-byte token and a one-time setup code:
//! `cerberus-setup:1:<base64url(json {url, token, pin})>`, where `pin` is `sha256/<base64>` of the SPKI of the setup
//! certificate. The code is written to `<data_dir>/setup-code` (mode `0600`, replaced at each start) and printed by
//! `cerberusd setup-code`. The log has the file path and the pin, never the token. The client pins the key of the
//! setup certificate, so the passphrase goes only to the server that holds the code.
//!
//! **`POST /v1/setup`** takes `{setup_token, owner_label, passphrase, device_label?, url?}`. The token is compared in
//! constant time. After [`FREE_ATTEMPTS`] wrong tokens from one address that address has to wait, 2 s, 4 s, 8 s ... up
//! to 5 minutes, before its next try (`429 too_many_failures` with `retry_after_seconds`); other addresses are not
//! affected, and nothing needs a restart. One setup runs at a time (the second call gets `409`), and once one succeeds no
//! other is accepted. The setup runs in a task of its own, so a connection that ends does not stop it half way; the vault
//! is built under a temporary name and gets `vault.cerberus` only when the client is enrolled and the answer is ready. The passphrase policy is
//! checked here, and the key-derivation cost is measured on this machine (ADR-0013): the client does not choose it.
//! The vault is made as the desktop makes it, the client is enrolled as an admin client like `cerberusd admin
//! enroll`, and the answer holds, one time, the recovery key and the admin bundle. Anything that fails before the answer
//! is ready removes every file of the attempt; the cases it cannot cover are in the daemon guide (a kill between the new
//! name of the vault and the answer, a connection that breaks while the answer is on the wire).
//!
//! Then the listener stops and the daemon goes on as it does for any vault, with no restart (the vault stays unlocked,
//! as `create_vault` leaves it).

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use cerberus_admin::bundle::{AdminBundle, check_url};
use cerberus_admin::clients::{EnrolmentId, check_label};
use cerberus_api::AdminState;
use cerberus_api::tls::{BootstrapTls, TlsPaths, bootstrap_tls, leaf_names};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreError, CreatedVault, NewVault, OperatorContext, VaultService};
use cerberus_crypto::{
    KdfParams, SecretString, ct_eq, meets_phrase_policy, normalize_phrase, total_ram_bytes,
    tune_kdf,
};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::wire::{ErrorBody, ErrorDetails, ErrorResponse, FieldProblem, WireSecret};
use cerberus_types::{
    Clock, ErrorCode, LockReason, OperatorId, OperatorRole, RequestId, Stopwatch, SystemClock,
};
use data_encoding::BASE64URL_NOPAD;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, Semaphore, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::daemon::{DaemonError, ServeOptions, VAULT_FILE, core_config};
use crate::status::probe_addr;
use crate::unlock::enrol_client;

/// The setup code file in the data directory.
pub const SETUP_CODE_FILE: &str = "setup-code";
/// What a setup code starts with: the format name and its version.
pub const SETUP_CODE_PREFIX: &str = "cerberus-setup:1:";
/// Wrong tokens that one address may send before it has to wait.
pub const FREE_ATTEMPTS: u32 = 5;
/// The longest wait of an address after wrong tokens.
const MAX_DELAY: Duration = Duration::from_secs(300);
/// Peer addresses whose wrong tokens are remembered.
const MAX_PEERS: usize = 1024;
/// Connections of one address at the same time.
const MAX_PER_PEER: usize = 4;
/// Time limit of the request body, from the end of the head.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest wait for the answer of a successful setup to leave before the daemon goes on or stops.
const DELIVERY_WAIT: Duration = Duration::from_secs(15);
/// The part of the temporary vault name after `vault.cerberus`.
const TEMP_INFIX: &str = ".setup-";
/// The device label when the request has none.
pub const DEFAULT_DEVICE_LABEL: &str = "desktop";
/// Longest request body. A passphrase and a few labels are far below it.
const MAX_BODY: usize = 16 * 1024;
/// Connections served at the same time. More are closed at once.
const MAX_CONNECTIONS: usize = 16;
/// Time limit of the TLS handshake and of the request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Time limit of a connection that has not started a setup (a health check, a wrong token, a slow client): the TLS
/// handshake, the head and the body fit in it with room to spare.
const SHORT_CONNECTION: Duration = Duration::from_secs(40);
/// Time limit of a connection that runs a setup. The setup runs the cost test and the key derivation, which take seconds
/// (the setup itself does not depend on it: it runs in a task of its own).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);
/// Target time of one key derivation at unlock (ADR-0013, DEC-049). The desktop uses the same value.
const KDF_TARGET: Duration = Duration::from_millis(700);
/// Longest owner label (the rule of `key_slots.label`).
const MAX_LABEL_CHARS: usize = 64;
/// The SQLite side files of the vault.
const SIDE_FILES: [&str; 2] = ["-wal", "-shm"];
/// Why the daemon answers every other route.
const NO_VAULT_MESSAGE: &str = "no vault yet: this server waits for its first client to create it (POST /v1/setup with the setup code from `cerberusd setup-code`)";

/// The path of the setup code file for a data directory.
#[must_use]
pub fn setup_code_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SETUP_CODE_FILE)
}

/// What a setup code holds. It has no `Debug` on purpose: it holds the token.
#[derive(Serialize)]
struct CodeBody<'a> {
    url: &'a str,
    token: &'a str,
    pin: &'a str,
}

/// The setup code text for a URL, a token and the pin of the setup certificate.
fn encode_code(url: &str, token: &str, pin: &str) -> Result<Zeroizing<String>, serde_json::Error> {
    let json = Zeroizing::new(serde_json::to_vec(&CodeBody { url, token, pin })?);
    let mut code = Zeroizing::new(String::with_capacity(
        SETUP_CODE_PREFIX.len() + 4 * json.len() / 3 + 4,
    ));
    code.push_str(SETUP_CODE_PREFIX);
    BASE64URL_NOPAD.encode_append(&json, &mut code);
    Ok(code)
}

/// Why `cerberusd setup-code` cannot show a code.
#[derive(Debug, thiserror::Error)]
pub enum SetupCodeError {
    /// A vault file is in the data directory: there is nothing to set up.
    #[error(
        "{path} exists: this server has a vault already, so no setup is pending",
        path = .path.display()
    )]
    VaultExists {
        /// The vault file.
        path: PathBuf,
    },
    /// No code file: the daemon did not start with an empty data directory, or the admin API is off.
    #[error(
        "no setup is pending ({path} does not exist). Start `cerberusd serve` with the admin API on (the default; no `enabled = false`) and an empty data directory; the daemon writes the code at start",
        path = .path.display()
    )]
    NotPending {
        /// The code file.
        path: PathBuf,
    },
    /// The code file is there but nothing listens: the daemon ended without removing it.
    #[error(
        "{path} is stale: no cerberusd waits for setup at {addr}. Start the daemon; it makes a new code",
        path = .path.display()
    )]
    NotListening {
        /// The code file.
        path: PathBuf,
        /// The address probed.
        addr: SocketAddr,
    },
    /// The code file cannot be read.
    #[error("cannot read {path}: {source}", path = .path.display())]
    Read {
        /// The code file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
}

/// The setup code of a waiting daemon, for `cerberusd setup-code`. The file must exist, no vault may exist, and the
/// daemon must listen (a file left by a killed daemon is stale).
///
/// # Errors
/// [`SetupCodeError`].
pub fn read_setup_code(config: &Config) -> Result<Zeroizing<String>, SetupCodeError> {
    let vault = config.data_dir.join(VAULT_FILE);
    if std::fs::symlink_metadata(&vault).is_ok() {
        return Err(SetupCodeError::VaultExists { path: vault });
    }
    let path = setup_code_path(&config.data_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => Zeroizing::new(text),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SetupCodeError::NotPending { path });
        }
        Err(source) => return Err(SetupCodeError::Read { path, source }),
    };
    if !is_listening(config) {
        return Err(SetupCodeError::NotListening {
            path,
            addr: probe_addr(config),
        });
    }
    Ok(Zeroizing::new(text.trim().to_owned()))
}

/// How the wait for the first client ended.
pub(crate) enum Waited {
    /// A client made the vault. It is open and unlocked, and its answer has left (or the wait for it ran out).
    Created(VaultService),
    /// The daemon was told to stop first.
    Stopped,
}

/// Where a setup stands. It lives in a lock that a running setup holds, so the phase cannot change under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No vault yet; a setup may start.
    Waiting,
    /// A setup worked: no other one is accepted.
    Done,
    /// The daemon is stopping: no setup is accepted any more.
    Closing,
}

/// The wrong tokens of one peer address.
#[derive(Default)]
struct PeerState {
    failed: u32,
    /// The time of the last wrong token (the oldest entry goes first when the table is full).
    last: Duration,
    /// The end of the wait, as time since the listener started (`Shared::clock`).
    blocked_until: Option<Duration>,
}

/// What every connection shares.
struct Shared {
    config: Config,
    admin: Arc<AdminState>,
    /// The one-time token. Zeroized when the listener ends.
    token: Zeroizing<String>,
    /// The URL that is in the setup code, and the default URL of the bundle.
    url: String,
    /// A fixed key-derivation cost, in place of the cost test. Tests set it; the daemon never does.
    kdf: Option<KdfParams>,
    /// A pause in the middle of the setup. Tests set it; the daemon never does.
    pause: Option<Duration>,
    /// Time since the listener started: the clock of the waits.
    clock: Stopwatch,
    /// When the last wrong token was logged, as time since the start (the log is limited to one line a second).
    last_warn: AtomicU64,
    /// Wrong tokens by peer (see [`peer_key`]), bounded by [`MAX_PEERS`]: the oldest entry goes first.
    peers: std::sync::Mutex<HashMap<IpAddr, PeerState>>,
    /// Open connections by peer (see [`peer_key`]).
    conns: std::sync::Mutex<HashMap<IpAddr, usize>>,
    /// The phase. A setup holds the lock from its start to its end, also when the connection that asked for it is gone.
    state: Arc<Mutex<Phase>>,
    done: std::sync::Mutex<Option<oneshot::Sender<VaultService>>>,
    /// Signalled when the connection that carried the answer of a successful setup has ended.
    delivered: Notify,
    connections: Arc<Semaphore>,
}

/// The key of a peer for the limits: an IPv4 address as it is, an IPv4-mapped IPv6 address as IPv4, any other IPv6
/// address as its /64 network (one customer of a provider has a whole /64, so per-address limits would mean nothing).
fn peer_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(octets.into())
            },
            IpAddr::V4,
        ),
    }
}

/// True when something accepts connections at the address that `cerberusd status` probes.
#[must_use]
pub fn is_listening(config: &Config) -> bool {
    std::net::TcpStream::connect_timeout(&probe_addr(config), Duration::from_secs(2)).is_ok()
}

/// Runs the setup listener until a client made the vault or `stop` completes.
///
/// `ready` gets the addresses once the listener is up (empty when the admin API is off and there is no listener).
///
/// # Errors
/// [`DaemonError`] when the certificate, the code file or the sockets cannot be made.
pub(crate) async fn wait_for_setup<S>(
    config: &Config,
    admin: Option<Arc<AdminState>>,
    options: &ServeOptions,
    mut stop: Pin<&mut S>,
    ready: impl FnOnce(Vec<SocketAddr>),
) -> Result<Waited, DaemonError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let code_path = setup_code_path(&config.data_dir);
    // A code of an earlier start is not valid any more, and no vault means the leftovers of a killed setup are garbage.
    remove_file(&code_path);
    clean_strays(&config.data_dir);
    let Some(admin) = admin else {
        tracing::warn!(
            data_dir = %config.data_dir.display(),
            "no vault yet, and [admin] enabled = false: the first client cannot create the vault. Remove that line (the default is true) \
             and restart, or copy a desktop backup here as {VAULT_FILE} (mode 0600) and restart"
        );
        ready(Vec::new());
        stop.await;
        return Ok(Waited::Stopped);
    };
    let now = SystemClock.now();
    let tls = bootstrap_tls(&leaf_names(&config.host_names), now)?;
    let token = new_token()?;
    let url = setup_url(config);
    let code = encode_code(&url, &token, &tls.pin)
        .map_err(|error| DaemonError::Io(io::Error::other(error)))?;
    // The sockets first: a bind that fails leaves no code file behind.
    let listeners = bind_all(config).await?;
    write_code_file(&code_path, &code)?;
    drop(code);
    let addrs = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<Vec<_>, _>>()?;
    let (done_tx, mut done_rx) = oneshot::channel();
    let shared = Arc::new(Shared {
        config: config.clone(),
        admin,
        token,
        url,
        kdf: options.setup_kdf,
        pause: options.setup_pause,
        clock: Stopwatch::start(),
        last_warn: AtomicU64::new(0),
        peers: std::sync::Mutex::new(HashMap::new()),
        conns: std::sync::Mutex::new(HashMap::new()),
        state: Arc::new(Mutex::new(Phase::Waiting)),
        done: std::sync::Mutex::new(Some(done_tx)),
        delivered: Notify::new(),
        connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
    });
    let accept = start_accepting(listeners, &tls, &shared);
    tracing::warn!(
        ?addrs,
        code_file = %code_path.display(),
        pin = %tls.pin,
        "no vault yet: waiting for the first client to create it. Show the setup code with `cerberusd setup-code`"
    );
    ready(addrs);

    tokio::select! {
        () = &mut stop => {
            close_listeners(accept).await;
            // A setup that is running finishes first (it holds the lock): it either makes the vault whole or removes
            // what it made. From here on a connection that is still open cannot start a setup.
            let mut phase = shared.state.lock().await;
            let created = *phase == Phase::Done;
            if *phase == Phase::Waiting {
                *phase = Phase::Closing;
            }
            drop(phase);
            remove_file(&code_path);
            if created {
                // The answer with the recovery key must leave before the process goes on.
                wait_delivered(&shared).await;
                if let Ok(core) = done_rx.try_recv() {
                    if let Err(error) = core.lock(LockReason::Quit).await {
                        tracing::error!(%error, "lock on stop failed");
                    }
                    core.close_store().await;
                }
            }
            Ok(Waited::Stopped)
        }
        created = &mut done_rx => {
            close_listeners(accept).await;
            remove_file(&code_path);
            match created {
                Ok(core) => {
                    // An error later in the start must not take the answer with the recovery key down with it.
                    wait_delivered(&shared).await;
                    Ok(Waited::Created(core))
                }
                // The sender lives in `shared` until a setup succeeds, so this cannot happen.
                Err(_) => Err(DaemonError::Io(io::Error::other(
                    "the setup listener ended without a vault",
                ))),
            }
        }
    }
}

/// Waits until the connection that carries the answer of the setup has ended (the answer is written and flushed, or the
/// connection broke), but not longer than [`DELIVERY_WAIT`].
async fn wait_delivered(shared: &Shared) {
    if tokio::time::timeout(DELIVERY_WAIT, shared.delivered.notified())
        .await
        .is_err()
    {
        tracing::warn!("the answer of the setup was not confirmed as sent in time; going on");
    }
}

/// Stops the accept loops and waits until their sockets are closed, so the port is free for the HTTPS listener. A
/// connection that is open keeps running to the end of its answer.
async fn close_listeners(accept: Vec<JoinHandle<()>>) {
    for handle in &accept {
        handle.abort();
    }
    for handle in accept {
        drop(handle.await);
    }
}

fn remove_file(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "could not remove a setup file");
        }
    }
}

/// With no vault in the data directory, removes what a setup that was killed left: the temporary vault files, named
/// `vault.cerberus.setup-<id>` (with `-wal` and `-shm`), which are never the vault, and the TLS leaf and CA files that
/// `create_vault` wrote (known names only; the TLS folder goes when it is empty). They belong to a CA that has no vault,
/// so a desktop backup that is copied in later must not meet a leaf of that dead CA.
fn clean_strays(data_dir: &Path) {
    for file in tls_files(data_dir) {
        remove_file(&file);
    }
    // Only an empty folder goes.
    let _ = std::fs::remove_dir(data_dir.join("tls"));
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };
    let prefix = format!("{VAULT_FILE}{TEMP_INFIX}");
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            tracing::warn!(path = %entry.path().display(), "removing the temporary vault of a setup that did not finish");
            remove_file(&entry.path());
        }
    }
}

/// A random 32-byte token as base64url text.
fn new_token() -> Result<Zeroizing<String>, DaemonError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut bytes[..])
        .map_err(|error| DaemonError::Io(io::Error::other(error.to_string())))?;
    Ok(Zeroizing::new(BASE64URL_NOPAD.encode(&bytes[..])))
}

/// The URL in the setup code: the first of `host_names` (the TLS names the operator chose), else `localhost`.
fn setup_url(config: &Config) -> String {
    let host = config
        .host_names
        .first()
        .map_or("localhost", String::as_str);
    format!("https://{host}:{}", config.port)
}

/// Writes the code to a new file of mode `0600` and renames it over the old one.
fn write_code_file(path: &Path, code: &str) -> Result<(), DaemonError> {
    let tmp = path.with_extension("tmp");
    remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(code.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Binds every configured address. An address that the host does not have (`::1` without IPv6) is skipped while
/// another is bound.
async fn bind_all(config: &Config) -> Result<Vec<TcpListener>, DaemonError> {
    let mut listeners = Vec::new();
    for addr in config.listen_addrs() {
        match TcpListener::bind(addr).await {
            Ok(listener) => listeners.push(listener),
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                tracing::warn!(%addr, "address not available; skipped");
            }
            Err(error) => return Err(error.into()),
        }
    }
    if listeners.is_empty() {
        return Err(DaemonError::Io(io::Error::from(
            io::ErrorKind::AddrNotAvailable,
        )));
    }
    Ok(listeners)
}

fn start_accepting(
    listeners: Vec<TcpListener>,
    tls: &BootstrapTls,
    shared: &Arc<Shared>,
) -> Vec<JoinHandle<()>> {
    let acceptor = TlsAcceptor::from(Arc::clone(&tls.config));
    listeners
        .into_iter()
        .map(|listener| tokio::spawn(accept_loop(listener, acceptor.clone(), Arc::clone(shared))))
        .collect()
}

/// One open connection of a peer address. The slot is given back when it is dropped.
struct PeerSlot {
    shared: Arc<Shared>,
    ip: IpAddr,
}

impl PeerSlot {
    /// Takes a slot, or `None` when the peer has [`MAX_PER_PEER`] connections open already.
    fn take(shared: &Arc<Shared>, ip: IpAddr) -> Option<Self> {
        let mut conns = shared
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let open = conns.entry(ip).or_insert(0);
        if *open >= MAX_PER_PEER {
            return None;
        }
        *open += 1;
        Some(Self {
            shared: Arc::clone(shared),
            ip,
        })
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut conns = self
            .shared
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(open) = conns.get_mut(&self.ip) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                conns.remove(&self.ip);
            }
        }
    }
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "setup accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ip = peer_key(peer.ip());
        let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
            tracing::debug!(%peer, "setup listener full; connection closed");
            continue;
        };
        let Some(slot) = PeerSlot::take(&shared, ip) else {
            tracing::debug!(%peer, "too many connections of this address; connection closed");
            continue;
        };
        let acceptor = acceptor.clone();
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let conn = Arc::new(Conn::default());
            tokio::select! {
                () = serve_connection(stream, ip, acceptor, &shared, &conn) => {}
                () = connection_limit(&conn) => tracing::debug!(%peer, "setup connection timed out"),
            }
            drop(slot);
            drop(permit);
        });
    }
}

/// What one connection knows about itself.
#[derive(Default)]
struct Conn {
    /// The connection carries the answer of a successful setup.
    carries_answer: AtomicBool,
    /// The connection runs a setup, which may take longer than [`SHORT_CONNECTION`].
    long: AtomicBool,
}

/// Returns when the connection has used its time: [`SHORT_CONNECTION`], or [`CONNECTION_TIMEOUT`] when it runs a setup.
async fn connection_limit(conn: &Conn) {
    tokio::time::sleep(SHORT_CONNECTION).await;
    if conn.long.load(Ordering::SeqCst) {
        tokio::time::sleep(CONNECTION_TIMEOUT.saturating_sub(SHORT_CONNECTION)).await;
    }
}

/// Tells the stop and the start of the daemon that the connection of a successful answer has ended, whatever way it
/// ended (finished, broke, timed out, was dropped).
struct Delivery {
    shared: Arc<Shared>,
    conn: Arc<Conn>,
}

impl Drop for Delivery {
    fn drop(&mut self) {
        if self.conn.carries_answer.load(Ordering::SeqCst) {
            self.shared.delivered.notify_one();
        }
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: IpAddr,
    acceptor: TlsAcceptor,
    shared: &Arc<Shared>,
    conn: &Arc<Conn>,
) {
    let Ok(Ok(tls)) = tokio::time::timeout(HEAD_TIMEOUT, acceptor.accept(stream)).await else {
        return;
    };
    let _delivery = Delivery {
        shared: Arc::clone(shared),
        conn: Arc::clone(conn),
    };
    let service = service_fn({
        let shared = Arc::clone(shared);
        let conn = Arc::clone(conn);
        move |request| {
            let shared = Arc::clone(&shared);
            let conn = Arc::clone(&conn);
            async move { Ok::<_, Infallible>(route(&shared, peer, &conn, request).await) }
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    // One request per connection: an idle keep-alive connection would hold one of the few slots.
    builder
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD_TIMEOUT);
    if let Err(error) = builder.serve_connection(TokioIo::new(tls), service).await {
        tracing::debug!(%error, "setup connection ended with an error");
    }
}

/// What the owner of a connection sees when a request fails.
#[derive(Debug)]
struct Failure {
    code: ErrorCode,
    message: String,
    fields: Vec<FieldProblem>,
    retryable: bool,
    retry_after: Option<u32>,
}

impl Failure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            fields: Vec::new(),
            retryable: code.retryable(),
            retry_after: None,
        }
    }

    fn field(field: &str, problem: &str) -> Self {
        Self {
            fields: vec![FieldProblem {
                field: field.to_owned(),
                problem: problem.to_owned(),
            }],
            ..Self::new(ErrorCode::ValidationFailed, "Some fields are not valid.")
        }
    }

    fn internal(message: &str) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    /// The answer to a peer that must wait before its next token.
    fn wait(wait: Duration) -> Self {
        let seconds = u32::try_from(wait.as_secs().saturating_add(1)).unwrap_or(u32::MAX);
        Self {
            retryable: true,
            retry_after: Some(seconds),
            ..Self::new(
                ErrorCode::TooManyFailures,
                format!(
                    "too many wrong setup tokens from this address: wait {seconds} s before you try again"
                ),
            )
        }
    }

    fn into_response(self) -> Response<Full<Bytes>> {
        let details =
            (!self.fields.is_empty() || self.retry_after.is_some()).then(|| ErrorDetails {
                fields: (!self.fields.is_empty()).then_some(self.fields),
                retry_after_seconds: self.retry_after,
                ..ErrorDetails::default()
            });
        let body = ErrorResponse {
            error: ErrorBody {
                code: self.code.into(),
                message: self.message,
                request_id: RequestId::generate().0,
                retryable: self.retryable,
                details,
            },
        };
        let status = self.code.http_status();
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        let mut response = respond(status, Bytes::from(bytes));
        if let Some(seconds) = self.retry_after
            && let Ok(value) = hyper::header::HeaderValue::from_str(&seconds.to_string())
        {
            response
                .headers_mut()
                .insert(hyper::header::RETRY_AFTER, value);
        }
        response
    }
}

fn respond(status: u16, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

/// A buffer that is wiped when the body that owns it is dropped after the send.
struct Wiped(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

async fn route(
    shared: &Arc<Shared>,
    peer: IpAddr,
    conn: &Conn,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/v1/health") => health(shared, peer),
        (&Method::POST, "/v1/setup") => match setup(shared, peer, conn, request).await {
            Ok(body) => {
                // The answer closes its connection after it is written: the end of the connection is the proof
                // that it left, which the daemon waits for before it goes on.
                conn.carries_answer.store(true, Ordering::SeqCst);
                let mut response = respond(200, Bytes::from_owner(Wiped(body)));
                response.headers_mut().insert(
                    hyper::header::CONNECTION,
                    hyper::header::HeaderValue::from_static("close"),
                );
                response
            }
            Err(failure) => failure.into_response(),
        },
        _ => Failure::new(ErrorCode::Unavailable, NO_VAULT_MESSAGE).into_response(),
    }
}

/// `GET /v1/health` with no vault: the usual fields, `vault` is `no_vault` and `setup` is `pending`, or `locked_out`
/// while the address of the caller has to wait after wrong tokens (the wait is temporary and per address).
fn health(shared: &Shared, peer: IpAddr) -> Response<Full<Bytes>> {
    let setup = if blocked_for(shared, peer).is_some() {
        "locked_out"
    } else {
        "pending"
    };
    let body = serde_json::json!({
        "status": "ok",
        "vault": "no_vault",
        "setup": setup,
        "version": env!("CARGO_PKG_VERSION"),
    });
    respond(200, Bytes::from(body.to_string()))
}

/// How long `peer` still has to wait, when it has to.
fn blocked_for(shared: &Shared, peer: IpAddr) -> Option<Duration> {
    let peers = shared
        .peers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    peers
        .get(&peer)
        .and_then(|state| state.blocked_until)
        .and_then(|until| until.checked_sub(shared.clock.elapsed()))
}

/// The request of `POST /v1/setup`. It has no `Debug` on purpose: it holds the passphrase.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRequest {
    #[serde(deserialize_with = "zeroizing_string")]
    setup_token: Zeroizing<String>,
    owner_label: String,
    #[serde(deserialize_with = "zeroizing_string")]
    passphrase: Zeroizing<String>,
    #[serde(default)]
    device_label: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// A secret goes straight into a `Zeroizing` string, so every path that drops the request wipes it.
fn zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// The answer of a successful setup. The recovery key and the bundle key are secrets.
#[derive(Serialize)]
struct SetupResponse {
    recovery_key: WireSecret,
    ca_pin: String,
    owner_id: String,
    bundle: AdminBundle,
}

/// Reads the body into a buffer of fixed size, so the passphrase is never copied to a bigger one.
async fn read_body(mut body: Incoming) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_BODY));
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|_| Failure::new(ErrorCode::InvalidRequest, "the body cannot be read"))?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > MAX_BODY {
                return Err(Failure::new(
                    ErrorCode::PayloadTooLarge,
                    "the request body is too large",
                ));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// `POST /v1/setup`. The body is read within [`BODY_TIMEOUT`], the token is checked, and then the setup runs in a task of
/// its own that holds the phase lock: a connection that ends, or a timeout, cannot stop it half way. This function only
/// waits for the result.
async fn setup(
    shared: &Arc<Shared>,
    peer: IpAddr,
    conn: &Conn,
    request: Request<Incoming>,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let body = tokio::time::timeout(BODY_TIMEOUT, read_body(request.into_body()))
        .await
        .map_err(|_| {
            Failure::new(
                ErrorCode::InvalidRequest,
                "the request body did not arrive in time",
            )
        })??;
    let asked: SetupRequest = serde_json::from_slice(&body).map_err(|_| {
        Failure::new(
            ErrorCode::InvalidRequest,
            "send a JSON object with setup_token, owner_label and passphrase",
        )
    })?;
    drop(body);
    check_token(shared, peer, &asked.setup_token)?;

    // One setup at a time. A running one holds the lock to its end, and the stop of the daemon takes it too.
    let guard = Arc::clone(&shared.state).try_lock_owned().map_err(|_| {
        Failure::new(
            ErrorCode::Conflict,
            "a setup is already running on this server",
        )
    })?;
    match *guard {
        Phase::Waiting => {}
        Phase::Done => {
            return Err(Failure::new(
                ErrorCode::Conflict,
                "this server has its vault already",
            ));
        }
        Phase::Closing => {
            return Err(Failure::new(
                ErrorCode::Unavailable,
                "this server is stopping; try again after it started",
            ));
        }
    }
    // The connection waits for the setup, which takes longer than a short connection lives.
    conn.long.store(true, Ordering::SeqCst);
    let (reply, answer) = oneshot::channel();
    tokio::spawn(run_setup(Arc::clone(shared), asked, guard, reply));
    answer.await.map_err(|_| {
        Failure::internal("the setup ended without an answer; check the log of the server")
    })?
}

/// The detached part of a setup: it makes the vault, enrols the client, hands the answer to the connection and, when the
/// answer is taken, hands the open vault to the daemon. If the connection is gone before the answer is taken, nobody can
/// receive the recovery key, so the vault is removed again and the setup can be repeated.
async fn run_setup(
    shared: Arc<Shared>,
    asked: SetupRequest,
    mut guard: OwnedMutexGuard<Phase>,
    reply: oneshot::Sender<Result<Zeroizing<Vec<u8>>, Failure>>,
) {
    if reply.is_closed() {
        return;
    }
    let mut built = match create(&shared, asked, &reply).await {
        Ok(built) => built,
        Err(failure) => {
            drop(reply.send(Err(failure)));
            return;
        }
    };
    let body = std::mem::take(&mut built.body);
    if reply.send(Ok(body)).is_err() {
        tracing::error!(
            "the client went away before it got the answer; the new vault is removed so the setup can be repeated"
        );
        discard(&shared, &built.core, Some(built.enrolment), built.made).await;
        return;
    }
    built.made.disarm();
    *guard = Phase::Done;
    remove_file(&setup_code_path(&shared.config.data_dir));
    tracing::warn!("vault created by the first client; the setup listener is closing");
    // The answer has left for the connection. Only now the vault is unlocked (one key derivation), so a crash in
    // between cannot leave an unlocked vault, and the time between the new name and the answer stays short.
    if let Err(error) = built
        .core
        .unlock_with_phrase(built.owner, built.phrase)
        .await
    {
        tracing::error!(%error, "the new vault could not be unlocked; it stays sealed: run `cerberusd unlock`");
    }
    let sender = shared
        .done
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(sender) = sender {
        drop(sender.send(built.core));
    }
}

/// The delay after `failed` wrong tokens of one address: none for the first [`FREE_ATTEMPTS`], then 2, 4, 8 ... seconds
/// up to [`MAX_DELAY`].
fn delay_for(failed: u32) -> Duration {
    let over = failed.saturating_sub(FREE_ATTEMPTS);
    if over == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs(1u64 << over.min(16)).min(MAX_DELAY)
}

/// Compares the token in constant time. A wrong token makes its address wait longer each time (after the free ones),
/// and while an address waits it is refused before the token is looked at. Other addresses are not affected, so a
/// flood from one address cannot lock the owner out.
fn check_token(shared: &Shared, peer: IpAddr, given: &str) -> Result<(), Failure> {
    let now = shared.clock.elapsed();
    let mut peers = shared
        .peers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(wait) = peers
        .get(&peer)
        .and_then(|state| state.blocked_until)
        .and_then(|until| until.checked_sub(now))
    {
        return Err(Failure::wait(wait));
    }
    if ct_eq(given.as_bytes(), shared.token.as_bytes()) {
        peers.remove(&peer);
        return Ok(());
    }
    if !peers.contains_key(&peer) && peers.len() >= MAX_PEERS {
        // Every address is tracked: the one that sent a wrong token longest ago makes room.
        let oldest = peers
            .iter()
            .min_by_key(|(_, state)| state.last)
            .map(|(key, _)| *key);
        if let Some(oldest) = oldest {
            peers.remove(&oldest);
        }
    }
    let state = peers.entry(peer).or_default();
    state.failed = state.failed.saturating_add(1);
    state.last = now;
    let delay = delay_for(state.failed);
    if !delay.is_zero() {
        state.blocked_until = Some(now + delay);
    }
    let failed = state.failed;
    drop(peers);
    // One log line a second at most, so a flood does not fill the log.
    let at = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
    if at
        >= shared
            .last_warn
            .load(Ordering::Relaxed)
            .saturating_add(1000)
        || shared.last_warn.load(Ordering::Relaxed) == 0
    {
        shared.last_warn.store(at.max(1), Ordering::Relaxed);
        tracing::warn!(%peer, failed, wait_seconds = delay.as_secs(), "setup refused: wrong token");
    }
    Err(Failure::new(
        ErrorCode::Unauthenticated,
        "the setup token is not valid",
    ))
}

/// A setup that made its vault and enrolled the client.
struct Built {
    /// The new vault, open and **sealed**: the unlock (one more key derivation) runs after the answer has left.
    core: VaultService,
    body: Zeroizing<Vec<u8>>,
    made: Made,
    enrolment: EnrolmentId,
    owner: OperatorId,
    phrase: SecretString,
}

/// The checks that need no file, then the vault, then the enrolment of the client, then the move of the vault into
/// place. It gives the open vault and the body of the answer. Everything it made is removed again when it fails, and
/// when it is dropped half way (`Made` removes its files when it is dropped armed).
async fn create(
    shared: &Shared,
    asked: SetupRequest,
    gone: &oneshot::Sender<Result<Zeroizing<Vec<u8>>, Failure>>,
) -> Result<Built, Failure> {
    let config = &shared.config;
    let SetupRequest {
        owner_label,
        passphrase,
        device_label,
        url,
        ..
    } = asked;
    let phrase = SecretString::new(passphrase.as_str().to_owned());
    drop(passphrase);
    check_policy(&owner_label, &phrase)?;
    let device = device_label.unwrap_or_else(|| DEFAULT_DEVICE_LABEL.to_owned());
    if check_label(&device).is_err() {
        return Err(Failure::field(
            "device_label",
            "must be 1 to 64 characters without control characters",
        ));
    }
    let url = bundle_url(shared, url)?;
    let vault_path = config.data_dir.join(VAULT_FILE);
    check_no_vault(&vault_path)?;
    let kdf = match shared.kdf {
        Some(kdf) => kdf,
        None => measure_kdf().await?,
    };
    // The cost test takes seconds: a client that left meanwhile gets no vault.
    if gone.is_closed() {
        return Err(Failure::internal(
            "the client left before the vault was made",
        ));
    }

    let mut made = Made::new(&config.data_dir, &vault_path)?;
    let (core, created) = make_vault(config, &mut made, &owner_label, &phrase, kdf).await?;
    if let Some(pause) = shared.pause {
        tokio::time::sleep(pause).await;
    }
    let ctx = OperatorContext {
        operator_id: created.owner_id,
        role: OperatorRole::Owner,
        request_id: RequestId::generate(),
    };
    let bundle = match enrol_client(&core, &shared.admin, &ctx, device, url, created.owner_id).await
    {
        Ok(bundle) => bundle,
        Err(reply) => {
            tracing::error!(
                error = reply.error.as_deref().unwrap_or("unknown"),
                "setup: the client could not be enrolled; the vault is removed"
            );
            discard(shared, &core, None, made).await;
            return Err(Failure::internal(
                "the client could not be enrolled, so nothing was created; try again",
            ));
        }
    };
    let enrolment = bundle.id;
    let response = SetupResponse {
        recovery_key: WireSecret::new(created.recovery_key.expose_secret().to_owned()),
        ca_pin: created.ca_pin,
        owner_id: created.owner_id.to_string(),
        bundle,
    };
    let body = match cerberus_admin::rpc::to_body(&response) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(%error, "setup answer not written; the vault is removed");
            discard(shared, &core, Some(enrolment), made).await;
            return Err(Failure::internal(
                "the answer could not be written, so nothing was created; try again",
            ));
        }
    };
    drop(response);
    match move_into_place(config, &core, &mut made).await {
        Ok(open) => Ok(Built {
            core: open,
            body,
            made,
            enrolment,
            owner: created.owner_id,
            phrase,
        }),
        Err(failure) => {
            discard(shared, &core, Some(enrolment), made).await;
            Err(failure)
        }
    }
}

/// Removes a vault that was made but could not be handed over: revoke its enrolment, lock, close the store, remove the
/// files (the drop of `made` does it).
async fn discard(shared: &Shared, core: &VaultService, enrolment: Option<EnrolmentId>, made: Made) {
    if let Some(id) = enrolment
        && let Err(error) = shared.admin.revoke(core, id).await
    {
        tracing::warn!(%error, "the enrolment of the removed vault could not be revoked in the registry");
    }
    // A lock that fails changes nothing: the files are removed next.
    drop(core.lock(LockReason::Quit).await);
    core.close_store().await;
    drop(made);
}

/// The URL of the bundle: the one the client used, else the one of the code. It must be a valid bundle URL, and its
/// host must be one of the names of the TLS leaf, or the desktop could not connect with it.
fn bundle_url(shared: &Shared, requested: Option<String>) -> Result<String, Failure> {
    let url = requested.unwrap_or_else(|| shared.url.clone());
    if check_url(&url).is_err() {
        return Err(Failure::field(
            "url",
            "must be https://host:port with no user, path, query or fragment",
        ));
    }
    let parsed = url::Url::parse(&url).map_err(|_| Failure::field("url", "is not a URL"))?;
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let names = leaf_names(&shared.config.host_names);
    if !names.iter().any(|name| name.eq_ignore_ascii_case(&host)) {
        return Err(Failure::field(
            "url",
            &format!(
                "the host {host:?} is not a TLS name of this server; add it to host_names in cerberusd.toml and restart"
            ),
        ));
    }
    Ok(url)
}

/// The rules of `create_vault` that can be checked without a file, so a refusal leaves nothing behind. The core
/// checks them again.
fn check_policy(label: &str, phrase: &SecretString) -> Result<(), Failure> {
    let chars = label.chars().count();
    if chars == 0 || chars > MAX_LABEL_CHARS || label.trim().is_empty() {
        return Err(Failure::field("owner_label", "must be 1..64 characters"));
    }
    if !meets_phrase_policy(&normalize_phrase(phrase.expose_secret()), &[label]) {
        return Err(Failure::field(
            "passphrase",
            "needs 12 characters or more and a strength score of 3 or more",
        ));
    }
    Ok(())
}

/// The cost test of this machine, run before any file exists (ADR-0013).
async fn measure_kdf() -> Result<KdfParams, Failure> {
    tracing::info!("measuring the key-derivation cost, this takes a few seconds");
    let ram = total_ram_bytes().unwrap_or(u64::MAX);
    let tuning = tokio::task::spawn_blocking(move || tune_kdf(KDF_TARGET, ram))
        .await
        .map_err(|error| {
            tracing::error!(%error, "cost test task failed");
            Failure::internal("the key-derivation cost could not be measured")
        })?
        .map_err(|error| {
            tracing::error!(%error, "cost test failed");
            Failure::internal("the key-derivation cost could not be measured")
        })?;
    Ok(tuning.params)
}

/// Refuses when the vault file or a side file of it exists, also as a dangling link. Temporary files of a setup are
/// not the vault and do not count. Side files without a vault file are leftovers: the message says to remove them (a
/// restart would not help).
fn check_no_vault(vault_path: &Path) -> Result<(), Failure> {
    if std::fs::symlink_metadata(vault_path).is_ok() {
        return Err(Failure::new(
            ErrorCode::Conflict,
            "a vault file is in the data directory of this server; restart cerberusd to serve it",
        ));
    }
    for suffix in SIDE_FILES {
        if std::fs::symlink_metadata(with_suffix(vault_path, suffix)).is_ok() {
            return Err(Failure::new(
                ErrorCode::Conflict,
                format!(
                    "the data directory of this server has a {VAULT_FILE}{suffix} file but no {VAULT_FILE}: check it, remove the {VAULT_FILE}-wal and {VAULT_FILE}-shm files, and try again"
                ),
            ));
        }
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// What one setup made, so a failure removes exactly that and nothing else, also when the future of the setup is dropped
/// (it removes its files in `Drop` unless it was disarmed). The data directory is not in the list: the daemon made it
/// at start, or the service manager did.
///
/// The vault is built under a temporary name (`vault.cerberus.setup-<id>`) and gets its real name only when everything
/// worked, so a crash never leaves a half vault named `vault.cerberus`.
struct Made {
    data_dir: PathBuf,
    /// The temporary vault file.
    temp: PathBuf,
    /// The final vault file.
    vault: PathBuf,
    tls_dir_existed: bool,
    /// The TLS files that existed before the run: they are not removed.
    tls_kept: Vec<PathBuf>,
    temp_made: bool,
    vault_made: bool,
    armed: bool,
}

impl Made {
    fn new(data_dir: &Path, vault: &Path) -> Result<Self, Failure> {
        let mut id = [0u8; 6];
        getrandom::fill(&mut id).map_err(|error| {
            tracing::error!(%error, "no random bytes for the temporary vault name");
            Failure::internal("the temporary vault file cannot be named")
        })?;
        let id: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            temp: with_suffix(vault, &format!("{TEMP_INFIX}{id}")),
            vault: vault.to_path_buf(),
            tls_dir_existed: data_dir.join("tls").exists(),
            tls_kept: tls_files(data_dir)
                .into_iter()
                .filter(|file| file.exists())
                .collect(),
            temp_made: false,
            vault_made: false,
            armed: true,
        })
    }

    /// The setup worked: keep everything.
    fn disarm(&mut self) {
        self.armed = false;
    }

    /// Removes the files of this run. The TLS files go unless they existed before the run, and the TLS folder only when
    /// it did not exist.
    fn remove(&self) {
        for (made, path) in [(self.temp_made, &self.temp), (self.vault_made, &self.vault)] {
            if made {
                for suffix in std::iter::once("").chain(SIDE_FILES) {
                    let _ = std::fs::remove_file(with_suffix(path, suffix));
                }
            }
        }
        for file in tls_files(&self.data_dir) {
            if !self.tls_kept.contains(&file) {
                let _ = std::fs::remove_file(file);
            }
        }
        if !self.tls_dir_existed {
            let _ = std::fs::remove_dir(self.data_dir.join("tls"));
        }
    }
}

impl Drop for Made {
    fn drop(&mut self) {
        if self.armed {
            self.remove();
        }
    }
}

/// The files that `issue_ca` writes in the TLS folder, and the temporary names of those writes.
fn tls_files(data_dir: &Path) -> Vec<PathBuf> {
    let tls = TlsPaths::in_data_dir(data_dir);
    // A failed write leaves its temporary file (`write_private` of the TLS code names it `<name>.tmp`).
    [tls.leaf_cert_der, tls.leaf_key_der, tls.ca_cert_der]
        .into_iter()
        .flat_map(|file| {
            let tmp = file.with_extension("tmp");
            [file, tmp]
        })
        .collect()
}

/// A new file that must not exist, mode `0600` from the first byte.
fn create_new_private(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Reserves the temporary vault file, then makes the vault in it with the core API. The vault is left unlocked and
/// open. When the vault cannot be made the store is closed and the caller's `Made` removes the files.
async fn make_vault(
    config: &Config,
    made: &mut Made,
    owner_label: &str,
    phrase: &SecretString,
    kdf: KdfParams,
) -> Result<(VaultService, CreatedVault), Failure> {
    drop(create_new_private(&made.temp).map_err(|source| {
        tracing::error!(%source, path = %made.temp.display(), "cannot create the temporary vault file");
        Failure::internal("the vault file cannot be created")
    })?);
    made.temp_made = true;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tls = TlsPaths::in_data_dir(&config.data_dir);
    let store = Store::open(
        OpenOptions {
            path: made.temp.clone(),
            create: true,
        },
        Arc::clone(&clock),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "cannot open the new vault file");
        Failure::internal("the vault file cannot be opened")
    })?;
    let core = match VaultService::open(store.clone(), clock, core_config(config, &tls)).await {
        Ok(core) => core,
        Err(error) => {
            // A store that is not closed can still hold the file when it is removed.
            store.close().await;
            return Err(from_core(&error));
        }
    };
    let created = core
        .create_vault(NewVault {
            owner_label: owner_label.to_owned(),
            phrase: SecretString::new(phrase.expose_secret().to_owned()),
            kdf,
            host_names: config.host_names.clone(),
        })
        .await;
    match created {
        Ok(created) => Ok((core, created)),
        Err(error) => {
            core.close_store().await;
            Err(from_core(&error))
        }
    }
}

/// Closes the new vault, gives its file the real name (without replacing a vault file that appeared meanwhile) and
/// opens it again, **sealed** (no key derivation, so the way to the answer stays short). The first service is closed and
/// must not be used again.
async fn move_into_place(
    config: &Config,
    core: &VaultService,
    made: &mut Made,
) -> Result<VaultService, Failure> {
    // A lock that fails changes nothing: the store is closed next.
    drop(core.lock(LockReason::Quit).await);
    core.close_store().await;
    for suffix in SIDE_FILES {
        if std::fs::symlink_metadata(with_suffix(&made.temp, suffix)).is_ok() {
            tracing::error!("the new vault was not closed cleanly (a side file is left)");
            return Err(Failure::internal(
                "the new vault could not be closed cleanly, so nothing was created; try again",
            ));
        }
    }
    let temp_left = put_in_place(&made.temp, &made.vault).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            Failure::new(
                ErrorCode::Conflict,
                "a vault file is in the data directory of this server; restart cerberusd to serve it",
            )
        } else {
            tracing::error!(%source, "cannot give the new vault its name");
            Failure::internal(
                "the vault file cannot be put in place: the file system of the data directory must support hard links",
            )
        }
    })?;
    made.vault_made = true;
    made.temp_made = temp_left;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tls = TlsPaths::in_data_dir(&config.data_dir);
    let store = Store::open(
        OpenOptions {
            path: made.vault.clone(),
            create: false,
        },
        Arc::clone(&clock),
    )
    .await
    .map_err(|error| {
        tracing::error!(%error, "cannot open the new vault in its place");
        Failure::internal("the new vault cannot be opened")
    })?;
    match VaultService::open(store.clone(), clock, core_config(config, &tls)).await {
        Ok(open) => Ok(open),
        Err(error) => {
            store.close().await;
            Err(from_core(&error))
        }
    }
}

/// Gives `temp` the name `vault` without replacing a file that has that name. A hard link does it (and `temp` is removed
/// after it); on a file system without hard links, Linux `renameat2` with `RENAME_NOREPLACE` does. Gives true when `temp`
/// is still there.
///
/// # Errors
/// `AlreadyExists` when `vault` exists; another error when the file system supports neither.
fn put_in_place(temp: &Path, vault: &Path) -> io::Result<bool> {
    match std::fs::hard_link(temp, vault) {
        Ok(()) => match std::fs::remove_file(temp) {
            Ok(()) => Ok(false),
            Err(error) => {
                tracing::warn!(%error, "the temporary vault name could not be removed");
                Ok(true)
            }
        },
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        #[cfg(target_os = "linux")]
        Err(_) => {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                temp,
                rustix::fs::CWD,
                vault,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(io::Error::from)?;
            Ok(false)
        }
        #[cfg(not(target_os = "linux"))]
        Err(error) => Err(error),
    }
}

fn from_core(error: &CoreError) -> Failure {
    match error {
        CoreError::Validation(problems) => Failure {
            fields: problems
                .iter()
                .map(|p| FieldProblem {
                    field: p.field.clone(),
                    problem: p.problem.clone(),
                })
                .collect(),
            ..Failure::new(ErrorCode::ValidationFailed, "Some fields are not valid.")
        },
        other => {
            tracing::error!(error = %other, "cannot create the vault");
            Failure::internal("the vault could not be created")
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn a_code_has_the_prefix_and_decodes_to_url_token_and_pin() {
        let code = encode_code("https://localhost:7373", "tok-en", "sha256/AAAA").unwrap();
        let body = code.strip_prefix(SETUP_CODE_PREFIX).unwrap();
        let json = BASE64URL_NOPAD.decode(body.as_bytes()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["url"], "https://localhost:7373");
        assert_eq!(value["token"], "tok-en");
        assert_eq!(value["pin"], "sha256/AAAA");
    }

    #[test]
    fn a_token_is_43_base64url_characters_and_never_repeats() {
        let first = new_token().unwrap();
        let second = new_token().unwrap();
        assert_eq!(first.len(), 43);
        assert_ne!(*first, *second);
    }

    #[test]
    fn the_url_of_the_code_is_the_first_host_name_or_localhost() {
        let mut config = crate::config::load(None, &|key: &str| {
            (key == "CERBERUSD_DATA_DIR").then(|| "/var/lib/cerberus".to_owned())
        })
        .unwrap();
        assert_eq!(setup_url(&config), "https://localhost:7373");
        config.host_names = vec!["vault.example.test".to_owned()];
        assert_eq!(setup_url(&config), "https://vault.example.test:7373");
    }

    fn shared() -> Arc<Shared> {
        let config = crate::config::load(None, &|key: &str| {
            (key == "CERBERUSD_DATA_DIR").then(|| "/var/lib/cerberus".to_owned())
        })
        .unwrap();
        let admin = AdminState::new(
            cerberus_admin::clients::AdminClients::default(),
            cerberus_api::AdminLimits::default(),
        );
        Arc::new(Shared {
            config,
            admin: Arc::new(admin),
            token: Zeroizing::new("the-token".to_owned()),
            url: "https://localhost:7373".to_owned(),
            kdf: None,
            pause: None,
            clock: Stopwatch::start(),
            last_warn: AtomicU64::new(0),
            peers: std::sync::Mutex::new(HashMap::new()),
            conns: std::sync::Mutex::new(HashMap::new()),
            state: Arc::new(Mutex::new(Phase::Waiting)),
            done: std::sync::Mutex::new(None),
            delivered: Notify::new(),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    #[test]
    fn the_wait_after_wrong_tokens_grows_and_is_capped() {
        assert_eq!(delay_for(0), Duration::ZERO);
        assert_eq!(delay_for(FREE_ATTEMPTS), Duration::ZERO);
        assert_eq!(delay_for(FREE_ATTEMPTS + 1), Duration::from_secs(2));
        assert_eq!(delay_for(FREE_ATTEMPTS + 2), Duration::from_secs(4));
        assert_eq!(delay_for(FREE_ATTEMPTS + 3), Duration::from_secs(8));
        assert_eq!(delay_for(u32::MAX), MAX_DELAY);
    }

    /// LOW regression: one address that sends wrong tokens waits, and other addresses (the owner) are not affected.
    #[test]
    fn a_flood_from_one_address_does_not_block_another() {
        let shared = shared();
        let attacker: IpAddr = "192.0.2.1".parse().unwrap();
        let owner: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..=FREE_ATTEMPTS {
            let refused = check_token(&shared, attacker, "wrong").err().unwrap();
            assert_eq!(refused.code, ErrorCode::Unauthenticated);
        }
        let waiting = check_token(&shared, attacker, "the-token").err().unwrap();
        assert_eq!(waiting.code, ErrorCode::TooManyFailures);
        assert!(waiting.retry_after.is_some());
        assert!(blocked_for(&shared, attacker).is_some());
        assert!(check_token(&shared, owner, "the-token").is_ok());
        assert!(blocked_for(&shared, owner).is_none());
    }

    #[test]
    fn a_peer_has_a_few_connections_at_a_time_and_gets_a_slot_back_when_one_ends() {
        let shared = shared();
        let ip: IpAddr = "192.0.2.3".parse().unwrap();
        let slots: Vec<_> = (0..MAX_PER_PEER)
            .map(|_| PeerSlot::take(&shared, ip).unwrap())
            .collect();
        assert!(PeerSlot::take(&shared, ip).is_none());
        assert!(PeerSlot::take(&shared, "192.0.2.4".parse().unwrap()).is_some());
        drop(slots);
        assert!(PeerSlot::take(&shared, ip).is_some());
    }

    /// HIGH regression: the files of a setup that is dropped half way are removed (`Made` cleans up in `Drop`).
    #[test]
    fn a_made_that_is_dropped_armed_removes_its_files_and_a_disarmed_one_keeps_them() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join(VAULT_FILE);
        let mut made = Made::new(dir.path(), &vault).unwrap();
        std::fs::write(&made.temp, b"x").unwrap();
        made.temp_made = true;
        let temp = made.temp.clone();
        drop(made);
        assert!(!temp.exists());
        let mut made = Made::new(dir.path(), &vault).unwrap();
        std::fs::write(&made.temp, b"x").unwrap();
        made.temp_made = true;
        made.disarm();
        let temp = made.temp.clone();
        drop(made);
        assert!(temp.exists());
    }

    /// LOW regression: IPv6 peers are limited by their /64, and an IPv4-mapped address counts as IPv4.
    #[test]
    fn peers_are_keyed_by_ipv4_address_or_ipv6_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(peer_key(a), peer_key(b));
        assert_ne!(peer_key(a), peer_key(other));
        assert_eq!(
            peer_key("192.0.2.9".parse().unwrap()),
            "192.0.2.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            peer_key("::ffff:192.0.2.9".parse().unwrap()),
            "192.0.2.9".parse::<IpAddr>().unwrap()
        );
    }

    /// LOW regression: when the table is full a new address is still tracked (the oldest entry makes room), instead of
    /// being let through with no wait.
    #[test]
    fn a_full_failure_table_still_tracks_new_addresses() {
        let shared = shared();
        for n in 0..MAX_PEERS {
            let ip = IpAddr::from([10, (n / 256) as u8, (n % 256) as u8, 1]);
            // Block every address in the table.
            for _ in 0..=FREE_ATTEMPTS {
                drop(check_token(&shared, ip, "wrong"));
            }
        }
        let fresh: IpAddr = "198.51.100.7".parse().unwrap();
        for _ in 0..=FREE_ATTEMPTS {
            let refused = check_token(&shared, fresh, "wrong").err().unwrap();
            assert_eq!(refused.code, ErrorCode::Unauthenticated);
        }
        assert!(
            blocked_for(&shared, fresh).is_some(),
            "a new address gets its wait although the table is full"
        );
        assert_eq!(shared.peers.lock().unwrap().len(), MAX_PEERS);
    }
}
