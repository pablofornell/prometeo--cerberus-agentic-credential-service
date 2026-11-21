//! Server configuration and the shared state of the handlers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use cerberus_core::{AgentApi, VaultService};
use cerberus_ssh_agent::SshBridge;
use tokio::sync::watch;

use crate::admin::{AdminConfig, AdminState};
use crate::idle::Owners;
use crate::server::ServerError;
use crate::tls::{TlsPaths, leaf_names};

/// The default port (ADR-0023).
pub const DEFAULT_PORT: u16 = 7373;

/// Body size limits and timeouts (ADR-0023 "Listener" points 4 and 5). The request rate limits
/// belong to core (`AuthLimits`, ADR-0030): the API only calls `auth().check`.
#[derive(Clone, Debug)]
pub struct ApiLimits {
    /// Body limit of most routes: 16 KiB.
    pub body_default_bytes: usize,
    /// Body limit of `POST /v1/credentials` and `POST /v1/sessions`: 1 MiB.
    pub body_large_bytes: usize,
    /// Time for the TLS handshake: 10 s.
    pub handshake_timeout: Duration,
    /// Time to read the request headers: 10 s. It also ends an idle keep-alive connection (DEC-T10-9).
    /// A new connection must complete its first request head within this time after the TLS
    /// handshake; bytes and HTTP/2 PING frames do not count (AUD-4, DEC-T27-D2-1).
    pub header_timeout: Duration,
    /// Longest life of a connection that has had no authenticated request, from accept: 30 s. It
    /// applies even while a request runs (AUD-4, DEC-T27-D2-1).
    pub auth_timeout: Duration,
    /// Time an authenticated connection may stay open with no authenticated request running: 60 s.
    /// Unauthenticated requests, bytes and PING frames do not reset it; a response that is still
    /// being sent (an SSE stream) counts as running (AUD-4, DEC-T27-D2-1).
    pub idle_timeout: Duration,
    /// Most connections that have not authenticated yet, from all addresses together: 64. When this
    /// budget or `max_connections` is full, a new connection evicts the oldest unauthenticated
    /// connection of the busiest source; authenticated connections are never evicted, so they keep
    /// `max_connections - max_unauthenticated` slots (NEW-1, DEC-T27-D2-2).
    pub max_unauthenticated: usize,
    /// Time to read a request body: 30 s.
    pub body_timeout: Duration,
    /// Most connections at the same time: 256. When all are authenticated, more wait in the accept
    /// queue; else a new one evicts an unauthenticated one (see `max_unauthenticated`).
    pub max_connections: usize,
    /// Most open connections that one agent (all its keys together) may have authenticated: 32.
    /// A request with a good token on a further connection gets `429 rate_limited`, and that
    /// connection stays unauthenticated (NEW-6, DEC-T27-E-2).
    pub max_connections_per_agent: usize,
    /// Time a response may wait for the client before hyper pulls more of its body: 30 s. When
    /// hyper has not pulled the next part of a response for this long (the client does not read,
    /// or holds an HTTP/2 window of 0), the connection is closed. A stream that waits for its own
    /// next event (SSE) does not count (NEW-6, DEC-T27-E-2).
    pub send_timeout: Duration,
    /// Time that open requests get to finish at shutdown: 10 s. After it the connections are cut.
    pub shutdown_grace: Duration,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            body_default_bytes: 16 * 1024,
            body_large_bytes: 1024 * 1024,
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            auth_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            max_unauthenticated: 64,
            body_timeout: Duration::from_secs(30),
            max_connections: 256,
            max_connections_per_agent: 32,
            send_timeout: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// Everything the server needs from its host (the desktop app or `cerberusd`).
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// Addresses to listen on. Default `127.0.0.1:7373` and `[::1]:7373`.
    pub bind: Vec<SocketAddr>,
    /// Names the `Host` header may have (the leaf names). Anything else gets `403 origin_refused`.
    pub allowed_hosts: Vec<String>,
    /// Where the leaf certificate and key are.
    pub tls: TlsPaths,
    /// The CA certificate (DER). It verifies client certificates. `None` turns client certificates off.
    pub client_ca_der: Option<Vec<u8>>,
    /// True: a client without a certificate fails the handshake. Needed for a non-loopback bind.
    pub require_client_cert: bool,
    /// Limits and timeouts.
    pub limits: ApiLimits,
    /// The admin API under `/admin/v1` (ADR-0034). `None` (the default, and always on the
    /// desktop): no `/admin` route exists. It needs `client_ca_der`.
    pub admin: Option<AdminConfig>,
}

impl ApiConfig {
    /// The default config: loopback on port 7373, the standard leaf names, no client certificates.
    #[must_use]
    pub fn loopback(tls: TlsPaths) -> Self {
        Self {
            bind: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PORT),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DEFAULT_PORT),
            ],
            allowed_hosts: leaf_names(&[]),
            tls,
            client_ca_der: None,
            require_client_cert: false,
            limits: ApiLimits::default(),
            admin: None,
        }
    }

    /// Checks the rules of ADR-0023: a non-loopback address needs mandatory client certificates.
    /// The admin API needs client certificates verified against the vault CA (ADR-0034 point 4).
    ///
    /// # Errors
    /// [`ServerError::NoBind`], [`ServerError::LanBindNeedsMtls`] or
    /// [`ServerError::AdminNeedsClientCa`].
    pub fn validate(&self) -> Result<(), ServerError> {
        if self.bind.is_empty() {
            return Err(ServerError::NoBind);
        }
        let lan = self.bind.iter().any(|addr| !addr.ip().is_loopback());
        if lan && !(self.require_client_cert && self.client_ca_der.is_some()) {
            return Err(ServerError::LanBindNeedsMtls);
        }
        if self.admin.is_some() && self.client_ca_der.is_none() {
            return Err(ServerError::AdminNeedsClientCa);
        }
        Ok(())
    }
}

struct Inner {
    core: VaultService,
    hosts: Vec<String>,
    limits: ApiLimits,
    warned: Mutex<HashMap<IpAddr, i64>>,
    /// The agent each authenticated connection belongs to (NEW-6).
    owners: Arc<Owners>,
    shutdown: watch::Sender<bool>,
    /// The shared ssh-agent bridge of the core (T22). Holding it keeps its sockets open.
    ssh: SshBridge,
    /// The admin API state, when the host turned it on (ADR-0034).
    admin: Option<Arc<AdminState>>,
}

/// The state of every handler. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

/// One warning per source IP per minute for refused tokens (ADR-0032 point 7).
const WARN_EVERY_MS: i64 = 60_000;
/// The warn table is cut when it holds more IPs than this.
const WARN_TABLE_MAX: usize = 4096;

impl AppState {
    /// The state for a core service and a config.
    #[must_use]
    pub fn new(core: VaultService, config: &ApiConfig) -> Self {
        let (shutdown, _) = watch::channel(false);
        let ssh = SshBridge::shared(&core);
        Self {
            inner: Arc::new(Inner {
                core,
                hosts: config
                    .allowed_hosts
                    .iter()
                    .map(|host| host.to_ascii_lowercase())
                    .collect(),
                limits: config.limits.clone(),
                warned: Mutex::new(HashMap::new()),
                owners: Owners::new(config.limits.max_connections_per_agent),
                shutdown,
                ssh,
                admin: config.admin.as_ref().map(|admin| Arc::clone(&admin.state)),
            }),
        }
    }

    /// The vault service.
    #[must_use]
    pub fn core(&self) -> &VaultService {
        &self.inner.core
    }

    /// The ssh-agent bridge of this server (signing sockets of `ssh-prepare`).
    #[must_use]
    pub fn ssh_bridge(&self) -> &SshBridge {
        &self.inner.ssh
    }

    /// The admin API state, when the admin API is on (ADR-0034).
    #[must_use]
    pub fn admin(&self) -> Option<&Arc<AdminState>> {
        self.inner.admin.as_ref()
    }

    /// The Agent API of the vault service.
    #[must_use]
    pub fn agent_api(&self) -> AgentApi {
        self.inner.core.agent_api()
    }

    pub(crate) fn limits(&self) -> &ApiLimits {
        &self.inner.limits
    }

    pub(crate) fn owners(&self) -> &Arc<Owners> {
        &self.inner.owners
    }

    pub(crate) fn host_allowed(&self, host: &str) -> bool {
        self.inner.hosts.iter().any(|allowed| allowed == host)
    }

    pub(crate) fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.inner.shutdown.subscribe()
    }

    pub(crate) fn begin_shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    /// True when a warning for this IP is due now. At most one per minute per IP.
    pub(crate) fn warn_due(&self, ip: IpAddr, now_ms: i64) -> bool {
        let mut table = self
            .inner
            .warned
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if table.len() > WARN_TABLE_MAX {
            table.retain(|_, last| now_ms.saturating_sub(*last) < WARN_EVERY_MS);
        }
        match table.get(&ip) {
            Some(last) if now_ms.saturating_sub(*last) < WARN_EVERY_MS => false,
            _ => {
                table.insert(ip, now_ms);
                true
            }
        }
    }
}
