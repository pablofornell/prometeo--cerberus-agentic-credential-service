//! The TLS listener (TLS 1.3 only, no plain HTTP) and graceful shutdown (ADR-0023).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use cerberus_core::{CoreEvent, VaultService};
use cerberus_types::VaultStateKind;

use crate::config::{ApiConfig, AppState};
use crate::idle::{Activity, Closed, ConnActivity, Pending};
use crate::layers::ConnInfo;
use crate::tls::{
    LeafResolver, LocalCa, TlsPaths, custom_from_stored, leaf_names, renew_leaf_if_needed,
    server_config,
};

/// Why the server cannot start.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// A file or socket error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// A certificate or key is not valid, or could not be made.
    #[error("certificate error: {0}")]
    Cert(String),
    /// rustls refused the settings.
    #[error("TLS error: {0}")]
    Tls(String),
    /// A non-loopback bind needs mandatory client certificates (ADR-0023).
    #[error("a non-loopback bind needs require_client_cert and a client CA")]
    LanBindNeedsMtls,
    /// The bind list is empty.
    #[error("no bind address")]
    NoBind,
}

/// A running server. Drop does not stop it: call [`RunningServer::shutdown`].
pub struct RunningServer {
    addrs: Vec<SocketAddr>,
    resolver: Arc<LeafResolver>,
    state: AppState,
    accept: Vec<JoinHandle<()>>,
    graceful: Arc<GracefulShutdown>,
    /// Set to true to cut every connection that is still open (after the grace time).
    cut: tokio::sync::watch::Sender<bool>,
}

impl RunningServer {
    /// The addresses that are bound (useful with port 0).
    #[must_use]
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Loads the leaf files again. Call it after a renewal ([`crate::tls::renew_leaf_if_needed`]).
    /// New connections use the new leaf; open ones keep running.
    ///
    /// # Errors
    /// [`ServerError`] when the files are not valid. The old leaf stays in use.
    pub fn reload_leaf(&self) -> Result<(), ServerError> {
        self.resolver.reload()
    }

    /// True when the owner custom certificate is served now (ADR-0023 point 8).
    #[must_use]
    pub fn is_custom(&self) -> bool {
        self.resolver.is_custom()
    }

    /// Makes the live server match the vault, with no restart: the stored custom certificate is
    /// served when there is one; else the local leaf is back (and renewed when due). Call it after
    /// [`crate::tls::store_custom_cert`] or `VaultService::tls_custom_clear`. New connections use
    /// the new certificate; open ones keep running. Needs an unlocked vault. Clients that pin the
    /// local CA no longer match while a custom certificate is served.
    ///
    /// # Errors
    /// [`ServerError`] when the vault is locked or a certificate does not load. The old
    /// certificate stays in use.
    pub async fn apply_tls(
        &self,
        core: &VaultService,
        tls: &TlsPaths,
        extra_names: &[String],
    ) -> Result<(), ServerError> {
        sync_custom(core, &self.resolver).await?;
        renew_and_reload(core, &self.resolver, tls, extra_names)
            .await
            .map(drop)
    }

    /// Renews the leaf when it is near its end or its names changed, then loads it (ADR-0023
    /// point 5). Needs the unlocked vault: the CA key is sealed. Names: the standard ones, the
    /// vault host names, then `extra_names`. Returns true when a new leaf was written. While a
    /// custom certificate is served it does nothing and returns false.
    ///
    /// # Errors
    /// [`ServerError::Cert`] when the vault is locked or the CA does not open, or the errors of
    /// [`renew_leaf_if_needed`]. The old leaf stays in use.
    pub async fn renew_leaf(
        &self,
        core: &VaultService,
        tls: &TlsPaths,
        extra_names: &[String],
    ) -> Result<bool, ServerError> {
        renew_and_reload(core, &self.resolver, tls, extra_names).await
    }

    /// Starts a task that runs [`Self::renew_leaf`] now (when unlocked) and at every unlock. The
    /// task ends when the core event channel closes; abort the handle to stop it sooner.
    #[must_use]
    pub fn spawn_leaf_renewal(
        &self,
        core: VaultService,
        tls: TlsPaths,
        extra_names: Vec<String>,
    ) -> JoinHandle<()> {
        let resolver = Arc::clone(&self.resolver);
        let mut events = core.subscribe();
        tokio::spawn(async move {
            let renew = || async {
                if core.state() != VaultStateKind::Unlocked {
                    return;
                }
                if let Err(error) = sync_custom(&core, &resolver).await {
                    tracing::warn!(%error, "custom TLS certificate not applied");
                    return;
                }
                match renew_and_reload(&core, &resolver, &tls, &extra_names).await {
                    Ok(true) => tracing::info!("TLS leaf renewed"),
                    Ok(false) => {}
                    Err(error) => tracing::warn!(%error, "TLS leaf renewal failed"),
                }
            };
            renew().await;
            loop {
                match events.recv().await {
                    Ok(CoreEvent::StateChanged(VaultStateKind::Unlocked))
                    | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => renew().await,
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        })
    }

    /// Stops accepting, ends SSE streams, and waits (up to 10 s) for open requests.
    pub async fn shutdown(self) {
        self.state.begin_shutdown();
        for handle in &self.accept {
            handle.abort();
        }
        for handle in self.accept {
            drop(handle.await);
        }
        let grace = self.state.limits().shutdown_grace;
        match Arc::try_unwrap(self.graceful) {
            Ok(graceful) => {
                if tokio::time::timeout(grace, graceful.shutdown())
                    .await
                    .is_err()
                {
                    tracing::warn!("open requests did not finish in time; closing them");
                }
            }
            Err(_) => tracing::warn!("a connection task still holds the shutdown guard"),
        }
        // Whatever is still open is cut now: a long request must not outlive the shutdown (a
        // restore swaps the vault under it).
        self.cut.send_replace(true);
    }
}

/// Puts the stored custom certificate in the resolver, or the local leaf back when there is none.
async fn sync_custom(core: &VaultService, resolver: &LeafResolver) -> Result<(), ServerError> {
    let stored = core
        .tls_custom_material()
        .await
        .map_err(|error| ServerError::Cert(format!("custom certificate not available: {error}")))?;
    match stored {
        Some(material) => {
            let cert = custom_from_stored(material.chain_der, &material.key_der)
                .map_err(|error| ServerError::Cert(error.to_string()))?;
            resolver.use_custom(cert.certified());
        }
        None if resolver.is_custom() => resolver.use_local()?,
        None => {}
    }
    Ok(())
}

async fn renew_and_reload(
    core: &VaultService,
    resolver: &LeafResolver,
    tls: &TlsPaths,
    extra_names: &[String],
) -> Result<bool, ServerError> {
    // A renewal never replaces the owner certificate (ADR-0023 point 8).
    if resolver.is_custom() {
        return Ok(false);
    }
    let material = core
        .tls_ca_material()
        .await
        .map_err(|error| ServerError::Cert(format!("CA not available: {error}")))?;
    let ca = LocalCa::from_parts(&material.cert_der, &material.key_der)?;
    let mut extra = material.host_names.clone();
    extra.extend(extra_names.iter().cloned());
    let now = core.clock().now();
    let renewed = renew_leaf_if_needed(&ca, tls, &leaf_names(&extra), now)?;
    if renewed {
        resolver.reload()?;
    }
    Ok(renewed)
}

/// Binds every address and serves `app` over TLS 1.3 until [`RunningServer::shutdown`].
///
/// A `::1` address that the host does not have is skipped with a warning when another address is bound.
///
/// # Errors
/// [`ServerError`] when the config breaks an ADR-0023 rule, the leaf cannot be loaded, or no address
/// can be bound.
pub async fn start(
    config: &ApiConfig,
    state: AppState,
    app: Router,
) -> Result<RunningServer, ServerError> {
    config.validate()?;
    let resolver = LeafResolver::load(config.tls.clone())?;
    let tls = TlsAcceptor::from(server_config(
        Arc::clone(&resolver),
        config.client_ca_der.as_deref(),
        config.require_client_cert,
    )?);
    let mut listeners = Vec::new();
    for addr in &config.bind {
        match TcpListener::bind(addr).await {
            Ok(listener) => listeners.push(listener),
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                tracing::warn!(%addr, "address not available; skipped");
            }
            Err(error) => return Err(error.into()),
        }
    }
    if listeners.is_empty() {
        return Err(ServerError::Io(io::Error::from(
            io::ErrorKind::AddrNotAvailable,
        )));
    }
    let addrs = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<Vec<_>, _>>()?;
    let graceful = Arc::new(GracefulShutdown::new());
    let permits = Arc::new(Semaphore::new(config.limits.max_connections));
    let pending = Pending::new(config.limits.max_unauthenticated);
    let (cut, _) = tokio::sync::watch::channel(false);
    let accept = listeners
        .into_iter()
        .map(|listener| {
            tokio::spawn(accept_loop(
                listener,
                tls.clone(),
                app.clone(),
                state.clone(),
                Arc::clone(&graceful),
                Arc::clone(&permits),
                Arc::clone(&pending),
                cut.subscribe(),
            ))
        })
        .collect();
    tracing::info!(?addrs, "agent API listening (TLS 1.3 only)");
    Ok(RunningServer {
        addrs,
        resolver,
        state,
        accept,
        graceful,
        cut,
    })
}

/// [`start`], then waits for `shutdown` and stops. The form `cerberusd` uses.
///
/// # Errors
/// As [`start`].
pub async fn serve(
    config: ApiConfig,
    state: AppState,
    app: Router,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), ServerError> {
    let running = start(&config, state, app).await?;
    shutdown.await;
    running.shutdown().await;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the accept loop owns each shared part of the server"
)]
async fn accept_loop(
    listener: TcpListener,
    tls: TlsAcceptor,
    app: Router,
    state: AppState,
    graceful: Arc<GracefulShutdown>,
    permits: Arc<Semaphore>,
    pending: Arc<Pending>,
    cut: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "accept failed");
                continue;
            }
        };
        // A new connection never waits behind connections that have not authenticated: when their
        // budget or the server is full, the oldest of the busiest source is evicted (NEW-1). Only
        // when every slot is authenticated does it wait for one.
        let activity = Activity::new();
        let held = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => {
                let (slot, evicted) = Pending::admit(&pending, peer.ip(), &activity, false);
                log_eviction(evicted, peer);
                (permit, slot)
            }
            Err(TryAcquireError::NoPermits) => {
                let (slot, evicted) = Pending::admit(&pending, peer.ip(), &activity, true);
                log_eviction(evicted, peer);
                let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                    return;
                };
                activity.admitted();
                (permit, slot)
            }
            Err(TryAcquireError::Closed) => return,
        };
        let tls = tls.clone();
        let app = app.clone();
        let state = state.clone();
        let graceful = Arc::clone(&graceful);
        let mut cut = cut.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = serve_connection(stream, peer, tls, app, &state, graceful, Arc::clone(&activity)) => {}
                () = activity.evicted() => tracing::debug!(%peer, "connection evicted for a newer one"),
                _ = cut.wait_for(|cut| *cut) => tracing::debug!(%peer, "connection cut at shutdown"),
            }
            activity.close();
            drop(held);
        });
    }
}

fn log_eviction(evicted: bool, peer: SocketAddr) {
    if evicted {
        tracing::debug!(%peer, "unauthenticated connections full; the oldest was evicted");
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    app: Router,
    state: &AppState,
    graceful: Arc<GracefulShutdown>,
    activity: Arc<Activity>,
) {
    let limits = state.limits();
    let handshake = tokio::time::timeout(limits.handshake_timeout, tls.accept(stream)).await;
    let tls_stream = match handshake {
        Ok(Ok(stream)) => stream,
        // A plain HTTP request, TLS 1.2 or a bad client certificate ends here (ADR-0023, A8).
        Ok(Err(error)) => {
            tracing::debug!(%peer, %error, "TLS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "TLS handshake timed out");
            return;
        }
    };
    let client_cert_sha256 = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| <[u8; 32]>::from(Sha256::digest(cert.as_ref())));
    let info = ConnInfo {
        peer,
        client_cert_sha256,
    };
    activity.handshake_done();
    let conn = ConnActivity(Arc::clone(&activity));
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        // A complete request head. Only this, never bytes, counts as the first request (AUD-4).
        conn.0.request_started();
        request.extensions_mut().insert(info);
        request.extensions_mut().insert(conn.clone());
        app.clone().oneshot(request)
    });
    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout);
    let connection = builder.serve_connection(TokioIo::new(tls_stream), service);
    let watched = graceful.watch(connection.into_owned());
    // The guard lives in `watched`. Dropping the Arc lets `shutdown` own the handle while this
    // request runs.
    drop(graceful);
    // hyper starts its own header timeout only after it knows the protocol, and HTTP/2 PING
    // frames keep an h2 connection, so the request deadlines are kept here (AUD-4).
    let core = state.core();
    let owner_live = |agent: cerberus_types::AgentId, key: cerberus_types::AgentKeyId| {
        core.auth().key_active(&agent, &key, core.clock().now())
    };
    tokio::select! {
        result = watched => {
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "connection ended with an error");
            }
        }
        closed = crate::idle::watch(activity, limits, &owner_live) => {
            let reason = match closed {
                Closed::NoRequest => "no request in time",
                Closed::NotAuthenticated => "no authenticated request in time",
                Closed::Idle => "idle",
                Closed::SendStalled => "the client did not take a response in time",
                Closed::OwnerGone => "the key of the connection is no longer valid",
            };
            tracing::debug!(%peer, reason, "connection closed");
        }
    }
}
