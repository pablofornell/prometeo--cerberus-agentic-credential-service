//! The HTTPS server inside the desktop process (D1): start, stop, restart and the network view.
//!
//! The server needs the leaf certificate files, which exist only after `vault_create` (the CA
//! issuer writes them). So it starts at boot when a vault exists, and right after `vault_create`.

use std::net::SocketAddr;

use cerberus_api::tls::leaf_names;
use cerberus_api::{ApiConfig, AppState, ServerError, TlsPaths};
use cerberus_core::VaultService;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::dto::NetworkView;
use crate::error::{IpcError, IpcResult};
use crate::state::DesktopState;

impl DesktopState {
    fn tls_paths(&self) -> TlsPaths {
        TlsPaths::in_data_dir(&self.inner.paths.data_dir)
    }

    /// Starts the server when the leaf files exist and no server runs. A failure is kept for
    /// `network_status` and logged; the app keeps running without the server.
    pub(crate) async fn start_server_if_ready(&self, core: &VaultService) {
        if !self.tls_paths().leaf_cert_der.exists() {
            return;
        }
        let mut services = self.inner.services.lock().await;
        if services.server.is_some() {
            return;
        }
        let names = services.extra_names.clone();
        match self.launch(core, &names).await {
            Ok((server, renewal)) => {
                services.server = Some(server);
                services.renewal = Some(renewal);
                *self.listen_error() = None;
            }
            Err(error) => {
                tracing::error!(%error, "the HTTPS server did not start");
                *self.listen_error() = Some(error.to_string());
            }
        }
    }

    fn listen_error(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.inner
            .listen_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn api_config(&self, core: &VaultService, names: &[String]) -> ApiConfig {
        let prefs = self.prefs();
        let mut config = ApiConfig::loopback(self.tls_paths());
        config.bind = prefs
            .bind
            .iter()
            .map(|ip| SocketAddr::new(*ip, prefs.port))
            .collect();
        config.allowed_hosts = leaf_names(names);
        config.client_ca_der = core.tls_ca_cert().await.ok();
        config.require_client_cert = prefs.is_lan();
        config
    }

    async fn launch(
        &self,
        core: &VaultService,
        names: &[String],
    ) -> Result<(cerberus_api::RunningServer, tokio::task::JoinHandle<()>), ServerError> {
        let config = self.api_config(core, names).await;
        let state = AppState::new(core.clone(), &config);
        let router = crate::mcp::app(&state);
        let server = cerberus_api::start(&config, state, router).await?;
        let renewal = server.spawn_leaf_renewal(core.clone(), self.tls_paths(), names.to_vec());
        Ok((server, renewal))
    }

    /// Stops the server and its renewal task. The renewal task holds a clone of the service, so it
    /// is awaited after the abort: once this returns it holds nothing (NEW-10).
    pub(crate) async fn stop_server(&self) {
        let (server, renewal) = {
            let mut services = self.inner.services.lock().await;
            (services.server.take(), services.renewal.take())
        };
        if let Some(renewal) = renewal {
            renewal.abort();
            drop(renewal.await);
        }
        if let Some(server) = server {
            server.shutdown().await;
        }
    }

    /// Stops every task of the current service (before a restore swaps the vault file).
    pub(crate) async fn stop_all(&self) {
        self.stop_server().await;
        let tasks = std::mem::take(&mut self.inner.services.lock().await.tasks);
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            drop(task.await);
        }
    }

    /// Stops and starts the server with the current preferences and names.
    ///
    /// # Errors
    /// `unavailable` with the reason when the new server cannot start (for example the port is in use).
    pub(crate) async fn restart_server(&self) -> IpcResult<()> {
        let core = self.core()?;
        self.stop_server().await;
        self.start_server_if_ready(&core).await;
        match self.listen_error().clone() {
            Some(reason) => Err(IpcError::unavailable(&reason)),
            None => Ok(()),
        }
    }

    /// After an unlock the CA key and the owner host names are readable. Makes the leaf when it is
    /// missing (after a restore), then starts the server, or restarts it when the host names changed
    /// (the renewal task renews the leaf itself, but the `Host` allow list is fixed at start).
    pub(crate) async fn after_unlock(&self) {
        let Ok(core) = self.core() else { return };
        let Ok(material) = core.tls_ca_material().await else {
            return;
        };
        let tls = self.tls_paths();
        if !tls.leaf_cert_der.exists() {
            let made = cerberus_api::LocalCa::from_parts(&material.cert_der, &material.key_der)
                .and_then(|ca| {
                    cerberus_api::tls::renew_leaf_if_needed(
                        &ca,
                        &tls,
                        &leaf_names(&material.host_names),
                        core.clock().now(),
                    )
                });
            if let Err(error) = made {
                tracing::error!(%error, "could not make the TLS leaf certificate");
                return;
            }
        }
        let running = {
            let mut services = self.inner.services.lock().await;
            let changed = services.extra_names != material.host_names;
            services.extra_names = material.host_names;
            services.server.is_some() && !changed
        };
        if !running {
            self.stop_server().await;
            self.start_server_if_ready(&core).await;
        }
    }

    /// Makes the running server match the vault after a change of the custom certificate: no
    /// restart. When no server runs (for example the port is busy) the next start reads the vault.
    ///
    /// # Errors
    /// `unavailable` when the running server cannot take the certificate.
    pub(crate) async fn apply_tls(&self, core: &VaultService) -> IpcResult<()> {
        let services = self.inner.services.lock().await;
        let Some(server) = services.server.as_ref() else {
            return Ok(());
        };
        server
            .apply_tls(core, &self.tls_paths(), &services.extra_names)
            .await
            .map_err(|error| IpcError::unavailable(&error.to_string()))
    }

    /// The network view. It works for any unlocked role; the caller checks the role.
    ///
    /// # Errors
    /// `no_vault` before a vault exists, `internal` when the CA certificate is not readable.
    pub(crate) async fn network_view(&self, core: &VaultService) -> IpcResult<NetworkView> {
        let prefs = self.prefs();
        let active = cerberus_api::tls::active_tls(core)
            .await
            .map_err(|e| IpcError::internal(&e))?;
        let export = active.anchor;
        let leaf_not_after = active
            .leaf_not_after
            .or_else(|| {
                let der = std::fs::read(self.tls_paths().leaf_cert_der).ok()?;
                let (_, cert) = X509Certificate::from_der(&der).ok()?;
                jiff::Timestamp::from_second(cert.validity().not_after.timestamp()).ok()
            })
            .map(crate::dto::ts);
        let listening = self.inner.services.lock().await.server.is_some();
        Ok(NetworkView {
            bind: prefs.bind.iter().map(ToString::to_string).collect(),
            port: prefs.port,
            listening,
            error: self.listen_error().clone(),
            pin: export.pin,
            ca_fingerprint: export.cert_sha256_hex,
            leaf_not_after,
            mtls_required: prefs.is_lan(),
            custom_cert: active.custom,
        })
    }
}
