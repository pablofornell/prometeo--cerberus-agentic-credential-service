//! `cerberusd status`: asks a running daemon for its health over HTTPS (`GET /v1/health`). It trusts the CA
//! certificate in the data directory, and connects to loopback. It also shows the CA pin and fingerprint (a person
//! compares them with what the desktop shows at a bundle import) and whether the admin API is on, from the config
//! and the registry file (ADR-0034 points 2.4, 7.10).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use cerberus_admin::clients::AdminClients;
use cerberus_api::tls::CaExport;
use cerberus_types::{Clock, SystemClock};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::config::Config;
use crate::daemon::ca_pem_path;
use crate::https::{self, HttpsError};
use crate::unlock::registry_path;

/// The admin API part of `cerberusd status`.
#[derive(Debug, PartialEq, Eq)]
pub struct AdminSummary {
    /// `[admin] enabled` of the config.
    pub enabled: bool,
    /// Live enrolments in the registry file, or why it cannot be read.
    pub enrolled: Result<usize, String>,
}

impl std::fmt::Display for AdminSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = if self.enabled { "on" } else { "off" };
        match &self.enrolled {
            Ok(count) => write!(f, "admin API: {state}, {count} enrolled clients"),
            Err(error) => write!(f, "admin API: {state}, registry not readable: {error}"),
        }
    }
}

/// Whether the admin API is on and how many live enrolments the registry has. No network call.
#[must_use]
pub fn admin_summary(config: &Config) -> AdminSummary {
    let enrolled = AdminClients::load(&registry_path(&config.data_dir))
        .map(|clients| clients.live_count(SystemClock.now()))
        .map_err(|error| error.to_string());
    AdminSummary {
        enabled: config.admin.enabled,
        enrolled,
    }
}

/// The CA pin and SHA-256 fingerprint from the CA file of the data directory.
///
/// # Errors
/// [`StatusError::Ca`] or [`StatusError::Pem`].
pub fn ca_fingerprints(config: &Config) -> Result<CaExport, StatusError> {
    let der = read_ca(config)?;
    CaExport::from_der(&der).map_err(|_| StatusError::Pem)
}

fn read_ca(config: &Config) -> Result<Vec<u8>, StatusError> {
    let path = ca_pem_path(&config.data_dir);
    let pem = std::fs::read(&path).map_err(|source| StatusError::Ca {
        path: path.clone(),
        source,
    })?;
    CertificateDer::from_pem_slice(&pem)
        .map(|der| der.as_ref().to_vec())
        .map_err(|_| StatusError::Pem)
}

/// What the daemon says about itself.
#[derive(Debug, PartialEq, Eq)]
pub struct Health {
    /// `locked` or `unlocked`.
    pub vault: String,
    /// The daemon version.
    pub version: String,
    /// The address that answered.
    pub address: SocketAddr,
}

/// Why the check failed.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// The CA file is missing. The daemon writes it at start.
    #[error(
        "cannot read the CA certificate at {path}: {source}. Has cerberusd started with this data directory?"
    )]
    Ca {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The CA file is not a certificate.
    #[error("the CA file is not a PEM certificate")]
    Pem,
    /// No daemon answered.
    #[error("no cerberusd answered at {addr}: {source}")]
    Unreachable {
        /// The address tried.
        addr: SocketAddr,
        /// The cause.
        source: HttpsError,
    },
    /// The daemon answered with an error status.
    #[error("the health check returned HTTP {0}")]
    Status(u16),
    /// The health body is not as expected.
    #[error("the health reply is not valid")]
    Body,
}

/// The loopback address to probe for a bind address. A wildcard maps to loopback.
#[must_use]
pub fn probe_addr(config: &Config) -> SocketAddr {
    let ip = match config.bind.first().copied() {
        Some(IpAddr::V4(v4)) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(IpAddr::V6(v6)) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        Some(ip) => ip,
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    SocketAddr::new(ip, config.port)
}

/// Checks the daemon of this data directory.
///
/// # Errors
/// [`StatusError`] when the CA file is missing, nothing answers, or the reply is not a health reply.
pub async fn check(config: &Config) -> Result<Health, StatusError> {
    let ca = read_ca(config)?;
    let addr = probe_addr(config);
    let reply = https::request(addr, &ca, "GET", "/v1/health", None, None)
        .await
        .map_err(|source| StatusError::Unreachable { addr, source })?;
    if reply.status != 200 {
        return Err(StatusError::Status(reply.status));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&reply.body).map_err(|_| StatusError::Body)?;
    let vault = body["vault"].as_str().ok_or(StatusError::Body)?.to_owned();
    let version = body["version"]
        .as_str()
        .ok_or(StatusError::Body)?
        .to_owned();
    Ok(Health {
        vault,
        version,
        address: addr,
    })
}
