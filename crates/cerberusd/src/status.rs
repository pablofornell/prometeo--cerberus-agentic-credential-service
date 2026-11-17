//! `cerberusd status`: asks a running daemon for its health over HTTPS (`GET /v1/health`). It trusts the CA
//! certificate in the data directory, and connects to loopback.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::config::Config;
use crate::daemon::ca_pem_path;
use crate::https::{self, HttpsError};

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
    let path = ca_pem_path(&config.data_dir);
    let pem = std::fs::read(&path).map_err(|source| StatusError::Ca {
        path: path.clone(),
        source,
    })?;
    let ca = CertificateDer::from_pem_slice(&pem).map_err(|_| StatusError::Pem)?;
    let addr = probe_addr(config);
    let reply = https::request(addr, ca.as_ref(), "GET", "/v1/health", None, None)
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
