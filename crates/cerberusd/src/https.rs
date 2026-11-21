//! A small HTTPS client for the daemon's own checks: `cerberusd status` and the tests. It trusts only the vault CA
//! and speaks TLS 1.3 only. [`request`] sends no client certificate; [`request_as`] sends one (the tests use it for
//! admin client certificates). Agents use their own clients.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The name the client asks for. The leaf always carries it (ADR-0023).
pub const SERVER_NAME: &str = "localhost";

/// A status code and the body.
#[derive(Debug)]
pub struct Reply {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
}

/// Why a request failed.
#[derive(Debug, thiserror::Error)]
pub enum HttpsError {
    /// TCP or socket error.
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    /// TLS error (for example a CA that does not match).
    #[error("TLS failed: {0}")]
    Tls(#[from] rustls::Error),
    /// HTTP error.
    #[error("HTTP failed: {0}")]
    Http(#[from] hyper::Error),
    /// The request could not be built.
    #[error("bad request: {0}")]
    Request(#[from] hyper::http::Error),
    /// The server name is not valid.
    #[error("bad server name")]
    ServerName,
}

/// Sends one request over TLS 1.3 to `addr`, trusting only `ca_der`.
///
/// # Errors
/// [`HttpsError`] for a connection, TLS or HTTP failure.
pub async fn request(
    addr: SocketAddr,
    ca_der: &[u8],
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<Reply, HttpsError> {
    request_as(addr, ca_der, None, method, path, token, body).await
}

/// A client certificate and its PKCS#8 key, both DER.
pub type Identity<'a> = (&'a [u8], &'a [u8]);

/// As [`request`], with a client certificate when `identity` is given. The key is copied into rustls, which
/// does not zeroize it: use it for tests and checks, not for a long-lived client.
///
/// # Errors
/// [`HttpsError`] for a connection, TLS or HTTP failure.
pub async fn request_as(
    addr: SocketAddr,
    ca_der: &[u8],
    identity: Option<Identity<'_>>,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<Reply, HttpsError> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec()))?;
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots);
    let config = match identity {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder.with_client_auth_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )?,
    };
    let name = ServerName::try_from(SERVER_NAME).map_err(|_| HttpsError::ServerName)?;
    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        drop(connection.await);
    });
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, SERVER_NAME);
    if let Some(token) = token {
        builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let payload = match body {
        Some(text) => {
            builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
            Bytes::from(text.to_owned())
        }
        None => Bytes::new(),
    };
    let request = builder.body(Full::new(payload))?;
    let response = sender.send_request(request).await?;
    let status = response.status().as_u16();
    let body = response.into_body().collect().await?.to_bytes().to_vec();
    Ok(Reply { status, body })
}
