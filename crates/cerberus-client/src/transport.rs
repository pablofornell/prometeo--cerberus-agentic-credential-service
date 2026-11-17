//! Pinned HTTPS transport: one TLS 1.3 connection per call, HTTP/1.1, bearer token.
//!
//! This is the public low-level layer. The typed [`crate::Client`] is built on it, and the MCP
//! stdio shim uses it directly to forward JSON-RPC to `/mcp`. It never retries: a call is sent
//! once, and the error type tells the caller whether anything may have been sent
//! ([`ClientError::Connect`] means nothing was).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use cerberus_types::wire::WireSecret;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::{self, SendRequest};
use hyper::header::{AUTHORIZATION, HOST, HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use hyper::{Method, Request as HttpRequest};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::{Host, Url};

use crate::config::{ClientConfig, Trust, parse_base_url};
use crate::error::ClientError;
use crate::tls::{client_config, is_pin_mismatch};

/// Time limit of the TCP connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default time limit of one call.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// One request. `path` starts with `/` and may hold a query string. It is joined to the path of
/// the base URL.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// HTTP method.
    pub method: Method,
    /// Path and query, for example `/v1/status`.
    pub path: &'a str,
    /// Extra headers (name, value). `Host`, `Authorization` and `User-Agent` are set by the
    /// transport and cannot be replaced.
    pub headers: Vec<(&'a str, &'a str)>,
    /// Request body. When present, `Content-Type` is `application/json` unless you set it.
    pub body: Option<Bytes>,
}

impl<'a> Request<'a> {
    /// A `GET` request.
    #[must_use]
    pub fn get(path: &'a str) -> Self {
        Self {
            method: Method::GET,
            path,
            headers: Vec::new(),
            body: None,
        }
    }

    /// A `POST` request with a JSON body.
    #[must_use]
    pub fn post_json(path: &'a str, body: impl Into<Bytes>) -> Self {
        Self {
            method: Method::POST,
            path,
            headers: Vec::new(),
            body: Some(body.into()),
        }
    }
}

/// The answer to a request. The body is read on demand, so an event stream can be consumed
/// chunk by chunk.
pub struct Response {
    status: u16,
    headers: HeaderMap,
    body: Incoming,
    idle: Duration,
    // Keeps the connection open while the body is read.
    _sender: SendRequest<Full<Bytes>>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Response {
    /// HTTP status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// A header value as text (case-insensitive name).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The next piece of the body, or `None` at the end. Fails with [`ClientError::Timeout`]
    /// when nothing arrives within the idle limit (event streams send a heartbeat every 15 s).
    ///
    /// # Errors
    /// [`ClientError::Timeout`] or [`ClientError::Transport`].
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, ClientError> {
        loop {
            let frame = timeout(self.idle, self.body.frame())
                .await
                .map_err(|_| ClientError::Timeout)?;
            match frame {
                None => return Ok(None),
                Some(Err(error)) => return Err(ClientError::Transport(error.to_string())),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }

    /// Reads the whole body. Fails when it is longer than `limit` bytes.
    ///
    /// # Errors
    /// [`ClientError::Decode`] when the body is too long, else as [`Response::chunk`].
    pub async fn bytes(mut self, limit: usize) -> Result<Vec<u8>, ClientError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            if out.len() + chunk.len() > limit {
                return Err(ClientError::Decode("response body too long".to_owned()));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

struct Inner {
    base: Url,
    host_header: String,
    server_name: ServerName<'static>,
    addr: (String, u16),
    connector: TlsConnector,
    auth: Option<HeaderValue>,
    timeout: Duration,
}

/// HTTPS client that trusts only the pinned Cerberus CA, speaks TLS 1.3 only and sends the
/// bearer token on every request. Cheap to clone.
#[derive(Clone)]
pub struct PinnedHttps {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for PinnedHttps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedHttps")
            .field("base", &self.inner.base.as_str())
            .finish_non_exhaustive()
    }
}

impl PinnedHttps {
    /// Builds the transport from the three things the MCP shim needs.
    ///
    /// # Errors
    /// [`ClientError::Config`] when the URL is not `https`, the pin or the CA file is not valid,
    /// or the token cannot be a header value. [`ClientError::PinMismatch`] when a CA file does
    /// not match the pin that goes with it.
    pub fn new(base_url: &str, trust: &Trust, token: &WireSecret) -> Result<Self, ClientError> {
        Self::build(
            parse_base_url(base_url)?,
            trust,
            None,
            Some(token),
            DEFAULT_TIMEOUT,
        )
    }

    /// Builds the transport from a full [`ClientConfig`] (adds mTLS and the call time limit).
    ///
    /// # Errors
    /// As [`PinnedHttps::new`].
    pub fn from_config(config: &ClientConfig) -> Result<Self, ClientError> {
        Self::build(
            config.base_url.clone(),
            &config.trust,
            config.client_cert.as_ref(),
            Some(&config.token),
            config.timeout,
        )
    }

    fn build(
        base: Url,
        trust: &Trust,
        client_cert: Option<&(std::path::PathBuf, std::path::PathBuf)>,
        token: Option<&WireSecret>,
        call_timeout: Duration,
    ) -> Result<Self, ClientError> {
        let tls = client_config(trust, client_cert)?;
        let (host, server_name) = match base.host() {
            Some(Host::Domain(name)) => (
                name.to_owned(),
                ServerName::try_from(name.to_owned())
                    .map_err(|_| ClientError::Config("the host name is not valid".to_owned()))?,
            ),
            Some(Host::Ipv4(ip)) => (
                ip.to_string(),
                ServerName::IpAddress(std::net::IpAddr::V4(ip).into()),
            ),
            Some(Host::Ipv6(ip)) => (
                ip.to_string(),
                ServerName::IpAddress(std::net::IpAddr::V6(ip).into()),
            ),
            None => {
                return Err(ClientError::Config(
                    "the service URL has no host".to_owned(),
                ));
            }
        };
        let port = base.port_or_known_default().unwrap_or(443);
        let host_header = match (base.host(), base.port()) {
            (Some(Host::Ipv6(ip)), Some(p)) => format!("[{ip}]:{p}"),
            (Some(Host::Ipv6(ip)), None) => format!("[{ip}]"),
            (_, Some(p)) => format!("{host}:{p}"),
            (_, None) => host.clone(),
        };
        let auth = match token {
            Some(secret) => {
                let mut value = HeaderValue::from_str(&format!("Bearer {}", secret.expose()))
                    .map_err(|_| ClientError::Config("the token is not valid".to_owned()))?;
                value.set_sensitive(true);
                Some(value)
            }
            None => None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                base,
                host_header,
                server_name,
                addr: (host, port),
                connector: TlsConnector::from(Arc::new(tls)),
                auth,
                timeout: call_timeout,
            }),
        })
    }

    /// The time limit of one call.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.inner.timeout
    }

    /// Sends one request and returns once the response headers arrive. No retry.
    ///
    /// # Errors
    /// [`ClientError::Connect`] (nothing sent), [`ClientError::PinMismatch`], [`ClientError::Tls`],
    /// [`ClientError::Timeout`] or [`ClientError::Transport`] (the server may have acted).
    pub async fn send(&self, request: Request<'_>) -> Result<Response, ClientError> {
        let inner = &self.inner;
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(inner.addr.clone()))
            .await
            .map_err(|_| ClientError::Connect("connect timed out".to_owned()))?
            .map_err(|e| ClientError::Connect(e.kind().to_string()))?;
        // Best effort: it only lowers latency.
        let _ = tcp.set_nodelay(true);
        let tls = timeout(
            inner.timeout,
            inner.connector.connect(inner.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| ClientError::Tls("handshake timed out".to_owned()))?
        .map_err(|e| map_handshake_error(&e))?;
        let (mut sender, connection) = http1::handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        tokio::spawn(async move {
            // The connection ends when the response is done or the peer closes it.
            let _ = connection.await;
        });
        let http = self.http_request(request)?;
        let response = timeout(inner.timeout, sender.send_request(http))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let (parts, body) = response.into_parts();
        Ok(Response {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
            idle: inner.timeout,
            _sender: sender,
        })
    }

    /// `POST` with a JSON body. Shortcut for [`PinnedHttps::send`].
    ///
    /// # Errors
    /// As [`PinnedHttps::send`].
    pub async fn post_json(&self, path: &str, body: &[u8]) -> Result<Response, ClientError> {
        self.send(Request::post_json(path, Bytes::copy_from_slice(body)))
            .await
    }

    /// `GET`. Shortcut for [`PinnedHttps::send`].
    ///
    /// # Errors
    /// As [`PinnedHttps::send`].
    pub async fn get(&self, path: &str) -> Result<Response, ClientError> {
        self.send(Request::get(path)).await
    }

    fn http_request(&self, request: Request<'_>) -> Result<HttpRequest<Full<Bytes>>, ClientError> {
        let inner = &self.inner;
        let base_path = inner.base.path().trim_end_matches('/');
        let uri = format!("{base_path}{}", request.path);
        let mut builder = HttpRequest::builder()
            .method(request.method)
            .uri(uri)
            .header(HOST, inner.host_header.as_str())
            .header(
                USER_AGENT,
                concat!("cerberus-client/", env!("CARGO_PKG_VERSION")),
            );
        let has_body = request.body.is_some();
        let mut has_content_type = false;
        for (name, value) in &request.headers {
            let name = HeaderName::try_from(*name)
                .map_err(|_| ClientError::Config("bad header name".to_owned()))?;
            if name == HOST || name == AUTHORIZATION || name == USER_AGENT {
                continue;
            }
            has_content_type |= name == hyper::header::CONTENT_TYPE;
            let value = HeaderValue::from_str(value)
                .map_err(|_| ClientError::Config("bad header value".to_owned()))?;
            builder = builder.header(name, value);
        }
        if has_body && !has_content_type {
            builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
        }
        if let Some(auth) = &inner.auth {
            builder = builder.header(AUTHORIZATION, auth.clone());
        }
        builder
            .body(Full::new(request.body.unwrap_or_default()))
            .map_err(|_| ClientError::Config("the request path is not valid".to_owned()))
    }
}

fn map_handshake_error(error: &std::io::Error) -> ClientError {
    let rustls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match rustls_error {
        Some(e) if is_pin_mismatch(e) => ClientError::PinMismatch,
        Some(e) => ClientError::Tls(e.to_string()),
        None => ClientError::Tls(error.to_string()),
    }
}
