//! The typed SDK over the agent REST API (`/v1`), with the retry rules of ADR-0021.
//!
//! Retry rules: a call is repeated only when the server marks the error `retryable`, or when the
//! TCP connect failed (nothing was sent). Calls that the server may already have counted (reveal,
//! totp, resolve, create) are never repeated after a timeout or a broken connection. Reads
//! (status, health, catalog, get request) are also repeated after those.

use std::time::Duration;

use cerberus_types::wire::{
    AccessRequestStatus, AccessRequestView, CatalogPage, CreateAccessRequest, CreateItemRequest,
    CreateSessionRequest, CreatedItem, ErrorResponse, HealthResponse, PendingResponse,
    ReleaseResponse, ResolveRequest, ResolveResponse, RevealRequest, SecretResponse,
    SshPrepareRequest, SshPrepareResponse, StatusResponse, TotpRequest, TotpResponse,
};
use cerberus_types::{AccessRequestId, ItemId, LeaseId};
use hyper::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::config::ClientConfig;
use crate::error::{ApiError, ClientError};
use crate::sse::RequestEvents;
use crate::transport::{PinnedHttps, Request};

/// Longest response body the SDK reads.
const MAX_BODY: usize = 8 << 20;
/// Poll interval of [`Client::wait_request`] when the event stream is not available.
const POLL_EVERY: Duration = Duration::from_secs(2);

/// When to repeat a failed call.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Total tries, including the first. `1` turns retries off.
    pub max_attempts: u32,
    /// Wait before the second try. It doubles for each later try.
    pub base_delay: Duration,
    /// Longest wait between two tries, also the cap on a server `Retry-After`.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(4),
        }
    }
}

impl RetryPolicy {
    /// No retries.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    fn delay(&self, attempt: u32, error: &ClientError) -> Duration {
        let server = error
            .api()
            .and_then(ApiError::retry_after_seconds)
            .map(|s| Duration::from_secs(u64::from(s)));
        let backoff = self
            .base_delay
            .saturating_mul(1u32 << attempt.saturating_sub(1).min(16));
        server.unwrap_or(backoff).min(self.max_delay)
    }
}

/// Query of [`Client::catalog`].
#[derive(Clone, Debug, Default)]
pub struct CatalogQuery {
    /// Workspace slug.
    pub workspace: Option<String>,
    /// Environment name (`dev`, `staging`, `prod`, `other`).
    pub environment: Option<String>,
    /// Item kind name (`web_login`, ...).
    pub kind: Option<String>,
    /// Tag.
    pub tag: Option<String>,
    /// Words to match.
    pub q: Option<String>,
    /// Page size, 1 to 500.
    pub limit: Option<u32>,
    /// Cursor from the previous page.
    pub cursor: Option<String>,
}

impl CatalogQuery {
    fn to_path(&self) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        let limit = self.limit.map(|l| l.to_string());
        for (name, value) in [
            ("workspace", self.workspace.as_deref()),
            ("environment", self.environment.as_deref()),
            ("kind", self.kind.as_deref()),
            ("tag", self.tag.as_deref()),
            ("q", self.q.as_deref()),
            ("limit", limit.as_deref()),
            ("cursor", self.cursor.as_deref()),
        ] {
            if let Some(value) = value {
                form.append_pair(name, value);
            }
        }
        let query = form.finish();
        if query.is_empty() {
            "/v1/credentials".to_owned()
        } else {
            format!("/v1/credentials?{query}")
        }
    }
}

/// Answer of reveal: the secret, or a pending approval.
#[derive(Debug)]
pub enum RevealResult {
    /// The secret and its lease.
    Secret(Box<SecretResponse>),
    /// A person must approve first. Wait with [`Client::wait_request`], then reveal again with
    /// the lease from the approved request.
    Pending(PendingResponse),
}

/// Answer of TOTP: the code, or a pending approval.
#[derive(Debug)]
pub enum TotpResult {
    /// The current code and its lease.
    Code(Box<TotpResponse>),
    /// A person must approve first.
    Pending(PendingResponse),
}

/// Answer of ssh-prepare: ready, or a pending approval.
#[derive(Debug)]
pub enum SshResult {
    /// The signing socket is ready.
    Ready(Box<SshPrepareResponse>),
    /// A person must approve first.
    Pending(PendingResponse),
}

/// What a call may have done on the server. It decides which transport errors allow a retry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Reads only. Safe to repeat after any error.
    Read,
    /// May be counted, logged or stored by the server.
    Counted,
}

struct Reply {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}

impl Reply {
    fn json<T: DeserializeOwned>(&self) -> Result<T, ClientError> {
        serde_json::from_slice(&self.body)
            .map_err(|_| ClientError::Decode("the body does not match the API".to_owned()))
    }
}

/// The agent API client. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Client {
    http: PinnedHttps,
    retry: RetryPolicy,
}

impl Client {
    /// Builds a client with the default retry policy.
    ///
    /// # Errors
    /// [`ClientError::Config`] or [`ClientError::PinMismatch`] (see [`PinnedHttps::from_config`]).
    pub fn new(config: &ClientConfig) -> Result<Self, ClientError> {
        Ok(Self {
            http: PinnedHttps::from_config(config)?,
            retry: RetryPolicy::default(),
        })
    }

    /// The same client with another retry policy.
    #[must_use]
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// The low-level transport of this client.
    #[must_use]
    pub fn transport(&self) -> &PinnedHttps {
        &self.http
    }

    /// `GET /v1/health`. Needs no token scope and works while the vault is locked.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn health(&self) -> Result<HealthResponse, ClientError> {
        self.get("/v1/health").await?.json()
    }

    /// `GET /v1/status`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn status(&self) -> Result<StatusResponse, ClientError> {
        self.get("/v1/status").await?.json()
    }

    /// `POST /v1/credentials/resolve`.
    ///
    /// # Errors
    /// [`ClientError`], for example `no_match` (404).
    pub async fn resolve(&self, req: &ResolveRequest) -> Result<ResolveResponse, ClientError> {
        self.post("/v1/credentials/resolve", req, Effect::Counted)
            .await?
            .json()
    }

    /// `GET /v1/credentials`. Metadata only.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn catalog(&self, query: &CatalogQuery) -> Result<CatalogPage, ClientError> {
        self.get(&query.to_path()).await?.json()
    }

    /// `POST /v1/credentials/{id}/reveal`. Never repeated after a timeout (it may be counted).
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn reveal(
        &self,
        id: ItemId,
        req: &RevealRequest,
    ) -> Result<RevealResult, ClientError> {
        let reply = self
            .post(
                &format!("/v1/credentials/{id}/reveal"),
                req,
                Effect::Counted,
            )
            .await?;
        if reply.status == 202 {
            Ok(RevealResult::Pending(reply.json()?))
        } else {
            Ok(RevealResult::Secret(Box::new(reply.json()?)))
        }
    }

    /// `POST /v1/credentials/{id}/totp`. Never repeated after a timeout.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn totp(&self, id: ItemId, req: &TotpRequest) -> Result<TotpResult, ClientError> {
        let reply = self
            .post(&format!("/v1/credentials/{id}/totp"), req, Effect::Counted)
            .await?;
        if reply.status == 202 {
            Ok(TotpResult::Pending(reply.json()?))
        } else {
            Ok(TotpResult::Code(Box::new(reply.json()?)))
        }
    }

    /// `POST /v1/credentials`. Never repeated after a timeout.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn create_item(&self, req: &CreateItemRequest) -> Result<CreatedItem, ClientError> {
        self.post("/v1/credentials", req, Effect::Counted)
            .await?
            .json()
    }

    /// `POST /v1/sessions`. Never repeated after a timeout.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn create_session(
        &self,
        req: &CreateSessionRequest,
    ) -> Result<CreatedItem, ClientError> {
        self.post("/v1/sessions", req, Effect::Counted)
            .await?
            .json()
    }

    /// `DELETE /v1/credentials/{id}`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn delete_item(&self, id: ItemId) -> Result<(), ClientError> {
        self.call(
            Method::DELETE,
            &format!("/v1/credentials/{id}"),
            None,
            Effect::Counted,
        )
        .await
        .map(|_| ())
    }

    /// `POST /v1/requests`: ask a person for access before the secret is needed.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn request_access(
        &self,
        req: &CreateAccessRequest,
    ) -> Result<AccessRequestView, ClientError> {
        self.post("/v1/requests", req, Effect::Counted)
            .await?
            .json()
    }

    /// `GET /v1/requests/{id}`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn get_request(&self, id: AccessRequestId) -> Result<AccessRequestView, ClientError> {
        self.get(&format!("/v1/requests/{id}")).await?.json()
    }

    /// `GET /v1/requests/{id}/events`: opens the event stream.
    ///
    /// # Errors
    /// [`ClientError`] before the stream starts (for example `404`).
    pub async fn watch_request(&self, id: AccessRequestId) -> Result<RequestEvents, ClientError> {
        let path = format!("/v1/requests/{id}/events");
        let response = self
            .with_retry_loop(Effect::Read, || async {
                let mut request = Request::get(&path);
                request.headers.push(("accept", "text/event-stream"));
                let response = self.http.send(request).await?;
                if response.status() >= 400 {
                    let status = response.status();
                    let body = Zeroizing::new(response.bytes(MAX_BODY).await?);
                    return Err(api_error(status, &body));
                }
                Ok(response)
            })
            .await?;
        Ok(RequestEvents::new(response))
    }

    /// Waits until the request leaves `pending`, for at most `max`. It reads the event stream and
    /// falls back to polling every 2 s. When `max` passes, it returns the current view, which
    /// may still be `pending`.
    ///
    /// # Errors
    /// [`ClientError`] from the server (for example `404`).
    pub async fn wait_request(
        &self,
        id: AccessRequestId,
        max: Duration,
    ) -> Result<AccessRequestView, ClientError> {
        let waiting = async {
            if let Ok(mut events) = self.watch_request(id).await {
                while let Some(event) = events.next().await {
                    match event {
                        Ok(view) if view.status != AccessRequestStatus::Pending => {
                            return Ok(view);
                        }
                        Ok(_) => {}
                        Err(ClientError::Api(error)) => return Err(ClientError::Api(error)),
                        Err(_) => break,
                    }
                }
            }
            loop {
                let view = self.get_request(id).await?;
                if view.status != AccessRequestStatus::Pending {
                    return Ok(view);
                }
                tokio::time::sleep(POLL_EVERY).await;
            }
        };
        match tokio::time::timeout(max, waiting).await {
            Ok(result) => result,
            Err(_) => self.get_request(id).await,
        }
    }

    /// `POST /v1/leases/{id}/release`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn release_lease(&self, id: LeaseId) -> Result<ReleaseResponse, ClientError> {
        self.call(
            Method::POST,
            &format!("/v1/leases/{id}/release"),
            Some(b"{}".to_vec()),
            Effect::Counted,
        )
        .await?
        .json()
    }

    /// `POST /v1/credentials/{id}/ssh-prepare`.
    ///
    /// # Errors
    /// [`ClientError`].
    pub async fn ssh_prepare(
        &self,
        id: ItemId,
        req: &SshPrepareRequest,
    ) -> Result<SshResult, ClientError> {
        let reply = self
            .post(
                &format!("/v1/credentials/{id}/ssh-prepare"),
                req,
                Effect::Counted,
            )
            .await?;
        if reply.status == 202 {
            Ok(SshResult::Pending(reply.json()?))
        } else {
            Ok(SshResult::Ready(Box::new(reply.json()?)))
        }
    }

    async fn get(&self, path: &str) -> Result<Reply, ClientError> {
        self.call(Method::GET, path, None, Effect::Read).await
    }

    async fn post(
        &self,
        path: &str,
        body: &impl Serialize,
        effect: Effect,
    ) -> Result<Reply, ClientError> {
        let body = serde_json::to_vec(body)
            .map_err(|_| ClientError::Config("the request cannot be encoded".to_owned()))?;
        self.call(Method::POST, path, Some(body), effect).await
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        effect: Effect,
    ) -> Result<Reply, ClientError> {
        self.with_retry_loop(effect, || async {
            let request = Request {
                method: method.clone(),
                path,
                headers: Vec::new(),
                body: body.as_deref().map(bytes::Bytes::copy_from_slice),
            };
            let response = self.http.send(request).await?;
            let status = response.status();
            let body = Zeroizing::new(response.bytes(MAX_BODY).await?);
            if status >= 400 {
                return Err(api_error(status, &body));
            }
            Ok(Reply { status, body })
        })
        .await
    }

    async fn with_retry_loop<T, F, Fut>(
        &self,
        effect: Effect,
        mut attempt: F,
    ) -> Result<T, ClientError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        let mut tries = 1;
        loop {
            match attempt().await {
                Ok(value) => return Ok(value),
                Err(error)
                    if tries < self.retry.max_attempts
                        && error.is_retryable(effect == Effect::Counted) =>
                {
                    tokio::time::sleep(self.retry.delay(tries, &error)).await;
                    tries += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Turns an error answer into [`ClientError::Api`].
fn api_error(status: u16, body: &[u8]) -> ClientError {
    match serde_json::from_slice::<ErrorResponse>(body) {
        Ok(parsed) => ClientError::Api(Box::new(ApiError::from_response(status, parsed))),
        Err(_) => ClientError::Decode(format!("HTTP {status} without an error object")),
    }
}
