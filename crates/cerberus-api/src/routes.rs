//! The `/v1` routes (docs/PLAN.md section 5.1 and `docs/api/openapi-draft.yaml`).
//!
//! Every handler gets the vault only through [`cerberus_core::AgentApi`] (ADR-0004). The token and
//! the lock are checked before the handler runs (see [`crate::layers`]), so a locked vault never
//! reads a body.

use std::str::FromStr;

use axum::Extension;
use axum::Router;
use axum::extract::{FromRequest, MatchedPath, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use cerberus_core::CoreError;
use cerberus_core::agent_api::{
    CatalogQuery, ResolveResult, RevealOutcome, TotpOutcome, routes as core_routes,
};
use cerberus_types::{AccessRequestId, AccessRequestStatus, ErrorCode, ItemId, LeaseId, RequestId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

use crate::config::AppState;
use crate::convert;
use crate::error::ApiError;
use crate::layers::{AgentCtx, ReqId, authenticate, locked_gate};
use crate::responses::{
    BadRequest, Conflict, Forbidden, Internal, Locked, NoMatch, NotFound, PayloadTooLarge,
    TooManyRequests, Unauthenticated, Unavailable, UnsupportedMediaType, ValidationFailed,
};
use crate::sse::stream_events;
use cerberus_types::wire::{
    AccessRequestView, CandidatesBody, CatalogPage, CreateAccessRequest, CreateItemRequest,
    CreateSessionRequest, CreatedItem, Environment, HealthResponse, ItemKind, PendingResponse,
    ReleaseResponse, ResolveRequest, ResolveResponse, RevealRequest, SecretResponse,
    SshPrepareRequest, SshPrepareResponse, StatusResponse, TotpRequest, TotpResponse,
};

/// The audit route name of `POST /v1/credentials/{id}/ssh-prepare`.
const SSH_PREPARE_ROUTE: &str = cerberus_core::agent_api::ssh::routes::PREPARE;

/// Seconds a client waits when every signing socket is in use.
const SSH_FULL_RETRY_SECONDS: u32 = 60;

const ALL_ROUTES: [&str; 13] = [
    core_routes::STATUS,
    core_routes::RESOLVE,
    core_routes::CATALOG,
    core_routes::CREATE_ITEM,
    core_routes::DELETE_ITEM,
    core_routes::REVEAL,
    core_routes::TOTP,
    SSH_PREPARE_ROUTE,
    core_routes::CREATE_SESSION,
    core_routes::REQUEST_ACCESS,
    core_routes::GET_REQUEST,
    core_routes::WAIT_REQUEST,
    core_routes::RELEASE_LEASE,
];

/// The route name (`"POST /v1/credentials/{id}/reveal"`) used in audit events, from the method and
/// the matched path.
#[must_use]
pub fn route_name(method: &str, matched: &str) -> Option<&'static str> {
    let wanted = format!("{method} {matched}");
    ALL_ROUTES.iter().copied().find(|name| *name == wanted)
}

/// The JSON body of a request. Checks `Content-Type` (415), reads at most the route limit (413) and
/// refuses unknown fields (400). The buffer is handed to the parser as is; it is not zeroized
/// (accepted: the agent sent the value, and TLS and hyper copy it anyway).
pub struct JsonBody<T>(pub T);

fn is_json(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

fn too_large(error: &axum::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if current.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        source = current.source();
    }
    false
}

impl<T: DeserializeOwned> FromRequest<AppState> for JsonBody<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, ApiError> {
        let id = req
            .extensions()
            .get::<ReqId>()
            .map_or_else(RequestId::generate, |r| r.0);
        if !is_json(&req) {
            return Err(ApiError::new(ErrorCode::UnsupportedMediaType, id));
        }
        let large = req
            .extensions()
            .get::<MatchedPath>()
            .is_some_and(|path| matches!(path.as_str(), "/v1/credentials" | "/v1/sessions"));
        let limits = state.limits();
        let limit = if large {
            limits.body_large_bytes
        } else {
            limits.body_default_bytes
        };
        let declared = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if declared.is_some_and(|len| len > limit) {
            return Err(ApiError::new(ErrorCode::PayloadTooLarge, id));
        }
        let read = tokio::time::timeout(
            limits.body_timeout,
            axum::body::to_bytes(req.into_body(), limit),
        )
        .await;
        let bytes = match read {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) if too_large(&error) => {
                return Err(ApiError::new(ErrorCode::PayloadTooLarge, id));
            }
            Ok(Err(_)) | Err(_) => return Err(ApiError::new(ErrorCode::InvalidRequest, id)),
        };
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, id))?;
        Ok(Self(value))
    }
}

fn parse_id<T: FromStr>(text: &str, id: RequestId) -> Result<T, ApiError> {
    text.parse()
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, id))
}

fn json<T: Serialize>(
    status: StatusCode,
    value: &T,
    id: RequestId,
    location: Option<String>,
) -> Result<Response, ApiError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ApiError::new(ErrorCode::Internal, id))?;
    let mut response = (status, bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(path) = location
        && let Ok(value) = HeaderValue::from_str(&path)
    {
        response.headers_mut().insert(header::LOCATION, value);
    }
    Ok(response)
}

fn core<T>(result: Result<T, CoreError>, id: RequestId) -> Result<T, ApiError> {
    result.map_err(|error| ApiError::from_core(error, id))
}

fn pending(result: cerberus_core::agent_api::PendingResult) -> Result<Response, ApiError> {
    let id = result.request_id;
    let location = format!("/v1/requests/{}", result.access_request.id);
    let body = convert::pending_response(result)?;
    json(StatusCode::ACCEPTED, &body, id, Some(location))
}

// ------------------------------------------------------------------------------------ handlers

/// `GET /health`: up, locked or unlocked. No auth.
#[utoipa::path(
    get, path = "/health", operation_id = "getHealth", tag = "service", security(()),
    responses(
        (status = 200, description = "The service runs.", body = HealthResponse),
        Forbidden, TooManyRequests, Unavailable
    )
)]
pub async fn health(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
) -> Result<Response, ApiError> {
    let vault = if state.core().state() == cerberus_types::VaultStateKind::Unlocked {
        "unlocked"
    } else {
        "locked"
    };
    let body = HealthResponse {
        status: "ok".into(),
        vault: vault.into(),
        version: env!("CARGO_PKG_VERSION").into(),
    };
    json(StatusCode::OK, &body, id, None)
}

/// `GET /status`.
#[utoipa::path(
    get, path = "/status", operation_id = "getStatus", tag = "service",
    responses(
        (status = 200, description = "Status of the vault and the caller.", body = StatusResponse),
        Unauthenticated, Forbidden, Locked, TooManyRequests, Internal
    )
)]
pub async fn status(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
) -> Result<Response, ApiError> {
    let view = core(state.agent_api().status(&ctx).await, id)?;
    json(StatusCode::OK, &convert::status_response(view), id, None)
}

/// `POST /credentials/resolve`.
#[utoipa::path(
    post, path = "/credentials/resolve", operation_id = "resolveCredential", tag = "credentials",
    request_body = ResolveRequest,
    responses(
        (status = 200, description = "A secret, or candidates (no secret).", body = ResolveResponse),
        (status = 202, description = "Approval needed. Poll or stream the access request, then call reveal.", body = ResolveResponse),
        BadRequest, Unauthenticated, Forbidden, NoMatch, PayloadTooLarge, UnsupportedMediaType,
        ValidationFailed, Locked, TooManyRequests, Internal
    )
)]
pub async fn resolve(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    JsonBody(body): JsonBody<ResolveRequest>,
) -> Result<Response, ApiError> {
    let result = core(
        state
            .agent_api()
            .resolve(&ctx, convert::resolve_input(body))
            .await,
        id,
    )?;
    match result {
        ResolveResult::Secret(secret) => {
            let body = ResolveResponse::Secret(Box::new(convert::secret_response(*secret)?));
            json(StatusCode::OK, &body, id, None)
        }
        ResolveResult::Pending(result) => {
            let location = format!("/v1/requests/{}", result.access_request.id);
            let body = ResolveResponse::Pending(convert::pending_response(result)?);
            json(StatusCode::ACCEPTED, &body, id, Some(location))
        }
        ResolveResult::Candidates(list) => {
            let body = ResolveResponse::Candidates(candidates(list));
            json(StatusCode::OK, &body, id, None)
        }
        ResolveResult::Ambiguous(list) => {
            let body = ResolveResponse::Ambiguous(candidates(list));
            json(StatusCode::OK, &body, id, None)
        }
    }
}

fn candidates(list: Vec<cerberus_core::resolve::Candidate>) -> CandidatesBody {
    CandidatesBody {
        candidates: list.into_iter().map(convert::candidate).collect(),
    }
}

/// Query of `GET /credentials`.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct CatalogParams {
    /// Workspace slug.
    workspace: Option<String>,
    /// Environment.
    environment: Option<Environment>,
    /// Item kind.
    kind: Option<ItemKind>,
    /// Tag.
    tag: Option<String>,
    /// Words to match in title, description, tags, target.
    q: Option<String>,
    /// Page size, 1 to 500 (default 100).
    limit: Option<u32>,
    /// Opaque cursor from `next_cursor`.
    cursor: Option<String>,
}

/// `GET /credentials`: the catalog. Metadata only.
#[utoipa::path(
    get, path = "/credentials", operation_id = "listCredentials", tag = "credentials",
    params(CatalogParams),
    responses(
        (status = 200, description = "One page of item metadata.", body = CatalogPage),
        BadRequest, Unauthenticated, Forbidden, Locked, TooManyRequests, Internal
    )
)]
pub async fn catalog(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    uri: Uri,
) -> Result<Response, ApiError> {
    let params = axum::extract::Query::<CatalogParams>::try_from_uri(&uri)
        .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, id))?
        .0;
    let query = CatalogQuery {
        workspace: params.workspace,
        environment: params.environment.map(Into::into),
        kind: params.kind.map(Into::into),
        tag: params.tag,
        q: params.q,
        limit: params.limit,
        cursor: params.cursor,
    };
    let page = core(state.agent_api().catalog(&ctx, query).await, id)?;
    json(StatusCode::OK, &convert::catalog_page(page), id, None)
}

/// `POST /credentials`: the agent creates an item.
#[utoipa::path(
    post, path = "/credentials", operation_id = "createCredential", tag = "credentials",
    request_body = CreateItemRequest,
    responses(
        (status = 201, description = "Item created. The response holds metadata only.", body = CreatedItem),
        BadRequest, Unauthenticated, Forbidden, NotFound, Conflict, PayloadTooLarge,
        UnsupportedMediaType, ValidationFailed, Locked, TooManyRequests, Internal
    )
)]
pub async fn create_item(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    JsonBody(body): JsonBody<CreateItemRequest>,
) -> Result<Response, ApiError> {
    let input = core(convert::create_item_input(body), id)?;
    let created = core(state.agent_api().create_item(&ctx, input).await, id)?;
    created_response(created, id)
}

fn created_response(
    created: cerberus_core::agent_api::CreatedItem,
    id: RequestId,
) -> Result<Response, ApiError> {
    let location = format!("/v1/credentials/{}", created.item.id);
    json(
        StatusCode::CREATED,
        &convert::created_item(created),
        id,
        Some(location),
    )
}

/// `DELETE /credentials/{id}`: delete an item this agent created.
#[utoipa::path(
    delete, path = "/credentials/{id}", operation_id = "deleteCredential", tag = "credentials",
    params(("id" = Uuid, Path, description = "Item ID.")),
    responses(
        (status = 204, description = "Deleted."),
        BadRequest, Unauthenticated, Forbidden, NotFound, Locked, TooManyRequests, Internal
    )
)]
pub async fn delete_item(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let item: ItemId = parse_id(&raw, id)?;
    core(state.agent_api().delete_item(&ctx, item).await, id)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /credentials/{id}/reveal`.
#[utoipa::path(
    post, path = "/credentials/{id}/reveal", operation_id = "revealCredential", tag = "credentials",
    params(("id" = Uuid, Path, description = "Item ID.")),
    request_body = RevealRequest,
    responses(
        (status = 200, description = "The secret.", body = SecretResponse),
        (status = 202, description = "Approval needed.", body = PendingResponse),
        BadRequest, Unauthenticated, Forbidden, NotFound, UnsupportedMediaType, ValidationFailed,
        Locked, TooManyRequests, Internal
    )
)]
pub async fn reveal(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
    JsonBody(body): JsonBody<RevealRequest>,
) -> Result<Response, ApiError> {
    let item: ItemId = parse_id(&raw, id)?;
    match core(
        state
            .agent_api()
            .reveal(&ctx, item, convert::reveal_input(body))
            .await,
        id,
    )? {
        RevealOutcome::Secret(secret) => json(
            StatusCode::OK,
            &convert::secret_response(*secret)?,
            id,
            None,
        ),
        RevealOutcome::Pending(result) => pending(result),
    }
}

/// `POST /credentials/{id}/totp`.
#[utoipa::path(
    post, path = "/credentials/{id}/totp", operation_id = "getTotpCode", tag = "credentials",
    params(("id" = Uuid, Path, description = "Item ID.")),
    request_body = TotpRequest,
    responses(
        (status = 200, description = "The current code.", body = TotpResponse),
        (status = 202, description = "Approval needed.", body = PendingResponse),
        BadRequest, Unauthenticated, Forbidden, NotFound, UnsupportedMediaType, ValidationFailed,
        Locked, TooManyRequests, Internal
    )
)]
pub async fn totp(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
    JsonBody(body): JsonBody<TotpRequest>,
) -> Result<Response, ApiError> {
    let item: ItemId = parse_id(&raw, id)?;
    match core(
        state
            .agent_api()
            .totp(&ctx, item, convert::totp_input(body))
            .await,
        id,
    )? {
        TotpOutcome::Code(code) => json(StatusCode::OK, &convert::totp_response(*code)?, id, None),
        TotpOutcome::Pending(result) => pending(result),
    }
}

/// The answer of [`prepare_ssh`]: what REST and MCP `ssh_prepare` send.
#[derive(Debug)]
pub enum SshPrepared {
    /// The signing socket is ready (`200`).
    Ready(SshPrepareResponse),
    /// A person must approve first (`202`). Core form, so MCP can wait on the request.
    Pending(cerberus_core::agent_api::PendingResult),
}

/// The ssh-agent bridge error as an API error. Socket and directory errors are logged here and
/// sent as `internal`.
fn bridge_error(error: cerberus_ssh_agent::BridgeError, id: RequestId) -> ApiError {
    use cerberus_ssh_agent::BridgeError;
    match error {
        BridgeError::Core(error) => ApiError::from_core(error, id),
        BridgeError::Full => {
            ApiError::new(ErrorCode::RateLimited, id).with_retry_after(SSH_FULL_RETRY_SECONDS)
        }
        BridgeError::Unsupported => ApiError::new(ErrorCode::Unavailable, id),
        error @ (BridgeError::PathTooLong | BridgeError::Io(_)) => {
            tracing::warn!(%error, "ssh-agent socket could not be opened");
            ApiError::new(ErrorCode::Internal, id)
        }
    }
}

/// `ssh-prepare` for REST and MCP: the Agent API checks (scope `ssh:use`, policy `use_ssh`,
/// lease or approval), then the signing socket of the lease on the shared bridge of `core`
/// ([`AppState`] holds it, T22). The private key stays in core; the answer has the socket path,
/// the public key and the host facts only.
///
/// # Errors
/// The [`ApiError`] of the refusal.
pub async fn prepare_ssh(
    core: &cerberus_core::VaultService,
    ctx: &cerberus_core::AgentContext,
    item: ItemId,
    body: SshPrepareRequest,
) -> Result<SshPrepared, ApiError> {
    let id = ctx.request_id;
    let outcome = cerberus_ssh_agent::SshBridge::shared(core)
        .prepare(ctx, item, convert::ssh_prepare_input(body))
        .await
        .map_err(|error| bridge_error(error, id))?;
    match outcome {
        cerberus_ssh_agent::PrepareOutcome::Ready(ready) => {
            Ok(SshPrepared::Ready(convert::ssh_prepare_response(*ready)?))
        }
        cerberus_ssh_agent::PrepareOutcome::Pending(pending) => Ok(SshPrepared::Pending(pending)),
    }
}

/// `POST /credentials/{id}/ssh-prepare`: opens an ssh-agent signing socket for an `ssh_key` item.
#[utoipa::path(
    post, path = "/credentials/{id}/ssh-prepare", operation_id = "prepareSshAgent", tag = "credentials",
    params(("id" = Uuid, Path, description = "Item ID.")),
    request_body = SshPrepareRequest,
    responses(
        (status = 200, description = "Socket ready.", body = SshPrepareResponse),
        (status = 202, description = "Approval needed.", body = PendingResponse),
        BadRequest, Unauthenticated, Forbidden, NotFound, UnsupportedMediaType, ValidationFailed,
        Locked, TooManyRequests, Internal, Unavailable
    )
)]
pub async fn ssh_prepare(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
    JsonBody(body): JsonBody<SshPrepareRequest>,
) -> Result<Response, ApiError> {
    let item: ItemId = parse_id(&raw, id)?;
    match prepare_ssh(state.core(), &ctx, item, body).await? {
        SshPrepared::Ready(ready) => json(StatusCode::OK, &ready, id, None),
        SshPrepared::Pending(result) => pending(result),
    }
}

/// `POST /sessions`.
#[utoipa::path(
    post, path = "/sessions", operation_id = "createSession", tag = "sessions",
    request_body = CreateSessionRequest,
    responses(
        (status = 201, description = "Session item created (metadata only).", body = CreatedItem),
        BadRequest, Unauthenticated, Forbidden, NotFound, Conflict, PayloadTooLarge,
        UnsupportedMediaType, ValidationFailed, Locked, TooManyRequests, Internal
    )
)]
pub async fn create_session(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    JsonBody(body): JsonBody<CreateSessionRequest>,
) -> Result<Response, ApiError> {
    let created = core(
        state
            .agent_api()
            .create_session(&ctx, convert::create_session_input(body))
            .await,
        id,
    )?;
    created_response(created, id)
}

/// `POST /requests`: ask a person for access ahead.
#[utoipa::path(
    post, path = "/requests", operation_id = "createAccessRequest", tag = "approvals",
    request_body = CreateAccessRequest,
    responses(
        (status = 200, description = "Already approved (an active lease exists), or mode `auto` gave a lease at once.", body = AccessRequestView),
        (status = 202, description = "Request pending.", body = AccessRequestView),
        BadRequest, Unauthenticated, Forbidden, NotFound, UnsupportedMediaType, ValidationFailed,
        Locked, TooManyRequests, Internal
    )
)]
pub async fn create_request(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    JsonBody(body): JsonBody<CreateAccessRequest>,
) -> Result<Response, ApiError> {
    let view = core(
        state
            .agent_api()
            .request_access(&ctx, convert::create_access_input(body))
            .await,
        id,
    )?;
    let status = if view.status == AccessRequestStatus::Pending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    let location = format!("/v1/requests/{}", view.id);
    json(
        status,
        &convert::access_request_view(view, id)?,
        id,
        Some(location),
    )
}

/// `GET /requests/{id}`: poll an approval.
#[utoipa::path(
    get, path = "/requests/{id}", operation_id = "getAccessRequest", tag = "approvals",
    params(("id" = Uuid, Path, description = "Access request ID.")),
    responses(
        (status = 200, description = "Current state of the request.", body = AccessRequestView),
        BadRequest, Unauthenticated, Forbidden, NotFound, Locked, TooManyRequests, Internal
    )
)]
pub async fn get_request(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let request: AccessRequestId = parse_id(&raw, id)?;
    let view = core(
        state.agent_api().get_access_request(&ctx, request).await,
        id,
    )?;
    json(
        StatusCode::OK,
        &convert::access_request_view(view, id)?,
        id,
        None,
    )
}

/// `GET /requests/{id}/events`: SSE stream of state changes. Each event is
/// `event: status`, `id: <counter>`, `data: <AccessRequestView JSON>`.
#[utoipa::path(
    get, path = "/requests/{id}/events", operation_id = "streamAccessRequest", tag = "approvals",
    params(("id" = Uuid, Path, description = "Access request ID.")),
    responses(
        (status = 200, description = "Event stream. Each `data` line is an `AccessRequestView` JSON object.", content_type = "text/event-stream", body = String),
        BadRequest, Unauthenticated, Forbidden, NotFound, Locked, TooManyRequests, Internal
    )
)]
pub async fn request_events(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let request: AccessRequestId = parse_id(&raw, id)?;
    let api = state.agent_api();
    let first = core(api.get_access_request(&ctx, request).await, id)?;
    Ok(stream_events(api, ctx, request, first, state.shutdown_signal()).into_response())
}

/// `POST /leases/{id}/release`.
#[utoipa::path(
    post, path = "/leases/{id}/release", operation_id = "releaseLease", tag = "leases",
    params(("id" = Uuid, Path, description = "Lease ID.")),
    responses(
        (status = 200, description = "Released.", body = ReleaseResponse),
        BadRequest, Unauthenticated, Forbidden, NotFound, Conflict, Locked, TooManyRequests, Internal
    )
)]
pub async fn release_lease(
    State(state): State<AppState>,
    Extension(ReqId(id)): Extension<ReqId>,
    Extension(AgentCtx(ctx)): Extension<AgentCtx>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let lease: LeaseId = parse_id(&raw, id)?;
    let outcome = core(state.agent_api().release_lease(&ctx, lease).await, id)?;
    json(
        StatusCode::OK,
        &convert::release_response(outcome),
        id,
        None,
    )
}

async fn not_found(Extension(ReqId(id)): Extension<ReqId>) -> ApiError {
    ApiError::new(ErrorCode::RouteNotFound, id)
}

async fn method_not_allowed(Extension(ReqId(id)): Extension<ReqId>) -> ApiError {
    ApiError::new(ErrorCode::MethodNotAllowed, id)
}

/// The router of `/v1` and the fallbacks, without the outer layers. `GET /v1/health` is open; every
/// other route runs [`authenticate`] and then [`locked_gate`].
pub(crate) fn v1(state: &AppState) -> Router<AppState> {
    let protected = Router::new()
        .route("/status", get(status))
        .route("/credentials/resolve", post(resolve))
        .route("/credentials", get(catalog).post(create_item))
        .route("/credentials/{id}", delete(delete_item))
        .route("/credentials/{id}/reveal", post(reveal))
        .route("/credentials/{id}/totp", post(totp))
        .route("/credentials/{id}/ssh-prepare", post(ssh_prepare))
        .route("/sessions", post(create_session))
        .route("/requests", post(create_request))
        .route("/requests/{id}", get(get_request))
        .route("/requests/{id}/events", get(request_events))
        .route("/leases/{id}/release", post(release_lease))
        .route_layer(middleware::from_fn_with_state(state.clone(), locked_gate))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let open = Router::new().route("/health", get(health));
    Router::new().nest("/v1", open.merge(protected))
}

/// The fallbacks for unknown paths and wrong methods (`404 route_not_found`, `405 method_not_allowed`).
pub(crate) fn with_fallbacks(router: Router<AppState>) -> Router<AppState> {
    router
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
}
