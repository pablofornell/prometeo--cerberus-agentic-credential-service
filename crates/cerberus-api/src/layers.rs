//! Middleware: request ID and headers, Host and Origin checks, token auth, lock gate (ADR-0008,
//! ADR-0015, ADR-0016, ADR-0023, ADR-0032).

use std::net::SocketAddr;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cerberus_core::auth::{AuthFailure, TokenCheckInput};
use cerberus_core::{AgentContext, CoreError, Surface};
use cerberus_types::{AgentId, ErrorCode, RequestId, Stopwatch, VaultStateKind};
use zeroize::Zeroizing;

use crate::config::AppState;
use crate::error::ApiError;
use crate::idle::{ConnActivity, hold_until_sent};

/// The request ID of this call. Set by [`envelope`] on every request (ADR-0015).
#[derive(Clone, Copy, Debug)]
pub struct ReqId(pub RequestId);

/// The authenticated agent. Set by [`authenticate`].
#[derive(Clone, Debug)]
pub struct AgentCtx(pub AgentContext);

/// What the listener knows about the connection. The server sets it on every request.
#[derive(Clone, Copy, Debug)]
pub struct ConnInfo {
    /// The peer address.
    pub peer: SocketAddr,
    /// SHA-256 of the client certificate, when the peer sent one that verified.
    pub client_cert_sha256: Option<[u8; 32]>,
}

/// Response extension that tells the log layer which agent made the call.
#[derive(Clone, Copy, Debug)]
struct AgentMark(AgentId);

const CSP: &str = "default-src 'none'; frame-ancestors 'none'";

fn request_id_of(req: &Request) -> RequestId {
    req.extensions()
        .get::<ReqId>()
        .map_or_else(RequestId::generate, |id| id.0)
}

/// Makes the request ID, runs the call, adds the security headers and `X-Request-Id`, and logs
/// method, route template, status, latency, request ID and agent (never headers, query or body).
pub async fn envelope(mut req: Request, next: Next) -> Response {
    let id = RequestId::generate();
    req.extensions_mut().insert(ReqId(id));
    let clock = Stopwatch::start();
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::PRAGMA, "no-cache"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CONTENT_SECURITY_POLICY, CSP),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
        headers.insert(HeaderName::from_static("x-request-id"), value);
    }
    let agent = response.extensions().get::<AgentMark>().map(|mark| mark.0);
    tracing::info!(
        %method,
        route = %route,
        status = response.status().as_u16(),
        latency_ms = u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX),
        request_id = %id,
        agent = agent.map(|a| a.to_string()).as_deref().unwrap_or("-"),
        "request"
    );
    response
}

/// The host part of a `Host` value: lower-case, without port. Handles `[::1]:7373`.
fn host_only(value: &str) -> String {
    let value = value.trim();
    let host = if let Some(rest) = value.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        value.split(':').next().unwrap_or(value)
    };
    host.to_ascii_lowercase()
}

fn host_of(req: &Request) -> Option<String> {
    if let Some(value) = req.headers().get(header::HOST) {
        return value.to_str().ok().map(host_only);
    }
    req.uri().authority().map(|a| host_only(a.as_str()))
}

/// Refuses a request with an `Origin` header, a `Sec-Fetch-Site` other than `none`, or a `Host`
/// that is not a leaf name (ADR-0023 HTTP rules 1 and 2). This blocks browsers and DNS rebinding.
pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let browser = headers.contains_key(header::ORIGIN)
        || headers
            .get("sec-fetch-site")
            .is_some_and(|value| value.as_bytes() != b"none");
    let host_ok = host_of(&req).is_some_and(|host| state.host_allowed(&host));
    if browser || !host_ok {
        return ApiError::new(ErrorCode::OriginRefused, request_id_of(&req)).into_response();
    }
    next.run(req).await
}

fn bearer_token(headers: &HeaderMap) -> Zeroizing<String> {
    let text = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(char::is_whitespace))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_owned())
        .unwrap_or_default();
    Zeroizing::new(text)
}

/// Checks the bearer token with core (`auth().check`: credential, agent limit, and for failed
/// checks the source limits and lockout) and puts the [`AgentCtx`] on the request. Every credential
/// failure is the same `401`. After the call it counts as agent activity (ADR-0026). A passed check
/// also binds the connection to the agent (at most `max_connections_per_agent`, NEW-6) and marks it
/// as authenticated, and the connection counts as busy until the response is fully sent (AUD-4).
/// Use it on `/v1` routes and on `/mcp` (through [`crate::agent_layers`]).
pub async fn authenticate(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let id = request_id_of(&req);
    let Some(conn) = req.extensions().get::<ConnInfo>().copied() else {
        return ApiError::new(ErrorCode::Internal, id).into_response();
    };
    let surface = if req.uri().path().starts_with("/mcp") {
        Surface::Mcp
    } else {
        Surface::Rest
    };
    let token = bearer_token(req.headers());
    let now = state.core().clock().now();
    let input = TokenCheckInput {
        raw_token: &token,
        source_ip: conn.peer.ip(),
        client_cert_sha256: conn.client_cert_sha256,
        request_id: id,
        surface,
    };
    match state.core().auth().check_refusal(&input, now) {
        Ok(ctx) => {
            let conn_activity = req
                .extensions()
                .get::<ConnActivity>()
                .map(|conn| std::sync::Arc::clone(&conn.0));
            // One agent may hold only so many authenticated connections (NEW-6). A further one is
            // refused here and stays unauthenticated, so the normal deadlines and eviction apply.
            if let Some(activity) = &conn_activity
                && !state.owners().bind(activity, ctx.agent_id, ctx.key_id)
            {
                if state.warn_due(conn.peer.ip(), now.as_millisecond()) {
                    tracing::warn!(agent = %ctx.agent_id, "agent connection limit reached");
                }
                let limited = CoreError::RateLimited {
                    retry_after_seconds: 1,
                };
                return ApiError::from_core(limited, id).into_response();
            }
            let running = conn_activity.map(|activity| activity.authenticated());
            req.extensions_mut().insert(AgentCtx(ctx.clone()));
            let mut response = next.run(req).await;
            state.core().note_agent_activity(&ctx);
            response.extensions_mut().insert(AgentMark(ctx.agent_id));
            match running {
                Some(running) => hold_until_sent(response, running),
                None => response,
            }
        }
        Err(refusal) => {
            warn_refused(&state, conn.peer, refusal.failure, now.as_millisecond());
            // Core writes `auth.failed`, at most once per source and class per minute, with the
            // reason under a lockout (DEC-FIX7-11, NEW-8).
            state
                .core()
                .audit_auth_failure(conn.peer.ip(), refusal, id, surface)
                .await;
            ApiError::from_core(refusal.failure.outward(), id).into_response()
        }
    }
}

fn warn_refused(state: &AppState, peer: SocketAddr, failure: AuthFailure, now_ms: i64) {
    if state.warn_due(peer.ip(), now_ms) {
        tracing::warn!(ip = %peer.ip(), reason = failure.reason(), "agent token refused");
    }
}

/// Every `/v1` route when the vault is not unlocked: `423 vault_locked`, no data (ADR-0008). The call
/// is audited through core (`api.locked_call`). Runs after [`authenticate`], so a bad token is `401`.
pub async fn locked_gate(
    State(state): State<AppState>,
    axum::Extension(ReqId(id)): axum::Extension<ReqId>,
    axum::Extension(AgentCtx(ctx)): axum::Extension<AgentCtx>,
    req: Request,
    next: Next,
) -> Response {
    if state.core().state() == VaultStateKind::Unlocked {
        return next.run(req).await;
    }
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .and_then(|path| crate::routes::route_name(req.method().as_str(), path.as_str()));
    if let Some(route) = route {
        state
            .core()
            .audit_locked_call(Some(&ctx), route, ErrorCode::VaultLocked)
            .await;
    }
    ApiError::new(ErrorCode::VaultLocked, id).into_response()
}
