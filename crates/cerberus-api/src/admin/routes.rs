//! The five admin routes (ADR-0034 point 5). They are not in the agent OpenAPI document; the
//! route-list test of `tests/admin.rs` fixes them.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use cerberus_admin::dto::{SessionView, VaultState};
use cerberus_admin::error::IpcError;
use cerberus_admin::events::from_core;
use cerberus_admin::remote::{ADMIN_PROTOCOL, Gate, REMOTE_COMMANDS, counts_as_activity, gate};
use cerberus_admin::rpc::{self, VaultUnlockArgs};
use cerberus_admin::wire::{
    EVENTS_PATH, HELLO_PATH, HelloView, RPC_PREFIX, SESSION_PATH, SessionOpenedView,
};
use cerberus_core::{
    AdminAudit, AdminEventKind, CoreError, CoreEvent, KeyCustody, OperatorContext, VaultService,
};
use cerberus_types::{OperatorId, RequestId, VaultStateKind};
use futures_util::{Stream, stream};
use http_body_util::BodyExt;
use tokio::sync::{broadcast, watch};
use zeroize::Zeroizing;

use super::errors::AdminError;
use super::layers::{
    Device, bind_connection, request_id, require_device, session_of, unbind_connection,
};
use super::session::NewSession;
use super::{AdminState, AttemptRefusal, SessionId, audit_closed};
use crate::config::AppState;
use crate::idle::{ConnActivity, hold_until_sent};

/// Body limit of `POST /admin/v1/session` (an operator ID and a phrase).
const SESSION_BODY_BYTES: usize = 8 * 1024;
/// Interval of the `: keep-alive` comment of the event stream.
const HEARTBEAT: Duration = Duration::from_secs(15);
/// The event stream checks its session at least this often.
const STREAM_CHECK: Duration = Duration::from_secs(1);

/// The admin routes, each behind [`require_device`].
pub(crate) fn router(state: &AppState) -> Router {
    Router::new()
        .route(HELLO_PATH, get(hello))
        .route(SESSION_PATH, post(open_session).delete(close_session))
        .route(&format!("{RPC_PREFIX}{{command}}"), post(rpc_call))
        .route(EVENTS_PATH, get(events))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_device,
        ))
        .with_state(state.clone())
}

fn admin_of(state: &AppState, id: RequestId) -> Result<Arc<AdminState>, AdminError> {
    state
        .admin()
        .cloned()
        .ok_or_else(|| AdminError::new(id, IpcError::internal(&"admin route without admin state")))
}

fn device_of(req: &Request, id: RequestId) -> Result<Device, AdminError> {
    req.extensions()
        .get::<Device>()
        .cloned()
        .ok_or_else(|| AdminError::new(id, IpcError::admin_cert_required()))
}

/// A zeroizing buffer as a response body: it is wiped when hyper is done with it.
struct Wiped(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn json_answer(body: Zeroizing<Vec<u8>>) -> Response {
    let mut response = (StatusCode::OK, Body::from(Bytes::from_owner(Wiped(body)))).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn is_json(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
}

/// Reads a JSON body of at most `limit` bytes into a zeroizing buffer that never grows, so this
/// read leaves no copy of a phrase or a secret in a freed buffer (ADR-0034 I-20). The JSON parse
/// after it has one residual: see `rpc::from_body` (AR-21).
async fn read_body(
    state: &AppState,
    req: Request,
    limit: usize,
    id: RequestId,
) -> Result<Zeroizing<Vec<u8>>, AdminError> {
    if !is_json(&req) {
        return Err(AdminError::code(
            id,
            "unsupported_media_type",
            "the body must be application/json",
        ));
    }
    let too_large = || AdminError::code(id, "payload_too_large", "the body is too large");
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|len| len > limit) {
        return Err(too_large());
    }
    let mut body = req.into_body();
    let mut out = Zeroizing::new(Vec::with_capacity(declared.unwrap_or(limit).min(limit)));
    let read = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| AdminError::new(id, IpcError::invalid_request()))?;
            if let Ok(data) = frame.into_data() {
                if out.len().saturating_add(data.len()) > limit {
                    return Err(too_large());
                }
                if out.len().saturating_add(data.len()) > out.capacity() {
                    // A wrong Content-Length: grow into a new zeroizing buffer, wipe the old one.
                    let mut grown = Zeroizing::new(Vec::with_capacity(limit));
                    grown.extend_from_slice(&out);
                    out = grown;
                }
                out.extend_from_slice(&data);
            }
        }
        Ok(())
    };
    match tokio::time::timeout(state.limits().body_timeout, read).await {
        Ok(Ok(())) => Ok(out),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(AdminError::new(id, IpcError::invalid_request())),
    }
}

/// `GET /admin/v1/hello`: device only.
async fn hello(State(state): State<AppState>, req: Request) -> Result<Response, AdminError> {
    let id = request_id(&req);
    let view = HelloView {
        server_version: crate::VERSION.to_owned(),
        admin_protocol: ADMIN_PROTOCOL,
        vault_state: VaultState::from(state.core().state()),
        remote_commands: REMOTE_COMMANDS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect(),
    };
    rpc::to_body(&view)
        .map(json_answer)
        .map_err(|error| AdminError::new(id, error))
}

/// Checks the phrase: unlocks a sealed vault, or verifies the phrase of the operator of the
/// unlocked vault without changing it. True in the second field when it unlocked the vault.
async fn phrase_check(
    core: &VaultService,
    operator: OperatorId,
    args: VaultUnlockArgs,
) -> Result<(OperatorContext, bool), CoreError> {
    match core.state() {
        VaultStateKind::Sealed => core
            .unlock_with_phrase(operator, args.phrase.into_core())
            .await
            .map(|ctx| (ctx, true)),
        VaultStateKind::Unlocked => core
            .verify_operator_phrase(operator, args.phrase.into_core())
            .await
            .map(|ctx| (ctx, false)),
        VaultStateKind::NoVault => Err(CoreError::NoVault),
        VaultStateKind::Locking => Err(CoreError::Locked),
    }
}

/// `POST /admin/v1/session`: opens a session with the bound operator's phrase (ADR-0034 point
/// 6.3). The recovery key is never accepted here.
async fn open_session(State(state): State<AppState>, req: Request) -> Result<Response, AdminError> {
    let id = request_id(&req);
    let admin = admin_of(&state, id)?;
    let device = device_of(&req, id)?;
    let core = state.core().clone();
    let now = core.clock().now();
    // A stolen bundle cannot drive the shared back-off far: refused before the KDF (D-9), and one
    // try of a device at a time, so parallel tries cannot all pass this check.
    let _attempt = match admin.begin_attempt(device.client.id, now) {
        Ok(attempt) => attempt,
        Err(refusal) => {
            let (code, message, retry) = match refusal {
                AttemptRefusal::Blocked(retry) => (
                    "too_many_failures",
                    "too many failed tries from this device; wait and try again",
                    retry,
                ),
                AttemptRefusal::Busy => (
                    "rate_limited",
                    "a session open of this device is running; wait for it",
                    1,
                ),
            };
            let mut error = IpcError::new(code, message);
            error.retry_after_seconds = Some(retry);
            return Err(AdminError::new(id, error));
        }
    };
    // The connection is marked authenticated only once the phrase passed (a failed try must not
    // lift the deadlines of an unauthenticated connection), so keep its activity for later.
    let activity = req
        .extensions()
        .get::<ConnActivity>()
        .map(|conn| Arc::clone(&conn.0));
    let body = read_body(&state, req, SESSION_BODY_BYTES, id).await?;
    let args: VaultUnlockArgs =
        rpc::from_body(&body).map_err(|error| AdminError::new(id, error))?;
    drop(body);
    let operator: OperatorId = args
        .operator_id
        .parse()
        .map_err(|_| AdminError::new(id, IpcError::invalid("operator_id", "is not a valid ID")))?;
    if operator != device.client.operator_id {
        return Err(AdminError::code(
            id,
            "forbidden",
            "this device is enrolled for another operator",
        ));
    }
    let epoch = core.lock_epoch();
    let (mut ctx, unlocked) = match phrase_check(&core, operator, args).await {
        Ok(done) => done,
        Err(CoreError::BadCredentials) => {
            admin.failure_record(device.client.id, now);
            return Err(AdminError::core(id, CoreError::BadCredentials));
        }
        Err(error) => return Err(AdminError::core(id, error)),
    };
    admin.failure_clear(device.client.id);
    // The session is bound to the vault session that the check saw: a lock since then voids it.
    if core.state() != VaultStateKind::Unlocked || core.lock_epoch() != epoch {
        return Err(AdminError::core(id, CoreError::Locked));
    }
    ctx.request_id = id;
    let session_view: SessionView = core
        .status()
        .await
        .session
        .map(Into::into)
        .ok_or_else(|| AdminError::core(id, CoreError::Locked))?;
    let opened = admin
        .open_session(
            NewSession {
                enrolment: device.client.id,
                label: device.client.label.clone(),
                cert_sha256: device.cert_sha256,
                ctx: ctx.clone(),
                epoch,
            },
            core.clock().now(),
        )
        .map_err(|error| AdminError::new(id, IpcError::internal(&error)))?;
    let mut event = AdminAudit::new(AdminEventKind::SessionOpen);
    event.enrolment = Some(device.client.id.to_string());
    event.label = Some(device.client.label.clone());
    event.operator = Some(operator);
    event.unlocked = Some(unlocked);
    let Some((session, token, pushed_out)) = opened else {
        // The device was revoked (or its certificate expired) during the phrase check: no
        // session. A vault the phrase unlocked stays unlocked, as when the open ends just before
        // the revoke, which never locks either (invariant 10). Audited as an open that the revoke
        // ended at once (DEC-RM-22).
        if let Err(error) = core.record_admin_event(Some(&ctx), event).await {
            tracing::warn!(%error, "admin.session_open was not audited");
        }
        let mut close = AdminAudit::new(AdminEventKind::SessionClose);
        close.enrolment = Some(device.client.id.to_string());
        close.label = Some(device.client.label.clone());
        close.operator = Some(operator);
        close.reason = Some(cerberus_core::SessionCloseReason::Revoked);
        if let Err(error) = core.record_admin_event(Some(&ctx), close).await {
            tracing::warn!(%error, "admin.session_close was not audited");
        }
        tracing::warn!(enrolment = %device.client.id, unlocked, "admin session refused: the device was revoked during the open");
        return Err(AdminError::new(id, IpcError::admin_cert_required()));
    };
    audit_closed(&core, pushed_out).await;
    if let Err(error) = core.record_admin_event(Some(&ctx), event).await {
        tracing::warn!(%error, "admin.session_open was not audited");
    }
    core.note_operator_activity();
    tracing::info!(enrolment = %device.client.id, unlocked, "admin session opened");
    let limits = admin.limits();
    let answer = SessionOpenedView {
        token,
        session: session_view,
        idle_seconds: limits.session_idle_seconds,
        max_seconds: limits.session_max_seconds,
    };
    let body = rpc::to_body(&answer).map_err(|error| AdminError::new(id, error))?;
    drop(answer);
    let response = json_answer(body);
    // The connection now belongs to the new session: it closes when the session ends.
    Ok(match activity {
        Some(activity) => {
            state.owners().bind_admin(&activity, session);
            hold_until_sent(response, activity.authenticated())
        }
        None => response,
    })
}

/// `DELETE /admin/v1/session`: closes the session of the token. The vault stays as it is
/// (invariant 10).
async fn close_session(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, AdminError> {
    let id = request_id(&req);
    let admin = admin_of(&state, id)?;
    let device = device_of(&req, id)?;
    let core = state.core().clone();
    let session = session_of(&core, &admin, req.headers(), &device, id).await?;
    let guard = bind_connection(&state, &req, None);
    unbind_connection(&state, &req, session.id);
    if let Some(closed) = admin.close_session(session.id) {
        audit_closed(&core, vec![closed]).await;
    }
    let response = StatusCode::NO_CONTENT.into_response();
    Ok(match guard {
        Some(guard) => hold_until_sent(response, guard),
        None => response,
    })
}

/// `POST /admin/v1/rpc/{command}`: one allowlisted command (ADR-0034 point 5, DEC-RM-6).
async fn rpc_call(
    State(state): State<AppState>,
    Path(command): Path<String>,
    req: Request,
) -> Result<Response, AdminError> {
    let id = request_id(&req);
    let admin = admin_of(&state, id)?;
    let device = device_of(&req, id)?;
    let core = state.core().clone();
    let mut ending = None;
    let (ctx, guard) = match gate(&command) {
        None => {
            return Err(AdminError::new(
                id,
                IpcError::remote_unsupported("this command is not available for a remote server"),
            ));
        }
        Some(Gate::OpensSession) => {
            return Err(AdminError::new(
                id,
                IpcError::remote_unsupported(
                    "vault_unlock opens an admin session; use POST /admin/v1/session",
                ),
            ));
        }
        // Device-only calls keep the deadlines of an unauthenticated connection.
        Some(Gate::PreSession) => (None, None),
        Some(Gate::Session) => {
            let session = session_of(&core, &admin, req.headers(), &device, id).await?;
            // Only the keep-alive and the actions of a person count as activity. Reads do not: the
            // desktop makes them in the background too (after live events), and they must not keep
            // an unattended desktop's session or the vault's idle lock alive (DEC-RM-26).
            if counts_as_activity(&command) {
                admin.touch(session.id, core.clock().now());
                core.note_operator_activity();
            }
            // A lock ends every session, this one too: a connection bound to it would be closed
            // by the idle watcher while the answer is still on its way (DEC-RM-23). These calls
            // leave the connection unbound while they run (also one that an earlier call on this
            // keep-alive connection bound); a failure binds it again, a success closes it after
            // the answer (DEC-RM-26).
            let ends_session = matches!(command.as_str(), "vault_lock" | "vault_panic");
            let bound = (!ends_session).then_some(session.id);
            let guard = bind_connection(&state, &req, bound);
            if ends_session {
                ending = req
                    .extensions()
                    .get::<ConnActivity>()
                    .map(|activity| (Arc::clone(&activity.0), session.id));
                unbind_connection(&state, &req, session.id);
            }
            (Some(session.ctx), guard)
        }
    };
    let limits = state.limits();
    let limit = if matches!(command.as_str(), "item_create" | "item_update") {
        limits.body_large_bytes
    } else {
        limits.body_default_bytes
    };
    let body = read_body(&state, req, limit, id).await?;
    let answered = rpc::dispatch(&core, ctx.as_ref(), &command, &body).await;
    drop(body);
    let answer = match answered {
        Ok(answer) => answer,
        Err(error) => {
            // A lock or panic that failed ended nothing: the connection belongs to its session
            // again, so a revoke or the session's end still closes it.
            if let Some((activity, session)) = &ending {
                state.owners().bind_admin(activity, *session);
            }
            return Err(AdminError::new(id, error));
        }
    };
    let mut response = json_answer(answer);
    if ending.is_some() {
        // The session of this connection is gone: close it once the answer is sent, so it does
        // not stay open without an owner until its idle deadline.
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(match guard {
        Some(guard) => hold_until_sent(response, guard),
        None => response,
    })
}

/// Gives the stream slot back when the stream ends.
struct StreamSlot {
    admin: Arc<AdminState>,
    session: SessionId,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.admin.stream_release(self.session);
    }
}

struct Streaming {
    core: VaultService,
    admin: Arc<AdminState>,
    session: SessionId,
    events: broadcast::Receiver<CoreEvent>,
    changed: watch::Receiver<u64>,
    shutdown: watch::Receiver<bool>,
    _slot: StreamSlot,
}

fn wire_event(event: CoreEvent) -> Option<Event> {
    let wire = from_core(event);
    Event::default().event(wire.name()).json_data(&wire).ok()
}

/// `GET /admin/v1/events`: the live UI events of the vault (ADR-0034 point 6.8). IDs and
/// metadata only (I-19, I-21). The stream ends when the session ends (closed, idle, absolute
/// limit, lock, revoke) and at server shutdown.
async fn events(State(state): State<AppState>, req: Request) -> Result<Response, AdminError> {
    let id = request_id(&req);
    let admin = admin_of(&state, id)?;
    let device = device_of(&req, id)?;
    let core = state.core().clone();
    let session = session_of(&core, &admin, req.headers(), &device, id).await?;
    if !admin.stream_acquire(session.id) {
        let mut error = IpcError::new(
            "rate_limited",
            "this session has the most event streams already",
        );
        error.retry_after_seconds = Some(1);
        return Err(AdminError::new(id, error));
    }
    let slot = StreamSlot {
        admin: Arc::clone(&admin),
        session: session.id,
    };
    let guard = bind_connection(&state, &req, Some(session.id));
    let st = Streaming {
        events: core.subscribe(),
        changed: admin.subscribe_changes(),
        shutdown: state.shutdown_signal(),
        core,
        admin,
        session: session.id,
        _slot: slot,
    };
    let stream = stream::unfold(st, |mut st| async move {
        loop {
            if !st.admin.session_live(&st.core, st.session) {
                return None;
            }
            tokio::select! {
                biased;
                event = st.events.recv() => match event {
                    Ok(event) => {
                        if let Some(event) = wire_event(event) {
                            return Some((Ok::<Event, Infallible>(event), st));
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return None,
                },
                _ = st.shutdown.changed() => return None,
                _ = st.changed.changed() => {}
                () = tokio::time::sleep(STREAM_CHECK) => {}
            }
        }
    });
    let response = sse_response(stream);
    Ok(match guard {
        Some(guard) => hold_until_sent(response, guard),
        None => response,
    })
}

fn sse_response(
    stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
) -> Response {
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(HEARTBEAT).text("keep-alive"))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rpc_route_is_under_the_shared_prefix() {
        assert_eq!(
            format!("{RPC_PREFIX}{{command}}"),
            "/admin/v1/rpc/{command}"
        );
    }

    #[test]
    fn events_have_the_ui_event_name() {
        let event = wire_event(CoreEvent::HeaderMismatch);
        assert!(event.is_some());
    }

    #[test]
    fn the_session_route_reads_only_the_unlock_arguments() {
        assert!(rpc::from_body::<VaultUnlockArgs>(br#"{"operator_id":"x","phrase":"y"}"#).is_ok());
        assert!(
            rpc::from_body::<VaultUnlockArgs>(br#"{"operator_id":"x","recovery_key":"y"}"#)
                .is_err()
        );
    }
}
