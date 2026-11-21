//! The two gates of the admin routes (ADR-0034 point 4): the enrolled device on every request,
//! and the admin session where the route or the command needs one.

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use cerberus_admin::clients::AdminClient;
use cerberus_admin::error::IpcError;
use cerberus_core::VaultService;
use cerberus_types::RequestId;

use super::errors::AdminError;
use super::session::{Refusal, Session};
use super::{AdminState, SessionId, audit_closed};
use crate::config::AppState;
use crate::idle::{AuthedRequest, ConnActivity};
use crate::layers::{ConnInfo, ReqId, bearer_token};

/// The enrolled device of the request, set by [`require_device`].
#[derive(Clone, Debug)]
pub(crate) struct Device {
    /// Its registry entry.
    pub client: AdminClient,
    /// SHA-256 of the client certificate of this connection.
    pub cert_sha256: [u8; 32],
}

pub(crate) fn request_id(req: &Request) -> RequestId {
    req.extensions()
        .get::<ReqId>()
        .map_or_else(RequestId::generate, |id| id.0)
}

/// Every admin route: the connection's client certificate (verified against the vault CA by the
/// TLS layer) must have its SHA-256 in the registry, not revoked and not expired. Checked on every
/// request, before any other work; else `403 admin_cert_required`. A CA-signed agent certificate
/// is not in the registry, so it does not pass (E-15).
pub(crate) async fn require_device(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let id = request_id(&req);
    let Some(admin) = state.admin() else {
        return AdminError::new(id, IpcError::internal(&"admin route without admin state"))
            .into_response();
    };
    let conn = req.extensions().get::<ConnInfo>().copied();
    let now = state.core().clock().now();
    let device = conn.and_then(|conn| {
        let cert = conn.client_cert_sha256?;
        admin.find_live(&cert, now).map(|client| Device {
            client,
            cert_sha256: cert,
        })
    });
    let Some(device) = device else {
        if let Some(conn) = conn
            && state.warn_due(conn.peer.ip(), now.as_millisecond())
        {
            tracing::warn!(ip = %conn.peer.ip(), "admin call without an enrolled client certificate");
        }
        return AdminError::new(id, IpcError::admin_cert_required()).into_response();
    };
    req.extensions_mut().insert(device);
    next.run(req).await
}

/// The live admin session of a request: a `cas_` bearer token of a session that this device
/// opened over a connection with this certificate. Anything else, a `cvt_` agent token included,
/// is `401 admin_session_required`. A session found past a limit is ended and audited here.
pub(crate) async fn session_of(
    core: &VaultService,
    admin: &AdminState,
    headers: &HeaderMap,
    device: &Device,
    id: RequestId,
) -> Result<Session, AdminError> {
    let token = bearer_token(headers);
    match admin.check_session(core, &token, &device.cert_sha256) {
        Ok(mut session) if session.enrolment == device.client.id => {
            session.ctx.request_id = id;
            Ok(session)
        }
        Ok(_) | Err(Refusal::Malformed | Refusal::Unknown | Refusal::OtherDevice) => {
            Err(AdminError::new(id, IpcError::admin_session_required()))
        }
        Err(Refusal::Ended(closed)) => {
            audit_closed(core, vec![closed]).await;
            Err(AdminError::new(id, IpcError::admin_session_required()))
        }
    }
}

/// Marks the connection of `req` as authenticated for this request and binds it to the session,
/// so the idle watcher keeps it while the session lives and closes it when the session ends.
pub(crate) fn bind_connection(
    state: &AppState,
    req: &Request,
    session: Option<SessionId>,
) -> Option<AuthedRequest> {
    let activity = req.extensions().get::<ConnActivity>()?;
    if let Some(session) = session {
        state.owners().bind_admin(&activity.0, session);
    }
    Some(activity.0.authenticated())
}

/// Unbinds the connection of `req` from `session` (the client closed it on this connection).
pub(crate) fn unbind_connection(state: &AppState, req: &Request, session: SessionId) {
    if let Some(activity) = req.extensions().get::<ConnActivity>() {
        state.owners().unbind_admin(&activity.0, session);
    }
}
