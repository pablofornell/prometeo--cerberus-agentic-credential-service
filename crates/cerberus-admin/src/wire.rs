//! The shapes of the admin routes that are not IPC DTOs (ADR-0034 point 5): the paths, the
//! `hello` answer, the session answer and the error body. The server (`cerberus-api`) writes them
//! and the desktop in remote mode reads them, so both sides use these types.

use cerberus_types::wire::WireSecret;
use serde::{Deserialize, Serialize};

use crate::dto::{SessionView, VaultState};
use crate::error::IpcError;

/// `GET`: server version, protocol, vault state and the remote commands. Device only.
pub const HELLO_PATH: &str = "/admin/v1/hello";
/// `POST` opens a session (body: the `vault_unlock` arguments); `DELETE` closes it.
pub const SESSION_PATH: &str = "/admin/v1/session";
/// `POST <RPC_PREFIX><command>`: one remote command.
pub const RPC_PREFIX: &str = "/admin/v1/rpc/";
/// `GET`: the live UI events (server-sent events). Needs a session.
pub const EVENTS_PATH: &str = "/admin/v1/events";

/// Prefix of an admin session token (`cas_<session id>.<secret>`). Secret scanners look for it.
pub const SESSION_TOKEN_PREFIX: &str = "cas_";

/// The answer of `GET /admin/v1/hello`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloView {
    /// Version of `cerberusd`.
    pub server_version: String,
    /// [`crate::remote::ADMIN_PROTOCOL`] of the server. The desktop refuses another value.
    pub admin_protocol: u32,
    /// The real state of the server vault.
    pub vault_state: VaultState,
    /// The names of [`crate::remote::REMOTE_COMMANDS`], in order.
    pub remote_commands: Vec<String>,
}

/// The answer of `POST /admin/v1/session`. `Debug` does not print the token.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionOpenedView {
    /// `cas_<session id>.<secret>`: send it as `Authorization: Bearer` on every admin call.
    pub token: WireSecret,
    /// The vault session the admin session acts in.
    pub session: SessionView,
    /// The session ends after this many seconds without a call (`ui_activity` counts).
    pub idle_seconds: u32,
    /// The session ends this many seconds after it opened, whatever happens.
    pub max_seconds: u32,
}

/// The error body of the admin routes: the IPC error as the UI gets it locally, with the request
/// ID (ADR-0034 point 5.4). Errors of the shared outer layers (`origin_refused`,
/// `route_not_found`) keep the agent shape of ADR-0021.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminErrorBody {
    /// The request ID (also in `X-Request-Id`).
    pub request_id: String,
    /// The error.
    pub error: IpcError,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::dto::OperatorRole;

    #[test]
    fn the_session_answer_round_trips_and_hides_the_token_in_debug() {
        let view = SessionOpenedView {
            token: WireSecret::new("cas_fake.fake-secret".to_owned()),
            session: SessionView {
                operator_id: "op".to_owned(),
                role: OperatorRole::Owner,
                unlocked_at: "2026-11-21T00:00:00Z".to_owned(),
                via_recovery: false,
            },
            idle_seconds: 900,
            max_seconds: 43_200,
        };
        assert!(!format!("{view:?}").contains("fake-secret"));
        let body = crate::rpc::to_body(&view).unwrap();
        let back: SessionOpenedView = crate::rpc::from_body(&body).unwrap();
        assert_eq!(back.token.expose(), "cas_fake.fake-secret");
        assert_eq!(back.idle_seconds, 900);
    }

    #[test]
    fn paths_are_under_admin_v1() {
        for path in [HELLO_PATH, SESSION_PATH, RPC_PREFIX, EVENTS_PATH] {
            assert!(path.starts_with("/admin/v1/"), "{path}");
        }
    }
}
