//! Types of the desktop's remote mode (ADR-0034 point 7). None of them holds a secret: the client
//! key and the session token stay in the backend of the desktop.

use serde::{Deserialize, Serialize};
use specta::Type;

use super::VaultState;

/// Which backend the desktop runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum BackendMode {
    /// The desktop opens its own vault and serves local agents (the default).
    Local,
    /// The desktop is a client of one `cerberusd`: no local vault, no local server.
    Remote,
}

/// The remote side of `vault_status` (DEC-RM-10). `null` in local mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct RemoteStatusView {
    /// Enrolment ID of the active profile.
    pub profile_id: String,
    /// Label of the profile (the enrolment label).
    pub label: String,
    /// Base URL of the server.
    pub url: String,
    /// The operator the enrolment is bound to: the only one who can open a session with it.
    pub operator_id: String,
    /// End of validity of the client certificate.
    pub not_after: String,
    /// The real state of the server vault, as last seen. `null` before the first answer.
    pub server_state: Option<VaultState>,
    /// True when the last call reached the server.
    pub reachable: bool,
    /// True while this desktop holds a live admin session.
    pub has_session: bool,
    /// Version of `cerberusd`, from `hello`. `null` before the first answer.
    pub server_version: Option<String>,
    /// Error code of the last failed contact (`remote_unreachable`, `remote_pin_mismatch`,
    /// `remote_protocol_mismatch`, `admin_cert_required`). `null` after a good answer.
    pub problem: Option<String>,
}

/// One stored remote profile: what the person checks against `cerberusd status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct RemoteProfileView {
    /// Enrolment ID.
    pub id: String,
    /// Enrolment label.
    pub label: String,
    /// Base URL of the server.
    pub url: String,
    /// `sha256/<base64>` pin of the server CA key.
    pub ca_pin: String,
    /// Lower-case hex SHA-256 of the CA certificate (`cerberusd status` prints it).
    pub ca_sha256: String,
    /// The operator the enrolment is bound to.
    pub operator_id: String,
    /// End of validity of the client certificate.
    pub not_after: String,
    /// True for the profile the desktop runs with now.
    pub active: bool,
}

/// Result of `remote_status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct RemoteOverview {
    /// The backend this run uses.
    pub mode: BackendMode,
    /// ID of the profile in use, in remote mode.
    pub active: Option<String>,
    /// The stored profiles.
    pub profiles: Vec<RemoteProfileView>,
    /// The commands a remote server answers (the remote allowlist). Every other command is local
    /// only.
    pub remote_commands: Vec<String>,
}
