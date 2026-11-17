//! Types of the network and backup commands.

use serde::{Deserialize, Serialize};
use specta::Type;

use super::Secret;

/// Result of `network_status` and `network_set_bind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct NetworkView {
    /// Addresses the server listens on, without the port.
    pub bind: Vec<String>,
    /// Port.
    pub port: u16,
    /// True when the HTTPS server is running.
    pub listening: bool,
    /// Why the server does not run (for example the port is in use).
    pub error: Option<String>,
    /// `sha256/...` pin of the active chain: the local CA key, or the top certificate of the
    /// custom chain. It survives leaf renewal. It changes when a custom certificate is loaded or removed.
    pub pin: String,
    /// SHA-256 of the top certificate of the active chain (the local CA, or the custom chain), in hex.
    pub ca_fingerprint: String,
    /// End of validity of the served leaf certificate (the custom one when `custom_cert` is true).
    pub leaf_not_after: Option<String>,
    /// True when the owner custom certificate is in use instead of the local CA.
    pub custom_cert: bool,
    /// True when a client certificate is mandatory (a LAN bind).
    pub mtls_required: bool,
}

/// What opens a backup before it replaces the vault (ADR-0031).
#[derive(Debug, Deserialize, Type)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RestoreUnlockInput {
    /// The phrase of one operator of the backup.
    Phrase {
        /// Operator ID.
        operator_id: String,
        /// The phrase.
        phrase: Secret,
    },
    /// The recovery key of the backup.
    Recovery {
        /// The recovery key text.
        recovery_key: Secret,
    },
}
