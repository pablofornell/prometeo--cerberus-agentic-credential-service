//! The one error shape of the IPC layer (`docs/interfaces.md` section 9, ADR-0021).
//!
//! Every command returns `Result<T, IpcError>`. The text never holds a secret, a token or a
//! reason text: it comes from the fixed `CoreError` messages or from this crate.

use cerberus_core::CoreError;
use serde::{Deserialize, Serialize};
use specta::Type;

/// Result of every IPC command.
pub type IpcResult<T> = Result<T, IpcError>;

/// One field problem of a `validation_failed` error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct FieldProblemView {
    /// Field path.
    pub field: String,
    /// What is wrong.
    pub problem: String,
}

/// The error the UI gets. `code` is a stable snake_case word.
///
/// Codes of the core: `vault_locked`, `no_vault`, `not_found`, `forbidden`, `role_not_allowed`,
/// `bad_credentials`, `too_many_failures`, `validation_failed`, `conflict`, `vault_corrupt`,
/// `internal`, and the other codes of ADR-0021. Codes of the desktop layer: `window_not_allowed`,
/// `invalid_request` and `unavailable`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type, thiserror::Error)]
#[error("{code}: {message}")]
pub struct IpcError {
    /// Stable code.
    pub code: String,
    /// Short English text for a person.
    pub message: String,
    /// Seconds to wait (unlock back-off, rate limits).
    pub retry_after_seconds: Option<u32>,
    /// Field problems (`validation_failed`).
    pub fields: Vec<FieldProblemView>,
}

impl IpcError {
    /// An error with a code and a text.
    #[must_use]
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
            retry_after_seconds: None,
            fields: Vec::new(),
        }
    }

    /// The window that made the call may not call this command.
    #[must_use]
    pub fn window_not_allowed() -> Self {
        Self::new(
            "window_not_allowed",
            "this window may not call this command",
        )
    }

    /// An argument is not valid (a bad ID text, a bad path, a bad address).
    #[must_use]
    pub fn invalid(field: &str, problem: &str) -> Self {
        Self {
            code: "validation_failed".to_owned(),
            message: "validation failed".to_owned(),
            retry_after_seconds: None,
            fields: vec![FieldProblemView {
                field: field.to_owned(),
                problem: problem.to_owned(),
            }],
        }
    }

    /// The feature is not available in this build or on this machine.
    #[must_use]
    pub fn unavailable(message: &str) -> Self {
        Self::new("unavailable", message)
    }

    /// The command is not available for a remote server (ADR-0034 point 5.2): it is not on the
    /// remote allowlist, or it needs something that lives on the desktop.
    #[must_use]
    pub fn remote_unsupported(message: &str) -> Self {
        Self::new("remote_unsupported", message)
    }

    /// The admin call needs a live admin session (ADR-0034 point 6.2).
    #[must_use]
    pub fn admin_session_required() -> Self {
        Self::new(
            "admin_session_required",
            "this call needs an open admin session",
        )
    }

    /// The admin call came without a client certificate whose hash is a live enrolment
    /// (ADR-0034 point 4.1).
    #[must_use]
    pub fn admin_cert_required() -> Self {
        Self::new(
            "admin_cert_required",
            "this call needs an enrolled admin client certificate",
        )
    }

    /// The arguments are not the JSON the command takes (a bad shape or an unknown field). The
    /// text never quotes the input: it can hold a secret.
    #[must_use]
    pub fn invalid_request() -> Self {
        Self::new(
            "invalid_request",
            "the arguments are not valid for this command",
        )
    }

    /// An internal failure. The cause goes to the log, never to the UI.
    #[must_use]
    pub fn internal(cause: &dyn std::fmt::Display) -> Self {
        tracing::warn!(%cause, "internal error in an IPC command");
        Self::new("internal", "internal error")
    }
}

impl From<CoreError> for IpcError {
    fn from(error: CoreError) -> Self {
        let message = error.to_string();
        let mut out = match &error {
            CoreError::NoVault => Self::new("no_vault", &message),
            CoreError::RoleNotAllowed => Self::new("role_not_allowed", &message),
            CoreError::BadCredentials => Self::new("bad_credentials", &message),
            CoreError::Store(_) | CoreError::Crypto(_) => {
                tracing::warn!(cause = ?error, "core error in an IPC command");
                Self::new(error.code().as_str(), &message)
            }
            _ => Self::new(error.code().as_str(), &message),
        };
        match error {
            CoreError::RateLimited {
                retry_after_seconds,
            }
            | CoreError::GrantRateLimited {
                retry_after_seconds,
            }
            | CoreError::UnlockBackoff {
                retry_after_seconds,
            } => out.retry_after_seconds = Some(retry_after_seconds),
            CoreError::Validation(fields) => {
                out.fields = fields
                    .into_iter()
                    .map(|f| FieldProblemView {
                        field: f.field,
                        problem: f.problem,
                    })
                    .collect();
            }
            _ => {}
        }
        out
    }
}

impl From<std::io::Error> for IpcError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(&error)
    }
}

impl From<cerberus_crypto::CryptoError> for IpcError {
    fn from(error: cerberus_crypto::CryptoError) -> Self {
        CoreError::from(error).into()
    }
}

impl From<cerberus_store::StoreError> for IpcError {
    fn from(error: cerberus_store::StoreError) -> Self {
        CoreError::from(error).into()
    }
}

impl From<cerberus_types::IdParseError> for IpcError {
    fn from(_: cerberus_types::IdParseError) -> Self {
        Self::invalid("id", "is not a valid ID")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_types::FieldProblem;

    #[test]
    fn locked_and_no_vault_have_their_own_codes() {
        assert_eq!(IpcError::from(CoreError::Locked).code, "vault_locked");
        assert_eq!(IpcError::from(CoreError::NoVault).code, "no_vault");
        assert_eq!(
            IpcError::from(CoreError::RoleNotAllowed).code,
            "role_not_allowed"
        );
    }

    #[test]
    fn backoff_and_fields_are_carried() {
        let wait = IpcError::from(CoreError::UnlockBackoff {
            retry_after_seconds: 7,
        });
        assert_eq!(wait.code, "too_many_failures");
        assert_eq!(wait.retry_after_seconds, Some(7));
        let bad = IpcError::from(CoreError::Validation(vec![FieldProblem {
            field: "title".to_owned(),
            problem: "is empty".to_owned(),
        }]));
        assert_eq!(bad.fields.len(), 1);
    }

    #[test]
    fn internal_errors_do_not_leak_the_cause() {
        let error = IpcError::internal(&"secret path /home/x");
        assert_eq!(error.message, "internal error");
    }
}
