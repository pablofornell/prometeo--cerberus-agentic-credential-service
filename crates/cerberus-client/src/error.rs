//! Typed client errors (ADR-0021). No message here holds a token or a secret value.

use cerberus_types::wire::{ErrorDetails, ErrorResponse};
use cerberus_types::{ErrorCode, RequestId};

/// An error answer of the server: the ADR-0021 error object plus the HTTP status.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP status of the answer.
    pub status: u16,
    /// Stable error code. Switch on this, not on the message.
    pub code: ErrorCode,
    /// Short English text for people.
    pub message: String,
    /// Request ID of the failed call. Give it to the owner when you ask for help.
    pub request_id: RequestId,
    /// True when the same call can succeed later without a change by the caller.
    pub retryable: bool,
    /// Optional details (retry delay, field problems, hints).
    pub details: Option<ErrorDetails>,
}

impl ApiError {
    pub(crate) fn from_response(status: u16, body: ErrorResponse) -> Self {
        let error = body.error;
        Self {
            status,
            code: error.code.into(),
            message: error.message,
            request_id: RequestId(error.request_id),
            retryable: error.retryable,
            details: error.details,
        }
    }

    /// Seconds the server asks the caller to wait (`details.retry_after_seconds`).
    #[must_use]
    pub fn retry_after_seconds(&self) -> Option<u32> {
        self.details.as_ref().and_then(|d| d.retry_after_seconds)
    }
}

/// Everything that can go wrong in the SDK.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The server answered with an error object.
    #[error("{} ({}): {} (request {})", .0.code, .0.status, .0.message, .0.request_id)]
    Api(Box<ApiError>),
    /// The TCP connection could not be made. Nothing was sent, so a retry is always safe.
    #[error("cannot connect: {0}")]
    Connect(String),
    /// The TLS handshake failed (old protocol version, unknown CA, bad certificate).
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    /// The server certificate chain does not match the pinned CA key.
    #[error("certificate pin mismatch")]
    PinMismatch,
    /// The call did not finish in time. The server may have done the work.
    #[error("timeout")]
    Timeout,
    /// The connection broke after the request was sent. The server may have done the work.
    #[error("transport error: {0}")]
    Transport(String),
    /// A setting is missing or not valid.
    #[error("bad configuration: {0}")]
    Config(String),
    /// The server answer is not what the API contract says.
    #[error("unexpected response: {0}")]
    Decode(String),
    /// Several items match and the caller did not say which one.
    #[error("several items match; narrow the search or pass the item id")]
    Ambiguous,
    /// The access request ended without approval (`denied`, `expired` or `cancelled`), or the wait ran out.
    #[error("access was not approved (status: {0})")]
    NotApproved(String),
    /// A local I/O error (for example, the child process could not start).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ClientError {
    /// The API error, when the server sent one.
    #[must_use]
    pub fn api(&self) -> Option<&ApiError> {
        match self {
            Self::Api(error) => Some(error),
            _ => None,
        }
    }

    /// The error code, when the server sent one.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        self.api().map(|e| e.code)
    }

    /// The request ID, when the server sent one.
    #[must_use]
    pub fn request_id(&self) -> Option<RequestId> {
        self.api().map(|e| e.request_id)
    }

    /// Exit code of the CLI for this error (ADR-0028 item 6): 70 auth, 71 locked, 72 denied,
    /// 73 no match, 74 other.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self.code() {
            Some(ErrorCode::Unauthenticated | ErrorCode::InsufficientScope) => 70,
            Some(ErrorCode::VaultLocked) => 71,
            Some(
                ErrorCode::Forbidden
                | ErrorCode::ApprovalDenied
                | ErrorCode::ApprovalUnavailable
                | ErrorCode::ConditionFailed,
            ) => 72,
            Some(ErrorCode::NoMatch | ErrorCode::NotFound) => 73,
            None => match self {
                Self::Ambiguous => 73,
                Self::NotApproved(_) => 72,
                _ => 74,
            },
            Some(_) => 74,
        }
    }

    /// Whether a retry is allowed. `may_be_counted` is true for a call that the server may
    /// already have counted (reveal, totp, resolve in `best` mode, create): then only an error
    /// that the server marks `retryable`, or a failed connect (nothing was sent), allows a retry.
    #[must_use]
    pub fn is_retryable(&self, may_be_counted: bool) -> bool {
        match self {
            Self::Api(error) => error.retryable,
            Self::Connect(_) => true,
            Self::Timeout | Self::Transport(_) => !may_be_counted,
            _ => false,
        }
    }
}
