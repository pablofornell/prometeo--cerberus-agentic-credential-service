//! Stable error codes and the one error shape (ADR-0021).

use serde::{Deserialize, Serialize};

use crate::enums::{Environment, ItemKind};
use crate::ids::{AccessRequestId, RequestId};

/// Stable error codes (ADR-0021). The wire value is snake_case. New codes need a new ADR.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ErrorCode {
    InvalidRequest,
    ReasonRequired,
    Unauthenticated,
    Forbidden,
    InsufficientScope,
    ApprovalDenied,
    ApprovalUnavailable,
    ConditionFailed,
    OriginRefused,
    NotFound,
    NoMatch,
    RouteNotFound,
    MethodNotAllowed,
    Conflict,
    PayloadTooLarge,
    UnsupportedMediaType,
    ValidationFailed,
    VaultLocked,
    RateLimited,
    GrantRateLimited,
    TooManyFailures,
    Internal,
    VaultCorrupt,
    Unavailable,
}

impl ErrorCode {
    /// Every code, in the order of the ADR-0021 table.
    pub const ALL: [Self; 24] = [
        Self::InvalidRequest,
        Self::ReasonRequired,
        Self::Unauthenticated,
        Self::Forbidden,
        Self::InsufficientScope,
        Self::ApprovalDenied,
        Self::ApprovalUnavailable,
        Self::ConditionFailed,
        Self::OriginRefused,
        Self::NotFound,
        Self::NoMatch,
        Self::RouteNotFound,
        Self::MethodNotAllowed,
        Self::Conflict,
        Self::PayloadTooLarge,
        Self::UnsupportedMediaType,
        Self::ValidationFailed,
        Self::VaultLocked,
        Self::RateLimited,
        Self::GrantRateLimited,
        Self::TooManyFailures,
        Self::Internal,
        Self::VaultCorrupt,
        Self::Unavailable,
    ];

    /// HTTP status of the code.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest | Self::ReasonRequired => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden
            | Self::InsufficientScope
            | Self::ApprovalDenied
            | Self::ApprovalUnavailable
            | Self::ConditionFailed
            | Self::OriginRefused => 403,
            Self::NotFound | Self::NoMatch | Self::RouteNotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::Conflict => 409,
            Self::PayloadTooLarge => 413,
            Self::UnsupportedMediaType => 415,
            Self::ValidationFailed => 422,
            Self::VaultLocked => 423,
            Self::RateLimited | Self::GrantRateLimited | Self::TooManyFailures => 429,
            Self::Internal | Self::VaultCorrupt => 500,
            Self::Unavailable => 503,
        }
    }

    /// True when the same call can succeed later without a change by the agent.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::ConditionFailed
                | Self::VaultLocked
                | Self::RateLimited
                | Self::GrantRateLimited
                | Self::TooManyFailures
                | Self::Unavailable
        )
    }

    /// The snake_case wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::ReasonRequired => "reason_required",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::InsufficientScope => "insufficient_scope",
            Self::ApprovalDenied => "approval_denied",
            Self::ApprovalUnavailable => "approval_unavailable",
            Self::ConditionFailed => "condition_failed",
            Self::OriginRefused => "origin_refused",
            Self::NotFound => "not_found",
            Self::NoMatch => "no_match",
            Self::RouteNotFound => "route_not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Conflict => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::ValidationFailed => "validation_failed",
            Self::VaultLocked => "vault_locked",
            Self::RateLimited => "rate_limited",
            Self::GrantRateLimited => "grant_rate_limited",
            Self::TooManyFailures => "too_many_failures",
            Self::Internal => "internal",
            Self::VaultCorrupt => "vault_corrupt",
            Self::Unavailable => "unavailable",
        }
    }

    /// Fixed English message for the code. It never contains caller data (threat model I-11).
    #[must_use]
    pub const fn default_message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "The request is not valid.",
            Self::ReasonRequired => "A reason of at least 8 characters is required.",
            Self::Unauthenticated => "Authentication failed.",
            Self::Forbidden => "The permission is not granted.",
            Self::InsufficientScope => "The token does not have the scope for this route.",
            Self::ApprovalDenied => "A person denied the access request.",
            Self::ApprovalUnavailable => "Approval is not available on this server.",
            Self::ConditionFailed => "A grant condition is not met now.",
            Self::OriginRefused => "The request origin is refused.",
            Self::NotFound => "Not found.",
            Self::NoMatch => "No credential matches the request.",
            Self::RouteNotFound => "Unknown route.",
            Self::MethodNotAllowed => "Method not allowed.",
            Self::Conflict => "The request conflicts with the current state.",
            Self::PayloadTooLarge => "The request body is too large.",
            Self::UnsupportedMediaType => "The request body must be application/json.",
            Self::ValidationFailed => "One or more fields are not valid.",
            Self::VaultLocked => "The vault is locked.",
            Self::RateLimited => "Too many requests.",
            Self::GrantRateLimited => "The grant read limit is reached.",
            Self::TooManyFailures => "Too many failed attempts.",
            Self::Internal => "Internal error.",
            Self::VaultCorrupt => "The vault data failed an integrity check.",
            Self::Unavailable => "The server is not available now.",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The one error body: `{"error": {...}}` (ADR-0021).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error.
    pub error: ErrorBody,
}

impl ErrorResponse {
    /// Error with the fixed message of the code and no details.
    #[must_use]
    pub fn new(code: ErrorCode, request_id: RequestId) -> Self {
        Self {
            error: ErrorBody {
                code,
                message: code.default_message().to_owned(),
                request_id,
                retryable: code.retryable(),
                details: None,
            },
        }
    }

    /// The same error with details.
    #[must_use]
    pub fn with_details(mut self, details: ErrorDetails) -> Self {
        self.error.details = Some(details);
        self
    }
}

/// Fields of the error object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable code.
    pub code: ErrorCode,
    /// Short text for people. Never a secret, token, reason text or hidden title.
    pub message: String,
    /// Request ID of the call (ADR-0015).
    pub request_id: RequestId,
    /// True when the same call can succeed later.
    pub retryable: bool,
    /// Optional details. Absent in JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

/// The only allowed detail keys (ADR-0021).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetails {
    /// Seconds to wait (429, 503). Same value as the `Retry-After` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u32>,
    /// Field problems (422).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<FieldProblem>>,
    /// Hints for a resolve that found nothing (404 `no_match`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<NoMatchHints>,
    /// The access request ID (403 `approval_denied`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<AccessRequestId>,
}

/// One field problem of a 422 error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldProblem {
    /// Field path.
    pub field: String,
    /// What is wrong.
    pub problem: String,
}

/// Hints for `no_match` (ADR-0020).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoMatchHints {
    /// True when the app name matched a known workspace or target.
    pub app_known: bool,
    /// Environments that exist for the app.
    pub environments: Vec<Environment>,
    /// Role labels that exist for the app.
    pub roles: Vec<String>,
    /// Item kinds that exist for the app.
    pub kinds: Vec<ItemKind>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde_for_every_code() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(code.to_string(), code.as_str());
        }
    }

    #[test]
    fn table_of_adr_0021() {
        let table: [(ErrorCode, u16, bool); 24] = [
            (ErrorCode::InvalidRequest, 400, false),
            (ErrorCode::ReasonRequired, 400, false),
            (ErrorCode::Unauthenticated, 401, false),
            (ErrorCode::Forbidden, 403, false),
            (ErrorCode::InsufficientScope, 403, false),
            (ErrorCode::ApprovalDenied, 403, false),
            (ErrorCode::ApprovalUnavailable, 403, false),
            (ErrorCode::ConditionFailed, 403, true),
            (ErrorCode::OriginRefused, 403, false),
            (ErrorCode::NotFound, 404, false),
            (ErrorCode::NoMatch, 404, false),
            (ErrorCode::RouteNotFound, 404, false),
            (ErrorCode::MethodNotAllowed, 405, false),
            (ErrorCode::Conflict, 409, false),
            (ErrorCode::PayloadTooLarge, 413, false),
            (ErrorCode::UnsupportedMediaType, 415, false),
            (ErrorCode::ValidationFailed, 422, false),
            (ErrorCode::VaultLocked, 423, true),
            (ErrorCode::RateLimited, 429, true),
            (ErrorCode::GrantRateLimited, 429, true),
            (ErrorCode::TooManyFailures, 429, true),
            (ErrorCode::Internal, 500, false),
            (ErrorCode::VaultCorrupt, 500, false),
            (ErrorCode::Unavailable, 503, true),
        ];
        for (code, status, retryable) in table {
            assert_eq!(code.http_status(), status, "{code}");
            assert_eq!(code.retryable(), retryable, "{code}");
        }
        assert_eq!(ErrorCode::Internal.default_message(), "Internal error.");
    }

    #[test]
    fn error_shape_json() {
        let id: RequestId = "01890000-0000-7000-8000-000000000000".parse().unwrap();
        let body = ErrorResponse::new(ErrorCode::VaultLocked, id);
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "error": {
                "code": "vault_locked",
                "message": "The vault is locked.",
                "request_id": "01890000-0000-7000-8000-000000000000",
                "retryable": true
            }})
        );

        let limited = ErrorResponse::new(ErrorCode::RateLimited, id).with_details(ErrorDetails {
            retry_after_seconds: Some(3),
            ..ErrorDetails::default()
        });
        let value = serde_json::to_value(&limited).unwrap();
        assert_eq!(
            value["error"]["details"],
            serde_json::json!({ "retry_after_seconds": 3 })
        );
        let back: ErrorResponse = serde_json::from_value(value).unwrap();
        assert_eq!(back, limited);
    }

    #[test]
    fn details_refuse_unknown_keys() {
        let bad = serde_json::json!({ "secret": "x" });
        assert!(serde_json::from_value::<ErrorDetails>(bad).is_err());
    }
}
