//! The one API error type and its one `IntoResponse` (ADR-0021).

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cerberus_core::CoreError;
use cerberus_types::{ErrorCode, RequestId};

use cerberus_types::wire::{ErrorBody, ErrorDetails, ErrorResponse, FieldProblem, NoMatchHints};

/// Seconds a client waits after `503 unavailable` when the server gives no better hint.
const DEFAULT_UNAVAILABLE_RETRY_SECONDS: u32 = 5;

/// An error of one request. It turns into the ADR-0021 JSON body and the matching status.
#[derive(Debug)]
pub struct ApiError {
    /// The stable code.
    pub code: ErrorCode,
    /// The ID of the request (ADR-0015).
    pub request_id: RequestId,
    /// Optional details. Only the keys of ADR-0021.
    pub details: Box<ErrorDetails>,
}

impl ApiError {
    /// An error with the fixed message of the code and no details.
    #[must_use]
    pub fn new(code: ErrorCode, request_id: RequestId) -> Self {
        let mut error = Self {
            code,
            request_id,
            details: Box::default(),
        };
        if code == ErrorCode::Unavailable {
            error.details.retry_after_seconds = Some(DEFAULT_UNAVAILABLE_RETRY_SECONDS);
        }
        error
    }

    /// An error with a wait time (`Retry-After` and `details.retry_after_seconds`).
    #[must_use]
    pub fn with_retry_after(mut self, seconds: u32) -> Self {
        self.details.retry_after_seconds = Some(seconds.max(1));
        self
    }

    /// Maps a core error. Internal causes go to the log with the request ID, never to the caller.
    #[must_use]
    pub fn from_core(error: CoreError, request_id: RequestId) -> Self {
        let code = error.code();
        let mut out = Self::new(code, request_id);
        match error {
            CoreError::NoMatch(hints) => {
                out.details.hints = Some(NoMatchHints::from(hints));
            }
            CoreError::Validation(fields) => {
                out.details.fields = Some(fields.into_iter().map(FieldProblem::from).collect());
            }
            CoreError::ApprovalDenied(Some(request)) => {
                out.details.request = Some(*request.as_uuid());
            }
            CoreError::RateLimited {
                retry_after_seconds,
            }
            | CoreError::GrantRateLimited {
                retry_after_seconds,
            }
            | CoreError::UnlockBackoff {
                retry_after_seconds,
            } => {
                out = out.with_retry_after(retry_after_seconds);
            }
            CoreError::UnsupportedKdfCost => {}
            CoreError::NoVault
            | CoreError::Store(_)
            | CoreError::Crypto(_)
            | CoreError::Corrupt => {
                tracing::error!(%request_id, %code, cause = %error, "internal error");
            }
            _ => {}
        }
        out
    }
}

impl From<(CoreError, RequestId)> for ApiError {
    fn from((error, request_id): (CoreError, RequestId)) -> Self {
        Self::from_core(error, request_id)
    }
}

impl ApiError {
    /// The JSON body of this error.
    #[must_use]
    pub fn body(&self) -> ErrorResponse {
        let details = (!self.details.is_empty()).then(|| (*self.details).clone());
        ErrorResponse {
            error: ErrorBody {
                code: self.code.into(),
                message: self.code.default_message().to_owned(),
                request_id: *self.request_id.as_uuid(),
                retryable: self.code.retryable(),
                details,
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let json = serde_json::to_vec(&self.body())
            .unwrap_or_else(|_| br#"{"error":{"code":"internal"}}"#.to_vec());
        let mut response = (status, json).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(seconds) = self.details.retry_after_seconds
            && matches!(status.as_u16(), 429 | 503)
        {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}
