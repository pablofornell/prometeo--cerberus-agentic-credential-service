//! The error answer of the admin routes: `{ "request_id", "error": <IpcError> }` with an HTTP
//! status from the code (ADR-0034 point 5.4). The desktop hands the `IpcError` to the UI as it
//! is, so the UI handles errors the same way in both modes.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cerberus_admin::error::IpcError;
use cerberus_admin::wire::AdminErrorBody;
use cerberus_core::CoreError;
use cerberus_types::{ErrorCode, RequestId};

/// The HTTP status of an IPC error code. The codes of the admin layer first, then the ADR-0021
/// status of an agent code with the same name, else 500.
#[must_use]
pub fn status_of(code: &str) -> u16 {
    match code {
        "vault_locked" => 423,
        "not_found" | "remote_unsupported" => 404,
        "forbidden" | "role_not_allowed" | "admin_cert_required" => 403,
        "bad_credentials" | "admin_session_required" => 401,
        "too_many_failures" | "rate_limited" => 429,
        "validation_failed" | "invalid_request" => 400,
        "conflict" => 409,
        other => ErrorCode::ALL
            .iter()
            .find(|known| known.as_str() == other)
            .map_or(500, |known| known.http_status()),
    }
}

/// One failed admin call.
#[derive(Debug)]
pub(crate) struct AdminError {
    request_id: RequestId,
    error: IpcError,
}

impl AdminError {
    pub(crate) fn new(request_id: RequestId, error: IpcError) -> Self {
        Self { request_id, error }
    }

    pub(crate) fn core(request_id: RequestId, error: CoreError) -> Self {
        Self::new(request_id, error.into())
    }

    pub(crate) fn code(request_id: RequestId, code: &str, message: &str) -> Self {
        Self::new(request_id, IpcError::new(code, message))
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(status_of(&self.error.code))
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let retry = self.error.retry_after_seconds;
        let body = AdminErrorBody {
            request_id: self.request_id.to_string(),
            error: self.error,
        };
        let json = serde_json::to_vec(&body).unwrap_or_else(|_| {
            br#"{"request_id":"","error":{"code":"internal","message":"internal error","retry_after_seconds":null,"fields":[]}}"#.to_vec()
        });
        let mut response = (status, json).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(seconds) = retry
            && matches!(status.as_u16(), 429 | 503)
        {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_table_of_the_plan() {
        for (code, status) in [
            ("vault_locked", 423),
            ("not_found", 404),
            ("remote_unsupported", 404),
            ("forbidden", 403),
            ("role_not_allowed", 403),
            ("admin_cert_required", 403),
            ("bad_credentials", 401),
            ("admin_session_required", 401),
            ("too_many_failures", 429),
            ("rate_limited", 429),
            ("validation_failed", 400),
            ("invalid_request", 400),
            ("conflict", 409),
            ("payload_too_large", 413),
            ("unsupported_media_type", 415),
            ("grant_rate_limited", 429),
            ("internal", 500),
            ("no_such_code", 500),
        ] {
            assert_eq!(status_of(code), status, "{code}");
        }
    }

    #[test]
    fn a_429_carries_retry_after() {
        let mut error = IpcError::new("too_many_failures", "wait");
        error.retry_after_seconds = Some(30);
        let response = AdminError::new(RequestId::generate(), error).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
    }
}
