//! The error responses of the OpenAPI document. Each type names one HTTP status of ADR-0021.

use utoipa::IntoResponses;

use cerberus_types::wire::ErrorResponse;

macro_rules! error_response {
    ($name:ident, $status:literal, $text:literal) => {
        #[doc = $text]
        #[derive(IntoResponses)]
        #[response(status = $status, description = $text)]
        pub struct $name(#[to_schema] pub ErrorResponse);
    };
}

error_response!(
    BadRequest,
    400,
    "`invalid_request` (malformed JSON, unknown field, bad ID) or `reason_required`."
);
error_response!(
    Unauthenticated,
    401,
    "`unauthenticated`: token missing, malformed, unknown, expired or revoked; agent not active; IP or mTLS check failed. Same answer for all reasons."
);
error_response!(
    Forbidden,
    403,
    "`forbidden`, `insufficient_scope`, `approval_denied`, `approval_unavailable`, `condition_failed` or `origin_refused`."
);
error_response!(
    NotFound,
    404,
    "`not_found`: unknown, invisible or expired item; unknown request or lease, or one of another agent."
);
error_response!(
    NoMatch,
    404,
    "`no_match`: resolve found nothing. `details.hints` lists what exists among visible items."
);
error_response!(
    Conflict,
    409,
    "`conflict`: lease already released or revoked, or a duplicate title in the workspace."
);
error_response!(
    PayloadTooLarge,
    413,
    "`payload_too_large`: body over the route limit (16 KiB, or 1 MiB for item and session creates)."
);
error_response!(
    UnsupportedMediaType,
    415,
    "`unsupported_media_type`: the body is not `application/json`."
);
error_response!(
    ValidationFailed,
    422,
    "`validation_failed`: field rules failed. `details.fields` lists each problem."
);
error_response!(
    Locked,
    423,
    "`vault_locked`: the vault is locked. No data. Poll `GET /health` (ADR-0008)."
);
error_response!(
    TooManyRequests,
    429,
    "`rate_limited`, `grant_rate_limited` or `too_many_failures` (ADR-0030). `Retry-After` is set."
);
error_response!(
    Internal,
    500,
    "`internal` or `vault_corrupt`. The message is fixed; the cause is only in the server log."
);
error_response!(
    Unavailable,
    503,
    "`unavailable`: the server is starting or shutting down, or the route needs a part that is not built yet."
);
