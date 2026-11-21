//! The OpenAPI document, generated from the handlers and the wire types (`utoipa`). The test
//! `openapi_matches_draft` compares it with `docs/api/openapi-draft.yaml`.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::routes;
use cerberus_types::wire::{
    ApiKeySecret, BrowserSessionSecret, CandidatesBody, CertificateSecret, CloudSecret,
    DatabaseSecret, EnvBundleSecret, ErrorBody, ErrorCode, ErrorDetails, ErrorResponse,
    FieldProblem, NoMatchHints, NoteSecret, RustdeskSecret, SessionPayload, SessionTokenSecret,
    SshKeySecret, TotpSeedInput, WebLoginSecret, WireSecret,
};

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("cvt_<agent_id>.<43 chars base64url>")
                    .description(Some(
                        "Agent key token (ADR-0016). Shown one time in the desktop app. Never put it in a URL.",
                    ))
                    .build(),
            ),
        );
    }
}

/// The Agent API document. Paths are relative to the server URL `https://127.0.0.1:7373/v1`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Cerberus Agent API",
        description = "Credential vault API for AI agents (REST part of the Agent API). HTTPS with TLS 1.3 only (ADR-0023). Every route except `GET /health` needs `Authorization: Bearer cvt_<agent_id>.<secret>` (ADR-0016). Order of checks: Host and Origin (403), IP rate limit (429), token (401), vault lock (423), scope (403), grants (404/403). Every response has `X-Request-Id` and `Cache-Control: no-store`. All errors use `ErrorResponse` (ADR-0021). Responses that hold secret values have `handling: \"secret \\u2014 do not print or log\"` (ADR-0028).",
    ),
    servers((url = "https://127.0.0.1:7373/v1", description = "Default loopback bind (ADR-0023). The port is a setting.")),
    security(("bearerAuth" = [])),
    tags(
        (name = "service"), (name = "credentials"), (name = "sessions"),
        (name = "approvals"), (name = "leases")
    ),
    paths(
        routes::health, routes::status, routes::resolve, routes::catalog, routes::create_item,
        routes::delete_item, routes::reveal, routes::totp, routes::ssh_prepare,
        routes::create_session, routes::create_request, routes::get_request,
        routes::request_events, routes::release_lease
    ),
    components(schemas(
        WireSecret, WebLoginSecret, ApiKeySecret, SshKeySecret, SessionTokenSecret,
        BrowserSessionSecret, DatabaseSecret, CloudSecret, CertificateSecret, EnvBundleSecret,
        NoteSecret, RustdeskSecret, SessionPayload, TotpSeedInput, CandidatesBody, ErrorResponse, ErrorBody,
        ErrorCode, ErrorDetails, FieldProblem, NoMatchHints
    )),
    modifiers(&BearerAuth)
)]
struct ApiDoc;

/// The OpenAPI document of the REST API.
#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}
