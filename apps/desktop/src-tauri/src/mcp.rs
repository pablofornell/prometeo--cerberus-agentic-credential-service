//! The router of the HTTPS server: the REST API under `/v1` and the MCP endpoint at `/mcp`.

use cerberus_api::AppState;

/// The full app router for the server.
pub(crate) fn app(state: &AppState) -> axum::Router {
    cerberus_api::app(state, cerberus_mcp::mcp_router(state))
}
