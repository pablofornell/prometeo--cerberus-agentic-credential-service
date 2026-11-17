//! Cerberus MCP server (ADR-0029): the tools of `docs/api/mcp-tools.md` over Streamable HTTP at
//! `/mcp`, and the stdio shim `cerberus-mcp` for agent hosts that only speak stdio.
//!
//! Hosts (`cerberusd`, the desktop app) mount the server like this:
//!
//! ```ignore
//! let state = cerberus_api::AppState::new(core.clone(), &config);
//! let app = cerberus_api::app(&state, cerberus_mcp::mcp_router(&state));
//! let server = cerberus_api::start(&config, state, app).await?;
//! ```
//!
//! [`mcp_router`] is already wrapped by [`cerberus_api::agent_layers`], so the bearer token, the Host
//! and Origin checks, the rate limits and the request ID apply as on `/v1`. The vault lock is not
//! checked at the transport: the session stays up and each tool returns `vault_locked`.

mod call;
mod schema;
mod server;
#[cfg(feature = "shim")]
pub mod shim;
mod tools;

use std::sync::Arc;

use axum::Router;
use cerberus_api::AppState;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

pub use call::{HANDLING_LINE, tool_error};
pub use schema::TOOL_NAMES;
pub use server::CerberusMcp;
#[doc(hidden)]
pub use tools::arguments_parse;

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The URI of the catalog resource.
pub const CATALOG_URI: &str = "cerberus://catalog";

/// The path of the MCP endpoint.
pub const MCP_PATH: &str = "/mcp";

/// Largest `/mcp` request body: 1 MiB, as `POST /v1/credentials` (DEC-T10-9).
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// The `tracing` directive hosts must add to their log filter. `rmcp` logs message bodies at
/// `debug` and `trace` level, and those hold secrets (ADR-0029 item 9).
pub const LOG_DIRECTIVE: &str = "rmcp=warn";

/// The `/mcp` router, already wrapped by [`cerberus_api::agent_layers`]. Pass it as the `extra`
/// argument of [`cerberus_api::app`].
pub fn mcp_router(state: &AppState) -> Router {
    let core = state.core().clone();
    // The Host and Origin checks belong to `cerberus_api` (they run before this router), so the
    // transport's own loopback-only Host check is off: the leaf names come from the vault.
    let config = StreamableHttpServerConfig::default()
        .disable_allowed_hosts()
        .with_max_request_body_bytes(MAX_REQUEST_BYTES);
    let service = StreamableHttpService::new(
        move || Ok(CerberusMcp::new(core.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    cerberus_api::agent_layers(state, Router::new().nest_service(MCP_PATH, service))
}
