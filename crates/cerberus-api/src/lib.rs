//! Cerberus agent REST API over HTTPS: the axum router under `/v1`, the TLS 1.3 listener, the local
//! CA, token auth, the error shape and the OpenAPI document (ADR-0008, ADR-0021, ADR-0023).
//!
//! Use it like this (the desktop app and `cerberusd` do the same):
//! 1. Build `CoreConfig` with a [`tls::LocalCaIssuer`], so a new vault makes the CA and the first leaf.
//! 2. Make an [`ApiConfig`] and an [`AppState`]. Get the router with [`router`] (add MCP with the
//!    `extra` argument of [`app`]).
//! 3. [`start`] it (or [`serve`] with a shutdown future).
//!
//! `cerberusd` may also turn on the admin API under `/admin/v1` ([`admin`], ADR-0034) by putting
//! an [`AdminConfig`] in [`ApiConfig::admin`]. The desktop app never does.

pub mod admin;
pub mod config;
pub mod convert;
pub mod error;
mod idle;
pub mod layers;
pub mod openapi;
pub mod responses;
pub mod routes;
pub mod server;
pub mod sse;
pub mod tls;

use axum::Router;
use axum::middleware;

pub use admin::{AdminConfig, AdminLimits, AdminState};
pub use config::{ApiConfig, ApiLimits, AppState, DEFAULT_PORT};
pub use error::ApiError;
pub use layers::{AgentCtx, ConnInfo, ReqId};
pub use openapi::openapi;
pub use routes::JsonBody;
pub use server::{RunningServer, ServerError, serve, start};
pub use tls::{CaExport, LocalCa, LocalCaIssuer, TlsPaths};

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The full REST app: `/v1` with its fallbacks, `extra` routes merged in (for example `/mcp`), the
/// admin routes when [`AppState::admin`] is set, then the layers every request passes: request ID
/// and headers, then the Host and Origin check (they apply to `/admin` too, ADR-0034 point 2.2).
///
/// Wrap the routes of `extra` that need a token with [`agent_layers`] first.
pub fn app(state: &AppState, extra: Router) -> Router {
    let mut app = routes::with_fallbacks(routes::v1(state))
        .with_state(state.clone())
        .merge(extra);
    if state.admin().is_some() {
        app = app.merge(admin::router(state));
    }
    app.layer(middleware::from_fn_with_state(state.clone(), layers::guard))
        .layer(middleware::from_fn(layers::envelope))
}

/// The REST app without extra routes.
pub fn router(state: &AppState) -> Router {
    app(state, Router::new())
}

/// Puts the token check in front of `router` (for `/mcp`). A valid token gives an [`AgentCtx`]; the lock
/// is not checked here, because MCP keeps its transport up while locked (ADR-0008 point 4).
pub fn agent_layers(state: &AppState, router: Router) -> Router {
    router.route_layer(middleware::from_fn_with_state(
        state.clone(),
        layers::authenticate,
    ))
}
