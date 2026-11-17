//! Cerberus client SDK for agents (ADR-0023, ADR-0024, ADR-0028).
//!
//! - [`Client`]: typed calls for every agent route, retry rules, error codes with request IDs.
//! - [`transport::PinnedHttps`]: the low-level pinned HTTPS layer (TLS 1.3 only, CA pin). The MCP
//!   stdio shim uses it directly.
//! - [`run`]: `cerberus run` (env injection into a child process, output masking).
//!
//! This crate depends on `cerberus-types` only. It never links vault, store, crypto or server code.
//! Secrets are [`WireSecret`] values: zeroized on drop, `Debug` prints `[REDACTED]`.

pub mod client;
pub mod config;
pub mod error;
pub mod run;
pub mod sse;
pub mod transport;

mod tls;

pub use cerberus_types::wire::WireSecret;
pub use client::{CatalogQuery, Client, RetryPolicy, RevealResult, SshResult, TotpResult};
pub use config::{ClientConfig, DEFAULT_URL, Overrides, Trust};
pub use error::{ApiError, ClientError};
pub use sse::RequestEvents;
pub use transport::PinnedHttps;

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
