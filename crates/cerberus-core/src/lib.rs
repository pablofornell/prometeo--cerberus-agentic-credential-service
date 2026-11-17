//! Cerberus core vault service. It has no transport: the API, MCP and Tauri layers call it.
//!
//! Module owners (Wave 5): `vault`, `context`, `error`, `index` (structure) = T05; `audit` = T08;
//! `auth` and `agents` = T09. Later: `items`, `resolve` and index scoring = T06; `policy`, `leases` = T07.

pub mod admin;
pub mod agent_api;
pub mod agents;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod context;
pub mod csvio;
pub mod error;
pub mod index;
pub mod items;
pub mod leases;
pub mod policy;
pub mod resolve;
pub mod vault;

pub use agent_api::AgentApi;
pub use context::{AgentContext, OperatorContext, Surface};
pub use error::CoreError;
pub use vault::{
    CaIssuer, CoreConfig, CoreEvent, CreatedVault, IssuedCa, KeyCustody, LockSettings, NewVault,
    OperatorInfo, OsEvent, OsEventSink, OsLockEvents, Session, TlsCaMaterial, TlsCustomMaterial,
    VaultService, VaultStatus,
};

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
