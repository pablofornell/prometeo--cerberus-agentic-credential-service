//! Cerberus shared types: IDs, enums, error codes and the error shape, and the clock.
//!
//! No crypto and no I/O here (ADR-0024). The wire DTOs of the agent API are in [`wire`].

pub mod clock;
pub mod enums;
pub mod env;
pub mod error;
pub mod ids;
pub mod text;
pub mod wire;

pub use clock::{Clock, ManualClock, Stopwatch, SystemClock, T0, t0};
pub use enums::{
    AccessRequestStatus, ApprovalOption, Environment, GrantMode, ItemKind, LockReason,
    OperatorRole, Permission, Scope, VaultStateKind,
};
pub use env::{is_agent_env_name_allowed, is_forbidden_env_name};
pub use error::{ErrorBody, ErrorCode, ErrorDetails, ErrorResponse, FieldProblem, NoMatchHints};
pub use ids::{
    AccessRequestId, AgentId, AgentKeyId, GrantId, IdParseError, ItemId, KeySlotId, LeaseId,
    OperatorId, RequestId, VaultId, WorkspaceId,
};

/// The `handling` text of every response that carries a secret value (ADR-0028). The dash is
/// U+2014.
pub const HANDLING_SECRET: &str = "secret \u{2014} do not print or log";

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
