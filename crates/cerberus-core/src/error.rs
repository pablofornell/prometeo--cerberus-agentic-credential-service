//! The one core error type and its mapping to wire codes (ADR-0021).

use cerberus_types::ids::AccessRequestId;
use cerberus_types::{ErrorCode, FieldProblem, NoMatchHints, Scope};

/// Every error the core service can return.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// The vault is locked.
    #[error("vault is locked")]
    Locked,
    /// No vault exists yet.
    #[error("no vault")]
    NoVault,
    /// The object does not exist, or the caller cannot see it.
    #[error("not found")]
    NotFound,
    /// Resolve found no item. Holds hints for the agent.
    #[error("no match")]
    NoMatch(NoMatchHints),
    /// Policy refuses the call.
    #[error("forbidden")]
    Forbidden,
    /// The token does not have this scope.
    #[error("insufficient scope")]
    InsufficientScope(Scope),
    /// A person denied the request.
    #[error("approval denied")]
    ApprovalDenied(Option<AccessRequestId>),
    /// No person can approve here (for example the headless daemon).
    #[error("approval unavailable")]
    ApprovalUnavailable,
    /// A grant condition is not met.
    #[error("condition failed")]
    ConditionFailed,
    /// The grant needs a reason text.
    #[error("reason required")]
    ReasonRequired,
    /// Too many calls. Retry later.
    #[error("rate limited")]
    RateLimited {
        /// Seconds until a retry can work.
        retry_after_seconds: u32,
    },
    /// The read limit of a grant is used up.
    #[error("grant rate limited")]
    GrantRateLimited {
        /// Seconds until a retry can work.
        retry_after_seconds: u32,
    },
    /// The change conflicts with the current state.
    #[error("conflict")]
    Conflict,
    /// The input is not valid.
    #[error("validation failed")]
    Validation(Vec<FieldProblem>),
    /// The operator role cannot do this. IPC only.
    #[error("wrong role")]
    RoleNotAllowed,
    /// Wrong passphrase or recovery key. IPC only.
    #[error("wrong passphrase or recovery key")]
    BadCredentials,
    /// Too many failed unlocks. Wait. IPC only.
    #[error("unlock delayed")]
    UnlockBackoff {
        /// Seconds until the next unlock try is allowed.
        retry_after_seconds: u32,
    },
    /// A key slot asks for a KDF cost above the cap of this machine (DEC-073): more memory than
    /// half of the RAM, or `t` above 10. The phrase was not checked, so this is never a wrong
    /// phrase and never counts as a failed unlock. IPC only.
    #[error("unsupported KDF cost")]
    UnsupportedKdfCost,
    /// Stored data failed a check.
    #[error("vault data is corrupt")]
    Corrupt,
    /// A storage error.
    #[error("store error")]
    Store(#[from] cerberus_store::StoreError),
    /// A crypto error.
    #[error("crypto error")]
    Crypto(#[from] cerberus_crypto::CryptoError),
}

impl CoreError {
    /// The single mapping to wire codes (ADR-0021).
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Locked => ErrorCode::VaultLocked,
            Self::NoVault | Self::Store(_) | Self::Crypto(_) => ErrorCode::Internal,
            Self::NotFound => ErrorCode::NotFound,
            Self::NoMatch(_) => ErrorCode::NoMatch,
            Self::Forbidden | Self::RoleNotAllowed => ErrorCode::Forbidden,
            Self::InsufficientScope(_) => ErrorCode::InsufficientScope,
            Self::ApprovalDenied(_) => ErrorCode::ApprovalDenied,
            Self::ApprovalUnavailable => ErrorCode::ApprovalUnavailable,
            Self::ConditionFailed => ErrorCode::ConditionFailed,
            Self::ReasonRequired => ErrorCode::ReasonRequired,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::GrantRateLimited { .. } => ErrorCode::GrantRateLimited,
            Self::Conflict => ErrorCode::Conflict,
            Self::Validation(_) => ErrorCode::ValidationFailed,
            Self::BadCredentials => ErrorCode::Unauthenticated,
            Self::UnlockBackoff { .. } => ErrorCode::TooManyFailures,
            Self::UnsupportedKdfCost => ErrorCode::Unavailable,
            Self::Corrupt => ErrorCode::VaultCorrupt,
        }
    }
}
