//! Shared enums (docs/interfaces.md section 1). Wire values are snake_case.

use serde::{Deserialize, Serialize};

/// Kind of an item (plan section 3). Plain column `items.kind` (ADR-0005).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ItemKind {
    WebLogin,
    ApiKey,
    SshKey,
    SessionToken,
    BrowserSession,
    Database,
    Cloud,
    Certificate,
    EnvBundle,
    Note,
}

/// Environment of an item.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Environment {
    Dev,
    Staging,
    Prod,
    Other,
}

/// A permission that a grant gives (ADR-0017).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Permission {
    Find,
    Read,
    CreateSession,
    Write,
    UseSsh,
}

/// Grant mode (ADR-0017).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum GrantMode {
    Auto,
    AskOnce,
    AskAlways,
    Deny,
}

/// Role of an operator key slot (ADR-0009).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum OperatorRole {
    Owner,
    Operator,
    Viewer,
}

impl OperatorRole {
    /// The text value stored in `key_slots.role` and used in the header MAC.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }
}

/// Token scope (ADR-0016). Wire values contain a colon.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Scope {
    #[serde(rename = "status:read")]
    StatusRead,
    #[serde(rename = "catalog:read")]
    CatalogRead,
    #[serde(rename = "secrets:read")]
    SecretsRead,
    #[serde(rename = "secrets:write")]
    SecretsWrite,
    #[serde(rename = "sessions:write")]
    SessionsWrite,
    #[serde(rename = "requests")]
    Requests,
    #[serde(rename = "ssh:use")]
    SshUse,
}

/// State of the vault (ADR-0026).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum VaultStateKind {
    NoVault,
    Sealed,
    Unlocked,
    Locking,
}

/// Status of an access request (ADR-0018).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum AccessRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

/// Option a person picks when approving a request (ADR-0018).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum ApprovalOption {
    Once,
    /// Wire value `minutes_15`, as in `docs/schema.sql` (serde would give `minutes15`).
    #[serde(rename = "minutes_15")]
    Minutes15,
    Session,
}

/// Why the vault was locked (ADR-0026).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum LockReason {
    Manual,
    Idle,
    MaxUnlocked,
    OsLock,
    Quit,
    Panic,
    PanicButton,
    Restore,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_are_snake_case() {
        let json = |v: &dyn erased::Ser| v.to_json();
        assert_eq!(json(&ItemKind::BrowserSession), "\"browser_session\"");
        assert_eq!(json(&Environment::Prod), "\"prod\"");
        assert_eq!(json(&Permission::UseSsh), "\"use_ssh\"");
        assert_eq!(json(&GrantMode::AskOnce), "\"ask_once\"");
        assert_eq!(json(&OperatorRole::Viewer), "\"viewer\"");
        assert_eq!(json(&Scope::SessionsWrite), "\"sessions:write\"");
        assert_eq!(json(&Scope::Requests), "\"requests\"");
        assert_eq!(json(&VaultStateKind::NoVault), "\"no_vault\"");
        assert_eq!(json(&AccessRequestStatus::Cancelled), "\"cancelled\"");
        assert_eq!(json(&ApprovalOption::Minutes15), "\"minutes_15\"");
        assert_eq!(json(&LockReason::PanicButton), "\"panic_button\"");
    }

    #[test]
    fn role_text_matches_serde() {
        for role in [
            OperatorRole::Owner,
            OperatorRole::Operator,
            OperatorRole::Viewer,
        ] {
            assert_eq!(
                serde_json::to_string(&role).unwrap(),
                format!("\"{}\"", role.as_str())
            );
        }
    }

    mod erased {
        pub trait Ser {
            fn to_json(&self) -> String;
        }
        impl<T: serde::Serialize> Ser for T {
            fn to_json(&self) -> String {
                serde_json::to_string(self).unwrap()
            }
        }
    }
}
