//! The data types of the IPC layer. They carry `specta::Type`, so `bindings.ts` has the same shape.
//!
//! The core types have no `specta` support and several have no `serde` support (secrets must not),
//! so each IPC type is a small mirror with `From` conversions. IDs and times are text on this side
//! of the wire (canonical UUID text, RFC 3339 time).

mod agents;
mod audit;
mod items;
mod network;
mod policy;
mod remote;
mod rustdesk;
mod vault;

use std::str::FromStr;

use cerberus_types::IdParseError;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use specta::Type;

pub use agents::*;
pub use audit::*;
pub use items::*;
pub use network::*;
pub use policy::*;
pub use remote::*;
pub use rustdesk::*;
pub use vault::*;

use crate::error::{IpcError, IpcResult};

/// Parses an ID argument. A bad text is a `validation_failed` error that names the field.
///
/// # Errors
/// `validation_failed` when `text` is not the canonical text form of an ID.
pub fn id<T: FromStr<Err = IdParseError>>(field: &str, text: &str) -> IpcResult<T> {
    text.parse()
        .map_err(|_| IpcError::invalid(field, "is not a valid ID"))
}

/// Parses an optional ID argument.
///
/// # Errors
/// As [`id`].
pub fn opt_id<T: FromStr<Err = IdParseError>>(
    field: &str,
    text: Option<&str>,
) -> IpcResult<Option<T>> {
    text.map(|t| id(field, t)).transpose()
}

/// Time as RFC 3339 text.
#[must_use]
pub fn ts(time: Timestamp) -> String {
    time.to_string()
}

/// Optional time as RFC 3339 text.
#[must_use]
pub fn opt_ts(time: Option<Timestamp>) -> Option<String> {
    time.map(ts)
}

/// Parses a time argument.
///
/// # Errors
/// `validation_failed` when `text` is not RFC 3339 time.
pub fn parse_ts(field: &str, text: &str) -> IpcResult<Timestamp> {
    text.parse()
        .map_err(|_| IpcError::invalid(field, "is not a valid time"))
}

/// Parses an optional time argument.
///
/// # Errors
/// As [`parse_ts`].
pub fn opt_parse_ts(field: &str, text: Option<&str>) -> IpcResult<Option<Timestamp>> {
    text.map(|t| parse_ts(field, t)).transpose()
}

/// Makes an enum that mirrors an enum of another crate, with `From` both ways. The wire value of
/// each variant is its snake_case name unless a `serde(rename)` says otherwise.
macro_rules! mirror_enum {
    ($(#[$meta:meta])* $name:ident ($core:ty) { $($(#[$vmeta:meta])* $var:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
        #[serde(rename_all = "snake_case")]
        #[allow(missing_docs)]
        pub enum $name { $($(#[$vmeta])* $var),+ }

        impl From<$core> for $name {
            fn from(value: $core) -> Self {
                match value { $(<$core>::$var => Self::$var),+ }
            }
        }

        impl From<$name> for $core {
            fn from(value: $name) -> Self {
                match value { $($name::$var => <$core>::$var),+ }
            }
        }
    };
}

// Declared here because the module uses `mirror_enum!`, which is in scope only below its definition.
mod csv;
pub use csv::*;

mirror_enum! {
    /// Kind of an item.
    ItemKind (cerberus_types::ItemKind) {
        WebLogin, ApiKey, SshKey, SessionToken, BrowserSession, Database, Cloud, Certificate, EnvBundle, Note,
        Rustdesk
    }
}

mirror_enum! {
    /// Environment of an item.
    Environment (cerberus_types::Environment) { Dev, Staging, Prod, Other }
}

mirror_enum! {
    /// What an agent may do with an item.
    Permission (cerberus_types::Permission) { Find, Read, CreateSession, Write, UseSsh }
}

mirror_enum! {
    /// How reads of a grant are approved.
    GrantMode (cerberus_types::GrantMode) { Auto, AskOnce, AskAlways, Deny }
}

mirror_enum! {
    /// Role of an operator.
    OperatorRole (cerberus_types::OperatorRole) { Owner, Operator, Viewer }
}

mirror_enum! {
    /// State of the vault.
    VaultState (cerberus_types::VaultStateKind) { NoVault, Sealed, Unlocked, Locking }
}

mirror_enum! {
    /// State of an access request.
    RequestStatus (cerberus_types::AccessRequestStatus) { Pending, Approved, Denied, Expired, Cancelled }
}

mirror_enum! {
    /// Status of an agent.
    AgentStatus (cerberus_store::AgentStatus) { Active, Suspended, Revoked }
}

mirror_enum! {
    /// How a lease was made.
    LeaseSource (cerberus_store::LeaseSource) { Auto, Approval }
}

/// What a person chooses when approving a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOption {
    /// One use.
    Once,
    /// 15 minutes.
    #[serde(rename = "minutes_15")]
    Minutes15,
    /// For the session.
    Session,
}

impl From<ApprovalOption> for cerberus_types::ApprovalOption {
    fn from(value: ApprovalOption) -> Self {
        match value {
            ApprovalOption::Once => Self::Once,
            ApprovalOption::Minutes15 => Self::Minutes15,
            ApprovalOption::Session => Self::Session,
        }
    }
}

/// Scope of an agent key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum Scope {
    /// Read the agent's own status.
    #[serde(rename = "status:read")]
    StatusRead,
    /// Read the catalog.
    #[serde(rename = "catalog:read")]
    CatalogRead,
    /// Read secrets.
    #[serde(rename = "secrets:read")]
    SecretsRead,
    /// Create items.
    #[serde(rename = "secrets:write")]
    SecretsWrite,
    /// Create sessions.
    #[serde(rename = "sessions:write")]
    SessionsWrite,
    /// Ask for access.
    #[serde(rename = "requests")]
    Requests,
    /// Use SSH keys.
    #[serde(rename = "ssh:use")]
    SshUse,
}

impl From<cerberus_types::Scope> for Scope {
    fn from(value: cerberus_types::Scope) -> Self {
        match value {
            cerberus_types::Scope::StatusRead => Self::StatusRead,
            cerberus_types::Scope::CatalogRead => Self::CatalogRead,
            cerberus_types::Scope::SecretsRead => Self::SecretsRead,
            cerberus_types::Scope::SecretsWrite => Self::SecretsWrite,
            cerberus_types::Scope::SessionsWrite => Self::SessionsWrite,
            cerberus_types::Scope::Requests => Self::Requests,
            cerberus_types::Scope::SshUse => Self::SshUse,
        }
    }
}

impl From<Scope> for cerberus_types::Scope {
    fn from(value: Scope) -> Self {
        match value {
            Scope::StatusRead => Self::StatusRead,
            Scope::CatalogRead => Self::CatalogRead,
            Scope::SecretsRead => Self::SecretsRead,
            Scope::SecretsWrite => Self::SecretsWrite,
            Scope::SessionsWrite => Self::SessionsWrite,
            Scope::Requests => Self::Requests,
            Scope::SshUse => Self::SshUse,
        }
    }
}
