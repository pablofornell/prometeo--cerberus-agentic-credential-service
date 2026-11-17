//! Wire DTOs of the agent REST API: the JSON bodies (ADR-0021, ADR-0027, ADR-0028, ADR-0024).
//!
//! They live here, and not in `cerberus-api`, so the client SDK uses the same types as the server.
//! The `openapi` feature adds the `utoipa` schemas; only `cerberus-api` turns it on.
//!
//! Secret text on the wire is a [`WireSecret`]: zeroized on drop and printed as `[REDACTED]`.
//! Request types refuse unknown fields (ADR-0023 HTTP rule 4). Conversions from and to the vault
//! types are in `cerberus-api`, because this crate knows nothing about the vault.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use jiff::Timestamp;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::Permission;

/// A secret text on the wire. Zeroized on drop. `Debug` prints `[REDACTED]`.
pub struct WireSecret(Zeroizing<String>);

impl WireSecret {
    /// Wraps a text. The caller should not keep another copy of it.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The text. Do not print or log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Moves the text out and leaves an empty string behind. The caller must wrap the result in a
    /// zeroizing type at once.
    #[must_use]
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

impl fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for WireSecret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

struct SecretVisitor;

impl Visitor<'_> for SecretVisitor {
    type Value = WireSecret;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<WireSecret, E> {
        Ok(WireSecret::new(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<WireSecret, E> {
        Ok(WireSecret::new(value))
    }
}

impl<'de> Deserialize<'de> for WireSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_string(SecretVisitor)
    }
}

#[cfg(feature = "openapi")]
impl utoipa::PartialSchema for WireSecret {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::Schema> {
        use utoipa::openapi::ObjectBuilder;
        use utoipa::openapi::schema::{KnownFormat, SchemaFormat, SchemaType, Type};

        ObjectBuilder::new()
            .schema_type(SchemaType::new(Type::String))
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Password)))
            .description(Some(
                "A secret value. Never print, log or store it in plain text.",
            ))
            .into()
    }
}

#[cfg(feature = "openapi")]
impl utoipa::ToSchema for WireSecret {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("SecretString")
    }
}

/// Makes a wire enum that mirrors an enum of `cerberus-types`, with `From` both ways.
macro_rules! mirror_enum {
    ($(#[$meta:meta])* $name:ident ($core:ty) { $($(#[$vmeta:meta])* $var:ident => $path:path),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
        #[serde(rename_all = "snake_case")]
        #[allow(missing_docs)]
        pub enum $name { $($(#[$vmeta])* $var),+ }

        impl From<$core> for $name {
            fn from(value: $core) -> Self {
                match value { $($path => Self::$var),+ }
            }
        }

        impl From<$name> for $core {
            fn from(value: $name) -> Self {
                match value { $($name::$var => $path),+ }
            }
        }
    };
}

mirror_enum!(
    /// Kind of an item.
    ItemKind(crate::ItemKind) {
        WebLogin => crate::ItemKind::WebLogin,
        ApiKey => crate::ItemKind::ApiKey,
        SshKey => crate::ItemKind::SshKey,
        SessionToken => crate::ItemKind::SessionToken,
        BrowserSession => crate::ItemKind::BrowserSession,
        Database => crate::ItemKind::Database,
        Cloud => crate::ItemKind::Cloud,
        Certificate => crate::ItemKind::Certificate,
        EnvBundle => crate::ItemKind::EnvBundle,
        Note => crate::ItemKind::Note,
    }
);

mirror_enum!(
    /// Deployment environment of an item.
    Environment(crate::Environment) {
        Dev => crate::Environment::Dev,
        Staging => crate::Environment::Staging,
        Prod => crate::Environment::Prod,
        Other => crate::Environment::Other,
    }
);

mirror_enum!(
    /// State of an access request.
    AccessRequestStatus(crate::AccessRequestStatus) {
        Pending => crate::AccessRequestStatus::Pending,
        Approved => crate::AccessRequestStatus::Approved,
        Denied => crate::AccessRequestStatus::Denied,
        Expired => crate::AccessRequestStatus::Expired,
        Cancelled => crate::AccessRequestStatus::Cancelled,
    }
);

mirror_enum!(
    /// State of the vault as an agent sees it.
    VaultState(crate::VaultStateKind) {
        NoVault => crate::VaultStateKind::NoVault,
        Sealed => crate::VaultStateKind::Sealed,
        Unlocked => crate::VaultStateKind::Unlocked,
        Locking => crate::VaultStateKind::Locking,
    }
);

mirror_enum!(
    /// Stable error code (ADR-0021).
    ErrorCode(crate::ErrorCode) {
        InvalidRequest => crate::ErrorCode::InvalidRequest,
        ReasonRequired => crate::ErrorCode::ReasonRequired,
        Unauthenticated => crate::ErrorCode::Unauthenticated,
        Forbidden => crate::ErrorCode::Forbidden,
        InsufficientScope => crate::ErrorCode::InsufficientScope,
        ApprovalDenied => crate::ErrorCode::ApprovalDenied,
        ApprovalUnavailable => crate::ErrorCode::ApprovalUnavailable,
        ConditionFailed => crate::ErrorCode::ConditionFailed,
        OriginRefused => crate::ErrorCode::OriginRefused,
        NotFound => crate::ErrorCode::NotFound,
        NoMatch => crate::ErrorCode::NoMatch,
        RouteNotFound => crate::ErrorCode::RouteNotFound,
        MethodNotAllowed => crate::ErrorCode::MethodNotAllowed,
        Conflict => crate::ErrorCode::Conflict,
        PayloadTooLarge => crate::ErrorCode::PayloadTooLarge,
        UnsupportedMediaType => crate::ErrorCode::UnsupportedMediaType,
        ValidationFailed => crate::ErrorCode::ValidationFailed,
        VaultLocked => crate::ErrorCode::VaultLocked,
        RateLimited => crate::ErrorCode::RateLimited,
        GrantRateLimited => crate::ErrorCode::GrantRateLimited,
        TooManyFailures => crate::ErrorCode::TooManyFailures,
        Internal => crate::ErrorCode::Internal,
        VaultCorrupt => crate::ErrorCode::VaultCorrupt,
        Unavailable => crate::ErrorCode::Unavailable,
    }
);

/// Token scope of an agent key (ADR-0016).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

impl From<crate::Scope> for Scope {
    fn from(value: crate::Scope) -> Self {
        use crate::Scope as C;
        match value {
            C::StatusRead => Self::StatusRead,
            C::CatalogRead => Self::CatalogRead,
            C::SecretsRead => Self::SecretsRead,
            C::SecretsWrite => Self::SecretsWrite,
            C::SessionsWrite => Self::SessionsWrite,
            C::Requests => Self::Requests,
            C::SshUse => Self::SshUse,
        }
    }
}

/// The permission a lease or an access request is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccessPermission {
    /// Read the secret.
    Read,
    /// Use the SSH key through the signing socket.
    UseSsh,
}

impl From<AccessPermission> for Permission {
    fn from(value: AccessPermission) -> Self {
        match value {
            AccessPermission::Read => Self::Read,
            AccessPermission::UseSsh => Self::UseSsh,
        }
    }
}

// ---------------------------------------------------------------------------------- errors

/// The one error body (ADR-0021).
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorResponse {
    /// The error.
    pub error: ErrorBody,
}

/// Fields of the error object.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorBody {
    /// Stable code.
    pub code: ErrorCode,
    /// Short English text. Never a secret, token, reason text or invisible title.
    pub message: String,
    /// Request ID of the call.
    pub request_id: Uuid,
    /// True when the same call can succeed later without a change by the agent.
    pub retryable: bool,
    /// Optional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

/// The only allowed detail keys (ADR-0021).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorDetails {
    /// Seconds to wait (429, 503).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u32>,
    /// Field problems (422).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<FieldProblem>>,
    /// Hints for `no_match`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<NoMatchHints>,
    /// Access request ID (`approval_denied`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<Uuid>,
}

impl ErrorDetails {
    /// True when no key is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.retry_after_seconds.is_none()
            && self.fields.is_none()
            && self.hints.is_none()
            && self.request.is_none()
    }
}

/// One field problem of a 422 error.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FieldProblem {
    /// Field path.
    pub field: String,
    /// What is wrong.
    pub problem: String,
}

impl From<crate::FieldProblem> for FieldProblem {
    fn from(value: crate::FieldProblem) -> Self {
        Self {
            field: value.field,
            problem: value.problem,
        }
    }
}

/// What exists among the visible items, for a `no_match` answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NoMatchHints {
    /// False when no visible item matched `app`.
    pub app_known: bool,
    /// Environments that exist for the app.
    pub environments: Vec<Environment>,
    /// Role labels that exist for the app.
    pub roles: Vec<String>,
    /// Item kinds that exist for the app.
    pub kinds: Vec<ItemKind>,
}

impl From<crate::NoMatchHints> for NoMatchHints {
    fn from(value: crate::NoMatchHints) -> Self {
        Self {
            app_known: value.app_known,
            environments: value
                .environments
                .into_iter()
                .map(Environment::from)
                .collect(),
            roles: value.roles,
            kinds: value.kinds.into_iter().map(ItemKind::from).collect(),
        }
    }
}

// ---------------------------------------------------------------------------------- service

/// `GET /health`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthResponse {
    /// Always `ok`.
    pub status: Cow<'static, str>,
    /// `locked` or `unlocked`.
    pub vault: Cow<'static, str>,
    /// Server version.
    pub version: Cow<'static, str>,
}

/// The agent in `GET /status`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StatusAgent {
    /// Agent ID.
    pub id: Uuid,
    /// Agent name.
    pub name: String,
    /// Key ID of this call.
    pub key_id: Uuid,
    /// Scopes of the key.
    pub scopes: Vec<Scope>,
    /// Expiry of the key.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime, required = true))]
    pub key_expires_at: Option<Timestamp>,
}

/// `GET /status`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StatusResponse {
    /// Vault state.
    pub vault: VaultState,
    /// The caller.
    pub agent: StatusAgent,
    /// Time of the vault clock.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub server_time: Timestamp,
}

// ---------------------------------------------------------------------------------- items

/// Metadata of an item. Never a secret value.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ItemSummary {
    /// Item ID.
    pub id: Uuid,
    /// Kind.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Role label.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub role_label: Option<String>,
    /// Category.
    pub category: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Environment.
    pub environment: Environment,
    /// Workspace slug.
    pub workspace: String,
    /// Target: URL, host or app name.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub target: Option<String>,
    /// `operator:<id>` or `agent:<id>`.
    pub created_by: String,
    /// Expiry.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime, required = true))]
    pub expires_at: Option<Timestamp>,
    /// Last change.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub updated_at: Timestamp,
    /// True when the item has a TOTP seed.
    pub has_totp: bool,
}

/// One page of the catalog.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CatalogPage {
    /// Items of the page.
    pub items: Vec<ItemSummary>,
    /// Cursor of the next page.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub next_cursor: Option<String>,
}

/// An item that was just created. Metadata only.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreatedItem {
    /// The item.
    pub item: ItemSummary,
}

// ---------------------------------------------------------------------------------- resolve

/// `POST /credentials/resolve` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    /// Workspace slug, alias or name, or an item target.
    pub app: String,
    /// `dev`, `staging`, `prod`, `other`, or a synonym.
    pub environment: Option<String>,
    /// Role label.
    pub role: Option<String>,
    /// Item kind.
    pub kind: Option<ItemKind>,
    /// Extra words to match.
    pub hint: Option<String>,
    /// Why the agent needs it. Audited. Not used for policy.
    pub purpose: String,
    /// `best` (default) or `candidates`.
    pub mode: Option<ResolveMode>,
}

/// Resolve mode.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ResolveMode {
    /// One confident item, else the list.
    Best,
    /// The list.
    Candidates,
}

/// A candidate of a resolve answer.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Candidate {
    /// Item metadata.
    pub item: ItemSummary,
    /// Score.
    pub score: u32,
}

/// The `candidates` and `ambiguous` outcomes.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CandidatesBody {
    /// The candidates. No secret.
    pub candidates: Vec<Candidate>,
}

/// The answer of resolve. `outcome` tells which one.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ResolveResponse {
    /// One confident match: the secret.
    Secret(Box<SecretResponse>),
    /// An approval is needed.
    Pending(PendingResponse),
    /// Candidates (mode `candidates`).
    Candidates(CandidatesBody),
    /// No confident match (mode `best`).
    Ambiguous(CandidatesBody),
}

// ---------------------------------------------------------------------------------- leases

/// What an agent sees of a lease.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LeaseView {
    /// Lease ID.
    pub id: Uuid,
    /// Item ID.
    pub item_id: Uuid,
    /// Permission.
    pub permission: AccessPermission,
    /// End of the lease.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: Timestamp,
    /// Uses left. `null` means no use limit.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub uses_left: Option<u32>,
}

/// An access request as the agent sees it.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AccessRequestView {
    /// Request ID.
    pub id: Uuid,
    /// Item ID.
    pub item_id: Uuid,
    /// Permission.
    pub permission: AccessPermission,
    /// State.
    pub status: AccessRequestStatus,
    /// TTL the agent asked for.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub requested_ttl_seconds: Option<u32>,
    /// Creation time.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub created_at: Timestamp,
    /// Time the request times out.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: Timestamp,
    /// Time of the decision.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = DateTime, required = true))]
    pub decided_at: Option<Timestamp>,
    /// The lease, when approved.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub lease: Option<LeaseView>,
}

/// An approval is needed (`202`).
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PendingResponse {
    /// Request ID of the call.
    pub request_id: Uuid,
    /// The access request to poll or stream.
    pub access_request: AccessRequestView,
}

/// `POST /leases/{id}/release` answer.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReleaseResponse {
    /// Lease ID.
    pub lease_id: Uuid,
    /// Time of the release.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub released_at: Timestamp,
}

// ---------------------------------------------------------------------------------- reveal / totp

/// `POST /credentials/{id}/reveal` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RevealRequest {
    /// Why the agent reads the secret.
    pub purpose: String,
    /// Use this lease.
    pub lease_id: Option<Uuid>,
    /// TTL to ask for if an approval starts.
    pub ttl_seconds: Option<u32>,
}

/// `POST /credentials/{id}/totp` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TotpRequest {
    /// Why the agent needs the code.
    pub purpose: String,
    /// Use this lease.
    pub lease_id: Option<Uuid>,
}

/// A secret for the agent. Do not print or log it.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SecretResponse {
    /// Always `secret — do not print or log` (ADR-0028).
    pub handling: Cow<'static, str>,
    /// Request ID of the call.
    pub request_id: Uuid,
    /// Item metadata.
    pub item: ItemSummary,
    /// The secret, typed by kind. The TOTP seed is never in it.
    pub secret: SecretPayload,
    /// The lease that covered the read.
    pub lease: LeaseView,
}

/// The answer of `POST /credentials/{id}/totp`. Do not print or log it.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TotpResponse {
    /// Always `secret — do not print or log`.
    pub handling: Cow<'static, str>,
    /// Request ID of the call.
    pub request_id: Uuid,
    /// Item ID.
    pub item_id: Uuid,
    /// The code.
    pub code: WireSecret,
    /// Step length in seconds.
    pub period: u32,
    /// Seconds until the code changes.
    pub expires_in_seconds: u32,
    /// The lease that covered the read.
    pub lease: LeaseView,
}

// ---------------------------------------------------------------------------------- payloads

/// A web login.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct WebLoginSecret {
    /// User name.
    pub username: WireSecret,
    /// Password.
    pub password: WireSecret,
    /// Login page.
    #[serde(default)]
    pub url: Option<String>,
}

/// An API key.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ApiKeySecret {
    /// The key.
    pub key: WireSecret,
    /// Public key ID.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Header that carries the key.
    #[serde(default)]
    pub header_name: Option<String>,
    /// Base URL of the API.
    #[serde(default)]
    pub base_url: Option<String>,
}

/// An SSH key.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SshKeySecret {
    /// OpenSSH private key text.
    pub private_key: WireSecret,
    /// Passphrase of an encrypted key.
    #[serde(default)]
    pub passphrase: Option<WireSecret>,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// Host the key is for. On create it is stored as item metadata.
    #[serde(default)]
    pub host: Option<String>,
    /// Port. On create it is stored as item metadata.
    #[serde(default)]
    pub port: Option<u16>,
    /// User name on the machine. On create it is stored as item metadata.
    #[serde(default)]
    pub user: Option<String>,
}

/// A session token.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionTokenSecret {
    /// The token.
    pub token: WireSecret,
    /// For example `Bearer`.
    #[serde(default)]
    pub token_type: Option<String>,
    /// Header that carries the token.
    #[serde(default)]
    pub header_name: Option<String>,
}

/// A Playwright browser session.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionSecret {
    /// Playwright storage state as JSON text.
    pub storage_state: WireSecret,
    /// The origin it belongs to.
    pub origin: String,
}

/// A database.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct DatabaseSecret {
    /// Connection URL.
    #[serde(default)]
    pub url: Option<WireSecret>,
    /// Engine.
    #[serde(default)]
    pub engine: Option<String>,
    /// Host.
    #[serde(default)]
    pub host: Option<String>,
    /// Port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Database name.
    #[serde(default)]
    pub database: Option<String>,
    /// User name.
    #[serde(default)]
    pub username: Option<WireSecret>,
    /// Password.
    #[serde(default)]
    pub password: Option<WireSecret>,
    /// Extra parameters.
    #[serde(default)]
    pub params: Option<BTreeMap<String, String>>,
}

/// Cloud provider keys.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CloudSecret {
    /// Provider.
    pub provider: String,
    /// Access key ID.
    #[serde(default)]
    pub access_key_id: Option<WireSecret>,
    /// Secret access key.
    #[serde(default)]
    pub secret_access_key: Option<WireSecret>,
    /// Temporary session token.
    #[serde(default)]
    pub session_token: Option<WireSecret>,
    /// Region.
    #[serde(default)]
    pub region: Option<String>,
    /// Other secret values by name.
    #[serde(default)]
    pub extra: Option<BTreeMap<String, WireSecret>>,
}

/// A certificate.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CertificateSecret {
    /// Certificate in PEM form.
    pub cert_pem: String,
    /// Private key in PEM form.
    #[serde(default)]
    pub key_pem: Option<WireSecret>,
    /// Chain in PEM form.
    #[serde(default)]
    pub chain_pem: Option<String>,
}

/// Environment variables.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EnvBundleSecret {
    /// Variable name to value.
    pub vars: BTreeMap<String, WireSecret>,
}

/// A secret note.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct NoteSecret {
    /// The text.
    pub text: WireSecret,
}

/// The secret of an item, typed by kind (ADR-0027). The kind is in the `kind` field.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretPayload {
    /// A web login.
    WebLogin(WebLoginSecret),
    /// An API key.
    ApiKey(ApiKeySecret),
    /// An SSH key.
    SshKey(SshKeySecret),
    /// A session token.
    SessionToken(SessionTokenSecret),
    /// A browser session.
    BrowserSession(BrowserSessionSecret),
    /// A database.
    Database(DatabaseSecret),
    /// Cloud keys.
    Cloud(CloudSecret),
    /// A certificate.
    Certificate(CertificateSecret),
    /// Environment variables.
    EnvBundle(EnvBundleSecret),
    /// A note.
    Note(NoteSecret),
}

/// The payload of a session: a session token or a browser session.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionPayload {
    /// A session token.
    SessionToken(SessionTokenSecret),
    /// A browser session.
    BrowserSession(BrowserSessionSecret),
}

/// Hash algorithm of a TOTP seed.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum TotpAlgorithmWire {
    /// HMAC-SHA1.
    #[serde(rename = "SHA1")]
    Sha1,
    /// HMAC-SHA256.
    #[serde(rename = "SHA256")]
    Sha256,
    /// HMAC-SHA512.
    #[serde(rename = "SHA512")]
    Sha512,
}

/// TOTP seed for a web login. Write only. Never returned.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct TotpSeedInput {
    /// Base32 seed.
    pub secret: WireSecret,
    /// Hash algorithm (default SHA1).
    pub algorithm: Option<TotpAlgorithmWire>,
    /// Digits: 6 or 8 (default 6).
    pub digits: Option<u8>,
    /// Period in seconds, 15 to 120 (default 30).
    pub period: Option<u32>,
}

// ---------------------------------------------------------------------------------- create

/// `POST /credentials` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateItemRequest {
    /// Workspace slug.
    pub workspace: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Environment.
    pub environment: Environment,
    /// Role label.
    pub role_label: Option<String>,
    /// Category.
    pub category: Option<String>,
    /// Tags.
    pub tags: Option<Vec<String>>,
    /// Target: URL, host or app name.
    pub target: Option<String>,
    /// Lifetime in seconds. No value means no expiry.
    pub ttl_seconds: Option<u32>,
    /// Reveals after which the item is deleted.
    pub max_uses: Option<u32>,
    /// The secret.
    pub payload: SecretPayload,
    /// TOTP seed of a web login.
    pub totp: Option<TotpSeedInput>,
}

/// `POST /sessions` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    /// Workspace slug.
    pub workspace: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: Option<String>,
    /// Environment.
    pub environment: Environment,
    /// Role label.
    pub role_label: Option<String>,
    /// Target: URL, host or app name.
    pub target: Option<String>,
    /// Lifetime in seconds (default 3600; at most `session_ttl_max_seconds`).
    pub ttl_seconds: Option<u32>,
    /// A session token or a browser session.
    pub payload: SessionPayload,
}

// ---------------------------------------------------------------------------------- approvals

/// `POST /requests` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateAccessRequest {
    /// Item ID.
    pub item_id: Uuid,
    /// `read` (default) or `use_ssh`.
    pub permission: Option<AccessPermission>,
    /// Shown to the person as untrusted text. Not used for policy.
    pub reason: String,
    /// TTL to ask for.
    pub ttl_seconds: Option<u32>,
}

/// `POST /credentials/{id}/ssh-prepare` body.
#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SshPrepareRequest {
    /// Why the agent needs the key.
    pub purpose: String,
    /// TTL of the socket.
    pub ttl_seconds: Option<u32>,
    /// Use this lease.
    pub lease_id: Option<Uuid>,
}

/// `POST /credentials/{id}/ssh-prepare` answer.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SshPrepareResponse {
    /// Request ID of the call.
    pub request_id: Uuid,
    /// Set `SSH_AUTH_SOCK` to this path.
    pub socket_path: String,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// Host.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub host: Option<String>,
    /// Port.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub port: Option<u16>,
    /// User.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub user: Option<String>,
    /// End of the socket.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = DateTime))]
    pub expires_at: Timestamp,
    /// The lease.
    pub lease: LeaseView,
}
