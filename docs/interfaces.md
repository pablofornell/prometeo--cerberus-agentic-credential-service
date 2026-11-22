# Cerberus module interfaces (T01)

Status: design contract for T02–T22. Signatures are Rust 2024. Bodies are not shown.

Reading rules:
- Trait definitions are complete Rust.
- For inherent `impl` blocks, each method is shown as a signature that ends with `;`. The implementer adds the body.
- Private fields are shown as comments when they matter for security.
- Versions of external crates: ADR-0011. Crate dependency rules: ADR-0024.

## 0. Crate dependency direction

```
                 cerberus-types  (IDs, enums, ErrorCode, Clock, wire DTOs)
                   ▲    ▲    ▲   ▲
                   │    │    │   └───────────────────────── cerberus-client (SDK + CLI `cerberus`)
   cerberus-crypto ┘    │    │                                     ▲
        ▲               │    │                                     │ (stdio shim only)
   cerberus-store ──────┘    │                                     │
        ▲                    │                                     │
   cerberus-core ────────────┘                                     │
        ▲      ▲                                                   │
        │   cerberus-ssh-agent                                     │
        │      ▲                                                   │
   cerberus-api ┘ ◄──────────── cerberus-mcp (lib + bin `cerberus-mcp`) ┘
        ▲                              ▲
        ├──────────── cerberusd ───────┤
        └──────── cerberus-desktop ────┘   (apps/desktop/src-tauri)
```
An arrow points from a crate to a crate it may use. `just deps-check` enforces the table in ADR-0024.

`cerberus-admin` (ADR-0034, DEC-RM-6) holds the IPC and admin DTOs and `IpcError`, with no transport. It uses
`cerberus-core`, `cerberus-store`, `cerberus-crypto` and `cerberus-types`. `cerberus-desktop` and `cerberus-api` (the
admin API, section 5) use it; ADR-0034 also lets `cerberusd` use it, and `cerberus-desktop` use `cerberus-client`.

---

## 1. `cerberus-types`

External deps: `serde`, `uuid` (v7), `jiff`, `zeroize`, `utoipa`, `thiserror`.

```rust
// ---- ids.rs -------------------------------------------------------------------------------------
/// Generates a UUID newtype with Display, FromStr, Serialize, Deserialize, ToSchema.
#[macro_export]
macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug,
                 serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
        #[serde(transparent)]
        pub struct $name(pub uuid::Uuid);
    };
}
uuid_id!(ItemId);
uuid_id!(WorkspaceId);
uuid_id!(AgentId);
uuid_id!(AgentKeyId);
uuid_id!(GrantId);
uuid_id!(LeaseId);
uuid_id!(AccessRequestId);
uuid_id!(KeySlotId);
uuid_id!(RequestId);

/// The operator ID is the ID of the operator's passphrase key slot (ADR-0009).
pub type OperatorId = KeySlotId;

/// 16 random bytes from `vault_header.vault_id` (UUIDv4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VaultId(pub [u8; 16]);

// ---- enums.rs -----------------------------------------------------------------------------------
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    WebLogin, ApiKey, SshKey, SessionToken, BrowserSession,
    Database, Cloud, Certificate, EnvBundle, Note,
    Rustdesk, // DEC-RD-1
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Environment { Dev, Staging, Prod, Other }

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Permission { Find, Read, CreateSession, Write, UseSsh }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode { Auto, AskOnce, AskAlways, Deny }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole { Owner, Operator, Viewer }

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub enum Scope {
    #[serde(rename = "status:read")]    StatusRead,
    #[serde(rename = "catalog:read")]   CatalogRead,
    #[serde(rename = "secrets:read")]   SecretsRead,
    #[serde(rename = "secrets:write")]  SecretsWrite,
    #[serde(rename = "sessions:write")] SessionsWrite,
    #[serde(rename = "requests")]       Requests,
    #[serde(rename = "ssh:use")]        SshUse,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VaultStateKind { NoVault, Sealed, Unlocked, Locking }

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessRequestStatus { Pending, Approved, Denied, Expired, Cancelled }

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOption { Once, Minutes15, Session }

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockReason { Manual, Idle, MaxUnlocked, OsLock, Quit, Panic, PanicButton, Restore }

// ---- error.rs -----------------------------------------------------------------------------------
/// Stable error codes (ADR-0021). `as_str()` gives the snake_case wire value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest, ReasonRequired, Unauthenticated, Forbidden, InsufficientScope, ApprovalDenied,
    ApprovalUnavailable, ConditionFailed, OriginRefused, NotFound, NoMatch, RouteNotFound,
    MethodNotAllowed, Conflict, PayloadTooLarge, UnsupportedMediaType, ValidationFailed, VaultLocked,
    RateLimited, GrantRateLimited, TooManyFailures, Internal, VaultCorrupt, Unavailable,
}
impl ErrorCode {
    pub const fn http_status(self) -> u16;
    pub const fn retryable(self) -> bool;
    pub const fn as_str(self) -> &'static str;
}

/// Exact text of the `handling` field (ADR-0028).
pub const HANDLING_SECRET: &str = "secret — do not print or log";

// ---- clock.rs (ADR-0022) ------------------------------------------------------------------------
pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
    fn now(&self) -> jiff::Timestamp;
}
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;
impl Clock for SystemClock { fn now(&self) -> jiff::Timestamp; }

#[derive(Debug, Clone)]
pub struct ManualClock { /* inner: std::sync::Arc<std::sync::Mutex<jiff::Timestamp>> */ }
impl ManualClock {
    pub fn new(start: jiff::Timestamp) -> Self;
    pub fn advance(&self, by: jiff::SignedDuration);
    pub fn set(&self, to: jiff::Timestamp);
}
impl Clock for ManualClock { fn now(&self) -> jiff::Timestamp; }

// ---- secret.rs ----------------------------------------------------------------------------------
/// A secret string on the wire (client and server DTOs). Debug prints `[REDACTED]`.
/// Zeroized on drop. Serialize/Deserialize are needed for the wire only.
#[derive(Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct WireSecret(/* zeroize::Zeroizing<String> */ String);
impl WireSecret {
    pub fn new(value: String) -> Self;
    pub fn expose(&self) -> &str;
}
impl std::fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}
impl Drop for WireSecret { fn drop(&mut self); }
```

### 1.1 Wire DTOs (`cerberus_types::wire`)
Field lists match `docs/api/openapi-draft.yaml`. All structs derive `Serialize`, `Deserialize`, `ToSchema`,
`Debug`, and use `#[serde(deny_unknown_fields)]` on requests.

```rust
pub struct HealthResponse { pub status: String, pub vault: VaultStateKind, pub version: String }
pub struct StatusResponse { pub vault: VaultStateKind, pub agent: AgentSelf, pub server_time: jiff::Timestamp }
pub struct AgentSelf { pub id: AgentId, pub name: String, pub key_id: AgentKeyId, pub scopes: Vec<Scope>,
                       pub key_expires_at: Option<jiff::Timestamp> }

pub enum ResolveMode { Best, Candidates }
pub struct ResolveRequest { pub app: String, pub environment: Option<String>, pub role: Option<String>,
                            pub kind: Option<ItemKind>, pub hint: Option<String>, pub purpose: String,
                            pub mode: ResolveMode }
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ResolveResponse {
    Secret(SecretResponse),
    Pending(PendingResponse),
    Candidates(CandidatesResponse),
    Ambiguous(CandidatesResponse),
}
pub struct CandidatesResponse { pub candidates: Vec<Candidate> }
pub struct Candidate { pub item: ItemSummary, pub score: u32 }

pub struct ItemSummary { pub id: ItemId, pub kind: ItemKind, pub title: String, pub description: String,
                         pub role_label: Option<String>, pub category: String, pub tags: Vec<String>,
                         pub environment: Environment, pub workspace: String, pub target: Option<String>,
                         pub created_by: String, pub expires_at: Option<jiff::Timestamp>,
                         pub updated_at: jiff::Timestamp, pub has_totp: bool }
pub struct CatalogQuery { pub workspace: Option<String>, pub environment: Option<Environment>,
                          pub kind: Option<ItemKind>, pub tag: Option<String>, pub q: Option<String>,
                          pub limit: Option<u32>, pub cursor: Option<String> }
pub struct CatalogPage { pub items: Vec<ItemSummary>, pub next_cursor: Option<String> }

pub struct RevealRequest { pub purpose: String, pub lease_id: Option<LeaseId>,
                           pub ttl_seconds: Option<u32> }
pub struct SecretResponse { pub handling: String, pub request_id: RequestId, pub item: ItemSummary,
                            pub secret: SecretPayloadWire, pub lease: LeaseView }
pub struct PendingResponse { pub request_id: RequestId, pub access_request: AccessRequestView }

/// Secret payload on the wire. TOTP seeds are never present (ADR-0027).
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretPayloadWire {
    WebLogin { username: WireSecret, password: WireSecret, url: Option<String> },
    ApiKey { key: WireSecret, key_id: Option<String>, header_name: Option<String>, base_url: Option<String> },
    SshKey { private_key: WireSecret, passphrase: Option<WireSecret>, public_key: String, fingerprint: String,
             host: Option<String>, port: Option<u16>, user: Option<String> },
    SessionToken { token: WireSecret, token_type: Option<String>, header_name: Option<String> },
    BrowserSession { storage_state: WireSecret /* JSON text */, origin: String },
    Database { url: Option<WireSecret>, engine: Option<String>, host: Option<String>, port: Option<u16>,
               database: Option<String>, username: Option<WireSecret>, password: Option<WireSecret>,
               params: Option<std::collections::BTreeMap<String, String>> },
    Cloud { provider: String, access_key_id: Option<WireSecret>, secret_access_key: Option<WireSecret>,
            session_token: Option<WireSecret>, region: Option<String>,
            extra: Option<std::collections::BTreeMap<String, WireSecret>> },
    Certificate { cert_pem: String, key_pem: Option<WireSecret>, chain_pem: Option<String> },
    EnvBundle { vars: std::collections::BTreeMap<String, WireSecret> },
    Note { text: WireSecret },
    // DEC-RD-1: the four plain fields are item metadata (`custom`); create stores them there, a read fills them in.
    Rustdesk { rustdesk_id: Option<String>, id_server: Option<String>, relay_server: Option<String>,
               server_key: Option<String>, password: Option<WireSecret> },
}

/// Input payload for creates. Same shape as `SecretPayloadWire`, plus the TOTP seed for web logins.
pub struct TotpSeedInput { pub secret: WireSecret, pub algorithm: Option<String>, pub digits: Option<u8>,
                           pub period: Option<u32> }
pub struct CreateItemRequest { pub workspace: String, pub title: String, pub description: Option<String>,
                               pub environment: Environment, pub role_label: Option<String>,
                               pub category: Option<String>, pub tags: Option<Vec<String>>,
                               pub target: Option<String>, pub ttl_seconds: Option<u32>,
                               pub max_uses: Option<u32>, pub payload: SecretPayloadWire,
                               pub totp: Option<TotpSeedInput> }
pub struct CreateSessionRequest { pub workspace: String, pub title: String, pub description: Option<String>,
                                  pub environment: Environment, pub role_label: Option<String>,
                                  pub target: Option<String>, pub ttl_seconds: Option<u32>,
                                  pub payload: SecretPayloadWire /* SessionToken or BrowserSession */ }
pub struct CreatedItem { pub item: ItemSummary }

pub struct TotpRequest { pub purpose: String, pub lease_id: Option<LeaseId> }
pub struct TotpResponse { pub handling: String, pub request_id: RequestId, pub item_id: ItemId,
                          pub code: WireSecret, pub period: u32, pub expires_in_seconds: u32,
                          pub lease: LeaseView }

pub struct CreateAccessRequest { pub item_id: ItemId, pub permission: Permission /* read | use_ssh */,
                                 pub reason: String, pub ttl_seconds: Option<u32> }
pub struct AccessRequestView { pub id: AccessRequestId, pub item_id: ItemId, pub permission: Permission,
                               pub status: AccessRequestStatus, pub requested_ttl_seconds: Option<u32>,
                               pub created_at: jiff::Timestamp, pub expires_at: jiff::Timestamp,
                               pub decided_at: Option<jiff::Timestamp>, pub lease: Option<LeaseView> }

pub struct LeaseView { pub id: LeaseId, pub item_id: ItemId, pub permission: Permission,
                       pub expires_at: jiff::Timestamp, pub uses_left: Option<u32> }
pub struct ReleaseResponse { pub lease_id: LeaseId, pub released_at: jiff::Timestamp }

pub struct SshPrepareRequest { pub purpose: String, pub ttl_seconds: Option<u32>, pub lease_id: Option<LeaseId> }
pub struct SshPrepareResponse { pub request_id: RequestId, pub socket_path: String,
                                pub public_key: String, pub fingerprint: String,
                                pub host: Option<String>, pub port: Option<u16>, pub user: Option<String>,
                                pub expires_at: jiff::Timestamp, pub lease: LeaseView }

pub struct ErrorResponse { pub error: ErrorBody }
pub struct ErrorBody { pub code: ErrorCode, pub message: String, pub request_id: RequestId,
                       pub retryable: bool, pub details: Option<ErrorDetails> }
pub struct ErrorDetails { pub retry_after_seconds: Option<u32>, pub fields: Option<Vec<FieldProblem>>,
                          pub hints: Option<NoMatchHints>, pub request: Option<AccessRequestId> }
pub struct FieldProblem { pub field: String, pub problem: String }
pub struct NoMatchHints { pub app_known: bool, pub environments: Vec<Environment>,
                          pub roles: Vec<String>, pub kinds: Vec<ItemKind> }
```
(Field visibility `pub` and derives are omitted after the first structs for space; every DTO is `pub` with `pub` fields.)

Notes for T02/T10:
- `utoipa` has no built-in schema for `jiff::Timestamp`. Each timestamp field gets
  `#[schema(value_type = String, format = DateTime)]`. Wire form is RFC 3339 UTC (`jiff` serde default).
- `WireSecret` gets `#[schema(value_type = String, format = Password)]`.

Signature check: on 2026-11-16 the code blocks of sections 1–8 were extracted into a scratch workspace (outside the
repo), stub bodies were added, and `cargo check` passed with Rust 1.100.0 and the versions in ADR-0011.

---

## 2. `cerberus-crypto`

External deps: `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `hmac`, `rand`, `getrandom`, `zeroize`, `secrecy`,
`subtle`, `zxcvbn`, `data-encoding`, `region`, `rustix`, `thiserror`. Internal: `cerberus-types`.

```rust
#![deny(unsafe_code)]   // `memlock` has #[allow(unsafe_code)] (ADR-0012)

use cerberus_types::{AgentId, KeySlotId, VaultId};

// ---- secret types -------------------------------------------------------------------------------
/// Heap bytes, zeroized on drop. Debug = "[REDACTED]". No Display, no Serialize.
pub struct SecretBytes(/* zeroize::Zeroizing<Vec<u8>> */);
impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self;
    pub fn expose_secret(&self) -> &[u8];
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}
/// UTF-8 secret text (phrases, passwords). Same rules as SecretBytes.
pub struct SecretString(/* secrecy::SecretString */);
impl SecretString {
    pub fn new(value: String) -> Self;
    pub fn expose_secret(&self) -> &str;
}
/// A 32-byte key in locked memory.
pub struct Key32(/* memlock::LockedBox<[u8; 32]> */);
impl Key32 {
    pub fn random() -> Result<Self, CryptoError>;
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError>;
    pub fn expose_secret(&self) -> &[u8; 32];
}
/// The vault master key. Only `KeyTree::derive` and slot functions read it.
pub struct Vmk(Key32);

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("integrity check failed")]          Integrity,
    #[error("invalid KDF parameters")]          InvalidKdfParams,
    #[error("key derivation failed")]           Kdf,
    #[error("random generator failed")]         Rng,
    #[error("invalid encoding")]                Encoding,
    #[error("recovery key checksum mismatch")]  ChecksumMismatch,
    #[error("unsupported envelope version")]    EnvelopeVersion,
    #[error("memory lock failed")]              MemLock,
}

// ---- KDF (ADR-0013) -----------------------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams { pub m_cost_kib: u32, pub t_cost: u32, pub p_cost: u32 }
impl KdfParams {
    pub const MIN_M_COST_KIB: u32 = 19_456;
    pub const MAX_M_COST_KIB: u32 = 4_194_304;
    pub fn validate(&self) -> Result<(), CryptoError>;
}
#[derive(Clone, Copy, Debug)]
pub struct KdfTuning { pub params: KdfParams, pub measured: std::time::Duration }
pub fn tune_kdf(target: std::time::Duration, total_ram_bytes: u64) -> Result<KdfTuning, CryptoError>;
pub fn derive_passphrase_kek(phrase: &SecretString, salt: &[u8; 32], params: &KdfParams) -> Result<Key32, CryptoError>;
pub fn derive_recovery_kek(recovery: &RecoveryKey, salt: &[u8; 32]) -> Result<Key32, CryptoError>;
pub fn normalize_phrase(input: &str) -> SecretString; // NFKC, no trim

// ---- envelope and AAD (ADR-0014) ----------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    SlotVmk, ItemDek, ItemPayload, ItemMeta, ItemMetaSnapshot, WorkspaceMeta, AgentMeta,
    GrantBody, RequestReason, AuditBody, SettingsValue, CaKey,
}
impl Purpose { pub const fn label(self) -> &'static str; }

#[derive(Clone, Copy, Debug)]
pub struct Aad<'a> {
    pub purpose: Purpose,
    pub vault_id: &'a VaultId,
    pub record_id: &'a [u8],
    pub version: u32,
}
impl Aad<'_> { pub fn to_bytes(&self) -> Vec<u8>; }

pub const ENVELOPE_VERSION: u8 = 0x01;
pub fn seal(key: &Key32, aad: &Aad<'_>, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub fn open(key: &Key32, aad: &Aad<'_>, envelope: &[u8]) -> Result<SecretBytes, CryptoError>;

// ---- key tree -----------------------------------------------------------------------------------
pub struct KeyTree {
    pub item_kek: Key32,
    pub meta_key: Key32,
    pub audit_key: Key32,
    pub ca_key: Key32,
    pub header_key: Key32,
    pub row_mac_key: Key32,
}
impl KeyTree { pub fn derive(vmk: &Vmk, vault_id: &VaultId) -> Result<Self, CryptoError>; }

/// Make and wrap a new per-version DEK.
pub fn new_dek() -> Result<Key32, CryptoError>;
pub fn wrap_dek(item_kek: &Key32, aad: &Aad<'_>, dek: &Key32) -> Result<Vec<u8>, CryptoError>;
pub fn unwrap_dek(item_kek: &Key32, aad: &Aad<'_>, wrapped: &[u8]) -> Result<Key32, CryptoError>;

// ---- key slots ----------------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub enum SlotKdf { Argon2id(KdfParams), HkdfSha256 }
#[derive(Clone, Debug)]
pub struct SlotMaterial { pub kdf: SlotKdf, pub salt: [u8; 32], pub wrapped_vmk: Vec<u8> }

impl Vmk {
    pub fn generate() -> Result<Self, CryptoError>;
}
pub fn create_passphrase_slot(vmk: &Vmk, vault_id: &VaultId, slot_id: &KeySlotId, phrase: &SecretString,
                              params: KdfParams) -> Result<SlotMaterial, CryptoError>;
pub fn open_passphrase_slot(vault_id: &VaultId, slot_id: &KeySlotId, phrase: &SecretString,
                            slot: &SlotMaterial) -> Result<Vmk, CryptoError>;
pub fn create_recovery_slot(vmk: &Vmk, vault_id: &VaultId, slot_id: &KeySlotId,
                            recovery: &RecoveryKey) -> Result<SlotMaterial, CryptoError>;
pub fn open_recovery_slot(vault_id: &VaultId, slot_id: &KeySlotId, recovery: &RecoveryKey,
                          slot: &SlotMaterial) -> Result<Vmk, CryptoError>;

/// 32 random bytes; text form `CRK1-XXXX-…` (14 groups, ADR-0013).
pub struct RecoveryKey(Key32);
impl RecoveryKey {
    pub fn generate() -> Result<Self, CryptoError>;
    pub fn parse(text: &str) -> Result<Self, CryptoError>;
    pub fn to_display(&self) -> SecretString;
}

// ---- MACs, hashes, comparison -------------------------------------------------------------------
pub fn hmac_sha256(key: &Key32, parts: &[&[u8]]) -> [u8; 32];
pub fn verify_hmac_sha256(key: &Key32, parts: &[&[u8]], tag: &[u8; 32]) -> bool; // constant time
pub fn sha256(parts: &[&[u8]]) -> [u8; 32];
/// u16-BE length prefix for each part (ADR-0014, ADR-0025).
pub fn length_prefixed(parts: &[&[u8]]) -> Vec<u8>;
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;

/// Header MAC input (ADR-0013).
pub struct HeaderMacInput<'a> {
    pub magic: &'a str,
    pub format_version: u32,
    pub vault_id: &'a VaultId,
    pub created_at_ms: i64,
    pub slots: Vec<SlotMacInput<'a>>,
}
pub struct SlotMacInput<'a> {
    pub id: &'a KeySlotId,
    pub kind: &'a str,
    pub role: &'a str,
    pub kdf_alg: &'a str,
    pub kdf: Option<KdfParams>,
    pub salt: &'a [u8; 32],
    pub wrapped_vmk: &'a [u8],
}
pub fn header_mac(header_key: &Key32, input: &HeaderMacInput<'_>) -> [u8; 32];

/// One column value for a row MAC (ADR-0033). `Null` = SQL NULL.
pub enum MacField<'a> { Null, Bytes(&'a [u8]), Int(i64), Text(&'a str) }
pub fn row_mac(row_mac_key: &Key32, vault_id: &VaultId, table: &str, fields: &[MacField<'_>]) -> [u8; 32];
pub fn verify_row_mac(row_mac_key: &Key32, vault_id: &VaultId, table: &str, fields: &[MacField<'_>],
                      tag: &[u8; 32]) -> bool;

// ---- agent tokens (ADR-0016) --------------------------------------------------------------------
pub struct TokenSecret(/* [u8; 32] in Zeroizing */);
impl TokenSecret {
    pub fn generate() -> Result<Self, CryptoError>;
    pub fn to_token_string(&self, agent: &AgentId) -> SecretString;   // "cvt_<agent>.<b64url>"
    pub fn hint(&self) -> String;                                    // last 4 characters
}
pub struct ParsedToken { pub agent_id: AgentId, pub secret: TokenSecret }
pub fn parse_token(raw: &str) -> Result<ParsedToken, CryptoError>;
pub fn token_hash(agent: &AgentId, secret: &TokenSecret) -> [u8; 32];

// ---- passphrases ---------------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct Strength { pub score: u8, pub guesses_log10: f64, pub warning: Option<String>, pub suggestions: Vec<String> }
pub const MIN_PHRASE_SCORE: u8 = 3;
pub const MIN_PHRASE_CHARS: usize = 12;
pub fn phrase_strength(phrase: &SecretString, user_inputs: &[&str]) -> Strength;
pub fn diceware(words: usize) -> Result<SecretString, CryptoError>;   // EFF large list, default 7

// ---- memlock (the only module with unsafe) --------------------------------------------------------
pub mod memlock {
    /// Heap value with locked pages (best effort) that is zeroized on drop.
    pub struct LockedBox<T: zeroize::Zeroize + Default> { /* Box<T>, Option<region::LockGuard> */ _p: core::marker::PhantomData<T> }
    impl<T: zeroize::Zeroize + Default> LockedBox<T> {
        pub fn new(value: T) -> Self;
        pub fn is_locked(&self) -> bool;
        pub fn get(&self) -> &T;
    }
    #[derive(Clone, Copy, Debug)]
    pub struct HardeningReport { pub dumpable_off: bool, pub core_limit_zero: bool, pub ptrace_denied: bool }
    pub fn harden_process() -> HardeningReport;
}
```

---

## 3. `cerberus-store`

External deps: `sqlx` (sqlite, runtime-tokio, migrate), `jiff`, `thiserror`, `tracing`. Internal: `cerberus-crypto`
(types only, for `SlotMaterial`/`KdfParams`), `cerberus-types`.
The store reads and writes **sealed bytes**. It never opens an envelope. It does not know the payload types.

```rust
use cerberus_types::*;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error")]                 Db(#[from] sqlx::Error),
    #[error("migration error")]                Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("not a Cerberus vault")]           NotAVault,
    #[error("vault made by a newer version")]  TooNew { found: i64, supported: i64 },
    #[error("row not found")]                  NotFound,
    #[error("constraint violated")]            Conflict,
    #[error("corrupt row")]                    Corrupt,
    #[error("io error")]                       Io(#[from] std::io::Error),
}

pub struct OpenOptions { pub path: std::path::PathBuf, pub create: bool }

#[derive(Clone)]
pub struct Store { /* pool: sqlx::SqlitePool, clock: Arc<dyn Clock> */ }
impl Store {
    pub async fn open(opts: OpenOptions, clock: std::sync::Arc<dyn Clock>) -> Result<Self, StoreError>;
    pub async fn initialize(&self, header: &HeaderRow, slots: &[KeySlotRow], ca: &TlsCaRow) -> Result<(), StoreError>;
    pub async fn begin(&self) -> Result<Tx<'_>, StoreError>;
    pub async fn header(&self) -> Result<HeaderRow, StoreError>;
    pub async fn record_unlock_failure(&self, at: jiff::Timestamp) -> Result<u32, StoreError>;
    pub async fn reset_unlock_failures(&self) -> Result<(), StoreError>;
    pub async fn key_slots(&self) -> Result<Vec<KeySlotRow>, StoreError>;
    pub async fn load_auth_rows(&self) -> Result<(Vec<AgentRow>, Vec<AgentKeyRow>), StoreError>;
    pub async fn load_all_for_index(&self) -> Result<IndexRows, StoreError>;
    pub async fn item_version(&self, item: ItemId, version: u32) -> Result<ItemVersionRow, StoreError>;
    pub async fn active_leases(&self, agent: AgentId, item: ItemId, now: jiff::Timestamp) -> Result<Vec<LeaseRow>, StoreError>;
    pub async fn access_request(&self, id: AccessRequestId) -> Result<AccessRequestRow, StoreError>;
    pub async fn audit_range(&self, from_seq: u64, limit: u32) -> Result<Vec<AuditRow>, StoreError>;
    pub async fn audit_head(&self) -> Result<Option<AuditHeadRow>, StoreError>;
    pub async fn push_audit_pending(&self, row: &AuditPendingRow, cap: u32) -> Result<(), StoreError>;
    pub async fn take_audit_pending(&self) -> Result<(Vec<AuditPendingRow>, u64), StoreError>;
    pub async fn backup_to(&self, dest: &std::path::Path) -> Result<(), StoreError>;
    pub async fn inspect_backup(path: &std::path::Path) -> Result<BackupInfo, StoreError>;
    pub async fn close(self);
}

/// A write transaction. Commit is explicit; drop rolls back.
pub struct Tx<'a> { /* sqlx::Transaction<'a, sqlx::Sqlite> */ _p: core::marker::PhantomData<&'a ()> }
impl<'a> Tx<'a> {
    pub async fn commit(self) -> Result<(), StoreError>;
    pub async fn upsert_slot(&mut self, row: &KeySlotRow) -> Result<(), StoreError>;
    pub async fn delete_slot(&mut self, id: KeySlotId) -> Result<(), StoreError>;
    pub async fn set_header_mac(&mut self, mac: &[u8; 32]) -> Result<(), StoreError>;
    pub async fn put_setting(&mut self, row: &SettingRow) -> Result<(), StoreError>;
    pub async fn put_workspace(&mut self, row: &WorkspaceRow) -> Result<(), StoreError>;
    pub async fn delete_workspace(&mut self, id: WorkspaceId) -> Result<(), StoreError>;
    pub async fn insert_item(&mut self, item: &ItemRow, first: &ItemVersionRow) -> Result<(), StoreError>;
    pub async fn add_item_version(&mut self, item: &ItemRow, version: &ItemVersionRow, keep: u32) -> Result<(), StoreError>;
    pub async fn update_item_meta(&mut self, item: &ItemRow) -> Result<(), StoreError>;
    /// Replaces `item_versions.meta_ct` of one version (a metadata-only update, DEC-INT10-6). NotFound for an unknown version.
    pub async fn update_version_meta(&mut self, item: ItemId, version: u32, meta_ct: &[u8]) -> Result<(), StoreError>;
    pub async fn delete_item(&mut self, id: ItemId) -> Result<bool, StoreError>;
    pub async fn put_agent(&mut self, row: &AgentRow) -> Result<(), StoreError>;
    pub async fn put_agent_key(&mut self, row: &AgentKeyRow) -> Result<(), StoreError>;
    pub async fn touch_agent_key(&mut self, id: AgentKeyId, at: jiff::Timestamp) -> Result<(), StoreError>;
    pub async fn put_grant(&mut self, row: &GrantRow) -> Result<(), StoreError>;
    pub async fn delete_grant(&mut self, id: GrantId) -> Result<(), StoreError>;
    pub async fn put_lease(&mut self, row: &LeaseRow) -> Result<(), StoreError>;
    pub async fn revoke_all_leases(&mut self, at: jiff::Timestamp, by: &str) -> Result<u64, StoreError>;
    pub async fn put_access_request(&mut self, row: &AccessRequestRow) -> Result<(), StoreError>;
    pub async fn cancel_pending_requests(&mut self, at: jiff::Timestamp) -> Result<u64, StoreError>;
    pub async fn append_audit(&mut self, row: &AuditRow, head: &AuditHeadRow) -> Result<(), StoreError>;
    pub async fn prune_audit(&mut self, before_seq: u64, head: &AuditHeadRow) -> Result<u64, StoreError>;
    pub async fn put_tls_ca(&mut self, row: &TlsCaRow) -> Result<(), StoreError>;
}

// ---- rows (plain columns as typed values; *_ct as Vec<u8>) ---------------------------------------
pub struct HeaderRow { pub format_version: u32, pub vault_id: VaultId, pub created_at: jiff::Timestamp,
                       pub failed_unlocks: u32, pub last_failed_unlock_at: Option<jiff::Timestamp>,
                       pub header_mac: [u8; 32] }
pub enum SlotKind { Passphrase, Recovery }
pub struct KeySlotRow { pub id: KeySlotId, pub kind: SlotKind, pub label: String, pub role: OperatorRole,
                        pub material: cerberus_crypto::SlotMaterial, pub created_at: jiff::Timestamp,
                        pub updated_at: jiff::Timestamp, pub last_unlock_at: Option<jiff::Timestamp> }
pub struct SettingRow { pub key: String, pub updated_at: jiff::Timestamp, pub value_ct: Vec<u8> }
pub struct TlsCaRow { pub ca_cert_der: Vec<u8>, pub ca_key_ct: Vec<u8>, pub created_at: jiff::Timestamp,
                      pub not_after: jiff::Timestamp }
pub struct WorkspaceRow { pub id: WorkspaceId, pub created_at: jiff::Timestamp, pub updated_at: jiff::Timestamp,
                          pub meta_ct: Vec<u8> }
pub struct ItemRow { pub id: ItemId, pub kind: ItemKind, pub expires_at: Option<jiff::Timestamp>,
                     pub created_at: jiff::Timestamp, pub updated_at: jiff::Timestamp,
                     pub current_version: u32, pub meta_ct: Vec<u8> }
pub struct ItemVersionRow { pub item_id: ItemId, pub version: u32, pub created_at: jiff::Timestamp,
                            pub wrapped_dek: Vec<u8>, pub payload_ct: Vec<u8>, pub meta_ct: Vec<u8> }
pub enum AgentStatus { Active, Suspended, Revoked }
pub struct AgentRow { pub id: AgentId, pub status: AgentStatus, pub created_at: jiff::Timestamp,
                      pub updated_at: jiff::Timestamp, pub meta_ct: Vec<u8>, pub row_mac: [u8; 32] }
pub struct AgentKeyRow { pub id: AgentKeyId, pub agent_id: AgentId, pub secret_hash: [u8; 32], pub hint: String,
                         pub scopes: Vec<Scope>, pub ip_allowlist: Vec<ipnet::IpNet>, pub require_mtls: bool,
                         pub client_cert_sha256: Option<[u8; 32]>, pub created_at: jiff::Timestamp,
                         pub expires_at: Option<jiff::Timestamp>, pub revoked_at: Option<jiff::Timestamp>,
                         pub last_used_at: Option<jiff::Timestamp>, pub row_mac: [u8; 32] }
pub struct GrantRow { pub id: GrantId, pub agent_id: AgentId, pub created_at: jiff::Timestamp,
                      pub updated_at: jiff::Timestamp, pub expires_at: Option<jiff::Timestamp>, pub body_ct: Vec<u8> }
pub enum LeaseSource { Auto, Approval }
pub struct LeaseRow { pub id: LeaseId, pub agent_id: AgentId, pub item_id: ItemId, pub permission: Permission,
                      pub source: LeaseSource, pub request_id: Option<AccessRequestId>,
                      pub created_at: jiff::Timestamp, pub expires_at: jiff::Timestamp,
                      pub max_uses: Option<u32>, pub uses: u32, pub released_at: Option<jiff::Timestamp>,
                      pub revoked_at: Option<jiff::Timestamp>, pub revoked_by: Option<String>,
                      pub row_mac: [u8; 32] }
pub struct AccessRequestRow { pub id: AccessRequestId, pub agent_id: AgentId, pub item_id: ItemId,
                              pub permission: Permission, pub status: AccessRequestStatus,
                              pub requested_ttl_seconds: Option<u32>, pub created_at: jiff::Timestamp,
                              pub expires_at: jiff::Timestamp, pub decided_at: Option<jiff::Timestamp>,
                              pub decided_by: Option<OperatorId>, pub approval_option: Option<ApprovalOption>,
                              pub lease_id: Option<LeaseId>, pub request_id: RequestId,
                              pub reason_ct: Option<Vec<u8>>, pub row_mac: [u8; 32] }
pub struct AuditRow { pub seq: u64, pub occurred_at: jiff::Timestamp, pub prev_hash: [u8; 32],
                      pub hmac: [u8; 32], pub body_ct: Vec<u8> }
pub struct AuditHeadRow { pub last_seq: u64, pub last_entry_hash: [u8; 32], pub anchor_seq: u64,
                          pub anchor_prev_hash: [u8; 32], pub head_hmac: [u8; 32] }
pub struct AuditPendingRow { pub occurred_at: jiff::Timestamp, pub event_type: String,
                             pub agent_id: Option<AgentId>, pub target_id: Option<String>,
                             pub result_code: String, pub route: Option<String>, pub request_id: Option<RequestId> }
pub struct IndexRows { pub workspaces: Vec<WorkspaceRow>, pub items: Vec<ItemRow>, pub agents: Vec<AgentRow>,
                       pub grants: Vec<GrantRow> }
pub struct BackupInfo { pub vault_id: VaultId, pub format_version: u32, pub schema_version: i64,
                        pub created_at: jiff::Timestamp, pub slots: Vec<KeySlotRow> }

// ---- sweeper (ADR-0027) -------------------------------------------------------------------------
#[derive(Debug, Default, Clone)]
pub struct SweepReport { pub expired_items: Vec<ItemId>, pub leases_deleted: u64, pub requests_deleted: u64,
                         pub vacuumed: bool }
pub struct Sweeper { /* store: Store, last_full_vacuum: Option<Timestamp> */ }
impl Sweeper {
    pub fn new(store: Store) -> Self;
    pub async fn run_once(&mut self, now: jiff::Timestamp) -> Result<SweepReport, StoreError>;
    pub fn spawn(self, period: std::time::Duration, clock: std::sync::Arc<dyn Clock>,
                 on_report: tokio::sync::mpsc::Sender<SweepReport>) -> tokio::task::JoinHandle<()>;
}
```
`cerberus-store` also depends on `ipnet` and `tokio` (for `Sweeper::spawn`).

---

## 4. `cerberus-core`

External deps: `tokio`, `futures-core`, `jiff`, `serde`, `serde_json`, `totp-rs`, `ssh-key`, `unicode-normalization`,
`governor`, `ipnet`, `thiserror`, `tracing`. Internal: `cerberus-store`, `cerberus-crypto`, `cerberus-types`.

```rust
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use cerberus_types::{wire::*, *};

// ---- errors -------------------------------------------------------------------------------------
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("vault is locked")]                 Locked,
    #[error("no vault")]                        NoVault,
    #[error("not found")]                       NotFound,
    #[error("no match")]                        NoMatch(NoMatchHints),
    #[error("forbidden")]                       Forbidden,
    #[error("insufficient scope")]              InsufficientScope(Scope),
    #[error("approval denied")]                 ApprovalDenied(Option<AccessRequestId>),
    #[error("approval unavailable")]            ApprovalUnavailable,
    #[error("condition failed")]                ConditionFailed,
    #[error("reason required")]                 ReasonRequired,
    #[error("rate limited")]                    RateLimited { retry_after_seconds: u32 },
    #[error("grant rate limited")]              GrantRateLimited { retry_after_seconds: u32 },
    #[error("conflict")]                        Conflict,
    #[error("validation failed")]               Validation(Vec<FieldProblem>),
    #[error("wrong role")]                      RoleNotAllowed,       // IPC only
    #[error("wrong passphrase or recovery key")] BadCredentials,     // IPC only
    #[error("unlock delayed")]                  UnlockBackoff { retry_after_seconds: u32 }, // IPC only
    #[error("vault data is corrupt")]           Corrupt,
    #[error("store error")]                     Store(#[from] cerberus_store::StoreError),
    #[error("crypto error")]                    Crypto(#[from] cerberus_crypto::CryptoError),
}
impl CoreError {
    /// The single mapping to wire codes (ADR-0021).
    pub fn code(&self) -> ErrorCode;
}

// ---- contexts -----------------------------------------------------------------------------------
/// Set by the auth middleware after a token check (ADR-0016).
#[derive(Clone, Debug)]
pub struct AgentContext {
    pub agent_id: AgentId,
    pub key_id: AgentKeyId,
    pub scopes: std::collections::BTreeSet<Scope>,
    pub request_id: RequestId,
    pub source_ip: IpAddr,
    pub surface: Surface,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface { Rest, Mcp }

/// Set by the Tauri layer for every IPC command.
#[derive(Clone, Debug)]
pub struct OperatorContext { pub operator_id: OperatorId, pub role: OperatorRole, pub request_id: RequestId }

// ---- auth (works while locked) ------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure { Malformed, UnknownAgent, NoKeyMatch, KeyExpired, KeyRevoked, AgentInactive,
                       IpNotAllowed, MtlsMismatch }
pub struct TokenCheckInput<'a> {
    pub raw_token: &'a str,
    pub source_ip: IpAddr,
    pub client_cert_sha256: Option<[u8; 32]>,
    pub request_id: RequestId,
    pub surface: Surface,
}
/// In-memory copy of agent status and key hashes (plain columns). Updated in the same call as the DB write.
/// Rebuilt at unlock with row-MAC checks (ADR-0033); rows with a bad MAC count as revoked.
pub struct AuthTable { /* RwLock<HashMap<AgentId, AgentAuth>> */ }
impl AuthTable {
    pub fn check(&self, input: &TokenCheckInput<'_>, now: jiff::Timestamp) -> Result<AgentContext, AuthFailure>;
}

// ---- events for the UI and SSE ------------------------------------------------------------------
#[derive(Clone, Debug)]
pub enum CoreEvent {
    StateChanged(VaultStateKind),
    AccessRequestCreated(AccessRequestId),
    AccessRequestResolved { id: AccessRequestId, status: AccessRequestStatus },
    AgentActivity { agent_id: AgentId, event_type: &'static str, item_id: Option<ItemId>, at: jiff::Timestamp },
    LeaseChanged(LeaseId),
    AutoLockTick { seconds_left: u64 },
    MassReadAlert { agent_id: AgentId, distinct_items: u32 },
    HeaderMismatch,
    /// A row MAC failed (ADR-0033). Table name and row ID only.
    IntegrityAlert { table: &'static str, row_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsEvent { Sleep, ScreenLocked }

// ---- config -------------------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub approvals_available: bool,           // false on cerberusd (ADR-0002)
    pub idle_lock_default: Option<std::time::Duration>,
    pub max_unlocked_default: Option<std::time::Duration>, // 12 h on the desktop, None on cerberusd (DEC-SRV-1)
    pub data_dir: std::path::PathBuf,
}

// ---- the service --------------------------------------------------------------------------------
/// Owns key custody, the index and all engines. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct VaultService { /* inner: Arc<Inner> */ }
impl VaultService {
    pub async fn open(store: cerberus_store::Store, clock: Arc<dyn Clock>, config: CoreConfig) -> Result<Self, CoreError>;
    pub fn state(&self) -> VaultStateKind;
    pub fn auth(&self) -> &AuthTable;
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CoreEvent>;
    pub fn on_os_event(&self, event: OsEvent);
    /// Called by the API layer after each authenticated agent call (idle timer, ADR-0026).
    pub fn note_agent_activity(&self, ctx: &AgentContext);
    /// Writes to `audit_pending` while locked, to the chain while unlocked.
    pub async fn audit_locked_call(&self, ctx: Option<&AgentContext>, route: &'static str, code: ErrorCode);
    /// Sync and allocation-free; used by the panic hook (ADR-0026).
    pub fn emergency_wipe(&self);
    /// Start background loops: sweeper, idle lock, approval expiry, audit prune.
    pub fn spawn_background(&self) -> Vec<tokio::task::JoinHandle<()>>;
    /// Admin API (ADR-0034 point 6.3): checks the phrase of the live session's operator with the
    /// KDF and a constant-time VMK compare; no state change. Failures count in the back-off.
    pub async fn verify_operator_phrase(&self, operator: OperatorId, phrase: cerberus_crypto::SecretString)
        -> Result<OperatorContext, CoreError>;
    /// Admin API audit events (`admin.*`): to the chain while unlocked; `api_start`,
    /// `session_close` and `client_revoke` to `audit_pending` while sealed.
    pub async fn record_admin_event(&self, ctx: Option<&OperatorContext>, event: AdminAudit) -> Result<(), CoreError>;
}

// ---- key custody (T05) --------------------------------------------------------------------------
pub struct NewVault {
    pub owner_label: String,
    pub phrase: cerberus_crypto::SecretString,
    pub kdf: cerberus_crypto::KdfParams,
    pub host_names: Vec<String>,
}
pub struct CreatedVault { pub owner_id: OperatorId, pub recovery_key: cerberus_crypto::SecretString,
                          pub ca_pin: String }
pub struct OperatorInfo { pub id: OperatorId, pub label: String, pub role: OperatorRole,
                          pub last_unlock_at: Option<jiff::Timestamp> }

pub trait KeyCustody: Send + Sync {
    fn create_vault(&self, new: NewVault) -> impl Future<Output = Result<CreatedVault, CoreError>> + Send;
    fn unlock_with_phrase(&self, operator: OperatorId, phrase: cerberus_crypto::SecretString)
        -> impl Future<Output = Result<OperatorContext, CoreError>> + Send;
    fn unlock_with_recovery(&self, recovery: cerberus_crypto::RecoveryKey)
        -> impl Future<Output = Result<OperatorContext, CoreError>> + Send;
    fn lock(&self, reason: LockReason) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Revoke all leases, cancel all requests, then lock (panic button).
    fn panic_lock(&self, ctx: &OperatorContext) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn list_operators(&self) -> impl Future<Output = Result<Vec<OperatorInfo>, CoreError>> + Send;
    fn add_operator(&self, ctx: &OperatorContext, label: String, role: OperatorRole,
                    phrase: cerberus_crypto::SecretString) -> impl Future<Output = Result<OperatorId, CoreError>> + Send;
    fn remove_operator(&self, ctx: &OperatorContext, id: OperatorId) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn set_operator_role(&self, ctx: &OperatorContext, id: OperatorId, role: OperatorRole)
        -> impl Future<Output = Result<(), CoreError>> + Send;
    fn change_phrase(&self, ctx: &OperatorContext, current: cerberus_crypto::SecretString,
                     new: cerberus_crypto::SecretString) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn rotate_recovery_key(&self, ctx: &OperatorContext)
        -> impl Future<Output = Result<cerberus_crypto::SecretString, CoreError>> + Send;
}

// ---- Agent API (REST and MCP call only this) ----------------------------------------------------
pub enum RevealOutcome { Secret(SecretResponse), Pending(PendingResponse) }
pub enum TotpOutcome { Code(TotpResponse), Pending(PendingResponse) }
pub enum SshOutcome { Ready(SshPrepareResponse), Pending(PendingResponse) }
pub type AccessRequestStream = std::pin::Pin<Box<dyn futures_core::Stream<Item = AccessRequestView> + Send>>;

pub trait AgentApi: Send + Sync {
    fn status(&self, ctx: &AgentContext) -> impl Future<Output = Result<StatusResponse, CoreError>> + Send;
    fn resolve(&self, ctx: &AgentContext, req: ResolveRequest) -> impl Future<Output = Result<ResolveResponse, CoreError>> + Send;
    fn catalog(&self, ctx: &AgentContext, query: CatalogQuery) -> impl Future<Output = Result<CatalogPage, CoreError>> + Send;
    fn reveal(&self, ctx: &AgentContext, id: ItemId, req: RevealRequest) -> impl Future<Output = Result<RevealOutcome, CoreError>> + Send;
    fn totp(&self, ctx: &AgentContext, id: ItemId, req: TotpRequest) -> impl Future<Output = Result<TotpOutcome, CoreError>> + Send;
    fn create_item(&self, ctx: &AgentContext, req: CreateItemRequest) -> impl Future<Output = Result<CreatedItem, CoreError>> + Send;
    fn create_session(&self, ctx: &AgentContext, req: CreateSessionRequest) -> impl Future<Output = Result<CreatedItem, CoreError>> + Send;
    fn delete_item(&self, ctx: &AgentContext, id: ItemId) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn request_access(&self, ctx: &AgentContext, req: CreateAccessRequest) -> impl Future<Output = Result<AccessRequestView, CoreError>> + Send;
    fn get_access_request(&self, ctx: &AgentContext, id: AccessRequestId) -> impl Future<Output = Result<AccessRequestView, CoreError>> + Send;
    /// First item = current state; ends after a terminal state or at expiry.
    fn watch_access_request(&self, ctx: &AgentContext, id: AccessRequestId) -> impl Future<Output = Result<AccessRequestStream, CoreError>> + Send;
    fn release_lease(&self, ctx: &AgentContext, id: LeaseId) -> impl Future<Output = Result<ReleaseResponse, CoreError>> + Send;
    fn ssh_prepare(&self, ctx: &AgentContext, id: ItemId, req: SshPrepareRequest) -> impl Future<Output = Result<SshOutcome, CoreError>> + Send;
}

// ---- Admin API (Tauri IPC only, ADR-0003) -------------------------------------------------------
pub struct WorkspaceInput { pub slug: String, pub name: String, pub description: String, pub aliases: Vec<String> }
pub struct WorkspaceView { pub id: WorkspaceId, pub slug: String, pub name: String, pub description: String,
                           pub aliases: Vec<String>, pub item_count: u32 }
pub struct ItemInput<P = items::Payload> {
    pub workspace_id: WorkspaceId, pub kind: ItemKind, pub title: String, pub description: String,
    pub role_label: Option<String>, pub category: String, pub tags: Vec<String>, pub environment: Environment,
    pub target: Option<String>, pub expires_at: Option<jiff::Timestamp>, pub max_uses: Option<u32>,
    pub payload: P,
}
/// What an update does with the secret (DEC-INT10-6).
pub enum PayloadChange { Keep, Replace(items::Payload) }
/// `update_item` takes `impl Into<ItemUpdate>`; an `ItemInput` converts to `Replace`.
pub type ItemUpdate = ItemInput<PayloadChange>;
pub struct ItemDetail { pub summary: ItemSummary, pub version: u32, pub use_count: u32, pub max_uses: Option<u32>,
                        pub exposed_to: Vec<(AgentId, jiff::Timestamp)> }
pub struct ItemVersionInfo { pub version: u32, pub created_at: jiff::Timestamp, pub title: String }
pub struct ItemFilter { pub workspace_id: Option<WorkspaceId>, pub environment: Option<Environment>,
                        pub kind: Option<ItemKind>, pub tag: Option<String>, pub q: Option<String> }
pub struct AgentInput { pub name: String, pub description: String }
pub struct AgentView { pub id: AgentId, pub name: String, pub description: String, pub status: cerberus_store::AgentStatus,
                       pub keys: Vec<AgentKeyView>, pub last_seen_at: Option<jiff::Timestamp> }
pub struct AgentKeyView { pub id: AgentKeyId, pub hint: String, pub scopes: Vec<Scope>,
                          pub expires_at: Option<jiff::Timestamp>, pub revoked_at: Option<jiff::Timestamp>,
                          pub last_used_at: Option<jiff::Timestamp>, pub require_mtls: bool }
pub struct AgentKeyInput { pub scopes: Vec<Scope>, pub lifetime_days: Option<u32>, pub ip_allowlist: Vec<ipnet::IpNet>,
                           pub require_mtls: bool }
/// The token text is in a SecretString; the UI shows it one time.
pub struct NewAgentKey { pub key: AgentKeyView, pub token: cerberus_crypto::SecretString }
pub struct ClientCertBundle { pub cert_pem: String, pub key_pem: cerberus_crypto::SecretString, pub sha256: [u8; 32] }
pub struct RevealedSecret { pub item_id: ItemId, pub payload: items::Payload }
pub struct AccessRequestDetail { pub view: AccessRequestView, pub agent_id: AgentId, pub agent_name: String,
                                 pub item_title: String, pub item_kind: ItemKind, pub role_label: Option<String>,
                                 pub environment: Environment,
                                 /// Untrusted. Control and format (Cf) characters removed. Max 500 chars.
                                 pub reason: String, pub burst_warning: bool }
pub struct LeaseDetail { pub view: LeaseView, pub agent_id: AgentId, pub source: cerberus_store::LeaseSource,
                         pub uses: u32, pub created_at: jiff::Timestamp }
pub struct AuditQuery { pub from: Option<jiff::Timestamp>, pub to: Option<jiff::Timestamp>,
                        pub event_type: Option<String>, pub agent_id: Option<AgentId>, pub item_id: Option<ItemId>,
                        pub outcome: Option<AuditOutcome>, // Ok = result "ok", Failed = any error code (DEC-INT10-11)
                        pub before_seq: Option<u64>, pub limit: u32,
                        pub text: Option<String> } // 1..200 chars, no case; metadata only (DEC-T27-A2-8)
pub enum AuditOutcome { Ok, Failed }
pub struct AuditEntry { pub seq: u64, pub occurred_at: jiff::Timestamp, pub event: audit::AuditEvent }
pub struct SettingsView { pub values: std::collections::BTreeMap<String, serde_json::Value> }

pub trait AdminApi: Send + Sync {
    fn list_workspaces(&self, ctx: &OperatorContext) -> impl Future<Output = Result<Vec<WorkspaceView>, CoreError>> + Send;
    fn put_workspace(&self, ctx: &OperatorContext, id: Option<WorkspaceId>, input: WorkspaceInput) -> impl Future<Output = Result<WorkspaceView, CoreError>> + Send;
    fn delete_workspace(&self, ctx: &OperatorContext, id: WorkspaceId) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn list_items(&self, ctx: &OperatorContext, filter: ItemFilter) -> impl Future<Output = Result<Vec<ItemSummary>, CoreError>> + Send;
    fn get_item(&self, ctx: &OperatorContext, id: ItemId) -> impl Future<Output = Result<ItemDetail, CoreError>> + Send;
    fn create_item(&self, ctx: &OperatorContext, input: ItemInput) -> impl Future<Output = Result<ItemDetail, CoreError>> + Send;
    fn update_item(&self, ctx: &OperatorContext, id: ItemId, input: impl Into<ItemUpdate>) -> impl Future<Output = Result<ItemDetail, CoreError>> + Send;
    fn delete_item(&self, ctx: &OperatorContext, id: ItemId) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn reveal_item(&self, ctx: &OperatorContext, id: ItemId) -> impl Future<Output = Result<RevealedSecret, CoreError>> + Send;
    fn item_versions(&self, ctx: &OperatorContext, id: ItemId) -> impl Future<Output = Result<Vec<ItemVersionInfo>, CoreError>> + Send;
    fn restore_item_version(&self, ctx: &OperatorContext, id: ItemId, version: u32) -> impl Future<Output = Result<ItemDetail, CoreError>> + Send;
    fn totp_preview(&self, ctx: &OperatorContext, id: ItemId) -> impl Future<Output = Result<TotpResponse, CoreError>> + Send;

    fn list_agents(&self, ctx: &OperatorContext) -> impl Future<Output = Result<Vec<AgentView>, CoreError>> + Send;
    fn create_agent(&self, ctx: &OperatorContext, input: AgentInput, key: AgentKeyInput) -> impl Future<Output = Result<(AgentView, NewAgentKey), CoreError>> + Send;
    fn update_agent(&self, ctx: &OperatorContext, id: AgentId, input: AgentInput) -> impl Future<Output = Result<AgentView, CoreError>> + Send;
    fn set_agent_status(&self, ctx: &OperatorContext, id: AgentId, status: cerberus_store::AgentStatus) -> impl Future<Output = Result<AgentView, CoreError>> + Send;
    fn create_agent_key(&self, ctx: &OperatorContext, agent: AgentId, key: AgentKeyInput) -> impl Future<Output = Result<NewAgentKey, CoreError>> + Send;
    fn rotate_agent_key(&self, ctx: &OperatorContext, key: AgentKeyId, overlap: std::time::Duration) -> impl Future<Output = Result<NewAgentKey, CoreError>> + Send;
    fn revoke_agent_key(&self, ctx: &OperatorContext, key: AgentKeyId) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn issue_client_cert(&self, ctx: &OperatorContext, key: AgentKeyId) -> impl Future<Output = Result<ClientCertBundle, CoreError>> + Send;

    fn list_grants(&self, ctx: &OperatorContext, agent: Option<AgentId>) -> impl Future<Output = Result<Vec<policy::Grant>, CoreError>> + Send;
    fn put_grant(&self, ctx: &OperatorContext, grant: policy::GrantInput) -> impl Future<Output = Result<policy::Grant, CoreError>> + Send;
    fn delete_grant(&self, ctx: &OperatorContext, id: GrantId) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn simulate(&self, ctx: &OperatorContext, agent: AgentId) -> impl Future<Output = Result<Vec<policy::SimulationRow>, CoreError>> + Send;

    fn pending_requests(&self, ctx: &OperatorContext) -> impl Future<Output = Result<Vec<AccessRequestDetail>, CoreError>> + Send;
    fn approve_request(&self, ctx: &OperatorContext, id: AccessRequestId, option: ApprovalOption) -> impl Future<Output = Result<LeaseView, CoreError>> + Send;
    fn deny_request(&self, ctx: &OperatorContext, id: AccessRequestId) -> impl Future<Output = Result<(), CoreError>> + Send;

    fn list_leases(&self, ctx: &OperatorContext) -> impl Future<Output = Result<Vec<LeaseDetail>, CoreError>> + Send;
    fn revoke_lease(&self, ctx: &OperatorContext, id: LeaseId) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn revoke_all_leases(&self, ctx: &OperatorContext) -> impl Future<Output = Result<u64, CoreError>> + Send;

    fn audit_query(&self, ctx: &OperatorContext, q: AuditQuery) -> impl Future<Output = Result<Vec<AuditEntry>, CoreError>> + Send;
    fn audit_verify(&self, ctx: &OperatorContext) -> impl Future<Output = Result<audit::ChainReport, CoreError>> + Send;
    fn audit_export(&self, ctx: &OperatorContext, dest: std::path::PathBuf) -> impl Future<Output = Result<u64, CoreError>> + Send;

    fn settings_get(&self, ctx: &OperatorContext) -> impl Future<Output = Result<SettingsView, CoreError>> + Send;
    fn settings_set(&self, ctx: &OperatorContext, key: String, value: serde_json::Value) -> impl Future<Output = Result<SettingsView, CoreError>> + Send;

    /// Custom TLS certificate (ADR-0023 point 8, DEC-FIX9-*). Owner only; the role comes from the session.
    /// The material is sealed in the setting `tls_custom`. Audit: `tls.custom_load`, `tls.custom_revert`.
    fn tls_custom_store(&self, ctx: &OperatorContext, chain_der: &[Vec<u8>], key_der: &SecretBytes) -> impl Future<Output = Result<(), CoreError>> + Send;
    fn tls_custom_clear(&self, ctx: &OperatorContext) -> impl Future<Output = Result<bool, CoreError>> + Send;
    /// For the TLS layer of this process only. Unlocked.
    fn tls_custom_material(&self) -> impl Future<Output = Result<Option<TlsCustomMaterial>, CoreError>> + Send;

    fn backup_create(&self, ctx: &OperatorContext, dest: std::path::PathBuf) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// After a restore: appends `backup.restore` on the restored, unlocked vault (DEC-FIX8-2). Any role; the role comes from the session.
    fn record_restore(&self, ctx: &OperatorContext) -> impl Future<Output = Result<(), CoreError>> + Send;
    /// Allowed for an owner, or in state NoVault (ctx = None).
    fn backup_restore(&self, ctx: Option<&OperatorContext>, src: std::path::PathBuf,
                      unlock: RestoreUnlock) -> impl Future<Output = Result<(), CoreError>> + Send;
}
pub enum RestoreUnlock { Phrase { operator: OperatorId, phrase: cerberus_crypto::SecretString },
                         Recovery(cerberus_crypto::RecoveryKey) }

// VaultService implements KeyCustody, AgentApi and AdminApi.

// ---- submodules ---------------------------------------------------------------------------------
pub mod items {
    use super::*;
    /// Typed payload inside `payload_ct` (ADR-0027). Secret fields use SecretString. Debug is redacted.
    pub enum Payload {
        WebLogin { username: cerberus_crypto::SecretString, password: cerberus_crypto::SecretString,
                   url: Option<String>, totp: Option<TotpSeed> },
        ApiKey { key: cerberus_crypto::SecretString, key_id: Option<String>, header_name: Option<String>, base_url: Option<String> },
        SshKey { private_key: cerberus_crypto::SecretString, passphrase: Option<cerberus_crypto::SecretString>,
                 public_key: String, fingerprint: String },
        SessionToken { token: cerberus_crypto::SecretString, token_type: Option<String>, header_name: Option<String> },
        BrowserSession { storage_state: cerberus_crypto::SecretString, origin: String },
        Database { url: Option<cerberus_crypto::SecretString>, engine: Option<String>, host: Option<String>,
                   port: Option<u16>, database: Option<String>, username: Option<cerberus_crypto::SecretString>,
                   password: Option<cerberus_crypto::SecretString>, params: std::collections::BTreeMap<String, String> },
        Cloud { provider: String, access_key_id: Option<cerberus_crypto::SecretString>,
                secret_access_key: Option<cerberus_crypto::SecretString>, session_token: Option<cerberus_crypto::SecretString>,
                region: Option<String>, extra: std::collections::BTreeMap<String, cerberus_crypto::SecretString> },
        Certificate { cert_pem: String, key_pem: Option<cerberus_crypto::SecretString>, chain_pem: Option<String> },
        EnvBundle { vars: std::collections::BTreeMap<String, cerberus_crypto::SecretString> },
        Note { text: cerberus_crypto::SecretString },
        // DEC-RD-1: ID, servers and key are in `custom` (`rustdesk_id`, `id_server`, `relay_server`, `server_key`).
        Rustdesk { password: Option<cerberus_crypto::SecretString> },
    }
    pub struct TotpSeed { pub secret: cerberus_crypto::SecretString, pub algorithm: TotpAlgorithm, pub digits: u8, pub period: u32 }
    #[derive(Clone, Copy, Debug)]
    pub enum TotpAlgorithm { Sha1, Sha256, Sha512 }

    /// Decrypted metadata (inside `meta_ct`), held by the index.
    #[derive(Clone, Debug)]
    pub struct ItemMeta {
        pub id: ItemId, pub kind: ItemKind, pub workspace_id: WorkspaceId, pub title: String,
        pub description: String, pub role_label: Option<String>, pub category: String, pub tags: Vec<String>,
        pub environment: Environment, pub target: Option<String>, pub created_by: CreatedBy,
        pub max_uses: Option<u32>, pub use_count: u32, pub expires_at: Option<jiff::Timestamp>,
        pub updated_at: jiff::Timestamp, pub has_totp: bool,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CreatedBy { Operator(OperatorId), Agent(AgentId) }

    pub fn validate(kind: ItemKind, meta: &ItemMeta, payload: &Payload) -> Result<(), Vec<FieldProblem>>;
    /// Strips vault-only fields (TOTP seed) and converts to the wire type.
    pub fn to_wire(payload: &Payload) -> SecretPayloadWire;
    pub fn totp_now(seed: &TotpSeed, now: jiff::Timestamp) -> Result<(cerberus_crypto::SecretString, u32), CoreError>;
}

pub mod index {
    use super::*;
    pub struct Index { /* maps listed in ADR-0006 */ }
    impl Index {
        pub fn build(metas: Vec<items::ItemMeta>, workspaces: Vec<WorkspaceView>, grants: Vec<policy::Grant>) -> Self;
        pub fn item(&self, id: &ItemId) -> Option<&items::ItemMeta>;
        pub fn workspace_by_slug(&self, slug: &str) -> Option<WorkspaceId>;
        pub fn grants_for(&self, agent: &AgentId) -> &[policy::Grant];
        pub fn upsert_item(&mut self, meta: items::ItemMeta);
        pub fn remove_item(&mut self, id: &ItemId);
        pub fn iter_items(&self) -> impl Iterator<Item = &items::ItemMeta>;
    }
    pub fn normalize(text: &str) -> String;
    pub fn words(text: &str) -> Vec<String>;
}

pub mod policy {
    use super::*;
    #[derive(Clone, Debug, Default)]
    pub struct Selector { pub workspace_ids: Vec<WorkspaceId>, pub environments: Vec<Environment>,
                          pub categories: Vec<String>, pub tags: Vec<String>, pub kinds: Vec<ItemKind>,
                          pub role_labels: Vec<String>, pub item_ids: Vec<ItemId> }
    #[derive(Clone, Debug)]
    pub struct TimeWindow { pub days: Vec<jiff::civil::Weekday>, pub start: jiff::civil::Time,
                            pub end: jiff::civil::Time, pub tz: String }
    #[derive(Clone, Debug, Default)]
    pub struct Conditions { pub time_window: Option<TimeWindow>, pub max_reads_per_hour: Option<u32>,
                            pub expires_at: Option<jiff::Timestamp>, pub reason_required: bool }
    #[derive(Clone, Debug)]
    pub struct Grant { pub id: GrantId, pub agent_id: AgentId, pub selector: Selector,
                       pub permissions: std::collections::BTreeSet<Permission>, pub mode: GrantMode,
                       pub conditions: Conditions, pub allow_prod_auto: bool,
                       pub created_at: jiff::Timestamp, pub updated_at: jiff::Timestamp }
    #[derive(Clone, Debug)]
    pub struct GrantInput { pub id: Option<GrantId>, pub agent_id: AgentId, pub selector: Selector,
                            pub permissions: std::collections::BTreeSet<Permission>, pub mode: GrantMode,
                            pub conditions: Conditions, pub allow_prod_auto: bool }
    /// What the item looks like to policy. For create checks it is the proposed metadata.
    pub struct PolicyItem<'a> { pub workspace_id: &'a WorkspaceId, pub environment: Environment,
                                pub category: &'a str, pub tags: &'a [String], pub kind: ItemKind,
                                pub role_label: Option<&'a str>, pub item_id: Option<&'a ItemId> }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Decision {
        Allow { mode: GrantMode, grant_id: GrantId },   // mode is Auto | AskOnce | AskAlways
        Deny { grant_id: GrantId },
        NoGrant,
        ConditionFailed { grant_id: GrantId },
        ReasonRequired { grant_id: GrantId },
        GrantRateLimited { grant_id: GrantId, retry_after_seconds: u32 },
    }
    pub struct EvalInput<'a> {
        pub grants: &'a [Grant],
        pub item: PolicyItem<'a>,
        pub permission: Permission,
        pub reason: Option<&'a str>,     // checked for presence only
        pub now: jiff::Timestamp,
    }
    pub trait ReadCounter: Send + Sync {
        /// Sliding one-hour count for (grant, agent); `record` adds one when allowed.
        fn check_and_record(&self, grant: &GrantId, agent: &AgentId, limit: u32, now: jiff::Timestamp) -> Result<(), u32>;
    }
    /// ADR-0017, steps 1–8. Pure apart from the read counter.
    pub fn evaluate(input: &EvalInput<'_>, agent: &AgentId, counter: &dyn ReadCounter) -> Decision;
    pub struct SimulationRow { pub item_id: ItemId, pub title: String, pub permission: Permission, pub decision: Decision }
}

pub mod resolve {
    use super::*;
    pub struct Scored { pub item_id: ItemId, pub score: u32 }
    pub enum ResolveOutcome { Confident(Scored), Candidates(Vec<Scored>), Ambiguous(Vec<Scored>), NoMatch(NoMatchHints) }
    /// ADR-0020. `visible` returns true when policy gives `find`.
    pub fn resolve(index: &index::Index, req: &ResolveRequest, now: jiff::Timestamp,
                   visible: &dyn Fn(&items::ItemMeta) -> bool) -> ResolveOutcome;
}

pub mod leases {
    use super::*;
    pub enum LeaseCheck { Active(cerberus_store::LeaseRow), NeedApproval, Blocked { until: jiff::Timestamp } }
    pub fn check(leases: &[cerberus_store::LeaseRow], mode: GrantMode, now: jiff::Timestamp,
                 wanted: Option<&LeaseId>) -> LeaseCheck;
    pub fn ttl_for(option: ApprovalOption, session_ttl_max: std::time::Duration,
                   item_expires_at: Option<jiff::Timestamp>, now: jiff::Timestamp,
                   next_hard_lock_at: Option<jiff::Timestamp>) -> jiff::Timestamp;
}

pub mod audit {
    use super::*;
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct Actor { pub kind: ActorKind, pub id: Option<String> }
    #[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ActorKind { Agent, Operator, System }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct Target { pub kind: String, pub id: String }
    /// Body inside `body_ct`. No field can hold a Secret* type (they are not Serialize).
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct AuditEvent {
        #[serde(rename = "type")] pub event_type: String,
        pub actor: Actor,
        pub target: Option<Target>,
        pub result: String,
        pub request_id: Option<RequestId>,
        pub details: serde_json::Map<String, serde_json::Value>,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BreakKind { HmacMismatch, PrevHashMismatch, MissingRow, HeadMismatch, UnreadableBody }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ChainReport { Ok { count: u64, first_seq: u64, last_seq: u64 }, Broken { seq: u64, kind: BreakKind } }
    pub fn entry_hash(seq: u64, occurred_at_ms: i64, prev_hash: &[u8; 32], body_ct: &[u8]) -> [u8; 32];
    pub fn genesis_prev_hash(vault: &VaultId) -> [u8; 32];
}
```

**As built (Wave 6, DEC-WIRE6-2, DEC-WIRE6-13).** The Agent API is the struct `cerberus_core::AgentApi`
(`VaultService::agent_api()`), not a trait. `watch_access_request` is `wait_access_request(ctx, id, max_wait)`;
`ssh_prepare` comes with T22. Results are core types (`agent_api::SecretResult` etc.) with the `handling` field set
to `cerberus_types::HANDLING_SECRET`; T10/T11 map them to the wire DTOs above. The admin side is inherent
`VaultService` methods (one per IPC command, see DEC-WIRE6-13); the policy engine is `VaultService::policy()`.

---

## 5. `cerberus-api`

External deps: `axum`, `tower`, `tower-http`, `tokio`, `tokio-rustls`, `rustls`, `rcgen`, `governor`, `utoipa`,
`tokio-stream`, `serde_json`, `tracing`, `thiserror`. Internal: `cerberus-core`, `cerberus-crypto`, `cerberus-types`,
`cerberus-ssh-agent`.

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use cerberus_core::{AgentContext, VaultService};
use cerberus_types::*;

/// Body limits, timeouts and connection budgets (`cerberus-api/src/config.rs`). Defaults are fixed in the build.
#[derive(Clone, Debug)]
pub struct ApiLimits {
    pub body_default_bytes: usize,        // 16 KiB, most routes
    pub body_large_bytes: usize,          // 1 MiB, POST /v1/credentials and POST /v1/sessions
    pub handshake_timeout: Duration,      // 10 s
    pub header_timeout: Duration,         // 10 s, first request head after the handshake (AUD-4)
    pub auth_timeout: Duration,           // 30 s from accept, while no request has authenticated (DEC-T27-D2-1)
    pub idle_timeout: Duration,           // 60 s with no authenticated request running (DEC-T27-D2-1)
    pub max_unauthenticated: usize,       // 64 connections without an authenticated request (DEC-T27-D2-2)
    pub body_timeout: Duration,           // 30 s to read a request body
    pub max_connections: usize,           // 256 open connections
    pub max_connections_per_agent: usize, // 32 authenticated connections per agent (DEC-T27-E-2)
    pub send_timeout: Duration,           // 30 s without hyper pulling a response (DEC-T27-E-2)
    pub shutdown_grace: Duration,         // 10 s for open requests at shutdown (DEC-FIX8-3)
}
impl Default for ApiLimits { fn default() -> Self; }  // the values above

/// Token, request and lockout limits (`cerberus-core/src/auth/limits.rs`, ADR-0030). Defaults are fixed in the build.
/// A good token is limited per agent only; the source fields count failed checks only (DEC-T27-E-1).
#[derive(Clone, Copy, Debug)]
pub struct AuthLimits {
    pub ip_per_second: u32, pub ip_burst: u32,        // 30/s, burst 60: failed checks per source IP
    pub agent_per_second: u32, pub agent_burst: u32,  // 20/s, burst 40: good tokens per agent
    pub failure_max: u32,                              // 10 failed checks per source IP starts a lockout
    pub global_failure_max: u32,                       // 100 failed checks from all sources start a lockout
    pub failure_window_seconds: u32,                   // 300
    pub lockout_seconds: u32,                          // 300
}
impl Default for AuthLimits { fn default() -> Self; }

// Policy limits (secret reads per minute, distinct items per hour, access requests per window, approval wait,
// deny cooldown) are `PolicySettings` in `cerberus-core/src/policy/settings.rs`. The owner can change them.

#[derive(Clone, Debug)]
pub struct TlsPaths { pub leaf_cert_der: std::path::PathBuf, pub leaf_key_der: std::path::PathBuf, pub ca_cert_der: std::path::PathBuf } // the server sends [leaf, CA] (DEC-FIX8-1)

#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub bind: Vec<SocketAddr>,          // default 127.0.0.1:7373 and [::1]:7373
    pub allowed_hosts: Vec<String>,     // leaf SAN names
    pub tls: TlsPaths,
    pub require_client_cert: bool,      // true when a bind address is not loopback
    pub limits: ApiLimits,
}

#[derive(Clone)]
pub struct AppState { pub core: VaultService, /* limiters, config */ }
impl AppState { pub fn new(core: VaultService, config: &ApiConfig) -> Self; }

/// The `/v1` router. The route list is fixed (test `routes_match_openapi`).
pub fn router(state: AppState) -> axum::Router;
/// Layers shared with `/mcp`: request ID, Host/Origin checks, IP limiter, auth, agent limiter, security headers.
pub fn agent_layers(state: AppState, router: axum::Router) -> axum::Router;
/// Bind all addresses with TLS 1.3 only and serve `router(state)` merged with `extra` (the MCP router).
pub async fn serve(config: ApiConfig, state: AppState, extra: axum::Router,
                   shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> Result<(), ApiError>;
pub fn openapi() -> utoipa::openapi::OpenApi;

/// Extractor: the authenticated agent. Rejects with 401/423 (ADR-0008, ADR-0016).
pub struct Agent(pub AgentContext);
/// Extractor: the request ID of this call.
pub struct ReqId(pub RequestId);

/// The one error type with the one IntoResponse (ADR-0021).
#[derive(Debug)]
pub struct ApiError { pub code: ErrorCode, pub request_id: RequestId, pub details: Option<wire::ErrorDetails> }
impl From<(cerberus_core::CoreError, RequestId)> for ApiError { fn from(v: (cerberus_core::CoreError, RequestId)) -> Self; }
impl axum::response::IntoResponse for ApiError { fn into_response(self) -> axum::response::Response; }

pub mod tls {
    use super::*;
    pub fn server_config(cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
                         key: rustls::pki_types::PrivateKeyDer<'static>,
                         client_ca: Option<rustls::pki_types::CertificateDer<'static>>)
        -> Result<Arc<rustls::ServerConfig>, ApiError>;          // TLS 1.3 only, ALPN h2 + http/1.1
    pub struct LocalCa { /* CA key in a Key32-protected buffer while unlocked */ }
    pub struct IssuedCert { pub cert_der: Vec<u8>, pub key_der: cerberus_crypto::SecretBytes, pub not_after: jiff::Timestamp }
    impl LocalCa {
        pub fn create(vault_short_id: &str, now: jiff::Timestamp) -> Result<(Self, IssuedCert), ApiError>;
        pub fn from_parts(cert_der: &[u8], key_der: &cerberus_crypto::SecretBytes) -> Result<Self, ApiError>;
        pub fn issue_leaf(&self, names: &[String], now: jiff::Timestamp) -> Result<IssuedCert, ApiError>;
        pub fn issue_client(&self, agent: &AgentId, now: jiff::Timestamp) -> Result<IssuedCert, ApiError>;
        /// `sha256/<base64>` of the CA SubjectPublicKeyInfo (ADR-0023).
        pub fn pin(&self) -> String;
        pub fn cert_pem(&self) -> String;
    }
    /// Write leaf files with mode 0600 (ADR-0023).
    pub fn write_leaf(paths: &TlsPaths, leaf: &IssuedCert) -> Result<(), ApiError>;
    pub fn leaf_needs_renewal(paths: &TlsPaths, names: &[String], now: jiff::Timestamp) -> Result<bool, ApiError>;
}
```

**As built (T10, DEC-T10-1 to DEC-T10-14).** The signatures above are the plan; the crate differs in these places.
`ApiConfig` has `bind`, `allowed_hosts`, `tls`, `client_ca_der`, `require_client_cert`, `limits`
(`ApiLimits` holds body limits, timeouts and connection budgets. The token and request limits are core `AuthLimits`,
ADR-0030. Neither is a setting in the app or the daemon config. `ApiConfig::loopback(tls)` uses the defaults.)
`AppState::new(core, &config)`. `app(&state, extra)` builds the whole router (with `/v1`, the fallbacks, `extra`, and the
`guard` and `envelope` layers); `router(&state)` is `app` with no extra routes; `agent_layers(&state, router)` adds the token
check (no lock check) in front of `/mcp`. `start(&config, state, app) -> RunningServer` (`local_addrs`, `reload_leaf`,
`shutdown`) and `serve(config, state, app, shutdown_future)` bind with TLS 1.3 only. `ApiError { code, request_id, details }`
has `from_core`, `with_retry_after`, `body` and the one `IntoResponse`. The extractors are the request extensions `ReqId` and
`AgentCtx`, and the body extractor `JsonBody<T>`. In `tls`: `LocalCa` (`create`, `from_parts`, `issue_leaf`, `issue_client`,
`export`, `to_issued`), `IssuedCert` (`sha256`, `cert_pem`, `key_pem`), `CaExport::from_der`, `LocalCaIssuer` (the core
`CaIssuer`), `TlsPaths::in_data_dir`, `leaf_names`, `write_leaf`, `read_leaf`, `leaf_needs_renewal`, `renew_leaf_if_needed`,
`LeafResolver`, `server_config`, `spki_pin`. The wire DTOs are in `cerberus_api::wire`.

**Admin API (ADR-0034, remote-mode plan step 5, DEC-RM-19).** `cerberus-api` also uses `cerberus-admin`. Module
`cerberus_api::admin`, mounted by `app()` only when `ApiConfig::admin` is `Some` (default `None`; the desktop never sets
it). `ApiConfig::validate` refuses `admin` without `client_ca_der` (`ServerError::AdminNeedsClientCa`).

```rust
pub struct AdminConfig { pub state: Arc<AdminState> }          // ApiConfig::admin: Option<AdminConfig>
pub struct AdminLimits {                                         // Default: the values of ADR-0034
    pub session_idle_seconds: u32, pub session_max_seconds: u32, // 900, 43 200
    pub max_sessions: usize, pub max_sessions_per_enrolment: usize, pub max_streams_per_session: usize, // 4, 2, 2
    pub failures_allowed: u32, pub failure_window_seconds: u32, pub failure_block_seconds: u32,           // 5, 900, 900
}
impl AdminState {
    pub fn new(clients: AdminClients, limits: AdminLimits) -> Self;
    pub fn with_registry_file(self, path: PathBuf) -> Self;     // enroll / revoke save it; reload_clients reads it
    pub fn enroll(&self, client: AdminClient) -> Result<(), ClientsError>;
    pub async fn revoke(&self, core: &VaultService, id: EnrolmentId) -> Result<bool, ClientsError>; // ends its sessions, audits
    pub async fn reload_clients(&self, core: &VaultService) -> Result<(), ClientsError>;
    pub fn find_live(&self, cert_sha256: &[u8; 32], now: Timestamp) -> Option<AdminClient>;
    pub fn clients(&self) -> AdminClients; pub fn session_count(&self) -> usize;
    pub fn session_live(&self, core: &VaultService, id: SessionId) -> bool;
    pub async fn sweep(&self, core: &VaultService);
}
impl AppState { pub fn admin(&self) -> Option<&Arc<AdminState>>; }
pub fn status_of(ipc_code: &str) -> u16;                         // the admin status table
```

Routes (paths in `cerberus_admin::wire`): `GET /admin/v1/hello` (`HelloView`), `POST /admin/v1/session` (body
`VaultUnlockArgs`, 8 KiB; answer `SessionOpenedView`), `DELETE /admin/v1/session` (204), `POST /admin/v1/rpc/{command}`
(`application/json`, 16 KiB, 1 MiB for `item_create` / `item_update`; answer the IPC result JSON), `GET /admin/v1/events`
(SSE, `event: <WireEvent::name()>`, `data: <WireEvent JSON>`, `: keep-alive` every 15 s). Errors are
`AdminErrorBody { request_id, error: IpcError }`; `origin_refused` and `route_not_found` keep the ADR-0021 shape. The
connection of a session request is bound to the session (`idle::ConnOwner::Admin`) and closes within about 1 s after
the session ends; `vault_lock` and `vault_panic` run unbound, bind again when they fail, and answer with
`Connection: close` when they succeed. Only `cerberus_admin::remote::ACTIVITY_COMMANDS` (`ui_activity` and the actions
of a person, never a read) reset the session idle limit and count as operator activity (DEC-RM-26). A sweeper task (started by `start`) ends sessions at every vault state change and every 15 s. Core
gained `VaultService::lock_epoch()` for the session binding.

---

## 6. `cerberus-mcp`

External deps: `rmcp` (server, transport-streamable-http-server), `axum`, `serde_json`, `schemars` (through rmcp),
`tokio`. Internal: `cerberus-api` (layers, error mapping), `cerberus-core`, `cerberus-types`, `cerberus-client` (shim only).

```rust
use cerberus_core::VaultService;

/// Tool names. Order matches docs/api/mcp-tools.md.
pub const TOOL_NAMES: [&str; 8] = [
    "vault_status", "find_credentials", "get_credential", "request_access",
    "get_totp", "store_secret", "release_credential", "ssh_prepare",
];
pub const CATALOG_URI: &str = "cerberus://catalog";

/// The MCP server handler. Implements `rmcp::ServerHandler` with one `#[tool]` method per tool name.
/// Each tool takes the `AgentContext` from the HTTP request extensions and calls `AgentApi`.
#[derive(Clone)]
pub struct CerberusMcp { /* core: VaultService */ }
impl CerberusMcp { pub fn new(core: VaultService) -> Self; }

/// `/mcp` router (Streamable HTTP), already wrapped by `cerberus_api::agent_layers`.
pub fn mcp_router(state: cerberus_api::AppState) -> axum::Router;

/// Tool error result: isError = true; structuredContent and text = the ADR-0021 error object.
pub fn tool_error(err: &cerberus_core::CoreError, request_id: cerberus_types::RequestId) -> rmcp::model::CallToolResult;

// ---- stdio shim (bin `cerberus-mcp`) -------------------------------------------------------------
pub mod shim {
    #[derive(Debug)]
    pub struct ShimConfig { pub client: cerberus_client::ClientConfig }
    impl ShimConfig { pub fn from_env() -> Result<Self, cerberus_client::ClientError>; }
    /// Read JSON-RPC from stdin, POST to `/mcp`, write replies to stdout. Logs to stderr only.
    pub async fn run_stdio(config: ShimConfig) -> Result<(), cerberus_client::ClientError>;
}
```

**As built (T11, DEC-T11-1 to DEC-T11-9).** `CerberusMcp::new(VaultService)`; `mcp_router(&AppState) -> Router` (the `/mcp` path,
already wrapped by `agent_layers`; pass it to `cerberus_api::app` as `extra`). Also public: `TOOL_NAMES`, `CATALOG_URI`, `MCP_PATH`,
`HANDLING_LINE`, `LOG_DIRECTIVE` and `tool_error(CoreError, RequestId) -> CallToolResult` (by value). The shim is
`shim::{ShimConfig, run_stdio, run}` behind the default feature `shim`; `run(config, reader, writer)` works on any reader and writer.

---

## 7. `cerberus-client`

External deps: `reqwest` 0.13 (rustls only, json, stream; no native-tls), `rustls`, `sha2`, `base64`, `url`, `tokio`,
`futures-core`, `serde_json`, `thiserror`. Internal: `cerberus-types` only.

```rust
use cerberus_types::{wire::*, *};

#[derive(Clone, Debug)]
pub enum Trust {
    /// PEM file of the Cerberus CA (exported from the app).
    CaFile(std::path::PathBuf),
    /// `sha256/<base64>` SPKI pin of the CA. Checked on every handshake.
    Pin(String),
    /// Both: the chain must verify and the pin must match.
    CaFileAndPin { ca: std::path::PathBuf, pin: String },
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub base_url: url::Url,             // default https://127.0.0.1:7373
    pub token: WireSecret,              // from CERBERUS_TOKEN or CERBERUS_TOKEN_FILE, never argv
    pub trust: Trust,
    pub client_cert: Option<(std::path::PathBuf, std::path::PathBuf)>, // mTLS cert + key PEM
    pub timeout: std::time::Duration,
}
impl ClientConfig { pub fn from_env() -> Result<Self, ClientError>; }

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{code:?}: {message} (request {request_id:?})")]
    Api { status: u16, code: ErrorCode, message: String, request_id: Option<RequestId>, retryable: bool,
          details: Option<ErrorDetails> },
    #[error("transport error")]            Transport(#[from] reqwest::Error),
    #[error("certificate pin mismatch")]   PinMismatch,
    #[error("bad configuration: {0}")]     Config(String),
    #[error("unexpected response")]        Decode,
    #[error("io error")]                   Io(#[from] std::io::Error),
}

pub enum RevealResult { Secret(SecretResponse), Pending(PendingResponse) }
pub enum TotpResult { Code(TotpResponse), Pending(PendingResponse) }
pub enum SshResult { Ready(SshPrepareResponse), Pending(PendingResponse) }
pub type RequestEvents = std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<AccessRequestView, ClientError>> + Send>>;

#[derive(Clone)]
pub struct Client { /* reqwest::Client with custom rustls verifier, config */ }
impl Client {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError>;
    pub async fn health(&self) -> Result<HealthResponse, ClientError>;
    pub async fn status(&self) -> Result<StatusResponse, ClientError>;
    pub async fn resolve(&self, req: &ResolveRequest) -> Result<ResolveResponse, ClientError>;
    pub async fn catalog(&self, query: &CatalogQuery) -> Result<CatalogPage, ClientError>;
    pub async fn reveal(&self, id: ItemId, req: &RevealRequest) -> Result<RevealResult, ClientError>;
    pub async fn totp(&self, id: ItemId, req: &TotpRequest) -> Result<TotpResult, ClientError>;
    pub async fn create_item(&self, req: &CreateItemRequest) -> Result<CreatedItem, ClientError>;
    pub async fn create_session(&self, req: &CreateSessionRequest) -> Result<CreatedItem, ClientError>;
    pub async fn delete_item(&self, id: ItemId) -> Result<(), ClientError>;
    pub async fn request_access(&self, req: &CreateAccessRequest) -> Result<AccessRequestView, ClientError>;
    pub async fn get_request(&self, id: AccessRequestId) -> Result<AccessRequestView, ClientError>;
    pub async fn watch_request(&self, id: AccessRequestId) -> Result<RequestEvents, ClientError>;
    /// Wait for a terminal state (SSE, falls back to polling every 2 s).
    pub async fn wait_request(&self, id: AccessRequestId, max: std::time::Duration) -> Result<AccessRequestView, ClientError>;
    pub async fn release_lease(&self, id: LeaseId) -> Result<ReleaseResponse, ClientError>;
    pub async fn ssh_prepare(&self, id: ItemId, req: &SshPrepareRequest) -> Result<SshResult, ClientError>;
    /// Raw JSON-RPC POST to `/mcp` for the stdio shim. Returns the response body and the MCP session header.
    pub async fn mcp_post(&self, body: Vec<u8>, session: Option<&str>) -> Result<(Vec<u8>, Option<String>), ClientError>;
}

pub mod run {
    use super::*;
    /// Options of `cerberus run` (ADR-0028).
    #[derive(Debug, Clone)]
    pub struct RunOptions {
        pub app: String, pub environment: Option<String>, pub role: Option<String>, pub kind: Option<ItemKind>,
        pub item_id: Option<ItemId>, pub purpose: String,
        pub vars: Vec<(String, String)>,     // NAME=field overrides
        pub mask_output: bool,               // default true
        pub pass_token: bool,                // default false
        pub wait: std::time::Duration,       // default 120 s
        pub command: Vec<std::ffi::OsString>,
    }
    /// Run the child with injected env. Returns the child exit code, or 70..=74 for CLI errors.
    pub async fn run(client: &Client, opts: RunOptions) -> i32;
    /// Default env names for a payload (ADR-0028 item 3).
    pub fn env_for(payload: &SecretPayloadWire) -> Vec<(String, WireSecret)>;
    /// Streaming masker for stdout/stderr.
    pub struct Masker { /* needles: Vec<Vec<u8>>, window: usize */ }
    impl Masker {
        pub fn new(secrets: &[&[u8]]) -> Self;
        pub fn push(&mut self, chunk: &[u8]) -> Vec<u8>;
        pub fn finish(self) -> Vec<u8>;
    }
}
```

**Admin transport (ADR-0034, remote-mode plan step 7, DEC-RM-21).** For the desktop in remote mode (step 8):

```rust
impl PinnedHttps {
    /// Client certificate (PEM chain file, PKCS#8 PEM key file), no token of its own.
    pub fn with_client_cert(base_url: &str, trust: &Trust, cert_and_key: (PathBuf, PathBuf),
                            call_timeout: Duration) -> Result<Self, ClientError>;
    /// `Some`: `Authorization: Bearer <bearer>` (sensitive) on this request; `None`: no Authorization.
    pub async fn send_bearer(&self, request: Request<'_>, bearer: Option<&WireSecret>) -> Result<Response, ClientError>;
}
impl Response { pub async fn bytes_zeroizing(self, limit: usize) -> Result<Zeroizing<Vec<u8>>, ClientError>; }
pub fn zeroizing_body(body: Zeroizing<Vec<u8>>) -> Bytes;  // request body wiped after the send
pub struct EventStream;                                     // generic SSE reader
impl EventStream {
    pub fn new(response: Response) -> Self;
    /// (event name, data): `message` without `event:`, data lines joined with `\n`, comments and
    /// data-less blocks skipped; `None` at the end of the stream.
    pub async fn next(&mut self) -> Option<Result<(String, Vec<u8>), ClientError>>;
}
```
`Request` still drops a caller-set `Authorization`. `RequestEvents` is built on `EventStream`.

---

## 8. `cerberus-ssh-agent` (T22, summary)

```rust
pub struct SshSocket { pub path: std::path::PathBuf, pub expires_at: jiff::Timestamp }
pub trait SignKey: Send + Sync {
    fn public_key(&self) -> &ssh_key::PublicKey;
    fn sign(&self, data: &[u8]) -> Result<ssh_key::Signature, ssh_key::Error>;
}
/// Opens a 0600 Unix socket in a 0700 runtime dir. Serves only REQUEST_IDENTITIES and SIGN_REQUEST
/// for one key, until `expires_at` or until the lease ends or the vault locks.
pub async fn serve_one_key(key: std::sync::Arc<dyn SignKey>, runtime_dir: &std::path::Path,
                           expires_at: jiff::Timestamp, stop: tokio::sync::watch::Receiver<bool>)
    -> std::io::Result<SshSocket>;
```

---

## 9. Tauri IPC commands (admin only, ADR-0003)

All commands are `#[tauri::command] #[specta::specta] async fn`. Each takes `tauri::Window` (to check the label) and
`tauri::State<'_, DesktopState>`, and returns `Result<T, IpcError>` where
`IpcError { code: String, message: String }`. Column "Window" = allowed window labels. Column "Role" = minimum role
(ADR-0009); `—` = works without unlock. Column "Remote" = what the command does in remote mode (ADR-0034, DEC-RM-6):
`device` and `session` = sent to `POST /admin/v1/rpc/{command}` (`device`: no admin session needed), `session route` =
`POST /admin/v1/session`, `desktop` = runs on the desktop in both modes, `local` = refused with `remote_unsupported`
before any network call (DEC-RM-11). The list is `cerberus_admin::remote::REMOTE_COMMANDS`; `remote_status` returns it.

| Command | Args → Result | Window | Role | Remote |
|---|---|---|---|---|
| `vault_status` | `() → VaultStatusView { state, operator?, role?, idle_seconds_left?, hard_lock_at?, memlock_ok, os_hook_ok, header_ok, kdf?, last_lock_reason?, failed_unlocks, free_unlock_tries_left, retry_after_seconds? }` (see below) | main, approval | — | device |
| `vault_list_operators` | `() → Vec<OperatorPublic { id, label, role }>` | main | — | device |
| `vault_create` | `{ owner_label, phrase, kdf: KdfParams, host_names } → CreatedVaultView { owner_id, recovery_key, ca_pin }` | main | — (NoVault only) | local |
| `vault_unlock` | `{ operator_id, phrase } → SessionView` | main | — | session route |
| `vault_unlock_recovery` | `{ recovery_key } → SessionView` | main | — | local |
| `vault_lock` | `() → ()` | main, approval | viewer | session |
| `vault_panic` | `() → ()` | main, approval | viewer | session |
| `kdf_benchmark` | `() → KdfTuning` | main | — | local |
| `passphrase_strength` | `{ phrase, user_inputs } → Strength` | main | — | local |
| `passphrase_generate` | `{ words } → String` | main | — | local |
| `phrase_change` | `{ current, new, kdf? } → ()` | main | viewer (own slot) | local |
| `recovery_rotate` | `() → String` (shown once) | main | owner | local |
| `operator_add` | `{ label, role, phrase } → OperatorPublic` | main | owner | local |
| `operator_remove` | `{ id } → ()` | main | owner | local |
| `operator_set_role` | `{ id, role } → ()` | main | owner | local |
| `workspace_list` | `() → Vec<WorkspaceView>` | main | viewer | session |
| `workspace_put` | `{ id?, input: WorkspaceInput } → WorkspaceView` | main | operator | session |
| `workspace_delete` | `{ id } → ()` (409 if not empty) | main | operator | local |
| `item_list` | `{ filter: ItemFilter } → Vec<ItemSummaryView>` (has `custom: Map<string,string>`, metadata only, DEC-INT10-7) | main | viewer | session |
| `item_get` | `{ id } → ItemDetail` | main | viewer | session |
| `item_create` | `{ input: ItemInput } → ItemDetail` | main | operator | session |
| `item_update` | `{ item, input: ItemInputView } → ItemDetailView`. `input.payload = { kind: "keep" }` changes the metadata only (DEC-INT10-6) | main | operator | session |
| `item_delete` | `{ id } → ()` | main | operator | session |
| `item_reveal` | `{ id } → RevealedSecretView` (UI hides after 15 s) | main | operator | session |
| `item_versions` | `{ id } → Vec<ItemVersionInfo>` | main | viewer | local |
| `item_restore_version` | `{ id, version } → ItemDetail` | main | operator | local |
| `item_totp_preview` | `{ id } → TotpView` | main | operator | session |
| `clipboard_copy_secret` | `{ item_id, field } → ()` (cleared after 30 s) | main | operator | local |
| `password_generate` | `{ length, classes } → String` | main | operator | local |
| `ssh_key_generate` | `{ comment } → SshKeyDraft { public_key, fingerprint }` (private key stays in backend draft) | main | operator | local |
| `ssh_key_import` | `{ path or pem, passphrase? } → SshKeyDraft` | main | operator | local |
| `agent_list` | `() → Vec<AgentView>` | main | viewer | session |
| `agent_create` | `{ input: AgentInput, key: AgentKeyInput } → { agent: AgentView, token: String }` (token shown once) | main | operator | local |
| `agent_update` | `{ id, input } → AgentView` | main | operator | local |
| `agent_set_status` | `{ id, status } → AgentView` | main | operator | local |
| `agent_key_create` | `{ agent_id, key } → { key: AgentKeyView, token: String }` | main | operator | local |
| `agent_key_rotate` | `{ key_id, overlap_seconds } → { key: AgentKeyView, token: String }` | main | operator | local |
| `agent_key_revoke` | `{ key_id } → ()` | main | operator | local |
| `agent_issue_client_cert` | `{ key_id, dest_dir } → { cert_path, key_path, sha256 }` | main | owner | local |
| `agent_snippets` | `{ agent_id } → Snippets { mcp_json, curl, env }` (no token inside) | main | viewer | local |
| `grant_list` | `{ agent_id? } → Vec<Grant>` | main | viewer | session |
| `grant_put` | `{ input: GrantInput } → Grant` (`allow_prod_auto` needs owner) | main | operator | session |
| `grant_delete` | `{ id } → ()` | main | operator | session |
| `policy_simulate` | `{ agent_id } → Vec<SimulationRow>` | main | viewer | local |
| `request_list_pending` | `() → Vec<AccessRequestView>` (also `item_kind`, `role_label`: metadata, DEC-T27-A2-7) | main, approval | viewer | session |
| `request_approve` | `{ id, option: ApprovalOption } → LeaseView` | approval, main | operator | session |
| `request_deny` | `{ id } → ()` | approval, main | operator | session |
| `lease_list` | `() → Vec<LeaseDetail>` | main | viewer | session |
| `lease_revoke` | `{ id } → ()` | main | viewer | session |
| `lease_revoke_all` | `() → u64` | main | viewer | local |
| `audit_query` | `{ query: AuditQueryView { from?, to?, event_type?, agent_id?, item_id?, outcome?: "ok" \| "failed", before_seq?, limit, text? } } → Vec<AuditEntryView>` (`text` matches event type, target, actor ID, agent name and item title, DEC-T27-A2-8) | main | viewer | session |
| `audit_verify` | `() → ChainReport` | main | viewer | local |
| `audit_export` | `{ dest } → u64` | main | viewer | local |
| `settings_get` | `() → SettingsView` | main | viewer | local |
| `settings_set` | `{ key, value } → SettingsView` (owner-only keys listed in ADR-0009) | main | operator | local |
| `network_status` | `() → NetworkView { bind, port, listening, error, pin, ca_fingerprint, leaf_not_after, custom_cert, mtls_required }` (`pin` and `ca_fingerprint` are of the active chain) | main | viewer | local |
| `network_set_bind` | `{ addrs, port } → NetworkView` | main | owner | local |
| `tls_export_ca` | `{ dest } → ()` | main | viewer | local |
| `tls_load_custom` | `{ chain_path, key_path } → NetworkView` (PEM files; checks, seals in the vault, serves with no restart; the pin changes, DEC-FIX9-1) | main | owner | local |
| `tls_use_local_ca` | `() → NetworkView` (removes the custom certificate; the local CA chain is served again) | main | owner | local |
| `backup_create` | `{ dest } → ()` | main | operator | local |
| `backup_restore` | `{ src, unlock: RestoreUnlockInput } → ()` | main | owner (or NoVault) | local |
| `csv_preview` | `{ request: CsvImportRequest } → ImportPreviewView` (T23; dry run: counts, row numbers, no secret) | main | operator | local |
| `csv_import` | `{ request: CsvImportRequest } → ImportReport` (T23; all or nothing) | main | operator | local |
| `csv_export` | `{ dest, workspace_id? } → u64` (T23; warns: plain secrets) | main | owner | local |
| `ui_activity` | `() → ()` (resets the idle timer; rate-limited to 1/s) | main, approval | — | session |
| `remote_status` | `() → RemoteOverview { mode: "local" \| "remote", active?, profiles: Vec<RemoteProfileView>, remote_commands }` | main | — | desktop |
| `remote_import_bundle` | `{ path } → RemoteProfileView { id, label, url, ca_pin, ca_sha256, operator_id, not_after, active }` (a file from `file_pick_open`; stages the import, which `remote_activate` stores; no secret comes back) | main | — | desktop |
| `remote_setup_check` | `{ code, url? } → RemoteSetupCheckView { url, state: "pending" \| "locked_out", version }` (`code` is the setup code of `cerberusd setup-code`; `GET /v1/health` over the channel the code pins; `url` replaces the address of the code; errors `validation_failed`, `setup_wrong_server`, `remote_unreachable`, `conflict`, `remote_protocol_mismatch`) | main | — | desktop |
| `remote_setup` | `{ code, owner_label, passphrase, device_label?, url? } → RemoteSetupView { profile?: RemoteProfileView, store_error?: IpcError, recovery_key }` (first-time setup: the server makes the vault; the backend holds the recovery key and the admin bundle the moment it exists, then stores the bundle as a profile that is not active. The key always comes back; if the profile cannot be stored, `profile` is null and `store_error` says why. A staged import is not touched. The bundle certificate is checked inside its validity, so a desktop clock that is behind does not fail it, and its end against the clock. Errors: `unauthenticated`, `too_many_failures`, `conflict`, `validation_failed` with fields, `unavailable`, `internal`, `setup_wrong_server`, `remote_unreachable`, `setup_unconfirmed` (timeout, broken connection or unreadable answer: the vault may exist)) | main | — | desktop |
| `remote_setup_save` | `() → RemoteProfileView` (stores the profile again from the bundle that `remote_setup` holds; `not_found` when nothing is held) | main | — | desktop |
| `remote_setup_copy_key` | `() → ()` (copies the recovery key that `remote_setup` holds, with the clipboard clear timer; it has its own lifetime and is not a `clipboard_copy_once` kind; `not_found` when nothing is held) | main | — | desktop |
| `remote_setup_finish` | `() → ()` (drops the held recovery key and bundle; a stored profile stays) | main | — | desktop |
| `remote_discard_import` | `() → ()` (drops a staged import; a stored profile of the same enrolment stays as it was) | main | — | desktop |
| `remote_activate` | `{ profile?, lock_local } → ()` (`null` = local mode; stores a staged import of `profile` first; saves the choice and restarts the app; refused while a local vault is unlocked unless `lock_local`, which locks it after every check passed) | main | — | desktop |
| `remote_disconnect` | `() → ()` (ends this desktop's admin session; the server vault stays as it is) | main | — | desktop |
| `remote_forget` | `{ profile } → ()` (removes a stored profile and its files; refused for the one in use) | main | — | desktop |

`vault_status` fields added by DEC-INT10-8 to DEC-INT10-10:

- `kdf: { m_cost_kib, t_cost, p_cost } | null`: Argon2id cost of the passphrase slot of the session operator. `null` while
  sealed and for a recovery session. No measured time is stored, so there is none.
- `last_lock_reason: "manual" | "idle" | "max_unlocked" | "os" | "quit" | "panic" | "restore" | null`: why the latest lock
  of this run happened. `null` when the vault was not locked in this run. It stays after the next unlock.
- `failed_unlocks`: failed unlocks in a row (from the vault header; a restart keeps it). `free_unlock_tries_left`:
  `5 - failed_unlocks`, not below 0 (`FREE_UNLOCK_FAILURES`). `retry_after_seconds`: seconds until the next try is
  allowed, or `null` when no wait runs.

`vault_status.remote` (ADR-0034 point 7.3, DEC-RM-10): `null` in local mode. In remote mode `RemoteStatusView {
profile_id, label, url, operator_id, not_after, server_state?, reachable, has_session, server_version?, problem? }`;
`state` is then `unlocked` only while this desktop holds an admin session, else `sealed`, and `problem` is the code of
the last failed contact (`remote_unreachable`, `remote_pin_mismatch`, `remote_protocol_mismatch`,
`admin_cert_required`). An unreachable server is a normal answer with `reachable = false`.

`item_update` and the payload: `PayloadView` has the input-only kinds `ssh_key_draft` and `keep`. `keep` leaves the stored
secret, its ciphertext and the version number as they are; the item metadata blobs of the current version are replaced; no
`item.reveal` event is written (`item.update` carries `payload: "kept"`). `item_create` answers `validation_failed` for
`keep`. The kind of an item cannot change with either option.

Backend → UI events (`tauri::Emitter`, typed with `tauri-specta`): `vault-state-changed`, `access-request-created`,
`access-request-resolved`, `agent-activity`, `lease-changed`, `autolock-tick`, `mass-read-alert`, `header-mismatch`,
`integrity-alert`.
Event payloads hold IDs and metadata only, never secret values.

IPC secret values (`item_reveal`, `agent_create` token, `recovery_rotate`, `vault_create` recovery key) cross into the
webview only as the return value of that one call. The UI keeps them in component state and clears it (ADR-0010).
