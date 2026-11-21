//! Types of the item, workspace and secret-generation commands.

use std::collections::BTreeMap;

use cerberus_core::admin::{
    WorkspaceInput as CoreWorkspaceInput, WorkspaceView as CoreWorkspaceView,
};
use cerberus_core::items::{
    ItemDetail as CoreItemDetail, ItemFilter as CoreItemFilter, ItemInput as CoreItemInput,
    ItemSummary as CoreItemSummary, ItemVersionInfo as CoreVersion, Payload, RevealedItem, SshMeta,
    TotpAlgorithm, TotpCode, TotpSeed,
};
use cerberus_crypto::SecretString;
use cerberus_types::wire::WireSecret;
use serde::{Deserialize, Serialize};
use specta::Type;

use super::{Environment, ItemKind, id, opt_id, opt_parse_ts, opt_ts, ts};
use crate::error::IpcResult;

fn secret(text: WireSecret) -> SecretString {
    SecretString::new(text.into_string())
}

fn wire(text: &SecretString) -> WireSecret {
    WireSecret::new(text.expose_secret().to_owned())
}

/// Hash algorithm of a TOTP seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub enum TotpAlgorithmView {
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

/// A TOTP seed. Operators may enter and reveal it; agents never get it.
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct TotpSeedView {
    /// Base32 seed.
    #[specta(type = String)]
    pub secret: WireSecret,
    /// Algorithm.
    pub algorithm: TotpAlgorithmView,
    /// Digits, 6 or 8.
    pub digits: u8,
    /// Period in seconds, 15 to 120.
    pub period: u32,
}

impl TotpSeedView {
    fn into_core(self) -> TotpSeed {
        TotpSeed {
            secret: secret(self.secret),
            algorithm: match self.algorithm {
                TotpAlgorithmView::Sha1 => TotpAlgorithm::Sha1,
                TotpAlgorithmView::Sha256 => TotpAlgorithm::Sha256,
                TotpAlgorithmView::Sha512 => TotpAlgorithm::Sha512,
            },
            digits: self.digits,
            period: self.period,
        }
    }

    fn of(seed: &TotpSeed) -> Self {
        Self {
            secret: wire(&seed.secret),
            algorithm: match seed.algorithm {
                TotpAlgorithm::Sha1 => TotpAlgorithmView::Sha1,
                TotpAlgorithm::Sha256 => TotpAlgorithmView::Sha256,
                TotpAlgorithm::Sha512 => TotpAlgorithmView::Sha512,
            },
            digits: seed.digits,
            period: seed.period,
        }
    }
}

/// The secret part of an item, by kind. The same shape goes in (`item_create`, `item_update`) and
/// out (`item_reveal`).
#[derive(Debug, Serialize, Deserialize, Type)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum PayloadView {
    WebLogin {
        #[specta(type = String)]
        username: WireSecret,
        #[specta(type = String)]
        password: WireSecret,
        url: Option<String>,
        totp: Option<TotpSeedView>,
    },
    ApiKey {
        #[specta(type = String)]
        key: WireSecret,
        key_id: Option<String>,
        header_name: Option<String>,
        base_url: Option<String>,
    },
    SshKey {
        #[specta(type = String)]
        private_key: WireSecret,
        #[specta(type = Option<String>)]
        passphrase: Option<WireSecret>,
        public_key: String,
        fingerprint: String,
    },
    /// An SSH key made by `ssh_key_generate` or `ssh_key_import`. The private key never left the
    /// backend: the draft ID stands for it. Input only.
    SshKeyDraft { draft_id: String },
    /// Leave the stored secret as it is. Input of `item_update` only: a metadata-only update
    /// (DEC-INT10-6). `item_create` refuses it.
    Keep,
    SessionToken {
        #[specta(type = String)]
        token: WireSecret,
        token_type: Option<String>,
        header_name: Option<String>,
    },
    BrowserSession {
        #[specta(type = String)]
        storage_state: WireSecret,
        origin: String,
    },
    Database {
        #[specta(type = Option<String>)]
        url: Option<WireSecret>,
        engine: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        database: Option<String>,
        #[specta(type = Option<String>)]
        username: Option<WireSecret>,
        #[specta(type = Option<String>)]
        password: Option<WireSecret>,
        params: BTreeMap<String, String>,
    },
    Cloud {
        provider: String,
        #[specta(type = Option<String>)]
        access_key_id: Option<WireSecret>,
        #[specta(type = Option<String>)]
        secret_access_key: Option<WireSecret>,
        #[specta(type = Option<String>)]
        session_token: Option<WireSecret>,
        region: Option<String>,
        #[specta(type = BTreeMap<String, String>)]
        extra: BTreeMap<String, WireSecret>,
    },
    Certificate {
        cert_pem: String,
        #[specta(type = Option<String>)]
        key_pem: Option<WireSecret>,
        chain_pem: Option<String>,
    },
    EnvBundle {
        #[specta(type = BTreeMap<String, String>)]
        vars: BTreeMap<String, WireSecret>,
    },
    Note {
        #[specta(type = String)]
        text: WireSecret,
    },
    /// A RustDesk connection. The ID, the servers and the key are in `custom` (DEC-RD-1).
    Rustdesk {
        #[specta(type = Option<String>)]
        password: Option<WireSecret>,
    },
}

/// What a payload view turns into: a core payload, or the ID of a backend draft to look up.
pub enum PayloadSource {
    /// A complete payload.
    Payload(Payload),
    /// A draft made by `ssh_key_generate` or `ssh_key_import`.
    Draft(String),
    /// No payload: the stored secret stays.
    Keep,
}

fn opt_secret(value: Option<WireSecret>) -> Option<SecretString> {
    value.map(secret)
}

fn opt_wire(value: Option<&SecretString>) -> Option<WireSecret> {
    value.map(wire)
}

impl PayloadView {
    /// The core payload, or the draft to look up.
    #[must_use]
    pub fn into_source(self) -> PayloadSource {
        let payload = match self {
            Self::SshKeyDraft { draft_id } => return PayloadSource::Draft(draft_id),
            Self::Keep => return PayloadSource::Keep,
            Self::WebLogin {
                username,
                password,
                url,
                totp,
            } => Payload::WebLogin {
                username: secret(username),
                password: secret(password),
                url,
                totp: totp.map(TotpSeedView::into_core),
            },
            Self::ApiKey {
                key,
                key_id,
                header_name,
                base_url,
            } => Payload::ApiKey {
                key: secret(key),
                key_id,
                header_name,
                base_url,
            },
            Self::SshKey {
                private_key,
                passphrase,
                public_key,
                fingerprint,
            } => Payload::SshKey {
                private_key: secret(private_key),
                passphrase: opt_secret(passphrase),
                public_key,
                fingerprint,
            },
            Self::SessionToken {
                token,
                token_type,
                header_name,
            } => Payload::SessionToken {
                token: secret(token),
                token_type,
                header_name,
            },
            Self::BrowserSession {
                storage_state,
                origin,
            } => Payload::BrowserSession {
                storage_state: secret(storage_state),
                origin,
            },
            Self::Database {
                url,
                engine,
                host,
                port,
                database,
                username,
                password,
                params,
            } => Payload::Database {
                url: opt_secret(url),
                engine,
                host,
                port,
                database,
                username: opt_secret(username),
                password: opt_secret(password),
                params,
            },
            Self::Cloud {
                provider,
                access_key_id,
                secret_access_key,
                session_token,
                region,
                extra,
            } => Payload::Cloud {
                provider,
                access_key_id: opt_secret(access_key_id),
                secret_access_key: opt_secret(secret_access_key),
                session_token: opt_secret(session_token),
                region,
                extra: extra.into_iter().map(|(k, v)| (k, secret(v))).collect(),
            },
            Self::Certificate {
                cert_pem,
                key_pem,
                chain_pem,
            } => Payload::Certificate {
                cert_pem,
                key_pem: opt_secret(key_pem),
                chain_pem,
            },
            Self::EnvBundle { vars } => Payload::EnvBundle {
                vars: vars.into_iter().map(|(k, v)| (k, secret(v))).collect(),
            },
            Self::Note { text } => Payload::Note { text: secret(text) },
            Self::Rustdesk { password } => Payload::Rustdesk {
                password: opt_secret(password),
            },
        };
        PayloadSource::Payload(payload)
    }

    /// The view of a core payload, including the TOTP seed (an operator may see it).
    #[must_use]
    pub fn of(payload: &Payload) -> Self {
        match payload {
            Payload::WebLogin {
                username,
                password,
                url,
                totp,
            } => Self::WebLogin {
                username: wire(username),
                password: wire(password),
                url: url.clone(),
                totp: totp.as_ref().map(TotpSeedView::of),
            },
            Payload::ApiKey {
                key,
                key_id,
                header_name,
                base_url,
            } => Self::ApiKey {
                key: wire(key),
                key_id: key_id.clone(),
                header_name: header_name.clone(),
                base_url: base_url.clone(),
            },
            Payload::SshKey {
                private_key,
                passphrase,
                public_key,
                fingerprint,
            } => Self::SshKey {
                private_key: wire(private_key),
                passphrase: opt_wire(passphrase.as_ref()),
                public_key: public_key.clone(),
                fingerprint: fingerprint.clone(),
            },
            Payload::SessionToken {
                token,
                token_type,
                header_name,
            } => Self::SessionToken {
                token: wire(token),
                token_type: token_type.clone(),
                header_name: header_name.clone(),
            },
            Payload::BrowserSession {
                storage_state,
                origin,
            } => Self::BrowserSession {
                storage_state: wire(storage_state),
                origin: origin.clone(),
            },
            Payload::Database {
                url,
                engine,
                host,
                port,
                database,
                username,
                password,
                params,
            } => Self::Database {
                url: opt_wire(url.as_ref()),
                engine: engine.clone(),
                host: host.clone(),
                port: *port,
                database: database.clone(),
                username: opt_wire(username.as_ref()),
                password: opt_wire(password.as_ref()),
                params: params.clone(),
            },
            Payload::Cloud {
                provider,
                access_key_id,
                secret_access_key,
                session_token,
                region,
                extra,
            } => Self::Cloud {
                provider: provider.clone(),
                access_key_id: opt_wire(access_key_id.as_ref()),
                secret_access_key: opt_wire(secret_access_key.as_ref()),
                session_token: opt_wire(session_token.as_ref()),
                region: region.clone(),
                extra: extra.iter().map(|(k, v)| (k.clone(), wire(v))).collect(),
            },
            Payload::Certificate {
                cert_pem,
                key_pem,
                chain_pem,
            } => Self::Certificate {
                cert_pem: cert_pem.clone(),
                key_pem: opt_wire(key_pem.as_ref()),
                chain_pem: chain_pem.clone(),
            },
            Payload::EnvBundle { vars } => Self::EnvBundle {
                vars: vars.iter().map(|(k, v)| (k.clone(), wire(v))).collect(),
            },
            Payload::Note { text } => Self::Note { text: wire(text) },
            Payload::Rustdesk { password } => Self::Rustdesk {
                password: opt_wire(password.as_ref()),
            },
        }
    }
}

/// Input of `item_create` and `item_update`. `payload` may be `{ kind: "keep" }` in
/// `item_update`: the stored secret stays and only the metadata changes (DEC-INT10-6).
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct ItemInputView {
    /// Workspace ID.
    pub workspace_id: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Role label.
    pub role_label: Option<String>,
    /// Category.
    pub category: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Environment.
    pub environment: Environment,
    /// Target: URL, host, machine or app name.
    pub target: Option<String>,
    /// Extra facts by name.
    pub custom: BTreeMap<String, String>,
    /// End of life.
    pub expires_at: Option<String>,
    /// Reveals after which the item is deleted.
    pub max_uses: Option<u32>,
    /// The secret part.
    pub payload: PayloadView,
}

impl ItemInputView {
    /// Splits the input into the core input (with `payload`) and checks the IDs and the time.
    /// `P` is [`Payload`] for a create and `PayloadChange` for an update.
    ///
    /// # Errors
    /// `validation_failed` for a bad ID or time.
    pub fn into_core<P>(self, payload: P) -> IpcResult<CoreItemInput<P>> {
        Ok(CoreItemInput {
            workspace_id: id("workspace_id", &self.workspace_id)?,
            title: self.title,
            description: self.description,
            role_label: self.role_label,
            category: self.category,
            tags: self.tags,
            environment: self.environment.into(),
            target: self.target,
            custom: self.custom,
            expires_at: opt_parse_ts("expires_at", self.expires_at.as_deref())?,
            max_uses: self.max_uses,
            payload,
        })
    }
}

/// Filter of `item_list`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Type)]
pub struct ItemFilterView {
    /// Only this workspace.
    pub workspace_id: Option<String>,
    /// Only this environment.
    pub environment: Option<Environment>,
    /// Only this kind.
    pub kind: Option<ItemKind>,
    /// Only items with this tag.
    pub tag: Option<String>,
    /// Free text.
    pub q: Option<String>,
}

impl ItemFilterView {
    /// The core filter.
    ///
    /// # Errors
    /// `validation_failed` for a bad workspace ID.
    pub fn into_core(self) -> IpcResult<CoreItemFilter> {
        Ok(CoreItemFilter {
            workspace_id: opt_id("workspace_id", self.workspace_id.as_deref())?,
            environment: self.environment.map(Into::into),
            kind: self.kind.map(Into::into),
            tag: self.tag,
            q: self.q,
        })
    }
}

/// Metadata of an item. It has no field that can hold a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ItemSummaryView {
    /// Item ID.
    pub id: String,
    /// Kind.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Role label.
    pub role_label: Option<String>,
    /// Category.
    pub category: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Environment.
    pub environment: Environment,
    /// Slug of the workspace.
    pub workspace: String,
    /// Target.
    pub target: Option<String>,
    /// `operator:<id>` or `agent:<id>`.
    pub created_by: String,
    /// Expiry.
    pub expires_at: Option<String>,
    /// Last change.
    pub updated_at: String,
    /// True when the item has a TOTP seed.
    pub has_totp: bool,
    /// Extra facts by name. Metadata only: a secret value is in the payload, not here. SSH items
    /// use `machine`, `host`, `port` and `user`; RustDesk items use `rustdesk_id`, `id_server`,
    /// `relay_server` and `server_key`.
    pub custom: BTreeMap<String, String>,
}

impl From<CoreItemSummary> for ItemSummaryView {
    fn from(value: CoreItemSummary) -> Self {
        Self {
            id: value.id.to_string(),
            kind: value.kind.into(),
            title: value.title,
            description: value.description,
            role_label: value.role_label,
            category: value.category,
            tags: value.tags,
            environment: value.environment.into(),
            workspace: value.workspace,
            target: value.target,
            created_by: value.created_by,
            expires_at: opt_ts(value.expires_at),
            updated_at: ts(value.updated_at),
            has_totp: value.has_totp,
            custom: value.custom,
        }
    }
}

/// An agent the secret was exposed to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ExposureView {
    /// Agent ID.
    pub agent_id: String,
    /// Time of the latest exposure.
    pub at: String,
}

/// An item with its counters, no payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ItemDetailView {
    /// The metadata.
    pub summary: ItemSummaryView,
    /// Current version.
    pub version: u32,
    /// Reveals so far.
    pub use_count: u32,
    /// Reveal limit.
    pub max_uses: Option<u32>,
    /// Agents the secret was exposed to, newest first.
    pub exposed_to: Vec<ExposureView>,
}

impl From<CoreItemDetail> for ItemDetailView {
    fn from(value: CoreItemDetail) -> Self {
        Self {
            summary: value.summary.into(),
            version: value.version,
            use_count: value.use_count,
            max_uses: value.max_uses,
            exposed_to: value
                .exposed_to
                .into_iter()
                .map(|(agent, at)| ExposureView {
                    agent_id: agent.to_string(),
                    at: ts(at),
                })
                .collect(),
        }
    }
}

/// Machine, host, port and user of an SSH key item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct SshMetaView {
    /// Machine name.
    pub machine: Option<String>,
    /// Host.
    pub host: Option<String>,
    /// Port.
    pub port: Option<u16>,
    /// User.
    pub user: Option<String>,
}

impl From<SshMeta> for SshMetaView {
    fn from(value: SshMeta) -> Self {
        Self {
            machine: value.machine,
            host: value.host,
            port: value.port,
            user: value.user,
        }
    }
}

/// Result of `item_reveal`. The only IPC answer that holds an item secret.
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct RevealedSecretView {
    /// The metadata.
    pub summary: ItemSummaryView,
    /// The secret part.
    pub payload: PayloadView,
    /// Reveals so far.
    pub use_count: u32,
    /// True when this reveal used the last allowed one and the item is deleted.
    pub exhausted: bool,
    /// SSH metadata.
    pub ssh: Option<SshMetaView>,
}

impl From<RevealedItem> for RevealedSecretView {
    fn from(value: RevealedItem) -> Self {
        Self {
            summary: value.summary.into(),
            payload: PayloadView::of(&value.payload),
            use_count: value.use_count,
            exhausted: value.exhausted,
            ssh: value.ssh.map(Into::into),
        }
    }
}

/// One entry of the version history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct ItemVersionView {
    /// Version number.
    pub version: u32,
    /// Creation time.
    pub created_at: String,
    /// Title at that version.
    pub title: String,
}

impl From<CoreVersion> for ItemVersionView {
    fn from(value: CoreVersion) -> Self {
        Self {
            version: value.version,
            created_at: ts(value.created_at),
            title: value.title,
        }
    }
}

/// Result of `item_totp_preview`. The code is a secret for a short time.
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct TotpView {
    /// The code.
    #[specta(type = String)]
    pub code: WireSecret,
    /// Length of one step in seconds.
    pub period: u32,
    /// Seconds until the code changes.
    pub expires_in_seconds: u32,
}

impl From<TotpCode> for TotpView {
    fn from(value: TotpCode) -> Self {
        Self {
            code: wire(&value.code),
            period: value.period,
            expires_in_seconds: value.expires_in_seconds,
        }
    }
}

/// An SSH key made or imported in the backend. The private key stays there; `draft_id` stands for
/// it in `item_create` and `item_update` (`PayloadView::SshKeyDraft`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct SshKeyDraft {
    /// ID of the backend draft. Drafts are dropped at lock.
    pub draft_id: String,
    /// OpenSSH public key line.
    pub public_key: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
}

/// Input of `workspace_put`.
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct WorkspaceInputView {
    /// Slug.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Aliases.
    pub aliases: Vec<String>,
}

impl From<WorkspaceInputView> for CoreWorkspaceInput {
    fn from(value: WorkspaceInputView) -> Self {
        Self {
            slug: value.slug,
            name: value.name,
            description: value.description,
            aliases: value.aliases,
        }
    }
}

/// A workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct WorkspaceView {
    /// Workspace ID.
    pub id: String,
    /// Slug.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Aliases.
    pub aliases: Vec<String>,
    /// Number of items.
    pub item_count: u32,
}

impl From<CoreWorkspaceView> for WorkspaceView {
    fn from(value: CoreWorkspaceView) -> Self {
        Self {
            id: value.id.to_string(),
            slug: value.slug,
            name: value.name,
            description: value.description,
            aliases: value.aliases,
            item_count: value.item_count,
        }
    }
}
