//! The typed payload of each item kind (ADR-0027) and its JSON form inside `payload_ct`.
//!
//! Secret fields are `SecretString`: `Debug` prints `[REDACTED]`, there is no `Display` and no
//! `Serialize`. The JSON form goes through a private mirror type, so a payload cannot be
//! serialized by accident into a log or an audit event.

use std::collections::BTreeMap;
use std::fmt;

use cerberus_crypto::SecretString;
use cerberus_types::ItemKind;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::CoreError;

/// Hash algorithm of a TOTP seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (the default of most services).
    #[serde(rename = "SHA1")]
    Sha1,
    /// HMAC-SHA256.
    #[serde(rename = "SHA256")]
    Sha256,
    /// HMAC-SHA512.
    #[serde(rename = "SHA512")]
    Sha512,
}

/// A TOTP seed. It never leaves the vault: agents get codes only (ADR-0027).
#[derive(Clone, Debug)]
pub struct TotpSeed {
    /// The seed in Base32, as shown by the service that issued it.
    pub secret: SecretString,
    /// Hash algorithm.
    pub algorithm: TotpAlgorithm,
    /// Digits of a code: 6 or 8.
    pub digits: u8,
    /// Seconds a code is valid: 15..=120.
    pub period: u32,
}

impl TotpSeed {
    /// A seed with the usual settings: SHA1, 6 digits, 30 seconds.
    #[must_use]
    pub fn standard(secret: SecretString) -> Self {
        Self {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        }
    }
}

/// Typed payload inside `payload_ct` (ADR-0027). `Debug` is redacted for every secret field.
#[derive(Clone, Debug)]
pub enum Payload {
    /// User name and password, with an optional TOTP seed.
    WebLogin {
        /// User name.
        username: SecretString,
        /// Password.
        password: SecretString,
        /// Login page.
        url: Option<String>,
        /// TOTP seed (never sent to agents).
        totp: Option<TotpSeed>,
    },
    /// An API key.
    ApiKey {
        /// The key.
        key: SecretString,
        /// Public key ID.
        key_id: Option<String>,
        /// Header that carries the key.
        header_name: Option<String>,
        /// Base URL of the API.
        base_url: Option<String>,
    },
    /// An SSH private key. Machine name, host, port and user are item metadata (`custom`).
    SshKey {
        /// OpenSSH private key text.
        private_key: SecretString,
        /// Passphrase of an encrypted key.
        passphrase: Option<SecretString>,
        /// OpenSSH public key line.
        public_key: String,
        /// `SHA256:...` fingerprint of the public key.
        fingerprint: String,
    },
    /// A session token.
    SessionToken {
        /// The token.
        token: SecretString,
        /// For example `Bearer`.
        token_type: Option<String>,
        /// Header that carries the token.
        header_name: Option<String>,
    },
    /// A Playwright browser session.
    BrowserSession {
        /// Playwright storage state, as JSON text.
        storage_state: SecretString,
        /// The origin it belongs to.
        origin: String,
    },
    /// A database: a URL, or the single fields.
    Database {
        /// Connection URL.
        url: Option<SecretString>,
        /// Engine, for example `postgres`.
        engine: Option<String>,
        /// Host.
        host: Option<String>,
        /// Port.
        port: Option<u16>,
        /// Database name.
        database: Option<String>,
        /// User name.
        username: Option<SecretString>,
        /// Password.
        password: Option<SecretString>,
        /// Extra connection parameters.
        params: BTreeMap<String, String>,
    },
    /// Cloud provider keys.
    Cloud {
        /// Provider, for example `aws`.
        provider: String,
        /// Access key ID.
        access_key_id: Option<SecretString>,
        /// Secret access key.
        secret_access_key: Option<SecretString>,
        /// Temporary session token.
        session_token: Option<SecretString>,
        /// Region.
        region: Option<String>,
        /// Other secret values by name.
        extra: BTreeMap<String, SecretString>,
    },
    /// A certificate with an optional private key.
    Certificate {
        /// Certificate in PEM form.
        cert_pem: String,
        /// Private key in PEM form.
        key_pem: Option<SecretString>,
        /// Chain in PEM form.
        chain_pem: Option<String>,
    },
    /// Environment variables.
    EnvBundle {
        /// Variable name to value.
        vars: BTreeMap<String, SecretString>,
    },
    /// A secret note.
    Note {
        /// The text.
        text: SecretString,
    },
    /// A RustDesk connection. The ID, the servers and the server key are item metadata
    /// (`custom`, DEC-RD-1); only the password is here.
    Rustdesk {
        /// Permanent password of the remote machine.
        password: Option<SecretString>,
    },
}

impl Payload {
    /// The kind of this payload.
    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        match self {
            Self::WebLogin { .. } => ItemKind::WebLogin,
            Self::ApiKey { .. } => ItemKind::ApiKey,
            Self::SshKey { .. } => ItemKind::SshKey,
            Self::SessionToken { .. } => ItemKind::SessionToken,
            Self::BrowserSession { .. } => ItemKind::BrowserSession,
            Self::Database { .. } => ItemKind::Database,
            Self::Cloud { .. } => ItemKind::Cloud,
            Self::Certificate { .. } => ItemKind::Certificate,
            Self::EnvBundle { .. } => ItemKind::EnvBundle,
            Self::Note { .. } => ItemKind::Note,
            Self::Rustdesk { .. } => ItemKind::Rustdesk,
        }
    }

    /// The TOTP seed of a web login.
    #[must_use]
    pub const fn totp(&self) -> Option<&TotpSeed> {
        match self {
            Self::WebLogin { totp, .. } => totp.as_ref(),
            _ => None,
        }
    }

    /// The payload without the TOTP seed, as an agent may get it (ADR-0027: the seed never
    /// leaves the vault).
    #[must_use]
    pub fn without_totp(self) -> Self {
        match self {
            Self::WebLogin {
                username,
                password,
                url,
                ..
            } => Self::WebLogin {
                username,
                password,
                url,
                totp: None,
            },
            other => other,
        }
    }

    /// True when the payload has a TOTP seed.
    #[must_use]
    pub const fn has_totp(&self) -> bool {
        self.totp().is_some()
    }

    /// The JSON text that is sealed as `payload_ct`. Zeroized on drop.
    pub(crate) fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let mirror = Json::from_payload(self);
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        serde_json::to_writer(&mut *out, &mirror).map_err(|_| CoreError::Corrupt)?;
        Ok(out)
    }

    /// Parses the opened `payload_ct`.
    pub(crate) fn from_json(bytes: &[u8]) -> Result<Self, CoreError> {
        let mirror: Json = serde_json::from_slice(bytes).map_err(|_| CoreError::Corrupt)?;
        Ok(mirror.into_payload())
    }
}

/// A secret text on the way to or from JSON. Zeroized on drop.
struct Sec(Zeroizing<String>);

impl Sec {
    fn of(secret: &SecretString) -> Self {
        Self(Zeroizing::new(secret.expose_secret().to_owned()))
    }

    fn of_opt(secret: Option<&SecretString>) -> Option<Self> {
        secret.map(Self::of)
    }

    fn into_secret(mut self) -> SecretString {
        SecretString::new(std::mem::take(&mut *self.0))
    }
}

impl Serialize for Sec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

struct SecVisitor;

impl Visitor<'_> for SecVisitor {
    type Value = Sec;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Sec, E> {
        Ok(Sec(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Sec, E> {
        Ok(Sec(Zeroizing::new(value)))
    }
}

impl<'de> Deserialize<'de> for Sec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_string(SecVisitor)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpJson {
    secret: Sec,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Json {
    WebLogin {
        username: Sec,
        password: Sec,
        url: Option<String>,
        totp: Option<TotpJson>,
    },
    ApiKey {
        key: Sec,
        key_id: Option<String>,
        header_name: Option<String>,
        base_url: Option<String>,
    },
    SshKey {
        private_key: Sec,
        passphrase: Option<Sec>,
        public_key: String,
        fingerprint: String,
    },
    SessionToken {
        token: Sec,
        token_type: Option<String>,
        header_name: Option<String>,
    },
    BrowserSession {
        storage_state: Sec,
        origin: String,
    },
    Database {
        url: Option<Sec>,
        engine: Option<String>,
        host: Option<String>,
        port: Option<u16>,
        database: Option<String>,
        username: Option<Sec>,
        password: Option<Sec>,
        #[serde(default)]
        params: BTreeMap<String, String>,
    },
    Cloud {
        provider: String,
        access_key_id: Option<Sec>,
        secret_access_key: Option<Sec>,
        session_token: Option<Sec>,
        region: Option<String>,
        #[serde(default)]
        extra: BTreeMap<String, Sec>,
    },
    Certificate {
        cert_pem: String,
        key_pem: Option<Sec>,
        chain_pem: Option<String>,
    },
    EnvBundle {
        vars: BTreeMap<String, Sec>,
    },
    Note {
        text: Sec,
    },
    Rustdesk {
        password: Option<Sec>,
    },
}

fn secrets_of(map: &BTreeMap<String, SecretString>) -> BTreeMap<String, Sec> {
    map.iter().map(|(k, v)| (k.clone(), Sec::of(v))).collect()
}

fn secrets_into(map: BTreeMap<String, Sec>) -> BTreeMap<String, SecretString> {
    map.into_iter().map(|(k, v)| (k, v.into_secret())).collect()
}

impl Json {
    fn from_payload(payload: &Payload) -> Self {
        match payload {
            Payload::WebLogin {
                username,
                password,
                url,
                totp,
            } => Self::WebLogin {
                username: Sec::of(username),
                password: Sec::of(password),
                url: url.clone(),
                totp: totp.as_ref().map(|t| TotpJson {
                    secret: Sec::of(&t.secret),
                    algorithm: t.algorithm,
                    digits: t.digits,
                    period: t.period,
                }),
            },
            Payload::ApiKey {
                key,
                key_id,
                header_name,
                base_url,
            } => Self::ApiKey {
                key: Sec::of(key),
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
                private_key: Sec::of(private_key),
                passphrase: Sec::of_opt(passphrase.as_ref()),
                public_key: public_key.clone(),
                fingerprint: fingerprint.clone(),
            },
            Payload::SessionToken {
                token,
                token_type,
                header_name,
            } => Self::SessionToken {
                token: Sec::of(token),
                token_type: token_type.clone(),
                header_name: header_name.clone(),
            },
            Payload::BrowserSession {
                storage_state,
                origin,
            } => Self::BrowserSession {
                storage_state: Sec::of(storage_state),
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
                url: Sec::of_opt(url.as_ref()),
                engine: engine.clone(),
                host: host.clone(),
                port: *port,
                database: database.clone(),
                username: Sec::of_opt(username.as_ref()),
                password: Sec::of_opt(password.as_ref()),
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
                access_key_id: Sec::of_opt(access_key_id.as_ref()),
                secret_access_key: Sec::of_opt(secret_access_key.as_ref()),
                session_token: Sec::of_opt(session_token.as_ref()),
                region: region.clone(),
                extra: secrets_of(extra),
            },
            Payload::Certificate {
                cert_pem,
                key_pem,
                chain_pem,
            } => Self::Certificate {
                cert_pem: cert_pem.clone(),
                key_pem: Sec::of_opt(key_pem.as_ref()),
                chain_pem: chain_pem.clone(),
            },
            Payload::EnvBundle { vars } => Self::EnvBundle {
                vars: secrets_of(vars),
            },
            Payload::Note { text } => Self::Note {
                text: Sec::of(text),
            },
            Payload::Rustdesk { password } => Self::Rustdesk {
                password: Sec::of_opt(password.as_ref()),
            },
        }
    }

    fn into_payload(self) -> Payload {
        match self {
            Self::WebLogin {
                username,
                password,
                url,
                totp,
            } => Payload::WebLogin {
                username: username.into_secret(),
                password: password.into_secret(),
                url,
                totp: totp.map(|t| TotpSeed {
                    secret: t.secret.into_secret(),
                    algorithm: t.algorithm,
                    digits: t.digits,
                    period: t.period,
                }),
            },
            Self::ApiKey {
                key,
                key_id,
                header_name,
                base_url,
            } => Payload::ApiKey {
                key: key.into_secret(),
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
                private_key: private_key.into_secret(),
                passphrase: passphrase.map(Sec::into_secret),
                public_key,
                fingerprint,
            },
            Self::SessionToken {
                token,
                token_type,
                header_name,
            } => Payload::SessionToken {
                token: token.into_secret(),
                token_type,
                header_name,
            },
            Self::BrowserSession {
                storage_state,
                origin,
            } => Payload::BrowserSession {
                storage_state: storage_state.into_secret(),
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
                url: url.map(Sec::into_secret),
                engine,
                host,
                port,
                database,
                username: username.map(Sec::into_secret),
                password: password.map(Sec::into_secret),
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
                access_key_id: access_key_id.map(Sec::into_secret),
                secret_access_key: secret_access_key.map(Sec::into_secret),
                session_token: session_token.map(Sec::into_secret),
                region,
                extra: secrets_into(extra),
            },
            Self::Certificate {
                cert_pem,
                key_pem,
                chain_pem,
            } => Payload::Certificate {
                cert_pem,
                key_pem: key_pem.map(Sec::into_secret),
                chain_pem,
            },
            Self::EnvBundle { vars } => Payload::EnvBundle {
                vars: secrets_into(vars),
            },
            Self::Note { text } => Payload::Note {
                text: text.into_secret(),
            },
            Self::Rustdesk { password } => Payload::Rustdesk {
                password: password.map(Sec::into_secret),
            },
        }
    }
}
