//! Client settings: URL, token and trust (ADR-0016, ADR-0023).
//!
//! Sources, in this order: explicit overrides (CLI flags), then the environment
//! (`CERBERUS_URL`, `CERBERUS_TOKEN`, `CERBERUS_TOKEN_FILE`, `CERBERUS_CA_FILE`, `CERBERUS_CA_PIN`),
//! then the default token file `<config dir>/cerberus/token`. A token is never read from an argument.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cerberus_types::wire::WireSecret;
use url::Url;

use crate::error::ClientError;

/// URL used when `CERBERUS_URL` is not set.
pub const DEFAULT_URL: &str = "https://127.0.0.1:7373";

/// How the client decides to trust the server (ADR-0023). There is no "trust nothing is set"
/// fallback and no system root store: the Cerberus CA is the only trust anchor.
#[derive(Clone, Debug)]
pub enum Trust {
    /// PEM file of the Cerberus CA (exported from the app). The chain must verify against it.
    CaFile(PathBuf),
    /// `sha256/<base64>` pin of the CA public key. The server must send the CA certificate
    /// after the leaf; that certificate must match the pin and must have signed the leaf.
    Pin(String),
    /// Both: the chain must verify against the file, and the file's CA key must match the pin.
    CaFileAndPin {
        /// PEM file of the CA.
        ca: PathBuf,
        /// `sha256/<base64>` pin.
        pin: String,
    },
}

/// Settings of a client. Not `Clone`: the token has one owner.
#[derive(Debug)]
pub struct ClientConfig {
    /// Base URL of the service. Must be `https`.
    pub base_url: Url,
    /// Agent token (`cvt_<agent_id>.<secret>`). Zeroized on drop; `Debug` is redacted.
    pub token: WireSecret,
    /// How to trust the server.
    pub trust: Trust,
    /// Optional mTLS client certificate and key (PEM files).
    pub client_cert: Option<(PathBuf, PathBuf)>,
    /// Time limit of one call (and the idle limit of an event stream).
    pub timeout: Duration,
}

/// Values that a caller (the CLI) can set before the environment is read.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    /// Service URL.
    pub url: Option<String>,
    /// Token file path.
    pub token_file: Option<PathBuf>,
    /// CA PEM file.
    pub ca_file: Option<PathBuf>,
    /// CA pin.
    pub ca_pin: Option<String>,
    /// Client certificate PEM file.
    pub client_cert: Option<PathBuf>,
    /// Client key PEM file.
    pub client_key: Option<PathBuf>,
}

impl ClientConfig {
    /// Reads the settings from the process environment and the default token file.
    ///
    /// # Errors
    /// [`ClientError::Config`] when the URL, the token or the trust setting is missing or invalid.
    pub fn from_env() -> Result<Self, ClientError> {
        Self::load(&Overrides::default())
    }

    /// As [`ClientConfig::from_env`], with explicit overrides first.
    ///
    /// # Errors
    /// [`ClientError::Config`] when the URL, the token or the trust setting is missing or invalid.
    pub fn load(overrides: &Overrides) -> Result<Self, ClientError> {
        Self::from_lookup(overrides, |name| std::env::var(name).ok())
    }

    /// As [`ClientConfig::load`], with a lookup function in place of the process environment.
    ///
    /// # Errors
    /// [`ClientError::Config`] when the URL, the token or the trust setting is missing or invalid.
    pub fn from_lookup(
        overrides: &Overrides,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ClientError> {
        let get = |name: &str| env(name).filter(|v| !v.trim().is_empty());
        let url_text = overrides
            .url
            .clone()
            .or_else(|| get("CERBERUS_URL"))
            .unwrap_or_else(|| DEFAULT_URL.to_owned());
        let base_url = parse_base_url(&url_text)?;
        let token = match get("CERBERUS_TOKEN") {
            Some(text) => text,
            None => {
                let path = overrides
                    .token_file
                    .clone()
                    .or_else(|| get("CERBERUS_TOKEN_FILE").map(PathBuf::from))
                    .or_else(|| default_token_file(&env))
                    .ok_or_else(|| config("no token: set CERBERUS_TOKEN or CERBERUS_TOKEN_FILE"))?;
                read_token_file(&path)?
            }
        };
        let token = check_token(token)?;
        let ca_file = overrides
            .ca_file
            .clone()
            .or_else(|| get("CERBERUS_CA_FILE").map(PathBuf::from));
        let ca_pin = overrides.ca_pin.clone().or_else(|| get("CERBERUS_CA_PIN"));
        let trust = match (ca_file, ca_pin) {
            (Some(ca), Some(pin)) => Trust::CaFileAndPin { ca, pin },
            (Some(ca), None) => Trust::CaFile(ca),
            (None, Some(pin)) => Trust::Pin(pin),
            (None, None) => {
                return Err(config(
                    "no trust anchor: set CERBERUS_CA_PIN or CERBERUS_CA_FILE",
                ));
            }
        };
        let client_cert = match (&overrides.client_cert, &overrides.client_key) {
            (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
            (None, None) => match (get("CERBERUS_CLIENT_CERT"), get("CERBERUS_CLIENT_KEY")) {
                (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
                (None, None) => None,
                _ => return Err(config("set both the client certificate and its key")),
            },
            _ => return Err(config("set both the client certificate and its key")),
        };
        Ok(Self {
            base_url,
            token,
            trust,
            client_cert,
            timeout: Duration::from_secs(30),
        })
    }
}

fn config(text: &str) -> ClientError {
    ClientError::Config(text.to_owned())
}

/// Parses and checks a base URL: `https` only, with a host.
pub(crate) fn parse_base_url(text: &str) -> Result<Url, ClientError> {
    let url = Url::parse(text).map_err(|_| config("the service URL is not valid"))?;
    if url.scheme() != "https" {
        return Err(config(
            "the service URL must use https (plain HTTP is refused)",
        ));
    }
    if url.host_str().is_none() {
        return Err(config("the service URL has no host"));
    }
    Ok(url)
}

fn check_token(text: String) -> Result<WireSecret, ClientError> {
    let secret = WireSecret::new(text.trim().to_owned());
    drop(text);
    if !secret.expose().starts_with("cvt_") {
        return Err(config("the token does not start with cvt_"));
    }
    Ok(secret)
}

fn default_token_file(env: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let base = env("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })?;
    let path = base.join("cerberus").join("token");
    path.is_file().then_some(path)
}

/// Reads a token file. On Unix the file must not be readable by group or others (mode 0600).
fn read_token_file(path: &Path) -> Result<String, ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|_| config("the token file cannot be read"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(config(
                "the token file must not be readable by group or others (chmod 600)",
            ));
        }
    }
    std::fs::read_to_string(path).map_err(|_| config("the token file cannot be read"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const TOKEN: &str = "cvt_00000000-0000-0000-0000-000000000000.fake";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn env_gives_url_token_and_trust() {
        let cfg = ClientConfig::from_lookup(
            &Overrides::default(),
            env(&[
                ("CERBERUS_TOKEN", TOKEN),
                ("CERBERUS_CA_PIN", "sha256/AAAA"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.base_url.as_str(), "https://127.0.0.1:7373/");
        assert_eq!(cfg.token.expose(), TOKEN);
        assert!(matches!(cfg.trust, Trust::Pin(_)));
        assert!(!format!("{cfg:?}").contains(TOKEN));
    }

    #[test]
    fn plain_http_and_missing_trust_are_refused() {
        let http = ClientConfig::from_lookup(
            &Overrides::default(),
            env(&[
                ("CERBERUS_TOKEN", TOKEN),
                ("CERBERUS_CA_PIN", "x"),
                ("CERBERUS_URL", "http://127.0.0.1:7373"),
            ]),
        );
        assert!(matches!(http, Err(ClientError::Config(_))));
        let none =
            ClientConfig::from_lookup(&Overrides::default(), env(&[("CERBERUS_TOKEN", TOKEN)]));
        assert!(matches!(none, Err(ClientError::Config(_))));
    }

    #[test]
    fn a_token_without_the_prefix_is_refused() {
        let cfg = ClientConfig::from_lookup(
            &Overrides::default(),
            env(&[("CERBERUS_TOKEN", "nope"), ("CERBERUS_CA_PIN", "x")]),
        );
        assert!(matches!(cfg, Err(ClientError::Config(_))));
    }

    #[cfg(unix)]
    #[test]
    fn token_file_needs_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
        let overrides = Overrides {
            token_file: Some(path.clone()),
            ..Overrides::default()
        };
        let vars = env(&[("CERBERUS_CA_PIN", "x")]);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ClientConfig::from_lookup(&overrides, &vars).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg = ClientConfig::from_lookup(&overrides, &vars).unwrap();
        assert_eq!(cfg.token.expose(), TOKEN);
    }
}
