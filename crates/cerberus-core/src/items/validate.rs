//! Validation of item input (ADR-0027 limits). Problems name the field and the rule, never a value.

use std::collections::{BTreeMap, BTreeSet};

use cerberus_crypto::SecretString;
use cerberus_types::{FieldProblem, ItemKind};
use serde::Deserialize;
use serde::de::IgnoredAny;

use super::payload::Payload;
use super::rustdesk;
use super::service::ItemInput;
use super::ssh;
use super::totp;
use crate::index::normalize;

/// Largest encoded payload of a `browser_session` (ADR-0027).
pub const MAX_SESSION_PAYLOAD_BYTES: usize = 1_048_576;
/// Largest encoded payload of every other kind (ADR-0027).
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

const MAX_TAGS: usize = 20;
const MAX_CUSTOM: usize = 20;
const MAX_ENV_VARS: usize = 100;
const MAX_URL: usize = 2_048;

struct Problems(Vec<FieldProblem>);

impl Problems {
    fn add(&mut self, field: &str, text: &str) {
        self.0.push(FieldProblem {
            field: field.to_owned(),
            problem: text.to_owned(),
        });
    }

    /// A text of `min..=max` characters without control characters.
    fn text(&mut self, field: &str, value: &str, min: usize, max: usize) {
        let len = value.chars().count();
        if len < min || len > max {
            self.add(field, &format!("must be {min}..{max} characters"));
        } else if value.chars().any(char::is_control) {
            self.add(field, "must not contain control characters");
        }
    }

    fn opt_text(&mut self, field: &str, value: Option<&String>, max: usize) {
        if let Some(value) = value {
            self.text(field, value, 1, max);
        }
    }

    fn secret(&mut self, field: &str, value: &SecretString, max: usize) {
        let len = value.expose_secret().chars().count();
        if len == 0 || len > max {
            self.add(field, &format!("must be 1..{max} characters"));
        }
    }

    fn opt_secret(&mut self, field: &str, value: Option<&SecretString>, max: usize) {
        if let Some(value) = value {
            self.secret(field, value, max);
        }
    }

    fn url(&mut self, field: &str, value: Option<&String>) {
        if let Some(value) = value
            && !is_http_url(value)
        {
            self.add(field, "must be an http or https URL");
        }
    }

    fn header(&mut self, field: &str, value: Option<&String>) {
        if let Some(value) = value
            && (value.is_empty()
                || value.len() > 128
                || !value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        {
            self.add(field, "must be a header name (letters, digits, - and _)");
        }
    }
}

fn is_http_url(value: &str) -> bool {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    rest.is_some_and(|r| {
        !r.is_empty()
            && !r.starts_with('/')
            && value.len() <= MAX_URL
            && !value.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Problems of a payload that an agent writes, on top of [`validate_payload`]: env bundle names
/// and cloud `extra` names that are not credential-shaped (AUD-5, DEC-T27-D1-1). Only names that
/// pass [`cerberus_types::env::is_agent_env_name_allowed`] are accepted (`*_TOKEN`, `*_KEY`,
/// `*_SECRET`, `*_PASSWORD`, `*_USER` ..., and a short list such as `AWS_ACCESS_KEY_ID` and
/// `DATABASE_URL`), and never a name on the deny list (DEC-T27-A2-1). Any other name could let the
/// item change what code a child of `cerberus run` loads (`LD_PRELOAD`, `MAVEN_OPTS`,
/// `OPENSSL_CONF`, ...), and a deny list cannot name them all. A person may still store them.
#[must_use]
pub(crate) fn agent_payload_problems(payload: &Payload) -> Vec<FieldProblem> {
    let names: Vec<(&str, &String)> = match payload {
        Payload::EnvBundle { vars } => vars.keys().map(|n| ("vars", n)).collect(),
        Payload::Cloud { extra, .. } => extra.keys().map(|n| ("extra", n)).collect(),
        _ => Vec::new(),
    };
    names
        .into_iter()
        .filter(|(_, name)| !cerberus_types::env::is_agent_env_name_allowed(name))
        .map(|(group, name)| FieldProblem {
            field: format!("payload.{group}.{name}"),
            problem: "is not a credential name that an item written by an agent may set (use a \
                      name such as NAME_TOKEN, NAME_KEY, NAME_SECRET, NAME_PASSWORD or NAME_USER)"
                .to_owned(),
        })
        .collect()
}

/// Trims text fields and turns empty optional texts into `None`. Validation runs on this form.
pub(crate) fn normalize_input<P>(mut input: ItemInput<P>) -> ItemInput<P> {
    let trim = |s: &mut String| *s = s.trim().to_owned();
    let trim_opt = |s: &mut Option<String>| {
        *s = s
            .take()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty());
    };
    trim(&mut input.title);
    trim(&mut input.description);
    trim(&mut input.category);
    trim_opt(&mut input.role_label);
    trim_opt(&mut input.target);
    input.tags.iter_mut().for_each(trim);
    input.custom = std::mem::take(&mut input.custom)
        .into_iter()
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    input
}

/// Checks the metadata and the payload of `input` (call it on the normalized form).
///
/// # Errors
/// All field problems found. Payload fields are named `payload.<field>`.
pub fn validate_item(input: &ItemInput) -> Result<(), Vec<FieldProblem>> {
    let mut problems = validate_fields(input, input.kind());
    problems.extend(validate_payload(&input.payload));
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Checks the metadata of `input` for an item of `kind`, not the payload.
#[must_use]
pub(crate) fn validate_fields<P>(input: &ItemInput<P>, kind: ItemKind) -> Vec<FieldProblem> {
    let mut p = Problems(Vec::new());
    p.text("title", &input.title, 1, 200);
    let desc_len = input.description.chars().count();
    if desc_len > 2_000 {
        p.add("description", "must be 0..2000 characters");
    }
    p.opt_text("role_label", input.role_label.as_ref(), 64);
    p.text("category", &input.category, 1, 64);
    p.opt_text("target", input.target.as_ref(), 512);
    if input.tags.len() > MAX_TAGS {
        p.add("tags", "at most 20 tags");
    }
    let mut seen = BTreeSet::new();
    for (i, tag) in input.tags.iter().enumerate() {
        p.text(&format!("tags[{i}]"), tag, 1, 50);
        if !seen.insert(normalize(tag).to_string()) {
            p.add(&format!("tags[{i}]"), "is a duplicate");
        }
    }
    check_custom(&input.custom, &mut p);
    if input.max_uses == Some(0) {
        p.add("max_uses", "must be at least 1");
    }
    match kind {
        ItemKind::SshKey => ssh::check_custom(&input.custom, &mut p.0),
        ItemKind::Rustdesk => rustdesk::check_custom(&input.custom, &mut p.0),
        _ => {}
    }
    p.0
}

fn check_custom(custom: &BTreeMap<String, String>, p: &mut Problems) {
    if custom.len() > MAX_CUSTOM {
        p.add("custom", "at most 20 entries");
    }
    for (key, value) in custom {
        let field = format!("custom.{key}");
        let key_ok = (1..=64).contains(&key.len())
            && key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !key_ok {
            p.add(&field, "name must be 1..64 of a-z, 0-9 and _");
        }
        let len = value.chars().count();
        if len > 512 || value.chars().any(char::is_control) {
            p.add(
                &field,
                "must be at most 512 characters, no control characters",
            );
        }
    }
}

/// Checks one payload: field rules, the TOTP seed, the SSH key and the size limit.
#[must_use]
pub fn validate_payload(payload: &Payload) -> Vec<FieldProblem> {
    let mut p = Problems(Vec::new());
    check_payload(payload, &mut p);
    let limit = if matches!(payload, Payload::BrowserSession { .. }) {
        MAX_SESSION_PAYLOAD_BYTES
    } else {
        MAX_PAYLOAD_BYTES
    };
    match payload.to_json() {
        Ok(json) if json.len() > limit => p.add("payload", "is too large"),
        Ok(_) => {}
        Err(_) => p.add("payload", "cannot be encoded"),
    }
    for problem in &mut p.0 {
        if !problem.field.starts_with("payload") {
            problem.field = format!("payload.{}", problem.field);
        }
    }
    p.0
}

#[derive(Deserialize)]
struct StorageState {
    #[serde(default, rename = "cookies")]
    _cookies: Option<Vec<IgnoredAny>>,
    #[serde(default, rename = "origins")]
    _origins: Option<Vec<IgnoredAny>>,
}

fn check_payload(payload: &Payload, p: &mut Problems) {
    match payload {
        Payload::WebLogin {
            username,
            password,
            url,
            totp,
        } => {
            p.secret("username", username, 256);
            p.secret("password", password, 1_024);
            p.url("url", url.as_ref());
            if let Some(problem) = totp.as_ref().and_then(totp::check) {
                p.add("totp", problem);
            }
        }
        Payload::ApiKey {
            key,
            key_id,
            header_name,
            base_url,
        } => {
            p.secret("key", key, 8_192);
            p.opt_text("key_id", key_id.as_ref(), 256);
            p.header("header_name", header_name.as_ref());
            p.url("base_url", base_url.as_ref());
        }
        Payload::SshKey {
            private_key,
            passphrase,
            public_key,
            fingerprint,
        } => {
            p.opt_secret("passphrase", passphrase.as_ref(), 1_024);
            ssh::check_payload(private_key, public_key, fingerprint, &mut p.0);
        }
        Payload::SessionToken {
            token,
            token_type,
            header_name,
        } => {
            p.secret("token", token, 8_192);
            p.opt_text("token_type", token_type.as_ref(), 64);
            p.header("header_name", header_name.as_ref());
        }
        Payload::BrowserSession {
            storage_state,
            origin,
        } => {
            if serde_json::from_str::<StorageState>(storage_state.expose_secret()).is_err() {
                p.add(
                    "storage_state",
                    "must be a Playwright storage state JSON object",
                );
            }
            p.url("origin", Some(origin));
        }
        Payload::Database { .. } => check_database(payload, p),
        Payload::Cloud {
            provider,
            access_key_id,
            secret_access_key,
            session_token,
            region,
            extra,
        } => {
            p.text("provider", provider, 1, 64);
            p.opt_secret("access_key_id", access_key_id.as_ref(), 512);
            p.opt_secret("secret_access_key", secret_access_key.as_ref(), 2_048);
            p.opt_secret("session_token", session_token.as_ref(), 8_192);
            p.opt_text("region", region.as_ref(), 64);
            if access_key_id.is_some() != secret_access_key.is_some() {
                p.add(
                    "access_key_id",
                    "access_key_id and secret_access_key go together",
                );
            }
            if access_key_id.is_none() && session_token.is_none() && extra.is_empty() {
                p.add("provider", "needs a key, a session token or extra values");
            }
            if extra.len() > MAX_CUSTOM {
                p.add("extra", "at most 20 entries");
            }
            for (name, value) in extra {
                p.text(&format!("extra.{name}"), name, 1, 64);
                p.secret(&format!("extra.{name}"), value, 4_096);
            }
        }
        Payload::Certificate {
            cert_pem,
            key_pem,
            chain_pem,
        } => check_certificate(cert_pem, key_pem.as_ref(), chain_pem.as_ref(), p),
        Payload::EnvBundle { vars } => {
            if vars.is_empty() || vars.len() > MAX_ENV_VARS {
                p.add("vars", "must have 1..100 variables");
            }
            for (name, value) in vars {
                if !valid_env_name(name) || name.len() > 128 {
                    p.add(&format!("vars.{name}"), "name must match [A-Z_][A-Z0-9_]*");
                }
                if value.expose_secret().len() > 8_192 {
                    p.add(&format!("vars.{name}"), "value is too long");
                }
            }
        }
        Payload::Note { text } => p.secret("text", text, 65_000),
        Payload::Rustdesk { password } => p.opt_secret("password", password.as_ref(), 1_024),
    }
}

fn check_database(payload: &Payload, p: &mut Problems) {
    let Payload::Database {
        url,
        engine,
        host,
        port,
        database,
        username,
        password,
        params,
    } = payload
    else {
        return;
    };
    p.opt_secret("url", url.as_ref(), 4_096);
    p.opt_text("engine", engine.as_ref(), 32);
    p.opt_text("host", host.as_ref(), 255);
    p.opt_text("database", database.as_ref(), 128);
    p.opt_secret("username", username.as_ref(), 256);
    p.opt_secret("password", password.as_ref(), 1_024);
    if *port == Some(0) {
        p.add("port", "must be 1..65535");
    }
    if params.len() > MAX_CUSTOM {
        p.add("params", "at most 20 entries");
    }
    for (name, value) in params {
        p.text(&format!("params.{name}"), name, 1, 64);
        p.text(&format!("params.{name}"), value, 0, 512);
    }
    let fields_used = engine.is_some()
        || host.is_some()
        || port.is_some()
        || database.is_some()
        || username.is_some()
        || password.is_some();
    match (url, fields_used) {
        (Some(url), false) => {
            if !url.expose_secret().contains("://") {
                p.add("url", "must be a connection URL such as postgres://host/db");
            }
        }
        (Some(_), true) => p.add("url", "give a url or the single fields, not both"),
        (None, true) => {
            for (name, missing) in [
                ("engine", engine.is_none()),
                ("host", host.is_none()),
                ("username", username.is_none()),
                ("password", password.is_none()),
            ] {
                if missing {
                    p.add(name, "is required when no url is given");
                }
            }
        }
        (None, false) => p.add("url", "give a url or the single fields"),
    }
}

fn check_certificate(
    cert_pem: &str,
    key_pem: Option<&SecretString>,
    chain_pem: Option<&String>,
    p: &mut Problems,
) {
    let is_cert = |t: &str| {
        t.contains("-----BEGIN CERTIFICATE-----") && t.contains("-----END CERTIFICATE-----")
    };
    if !is_cert(cert_pem) {
        p.add("cert_pem", "must be a PEM certificate");
    }
    // `cert_pem` and `chain_pem` are public texts. A private key there would leak to agents.
    if cert_pem.contains("PRIVATE KEY") {
        p.add("cert_pem", "must not contain a private key");
    }
    if let Some(chain) = chain_pem {
        if !is_cert(chain) {
            p.add("chain_pem", "must be PEM certificates");
        }
        if chain.contains("PRIVATE KEY") {
            p.add("chain_pem", "must not contain a private key");
        }
    }
    if let Some(key) = key_pem {
        let text = key.expose_secret();
        if !(text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----")) {
            p.add("key_pem", "must be a PEM private key");
        }
    }
}
