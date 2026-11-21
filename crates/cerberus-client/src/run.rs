//! `cerberus run`: resolve a credential, put it in the environment of a child process only,
//! never print it (ADR-0028).
//!
//! The child gets the variables. The CLI keeps them out of its own environment (`Command::env`
//! sets them for the child), out of its own output and out of its arguments. The child output is
//! masked: each secret value, and its Base64, URL-encoded and JSON-escaped forms, becomes
//! `[REDACTED]`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use cerberus_types::wire::{
    AccessRequestStatus, ItemKind, PendingResponse, ResolveMode, ResolveRequest, RevealRequest,
    SecretPayload, SecretResponse, WireSecret,
};
use cerberus_types::{ItemId, LeaseId, is_agent_env_name_allowed, is_forbidden_env_name};
use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::client::{Client, RevealResult};
use crate::error::ClientError;

/// Text that replaces a secret in the child output.
const MASK: &[u8] = b"[REDACTED]";
/// Values shorter than this are not masked: they would damage ordinary output.
const MIN_MASKED: usize = 4;

/// Options of `cerberus run` (ADR-0028).
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// App name to resolve.
    pub app: String,
    /// Environment filter.
    pub environment: Option<String>,
    /// Role filter.
    pub role: Option<String>,
    /// Kind filter.
    pub kind: Option<ItemKind>,
    /// Item to reveal directly, without resolve.
    pub item_id: Option<ItemId>,
    /// Reason text for the audit log (at least 8 characters).
    pub purpose: String,
    /// `NAME=field` pairs. When present, only these variables are set.
    pub vars: Vec<(String, String)>,
    /// Mask secrets in the child output.
    pub mask_output: bool,
    /// Keep `CERBERUS_TOKEN` in the child environment.
    pub pass_token: bool,
    /// Longest wait for an approval.
    pub wait: Duration,
    /// The command and its arguments.
    pub command: Vec<OsString>,
}

/// One variable for the child.
#[derive(Debug)]
pub struct EnvVar {
    /// Variable name.
    pub name: String,
    /// Value. `Debug` is redacted.
    pub value: WireSecret,
    /// True when the value must be masked in output.
    pub secret: bool,
    /// True when the value goes to a `0600` temp file and the variable holds the file path.
    pub file: bool,
}

/// A field of a payload, by its JSON name.
struct Field {
    name: String,
    value: WireSecret,
    secret: bool,
}

fn dup(secret: &WireSecret) -> WireSecret {
    WireSecret::new(secret.expose().to_owned())
}

fn text(name: &str, value: Option<&String>) -> Option<Field> {
    value.map(|v| Field {
        name: name.to_owned(),
        value: WireSecret::new(v.clone()),
        secret: false,
    })
}

fn secret(name: &str, value: Option<&WireSecret>) -> Option<Field> {
    value.map(|v| Field {
        name: name.to_owned(),
        value: dup(v),
        secret: true,
    })
}

fn number(name: &str, value: Option<u16>) -> Option<Field> {
    value.map(|v| Field {
        name: name.to_owned(),
        value: WireSecret::new(v.to_string()),
        secret: false,
    })
}

fn fields(payload: &SecretPayload) -> Vec<Field> {
    let all: Vec<Option<Field>> = match payload {
        SecretPayload::WebLogin(p) => vec![
            secret("username", Some(&p.username)),
            secret("password", Some(&p.password)),
            text("url", p.url.as_ref()),
        ],
        SecretPayload::ApiKey(p) => vec![
            secret("key", Some(&p.key)),
            text("key_id", p.key_id.as_ref()),
            text("header_name", p.header_name.as_ref()),
            text("base_url", p.base_url.as_ref()),
        ],
        SecretPayload::SshKey(p) => vec![
            secret("private_key", Some(&p.private_key)),
            secret("passphrase", p.passphrase.as_ref()),
            text("public_key", Some(&p.public_key)),
            text("fingerprint", Some(&p.fingerprint)),
            text("host", p.host.as_ref()),
            number("port", p.port),
            text("user", p.user.as_ref()),
        ],
        SecretPayload::SessionToken(p) => vec![
            secret("token", Some(&p.token)),
            text("token_type", p.token_type.as_ref()),
            text("header_name", p.header_name.as_ref()),
        ],
        SecretPayload::BrowserSession(p) => vec![
            secret("storage_state", Some(&p.storage_state)),
            text("origin", Some(&p.origin)),
        ],
        SecretPayload::Database(p) => vec![
            secret("url", p.url.as_ref()),
            text("engine", p.engine.as_ref()),
            text("host", p.host.as_ref()),
            number("port", p.port),
            text("database", p.database.as_ref()),
            secret("username", p.username.as_ref()),
            secret("password", p.password.as_ref()),
        ],
        SecretPayload::Cloud(p) => {
            let mut list = vec![
                text("provider", Some(&p.provider)),
                secret("access_key_id", p.access_key_id.as_ref()),
                secret("secret_access_key", p.secret_access_key.as_ref()),
                secret("session_token", p.session_token.as_ref()),
                text("region", p.region.as_ref()),
            ];
            for (key, value) in p.extra.iter().flatten() {
                list.push(secret(key, Some(value)));
            }
            list
        }
        SecretPayload::Certificate(p) => vec![
            text("cert_pem", Some(&p.cert_pem)),
            secret("key_pem", p.key_pem.as_ref()),
            text("chain_pem", p.chain_pem.as_ref()),
        ],
        SecretPayload::EnvBundle(p) => p
            .vars
            .iter()
            .map(|(key, value)| secret(key, Some(value)))
            .collect(),
        SecretPayload::Note(p) => vec![secret("text", Some(&p.text))],
        SecretPayload::Rustdesk(p) => vec![
            text("rustdesk_id", p.rustdesk_id.as_ref()),
            text("id_server", p.id_server.as_ref()),
            text("relay_server", p.relay_server.as_ref()),
            text("server_key", p.server_key.as_ref()),
            secret("password", p.password.as_ref()),
        ],
    };
    all.into_iter().flatten().collect()
}

/// The names of the fields of a payload with a flag for the secret ones. It is what `get` shows
/// when it does not print secrets.
#[must_use]
pub fn field_names(payload: &SecretPayload) -> Vec<(String, bool)> {
    fields(payload)
        .into_iter()
        .map(|f| (f.name, f.secret))
        .collect()
}

/// The value of one field, by JSON name.
#[must_use]
pub fn field_value(payload: &SecretPayload, name: &str) -> Option<WireSecret> {
    fields(payload)
        .into_iter()
        .find(|f| f.name == name)
        .map(|f| f.value)
}

fn var(name: &str, field: Option<Field>) -> Option<EnvVar> {
    field.map(|f| EnvVar {
        name: name.to_owned(),
        value: f.value,
        secret: f.secret,
        file: false,
    })
}

fn pick(all: &mut Vec<Field>, name: &str) -> Option<Field> {
    all.iter()
        .position(|f| f.name == name)
        .map(|i| all.remove(i))
}

fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// True for a usable environment variable name.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True when `cerberus run` may set `name` from an `env_bundle` name or a `cloud` extra key of the
/// item. Never a name on the deny list (AUD-5). For an item that an agent wrote (`by_agent`), the
/// name must also be credential-shaped (DEC-T27-D1-1), so an agent item stored before core checked
/// that rule cannot set `MAVEN_OPTS` or `OPENSSL_CONF` either.
fn item_may_set(name: &str, by_agent: bool) -> bool {
    valid_name(name)
        && !is_forbidden_env_name(name)
        && (!by_agent || is_agent_env_name_allowed(name))
}

/// True unless the item was written by a person. A `created_by` that is not `operator:...` counts
/// as an agent, so an unknown writer gets the narrow rule.
fn written_by_agent(created_by: &str) -> bool {
    !created_by.starts_with("operator:")
}

/// Default variable names for a payload (ADR-0028 item 3). `by_agent` is true when an agent wrote
/// the item (see [`item_may_set`]).
///
/// # Errors
/// [`ClientError::Config`] for an SSH key (use `ssh-prepare`, the key must not enter an environment).
pub fn env_for(payload: &SecretPayload, by_agent: bool) -> Result<Vec<EnvVar>, ClientError> {
    let mut all = fields(payload);
    let mut out: Vec<Option<EnvVar>> = Vec::new();
    match payload {
        SecretPayload::WebLogin(_) => {
            out.push(var("CERBERUS_USERNAME", pick(&mut all, "username")));
            out.push(var("CERBERUS_PASSWORD", pick(&mut all, "password")));
            out.push(var("CERBERUS_URL", pick(&mut all, "url")));
        }
        SecretPayload::ApiKey(_) => out.push(var("CERBERUS_API_KEY", pick(&mut all, "key"))),
        SecretPayload::SessionToken(_) => {
            out.push(var("CERBERUS_SESSION_TOKEN", pick(&mut all, "token")));
        }
        SecretPayload::BrowserSession(_) => {
            out.push(pick(&mut all, "storage_state").map(|f| EnvVar {
                name: "CERBERUS_STORAGE_STATE".to_owned(),
                value: f.value,
                secret: true,
                file: true,
            }));
        }
        SecretPayload::Database(p) => {
            let url = match &p.url {
                Some(url) => Some(dup(url)),
                None => database_url(p),
            };
            out.push(url.map(|value| EnvVar {
                name: "DATABASE_URL".to_owned(),
                value,
                secret: true,
                file: false,
            }));
        }
        SecretPayload::Cloud(p) => {
            let prefix = if p.provider.eq_ignore_ascii_case("aws") {
                (
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN",
                    "AWS_REGION",
                )
            } else {
                (
                    "CERBERUS_CLOUD_ACCESS_KEY_ID",
                    "CERBERUS_CLOUD_SECRET_ACCESS_KEY",
                    "CERBERUS_CLOUD_SESSION_TOKEN",
                    "CERBERUS_CLOUD_REGION",
                )
            };
            out.push(var(prefix.0, pick(&mut all, "access_key_id")));
            out.push(var(prefix.1, pick(&mut all, "secret_access_key")));
            out.push(var(prefix.2, pick(&mut all, "session_token")));
            out.push(var(prefix.3, pick(&mut all, "region")));
            for field in all.drain(..).filter(|f| f.name != "provider") {
                if item_may_set(&field.name, by_agent) {
                    out.push(Some(EnvVar {
                        name: field.name,
                        value: field.value,
                        secret: field.secret,
                        file: false,
                    }));
                }
            }
        }
        SecretPayload::Certificate(_) => {
            out.push(var("CERBERUS_CERT_PEM", pick(&mut all, "cert_pem")));
            out.push(var("CERBERUS_KEY_PEM", pick(&mut all, "key_pem")));
            out.push(var("CERBERUS_CHAIN_PEM", pick(&mut all, "chain_pem")));
        }
        SecretPayload::EnvBundle(_) => {
            for field in all.drain(..) {
                if item_may_set(&field.name, by_agent) {
                    out.push(Some(EnvVar {
                        name: field.name,
                        value: field.value,
                        secret: true,
                        file: false,
                    }));
                }
            }
        }
        SecretPayload::Note(_) => out.push(var("CERBERUS_NOTE", pick(&mut all, "text"))),
        SecretPayload::Rustdesk(_) => {
            out.push(var("CERBERUS_RUSTDESK_ID", pick(&mut all, "rustdesk_id")));
            out.push(var(
                "CERBERUS_RUSTDESK_PASSWORD",
                pick(&mut all, "password"),
            ));
            out.push(var(
                "CERBERUS_RUSTDESK_ID_SERVER",
                pick(&mut all, "id_server"),
            ));
            out.push(var(
                "CERBERUS_RUSTDESK_RELAY_SERVER",
                pick(&mut all, "relay_server"),
            ));
            out.push(var("CERBERUS_RUSTDESK_KEY", pick(&mut all, "server_key")));
        }
        SecretPayload::SshKey(_) => {
            return Err(ClientError::Config(
                "an SSH key cannot go into an environment: use ssh-prepare".to_owned(),
            ));
        }
    }
    Ok(out.into_iter().flatten().collect())
}

/// `engine://user:password@host:port/database` from the parts, with percent-encoding.
fn database_url(p: &cerberus_types::wire::DatabaseSecret) -> Option<WireSecret> {
    let engine = p.engine.as_deref()?;
    let host = p.host.as_deref()?;
    let mut url = format!("{engine}://");
    if let Some(user) = &p.username {
        url.push_str(&percent_encode(user.expose()));
        if let Some(password) = &p.password {
            url.push(':');
            url.push_str(&percent_encode(password.expose()));
        }
        url.push('@');
    }
    url.push_str(host);
    if let Some(port) = p.port {
        url.push_str(&format!(":{port}"));
    }
    if let Some(database) = &p.database {
        url.push('/');
        url.push_str(database);
    }
    Some(WireSecret::new(url))
}

/// Variables from `NAME=field` pairs: each field of the payload by its JSON name.
///
/// # Errors
/// [`ClientError::Config`] for a bad name or an unknown field.
pub fn mapped_env(
    payload: &SecretPayload,
    vars: &[(String, String)],
) -> Result<Vec<EnvVar>, ClientError> {
    let all = fields(payload);
    let mut out = Vec::new();
    for (name, field) in vars {
        if !valid_name(name) {
            return Err(ClientError::Config(format!(
                "{name:?} is not a valid variable name"
            )));
        }
        let found = all
            .iter()
            .find(|f| &f.name == field)
            .ok_or_else(|| ClientError::Config(format!("this item has no field {field:?}")))?;
        out.push(EnvVar {
            name: name.clone(),
            value: dup(&found.value),
            secret: found.secret,
            file: false,
        });
    }
    Ok(out)
}

/// Every value that the output of the child must not show: the injected secret variables and
/// every secret field of the item, so the parts of a built `DATABASE_URL` (user name, password)
/// are masked one by one and not only as a whole (AUD-18).
fn mask_values(payload: &SecretPayload, vars: &[EnvVar]) -> Vec<WireSecret> {
    let mut values: Vec<WireSecret> = vars
        .iter()
        .filter(|v| v.secret)
        .map(|v| dup(&v.value))
        .collect();
    values.extend(
        fields(payload)
            .into_iter()
            .filter(|f| f.secret)
            .map(|f| f.value),
    );
    values
}

/// Names that the item gives for the environment of the child and that `cerberus run` refuses to
/// set (loader and interpreter hooks, `PATH`, `CERBERUS_*` ...; the list is in `cerberus-types`;
/// for an agent item also every name that is not credential-shaped). Only `env_bundle` names and
/// `cloud` extra keys come from the item: the other names are fixed by this program (AUD-5).
fn forbidden_names(payload: &SecretPayload, by_agent: bool) -> Vec<String> {
    let names: Vec<String> = match payload {
        SecretPayload::EnvBundle(p) => p.vars.keys().cloned().collect(),
        SecretPayload::Cloud(p) => p.extra.iter().flatten().map(|(k, _)| k.clone()).collect(),
        _ => Vec::new(),
    };
    names
        .into_iter()
        .filter(|name| valid_name(name) && !item_may_set(name, by_agent))
        .collect()
}

/// The warning for skipped variables. It names them and never shows a value.
fn skipped_warning(names: &[String]) -> Option<String> {
    (!names.is_empty()).then(|| {
        format!(
            "cerberus: skipped {} variable(s) that an item must not set in a child process: {} \
             (set one on purpose with --var NAME=field)",
            names.len(),
            names.join(", ")
        )
    })
}

/// Streaming masker for the child output.
#[derive(Debug)]
pub struct Masker {
    needles: Vec<Vec<u8>>,
    carry: Vec<u8>,
}

impl Masker {
    /// Builds a masker for these secret values. Each value is masked in its raw, Base64
    /// (standard and URL-safe, with and without padding), URL-encoded and JSON-escaped forms.
    #[must_use]
    pub fn new(secrets: &[&[u8]]) -> Self {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for value in secrets.iter().filter(|v| v.len() >= MIN_MASKED) {
            needles.push(value.to_vec());
            needles.push(BASE64.encode(value).into_bytes());
            needles.push(BASE64_NOPAD.encode(value).into_bytes());
            needles.push(BASE64URL.encode(value).into_bytes());
            needles.push(BASE64URL_NOPAD.encode(value).into_bytes());
            if let Ok(s) = std::str::from_utf8(value) {
                needles.push(percent_encode(s).into_bytes());
                if let Ok(json) = serde_json::to_string(s) {
                    let inner = json.trim_matches('"');
                    needles.push(inner.as_bytes().to_vec());
                }
            }
        }
        needles.sort();
        needles.dedup();
        // Longest first, so the longest match wins at one position.
        needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        Self {
            needles,
            carry: Vec::new(),
        }
    }

    /// Masks one chunk. It holds back a tail that could still grow into a longer secret.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let (out, kept) = self.scan(&buf, false);
        self.carry = buf[kept..].to_vec();
        out
    }

    /// The end of the stream. The held-back tail is masked as far as it matches a secret.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.scan(&self.carry, true).0
    }

    /// Masks `buf`. Returns the output and how many bytes at the end are held back. At a position
    /// the longest secret that matches wins. If a longer secret could still match once more bytes
    /// arrive (`eof` is false), the scan stops there, so a short secret never hides the start of a
    /// longer one (AUD-18).
    fn scan(&self, buf: &[u8], eof: bool) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < buf.len() {
            let rest = &buf[i..];
            if !eof
                && self
                    .needles
                    .iter()
                    .any(|n| n.len() > rest.len() && n.starts_with(rest))
            {
                return (out, i);
            }
            if let Some(needle) = self.needles.iter().find(|n| rest.starts_with(n)) {
                out.extend_from_slice(MASK);
                i += needle.len();
            } else {
                out.push(buf[i]);
                i += 1;
            }
        }
        (out, buf.len())
    }
}

/// Reveals an item. When a person must approve first, waits up to `wait` and reveals again with
/// the lease of the approved request.
///
/// # Errors
/// [`ClientError`], [`ClientError::NotApproved`] when the request is not approved in time.
pub async fn reveal_with_approval(
    client: &Client,
    id: ItemId,
    purpose: &str,
    wait: Duration,
) -> Result<SecretResponse, ClientError> {
    let first = RevealRequest {
        purpose: purpose.to_owned(),
        lease_id: None,
        ttl_seconds: None,
    };
    match client.reveal(id, &first).await? {
        RevealResult::Secret(secret) => Ok(*secret),
        RevealResult::Pending(pending) => {
            let lease = approved_lease(client, &pending, wait).await?;
            let second = RevealRequest {
                purpose: purpose.to_owned(),
                lease_id: Some(lease),
                ttl_seconds: None,
            };
            match client.reveal(id, &second).await? {
                RevealResult::Secret(secret) => Ok(*secret),
                RevealResult::Pending(_) => Err(ClientError::NotApproved("pending".to_owned())),
            }
        }
    }
}

/// Waits for an access request and returns the lease of the approved request.
///
/// # Errors
/// [`ClientError::NotApproved`] when the request is denied, expired, cancelled or still pending.
pub async fn approved_lease(
    client: &Client,
    pending: &PendingResponse,
    wait: Duration,
) -> Result<uuid::Uuid, ClientError> {
    let view = client
        .wait_request(
            cerberus_types::AccessRequestId(pending.access_request.id),
            wait,
        )
        .await?;
    match (view.status, view.lease) {
        (AccessRequestStatus::Approved, Some(lease)) => Ok(lease.id),
        (status, _) => Err(ClientError::NotApproved(
            format!("{status:?}").to_lowercase(),
        )),
    }
}

/// Resolves (`best`) and reveals, as `cerberus run` and `cerberus get --app` do.
///
/// # Errors
/// [`ClientError`], [`ClientError::Ambiguous`] when several items match.
pub async fn resolve_secret(
    client: &Client,
    request: &ResolveRequest,
    wait: Duration,
) -> Result<SecretResponse, ClientError> {
    use cerberus_types::wire::ResolveResponse;
    match client.resolve(request).await? {
        ResolveResponse::Secret(secret) => Ok(*secret),
        ResolveResponse::Pending(pending) => {
            reveal_with_approval(
                client,
                ItemId(pending.access_request.item_id),
                &request.purpose,
                wait,
            )
            .await
        }
        ResolveResponse::Candidates(_) | ResolveResponse::Ambiguous(_) => {
            Err(ClientError::Ambiguous)
        }
    }
}

/// Deletes a file when dropped.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        // Best effort: the file is `0600` in the temp dir.
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_private_file(value: &WireSecret) -> Result<TempFile, ClientError> {
    use std::io::Write;
    let path = std::env::temp_dir().join(format!("cerberus-{}.json", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    let guard = TempFile(path);
    file.write_all(value.expose().as_bytes())?;
    Ok(guard)
}

/// Runs the command with the secret in its environment. Returns the child exit code, or 70 to 74
/// for a CLI error. It prints only error codes and request IDs, never a secret.
pub async fn run(client: &Client, opts: RunOptions) -> i32 {
    match run_inner(client, opts).await {
        Ok(code) => code,
        Err(error) => {
            report(&error);
            error.exit_code()
        }
    }
}

/// Prints an error as code and request ID only.
pub fn report(error: &ClientError) {
    match error.api() {
        Some(api) => eprintln!("cerberus: {} (request {})", api.code, api.request_id),
        None => eprintln!("cerberus: {error}"),
    }
}

async fn run_inner(client: &Client, opts: RunOptions) -> Result<i32, ClientError> {
    let Some((program, args)) = opts.command.split_first() else {
        return Err(ClientError::Config("no command to run".to_owned()));
    };
    let revealed = match opts.item_id {
        Some(id) => reveal_with_approval(client, id, &opts.purpose, opts.wait).await?,
        None => {
            let request = ResolveRequest {
                app: opts.app.clone(),
                environment: opts.environment.clone(),
                role: opts.role.clone(),
                kind: opts.kind,
                hint: None,
                purpose: opts.purpose.clone(),
                mode: Some(ResolveMode::Best),
            };
            resolve_secret(client, &request, opts.wait).await?
        }
    };
    let lease: LeaseId = LeaseId(revealed.lease.id);
    make_not_dumpable();
    let outcome = spawn_and_wait(&revealed, &opts, program, args).await;
    // The lease ends with the child (ADR-0028 item 7).
    if let Err(error) = client.release_lease(lease).await {
        report(&error);
    }
    outcome
}

/// Makes this process not dumpable (Linux). The child runs as the same user and could otherwise
/// read the token from `/proc/<this pid>/environ` (AUD-19). The flag is not inherited by the
/// child. A token file stays readable by the same user (AR-3). A failure is ignored: the
/// protection is best effort.
fn make_not_dumpable() {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    }
}

async fn spawn_and_wait(
    revealed: &SecretResponse,
    opts: &RunOptions,
    program: &OsString,
    args: &[OsString],
) -> Result<i32, ClientError> {
    let by_agent = written_by_agent(&revealed.item.created_by);
    let vars = if opts.vars.is_empty() {
        env_for(&revealed.secret, by_agent)?
    } else {
        mapped_env(&revealed.secret, &opts.vars)?
    };
    if opts.vars.is_empty()
        && let Some(warning) = skipped_warning(&forbidden_names(&revealed.secret, by_agent))
    {
        eprintln!("{warning}");
    }
    let mut command = Command::new(program);
    command.args(args).kill_on_drop(true);
    if !opts.pass_token {
        command
            .env_remove("CERBERUS_TOKEN")
            .env_remove("CERBERUS_TOKEN_FILE");
    }
    let mut temp_files = Vec::new();
    for var in &vars {
        if var.file {
            let file = write_private_file(&var.value)?;
            command.env(&var.name, &file.0);
            temp_files.push(file);
        } else {
            command.env(&var.name, var.value.expose());
        }
    }
    let masked = mask_values(&revealed.secret, &vars);
    let secrets: Vec<&[u8]> = masked.iter().map(|v| v.expose().as_bytes()).collect();
    let mask = opts.mask_output;
    if mask {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = command.spawn()?;
    let mut pumps = Vec::new();
    if mask {
        if let Some(out) = child.stdout.take() {
            pumps.push(tokio::spawn(pump(
                out,
                tokio::io::stdout(),
                Masker::new(&secrets),
            )));
        }
        if let Some(err) = child.stderr.take() {
            pumps.push(tokio::spawn(pump(
                err,
                tokio::io::stderr(),
                Masker::new(&secrets),
            )));
        }
    }
    let status = wait_forwarding_signals(&mut child).await?;
    for task in pumps {
        // A failed pump only loses output; the exit code still counts.
        let _ = task.await;
    }
    drop(temp_files);
    Ok(exit_code(status))
}

async fn pump<R, W>(mut from: R, mut to: W, mut masker: Masker)
where
    R: AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let out = masker.push(&buf[..n]);
                if to.write_all(&out).await.is_err() || to.flush().await.is_err() {
                    return;
                }
            }
        }
    }
    let tail = masker.finish();
    let _ = to.write_all(&tail).await;
    let _ = to.flush().await;
}

#[cfg(unix)]
async fn wait_forwarding_signals(
    child: &mut tokio::process::Child,
) -> Result<std::process::ExitStatus, ClientError> {
    use rustix::process::{Pid, Signal, kill_process};
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut quit = signal(SignalKind::quit())?;
    let pid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    loop {
        let forward = tokio::select! {
            status = child.wait() => return Ok(status?),
            _ = interrupt.recv() => Signal::INT,
            _ = terminate.recv() => Signal::TERM,
            _ = hangup.recv() => Signal::HUP,
            _ = quit.recv() => Signal::QUIT,
        };
        if let Some(pid) = pid {
            // The child may have exited already; then there is nobody to signal.
            let _ = kill_process(pid, forward);
        }
    }
}

#[cfg(not(unix))]
async fn wait_forwarding_signals(
    child: &mut tokio::process::Child,
) -> Result<std::process::ExitStatus, ClientError> {
    loop {
        tokio::select! {
            status = child.wait() => return Ok(status?),
            _ = tokio::signal::ctrl_c() => { let _ = child.start_kill(); }
        }
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(chunks: &[&[u8]], secrets: &[&[u8]]) -> Vec<u8> {
        let mut masker = Masker::new(secrets);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(masker.push(chunk));
        }
        out.extend(masker.finish());
        out
    }

    #[test]
    fn masks_a_value_in_one_chunk() {
        let out = mask(&[b"user=fake-secret-1 ok"], &[b"fake-secret-1"]);
        assert_eq!(out, b"user=[REDACTED] ok");
    }

    #[test]
    fn masks_a_value_split_across_chunks() {
        let out = mask(&[b"x fake-sec", b"ret-1 y"], &[b"fake-secret-1"]);
        assert_eq!(out, b"x [REDACTED] y");
    }

    #[test]
    fn masks_encoded_forms() {
        let secret: &[u8] = b"fake secret/1";
        let b64 = BASE64.encode(secret);
        let url = percent_encode("fake secret/1");
        let input = format!("a {b64} b {url} c");
        let out = mask(&[input.as_bytes()], &[secret]);
        assert_eq!(out, b"a [REDACTED] b [REDACTED] c");
    }

    #[test]
    fn keeps_a_partial_match_that_never_completes() {
        let out = mask(&[b"fake-sec", b"ond"], &[b"fake-secret-1"]);
        assert_eq!(out, b"fake-second");
    }

    #[test]
    fn short_values_are_not_masked() {
        assert_eq!(mask(&[b"abc abc"], &[b"abc"]), b"abc abc");
    }

    #[test]
    fn aud18_a_longer_secret_that_starts_with_a_shorter_one_is_fully_masked() {
        let secrets: [&[u8]; 2] = [b"admin", b"admin2024!secret"];
        let out = mask(&[b"pw=admin", b"2024!secret done"], &secrets);
        assert_eq!(out, b"pw=[REDACTED] done");
        // The same in one chunk, and byte by byte.
        assert_eq!(
            mask(&[b"pw=admin2024!secret done"], &secrets),
            b"pw=[REDACTED] done"
        );
        let bytes: Vec<&[u8]> = b"pw=admin2024!secret done".chunks(1).collect();
        assert_eq!(mask(&bytes, &secrets), b"pw=[REDACTED] done");
        // The short secret alone is still masked, also at the end of the stream.
        assert_eq!(mask(&[b"user=admin"], &secrets), b"user=[REDACTED]");
        assert_eq!(mask(&[b"user=admin ok"], &secrets), b"user=[REDACTED] ok");
    }

    #[test]
    fn aud18_the_parts_of_a_built_database_url_are_masked_one_by_one() {
        let payload: SecretPayload = serde_json::from_str(
            r#"{"kind":"database","engine":"postgres","host":"db","port":5432,"database":"shop","username":"fake-dbuser","password":"fake-dbpass-1"}"#,
        )
        .unwrap();
        let secrets = mask_values(&payload, &env_for(&payload, false).unwrap());
        let refs: Vec<&[u8]> = secrets.iter().map(|v| v.expose().as_bytes()).collect();
        let out = mask(&[b"user fake-dbuser pw fake-dbpass-1"], &refs);
        assert_eq!(out, b"user [REDACTED] pw [REDACTED]");
    }

    #[test]
    fn aud5_loader_and_interpreter_names_from_an_item_are_not_set() {
        let bundle: SecretPayload = serde_json::from_str(
            r#"{"kind":"env_bundle","vars":{"LD_PRELOAD":"/tmp/a.so","NODE_OPTIONS":"--require x","PATH":"/tmp","CERBERUS_TOKEN":"cvt_x","API_TOKEN":"fake-api-token-1"}}"#,
        )
        .unwrap();
        let vars = env_for(&bundle, false).unwrap();
        let names: Vec<_> = vars.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["API_TOKEN"]);
        let cloud: SecretPayload = serde_json::from_str(
            r#"{"kind":"cloud","provider":"aws","access_key_id":"AKIAFAKE","extra":{"BASH_ENV":"/tmp/x","GIT_SSH_COMMAND":"y","REGION_HINT":"eu"}}"#,
        )
        .unwrap();
        let names: Vec<_> = env_for(&cloud, false)
            .unwrap()
            .into_iter()
            .map(|v| v.name)
            .collect();
        assert_eq!(names, ["AWS_ACCESS_KEY_ID", "REGION_HINT"]);
    }

    #[test]
    fn aud5_skipped_names_are_reported_by_name_only() {
        let bundle: SecretPayload = serde_json::from_str(
            r#"{"kind":"env_bundle","vars":{"LD_PRELOAD":"/tmp/a.so","API_TOKEN":"fake-api-token-1"}}"#,
        )
        .unwrap();
        let skipped = forbidden_names(&bundle, false);
        assert_eq!(skipped, ["LD_PRELOAD"]);
        let warning = skipped_warning(&skipped).unwrap();
        assert!(warning.contains("LD_PRELOAD"));
        assert!(!warning.contains("/tmp/a.so"));
        assert!(skipped_warning(&[]).is_none());
    }

    /// AUD-5 re-check (DEC-T27-D1-1): from an agent item, only credential-shaped names are set,
    /// in any case; the deny list still applies to a person's item.
    #[test]
    fn aud5_an_agent_item_sets_only_credential_names() {
        let bundle: SecretPayload = serde_json::from_str(
            r#"{"kind":"env_bundle","vars":{"MAVEN_OPTS":"-javaagent:/tmp/a.jar","OPENSSL_CONF":"/tmp/a.cnf","RUSTFLAGS":"-C linker=/tmp/x","maven_opts":"x","OpenSSL_Conf":"y","KUBECONFIG":"/tmp/k","API_TOKEN":"fake-api-token-1"}}"#,
        )
        .unwrap();
        let names = |by_agent: bool| -> Vec<String> {
            env_for(&bundle, by_agent)
                .unwrap()
                .into_iter()
                .map(|v| v.name)
                .collect()
        };
        assert_eq!(names(true), ["API_TOKEN"]);
        // A person's item: the deny list (now with `_OPTS` and `OPENSSL_CONF`) still skips the
        // code-load hooks, but `KUBECONFIG` stays as before.
        assert_eq!(names(false), ["API_TOKEN", "KUBECONFIG"]);
        let mut skipped = forbidden_names(&bundle, true);
        skipped.sort();
        assert_eq!(
            skipped,
            [
                "KUBECONFIG",
                "MAVEN_OPTS",
                "OPENSSL_CONF",
                "OpenSSL_Conf",
                "RUSTFLAGS",
                "maven_opts"
            ]
        );
        let cloud: SecretPayload = serde_json::from_str(
            r#"{"kind":"cloud","provider":"aws","access_key_id":"AKIAFAKE","extra":{"GOFLAGS":"-toolexec=/tmp/x","DOCKER_HOST":"tcp://x","DEPLOY_TOKEN":"fake-deploy-1"}}"#,
        )
        .unwrap();
        let names: Vec<_> = env_for(&cloud, true)
            .unwrap()
            .into_iter()
            .map(|v| v.name)
            .collect();
        assert_eq!(names, ["AWS_ACCESS_KEY_ID", "DEPLOY_TOKEN"]);
        assert!(written_by_agent("agent:0193"));
        assert!(written_by_agent(""));
        assert!(!written_by_agent("operator:0193"));
    }

    #[test]
    fn aud5_an_explicit_var_mapping_may_set_such_a_name() {
        let vars = mapped_env(&web_login(), &[("PATH".to_owned(), "url".to_owned())]).unwrap();
        assert_eq!(vars[0].name, "PATH");
    }

    fn web_login() -> SecretPayload {
        serde_json::from_str(
            r#"{"kind":"web_login","username":"fake-user","password":"fake-pass-1","url":"https://x.test"}"#,
        )
        .unwrap()
    }

    #[test]
    fn web_login_defaults() {
        let vars = env_for(&web_login(), false).unwrap();
        let names: Vec<_> = vars.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            names,
            ["CERBERUS_USERNAME", "CERBERUS_PASSWORD", "CERBERUS_URL"]
        );
        assert!(vars[0].secret && !vars[2].secret);
    }

    #[test]
    fn rustdesk_defaults_hold_the_id_and_the_password_only_as_secret() {
        let payload: SecretPayload = serde_json::from_str(
            r#"{"kind":"rustdesk","rustdesk_id":"123456789","server_key":"fakekey=","password":"fake-rd-pass"}"#,
        )
        .unwrap();
        let vars = env_for(&payload, false).unwrap();
        let named: Vec<_> = vars.iter().map(|v| (v.name.as_str(), v.secret)).collect();
        assert_eq!(
            named,
            [
                ("CERBERUS_RUSTDESK_ID", false),
                ("CERBERUS_RUSTDESK_PASSWORD", true),
                ("CERBERUS_RUSTDESK_KEY", false)
            ]
        );
    }

    #[test]
    fn mapping_picks_fields_and_rejects_unknown_ones() {
        let vars =
            mapped_env(&web_login(), &[("DB_PW".to_owned(), "password".to_owned())]).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].value.expose(), "fake-pass-1");
        assert!(mapped_env(&web_login(), &[("A".to_owned(), "nope".to_owned())]).is_err());
        assert!(mapped_env(&web_login(), &[("1A".to_owned(), "password".to_owned())]).is_err());
    }

    #[test]
    fn an_ssh_key_is_refused() {
        let payload: SecretPayload = serde_json::from_str(
            r#"{"kind":"ssh_key","private_key":"fake","public_key":"p","fingerprint":"f"}"#,
        )
        .unwrap();
        assert!(env_for(&payload, false).is_err());
    }

    #[test]
    fn database_url_is_built_with_encoding() {
        let payload: SecretPayload = serde_json::from_str(
            r#"{"kind":"database","engine":"postgres","host":"db","port":5432,"database":"shop","username":"u","password":"p@ss"}"#,
        )
        .unwrap();
        let vars = env_for(&payload, false).unwrap();
        assert_eq!(vars[0].value.expose(), "postgres://u:p%40ss@db:5432/shop");
    }
}
