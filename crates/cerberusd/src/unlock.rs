//! The local unlock socket (DEC-T13-1). `cerberusd unlock` sends the passphrase here, and the
//! `cerberusd admin` commands enrol, list and revoke admin clients here (ADR-0034 point 3). The phrase
//! never goes in argv or in an environment variable.
//!
//! The socket is `<data_dir>/cerberusd.sock`, mode `0600`. The server accepts only the uid it runs as. A
//! request is one JSON line. An unlock is `{"operator": "<label or null>", "phrase": "..."}` (the `op`
//! field is optional and defaults to `unlock`, so old clients keep working). The admin requests are
//! `{"op": "admin_enroll", "owner", "operator", "label", "url", "phrase"}`, `{"op": "admin_list"}` and
//! `{"op": "admin_revoke", "id"}`. A reply is one JSON line. The phrase is never logged.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cerberus_admin::bundle::{AdminBundle, BUNDLE_FORMAT, BUNDLE_VERSION};
use cerberus_admin::clients::{
    ADMIN_CLIENTS_FILE, AdminClient, AdminClients, EnrolmentId, check_label,
};
use cerberus_api::AdminState;
use cerberus_api::tls::{CaExport, LocalCa};
use cerberus_core::vault::KeyCustody;
use cerberus_core::{AdminAudit, AdminEventKind, CoreError, VaultService};
use cerberus_crypto::SecretString;
use cerberus_types::wire::WireSecret;
use cerberus_types::{ErrorCode, GrantMode, OperatorId, OperatorRole, VaultStateKind};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

use crate::daemon::DaemonError;

/// Name of the socket file in the data directory.
pub const SOCKET_FILE: &str = "cerberusd.sock";
/// Longest request line. A phrase of 1 KiB is far above any real phrase.
const MAX_REQUEST_BYTES: u64 = 8 * 1024;
/// Longest reply line. A reply with a bundle (two certificates and a key) or a client list needs
/// more room than an unlock reply.
pub(crate) const MAX_REPLY_BYTES: usize = 64 * 1024;

/// The registry of admin clients for a data directory (ADR-0034 point 3.5).
#[must_use]
pub fn registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ADMIN_CLIENTS_FILE)
}

/// The socket path for a data directory.
#[must_use]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE)
}

/// What a socket request asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Unlock the vault (the default, so a line without `op` is an unlock).
    #[default]
    Unlock,
    /// Enrol a desktop for the admin API and give back its bundle.
    AdminEnroll,
    /// List the enrolments.
    AdminList,
    /// Revoke an enrolment.
    AdminRevoke,
}

/// A request as the server reads it. It has no `Debug` on purpose: it holds the phrase.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    op: Op,
    /// Unlock: the operator to unlock as. Enrol: the operator the enrolment is bound to.
    #[serde(default)]
    operator: Option<String>,
    /// Unlock: the operator's phrase. Enrol: the owner's phrase.
    #[serde(default, deserialize_with = "zeroizing_string")]
    phrase: Option<Zeroizing<String>>,
    /// Enrol: the owner who types the phrase (default: the one owner).
    #[serde(default)]
    owner: Option<String>,
    /// Enrol: the label of the enrolment.
    #[serde(default)]
    label: Option<String>,
    /// Enrol: the URL the desktop reaches the daemon at.
    #[serde(default)]
    url: Option<String>,
    /// Revoke: the enrolment ID.
    #[serde(default)]
    id: Option<String>,
}

/// The phrase goes straight into a `Zeroizing` string, so every path that drops the request wipes it
/// (AUD-20).
fn zeroizing_string<'de, D>(deserializer: D) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|text| text.map(Zeroizing::new))
}

/// Reads one request line into a buffer of fixed size, so it is never copied to a bigger one. A plain
/// `BufReader` keeps a copy of the phrase in a buffer that nobody wipes.
async fn read_request_line<R>(reader: &mut R) -> io::Result<Zeroizing<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    read_line_into_fixed(reader, MAX_REQUEST_BYTES as usize).await
}

/// Reads one line of at most `limit` bytes into a buffer of that size, which never grows.
pub(crate) async fn read_line_into_fixed<R>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Zeroizing<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Zeroizing::new(vec![0u8; limit]);
    let mut filled = 0;
    loop {
        if filled == limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request line too long",
            ));
        }
        let read = reader.read(&mut buf[filled..]).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let start = filled;
        filled += read;
        if let Some(at) = buf[start..filled].iter().position(|b| *b == b'\n') {
            buf.truncate(start + at);
            return Ok(buf);
        }
    }
}

/// Room for the JSON of a request: a character takes at most six bytes when escaped.
fn request_capacity(operator: Option<&str>, phrase: &str) -> usize {
    64 + 6 * (operator.map_or(0, str::len) + phrase.len())
}

/// The request line for the socket, in a buffer that is big enough from the start, so no grown copy
/// of the phrase is left behind (AUD-20).
fn request_bytes(
    operator: Option<&str>,
    phrase: &Zeroizing<String>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(request_capacity(operator, phrase)));
    serde_json::to_writer(
        &mut *out,
        &RequestRef {
            operator,
            phrase: phrase.as_str(),
        },
    )
    .map_err(io::Error::other)?;
    out.push(b'\n');
    Ok(out)
}

/// A request as the client writes it.
#[derive(Serialize)]
struct RequestRef<'a> {
    operator: Option<&'a str>,
    phrase: &'a str,
}

/// A reply, from either side. `Debug` does not print the bundle key.
#[derive(Debug, Deserialize, Serialize)]
pub struct Reply {
    /// True when the vault is unlocked.
    pub ok: bool,
    /// The label of the operator who unlocked, when `ok`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operator: Option<String>,
    /// The wire error code (ADR-0021), when not `ok`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    /// A short text for the person, when not `ok`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// The bundle of a new enrolment (`admin_enroll`). It holds the client key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bundle: Option<Box<AdminBundle>>,
    /// The enrolments (`admin_list`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub clients: Option<Vec<AdminClient>>,
}

impl Reply {
    fn success(operator: String) -> Self {
        Self {
            ok: true,
            operator: Some(operator),
            ..Self::empty()
        }
    }

    fn empty() -> Self {
        Self {
            ok: true,
            operator: None,
            error: None,
            message: None,
            bundle: None,
            clients: None,
        }
    }

    fn failure(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            error: Some(code.to_owned()),
            message: Some(message.to_owned()),
            ..Self::empty()
        }
    }
}

/// Why `cerberusd unlock` failed.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// No daemon is listening on the socket.
    #[error("no cerberusd is running for this data directory (socket {path} not reachable)")]
    NotRunning {
        /// The socket path.
        path: PathBuf,
    },
    /// The passphrase could not be read (no terminal, for example).
    #[error("cannot read the passphrase: {0}. Run this command from a local terminal.")]
    Prompt(io::Error),
    /// The socket failed mid-request.
    #[error("unlock socket error: {0}")]
    Socket(io::Error),
    /// The daemon refused. The text is for the person.
    #[error("{message} ({code})")]
    Refused {
        /// The wire error code.
        code: String,
        /// What to show.
        message: String,
    },
}

/// Binds the unlock socket. A live socket of another daemon is an error. A stale file is replaced.
///
/// # Errors
/// [`DaemonError::AlreadyRunning`] or an I/O error.
pub async fn bind(data_dir: &Path) -> Result<UnixListener, DaemonError> {
    let path = socket_path(data_dir);
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            return Err(DaemonError::AlreadyRunning(path));
        }
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// What the socket handler shares: the core, the admin state when the admin API is on, and the
/// data directory (for the registry file when it is off).
#[derive(Clone)]
pub struct SocketContext {
    /// The vault service.
    pub core: VaultService,
    /// The admin state, when `[admin] enabled = true`.
    pub admin: Option<Arc<AdminState>>,
    /// The data directory.
    pub data_dir: PathBuf,
}

/// Accepts socket requests until the task is aborted.
pub async fn accept_loop(listener: UnixListener, context: SocketContext) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let context = context.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle(stream, &context).await {
                        tracing::debug!(%error, "unlock connection ended with an error");
                    }
                });
            }
            Err(error) => {
                tracing::warn!(%error, "unlock socket accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(stream: UnixStream, context: &SocketContext) -> io::Result<()> {
    let core = &context.core;
    let peer = stream.peer_cred()?;
    if peer.uid() != rustix::process::getuid().as_raw() {
        tracing::warn!(uid = peer.uid(), "unlock refused: another user");
        return Ok(());
    }
    let (mut read, mut write) = stream.into_split();
    // The line holds the phrase: it is erased when this request ends.
    let request = read_request_line(&mut read)
        .await
        .ok()
        .and_then(|line| serde_json::from_slice::<Request>(&line).ok());
    // The line is wiped here, before the slow unlock starts.
    let reply = match request {
        Some(request) => match request.op {
            Op::Unlock => unlock(core, request, context.admin.is_some()).await,
            Op::AdminEnroll => admin_enroll(core, context.admin.as_deref(), request).await,
            Op::AdminList => admin_list(context),
            Op::AdminRevoke => admin_revoke(context, request).await,
        },
        None => Reply::failure(
            ErrorCode::InvalidRequest.as_str(),
            "send one JSON line with operator and phrase",
        ),
    };
    // The reply can hold a bundle key: it is written from a zeroizing buffer that never leaves a
    // grown copy behind, and the newline goes separately.
    let out = cerberus_admin::rpc::to_body(&reply).map_err(io::Error::other)?;
    drop(reply);
    write.write_all(&out).await?;
    write.write_all(b"\n").await
}

fn invalid(message: &str) -> Reply {
    Reply::failure(ErrorCode::InvalidRequest.as_str(), message)
}

/// The unlock itself. The same call the desktop app makes: `unlock_with_phrase` (ADR-0026).
async fn unlock(core: &VaultService, mut request: Request, approvals: bool) -> Reply {
    if core.state() != VaultStateKind::Sealed {
        return Reply::failure(
            ErrorCode::Conflict.as_str(),
            "the vault is not sealed; it is already unlocked or has no vault",
        );
    }
    let Some(mut text) = request.phrase.take() else {
        return invalid("send one JSON line with operator and phrase");
    };
    let phrase = SecretString::new(std::mem::take(&mut *text));
    let (id, label) = match select_operator(core, request.operator.as_deref()).await {
        Ok(found) => found,
        Err(reply) => return reply,
    };
    match core.unlock_with_phrase(id, phrase).await {
        Ok(ctx) => {
            tracing::info!(operator = %label, "vault unlocked");
            log_ask_grants(core, &ctx, approvals).await;
            Reply::success(label)
        }
        Err(error) => refused(&error),
    }
}

/// `admin_enroll` (ADR-0034 point 3): the vault must be unlocked (the CA key is sealed otherwise),
/// an owner's phrase is checked (it counts in the unlock back-off), then a client certificate is
/// signed, the enrolment is saved in the registry and audited, and the bundle goes back.
async fn admin_enroll(
    core: &VaultService,
    admin: Option<&AdminState>,
    mut request: Request,
) -> Reply {
    let Some(admin) = admin else {
        return Reply::failure(
            ErrorCode::Unavailable.as_str(),
            "the admin API is off: set [admin] enabled = true in cerberusd.toml and restart",
        );
    };
    let Some(mut text) = request.phrase.take() else {
        return invalid("send the owner passphrase");
    };
    let phrase = SecretString::new(std::mem::take(&mut *text));
    let (Some(label), Some(url)) = (request.label.take(), request.url.take()) else {
        return invalid("send a label and a URL");
    };
    if check_label(&label).is_err() {
        return invalid("the label must be 1 to 64 characters without control characters");
    }
    if core.state() != VaultStateKind::Unlocked {
        return Reply::failure(
            ErrorCode::VaultLocked.as_str(),
            "the vault is sealed: run cerberusd unlock first (the CA key is sealed until then)",
        );
    }
    let operators = match core.list_operators().await {
        Ok(operators) => operators,
        Err(error) => return refused(&error),
    };
    let (owner_id, owner_label) = match select_operator(core, request.owner.as_deref()).await {
        Ok(found) => found,
        Err(reply) => return reply,
    };
    let not_owner = || {
        Reply::failure(
            ErrorCode::Forbidden.as_str(),
            "an enrolment needs the passphrase of an owner",
        )
    };
    // The stored role first, so a viewer spends no KDF; the session role decides below.
    if !operators
        .iter()
        .any(|op| op.id == owner_id && op.role == OperatorRole::Owner)
    {
        return not_owner();
    }
    let ctx = match core.verify_operator_phrase(owner_id, phrase).await {
        Ok(ctx) => ctx,
        Err(CoreError::Conflict) => {
            return Reply::failure(
                ErrorCode::Conflict.as_str(),
                "the vault is unlocked by another operator; use that owner's passphrase",
            );
        }
        Err(CoreError::BadCredentials) => {
            return Reply::failure(
                "bad_credentials",
                "enrolment refused: wrong owner passphrase",
            );
        }
        Err(error) => return refused_with("enrolment refused", &error),
    };
    // The role of the live session, not the one stored in the key slots: a header MAC failure
    // makes the session viewer although the slot says owner (DEC-FIX5-4, DEC-RM-22).
    if ctx.role != OperatorRole::Owner {
        return not_owner();
    }
    let operator = match request.operator.as_deref() {
        None => owner_id,
        Some(wanted) => match operators.iter().find(|op| op.label == wanted) {
            Some(op) => op.id,
            None => return invalid("no operator has this label"),
        },
    };
    let now = core.clock().now();
    let (bundle, cert_der) = match issue_bundle(core, label.clone(), url, operator, now).await {
        Ok(issued) => issued,
        Err(reply) => return reply,
    };
    let entry = match AdminClient::enrolled(
        bundle.id,
        label.clone(),
        operator,
        &cert_der,
        bundle.not_after,
        now,
    ) {
        Ok(entry) => entry,
        Err(error) => return invalid(&error.to_string()),
    };
    if let Err(error) = admin.enroll(entry) {
        tracing::error!(%error, "admin client registry not saved");
        return Reply::failure(
            ErrorCode::Internal.as_str(),
            &format!("the admin client registry could not be saved: {error}"),
        );
    }
    let mut event = AdminAudit::new(AdminEventKind::ClientEnroll);
    event.enrolment = Some(bundle.id.to_string());
    event.label = Some(label);
    event.operator = Some(operator);
    if let Err(error) = core.record_admin_event(Some(&ctx), event).await {
        tracing::warn!(%error, "admin.client_enroll was not audited");
    }
    tracing::warn!(enrolment = %bundle.id, "admin client enrolled");
    Reply {
        operator: Some(owner_label),
        bundle: Some(Box::new(bundle)),
        ..Reply::empty()
    }
}

/// Signs a client certificate with the vault CA and builds the bundle; also gives the certificate
/// (DER) for the registry hash. The bundle is checked as the desktop will check it, so a bad URL
/// fails here and not at import.
async fn issue_bundle(
    core: &VaultService,
    label: String,
    url: String,
    operator: OperatorId,
    now: jiff::Timestamp,
) -> Result<(AdminBundle, Vec<u8>), Reply> {
    let internal = |error: &dyn std::fmt::Display| {
        tracing::error!(%error, "admin client certificate not made");
        Reply::failure(
            ErrorCode::Internal.as_str(),
            "the client certificate could not be made",
        )
    };
    let material = core
        .tls_ca_material()
        .await
        .map_err(|error| refused(&error))?;
    let export = CaExport::from_der(&material.cert_der).map_err(|e| internal(&e))?;
    let ca =
        LocalCa::from_parts(&material.cert_der, &material.key_der).map_err(|e| internal(&e))?;
    let id = EnrolmentId::generate();
    let issued = ca
        .issue_admin_client(&id.to_string(), now)
        .map_err(|e| internal(&e))?;
    let bundle = AdminBundle {
        format: BUNDLE_FORMAT.to_owned(),
        version: BUNDLE_VERSION,
        id,
        label,
        url,
        operator_id: operator,
        ca_pin: export.pin,
        ca_cert_pem: export.pem,
        client_cert_pem: issued.cert_pem(),
        client_key_pem: WireSecret::new(issued.key_pem()),
        not_after: issued.not_after,
    };
    bundle
        .check(now)
        .map_err(|error| invalid(&error.to_string()))?;
    Ok((bundle, issued.cert_der))
}

/// `admin_list`: from the live registry, or from the file when the admin API is off.
fn admin_list(context: &SocketContext) -> Reply {
    let clients = match &context.admin {
        Some(admin) => admin.clients(),
        None => match AdminClients::load(&registry_path(&context.data_dir)) {
            Ok(clients) => clients,
            Err(error) => {
                return Reply::failure(ErrorCode::Internal.as_str(), &error.to_string());
            }
        },
    };
    Reply {
        clients: Some(clients.list().to_vec()),
        ..Reply::empty()
    }
}

/// `admin_revoke` (ADR-0034 point 3.6). No phrase: it only removes power. With the admin API on, the
/// sessions of the enrolment end at once; with it off, the file is edited and the revoke audited.
async fn admin_revoke(context: &SocketContext, request: Request) -> Reply {
    let Some(id) = request
        .id
        .as_deref()
        .and_then(|id| id.parse::<EnrolmentId>().ok())
    else {
        return invalid("send the enrolment ID");
    };
    let core = &context.core;
    let not_found = || {
        Reply::failure(
            ErrorCode::NotFound.as_str(),
            "no enrolment with this ID, or it is revoked already",
        )
    };
    match &context.admin {
        Some(admin) => match admin.revoke(core, id).await {
            Ok(true) => {
                tracing::warn!(enrolment = %id, "admin client revoked");
                Reply::empty()
            }
            Ok(false) => not_found(),
            Err(error) => Reply::failure(
                ErrorCode::Internal.as_str(),
                &format!(
                    "revoked until the daemon stops, but the registry could not be saved: {error}; \
                     fix the cause and revoke again to save it"
                ),
            ),
        },
        None => {
            let path = registry_path(&context.data_dir);
            let mut clients = match AdminClients::load(&path) {
                Ok(clients) => clients,
                Err(error) => {
                    return Reply::failure(ErrorCode::Internal.as_str(), &error.to_string());
                }
            };
            if !clients.revoke(id, core.clock().now()) {
                return not_found();
            }
            if let Err(error) = clients.save(&path) {
                return Reply::failure(ErrorCode::Internal.as_str(), &error.to_string());
            }
            let mut event = AdminAudit::new(AdminEventKind::ClientRevoke);
            event.enrolment = Some(id.to_string());
            if let Some(entry) = clients.get(id) {
                event.label = Some(entry.label.clone());
                event.operator = Some(entry.operator_id);
            }
            if let Err(error) = core.record_admin_event(None, event).await {
                tracing::warn!(%error, "admin.client_revoke was not audited");
            }
            tracing::warn!(enrolment = %id, "admin client revoked in the registry file");
            Reply::empty()
        }
    }
}

/// The operator a request names by label. With no label, the one owner. Two owners need a label.
async fn select_operator(
    core: &VaultService,
    label: Option<&str>,
) -> Result<(OperatorId, String), Reply> {
    let operators = core
        .list_operators()
        .await
        .map_err(|error| refused(&error))?;
    let chosen = match label {
        Some(wanted) => operators.iter().find(|op| op.label == wanted),
        None => {
            let owners: Vec<_> = operators
                .iter()
                .filter(|op| op.role == OperatorRole::Owner)
                .collect();
            if owners.len() == 1 {
                owners.first().copied()
            } else {
                None
            }
        }
    };
    match chosen {
        Some(op) => Ok((op.id, op.label.clone())),
        None => Err(Reply::failure(
            ErrorCode::InvalidRequest.as_str(),
            "no single owner: name the operator with --operator <label>",
        )),
    }
}

fn refused(error: &CoreError) -> Reply {
    refused_with("unlock refused", error)
}

fn refused_with(what: &str, error: &CoreError) -> Reply {
    let code = error.code();
    Reply::failure(code.as_str(), &format!("{what}: {error}"))
}

/// Logs every `ask_once` and `ask_always` grant. Without the admin API these give
/// `403 approval_unavailable` (ADR-0002 point 4); with it, an enrolled desktop decides them
/// (ADR-0034 point 2.3).
async fn log_ask_grants(
    core: &VaultService,
    ctx: &cerberus_core::OperatorContext,
    approvals: bool,
) {
    let Ok(grants) = core.policy().list_grants(ctx, None).await else {
        tracing::warn!("could not list grants after unlock");
        return;
    };
    for grant in grants {
        if !matches!(grant.mode, GrantMode::AskOnce | GrantMode::AskAlways) {
            continue;
        }
        if approvals {
            tracing::info!(
                grant = %grant.id,
                agent = %grant.agent_id,
                mode = ?grant.mode,
                "grant needs an approval; an enrolled desktop decides it, else it expires"
            );
        } else {
            tracing::warn!(
                grant = %grant.id,
                agent = %grant.agent_id,
                mode = ?grant.mode,
                "grant needs an approval; cerberusd answers 403 approval_unavailable for it"
            );
        }
    }
}

/// Client side of `cerberusd unlock`: reads the phrase with `read_phrase`, sends it to the socket, and returns the
/// label of the operator who unlocked. `read_phrase` gets the prompt text. The real caller prompts with echo off.
///
/// # Errors
/// [`UnlockError`] when the daemon is not running, the phrase cannot be read, or the daemon refuses.
pub async fn unlock_with<R>(
    socket: &Path,
    operator: Option<&str>,
    read_phrase: R,
) -> Result<String, UnlockError>
where
    R: FnOnce(&str) -> io::Result<String>,
{
    let phrase = Zeroizing::new(read_phrase("Passphrase: ").map_err(UnlockError::Prompt)?);
    let stream = connect(socket).await?;
    let (read, mut write) = stream.into_split();
    let out = request_bytes(operator, &phrase).map_err(UnlockError::Socket)?;
    write.write_all(&out).await.map_err(UnlockError::Socket)?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(read.take(MAX_REQUEST_BYTES))
        .read_line(&mut line)
        .await
        .map_err(UnlockError::Socket)?;
    let reply: Reply = serde_json::from_str(&line)
        .map_err(|error| UnlockError::Socket(io::Error::other(error)))?;
    if reply.ok {
        return Ok(reply.operator.unwrap_or_default());
    }
    Err(UnlockError::Refused {
        code: reply.error.unwrap_or_else(|| "internal".into()),
        message: reply.message.unwrap_or_else(|| "unlock refused".into()),
    })
}

/// Connects to the socket of a running daemon. Only "no socket file" (`ENOENT`) and "nobody
/// listens" (`ECONNREFUSED`, a stale file) mean that no daemon runs: any other error (a denied
/// permission, a bad path) is [`UnlockError::Socket`], so `cerberusd admin` never edits the
/// registry file under a daemon that runs (DEC-RM-22).
pub(crate) async fn connect(socket: &Path) -> Result<UnixStream, UnlockError> {
    UnixStream::connect(socket)
        .await
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => UnlockError::NotRunning {
                path: socket.to_path_buf(),
            },
            _ => UnlockError::Socket(error),
        })
}

/// Sends one request line and reads the reply line into a fixed zeroizing buffer (a reply can hold
/// a bundle key). A refusal becomes [`UnlockError::Refused`].
pub(crate) async fn exchange(socket: &Path, line: &[u8]) -> Result<Reply, UnlockError> {
    let stream = connect(socket).await?;
    let (mut read, mut write) = stream.into_split();
    write.write_all(line).await.map_err(UnlockError::Socket)?;
    let reply_line = read_line_into_fixed(&mut read, MAX_REPLY_BYTES)
        .await
        .map_err(UnlockError::Socket)?;
    let reply: Reply = serde_json::from_slice(&reply_line)
        .map_err(|error| UnlockError::Socket(io::Error::other(error)))?;
    if reply.ok {
        return Ok(reply);
    }
    Err(UnlockError::Refused {
        code: reply.error.unwrap_or_else(|| "internal".into()),
        message: reply.message.unwrap_or_else(|| "refused".into()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
mod tests {
    use super::*;

    /// AUD-20: the phrase of a request is `Zeroizing` from the moment it is parsed, also on the path
    /// where the vault is not sealed and the request is dropped.
    #[test]
    fn aud20_the_phrase_of_a_request_is_zeroizing() {
        let mut request: Request =
            serde_json::from_slice(br#"{"operator":null,"phrase":"fake phrase one"}"#).unwrap();
        let phrase: &mut Zeroizing<String> = request.phrase.as_mut().unwrap();
        assert_eq!(phrase.as_str(), "fake phrase one");
        assert_eq!(request.op, Op::Unlock, "a line without op is an unlock");
    }

    #[test]
    fn admin_requests_parse_and_unknown_fields_are_refused() {
        let enroll: Request = serde_json::from_slice(
            br#"{"op":"admin_enroll","owner":null,"operator":"ops","label":"laptop","url":"https://h:7373","phrase":"p"}"#,
        )
        .unwrap();
        assert_eq!(enroll.op, Op::AdminEnroll);
        assert_eq!(enroll.label.as_deref(), Some("laptop"));
        let revoke: Request = serde_json::from_slice(br#"{"op":"admin_revoke","id":"x"}"#).unwrap();
        assert_eq!(revoke.op, Op::AdminRevoke);
        assert!(revoke.phrase.is_none());
        assert!(serde_json::from_slice::<Request>(br#"{"op":"admin_list","x":1}"#).is_err());
        assert!(serde_json::from_slice::<Request>(br#"{"op":"restore"}"#).is_err());
    }

    #[tokio::test]
    async fn aud20_a_request_line_is_read_into_a_buffer_that_never_grows() {
        let mut input: &[u8] = b"{\"operator\":null,\"phrase\":\"fake phrase one\"}\nrest";
        let line = read_request_line(&mut input).await.unwrap();
        assert_eq!(
            &line[..],
            b"{\"operator\":null,\"phrase\":\"fake phrase one\"}"
        );
        assert_eq!(line.capacity(), MAX_REQUEST_BYTES as usize);
    }

    #[tokio::test]
    async fn aud20_a_request_without_a_newline_or_over_the_limit_is_refused() {
        let mut short: &[u8] = b"{\"operator\":null";
        assert!(read_request_line(&mut short).await.is_err());
        let long = vec![b'a'; MAX_REQUEST_BYTES as usize + 10];
        let mut over: &[u8] = &long;
        assert!(read_request_line(&mut over).await.is_err());
    }

    const OWNER_PHRASE: &str = "fake owner phrase for this test";
    const VIEWER_PHRASE: &str = "fake viewer phrase for this test";

    /// A vault in `dir` with an owner (`owner`) and a viewer (`ops`), sealed. Gives the service
    /// and the viewer's ID.
    async fn sealed_vault_with_a_viewer(dir: &Path) -> (VaultService, OperatorId) {
        use cerberus_api::tls::{LocalCaIssuer, TlsPaths};
        use cerberus_core::{CoreConfig, NewVault, OperatorContext};
        use cerberus_store::{OpenOptions, Store};
        use cerberus_types::{Clock, LockReason, RequestId, SystemClock};

        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let store = Store::open(
            OpenOptions {
                path: dir.join("vault.cerberus"),
                create: true,
            },
            Arc::clone(&clock),
        )
        .await
        .unwrap();
        let core = VaultService::open(
            store,
            clock,
            CoreConfig {
                approvals_available: true,
                idle_lock_default: None,
                data_dir: dir.to_path_buf(),
                ca_issuer: Arc::new(LocalCaIssuer::new(TlsPaths::in_data_dir(dir), Vec::new())),
            },
        )
        .await
        .unwrap();
        let created = core
            .create_vault(NewVault {
                owner_label: "owner".to_owned(),
                phrase: SecretString::new(OWNER_PHRASE.to_owned()),
                kdf: cerberus_crypto::KdfParams::new(19_456, 1, 1).unwrap(),
                host_names: vec![],
            })
            .await
            .unwrap();
        let owner = OperatorContext {
            operator_id: created.owner_id,
            role: OperatorRole::Owner,
            request_id: RequestId::generate(),
        };
        let viewer = core
            .add_operator(
                &owner,
                "ops".to_owned(),
                OperatorRole::Viewer,
                SecretString::new(VIEWER_PHRASE.to_owned()),
            )
            .await
            .unwrap();
        core.lock(LockReason::Manual).await.unwrap();
        (core, viewer)
    }

    /// DEC-RM-22: an enrolment needs the owner role of the live session. A slot role edited in
    /// the file to `owner` fails the header MAC, so the session is viewer (DEC-FIX5-4); the stored
    /// role alone must not let that operator enrol a desktop.
    #[tokio::test]
    async fn an_enrolment_needs_the_owner_role_of_the_session_not_of_the_slot() {
        use cerberus_store::{OpenOptions, Store};
        use cerberus_types::SystemClock;

        let dir = tempfile::tempdir().unwrap();
        let (core, viewer) = sealed_vault_with_a_viewer(dir.path()).await;
        let raw = Store::open(
            OpenOptions {
                path: dir.path().join("vault.cerberus"),
                create: false,
            },
            Arc::new(SystemClock),
        )
        .await
        .unwrap();
        let mut row = raw
            .key_slots()
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.id == viewer)
            .unwrap();
        row.role = OperatorRole::Owner;
        let mut tx = raw.begin().await.unwrap();
        tx.upsert_slot(&row).await.unwrap();
        tx.commit().await.unwrap();
        raw.close().await;
        let ctx = core
            .unlock_with_phrase(viewer, SecretString::new(VIEWER_PHRASE.to_owned()))
            .await
            .unwrap();
        assert_eq!(ctx.role, OperatorRole::Viewer, "the header MAC failed");
        let admin = AdminState::new(
            AdminClients::default(),
            cerberus_api::AdminLimits::default(),
        );
        let request: Request = serde_json::from_value(serde_json::json!({
            "op": "admin_enroll",
            "owner": "ops",
            "label": "laptop",
            "url": "https://localhost:7373",
            "phrase": VIEWER_PHRASE,
        }))
        .unwrap();
        let reply = admin_enroll(&core, Some(&admin), request).await;
        assert!(!reply.ok, "{reply:?}");
        assert_eq!(reply.error.as_deref(), Some("forbidden"));
        assert!(reply.bundle.is_none());
        assert!(admin.clients().list().is_empty());
    }

    #[test]
    fn aud20_the_client_request_is_written_without_growing_the_buffer() {
        let phrase = Zeroizing::new("fake \"quoted\" phrase".to_owned());
        let out = request_bytes(Some("owner"), &phrase).unwrap();
        let start = out.capacity();
        assert!(out.ends_with(b"\n"));
        let parsed: Request = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed.phrase.unwrap().as_str(), phrase.as_str());
        assert_eq!(start, out.capacity());
        assert_eq!(out.capacity(), request_capacity(Some("owner"), &phrase));
    }
}
