//! The local unlock socket (DEC-T13-1). `cerberusd unlock` sends the passphrase here. The phrase never
//! goes in argv or in an environment variable.
//!
//! The socket is `<data_dir>/cerberusd.sock`, mode `0600`. The server accepts only the uid it runs as. A
//! request is one JSON line: `{"operator": "<label or null>", "phrase": "..."}`. A reply is one JSON line.
//! The phrase is never logged.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreError, VaultService};
use cerberus_crypto::SecretString;
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

/// The socket path for a data directory.
#[must_use]
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SOCKET_FILE)
}

/// A request as the server reads it. It has no `Debug` on purpose: it holds the phrase.
#[derive(Deserialize)]
struct Request {
    operator: Option<String>,
    #[serde(deserialize_with = "zeroizing_string")]
    phrase: Zeroizing<String>,
}

/// The phrase goes straight into a `Zeroizing` string, so every path that drops the request wipes it
/// (AUD-20).
fn zeroizing_string<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// Reads one request line into a buffer of fixed size, so it is never copied to a bigger one. A plain
/// `BufReader` keeps a copy of the phrase in a buffer that nobody wipes.
async fn read_request_line<R>(reader: &mut R) -> io::Result<Zeroizing<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let limit = MAX_REQUEST_BYTES as usize;
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

/// A reply, from either side.
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
}

impl Reply {
    fn success(operator: String) -> Self {
        Self {
            ok: true,
            operator: Some(operator),
            error: None,
            message: None,
        }
    }

    fn failure(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            operator: None,
            error: Some(code.to_owned()),
            message: Some(message.to_owned()),
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

/// Accepts unlock requests until the task is aborted.
pub async fn accept_loop(listener: UnixListener, core: VaultService) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let core = core.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle(stream, &core).await {
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

async fn handle(stream: UnixStream, core: &VaultService) -> io::Result<()> {
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
        Some(request) => unlock(core, request).await,
        None => Reply::failure(
            ErrorCode::InvalidRequest.as_str(),
            "send one JSON line with operator and phrase",
        ),
    };
    let mut out = Zeroizing::new(serde_json::to_vec(&reply).map_err(io::Error::other)?);
    out.push(b'\n');
    write.write_all(&out).await
}

/// The unlock itself. The same call the desktop app makes: `unlock_with_phrase` (ADR-0026).
async fn unlock(core: &VaultService, mut request: Request) -> Reply {
    if core.state() != VaultStateKind::Sealed {
        return Reply::failure(
            ErrorCode::Conflict.as_str(),
            "the vault is not sealed; it is already unlocked or has no vault",
        );
    }
    let phrase = SecretString::new(std::mem::take(&mut *request.phrase));
    let (id, label) = match select_operator(core, request.operator.as_deref()).await {
        Ok(found) => found,
        Err(reply) => return reply,
    };
    match core.unlock_with_phrase(id, phrase).await {
        Ok(ctx) => {
            tracing::info!(operator = %label, "vault unlocked");
            log_ask_grants(core, &ctx).await;
            Reply::success(label)
        }
        Err(error) => refused(&error),
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
    let code = error.code();
    Reply::failure(code.as_str(), &format!("unlock refused: {error}"))
}

/// Logs every `ask_once` and `ask_always` grant. On `cerberusd` these give `403 approval_unavailable` (ADR-0002 point 4).
async fn log_ask_grants(core: &VaultService, ctx: &cerberus_core::OperatorContext) {
    let Ok(grants) = core.policy().list_grants(ctx, None).await else {
        tracing::warn!("could not list grants after unlock");
        return;
    };
    for grant in grants {
        if matches!(grant.mode, GrantMode::AskOnce | GrantMode::AskAlways) {
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
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|_| UnlockError::NotRunning {
            path: socket.to_path_buf(),
        })?;
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
        let phrase: &mut Zeroizing<String> = &mut request.phrase;
        assert_eq!(phrase.as_str(), "fake phrase one");
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

    #[test]
    fn aud20_the_client_request_is_written_without_growing_the_buffer() {
        let phrase = Zeroizing::new("fake \"quoted\" phrase".to_owned());
        let out = request_bytes(Some("owner"), &phrase).unwrap();
        let start = out.capacity();
        assert!(out.ends_with(b"\n"));
        let parsed: Request = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed.phrase.as_str(), phrase.as_str());
        assert_eq!(start, out.capacity());
        assert_eq!(out.capacity(), request_capacity(Some("owner"), &phrase));
    }
}
