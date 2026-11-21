//! Client side of `cerberusd admin` (ADR-0034 point 3): `enroll`, `list` and `revoke` talk to the
//! running daemon over the unlock socket. `list` and `revoke` also work when no daemon runs: then
//! they read or edit `<data_dir>/admin-clients.json` directly.

use std::io;
use std::path::{Path, PathBuf};

use cerberus_admin::bundle::{AdminBundle, BundleError};
use cerberus_admin::clients::{AdminClient, AdminClients, ClientsError, EnrolmentId};
use cerberus_types::{Clock, SystemClock};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::unlock::{Op, UnlockError, exchange, registry_path};

/// What `cerberusd admin enroll` asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollRequest {
    /// Label of the owner who types the phrase. `None`: the one owner.
    pub owner: Option<String>,
    /// Label of the operator the enrolment is bound to. `None`: the owner.
    pub operator: Option<String>,
    /// Label of the enrolment (for example the desktop's name).
    pub label: String,
    /// The URL the desktop reaches the daemon at, `https://host:port`.
    pub url: String,
}

/// Where `list` and `revoke` did their work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The running daemon (a revoke takes effect at once).
    Daemon,
    /// The registry file, because no daemon answered (a revoke takes effect at the next start).
    File,
}

/// Why an admin command failed.
#[derive(Debug, thiserror::Error)]
pub enum AdminCliError {
    /// The socket exchange failed, or the daemon refused.
    #[error(transparent)]
    Socket(#[from] UnlockError),
    /// The registry file cannot be read or written.
    #[error("{path}: {source}", path = .path.display())]
    Registry {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: ClientsError,
    },
    /// The bundle cannot be written.
    #[error(transparent)]
    Bundle(#[from] BundleError),
    /// The enrolment ID is not valid.
    #[error("{0:?} is not an enrolment ID")]
    BadId(String),
    /// No enrolment with the ID, or revoked already.
    #[error("no enrolment {0} that is not revoked")]
    NotFound(EnrolmentId),
    /// The daemon answered without the expected part.
    #[error("the daemon reply has no {0}")]
    Reply(&'static str),
}

/// The JSON line of an admin request. The phrase is borrowed and the line is written into a buffer
/// big enough from the start (AUD-20).
#[derive(Serialize)]
struct AdminRequestRef<'a> {
    op: Op,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operator: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phrase: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
}

impl AdminRequestRef<'_> {
    fn new(op: Op) -> Self {
        Self {
            op,
            owner: None,
            operator: None,
            label: None,
            url: None,
            phrase: None,
            id: None,
        }
    }

    fn line(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let room = [
            self.owner,
            self.operator,
            self.label,
            self.url,
            self.phrase,
            self.id,
        ]
        .iter()
        .flatten()
        .map(|text| text.len())
        .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(160 + 6 * room));
        serde_json::to_writer(&mut *out, self).map_err(io::Error::other)?;
        out.push(b'\n');
        Ok(out)
    }
}

/// `cerberusd admin enroll`: reads the owner phrase with `read_phrase` (the real caller prompts with
/// echo off), sends the request, and returns the bundle. The caller writes it with
/// [`AdminBundle::write_new`].
///
/// # Errors
/// [`AdminCliError::Socket`] when the daemon is not running, the phrase cannot be read, or the daemon
/// refuses (`vault_locked`, `bad_credentials`, `unavailable` when the admin API is off).
pub async fn enroll_with<R>(
    socket: &Path,
    request: &EnrollRequest,
    read_phrase: R,
) -> Result<AdminBundle, AdminCliError>
where
    R: FnOnce(&str) -> io::Result<String>,
{
    let phrase = Zeroizing::new(read_phrase("Owner passphrase: ").map_err(UnlockError::Prompt)?);
    let line = AdminRequestRef {
        owner: request.owner.as_deref(),
        operator: request.operator.as_deref(),
        label: Some(&request.label),
        url: Some(&request.url),
        phrase: Some(phrase.as_str()),
        ..AdminRequestRef::new(Op::AdminEnroll)
    }
    .line()
    .map_err(UnlockError::Socket)?;
    drop(phrase);
    let reply = exchange(socket, &line).await?;
    reply
        .bundle
        .map(|bundle| *bundle)
        .ok_or(AdminCliError::Reply("bundle"))
}

/// `cerberusd admin list`: from the daemon, or from the registry file when no daemon runs.
///
/// # Errors
/// [`AdminCliError`] when the daemon refuses or the file cannot be read.
pub async fn list_with(
    socket: &Path,
    data_dir: &Path,
) -> Result<(Vec<AdminClient>, Source), AdminCliError> {
    let line = AdminRequestRef::new(Op::AdminList)
        .line()
        .map_err(UnlockError::Socket)?;
    match exchange(socket, &line).await {
        Ok(reply) => Ok((
            reply.clients.ok_or(AdminCliError::Reply("client list"))?,
            Source::Daemon,
        )),
        Err(UnlockError::NotRunning { .. }) => {
            let path = registry_path(data_dir);
            let clients = AdminClients::load(&path)
                .map_err(|source| AdminCliError::Registry { path, source })?;
            Ok((clients.list().to_vec(), Source::File))
        }
        Err(error) => Err(error.into()),
    }
}

/// `cerberusd admin revoke <id>`: through the daemon, so its sessions end at once; when no daemon
/// runs, in the registry file (it takes effect at the next start; no audit event, because the vault
/// is not open).
///
/// # Errors
/// [`AdminCliError::BadId`], [`AdminCliError::NotFound`], or a socket or file error.
pub async fn revoke_with(
    socket: &Path,
    data_dir: &Path,
    id: &str,
) -> Result<Source, AdminCliError> {
    let enrolment: EnrolmentId = id
        .parse()
        .map_err(|_| AdminCliError::BadId(id.to_owned()))?;
    let text = enrolment.to_string();
    let line = AdminRequestRef {
        id: Some(&text),
        ..AdminRequestRef::new(Op::AdminRevoke)
    }
    .line()
    .map_err(UnlockError::Socket)?;
    match exchange(socket, &line).await {
        Ok(_) => Ok(Source::Daemon),
        Err(UnlockError::Refused { code, .. }) if code == "not_found" => {
            Err(AdminCliError::NotFound(enrolment))
        }
        Err(UnlockError::NotRunning { .. }) => {
            let path = registry_path(data_dir);
            let mut clients =
                AdminClients::load(&path).map_err(|source| AdminCliError::Registry {
                    path: path.clone(),
                    source,
                })?;
            if !clients.revoke(enrolment, SystemClock.now()) {
                return Err(AdminCliError::NotFound(enrolment));
            }
            clients
                .save(&path)
                .map_err(|source| AdminCliError::Registry { path, source })?;
            Ok(Source::File)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn an_enrol_line_is_written_without_growing_and_omits_empty_fields() {
        let request = AdminRequestRef {
            label: Some("laptop"),
            url: Some("https://h:7373"),
            phrase: Some("fake \"quoted\" phrase"),
            ..AdminRequestRef::new(Op::AdminEnroll)
        };
        let out = request.line().unwrap();
        let start = out.capacity();
        assert!(out.ends_with(b"\n"));
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["op"], "admin_enroll");
        assert_eq!(value["phrase"], "fake \"quoted\" phrase");
        assert!(value.get("owner").is_none());
        assert_eq!(start, out.capacity());
        let list = AdminRequestRef::new(Op::AdminList).line().unwrap();
        assert_eq!(&list[..], b"{\"op\":\"admin_list\"}\n");
    }
}
