//! One signing socket: a Unix listener for one lease, and its connections.
//!
//! - Only a peer with the user ID of this process may talk to the socket (`SO_PEERCRED`, or
//!   `getpeereid` on macOS, read through tokio). Other peers are dropped without an answer.
//! - At most [`MAX_CONNECTIONS`] connections at a time; a connection that sends nothing for
//!   [`IDLE_TIMEOUT`] is closed.
//! - Dropping the [`Socket`] stops the listener and every connection, and removes the file.

use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use cerberus_core::AgentApi;
use cerberus_core::agent_api::ssh::SshTicket;
use cerberus_types::LeaseId;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::{JoinHandle, JoinSet};

use crate::dirs::{SOCKET_MODE, own_uid};
use crate::protocol::{self, Request, read_frame};

/// Connections one socket serves at a time.
pub const MAX_CONNECTIONS: usize = 8;
/// A connection that sends no message for this long is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Wait after a failed `accept` (for example too many open files), so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What the connections of one socket share.
struct Shared {
    api: AgentApi,
    ticket: Mutex<SshTicket>,
    uid: u32,
    /// Tells the bridge to check (and maybe close) this socket after a refused sign.
    check: UnboundedSender<LeaseId>,
}

impl Shared {
    fn ticket(&self) -> SshTicket {
        self.ticket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// A listening signing socket.
pub(crate) struct Socket {
    path: PathBuf,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socket")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Socket {
    /// Binds a new socket at `path` (mode 0600) and starts to accept connections.
    pub(crate) fn open(
        path: PathBuf,
        api: AgentApi,
        ticket: SshTicket,
        check: UnboundedSender<LeaseId>,
    ) -> io::Result<Self> {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        // The directory is 0700, so nobody else can reach the socket before this.
        if let Err(error) = fs::set_permissions(&path, Permissions::from_mode(SOCKET_MODE)) {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        let shared = Arc::new(Shared {
            api,
            ticket: Mutex::new(ticket),
            uid: own_uid(),
            check,
        });
        let task = tokio::spawn(accept_loop(listener, Arc::clone(&shared)));
        Ok(Self { path, shared, task })
    }

    /// The socket path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The current ticket.
    pub(crate) fn ticket(&self) -> SshTicket {
        self.shared.ticket()
    }

    /// Puts a newer ticket of the same lease in place (a second prepare on the same lease).
    pub(crate) fn replace_ticket(&self, ticket: SshTicket) {
        let mut current = self
            .shared
            .ticket
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // The rate limit belongs to the lease, not to one ticket (DEC-FIX8-7).
        ticket.carry_rate_window(&current);
        *current = ticket;
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        // Aborting the accept task drops its `JoinSet`, which aborts every connection task.
        self.task.abort();
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(path = %self.path.display(), %error, "could not remove an ssh-agent socket");
            }
        }
    }
}

/// True when the peer runs as the same user as this process.
fn peer_allowed(stream: &UnixStream, uid: u32) -> bool {
    stream.peer_cred().is_ok_and(|cred| cred.uid() == uid)
}

async fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    let mut connections = JoinSet::new();
    loop {
        let accepted = listener.accept().await;
        while connections.try_join_next().is_some() {}
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "ssh-agent socket accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if !peer_allowed(&stream, shared.uid) {
            tracing::warn!("ssh-agent socket refused a peer of another user");
            continue;
        }
        if connections.len() >= MAX_CONNECTIONS {
            tracing::warn!("ssh-agent socket refused a connection: too many open");
            continue;
        }
        connections.spawn(serve(stream, Arc::clone(&shared)));
    }
}

/// The comment of the one identity: the Cerberus item, never key material.
fn comment(ticket: &SshTicket) -> String {
    format!("cerberus:{}", ticket.item_id())
}

async fn answer(shared: &Shared, frame: &[u8]) -> Vec<u8> {
    match protocol::parse_request(frame) {
        Request::Identities => {
            let ticket = shared.ticket();
            if shared.api.ssh_ticket_open(&ticket).await {
                protocol::identities_answer(&[(ticket.key_blob(), &comment(&ticket))])
            } else {
                protocol::identities_answer(&[])
            }
        }
        Request::Sign {
            key_blob,
            data,
            flags,
        } => {
            let ticket = shared.ticket();
            if key_blob != ticket.key_blob() {
                return protocol::failure();
            }
            match shared.api.ssh_sign(&ticket, data, flags).await {
                Ok(signature) => protocol::sign_response(&signature),
                Err(error) => {
                    tracing::info!(code = error.code().as_str(), "ssh-agent sign refused");
                    let _ = shared.check.send(ticket.lease_id());
                    protocol::failure()
                }
            }
        }
        Request::Refused(kind) => {
            tracing::debug!(kind, "ssh-agent message refused");
            protocol::failure()
        }
    }
}

async fn serve(mut stream: UnixStream, shared: Arc<Shared>) {
    loop {
        let frame = match tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut stream)).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => return,
            Ok(Err(error)) => {
                tracing::debug!(?error, "ssh-agent connection closed on a bad frame");
                return;
            }
            Err(_) => return,
        };
        let reply = answer(&shared, &frame).await;
        if stream.write_all(&reply).await.is_err() {
            return;
        }
    }
}
