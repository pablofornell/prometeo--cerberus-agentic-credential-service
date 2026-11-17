//! Cerberus ssh-agent bridge (T22, ADR-0028).
//!
//! An agent calls `ssh-prepare` and gets the path of a Unix socket that speaks the ssh-agent
//! protocol. `ssh`, `git` and `scp` use it through `SSH_AUTH_SOCK` (or `IdentityAgent`). The
//! private key stays in `cerberus-core`: the bridge only moves the public key and the
//! signatures, and core checks state, agent key, policy and lease, and audits `ssh.sign`, at
//! every signature.
//!
//! - One socket per lease, at most [`MAX_SOCKETS`] (and [`MAX_SOCKETS_PER_AGENT`] per agent).
//! - Socket mode 0600 in a 0700 directory of this user. Only peers with the same user ID are
//!   served (peer credentials). Frames are at most [`protocol::MAX_FRAME_BYTES`].
//! - Only `REQUEST_IDENTITIES` and `SIGN_REQUEST` are served; every other message gets
//!   `SSH_AGENT_FAILURE`.
//! - The socket closes and its file goes when the lease ends, is released or revoked, at lock,
//!   and when the bridge is dropped (process exit). Sockets of a crashed process are removed by
//!   the next bridge in the same runtime directory.
//!
//! Unix only. On other platforms `prepare` gives [`BridgeError::Unsupported`].

#![forbid(unsafe_code)]

mod bridge;
#[cfg(unix)]
mod dirs;
pub mod protocol;
#[cfg(unix)]
mod socket;

pub use bridge::{
    BridgeConfig, BridgeError, MAX_SOCKET_PATH_BYTES, MAX_SOCKETS, MAX_SOCKETS_PER_AGENT,
    PrepareOutcome, SshBridge, SshReady,
};
#[cfg(unix)]
pub use socket::{IDLE_TIMEOUT, MAX_CONNECTIONS};

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
