//! Types of the RustDesk commands (DEC-RD-3). None of them holds a secret.

use serde::{Deserialize, Serialize};
use specta::Type;

/// Where the RustDesk client was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum RustdeskClientKind {
    /// The program chosen in Settings.
    Custom,
    /// `rustdesk` on the search path.
    Path,
    /// A standard install location.
    Installed,
    /// The Flatpak app `com.rustdesk.RustDesk`.
    Flatpak,
}

/// The RustDesk client that `rustdesk_connect` starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct RustdeskClientView {
    /// Where it was found.
    pub kind: RustdeskClientKind,
    /// The program that runs: the client itself, or `flatpak` for the Flatpak app.
    pub program: String,
}

/// Result of `rustdesk_status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct RustdeskStatusView {
    /// The program chosen in Settings, if any. When it is set, nothing else is looked for.
    pub custom_path: Option<String>,
    /// The client `rustdesk_connect` would start. `None`: RustDesk was not found.
    pub client: Option<RustdeskClientView>,
}

/// What `rustdesk_connect` did with the password of the item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum RustdeskPasswordCopy {
    /// On the clipboard. It is cleared after 30 seconds if it is still there.
    Copied,
    /// The item has no password.
    NotStored,
    /// The password could not be read or copied (for example the role cannot reveal).
    NotCopied,
    /// The caller did not ask for it.
    Skipped,
}

/// Result of `rustdesk_connect`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
pub struct RustdeskConnectView {
    /// The client that was started.
    pub client: RustdeskClientView,
    /// What happened to the password.
    pub password: RustdeskPasswordCopy,
}
