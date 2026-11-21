//! The command layer without a window: one function per IPC command, taking the state and the
//! label of the calling window. The `#[tauri::command]` wrappers in `commands.rs` only pass those
//! on. Tests call these functions directly with a fake window label.
//!
//! Each function (1) checks the window label, (2) builds the `OperatorContext` from the unlocked
//! session (`DesktopState::operator`), and (3) calls exactly one `VaultService` method, which
//! checks the role of the session (`authorize`, DEC-WIRE6-13). The commands of the remote
//! allowlist make that call through the shared handler in `cerberus_admin::handlers`, the same
//! one the admin API of `cerberusd` runs (ADR-0034).

mod agents;
mod csv;
mod files;
mod generate;
mod items;
mod policy;
mod restore;
mod rustdesk;
mod system;
mod vault;

pub use agents::*;
pub use csv::*;
pub use generate::CharClass;
pub use items::*;
pub use policy::*;
pub use restore::*;
pub use rustdesk::{RUSTDESK_PATH_KEY, rustdesk_connect, rustdesk_status};
pub use system::*;
pub use vault::*;
