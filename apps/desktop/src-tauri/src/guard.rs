//! The window label check (ADR-0003, threat S-6 and E-12). Every command calls [`check`] first.
//!
//! The `main` window may call every command. The `approval` window may call only
//! [`APPROVAL_COMMANDS`]. Any other label (a window an injected script opened, or a remote page)
//! may call nothing. Tauri capability files say the same thing a second time, so a window cannot
//! even reach a command that its capability does not list.

use crate::error::{IpcError, IpcResult};

include!("names.rs");

/// Label of the main window.
pub const MAIN_WINDOW: &str = "main";
/// Label of the approval window.
pub const APPROVAL_WINDOW: &str = "approval";

/// True when the window `label` may call `command`. An unknown command is never allowed.
#[must_use]
pub fn allowed(label: &str, command: &str) -> bool {
    if !ALL_COMMANDS.contains(&command) {
        return false;
    }
    match label {
        MAIN_WINDOW => true,
        APPROVAL_WINDOW => APPROVAL_COMMANDS.contains(&command),
        _ => false,
    }
}

/// Checks the label of the calling window.
///
/// # Errors
/// `window_not_allowed` when the window may not call `command`.
pub fn check(label: &str, command: &str) -> IpcResult<()> {
    if allowed(label, command) {
        Ok(())
    } else {
        tracing::warn!(
            window = label,
            command,
            "IPC call from a window that may not make it"
        );
        Err(IpcError::window_not_allowed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_may_call_everything() {
        for command in ALL_COMMANDS {
            assert!(allowed(MAIN_WINDOW, command), "{command}");
        }
    }

    #[test]
    fn approval_window_may_call_only_its_commands() {
        for command in ALL_COMMANDS {
            assert_eq!(
                allowed(APPROVAL_WINDOW, command),
                APPROVAL_COMMANDS.contains(&command),
                "{command}"
            );
        }
        assert!(!allowed(APPROVAL_WINDOW, "item_reveal"));
        assert!(!allowed(APPROVAL_WINDOW, "vault_unlock"));
        assert!(allowed(APPROVAL_WINDOW, "request_approve"));
    }

    #[test]
    fn other_labels_and_unknown_commands_are_refused() {
        assert!(!allowed("evil", "vault_status"));
        assert!(!allowed("", "vault_status"));
        assert!(!allowed(MAIN_WINDOW, "shell_exec"));
        assert_eq!(
            check("approval", "item_list").unwrap_err().code,
            "window_not_allowed"
        );
    }
}
