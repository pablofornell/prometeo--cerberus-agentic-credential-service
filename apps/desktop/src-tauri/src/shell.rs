//! The real [`Shell`]: clipboard, autostart and content protection through Tauri and its plugins,
//! and the start of a local program (the RustDesk client, DEC-RD-3).

use std::path::Path;
use std::process::{Command, Stdio};

use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_autostart::ManagerExt as AutostartExt;
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

use crate::error::{IpcError, IpcResult};
use crate::guard::MAIN_WINDOW;
use crate::state::Shell;

/// [`Shell`] over a Tauri app handle.
pub struct TauriShell {
    app: AppHandle<Wry>,
}

impl TauriShell {
    /// A shell for `app`.
    #[must_use]
    pub const fn new(app: AppHandle<Wry>) -> Self {
        Self { app }
    }
}

impl Shell for TauriShell {
    fn clipboard_write(&self, text: &str) -> IpcResult<()> {
        self.app
            .clipboard()
            .write_text(text.to_owned())
            .map_err(|error| {
                tracing::warn!(%error, "clipboard write failed");
                IpcError::unavailable("the clipboard cannot be written")
            })
    }

    fn clipboard_read(&self) -> Option<String> {
        self.app.clipboard().read_text().ok()
    }

    fn clipboard_clear(&self) {
        if let Err(error) = self.app.clipboard().clear() {
            tracing::warn!(%error, "clipboard clear failed");
        }
    }

    fn set_autostart(&self, enabled: bool) -> IpcResult<()> {
        let manager = self.app.autolaunch();
        let result = if enabled {
            manager.enable()
        } else {
            manager.disable()
        };
        result.map_err(|error| {
            tracing::warn!(%error, "autostart change failed");
            IpcError::unavailable("the start-at-login setting cannot be changed on this system")
        })
    }

    fn pick_file(&self, title: Option<&str>, extensions: &[String]) -> Option<std::path::PathBuf> {
        let mut dialog = self.app.dialog().file();
        if let Some(title) = title {
            dialog = dialog.set_title(title);
        }
        let extensions: Vec<&str> = extensions.iter().map(String::as_str).collect();
        if !extensions.is_empty() {
            dialog = dialog.add_filter("Files", &extensions);
        }
        dialog.blocking_pick_file()?.into_path().ok()
    }

    fn launch(&self, program: &Path, args: &[String]) -> IpcResult<()> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                tracing::warn!(%error, program = %program.display(), "a program could not be started");
                IpcError::unavailable("the program could not be started")
            })?;
        // Wait for the child on its own thread, so it does not stay a zombie once it exits.
        let reaper = std::thread::Builder::new()
            .name("launch-reaper".to_owned())
            .spawn(move || {
                if let Err(error) = child.wait() {
                    tracing::warn!(%error, "waiting for a started program failed");
                }
            });
        if let Err(error) = reaper {
            tracing::warn!(%error, "no thread to wait for a started program");
        }
        Ok(())
    }

    fn set_content_protection(&self, enabled: bool) {
        for label in [MAIN_WINDOW, crate::guard::APPROVAL_WINDOW] {
            if let Some(window) = self.app.get_webview_window(label)
                && let Err(error) = window.set_content_protected(enabled)
            {
                tracing::warn!(%error, window = label, "content protection change failed");
            }
        }
    }
}
