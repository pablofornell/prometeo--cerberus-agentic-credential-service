//! The main window and the approval window.
//!
//! The approval window is small, always on top, and made on demand with the label `approval`. It
//! does not take the focus when it opens, so a person who types in another app does not hit an
//! approve key by accident (design brief: the window flashes the tray and asks for attention).

use tauri::{AppHandle, Manager, UserAttentionType, WebviewUrl, WebviewWindowBuilder, Wry};

use crate::guard::{APPROVAL_WINDOW, MAIN_WINDOW};

/// Width and height of the approval window.
const APPROVAL_SIZE: (f64, f64) = (440.0, 640.0);

/// Shows the approval window, making it when needed. It is not focused.
///
/// # Errors
/// A Tauri window error.
pub fn show_approval(app: &AppHandle<Wry>) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(APPROVAL_WINDOW) {
        window.show()?;
        window.request_user_attention(Some(UserAttentionType::Critical))?;
        return Ok(());
    }
    // The setting counts for a window made later too (AUD-15), not only for the ones that exist
    // when the person changes it.
    let protected = app
        .try_state::<crate::DesktopState>()
        .is_some_and(|state| state.prefs().content_protection);
    let window = WebviewWindowBuilder::new(
        app,
        APPROVAL_WINDOW,
        WebviewUrl::App("index.html#approval".into()),
    )
    .title("Cerberus approval")
    .inner_size(APPROVAL_SIZE.0, APPROVAL_SIZE.1)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    .always_on_top(true)
    .focused(false)
    .content_protected(protected)
    .center()
    .build()?;
    window.request_user_attention(Some(UserAttentionType::Critical))?;
    Ok(())
}

/// Closes the approval window if it exists.
pub fn close_approval(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window(APPROVAL_WINDOW)
        && let Err(error) = window.destroy()
    {
        tracing::warn!(%error, "could not close the approval window");
    }
}

/// Shows and focuses the main window.
pub fn show_main(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        for step in [window.show(), window.unminimize(), window.set_focus()] {
            if let Err(error) = step {
                tracing::warn!(%error, "could not show the main window");
            }
        }
    }
}
