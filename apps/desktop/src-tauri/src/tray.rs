//! The tray icon: lock state, the number of requests that wait, Lock, and Lock and revoke all.
//!
//! The tray shows a count only, never a title or an agent name (threat I-19).

use cerberus_types::VaultStateKind;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};

use crate::guard::MAIN_WINDOW;
use crate::ops;
use crate::state::DesktopState;

const TRAY_ID: &str = "cerberus";

/// The menu items whose text changes.
pub struct TrayItems {
    status: MenuItem<Wry>,
    pending: MenuItem<Wry>,
    lock: MenuItem<Wry>,
    panic: MenuItem<Wry>,
}

fn status_text(state: VaultStateKind) -> &'static str {
    match state {
        VaultStateKind::NoVault => "No vault yet",
        VaultStateKind::Sealed | VaultStateKind::Locking => "Vault locked",
        VaultStateKind::Unlocked => "Vault unlocked",
    }
}

fn pending_text(count: u32) -> String {
    match count {
        0 => "Nothing waits for approval".to_owned(),
        1 => "1 request waits for approval".to_owned(),
        n => format!("{n} requests wait for approval"),
    }
}

/// Makes the tray icon. Returns false when the desktop has no tray (the app then quits when the
/// main window closes).
pub fn create(app: &AppHandle<Wry>) -> bool {
    match build(app) {
        Ok(items) => {
            app.manage(items);
            true
        }
        Err(error) => {
            tracing::warn!(%error, "no tray icon on this desktop");
            false
        }
    }
}

fn build(app: &AppHandle<Wry>) -> tauri::Result<TrayItems> {
    let status = MenuItem::with_id(
        app,
        "status",
        status_text(VaultStateKind::Sealed),
        false,
        None::<&str>,
    )?;
    let pending = MenuItem::with_id(app, "pending", pending_text(0), false, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Open Cerberus", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock", false, None::<&str>)?;
    let panic = MenuItem::with_id(app, "panic", "Lock and revoke all", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let separator_two = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &pending,
            &separator,
            &show,
            &lock,
            &panic,
            &separator_two,
            &quit,
        ],
    )?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("Cerberus")
        .menu(&menu)
        .on_menu_event(on_menu_event);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(TrayItems {
        status,
        pending,
        lock,
        panic,
    })
}

fn on_menu_event(app: &AppHandle<Wry>, event: MenuEvent) {
    let app = app.clone();
    match event.id().as_ref() {
        "show" => crate::windows::show_main(&app),
        "quit" => app.exit(0),
        "lock" => run_command(&app, Action::Lock),
        "panic" => run_command(&app, Action::Panic),
        _ => {}
    }
}

enum Action {
    Lock,
    Panic,
}

fn run_command(app: &AppHandle<Wry>, action: Action) {
    let state = app.state::<DesktopState>().inner().clone();
    drop(tauri::async_runtime::spawn(async move {
        let result = match action {
            Action::Lock => ops::vault_lock(&state, MAIN_WINDOW).await,
            Action::Panic => ops::vault_panic(&state, MAIN_WINDOW).await,
        };
        if let Err(error) = result {
            tracing::warn!(code = %error.code, "tray action failed");
        }
    }));
}

/// Updates the menu text and the tooltip for the vault state and the pending count.
pub fn update(app: &AppHandle<Wry>, state: VaultStateKind, pending: u32) {
    let Some(items) = app.try_state::<TrayItems>() else {
        return;
    };
    let unlocked = state == VaultStateKind::Unlocked;
    let steps = [
        items.status.set_text(status_text(state)),
        items.pending.set_text(pending_text(pending)),
        items.lock.set_enabled(unlocked),
        items.panic.set_enabled(unlocked),
    ];
    for step in steps {
        if let Err(error) = step {
            tracing::warn!(%error, "could not update the tray menu");
        }
    }
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let tooltip = if pending > 0 {
            format!("Cerberus ({pending} waiting)")
        } else {
            "Cerberus".to_owned()
        };
        if let Err(error) = tray.set_tooltip(Some(tooltip)) {
            tracing::warn!(%error, "could not update the tray tooltip");
        }
    }
}
