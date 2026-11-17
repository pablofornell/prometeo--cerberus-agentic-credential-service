//! Cerberus desktop shell (Tauri v2). One process holds the vault, the HTTPS agent API and the
//! admin UI (D1, ADR-0001). Admin actions reach the vault only through typed IPC (ADR-0003): the
//! commands are in [`commands`], the logic behind them in [`ops`], and `bindings.ts` is generated
//! from them by `tauri-specta`.

pub mod commands;
pub mod dto;
pub mod error;
pub mod events;
pub mod guard;
pub mod logging;
mod mcp;
pub mod ops;
pub mod os_hooks;
mod prefs;
mod pump;
mod server;
pub mod shell;
pub mod state;
mod tray;
mod windows;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{Manager, RunEvent, WindowEvent, Wry};
use tauri_plugin_autostart::MacosLauncher;
use tauri_specta::{Builder, ErrorHandlingMode, collect_commands, collect_events};

pub use prefs::{AppPaths, Prefs};
pub use state::{DesktopState, Shell, StateOptions};

/// Where `bindings.ts` is written by a debug run and compared by the test.
pub const BINDINGS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../ui/src/bindings.ts");

/// Longest the quit sequence waits for the lock and the server to stop.
const QUIT_WAIT: Duration = Duration::from_secs(10);

/// True once a quit started, so the second exit request passes.
static QUITTING: AtomicBool = AtomicBool::new(false);

/// Whether the tray exists. Closing the main window hides it only when it does.
struct TrayAvailable(bool);

/// The typed IPC: every command, every event, and how the bindings are written.
///
/// Errors come back as `{ status: "error", error: IpcError }` instead of a rejected promise, and
/// 64-bit counters are exported as `number` (they are row counts and sequence numbers, far below 2^53).
#[must_use]
pub fn ipc_builder() -> Builder<Wry> {
    Builder::<Wry>::new()
        .commands(collect_commands![
            commands::vault_status,
            commands::vault_list_operators,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_unlock_recovery,
            commands::vault_recover_stranded,
            commands::vault_lock,
            commands::vault_panic,
            commands::kdf_benchmark,
            commands::passphrase_strength,
            commands::passphrase_generate,
            commands::phrase_change,
            commands::recovery_rotate,
            commands::operator_add,
            commands::operator_remove,
            commands::operator_set_role,
            commands::workspace_list,
            commands::workspace_put,
            commands::workspace_delete,
            commands::item_list,
            commands::item_get,
            commands::item_create,
            commands::item_update,
            commands::item_delete,
            commands::item_reveal,
            commands::item_versions,
            commands::item_restore_version,
            commands::item_totp_preview,
            commands::clipboard_copy_secret,
            commands::password_generate,
            commands::ssh_key_generate,
            commands::ssh_key_import,
            commands::agent_list,
            commands::agent_create,
            commands::agent_update,
            commands::agent_set_status,
            commands::agent_key_create,
            commands::agent_key_rotate,
            commands::agent_key_revoke,
            commands::agent_issue_client_cert,
            commands::agent_snippets,
            commands::grant_list,
            commands::grant_put,
            commands::grant_delete,
            commands::policy_simulate,
            commands::request_list_pending,
            commands::request_approve,
            commands::request_deny,
            commands::lease_list,
            commands::lease_revoke,
            commands::lease_revoke_all,
            commands::audit_query,
            commands::audit_verify,
            commands::audit_export,
            commands::settings_get,
            commands::settings_set,
            commands::network_status,
            commands::network_set_bind,
            commands::tls_export_ca,
            commands::tls_load_custom,
            commands::tls_use_local_ca,
            commands::backup_create,
            commands::backup_restore,
            commands::csv_preview,
            commands::csv_import,
            commands::csv_export,
            commands::ui_activity,
            commands::clipboard_copy_once,
            commands::file_pick_open
        ])
        .events(collect_events![
            events::VaultStateChanged,
            events::AccessRequestCreated,
            events::AccessRequestResolved,
            events::AgentActivity,
            events::LeaseChanged,
            events::AutolockTick,
            events::MassReadAlert,
            events::HeaderMismatch,
            events::IntegrityAlert,
            events::PendingCountChanged,
        ])
        .error_handling(ErrorHandlingMode::Result)
        .dangerously_cast_bigints_to_number()
}

/// Writes the TypeScript bindings to `path`.
///
/// # Errors
/// An export error (for example the file cannot be written).
pub fn export_bindings(path: &Path) -> Result<(), specta_typescript::Error> {
    ipc_builder().export(specta_typescript::Typescript::default(), path)
}

/// The panic hook: wipes the keys first (ADR-0026), then runs the previous hook.
fn install_panic_hook(state: &DesktopState) {
    let state = state.clone();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        state.emergency_wipe();
        previous(info);
    }));
}

fn setup(
    app: &mut tauri::App<Wry>,
    builder: &Builder<Wry>,
) -> Result<(), Box<dyn std::error::Error>> {
    builder.mount_events(app);
    let data_dir = app.path().app_data_dir()?;
    let shell = Arc::new(shell::TauriShell::new(app.handle().clone()));
    let state = tauri::async_runtime::block_on(DesktopState::open(
        AppPaths::new(data_dir),
        shell,
        StateOptions::default(),
    ))?;
    install_panic_hook(&state);
    let watcher = state.clone();
    let is_locked: os_hooks::IsLocked = Arc::new(move || {
        watcher.core().map_or(true, |core| {
            core.state() != cerberus_types::VaultStateKind::Unlocked
        })
    });
    if !state.attach_os_events(os_hooks::platform_source(is_locked))? {
        tracing::warn!("no OS sleep or screen-lock hook; the idle lock still applies");
    }
    app.manage(state.clone());
    app.manage(TrayAvailable(tray::create(app.handle())));
    if state.prefs().content_protection {
        use state::Shell as _;
        shell::TauriShell::new(app.handle().clone()).set_content_protection(true);
    }
    pump::spawn(app.handle().clone(), state);
    Ok(())
}

fn on_window_event(window: &tauri::Window<Wry>, event: &WindowEvent) {
    if window.label() != guard::MAIN_WINDOW {
        return;
    }
    // A file dropped on the window comes from the OS, so the backend may read it like a file
    // from the dialog (AUD-11). The webview cannot fake this event.
    if let WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event
        && let Some(state) = window.app_handle().try_state::<DesktopState>()
    {
        state.note_dropped(paths);
    }
    if let WindowEvent::CloseRequested { api, .. } = event {
        let has_tray = window
            .app_handle()
            .try_state::<TrayAvailable>()
            .is_some_and(|tray| tray.0);
        if has_tray && !QUITTING.load(Ordering::SeqCst) {
            api.prevent_close();
            if let Err(error) = window.hide() {
                tracing::warn!(%error, "could not hide the main window");
            }
        }
    }
}

/// Quit: lock first, stop the server, then exit (ADR-0026). The wait is bounded.
fn on_run_event(app: &tauri::AppHandle<Wry>, event: RunEvent) {
    let RunEvent::ExitRequested { api, code, .. } = event else {
        return;
    };
    if QUITTING.swap(true, Ordering::SeqCst) {
        return;
    }
    api.prevent_exit();
    let code = code.unwrap_or(0);
    let app = app.clone();
    drop(tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<DesktopState>() {
            let state = state.inner().clone();
            if tokio::time::timeout(QUIT_WAIT, state.shutdown())
                .await
                .is_err()
            {
                tracing::warn!("the quit sequence took too long; exiting");
            }
        }
        app.exit(code);
    }));
}

/// Runs the desktop app.
pub fn run() {
    logging::init();
    let report = cerberus_crypto::memlock::harden_process();
    tracing::info!(?report, "process hardening applied");
    let builder = ipc_builder();
    #[cfg(debug_assertions)]
    if let Err(error) = export_bindings(Path::new(BINDINGS_PATH)) {
        tracing::warn!(%error, "could not write bindings.ts");
    }
    let invoke = builder.invoke_handler();
    let app = tauri::Builder::<Wry>::default()
        // The single-instance plugin must be the first one.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            windows::show_main(app);
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .invoke_handler(invoke)
        .setup(move |app| setup(app, &builder))
        .on_window_event(on_window_event)
        .build(tauri::generate_context!());
    match app {
        Ok(app) => app.run(on_run_event),
        Err(error) => {
            eprintln!("cerberus-desktop failed to start: {error}");
            std::process::exit(1);
        }
    }
}
