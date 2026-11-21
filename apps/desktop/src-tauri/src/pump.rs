//! The event pump: turns `CoreEvent`s into typed UI events (through the wire events of
//! `cerberus-admin`, so a remote server maps them the same way), keeps the pending count, opens
//! and closes the approval window, updates the tray, and drops backend-held secrets at lock.
//!
//! It follows the vault service: a restore opens a new one, and the pump subscribes again.

use cerberus_admin::events::{WireEvent, from_core};
use cerberus_core::CoreEvent;
use cerberus_types::VaultStateKind;
use tauri::{AppHandle, Wry};
use tauri_specta::Event;
use tokio::sync::broadcast::error::RecvError;

use crate::dto::VaultState;
use crate::events::{
    AccessRequestCreated, AccessRequestResolved, AgentActivity, AutolockTick, HeaderMismatch,
    IntegrityAlert, LeaseChanged, MassReadAlert, PendingCountChanged, VaultStateChanged,
};
use crate::state::DesktopState;

/// Starts the pump on the async runtime.
pub fn spawn(app: AppHandle<Wry>, state: DesktopState) {
    drop(tauri::async_runtime::spawn(run(app, state)));
}

fn emit<E: Event + serde::Serialize + Clone>(app: &AppHandle<Wry>, event: &E) {
    if let Err(error) = event.emit(app) {
        tracing::warn!(%error, "could not emit a UI event");
    }
}

async fn run(app: AppHandle<Wry>, state: DesktopState) {
    let mut generations = state.generations();
    loop {
        if let Ok(core) = state.core() {
            let mut events = core.subscribe();
            on_state(&app, &state, core.state()).await;
            loop {
                tokio::select! {
                    received = events.recv() => match received {
                        Ok(event) => on_event(&app, &state, event).await,
                        Err(RecvError::Lagged(_)) => on_lag(&app, &state, &core).await,
                        Err(RecvError::Closed) => break,
                    },
                    changed = generations.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        break;
                    }
                }
            }
        } else if generations.changed().await.is_err() {
            return;
        }
    }
}

async fn on_state(app: &AppHandle<Wry>, state: &DesktopState, kind: VaultStateKind) {
    emit(
        app,
        &VaultStateChanged {
            state: VaultState::from(kind),
        },
    );
    match kind {
        VaultStateKind::Unlocked => {
            state.after_unlock().await;
            recount(app, state).await;
        }
        VaultStateKind::Sealed | VaultStateKind::NoVault => {
            state.clear_held();
            state.set_pending_count(0);
            crate::windows::close_approval(app);
            crate::tray::update(app, kind, 0);
            emit(app, &PendingCountChanged { count: 0 });
        }
        VaultStateKind::Locking => crate::tray::update(app, kind, state.pending_count()),
    }
}

/// Events were lost (the channel holds 256). A lock may be among them, so the held values are
/// dropped when the vault is not unlocked now; a new unlock makes them stale by their tag.
async fn on_lag(app: &AppHandle<Wry>, state: &DesktopState, core: &cerberus_core::VaultService) {
    if core.state() != VaultStateKind::Unlocked {
        state.clear_held();
    }
    recount(app, state).await;
}

/// Counts the pending requests, tells the UI and the tray, and opens or closes the approval window.
async fn recount(app: &AppHandle<Wry>, state: &DesktopState) {
    let Ok((core, ctx)) = state.session().await else {
        return;
    };
    let count = match core.pending_requests(&ctx).await {
        Ok(list) => u32::try_from(list.len()).unwrap_or(u32::MAX),
        Err(error) => {
            tracing::warn!(%error, "could not count pending requests");
            return;
        }
    };
    let changed = count != state.pending_count();
    state.set_pending_count(count);
    crate::tray::update(app, core.state(), count);
    if changed {
        emit(app, &PendingCountChanged { count });
    }
    if count == 0 {
        crate::windows::close_approval(app);
    } else if let Err(error) = crate::windows::show_approval(app) {
        tracing::warn!(%error, "could not show the approval window");
    }
}

async fn on_event(app: &AppHandle<Wry>, state: &DesktopState, event: CoreEvent) {
    match from_core(event) {
        WireEvent::VaultStateChanged { state: kind } => {
            on_state(app, state, VaultStateKind::from(kind)).await;
        }
        WireEvent::AccessRequestCreated { id } => {
            emit(app, &AccessRequestCreated { id });
            recount(app, state).await;
        }
        WireEvent::AccessRequestResolved { id, status } => {
            emit(app, &AccessRequestResolved { id, status });
            recount(app, state).await;
        }
        WireEvent::AgentActivity {
            agent_id,
            event_type,
            item_id,
            at,
        } => emit(
            app,
            &AgentActivity {
                agent_id,
                event_type,
                item_id,
                at,
            },
        ),
        WireEvent::LeaseChanged { id } => emit(app, &LeaseChanged { id }),
        WireEvent::AutolockTick { seconds_left } => emit(app, &AutolockTick { seconds_left }),
        WireEvent::MassReadAlert {
            agent_id,
            distinct_items,
        } => emit(
            app,
            &MassReadAlert {
                agent_id,
                distinct_items,
            },
        ),
        WireEvent::HeaderMismatch => emit(app, &HeaderMismatch {}),
        WireEvent::IntegrityAlert { table, row_id } => {
            emit(app, &IntegrityAlert { table, row_id });
        }
        // The core has no such event (`from_core` never makes it); the pending count is
        // `recount`'s work.
        WireEvent::PendingCountChanged { count } => emit(app, &PendingCountChanged { count }),
    }
}
