//! The event pump: turns `CoreEvent`s into typed UI events, keeps the pending count, opens and
//! closes the approval window, updates the tray, and drops backend-held secrets at lock.
//!
//! It follows the vault service: a restore opens a new one, and the pump subscribes again.

use cerberus_core::CoreEvent;
use cerberus_types::VaultStateKind;
use tauri::{AppHandle, Wry};
use tauri_specta::Event;
use tokio::sync::broadcast::error::RecvError;

use crate::dto::{RequestStatus, VaultState};
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
    match event {
        CoreEvent::StateChanged(kind) => on_state(app, state, kind).await,
        CoreEvent::AccessRequestCreated(id) => {
            emit(app, &AccessRequestCreated { id: id.to_string() });
            recount(app, state).await;
        }
        CoreEvent::AccessRequestResolved { id, status } => {
            emit(
                app,
                &AccessRequestResolved {
                    id: id.to_string(),
                    status: RequestStatus::from(status),
                },
            );
            recount(app, state).await;
        }
        CoreEvent::AgentActivity {
            agent_id,
            event_type,
            item_id,
            at,
        } => emit(
            app,
            &AgentActivity {
                agent_id: agent_id.to_string(),
                event_type: event_type.to_owned(),
                item_id: item_id.map(|i| i.to_string()),
                at: at.to_string(),
            },
        ),
        CoreEvent::LeaseChanged(id) => emit(app, &LeaseChanged { id: id.to_string() }),
        CoreEvent::AutoLockTick { seconds_left } => emit(
            app,
            &AutolockTick {
                seconds_left: u32::try_from(seconds_left).unwrap_or(u32::MAX),
            },
        ),
        CoreEvent::MassReadAlert {
            agent_id,
            distinct_items,
        } => emit(
            app,
            &MassReadAlert {
                agent_id: agent_id.to_string(),
                distinct_items,
            },
        ),
        CoreEvent::HeaderMismatch => emit(app, &HeaderMismatch {}),
        CoreEvent::IntegrityAlert { table, row_id } => emit(
            app,
            &IntegrityAlert {
                table: table.to_owned(),
                row_id,
            },
        ),
    }
}
