//! The remote event pump (ADR-0034 point 7.6): reads `GET /admin/v1/events` while this desktop
//! holds a session and does what the local pump does with the core events: the same Tauri
//! events, the pending count (the server never sends it, DEC-RM-19 i), the approval window and
//! the tray.
//!
//! Two halves: [`drive`] knows no Tauri. It follows the session of the [`RemoteBackend`], reads
//! the stream (reconnecting after 1 s, doubling to 30 s), counts the pending requests and sends
//! the resulting UI events into a channel. A session that opens or ends is a
//! `VaultStateChanged` (`unlocked` / `sealed`), so the UI works as in local mode. The Tauri half
//! ([`spawn`]) emits them and runs the window and tray side effects.

use std::sync::Arc;
use std::time::Duration;

use cerberus_admin::dto::{AccessRequestView, VaultState};
use cerberus_admin::events::WireEvent;
use cerberus_types::VaultStateKind;
use tauri::{AppHandle, Wry};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::sync::watch;

use super::{EMPTY, Link, RemoteBackend};
use crate::events::PendingCountChanged;
use crate::state::DesktopState;

/// First wait before the stream is opened again.
const FIRST_RETRY: Duration = Duration::from_secs(1);
/// Longest wait before the stream is opened again.
const MAX_RETRY: Duration = Duration::from_secs(30);

/// Starts the pump of `backend` on the async runtime.
pub fn spawn(app: AppHandle<Wry>, state: DesktopState, backend: Arc<RemoteBackend>) {
    let (tx, mut rx) = unbounded_channel();
    drop(tauri::async_runtime::spawn(drive(Arc::clone(&backend), tx)));
    drop(tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            apply(&app, &state, &backend, event);
        }
    }));
}

/// The Tauri side of one event.
fn apply(app: &AppHandle<Wry>, state: &DesktopState, backend: &RemoteBackend, event: WireEvent) {
    let kind = if backend.has_session() {
        VaultStateKind::Unlocked
    } else {
        VaultStateKind::Sealed
    };
    match event {
        WireEvent::VaultStateChanged { state: shown } => {
            crate::pump::emit_wire(app, WireEvent::VaultStateChanged { state: shown });
            let shown = VaultStateKind::from(shown);
            if matches!(shown, VaultStateKind::Unlocked | VaultStateKind::Locking) {
                crate::tray::update(app, shown, state.pending_count());
            } else {
                // The session ended: drop what belongs to it, as a local lock does (I-16).
                state.clear_held();
                crate::windows::close_approval(app);
                crate::tray::update(app, shown, 0);
            }
        }
        WireEvent::PendingCountChanged { count } => {
            let changed = count != state.pending_count();
            state.set_pending_count(count);
            crate::tray::update(app, kind, count);
            if changed {
                crate::pump::emit(app, &PendingCountChanged { count });
            }
            if count == 0 {
                crate::windows::close_approval(app);
            } else if let Err(error) = crate::windows::show_approval(app) {
                tracing::warn!(%error, "could not show the approval window");
            }
        }
        event => crate::pump::emit_wire(app, event),
    }
}

/// Counts the requests that wait (`request_list_pending` does not count as activity on the
/// server, so the background count never keeps a session alive).
async fn recount(backend: &RemoteBackend, out: &UnboundedSender<WireEvent>) -> bool {
    match backend
        .forward::<Vec<AccessRequestView>, _>("request_list_pending", &EMPTY)
        .await
    {
        Ok(list) => {
            let count = u32::try_from(list.len()).unwrap_or(u32::MAX);
            out.send(WireEvent::PendingCountChanged { count }).is_ok()
        }
        Err(error) => {
            tracing::info!(code = %error.code, "could not count the pending requests");
            !out.is_closed()
        }
    }
}

/// Waits `wait`, or less when the session changes. False when the backend is gone.
async fn pause(link: &mut watch::Receiver<Link>, session: u64, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    if link.borrow_and_update().session != Some(session) {
        return true;
    }
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return true,
            changed = link.changed() => {
                if changed.is_err() {
                    return false;
                }
                if link.borrow_and_update().session != Some(session) {
                    return true;
                }
            }
        }
    }
}

/// One event of the stream. False when the receiver is gone.
async fn on_wire(
    backend: &RemoteBackend,
    out: &UnboundedSender<WireEvent>,
    serial: u64,
    name: &str,
    data: &[u8],
) -> bool {
    let Ok(event) = serde_json::from_slice::<WireEvent>(data) else {
        tracing::info!(
            event = name,
            "an event of the server does not parse; skipped"
        );
        return true;
    };
    if event.name() != name {
        tracing::info!(
            event = name,
            "an event of the server has another name than its data"
        );
        return true;
    }
    match event {
        WireEvent::VaultStateChanged { state } => {
            backend.note_server_state(state);
            match state {
                // A lock ends every admin session on the server (DEC-RM-19 a).
                VaultState::Sealed | VaultState::NoVault => {
                    backend.drop_session(Some(serial));
                    true
                }
                VaultState::Locking => out.send(WireEvent::VaultStateChanged { state }).is_ok(),
                VaultState::Unlocked => true,
            }
        }
        event @ (WireEvent::AccessRequestCreated { .. }
        | WireEvent::AccessRequestResolved { .. }) => {
            out.send(event).is_ok() && recount(backend, out).await
        }
        // The server never sends it; the count is ours.
        WireEvent::PendingCountChanged { .. } => true,
        event => out.send(event).is_ok(),
    }
}

/// The pump without Tauri: follows the session of `backend` and sends the UI events to `out`.
/// It ends when it finds `out` closed.
pub async fn drive(backend: Arc<RemoteBackend>, out: UnboundedSender<WireEvent>) {
    let mut link = backend.subscribe();
    let mut shown: Option<Option<u64>> = None;
    let mut retry = FIRST_RETRY;
    loop {
        let session = link.borrow_and_update().session;
        if shown != Some(session) {
            shown = Some(session);
            let state = if session.is_some() {
                VaultState::Unlocked
            } else {
                VaultState::Sealed
            };
            if out.send(WireEvent::VaultStateChanged { state }).is_err() {
                return;
            }
            let counted = if session.is_some() {
                recount(&backend, &out).await
            } else {
                out.send(WireEvent::PendingCountChanged { count: 0 })
                    .is_ok()
            };
            if !counted {
                return;
            }
            continue;
        }
        let Some(serial) = session else {
            if link.changed().await.is_err() {
                return;
            }
            continue;
        };
        match backend.events().await {
            Ok((serial, mut stream)) => {
                retry = FIRST_RETRY;
                // Requests may have come and gone while no stream was open.
                if !recount(&backend, &out).await {
                    return;
                }
                loop {
                    tokio::select! {
                        next = stream.next() => match next {
                            Some(Ok((name, data))) => {
                                if !on_wire(&backend, &out, serial, &name, &data).await {
                                    return;
                                }
                            }
                            Some(Err(error)) => {
                                tracing::info!(%error, "the server event stream broke");
                                break;
                            }
                            None => break,
                        },
                        changed = link.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            if link.borrow().session != Some(serial) {
                                break;
                            }
                        }
                    }
                }
                // A stream that ends often means the session ended: the next open finds out.
                if !pause(&mut link, serial, FIRST_RETRY).await {
                    return;
                }
            }
            Err(error) => {
                tracing::info!(code = %error.code, "the server event stream did not open");
                if !pause(&mut link, serial, retry).await {
                    return;
                }
                retry = (retry * 2).min(MAX_RETRY);
            }
        }
    }
}
