//! Commands of remote mode (ADR-0034 point 7): the stored profiles, the bundle import, the mode
//! switch and the disconnect. They work in both modes; none of them reads or sends a secret to
//! the UI.

use cerberus_admin::bundle::MAX_BUNDLE_BYTES;
use cerberus_types::VaultStateKind;

use super::files;
use crate::dto::{BackendMode, RemoteOverview, RemoteProfileView};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::remote::{profile, remote_command_names};
use crate::state::DesktopState;

/// `remote_status`: the mode of this run, the stored profiles and the remote allowlist (the UI
/// reads it from here instead of keeping a copy).
pub async fn remote_status(state: &DesktopState, window: &str) -> IpcResult<RemoteOverview> {
    check(window, "remote_status")?;
    let prefs = state.prefs();
    let running = state.remote().map(|remote| remote.profile().id.clone());
    let profiles = prefs
        .remote
        .profiles
        .iter()
        .map(|p| profile::view(p, running.as_deref() == Some(p.id.as_str())))
        .collect();
    Ok(RemoteOverview {
        mode: if running.is_some() {
            BackendMode::Remote
        } else {
            BackendMode::Local
        },
        active: running,
        profiles,
        remote_commands: remote_command_names(),
    })
}

/// `remote_import_bundle`: reads an enrolment bundle that the person chose in the native dialog
/// (`file_pick_open`, AUD-11), checks it and stores the profile. Nothing secret comes back: the
/// view holds the URL, the pin and fingerprint to compare with `cerberusd status`, the operator
/// and the expiry. A profile of the same enrolment is replaced.
pub async fn remote_import_bundle(
    state: &DesktopState,
    window: &str,
    path: String,
) -> IpcResult<RemoteProfileView> {
    check(window, "remote_import_bundle")?;
    let file = files::picked_file(state, "path", &path, MAX_BUNDLE_BYTES)?;
    let imported = profile::import(&state.inner.paths, &file, state.now())?;
    let mut prefs = state.prefs();
    prefs.remote.profiles.retain(|p| p.id != imported.id);
    prefs.remote.profiles.push(imported.clone());
    state.set_prefs(prefs)?;
    let running = state
        .remote()
        .is_some_and(|remote| remote.profile().id == imported.id);
    Ok(profile::view(&imported, running))
}

/// `remote_activate`: chooses the backend of the next start, `None` for local mode. Returns
/// true when the app must restart to use it (the command restarts it, so the two backends never
/// run side by side, DEC-RM-9).
///
/// # Errors
/// `not_found` for an unknown profile; `unavailable` when its files are not usable; `conflict`
/// while a local vault is unlocked (lock it first).
pub async fn remote_activate(
    state: &DesktopState,
    window: &str,
    profile: Option<String>,
) -> IpcResult<bool> {
    check(window, "remote_activate")?;
    let mut prefs = state.prefs();
    if let Some(id) = &profile {
        let stored = prefs
            .remote
            .profile(id)
            .ok_or_else(|| IpcError::new("not_found", "no remote profile with this ID"))?;
        // A broken profile is refused now, not at the next start.
        profile::transport(&state.inner.paths, stored)?;
    }
    let running = state.remote().map(|remote| remote.profile().id.clone());
    if running == profile {
        if prefs.remote.active != profile {
            prefs.remote.active.clone_from(&profile);
            state.set_prefs(prefs)?;
        }
        return Ok(false);
    }
    if running.is_none()
        && let Ok(core) = state.core()
        && core.state() == VaultStateKind::Unlocked
    {
        return Err(IpcError::new(
            "conflict",
            "lock the local vault before you switch to a remote server",
        ));
    }
    if let Some(remote) = state.remote() {
        remote.close_session().await;
    }
    prefs.remote.active.clone_from(&profile);
    state.set_prefs(prefs)?;
    tracing::info!(
        profile = profile.as_deref().unwrap_or("local"),
        "backend switched; the app restarts"
    );
    Ok(true)
}

/// `remote_disconnect`: ends this desktop's admin session. The server vault stays as it is: its
/// agents keep working (DEC-RM-8).
///
/// # Errors
/// `unavailable` in local mode.
pub async fn remote_disconnect(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "remote_disconnect")?;
    let remote = state
        .remote()
        .ok_or_else(|| IpcError::unavailable("not connected to a remote server"))?;
    remote.close_session().await;
    state.clear_held();
    Ok(())
}

/// `remote_forget`: removes a stored profile and its files.
///
/// # Errors
/// `conflict` for the profile in use or chosen for the next start; `validation_failed` for a
/// bad ID.
pub async fn remote_forget(state: &DesktopState, window: &str, profile: String) -> IpcResult<()> {
    check(window, "remote_forget")?;
    let mut prefs = state.prefs();
    let running = state
        .remote()
        .is_some_and(|remote| remote.profile().id == profile);
    if running || prefs.remote.active.as_deref() == Some(profile.as_str()) {
        return Err(IpcError::new(
            "conflict",
            "this profile is in use; switch to another backend first",
        ));
    }
    profile::forget(&state.inner.paths, &profile)?;
    prefs.remote.profiles.retain(|p| p.id != profile);
    state.set_prefs(prefs)?;
    Ok(())
}
