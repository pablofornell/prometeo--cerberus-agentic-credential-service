//! Commands of remote mode (ADR-0034 point 7): the stored profiles, the bundle import, the mode
//! switch and the disconnect. They work in both modes; none of them reads or sends a secret to
//! the UI.

use cerberus_admin::bundle::MAX_BUNDLE_BYTES;
use cerberus_client::WireSecret;
use cerberus_client::setup::{SetupRequest, health, setup};
use cerberus_types::VaultStateKind;
use zeroize::Zeroizing;

use super::files;
use crate::dto::{BackendMode, RemoteOverview, RemoteProfileView, Secret};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::prefs::RemoteProfile;
use crate::remote::setup::{self as server_setup, RemoteSetupCheckView, RemoteSetupView};
use crate::remote::{profile, remote_command_names};
use crate::state::{DesktopState, SetupHold};

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
/// (`file_pick_open`, AUD-11), checks it and **stages** it. Nothing secret comes back: the view
/// holds the URL, the pin and fingerprint to compare with `cerberusd status`, the operator and the
/// expiry. A stored profile of the same enrolment does not change until the person connects
/// (`remote_activate`); `remote_discard_import` drops the stage (DEC-RM-26).
pub async fn remote_import_bundle(
    state: &DesktopState,
    window: &str,
    path: String,
) -> IpcResult<RemoteProfileView> {
    check(window, "remote_import_bundle")?;
    let file = files::picked_file(state, "path", &path, MAX_BUNDLE_BYTES)?;
    state.set_pending_import(None);
    let staged = profile::stage(&state.inner.paths, &file, state.now())?;
    state.set_pending_import(Some(staged.clone()));
    Ok(profile::view(&staged, false))
}

/// `remote_setup_check`: asks the server of a setup code what it says (`GET /v1/health` over the
/// channel that the code pins), before the person types a passphrase. `url` replaces the address
/// of the code (the end of an SSH tunnel, for example). Nothing is stored and nothing secret
/// comes back.
///
/// # Errors
/// `validation_failed` (the code or the address is bad), `setup_wrong_server` (the pin of the
/// code does not match: another server, or it restarted and has a new code), `remote_unreachable`,
/// `conflict` (the server has a vault), `remote_protocol_mismatch`.
pub async fn remote_setup_check(
    _state: &DesktopState,
    window: &str,
    code: Secret,
    url: Option<String>,
) -> IpcResult<RemoteSetupCheckView> {
    check(window, "remote_setup_check")?;
    let code = server_setup::parse_code(code, url.as_deref())?;
    let answer = health(&code)
        .await
        .map_err(|error| server_setup::setup_error(&error, false))?;
    server_setup::check_view(&code.url, answer)
}

/// `remote_setup`: makes the vault on the server of a setup code (`POST /v1/setup`; the server
/// measures its own key-derivation cost, so this can take a minute), then stores the admin bundle
/// that the server answers as a remote profile, from memory, without a file. The profile is not
/// the active one: the UI shows the recovery key, then calls `remote_activate`.
///
/// The server shows the recovery key and the bundle only once, so the moment the vault exists
/// both are held by the backend (`SetupHold`), before anything else can fail. The key always
/// comes back. If this desktop cannot keep the profile (a full disk, a folder it cannot write),
/// `profile` is `None` and `store_error` says why; `remote_setup_save` tries again from the held
/// bundle. The hold ends with `remote_setup_finish`. A staged import of the person is not touched.
///
/// # Errors
/// The errors of [`remote_setup_check`], and: `unauthenticated` (wrong token), `too_many_failures`
/// (this address must wait: `retry_after_seconds` has the time, and the code stays valid), `conflict` (a setup already ran), `validation_failed` with the
/// fields `passphrase`, `owner_label`, `device_label`, `url`, and `setup_unconfirmed` (the answer
/// did not arrive or cannot be read: the vault may exist, check `cerberusd status`). Nothing else
/// fails after the vault exists: those errors are in `store_error`.
pub async fn remote_setup(
    state: &DesktopState,
    window: &str,
    code: Secret,
    owner_label: String,
    passphrase: Secret,
    device_label: Option<String>,
    url: Option<String>,
) -> IpcResult<RemoteSetupView> {
    check(window, "remote_setup")?;
    let chosen = server_setup::chosen_url(url.as_deref())?;
    let code = server_setup::parse_code(code, chosen.as_deref())?;
    let mut request = SetupRequest::new(
        owner_label.trim(),
        WireSecret::new(passphrase.into_core().expose_secret().to_owned()),
    );
    request.device_label = device_label
        .map(|label| label.trim().to_owned())
        .filter(|label| !label.is_empty());
    request.url = chosen;
    let outcome = setup(&code, &request)
        .await
        .map_err(|error| server_setup::setup_error(&error, true))?;
    // The vault exists. Nothing below may lose the key or the bundle.
    let bundle = outcome
        .bundle
        .to_json()
        .unwrap_or_else(|_| Zeroizing::new(Vec::new()));
    let recovery_key = outcome.recovery_key.expose().to_owned();
    state.set_setup_hold(Some(SetupHold {
        recovery_key: Zeroizing::new(recovery_key.clone()),
        bundle: bundle.clone(),
    }));
    let (profile, store_error) = match store_profile(state, &bundle) {
        Ok(profile) => (Some(profile::view(&profile, false)), None),
        Err(error) => {
            tracing::warn!(code = %error.code, "the server was set up, but its profile is not stored");
            (None, Some(error))
        }
    };
    Ok(RemoteSetupView {
        profile,
        store_error,
        recovery_key: Secret::new(recovery_key),
    })
}

/// Checks the bundle JSON of a setup, stores it as a profile (not the active one) and saves the
/// preferences. Running it again for the same bundle replaces the profile with the same files.
fn store_profile(state: &DesktopState, json: &[u8]) -> IpcResult<RemoteProfile> {
    let bundle = server_setup::bundle_from_json(json, state.now())?;
    let stored = profile::store_bundle(&state.inner.paths, &bundle)?;
    let mut prefs = state.prefs();
    prefs.remote.profiles.retain(|p| p.id != stored.id);
    prefs.remote.profiles.push(stored.clone());
    state.set_prefs(prefs)?;
    tracing::info!(profile = %stored.id, "server set up; its profile is stored");
    Ok(stored)
}

/// `remote_setup_save`: tries again to store the profile of the server that `remote_setup` set up,
/// from the bundle that the backend holds ("Save the connection" after a `store_error`).
///
/// # Errors
/// `not_found` when no setup result is held; the errors that `store_error` has.
pub async fn remote_setup_save(state: &DesktopState, window: &str) -> IpcResult<RemoteProfileView> {
    check(window, "remote_setup_save")?;
    let bundle = state
        .setup_bundle()
        .ok_or_else(|| IpcError::new("not_found", "there is no server setup to save"))?;
    let stored = store_profile(state, &bundle)?;
    Ok(profile::view(&stored, false))
}

/// `remote_setup_copy_key`: copies the recovery key of the server that `remote_setup` set up. It
/// has its own value and lifetime: it never gives a key of the local vault, and a local create or
/// rotate never gives this one.
///
/// # Errors
/// `not_found` when no setup result is held.
pub async fn remote_setup_copy_key(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "remote_setup_copy_key")?;
    let key = state
        .setup_recovery_key()
        .ok_or_else(|| IpcError::new("not_found", "there is no such value to copy"))?;
    state.copy_and_clear(&key)
}

/// `remote_setup_finish`: the person is done with the recovery step: the backend drops the held
/// recovery key and bundle. Nothing held is not an error. A stored profile stays.
pub async fn remote_setup_finish(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "remote_setup_finish")?;
    state.set_setup_hold(None);
    Ok(())
}

/// `remote_discard_import`: drops a staged import (the person cancelled after the import). A
/// stored profile of the same enrolment stays as it was. Nothing staged is not an error.
pub async fn remote_discard_import(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "remote_discard_import")?;
    state.set_pending_import(None);
    profile::discard(&state.inner.paths)
}

/// `remote_activate`: chooses the backend of the next start, `None` for local mode. A staged
/// import of `profile` is stored first: connecting is the person's confirmation of its pin.
/// Returns true when the app must restart to use it (the command restarts it, so the two backends
/// never run side by side, DEC-RM-9).
///
/// An unlocked local vault refuses the switch (`conflict`), unless `lock_local` is set ("Lock and
/// connect"): then it is locked here, after every check passed, so a refused switch leaves it
/// unlocked and the screen that asked still shows the error (DEC-RM-26).
///
/// # Errors
/// `not_found` for an unknown profile; `unavailable` when its files are not usable; `conflict`
/// while a local vault is unlocked and `lock_local` is false.
pub async fn remote_activate(
    state: &DesktopState,
    window: &str,
    profile: Option<String>,
    lock_local: bool,
) -> IpcResult<bool> {
    check(window, "remote_activate")?;
    let mut prefs = state.prefs();
    let staged = state
        .pending_import()
        .filter(|p| profile.as_deref() == Some(p.id.as_str()));
    if let Some(id) = &profile {
        match &staged {
            Some(p) => {
                profile::transport_in(&profile::pending_dir(&state.inner.paths, id)?, p)?;
            }
            None => {
                let stored = prefs
                    .remote
                    .profile(id)
                    .ok_or_else(|| IpcError::new("not_found", "no remote profile with this ID"))?;
                // A broken profile is refused now, not at the next start.
                profile::transport(&state.inner.paths, stored)?;
            }
        }
    }
    let running = state.remote().map(|remote| remote.profile().id.clone());
    let unlocked_local = running.is_none()
        && state
            .core()
            .is_ok_and(|core| core.state() == VaultStateKind::Unlocked);
    if running != profile && unlocked_local && !lock_local {
        return Err(IpcError::new(
            "conflict",
            "lock the local vault before you switch to a remote server",
        ));
    }
    if let Some(staged) = staged {
        profile::commit(&state.inner.paths, &staged.id)?;
        state.set_pending_import(None);
        prefs.remote.profiles.retain(|p| p.id != staged.id);
        prefs.remote.profiles.push(staged);
        state.set_prefs(prefs.clone())?;
    }
    if running == profile {
        if prefs.remote.active != profile {
            prefs.remote.active.clone_from(&profile);
            state.set_prefs(prefs)?;
        }
        return Ok(false);
    }
    if unlocked_local {
        cerberus_admin::handlers::vault_lock(&state.core()?).await?;
        state.clear_held();
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
