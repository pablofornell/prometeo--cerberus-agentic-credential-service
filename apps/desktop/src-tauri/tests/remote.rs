//! Remote mode of the desktop (ADR-0034 point 7, plan step 8) against a real `cerberusd` with the
//! admin API: bundle import and the mode switch, the proxy of the allowlist, the local refusal of
//! every other command, sessions that end on the server, the event pump, quit, and a log that
//! never holds the phrase, the session token or a secret. Own test binary: the log capture is the
//! global subscriber of the process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerberus_admin::events::WireEvent;
use cerberus_core::KeyCustody;
use cerberus_desktop::dto::{
    BackendMode, ItemDetailView, ItemSummaryView, OperatorPublic, PayloadView, RevealedSecretView,
    Secret, VaultState,
};
use cerberus_desktop::error::IpcError;
use cerberus_desktop::remote::{self, RemoteBackend};
use cerberus_desktop::{AppPaths, DesktopState, Prefs, StateOptions, ops};
use common::{Daemon, FakeShell, MAIN, PASSWORD, PHRASE, remote_desktop, web_login_input};
use serde_json::json;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, IpcError>) -> String {
    result.expect_err("an error").code
}

/// The next UI event of the pump, within a few seconds.
async fn next_event(events: &mut UnboundedReceiver<WireEvent>) -> WireEvent {
    tokio::time::timeout(Duration::from_secs(10), events.recv())
        .await
        .expect("an event in time")
        .expect("the pump runs")
}

/// Reads events until one matches, and returns it.
async fn wait_for(
    events: &mut UnboundedReceiver<WireEvent>,
    wanted: impl Fn(&WireEvent) -> bool,
) -> WireEvent {
    loop {
        let event = next_event(events).await;
        if wanted(&event) {
            return event;
        }
    }
}

fn is_state(event: &WireEvent, state: VaultState) -> bool {
    matches!(event, WireEvent::VaultStateChanged { state: s } if *s == state)
}

fn is_count(event: &WireEvent, count: u32) -> bool {
    matches!(event, WireEvent::PendingCountChanged { count: c } if *c == count)
}

/// Import and switch, in local mode: the bundle comes through the native dialog only, the view
/// holds what the person compares with `cerberusd status`, the switch is refused while the local
/// vault is unlocked, and the active profile cannot be forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bundle_import_and_the_mode_switch_in_local_mode() {
    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().to_path_buf());
    Prefs {
        port: 0,
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(FakeShell::default());
    let state = DesktopState::open(paths.clone(), shell.clone(), StateOptions::default())
        .await
        .expect("open");

    // A path the dialog did not return is refused.
    let text = file.to_str().expect("utf-8").to_owned();
    assert_eq!(
        code(ops::remote_import_bundle(&state, MAIN, text.clone()).await),
        "validation_failed"
    );
    *shell.pick.lock().unwrap() = Some(file.clone());
    let picked = ops::file_pick_open(&state, MAIN, None, vec!["cerberus-admin".to_owned()])
        .await
        .expect("pick")
        .expect("a path");
    let view = ops::remote_import_bundle(&state, MAIN, picked.clone())
        .await
        .expect("import");
    let fingerprints = cerberusd::status::ca_fingerprints(&daemon.config).expect("status");
    assert_eq!(view.id, bundle.id.to_string());
    assert_eq!(view.url, format!("https://localhost:{}", daemon.port));
    assert_eq!(view.ca_pin, fingerprints.pin);
    assert_eq!(view.ca_pin, bundle.ca_pin);
    assert_eq!(view.ca_sha256, bundle.ca_sha256_hex().expect("sha"));
    assert_eq!(view.operator_id, bundle.operator_id.to_string());
    assert!(!view.active);
    // Staged: the key waits privately in the stage, and nothing is a profile yet.
    let key = dir
        .path()
        .join("remote")
        .join("pending")
        .join(&view.id)
        .join(remote::profile::KEY_FILE);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&key).expect("key").permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(key.parent().unwrap())
            .expect("dir")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let prefs_text =
        std::fs::read_to_string(dir.path().join("desktop-prefs.json")).expect("prefs file");
    assert!(!prefs_text.contains("PRIVATE KEY"));
    // A second import of the same enrolment replaces the stage.
    ops::remote_import_bundle(&state, MAIN, picked)
        .await
        .expect("again");
    let overview = ops::remote_status(&state, MAIN).await.expect("status");
    assert_eq!(overview.mode, BackendMode::Local);
    assert_eq!(overview.active, None);
    assert!(overview.profiles.is_empty(), "staged, not stored");
    assert_eq!(overview.remote_commands.len(), 25);

    // An unlocked local vault: the switch is refused until it is locked.
    state
        .core()
        .expect("core")
        .create_vault(cerberus_core::NewVault {
            owner_label: "local".to_owned(),
            phrase: cerberus_crypto::SecretString::new(PHRASE.to_owned()),
            kdf: cerberus_crypto::KdfParams::new(19_456, 1, 1).expect("kdf"),
            host_names: Vec::new(),
        })
        .await
        .expect("local vault");
    assert_eq!(
        code(ops::remote_activate(&state, MAIN, Some(view.id.clone()), false).await),
        "conflict"
    );
    // "Lock and connect" checks everything before it locks: a refused switch leaves the local
    // vault unlocked, so the screen that asked still shows the error (DEC-RM-26).
    assert_eq!(
        code(ops::remote_activate(&state, MAIN, Some("nope".to_owned()), true).await),
        "not_found"
    );
    assert_eq!(
        state.core().expect("core").state(),
        cerberus_types::VaultStateKind::Unlocked
    );
    assert!(state.prefs().remote.profiles.is_empty());
    assert!(
        ops::remote_activate(&state, MAIN, Some(view.id.clone()), true)
            .await
            .expect("lock and connect"),
        "a switch needs a restart"
    );
    assert_eq!(
        state.core().expect("core").state(),
        cerberus_types::VaultStateKind::Sealed
    );
    // Connecting stored the staged import.
    assert_eq!(state.prefs().remote.profiles.len(), 1);
    let stored_key = dir
        .path()
        .join("remote")
        .join(&view.id)
        .join(remote::profile::KEY_FILE);
    assert_eq!(
        std::fs::metadata(&stored_key)
            .expect("stored key")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(!dir.path().join("remote").join("pending").exists());
    assert_eq!(
        state.prefs().remote.active.as_deref(),
        Some(view.id.as_str())
    );
    assert_eq!(
        code(ops::remote_forget(&state, MAIN, view.id.clone()).await),
        "conflict"
    );
    // Back to local before the restart: nothing to restart for.
    assert!(
        !ops::remote_activate(&state, MAIN, None, false)
            .await
            .expect("local")
    );
    ops::remote_forget(&state, MAIN, view.id.clone())
        .await
        .expect("forget");
    assert!(state.prefs().remote.profiles.is_empty());
    assert!(!dir.path().join("remote").join(&view.id).exists());
    assert_eq!(
        code(ops::remote_disconnect(&state, MAIN).await),
        "unavailable"
    );
    state.shutdown().await;
    daemon.stop().await;
}

/// A second import of an enrolment that is already stored, then Cancel: the stored profile, its
/// files and its preferences stay as they were (DEC-RM-26). The bundle's URL is not signed, so a
/// changed one is the case that matters: it must not replace the stored address before the
/// person compared the pin and connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reimport_waits_for_connect_and_a_cancel_keeps_the_stored_profile() {
    use std::os::unix::fs::PermissionsExt;
    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().to_path_buf());
    Prefs {
        port: 0,
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(FakeShell::default());
    let state = DesktopState::open(paths.clone(), shell.clone(), StateOptions::default())
        .await
        .expect("open");
    let pick = |path: &std::path::Path| {
        *shell.pick.lock().unwrap() = Some(path.to_path_buf());
    };
    pick(&file);
    let picked = ops::file_pick_open(&state, MAIN, None, Vec::new())
        .await
        .expect("pick")
        .expect("path");
    let first = ops::remote_import_bundle(&state, MAIN, picked)
        .await
        .expect("import");
    assert!(
        ops::remote_activate(&state, MAIN, Some(first.id.clone()), false)
            .await
            .expect("connect")
    );
    let stored_dir = dir.path().join("remote").join(&first.id);
    let stored_key = std::fs::read(stored_dir.join(remote::profile::KEY_FILE)).expect("key");

    // The same enrolment again, with another URL in the (unsigned) JSON.
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).expect("bundle")).expect("json");
    json["url"] = serde_json::Value::String("https://localhost:9".to_owned());
    let changed = daemon.dir.path().join("changed.cerberus-admin");
    std::fs::write(&changed, serde_json::to_vec(&json).expect("json")).expect("write");
    std::fs::set_permissions(&changed, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    pick(&changed);
    let picked = ops::file_pick_open(&state, MAIN, None, Vec::new())
        .await
        .expect("pick")
        .expect("path");
    let staged = ops::remote_import_bundle(&state, MAIN, picked)
        .await
        .expect("stage");
    assert_eq!(staged.id, first.id);
    assert_eq!(staged.url, "https://localhost:9");
    // Before the connect nothing of the stored profile changed.
    let url = |state: &DesktopState| {
        state
            .prefs()
            .remote
            .profile(&first.id)
            .map(|p| p.url.clone())
    };
    assert_eq!(url(&state).as_deref(), Some(first.url.as_str()));
    assert_eq!(
        std::fs::read(stored_dir.join(remote::profile::KEY_FILE)).expect("key"),
        stored_key
    );
    // Cancel.
    ops::remote_discard_import(&state, MAIN)
        .await
        .expect("discard");
    assert_eq!(url(&state).as_deref(), Some(first.url.as_str()));
    assert!(stored_dir.join(remote::profile::KEY_FILE).is_file());
    assert!(!dir.path().join("remote").join("pending").exists());
    // A connect after a cancel is to the stored profile, not to the dropped stage.
    ops::remote_activate(&state, MAIN, Some(first.id.clone()), false)
        .await
        .expect("same choice");
    assert_eq!(url(&state).as_deref(), Some(first.url.as_str()));

    // Staged again and connected: now the new address is stored, its key file private.
    pick(&changed);
    let picked = ops::file_pick_open(&state, MAIN, None, Vec::new())
        .await
        .expect("pick")
        .expect("path");
    ops::remote_import_bundle(&state, MAIN, picked)
        .await
        .expect("stage");
    ops::remote_activate(&state, MAIN, Some(first.id.clone()), false)
        .await
        .expect("connect");
    assert_eq!(url(&state).as_deref(), Some("https://localhost:9"));
    assert_eq!(
        std::fs::metadata(stored_dir.join(remote::profile::KEY_FILE))
            .expect("key")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    state.shutdown().await;
    daemon.stop().await;
}

/// A profile whose files are gone starts in local mode, and the broken choice is cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broken_profile_starts_in_local_mode() {
    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");
    let (state, dir, _shell) = remote_desktop(&file).await;
    assert!(state.remote().is_some());
    state.shutdown().await;
    drop(state);
    std::fs::remove_file(
        dir.path()
            .join("remote")
            .join(bundle.id.to_string())
            .join(remote::profile::KEY_FILE),
    )
    .expect("remove key");
    let paths = AppPaths::new(dir.path().to_path_buf());
    let state = DesktopState::open(
        paths.clone(),
        Arc::new(FakeShell::default()),
        StateOptions::default(),
    )
    .await
    .expect("open");
    assert!(state.remote().is_none(), "local mode");
    assert!(Prefs::load(&paths).remote.active.is_none());
    assert_eq!(
        Prefs::load(&paths).remote.profiles.len(),
        1,
        "the profile stays"
    );
    state.shutdown().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_mode_proxies_the_allowlist_and_follows_the_server() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .init();
    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");
    let (state, dir, _shell) = remote_desktop(&file).await;
    let backend = Arc::clone(state.remote().expect("remote mode"));
    let operator = bundle.operator_id.to_string();

    // No local vault, no local store.
    assert!(!dir.path().join("vault.cerberus").exists());
    assert_eq!(code(state.core()), "remote_unsupported");

    // Sealed for this desktop (no session), although the server vault is unlocked (DEC-RM-10).
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed);
    assert!(status.operator.is_none());
    let link = status.remote.expect("remote field");
    assert!(link.reachable && !link.has_session);
    assert_eq!(link.server_state, Some(VaultState::Unlocked));
    assert_eq!(link.server_version.as_deref(), Some(cerberusd_version()));
    assert_eq!(link.operator_id, operator);
    let overview = ops::remote_status(&state, MAIN).await.expect("overview");
    assert_eq!(overview.mode, BackendMode::Remote);
    assert_eq!(
        overview.active.as_deref(),
        Some(bundle.id.to_string().as_str())
    );

    // Pre-session commands work; session commands do not, and a local-only one never leaves.
    let operators: Vec<OperatorPublic> = backend
        .forward("vault_list_operators", &json!({}))
        .await
        .expect("operators");
    assert!(operators.iter().any(|o| o.id == operator));
    assert_eq!(
        code(
            backend
                .forward::<Vec<ItemSummaryView>, _>("item_list", &json!({ "filter": {} }))
                .await
        ),
        "vault_locked"
    );
    assert_eq!(
        code(ops::item_versions(&state, MAIN, daemon.seed.item.to_string()).await),
        "remote_unsupported"
    );
    assert_eq!(
        code(ops::settings_get(&state, MAIN).await),
        "remote_unsupported"
    );
    // The allowlist gate runs before the network: a backend whose server cannot be reached
    // still answers `remote_unsupported`, not `remote_unreachable`.
    let mut nowhere = backend.profile().clone();
    nowhere.url = "https://127.0.0.1:9".to_owned();
    let paths = AppPaths::new(dir.path().to_path_buf());
    let offline = RemoteBackend::new(
        nowhere.clone(),
        remote::profile::transport(&paths, &nowhere).expect("transport"),
        Arc::new(cerberus_types::SystemClock),
    );
    assert_eq!(
        code(
            offline
                .forward::<(), _>("item_versions", &json!({ "item": "x" }))
                .await
        ),
        "remote_unsupported"
    );
    assert_eq!(
        code(offline.forward::<(), _>("vault_status", &json!({})).await),
        "remote_unreachable"
    );
    assert!(!offline.link().reachable);
    assert_eq!(
        offline.link().problem.as_deref(),
        Some("remote_unreachable")
    );

    // The pump: sealed first.
    let (tx, mut events) = unbounded_channel();
    let pump = tokio::spawn(remote::pump::drive(Arc::clone(&backend), tx));
    assert!(is_state(&next_event(&mut events).await, VaultState::Sealed));
    assert!(is_count(&next_event(&mut events).await, 0));

    // A wrong phrase, then the right one: a session, and the state is unlocked.
    let wrong = ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new("wrong words for this test".to_owned()),
    )
    .await;
    assert_eq!(code(wrong), "bad_credentials");
    let session = ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock");
    assert_eq!(session.operator_id, operator);
    wait_for(&mut events, |e| is_state(e, VaultState::Unlocked)).await;
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Unlocked);
    assert_eq!(status.operator.as_deref(), Some(operator.as_str()));
    assert!(status.idle_seconds_left.is_some_and(|s| s > 800));
    assert!(status.remote.expect("remote").has_session);

    // Items round-trip through the server.
    let workspace = daemon.seed.workspace.to_string();
    let created: ItemDetailView = backend
        .forward(
            "item_create",
            &json!({ "input": web_login_input(&workspace, "Remote login") }),
        )
        .await
        .expect("create");
    let listed: Vec<ItemSummaryView> = backend
        .forward("item_list", &json!({ "filter": {} }))
        .await
        .expect("list");
    assert!(listed.iter().any(|i| i.id == created.summary.id));
    let revealed: RevealedSecretView = backend
        .forward("item_reveal", &json!({ "item": created.summary.id }))
        .await
        .expect("reveal");
    match revealed.payload {
        PayloadView::WebLogin { password, .. } => assert_eq!(password.expose(), PASSWORD),
        other => panic!("{other:?}"),
    }
    // An SSH draft of the desktop is refused: it does not live on the server.
    let draft = json!({ "input": {
        "workspace_id": workspace, "title": "Draft key", "description": "", "role_label": null,
        "category": "SSH key", "tags": [], "environment": "dev", "target": null, "custom": {},
        "expires_at": null, "max_uses": null,
        "payload": { "kind": "ssh_key_draft", "draft_id": "d" } } });
    assert_eq!(
        code(
            backend
                .forward::<ItemDetailView, _>("item_create", &draft)
                .await
        ),
        "remote_unsupported"
    );

    // Approvals over the admin channel: an agent read waits, the desktop sees it and approves.
    let reveal_path = format!("/v1/credentials/{}/reveal", daemon.seed.item);
    let purpose = r#"{"purpose":"remote mode test read"}"#;
    let pending = daemon.agent("POST", &reveal_path, Some(purpose)).await;
    assert_eq!(
        pending.status,
        202,
        "{}",
        String::from_utf8_lossy(&pending.body)
    );
    let request =
        serde_json::from_slice::<serde_json::Value>(&pending.body).expect("json")["access_request"]
            ["id"]
            .as_str()
            .expect("id")
            .to_owned();
    let created_event = wait_for(&mut events, |e| {
        matches!(e, WireEvent::AccessRequestCreated { .. })
    })
    .await;
    assert_eq!(
        created_event,
        WireEvent::AccessRequestCreated {
            id: request.clone()
        }
    );
    wait_for(&mut events, |e| is_count(e, 1)).await;
    let _lease: cerberus_desktop::dto::LeaseView = backend
        .forward(
            "request_approve",
            &json!({ "request": request, "option": "once" }),
        )
        .await
        .expect("approve");
    wait_for(&mut events, |e| {
        matches!(e, WireEvent::AccessRequestResolved { .. })
    })
    .await;
    wait_for(&mut events, |e| is_count(e, 0)).await;
    let read = daemon.agent("POST", &reveal_path, Some(purpose)).await;
    assert_eq!(read.status, 200);

    // Disconnect is not lock: the session ends, the server vault stays open for its agents.
    ops::remote_disconnect(&state, MAIN)
        .await
        .expect("disconnect");
    wait_for(&mut events, |e| is_state(e, VaultState::Sealed)).await;
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed);
    assert_eq!(
        status.remote.expect("remote").server_state,
        Some(VaultState::Unlocked)
    );
    assert_eq!(daemon.agent("GET", "/v1/status", None).await.status, 200);

    // A lock on the server (here from a second session of the same enrolment) ends the
    // desktop's session: the event stream says so, and the desktop is sealed.
    ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock again");
    wait_for(&mut events, |e| is_state(e, VaultState::Unlocked)).await;
    let other = daemon.open_session(&bundle).await;
    let locked = daemon
        .admin_call(
            &bundle,
            "POST",
            "/admin/v1/rpc/vault_lock",
            Some(&other),
            Some("{}"),
        )
        .await;
    assert_eq!(
        locked.status,
        200,
        "{}",
        String::from_utf8_lossy(&locked.body)
    );
    wait_for(&mut events, |e| is_state(e, VaultState::Sealed)).await;
    assert!(!backend.has_session());
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed);
    assert_eq!(
        status.remote.expect("remote").server_state,
        Some(VaultState::Sealed)
    );
    assert_eq!(daemon.agent("GET", "/v1/status", None).await.status, 423);

    // A remote unlock of the sealed server vault, then "Lock the server vault" from the desktop.
    ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("remote unlock");
    wait_for(&mut events, |e| is_state(e, VaultState::Unlocked)).await;
    assert_eq!(daemon.agent("GET", "/v1/status", None).await.status, 200);
    ops::vault_lock(&state, MAIN)
        .await
        .expect("lock the server");
    wait_for(&mut events, |e| is_state(e, VaultState::Sealed)).await;
    assert_eq!(daemon.agent("GET", "/v1/status", None).await.status, 423);

    // Quit closes the session and leaves the server vault as it is.
    ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock for quit");
    state.shutdown().await;
    assert!(!backend.has_session());
    assert_eq!(daemon.agent("GET", "/v1/status", None).await.status, 200);

    // A revoked enrolment is refused at once: the desktop says why.
    ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock before revoke");
    daemon.revoke(&bundle).await;
    let refused = code(
        backend
            .forward::<Vec<ItemSummaryView>, _>("item_list", &json!({ "filter": {} }))
            .await,
    );
    // The pump's stream is cut by the revoke and may find out first; then the session is gone.
    assert!(
        refused == "admin_cert_required" || refused == "vault_locked",
        "{refused}"
    );
    assert_eq!(code(backend.hello().await), "admin_cert_required");
    assert!(!backend.has_session());
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed);
    assert_eq!(
        status.remote.expect("remote").problem.as_deref(),
        Some("admin_cert_required")
    );

    pump.abort();
    daemon.stop().await;
    let log = String::from_utf8(capture.0.lock().expect("lock").clone()).expect("utf-8");
    assert!(
        log.contains("remote admin session opened"),
        "the capture works"
    );
    assert!(!log.contains(PHRASE), "the phrase is in the log");
    assert!(!log.contains(PASSWORD), "a secret is in the log");
    assert!(!log.contains("cas_"), "a session token is in the log");
    assert!(!log.contains("PRIVATE KEY"), "the client key is in the log");
}

fn cerberusd_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The session limits on the desktop's own clock (DEC-RM-26): background reads are not activity,
/// a keep-alive is; the pump counts this session down (not the server's idle lock), and ends the
/// session at its idle or absolute limit even though the server, on its own clock, would still
/// take the token. Both ends are `VaultStateChanged { sealed }`, so the UI drops its data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_limits_run_on_the_desktop_clock() {
    let daemon = Daemon::start_with(
        true,
        "session_idle_seconds = 600\nsession_max_seconds = 900\n",
    )
    .await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");
    let clock =
        cerberus_types::ManualClock::new(cerberus_types::Clock::now(&cerberus_types::SystemClock));
    let (state, _dir, _shell) = common::remote_desktop_with(
        &file,
        StateOptions {
            clock: Some(Arc::new(clock.clone())),
            ..StateOptions::default()
        },
    )
    .await;
    let backend = Arc::clone(state.remote().expect("remote mode"));
    let operator = bundle.operator_id.to_string();
    let advance = |seconds: i64| clock.advance(jiff::SignedDuration::from_secs(seconds));
    let idle_left = |state: DesktopState| async move {
        ops::vault_status(&state, MAIN)
            .await
            .expect("status")
            .idle_seconds_left
    };
    let (tx, mut events) = unbounded_channel();
    let pump = tokio::spawn(remote::pump::drive(Arc::clone(&backend), tx));
    ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock");
    wait_for(&mut events, |e| is_state(e, VaultState::Unlocked)).await;

    // The rail counts down this session: 600 s idle, not the server's idle lock (off here).
    let tick = wait_for(&mut events, |e| matches!(e, WireEvent::AutolockTick { .. })).await;
    assert!(
        matches!(tick, WireEvent::AutolockTick { seconds_left } if (590..=600).contains(&seconds_left)),
        "{tick:?}"
    );

    // Reads that the UI makes after live events do not reset the idle limit; a keep-alive does.
    advance(300);
    let _: Vec<ItemSummaryView> = backend
        .forward("item_list", &json!({ "filter": {} }))
        .await
        .expect("read");
    let _: Vec<cerberus_desktop::dto::AgentView> = backend
        .forward("agent_list", &json!({}))
        .await
        .expect("read");
    let left = idle_left(state.clone()).await.expect("idle left");
    assert!(
        (295..=300).contains(&left),
        "a read reset the idle limit: {left}"
    );
    let () = backend
        .forward("ui_activity", &json!({}))
        .await
        .expect("keep-alive");
    let left = idle_left(state.clone()).await.expect("idle left");
    assert!((595..=600).contains(&left), "{left}");

    // The absolute limit (900 s after the open) ends a session that stays active.
    advance(500);
    let () = backend
        .forward("ui_activity", &json!({}))
        .await
        .expect("keep-alive");
    advance(150);
    wait_for(&mut events, |e| is_state(e, VaultState::Sealed)).await;
    assert!(!backend.has_session());
    assert_eq!(
        ops::vault_status(&state, MAIN).await.expect("status").state,
        VaultState::Sealed
    );

    // The idle limit ends a session with no activity, without asking the server.
    ops::vault_unlock(&state, MAIN, operator, Secret::new(PHRASE.to_owned()))
        .await
        .expect("unlock again");
    wait_for(&mut events, |e| is_state(e, VaultState::Unlocked)).await;
    advance(601);
    wait_for(&mut events, |e| is_state(e, VaultState::Sealed)).await;
    assert!(!backend.has_session());
    // A call after the end has no token to send: `vault_locked` with no network call.
    assert_eq!(
        code(
            backend
                .forward::<Vec<ItemSummaryView>, _>("item_list", &json!({ "filter": {} }))
                .await
        ),
        "vault_locked"
    );
    pump.abort();
    state.shutdown().await;
    daemon.stop().await;
}

/// The code that `ipc!` generates for each command arm (`commands::Dispatch`, which the Tauri
/// command only calls): an `@remote` command checks the window label first and then sends its
/// typed arguments under their IPC names; a local-only command checks the label and refuses with
/// `remote_unsupported`, without a network call; in local mode both call `ops` (DEC-RM-26).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_generated_command_arms_forward_check_the_label_and_refuse_local_only() {
    use cerberus_desktop::commands::Dispatch;
    use cerberus_desktop::dto::{ItemFilterView, WorkspaceInputView};

    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");
    let (state, _dir, _shell) = remote_desktop(&file).await;
    let operator = bundle.operator_id.to_string();
    let filter = || -> ItemFilterView { serde_json::from_value(json!({})).expect("filter") };

    // Before a session: the label check comes first, then the missing session.
    assert_eq!(
        code(Dispatch::item_list(&state, "evil", filter()).await),
        "window_not_allowed"
    );
    assert_eq!(
        code(Dispatch::item_list(&state, MAIN, filter()).await),
        "vault_locked"
    );
    let operators = Dispatch::vault_list_operators(&state, MAIN)
        .await
        .expect("pre-session command");
    assert!(operators.iter().any(|o| o.id == operator));
    Dispatch::vault_unlock(&state, MAIN, operator, Secret::new(PHRASE.to_owned()))
        .await
        .expect("unlock");

    // `@remote`: the typed arguments reach the server under their names (one, several, optional).
    let items = Dispatch::item_list(&state, MAIN, filter())
        .await
        .expect("item_list");
    assert!(items.iter().any(|i| i.id == daemon.seed.item.to_string()));
    let input: WorkspaceInputView = serde_json::from_value(
        json!({ "slug": "ops", "name": "Ops", "description": "", "aliases": [] }),
    )
    .expect("workspace input");
    let workspace = Dispatch::workspace_put(&state, MAIN, None, input)
        .await
        .expect("workspace_put");
    assert_eq!(workspace.slug, "ops");
    let grants = Dispatch::grant_list(&state, MAIN, None)
        .await
        .expect("grant_list");
    assert_eq!(grants.len(), 1);
    let detail = Dispatch::item_get(&state, MAIN, daemon.seed.item.to_string())
        .await
        .expect("item_get");
    assert_eq!(detail.summary.id, daemon.seed.item.to_string());
    // The approval window may decide, but not read items; the refusal comes before the server.
    assert_eq!(
        code(Dispatch::item_get(&state, "approval", daemon.seed.item.to_string()).await),
        "window_not_allowed"
    );
    let unknown = Dispatch::request_deny(&state, "approval", "not-an-id".to_owned()).await;
    assert_eq!(code(unknown), "validation_failed", "it reached the server");

    // Local only: the label check, then `remote_unsupported`; nothing is sent.
    assert_eq!(
        code(Dispatch::item_versions(&state, "evil", daemon.seed.item.to_string()).await),
        "window_not_allowed"
    );
    assert_eq!(
        code(Dispatch::item_versions(&state, MAIN, daemon.seed.item.to_string()).await),
        "remote_unsupported"
    );
    assert_eq!(
        code(Dispatch::settings_get(&state, MAIN).await),
        "remote_unsupported"
    );
    assert_eq!(
        code(Dispatch::lease_revoke_all(&state, MAIN).await),
        "remote_unsupported"
    );
    state.shutdown().await;

    // Local mode: the same arms call `ops`.
    let dir = tempfile::tempdir().expect("tempdir");
    let local = DesktopState::open(
        AppPaths::new(dir.path().to_path_buf()),
        Arc::new(FakeShell::default()),
        StateOptions::default(),
    )
    .await
    .expect("open");
    assert_eq!(
        code(Dispatch::item_list(&local, MAIN, filter()).await),
        "no_vault"
    );
    assert_eq!(
        code(Dispatch::item_versions(&local, MAIN, daemon.seed.item.to_string()).await),
        "no_vault"
    );
    local.shutdown().await;
    daemon.stop().await;
}
