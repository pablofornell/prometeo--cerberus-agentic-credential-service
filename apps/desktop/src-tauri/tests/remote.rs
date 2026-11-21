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
    // The key is stored privately and never in the preferences.
    let key = dir
        .path()
        .join("remote")
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
    // A second import of the same enrolment replaces the profile.
    ops::remote_import_bundle(&state, MAIN, picked)
        .await
        .expect("again");
    let overview = ops::remote_status(&state, MAIN).await.expect("status");
    assert_eq!(overview.mode, BackendMode::Local);
    assert_eq!(overview.active, None);
    assert_eq!(overview.profiles.len(), 1);
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
        code(ops::remote_activate(&state, MAIN, Some(view.id.clone())).await),
        "conflict"
    );
    ops::vault_lock(&state, MAIN).await.expect("lock");
    assert_eq!(
        code(ops::remote_activate(&state, MAIN, Some("nope".to_owned())).await),
        "not_found"
    );
    assert!(
        ops::remote_activate(&state, MAIN, Some(view.id.clone()))
            .await
            .expect("activate"),
        "a switch needs a restart"
    );
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
        !ops::remote_activate(&state, MAIN, None)
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
