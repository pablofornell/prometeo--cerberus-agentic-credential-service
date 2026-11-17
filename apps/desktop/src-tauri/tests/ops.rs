//! The command layer without a window: fake window labels, a fake shell, a real vault file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerberus_core::{KeyCustody, NewVault};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_desktop::dto::{OperatorRole, Secret};
use cerberus_desktop::error::{IpcError, IpcResult};
use cerberus_desktop::ops;
use cerberus_desktop::{AppPaths, DesktopState, Prefs, Shell, StateOptions};
use serde_json::json;

const MAIN: &str = "main";
const APPROVAL: &str = "approval";
const PHRASE: &str = "correct horse battery staple jumbo violet";

#[derive(Default)]
struct FakeShell {
    clipboard: Mutex<Option<String>>,
    pick: Mutex<Option<std::path::PathBuf>>,
}

impl Shell for FakeShell {
    fn pick_file(
        &self,
        _title: Option<&str>,
        _extensions: &[String],
    ) -> Option<std::path::PathBuf> {
        self.pick.lock().unwrap().clone()
    }
    fn clipboard_write(&self, text: &str) -> IpcResult<()> {
        *self.clipboard.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }
    fn clipboard_read(&self) -> Option<String> {
        self.clipboard.lock().unwrap().clone()
    }
    fn clipboard_clear(&self) {
        *self.clipboard.lock().unwrap() = None;
    }
    fn set_autostart(&self, _enabled: bool) -> IpcResult<()> {
        Ok(())
    }
    fn set_content_protection(&self, _enabled: bool) {}
}

struct Fixture {
    clock: cerberus_types::ManualClock,
    state: DesktopState,
    shell: Arc<FakeShell>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().to_path_buf());
    Prefs {
        port: 0,
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(FakeShell::default());
    // A manual clock: time rules (the unlock back-off) do not depend on how fast the machine is.
    let clock =
        cerberus_types::ManualClock::new(cerberus_types::Clock::now(&cerberus_types::SystemClock));
    let state = DesktopState::open(
        paths,
        shell.clone(),
        StateOptions {
            clipboard_ttl: Duration::from_millis(150),
            clock: Some(Arc::new(clock.clone())),
        },
    )
    .await
    .expect("open");
    Fixture {
        clock,
        state,
        shell,
        _dir: dir,
    }
}

/// Makes the vault (owner, unlocked) with the cheapest KDF the schema allows.
async fn create_vault(f: &Fixture) {
    f.state
        .core()
        .expect("core")
        .create_vault(NewVault {
            owner_label: "owner".to_owned(),
            phrase: SecretString::new(PHRASE.to_owned()),
            kdf: KdfParams::new(19_456, 1, 1).expect("kdf"),
            host_names: Vec::new(),
        })
        .await
        .expect("create vault");
}

/// The person chooses `path` in the fake native dialog. Returns the text the UI would send.
async fn pick(f: &Fixture, path: &std::path::Path) -> String {
    *f.shell.pick.lock().unwrap() = Some(path.to_path_buf());
    ops::file_pick_open(&f.state, MAIN, None, Vec::new())
        .await
        .expect("pick")
        .expect("a path")
}

fn code<T>(result: IpcResult<T>) -> String {
    result.err().map(|e: IpcError| e.code).unwrap_or_default()
}

fn note_input(workspace: &str, title: &str, text: &str) -> cerberus_desktop::dto::ItemInputView {
    serde_json::from_value(json!({
        "workspace_id": workspace, "title": title, "description": "", "role_label": null,
        "category": "Note", "tags": [], "environment": "dev", "target": null, "custom": {},
        "expires_at": null, "max_uses": null,
        "payload": { "kind": "note", "text": text }
    }))
    .expect("input")
}

async fn workspace(f: &Fixture) -> String {
    let input = serde_json::from_value(
        json!({ "slug": "shop", "name": "Shop", "description": "", "aliases": [] }),
    )
    .expect("ws");
    ops::workspace_put(&f.state, MAIN, None, input)
        .await
        .expect("workspace")
        .id
}

#[tokio::test]
async fn no_vault_then_locked_errors() {
    let f = fixture().await;
    assert_eq!(
        code(ops::item_list(&f.state, MAIN, Default::default()).await),
        "no_vault"
    );
    create_vault(&f).await;
    f.state
        .core()
        .expect("core")
        .lock(cerberus_types::LockReason::Manual)
        .await
        .expect("lock");
    assert_eq!(
        code(ops::workspace_list(&f.state, MAIN).await),
        "vault_locked"
    );
    assert_eq!(code(ops::vault_panic(&f.state, MAIN).await), "vault_locked");
    let status = ops::vault_status(&f.state, MAIN).await.expect("status");
    assert!(status.operator.is_none() && status.role.is_none());
}

#[tokio::test]
async fn bad_window_labels_are_rejected_before_anything_runs() {
    let f = fixture().await;
    create_vault(&f).await;
    let ws = workspace(&f).await;
    let item = ops::item_create(&f.state, MAIN, note_input(&ws, "n", "s3cret"))
        .await
        .expect("item");
    for label in [APPROVAL, "evil", ""] {
        assert_eq!(
            code(ops::item_reveal(&f.state, label, item.summary.id.clone()).await),
            "window_not_allowed",
            "{label}"
        );
    }
    assert_eq!(
        code(ops::workspace_list(&f.state, APPROVAL).await),
        "window_not_allowed"
    );
    assert_eq!(
        code(ops::vault_unlock(&f.state, APPROVAL, "x".into(), Secret::new("x".into())).await),
        "window_not_allowed"
    );
    // The commands the approval window needs pass the guard.
    assert!(ops::vault_status(&f.state, APPROVAL).await.is_ok());
    assert!(ops::request_list_pending(&f.state, APPROVAL).await.is_ok());
    assert_ne!(
        code(ops::request_deny(&f.state, APPROVAL, "not-an-id".into()).await),
        "window_not_allowed"
    );
    // The main window reveals, and the reveal is the only place the secret shows.
    let revealed = ops::item_reveal(&f.state, MAIN, item.summary.id.clone())
        .await
        .expect("reveal");
    let text = serde_json::to_string(&revealed).expect("json");
    assert!(text.contains("s3cret"));
    let detail = serde_json::to_string(
        &ops::item_get(&f.state, MAIN, item.summary.id)
            .await
            .expect("get"),
    )
    .expect("json");
    assert!(!detail.contains("s3cret"));
}

#[tokio::test]
async fn the_role_comes_from_the_session_not_the_caller() {
    let f = fixture().await;
    create_vault(&f).await;
    let ws = workspace(&f).await;
    let viewer = ops::operator_add(
        &f.state,
        MAIN,
        "view".into(),
        OperatorRole::Viewer,
        Secret::new("another long passphrase here 9".into()),
    )
    .await
    .expect("add viewer");
    assert_eq!(viewer.role, OperatorRole::Viewer);
    f.state
        .core()
        .expect("core")
        .lock(cerberus_types::LockReason::Manual)
        .await
        .expect("lock");
    ops::vault_unlock(
        &f.state,
        MAIN,
        viewer.id,
        Secret::new("another long passphrase here 9".into()),
    )
    .await
    .expect("unlock viewer");
    // No command takes a role: whatever the UI sends, the session role (viewer) decides.
    assert!(ops::workspace_list(&f.state, MAIN).await.is_ok());
    assert_eq!(
        code(ops::item_create(&f.state, MAIN, note_input(&ws, "x", "y")).await),
        "role_not_allowed"
    );
    assert_eq!(
        code(
            ops::operator_add(
                &f.state,
                MAIN,
                "z".into(),
                OperatorRole::Owner,
                Secret::new("yet another long passphrase 1".into())
            )
            .await
        ),
        "role_not_allowed"
    );
    assert_eq!(
        code(ops::password_generate(&f.state, MAIN, 16, vec![ops::CharClass::Lower]).await),
        "role_not_allowed"
    );
    assert_eq!(
        code(ops::network_set_bind(&f.state, MAIN, vec!["0.0.0.0".into()], 9000).await),
        "role_not_allowed"
    );
    assert!(ops::vault_lock(&f.state, MAIN).await.is_ok());
}

#[tokio::test]
async fn clipboard_clears_only_when_unchanged() {
    let f = fixture().await;
    create_vault(&f).await;
    let ws = workspace(&f).await;
    let item = ops::item_create(&f.state, MAIN, note_input(&ws, "n", "clip-secret"))
        .await
        .expect("item");
    ops::clipboard_copy_secret(&f.state, MAIN, item.summary.id.clone(), "secret".into())
        .await
        .expect("copy");
    assert_eq!(f.shell.clipboard_read().as_deref(), Some("clip-secret"));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(f.shell.clipboard_read(), None, "cleared after the time");
    ops::clipboard_copy_secret(&f.state, MAIN, item.summary.id, "secret".into())
        .await
        .expect("copy");
    f.shell.clipboard_write("something else").expect("write");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        f.shell.clipboard_read().as_deref(),
        Some("something else"),
        "changed content stays"
    );
}

#[tokio::test]
async fn ssh_drafts_keep_the_private_key_in_the_backend() {
    let f = fixture().await;
    create_vault(&f).await;
    let ws = workspace(&f).await;
    let draft = ops::ssh_key_generate(&f.state, MAIN, "me@host".into())
        .await
        .expect("draft");
    assert!(draft.public_key.starts_with("ssh-ed25519"));
    assert!(
        !serde_json::to_string(&draft)
            .expect("json")
            .contains("PRIVATE")
    );
    let input = |d: &str| -> cerberus_desktop::dto::ItemInputView {
        serde_json::from_value(json!({
            "workspace_id": ws, "title": "key", "description": "", "role_label": null,
            "category": "SSH", "tags": [], "environment": "dev", "target": null, "custom": {},
            "expires_at": null, "max_uses": null,
            "payload": { "kind": "ssh_key_draft", "draft_id": d }
        }))
        .expect("input")
    };
    assert_eq!(
        code(ops::item_create(&f.state, MAIN, input("nope")).await),
        "not_found"
    );
    let made = ops::item_create(&f.state, MAIN, input(&draft.draft_id))
        .await
        .expect("create");
    assert_eq!(made.summary.kind, cerberus_desktop::dto::ItemKind::SshKey);
    assert_eq!(
        code(ops::item_create(&f.state, MAIN, input(&draft.draft_id)).await),
        "not_found",
        "a draft is used once"
    );
}

#[tokio::test]
async fn lock_drops_one_time_values_and_the_files_check_refuses_bad_paths() {
    let f = fixture().await;
    create_vault(&f).await;
    f.state
        .set_one_time(cerberus_desktop::dto::OneTimeKind::AgentToken, "cvt_x.y")
        .await;
    ops::clipboard_copy_once(
        &f.state,
        MAIN,
        cerberus_desktop::dto::OneTimeKind::AgentToken,
    )
    .await
    .expect("copy once");
    assert_eq!(f.shell.clipboard_read().as_deref(), Some("cvt_x.y"));
    f.state.clear_held();
    assert_eq!(
        code(
            ops::clipboard_copy_once(
                &f.state,
                MAIN,
                cerberus_desktop::dto::OneTimeKind::AgentToken
            )
            .await
        ),
        "not_found"
    );
    assert_eq!(
        code(ops::audit_export(&f.state, MAIN, "relative.csv".into()).await),
        "validation_failed"
    );
    assert_eq!(
        code(ops::backup_create(&f.state, MAIN, "/tmp/../etc/x".into()).await),
        "validation_failed"
    );
    assert_eq!(
        code(
            ops::tls_load_custom(
                &f.state,
                MAIN,
                "/nonexistent/a".into(),
                "/nonexistent/b".into()
            )
            .await
        ),
        "validation_failed"
    );
}

#[tokio::test]
async fn settings_include_desktop_keys_and_validate_types() {
    let f = fixture().await;
    create_vault(&f).await;
    let view = ops::settings_get(&f.state, MAIN).await.expect("get");
    assert_eq!(view.values["autostart"], json!(false));
    let view = ops::settings_set(&f.state, MAIN, "autostart".into(), json!(true))
        .await
        .expect("set");
    assert_eq!(view.values["autostart"], json!(true));
    assert_eq!(
        code(ops::settings_set(&f.state, MAIN, "autostart".into(), json!("yes")).await),
        "validation_failed"
    );
    assert_eq!(
        code(ops::settings_set(&f.state, MAIN, "no_such_key".into(), json!(1)).await),
        "validation_failed"
    );
}

#[tokio::test]
async fn backup_and_restore_round_trip() {
    let f = fixture().await;
    create_vault(&f).await;
    let ws = workspace(&f).await;
    ops::item_create(&f.state, MAIN, note_input(&ws, "kept", "v"))
        .await
        .expect("item");
    let dest = f._dir.path().join("b.cerberus-backup");
    ops::backup_create(&f.state, MAIN, dest.display().to_string())
        .await
        .expect("backup");
    let dest_text = pick(&f, &dest).await;
    ops::item_create(&f.state, MAIN, note_input(&ws, "later", "v"))
        .await
        .expect("item2");
    let unlock = serde_json::from_value(json!({ "kind": "phrase", "operator_id": ops::vault_list_operators(&f.state, MAIN).await.expect("ops")[0].id, "phrase": PHRASE })).expect("unlock");
    let wrong = serde_json::from_value(json!({ "kind": "phrase", "operator_id": ops::vault_list_operators(&f.state, MAIN).await.expect("ops")[0].id, "phrase": "wrong wrong wrong wrong wrong" })).expect("unlock");
    assert_eq!(
        code(ops::backup_restore(&f.state, MAIN, dest_text.clone(), wrong).await),
        "bad_credentials"
    );
    // DEC-FIX8-4: the old vault is locked before it is dropped, so its events reach listeners.
    let mut old_events = f.state.core().expect("core").subscribe();
    ops::backup_restore(&f.state, MAIN, dest_text, unlock)
        .await
        .expect("restore");
    let mut old_locked = false;
    while let Ok(event) = old_events.try_recv() {
        old_locked |= matches!(
            event,
            cerberus_core::CoreEvent::StateChanged(cerberus_types::VaultStateKind::Sealed)
        );
    }
    assert!(old_locked, "the old vault was locked before the swap");
    let status = ops::vault_status(&f.state, MAIN).await.expect("status");
    assert_eq!(status.state, cerberus_desktop::dto::VaultState::Sealed);
    let id = ops::vault_list_operators(&f.state, MAIN)
        .await
        .expect("ops")[0]
        .id
        .clone();
    ops::vault_unlock(&f.state, MAIN, id, Secret::new(PHRASE.into()))
        .await
        .expect("unlock");
    let items = ops::item_list(&f.state, MAIN, Default::default())
        .await
        .expect("list");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].title, "kept");
    // DEC-FIX8-2: the restore is in the audit chain of the restored vault.
    let rows = ops::audit_query(
        &f.state,
        MAIN,
        serde_json::from_value(json!({
            "from": null, "to": null, "event_type": "backup.restore", "agent_id": null,
            "item_id": null, "before_seq": null, "limit": 10
        }))
        .expect("query"),
    )
    .await
    .expect("audit");
    assert_eq!(rows.len(), 1, "one backup.restore event");
}

/// DEC-FIX8-6: a held one-time value dies with its unlock even when no event reaches the pump
/// (lag), and it never serves another unlock.
#[tokio::test]
async fn held_values_do_not_survive_a_new_unlock() {
    let f = fixture().await;
    create_vault(&f).await;
    let kind = cerberus_desktop::dto::OneTimeKind::AgentToken;
    f.state.set_one_time(kind, "cvt_x.y").await;
    // Lock and unlock with the core directly: no `clear_held`, no pump (as after a lag).
    let core = f.state.core().expect("core");
    core.lock(cerberus_types::LockReason::Manual)
        .await
        .expect("lock");
    // The held value is tied to the unlock time. The fixture clock is manual, so move it.
    f.clock.advance(jiff::SignedDuration::from_secs(1));
    let id = ops::vault_list_operators(&f.state, MAIN)
        .await
        .expect("ops")[0]
        .id
        .clone();
    ops::vault_unlock(&f.state, MAIN, id, Secret::new(PHRASE.into()))
        .await
        .expect("unlock");
    assert_eq!(
        code(ops::clipboard_copy_once(&f.state, MAIN, kind).await),
        "not_found"
    );
    // A value stored in this unlock works, and `vault_lock` drops it at once.
    f.state.set_one_time(kind, "cvt_a.b").await;
    ops::clipboard_copy_once(&f.state, MAIN, kind)
        .await
        .expect("copy");
    ops::vault_lock(&f.state, MAIN).await.expect("lock");
    assert!(f.state.one_time(kind).await.is_none());
}

#[tokio::test]
async fn vault_create_starts_the_https_server() {
    let f = fixture().await;
    assert_eq!(code(ops::network_status(&f.state, MAIN).await), "no_vault");
    let created = ops::vault_create(
        &f.state,
        MAIN,
        "owner".to_owned(),
        Secret::new(PHRASE.to_owned()),
        serde_json::from_value(json!({ "m_cost_kib": 19456, "t_cost": 1, "p_cost": 1 }))
            .expect("kdf"),
        Vec::new(),
    )
    .await
    .expect("create");
    assert!(created.ca_pin.starts_with("sha256/"));
    let view = ops::network_status(&f.state, MAIN).await.expect("network");
    assert!(view.listening, "server error: {:?}", view.error);
    assert!(!view.mtls_required);
    // The recovery key was kept for the one-time clipboard copy.
    ops::clipboard_copy_once(
        &f.state,
        MAIN,
        cerberus_desktop::dto::OneTimeKind::RecoveryKey,
    )
    .await
    .expect("copy recovery key");
    assert!(
        f.shell
            .clipboard_read()
            .expect("clipboard")
            .starts_with("CRK1")
    );
    f.state.shutdown().await;
}

#[tokio::test]
async fn a_custom_certificate_is_loaded_served_and_reverted() {
    use cerberus_api::tls::{LocalCa, leaf_names};
    use cerberus_types::{Clock, SystemClock, VaultId};
    let f = fixture().await;
    create_vault(&f).await;
    let before = ops::network_status(&f.state, MAIN).await.expect("network");
    assert!(!before.custom_cert);
    // A certificate from another CA, made for this test only.
    let now = SystemClock.now();
    let ca = LocalCa::create(&VaultId::generate(), now).expect("ca");
    let leaf = ca.issue_leaf(&leaf_names(&[]), now).expect("leaf");
    let dir = tempfile::tempdir().expect("dir");
    let chain = dir.path().join("chain.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(
        &chain,
        format!("{}{}", leaf.cert_pem(), ca.export().expect("export").pem),
    )
    .expect("chain");
    std::fs::write(&key, leaf.key_pem()).expect("key");
    // A key that does not match is refused with a field problem and changes nothing.
    let other = ca.issue_leaf(&leaf_names(&[]), now).expect("other");
    let bad_key = dir.path().join("bad.pem");
    std::fs::write(&bad_key, other.key_pem()).expect("bad key");
    let (chain_text, key_text, bad_text) = (
        pick(&f, &chain).await,
        pick(&f, &key).await,
        pick(&f, &bad_key).await,
    );
    let error = ops::tls_load_custom(&f.state, MAIN, chain_text.clone(), bad_text)
        .await
        .unwrap_err();
    assert_eq!(error.code, "validation_failed");
    assert_ne!(
        error.fields[0].problem, "cannot be used",
        "the key was read"
    );
    assert!(
        !ops::network_status(&f.state, MAIN)
            .await
            .expect("network")
            .custom_cert
    );
    let view = ops::tls_load_custom(&f.state, MAIN, chain_text, key_text)
        .await
        .expect("load");
    assert!(view.custom_cert);
    assert_ne!(view.pin, before.pin, "the pin follows the active chain");
    assert_eq!(
        view.pin,
        cerberus_api::tls::spki_pin(ca.cert_der()).expect("pin")
    );
    let back = ops::tls_use_local_ca(&f.state, MAIN).await.expect("revert");
    assert!(!back.custom_cert);
    assert_eq!(back.pin, before.pin);
}

fn audit_filter(
    event_type: Option<&str>,
    outcome: Option<&str>,
) -> cerberus_desktop::dto::AuditQueryView {
    let mut query = json!({ "limit": 1000, "event_type": event_type });
    if let Some(outcome) = outcome {
        query["outcome"] = json!(outcome);
    }
    serde_json::from_value(query).expect("query")
}

#[tokio::test]
async fn item_update_can_keep_the_payload_and_views_carry_custom() {
    let f = fixture().await;
    create_vault(&f).await;
    let ws = workspace(&f).await;
    let with = |custom: serde_json::Value, payload: serde_json::Value| {
        let mut input = json!({
            "workspace_id": ws, "title": "memo", "description": "", "role_label": null,
            "category": "Note", "tags": [], "environment": "dev", "target": null,
            "custom": custom, "expires_at": null, "max_uses": null, "payload": payload
        });
        input["title"] = json!("memo");
        serde_json::from_value::<cerberus_desktop::dto::ItemInputView>(input).expect("input")
    };
    let note = |text: &str| json!({ "kind": "note", "text": text });
    let made = ops::item_create(
        &f.state,
        MAIN,
        with(json!({ "owner": "team-a" }), note("zq-fake-note-1")),
    )
    .await
    .expect("create");
    let id = made.summary.id.clone();
    let listed = ops::item_list(&f.state, MAIN, Default::default())
        .await
        .expect("list");
    assert_eq!(
        listed[0].custom.get("owner").map(String::as_str),
        Some("team-a")
    );

    // `keep` is for updates only.
    assert_eq!(
        code(ops::item_create(&f.state, MAIN, with(json!({}), json!({ "kind": "keep" }))).await),
        "validation_failed"
    );

    // Keep: the metadata changes, the secret and the version stay, and no reveal is audited.
    let kept = ops::item_update(
        &f.state,
        MAIN,
        id.clone(),
        with(json!({ "owner": "team-b" }), json!({ "kind": "keep" })),
    )
    .await
    .expect("keep");
    assert_eq!(kept.version, 1);
    assert_eq!(
        kept.summary.custom.get("owner").map(String::as_str),
        Some("team-b")
    );
    let reveals = ops::audit_query(&f.state, MAIN, audit_filter(Some("item.reveal"), None))
        .await
        .expect("audit");
    assert!(reveals.is_empty(), "a metadata-only update reveals nothing");
    let revealed = ops::item_reveal(&f.state, MAIN, id.clone())
        .await
        .expect("reveal");
    let text = serde_json::to_value(&revealed.payload).expect("json");
    assert_eq!(text["text"], "zq-fake-note-1");
    assert_eq!(
        revealed.summary.custom.get("owner").map(String::as_str),
        Some("team-b")
    );

    // Replace still works and makes a new version.
    let replaced = ops::item_update(
        &f.state,
        MAIN,
        id.clone(),
        with(json!({ "owner": "team-c" }), note("zq-fake-note-2")),
    )
    .await
    .expect("replace");
    assert_eq!(replaced.version, 2);
    let again = ops::item_reveal(&f.state, MAIN, id).await.expect("reveal");
    let text = serde_json::to_value(&again.payload).expect("json");
    assert_eq!(text["text"], "zq-fake-note-2");
    assert_eq!(
        again.summary.custom.get("owner").map(String::as_str),
        Some("team-c")
    );
}

#[tokio::test]
async fn vault_status_carries_cost_lock_reason_and_unlock_failures() {
    let f = fixture().await;
    create_vault(&f).await;
    let status = ops::vault_status(&f.state, MAIN).await.expect("status");
    let kdf = status.kdf.expect("kdf");
    assert_eq!((kdf.m_cost_kib, kdf.t_cost, kdf.p_cost), (19_456, 1, 1));
    assert!(status.last_lock_reason.is_none());
    assert_eq!(
        (status.failed_unlocks, status.free_unlock_tries_left),
        (0, 5)
    );
    assert!(status.retry_after_seconds.is_none());

    ops::vault_lock(&f.state, MAIN).await.expect("lock");
    let sealed = ops::vault_status(&f.state, MAIN).await.expect("status");
    assert!(sealed.kdf.is_none(), "the cost is for a session");
    assert_eq!(
        serde_json::to_value(sealed.last_lock_reason).expect("json"),
        json!("manual")
    );

    let operator = ops::vault_list_operators(&f.state, MAIN)
        .await
        .expect("operators")
        .remove(0)
        .id;
    for done in 1..=5_u32 {
        let wrong = ops::vault_unlock(
            &f.state,
            MAIN,
            operator.clone(),
            Secret::new("wrong phrase for the failure count".into()),
        )
        .await;
        assert_eq!(code(wrong), "bad_credentials");
        let status = ops::vault_status(&f.state, MAIN).await.expect("status");
        assert_eq!(status.failed_unlocks, done);
        assert_eq!(status.free_unlock_tries_left, 5 - done);
    }
    let waiting = ops::vault_status(&f.state, MAIN).await.expect("status");
    assert!(waiting.retry_after_seconds.is_some_and(|s| s >= 1));

    f.clock.advance(jiff::SignedDuration::from_millis(1_200));
    ops::vault_unlock(&f.state, MAIN, operator, Secret::new(PHRASE.into()))
        .await
        .expect("unlock");
    let open = ops::vault_status(&f.state, MAIN).await.expect("status");
    assert_eq!((open.failed_unlocks, open.free_unlock_tries_left), (0, 5));

    // The failed unlocks are in the audit log; the outcome filter finds them.
    let failed = ops::audit_query(&f.state, MAIN, audit_filter(None, Some("failed")))
        .await
        .expect("audit");
    assert_eq!(failed.len(), 5);
    assert!(failed.iter().all(|e| e.event_type == "vault.unlock_failed"));
    let ok = ops::audit_query(&f.state, MAIN, audit_filter(None, Some("ok")))
        .await
        .expect("audit");
    assert!(!ok.is_empty() && ok.iter().all(|e| e.result == "ok"));
}
