//! T27-C: fixes of the security audit in the desktop app (AUD-11, AUD-13, AUD-14). Fake values only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerberus_core::{KeyCustody, NewVault};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_desktop::dto::{
    CsvImportRequest, CsvMapping, CsvSource, DuplicatePolicy, Environment,
};
use cerberus_desktop::error::{IpcError, IpcResult};
use cerberus_desktop::ops;
use cerberus_desktop::{AppPaths, DesktopState, Prefs, Shell, StateOptions};
use serde_json::json;

const MAIN: &str = "main";
const PHRASE: &str = "correct horse battery staple jumbo violet";

#[derive(Default)]
struct FakeShell {
    clipboard: Mutex<Option<String>>,
    pick: Mutex<Option<PathBuf>>,
}

impl Shell for FakeShell {
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
    fn pick_file(&self, _title: Option<&str>, _extensions: &[String]) -> Option<PathBuf> {
        self.pick.lock().unwrap().clone()
    }
}

struct Fixture {
    state: DesktopState,
    shell: Arc<FakeShell>,
    dir: tempfile::TempDir,
    workspace: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let app = dir.path().join("app");
    std::fs::create_dir_all(&app).unwrap();
    let paths = AppPaths::new(app);
    Prefs {
        port: 0,
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(FakeShell::default());
    let state = DesktopState::open(
        paths,
        shell.clone(),
        StateOptions {
            clipboard_ttl: Duration::from_secs(60),
            clock: None,
        },
    )
    .await
    .expect("open");
    state
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
    let input = serde_json::from_value(
        json!({ "slug": "shop", "name": "Shop", "description": "", "aliases": [] }),
    )
    .expect("ws");
    let workspace = ops::workspace_put(&state, MAIN, None, input)
        .await
        .expect("workspace")
        .id;
    Fixture {
        state,
        shell,
        dir,
        workspace,
    }
}

fn code<T>(result: IpcResult<T>) -> String {
    result.err().map(|e: IpcError| e.code).unwrap_or_default()
}

fn csv_request(f: &Fixture, path: &str) -> CsvImportRequest {
    CsvImportRequest {
        path: path.to_owned(),
        workspace_id: f.workspace.clone(),
        source: CsvSource::Auto,
        environment: Environment::Staging,
        role_label: None,
        mapping: CsvMapping::default(),
        duplicates: DuplicatePolicy::Skip,
    }
}

const CHROME: &str =
    "name,url,username,password,note\r\nfake.test,https://fake.test,fake.user,zq-fake-pw,\r\n";

/// AUD-11: a path the webview made up is refused. Only a path the native dialog returned works.
#[tokio::test]
async fn aud11_csv_preview_refuses_a_path_the_dialog_did_not_return() {
    let f = fixture().await;
    let file = f.dir.path().join("secrets.csv");
    std::fs::write(&file, CHROME).unwrap();
    let text = file.to_str().unwrap();
    let missing = f.dir.path().join("missing.csv");
    // A real file and a missing file give the same answer: no hint about what exists.
    let real = ops::csv_preview(&f.state, MAIN, csv_request(&f, text))
        .await
        .unwrap_err();
    let none = ops::csv_preview(&f.state, MAIN, csv_request(&f, missing.to_str().unwrap()))
        .await
        .unwrap_err();
    assert_eq!(real, none);
    assert_eq!(real.code, "validation_failed");
    assert_eq!(
        code(ops::csv_import(&f.state, MAIN, csv_request(&f, text)).await),
        "validation_failed"
    );
}

/// AUD-11: a path that the native dialog returned can be read, until the next lock.
#[tokio::test]
async fn aud11_a_picked_path_works_until_the_vault_locks() {
    let f = fixture().await;
    let file = f.dir.path().join("secrets.csv");
    std::fs::write(&file, CHROME).unwrap();
    *f.shell.pick.lock().unwrap() = Some(file.clone());
    let text = ops::file_pick_open(&f.state, MAIN, Some("Pick".into()), vec!["csv".into()])
        .await
        .unwrap()
        .expect("a path");
    assert_eq!(text, file.to_str().unwrap());
    let preview = ops::csv_preview(&f.state, MAIN, csv_request(&f, &text))
        .await
        .expect("picked file");
    assert_eq!(preview.total_rows, 1);
    // Another file next to it is still refused.
    let other = f.dir.path().join("other.csv");
    std::fs::write(&other, CHROME).unwrap();
    assert_eq!(
        code(ops::csv_preview(&f.state, MAIN, csv_request(&f, other.to_str().unwrap())).await),
        "validation_failed"
    );
    // A dropped file comes from the OS and counts like a picked one.
    f.state.note_dropped(std::slice::from_ref(&other));
    ops::csv_preview(&f.state, MAIN, csv_request(&f, other.to_str().unwrap()))
        .await
        .expect("dropped file");
    ops::vault_lock(&f.state, MAIN).await.unwrap();
    assert_eq!(
        code(ops::csv_preview(&f.state, MAIN, csv_request(&f, &text)).await),
        "vault_locked"
    );
    // Only the main window may open the dialog.
    assert_eq!(
        code(ops::file_pick_open(&f.state, "approval", None, Vec::new()).await),
        "window_not_allowed"
    );
}

/// AUD-11: the lock forgets the picked paths. After the next unlock, both the picked and the
/// dropped path are refused (the `vault_locked` answer above comes from the operator check, so it
/// does not prove this).
#[tokio::test]
async fn aud11_the_lock_clears_the_picked_paths() {
    let f = fixture().await;
    let picked = f.dir.path().join("picked.csv");
    let dropped = f.dir.path().join("dropped.csv");
    std::fs::write(&picked, CHROME).unwrap();
    std::fs::write(&dropped, CHROME).unwrap();
    *f.shell.pick.lock().unwrap() = Some(picked.clone());
    let picked_text = ops::file_pick_open(&f.state, MAIN, None, Vec::new())
        .await
        .unwrap()
        .expect("a path");
    f.state.note_dropped(std::slice::from_ref(&dropped));
    let dropped_text = dropped.to_str().unwrap();
    for text in [picked_text.as_str(), dropped_text] {
        ops::csv_preview(&f.state, MAIN, csv_request(&f, text))
            .await
            .expect("known before the lock");
    }
    ops::vault_lock(&f.state, MAIN).await.unwrap();
    let id = ops::vault_list_operators(&f.state, MAIN).await.unwrap()[0]
        .id
        .clone();
    ops::vault_unlock(
        &f.state,
        MAIN,
        id,
        cerberus_desktop::dto::Secret::new(PHRASE.into()),
    )
    .await
    .expect("unlock");
    for text in [picked_text.as_str(), dropped_text] {
        assert_eq!(
            code(ops::csv_preview(&f.state, MAIN, csv_request(&f, text)).await),
            "validation_failed",
            "{text} was forgotten at the lock"
        );
    }
    // Picking again works.
    ops::file_pick_open(&f.state, MAIN, None, Vec::new())
        .await
        .unwrap();
    ops::csv_preview(&f.state, MAIN, csv_request(&f, &picked_text))
        .await
        .expect("picked again");
}

/// AUD-11: the other readers of a path use the same rule.
#[tokio::test]
async fn aud11_other_readers_refuse_unpicked_paths() {
    let f = fixture().await;
    let key = f.dir.path().join("id_fake");
    std::fs::write(&key, "not a key").unwrap();
    let source: ops::SshKeySource =
        serde_json::from_value(json!({ "kind": "path", "path": key.to_str().unwrap() })).unwrap();
    let error = ops::ssh_key_import(&f.state, MAIN, source, None)
        .await
        .unwrap_err();
    // The same text as any other path problem: the key file was not even opened.
    assert_eq!(error.code, "validation_failed");
    assert_eq!(error.fields[0].problem, "cannot be used");
    let unlock =
        serde_json::from_value(json!({ "kind": "recovery", "recovery_key": "XXXX-XXXX-XXXX" }))
            .unwrap();
    assert_eq!(
        code(ops::backup_restore(&f.state, MAIN, key.display().to_string(), unlock).await),
        "validation_failed"
    );
    assert_eq!(
        code(
            ops::tls_load_custom(
                &f.state,
                MAIN,
                key.display().to_string(),
                key.display().to_string()
            )
            .await
        ),
        "validation_failed"
    );
}

/// AUD-13: while the server listens on a LAN address, a new key has no mTLS binding, so it is refused.
#[tokio::test]
async fn aud13_no_new_key_without_a_binding_on_a_lan_bind() {
    let f = fixture().await;
    let agent: cerberus_desktop::dto::AgentInputView =
        serde_json::from_value(json!({ "name": "bot", "description": "" })).unwrap();
    let key = || -> cerberus_desktop::dto::AgentKeyInputView {
        serde_json::from_value(json!({
            "scopes": ["catalog:read"], "lifetime_days": 30, "ip_allowlist": []
        }))
        .unwrap()
    };
    let created = ops::agent_create(&f.state, MAIN, agent.clone(), key())
        .await
        .expect("loopback bind: a key without binding is fine");
    let mut prefs = f.state.prefs();
    prefs.bind = vec!["0.0.0.0".parse().unwrap()];
    f.state.set_prefs(prefs).unwrap();
    assert_eq!(
        code(ops::agent_create(&f.state, MAIN, agent, key()).await),
        "validation_failed"
    );
    assert_eq!(
        code(ops::agent_key_create(&f.state, MAIN, created.agent.id.clone(), key()).await),
        "validation_failed"
    );
    let key_id = created.agent.keys[0].id.clone();
    assert_eq!(
        code(ops::agent_key_rotate(&f.state, MAIN, key_id, 0).await),
        "validation_failed"
    );
}

/// AUD-14: lock, panic and quit clear the clipboard while it still holds the copied secret.
#[tokio::test]
async fn aud14_lock_panic_and_quit_clear_our_clipboard_value() {
    let f = fixture().await;
    let token = "cvt_fake.token";
    for round in 0..3 {
        f.state.copy_and_clear(token).expect("copy");
        assert_eq!(f.shell.clipboard_read().as_deref(), Some(token));
        match round {
            0 => ops::vault_lock(&f.state, MAIN).await.expect("lock"),
            1 => {
                let (core, _) = f
                    .state
                    .operator()
                    .await
                    .unwrap_or_else(|_| panic!("session"));
                drop(core);
                ops::vault_panic(&f.state, MAIN).await.expect("panic");
            }
            _ => f.state.shutdown().await,
        }
        assert_eq!(f.shell.clipboard_read(), None, "round {round}");
        if round < 2 {
            let id = ops::vault_list_operators(&f.state, MAIN).await.unwrap()[0]
                .id
                .clone();
            ops::vault_unlock(
                &f.state,
                MAIN,
                id,
                cerberus_desktop::dto::Secret::new(PHRASE.into()),
            )
            .await
            .expect("unlock");
        }
    }
}

/// AUD-14: a value the person copied by hand is not ours and stays.
#[tokio::test]
async fn aud14_lock_keeps_a_clipboard_value_we_did_not_copy() {
    let f = fixture().await;
    f.state.copy_and_clear("cvt_fake.token").expect("copy");
    f.shell.clipboard_write("something else").unwrap();
    ops::vault_lock(&f.state, MAIN).await.expect("lock");
    assert_eq!(f.shell.clipboard_read().as_deref(), Some("something else"));
}

/// AUD-14: the panic hook clears held values and the clipboard without waiting on a lock.
#[tokio::test]
async fn aud14_the_emergency_wipe_clears_held_values_and_the_clipboard() {
    let f = fixture().await;
    f.state.copy_and_clear("cvt_fake.token").expect("copy");
    f.state
        .set_one_time(
            cerberus_desktop::dto::OneTimeKind::RecoveryKey,
            "fake-recovery",
        )
        .await;
    f.state.emergency_wipe();
    assert_eq!(f.shell.clipboard_read(), None);
    assert!(
        f.state
            .one_time(cerberus_desktop::dto::OneTimeKind::RecoveryKey)
            .await
            .is_none()
    );
}
