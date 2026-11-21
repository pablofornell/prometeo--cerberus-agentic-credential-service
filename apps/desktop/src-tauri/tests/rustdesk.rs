//! The RustDesk commands (DEC-RD-3) without a window: a fake shell records what would be started,
//! so no test ever runs a program.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerberus_core::{KeyCustody, NewVault};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_desktop::dto::{ItemInputView, RustdeskClientKind, RustdeskPasswordCopy};
use cerberus_desktop::error::{IpcError, IpcResult};
use cerberus_desktop::ops;
use cerberus_desktop::{AppPaths, DesktopState, Prefs, Shell, StateOptions};
use serde_json::{Value, json};

const MAIN: &str = "main";
const PHRASE: &str = "correct horse battery staple jumbo violet";
const ID: &str = "123456789";

#[derive(Default)]
struct FakeShell {
    clipboard: Mutex<Option<String>>,
    launched: Mutex<Vec<(PathBuf, Vec<String>)>>,
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
    fn launch(&self, program: &Path, args: &[String]) -> IpcResult<()> {
        self.launched
            .lock()
            .unwrap()
            .push((program.to_path_buf(), args.to_vec()));
        Ok(())
    }
}

struct Fixture {
    state: DesktopState,
    shell: Arc<FakeShell>,
    dir: tempfile::TempDir,
    workspace: String,
}

impl Fixture {
    fn launched(&self) -> Vec<(PathBuf, Vec<String>)> {
        self.shell.launched.lock().unwrap().clone()
    }

    fn clipboard(&self) -> Option<String> {
        self.shell.clipboard.lock().unwrap().clone()
    }

    /// A file named `name` in the test folder that counts as a program (mode 0755).
    fn program(&self, name: &str) -> PathBuf {
        let path = self.dir.path().join("bin").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    async fn choose(&self, value: Value) -> IpcResult<Value> {
        ops::settings_set(&self.state, MAIN, "rustdesk_path".to_owned(), value)
            .await
            .map(|view| view.values["rustdesk_path"].clone())
    }

    async fn item(&self, kind_payload: Value, custom: Value) -> String {
        self.titled("My laptop", kind_payload, custom).await
    }

    async fn titled(&self, title: &str, kind_payload: Value, custom: Value) -> String {
        let input: ItemInputView = serde_json::from_value(json!({
            "workspace_id": self.workspace, "title": title, "description": "",
            "role_label": null, "category": "Remote desktop", "tags": [], "environment": "other",
            "target": null, "custom": custom, "expires_at": null, "max_uses": null,
            "payload": kind_payload
        }))
        .expect("input");
        ops::item_create(&self.state, MAIN, input)
            .await
            .expect("create")
            .summary
            .id
    }
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().join("app"));
    std::fs::create_dir_all(&paths.data_dir).unwrap();
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
            clipboard_ttl: Duration::from_secs(30),
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
        json!({ "slug": "home", "name": "Home", "description": "", "aliases": [] }),
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

fn laptop() -> (Value, Value) {
    (
        json!({ "kind": "rustdesk", "password": "fake-rd-password" }),
        json!({ "rustdesk_id": ID, "id_server": "rd.example.test" }),
    )
}

#[tokio::test]
async fn connect_starts_the_chosen_client_with_the_id_and_copies_the_password() {
    let f = fixture().await;
    let program = f.program("rustdesk");
    assert_eq!(
        f.choose(Value::String(program.display().to_string()))
            .await
            .unwrap(),
        Value::String(program.display().to_string())
    );
    let status = ops::rustdesk_status(&f.state, MAIN).await.unwrap();
    assert_eq!(
        status.client.as_ref().map(|c| c.kind),
        Some(RustdeskClientKind::Custom)
    );

    let (payload, custom) = laptop();
    let item = f.item(payload, custom).await;
    let done = ops::rustdesk_connect(&f.state, MAIN, item.clone(), true)
        .await
        .unwrap();
    assert_eq!(done.client.kind, RustdeskClientKind::Custom);
    assert_eq!(done.password, RustdeskPasswordCopy::Copied);
    assert_eq!(
        f.launched(),
        [(
            program.clone(),
            vec!["--connect".to_owned(), format!("{ID}@rd.example.test")]
        )],
        "the ID server of the item goes with the ID (DEC-RD-6)"
    );
    assert!(
        f.launched()
            .iter()
            .all(|(_, args)| !args.iter().any(|a| a.contains("fake-rd-password"))),
        "the password never goes on the command line"
    );
    assert_eq!(f.clipboard().as_deref(), Some("fake-rd-password"));

    // Without the copy the clipboard is left alone and the reveal count does not grow.
    f.shell.clipboard_clear();
    let before = ops::item_get(&f.state, MAIN, item.clone())
        .await
        .unwrap()
        .use_count;
    let done = ops::rustdesk_connect(&f.state, MAIN, item.clone(), false)
        .await
        .unwrap();
    assert_eq!(done.password, RustdeskPasswordCopy::Skipped);
    assert_eq!(f.clipboard(), None);
    assert_eq!(
        ops::item_get(&f.state, MAIN, item).await.unwrap().use_count,
        before
    );
    assert_eq!(f.launched().len(), 2);
}

#[tokio::test]
async fn the_key_goes_with_a_named_server_and_an_ipv6_server_stays_out() {
    let f = fixture().await;
    let program = f.program("rustdesk");
    f.choose(Value::String(program.display().to_string()))
        .await
        .unwrap();
    let keyed = f
        .titled(
            "Keyed",
            json!({ "kind": "rustdesk", "password": null }),
            json!({ "rustdesk_id": ID, "id_server": "rd.example.test:21116",
                    "relay_server": "relay.example.test", "server_key": "FAKE+KEY/FAKE=" }),
        )
        .await;
    let ipv6 = f
        .titled(
            "IPv6",
            json!({ "kind": "rustdesk", "password": null }),
            json!({ "rustdesk_id": ID, "id_server": "[2001:db8::1]:21116", "server_key": "FAKE=" }),
        )
        .await;
    let keyless = f
        .titled(
            "Keyless",
            json!({ "kind": "rustdesk", "password": null }),
            json!({ "rustdesk_id": ID, "server_key": "FAKE=" }),
        )
        .await;
    for item in [keyed, ipv6, keyless] {
        ops::rustdesk_connect(&f.state, MAIN, item, false)
            .await
            .unwrap();
    }
    let peers: Vec<String> = f
        .launched()
        .into_iter()
        .map(|(_, args)| args[1].clone())
        .collect();
    assert_eq!(
        peers,
        [
            format!("{ID}@rd.example.test:21116?key=FAKE+KEY/FAKE="),
            ID.to_owned(),
            ID.to_owned()
        ]
    );
}

#[tokio::test]
async fn a_server_that_could_read_as_an_option_is_refused_at_save() {
    let f = fixture().await;
    let input: ItemInputView = serde_json::from_value(json!({
        "workspace_id": f.workspace, "title": "Laptop", "description": "", "role_label": null,
        "category": "Remote desktop", "tags": [], "environment": "other", "target": null,
        "custom": { "rustdesk_id": ID, "id_server": "-oProxyCommand=x" }, "expires_at": null,
        "max_uses": null, "payload": { "kind": "rustdesk", "password": null }
    }))
    .unwrap();
    let error = ops::item_create(&f.state, MAIN, input).await.unwrap_err();
    assert!(
        error.fields.iter().any(|p| p.field == "custom.id_server"),
        "{:?}",
        error.fields
    );
}

#[tokio::test]
async fn an_item_without_a_password_says_so_and_other_kinds_are_refused() {
    let f = fixture().await;
    let program = f.program("RustDesk-1.4.2-x86_64.AppImage");
    f.choose(Value::String(program.display().to_string()))
        .await
        .unwrap();
    let item = f
        .item(
            json!({ "kind": "rustdesk", "password": null }),
            json!({ "rustdesk_id": ID }),
        )
        .await;
    let done = ops::rustdesk_connect(&f.state, MAIN, item, true)
        .await
        .unwrap();
    assert_eq!(done.password, RustdeskPasswordCopy::NotStored);
    assert_eq!(f.clipboard(), None);

    let note: ItemInputView = serde_json::from_value(json!({
        "workspace_id": f.workspace, "title": "Note", "description": "", "role_label": null,
        "category": "Other", "tags": [], "environment": "dev", "target": null,
        "custom": { "rustdesk_id": ID }, "expires_at": null, "max_uses": null,
        "payload": { "kind": "note", "text": "fake" }
    }))
    .unwrap();
    let note = ops::item_create(&f.state, MAIN, note)
        .await
        .unwrap()
        .summary
        .id;
    assert_eq!(
        code(ops::rustdesk_connect(&f.state, MAIN, note, true).await),
        "validation_failed"
    );
    assert_eq!(f.launched().len(), 1, "nothing started for the note");
}

#[tokio::test]
async fn a_missing_client_starts_nothing_and_a_bad_program_is_refused() {
    let f = fixture().await;
    let program = f.program("rustdesk");
    f.choose(Value::String(program.display().to_string()))
        .await
        .unwrap();
    std::fs::remove_file(&program).unwrap();
    let status = ops::rustdesk_status(&f.state, MAIN).await.unwrap();
    assert_eq!(status.client, None);
    assert_eq!(status.custom_path, Some(program.display().to_string()));

    let (payload, custom) = laptop();
    let item = f.item(payload, custom).await;
    assert_eq!(
        code(ops::rustdesk_connect(&f.state, MAIN, item, true).await),
        "unavailable"
    );
    assert!(f.launched().is_empty());
    assert_eq!(f.clipboard(), None, "no password without a client");

    let other = f.program("not-rustdesk");
    for bad in [
        Value::String(other.display().to_string()),
        Value::String("rustdesk".to_owned()),
        Value::String(program.display().to_string()),
        json!(7),
    ] {
        assert_eq!(code(f.choose(bad).await), "validation_failed");
    }
    assert_eq!(f.choose(Value::Null).await.unwrap(), Value::Null);
    assert_eq!(
        code(ops::rustdesk_status(&f.state, "approval").await),
        "window_not_allowed"
    );
}

#[tokio::test]
async fn the_id_is_required_checked_and_searchable() {
    let f = fixture().await;
    let bad: ItemInputView = serde_json::from_value(json!({
        "workspace_id": f.workspace, "title": "Laptop", "description": "", "role_label": null,
        "category": "Remote desktop", "tags": [], "environment": "other", "target": null,
        "custom": { "rustdesk_id": "123 456 789" }, "expires_at": null, "max_uses": null,
        "payload": { "kind": "rustdesk", "password": null }
    }))
    .unwrap();
    let error = ops::item_create(&f.state, MAIN, bad).await.unwrap_err();
    assert_eq!(error.code, "validation_failed");
    assert!(
        error.fields.iter().any(|p| p.field == "custom.rustdesk_id"),
        "{:?}",
        error.fields
    );

    let (payload, custom) = laptop();
    let item = f.item(payload, custom).await;
    let filter = serde_json::from_value(json!({ "q": ID })).unwrap();
    let found = ops::item_list(&f.state, MAIN, filter).await.unwrap();
    assert_eq!(
        found.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
        [item.as_str()]
    );
    assert_eq!(found[0].custom["rustdesk_id"], ID);
}
