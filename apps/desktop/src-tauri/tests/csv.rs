//! The CSV commands without a window: window labels, roles from the session, file checks, the
//! export file mode, and an import that reads a real file. Fake values only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use cerberus_core::{KeyCustody, NewVault};
use cerberus_crypto::{KdfParams, SecretString};
use cerberus_desktop::dto::{
    CsvImportRequest, CsvMapping, CsvSource, DuplicatePolicy, Environment, OperatorRole, Secret,
};
use cerberus_desktop::error::{IpcError, IpcResult};
use cerberus_desktop::ops;
use cerberus_desktop::{AppPaths, DesktopState, Prefs, Shell, StateOptions};
use serde_json::json;

const MAIN: &str = "main";
const PHRASE: &str = "correct horse battery staple jumbo violet";

/// The fake native dialog returns the path that the test set (AUD-11).
#[derive(Default)]
struct NoShell {
    pick: std::sync::Mutex<Option<std::path::PathBuf>>,
}

impl Shell for NoShell {
    fn pick_file(
        &self,
        _title: Option<&str>,
        _extensions: &[String],
    ) -> Option<std::path::PathBuf> {
        self.pick.lock().unwrap().clone()
    }
    fn clipboard_write(&self, _text: &str) -> IpcResult<()> {
        Ok(())
    }
    fn clipboard_read(&self) -> Option<String> {
        None
    }
    fn clipboard_clear(&self) {}
    fn set_autostart(&self, _enabled: bool) -> IpcResult<()> {
        Ok(())
    }
    fn set_content_protection(&self, _enabled: bool) {}
}

struct Fixture {
    state: DesktopState,
    shell: Arc<NoShell>,
    dir: tempfile::TempDir,
    workspace: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().join("app"));
    std::fs::create_dir_all(dir.path().join("app")).unwrap();
    Prefs {
        port: 0,
        ..Prefs::default()
    }
    .save(&paths)
    .expect("prefs");
    let shell = Arc::new(NoShell::default());
    let state = DesktopState::open(
        paths,
        shell.clone(),
        StateOptions {
            clipboard_ttl: Duration::from_millis(150),
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

/// Makes a file and picks it through the fake dialog, as the person would.
async fn write_csv(f: &Fixture, name: &str, text: &str) -> String {
    let path = f.dir.path().join(name);
    std::fs::write(&path, text).unwrap();
    pick(f, &path).await
}

async fn pick(f: &Fixture, path: &std::path::Path) -> String {
    *f.shell.pick.lock().unwrap() = Some(path.to_path_buf());
    ops::file_pick_open(&f.state, MAIN, None, Vec::new())
        .await
        .expect("pick")
        .expect("a path")
}

fn request(f: &Fixture, path: String) -> CsvImportRequest {
    CsvImportRequest {
        path,
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

#[tokio::test]
async fn preview_then_import_from_a_real_file() {
    let f = fixture().await;
    let path = write_csv(&f, "chrome.csv", CHROME).await;
    let preview = ops::csv_preview(&f.state, MAIN, request(&f, path.clone()))
        .await
        .expect("preview");
    assert_eq!((preview.total_rows, preview.importable), (1, 1));
    let text = serde_json::to_string(&preview).unwrap();
    assert!(!text.contains("zq-fake-pw"), "a preview holds no secret");
    assert_eq!(
        ops::item_list(&f.state, MAIN, Default::default())
            .await
            .unwrap()
            .len(),
        0,
        "a preview writes nothing"
    );
    let report = ops::csv_import(&f.state, MAIN, request(&f, path))
        .await
        .expect("import");
    assert_eq!(report.imported, 1);
    let items = ops::item_list(&f.state, MAIN, Default::default())
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn files_are_checked_before_they_are_read() {
    let f = fixture().await;
    for bad in ["relative.csv", "/tmp/../etc/passwd", "/nonexistent/x.csv"] {
        assert_eq!(
            code(ops::csv_preview(&f.state, MAIN, request(&f, bad.into())).await),
            "validation_failed",
            "{bad}"
        );
    }
    let latin1 = {
        let path = f.dir.path().join("latin1.csv");
        std::fs::write(
            &path,
            b"name,url,username,password\nx,https://a.test,\xe9,p\n",
        )
        .unwrap();
        path
    };
    let latin1 = pick(&f, &latin1).await;
    let error = ops::csv_preview(&f.state, MAIN, request(&f, latin1))
        .await
        .unwrap_err();
    assert_eq!(error.code, "validation_failed");
    assert!(error.fields.iter().any(|p| p.problem.contains("UTF-8")));
    let mut bad = request(&f, write_csv(&f, "ok.csv", CHROME).await);
    bad.workspace_id = "nope".into();
    assert_eq!(
        code(ops::csv_preview(&f.state, MAIN, bad).await),
        "validation_failed"
    );
    let mut bad = request(&f, write_csv(&f, "ok2.csv", CHROME).await);
    bad.mapping.columns.insert("not_a_field".into(), "x".into());
    assert_eq!(
        code(ops::csv_preview(&f.state, MAIN, bad).await),
        "validation_failed"
    );
}

#[tokio::test]
async fn only_the_main_window_may_call() {
    let f = fixture().await;
    let path = write_csv(&f, "chrome.csv", CHROME).await;
    for label in ["approval", "evil", ""] {
        assert_eq!(
            code(ops::csv_preview(&f.state, label, request(&f, path.clone())).await),
            "window_not_allowed"
        );
        assert_eq!(
            code(ops::csv_import(&f.state, label, request(&f, path.clone())).await),
            "window_not_allowed"
        );
        assert_eq!(
            code(ops::csv_export(&f.state, label, "/tmp/x.csv".into(), None).await),
            "window_not_allowed"
        );
    }
}

#[tokio::test]
async fn export_writes_a_private_file_for_the_owner_only() {
    let f = fixture().await;
    let path = write_csv(&f, "chrome.csv", CHROME).await;
    ops::csv_import(&f.state, MAIN, request(&f, path))
        .await
        .expect("import");
    let dest = f.dir.path().join("out.csv");
    let dest_text = dest.to_str().unwrap().to_owned();
    assert_eq!(
        code(ops::csv_export(&f.state, MAIN, "relative.csv".into(), None).await),
        "validation_failed"
    );
    assert_eq!(
        ops::csv_export(&f.state, MAIN, dest_text.clone(), Some(f.workspace.clone()))
            .await
            .expect("export"),
        1
    );
    let text = std::fs::read_to_string(&dest).unwrap();
    assert!(
        text.contains("zq-fake-pw"),
        "the export holds the secret in plain text"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        code(ops::csv_export(&f.state, MAIN, dest_text, None).await),
        "conflict",
        "an existing file is never overwritten"
    );

    // An operator and a viewer cannot export, whatever the UI sends.
    for (label, role, may_import) in [
        ("op", OperatorRole::Operator, true),
        ("view", OperatorRole::Viewer, false),
    ] {
        let phrase = format!("another long passphrase for {label} 9");
        let added = ops::operator_add(
            &f.state,
            MAIN,
            label.into(),
            role,
            Secret::new(phrase.clone()),
        )
        .await
        .expect("add");
        f.state
            .core()
            .unwrap()
            .lock(cerberus_types::LockReason::Manual)
            .await
            .unwrap();
        ops::vault_unlock(&f.state, MAIN, added.id, Secret::new(phrase))
            .await
            .expect("unlock");
        let other = f.dir.path().join(format!("{label}.csv"));
        assert_eq!(
            code(ops::csv_export(&f.state, MAIN, other.to_str().unwrap().into(), None).await),
            "role_not_allowed"
        );
        assert!(!other.exists());
        let file = write_csv(&f, &format!("in-{label}.csv"), CHROME).await;
        let result = ops::csv_import(&f.state, MAIN, request(&f, file)).await;
        if may_import {
            assert!(
                result.is_ok() || code(Err::<(), _>(result.unwrap_err())) == "validation_failed"
            );
        } else {
            assert_eq!(code(result), "role_not_allowed");
        }
        f.state
            .core()
            .unwrap()
            .lock(cerberus_types::LockReason::Manual)
            .await
            .unwrap();
        ops::vault_unlock(
            &f.state,
            MAIN,
            f.state.core().unwrap().list_operators().await.unwrap()[0]
                .id
                .to_string(),
            Secret::new(PHRASE.into()),
        )
        .await
        .expect("owner again");
    }
}
