//! Contract tests of the IPC surface: the bindings file is current, every command of
//! `docs/interfaces.md` section 9 exists, the capability files and the label guard agree, every
//! command checks its window label first, and the remote allowlist names IPC commands with their
//! IPC argument names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use cerberus_admin::remote::REMOTE_COMMANDS;
use cerberus_admin::rpc::arg_names;
use cerberus_desktop::guard::{ALL_COMMANDS, APPROVAL_COMMANDS};
use cerberus_desktop::{BINDINGS_PATH, export_bindings};

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(manifest(path)).expect("read file")
}

/// The command names of the table in section 9 of the interfaces document.
fn documented_commands() -> BTreeSet<String> {
    let doc = read("../../../docs/interfaces.md");
    let section = doc
        .split("## 9. Tauri IPC commands")
        .nth(1)
        .expect("section 9");
    section
        .lines()
        .filter(|line| line.starts_with("| `"))
        .filter_map(|line| line.split('`').nth(1))
        .map(ToOwned::to_owned)
        .collect()
}

fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in name.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn bindings_file_is_up_to_date() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fresh = dir.path().join("bindings.ts");
    export_bindings(&fresh).expect("export");
    let fresh = std::fs::read_to_string(fresh).expect("read fresh");
    let target = PathBuf::from(BINDINGS_PATH);
    if std::env::var_os("CERBERUS_UPDATE_BINDINGS").is_some() {
        std::fs::write(&target, &fresh).expect("write bindings");
    }
    let current = std::fs::read_to_string(&target).expect("bindings.ts exists");
    assert!(
        current == fresh,
        "bindings.ts is out of date: run `CERBERUS_UPDATE_BINDINGS=1 cargo test -p cerberus-desktop --test contract`"
    );
}

#[test]
fn every_documented_command_exists_and_nothing_is_undocumented_but_the_added_ones() {
    let documented = documented_commands();
    assert_eq!(documented.len(), 66, "interfaces.md lists 66 commands");
    let ours: BTreeSet<String> = ALL_COMMANDS.iter().map(|s| (*s).to_owned()).collect();
    let missing: Vec<_> = documented.difference(&ours).collect();
    assert!(missing.is_empty(), "missing commands: {missing:?}");
    let added: Vec<_> = ours.difference(&documented).collect();
    assert_eq!(
        added,
        [
            "clipboard_copy_once",
            "file_pick_open",
            "rustdesk_connect",
            "rustdesk_status",
            "vault_recover_stranded"
        ],
        "added commands"
    );
}

#[test]
fn bindings_hold_every_command_and_event() {
    let bindings = read("../ui/src/bindings.ts");
    for name in ALL_COMMANDS {
        assert!(
            bindings.contains(&format!("\t{}: (", camel(name))),
            "bindings.ts has no `{name}`"
        );
    }
    for event in [
        "vaultStateChanged",
        "accessRequestCreated",
        "accessRequestResolved",
        "agentActivity",
        "leaseChanged",
        "autolockTick",
        "massReadAlert",
        "headerMismatch",
        "integrityAlert",
        "pendingCountChanged",
    ] {
        assert!(
            bindings.contains(event),
            "bindings.ts has no event `{event}`"
        );
    }
}

/// The argument names of `command` in its generated `__TAURI_INVOKE` call, in order.
fn invoke_args(bindings: &str, command: &str) -> Vec<String> {
    let call = format!("__TAURI_INVOKE(\"{command}\", ");
    let rest = bindings
        .split(&call)
        .nth(1)
        .unwrap_or_else(|| panic!("bindings.ts has no call of `{command}`"));
    if rest.starts_with("undefined") {
        return Vec::new();
    }
    let inner = rest
        .strip_prefix("{ ")
        .and_then(|r| r.split(" }").next())
        .unwrap_or_else(|| panic!("unexpected arguments of `{command}`"));
    inner.split(", ").map(ToOwned::to_owned).collect()
}

#[test]
fn remote_commands_are_ipc_commands() {
    let bindings = read("../ui/src/bindings.ts");
    for (name, _) in REMOTE_COMMANDS {
        assert!(
            ALL_COMMANDS.contains(&name),
            "`{name}` is not an IPC command"
        );
        let ours: Vec<String> = arg_names(name)
            .unwrap_or_else(|| panic!("`{name}` has no argument names"))
            .iter()
            .map(|arg| camel(arg))
            .collect();
        assert_eq!(invoke_args(&bindings, name), ours, "arguments of `{name}`");
    }
}

fn permissions(file: &str) -> BTreeSet<String> {
    let json: serde_json::Value = serde_json::from_str(&read(file)).expect("json");
    json["permissions"]
        .as_array()
        .expect("permissions")
        .iter()
        .filter_map(|p| p.as_str())
        .filter(|p| p.starts_with("allow-"))
        .map(ToOwned::to_owned)
        .collect()
}

fn allow(name: &str) -> String {
    format!("allow-{}", name.replace('_', "-"))
}

#[test]
fn capability_files_match_the_label_guard() {
    let main: BTreeSet<String> = ALL_COMMANDS.iter().map(|n| allow(n)).collect();
    assert_eq!(permissions("capabilities/main.json"), main);
    let approval: BTreeSet<String> = APPROVAL_COMMANDS.iter().map(|n| allow(n)).collect();
    assert_eq!(permissions("capabilities/approval.json"), approval);
    for file in ["capabilities/main.json", "capabilities/approval.json"] {
        let text = read(file);
        assert!(
            !text.contains("shell:"),
            "{file} must not use the shell plugin"
        );
        assert!(!text.contains("fs:"), "{file} must not use the fs plugin");
    }
}

#[test]
fn every_command_checks_its_window_label_first() {
    let mut sources = String::new();
    for file in [
        "vault", "items", "agents", "policy", "restore", "system", "csv", "rustdesk",
    ] {
        sources.push_str(&read(&format!("src/ops/{file}.rs")));
    }
    for name in ALL_COMMANDS {
        let header = format!("fn {name}(");
        let at = sources
            .find(&header)
            .unwrap_or_else(|| panic!("no ops function `{name}`"));
        let body = &sources[at..];
        let guard = format!("check(window, \"{name}\")?;");
        let first = body
            .find(&guard)
            .unwrap_or_else(|| panic!("`{name}` has no label check"));
        // The check is the first statement: nothing but the signature comes before it.
        let open = body.find('{').expect("open brace");
        assert!(
            body[open + 1..first].trim().is_empty(),
            "`{name}` does something before its label check"
        );
    }
}

#[test]
fn tauri_config_is_strict() {
    let conf: serde_json::Value = serde_json::from_str(&read("tauri.conf.json")).expect("json");
    let csp = conf["app"]["security"]["csp"].as_str().expect("csp");
    assert!(!csp.contains("unsafe-eval"), "no unsafe-eval");
    assert!(
        !csp.contains("unsafe-inline"),
        "no unsafe-inline in the release CSP"
    );
    assert!(
        !csp.contains("http://") || csp.contains("http://ipc.localhost"),
        "no remote http"
    );
    assert!(!csp.contains("https:"), "no remote https");
    assert!(csp.contains("object-src 'none'"));
    let cargo = read("Cargo.toml");
    assert!(!cargo.contains("tauri-plugin-shell"), "no shell plugin");
    assert!(
        !cargo.contains("\"devtools\""),
        "devtools stays off in release"
    );
}

/// AUD-12: no window gets the whole `core:default` set. Each window lists the exact core
/// permissions it uses, and none of the risky ones (tray, image from path, emit).
#[test]
fn capabilities_list_exact_core_permissions() {
    let used = |file: &str| -> BTreeSet<String> {
        let json: serde_json::Value = serde_json::from_str(&read(file)).expect("json");
        json["permissions"]
            .as_array()
            .expect("permissions")
            .iter()
            .filter_map(|p| p.as_str())
            .filter(|p| p.starts_with("core:") || p.starts_with("dialog:"))
            .map(ToOwned::to_owned)
            .collect()
    };
    for file in ["capabilities/main.json", "capabilities/approval.json"] {
        let text = read(file);
        assert!(
            !text.contains("core:default"),
            "{file} must not use core:default"
        );
        for risky in ["tray", "image", "emit", "menu", "resources", "path"] {
            assert!(
                !used(file).iter().any(|p| p.contains(risky)),
                "{file} grants a {risky} permission"
            );
        }
    }
    assert_eq!(
        used("capabilities/approval.json"),
        BTreeSet::from(
            ["core:event:allow-listen", "core:event:allow-unlisten"].map(ToOwned::to_owned)
        )
    );
    // The JS dialogs only choose where to write (a new file, a folder). Files to read come from
    // `file_pick_open`, so the backend knows which path the person chose (AUD-11).
    let main = used("capabilities/main.json");
    assert!(main.contains("dialog:allow-save") && main.contains("dialog:allow-open"));
    // The UI scale setting zooms the main webview. The approval window is a fixed popup and has no such permission
    // (the exact-set check above).
    assert!(main.contains("core:webview:allow-set-webview-zoom"));
}

/// AUD-15: the approval window gets the content protection setting when it is made. The Tauri
/// window builder has no getter and the mock runtime ignores the flag, so this reads the builder
/// chain of `show_approval`: the call must exist on that chain, take the value read from the
/// saved setting, and not a constant `false`.
#[test]
fn approval_window_is_built_with_content_protection() {
    let windows = read("src/windows.rs");
    let start = windows
        .find("WebviewWindowBuilder::new(")
        .expect("the approval window builder");
    let chain = &windows[start..start + windows[start..].find(".build()").expect("build")];
    assert!(
        chain.contains("APPROVAL_WINDOW"),
        "the first builder in windows.rs is the approval window"
    );
    assert_eq!(
        chain.matches(".content_protected(").count(),
        1,
        "the approval window builder sets content protection exactly once"
    );
    assert!(
        chain.contains(".content_protected(protected)"),
        "the approval window must pass the `protected` value, not a constant"
    );
    // `protected` comes from the saved setting of the managed state, and the default is not a
    // value that turns protection off for a window made later.
    let binding_start = windows
        .find("let protected =")
        .expect("the protected binding");
    let binding = &windows[binding_start..start];
    assert!(
        binding.contains("try_state::<crate::DesktopState>")
            && binding.contains("prefs().content_protection"),
        "`protected` must be the content_protection setting: {binding}"
    );
    assert!(
        !binding.contains("false") && !binding.contains("true"),
        "`protected` must not be a constant: {binding}"
    );
}
