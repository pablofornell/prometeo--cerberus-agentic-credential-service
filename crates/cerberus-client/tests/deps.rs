//! ADR-0024 rule 4: the client builds without the vault and the server stack.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

/// Crates that must not be in the normal dependency tree of `cerberus-client`.
const FORBIDDEN: [&str; 12] = [
    "axum",
    "sqlx",
    "argon2",
    "tauri",
    "utoipa",
    "rcgen",
    "x509-parser",
    "cerberus-api",
    "cerberus-core",
    "cerberus-store",
    "cerberus-crypto",
    "cerberus-mcp",
];

#[test]
fn the_normal_dependency_tree_has_no_vault_or_server_crates() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "tree",
            "-p",
            "cerberus-client",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--offline",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    let names: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert!(
        names.contains(&"cerberus-types"),
        "the client uses the shared types"
    );
    for banned in FORBIDDEN {
        assert!(
            !names.contains(&banned),
            "{banned} is in the client dependency tree"
        );
    }
}
