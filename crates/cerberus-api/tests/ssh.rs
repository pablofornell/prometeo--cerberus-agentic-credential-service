//! `POST /v1/credentials/{id}/ssh-prepare` over real TLS (T22): scope, kind, the answer shape, a
//! real signing socket, its end at lease release, and no private key text in any answer.
// The signing socket is a Unix socket (DEC-T22-7).
#![cfg(unix)]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use cerberus_core::agents::AgentKeyInput;
use cerberus_core::items::{ItemInput, Payload, generate_ed25519};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_types::{Environment, GrantMode, ItemId, Permission, Scope};
use common::{Fixture, assert_error_shape, op_ctx};
use serde_json::json;

fn body() -> String {
    json!({ "purpose": "deploy the build" }).to_string()
}

/// An SSH key item and a `use_ssh` grant for the fixture agent. Returns the item and the Base64
/// lines of its private key text.
async fn ssh_setup(fx: &Fixture) -> (ItemId, Vec<String>) {
    let payload = generate_ed25519("fake-build-01").expect("key");
    let Payload::SshKey { private_key, .. } = &payload else {
        panic!("ssh payload");
    };
    let markers = private_key
        .expose_secret()
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
        .map(str::to_owned)
        .collect();
    let mut custom = BTreeMap::new();
    custom.insert("host".to_owned(), "127.0.0.1".to_owned());
    custom.insert("port".to_owned(), "2222".to_owned());
    custom.insert("user".to_owned(), "ci".to_owned());
    let item = fx
        .core
        .create_item_as_operator(
            &op_ctx(&fx.owner),
            ItemInput {
                workspace_id: fx.workspace,
                title: "Build key".to_owned(),
                description: "fake test key".to_owned(),
                role_label: None,
                category: "SSH key".to_owned(),
                tags: vec![],
                environment: Environment::Dev,
                target: Some("build-01".to_owned()),
                custom,
                expires_at: None,
                max_uses: None,
                payload,
            },
        )
        .await
        .expect("item")
        .summary
        .id;
    let mut permissions = BTreeSet::new();
    permissions.insert(Permission::UseSsh);
    fx.core
        .put_grant(
            &op_ctx(&fx.owner),
            GrantInput {
                id: None,
                agent_id: fx.agent,
                selector: Selector::default(),
                permissions,
                mode: GrantMode::Auto,
                conditions: Conditions::default(),
                allow_prod_auto: false,
            },
        )
        .await
        .expect("grant");
    (item, markers)
}

async fn ssh_token(fx: &Fixture) -> String {
    fx.core
        .create_agent_key(
            &op_ctx(&fx.owner),
            fx.agent,
            AgentKeyInput {
                scopes: vec![Scope::SshUse, Scope::Requests],
                lifetime_days: Some(30),
                ip_allowlist: vec![],
                require_mtls: false,
            },
        )
        .await
        .expect("key")
        .token
        .expose_secret()
        .to_owned()
}

#[tokio::test]
async fn ssh_prepare_opens_a_signing_socket() {
    let fx = Fixture::new().await;
    let (item, markers) = ssh_setup(&fx).await;
    let client = fx.client();
    let path = format!("/v1/credentials/{item}/ssh-prepare");

    // The default test key has no `ssh:use` scope.
    let resp = client.post(&path, &fx.token, &body()).await;
    assert_error_shape(&resp, 403, "insufficient_scope");

    let token = ssh_token(&fx).await;
    // A web login is not an SSH key.
    let web = format!("/v1/credentials/{}/ssh-prepare", fx.item);
    assert_error_shape(
        &client.post(&web, &token, &body()).await,
        422,
        "validation_failed",
    );
    // Unknown fields are refused.
    let extra = json!({ "purpose": "deploy", "socket": "/tmp/x" }).to_string();
    assert_eq!(client.post(&path, &token, &extra).await.status, 400);

    let resp = client.post(&path, &token, &body()).await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let json = resp.json();
    let keys: BTreeSet<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "request_id",
            "socket_path",
            "public_key",
            "fingerprint",
            "host",
            "port",
            "user",
            "expires_at",
            "lease"
        ])
    );
    assert!(json["fingerprint"].as_str().unwrap().starts_with("SHA256:"));
    assert!(
        json["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    assert_eq!(json["host"], "127.0.0.1");
    assert_eq!(json["port"], 2222);
    assert_eq!(json["user"], "ci");
    assert_eq!(json["lease"]["permission"], "use_ssh");
    let text = String::from_utf8_lossy(&resp.body);
    assert!(!text.contains("PRIVATE KEY"));
    for marker in &markers {
        assert!(
            !text.contains(marker.as_str()),
            "no private key text in the answer"
        );
    }
    let socket = std::path::PathBuf::from(json["socket_path"].as_str().unwrap());
    let meta = std::fs::symlink_metadata(&socket).expect("socket exists");
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
    assert_eq!(fx.state.ssh_bridge().socket_count(), 1);

    // Release of the lease closes the socket.
    let lease = json["lease"]["id"].as_str().unwrap().to_owned();
    let resp = client
        .post(&format!("/v1/leases/{lease}/release"), &token, "{}")
        .await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let mut closed = false;
    for _ in 0..100 {
        if !socket.exists() {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(closed, "socket removed after release");

    // The audit export has the events and no private key text.
    let dest = fx.dir.path().join("audit.jsonl");
    fx.core
        .audit_export(&op_ctx(&fx.owner), &dest)
        .await
        .expect("export");
    let audit = std::fs::read_to_string(&dest).expect("read");
    assert!(audit.contains("\"ssh.prepare\""));
    for marker in &markers {
        assert!(!audit.contains(marker.as_str()));
    }

    // Locked: 423 before any body is read.
    fx.lock().await;
    assert_eq!(client.post(&path, &token, &body()).await.status, 423);
    fx.stop().await;
}
