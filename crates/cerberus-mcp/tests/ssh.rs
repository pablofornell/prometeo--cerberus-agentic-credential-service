//! `ssh_prepare` over MCP (T22): the scope check, and the same answer as the REST route on the
//! same shared bridge (same socket, same fields, plus `outcome`). No private key text anywhere.
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

use cerberus_core::agents::AgentKeyInput;
use cerberus_core::items::{ItemInput, Payload, generate_ed25519};
use cerberus_core::policy::{Conditions, GrantInput, Selector};
use cerberus_types::{Environment, GrantMode, Permission, Scope};
use common::{Fixture, call, data, error_code, op_ctx, text};
use serde_json::{Value, json};

#[tokio::test]
async fn ssh_prepare_gives_the_same_socket_and_fields_as_rest() {
    let fx = Fixture::new().await;
    let payload = generate_ed25519("fake-build-01").expect("key");
    let Payload::SshKey { private_key, .. } = &payload else {
        panic!("ssh payload");
    };
    let markers: Vec<String> = private_key
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
    fx.core
        .put_grant(
            &op_ctx(&fx.owner),
            GrantInput {
                id: None,
                agent_id: fx.agent,
                selector: Selector::default(),
                permissions: BTreeSet::from([Permission::UseSsh]),
                mode: GrantMode::Auto,
                conditions: Conditions::default(),
                allow_prod_auto: false,
            },
        )
        .await
        .expect("grant");
    let args = json!({"item_id": item.to_string(), "purpose": "deploy the build"});

    // The default test key has no `ssh:use` scope.
    let no_scope = call(&fx.client().await, "ssh_prepare", args.clone()).await;
    assert_eq!(error_code(&no_scope), "insufficient_scope");

    let token = fx
        .core
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
        .to_owned();
    let result = call(&fx.client_with(&token).await, "ssh_prepare", args).await;
    assert_eq!(result.is_error, Some(false), "{result:?}");
    let mcp = data(&result);
    assert_eq!(mcp["outcome"], "ready");
    let shown = text(&result);
    assert!(
        !shown.starts_with("HANDLING:"),
        "no secret value in this answer"
    );

    let http = reqwest::Client::builder()
        .use_preconfigured_tls(fx.tls_config())
        .build()
        .expect("http client");
    let resp = http
        .post(format!(
            "https://localhost:{}/v1/credentials/{item}/ssh-prepare",
            fx.addr.port()
        ))
        .bearer_auth(&token)
        .header("content-type", "application/json")
        .body(json!({"purpose": "deploy the build"}).to_string())
        .send()
        .await
        .expect("rest call");
    assert_eq!(resp.status().as_u16(), 200);
    let rest: Value = serde_json::from_slice(&resp.bytes().await.expect("body")).expect("json");

    let keys = |value: &Value| -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    };
    let mut mcp_keys = keys(&mcp);
    mcp_keys.remove("outcome");
    assert_eq!(mcp_keys, keys(&rest), "same fields as REST");
    for field in [
        "socket_path",
        "public_key",
        "fingerprint",
        "host",
        "port",
        "user",
    ] {
        assert_eq!(mcp[field], rest[field], "{field}");
    }
    assert_eq!(
        mcp["lease"]["id"], rest["lease"]["id"],
        "one lease, one socket"
    );
    assert_eq!(fx.state.ssh_bridge().socket_count(), 1);
    let rest_text = rest.to_string();
    for marker in &markers {
        assert!(!shown.contains(marker.as_str()));
        assert!(!rest_text.contains(marker.as_str()));
    }
    fx.stop().await;
}
