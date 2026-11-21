//! Acceptance suite: scenarios A1 to A12 of docs/PLAN.md section 11, one test each, and A13, the remote admin API of
//! `cerberusd` (ADR-0034).
//!
//! Every test uses the public surface: a real vault on a temporary directory, the real TLS server
//! of `cerberus-api` with `/mcp` mounted, an HTTPS client, an MCP client, and the `cerberus`
//! binary for A12. The clock is a `ManualClock` (A3 moves it by 3600 s). The assertions are the
//! "Pass when" column of the plan. All secret values are fake test values.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod harness;

use std::time::Duration;

use cerberus_client::transport::Request;
use cerberus_client::{EventStream, PinnedHttps, Trust, WireSecret};
use cerberus_core::CoreError;
use cerberus_core::KeyCustody;
use cerberus_core::admin::AuditQuery;
use cerberus_core::audit::ChainReport;
use cerberus_crypto::{RecoveryKey, SecretString};
use cerberus_types::{AccessRequestId, ApprovalOption, Environment, LockReason, Scope};
use harness::remote::{Daemon, bundle_identity};
use harness::{
    ALT_PHRASE, Env, PASSWORD, PHRASE, USERNAME, error_code, mcp_call, mcp_data, op_ctx,
};
use jiff::SignedDuration;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PURPOSE: &str = "Run the checkout test on the shop page";

fn resolve_args() -> Value {
    json!({"app": "shop-frontend", "environment": "staging", "role": "admin", "purpose": PURPOSE})
}

async fn audit_rows(env: &Env, event_type: &str) -> usize {
    env.core
        .audit_query(
            &op_ctx(&env.owner),
            AuditQuery {
                event_type: Some(event_type.to_owned()),
                limit: 500,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit")
        .len()
}

/// A1: create the vault, lock, unlock; a wrong phrase fails; the recovery key unlocks.
#[tokio::test]
async fn a01_wrong_phrase_fails_and_the_recovery_key_unlocks() {
    let env = Env::new().await;
    env.core.lock(LockReason::Manual).await.expect("lock");
    // Locked: the server says so and gives no data.
    let health = env.rest.get("/v1/health", None).await;
    assert_eq!(health.status, 200);
    assert_eq!(health.json["vault"], "locked", "{}", health.json);
    // A wrong phrase fails and the vault stays locked.
    let wrong = env
        .core
        .unlock_with_phrase(env.owner_id, SecretString::new(ALT_PHRASE.to_owned()))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)), "{wrong:?}");
    assert_eq!(
        env.rest.get("/v1/status", Some(&env.token)).await.status,
        423
    );
    // The right phrase unlocks.
    env.core
        .unlock_with_phrase(env.owner_id, SecretString::new(PHRASE.to_owned()))
        .await
        .expect("unlock");
    assert_eq!(
        env.rest.get("/v1/status", Some(&env.token)).await.status,
        200
    );
    // The recovery key unlocks a locked vault, and a made-up one does not.
    env.core.lock(LockReason::Manual).await.expect("lock");
    let other = RecoveryKey::generate().expect("key");
    assert!(matches!(
        env.core.unlock_with_recovery(other).await,
        Err(CoreError::BadCredentials)
    ));
    let key = RecoveryKey::parse(env.recovery_key.expose_secret()).expect("parse");
    env.core.unlock_with_recovery(key).await.expect("recovery");
    assert_eq!(
        env.rest.get("/v1/status", Some(&env.token)).await.status,
        200
    );
    env.stop().await;
}

/// A2: `resolve` for the shop gives user and password in one response, and an audit event exists.
/// Checked on REST and on MCP.
#[tokio::test]
async fn a02_resolve_gives_user_and_password_in_one_response_and_audits() {
    let env = Env::new().await;
    let resp = env
        .rest
        .post(
            "/v1/credentials/resolve",
            Some(&env.token),
            &json!({"app": "shop-frontend", "environment": "staging", "role": "admin",
                    "purpose": PURPOSE, "mode": "best"}),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.json);
    assert_eq!(resp.json["secret"]["username"], USERNAME);
    assert_eq!(resp.json["secret"]["password"], PASSWORD);
    assert_eq!(audit_rows(&env, "item.reveal").await, 1);

    let client = env.mcp().await;
    let result = mcp_call(&client, "get_credential", resolve_args()).await;
    assert_eq!(result.is_error, Some(false), "{result:?}");
    let body = mcp_data(&result);
    assert_eq!(body["secret"]["username"], USERNAME);
    assert_eq!(body["secret"]["password"], PASSWORD);
    assert_eq!(audit_rows(&env, "item.reveal").await, 2);
    env.stop().await;
}

/// A3: a session token with `ttl_seconds: 3600` exists, and after 3600 s on the test clock it is gone.
#[tokio::test]
async fn a03_session_with_ttl_is_gone_after_the_ttl() {
    let env = Env::new().await;
    let created = env
        .rest
        .post(
            "/v1/sessions",
            Some(&env.token),
            &json!({"workspace": "shop-frontend", "title": "Checkout session",
                    "environment": "staging", "ttl_seconds": 3600,
                    "payload": {"kind": "session_token", "token": "canary-session-a03"}}),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.json);
    let id = created.json["item"]["id"].as_str().expect("id").to_owned();
    let reveal = format!("/v1/credentials/{id}/reveal");
    let body = json!({"purpose": PURPOSE});

    env.clock.advance(SignedDuration::from_secs(3599));
    let still = env.rest.post(&reveal, Some(&env.token), &body).await;
    assert_eq!(still.status, 200, "the item exists at 3599 s");
    assert_eq!(still.json["secret"]["token"], "canary-session-a03");

    env.clock.advance(SignedDuration::from_secs(1));
    let gone = env.rest.post(&reveal, Some(&env.token), &body).await;
    assert_eq!(
        gone.status, 404,
        "the item is gone at 3600 s: {}",
        gone.json
    );
    let catalog = env.rest.get("/v1/credentials", Some(&env.token)).await;
    assert!(
        !catalog.json.to_string().contains("Checkout session"),
        "{}",
        catalog.json
    );
    env.stop().await;
}

/// A4: the agent asks for the SSH key of machine "build-01" and gets a signing socket (T22).
/// The private key never appears.
#[cfg(unix)]
#[tokio::test]
async fn a04_ssh_key_of_build_01_gives_a_signing_socket() {
    let mut env = Env::new().await;
    let markers = env.add_ssh_machine("build-01").await;
    let token = env
        .agent_token(&[Scope::SshUse, Scope::Requests, Scope::CatalogRead])
        .await;
    let client = env.mcp_with(&token).await;
    // The agent finds the machine by name, then asks for its key.
    let candidates = mcp_call(
        &client,
        "find_credentials",
        json!({"app": "build-01", "kind": "ssh_key", "purpose": PURPOSE}),
    )
    .await;
    assert_eq!(candidates.is_error, Some(false), "{candidates:?}");
    let id = mcp_data(&candidates)["candidates"][0]["item"]["id"]
        .as_str()
        .expect("candidate id")
        .to_owned();
    assert_eq!(id, env.ssh_item.to_string());
    let found = mcp_call(
        &client,
        "ssh_prepare",
        json!({"item_id": id, "purpose": PURPOSE}),
    )
    .await;
    assert_eq!(found.is_error, Some(false), "{found:?}");
    let body = mcp_data(&found);
    assert_eq!(body["outcome"], "ready", "{body}");
    let socket = body["socket_path"].as_str().expect("socket path");
    // The socket speaks the ssh-agent protocol: REQUEST_IDENTITIES (11) gives IDENTITIES_ANSWER (12) with one key.
    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .expect("connect");
    stream.write_all(&[0, 0, 0, 1, 11]).await.expect("write");
    let mut len = [0_u8; 4];
    stream.read_exact(&mut len).await.expect("length");
    let mut reply = vec![0_u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut reply).await.expect("reply");
    assert_eq!(reply[0], 12, "IDENTITIES_ANSWER");
    assert_eq!(
        u32::from_be_bytes(reply[1..5].try_into().expect("count")),
        1
    );
    let shown = body.to_string();
    for marker in &markers {
        assert!(!shown.contains(marker.as_str()), "no private key text");
    }
    env.stop().await;
}

/// A5: the vault is locked and the agent calls routes: HTTP 423 and no data.
#[tokio::test]
async fn a05_locked_vault_gives_423_and_no_data() {
    let env = Env::new().await;
    env.core.lock(LockReason::Manual).await.expect("lock");
    let routes: [(&str, &str, Option<Value>); 5] = [
        ("GET", "/v1/status", None),
        ("GET", "/v1/credentials", None),
        (
            "POST",
            "/v1/credentials/resolve",
            Some(json!({"app": "shop-frontend", "environment": "staging",
            "role": "admin", "purpose": PURPOSE, "mode": "best"})),
        ),
        (
            "POST",
            "/v1/credentials/0190f000-0000-7000-8000-000000000001/reveal",
            Some(json!({"purpose": PURPOSE})),
        ),
        (
            "POST",
            "/v1/sessions",
            Some(json!({"workspace": "shop-frontend", "title": "x",
            "environment": "staging", "payload": {"kind": "session_token", "token": "t"}})),
        ),
    ];
    for (method, path, body) in routes {
        let resp = env
            .rest
            .send(method, path, Some(&env.token), body.as_ref())
            .await;
        assert_eq!(resp.status, 423, "{method} {path}: {}", resp.json);
        assert_eq!(resp.json["error"]["code"], "vault_locked");
        let text = resp.json.to_string();
        assert!(
            !text.contains(PASSWORD) && !text.contains(USERNAME),
            "no data"
        );
    }
    // The MCP endpoint says the same and also gives no data.
    let client = env.mcp().await;
    let result = mcp_call(&client, "get_credential", resolve_args()).await;
    assert_eq!(error_code(&result), "vault_locked");
    assert!(!format!("{result:?}").contains(PASSWORD));
    env.stop().await;
}

/// A6: a `prod` item opens an approval window. A deny gives 403. An approve gives a lease.
#[tokio::test]
async fn a06_prod_item_needs_approval_deny_gives_403_approve_gives_a_lease() {
    let env = Env::new().await;
    let denied_item = env.prod_item("Shop admin prod one").await;
    let approved_item = env.prod_item("Shop admin prod two").await;
    let body = json!({"purpose": PURPOSE});

    // Deny.
    let path = format!("/v1/credentials/{denied_item}/reveal");
    let first = env.rest.post(&path, Some(&env.token), &body).await;
    assert_eq!(
        first.status, 202,
        "an approval window opens: {}",
        first.json
    );
    assert_eq!(first.json["access_request"]["status"], "pending");
    assert!(!first.json.to_string().contains(PASSWORD));
    let id: AccessRequestId = first.json["access_request"]["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("request id");
    let pending = env
        .core
        .pending_requests(&op_ctx(&env.owner))
        .await
        .expect("pending");
    assert!(
        pending.iter().any(|p| p.view.id == id),
        "the window shows in the approval list"
    );
    env.core
        .deny_request(&op_ctx(&env.owner), id)
        .await
        .expect("deny");
    let denied = env.rest.post(&path, Some(&env.token), &body).await;
    assert_eq!(denied.status, 403, "{}", denied.json);
    assert_eq!(denied.json["error"]["code"], "approval_denied");
    assert!(!denied.json.to_string().contains(PASSWORD));

    // Approve.
    let path = format!("/v1/credentials/{approved_item}/reveal");
    let first = env.rest.post(&path, Some(&env.token), &body).await;
    assert_eq!(first.status, 202);
    let id: AccessRequestId = first.json["access_request"]["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("request id");
    env.core
        .approve_request(&op_ctx(&env.owner), id, ApprovalOption::Once)
        .await
        .expect("approve");
    let granted = env.rest.post(&path, Some(&env.token), &body).await;
    assert_eq!(granted.status, 200, "{}", granted.json);
    assert!(
        granted.json["lease"]["id"].is_string(),
        "a lease: {}",
        granted.json
    );
    assert_eq!(granted.json["secret"]["password"], PASSWORD);

    // The same window over MCP: a person approves while the agent waits.
    let third = env.prod_item("Shop admin prod three").await;
    let client = env.mcp().await;
    let args = json!({"id": third.to_string(), "purpose": PURPOSE, "wait_seconds": 20});
    let waiting = {
        let client = client.peer().clone();
        tokio::spawn(async move { mcp_call(&client, "get_credential", args).await })
    };
    let request = env.wait_for_pending().await;
    env.core
        .approve_request(&op_ctx(&env.owner), request, ApprovalOption::Once)
        .await
        .expect("approve");
    let result = waiting.await.expect("join");
    assert_eq!(result.is_error, Some(false), "{result:?}");
    let data = mcp_data(&result);
    assert_eq!(data["outcome"], "secret");
    assert!(data["lease"]["id"].is_string());
    env.stop().await;
}

/// A7: the database file as bytes has no secret, no title and no description in plain text.
#[tokio::test]
async fn a07_the_database_file_has_no_plaintext() {
    let env = Env::new().await;
    let (title, description, secret, user) = (
        "Zebra-Quasar-Title-9137",
        "Nebula-Description-4471",
        "Canary-Secret-Value-8826",
        "Canary-Login-User-5519",
    );
    let item = harness::web_login(
        env.workspace,
        title,
        Environment::Staging,
        (description, user, secret),
    );
    env.core
        .create_item_as_operator(&op_ctx(&env.owner), item)
        .await
        .expect("item");
    // Use the item through the agent, so audit rows and leases exist as well.
    let found = env
        .rest
        .post(
            "/v1/credentials/resolve",
            Some(&env.token),
            &json!({"app": "shop-frontend", "environment": "staging", "role": "admin",
                    "purpose": PURPOSE, "mode": "best"}),
        )
        .await;
    assert_eq!(found.status, 200, "{}", found.json);
    env.core.lock(LockReason::Manual).await.expect("lock");
    let mut checked = 0;
    for name in ["vault.cerberus", "vault.cerberus-wal", "vault.cerberus-shm"] {
        let Ok(bytes) = std::fs::read(env.dir.path().join(name)) else {
            continue;
        };
        checked += bytes.len();
        for needle in [
            title,
            description,
            secret,
            user,
            PASSWORD,
            USERNAME,
            "Shop admin login",
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{name} holds the plain text {needle}"
            );
        }
    }
    assert!(checked > 4096, "the vault file was read ({checked} bytes)");
    env.stop().await;
}

/// A8: TLS 1.2 fails. Plain HTTP fails.
#[tokio::test]
async fn a08_tls12_and_plain_http_both_fail() {
    let env = Env::new().await;
    let config = harness::client_config(&env.ca_der, &[&rustls::version::TLS12]);
    let tcp = tokio::net::TcpStream::connect(env.addr).await.expect("tcp");
    let tls12 = tokio_rustls::TlsConnector::from(config)
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").expect("name"),
            tcp,
        )
        .await;
    assert!(tls12.is_err(), "a TLS 1.2 handshake must fail");
    // TLS 1.3 works on the same port, so the failure is the version.
    let good = harness::client_config(&env.ca_der, &[&rustls::version::TLS13]);
    let tcp = tokio::net::TcpStream::connect(env.addr).await.expect("tcp");
    assert!(
        tokio_rustls::TlsConnector::from(good)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").expect("name"),
                tcp
            )
            .await
            .is_ok()
    );

    let mut plain = tokio::net::TcpStream::connect(env.addr).await.expect("tcp");
    plain
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write");
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), plain.read_to_end(&mut got)).await;
    assert!(read.is_ok(), "the server closes a plain connection");
    assert!(
        !String::from_utf8_lossy(&got).contains("HTTP/1"),
        "no HTTP answer to plain HTTP"
    );
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(
            harness::client_config(&env.ca_der, &[&rustls::version::TLS13])
                .as_ref()
                .clone(),
        )
        .build()
        .expect("http client")
        .get(format!("http://127.0.0.1:{}/v1/health", env.addr.port()))
        .timeout(Duration::from_secs(10))
        .send()
        .await;
    assert!(
        http.map_or(true, |r| !r.status().is_success()),
        "plain HTTP gives no success"
    );
    env.stop().await;
}

/// A9: one audit row is changed in the file; verify reports the broken position.
#[tokio::test]
async fn a09_a_changed_audit_row_is_reported_at_its_position() {
    let env = Env::new().await;
    for _ in 0..3 {
        let resp = env
            .rest
            .post(
                "/v1/credentials/resolve",
                Some(&env.token),
                &json!({"app": "shop-frontend", "environment": "staging", "role": "admin",
                        "purpose": PURPOSE, "mode": "best"}),
            )
            .await;
        assert_eq!(resp.status, 200);
    }
    let ctx = op_ctx(&env.owner);
    assert!(matches!(
        env.core.audit_verify(&ctx).await.expect("verify"),
        ChainReport::Ok { .. }
    ));
    let rows = env
        .core
        .audit_query(
            &ctx,
            AuditQuery {
                event_type: Some("item.reveal".to_owned()),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("rows");
    assert_eq!(rows.len(), 3);
    let target = rows[1].seq;
    env.tamper_audit_row(target).await;
    match env
        .core
        .audit_verify(&op_ctx(&env.owner))
        .await
        .expect("verify")
    {
        ChainReport::Broken { seq, .. } => assert_eq!(seq, target, "the broken position"),
        other @ ChainReport::Ok { .. } => panic!("the change was not found: {other:?}"),
    }
    env.stop().await;
}

/// A10: revoke an agent key; the next call gives 401 at once.
#[tokio::test]
async fn a10_a_revoked_key_gives_401_on_the_next_call() {
    let env = Env::new().await;
    assert_eq!(
        env.rest.get("/v1/status", Some(&env.token)).await.status,
        200
    );
    let client = env.mcp().await;
    assert_eq!(
        mcp_call(&client, "get_credential", resolve_args())
            .await
            .is_error,
        Some(false)
    );
    env.core
        .revoke_agent_key(&op_ctx(&env.owner), env.key_id)
        .await
        .expect("revoke");
    let resp = env.rest.get("/v1/status", Some(&env.token)).await;
    assert_eq!(resp.status, 401, "{}", resp.json);
    assert_eq!(resp.json["error"]["code"], "unauthenticated");
    let resolve = env
        .rest
        .post(
            "/v1/credentials/resolve",
            Some(&env.token),
            &json!({"app": "shop-frontend",
            "environment": "staging", "role": "admin", "purpose": PURPOSE, "mode": "best"}),
        )
        .await;
    assert_eq!(resolve.status, 401);
    // A new MCP session with the revoked key does not open.
    assert!(env.try_mcp(&env.token).await.is_err());
    env.stop().await;
}

/// A11: an agent without `write` stores a secret: HTTP 403.
#[tokio::test]
async fn a11_an_agent_without_write_gets_403() {
    let env = Env::new().await;
    let create = json!({"workspace": "shop-frontend", "title": "New key", "environment": "staging",
        "payload": {"kind": "api_key", "key": "canary-key-a11"}});
    let resp = env
        .rest
        .post("/v1/credentials", Some(&env.token), &create)
        .await;
    assert_eq!(resp.status, 403, "{}", resp.json);
    assert_eq!(resp.json["error"]["code"], "forbidden");
    // Nothing was stored.
    let found = env.rest.get("/v1/credentials", Some(&env.token)).await;
    assert!(!found.json.to_string().contains("New key"));
    // The same through MCP.
    let client = env.mcp().await;
    let result = mcp_call(
        &client,
        "store_secret",
        json!({"kind": "api_key", "workspace": "shop-frontend", "title": "New key",
               "environment": "staging", "value": "canary-key-a11"}),
    )
    .await;
    assert_eq!(error_code(&result), "forbidden");
    env.stop().await;
}

/// A12: `cerberus run --app shop -- env`: the child sees the variable, the agent output does not.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a12_the_child_sees_the_variable_and_the_agent_output_does_not() {
    let env = Env::new().await;
    let seen = env.dir.path().join("child-saw.txt");
    let script = format!(
        r#"printf %s "$CERBERUS_PASSWORD" > '{}'; env"#,
        seen.display()
    );
    let out = env
        .cli(&[
            "run", "--app", "shop", "--env", "staging", "--role", "admin", "--", "sh", "-c",
            &script,
        ])
        .await;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(&seen).expect("child file"),
        PASSWORD,
        "the child sees it"
    );
    for (label, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(!text.contains(PASSWORD), "{label} shows the password");
        assert!(!text.contains(USERNAME), "{label} shows the username");
    }
    assert!(
        stdout.contains("CERBERUS_PASSWORD=[REDACTED]"),
        "the output has the mask: {stdout}"
    );
    assert!(
        !stdout.contains(&env.token),
        "the token does not reach the child"
    );
    env.stop().await;
}

/// A13 (ADR-0034): remote admin through a real `cerberusd`. The admin API is off unless turned on; an admin call needs
/// an enrolled device certificate and an operator session; items and approvals work over it as the operator; closing a
/// session leaves the vault open for agents; a revoke takes the device out at once; a remote lock locks the agents out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a13_remote_admin_through_cerberusd() {
    // 1. A daemon with the admin API off has no admin route at all.
    let off = Daemon::start(false).await;
    let reply = off
        .client(None)
        .send("GET", "/admin/v1/hello", None, None)
        .await;
    assert_eq!(reply.status, 404, "{}", reply.json);
    assert_eq!(reply.json["error"]["code"], "route_not_found");
    off.stop().await;

    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let (cert, key) = bundle_identity(&bundle);
    let admin = daemon.client(Some((&cert, &key)));
    let agent = daemon.client(None);
    let operator = bundle.operator_id.to_string();
    assert_eq!(operator, daemon.seed.owner.to_string());

    // 2. The device gate: no certificate, or a CA-signed agent certificate, is refused before anything else.
    let bare = agent.send("GET", "/admin/v1/hello", None, None).await;
    assert_eq!(bare.status, 403);
    assert_eq!(bare.json["error"]["code"], "admin_cert_required");
    let (agent_cert, agent_key) = &daemon.seed.agent_identity;
    let agent_device = daemon
        .client(Some((agent_cert, agent_key)))
        .send("GET", "/admin/v1/hello", None, None)
        .await;
    assert_eq!(agent_device.status, 403);
    assert_eq!(agent_device.json["error"]["code"], "admin_cert_required");
    let hello = admin.send("GET", "/admin/v1/hello", None, None).await;
    assert_eq!(hello.status, 200, "{}", hello.json);
    assert_eq!(hello.json["admin_protocol"], 1);
    assert_eq!(hello.json["vault_state"], "unlocked");

    // 3. The person gate: no session, a wrong phrase, then the right one.
    let no_session = admin.rpc("item_list", None, &json!({ "filter": {} })).await;
    assert_eq!(no_session.status, 401);
    assert_eq!(no_session.json["error"]["code"], "admin_session_required");
    let wrong = admin
        .send(
            "POST",
            "/admin/v1/session",
            None,
            Some(&json!({ "operator_id": operator, "phrase": ALT_PHRASE })),
        )
        .await;
    assert_eq!(wrong.status, 401, "{}", wrong.json);
    assert_eq!(wrong.json["error"]["code"], "bad_credentials");
    let opened = admin
        .send(
            "POST",
            "/admin/v1/session",
            None,
            Some(&json!({ "operator_id": operator, "phrase": PHRASE })),
        )
        .await;
    assert_eq!(opened.status, 200, "{}", opened.json);
    let token = opened.json["token"].as_str().expect("token").to_owned();
    assert!(token.starts_with("cas_"));

    // 4. Items through the admin API, audited with the operator as the actor.
    let workspaces = admin.rpc("workspace_list", Some(&token), &json!({})).await;
    assert_eq!(workspaces.status, 200);
    let workspace = workspaces.json[0]["id"]
        .as_str()
        .expect("workspace")
        .to_owned();
    let created = admin
        .rpc(
            "item_create",
            Some(&token),
            &json!({ "input": {
                "workspace_id": workspace, "title": "Remote login", "description": "", "role_label": null,
                "category": "Web login", "tags": [], "environment": "dev", "target": null, "custom": {},
                "expires_at": null, "max_uses": null,
                "payload": { "kind": "web_login", "username": USERNAME, "password": PASSWORD, "url": null, "totp": null }
            } }),
        )
        .await;
    assert_eq!(created.status, 200, "{}", created.json);
    let item = created.json["summary"]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let listed = admin
        .rpc("item_list", Some(&token), &json!({ "filter": {} }))
        .await;
    assert!(
        listed
            .json
            .as_array()
            .expect("list")
            .iter()
            .any(|i| i["id"] == item.as_str())
    );
    let revealed = admin
        .rpc("item_reveal", Some(&token), &json!({ "item": item }))
        .await;
    assert_eq!(revealed.status, 200);
    assert_eq!(revealed.json["payload"]["password"], PASSWORD);
    let reveals = admin
        .rpc(
            "audit_query",
            Some(&token),
            &json!({ "query": { "event_type": "item.reveal", "limit": 50 } }),
        )
        .await;
    assert_eq!(reveals.status, 200, "{}", reveals.json);
    assert!(
        reveals
            .json
            .as_array()
            .expect("rows")
            .iter()
            .any(|row| { row["actor_kind"] == "operator" && row["actor_id"] == operator.as_str() }),
        "{}",
        reveals.json
    );
    let opens = admin
        .rpc(
            "audit_query",
            Some(&token),
            &json!({ "query": { "event_type": "admin.session_open", "limit": 50 } }),
        )
        .await;
    assert_eq!(
        opens.json.as_array().expect("rows").len(),
        1,
        "{}",
        opens.json
    );

    // 5. Approvals over the admin channel: the desktop-side client (`PinnedHttps`, pinned CA, the bundle's
    //    certificate) follows the event stream, sees the agent's request and approves it.
    let files = daemon.dir.path().join("desktop");
    std::fs::create_dir_all(&files).expect("desktop dir");
    let (cert_file, key_file, ca_file) = (
        files.join("cert.pem"),
        files.join("key.pem"),
        files.join("ca.pem"),
    );
    std::fs::write(&cert_file, &bundle.client_cert_pem).expect("cert file");
    std::fs::write(&key_file, bundle.client_key_pem.expose()).expect("key file");
    std::fs::set_permissions(
        &key_file,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");
    std::fs::write(&ca_file, &bundle.ca_cert_pem).expect("ca file");
    let pinned = PinnedHttps::with_client_cert(
        &bundle.url,
        &Trust::CaFileAndPin {
            ca: ca_file,
            pin: bundle.ca_pin.clone(),
        },
        (cert_file, key_file),
        Duration::from_secs(30),
    )
    .expect("pinned transport");
    let bearer = WireSecret::new(token.clone());
    let stream = pinned
        .send_bearer(Request::get("/admin/v1/events"), Some(&bearer))
        .await
        .expect("event stream");
    assert_eq!(stream.status(), 200);
    let mut events = EventStream::new(stream);
    let reveal_path = format!("/v1/credentials/{}/reveal", daemon.seed.prod_item);
    let purpose = json!({ "purpose": PURPOSE });
    let pending = agent
        .send(
            "POST",
            &reveal_path,
            Some(&daemon.seed.token),
            Some(&purpose),
        )
        .await;
    assert_eq!(pending.status, 202, "{}", pending.json);
    let request = pending.json["access_request"]["id"]
        .as_str()
        .expect("request")
        .to_owned();
    let seen = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = events.next().await {
            let (name, data) = event.expect("event");
            if name == "AccessRequestCreated" {
                let data: Value = serde_json::from_slice(&data).expect("json");
                return Some(data["id"].as_str().unwrap_or_default().to_owned());
            }
        }
        None
    })
    .await
    .expect("the request event in time");
    assert_eq!(seen.as_deref(), Some(request.as_str()));
    let approved = admin
        .rpc(
            "request_approve",
            Some(&token),
            &json!({ "request": request, "option": "once" }),
        )
        .await;
    assert_eq!(approved.status, 200, "{}", approved.json);
    let read = agent
        .send(
            "POST",
            &reveal_path,
            Some(&daemon.seed.token),
            Some(&purpose),
        )
        .await;
    assert_eq!(read.status, 200, "{}", read.json);
    assert!(read.json.to_string().contains(PASSWORD));
    drop(events);

    // 6. Closing the session does not lock: the agents keep working, the old token is dead.
    let closed = admin
        .send("DELETE", "/admin/v1/session", Some(&token), None)
        .await;
    assert_eq!(closed.status, 204);
    assert_eq!(agent.get_status(&daemon.seed.token).await, 200);
    let stale = admin
        .rpc("item_list", Some(&token), &json!({ "filter": {} }))
        .await;
    assert_eq!(stale.status, 401);

    // 7. A revoke takes the device out at once.
    daemon.revoke(&bundle).await;
    let revoked = admin.send("GET", "/admin/v1/hello", None, None).await;
    assert_eq!(revoked.status, 403);
    assert_eq!(revoked.json["error"]["code"], "admin_cert_required");

    // 8. `vault_lock` from a session of another enrolled desktop locks the server vault: agents get 423.
    let second = daemon.enroll("second").await;
    let (cert, key) = bundle_identity(&second);
    let other = daemon.client(Some((&cert, &key)));
    let session = other
        .send(
            "POST",
            "/admin/v1/session",
            None,
            Some(&json!({ "operator_id": operator, "phrase": PHRASE })),
        )
        .await;
    assert_eq!(session.status, 200, "{}", session.json);
    let token = session.json["token"].as_str().expect("token").to_owned();
    let locked = other.rpc("vault_lock", Some(&token), &json!({})).await;
    assert_eq!(locked.status, 200, "{}", locked.json);
    assert_eq!(agent.get_status(&daemon.seed.token).await, 423);
    let after = other
        .rpc("item_list", Some(&token), &json!({ "filter": {} }))
        .await;
    assert_eq!(after.status, 401);
    daemon.stop().await;
}
