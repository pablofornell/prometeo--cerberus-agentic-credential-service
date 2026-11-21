//! The admin API under `/admin/v1` (ADR-0034, threat model TB-10, invariants 8 to 10), over real
//! TLS with admin and agent certificates from the vault CA. The log canary is in
//! `admin_logging.rs` (it needs the global log subscriber of its own process).
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::time::Duration;

use cerberus_admin::clients::{AdminClient, AdminClients, EnrolmentId};
use cerberus_api::{AdminLimits, AdminState};
use cerberus_core::admin::AuditQuery;
use cerberus_core::vault::KeyCustody;
use cerberus_crypto::SecretString;
use cerberus_types::{Environment, OperatorId, OperatorRole, Stopwatch, VaultStateKind};
use common::{
    Client, Fixture, Options, PASSWORD, PHRASE, Resp, assert_error_shape, op_ctx, read_events,
    web_login,
};
use jiff::SignedDuration;
use serde_json::{Value, json};

const SECOND_PHRASE: &str = "lantern quartz meadow ripple 9";

/// An admin fixture: the admin API on, one enrolment of the owner.
async fn admin_fixture(manual_clock: bool) -> (Fixture, EnrolmentId, Client) {
    let fx = Fixture::with(Options {
        admin: true,
        manual_clock,
        ..Options::default()
    })
    .await;
    let owner = fx.owner_label_id;
    let (id, client) = enroll(&fx, owner, "laptop");
    (fx, id, client)
}

fn now(fx: &Fixture) -> jiff::Timestamp {
    fx.core.clock().now()
}

/// Enrols a new desktop bound to `operator` and returns a client with its certificate.
fn enroll(fx: &Fixture, operator: OperatorId, label: &str) -> (EnrolmentId, Client) {
    let ca = fx.ca.as_ref().expect("ca");
    let id = EnrolmentId::generate();
    let cert = ca
        .issue_admin_client(&id.to_string(), now(fx))
        .expect("admin cert");
    let entry = AdminClient::enrolled(
        id,
        label.to_owned(),
        operator,
        &cert.cert_der,
        cert.not_after,
        now(fx),
    )
    .expect("entry");
    fx.admin
        .as_ref()
        .expect("admin")
        .enroll(entry)
        .expect("enroll");
    let client = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    (id, client)
}

fn agent_cert_client(fx: &Fixture) -> Client {
    let ca = fx.ca.as_ref().expect("ca");
    let cert = ca.issue_client(fx.agent, now(fx)).expect("agent cert");
    Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    )
}

/// The admin error shape: `{ request_id, error: IpcError }`.
fn assert_admin_error(resp: &Resp, status: u16, code: &str) {
    assert_eq!(
        resp.status,
        status,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let json = resp.json();
    assert_eq!(json["error"]["code"], code, "{json}");
    assert!(json["error"]["message"].is_string());
    assert!(json["error"]["fields"].is_array());
    assert_eq!(
        json["request_id"].as_str(),
        resp.header("x-request-id").as_deref()
    );
    assert_eq!(json.as_object().map(serde_json::Map::len), Some(2));
}

async fn rpc(client: &Client, command: &str, token: Option<&str>, body: &Value) -> Resp {
    client
        .send(
            "POST",
            &format!("/admin/v1/rpc/{command}"),
            token,
            &[],
            Some(&body.to_string()),
        )
        .await
}

async fn open(client: &Client, operator: OperatorId, phrase: &str) -> Resp {
    let body = json!({ "operator_id": operator.to_string(), "phrase": phrase }).to_string();
    client
        .send("POST", "/admin/v1/session", None, &[], Some(&body))
        .await
}

async fn session(client: &Client, fx: &Fixture) -> String {
    let resp = open(client, fx.owner_label_id, PHRASE).await;
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    resp.json()["token"].as_str().expect("token").to_owned()
}

async fn failed_unlocks(fx: &Fixture) -> u32 {
    fx.core.status().await.failed_unlocks
}

async fn audit_rows(fx: &Fixture, ty: &str) -> Vec<cerberus_core::admin::AuditEntry> {
    fx.core
        .audit_query(
            &op_ctx(&fx.owner),
            AuditQuery {
                from: None,
                to: None,
                event_type: Some(ty.to_owned()),
                agent_id: None,
                item_id: None,
                outcome: None,
                before_seq: None,
                limit: 100,
                text: None,
            },
        )
        .await
        .expect("audit")
}

fn advance(fx: &Fixture, seconds: i64) {
    fx.clock
        .as_ref()
        .expect("manual clock")
        .advance(SignedDuration::from_secs(seconds));
}

const ADMIN_PATHS: [(&str, &str); 5] = [
    ("GET", "/admin/v1/hello"),
    ("POST", "/admin/v1/session"),
    ("DELETE", "/admin/v1/session"),
    ("POST", "/admin/v1/rpc/vault_status"),
    ("GET", "/admin/v1/events"),
];

// ------------------------------------------------------------------------------------------ 1

#[tokio::test]
async fn g01_without_admin_config_every_admin_path_is_route_not_found() {
    let fx = Fixture::with(Options {
        keep_ca: true,
        client_ca: true,
        ..Options::default()
    })
    .await;
    // Even an admin certificate signed by the vault CA finds no admin route (invariant 8).
    let ca = fx.ca.as_ref().expect("ca");
    let cert = ca.issue_admin_client("x", now(&fx)).expect("cert");
    let with_cert = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    for client in [fx.client(), with_cert] {
        for (method, path) in ADMIN_PATHS.iter().copied().chain([
            ("GET", "/admin"),
            ("GET", "/admin/v1"),
            ("POST", "/admin/v2/rpc/x"),
        ]) {
            let body = (method == "POST").then_some("{}");
            let resp = client.send(method, path, None, &[], body).await;
            assert_error_shape(&resp, 404, "route_not_found");
        }
    }
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 2

#[tokio::test]
async fn g02_only_a_live_enrolled_certificate_passes_the_device_check() {
    let (fx, _, admin) = admin_fixture(false).await;
    assert_eq!(admin.get("/admin/v1/hello", "").await.status, 200);
    // No client certificate: every admin route refuses it first.
    let bare = fx.client();
    for (method, path) in ADMIN_PATHS {
        let body = (method == "POST").then_some("{}");
        let resp = bare.send(method, path, None, &[], body).await;
        assert_admin_error(&resp, 403, "admin_cert_required");
    }
    // A CA-signed agent certificate is not enrolled (E-15).
    let agent = agent_cert_client(&fx);
    assert_admin_error(
        &agent.get("/admin/v1/hello", "").await,
        403,
        "admin_cert_required",
    );
    // The agent certificate still works for its agent API.
    assert_eq!(agent.get("/v1/status", &fx.token).await.status, 200);
    // A revoked enrolment, with a live session and an open event stream.
    let (revoked, revoked_client) = enroll(&fx, fx.owner_label_id, "old laptop");
    let token = session(&revoked_client, &fx).await;
    let (status, _, stream) = revoked_client
        .send_stream("GET", "/admin/v1/events", Some(&token), &[], None)
        .await;
    assert_eq!(status, 200);
    let state = fx.admin.as_ref().expect("admin");
    assert!(state.revoke(&fx.core, revoked).await.expect("revoke"));
    assert!(!state.revoke(&fx.core, revoked).await.expect("again"));
    let started = Stopwatch::start();
    let _ = read_events(stream, 100, Duration::from_secs(10)).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the stream ends at revoke"
    );
    assert_admin_error(
        &revoked_client.get("/admin/v1/hello", "").await,
        403,
        "admin_cert_required",
    );
    assert_eq!(audit_rows(&fx, "admin.client_revoke").await.len(), 1);
    let closes = audit_rows(&fx, "admin.session_close").await;
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].event.details["reason"], "revoked");
    // An expired enrolment.
    let ca = fx.ca.as_ref().expect("ca");
    let id = EnrolmentId::generate();
    let cert = ca
        .issue_admin_client(&id.to_string(), now(&fx))
        .expect("cert");
    let expired = AdminClient::enrolled(
        id,
        "expired".to_owned(),
        fx.owner_label_id,
        &cert.cert_der,
        now(&fx) - SignedDuration::from_secs(1),
        now(&fx) - SignedDuration::from_hours(1),
    )
    .expect("entry");
    state.enroll(expired).expect("enroll");
    let client = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    assert_admin_error(
        &client.get("/admin/v1/hello", "").await,
        403,
        "admin_cert_required",
    );
    // The vault is still unlocked: a revoke never locks (invariant 10).
    assert_eq!(fx.core.state(), VaultStateKind::Unlocked);
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 3

#[tokio::test]
async fn g03_the_device_alone_opens_hello_and_the_two_pre_session_commands() {
    let (fx, _, admin) = admin_fixture(false).await;
    let hello = admin.get("/admin/v1/hello", "").await;
    assert_eq!(hello.status, 200);
    let body = hello.json();
    assert_eq!(body["admin_protocol"], 1);
    assert_eq!(body["vault_state"], "unlocked");
    assert_eq!(body["server_version"], cerberus_api::VERSION);
    assert_eq!(body["remote_commands"].as_array().map(Vec::len), Some(25));
    let status = rpc(&admin, "vault_status", None, &json!({})).await;
    assert_eq!(status.status, 200);
    assert_eq!(status.json()["state"], "unlocked");
    let operators = rpc(&admin, "vault_list_operators", None, &json!({})).await;
    assert_eq!(operators.status, 200);
    assert_eq!(operators.json().as_array().map(Vec::len), Some(1));
    // Sealed: the pre-session commands still answer.
    fx.lock().await;
    let status = rpc(&admin, "vault_status", None, &json!({})).await;
    assert_eq!(status.json()["state"], "sealed");
    assert_eq!(
        admin.get("/admin/v1/hello", "").await.json()["vault_state"],
        "sealed"
    );
    fx.unlock().await;
    // Everything else needs a session.
    for (command, body) in [
        ("item_list", json!({ "filter": {} })),
        ("vault_lock", json!({})),
        ("request_list_pending", json!({})),
    ] {
        assert_admin_error(
            &rpc(&admin, command, None, &body).await,
            401,
            "admin_session_required",
        );
    }
    assert_admin_error(
        &admin.send("GET", "/admin/v1/events", None, &[], None).await,
        401,
        "admin_session_required",
    );
    assert_admin_error(
        &admin
            .send("DELETE", "/admin/v1/session", None, &[], None)
            .await,
        401,
        "admin_session_required",
    );
    assert_eq!(fx.core.state(), VaultStateKind::Unlocked);
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 4

#[tokio::test]
async fn g04_session_open_checks_the_phrase_and_the_bound_operator() {
    let (fx, enrolment, admin) = admin_fixture(false).await;
    // Wrong phrase: 401 bad_credentials, one more failed unlock in the shared counter.
    let before = failed_unlocks(&fx).await;
    let wrong = open(&admin, fx.owner_label_id, "not the phrase at all 1").await;
    assert_admin_error(&wrong, 401, "bad_credentials");
    assert_eq!(failed_unlocks(&fx).await, before + 1);
    // The recovery key is not a session credential: the unlock arguments only.
    let body = json!({ "operator_id": fx.owner_label_id.to_string(), "recovery_key": "x" });
    let resp = admin
        .send(
            "POST",
            "/admin/v1/session",
            None,
            &[],
            Some(&body.to_string()),
        )
        .await;
    assert_admin_error(&resp, 400, "invalid_request");
    // Unlocked by the same operator: a session, and the vault session is the same.
    let unlocked_at = fx.core.status().await.session.expect("session").unlocked_at;
    let resp = open(&admin, fx.owner_label_id, PHRASE).await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let answer = resp.json();
    assert!(answer["token"].as_str().expect("token").starts_with("cas_"));
    assert_eq!(
        answer["session"]["operator_id"],
        fx.owner_label_id.to_string()
    );
    assert_eq!(answer["idle_seconds"], 900);
    assert_eq!(answer["max_seconds"], 43_200);
    assert_eq!(
        fx.core.status().await.session.expect("session").unlocked_at,
        unlocked_at
    );
    assert_eq!(
        failed_unlocks(&fx).await,
        0,
        "a good phrase resets the counter"
    );
    // Sealed: the session open unlocks the vault for that operator.
    fx.lock().await;
    let resp = open(&admin, fx.owner_label_id, PHRASE).await;
    assert_eq!(resp.status, 200);
    assert_eq!(fx.core.state(), VaultStateKind::Unlocked);
    let opens = audit_rows(&fx, "admin.session_open").await;
    assert_eq!(opens.len(), 2);
    assert!(
        opens
            .iter()
            .all(|row| row.event.details["label"] == "laptop"
                && row.event.target.as_ref().map(|t| t.id.clone()) == Some(enrolment.to_string()))
    );
    assert_eq!(
        opens
            .iter()
            .filter(|row| row.event.details["unlocked"] == true)
            .count(),
        1
    );
    // A second operator: enrolment of another operator → 403; session of another operator → 409.
    let second = fx
        .core
        .add_operator(
            &op_ctx(&fx.owner),
            "second".to_owned(),
            OperatorRole::Operator,
            SecretString::new(SECOND_PHRASE.to_owned()),
        )
        .await
        .expect("operator");
    let resp = open(&admin, second, SECOND_PHRASE).await;
    assert_admin_error(&resp, 403, "forbidden");
    let (_, second_device) = enroll(&fx, second, "second laptop");
    let resp = open(&second_device, second, SECOND_PHRASE).await;
    assert_admin_error(&resp, 409, "conflict");
    // A bad operator ID is a validation error; a bad body an invalid request.
    let resp = admin
        .send(
            "POST",
            "/admin/v1/session",
            None,
            &[],
            Some(r#"{"operator_id":"nope","phrase":"x"}"#),
        )
        .await;
    assert_admin_error(&resp, 400, "validation_failed");
    let resp = admin
        .send("POST", "/admin/v1/session", None, &[], Some("[]"))
        .await;
    assert_admin_error(&resp, 400, "invalid_request");
    fx.stop().await;
}

#[tokio::test]
async fn g04_six_wrong_phrases_from_one_device_are_refused_before_the_kdf() {
    let (fx, _, admin) = admin_fixture(true).await;
    for n in 1..=5 {
        let resp = open(&admin, fx.owner_label_id, "not the phrase at all 1").await;
        assert_admin_error(&resp, 401, "bad_credentials");
        assert_eq!(failed_unlocks(&fx).await, n);
        // Past the shared back-off of ADR-0026, so only the device limit can refuse.
        advance(&fx, 60);
    }
    let resp = open(&admin, fx.owner_label_id, "not the phrase at all 1").await;
    assert_admin_error(&resp, 429, "too_many_failures");
    assert!(resp.header("retry-after").is_some());
    assert_eq!(failed_unlocks(&fx).await, 5, "no KDF ran");
    // Also the right phrase, while the device is refused.
    let resp = open(&admin, fx.owner_label_id, PHRASE).await;
    assert_admin_error(&resp, 429, "too_many_failures");
    // Another device is not refused by this device's limit.
    let (_, other) = enroll(&fx, fx.owner_label_id, "other laptop");
    assert_eq!(open(&other, fx.owner_label_id, PHRASE).await.status, 200);
    advance(&fx, 15 * 60);
    assert_eq!(open(&admin, fx.owner_label_id, PHRASE).await.status, 200);
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 5

#[tokio::test]
async fn g05_agent_tokens_never_pass_on_admin_and_session_tokens_never_on_v1() {
    let (fx, _, admin) = admin_fixture(false).await;
    let token = session(&admin, &fx).await;
    // A cvt_ agent token on an admin route: no session.
    assert_admin_error(
        &rpc(
            &admin,
            "item_list",
            Some(&fx.token),
            &json!({ "filter": {} }),
        )
        .await,
        401,
        "admin_session_required",
    );
    // A cas_ session token on the agent API: the same 401 as any bad token.
    let resp = fx.client().get("/v1/status", &token).await;
    assert_error_shape(&resp, 401, "unauthenticated");
    let resp = admin.get("/v1/credentials", &token).await;
    assert_error_shape(&resp, 401, "unauthenticated");
    // The session token works where it belongs.
    assert_eq!(
        rpc(&admin, "item_list", Some(&token), &json!({ "filter": {} }))
            .await
            .status,
        200
    );
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 6

#[tokio::test]
async fn g06_a_token_over_another_enrolled_certificate_is_refused() {
    let (fx, _, admin) = admin_fixture(false).await;
    let token = session(&admin, &fx).await;
    let (_, other) = enroll(&fx, fx.owner_label_id, "other laptop");
    assert_admin_error(
        &rpc(&other, "item_list", Some(&token), &json!({ "filter": {} })).await,
        401,
        "admin_session_required",
    );
    // The session itself is not ended by the replay.
    assert_eq!(
        rpc(&admin, "item_list", Some(&token), &json!({ "filter": {} }))
            .await
            .status,
        200
    );
    // A forged secret for the right session ID is refused too.
    let (head, _) = token.split_once('.').expect("shape");
    let forged = format!("{head}.{}", "A".repeat(43));
    assert_admin_error(
        &rpc(&admin, "item_list", Some(&forged), &json!({ "filter": {} })).await,
        401,
        "admin_session_required",
    );
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 7

#[tokio::test]
async fn g07_the_idle_limit_ends_a_session_without_a_lock() {
    let (fx, _, admin) = admin_fixture(true).await;
    let list = json!({ "filter": {} });
    // Idle: 900 s without a call.
    let token = session(&admin, &fx).await;
    advance(&fx, 899);
    assert_eq!(
        rpc(&admin, "item_list", Some(&token), &list).await.status,
        200
    );
    advance(&fx, 899);
    assert_eq!(
        rpc(&admin, "ui_activity", Some(&token), &json!({}))
            .await
            .status,
        200
    );
    advance(&fx, 900);
    assert_admin_error(
        &rpc(&admin, "item_list", Some(&token), &list).await,
        401,
        "admin_session_required",
    );
    assert_eq!(
        fx.core.state(),
        VaultStateKind::Unlocked,
        "expiry never locks"
    );
    // The background pending count does not keep a session alive.
    let token = session(&admin, &fx).await;
    advance(&fx, 600);
    assert_eq!(
        rpc(&admin, "request_list_pending", Some(&token), &json!({}))
            .await
            .status,
        200
    );
    advance(&fx, 400);
    assert_admin_error(
        &rpc(&admin, "item_list", Some(&token), &list).await,
        401,
        "admin_session_required",
    );
    let reasons: Vec<Value> = audit_rows(&fx, "admin.session_close")
        .await
        .into_iter()
        .filter_map(|row| row.event.details.get("reason").cloned())
        .collect();
    assert!(reasons.contains(&json!("idle")), "{reasons:?}");
    fx.stop().await;
}

#[tokio::test]
async fn g07_the_absolute_limit_ends_a_busy_session() {
    // A short absolute limit, so the vault's own 12 h hard lock is not what ends it.
    let fx = Fixture::with(Options {
        admin: true,
        manual_clock: true,
        admin_limits: Some(cerberus_api::AdminLimits {
            session_max_seconds: 3600,
            ..cerberus_api::AdminLimits::default()
        }),
        ..Options::default()
    })
    .await;
    let (_, admin) = enroll(&fx, fx.owner_label_id, "laptop");
    let token = session(&admin, &fx).await;
    let mut elapsed = 0;
    while elapsed + 800 < 3600 {
        advance(&fx, 800);
        elapsed += 800;
        assert_eq!(
            rpc(&admin, "ui_activity", Some(&token), &json!({}))
                .await
                .status,
            200,
            "at {elapsed}"
        );
    }
    advance(&fx, 800);
    assert_admin_error(
        &rpc(&admin, "ui_activity", Some(&token), &json!({})).await,
        401,
        "admin_session_required",
    );
    assert_eq!(
        fx.core.state(),
        VaultStateKind::Unlocked,
        "expiry never locks"
    );
    let reasons: Vec<Value> = audit_rows(&fx, "admin.session_close")
        .await
        .into_iter()
        .filter_map(|row| row.event.details.get("reason").cloned())
        .collect();
    assert_eq!(reasons, vec![json!("max")]);
    fx.stop().await;
}

#[tokio::test]
async fn g07_a_lock_and_a_new_unlock_void_every_session_and_delete_keeps_the_vault() {
    let (fx, _, admin) = admin_fixture(false).await;
    let list = json!({ "filter": {} });
    let (_, other) = enroll(&fx, fx.owner_label_id, "other laptop");
    let first = session(&admin, &fx).await;
    let second = session(&other, &fx).await;
    fx.lock().await;
    fx.unlock().await;
    for (client, token) in [(&admin, &first), (&other, &second)] {
        assert_admin_error(
            &rpc(client, "item_list", Some(token), &list).await,
            401,
            "admin_session_required",
        );
    }
    // DELETE closes the session; the vault stays unlocked and agents keep working.
    let token = session(&admin, &fx).await;
    let resp = admin
        .send("DELETE", "/admin/v1/session", Some(&token), &[], None)
        .await;
    assert_eq!(resp.status, 204);
    assert_eq!(fx.core.state(), VaultStateKind::Unlocked);
    assert_eq!(fx.client().get("/v1/status", &fx.token).await.status, 200);
    assert_admin_error(
        &rpc(&admin, "item_list", Some(&token), &list).await,
        401,
        "admin_session_required",
    );
    // rpc/vault_lock locks the server vault and so ends the session.
    let token = session(&admin, &fx).await;
    assert_eq!(
        rpc(&admin, "vault_lock", Some(&token), &json!({}))
            .await
            .status,
        200
    );
    assert_eq!(fx.core.state(), VaultStateKind::Sealed);
    assert_eq!(fx.client().get("/v1/status", &fx.token).await.status, 423);
    assert_admin_error(
        &rpc(&admin, "item_list", Some(&token), &list).await,
        401,
        "admin_session_required",
    );
    fx.unlock().await;
    let reasons: Vec<Value> = audit_rows(&fx, "admin.session_close")
        .await
        .into_iter()
        .filter_map(|row| row.event.details.get("reason").cloned())
        .collect();
    assert!(reasons.contains(&json!("closed")), "{reasons:?}");
    fx.stop().await;
}

#[tokio::test]
async fn g07_session_caps_push_out_the_oldest_session_of_the_enrolment() {
    let (fx, _, admin) = admin_fixture(false).await;
    let list = json!({ "filter": {} });
    let first = session(&admin, &fx).await;
    let second = session(&admin, &fx).await;
    let third = session(&admin, &fx).await;
    assert_admin_error(
        &rpc(&admin, "item_list", Some(&first), &list).await,
        401,
        "admin_session_required",
    );
    for token in [&second, &third] {
        assert_eq!(
            rpc(&admin, "item_list", Some(token), &list).await.status,
            200
        );
    }
    assert_eq!(fx.admin.as_ref().expect("admin").session_count(), 2);
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 8

#[tokio::test]
async fn g08_commands_off_the_list_bad_arguments_and_large_bodies() {
    let (fx, _, admin) = admin_fixture(false).await;
    let token = session(&admin, &fx).await;
    let item = json!({ "item": fx.item.to_string() });
    for command in [
        "item_versions",
        "vault_unlock_recovery",
        "settings_set",
        "nope",
    ] {
        assert_admin_error(
            &rpc(&admin, command, Some(&token), &item).await,
            404,
            "remote_unsupported",
        );
    }
    // vault_unlock only goes to the session route.
    let unlock = json!({ "operator_id": fx.owner_label_id.to_string(), "phrase": PHRASE });
    assert_admin_error(
        &rpc(&admin, "vault_unlock", Some(&token), &unlock).await,
        404,
        "remote_unsupported",
    );
    // Unknown JSON field, bad shape, empty body.
    assert_admin_error(
        &rpc(&admin, "vault_status", None, &json!({ "extra": 1 })).await,
        400,
        "invalid_request",
    );
    assert_admin_error(
        &rpc(
            &admin,
            "item_get",
            Some(&token),
            &json!({ "item": fx.item.to_string(), "x": 1 }),
        )
        .await,
        400,
        "invalid_request",
    );
    let empty = admin
        .send("POST", "/admin/v1/rpc/vault_status", None, &[], Some(""))
        .await;
    assert_admin_error(&empty, 400, "invalid_request");
    // Not JSON.
    let text = admin
        .send(
            "POST",
            "/admin/v1/rpc/vault_status",
            None,
            &[("content-type", "text/plain")],
            Some("{}"),
        )
        .await;
    assert_admin_error(&text, 415, "unsupported_media_type");
    // Over 16 KiB for most commands; item_create takes up to 1 MiB.
    let big = json!({ "item": "x".repeat(17 * 1024) });
    assert_admin_error(
        &rpc(&admin, "item_get", Some(&token), &big).await,
        413,
        "payload_too_large",
    );
    let large_note = json!({ "input": {
        "workspace_id": fx.workspace.to_string(), "title": "Large note", "description": "",
        "role_label": null, "category": "Note", "tags": [], "environment": "dev", "target": null,
        "custom": {}, "expires_at": null, "max_uses": null,
        "payload": { "kind": "note", "text": "n".repeat(20 * 1024) },
    }});
    let created = rpc(&admin, "item_create", Some(&token), &large_note).await;
    assert_eq!(
        created.status,
        200,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    let huge = json!({ "input": { "title": "x".repeat(1024 * 1024 + 1) } });
    assert_admin_error(
        &rpc(&admin, "item_create", Some(&token), &huge).await,
        413,
        "payload_too_large",
    );
    // A bad ID inside good arguments is a validation error, as in local IPC.
    assert_admin_error(
        &rpc(&admin, "item_get", Some(&token), &json!({ "item": "nope" })).await,
        400,
        "validation_failed",
    );
    fx.stop().await;
}

// ------------------------------------------------------------------------------------------ 9

#[tokio::test]
async fn g09_approvals_over_the_admin_channel_and_the_event_stream() {
    let (fx, _, admin) = admin_fixture(false).await;
    let token = session(&admin, &fx).await;
    let prod = fx
        .core
        .create_item_as_operator(
            &op_ctx(&fx.owner),
            web_login(fx.workspace, "Shop admin prod", Environment::Prod),
        )
        .await
        .expect("prod item")
        .summary
        .id;
    let (status, headers, stream) = admin
        .send_stream("GET", "/admin/v1/events", Some(&token), &[], None)
        .await;
    assert_eq!(status, 200);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"))
    );
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    // At most two streams per session.
    let (second_status, _, second_stream) = admin
        .send_stream("GET", "/admin/v1/events", Some(&token), &[], None)
        .await;
    assert_eq!(second_status, 200);
    let third = admin
        .send("GET", "/admin/v1/events", Some(&token), &[], None)
        .await;
    assert_admin_error(&third, 429, "rate_limited");
    drop(second_stream);

    let agent = fx.client();
    let path = format!("/v1/credentials/{prod}/reveal");
    let purpose = json!({ "purpose": "Run the deploy check for the checkout page" }).to_string();
    let pending = agent.post(&path, &fx.token, &purpose).await;
    assert_eq!(
        pending.status,
        202,
        "{}",
        String::from_utf8_lossy(&pending.body)
    );
    let request = pending.json()["access_request"]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let list = rpc(&admin, "request_list_pending", Some(&token), &json!({})).await;
    assert_eq!(list.status, 200);
    assert!(
        list.json()
            .as_array()
            .expect("list")
            .iter()
            .any(|r| r["id"] == request.as_str())
    );
    let approved = rpc(
        &admin,
        "request_approve",
        Some(&token),
        &json!({ "request": request, "option": "once" }),
    )
    .await;
    assert_eq!(
        approved.status,
        200,
        "{}",
        String::from_utf8_lossy(&approved.body)
    );
    let leases = rpc(&admin, "lease_list", Some(&token), &json!({})).await;
    assert!(
        leases
            .json()
            .as_array()
            .expect("leases")
            .iter()
            .any(|l| l["view"]["item_id"] == prod.to_string() && l["source"] == "approval")
    );
    let revealed = agent.post(&path, &fx.token, &purpose).await;
    assert_eq!(revealed.status, 200);
    assert_eq!(revealed.json()["secret"]["password"], PASSWORD);
    // The admin action is audited with the operator as the actor (R-6).
    let rows = audit_rows(&fx, "request.approve").await;
    assert!(
        rows.iter().any(
            |row| row.event.actor.id.as_deref() == Some(fx.owner_label_id.to_string().as_str())
        ),
        "{rows:?}"
    );
    // A lock ends the stream.
    let started = Stopwatch::start();
    assert_eq!(
        rpc(&admin, "vault_lock", Some(&token), &json!({}))
            .await
            .status,
        200
    );
    let events = read_events(stream, 100, Duration::from_secs(10)).await;
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "the stream ends at lock"
    );
    let names: Vec<&str> = events.iter().map(|(name, _)| name.as_str()).collect();
    let created = names
        .iter()
        .position(|n| *n == "AccessRequestCreated")
        .expect("created");
    let resolved = names
        .iter()
        .position(|n| *n == "AccessRequestResolved")
        .expect("resolved");
    assert!(created < resolved, "{names:?}");
    assert_eq!(events[created].1["id"], request.as_str());
    assert_eq!(events[resolved].1["status"], "approved");
    for (_, data) in &events {
        assert!(!data.to_string().contains(PASSWORD), "no secret in events");
    }
    fx.unlock().await;
    fx.stop().await;
}

// ----------------------------------------------------------------------------------------- 10

#[tokio::test]
async fn g10_origin_and_host_rules_apply_to_admin_routes() {
    let (fx, _, admin) = admin_fixture(false).await;
    let resp = admin
        .send(
            "GET",
            "/admin/v1/hello",
            None,
            &[("origin", "https://evil.example")],
            None,
        )
        .await;
    assert_error_shape(&resp, 403, "origin_refused");
    let resp = admin
        .send(
            "GET",
            "/admin/v1/hello",
            None,
            &[("sec-fetch-site", "cross-site")],
            None,
        )
        .await;
    assert_error_shape(&resp, 403, "origin_refused");
    // A wrong Host header (DNS rebinding).
    let mut sender = admin.connect().await.expect("connect");
    let request = hyper::Request::builder()
        .uri("/admin/v1/hello")
        .header("host", "evil.example")
        .body(common::http_body_util_lite::Full::new(""))
        .expect("request");
    let response = sender.send_request(request).await.expect("send");
    assert_eq!(response.status().as_u16(), 403);
    // The security headers are on admin answers too.
    let hello = admin.get("/admin/v1/hello", "").await;
    assert_eq!(hello.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(
        hello.header("x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert!(hello.header("x-request-id").is_some());
    fx.stop().await;
}

// ----------------------------------------------------------------------------------------- 11

#[tokio::test]
async fn g11_exactly_the_five_admin_routes_exist() {
    let (fx, _, admin) = admin_fixture(false).await;
    let token = session(&admin, &fx).await;
    // Each of the five answers with something other than route_not_found.
    for (method, path) in ADMIN_PATHS {
        let body = (method == "POST").then_some("{}");
        let resp = admin.send(method, path, Some(&token), &[], body).await;
        assert_ne!(resp.status, 404, "{method} {path}");
    }
    // Neighbours do not exist.
    for (method, path) in [
        ("GET", "/admin"),
        ("GET", "/admin/v1"),
        ("GET", "/admin/v1/sessions"),
        ("POST", "/admin/v1/rpc"),
        ("POST", "/admin/v1/rpc/item_list/x"),
        ("GET", "/admin/v2/hello"),
        ("GET", "/admin/v1/openapi.json"),
    ] {
        let body = (method == "POST").then_some("{}");
        let resp = admin.send(method, path, Some(&token), &[], body).await;
        assert_error_shape(&resp, 404, "route_not_found");
    }
    // Wrong methods on the five.
    for (method, path) in [
        ("POST", "/admin/v1/hello"),
        ("GET", "/admin/v1/session"),
        ("GET", "/admin/v1/rpc/vault_status"),
        ("POST", "/admin/v1/events"),
    ] {
        let body = (method == "POST").then_some("{}");
        let resp = admin.send(method, path, Some(&token), &[], body).await;
        assert_eq!(resp.status, 405, "{method} {path}");
    }
    fx.stop().await;
}

// ----------------------------------------------------------------------------------------- 12

/// SHA-256 of a fake certificate, as the device check sees it.
fn cert_digest(cert: &[u8]) -> [u8; 32] {
    cerberus_crypto::sha256(&[cert])
}

/// A registry entry of a fake certificate, bound to the owner, valid for `seconds`.
fn fake_entry(fx: &Fixture, cert: &[u8], seconds: i64) -> AdminClient {
    AdminClient::enrolled(
        EnrolmentId::generate(),
        "laptop".to_owned(),
        fx.owner_label_id,
        cert,
        now(fx) + SignedDuration::from_secs(seconds),
        now(fx),
    )
    .expect("entry")
}

/// DEC-RM-22: a revoke whose registry save failed is retried by the next revoke of the same
/// enrolment, which answers the truth; before, it answered "revoked already" and the stolen
/// device was live again after a restart.
#[tokio::test]
async fn g12_a_revoke_whose_save_failed_is_saved_by_the_next_revoke() {
    let (fx, _, _) = admin_fixture(false).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let folder = dir.path().join("data");
    let path = folder.join("admin-clients.json");
    let entry = fake_entry(&fx, b"stolen laptop", 86_400);
    let mut clients = AdminClients::default();
    clients.add(entry.clone()).expect("add");
    let state = AdminState::new(clients, AdminLimits::default()).with_registry_file(path.clone());
    // The folder is missing, so the save fails; the revoke is in effect in memory.
    assert!(state.revoke(&fx.core, entry.id).await.is_err());
    assert!(
        state
            .find_live(&cert_digest(b"stolen laptop"), now(&fx))
            .is_none()
    );
    assert!(
        state.revoke(&fx.core, entry.id).await.is_err(),
        "still not saved, and said so"
    );
    std::fs::create_dir(&folder).expect("folder");
    assert!(state.revoke(&fx.core, entry.id).await.expect("saved"));
    let on_disk = AdminClients::load(&path).expect("registry");
    assert!(on_disk.get(entry.id).expect("entry").revoked_at.is_some());
    assert!(
        !state.revoke(&fx.core, entry.id).await.expect("saved"),
        "saved now: revoked already"
    );
    assert_eq!(audit_rows(&fx, "admin.client_revoke").await.len(), 1);
    fx.stop().await;
}

/// DEC-RM-22: a registry write never drops a revoke that the file has and memory lacks (an
/// offline `cerberusd admin revoke`), and a reload never drops a revoke that memory has and the
/// file lacks.
#[tokio::test]
async fn g12_registry_writes_and_reloads_never_undo_a_revoke() {
    let (fx, _, _) = admin_fixture(false).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("admin-clients.json");
    let (a, b) = (fake_entry(&fx, b"a", 86_400), fake_entry(&fx, b"b", 86_400));
    let mut clients = AdminClients::default();
    clients.add(a.clone()).expect("add");
    clients.add(b.clone()).expect("add");
    clients.save(&path).expect("save");
    let state = AdminState::new(
        AdminClients::load(&path).expect("load"),
        AdminLimits::default(),
    )
    .with_registry_file(path.clone());
    // An offline revoke after the daemon read the file, then a write of the daemon.
    let mut offline = AdminClients::load(&path).expect("load");
    assert!(offline.revoke(a.id, now(&fx)));
    offline.save(&path).expect("save");
    state.enroll(fake_entry(&fx, b"c", 86_400)).expect("enroll");
    let on_disk = AdminClients::load(&path).expect("load");
    assert!(
        on_disk.get(a.id).expect("a").revoked_at.is_some(),
        "kept on disk"
    );
    assert_eq!(on_disk.list().len(), 3);
    assert!(state.find_live(&cert_digest(b"a"), now(&fx)).is_none());
    assert!(state.find_live(&cert_digest(b"c"), now(&fx)).is_some());
    // A file that lacks a revoke of the daemon (an old copy put back), then a reload.
    let before = std::fs::read(&path).expect("read");
    assert!(state.revoke(&fx.core, b.id).await.expect("revoke"));
    std::fs::write(&path, before).expect("write back");
    state.reload_clients(&fx.core).await.expect("reload");
    assert!(state.find_live(&cert_digest(b"b"), now(&fx)).is_none());
    // The file lacks it, so the next revoke saves it again.
    assert!(state.revoke(&fx.core, b.id).await.expect("saved again"));
    let on_disk = AdminClients::load(&path).expect("load");
    assert!(on_disk.get(b.id).expect("b").revoked_at.is_some());
    fx.stop().await;
}

/// DEC-RM-22: the sweep ends a session whose enrolment is no longer live although the session
/// is within its own limits (here the entry expires a minute after the open).
#[tokio::test]
async fn g12_the_sweep_ends_sessions_of_an_enrolment_that_is_no_longer_live() {
    let (fx, _, _) = admin_fixture(true).await;
    let state = fx.admin.as_ref().expect("admin");
    let ca = fx.ca.as_ref().expect("ca");
    let id = EnrolmentId::generate();
    let cert = ca
        .issue_admin_client(&id.to_string(), now(&fx))
        .expect("admin cert");
    let entry = AdminClient::enrolled(
        id,
        "short".to_owned(),
        fx.owner_label_id,
        &cert.cert_der,
        now(&fx) + SignedDuration::from_secs(60),
        now(&fx),
    )
    .expect("entry");
    state.enroll(entry).expect("enroll");
    let client = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    session(&client, &fx).await;
    assert_eq!(state.session_count(), 1);
    advance(&fx, 61);
    state.sweep(&fx.core).await;
    assert_eq!(state.session_count(), 0);
    let reasons: Vec<Value> = audit_rows(&fx, "admin.session_close")
        .await
        .into_iter()
        .filter_map(|row| row.event.details.get("reason").cloned())
        .collect();
    assert_eq!(reasons, vec![json!("revoked")]);
    fx.stop().await;
}
