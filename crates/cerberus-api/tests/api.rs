//! REST API over real TLS: acceptance scenarios A2, A5, A6, A10, A11 and the rules of ADR-0008,
//! ADR-0015, ADR-0016, ADR-0021, ADR-0023, ADR-0028 and ADR-0030.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use cerberus_core::admin::AuditQuery;
use cerberus_core::items::{Payload, TotpSeed};
use cerberus_core::vault::KeyCustody;
use cerberus_crypto::SecretString;
use cerberus_types::{ApprovalOption, Environment, HANDLING_SECRET};
use common::{
    Fixture, Options, PASSWORD, USERNAME, assert_error_shape, op_ctx, read_events,
    token_with_secret, web_login,
};
use serde_json::json;

const PURPOSE: &str = "Run the Playwright login test for the checkout page";

fn resolve_body() -> String {
    json!({"app":"shop-frontend","environment":"staging","role":"admin","purpose":PURPOSE,"mode":"best"})
        .to_string()
}

fn purpose_body() -> String {
    json!({ "purpose": PURPOSE }).to_string()
}

async fn audit_types(fx: &Fixture, ty: &str) -> usize {
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
        .len()
}

async fn prod_item(fx: &Fixture, title: &str) -> cerberus_types::ItemId {
    fx.core
        .create_item_as_operator(
            &op_ctx(&fx.owner),
            web_login(fx.workspace, title, Environment::Prod),
        )
        .await
        .expect("prod item")
        .summary
        .id
}

#[tokio::test]
async fn a2_resolve_returns_user_and_password_in_one_response() {
    let fx = Fixture::new().await;
    let resp = fx
        .client()
        .post("/v1/credentials/resolve", &fx.token, &resolve_body())
        .await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let json = resp.json();
    assert_eq!(json["outcome"], "secret");
    assert_eq!(json["secret"]["kind"], "web_login");
    assert_eq!(json["secret"]["username"], USERNAME);
    assert_eq!(json["secret"]["password"], PASSWORD);
    assert_eq!(json["handling"], HANDLING_SECRET);
    assert_eq!(json["handling"], "secret \u{2014} do not print or log");
    assert_eq!(json["item"]["title"], "Shop admin");
    assert!(json["lease"]["id"].is_string());
    assert_eq!(
        json["request_id"].as_str(),
        resp.header("x-request-id").as_deref()
    );
    assert_eq!(resp.header("cache-control").as_deref(), Some("no-store"));
    assert!(audit_types(&fx, "item.reveal").await >= 1);
    assert!(audit_types(&fx, "api.resolve").await >= 1);
    fx.stop().await;
}

#[tokio::test]
async fn secret_responses_carry_handling_and_security_headers() {
    let fx = Fixture::new().await;
    let path = format!("/v1/credentials/{}/reveal", fx.item);
    let resp = fx.client().post(&path, &fx.token, &purpose_body()).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["handling"], HANDLING_SECRET);
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        assert_eq!(resp.header(name).as_deref(), Some(value), "{name}");
    }
    assert!(resp.header("access-control-allow-origin").is_none());
    fx.stop().await;
}

#[tokio::test]
async fn health_needs_no_token_and_shows_lock_state() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let resp = client.send("GET", "/v1/health", None, &[], None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["vault"], "unlocked");
    assert_eq!(resp.json()["status"], "ok");
    fx.lock().await;
    let resp = client.send("GET", "/v1/health", None, &[], None).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["vault"], "locked");
    assert_eq!(resp.json().as_object().map(serde_json::Map::len), Some(3));
    fx.stop().await;
}

#[tokio::test]
async fn a5_every_route_gives_423_and_no_data_when_locked() {
    let fx = Fixture::new().await;
    fx.lock().await;
    let doc = serde_json::to_value(cerberus_api::openapi()).expect("openapi json");
    let id = "0190f000-0000-7000-8000-000000000001";
    let mut checked = 0;
    for (path, item) in doc["paths"].as_object().expect("paths") {
        if path == "/health" {
            continue;
        }
        for method in item.as_object().expect("item").keys() {
            if !["get", "post", "delete"].contains(&method.as_str()) {
                continue;
            }
            let url = format!("/v1{}", path.replace("{id}", id));
            let body = (method == "post").then_some("{}");
            let resp = fx
                .client()
                .send(&method.to_uppercase(), &url, Some(&fx.token), &[], body)
                .await;
            assert_error_shape(&resp, 423, "vault_locked");
            assert_eq!(resp.json()["error"]["retryable"], true);
            assert!(resp.header("retry-after").is_none(), "{method} {path}");
            assert_eq!(
                resp.json()["error"].as_object().map(serde_json::Map::len),
                Some(4)
            );
            checked += 1;
        }
    }
    assert!(checked >= 13, "checked {checked} routes");
    // The locked calls are audited once each, in audit_pending, and move into the chain at unlock.
    fx.unlock().await;
    assert_eq!(audit_types(&fx, "api.locked_call").await, checked);
    fx.stop().await;
}

#[tokio::test]
async fn a10_revoke_gives_401_on_the_next_call() {
    let fx = Fixture::new().await;
    let client = fx.client();
    assert_eq!(client.get("/v1/status", &fx.token).await.status, 200);
    fx.core
        .revoke_agent_key(&op_ctx(&fx.owner), fx.key_id)
        .await
        .expect("revoke");
    let resp = client.get("/v1/status", &fx.token).await;
    assert_error_shape(&resp, 401, "unauthenticated");
    fx.stop().await;
}

#[tokio::test]
async fn bad_token_while_locked_is_401_and_good_token_is_423() {
    let fx = Fixture::new().await;
    fx.lock().await;
    let client = fx.client();
    let resp = client.get("/v1/status", "cvt_nonsense").await;
    assert_error_shape(&resp, 401, "unauthenticated");
    let resp = client.get("/v1/status", &fx.token).await;
    assert_error_shape(&resp, 423, "vault_locked");
    fx.stop().await;
}

#[tokio::test]
async fn the_401_shape_is_the_same_for_every_reason() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let (head, _) = fx.token.split_once('.').expect("token");
    let unknown_agent = format!(
        "cvt_0190f000-0000-7000-8000-0000000000ff.{}",
        "A".repeat(43)
    );
    let wrong_secret = token_with_secret(&fx.token, &"B".repeat(43));
    let mut cases: Vec<(&str, Option<String>)> = vec![
        ("unknown agent", Some(unknown_agent)),
        ("wrong secret", Some(wrong_secret)),
        ("malformed", Some(head.to_owned())),
        ("no header", None),
    ];
    // A revoked key last, because it changes the fixture.
    fx.core
        .revoke_agent_key(&op_ctx(&fx.owner), fx.key_id)
        .await
        .expect("revoke");
    cases.push(("revoked", Some(fx.token.clone())));
    let mut shapes = BTreeSet::new();
    for (name, token) in cases {
        let resp = client
            .send("GET", "/v1/status", token.as_deref(), &[], None)
            .await;
        assert_error_shape(&resp, 401, "unauthenticated");
        let mut body = resp.json();
        body["error"]["request_id"] = json!("x");
        let mut headers: Vec<String> = resp
            .headers
            .iter()
            .filter(|(n, _)| n.as_str() != "x-request-id" && n.as_str() != "date")
            .map(|(n, v)| format!("{n}={}", v.to_str().unwrap_or_default()))
            .collect();
        headers.sort();
        shapes.insert(format!("{body}|{headers:?}"));
        eprintln!("checked: {name}");
    }
    assert_eq!(shapes.len(), 1, "{shapes:?}");
    fx.stop().await;
}

#[tokio::test]
async fn a11_agent_without_write_gets_403() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let create = json!({
        "workspace": "shop-frontend", "title": "New key", "environment": "staging",
        "payload": {"kind": "api_key", "key": "canary-key-1"}
    })
    .to_string();
    // The key has the scope, the grant has no `write`: forbidden.
    let resp = client.post("/v1/credentials", &fx.token, &create).await;
    assert_error_shape(&resp, 403, "forbidden");
    // A key without the scope: insufficient_scope.
    let narrow = fx
        .core
        .create_agent_key(
            &op_ctx(&fx.owner),
            fx.agent,
            cerberus_core::agents::AgentKeyInput {
                scopes: vec![
                    cerberus_types::Scope::StatusRead,
                    cerberus_types::Scope::SecretsRead,
                ],
                lifetime_days: Some(30),
                ip_allowlist: vec![],
                require_mtls: false,
            },
        )
        .await
        .expect("key");
    let resp = client
        .post("/v1/credentials", narrow.token.expose_secret(), &create)
        .await;
    assert_error_shape(&resp, 403, "insufficient_scope");
    fx.stop().await;
}

#[tokio::test]
async fn request_id_is_made_by_the_server() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let sent = "11111111-1111-4111-8111-111111111111";
    let resp = client
        .send(
            "GET",
            "/v1/status",
            Some(&fx.token),
            &[("x-request-id", sent)],
            None,
        )
        .await;
    let id = resp.header("x-request-id").expect("id");
    assert_ne!(id, sent);
    assert_eq!(id.len(), 36);
    assert_eq!(id.as_bytes()[14], b'7', "UUIDv7");
    let resp = client
        .send("GET", "/v1/status", None, &[("x-request-id", sent)], None)
        .await;
    assert_error_shape(&resp, 401, "unauthenticated");
    assert_ne!(resp.header("x-request-id").as_deref(), Some(sent));
    fx.stop().await;
}

#[tokio::test]
async fn origin_and_unknown_host_are_refused() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let resp = client
        .send(
            "GET",
            "/v1/status",
            Some(&fx.token),
            &[("origin", "https://evil.example")],
            None,
        )
        .await;
    assert_error_shape(&resp, 403, "origin_refused");
    let resp = client
        .send(
            "GET",
            "/v1/health",
            None,
            &[("sec-fetch-site", "cross-site")],
            None,
        )
        .await;
    assert_error_shape(&resp, 403, "origin_refused");
    let resp = client
        .send(
            "GET",
            "/v1/health",
            None,
            &[("sec-fetch-site", "none")],
            None,
        )
        .await;
    assert_eq!(resp.status, 200);
    // The test client sets `host` first; a second header would be a duplicate, so build it by hand.
    let mut sender = client.connect().await.expect("connect");
    let request = hyper::Request::builder()
        .uri("/v1/health")
        .header("host", "rebind.example:7373")
        .body(common::http_body_util_lite::Full::new(""))
        .expect("request");
    let response = sender.send_request(request).await.expect("send");
    assert_eq!(response.status(), 403);
    let body = common::http_body_util_lite::collect(response.into_body()).await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")["error"]["code"],
        "origin_refused"
    );
    // The loopback names of the leaf are allowed, with or without a port.
    for host in [
        "127.0.0.1",
        "127.0.0.1:7373",
        "localhost",
        "[::1]:7373",
        "LOCALHOST",
    ] {
        let mut sender = client.connect().await.expect("connect");
        let request = hyper::Request::builder()
            .uri("/v1/health")
            .header("host", host)
            .body(common::http_body_util_lite::Full::new(""))
            .expect("request");
        let response = sender.send_request(request).await.expect("send");
        assert_eq!(response.status(), 200, "{host}");
    }
    fx.stop().await;
}

#[tokio::test]
async fn bodies_are_limited_typed_and_strict() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let big = json!({"app": "a".repeat(20_000), "purpose": PURPOSE}).to_string();
    let resp = client
        .post("/v1/credentials/resolve", &fx.token, &big)
        .await;
    assert_error_shape(&resp, 413, "payload_too_large");
    // Item creates may be bigger (1 MiB).
    let ok = json!({
        "workspace": "shop-frontend", "title": "Big note", "environment": "dev",
        "payload": {"kind": "note", "text": "x".repeat(100_000)}
    })
    .to_string();
    let resp = client.post("/v1/credentials", &fx.token, &ok).await;
    assert_ne!(resp.status, 413, "{}", String::from_utf8_lossy(&resp.body));
    let huge = json!({
        "workspace": "shop-frontend", "title": "Huge", "environment": "dev",
        "payload": {"kind": "note", "text": "x".repeat(1_100_000)}
    })
    .to_string();
    let resp = client.post("/v1/credentials", &fx.token, &huge).await;
    assert_error_shape(&resp, 413, "payload_too_large");
    // Not JSON.
    let resp = client
        .send(
            "POST",
            "/v1/credentials/resolve",
            Some(&fx.token),
            &[("content-type", "text/plain")],
            Some("{}"),
        )
        .await;
    assert_error_shape(&resp, 415, "unsupported_media_type");
    // Unknown field, malformed JSON, bad ID.
    let resp = client
        .post(
            "/v1/credentials/resolve",
            &fx.token,
            r#"{"app":"x","purpose":"p","user":"u"}"#,
        )
        .await;
    assert_error_shape(&resp, 400, "invalid_request");
    let resp = client
        .post("/v1/credentials/resolve", &fx.token, "{nope")
        .await;
    assert_error_shape(&resp, 400, "invalid_request");
    let resp = client
        .post(
            "/v1/credentials/not-a-uuid/reveal",
            &fx.token,
            &purpose_body(),
        )
        .await;
    assert_error_shape(&resp, 400, "invalid_request");
    // Field rules are 422.
    let resp = client
        .post(
            "/v1/credentials/resolve",
            &fx.token,
            r#"{"app":"shop-frontend","purpose":""}"#,
        )
        .await;
    assert_error_shape(&resp, 422, "validation_failed");
    assert!(resp.json()["error"]["details"]["fields"].is_array());
    fx.stop().await;
}

#[tokio::test]
async fn unknown_route_and_wrong_method_use_the_error_shape() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let resp = client.get("/v1/nothing-here", &fx.token).await;
    assert_error_shape(&resp, 404, "route_not_found");
    let resp = client.send("PUT", "/v1/health", None, &[], None).await;
    assert_error_shape(&resp, 405, "method_not_allowed");
    let resp = client.send("GET", "/nothing", None, &[], None).await;
    assert_error_shape(&resp, 404, "route_not_found");
    fx.stop().await;
}

#[tokio::test]
async fn rate_limit_gives_429_with_retry_after() {
    // The limiter reads the vault clock. A frozen clock means no refill between calls, so the 429
    // comes after exactly the burst, however slow the machine is (DEC-T24-4).
    let fx = Fixture::with(Options {
        manual_clock: true,
        ..Options::default()
    })
    .await;
    let clock = fx.clock.clone().expect("manual clock");
    let client = fx.client();
    // A good token is counted by the agent bucket only; the source bucket counts failed checks
    // (NEW-5).
    let limits = cerberus_core::auth::AuthLimits::default();
    let burst = usize::try_from(limits.agent_burst).expect("burst");
    let mut limited = None;
    for call in 0..=burst {
        let resp = client.get("/v1/status", &fx.token).await;
        if resp.status == 429 {
            assert_eq!(call, burst, "the burst is served first");
            limited = Some(resp);
            break;
        }
        assert_eq!(resp.status, 200, "call {call}");
    }
    let resp = limited.expect("a 429 after the burst");
    assert_eq!(resp.code(), "rate_limited");
    let after = resp.header("retry-after").expect("retry-after");
    let seconds: u64 = after.parse().expect("seconds");
    assert!(seconds >= 1);
    assert_eq!(
        resp.json()["error"]["details"]["retry_after_seconds"],
        seconds
    );
    assert_eq!(resp.json()["error"]["retryable"], true);
    // After the wait the bucket has a token again.
    clock.advance(jiff::SignedDuration::from_secs(
        i64::try_from(seconds).expect("seconds"),
    ));
    assert_eq!(client.get("/v1/status", &fx.token).await.status, 200);
    fx.stop().await;
}

/// Bad tokens from one address are locked out after the failure limit, but a good token from the
/// same address is still served (NEW-5, DEC-T27-E-1).
#[tokio::test]
async fn repeated_bad_tokens_lock_the_ip_out() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let mut locked = None;
    for _ in 0..15 {
        let resp = client.get("/v1/status", "cvt_bad").await;
        if resp.status == 429 {
            locked = Some(resp);
            break;
        }
        assert_eq!(resp.status, 401);
    }
    let resp = locked.expect("a lockout within 15 failures");
    assert_eq!(resp.code(), "too_many_failures");
    assert!(resp.header("retry-after").is_some());
    // The lockout refuses failing tokens only: a good token from this IP is served.
    assert_eq!(client.get("/v1/status", &fx.token).await.status, 200);
    let resp = client.get("/v1/status", "cvt_bad").await;
    assert_eq!(resp.code(), "too_many_failures");
    fx.stop().await;
}

/// NEW-5: a local user with no token floods bad tokens at `127.0.0.1`, the address of every local
/// agent. The flood is refused with `429 too_many_failures` after the failure limit and is still
/// audited (one `auth.failed` per minute with the count), but the agent on the same address gets
/// `200` all the time. The clock is frozen, so neither the lockout nor any bucket refills.
#[tokio::test]
async fn new5_a_bad_token_flood_from_loopback_does_not_lock_out_an_agent() {
    let fx = Fixture::with(Options {
        manual_clock: true,
        ..Options::default()
    })
    .await;
    let clock = fx.clock.clone().expect("manual clock");
    let client = fx.client();
    let wrong = token_with_secret(&fx.token, &"B".repeat(43));
    let limits = cerberus_core::auth::AuthLimits::default();
    let allowed = usize::try_from(limits.failure_max).expect("max");
    let flood = 70;
    for n in 0..flood {
        let token = if n % 2 == 0 {
            "cvt_bad"
        } else {
            wrong.as_str()
        };
        let resp = client.get("/v1/status", token).await;
        if n < allowed {
            assert_eq!(resp.status, 401, "attempt {n}");
        } else {
            assert_eq!(resp.status, 429, "attempt {n}");
            assert_eq!(resp.code(), "too_many_failures", "attempt {n}");
        }
        if n % 10 == 9 {
            let agent = client.get("/v1/status", &fx.token).await;
            assert_eq!(agent.status, 200, "agent after attempt {n}");
        }
    }
    // A minute later the next refused attempt writes `auth.failed` with the count in between.
    clock.advance(jiff::SignedDuration::from_secs(61));
    let resp = client.get("/v1/status", "cvt_bad").await;
    assert_eq!(resp.code(), "too_many_failures");
    assert_eq!(client.get("/v1/status", &fx.token).await.status, 200);
    let rows = fx
        .core
        .audit_query(
            &op_ctx(&fx.owner),
            AuditQuery {
                event_type: Some("auth.failed".to_owned()),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit");
    let throttled = rows
        .iter()
        .find(|row| row.event.result == "too_many_failures")
        .expect("the throttled attempts are audited");
    assert_eq!(throttled.event.details["source_ip"], "127.0.0.1");
    assert_eq!(throttled.event.details["suppressed_before"], flood - 1);
    fx.stop().await;
}

#[tokio::test]
async fn status_catalog_and_no_secret_in_the_catalog() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let resp = client.get("/v1/status", &fx.token).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["agent"]["name"], "qa-agent");
    assert_eq!(resp.json()["vault"], "unlocked");
    let resp = client
        .get(
            "/v1/credentials?workspace=shop-frontend&limit=10",
            &fx.token,
        )
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["items"][0]["title"], "Shop admin");
    let text = String::from_utf8_lossy(&resp.body);
    assert!(!text.contains(PASSWORD) && !text.contains(USERNAME));
    let resp = client.get("/v1/credentials?bogus=1", &fx.token).await;
    assert_error_shape(&resp, 400, "invalid_request");
    let resp = client.get("/v1/credentials?limit=0", &fx.token).await;
    assert_error_shape(&resp, 422, "validation_failed");
    fx.stop().await;
}

#[tokio::test]
async fn resolve_candidates_and_no_match() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let body = json!({"app":"shop-frontend","purpose":PURPOSE,"mode":"candidates"}).to_string();
    let resp = client
        .post("/v1/credentials/resolve", &fx.token, &body)
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json()["outcome"], "candidates");
    assert!(resp.json()["candidates"][0]["score"].is_number());
    assert!(!String::from_utf8_lossy(&resp.body).contains(PASSWORD));
    let body = json!({"app":"no-such-app","purpose":PURPOSE}).to_string();
    let resp = client
        .post("/v1/credentials/resolve", &fx.token, &body)
        .await;
    assert_error_shape(&resp, 404, "no_match");
    assert!(resp.json()["error"]["details"]["hints"]["app_known"] == false);
    fx.stop().await;
}

#[tokio::test]
async fn totp_returns_a_code_and_never_the_seed() {
    let fx = Fixture::new().await;
    let mut input = web_login(fx.workspace, "Shop with 2FA", Environment::Dev);
    input.payload = Payload::WebLogin {
        username: SecretString::new(USERNAME.to_owned()),
        password: SecretString::new(PASSWORD.to_owned()),
        url: None,
        totp: Some(TotpSeed::standard(SecretString::new(
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_owned(),
        ))),
    };
    let item = fx
        .core
        .create_item_as_operator(&op_ctx(&fx.owner), input)
        .await
        .expect("item");
    let client = fx.client();
    let path = format!("/v1/credentials/{}/totp", item.summary.id);
    let resp = client.post(&path, &fx.token, &purpose_body()).await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let json = resp.json();
    assert_eq!(json["handling"], HANDLING_SECRET);
    assert_eq!(json["code"].as_str().map(str::len), Some(6));
    assert!(!String::from_utf8_lossy(&resp.body).contains("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
    let reveal = client
        .post(
            &format!("/v1/credentials/{}/reveal", item.summary.id),
            &fx.token,
            &purpose_body(),
        )
        .await;
    assert!(!String::from_utf8_lossy(&reveal.body).contains("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
    assert_eq!(reveal.json()["item"]["has_totp"], true);
    fx.stop().await;
}

#[tokio::test]
async fn sessions_create_delete_and_release() {
    let fx = Fixture::new().await;
    let client = fx.client();
    let body = json!({
        "workspace": "shop-frontend", "title": "Checkout session", "environment": "staging",
        "ttl_seconds": 3600,
        "payload": {"kind": "session_token", "token": "canary-session-77"}
    })
    .to_string();
    let resp = client.post("/v1/sessions", &fx.token, &body).await;
    assert_eq!(resp.status, 201, "{}", String::from_utf8_lossy(&resp.body));
    let created = resp.json()["item"]["id"].as_str().expect("id").to_owned();
    assert_eq!(
        resp.header("location"),
        Some(format!("/v1/credentials/{created}"))
    );
    assert!(!String::from_utf8_lossy(&resp.body).contains("canary-session-77"));
    // A session payload on the wrong kind is refused.
    let bad = body
        .replace("session_token", "note")
        .replace("\"token\"", "\"text\"");
    let resp = client.post("/v1/sessions", &fx.token, &bad).await;
    assert_eq!(resp.status, 400, "kind note is not a session payload");
    // The agent deletes its own item.
    let resp = client
        .send(
            "DELETE",
            &format!("/v1/credentials/{created}"),
            Some(&fx.token),
            &[],
            None,
        )
        .await;
    assert_eq!(resp.status, 204);
    assert!(resp.body.is_empty());
    // Deleting an item of an operator is 403 (visible) .
    let resp = client
        .send(
            "DELETE",
            &format!("/v1/credentials/{}", fx.item),
            Some(&fx.token),
            &[],
            None,
        )
        .await;
    assert!(matches!(resp.status, 403 | 404), "{}", resp.status);
    // Lease release.
    let reveal = client
        .post(
            &format!("/v1/credentials/{}/reveal", fx.item),
            &fx.token,
            &purpose_body(),
        )
        .await;
    let lease = reveal.json()["lease"]["id"]
        .as_str()
        .expect("lease")
        .to_owned();
    let release = client
        .post(&format!("/v1/leases/{lease}/release"), &fx.token, "{}")
        .await;
    assert_eq!(
        release.status,
        200,
        "{}",
        String::from_utf8_lossy(&release.body)
    );
    assert_eq!(release.json()["lease_id"], lease);
    let again = client
        .post(&format!("/v1/leases/{lease}/release"), &fx.token, "{}")
        .await;
    assert_error_shape(&again, 409, "conflict");
    fx.stop().await;
}

#[tokio::test]
async fn a6_prod_item_needs_approval_then_deny_gives_403() {
    let fx = Fixture::new().await;
    let prod = prod_item(&fx, "Shop admin prod").await;
    let client = fx.client();
    let path = format!("/v1/credentials/{prod}/reveal");
    let resp = client.post(&path, &fx.token, &purpose_body()).await;
    assert_eq!(resp.status, 202, "{}", String::from_utf8_lossy(&resp.body));
    let request = resp.json()["access_request"]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert_eq!(
        resp.header("location"),
        Some(format!("/v1/requests/{request}"))
    );
    assert_eq!(resp.json()["access_request"]["status"], "pending");
    assert!(!String::from_utf8_lossy(&resp.body).contains(PASSWORD));
    let id: cerberus_types::AccessRequestId = request.parse().expect("id");
    fx.core
        .deny_request(&op_ctx(&fx.owner), id)
        .await
        .expect("deny");
    let poll = client
        .get(&format!("/v1/requests/{request}"), &fx.token)
        .await;
    assert_eq!(poll.json()["status"], "denied");
    let resp = client.post(&path, &fx.token, &purpose_body()).await;
    assert_error_shape(&resp, 403, "approval_denied");
    // Approve path: a second prod item.
    let second = prod_item(&fx, "Shop admin prod two").await;
    let path = format!("/v1/credentials/{second}/reveal");
    let resp = client.post(&path, &fx.token, &purpose_body()).await;
    assert_eq!(resp.status, 202);
    let id: cerberus_types::AccessRequestId = resp.json()["access_request"]["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("id");
    fx.core
        .approve_request(&op_ctx(&fx.owner), id, ApprovalOption::Once)
        .await
        .expect("approve");
    let resp = client.post(&path, &fx.token, &purpose_body()).await;
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    assert_eq!(resp.json()["secret"]["password"], PASSWORD);
    fx.stop().await;
}

#[tokio::test]
async fn post_requests_creates_a_pending_request_and_polling_works() {
    let fx = Fixture::new().await;
    let prod = prod_item(&fx, "Shop admin prod").await;
    let client = fx.client();
    let body = json!({"item_id": prod.to_string(), "reason": "Deploy check for the checkout page"})
        .to_string();
    let resp = client.post("/v1/requests", &fx.token, &body).await;
    assert_eq!(resp.status, 202, "{}", String::from_utf8_lossy(&resp.body));
    let id = resp.json()["id"].as_str().expect("id").to_owned();
    assert_eq!(resp.header("location"), Some(format!("/v1/requests/{id}")));
    let poll = client.get(&format!("/v1/requests/{id}"), &fx.token).await;
    assert_eq!(poll.status, 200);
    assert_eq!(poll.json()["status"], "pending");
    let other = client
        .get(
            "/v1/requests/0190f000-0000-7000-8000-000000000009",
            &fx.token,
        )
        .await;
    assert_error_shape(&other, 404, "not_found");
    fx.stop().await;
}

#[tokio::test]
async fn sse_ends_with_a_terminal_event_on_approve() {
    let fx = Fixture::new().await;
    let prod = prod_item(&fx, "Shop admin prod").await;
    let client = fx.client();
    let body = json!({"item_id": prod.to_string(), "reason": "Deploy check for the checkout page"})
        .to_string();
    let resp = client.post("/v1/requests", &fx.token, &body).await;
    let id = resp.json()["id"].as_str().expect("id").to_owned();
    let (status, headers, stream) = client
        .send_stream(
            "GET",
            &format!("/v1/requests/{id}/events"),
            Some(&fx.token),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        headers["content-type"]
            .to_str()
            .expect("ct")
            .starts_with("text/event-stream")
    );
    assert_eq!(headers["cache-control"], "no-store");
    let core = fx.core.clone();
    let owner = op_ctx(&fx.owner);
    let request_id: cerberus_types::AccessRequestId = id.parse().expect("id");
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.approve_request(&owner, request_id, ApprovalOption::Once)
            .await
            .expect("approve");
    });
    let events = read_events(stream, 10, Duration::from_secs(10)).await;
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].0, "status");
    assert_eq!(events[0].1["status"], "pending");
    assert_eq!(events[1].0, "status");
    assert_eq!(events[1].1["status"], "approved");
    assert!(events[1].1["lease"]["id"].is_string());
    fx.stop().await;
}

#[tokio::test]
async fn sse_ends_with_cancelled_when_the_vault_locks() {
    let fx = Fixture::new().await;
    let prod = prod_item(&fx, "Shop admin prod").await;
    let client = fx.client();
    let body = json!({"item_id": prod.to_string(), "reason": "Deploy check for the checkout page"})
        .to_string();
    let resp = client.post("/v1/requests", &fx.token, &body).await;
    let id = resp.json()["id"].as_str().expect("id").to_owned();
    let (status, _, stream) = client
        .send_stream(
            "GET",
            &format!("/v1/requests/{id}/events"),
            Some(&fx.token),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 200);
    let core = fx.core.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.lock(cerberus_types::LockReason::Manual)
            .await
            .expect("lock");
    });
    let events = read_events(stream, 10, Duration::from_secs(10)).await;
    let last = events.last().expect("events");
    assert_eq!(last.0, "status", "{events:?}");
    assert_eq!(last.1["status"], "cancelled", "{events:?}");
    fx.stop().await;
}

#[tokio::test]
async fn sse_of_a_missing_request_is_a_json_error() {
    let fx = Fixture::new().await;
    let resp = fx
        .client()
        .get(
            "/v1/requests/0190f000-0000-7000-8000-000000000009/events",
            &fx.token,
        )
        .await;
    assert_error_shape(&resp, 404, "not_found");
    fx.stop().await;
}

/// DEC-FIX7-11: a refused token writes `auth.failed` through core, at most once per IP per
/// minute; the event holds the reason and never the token.
#[tokio::test]
async fn refused_tokens_are_audited_once_per_ip_per_minute() {
    let fx = Fixture::new().await;
    let wrong = token_with_secret(&fx.token, &"B".repeat(43));
    for _ in 0..3 {
        assert_eq!(fx.client().get("/v1/status", &wrong).await.status, 401);
    }
    let rows = fx
        .core
        .audit_query(
            &op_ctx(&fx.owner),
            AuditQuery {
                event_type: Some("auth.failed".to_owned()),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit");
    let refused: Vec<_> = rows
        .iter()
        .filter(|row| row.event.details.get("source_ip").is_some())
        .collect();
    assert_eq!(refused.len(), 1, "{rows:?}");
    let event = &refused[0].event;
    assert_eq!(event.result, "unauthenticated");
    assert!(
        event.details["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    assert_eq!(event.details["source_ip"], "127.0.0.1");
    let text = serde_json::to_string(event).expect("json");
    assert!(!text.contains(&wrong), "no token in the audit body");
    fx.stop().await;
}
