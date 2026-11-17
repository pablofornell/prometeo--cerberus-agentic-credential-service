//! Retry rules: only `retryable` errors and failed connects are repeated; a call that may have
//! been counted is never repeated after the connection broke.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use cerberus_client::{Client, ClientConfig, ClientError, RetryPolicy, Trust, WireSecret};
use cerberus_types::wire::RevealRequest;
use cerberus_types::{ErrorCode, ItemId};
use common::script::{Pki, Reply, Script, Versions};

const TOKEN: &str = "cvt_00000000-0000-0000-0000-000000000000.fake-token";
const REQ: &str = "0190f000-0000-7000-8000-000000000003";

fn error_body(code: &str, retryable: bool, details: &str) -> String {
    format!(
        r#"{{"error":{{"code":"{code}","message":"text","request_id":"{REQ}","retryable":{retryable}{details}}}}}"#
    )
}

const STATUS: &str = r#"{"vault":"unlocked","agent":{"id":"0190f000-0000-7000-8000-000000000001","name":"a","key_id":"0190f000-0000-7000-8000-000000000002","scopes":["status:read"],"key_expires_at":null},"server_time":"2026-01-01T00:00:00Z"}"#;

fn fast() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
    }
}

async fn setup(replies: Vec<Reply>) -> (Script, Client) {
    let pki = Pki::new();
    let server = Script::start(&pki, true, Versions::Tls13, replies).await;
    let config = ClientConfig {
        base_url: url::Url::parse(&server.url()).unwrap(),
        token: WireSecret::new(TOKEN.to_owned()),
        trust: Trust::Pin(pki.export.pin.clone()),
        client_cert: None,
        timeout: Duration::from_secs(5),
    };
    (server, Client::new(&config).unwrap().with_retry(fast()))
}

#[tokio::test]
async fn a_retryable_error_is_repeated_until_it_works() {
    let (server, client) = setup(vec![
        Reply::Json(423, error_body("vault_locked", true, "")),
        Reply::Json(
            429,
            error_body(
                "rate_limited",
                true,
                r#","details":{"retry_after_seconds":0}"#,
            ),
        ),
        Reply::Json(200, STATUS.into()),
    ])
    .await;
    assert!(client.status().await.is_ok());
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn a_retryable_error_stops_after_the_last_try() {
    let (server, client) = setup(vec![
        Reply::Json(423, error_body("vault_locked", true, "")),
        Reply::Json(423, error_body("vault_locked", true, "")),
        Reply::Json(423, error_body("vault_locked", true, "")),
        Reply::Json(200, STATUS.into()),
    ])
    .await;
    let error = client.status().await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::VaultLocked));
    assert_eq!(error.request_id().unwrap().to_string(), REQ);
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn a_not_retryable_error_is_not_repeated() {
    let (server, client) = setup(vec![
        Reply::Json(401, error_body("unauthenticated", false, "")),
        Reply::Json(200, STATUS.into()),
    ])
    .await;
    let error = client.status().await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Unauthenticated));
    assert_eq!(error.exit_code(), 70);
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn a_read_is_repeated_after_a_broken_connection() {
    let (server, client) = setup(vec![Reply::Drop, Reply::Json(200, STATUS.into())]).await;
    assert!(client.status().await.is_ok());
    assert_eq!(server.count(), 2);
}

#[tokio::test]
async fn a_reveal_is_never_repeated_after_a_broken_connection() {
    let (server, client) = setup(vec![Reply::Drop, Reply::Json(200, STATUS.into())]).await;
    let request = RevealRequest {
        purpose: "retry rule test".to_owned(),
        lease_id: None,
        ttl_seconds: None,
    };
    let error = client
        .reveal(ItemId::generate(), &request)
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Transport(_)), "{error}");
    assert_eq!(server.count(), 1, "the reveal may have been counted");
}

#[tokio::test]
async fn a_reveal_is_repeated_when_the_server_says_retryable() {
    let (server, client) = setup(vec![
        Reply::Json(423, error_body("vault_locked", true, "")),
        Reply::Json(403, error_body("forbidden", false, "")),
    ])
    .await;
    let request = RevealRequest {
        purpose: "retry rule test".to_owned(),
        lease_id: None,
        ttl_seconds: None,
    };
    let error = client
        .reveal(ItemId::generate(), &request)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Forbidden));
    assert_eq!(server.count(), 2);
}

#[tokio::test]
async fn a_failed_connect_is_retryable_for_every_call() {
    // Nothing listens on this port, so nothing is ever sent. The socket is bound but never listens
    // and stays open until the end of the test: the port cannot go to another test running at the
    // same time, and a connect to it is always refused (DEC-T24-3).
    let pki = Pki::new();
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = reserved.local_addr().unwrap().port();
    let config = ClientConfig {
        base_url: url::Url::parse(&format!("https://127.0.0.1:{port}")).unwrap(),
        token: WireSecret::new(TOKEN.to_owned()),
        trust: Trust::Pin(pki.export.pin.clone()),
        client_cert: None,
        timeout: Duration::from_secs(5),
    };
    let client = Client::new(&config).unwrap().with_retry(fast());
    let error = client.status().await.unwrap_err();
    assert!(matches!(error, ClientError::Connect(_)), "{error}");
    assert!(error.is_retryable(true));
    assert!(error.is_retryable(false));
    drop(reserved);
}

#[test]
fn retry_flags_follow_the_rules() {
    assert!(ClientError::Timeout.is_retryable(false));
    assert!(!ClientError::Timeout.is_retryable(true));
    assert!(ClientError::Transport("x".into()).is_retryable(false));
    assert!(!ClientError::Transport("x".into()).is_retryable(true));
    assert!(!ClientError::PinMismatch.is_retryable(false));
    assert!(!ClientError::Tls("x".into()).is_retryable(false));
}
