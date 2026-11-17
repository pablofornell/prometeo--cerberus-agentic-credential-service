//! ADR-0032: logs hold no secret value and no token. Own test binary, because the log capture is the
//! global subscriber of the process.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};

use common::{Fixture, PASSWORD, USERNAME};
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn logs_of_a_reveal_hold_no_secret_and_no_token() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .init();
    let fx = Fixture::new().await;
    let client = fx.client();
    let purpose = json!({"purpose": "Run the Playwright login test"}).to_string();
    let resolve = json!({"app":"shop-frontend","environment":"staging","role":"admin","purpose":"Run the Playwright login test"}).to_string();
    let reveal = client
        .post(
            &format!("/v1/credentials/{}/reveal", fx.item),
            &fx.token,
            &purpose,
        )
        .await;
    assert_eq!(reveal.status, 200);
    assert!(
        String::from_utf8_lossy(&reveal.body).contains(PASSWORD),
        "the call returned the secret"
    );
    assert_eq!(
        client
            .post("/v1/credentials/resolve", &fx.token, &resolve)
            .await
            .status,
        200
    );
    // Failed calls: a wrong secret, a malformed token, a locked call.
    let token = fx.token.clone();
    let (_, secret) = token.split_once('.').expect("token");
    let wrong = common::token_with_secret(&fx.token, &"C".repeat(43));
    assert_eq!(client.get("/v1/status", &wrong).await.status, 401);
    assert_eq!(client.get("/v1/status", "cvt_malformed").await.status, 401);
    fx.lock().await;
    assert_eq!(client.get("/v1/status", &fx.token).await.status, 423);
    fx.unlock().await;
    fx.stop().await;

    let log = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(log.contains("request"), "the request log line exists");
    assert!(
        log.contains("/v1/credentials/{id}/reveal"),
        "the route template is logged"
    );
    for forbidden in [
        PASSWORD,
        USERNAME,
        secret,
        token.as_str(),
        &"C".repeat(43),
        "cvt_malformed",
        "Shop admin",
        "Playwright",
    ] {
        assert!(!log.contains(forbidden), "log holds `{forbidden}`");
    }
    assert!(
        !log.to_lowercase().contains("authorization"),
        "no header is logged"
    );
    assert!(
        log.contains("agent token refused"),
        "refused tokens are logged once per minute, without the token"
    );
}
