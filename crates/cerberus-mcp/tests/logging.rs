//! Logs of the MCP path hold no secret and no token (ADR-0029 item 9). `rmcp` itself logs message
//! bodies below `warn`, so hosts cap it with `cerberus_mcp::LOG_DIRECTIVE`; this test applies the
//! same cap to the captured lines. All secret values are fake test values.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{Fixture, PASSWORD, USERNAME, call};
use serde_json::json;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_hold_no_secret_and_no_token() {
    let capture = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    )
    .expect("subscriber");
    let fx = Fixture::new().await;
    let client = fx.client().await;
    let got = call(
        &client,
        "get_credential",
        json!({"id": fx.item.to_string(), "purpose": "Check the checkout page"}),
    )
    .await;
    assert_eq!(got.is_error, Some(false));
    let stored = call(
        &client,
        "store_secret",
        json!({"kind": "session_token", "workspace": "shop-frontend", "title": "s",
               "environment": "dev", "value": "canary-session-log-1"}),
    )
    .await;
    assert_eq!(stored.is_error, Some(false));
    fx.lock().await;
    let locked = call(&client, "vault_status", json!({})).await;
    assert_eq!(locked.is_error, Some(false));
    let token = fx.token.clone();
    fx.stop().await;
    let text = String::from_utf8(capture.0.lock().expect("lock").clone()).expect("utf8");
    // The cap hosts apply: `rmcp` below `warn` is dropped.
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            let level = line.split_whitespace().nth(1).unwrap_or_default();
            !(line.contains(" rmcp::") && matches!(level, "TRACE" | "DEBUG" | "INFO"))
        })
        .collect();
    assert!(!kept.is_empty(), "the capture works");
    for secret in [PASSWORD, USERNAME, "canary-session-log-1", token.as_str()] {
        let bad: Vec<String> = kept
            .iter()
            .filter(|line| line.contains(secret))
            .map(|line| line.chars().take(120).collect())
            .collect();
        assert!(
            bad.is_empty(),
            "a log line holds a secret or the token: {bad:?}"
        );
    }
}
