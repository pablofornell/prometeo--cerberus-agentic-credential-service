//! ADR-0034, ADR-0032: the operator phrase, the `cas_` session token and the secrets of an admin
//! reveal never reach the log. Own test binary, because the log capture is the global subscriber
//! of the process.
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

use cerberus_admin::clients::{AdminClient, EnrolmentId};
use common::{Client, Fixture, Options, PASSWORD, PHRASE, USERNAME};
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

const WRONG_PHRASE: &str = "canary wrong phrase 3c81f0";

#[tokio::test]
async fn admin_logs_hold_no_phrase_no_session_token_and_no_secret() {
    let capture = Capture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(capture.clone())
        .init();
    let fx = Fixture::with(Options {
        admin: true,
        ..Options::default()
    })
    .await;
    let ca = fx.ca.as_ref().expect("ca");
    let now = fx.core.clock().now();
    let id = EnrolmentId::generate();
    let cert = ca.issue_admin_client(&id.to_string(), now).expect("cert");
    let entry = AdminClient::enrolled(
        id,
        "laptop".to_owned(),
        fx.owner_label_id,
        &cert.cert_der,
        cert.not_after,
        now,
    )
    .expect("entry");
    fx.admin
        .as_ref()
        .expect("admin")
        .enroll(entry)
        .expect("enroll");
    let admin = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    let open = |phrase: &str| {
        json!({ "operator_id": fx.owner_label_id.to_string(), "phrase": phrase }).to_string()
    };
    let wrong = admin
        .send(
            "POST",
            "/admin/v1/session",
            None,
            &[],
            Some(&open(WRONG_PHRASE)),
        )
        .await;
    assert_eq!(wrong.status, 401);
    // A sealed vault unlocked over the admin API.
    fx.lock().await;
    let resp = admin
        .send("POST", "/admin/v1/session", None, &[], Some(&open(PHRASE)))
        .await;
    assert_eq!(resp.status, 200);
    let token = resp.json()["token"].as_str().expect("token").to_owned();
    let (_, secret) = token.split_once('.').expect("shape");
    let secret = secret.to_owned();
    let reveal = admin
        .send(
            "POST",
            "/admin/v1/rpc/item_reveal",
            Some(&token),
            &[],
            Some(&json!({ "item": fx.item.to_string() }).to_string()),
        )
        .await;
    assert_eq!(reveal.status, 200);
    assert!(String::from_utf8_lossy(&reveal.body).contains(PASSWORD));
    // A session token on the agent API, and a forged one on the admin API.
    assert_eq!(fx.client().get("/v1/status", &token).await.status, 401);
    let forged = format!(
        "{}.{}",
        token.split_once('.').expect("shape").0,
        "B".repeat(43)
    );
    let refused = admin
        .send(
            "POST",
            "/admin/v1/rpc/agent_list",
            Some(&forged),
            &[],
            Some("{}"),
        )
        .await;
    assert_eq!(refused.status, 401);
    let closed = admin
        .send("DELETE", "/admin/v1/session", Some(&token), &[], None)
        .await;
    assert_eq!(closed.status, 204);
    fx.stop().await;

    let log = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        log.contains("/admin/v1/rpc/{command}"),
        "the route template is logged"
    );
    assert!(log.contains("admin session opened"));
    for forbidden in [
        PHRASE,
        WRONG_PHRASE,
        token.as_str(),
        secret.as_str(),
        forged.as_str(),
        "cas_",
        PASSWORD,
        USERNAME,
    ] {
        assert!(!log.contains(forbidden), "log holds `{forbidden}`");
    }
    assert!(
        !log.to_lowercase().contains("authorization"),
        "no header is logged"
    );
}
