//! CA pinning and TLS version rules (ADR-0023, A8 from the client side).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use cerberus_api::tls::spki_pin;
use cerberus_client::transport::Request;
use cerberus_client::{
    Client, ClientConfig, ClientError, PinnedHttps, RetryPolicy, Trust, WireSecret,
};
use common::real::Real;
use common::script::{Pki, Reply, Script, Versions};

const TOKEN: &str = "cvt_00000000-0000-0000-0000-000000000000.fake-token";
const HEALTH: &str = r#"{"status":"ok","vault":"unlocked","version":"0.1.0"}"#;

fn config(url: &str, trust: Trust) -> ClientConfig {
    ClientConfig {
        base_url: url::Url::parse(url).unwrap(),
        token: WireSecret::new(TOKEN.to_owned()),
        trust,
        client_cert: None,
        timeout: std::time::Duration::from_secs(5),
    }
}

fn client(url: &str, trust: Trust) -> Client {
    Client::new(&config(url, trust))
        .unwrap()
        .with_retry(RetryPolicy::none())
}

#[tokio::test]
async fn the_right_pin_works_when_the_server_sends_the_ca() {
    let pki = Pki::new();
    let server = Script::start(
        &pki,
        true,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let c = client(&server.url(), Trust::Pin(pki.export.pin.clone()));
    let health = c.health().await.unwrap();
    assert_eq!(health.status, "ok");
    assert!(server.seen.lock().unwrap()[0].contains("auth=true"));
}

#[tokio::test]
async fn a_wrong_pin_fails_the_handshake() {
    let pki = Pki::new();
    let other = Pki::new();
    let server = Script::start(
        &pki,
        true,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let c = client(&server.url(), Trust::Pin(other.export.pin.clone()));
    let error = c.health().await.unwrap_err();
    assert!(matches!(error, ClientError::PinMismatch), "{error}");
    assert_eq!(server.count(), 0, "no request may reach the server");
}

#[tokio::test]
async fn a_pin_without_the_ca_in_the_chain_fails() {
    let pki = Pki::new();
    let server = Script::start(
        &pki,
        false,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let c = client(&server.url(), Trust::Pin(pki.export.pin.clone()));
    let error = c.health().await.unwrap_err();
    assert!(matches!(error, ClientError::PinMismatch), "{error}");
}

#[tokio::test]
async fn a_chain_signed_by_another_key_with_the_pinned_name_is_not_trusted() {
    // The attacker sends the real CA certificate but signed the leaf with a different CA.
    let real = Pki::new();
    let attacker = Pki::new();
    let server = Script::start(
        &attacker,
        true,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let c = client(&server.url(), Trust::Pin(real.export.pin.clone()));
    assert!(c.health().await.is_err());
}

#[tokio::test]
async fn ca_file_with_the_right_pin_works_with_a_leaf_only_server() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let server = Script::start(
        &pki,
        false,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let trust = Trust::CaFileAndPin {
        ca: pki.ca_file(dir.path()),
        pin: pki.export.pin.clone(),
    };
    assert!(client(&server.url(), trust).health().await.is_ok());
}

#[tokio::test]
async fn ca_file_with_a_wrong_pin_is_refused_before_any_connection() {
    let pki = Pki::new();
    let other = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let trust = Trust::CaFileAndPin {
        ca: pki.ca_file(dir.path()),
        pin: other.export.pin.clone(),
    };
    let error = Client::new(&config("https://127.0.0.1:1", trust)).unwrap_err();
    assert!(matches!(error, ClientError::PinMismatch), "{error}");
}

#[tokio::test]
async fn a_ca_file_of_another_ca_does_not_trust_the_server() {
    let pki = Pki::new();
    let other = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let server = Script::start(
        &pki,
        true,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let c = client(&server.url(), Trust::CaFile(other.ca_file(dir.path())));
    let error = c.health().await.unwrap_err();
    assert!(matches!(error, ClientError::Tls(_)), "{error}");
}

#[tokio::test]
async fn a_tls12_only_server_is_refused() {
    let pki = Pki::new();
    let server = Script::start(
        &pki,
        true,
        Versions::Tls12Only,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let c = client(&server.url(), Trust::Pin(pki.export.pin.clone()));
    let error = c.health().await.unwrap_err();
    assert!(matches!(error, ClientError::Tls(_)), "{error}");
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn plain_http_urls_are_refused() {
    let error = PinnedHttps::new(
        "http://127.0.0.1:7373",
        &Trust::Pin("sha256/AAAA".to_owned()),
        &WireSecret::new(TOKEN.to_owned()),
    )
    .unwrap_err();
    assert!(matches!(error, ClientError::Config(_)), "{error}");
}

#[tokio::test]
async fn our_pin_matches_the_pin_the_app_shows() {
    // The app computes the pin with x509-parser; the client computes it with webpki parts.
    // This test runs a real handshake against the real server and compares both numbers.
    let real = Real::start().await;
    let shown = spki_pin(&real.core.tls_ca_cert().await.unwrap()).unwrap();
    assert_eq!(shown, real.export.pin);
    let c = Client::new(&ClientConfig {
        trust: Trust::CaFileAndPin {
            ca: real.ca_file.clone(),
            pin: shown,
        },
        ..real.config()
    })
    .unwrap();
    assert_eq!(c.health().await.unwrap().status, "ok");
    real.stop().await;
}

#[tokio::test]
async fn a_pin_only_client_trusts_the_real_server_and_rejects_another_ca() {
    // DEC-FIX8-1: the real server sends [leaf, CA], so a pin alone is enough.
    let real = Real::start().await;
    let c = Client::new(&ClientConfig {
        trust: Trust::Pin(real.export.pin.clone()),
        ..real.config()
    })
    .unwrap();
    assert_eq!(c.health().await.unwrap().status, "ok");
    let other = Pki::new();
    let wrong = Client::new(&ClientConfig {
        trust: Trust::Pin(other.export.pin.clone()),
        ..real.config()
    })
    .unwrap()
    .with_retry(RetryPolicy::none());
    assert!(matches!(
        wrong.health().await.unwrap_err(),
        ClientError::PinMismatch
    ));
    real.stop().await;
}

/// AUD-17: with a pin, only the pinned certificate of the CA file is a root. A bundle that also
/// holds another CA must not make a server of that CA trusted.
#[tokio::test]
async fn aud17_a_pin_trusts_only_the_pinned_certificate_of_a_bundle() {
    let ours = Pki::new();
    let other = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(
        &bundle,
        format!("{}\n{}", ours.export.pem, other.export.pem),
    )
    .unwrap();
    let server = Script::start(
        &other,
        true,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let trust = Trust::CaFileAndPin {
        ca: bundle.clone(),
        pin: ours.export.pin.clone(),
    };
    let error = client(&server.url(), trust).health().await.unwrap_err();
    assert!(matches!(error, ClientError::Tls(_)), "{error}");
    assert_eq!(server.count(), 0, "no request may reach the server");
    // The pinned CA still works from the same bundle.
    let good = Script::start(
        &ours,
        true,
        Versions::Tls13,
        vec![Reply::Json(200, HEALTH.into())],
    )
    .await;
    let trust = Trust::CaFileAndPin {
        ca: bundle,
        pin: ours.export.pin.clone(),
    };
    assert!(client(&good.url(), trust).health().await.is_ok());
}

// ---------------------------------------------------------------- admin transport (ADR-0034)

/// An admin client certificate of the test CA, written as PEM files.
fn admin_identity(
    pki: &Pki,
    dir: &std::path::Path,
) -> ((std::path::PathBuf, std::path::PathBuf), [u8; 32]) {
    use cerberus_types::Clock;
    let cert = pki
        .ca
        .issue_admin_client(
            "0190f000-0000-7000-8000-00000000000a",
            cerberus_types::SystemClock.now(),
        )
        .unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert_pem()).unwrap();
    std::fs::write(&key_path, cert.key_pem()).unwrap();
    ((cert_path, key_path), cert.sha256())
}

#[tokio::test]
async fn a_client_certificate_is_presented_and_verified() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let server = Script::start_mtls(&pki, vec![Reply::Json(200, HEALTH.into())]).await;
    let (files, sha) = admin_identity(&pki, dir.path());
    let http = PinnedHttps::with_client_cert(
        &server.url(),
        &Trust::Pin(pki.export.pin.clone()),
        files,
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let response = http
        .send_bearer(Request::get("/admin/v1/hello"), None)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(server.client_certs.lock().unwrap().as_slice(), &[sha]);
    assert_eq!(server.auths.lock().unwrap().as_slice(), &[String::new()]);
    // Without a certificate the server refuses the handshake.
    let bare = PinnedHttps::new(
        &server.url(),
        &Trust::Pin(pki.export.pin.clone()),
        &WireSecret::new(TOKEN.to_owned()),
    )
    .unwrap();
    assert!(bare.get("/admin/v1/hello").await.is_err());
    // A certificate of another CA is refused too.
    let other = Pki::new();
    let other_dir = tempfile::tempdir().unwrap();
    let (files, _) = admin_identity(&other, other_dir.path());
    let foreign = PinnedHttps::with_client_cert(
        &server.url(),
        &Trust::Pin(pki.export.pin.clone()),
        files,
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        foreign
            .send_bearer(Request::get("/admin/v1/hello"), None)
            .await
            .is_err()
    );
    assert_eq!(
        server.count(),
        1,
        "only the enrolled certificate got an answer"
    );
}

#[tokio::test]
async fn each_request_carries_its_own_bearer() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let server = Script::start_mtls(
        &pki,
        vec![
            Reply::Json(200, "{}".into()),
            Reply::Json(200, "{}".into()),
            Reply::Json(200, "{}".into()),
        ],
    )
    .await;
    let (files, _) = admin_identity(&pki, dir.path());
    let http = PinnedHttps::with_client_cert(
        &server.url(),
        &Trust::Pin(pki.export.pin.clone()),
        files,
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let first = WireSecret::new("cas_first.fake-secret".to_owned());
    let second = WireSecret::new("cas_second.fake-secret".to_owned());
    let mut forged = Request::post_json("/admin/v1/rpc/item_list", r#"{"filter":{}}"#);
    forged.headers.push(("authorization", "Bearer forged"));
    http.send_bearer(forged, Some(&first)).await.unwrap();
    let body = cerberus_client::zeroizing_body(zeroize::Zeroizing::new(b"{}".to_vec()));
    http.send_bearer(
        Request::post_json("/admin/v1/rpc/agent_list", body),
        Some(&second),
    )
    .await
    .unwrap();
    http.send_bearer(Request::get("/admin/v1/hello"), None)
        .await
        .unwrap();
    assert_eq!(
        server.auths.lock().unwrap().as_slice(),
        &[
            "Bearer cas_first.fake-secret".to_owned(),
            "Bearer cas_second.fake-secret".to_owned(),
            String::new(),
        ]
    );
}

#[tokio::test]
async fn the_generic_event_stream_reads_names_data_and_skips_comments() {
    let pki = Pki::new();
    let dir = tempfile::tempdir().unwrap();
    let body = concat!(
        ": keep-alive\n\n",
        "event: AccessRequestCreated\r\ndata: {\"event\":\"AccessRequestCreated\",\"id\":\"r1\"}\r\n\r\n",
        "event: Multi\ndata: line one\ndata: line two\n\n",
        "id: 7\nretry: 1000\n\n",
        "data: no name\n\n",
    );
    let server = Script::start_mtls(&pki, vec![Reply::Events(body.to_owned())]).await;
    let (files, _) = admin_identity(&pki, dir.path());
    let http = PinnedHttps::with_client_cert(
        &server.url(),
        &Trust::Pin(pki.export.pin.clone()),
        files,
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let token = WireSecret::new("cas_x.fake-secret".to_owned());
    let response = http
        .send_bearer(Request::get("/admin/v1/events"), Some(&token))
        .await
        .unwrap();
    assert_eq!(response.header("content-type"), Some("text/event-stream"));
    let mut events = cerberus_client::EventStream::new(response);
    let mut got = Vec::new();
    while let Some(event) = events.next().await {
        let (name, data) = event.unwrap();
        got.push((name, String::from_utf8(data).unwrap()));
    }
    assert_eq!(
        got,
        vec![
            (
                "AccessRequestCreated".to_owned(),
                r#"{"event":"AccessRequestCreated","id":"r1"}"#.to_owned()
            ),
            ("Multi".to_owned(), "line one\nline two".to_owned()),
            ("message".to_owned(), "no name".to_owned()),
        ]
    );
}
