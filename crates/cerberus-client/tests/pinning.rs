//! CA pinning and TLS version rules (ADR-0023, A8 from the client side).
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use cerberus_api::tls::spki_pin;
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
