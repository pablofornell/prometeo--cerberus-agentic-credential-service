//! Payload validation per kind, JSON round trip and redacted `Debug`.

use std::collections::BTreeMap;

use cerberus_types::ItemKind;

use super::fixture::{input, login_payload, secret};
use crate::items::{
    MAX_PAYLOAD_BYTES, Payload, TotpSeed, generate_ed25519, validate_item, validate_payload,
};

const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const CERT: &str = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";

fn problems(payload: &Payload) -> Vec<String> {
    validate_payload(payload)
        .into_iter()
        .map(|p| p.field)
        .collect()
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, cerberus_crypto::SecretString> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), secret(v)))
        .collect()
}

fn db(url: Option<&str>, engine: Option<&str>, host: Option<&str>) -> Payload {
    Payload::Database {
        url: url.map(secret),
        engine: engine.map(str::to_owned),
        host: host.map(str::to_owned),
        port: None,
        database: None,
        username: engine.map(|_| secret("fake-user")),
        password: engine.map(|_| secret("fake-pass")),
        params: BTreeMap::new(),
    }
}

fn cloud(key: Option<&str>, secret_key: Option<&str>, token: Option<&str>) -> Payload {
    Payload::Cloud {
        provider: "aws".to_owned(),
        access_key_id: key.map(secret),
        secret_access_key: secret_key.map(secret),
        session_token: token.map(secret),
        region: None,
        extra: BTreeMap::new(),
    }
}

fn totp(seed: &str, digits: u8, period: u32) -> Payload {
    Payload::WebLogin {
        username: secret("u"),
        password: secret("p"),
        url: None,
        totp: Some(TotpSeed {
            secret: secret(seed),
            algorithm: crate::items::TotpAlgorithm::Sha1,
            digits,
            period,
        }),
    }
}

fn cert(cert_pem: &str, key: Option<&str>) -> Payload {
    Payload::Certificate {
        cert_pem: cert_pem.to_owned(),
        key_pem: key.map(secret),
        chain_pem: None,
    }
}

fn browser(state: &str, origin: &str) -> Payload {
    Payload::BrowserSession {
        storage_state: secret(state),
        origin: origin.to_owned(),
    }
}

#[test]
fn valid_payloads_of_every_kind_pass() {
    let ssh = generate_ed25519("fake@test").unwrap();
    let valid = [
        login_payload("alice", "fake-password-1"),
        totp(SEED, 6, 30),
        Payload::ApiKey {
            key: secret("fake-key"),
            key_id: Some("id-1".to_owned()),
            header_name: Some("X-Api-Key".to_owned()),
            base_url: Some("https://api.example.test".to_owned()),
        },
        ssh,
        Payload::SessionToken {
            token: secret("fake-token"),
            token_type: Some("Bearer".to_owned()),
            header_name: Some("Authorization".to_owned()),
        },
        browser(
            r#"{"cookies":[{"name":"a"}],"origins":[]}"#,
            "https://shop.example.test",
        ),
        db(Some("postgres://u:p@db.example.test/app"), None, None),
        db(None, Some("postgres"), Some("db.example.test")),
        cloud(Some("AKIAFAKE"), Some("fake-secret"), None),
        cloud(None, None, Some("fake-session")),
        cert(
            CERT,
            Some("-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----"),
        ),
        Payload::EnvBundle {
            vars: map(&[("DATABASE_URL", "fake"), ("_X1", "fake")]),
        },
        Payload::Note {
            text: secret("a fake note"),
        },
    ];
    for payload in &valid {
        assert!(
            problems(payload).is_empty(),
            "{:?}",
            validate_payload(payload)
        );
    }
    let kinds: std::collections::BTreeSet<_> =
        valid.iter().map(|p| format!("{:?}", p.kind())).collect();
    assert_eq!(kinds.len(), 10, "every kind is covered");
}

#[test]
fn invalid_payloads_name_the_field() {
    let long = "x".repeat(70_000);
    let cases: Vec<(&str, Payload, &str)> = vec![
        (
            "empty password",
            Payload::WebLogin {
                username: secret("u"),
                password: secret(""),
                url: None,
                totp: None,
            },
            "payload.password",
        ),
        (
            "empty username",
            Payload::WebLogin {
                username: secret(""),
                password: secret("p"),
                url: None,
                totp: None,
            },
            "payload.username",
        ),
        (
            "ftp url",
            Payload::WebLogin {
                username: secret("u"),
                password: secret("p"),
                url: Some("ftp://x".into()),
                totp: None,
            },
            "payload.url",
        ),
        (
            "seed not base32",
            totp("not base32!!", 6, 30),
            "payload.totp",
        ),
        ("seed too short", totp("GEZDGNBV", 6, 30), "payload.totp"),
        ("7 digits", totp(SEED, 7, 30), "payload.totp"),
        ("period 10", totp(SEED, 6, 10), "payload.totp"),
        ("period 121", totp(SEED, 6, 121), "payload.totp"),
        (
            "empty api key",
            Payload::ApiKey {
                key: secret(""),
                key_id: None,
                header_name: None,
                base_url: None,
            },
            "payload.key",
        ),
        (
            "bad header",
            Payload::ApiKey {
                key: secret("k"),
                key_id: None,
                header_name: Some("X Key".into()),
                base_url: None,
            },
            "payload.header_name",
        ),
        (
            "bad base url",
            Payload::ApiKey {
                key: secret("k"),
                key_id: None,
                header_name: None,
                base_url: Some("api".into()),
            },
            "payload.base_url",
        ),
        (
            "ssh garbage",
            Payload::SshKey {
                private_key: secret("nope"),
                passphrase: None,
                public_key: "x".into(),
                fingerprint: "y".into(),
            },
            "payload.private_key",
        ),
        (
            "empty token",
            Payload::SessionToken {
                token: secret(""),
                token_type: None,
                header_name: None,
            },
            "payload.token",
        ),
        (
            "storage not json",
            browser("nope", "https://a.test"),
            "payload.storage_state",
        ),
        (
            "storage not object",
            browser("[1]", "https://a.test"),
            "payload.storage_state",
        ),
        (
            "cookies not array",
            browser(r#"{"cookies":3}"#, "https://a.test"),
            "payload.storage_state",
        ),
        ("bad origin", browser("{}", "a.test"), "payload.origin"),
        ("db empty", db(None, None, None), "payload.url"),
        (
            "db url and fields",
            Payload::Database {
                url: Some(secret("postgres://h/d")),
                engine: Some("postgres".into()),
                host: None,
                port: None,
                database: None,
                username: None,
                password: None,
                params: BTreeMap::new(),
            },
            "payload.url",
        ),
        (
            "db url no scheme",
            db(Some("hostonly"), None, None),
            "payload.url",
        ),
        (
            "db no host",
            db(None, Some("postgres"), None),
            "payload.host",
        ),
        (
            "db port 0",
            Payload::Database {
                url: None,
                engine: Some("pg".into()),
                host: Some("h".into()),
                port: Some(0),
                database: None,
                username: Some(secret("u")),
                password: Some(secret("p")),
                params: BTreeMap::new(),
            },
            "payload.port",
        ),
        ("cloud empty", cloud(None, None, None), "payload.provider"),
        (
            "cloud key without secret",
            cloud(Some("AK"), None, None),
            "payload.access_key_id",
        ),
        ("cert not pem", cert("hello", None), "payload.cert_pem"),
        (
            "cert has private key",
            cert(
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----",
                None,
            ),
            "payload.cert_pem",
        ),
        ("key not pem", cert(CERT, Some("hello")), "payload.key_pem"),
        (
            "env empty",
            Payload::EnvBundle {
                vars: BTreeMap::new(),
            },
            "payload.vars",
        ),
        (
            "env lower case name",
            Payload::EnvBundle {
                vars: map(&[("path", "x")]),
            },
            "payload.vars.path",
        ),
        (
            "env digit first",
            Payload::EnvBundle {
                vars: map(&[("1A", "x")]),
            },
            "payload.vars.1A",
        ),
        (
            "empty note",
            Payload::Note { text: secret("") },
            "payload.text",
        ),
        (
            "note too large",
            Payload::Note {
                text: secret(&long),
            },
            "payload",
        ),
    ];
    for (name, payload, field) in cases {
        let got = problems(&payload);
        assert!(
            got.iter().any(|f| f == field),
            "{name}: wanted {field}, got {got:?}"
        );
    }
}

#[test]
fn size_limits_differ_for_browser_sessions() {
    let big = format!(
        r#"{{"cookies":[],"pad":"{}"}}"#,
        "x".repeat(MAX_PAYLOAD_BYTES * 2)
    );
    assert!(
        problems(&browser(&big, "https://a.test")).is_empty(),
        "1 MiB allowed"
    );
    let huge = format!(r#"{{"pad":"{}"}}"#, "x".repeat(1_100_000));
    assert!(problems(&browser(&huge, "https://a.test")).contains(&"payload".to_owned()));
}

#[test]
fn metadata_rules() {
    let ws = cerberus_types::WorkspaceId::generate();
    let ok = || input(ws, "Staging admin", login_payload("u", "p"));
    assert!(validate_item(&ok()).is_ok());
    let mut cases: Vec<(&str, crate::items::ItemInput, &str)> = Vec::new();
    let mut a = ok();
    a.title = String::new();
    cases.push(("empty title", a, "title"));
    let mut a = ok();
    a.title = "x".repeat(201);
    cases.push(("long title", a, "title"));
    let mut a = ok();
    a.title = "bad\ntitle".into();
    cases.push(("control char", a, "title"));
    let mut a = ok();
    a.description = "x".repeat(2001);
    cases.push(("long description", a, "description"));
    let mut a = ok();
    a.role_label = Some("x".repeat(65));
    cases.push(("long role", a, "role_label"));
    let mut a = ok();
    a.category = String::new();
    cases.push(("no category", a, "category"));
    let mut a = ok();
    a.tags = (0..21).map(|i| format!("t{i}")).collect();
    cases.push(("21 tags", a, "tags"));
    let mut a = ok();
    a.tags = vec!["Dup".into(), "dup".into()];
    cases.push(("duplicate tag", a, "tags[1]"));
    let mut a = ok();
    a.target = Some("x".repeat(513));
    cases.push(("long target", a, "target"));
    let mut a = ok();
    a.custom.insert("Bad Key".into(), "v".into());
    cases.push(("custom key", a, "custom.Bad Key"));
    let mut a = ok();
    a.max_uses = Some(0);
    cases.push(("max uses 0", a, "max_uses"));
    for (name, item, field) in cases {
        let got: Vec<String> = validate_item(&item)
            .unwrap_err()
            .into_iter()
            .map(|p| p.field)
            .collect();
        assert!(got.iter().any(|f| f == field), "{name}: {got:?}");
    }
}

#[test]
fn ssh_custom_port_is_checked() {
    let mut item = input(
        cerberus_types::WorkspaceId::generate(),
        "build-01 key",
        generate_ed25519("fake").unwrap(),
    );
    item.custom.insert("port".into(), "70000".into());
    let fields: Vec<String> = validate_item(&item)
        .unwrap_err()
        .into_iter()
        .map(|p| p.field)
        .collect();
    assert!(fields.contains(&"custom.port".to_owned()), "{fields:?}");
    item.custom.insert("port".into(), "22".into());
    assert!(validate_item(&item).is_ok());
}

#[test]
fn json_round_trip_keeps_every_field() {
    let payloads = [
        totp(SEED, 8, 60),
        db(None, Some("postgres"), Some("db.example.test")),
        cloud(Some("AK"), Some("SK"), Some("TOK")),
        generate_ed25519("fake").unwrap(),
        Payload::EnvBundle {
            vars: map(&[("A_B", "1"), ("C", "2")]),
        },
        cert(
            CERT,
            Some("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"),
        ),
        browser("{}", "https://a.test"),
    ];
    for payload in payloads {
        let json = payload.to_json().unwrap();
        let back = Payload::from_json(&json).unwrap();
        assert_eq!(back.to_json().unwrap().as_slice(), json.as_slice());
        assert_eq!(back.kind(), payload.kind());
        assert_eq!(back.has_totp(), payload.has_totp());
    }
    assert!(Payload::from_json(b"{}").is_err());
    assert!(Payload::from_json(br#"{"kind":"note","text":"x","extra":1}"#).is_err());
}

#[test]
fn debug_never_prints_a_secret() {
    let payload = Payload::WebLogin {
        username: secret("marker-user-71"),
        password: secret("marker-pass-71"),
        url: None,
        totp: Some(TotpSeed::standard(secret("MARKERSEED71MARKERSEED71MARKER"))),
    };
    let text = format!("{payload:?}");
    assert!(
        !text.contains("marker") && !text.contains("MARKER"),
        "{text}"
    );
    assert!(text.contains("[REDACTED]"));
    assert_eq!(payload.kind(), ItemKind::WebLogin);
}
