//! Tests of the bundle format with a CA and certificates made here (rcgen), as the daemon's
//! local CA makes them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cerberus_types::{Clock, SystemClock};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};

use super::*;

struct Ca {
    der: Vec<u8>,
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn ca() -> Ca {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Cerberus Local CA test");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().to_vec();
    let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(der.clone()), key).unwrap();
    Ca {
        pem: cert.pem(),
        der,
        issuer,
    }
}

struct Client {
    cert_pem: String,
    key_pem: String,
    not_after: Timestamp,
}

fn client(ca: &Ca, common_name: &str, expired: bool) -> Client {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = if expired {
        rcgen::date_time_ymd(2021, 1, 1)
    } else {
        rcgen::date_time_ymd(2090, 1, 1)
    };
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    let not_after = Timestamp::from_second(params.not_after.unix_timestamp()).unwrap();
    Client {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        not_after,
    }
}

fn bundle_with(ca: &Ca, id: EnrolmentId, client: Client) -> AdminBundle {
    AdminBundle {
        format: BUNDLE_FORMAT.to_owned(),
        version: BUNDLE_VERSION,
        id,
        label: "laptop".to_owned(),
        url: "https://vault.example.test:8443".to_owned(),
        operator_id: OperatorId::generate(),
        ca_pin: spki_pin(&ca.der).unwrap(),
        ca_cert_pem: ca.pem.clone(),
        client_cert_pem: client.cert_pem,
        client_key_pem: WireSecret::new(client.key_pem),
        not_after: client.not_after,
    }
}

fn bundle(ca: &Ca) -> AdminBundle {
    let id = EnrolmentId::generate();
    let made = client(ca, &format!("cerberus-admin {id}"), false);
    bundle_with(ca, id, made)
}

fn now() -> Timestamp {
    SystemClock.now()
}

#[test]
fn a_written_bundle_reads_back_and_is_never_overwritten() {
    let ca = ca();
    let original = bundle(&ca);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("laptop.cerberus-admin");
    original.write_new(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let read = AdminBundle::read(&path, now()).unwrap();
    assert_eq!(read.id, original.id);
    assert_eq!(read.label, original.label);
    assert_eq!(read.url, original.url);
    assert_eq!(read.operator_id, original.operator_id);
    assert_eq!(read.ca_pin, original.ca_pin);
    assert_eq!(read.client_cert_pem, original.client_cert_pem);
    assert_eq!(
        read.client_key_pem.expose(),
        original.client_key_pem.expose()
    );
    assert_eq!(read.not_after, original.not_after);
    assert_eq!(read.ca_sha256_hex().unwrap(), sha256_hex(&ca.der));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"format\":\"cerberus-admin-bundle\""));
    assert!(text.contains("\"version\":1"));

    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        bundle(&ca).write_new(&path),
        Err(BundleError::Exists)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn debug_never_prints_the_key() {
    let ca = ca();
    let bundle = bundle(&ca);
    let text = format!("{bundle:?}");
    assert!(text.contains("[REDACTED]"));
    assert!(!text.contains("PRIVATE KEY"));
}

#[test]
fn format_version_label_and_url_are_checked() {
    let ca = ca();
    let mut wrong = bundle(&ca);
    wrong.version = 2;
    assert!(matches!(wrong.check(now()), Err(BundleError::Version(2))));
    let mut other = bundle(&ca);
    other.format = "something-else".to_owned();
    assert!(matches!(other.check(now()), Err(BundleError::Format(_))));
    let mut label = bundle(&ca);
    label.label = String::new();
    assert!(matches!(label.check(now()), Err(BundleError::Label)));
    for url in [
        "http://vault.example.test:8443",
        "https://user:pw@vault.example.test",
        "https://vault.example.test/?x=1",
        "https://vault.example.test/admin",
        "https://vault.example.test/#top",
        "not a url",
    ] {
        let mut bad = bundle(&ca);
        bad.url = url.to_owned();
        assert!(matches!(bad.check(now()), Err(BundleError::Url)), "{url}");
    }
    let mut plain = bundle(&ca);
    plain.url = "https://127.0.0.1:9443/".to_owned();
    assert!(plain.check(now()).is_ok());
}

#[test]
fn the_pin_must_match_the_ca() {
    let ca = ca();
    let other = self::ca();
    let mut wrong = bundle(&ca);
    wrong.ca_pin = spki_pin(&other.der).unwrap();
    assert!(matches!(wrong.check(now()), Err(BundleError::Pin)));
    let mut no_prefix = bundle(&ca);
    no_prefix.ca_pin = no_prefix.ca_pin.trim_start_matches("sha256/").to_owned();
    assert!(matches!(no_prefix.check(now()), Err(BundleError::Pin)));
    // A swapped CA with its own matching pin still fails: the client is not signed by it.
    let mut swapped = bundle(&ca);
    swapped.ca_cert_pem = other.pem.clone();
    swapped.ca_pin = spki_pin(&other.der).unwrap();
    assert!(matches!(swapped.check(now()), Err(BundleError::Chain)));
}

#[test]
fn the_client_certificate_must_chain_be_current_and_match_its_key() {
    let ca = ca();
    let other = self::ca();
    let id = EnrolmentId::generate();
    let foreign = bundle_with(
        &ca,
        id,
        client(&other, &format!("cerberus-admin {id}"), false),
    );
    assert!(matches!(foreign.check(now()), Err(BundleError::Chain)));
    let expired = bundle_with(&ca, id, client(&ca, &format!("cerberus-admin {id}"), true));
    assert!(matches!(expired.check(now()), Err(BundleError::Chain)));

    let mut wrong_key = bundle(&ca);
    let stranger = client(&ca, "cerberus-admin someone-else", false);
    wrong_key.client_key_pem = WireSecret::new(stranger.key_pem);
    assert!(matches!(wrong_key.check(now()), Err(BundleError::Key)));
    let mut not_pkcs8 = bundle(&ca);
    not_pkcs8.client_key_pem = WireSecret::new("not a key".to_owned());
    assert!(matches!(not_pkcs8.check(now()), Err(BundleError::Key)));

    let other_id = bundle_with(
        &ca,
        EnrolmentId::generate(),
        client(&ca, &format!("cerberus-admin {id}"), false),
    );
    assert!(matches!(other_id.check(now()), Err(BundleError::Format(_))));
    let mut late = bundle(&ca);
    late.not_after += jiff::SignedDuration::from_secs(1);
    assert!(matches!(late.check(now()), Err(BundleError::Format(_))));
    let mut two = bundle(&ca);
    two.ca_cert_pem = format!("{}{}", ca.pem, other.pem);
    assert!(matches!(two.check(now()), Err(BundleError::Format(_))));
}

#[test]
fn a_bad_file_is_refused_without_quoting_it() {
    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("big");
    std::fs::write(&big, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert!(matches!(
        AdminBundle::read(&big, now()),
        Err(BundleError::TooLarge)
    ));
    assert!(matches!(
        AdminBundle::read(dir.path(), now()),
        Err(BundleError::NotAFile)
    ));
    let ca = ca();
    let mut json: serde_json::Value =
        serde_json::from_slice(&crate::rpc::zeroizing_json(&bundle(&ca)).unwrap()).unwrap();
    json["extra"] = serde_json::json!(true);
    let extra = dir.path().join("extra");
    std::fs::write(&extra, serde_json::to_vec(&json).unwrap()).unwrap();
    let error = AdminBundle::read(&extra, now()).unwrap_err();
    assert!(matches!(error, BundleError::Format(_)));
    assert!(!error.to_string().contains("PRIVATE KEY"));
    json.as_object_mut().unwrap().remove("extra");
    json["version"] = serde_json::json!("one");
    let typed = dir.path().join("typed");
    std::fs::write(&typed, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(matches!(
        AdminBundle::read(&typed, now()),
        Err(BundleError::Format(_))
    ));
}
