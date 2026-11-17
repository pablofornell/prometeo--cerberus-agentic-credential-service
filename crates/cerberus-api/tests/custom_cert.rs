//! The owner custom certificate (ADR-0023 point 8, DEC-FIX9-*): load, reject, renewal, revert.
//! The certificates are made with rcgen through `LocalCa`, never real ones.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::net::SocketAddr;

use cerberus_api::tls::{
    CustomCertError, LocalCa, parse_custom_pem, spki_pin, store_custom_cert, write_leaf,
};
use cerberus_core::OperatorContext;
use cerberus_core::admin::AuditQuery;
use cerberus_types::{Clock, SystemClock, VaultId};
use common::{Fixture, Options, client_config, op_ctx};
use jiff::SignedDuration;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A foreign CA and a leaf for `names`, as PEM (chain = leaf + CA).
struct Owner {
    ca_der: Vec<u8>,
    leaf_der: Vec<u8>,
    chain_pem: String,
    key_pem: String,
}

fn owner_cert(names: &[&str], issued_at: jiff::Timestamp) -> Owner {
    let ca = LocalCa::create(&VaultId::generate(), SystemClock.now()).expect("ca");
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    let leaf = ca.issue_leaf(&names, issued_at).expect("leaf");
    Owner {
        ca_der: ca.cert_der().to_vec(),
        leaf_der: leaf.cert_der.clone(),
        chain_pem: format!("{}{}", leaf.cert_pem(), ca.export().expect("export").pem),
        key_pem: leaf.key_pem(),
    }
}

async fn handshake(addr: SocketAddr, trust: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
    let config = client_config(trust, &[&rustls::version::TLS13], None);
    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await?;
    Ok(tls
        .get_ref()
        .1
        .peer_certificates()
        .expect("certs")
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect())
}

async fn count(fx: &Fixture, ty: &str) -> usize {
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

async fn load(fx: &Fixture, owner: &Owner) -> Result<(), CustomCertError> {
    store_custom_cert(
        &fx.core,
        &op_ctx(&fx.owner),
        owner.chain_pem.as_bytes(),
        owner.key_pem.as_bytes(),
        &[],
    )
    .await
    .map(drop)
}

fn invalid_text(result: Result<(), CustomCertError>) -> String {
    match result {
        Err(CustomCertError::Invalid(text)) => text,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[tokio::test]
async fn a_loaded_certificate_is_served_with_no_restart_and_the_pin_changes() {
    let fx = Fixture::new().await;
    let server = fx.server.as_ref().expect("server");
    let owner = owner_cert(&["localhost", "127.0.0.1"], SystemClock.now());
    load(&fx, &owner).await.expect("load");
    server
        .apply_tls(&fx.core, &fx.tls, &[])
        .await
        .expect("apply");
    assert!(server.is_custom());
    let chain = handshake(fx.addr, &owner.ca_der).await.expect("handshake");
    assert_eq!(chain[0], owner.leaf_der);
    assert_eq!(chain.len(), 2);
    assert!(
        handshake(fx.addr, &fx.ca_der).await.is_err(),
        "a client that pins the local CA no longer matches"
    );
    let active = cerberus_api::tls::active_tls(&fx.core)
        .await
        .expect("active");
    assert!(active.custom);
    assert_eq!(active.anchor.pin, spki_pin(&owner.ca_der).expect("pin"));
    assert_eq!(count(&fx, "tls.custom_load").await, 1);
    fx.stop().await;
}

#[tokio::test]
async fn bad_certificates_are_refused_and_nothing_changes() {
    let fx = Fixture::new().await;
    let now = SystemClock.now();
    // The key of another certificate.
    let mut mismatch = owner_cert(&["localhost"], now);
    mismatch.key_pem = owner_cert(&["localhost"], now).key_pem;
    assert!(invalid_text(load(&fx, &mismatch).await).contains("does not match"));
    // Expired: issued 100 days ago, valid 90.
    let old = now - SignedDuration::from_hours(100 * 24);
    let expired = owner_cert(&["localhost"], old);
    assert!(invalid_text(load(&fx, &expired).await).contains("expired"));
    // No SAN for any standard name.
    let other = owner_cert(&["other.test"], now);
    assert!(invalid_text(load(&fx, &other).await).contains("covers none"));
    // A host name of the owner that the SAN lacks.
    let good = owner_cert(&["localhost"], now);
    let result = store_custom_cert(
        &fx.core,
        &op_ctx(&fx.owner),
        good.chain_pem.as_bytes(),
        good.key_pem.as_bytes(),
        &["agents.example".to_owned()],
    )
    .await
    .map(drop);
    assert!(invalid_text(result).contains("agents.example"));
    // Garbage.
    let mut junk = owner_cert(&["localhost"], now);
    junk.key_pem = "not a key".to_owned();
    assert!(invalid_text(load(&fx, &junk).await).contains("no usable private key"));
    junk.chain_pem = String::new();
    assert!(invalid_text(load(&fx, &junk).await).contains("no certificate"));
    assert!(fx.core.tls_custom_material().await.expect("read").is_none());
    assert_eq!(count(&fx, "tls.custom_load").await, 0);
    let server = fx.server.as_ref().expect("server");
    assert!(!server.is_custom());
    assert!(handshake(fx.addr, &fx.ca_der).await.is_ok());
    fx.stop().await;
}

#[tokio::test]
async fn only_the_owner_session_may_load_or_revert() {
    let fx = Fixture::new().await;
    let owner = owner_cert(&["localhost"], SystemClock.now());
    // A context for another operator is refused, whatever role it claims.
    let stranger = OperatorContext {
        operator_id: cerberus_types::OperatorId::generate(),
        ..op_ctx(&fx.owner)
    };
    let result = store_custom_cert(
        &fx.core,
        &stranger,
        owner.chain_pem.as_bytes(),
        owner.key_pem.as_bytes(),
        &[],
    )
    .await;
    assert!(matches!(result, Err(CustomCertError::Core(_))));
    assert!(fx.core.tls_custom_clear(&stranger).await.is_err());
    assert!(fx.core.tls_custom_material().await.expect("read").is_none());
    fx.stop().await;
}

#[tokio::test]
async fn renewal_leaves_a_custom_certificate_alone() {
    let fx = Fixture::with(Options {
        keep_ca: true,
        ..Options::default()
    })
    .await;
    let server = fx.server.as_ref().expect("server");
    let owner = owner_cert(&["localhost"], SystemClock.now());
    load(&fx, &owner).await.expect("load");
    server
        .apply_tls(&fx.core, &fx.tls, &[])
        .await
        .expect("apply");
    // An old local leaf is due for renewal, but the custom certificate stays.
    let ca = fx.ca.as_ref().expect("ca");
    let old_start = SystemClock.now() - SignedDuration::from_hours(80 * 24);
    let old = ca
        .issue_leaf(&cerberus_api::tls::leaf_names(&[]), old_start)
        .expect("old");
    write_leaf(&fx.tls, &old).expect("write");
    server.reload_leaf().expect("reload is a no-op");
    assert!(
        !server
            .renew_leaf(&fx.core, &fx.tls, &[])
            .await
            .expect("renew"),
        "no renewal while custom"
    );
    // A lock and unlock runs the renewal task, which applies the stored certificate again.
    let task = server.spawn_leaf_renewal(fx.core.clone(), fx.tls.clone(), Vec::new());
    fx.lock().await;
    fx.unlock().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let chain = handshake(fx.addr, &owner.ca_der).await.expect("handshake");
    assert_eq!(chain[0], owner.leaf_der);
    assert_eq!(
        std::fs::read(&fx.tls.leaf_cert_der).expect("file"),
        old.cert_der,
        "the local leaf file was not touched"
    );
    task.abort();
    fx.stop().await;
}

#[tokio::test]
async fn reverting_restores_the_local_ca_chain() {
    let fx = Fixture::new().await;
    let server = fx.server.as_ref().expect("server");
    let owner = owner_cert(&["localhost"], SystemClock.now());
    load(&fx, &owner).await.expect("load");
    server
        .apply_tls(&fx.core, &fx.tls, &[])
        .await
        .expect("apply");
    assert!(
        fx.core
            .tls_custom_clear(&op_ctx(&fx.owner))
            .await
            .expect("clear")
    );
    server
        .apply_tls(&fx.core, &fx.tls, &[])
        .await
        .expect("apply");
    assert!(!server.is_custom());
    let chain = handshake(fx.addr, &fx.ca_der).await.expect("handshake");
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1], fx.ca_der, "the local CA follows the leaf again");
    assert!(handshake(fx.addr, &owner.ca_der).await.is_err());
    assert!(fx.core.tls_custom_material().await.expect("read").is_none());
    assert_eq!(count(&fx, "tls.custom_revert").await, 1);
    // A second revert is a no-op and writes no event.
    assert!(
        !fx.core
            .tls_custom_clear(&op_ctx(&fx.owner))
            .await
            .expect("clear")
    );
    assert_eq!(count(&fx, "tls.custom_revert").await, 1);
    fx.stop().await;
}

#[test]
fn a_wildcard_san_and_an_unsupported_or_weak_input() {
    let now = SystemClock.now();
    let wild = owner_cert(&["*.example.test"], now);
    let names = vec!["agents.example.test".to_owned()];
    assert!(
        parse_custom_pem(
            wild.chain_pem.as_bytes(),
            wild.key_pem.as_bytes(),
            &names,
            now
        )
        .is_ok()
    );
    let deep = vec!["a.b.example.test".to_owned()];
    assert!(
        parse_custom_pem(
            wild.chain_pem.as_bytes(),
            wild.key_pem.as_bytes(),
            &deep,
            now
        )
        .is_err()
    );
    let bare = vec!["example.test".to_owned()];
    assert!(
        parse_custom_pem(
            wild.chain_pem.as_bytes(),
            wild.key_pem.as_bytes(),
            &bare,
            now
        )
        .is_err()
    );
    let encrypted =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
    let result = parse_custom_pem(wild.chain_pem.as_bytes(), encrypted.as_bytes(), &names, now);
    assert!(matches!(result, Err(CustomCertError::Invalid(t)) if t.contains("encrypted")));
}
