//! The local CA material and the owner custom certificate.

use cerberus_crypto::SecretBytes;
use cerberus_store::SettingRow;
use cerberus_types::{LockReason, OperatorRole};

use super::fixture::*;
use crate::admin::AuditQuery;
use crate::error::CoreError;
use crate::vault::{KeyCustody, TLS_CUSTOM_SETTING};

fn chain(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|n| vec![0xA0, u8::try_from(n).unwrap()])
        .collect()
}

fn key() -> SecretBytes {
    SecretBytes::new(b"fake-leaf-key".to_vec())
}

/// Seals `plain` as the custom setting, bypassing the framing code.
async fn put_raw_custom(fixture: &Fixture, plain: &[u8]) {
    let guard = fixture.service.unlocked().await.unwrap();
    let row = SettingRow {
        key: TLS_CUSTOM_SETTING.to_owned(),
        updated_at: fixture.clock_now(),
        value_ct: guard
            .blobs()
            .seal_setting(TLS_CUSTOM_SETTING, plain)
            .unwrap(),
    };
    let mut tx = fixture.service.store().begin().await.unwrap();
    tx.put_setting(&row).await.unwrap();
    tx.commit().await.unwrap();
}

async fn event_types(fixture: &Fixture, ctx: &crate::context::OperatorContext) -> Vec<String> {
    let mut rows = fixture
        .service
        .audit_query(
            ctx,
            AuditQuery {
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    rows.reverse();
    rows.into_iter().map(|e| e.event.event_type).collect()
}

#[tokio::test]
async fn ca_cert_is_readable_while_locked() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    assert_eq!(
        fixture.service.tls_ca_cert().await.unwrap(),
        b"fake-ca-cert".to_vec()
    );
}

#[tokio::test]
async fn ca_cert_before_a_vault_exists_is_no_vault() {
    let fixture = Fixture::empty().await;
    assert!(matches!(
        fixture.service.tls_ca_cert().await,
        Err(CoreError::NoVault)
    ));
}

#[tokio::test]
async fn ca_material_has_cert_key_and_host_names() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let material = fixture.service.tls_ca_material().await.unwrap();
    assert_eq!(material.cert_der, b"fake-ca-cert".to_vec());
    assert_eq!(material.key_der.expose_secret(), b"fake-ca-key");
    assert_eq!(material.host_names, vec!["build-box".to_owned()]);
    let shown = format!("{material:?}");
    assert!(shown.contains("[REDACTED]"));
    assert!(!shown.contains("fake-ca-key"));
}

#[tokio::test]
async fn ca_material_needs_an_unlocked_vault() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    assert!(matches!(
        fixture.service.tls_ca_material().await,
        Err(CoreError::Locked)
    ));
}

#[tokio::test]
async fn ca_material_with_a_broken_key_is_an_internal_error() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let raw = fixture.raw().await;
    sqlx::query("UPDATE tls_ca SET ca_key_ct = x'00010203'")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    // The store reports the failed open; the wire code is `internal`.
    let error = fixture.service.tls_ca_material().await.unwrap_err();
    assert!(matches!(error, CoreError::Store(_)));
    assert_eq!(error.code(), cerberus_types::ErrorCode::Internal);
}

#[tokio::test]
async fn ca_material_with_unreadable_host_names_is_corrupt() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let guard = fixture.service.unlocked().await.unwrap();
    let row = SettingRow {
        key: "tls_host_names".to_owned(),
        updated_at: fixture.clock_now(),
        value_ct: guard
            .blobs()
            .seal_setting("tls_host_names", b"not json")
            .unwrap(),
    };
    let mut tx = fixture.service.store().begin().await.unwrap();
    tx.put_setting(&row).await.unwrap();
    tx.commit().await.unwrap();
    drop(guard);
    assert!(matches!(
        fixture.service.tls_ca_material().await,
        Err(CoreError::Corrupt)
    ));
}

#[tokio::test]
async fn ca_material_without_host_names_has_an_empty_list() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let mut tx = fixture.service.store().begin().await.unwrap();
    assert!(tx.delete_setting("tls_host_names").await.unwrap());
    tx.commit().await.unwrap();
    let material = fixture.service.tls_ca_material().await.unwrap();
    assert!(material.host_names.is_empty());
}

#[tokio::test]
async fn custom_certificate_round_trips_and_is_audited() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert!(service.tls_custom_material().await.unwrap().is_none());
    service
        .tls_custom_store(&ctx, &chain(3), &key())
        .await
        .unwrap();
    let material = service.tls_custom_material().await.unwrap().unwrap();
    assert_eq!(material.chain_der, chain(3));
    assert_eq!(material.key_der.expose_secret(), b"fake-leaf-key");
    let shown = format!("{material:?}");
    assert!(shown.contains("chain_len: 3"));
    assert!(!shown.contains("fake-leaf-key"));

    // A restart reads the same material: it is stored, not cached.
    service.lock(LockReason::Manual).await.unwrap();
    let again = fixture.reopen().await;
    again
        .unlock_with_phrase(ctx.operator_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert_eq!(
        again
            .tls_custom_material()
            .await
            .unwrap()
            .unwrap()
            .chain_der
            .len(),
        3
    );

    let ctx = service
        .unlock_with_phrase(ctx.operator_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert!(service.tls_custom_clear(&ctx).await.unwrap());
    assert!(service.tls_custom_material().await.unwrap().is_none());
    assert!(
        !service.tls_custom_clear(&ctx).await.unwrap(),
        "nothing left to clear"
    );
    let types = event_types(&fixture, &ctx).await;
    assert_eq!(types.iter().filter(|t| *t == "tls.custom_load").count(), 1);
    assert_eq!(
        types.iter().filter(|t| *t == "tls.custom_revert").count(),
        1,
        "the second clear wrote nothing"
    );
}

#[tokio::test]
async fn custom_certificate_rejects_an_empty_or_too_long_chain() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert!(matches!(
        service.tls_custom_store(&ctx, &[], &key()).await,
        Err(CoreError::Corrupt)
    ));
    assert!(matches!(
        service.tls_custom_store(&ctx, &chain(9), &key()).await,
        Err(CoreError::Corrupt)
    ));
    service
        .tls_custom_store(&ctx, &chain(8), &key())
        .await
        .unwrap();
    assert!(service.tls_custom_material().await.unwrap().is_some());
}

#[tokio::test]
async fn custom_certificate_changes_need_the_owner_session() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let operator = service
        .add_operator(
            &ctx,
            "Second".to_owned(),
            OperatorRole::Operator,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let operator_ctx = service
        .unlock_with_phrase(operator, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    assert!(matches!(
        service
            .tls_custom_store(&operator_ctx, &chain(1), &key())
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        service.tls_custom_clear(&operator_ctx).await,
        Err(CoreError::RoleNotAllowed)
    ));
    // A context of another operator is refused too.
    assert!(matches!(
        service.tls_custom_clear(&ctx).await,
        Err(CoreError::Forbidden)
    ));
    service.lock(LockReason::Manual).await.unwrap();
    assert!(matches!(
        service.tls_custom_store(&ctx, &chain(1), &key()).await,
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        service.tls_custom_clear(&ctx).await,
        Err(CoreError::Locked)
    ));
    assert!(matches!(
        service.tls_custom_material().await,
        Err(CoreError::Locked)
    ));
    let _ = created;
}

#[tokio::test]
async fn custom_certificate_with_bad_framing_is_corrupt() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("too short for a count", vec![0, 0]),
        ("zero certificates", vec![0, 0, 0, 0]),
        ("too many certificates", vec![0, 0, 0, 9]),
        ("count without parts", vec![0, 0, 0, 1]),
        (
            "part longer than the data",
            vec![0, 0, 0, 1, 0, 0, 0, 9, 1, 2],
        ),
        ("certificate without a key", vec![0, 0, 0, 1, 0, 0, 0, 1, 7]),
        (
            "bytes after the key",
            vec![0, 0, 0, 1, 0, 0, 0, 1, 7, 0, 0, 0, 1, 8, 9],
        ),
    ];
    for (name, plain) in cases {
        put_raw_custom(&fixture, &plain).await;
        assert!(
            matches!(
                fixture.service.tls_custom_material().await,
                Err(CoreError::Corrupt)
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn custom_certificate_that_does_not_open_is_corrupt() {
    let (fixture, _created, ctx) = Fixture::created().await;
    fixture
        .service
        .tls_custom_store(&ctx, &chain(1), &key())
        .await
        .unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE settings SET value_ct = x'00010203' WHERE key = 'tls_custom'")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    assert!(matches!(
        fixture.service.tls_custom_material().await,
        Err(CoreError::Corrupt)
    ));
}
