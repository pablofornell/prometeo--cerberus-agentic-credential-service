//! The phrase check of an admin session on an unlocked vault, and the admin audit events
//! (ADR-0034 points 3, 6.3 and 6.7).

use cerberus_store::SlotKind;
use cerberus_types::{LockReason, OperatorId, OperatorRole, VaultStateKind};

use super::fixture::*;
use crate::admin::{AuditEntry, AuditQuery};
use crate::audit::ChainReport;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::vault::{AdminAudit, AdminEventKind, KeyCustody, SessionCloseReason};

async fn failed_unlocks(fixture: &Fixture) -> u32 {
    fixture
        .service
        .store()
        .header()
        .await
        .unwrap()
        .failed_unlocks
}

async fn events(fixture: &Fixture, ctx: &OperatorContext, kind: &str) -> Vec<AuditEntry> {
    fixture
        .service
        .audit_query(
            ctx,
            AuditQuery {
                from: None,
                to: None,
                event_type: Some(kind.to_owned()),
                agent_id: None,
                item_id: None,
                outcome: None,
                before_seq: None,
                limit: 100,
                text: None,
            },
        )
        .await
        .unwrap()
}

async fn recovery_slot(fixture: &Fixture) -> OperatorId {
    fixture
        .service
        .store()
        .key_slots()
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.kind == SlotKind::Recovery)
        .unwrap()
        .id
}

#[tokio::test]
async fn the_right_phrase_gives_the_session_context_and_changes_nothing() {
    let (fixture, created, ctx) = Fixture::created().await;
    let before = fixture.service.status().await;
    let checked = fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert_eq!(checked.operator_id, ctx.operator_id);
    assert_eq!(checked.role, OperatorRole::Owner);
    assert_ne!(checked.request_id, ctx.request_id);
    let after = fixture.service.status().await;
    assert_eq!(after.state, VaultStateKind::Unlocked);
    assert_eq!(after.session, before.session);
    assert_eq!(failed_unlocks(&fixture).await, 0);
    // The context works for operator calls of the live session.
    assert!(fixture.service.list_workspaces(&checked).await.is_ok());
    assert!(
        events(&fixture, &ctx, "vault.unlock_failed")
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_wrong_phrase_counts_as_a_failed_unlock() {
    let (fixture, created, ctx) = Fixture::created().await;
    let wrong = fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(WRONG_PHRASE))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    assert_eq!(failed_unlocks(&fixture).await, 1);
    let failed = events(&fixture, &ctx, "vault.unlock_failed").await;
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].event.details["operator"],
        created.owner_id.to_string()
    );
    assert_eq!(fixture.service.state(), VaultStateKind::Unlocked);
    // A right phrase clears the counter.
    fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert_eq!(failed_unlocks(&fixture).await, 0);
}

#[tokio::test]
async fn a_sealed_vault_is_locked() {
    let (fixture, created, _) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let sealed = fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(sealed, Err(CoreError::Locked)));
    assert_eq!(failed_unlocks(&fixture).await, 0);
    let empty = Fixture::empty().await;
    let none = empty
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(none, Err(CoreError::NoVault)));
}

#[tokio::test]
async fn another_operator_is_a_conflict() {
    let (fixture, _, ctx) = Fixture::created().await;
    let second = fixture
        .service
        .add_operator(
            &ctx,
            "Second".to_owned(),
            OperatorRole::Operator,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    let other = fixture
        .service
        .verify_operator_phrase(second, phrase(SECOND_PHRASE))
        .await;
    assert!(matches!(other, Err(CoreError::Conflict)));
    assert_eq!(failed_unlocks(&fixture).await, 0);
}

#[tokio::test]
async fn the_back_off_refuses_before_the_kdf() {
    let (fixture, created, _) = Fixture::created().await;
    for _ in 0..5 {
        let wrong = fixture
            .service
            .verify_operator_phrase(created.owner_id, phrase(WRONG_PHRASE))
            .await;
        assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    }
    // Even the right phrase is refused, and the counter does not move: the KDF did not run.
    let right = fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(
        right,
        Err(CoreError::UnlockBackoff {
            retry_after_seconds: 1
        })
    ));
    assert_eq!(failed_unlocks(&fixture).await, 5);
    fixture.advance(1);
    fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_recovery_slot_and_unknown_operators_are_failed_tries() {
    let (fixture, _, _) = Fixture::created().await;
    let recovery = recovery_slot(&fixture).await;
    let by_recovery = fixture
        .service
        .verify_operator_phrase(recovery, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(by_recovery, Err(CoreError::BadCredentials)));
    let unknown = fixture
        .service
        .verify_operator_phrase(OperatorId::generate(), phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(unknown, Err(CoreError::BadCredentials)));
    assert_eq!(failed_unlocks(&fixture).await, 2);
}

#[tokio::test]
async fn a_session_opened_by_the_recovery_key_cannot_be_checked() {
    let (fixture, created, _) = Fixture::created().await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let key = cerberus_crypto::RecoveryKey::parse(created.recovery_key.expose_secret()).unwrap();
    fixture.service.unlock_with_recovery(key).await.unwrap();
    let recovery = recovery_slot(&fixture).await;
    let check = fixture
        .service
        .verify_operator_phrase(recovery, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(check, Err(CoreError::BadCredentials)));
    // The owner is another operator than the recovery session.
    let owner = fixture
        .service
        .verify_operator_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await;
    assert!(matches!(owner, Err(CoreError::Conflict)));
}

fn enrolment(kind: AdminEventKind) -> AdminAudit {
    AdminAudit {
        enrolment: Some("0190e0a0-0000-7000-8000-000000000001".to_owned()),
        label: Some("laptop".to_owned()),
        ..AdminAudit::new(kind)
    }
}

#[tokio::test]
async fn admin_events_join_the_chain_while_unlocked() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    service
        .record_admin_event(None, AdminAudit::new(AdminEventKind::ApiStart))
        .await
        .unwrap();
    service
        .record_admin_event(
            Some(&ctx),
            AdminAudit {
                operator: Some(created.owner_id),
                ..enrolment(AdminEventKind::ClientEnroll)
            },
        )
        .await
        .unwrap();
    service
        .record_admin_event(
            Some(&ctx),
            AdminAudit {
                operator: Some(created.owner_id),
                unlocked: Some(false),
                ..enrolment(AdminEventKind::SessionOpen)
            },
        )
        .await
        .unwrap();
    service
        .record_admin_event(
            None,
            AdminAudit {
                reason: Some(SessionCloseReason::Idle),
                ..enrolment(AdminEventKind::SessionClose)
            },
        )
        .await
        .unwrap();
    service
        .record_admin_event(None, enrolment(AdminEventKind::ClientRevoke))
        .await
        .unwrap();

    let open = events(&fixture, &ctx, "admin.session_open").await;
    assert_eq!(open.len(), 1);
    let event = &open[0].event;
    assert_eq!(
        event.actor.id.as_deref(),
        Some(ctx.operator_id.to_string().as_str())
    );
    let target = event.target.as_ref().unwrap();
    assert_eq!(target.kind, "admin_client");
    assert_eq!(event.details["unlocked"], false);
    assert_eq!(event.details["operator"], created.owner_id.to_string());
    let close = events(&fixture, &ctx, "admin.session_close").await;
    assert_eq!(close[0].event.details["reason"], "idle");
    assert_eq!(close[0].event.actor.id, None);
    for kind in [
        "admin.api_start",
        "admin.client_enroll",
        "admin.client_revoke",
    ] {
        assert_eq!(events(&fixture, &ctx, kind).await.len(), 1, "{kind}");
    }
    assert!(matches!(
        service.audit_verify(&ctx).await.unwrap(),
        ChainReport::Ok { .. }
    ));
}

#[tokio::test]
async fn while_sealed_only_the_locked_kinds_are_kept_and_join_at_unlock() {
    let (fixture, created, _) = Fixture::created().await;
    let service = &fixture.service;
    service.lock(LockReason::Manual).await.unwrap();
    for kind in [
        AdminEventKind::ApiStart,
        AdminEventKind::SessionClose,
        AdminEventKind::ClientRevoke,
    ] {
        service
            .record_admin_event(None, enrolment(kind))
            .await
            .unwrap();
    }
    for kind in [AdminEventKind::SessionOpen, AdminEventKind::ClientEnroll] {
        let refused = service.record_admin_event(None, enrolment(kind)).await;
        assert!(matches!(refused, Err(CoreError::Locked)), "{kind:?}");
    }
    let ctx = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    for kind in [
        "admin.api_start",
        "admin.session_close",
        "admin.client_revoke",
    ] {
        let rows = events(&fixture, &ctx, kind).await;
        assert_eq!(rows.len(), 1, "{kind}");
        assert_eq!(rows[0].event.details["recorded_while_locked"], true);
    }
    assert!(
        events(&fixture, &ctx, "admin.session_open")
            .await
            .is_empty()
    );
    assert!(matches!(
        service.audit_verify(&ctx).await.unwrap(),
        ChainReport::Ok { .. }
    ));
    let take = service.store().take_audit_pending().await.unwrap();
    assert!(take.rows.is_empty() && take.malformed == 0);
}
