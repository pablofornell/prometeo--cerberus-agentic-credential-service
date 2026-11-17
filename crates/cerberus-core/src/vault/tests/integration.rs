//! The audit chain and the token table as the vault service drives them.

use cerberus_types::{LockReason, OperatorRole};

use super::fixture::*;
use crate::audit::{Actor, ChainReport, verify_chain};
use crate::error::CoreError;
use crate::vault::{CoreEvent, KeyCustody};

async fn chain(fixture: &Fixture) -> ChainReport {
    let guard = fixture.service.unlocked().await.unwrap();
    verify_chain(fixture.service.store(), &guard.keys, &guard.vault_id)
        .await
        .unwrap()
}

#[tokio::test]
async fn custody_actions_are_audited_and_failures_join_at_unlock() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let ChainReport::Ok {
        count: after_create,
        ..
    } = chain(&fixture).await
    else {
        panic!("broken chain after create");
    };
    assert_eq!(after_create, 1, "vault.create");
    service
        .add_operator(
            &ctx,
            "Second".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let wrong = service
        .unlock_with_phrase(created.owner_id, phrase(WRONG_PHRASE))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    // create, operator.add, vault.lock, vault.unlock_failed (from pending), vault.unlock.
    let ChainReport::Ok { count, .. } = chain(&fixture).await else {
        panic!("broken chain");
    };
    assert_eq!(count, 5);
    let take = service.store().take_audit_pending().await.unwrap();
    let (pending, overflow) = (take.rows, take.overflow);
    assert!(
        pending.is_empty() && overflow == 0,
        "pending rows were drained"
    );
}

#[tokio::test]
async fn a_bad_agent_row_mac_is_flagged_at_unlock() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let item = fixture.add_item("For agent").await;
    fixture.add_lease_and_request(item).await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE agents SET created_at = created_at + 1")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    let mut events = fixture.service.subscribe();
    fixture
        .service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let mut flagged = false;
    while let Ok(event) = events.try_recv() {
        flagged |= matches!(
            event,
            CoreEvent::IntegrityAlert {
                table: "agents",
                ..
            }
        );
    }
    assert!(flagged);
}

#[tokio::test]
async fn a_bad_agent_row_mac_is_written_to_the_chain_at_unlock() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let item = fixture.add_item("For agent").await;
    fixture.add_lease_and_request(item).await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE agents SET created_at = created_at + 1")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    let bad_id: String = {
        let raw = fixture.raw().await;
        let id = sqlx::query_scalar("SELECT id FROM agents")
            .fetch_one(&raw)
            .await
            .unwrap();
        raw.close().await;
        id
    };
    fixture
        .service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let mut out = Vec::new();
    {
        let guard = fixture.service.unlocked().await.unwrap();
        guard
            .audit
            .export_jsonl(Actor::system(), &mut out)
            .await
            .unwrap();
    }
    let lines: Vec<serde_json::Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let hits: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["body"]["type"] == "integrity.row_mac_mismatch")
        .collect();
    assert_eq!(hits.len(), 1, "one event per bad row");
    let body = &hits[0]["body"];
    assert_eq!(body["actor"]["kind"], "system");
    assert_eq!(body["target"]["kind"], "agents");
    assert_eq!(body["target"]["id"].as_str().unwrap(), bad_id);
    assert_eq!(body["result"], "vault_corrupt");
    assert!(body["details"].as_object().unwrap().is_empty());
}
