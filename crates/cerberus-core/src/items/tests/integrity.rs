//! T27 integrity fixes on stored items and the audit chain, tested through the vault service.
//! A file attacker is simulated with a raw SQLite connection next to the store. Fake values only.

use cerberus_store::Sweeper;
use cerberus_types::{Environment, ItemId, ItemKind, LockReason};
use sqlx::Connection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};

use super::fixture::{Fx, OWNER_PHRASE, input, login_payload, phrase};
use crate::admin::AuditQuery;
use crate::audit::ChainReport;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::encode_item_meta;
use crate::items::{ItemFilter, ItemUpdate, Payload, PayloadChange, generate_ed25519};
use crate::vault::{CoreEvent, KeyCustody};

async fn raw(fx: &Fx) -> SqliteConnection {
    let options = SqliteConnectOptions::new().filename(&fx.path);
    SqliteConnection::connect_with(&options).await.unwrap()
}

async fn exec(fx: &Fx, sql: &str, id: ItemId) {
    let mut conn = raw(fx).await;
    sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .bind(id.to_string())
        .execute(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
}

async fn lock(fx: &Fx) {
    fx.service.lock(LockReason::Manual).await.unwrap();
}

async fn unlock(fx: &Fx) -> OperatorContext {
    let owner = fx.service.list_operators().await.unwrap().remove(0);
    fx.service
        .unlock_with_phrase(owner.id, phrase(OWNER_PHRASE))
        .await
        .unwrap()
}

/// The table names of every integrity alert sent so far.
fn alerts(events: &mut tokio::sync::broadcast::Receiver<CoreEvent>) -> Vec<&'static str> {
    let mut out = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let CoreEvent::IntegrityAlert { table, .. } = event {
            out.push(table);
        }
    }
    out
}

fn password_of(payload: &Payload) -> String {
    match payload {
        Payload::WebLogin { password, .. } => password.expose_secret().to_owned(),
        other => panic!("not a web login: {other:?}"),
    }
}

/// The opened `items.meta_ct` of `id` as JSON.
async fn sealed_meta(fx: &Fx, id: ItemId) -> serde_json::Value {
    let row = fx.service.store().item(id).await.unwrap();
    let guard = fx.service.unlocked().await.unwrap();
    let plain = guard
        .blobs()
        .open_item_meta(&id, row.current_version, &row.meta_ct)
        .unwrap();
    serde_json::from_slice(plain.expose_secret()).unwrap()
}

/// Rewrites `items.meta_ct` of `id` in the form written before T27: the same JSON without the
/// `kind` field (DEC-T27-A1-2).
async fn make_legacy(fx: &Fx, id: ItemId) {
    let mut row = fx.service.store().item(id).await.unwrap();
    let guard = fx.service.unlocked().await.unwrap();
    let meta = guard.index.item(&id).unwrap().clone();
    let mut json: serde_json::Value =
        serde_json::from_slice(&encode_item_meta(&meta).unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("kind");
    let bytes = serde_json::to_vec(&json).unwrap();
    row.meta_ct = guard
        .blobs()
        .seal_item_meta(&id, row.current_version, &bytes)
        .unwrap();
    let mut tx = fx.service.store().begin().await.unwrap();
    tx.update_item_meta(&row).await.unwrap();
    tx.commit().await.unwrap();
}

async fn chain_ok(fx: &Fx, ctx: &OperatorContext) -> bool {
    matches!(
        fx.service.audit_verify(ctx).await.unwrap(),
        ChainReport::Ok { .. }
    )
}

/// AUD-2: a file edit of the plain `items.kind` column takes the item out of the index at unlock.
#[tokio::test]
async fn aud2_a_changed_plain_kind_is_refused_at_unlock() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "build-01 deploy key",
            generate_ed25519("deploy@build-01").unwrap(),
        ))
        .await;
    lock(&fx).await;
    exec(&fx, "UPDATE items SET kind = 'api_key' WHERE id = ?1", id).await;
    let mut events = fx.service.subscribe();
    let ctx = unlock(&fx).await;
    assert!(matches!(
        fx.service.get_item(&ctx, id).await,
        Err(CoreError::NotFound)
    ));
    let listed = fx
        .service
        .list_items(&ctx, ItemFilter::default())
        .await
        .unwrap();
    assert!(listed.is_empty());
    assert!(alerts(&mut events).contains(&"items"));
}

/// AUD-2: an edit of the plain kind while the vault is unlocked is refused at the next read.
#[tokio::test]
async fn aud2_a_changed_plain_kind_is_refused_at_reveal() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Shop admin",
            login_payload("alice", "fake-pw"),
        ))
        .await;
    exec(&fx, "UPDATE items SET kind = 'api_key' WHERE id = ?1", id).await;
    assert!(matches!(
        fx.service.read_payload(id, true).await,
        Err(CoreError::Corrupt)
    ));
}

/// AUD-6: moving `items.current_version` back to an older kept version is refused.
#[tokio::test]
async fn aud6_a_moved_back_current_version_is_refused() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Shop admin",
            login_payload("alice", "fake-old"),
        ))
        .await;
    fx.service
        .update_item(
            &fx.ctx,
            id,
            input(fx.ws, "Shop admin", login_payload("alice", "fake-new")),
        )
        .await
        .unwrap();
    assert_eq!(
        password_of(&fx.service.read_payload(id, false).await.unwrap().payload),
        "fake-new"
    );
    exec(
        &fx,
        "UPDATE items SET current_version = 1 WHERE id = ?1",
        id,
    )
    .await;
    let mut events = fx.service.subscribe();
    assert!(matches!(
        fx.service.read_payload(id, true).await,
        Err(CoreError::Corrupt)
    ));
    assert!(matches!(
        fx.service.get_item(&fx.ctx, id).await,
        Err(CoreError::Corrupt)
    ));
    assert!(alerts(&mut events).contains(&"items"));
}

/// AUD-2 migration: an item written before T27 (no sealed kind) gets its kind sealed at the first
/// unlock, after the kind of its authenticated payload matched the plain column.
#[tokio::test]
async fn aud2_a_vault_from_before_t27_gets_sealed_kinds_at_first_unlock() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Shop admin",
            login_payload("alice", "fake-pw"),
        ))
        .await;
    make_legacy(&fx, id).await;
    assert!(sealed_meta(&fx, id).await.get("kind").is_none());
    lock(&fx).await;
    let mut events = fx.service.subscribe();
    let ctx = unlock(&fx).await;
    assert!(alerts(&mut events).is_empty());
    let detail = fx.service.get_item(&ctx, id).await.unwrap();
    assert_eq!(detail.summary.kind, ItemKind::WebLogin);
    assert_eq!(sealed_meta(&fx, id).await["kind"], "web_login");
    assert_eq!(
        password_of(&fx.service.read_payload(id, false).await.unwrap().payload),
        "fake-pw"
    );
    assert!(chain_ok(&fx, &ctx).await);
}

/// AUD-2 migration: a pre-T27 row whose plain kind was changed does not get that kind sealed.
#[tokio::test]
async fn aud2_a_legacy_row_with_a_changed_plain_kind_is_refused() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Shop admin",
            login_payload("alice", "fake-pw"),
        ))
        .await;
    make_legacy(&fx, id).await;
    lock(&fx).await;
    exec(&fx, "UPDATE items SET kind = 'note' WHERE id = ?1", id).await;
    let mut events = fx.service.subscribe();
    let ctx = unlock(&fx).await;
    assert!(matches!(
        fx.service.get_item(&ctx, id).await,
        Err(CoreError::NotFound)
    ));
    assert!(alerts(&mut events).contains(&"items"));
}

/// AUD-8: an item whose plain `expires_at` was cleared is still deleted after its sealed end.
#[tokio::test]
async fn aud8_an_item_with_a_cleared_plain_expiry_is_deleted_after_its_sealed_end() {
    let fx = Fx::new().await;
    let mut item = input(fx.ws, "Short login", login_payload("alice", "fake-pw"));
    item.expires_at = Some(fx.now() + jiff::SignedDuration::from_secs(3600));
    let id = fx.create(item).await;
    exec(&fx, "UPDATE items SET expires_at = NULL WHERE id = ?1", id).await;
    fx.advance(3601);
    let report = Sweeper::new(fx.service.store().clone())
        .run_once(fx.now())
        .await
        .unwrap();
    assert!(report.expired_items.is_empty(), "the plain sweep misses it");
    fx.service.apply_sweep_report(&report).await;
    let mut conn = raw(&fx).await;
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM items WHERE id = ?1")
        .bind(id.to_string())
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(left, 0);
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM item_versions WHERE item_id = ?1")
        .bind(id.to_string())
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(versions, 0);
    let expired = fx
        .service
        .audit_query(
            &fx.ctx,
            AuditQuery {
                event_type: Some("item.expire".to_owned()),
                item_id: Some(id),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(expired.len(), 1);
}

/// AUD-27: `item.update` names the changed fields (not their values) and the old and new
/// environment and workspace.
#[tokio::test]
async fn aud27_item_update_names_the_changed_fields() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Shop admin",
            login_payload("alice", "fake-pw"),
        ))
        .await;
    let mut changed = input(fx.ws, "Shop admin two", login_payload("x", "y"));
    changed.environment = Environment::Dev;
    let update = ItemUpdate {
        workspace_id: changed.workspace_id,
        title: changed.title.clone(),
        description: changed.description.clone(),
        role_label: changed.role_label.clone(),
        category: changed.category.clone(),
        tags: changed.tags.clone(),
        environment: changed.environment,
        target: changed.target.clone(),
        custom: changed.custom.clone(),
        expires_at: None,
        max_uses: None,
        payload: PayloadChange::Keep,
    };
    fx.service.update_item(&fx.ctx, id, update).await.unwrap();
    let events = fx
        .service
        .audit_query(
            &fx.ctx,
            AuditQuery {
                event_type: Some("item.update".to_owned()),
                item_id: Some(id),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    let details = &events[0].event.details;
    let names: Vec<&str> = details["changed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(names, ["title", "environment"]);
    assert_eq!(details["old_environment"], "staging");
    assert_eq!(details["new_environment"], "dev");
    assert_eq!(details["old_workspace_id"], fx.ws.to_string());
    assert_eq!(details["new_workspace_id"], fx.ws.to_string());
    let text = serde_json::to_string(details).unwrap();
    assert!(!text.contains("Shop admin two"), "no field value");
}

/// AUD-1: a cut tail with an edited head is found at the next unlock: the head is not signed
/// again, the chain reads as broken, and the alert is raised.
#[tokio::test]
async fn aud1_a_cut_tail_with_an_edited_head_is_found_at_unlock() {
    let fx = Fx::new().await;
    for n in 0..4 {
        fx.create(input(
            fx.ws,
            &format!("Item {n}"),
            login_payload("alice", "fake-pw"),
        ))
        .await;
    }
    lock(&fx).await;
    let mut conn = raw(&fx).await;
    let last: i64 = sqlx::query_scalar("SELECT last_seq FROM audit_head")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    let cut = last - 2;
    let prev: Vec<u8> = sqlx::query_scalar("SELECT prev_hash FROM audit_events WHERE seq = ?1")
        .bind(cut)
        .fetch_one(&mut conn)
        .await
        .unwrap();
    for sql in [
        "DROP TRIGGER audit_events_no_delete",
        "DELETE FROM audit_events WHERE seq >= ?1",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .bind(cut)
            .execute(&mut conn)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE audit_head SET last_seq = ?1, last_entry_hash = ?2")
        .bind(cut - 1)
        .bind(prev)
        .execute(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    let mut events = fx.service.subscribe();
    let ctx = unlock(&fx).await;
    // The check that runs after each unlock reports the break too.
    let walked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut seen = Vec::new();
        loop {
            if let Ok(CoreEvent::IntegrityAlert { table, .. }) = events.recv().await {
                seen.push(table);
                if table == "audit_events" {
                    return seen;
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(walked.contains(&"audit_head"), "{walked:?}");
    assert!(!chain_ok(&fx, &ctx).await);
}

/// AUD-1: a log that was wiped (every row and the head deleted) does not start again as a new,
/// good chain at the next unlock: the first row is a break mark (DEC-T27-A1-1).
#[tokio::test]
async fn aud1_a_wiped_log_is_found_at_unlock() {
    let fx = Fx::new().await;
    fx.create(input(
        fx.ws,
        "Shop admin",
        login_payload("alice", "fake-pw"),
    ))
    .await;
    lock(&fx).await;
    let mut conn = raw(&fx).await;
    for sql in [
        "DROP TRIGGER audit_events_no_delete",
        "DELETE FROM audit_events",
        "DELETE FROM audit_head",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
            .execute(&mut conn)
            .await
            .unwrap();
    }
    conn.close().await.unwrap();
    let mut events = fx.service.subscribe();
    let ctx = unlock(&fx).await;
    assert!(alerts(&mut events).contains(&"audit_head"));
    assert!(matches!(
        fx.service.audit_verify(&ctx).await.unwrap(),
        ChainReport::Broken { seq: 1, .. }
    ));
}

/// AUD-9: a drain of the pending events that fails is an integrity alert, not only a log line.
#[tokio::test]
async fn aud9_a_failed_drain_raises_the_alert() {
    let fx = Fx::new().await;
    lock(&fx).await;
    let owner = fx.service.list_operators().await.unwrap().remove(0);
    assert!(
        fx.service
            .unlock_with_phrase(owner.id, phrase("wrong phrase for the test"))
            .await
            .is_err()
    );
    let mut conn = raw(&fx).await;
    sqlx::query(
        "CREATE TRIGGER audit_events_stop BEFORE INSERT ON audit_events \
         BEGIN SELECT RAISE(ABORT, 'stopped by the test'); END",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    let mut events = fx.service.subscribe();
    unlock(&fx).await;
    assert!(alerts(&mut events).contains(&"audit_pending"));
}

/// AUD-9: one malformed `audit_pending` row does not keep the other events out of the chain.
#[tokio::test]
async fn aud9_a_malformed_pending_row_does_not_block_the_others() {
    let fx = Fx::new().await;
    lock(&fx).await;
    let owner = fx.service.list_operators().await.unwrap().remove(0);
    assert!(
        fx.service
            .unlock_with_phrase(owner.id, phrase("wrong phrase for the test"))
            .await
            .is_err()
    );
    let mut conn = raw(&fx).await;
    sqlx::query(
        "INSERT INTO audit_pending (occurred_at, event_type, agent_id, result_code) \
         VALUES (1, 'auth.failed', 'not-a-uuid', 'unauthenticated')",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    let ctx = unlock(&fx).await;
    let failed = fx
        .service
        .audit_query(
            &ctx,
            AuditQuery {
                event_type: Some("vault.unlock_failed".to_owned()),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(failed.len(), 1);
}
