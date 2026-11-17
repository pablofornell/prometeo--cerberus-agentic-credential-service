//! Lease tests (ADR-0019): auto leases, reuse, revoke, release, expiry, MAC checks, limits.
//! All values are fake test values.

use cerberus_store::LeaseSource;
use cerberus_types::{ApprovalOption, Environment, GrantMode, Permission};
use jiff::SignedDuration;
use proptest::prelude::*;

use super::*;
use crate::error::CoreError;
use crate::policy::testkit::{ItemSpec, Kit, input};
use crate::policy::{PolicySettings, SecretAccess, Selector};
use crate::vault::CoreEvent;

fn granted(access: &SecretAccess) -> &LeaseView {
    match access {
        SecretAccess::Granted { lease, .. } => lease,
        SecretAccess::Pending(view) => panic!("expected a grant, got pending {view:?}"),
    }
}

/// An approved lease for (agent, prod item) with `option`. Returns the lease view.
async fn approved_lease(
    kit: &Kit,
    ctx: &crate::context::AgentContext,
    item: cerberus_types::ItemId,
    option: ApprovalOption,
) -> LeaseView {
    let pending = kit
        .engine
        .authorize_secret(ctx, Kit::ask(item))
        .await
        .unwrap();
    let SecretAccess::Pending(view) = pending else {
        panic!("expected pending")
    };
    kit.engine
        .approve_request(&kit.owner, view.id, option)
        .await
        .unwrap()
}

#[tokio::test]
async fn auto_read_makes_one_lease_and_reuses_it() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let first = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    let second = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert_eq!(granted(&first).id, granted(&second).id);
    assert_eq!(
        granted(&first).expires_at,
        kit.now() + SignedDuration::from_secs(900)
    );
    let row = kit.service.store().lease(granted(&first).id).await.unwrap();
    assert_eq!((row.uses, row.source), (2, LeaseSource::Auto));
    let types = kit.audit_types().await;
    assert_eq!(types.iter().filter(|t| *t == "lease.create").count(), 1);
    assert_eq!(types.iter().filter(|t| *t == "lease.use").count(), 2);
    assert!(
        !kit.audit_text().await.contains("fake-key"),
        "no secret in the audit log"
    );
}

#[tokio::test]
async fn no_grant_hides_item_and_find_only_forbids_read() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::NotFound));
    kit.grant_all(agent.agent_id, &[Permission::Find], GrantMode::Auto)
        .await;
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Forbidden));
    let types = kit.audit_types().await;
    assert_eq!(
        types.iter().filter(|t| *t == "item.reveal").count(),
        2,
        "refusals are audited"
    );
}

#[tokio::test]
async fn revoked_auto_lease_blocks_new_auto_leases_until_its_end() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let lease = granted(
        &kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap(),
    )
    .clone();
    kit.engine.revoke_lease(&kit.owner, lease.id).await.unwrap();
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Forbidden));
    kit.advance(899);
    assert!(
        kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .is_err()
    );
    kit.advance(1);
    let fresh = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert_ne!(granted(&fresh).id, lease.id);
    assert!(matches!(
        kit.engine.revoke_lease(&kit.owner, lease.id).await,
        Err(CoreError::Conflict)
    ));
}

#[tokio::test]
async fn release_is_for_the_owner_agent_only() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let other = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Minutes15).await;
    assert!(matches!(
        kit.engine.release_lease(&other, lease.id).await,
        Err(CoreError::NotFound)
    ));
    let out = kit.engine.release_lease(&agent, lease.id).await.unwrap();
    assert_eq!(out.lease_id, lease.id);
    let next = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert!(
        matches!(next, SecretAccess::Pending(_)),
        "a released lease cannot be used"
    );
    assert!(
        kit.audit_types()
            .await
            .contains(&"lease.release".to_owned())
    );
}

#[tokio::test]
async fn approval_lease_does_not_serve_after_mode_change_and_auto_lease_does_not_serve_ask() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    let grant = kit
        .grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    granted(
        &kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap(),
    );
    let mut change = input(
        agent.agent_id,
        Selector::default(),
        &[Permission::Read],
        GrantMode::AskAlways,
    );
    change.id = Some(grant.id);
    kit.grant(change).await;
    let next = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert!(
        matches!(next, SecretAccess::Pending(_)),
        "the auto lease no longer serves"
    );
}

#[tokio::test]
async fn ask_always_lease_has_one_use() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Prod))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Minutes15).await;
    assert_eq!(lease.uses_left, Some(1), "prod forces ask_always: one use");
    let read = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert_eq!(granted(&read).uses_left, Some(0));
    let again = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert!(matches!(again, SecretAccess::Pending(_)));
}

#[tokio::test]
async fn session_lease_ends_at_lock() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Session).await;
    assert!(lease.expires_at <= kit.now() + SignedDuration::from_hours(8));
    granted(
        &kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap(),
    );
    kit.lock().await;
    kit.advance(1);
    kit.unlock().await;
    let next = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert!(matches!(next, SecretAccess::Pending(_)));
}

#[tokio::test]
async fn minutes_15_lease_survives_lock() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    approved_lease(&kit, &agent, item, ApprovalOption::Minutes15).await;
    kit.lock().await;
    kit.unlock().await;
    granted(
        &kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap(),
    );
}

/// AUD-7: the panic button does not sign a forged lease row again. The row is left as it is and
/// raised as an integrity alert.
#[tokio::test]
async fn aud7_panic_revoke_leaves_a_forged_lease_and_raises_the_alert() {
    use crate::vault::KeyCustody;
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Once).await;
    let raw = kit.raw().await;
    sqlx::query("UPDATE leases SET expires_at = expires_at + 86400000 WHERE id = ?1")
        .bind(lease.id.to_string())
        .execute(&raw)
        .await
        .unwrap();
    let mut events = kit.service.subscribe();
    kit.service.panic_lock(&kit.owner).await.unwrap();
    let mut alerted = false;
    while let Ok(event) = events.try_recv() {
        alerted |= matches!(
            event,
            CoreEvent::IntegrityAlert {
                table: "leases",
                ..
            }
        );
    }
    assert!(alerted);
    let revoked: Option<i64> = sqlx::query_scalar("SELECT revoked_at FROM leases WHERE id = ?1")
        .bind(lease.id.to_string())
        .fetch_one(&raw)
        .await
        .unwrap();
    assert_eq!(revoked, None, "the forged row is not signed again");
    raw.close().await;
}

/// NEW-3: one lease row that cannot be read (a bad ID) does not stop the panic revoke. The real
/// lease of the agent is revoked at once, and the bad row raises the alert.
#[tokio::test]
async fn new3_an_unreadable_lease_row_does_not_block_the_panic_revoke() {
    use crate::vault::KeyCustody;
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Once).await;
    let raw = kit.raw().await;
    let mut conn = raw.acquire().await.unwrap();
    sqlx::query("CREATE TEMP TABLE copy AS SELECT * FROM leases WHERE id = ?1")
        .bind(lease.id.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    for sql in [
        "UPDATE copy SET id = 'not-a-uuid'",
        "INSERT INTO leases SELECT * FROM copy",
        "DROP TABLE copy",
    ] {
        sqlx::query(sql).execute(&mut *conn).await.unwrap();
    }
    drop(conn);
    let mut events = kit.service.subscribe();
    kit.service.panic_lock(&kit.owner).await.unwrap();
    let mut alerted = false;
    while let Ok(event) = events.try_recv() {
        alerted |= matches!(
            &event,
            CoreEvent::IntegrityAlert {
                table: "leases",
                row_id,
            } if row_id.is_empty()
        );
    }
    assert!(alerted, "the unreadable row raises the alert");
    let revoked: Option<i64> = sqlx::query_scalar("SELECT revoked_at FROM leases WHERE id = ?1")
        .bind(lease.id.to_string())
        .fetch_one(&raw)
        .await
        .unwrap();
    assert!(revoked.is_some(), "the real lease is revoked by the panic");
    raw.close().await;
}

#[tokio::test]
async fn tampered_lease_row_is_not_trusted() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Once).await;
    let mut events = kit.service.subscribe();
    let raw = kit.raw().await;
    sqlx::query(
        "UPDATE leases SET expires_at = expires_at + 86400000, max_uses = NULL WHERE id = ?1",
    )
    .bind(lease.id.to_string())
    .execute(&raw)
    .await
    .unwrap();
    raw.close().await;
    let next = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();
    assert!(
        matches!(next, SecretAccess::Pending(_)),
        "a bad MAC means no lease"
    );
    let mut alerted = false;
    while let Ok(event) = events.try_recv() {
        alerted |= matches!(
            event,
            CoreEvent::IntegrityAlert {
                table: "leases",
                ..
            }
        );
    }
    assert!(alerted);
    assert!(
        kit.audit_types()
            .await
            .contains(&"integrity.row_mac_mismatch".to_owned())
    );
    assert!(matches!(
        kit.engine.revoke_lease(&kit.owner, lease.id).await,
        Err(CoreError::Corrupt)
    ));
    assert!(
        kit.engine
            .list_leases(&kit.owner)
            .await
            .unwrap()
            .iter()
            .all(|l| l.view.id != lease.id)
    );
}

#[tokio::test]
async fn concurrent_reads_use_a_one_use_lease_once() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Staging))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let lease = approved_lease(&kit, &agent, item, ApprovalOption::Once).await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let engine = kit.engine.clone();
        let ctx = agent.clone();
        tasks.push(tokio::spawn(async move {
            engine.authorize_secret(&ctx, Kit::ask(item)).await
        }));
    }
    let mut grants = 0;
    for task in tasks {
        if let Ok(SecretAccess::Granted { lease: used, .. }) = task.await.unwrap() {
            assert_eq!(used.id, lease.id);
            grants += 1;
        }
    }
    assert_eq!(grants, 1);
    assert_eq!(kit.service.store().lease(lease.id).await.unwrap().uses, 1);
}

#[tokio::test]
async fn revoke_racing_with_uses_is_never_undone() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let lease = granted(
        &kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap(),
    )
    .clone();
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let engine = kit.engine.clone();
        let ctx = agent.clone();
        tasks.push(tokio::spawn(async move {
            drop(engine.authorize_secret(&ctx, Kit::ask(item)).await)
        }));
    }
    kit.engine.revoke_lease(&kit.owner, lease.id).await.unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    let row = kit.service.store().lease(lease.id).await.unwrap();
    assert!(
        row.revoked_at.is_some(),
        "a use after the revoke must not write the old row back"
    );
    assert!(
        kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn revoke_all_and_lease_expiry_events() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let a = kit.dev_item().await;
    let b = kit.dev_item().await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    kit.engine
        .authorize_secret(&agent, Kit::ask(a))
        .await
        .unwrap();
    assert_eq!(
        kit.engine
            .expire_due(kit.now())
            .await
            .unwrap()
            .leases_expired,
        0
    );
    kit.advance(1000);
    kit.engine
        .authorize_secret(&agent, Kit::ask(b))
        .await
        .unwrap();
    let report = kit.engine.expire_due(kit.now()).await.unwrap();
    assert_eq!(report.leases_expired, 1, "the lease of `a` ended");
    assert!(kit.audit_types().await.contains(&"lease.expire".to_owned()));
    assert_eq!(kit.engine.list_leases(&kit.owner).await.unwrap().len(), 1);
    assert_eq!(
        kit.engine.revoke_all_leases(&kit.owner).await.unwrap(),
        2,
        "also the ended lease of `a`, which was never released"
    );
    assert!(kit.engine.list_leases(&kit.owner).await.unwrap().is_empty());
    assert!(
        kit.engine
            .authorize_secret(&agent, Kit::ask(b))
            .await
            .is_err(),
        "revoked auto lease blocks"
    );
}

#[tokio::test]
async fn grant_read_limit_and_mass_read_alert() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    let mut limited = input(
        agent.agent_id,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    limited.conditions.max_reads_per_hour = Some(2);
    kit.grant(limited).await;
    for _ in 0..2 {
        kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap();
    }
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::GrantRateLimited { .. }));
    kit.advance(3600);
    kit.engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap();

    let reader = kit.agent().await;
    kit.grant_all(reader.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let settings = PolicySettings {
        distinct_items_per_hour: 2,
        ..PolicySettings::default()
    };
    kit.engine
        .set_policy_settings(&kit.owner, settings)
        .await
        .unwrap();
    let mut events = kit.service.subscribe();
    for _ in 0..2 {
        let id = kit.dev_item().await;
        kit.engine
            .authorize_secret(&reader, Kit::ask(id))
            .await
            .unwrap();
    }
    let third = kit.dev_item().await;
    let err = kit
        .engine
        .authorize_secret(&reader, Kit::ask(third))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::RateLimited { .. }));
    let mut alert = None;
    while let Ok(event) = events.try_recv() {
        if let CoreEvent::MassReadAlert {
            agent_id,
            distinct_items,
        } = event
        {
            alert = Some((agent_id, distinct_items));
        }
    }
    assert_eq!(alert, Some((reader.agent_id, 2)));
}

#[test]
fn ttl_rules() {
    let now = cerberus_types::t0();
    let eight_h = SignedDuration::from_hours(8);
    let once = ttl_for(
        ApprovalOption::Once,
        GrantMode::AskOnce,
        eight_h,
        None,
        now,
        None,
        None,
    );
    assert_eq!(
        once,
        LeaseTerms {
            expires_at: now + ONCE_TTL,
            max_uses: Some(1)
        }
    );
    let fifteen = ttl_for(
        ApprovalOption::Minutes15,
        GrantMode::AskOnce,
        eight_h,
        None,
        now,
        None,
        None,
    );
    assert_eq!(fifteen.max_uses, None);
    let always = ttl_for(
        ApprovalOption::Minutes15,
        GrantMode::AskAlways,
        eight_h,
        None,
        now,
        None,
        None,
    );
    assert_eq!(always.max_uses, Some(1));
    let lock_at = now + SignedDuration::from_hours(2);
    let session = ttl_for(
        ApprovalOption::Session,
        GrantMode::AskOnce,
        eight_h,
        None,
        now,
        Some(lock_at),
        None,
    );
    assert_eq!(session.expires_at, lock_at);
    let item_end = now + SignedDuration::from_secs(100);
    let short = ttl_for(
        ApprovalOption::Minutes15,
        GrantMode::AskOnce,
        eight_h,
        Some(item_end),
        now,
        None,
        Some(600),
    );
    assert_eq!(short.expires_at, item_end);
    let asked = ttl_for(
        ApprovalOption::Session,
        GrantMode::AskOnce,
        eight_h,
        None,
        now,
        None,
        Some(600),
    );
    assert_eq!(asked.expires_at, now + SignedDuration::from_secs(600));
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// A revoke ends a lease at once: the next check does not use it, whatever came before.
    #[test]
    fn prop_revoke_ends_lease_at_once(uses_before in 0usize..4, auto in any::<bool>(), wait in 0i64..800) {
        runtime().block_on(async {
            let kit = Kit::new().await;
            let agent = kit.agent().await;
            let item = kit.item(&ItemSpec::new(kit.workspace, Environment::Staging)).await;
            let mode = if auto { GrantMode::Auto } else { GrantMode::AskOnce };
            kit.grant_all(agent.agent_id, &[Permission::Read], mode).await;
            let lease = if auto {
                granted(&kit.engine.authorize_secret(&agent, Kit::ask(item)).await.unwrap()).clone()
            } else {
                approved_lease(&kit, &agent, item, ApprovalOption::Minutes15).await
            };
            for _ in 0..uses_before {
                granted(&kit.engine.authorize_secret(&agent, Kit::ask(item)).await.unwrap());
            }
            kit.advance(wait);
            kit.engine.revoke_lease(&kit.owner, lease.id).await.unwrap();
            let mut ask = Kit::ask(item);
            ask.lease_id = Some(lease.id);
            match kit.engine.authorize_secret(&agent, ask).await {
                Ok(SecretAccess::Granted { lease: used, .. }) => assert_ne!(used.id, lease.id),
                Ok(SecretAccess::Pending(_)) | Err(_) => {}
            }
        });
    }

    /// A lease past its end (manual clock) gives no access; before its end it does.
    #[test]
    fn prop_expired_lease_gives_no_access(fifteen in any::<bool>(), offset in 0i64..2000) {
        runtime().block_on(async {
            let kit = Kit::new().await;
            let agent = kit.agent().await;
            let item = kit.item(&ItemSpec::new(kit.workspace, Environment::Staging)).await;
            kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce).await;
            let option = if fifteen { ApprovalOption::Minutes15 } else { ApprovalOption::Once };
            let lease = approved_lease(&kit, &agent, item, option).await;
            let ttl = lease.expires_at.duration_since(kit.now()).as_secs();
            kit.advance(offset);
            let result = kit.engine.authorize_secret(&agent, Kit::ask(item)).await.unwrap();
            if offset >= ttl {
                assert!(matches!(result, SecretAccess::Pending(_)), "expired at {offset} >= {ttl}");
            } else {
                assert_eq!(granted(&result).id, lease.id);
            }
        });
    }
}
