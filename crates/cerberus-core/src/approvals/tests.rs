//! Approval queue tests (ADR-0018) and grant CRUD and simulator tests (ADR-0017).
//! All values are fake test values.

use std::time::Duration;

use cerberus_crypto::SecretString;
use cerberus_types::{
    AccessRequestStatus, ApprovalOption, Environment, GrantMode, ItemId, OperatorRole, Permission,
};

use super::*;
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::policy::testkit::{ItemSpec, Kit, input};
use crate::policy::{Decision, SecretAccess, Selector};
use crate::vault::{CoreEvent, KeyCustody};

const REASON: &str = "deploy hotfix\u{7} for ticket 42";

async fn prod_setup(kit: &Kit) -> (AgentContext, ItemId) {
    let agent = kit.agent().await;
    let item = kit
        .item(&ItemSpec::new(kit.workspace, Environment::Prod))
        .await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    (agent, item)
}

async fn pending(kit: &Kit, agent: &AgentContext, item: ItemId) -> AccessRequestView {
    let mut ask = Kit::ask(item);
    ask.reason = Some(REASON);
    match kit.engine.authorize_secret(agent, ask).await.unwrap() {
        SecretAccess::Pending(view) => view,
        SecretAccess::Granted { .. } => panic!("expected pending"),
    }
}

#[tokio::test]
async fn prod_read_asks_and_approve_once_gives_one_read() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let mut events = kit.service.subscribe();
    let view = pending(&kit, &agent, item).await;
    assert_eq!(view.status, AccessRequestStatus::Pending);
    assert_eq!(
        view.expires_at,
        kit.now() + jiff::SignedDuration::from_secs(120)
    );
    assert!(matches!(events.try_recv(), Ok(CoreEvent::AccessRequestCreated(id)) if id == view.id));
    let again = pending(&kit, &agent, item).await;
    assert_eq!(again.id, view.id, "dedupe");

    let list = kit.engine.pending_requests(&kit.owner).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].agent_name, "fake-agent");
    assert_eq!(list[0].environment, Environment::Prod);
    assert_eq!(list[0].item_kind, cerberus_types::ItemKind::WebLogin);
    assert_eq!(list[0].role_label.as_deref(), Some("admin"));
    assert_eq!(
        list[0].reason, "deploy hotfix for ticket 42",
        "control characters removed"
    );

    let lease = kit
        .engine
        .approve_request(&kit.owner, view.id, ApprovalOption::Once)
        .await
        .unwrap();
    assert_eq!(lease.uses_left, Some(1));
    let got = kit
        .engine
        .get_access_request(&agent, view.id)
        .await
        .unwrap();
    assert_eq!(got.status, AccessRequestStatus::Approved);
    assert_eq!(got.lease.map(|l| l.id), Some(lease.id));
    assert!(matches!(
        kit.engine
            .authorize_secret(&agent, Kit::ask(item))
            .await
            .unwrap(),
        SecretAccess::Granted { .. }
    ));
    let next = pending(&kit, &agent, item).await;
    assert_ne!(next.id, view.id, "one use only");
    let audit = kit.audit_text().await;
    assert!(
        !audit.contains("hotfix"),
        "the reason is not in the audit log"
    );
    let types = kit.audit_types().await;
    for t in [
        "request.create",
        "request.approve",
        "lease.create",
        "lease.use",
    ] {
        assert!(types.contains(&t.to_owned()), "{t}");
    }
}

#[tokio::test]
async fn deny_gives_403_and_a_cool_down() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    kit.engine.deny_request(&kit.owner, view.id).await.unwrap();
    let got = kit
        .engine
        .get_access_request(&agent, view.id)
        .await
        .unwrap();
    assert_eq!(got.status, AccessRequestStatus::Denied);
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::ApprovalDenied(Some(id)) if id == view.id));
    kit.advance(600);
    let fresh = pending(&kit, &agent, item).await;
    assert_ne!(fresh.id, view.id);
    assert!(matches!(
        kit.engine
            .approve_request(&kit.owner, view.id, ApprovalOption::Once)
            .await,
        Err(CoreError::Conflict)
    ));
}

#[tokio::test]
async fn timeout_expires_the_request() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    kit.advance(119);
    assert_eq!(
        kit.engine
            .expire_due(kit.now())
            .await
            .unwrap()
            .requests_expired,
        0
    );
    kit.advance(1);
    assert_eq!(
        kit.engine
            .expire_due(kit.now())
            .await
            .unwrap()
            .requests_expired,
        1
    );
    let got = kit
        .engine
        .get_access_request(&agent, view.id)
        .await
        .unwrap();
    assert_eq!(got.status, AccessRequestStatus::Expired);
    assert!(matches!(
        kit.engine
            .approve_request(&kit.owner, view.id, ApprovalOption::Once)
            .await,
        Err(CoreError::Conflict)
    ));
    // A poll alone also expires it, without the background loop.
    let second = pending(&kit, &agent, item).await;
    kit.advance(121);
    let got = kit
        .engine
        .get_access_request(&agent, second.id)
        .await
        .unwrap();
    assert_eq!(got.status, AccessRequestStatus::Expired);
    assert!(
        kit.audit_types()
            .await
            .contains(&"request.expire".to_owned())
    );
}

#[tokio::test]
async fn headless_gives_approval_unavailable() {
    let kit = Kit::with_approvals(false).await;
    let (agent, item) = prod_setup(&kit).await;
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(item))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::ApprovalUnavailable));
}

#[tokio::test]
async fn pending_cap_and_other_agents_requests() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    kit.grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskAlways)
        .await;
    let mut views = Vec::new();
    for _ in 0..5 {
        let item = kit.dev_item().await;
        views.push(pending(&kit, &agent, item).await);
    }
    let sixth = kit.dev_item().await;
    let err = kit
        .engine
        .authorize_secret(&agent, Kit::ask(sixth))
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::RateLimited { .. }));
    let other = kit.agent().await;
    assert!(matches!(
        kit.engine.get_access_request(&other, views[0].id).await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn request_access_ahead_and_conflict_when_not_needed() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let req = CreateAccess {
        item_id: item,
        permission: Permission::Read,
        reason: "need it for the deploy".into(),
        ttl_seconds: Some(300),
    };
    let view = kit
        .engine
        .request_access(&agent, req.clone())
        .await
        .unwrap();
    assert_eq!(view.requested_ttl_seconds, Some(300));
    let lease = kit
        .engine
        .approve_request(&kit.owner, view.id, ApprovalOption::Minutes15)
        .await
        .unwrap();
    assert_eq!(
        lease.expires_at,
        kit.now() + jiff::SignedDuration::from_secs(300),
        "asked TTL is shorter"
    );
    let dev = kit.dev_item().await;
    let ahead = CreateAccess {
        item_id: dev,
        ..req
    };
    assert!(
        matches!(
            kit.engine.request_access(&agent, ahead).await,
            Err(CoreError::Conflict)
        ),
        "auto needs no approval"
    );
}

#[tokio::test]
async fn waiting_agent_learns_the_decision() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    let engine = kit.engine.clone();
    let ctx = agent.clone();
    let waiter = tokio::spawn(async move {
        engine
            .wait_access_request(&ctx, view.id, Duration::from_secs(30))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    kit.engine
        .approve_request(&kit.owner, view.id, ApprovalOption::Minutes15)
        .await
        .unwrap();
    let done = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(done.status, AccessRequestStatus::Approved);
    assert!(done.lease.is_some());
}

#[tokio::test]
async fn short_wait_returns_pending() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    let got = kit
        .engine
        .wait_access_request(&agent, view.id, Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(got.status, AccessRequestStatus::Pending);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_does_not_block_lock() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    let engine = kit.engine.clone();
    let ctx = agent.clone();
    let waiter = tokio::spawn(async move {
        engine
            .wait_access_request(&ctx, view.id, Duration::from_secs(60))
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(5), kit.lock())
        .await
        .expect("lock must not wait for the agent");
    let result = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap();
    // The lock cancels the request and tells the waiter (a terminal event, DEC-WIRE6-3).
    let ended = result.unwrap();
    assert_eq!(ended.id, view.id);
    assert_eq!(ended.status, AccessRequestStatus::Cancelled);
    kit.unlock().await;
    let got = kit
        .engine
        .get_access_request(&agent, view.id)
        .await
        .unwrap();
    assert_eq!(
        got.status,
        AccessRequestStatus::Cancelled,
        "lock cancels pending requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approve_racing_deny_and_timeout_has_one_winner() {
    for round in 0..6 {
        let kit = Kit::new().await;
        let (agent, item) = prod_setup(&kit).await;
        let view = pending(&kit, &agent, item).await;
        if round % 2 == 1 {
            kit.advance(119);
        }
        let (a, d, e) = (kit.engine.clone(), kit.engine.clone(), kit.engine.clone());
        let (o1, o2) = (kit.owner.clone(), kit.owner.clone());
        let now = kit.now() + jiff::SignedDuration::from_secs(1);
        let approve = tokio::spawn(async move {
            a.approve_request(&o1, view.id, ApprovalOption::Minutes15)
                .await
        });
        let deny = tokio::spawn(async move { d.deny_request(&o2, view.id).await });
        let expire = tokio::spawn(async move { e.expire_due(now).await });
        let approved = approve.await.unwrap();
        let denied = deny.await.unwrap();
        let expired = expire.await.unwrap().unwrap().requests_expired;
        let wins = usize::from(approved.is_ok())
            + usize::from(denied.is_ok())
            + usize::try_from(expired).unwrap();
        assert_eq!(wins, 1, "round {round}: {approved:?} {denied:?} {expired}");
        let row = kit.service.store().access_request(view.id).await.unwrap();
        let expected = if approved.is_ok() {
            AccessRequestStatus::Approved
        } else if denied.is_ok() {
            AccessRequestStatus::Denied
        } else {
            AccessRequestStatus::Expired
        };
        assert_eq!(row.status, expected);
        assert_eq!(row.lease_id.is_some(), approved.is_ok());
    }
}

#[tokio::test]
async fn tampered_request_row_is_not_approved() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    let raw = kit.raw().await;
    sqlx::query("UPDATE access_requests SET status = 'approved' WHERE id = ?1")
        .bind(view.id.to_string())
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    assert!(matches!(
        kit.engine.get_access_request(&agent, view.id).await,
        Err(CoreError::Corrupt)
    ));
    assert!(matches!(
        kit.engine
            .approve_request(&kit.owner, view.id, ApprovalOption::Once)
            .await,
        Err(CoreError::Corrupt)
    ));
    assert!(
        kit.engine
            .pending_requests(&kit.owner)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn approve_rechecks_policy() {
    let kit = Kit::new().await;
    let (agent, item) = prod_setup(&kit).await;
    let view = pending(&kit, &agent, item).await;
    kit.grant(input(
        agent.agent_id,
        Selector::default(),
        &[],
        GrantMode::Deny,
    ))
    .await;
    assert!(matches!(
        kit.engine
            .approve_request(&kit.owner, view.id, ApprovalOption::Once)
            .await,
        Err(CoreError::Conflict)
    ));
}

#[tokio::test]
async fn operator_session_cannot_set_allow_prod_auto_even_with_owner_in_ctx() {
    let kit = Kit::new().await;
    let phrase = "lantern quartz meadow ripple 3";
    let op = kit
        .service
        .add_operator(
            &kit.owner,
            "Second".into(),
            OperatorRole::Operator,
            SecretString::new(phrase.into()),
        )
        .await
        .unwrap();
    let agent = kit.agent().await;
    kit.lock().await;
    let mut ctx = kit
        .service
        .unlock_with_phrase(op, SecretString::new(phrase.into()))
        .await
        .unwrap();
    ctx.role = OperatorRole::Owner; // a forged role in the context must not count
    let mut owner_only = input(
        agent.agent_id,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    owner_only.allow_prod_auto = true;
    assert!(matches!(
        kit.engine.put_grant(&ctx, owner_only.clone()).await,
        Err(CoreError::RoleNotAllowed)
    ));
    owner_only.allow_prod_auto = false;
    assert!(kit.engine.put_grant(&ctx, owner_only).await.is_ok());
    assert!(matches!(
        kit.engine
            .set_policy_settings(&ctx, crate::policy::PolicySettings::default())
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(
        matches!(
            kit.engine.list_grants(&kit.owner, None).await,
            Err(CoreError::Forbidden)
        ),
        "stale context"
    );
}

#[tokio::test]
async fn grant_crud_validation_and_simulator() {
    let kit = Kit::new().await;
    let agent = kit.agent().await;
    let item = kit.dev_item().await;
    let mut bad = input(agent.agent_id, Selector::default(), &[], GrantMode::Auto);
    bad.conditions.max_reads_per_hour = Some(0);
    let Err(CoreError::Validation(problems)) = kit.engine.put_grant(&kit.owner, bad).await else {
        panic!("validation")
    };
    assert_eq!(problems.len(), 2);
    let unknown = input(
        cerberus_types::AgentId::generate(),
        Selector::default(),
        &[Permission::Find],
        GrantMode::Auto,
    );
    assert!(matches!(
        kit.engine.put_grant(&kit.owner, unknown).await,
        Err(CoreError::NotFound)
    ));

    let created = kit
        .grant_all(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    kit.advance(10);
    let mut change = input(
        agent.agent_id,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    change.id = Some(created.id);
    let updated = kit.grant(change).await;
    assert_eq!(updated.created_at, created.created_at);
    assert_ne!(updated.updated_at, created.updated_at);
    assert_eq!(
        kit.engine
            .list_grants(&kit.owner, Some(agent.agent_id))
            .await
            .unwrap(),
        vec![updated.clone()]
    );

    let rows = kit
        .engine
        .simulate(&kit.owner, agent.agent_id)
        .await
        .unwrap();
    assert_eq!(rows.len(), crate::policy::ALL_PERMISSIONS.len());
    let read = rows
        .iter()
        .find(|r| r.item_id == item && r.permission == Permission::Read)
        .unwrap();
    assert_eq!(
        read.decision,
        Decision::Allow {
            mode: GrantMode::Auto,
            grant_id: updated.id
        }
    );
    let write = rows
        .iter()
        .find(|r| r.permission == Permission::Write)
        .unwrap();
    assert_eq!(write.decision, Decision::NoGrant);

    kit.engine
        .delete_grant(&kit.owner, updated.id)
        .await
        .unwrap();
    assert!(matches!(
        kit.engine.delete_grant(&kit.owner, updated.id).await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        kit.engine.authorize_secret(&agent, Kit::ask(item)).await,
        Err(CoreError::NotFound)
    ));
    let types = kit.audit_types().await;
    for t in ["grant.create", "grant.update", "grant.delete"] {
        assert!(types.contains(&t.to_owned()), "{t}");
    }
    // Grants survive a lock: the index is rebuilt from the sealed rows.
    let again = kit
        .grant_all(agent.agent_id, &[Permission::Find], GrantMode::Auto)
        .await;
    kit.lock().await;
    kit.unlock().await;
    assert_eq!(
        kit.engine.list_grants(&kit.owner, None).await.unwrap(),
        vec![again]
    );
}

#[tokio::test]
async fn resolve_snapshot_answers_like_the_engine() {
    use crate::resolve::{ReadAccess, ResolvePolicy};
    let kit = Kit::new().await;
    let (agent, prod) = prod_setup(&kit).await;
    let dev = kit.dev_item().await;
    let hidden_agent = kit.agent().await;
    let (prod_meta, dev_meta) = {
        let guard = kit.service.unlocked().await.unwrap();
        (
            guard.index.item(&prod).cloned().unwrap(),
            guard.index.item(&dev).cloned().unwrap(),
        )
    };
    let snap = kit.engine.resolve_policy(&agent, None).await.unwrap();
    assert!(snap.can_find(&prod_meta) && snap.can_find(&dev_meta));
    assert_eq!(snap.read_access(&dev_meta).unwrap(), ReadAccess::Granted);
    assert_eq!(
        snap.read_access(&prod_meta).unwrap(),
        ReadAccess::NeedsApproval
    );
    let view = pending(&kit, &agent, prod).await;
    kit.engine
        .approve_request(&kit.owner, view.id, ApprovalOption::Minutes15)
        .await
        .unwrap();
    let snap = kit.engine.resolve_policy(&agent, None).await.unwrap();
    assert_eq!(
        snap.read_access(&prod_meta).unwrap(),
        ReadAccess::Granted,
        "approved lease"
    );
    let none = kit
        .engine
        .resolve_policy(&hidden_agent, None)
        .await
        .unwrap();
    assert!(!none.can_find(&dev_meta));
    assert!(matches!(
        none.read_access(&dev_meta),
        Err(CoreError::Forbidden)
    ));
}
