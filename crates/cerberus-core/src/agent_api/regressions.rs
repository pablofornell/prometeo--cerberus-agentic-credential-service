//! Regression tests for the second security review of the core (DEC-FIX7-1 ..). Each test fails
//! on the code before the fix. Every secret here is a fake test value with the marker `zq-fake`.

use std::collections::BTreeMap;
use std::sync::Arc;

use cerberus_crypto::SecretString;
use cerberus_types::{ApprovalOption, Environment, GrantMode, ItemId, Permission, Scope};

use super::tests::{Fx, all_scopes, login};
use super::{AgentItemInput, RevealInput, RevealOutcome};
use crate::admin::AuditQuery;
use crate::approvals::CreateAccess;
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::items::{ItemUpdate, Payload, PayloadChange};
use crate::policy::{Conditions, Grant, GrantInput, PolicySettings, Selector};
use crate::resolve::ResolveRequest;

fn ri() -> RevealInput {
    RevealInput {
        purpose: "regression test read".to_owned(),
        ..RevealInput::default()
    }
}

fn note(ws: &str, title: &str) -> AgentItemInput {
    AgentItemInput {
        workspace: ws.to_owned(),
        title: title.to_owned(),
        description: None,
        environment: Environment::Dev,
        role_label: None,
        category: None,
        tags: Vec::new(),
        target: None,
        custom: BTreeMap::new(),
        ttl_seconds: None,
        max_uses: None,
        payload: Payload::Note {
            text: SecretString::new("zq-fake-note".to_owned()),
        },
    }
}

fn grant_input(agent: &AgentContext, perms: &[Permission], mode: GrantMode) -> GrantInput {
    GrantInput {
        id: None,
        agent_id: agent.agent_id,
        selector: Selector::default(),
        permissions: perms.iter().copied().collect(),
        mode,
        conditions: Conditions::default(),
        allow_prod_auto: false,
    }
}

async fn secrets_in_five(fx: &Fx, agent: &AgentContext, id: ItemId) -> usize {
    let api = fx.service.agent_api();
    let mut secrets = 0;
    for _ in 0..5 {
        if matches!(
            api.reveal(agent, id, ri()).await.unwrap(),
            RevealOutcome::Secret(_)
        ) {
            secrets += 1;
        }
    }
    secrets
}

/// The newest-last audit events (type and body).
async fn audit_events(fx: &Fx) -> Vec<crate::audit::AuditEvent> {
    let mut rows = fx
        .service
        .audit_query(
            &fx.owner,
            AuditQuery {
                limit: 1000,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    rows.reverse();
    rows.into_iter().map(|e| e.event).collect()
}

/// Finding 3: an agent create must not tell hidden titles or workspaces apart.
#[tokio::test]
async fn fix7_create_is_no_oracle_for_hidden_titles_or_workspaces() {
    let fx = Fx::new().await;
    let ws = fx.workspace("secret-ws").await;
    fx.item(login(
        ws,
        "Payroll prod root",
        Environment::Prod,
        "u",
        "zq-fake-r1",
    ))
    .await;
    let agent = fx.agent(&[Scope::SecretsWrite]).await;
    let api = fx.service.agent_api();
    let hit = api
        .create_item(&agent, note("secret-ws", "Payroll prod root"))
        .await;
    let miss = api
        .create_item(&agent, note("secret-ws", "No such title"))
        .await;
    let no_ws = api.create_item(&agent, note("no-such-ws", "x")).await;
    assert!(matches!(hit, Err(CoreError::Forbidden)), "{hit:?}");
    assert!(matches!(miss, Err(CoreError::Forbidden)), "{miss:?}");
    assert!(matches!(no_ws, Err(CoreError::Forbidden)), "{no_ws:?}");

    // Write without find: the hidden item stays hidden, the create is allowed.
    let writer = fx.agent(&[Scope::SecretsWrite]).await;
    fx.grant(writer.agent_id, &[Permission::Write], GrantMode::Auto)
        .await;
    let dup = api
        .create_item(&writer, note("secret-ws", "Payroll prod root"))
        .await;
    assert!(dup.is_ok(), "{dup:?}");
    let unknown = api.create_item(&writer, note("no-such-ws", "x")).await;
    assert!(matches!(unknown, Err(CoreError::Forbidden)), "{unknown:?}");

    // With find the clash is visible, so it is a conflict.
    let finder = fx.agent(&[Scope::SecretsWrite]).await;
    fx.grant(
        finder.agent_id,
        &[Permission::Find, Permission::Write],
        GrantMode::Auto,
    )
    .await;
    let seen = api
        .create_item(&finder, note("secret-ws", "Payroll prod root"))
        .await;
    assert!(matches!(seen, Err(CoreError::Conflict)), "{seen:?}");
}

async fn ask_once_setup(fx: &Fx) -> (AgentContext, ItemId, Grant) {
    let ws = fx.workspace("shop").await;
    let id = fx
        .item(login(ws, "Dev admin", Environment::Dev, "u", "zq-fake-r2"))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    let grant = fx
        .service
        .put_grant(
            &fx.owner,
            grant_input(&agent, &[Permission::Read], GrantMode::AskOnce),
        )
        .await
        .unwrap();
    let api = fx.service.agent_api();
    let RevealOutcome::Pending(p) = api.reveal(&agent, id, ri()).await.unwrap() else {
        panic!("pending")
    };
    fx.service
        .approve_request(&fx.owner, p.access_request.id, ApprovalOption::Session)
        .await
        .unwrap();
    assert!(matches!(
        api.reveal(&agent, id, ri()).await.unwrap(),
        RevealOutcome::Secret(_)
    ));
    (agent, id, grant)
}

/// Finding 1: a grant tightened to `ask_always` needs a new approval for each read.
#[tokio::test]
async fn fix7_session_approval_does_not_serve_ask_always() {
    let fx = Fx::new().await;
    let (agent, id, grant) = ask_once_setup(&fx).await;
    let mut tighter = grant_input(&agent, &[Permission::Read], GrantMode::AskAlways);
    tighter.id = Some(grant.id);
    fx.service.put_grant(&fx.owner, tighter).await.unwrap();
    assert_eq!(secrets_in_five(&fx, &agent, id).await, 0);

    // One approval under ask_always gives exactly one read.
    let api = fx.service.agent_api();
    let RevealOutcome::Pending(p) = api.reveal(&agent, id, ri()).await.unwrap() else {
        panic!("pending")
    };
    fx.service
        .approve_request(&fx.owner, p.access_request.id, ApprovalOption::Session)
        .await
        .unwrap();
    assert_eq!(secrets_in_five(&fx, &agent, id).await, 1);
}

/// Finding 1: moving the item to prod ends the approval leases and forces a new approval.
#[tokio::test]
async fn fix7_move_to_prod_ends_approval_leases() {
    let fx = Fx::new().await;
    let (agent, id, _grant) = ask_once_setup(&fx).await;
    let detail = fx.service.get_item(&fx.owner, id).await.unwrap();
    let wsid = fx
        .service
        .list_workspaces(&fx.owner)
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.slug == detail.summary.workspace)
        .unwrap()
        .id;
    fx.service
        .update_item(
            &fx.owner,
            id,
            login(wsid, "Dev admin", Environment::Prod, "u", "zq-fake-r2-prod"),
        )
        .await
        .unwrap();
    let live = fx.service.policy().list_leases(&fx.owner).await.unwrap();
    assert!(
        live.iter().all(|l| l.view.item_id != id),
        "approval lease must end on the move: {live:?}"
    );
    assert_eq!(secrets_in_five(&fx, &agent, id).await, 0);
}

/// Finding 4 (ADR-0019 point 7): the sweeper keeps a revoked auto lease until its old end.
#[tokio::test]
async fn fix7_revoke_block_survives_the_sweeper() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let id = fx
        .item(login(ws, "Dev admin", Environment::Dev, "u", "zq-fake-r3"))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    fx.service
        .set_policy_settings(
            &fx.owner,
            PolicySettings {
                lease_ttl_auto_seconds: 86_400,
                ..PolicySettings::default()
            },
        )
        .await
        .unwrap();
    let api = fx.service.agent_api();
    let RevealOutcome::Secret(s) = api.reveal(&agent, id, ri()).await.unwrap() else {
        panic!("secret")
    };
    fx.service
        .revoke_lease(&fx.owner, s.lease.id)
        .await
        .unwrap();
    assert!(matches!(
        api.reveal(&agent, id, ri()).await,
        Err(CoreError::Forbidden)
    ));
    fx.advance(3601);
    let mut sweeper = cerberus_store::Sweeper::new(fx.service.store().clone());
    sweeper.run_once(fx.now()).await.unwrap();
    assert!(
        matches!(
            api.reveal(&agent, id, ri()).await,
            Err(CoreError::Forbidden)
        ),
        "block must last until the old lease end"
    );
    // After the old end the block is over.
    fx.advance(86_400);
    sweeper.run_once(fx.now()).await.unwrap();
    assert!(matches!(
        api.reveal(&agent, id, ri()).await.unwrap(),
        RevealOutcome::Secret(_)
    ));
}

/// Finding 5: a session approval of an earlier unlock does not stop a new request.
#[tokio::test]
async fn fix7_request_access_after_relock_opens_a_request() {
    let fx = Fx::new().await;
    let (agent, id, _g) = ask_once_setup(&fx).await;
    fx.lock().await;
    fx.advance(5);
    fx.unlock().await;
    let api = fx.service.agent_api();
    let ra = api
        .request_access(
            &agent,
            CreateAccess {
                item_id: id,
                permission: Permission::Read,
                reason: "need it again please".to_owned(),
                ttl_seconds: None,
            },
        )
        .await;
    assert!(ra.is_ok(), "{ra:?}");
}

/// Finding 2: a deny that lands while a read is in flight is ordered: either the read ends
/// before the deny (its `item.reveal` comes first in the chain) or the read is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fix7_deny_during_read_cannot_slip_between_check_and_read() {
    let fx = Arc::new(Fx::new().await);
    let ws = fx.workspace("shop").await;
    let id = fx
        .item(login(ws, "Dev admin", Environment::Dev, "u", "zq-fake-r5"))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    // Stall the read inside the lease step.
    let gate = fx.service.policy_state().lease_gate.lock().await;
    let reveal = {
        let fx = fx.clone();
        let agent = agent.clone();
        tokio::spawn(async move { fx.service.agent_api().reveal(&agent, id, ri()).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let deny = {
        let fx = fx.clone();
        let agent_id = agent.agent_id;
        tokio::spawn(async move {
            fx.service
                .put_grant(
                    &fx.owner,
                    GrantInput {
                        id: None,
                        agent_id,
                        selector: Selector {
                            item_ids: vec![id],
                            ..Selector::default()
                        },
                        permissions: Default::default(),
                        mode: GrantMode::Deny,
                        conditions: Conditions::default(),
                        allow_prod_auto: false,
                    },
                )
                .await
                .unwrap();
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(gate);
    deny.await.unwrap();
    let got = reveal.await.unwrap();
    let events = audit_events(&fx).await;
    if matches!(got, Ok(RevealOutcome::Secret(_))) {
        // The only `ok` reveal so far, and the deny grant (the second `grant.create`).
        let reveal_at = events
            .iter()
            .position(|e| e.event_type == "item.reveal" && e.result == "ok")
            .unwrap();
        let deny_at = events
            .iter()
            .rposition(|e| e.event_type == "grant.create")
            .unwrap();
        assert!(
            reveal_at < deny_at,
            "secret given out after the deny grant committed"
        );
    }
    // The deny hides the item now.
    let next = fx.service.agent_api().reveal(&agent, id, ri()).await;
    assert!(
        matches!(next, Err(CoreError::NotFound | CoreError::Forbidden)),
        "{next:?}"
    );
}

/// Finding 6: purpose text in audit bodies is trimmed and cut to 500 characters.
#[tokio::test]
async fn fix7_purpose_is_trimmed_and_cut_in_audit() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let id = fx
        .item(login(ws, "Dev admin", Environment::Dev, "u", "zq-fake-r6"))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();
    let padded = RevealInput {
        purpose: "   deploy check   ".to_owned(),
        ..RevealInput::default()
    };
    api.reveal(&agent, id, padded).await.unwrap();
    let long = "a".repeat(5000);
    let bad = api.resolve(&agent, ResolveRequest::new("shop", long)).await;
    assert!(matches!(bad, Err(CoreError::Validation(_))), "{bad:?}");
    let events = audit_events(&fx).await;
    let purposes: Vec<&str> = events
        .iter()
        .filter_map(|e| e.details.get("purpose").and_then(serde_json::Value::as_str))
        .collect();
    assert!(purposes.contains(&"deploy check"), "{purposes:?}");
    assert!(
        purposes
            .iter()
            .all(|p| p.chars().count() <= 500 && p.trim() == *p),
        "raw purpose in audit"
    );
}

/// Finding 8: the last allowed reveal writes `item.reveal` before the item is deleted.
#[tokio::test]
async fn fix7_last_reveal_is_audited_before_the_delete() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop").await;
    let mut input = login(ws, "One shot", Environment::Dev, "u", "zq-fake-r8");
    input.max_uses = Some(1);
    let id = fx.item(input).await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();
    assert!(matches!(
        api.reveal(&agent, id, ri()).await.unwrap(),
        RevealOutcome::Secret(_)
    ));
    let types = fx.audit_types().await;
    let reveal_at = types.iter().rposition(|t| t == "item.reveal").unwrap();
    let delete_at = types.iter().rposition(|t| t == "item.delete").unwrap();
    assert!(reveal_at < delete_at, "{types:?}");
    assert!(matches!(
        api.reveal(&agent, id, ri()).await,
        Err(CoreError::NotFound)
    ));
}

/// Finding 7: a settings load that read the row before a save never puts its stale value over
/// the saved one.
#[tokio::test]
async fn fix7_stale_settings_load_does_not_overwrite_a_save() {
    let fx = Fx::new().await;
    let engine = fx.service.policy();
    let key = {
        let guard = fx.service.unlocked().await.unwrap();
        guard.session.unlocked_at
    };
    // A load starts: it notes the save counter, then reads the old row.
    let generation = engine.settings_generation();
    let stale = PolicySettings::default();
    // A save lands while that load runs.
    let saved = PolicySettings {
        lease_ttl_auto_seconds: 7200,
        ..PolicySettings::default()
    };
    fx.service
        .set_policy_settings(&fx.owner, saved)
        .await
        .unwrap();
    // The load ends: the saved value wins, in the answer and in the cache.
    assert_eq!(engine.store_loaded_settings(key, generation, stale), saved);
    assert_eq!(engine.policy_settings(&fx.owner).await.unwrap(), saved);
}

/// DEC-FIX7-9: `AgentApi::resolve` gives a `Send` future, so a web server can run it on its
/// own task. The future is built and dropped, never run.
#[tokio::test]
async fn fix7_resolve_future_is_send() {
    fn is_send<T: Send>(value: T) -> T {
        value
    }
    let fx = Fx::new().await;
    let agent = fx.agent(&all_scopes()).await;
    let api = fx.service.agent_api();
    drop(is_send(
        api.resolve(&agent, ResolveRequest::new("shop", "send check")),
    ));
}

/// DEC-INT10-6: a metadata-only update that moves the item to prod ends the approval leases too.
#[tokio::test]
async fn int10_keep_payload_move_to_prod_ends_approval_leases() {
    let fx = Fx::new().await;
    let (agent, id, _grant) = ask_once_setup(&fx).await;
    let detail = fx.service.get_item(&fx.owner, id).await.unwrap();
    let wsid = fx
        .service
        .list_workspaces(&fx.owner)
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.slug == detail.summary.workspace)
        .unwrap()
        .id;
    let moved = ItemUpdate {
        payload: PayloadChange::Keep,
        ..ItemUpdate::from(login(
            wsid,
            "Dev admin",
            Environment::Prod,
            "u",
            "zq-fake-int10-unused",
        ))
    };
    fx.service.update_item(&fx.owner, id, moved).await.unwrap();
    let live = fx.service.policy().list_leases(&fx.owner).await.unwrap();
    assert!(
        live.iter().all(|l| l.view.item_id != id),
        "approval lease must end on the move: {live:?}"
    );
    assert_eq!(secrets_in_five(&fx, &agent, id).await, 0);
}
