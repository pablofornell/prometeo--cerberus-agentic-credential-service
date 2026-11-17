//! Regression tests for the T26 audit findings that the core fixes in T27 (AUD-5, AUD-22,
//! AUD-24). Each test fails on the code before the fix. Every secret here is a fake test value
//! with the marker `zq-fake`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use cerberus_crypto::SecretString;
use cerberus_types::{ApprovalOption, Environment, GrantMode, ItemId, Permission};

use super::AgentItemInput;
use super::tests::{Fx, all_scopes, login};
use crate::agents::{AgentInput, AgentKeyInput};
use crate::approvals::{CreateAccess, clean_reason};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::items::Payload;

fn secret(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

fn agent_item(title: &str, payload: Payload) -> AgentItemInput {
    AgentItemInput {
        workspace: "shop".to_owned(),
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
        payload,
    }
}

fn env_bundle(names: &[&str]) -> Payload {
    Payload::EnvBundle {
        vars: names
            .iter()
            .map(|n| ((*n).to_owned(), secret("zq-fake-value")))
            .collect(),
    }
}

fn cloud_with_extra(name: &str) -> Payload {
    Payload::Cloud {
        provider: "aws".to_owned(),
        access_key_id: None,
        secret_access_key: None,
        session_token: Some(secret("zq-fake-session")),
        region: None,
        extra: [(name.to_owned(), secret("zq-fake-extra"))]
            .into_iter()
            .collect(),
    }
}

/// A fixture with workspace `shop` and an agent with `write` (auto).
async fn writer() -> (Fx, AgentContext) {
    let fx = Fx::new().await;
    fx.workspace("shop").await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Write], GrantMode::Auto)
        .await;
    (fx, agent)
}

fn fields(error: CoreError) -> Vec<String> {
    match error {
        CoreError::Validation(problems) => problems.into_iter().map(|p| p.field).collect(),
        other => panic!("expected a validation error, got {other:?}"),
    }
}

/// AUD-5: an agent cannot store an env bundle or cloud `extra` name that changes what code a
/// child of `cerberus run` loads.
#[tokio::test]
async fn agent_items_cannot_set_forbidden_env_names() {
    let (fx, agent) = writer().await;
    let api = fx.service.agent_api();
    for name in [
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PATH",
        "BASH_ENV",
        "PYTHONSTARTUP",
    ] {
        let error = api
            .create_item(
                &agent,
                agent_item("Shop env", env_bundle(&["API_KEY", name])),
            )
            .await
            .unwrap_err();
        assert_eq!(fields(error), [format!("payload.vars.{name}")], "{name}");
    }
    let error = api
        .create_item(
            &agent,
            agent_item("Shop cloud", cloud_with_extra("DYLD_INSERT_LIBRARIES")),
        )
        .await
        .unwrap_err();
    assert_eq!(fields(error), ["payload.extra.DYLD_INSERT_LIBRARIES"]);
    // Normal names still work for the agent.
    api.create_item(
        &agent,
        agent_item("Shop env", env_bundle(&["API_KEY", "DATABASE_URL"])),
    )
    .await
    .unwrap();
    // A person may store any valid name; `cerberus run` sets it only with an explicit `--var`.
    let ws = fx.workspace("ops").await;
    let mut input = login(ws, "Ops env", Environment::Dev, "u", "zq-fake-p");
    input.payload = env_bundle(&["PATH"]);
    fx.item(input).await;
}

/// AUD-5 re-check (DEC-T27-D1-1): a deny list misses names such as `MAVEN_OPTS` or
/// `OPENSSL_CONF`, so an agent item may only set credential-shaped names, in any case.
#[tokio::test]
async fn agent_items_may_set_only_credential_env_names() {
    let (fx, agent) = writer().await;
    let api = fx.service.agent_api();
    for name in [
        "MAVEN_OPTS",
        "OPENSSL_CONF",
        "RUSTFLAGS",
        "KUBECONFIG",
        "AWS_CONFIG_FILE",
        "DOCKER_HOST",
        "maven_opts",
        "OpenSSL_Conf",
    ] {
        let error = api
            .create_item(
                &agent,
                agent_item("Shop env", env_bundle(&["API_KEY", name])),
            )
            .await
            .unwrap_err();
        assert_eq!(fields(error), [format!("payload.vars.{name}")], "{name}");
    }
    for name in ["RustFlags", "openssl_conf", "MAVEN_OPTS", "GOFLAGS"] {
        let error = api
            .create_item(&agent, agent_item("Shop cloud", cloud_with_extra(name)))
            .await
            .unwrap_err();
        assert_eq!(fields(error), [format!("payload.extra.{name}")], "{name}");
    }
    // Credential names still work for the agent.
    api.create_item(
        &agent,
        agent_item(
            "Shop env",
            env_bundle(&[
                "GITHUB_TOKEN",
                "STRIPE_SECRET_KEY",
                "DB_PASSWORD",
                "SMTP_USER",
            ]),
        ),
    )
    .await
    .unwrap();
    api.create_item(
        &agent,
        agent_item("Shop cloud", cloud_with_extra("DEPLOY_TOKEN")),
    )
    .await
    .unwrap();
    // A person keeps the old rule: any valid name may be stored.
    let ws = fx.workspace("ops").await;
    let mut input = login(ws, "Ops env", Environment::Dev, "u", "zq-fake-p");
    input.payload = env_bundle(&["MAVEN_OPTS"]);
    fx.item(input).await;
}

/// AUD-24: bidi controls, zero-width and tag characters are removed from reasons, agent names
/// and agent-written item text.
#[tokio::test]
async fn hidden_format_characters_are_removed_from_untrusted_text() {
    assert_eq!(
        clean_reason("deploy to p\u{202E}dorp\u{202C} now\u{200B}\u{E0041}"),
        "deploy to pdorp now"
    );

    let (fx, agent) = writer().await;
    let created = fx
        .service
        .agent_api()
        .create_item(
            &agent,
            AgentItemInput {
                description: Some("for \u{2066}staging\u{2069}".to_owned()),
                tags: vec!["q\u{200D}a".to_owned()],
                target: Some("shop\u{200B}.example".to_owned()),
                role_label: Some("ad\u{202E}min".to_owned()),
                ..agent_item(
                    "Shop \u{202E}dorp\u{202C}",
                    Payload::Note {
                        text: secret("zq-fake-note"),
                    },
                )
            },
        )
        .await
        .unwrap();
    let item = created.item;
    assert_eq!(item.title, "Shop dorp");
    assert_eq!(item.description, "for staging");
    assert_eq!(item.tags, ["qa"]);
    assert_eq!(item.target.as_deref(), Some("shop.example"));
    assert_eq!(item.role_label.as_deref(), Some("admin"));

    let (view, _) = fx
        .service
        .create_agent(
            &fx.owner,
            AgentInput {
                name: "deploy\u{202E}-bot".to_owned(),
                description: "runs \u{200B}deploys".to_owned(),
            },
            AgentKeyInput {
                scopes: all_scopes(),
                lifetime_days: Some(90),
                ip_allowlist: Vec::new(),
                require_mtls: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(view.name, "deploy-bot");
    assert_eq!(view.description, "runs deploys");
}

/// AUD-22: an approval that lands between the lease check and the pending check of a repeated
/// `request_access` does not open a second pending request. The test holds `request_gate`,
/// queues the approval on it first, then the repeated call; before the fix that call did its
/// lease check before it waited for the gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_during_a_repeated_request_opens_no_second_request() {
    let fx = Arc::new(Fx::new().await);
    let ws = fx.workspace("shop").await;
    let id: ItemId = fx
        .item(login(
            ws,
            "Shop admin",
            Environment::Dev,
            "u",
            "zq-fake-r22",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let ask = move || CreateAccess {
        item_id: id,
        permission: Permission::Read,
        reason: "need it for the race test".to_owned(),
        ttl_seconds: None,
    };
    let api = fx.service.agent_api();
    let first = api.request_access(&agent, ask()).await.unwrap();

    let gate = fx.service.policy_state().request_gate.lock().await;
    let approve = {
        let fx = fx.clone();
        tokio::spawn(async move {
            fx.service
                .approve_request(&fx.owner, first.id, ApprovalOption::Once)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let again = {
        let api = fx.service.agent_api();
        let agent = agent.clone();
        tokio::spawn(async move { api.request_access(&agent, ask()).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(gate);
    approve.await.unwrap().unwrap();
    let again = again.await.unwrap();

    let requests = fx
        .service
        .store()
        .access_requests_for(agent.agent_id, id)
        .await
        .unwrap();
    assert_eq!(
        requests.len(),
        1,
        "one request only; the repeated call gave {again:?}"
    );
    assert!(
        matches!(again, Err(CoreError::Conflict)) || again.is_ok_and(|v| v.id == first.id),
        "the repeated call sees the approval or the first request"
    );
}

/// T21 ask (DEC-T27-A2-8): the `audit_query` text filter matches metadata (event type, target,
/// agent name, item title), never other detail values.
#[tokio::test]
async fn the_audit_text_filter_matches_metadata_only() {
    let (fx, agent) = writer().await;
    let api = fx.service.agent_api();
    let made = api
        .create_item(
            &agent,
            agent_item(
                "Shop deploy note",
                Payload::Note {
                    text: secret("zq-fake-note"),
                },
            ),
        )
        .await
        .unwrap();
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    api.reveal(
        &agent,
        made.item.id,
        super::RevealInput {
            purpose: "purpose word zqpurpose".to_owned(),
            ..super::RevealInput::default()
        },
    )
    .await
    .unwrap();
    let find = |text: &str| {
        let fx = &fx;
        let text = text.to_owned();
        async move {
            fx.service
                .audit_query(
                    &fx.owner,
                    crate::admin::AuditQuery {
                        text: Some(text),
                        limit: 1000,
                        ..crate::admin::AuditQuery::default()
                    },
                )
                .await
                .unwrap()
                .into_iter()
                .map(|e| e.event.event_type)
                .collect::<Vec<_>>()
        }
    };
    let by_name = find("QA-AGENT").await;
    assert!(by_name.contains(&"item.create".to_owned()), "{by_name:?}");
    assert!(by_name.contains(&"item.reveal".to_owned()), "{by_name:?}");
    let by_title = find("deploy note").await;
    assert!(by_title.contains(&"item.reveal".to_owned()), "{by_title:?}");
    assert_eq!(find("item.reveal").await, ["item.reveal"]);
    assert!(find("zq-fake").await.is_empty(), "no secret value matches");
    assert!(
        find("zqpurpose").await.is_empty(),
        "detail values do not match"
    );
    let long = "x".repeat(201);
    assert!(matches!(
        fx.service
            .audit_query(
                &fx.owner,
                crate::admin::AuditQuery {
                    text: Some(long),
                    limit: 10,
                    ..crate::admin::AuditQuery::default()
                },
            )
            .await,
        Err(CoreError::Validation(_))
    ));
}
