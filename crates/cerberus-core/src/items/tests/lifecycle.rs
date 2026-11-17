//! Create, change, delete, versions, TTL, uses, settings and TOTP through the vault service.

use cerberus_store::Sweeper;
use cerberus_types::{ItemKind, OperatorRole, RequestId};
use jiff::SignedDuration;

use super::fixture::{
    Fx, VIEWER_PHRASE, input, login_payload, open_service, phrase, secret, session_payload,
    totp_login_payload,
};
use crate::admin::AuditQuery;
use crate::context::{AgentContext, OperatorContext, Surface};
use crate::error::CoreError;
use crate::items::{
    ItemFilter, ItemInput, ItemSettings, ItemUpdate, Payload, PayloadChange, generate_ed25519,
};
use crate::vault::KeyCustody;

fn agent_ctx() -> AgentContext {
    AgentContext {
        agent_id: cerberus_types::AgentId::generate(),
        key_id: cerberus_types::AgentKeyId::generate(),
        scopes: std::collections::BTreeSet::new(),
        request_id: RequestId::generate(),
        source_ip: std::net::IpAddr::from([127, 0, 0, 1]),
        surface: Surface::Rest,
    }
}

fn password_of(payload: &Payload) -> String {
    match payload {
        Payload::WebLogin { password, .. } => password.expose_secret().to_owned(),
        other => panic!("not a web login: {other:?}"),
    }
}

#[tokio::test]
async fn create_get_list_and_read_back() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Staging admin",
            login_payload("alice", "fake-pw-1"),
        ))
        .await;
    let detail = fx.service.get_item(&fx.ctx, id).await.unwrap();
    assert_eq!(detail.version, 1);
    assert_eq!(detail.summary.kind, ItemKind::WebLogin);
    assert_eq!(detail.summary.workspace, "shop-frontend");
    assert!(detail.summary.created_by.starts_with("operator:"));
    let listed = fx
        .service
        .list_items(&fx.ctx, ItemFilter::default())
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    let read = fx.service.read_payload(id, false).await.unwrap();
    assert_eq!(password_of(&read.payload), "fake-pw-1");
    assert_eq!(read.use_count, 0);
}

#[tokio::test]
async fn list_filters() {
    let fx = Fx::new().await;
    let other = fx.add_workspace("infra", "Infra", &[]).await;
    fx.create(input(fx.ws, "Alpha login", login_payload("a", "p")))
        .await;
    let mut b = input(other, "Beta key", generate_ed25519("fake").unwrap());
    b.environment = cerberus_types::Environment::Prod;
    b.tags = vec!["deploy".into()];
    fx.create(b).await;
    let svc = &fx.service;
    let count = |f: ItemFilter| {
        let ctx = fx.ctx.clone();
        async move { svc.list_items(&ctx, f).await.unwrap().len() }
    };
    assert_eq!(count(ItemFilter::default()).await, 2);
    assert_eq!(
        count(ItemFilter {
            workspace_id: Some(other),
            ..Default::default()
        })
        .await,
        1
    );
    assert_eq!(
        count(ItemFilter {
            kind: Some(ItemKind::SshKey),
            ..Default::default()
        })
        .await,
        1
    );
    assert_eq!(
        count(ItemFilter {
            environment: Some(cerberus_types::Environment::Prod),
            ..Default::default()
        })
        .await,
        1
    );
    assert_eq!(
        count(ItemFilter {
            tag: Some("DEPLOY".into()),
            ..Default::default()
        })
        .await,
        1
    );
    assert_eq!(
        count(ItemFilter {
            q: Some("alpha".into()),
            ..Default::default()
        })
        .await,
        1
    );
    assert_eq!(
        count(ItemFilter {
            q: Some("alpha beta".into()),
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn duplicate_title_in_a_workspace_conflicts() {
    let fx = Fx::new().await;
    fx.create(input(fx.ws, "Staging admin", login_payload("a", "p")))
        .await;
    let again = fx
        .service
        .create_item_as_operator(
            &fx.ctx,
            input(fx.ws, "  staging   ADMIN ", login_payload("b", "q")),
        )
        .await;
    assert!(matches!(again, Err(CoreError::Conflict)), "{again:?}");
    let other = fx.add_workspace("infra", "Infra", &[]).await;
    fx.create(input(other, "Staging admin", login_payload("b", "q")))
        .await;
}

#[tokio::test]
async fn validation_errors_and_unknown_workspace() {
    let fx = Fx::new().await;
    let bad = fx
        .service
        .create_item_as_operator(&fx.ctx, input(fx.ws, "", login_payload("a", "")))
        .await;
    let Err(CoreError::Validation(list)) = bad else {
        panic!("wanted validation")
    };
    let fields: Vec<_> = list.iter().map(|p| p.field.as_str()).collect();
    assert!(
        fields.contains(&"title") && fields.contains(&"payload.password"),
        "{fields:?}"
    );
    let unknown = fx
        .service
        .create_item_as_operator(
            &fx.ctx,
            input(
                cerberus_types::WorkspaceId::generate(),
                "T",
                login_payload("a", "p"),
            ),
        )
        .await;
    assert!(matches!(unknown, Err(CoreError::Validation(_))));
}

#[tokio::test]
async fn viewer_cannot_write_and_locked_vault_refuses() {
    let fx = Fx::new().await;
    fx.service
        .add_operator(
            &fx.ctx,
            "Viewer".into(),
            OperatorRole::Viewer,
            phrase(VIEWER_PHRASE),
        )
        .await
        .unwrap();
    let id = fx.create(input(fx.ws, "T", login_payload("a", "p"))).await;
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    let locked = fx.service.read_payload(id, false).await;
    assert!(matches!(locked, Err(CoreError::Locked)));
    let viewer = fx
        .service
        .list_operators()
        .await
        .unwrap()
        .into_iter()
        .find(|o| o.role == OperatorRole::Viewer)
        .unwrap();
    let ctx = fx
        .service
        .unlock_with_phrase(viewer.id, phrase(VIEWER_PHRASE))
        .await
        .unwrap();
    assert!(
        fx.service.get_item(&ctx, id).await.is_ok(),
        "viewers may browse"
    );
    let denied = fx
        .service
        .create_item_as_operator(&ctx, input(fx.ws, "U", login_payload("a", "p")))
        .await;
    assert!(matches!(denied, Err(CoreError::RoleNotAllowed)));
    assert!(matches!(
        fx.service.delete_item_as_operator(&ctx, id).await,
        Err(CoreError::RoleNotAllowed)
    ));
}

/// Acceptance A3: store a session with ttl 3600, it is gone after 3600 s, the sweeper deletes the row.
#[tokio::test]
async fn session_ttl_expires_on_the_manual_clock() {
    let fx = Fx::new().await;
    let expires = fx
        .service
        .expiry_from_ttl(ItemKind::SessionToken, Some(3600))
        .await
        .unwrap();
    let mut item = input(fx.ws, "QA session", session_payload("fake-token-1"));
    item.expires_at = expires;
    let created = fx
        .service
        .create_item_as_agent(&agent_ctx(), item, &|_, _| Ok(()))
        .await
        .unwrap();
    let id = created.summary.id;
    assert!(created.summary.created_by.starts_with("agent:"));
    assert_eq!(
        created.summary.expires_at,
        Some(fx.now() + SignedDuration::from_secs(3600))
    );
    fx.advance(3599);
    assert!(fx.service.get_item(&fx.ctx, id).await.is_ok());
    fx.advance(1);
    assert!(matches!(
        fx.service.get_item(&fx.ctx, id).await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        fx.service.read_payload(id, true).await,
        Err(CoreError::NotFound)
    ));
    assert!(
        fx.service
            .list_items(&fx.ctx, ItemFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    let report = Sweeper::new(fx.service.store().clone())
        .run_once(fx.now())
        .await
        .unwrap();
    assert_eq!(report.expired_items, [id]);
}

#[tokio::test]
async fn ttl_rules_default_max_and_other_kinds() {
    let fx = Fx::new().await;
    let svc = &fx.service;
    let now = fx.now();
    let hour = |s| Some(now + SignedDuration::from_secs(s));
    assert_eq!(
        svc.expiry_from_ttl(ItemKind::SessionToken, None)
            .await
            .unwrap(),
        hour(3600)
    );
    assert_eq!(
        svc.expiry_from_ttl(ItemKind::BrowserSession, Some(86_400))
            .await
            .unwrap(),
        hour(86_400)
    );
    let over = svc
        .expiry_from_ttl(ItemKind::SessionToken, Some(86_401))
        .await;
    let Err(CoreError::Validation(list)) = over else {
        panic!("wanted validation")
    };
    assert_eq!(list[0].field, "ttl_seconds");
    assert!(
        svc.expiry_from_ttl(ItemKind::SessionToken, Some(59))
            .await
            .is_err()
    );
    assert_eq!(
        svc.expiry_from_ttl(ItemKind::ApiKey, None).await.unwrap(),
        None
    );
    assert_eq!(
        svc.expiry_from_ttl(ItemKind::ApiKey, Some(31_536_000))
            .await
            .unwrap(),
        hour(31_536_000)
    );
    assert!(
        svc.expiry_from_ttl(ItemKind::ApiKey, Some(31_536_001))
            .await
            .is_err()
    );
    assert!(
        svc.expiry_from_ttl(ItemKind::ApiKey, Some(30))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn session_items_without_expiry_get_the_default_and_far_ones_are_refused() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(fx.ws, "S1", session_payload("fake-token-2")))
        .await;
    let detail = fx.service.get_item(&fx.ctx, id).await.unwrap();
    assert_eq!(
        detail.summary.expires_at,
        Some(fx.now() + SignedDuration::from_secs(3600))
    );
    let mut far = input(fx.ws, "S2", session_payload("fake-token-3"));
    far.expires_at = Some(fx.now() + SignedDuration::from_secs(90_000));
    assert!(matches!(
        fx.service.create_item_as_operator(&fx.ctx, far).await,
        Err(CoreError::Validation(_))
    ));
    let mut past = input(fx.ws, "S3", login_payload("a", "p"));
    past.expires_at = Some(fx.now());
    assert!(matches!(
        fx.service.create_item_as_operator(&fx.ctx, past).await,
        Err(CoreError::Validation(_))
    ));
}

#[tokio::test]
async fn settings_change_the_ttl_and_need_the_owner() {
    let fx = Fx::new().await;
    let current = fx.service.item_settings(&fx.ctx).await.unwrap();
    assert_eq!(current, ItemSettings::default());
    let value = ItemSettings {
        session_ttl_default_seconds: 600,
        session_ttl_max_seconds: 1_200,
        versions_keep: 3,
    };
    fx.service.set_item_settings(&fx.ctx, value).await.unwrap();
    assert_eq!(fx.service.item_settings(&fx.ctx).await.unwrap(), value);
    let expiry = fx
        .service
        .expiry_from_ttl(ItemKind::SessionToken, None)
        .await
        .unwrap();
    assert_eq!(expiry, Some(fx.now() + SignedDuration::from_secs(600)));
    assert!(
        fx.service
            .expiry_from_ttl(ItemKind::SessionToken, Some(1_201))
            .await
            .is_err()
    );
    for bad in [
        ItemSettings {
            session_ttl_max_seconds: 100,
            ..value
        },
        ItemSettings {
            session_ttl_max_seconds: 604_801,
            ..value
        },
        ItemSettings {
            session_ttl_default_seconds: 1_201,
            ..value
        },
        ItemSettings {
            session_ttl_default_seconds: 59,
            ..value
        },
        ItemSettings {
            versions_keep: 0,
            ..value
        },
        ItemSettings {
            versions_keep: 101,
            ..value
        },
    ] {
        assert!(matches!(
            fx.service.set_item_settings(&fx.ctx, bad).await,
            Err(CoreError::Validation(_))
        ));
    }
    fx.service
        .add_operator(
            &fx.ctx,
            "Op".into(),
            OperatorRole::Operator,
            phrase(VIEWER_PHRASE),
        )
        .await
        .unwrap();
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    let op = fx
        .service
        .list_operators()
        .await
        .unwrap()
        .into_iter()
        .find(|o| o.role == OperatorRole::Operator)
        .unwrap();
    let op_ctx = fx
        .service
        .unlock_with_phrase(op.id, phrase(VIEWER_PHRASE))
        .await
        .unwrap();
    assert!(matches!(
        fx.service
            .set_item_settings(&op_ctx, ItemSettings::default())
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert_eq!(
        fx.service.item_settings(&op_ctx).await.unwrap(),
        value,
        "settings survive a lock"
    );
}

#[tokio::test]
async fn max_uses_counts_reveals_and_deletes_after_the_last() {
    let fx = Fx::new().await;
    let mut item = input(fx.ws, "One-shot", login_payload("a", "fake-pw-2"));
    item.max_uses = Some(2);
    let id = fx.create(item).await;
    let peek = fx.service.read_payload(id, false).await.unwrap();
    assert_eq!(
        (peek.use_count, peek.exhausted),
        (0, false),
        "an operator look does not count"
    );
    let first = fx.service.read_payload(id, true).await.unwrap();
    assert_eq!((first.use_count, first.exhausted), (1, false));
    assert_eq!(fx.service.get_item(&fx.ctx, id).await.unwrap().use_count, 1);
    let last = fx.service.read_payload(id, true).await.unwrap();
    assert!(last.exhausted);
    assert_eq!(
        password_of(&last.payload),
        "fake-pw-2",
        "the last reveal still gets the secret"
    );
    assert!(matches!(
        fx.service.read_payload(id, true).await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        fx.service.get_item(&fx.ctx, id).await,
        Err(CoreError::NotFound)
    ));
    assert!(matches!(
        fx.service.store().item(id).await,
        Err(cerberus_store::StoreError::NotFound)
    ));
    let update = fx.service.item_versions(&fx.ctx, id).await;
    assert!(matches!(update, Err(CoreError::NotFound)));
}

#[tokio::test]
async fn use_count_survives_a_restart() {
    let fx = Fx::new().await;
    let mut item = input(fx.ws, "Counted", login_payload("a", "p"));
    item.max_uses = Some(5);
    let id = fx.create(item).await;
    fx.service.read_payload(id, true).await.unwrap();
    fx.service.read_payload(id, true).await.unwrap();
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    let again = open_service(&fx.path, &fx.clock).await;
    let owner = again.list_operators().await.unwrap().remove(0);
    let ctx = again
        .unlock_with_phrase(owner.id, phrase(super::fixture::OWNER_PHRASE))
        .await
        .unwrap();
    let detail = again.get_item(&ctx, id).await.unwrap();
    assert_eq!((detail.use_count, detail.max_uses), (2, Some(5)));
    assert_eq!(
        password_of(&again.read_payload(id, false).await.unwrap().payload),
        "p"
    );
}

#[tokio::test]
async fn updates_make_versions_and_keep_the_last_n() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(fx.ws, "Rotating", login_payload("a", "pw-v1")))
        .await;
    for n in 2..=12 {
        let d = fx
            .service
            .update_item(
                &fx.ctx,
                id,
                input(fx.ws, "Rotating", login_payload("a", &format!("pw-v{n}"))),
            )
            .await
            .unwrap();
        assert_eq!(d.version, n);
    }
    let versions = fx.service.item_versions(&fx.ctx, id).await.unwrap();
    assert_eq!(versions.len(), 10, "default retention is 10");
    assert_eq!(versions.first().map(|v| v.version), Some(12));
    assert_eq!(versions.last().map(|v| v.version), Some(3));
    assert_eq!(
        password_of(&fx.service.read_payload(id, false).await.unwrap().payload),
        "pw-v12"
    );
    let restored = fx
        .service
        .restore_item_version(&fx.ctx, id, 5)
        .await
        .unwrap();
    assert_eq!(restored.version, 13);
    assert_eq!(
        password_of(&fx.service.read_payload(id, false).await.unwrap().payload),
        "pw-v5"
    );
    assert!(
        matches!(
            fx.service.restore_item_version(&fx.ctx, id, 1).await,
            Err(CoreError::NotFound)
        ),
        "version 1 was pruned"
    );
}

#[tokio::test]
async fn retention_setting_and_session_kinds() {
    let fx = Fx::new().await;
    fx.service
        .set_item_settings(
            &fx.ctx,
            ItemSettings {
                versions_keep: 2,
                ..ItemSettings::default()
            },
        )
        .await
        .unwrap();
    let id = fx
        .create(input(fx.ws, "Two", login_payload("a", "p1")))
        .await;
    for n in 2..=4 {
        fx.service
            .update_item(
                &fx.ctx,
                id,
                input(fx.ws, "Two", login_payload("a", &format!("p{n}"))),
            )
            .await
            .unwrap();
    }
    assert_eq!(
        fx.service.item_versions(&fx.ctx, id).await.unwrap().len(),
        2
    );
    let sid = fx.create(input(fx.ws, "Sess", session_payload("t1"))).await;
    let mut next = input(fx.ws, "Sess", session_payload("t2"));
    next.expires_at = Some(fx.now() + SignedDuration::from_secs(600));
    fx.service.update_item(&fx.ctx, sid, next).await.unwrap();
    assert_eq!(
        fx.service.item_versions(&fx.ctx, sid).await.unwrap().len(),
        1,
        "sessions keep one version"
    );
}

#[tokio::test]
async fn update_rules() {
    let fx = Fx::new().await;
    let id = fx.create(input(fx.ws, "A", login_payload("a", "p"))).await;
    let other = fx.create(input(fx.ws, "B", login_payload("a", "p"))).await;
    let clash = fx
        .service
        .update_item(&fx.ctx, other, input(fx.ws, "A", login_payload("a", "p")))
        .await;
    assert!(matches!(clash, Err(CoreError::Conflict)));
    let kind = fx
        .service
        .update_item(&fx.ctx, id, input(fx.ws, "A", session_payload("t")))
        .await;
    assert!(matches!(kind, Err(CoreError::Validation(_))));
    let missing = fx
        .service
        .update_item(
            &fx.ctx,
            cerberus_types::ItemId::generate(),
            input(fx.ws, "Z", login_payload("a", "p")),
        )
        .await;
    assert!(matches!(missing, Err(CoreError::NotFound)));
    let mut metered = fx.create(input(fx.ws, "M", login_payload("a", "p"))).await;
    fx.service.read_payload(metered, true).await.unwrap();
    let mut low = input(fx.ws, "M", login_payload("a", "p"));
    low.max_uses = Some(1);
    assert!(matches!(
        fx.service.update_item(&fx.ctx, metered, low).await,
        Err(CoreError::Validation(_))
    ));
    metered = id;
    let _ = metered;
}

#[tokio::test]
async fn delete_rules_for_agents_and_operators() {
    let fx = Fx::new().await;
    let agent = agent_ctx();
    let by_agent = fx
        .service
        .create_item_as_agent(
            &agent,
            input(fx.ws, "Agent made", login_payload("a", "p")),
            &|_, _| Ok(()),
        )
        .await
        .unwrap()
        .summary
        .id;
    let by_human = fx
        .create(input(fx.ws, "Human made", login_payload("a", "p")))
        .await;
    assert!(matches!(
        fx.service.delete_item_as_agent(&agent, by_human).await,
        Err(CoreError::Forbidden)
    ));
    assert!(
        matches!(
            fx.service
                .delete_item_as_agent(&agent_ctx(), by_agent)
                .await,
            Err(CoreError::Forbidden)
        ),
        "another agent"
    );
    fx.service
        .delete_item_as_agent(&agent, by_agent)
        .await
        .unwrap();
    fx.service
        .delete_item_as_operator(&fx.ctx, by_human)
        .await
        .unwrap();
    assert!(matches!(
        fx.service.delete_item_as_operator(&fx.ctx, by_human).await,
        Err(CoreError::NotFound)
    ));
    assert!(
        fx.service
            .list_items(&fx.ctx, ItemFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        fx.service.store().item(by_agent).await,
        Err(cerberus_store::StoreError::NotFound)
    ));
}

#[tokio::test]
async fn totp_through_the_service_never_shows_the_seed() {
    let fx = Fx::new().await;
    let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let id = fx
        .create(input(fx.ws, "With 2FA", totp_login_payload(seed)))
        .await;
    let detail = fx.service.get_item(&fx.ctx, id).await.unwrap();
    assert!(detail.summary.has_totp);
    assert!(!format!("{detail:?}").contains(seed));
    let code = fx.service.totp_code(id).await.unwrap();
    assert_eq!(code.code.expose_secret().len(), 6);
    assert_eq!(
        (code.period, code.expires_in_seconds),
        (30, 30),
        "t0 is on a step edge"
    );
    fx.advance(10);
    assert_eq!(
        fx.service.totp_code(id).await.unwrap().expires_in_seconds,
        20
    );
    let plain = fx
        .create(input(fx.ws, "No 2FA", login_payload("a", "p")))
        .await;
    assert!(matches!(
        fx.service.totp_code(plain).await,
        Err(CoreError::NotFound)
    ));
    let mut metered = input(fx.ws, "Metered 2FA", totp_login_payload(seed));
    metered.max_uses = Some(1);
    let mid = fx.create(metered).await;
    fx.service.totp_code(mid).await.unwrap();
    assert!(
        fx.service.totp_code(mid).await.is_ok(),
        "a code is not a reveal"
    );
}

#[tokio::test]
async fn ssh_metadata_survives_lock_and_unlock() {
    let fx = Fx::new().await;
    let mut item = input(
        fx.ws,
        "build-01 deploy key",
        generate_ed25519("deploy@build-01").unwrap(),
    );
    item.target = Some("build-01".into());
    item.custom = crate::items::SshMeta {
        machine: Some("build-01".into()),
        host: Some("10.0.0.5".into()),
        port: Some(2222),
        user: Some("deploy".into()),
    }
    .into_custom();
    let id = fx.create(item).await;
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    let owner = fx.service.list_operators().await.unwrap().remove(0);
    fx.service
        .unlock_with_phrase(owner.id, phrase(super::fixture::OWNER_PHRASE))
        .await
        .unwrap();
    let guard = fx.service.unlocked().await.unwrap();
    let meta = guard.index.item(&id).unwrap();
    let ssh = crate::items::SshMeta::from_custom(|k| meta.custom.get(k).map(|v| v.as_str()));
    assert_eq!(ssh.port, Some(2222));
    assert_eq!(ssh.user.as_deref(), Some("deploy"));
    assert_eq!(ssh.machine.as_deref(), Some("build-01"));
    assert_eq!(ssh.host.as_deref(), Some("10.0.0.5"));
}

#[tokio::test]
async fn the_database_file_has_no_secret_or_title_in_clear() {
    let fx = Fx::new().await;
    fx.create(input(
        fx.ws,
        "Marker title Q7",
        login_payload("marker-user-q7", "marker-pass-q7"),
    ))
    .await;
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    drop(secret("unused"));
    let bytes = std::fs::read(&fx.path).unwrap();
    for needle in [
        "marker-user-q7",
        "marker-pass-q7",
        "Marker title Q7",
        "fake test item",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle}"
        );
    }
    let _: &OperatorContext = &fx.ctx;
}

/// An update that races with a delete must not bring the item back (orchestrator rule 2).
#[tokio::test]
async fn update_racing_with_delete_never_resurrects() {
    for _ in 0..10 {
        let fx = Fx::new().await;
        let id = fx
            .create(input(fx.ws, "Racy", login_payload("a", "p1")))
            .await;
        let upd =
            fx.service
                .update_item(&fx.ctx, id, input(fx.ws, "Racy", login_payload("a", "p2")));
        let del = fx.service.delete_item_as_operator(&fx.ctx, id);
        let sweep = async {
            // The sweeper deletes by plain columns, outside the state guard.
            let mut tx = fx.service.store().begin().await.unwrap();
            tx.delete_item(id).await.unwrap();
            tx.commit().await.unwrap();
        };
        let (u, d, ()) = tokio::join!(upd, del, sweep);
        assert!(
            u.is_ok() || matches!(u, Err(CoreError::NotFound | CoreError::Store(_))),
            "{u:?}"
        );
        assert!(d.is_ok() || matches!(d, Err(CoreError::NotFound)), "{d:?}");
        assert!(
            matches!(
                fx.service.store().item(id).await,
                Err(cerberus_store::StoreError::NotFound)
            ),
            "row is gone"
        );
        let mut tx = fx.service.store().begin().await.unwrap();
        assert!(
            !tx.delete_item(id).await.unwrap(),
            "no version rows resurrected either"
        );
        tx.commit().await.unwrap();
    }
}

/// The update of `base` that leaves the secret as it is.
fn keep(base: ItemInput) -> ItemUpdate {
    ItemUpdate {
        payload: PayloadChange::Keep,
        ..ItemUpdate::from(base)
    }
}

fn custom(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

async fn audit_count(fx: &Fx, event_type: &str, item: cerberus_types::ItemId) -> usize {
    let query = AuditQuery {
        event_type: Some(event_type.to_owned()),
        item_id: Some(item),
        limit: 1000,
        ..AuditQuery::default()
    };
    fx.service.audit_query(&fx.ctx, query).await.unwrap().len()
}

/// DEC-INT10-6: an update without a payload changes metadata only.
#[tokio::test]
async fn update_without_payload_keeps_the_ciphertext_and_writes_no_reveal() {
    let fx = Fx::new().await;
    let mut first = input(fx.ws, "Shop admin", login_payload("alice", "fake-pw-keep"));
    first.custom = custom(&[("owner", "team-a")]);
    let id = fx.create(first).await;
    let before = fx.service.store().item_version(id, 1).await.unwrap();
    fx.advance(10);

    let mut next = input(fx.ws, "Shop admin renamed", login_payload("x", "x"));
    next.environment = cerberus_types::Environment::Dev;
    next.tags = vec!["renamed".to_owned()];
    next.custom = custom(&[("owner", "team-b"), ("region", "eu")]);
    let detail = fx
        .service
        .update_item(&fx.ctx, id, keep(next))
        .await
        .unwrap();

    assert_eq!(detail.version, 1, "no new version");
    assert_eq!(detail.summary.title, "Shop admin renamed");
    assert_eq!(detail.summary.environment, cerberus_types::Environment::Dev);
    assert_eq!(detail.summary.tags, ["renamed"]);
    assert_eq!(
        detail.summary.custom,
        custom(&[("owner", "team-b"), ("region", "eu")])
    );
    assert_eq!(detail.summary.updated_at, fx.now());
    let after = fx.service.store().item_version(id, 1).await.unwrap();
    assert_eq!(after.payload_ct, before.payload_ct, "same ciphertext bytes");
    assert_eq!(after.wrapped_dek, before.wrapped_dek);
    let read = fx.service.read_payload(id, false).await.unwrap();
    assert_eq!(password_of(&read.payload), "fake-pw-keep");
    assert_eq!(audit_count(&fx, "item.reveal", id).await, 0, "no reveal");
    assert_eq!(audit_count(&fx, "item.update", id).await, 1);

    // The history shows the new title for the current version.
    let versions = fx.service.item_versions(&fx.ctx, id).await.unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].title, "Shop admin renamed");

    // The sealed blobs open again after a lock and an unlock.
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    let owner = fx.service.list_operators().await.unwrap().remove(0);
    let ctx = fx
        .service
        .unlock_with_phrase(owner.id, phrase(super::fixture::OWNER_PHRASE))
        .await
        .unwrap();
    let again = fx.service.get_item(&ctx, id).await.unwrap();
    assert_eq!(again.summary.custom, detail.summary.custom);
    assert_eq!(again.version, 1);
}

#[tokio::test]
async fn update_with_payload_replaces_the_secret_and_the_custom_map() {
    let fx = Fx::new().await;
    let mut first = input(fx.ws, "Shop admin", login_payload("alice", "fake-pw-1"));
    first.custom = custom(&[("owner", "team-a")]);
    let id = fx.create(first).await;
    let before = fx.service.store().item_version(id, 1).await.unwrap();

    let mut next = input(fx.ws, "Shop admin", login_payload("alice", "fake-pw-2"));
    next.custom = custom(&[("region", "eu")]);
    let detail = fx.service.update_item(&fx.ctx, id, next).await.unwrap();

    assert_eq!(detail.version, 2);
    assert_eq!(detail.summary.custom, custom(&[("region", "eu")]));
    let after = fx.service.store().item_version(id, 2).await.unwrap();
    assert_ne!(after.payload_ct, before.payload_ct);
    let read = fx.service.read_payload(id, false).await.unwrap();
    assert_eq!(password_of(&read.payload), "fake-pw-2");
    assert_eq!(audit_count(&fx, "item.update", id).await, 1);
    let listed = fx
        .service
        .list_items(&fx.ctx, ItemFilter::default())
        .await
        .unwrap();
    assert_eq!(listed[0].custom, custom(&[("region", "eu")]));
}

#[tokio::test]
async fn keep_payload_rules() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Seeded",
            totp_login_payload("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
        ))
        .await;
    let other = fx
        .create(input(fx.ws, "Other", login_payload("a", "p")))
        .await;

    // The TOTP flag comes from the stored payload.
    let kept = fx
        .service
        .update_item(
            &fx.ctx,
            id,
            keep(input(fx.ws, "Seeded", login_payload("a", "p"))),
        )
        .await
        .unwrap();
    assert!(kept.summary.has_totp);

    // The metadata rules still hold.
    let clash = fx
        .service
        .update_item(
            &fx.ctx,
            other,
            keep(input(fx.ws, "Seeded", login_payload("a", "p"))),
        )
        .await;
    assert!(matches!(clash, Err(CoreError::Conflict)));
    let mut bad = input(fx.ws, "Other", login_payload("a", "p"));
    bad.custom = custom(&[("Bad Name", "x")]);
    assert!(matches!(
        fx.service.update_item(&fx.ctx, other, keep(bad)).await,
        Err(CoreError::Validation(_))
    ));
    let missing = fx
        .service
        .update_item(
            &fx.ctx,
            cerberus_types::ItemId::generate(),
            keep(input(fx.ws, "Z", login_payload("a", "p"))),
        )
        .await;
    assert!(matches!(missing, Err(CoreError::NotFound)));

    // SSH facts in `custom` are checked for the kind of the stored item.
    let ssh = fx
        .create(input(
            fx.ws,
            "Build box",
            generate_ed25519("fake-comment").unwrap(),
        ))
        .await;
    let mut port = input(fx.ws, "Build box", login_payload("a", "p"));
    port.custom = custom(&[("port", "not-a-number")]);
    assert!(matches!(
        fx.service.update_item(&fx.ctx, ssh, keep(port)).await,
        Err(CoreError::Validation(_))
    ));
    let mut good = input(fx.ws, "Build box", login_payload("a", "p"));
    good.custom = custom(&[("host", "build.example.test"), ("port", "2222")]);
    let detail = fx
        .service
        .update_item(&fx.ctx, ssh, keep(good))
        .await
        .unwrap();
    assert_eq!(
        detail.summary.custom.get("port").map(String::as_str),
        Some("2222")
    );
    let revealed = fx.service.read_payload(ssh, false).await.unwrap();
    assert_eq!(revealed.ssh.and_then(|s| s.port), Some(2222));
}

#[tokio::test]
async fn keep_payload_needs_the_operator_role() {
    let fx = Fx::new().await;
    fx.service
        .add_operator(
            &fx.ctx,
            "Viewer".into(),
            OperatorRole::Viewer,
            phrase(VIEWER_PHRASE),
        )
        .await
        .unwrap();
    let id = fx.create(input(fx.ws, "T", login_payload("a", "p"))).await;
    fx.service
        .lock(cerberus_types::LockReason::Manual)
        .await
        .unwrap();
    let viewer = fx
        .service
        .list_operators()
        .await
        .unwrap()
        .into_iter()
        .find(|o| o.role == OperatorRole::Viewer)
        .unwrap();
    let ctx = fx
        .service
        .unlock_with_phrase(viewer.id, phrase(VIEWER_PHRASE))
        .await
        .unwrap();
    let denied = fx
        .service
        .update_item(&ctx, id, keep(input(fx.ws, "T2", login_payload("a", "p"))))
        .await;
    assert!(matches!(denied, Err(CoreError::RoleNotAllowed)));
}
