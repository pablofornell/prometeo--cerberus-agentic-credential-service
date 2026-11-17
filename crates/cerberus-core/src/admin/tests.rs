//! Tests of the operator calls: workspaces, roles from the session, settings, audit, backup and
//! the operator reveal. Fake values only.

use cerberus_crypto::SecretString;
use cerberus_types::{Environment, GrantMode, OperatorRole, Permission};

use super::{AuditOutcome, AuditQuery, WorkspaceInput};
use crate::agent_api::tests::{Fx, all_scopes, login};
use crate::audit::ChainReport;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::items::Payload;
use crate::vault::KeyCustody;

const VIEWER_PHRASE: &str = "lantern quartz meadow ripple 3";

fn ws_input(slug: &str, aliases: &[&str]) -> WorkspaceInput {
    WorkspaceInput {
        slug: slug.to_owned(),
        name: format!("{slug} name"),
        description: "fake workspace".to_owned(),
        aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
    }
}

/// Adds a viewer, locks, and unlocks as that viewer.
async fn viewer_session(fx: &Fx) -> OperatorContext {
    let id = fx
        .service
        .add_operator(
            &fx.owner,
            "Viewer".to_owned(),
            OperatorRole::Viewer,
            SecretString::new(VIEWER_PHRASE.to_owned()),
        )
        .await
        .unwrap();
    fx.lock().await;
    fx.service
        .unlock_with_phrase(id, SecretString::new(VIEWER_PHRASE.to_owned()))
        .await
        .unwrap()
}

#[tokio::test]
async fn workspace_create_update_delete() {
    let fx = Fx::new().await;
    let shop = fx
        .service
        .put_workspace(&fx.owner, None, ws_input("shop-frontend", &["shop"]))
        .await
        .unwrap();
    assert_eq!((shop.slug.as_str(), shop.item_count), ("shop-frontend", 0));
    assert!(
        matches!(
            fx.service
                .put_workspace(&fx.owner, None, ws_input("other", &["Shop"]))
                .await,
            Err(CoreError::Conflict)
        ),
        "an alias of another workspace is taken (normalized)"
    );
    assert!(matches!(
        fx.service
            .put_workspace(&fx.owner, None, ws_input("Bad Slug", &[]))
            .await,
        Err(CoreError::Validation(_))
    ));
    let renamed = fx
        .service
        .put_workspace(
            &fx.owner,
            Some(shop.id),
            ws_input("shop-frontend", &["shop", "web"]),
        )
        .await
        .unwrap();
    assert_eq!(renamed.aliases, ["shop", "web"]);
    fx.item(login(
        shop.id,
        "Staging admin",
        Environment::Staging,
        "u",
        "zq-fake-ws",
    ))
    .await;
    assert!(
        matches!(
            fx.service.delete_workspace(&fx.owner, shop.id).await,
            Err(CoreError::Conflict)
        ),
        "a workspace with items is not deleted"
    );
    let empty = fx
        .service
        .put_workspace(&fx.owner, None, ws_input("empty", &[]))
        .await
        .unwrap();
    fx.service
        .delete_workspace(&fx.owner, empty.id)
        .await
        .unwrap();
    let list = fx.service.list_workspaces(&fx.owner).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].item_count, 1);
    let types = fx.audit_types().await;
    for wanted in ["workspace.create", "workspace.update", "workspace.delete"] {
        assert!(types.contains(&wanted.to_owned()), "{wanted}");
    }
}

#[tokio::test]
async fn roles_come_from_the_session() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let id = fx
        .item(login(
            ws,
            "Staging admin",
            Environment::Staging,
            "u",
            "zq-fake-role",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let mut viewer = viewer_session(&fx).await;
    // A context that claims a higher role still has the session role.
    viewer.role = OperatorRole::Owner;
    assert!(matches!(
        fx.service
            .put_workspace(&viewer, None, ws_input("x", &[]))
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        fx.service.reveal_item(&viewer, id).await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        fx.service
            .backup_create(&viewer, &fx.dir.path().join("b1"))
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        fx.service.authorize_restore(Some(&viewer)).await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        fx.service.authorize_restore(None).await,
        Err(CoreError::Forbidden)
    ));
    // ADR-0009: a viewer may browse, verify the chain, and revoke leases.
    assert_eq!(fx.service.list_workspaces(&viewer).await.unwrap().len(), 1);
    assert!(matches!(
        fx.service.audit_verify(&viewer).await.unwrap(),
        ChainReport::Ok { .. }
    ));
    assert_eq!(fx.service.revoke_all_leases(&viewer).await.unwrap(), 0);
    // The old owner context is not this session.
    assert!(matches!(
        fx.service.list_workspaces(&fx.owner).await,
        Err(CoreError::Forbidden)
    ));
}

#[tokio::test]
async fn settings_view_and_single_key_changes() {
    let fx = Fx::new().await;
    let view = fx.service.settings_get(&fx.owner).await.unwrap();
    for key in [
        "idle_lock_seconds",
        "session_ttl_max_seconds",
        "approval_timeout_seconds",
        "lease_ttl_auto_seconds",
    ] {
        assert!(view.values.contains_key(key), "{key}");
    }
    assert!(
        !view.values.contains_key("session_approval_max_seconds"),
        "one source of truth"
    );
    let view = fx
        .service
        .settings_set(
            &fx.owner,
            "session_ttl_max_seconds",
            serde_json::json!(7200),
        )
        .await
        .unwrap();
    assert_eq!(
        view.values["session_ttl_max_seconds"],
        serde_json::json!(7200)
    );
    let view = fx
        .service
        .settings_set(&fx.owner, "idle_lock_seconds", serde_json::Value::Null)
        .await
        .unwrap();
    assert!(view.values["idle_lock_seconds"].is_null());
    let view = fx
        .service
        .settings_set(&fx.owner, "approval_timeout_seconds", serde_json::json!(60))
        .await
        .unwrap();
    assert_eq!(
        view.values["approval_timeout_seconds"],
        serde_json::json!(60)
    );
    for (key, value) in [
        ("no_such_key", serde_json::json!(1)),
        ("approval_timeout_seconds", serde_json::json!(5)),
        ("lock_on_os_lock", serde_json::json!("yes")),
    ] {
        assert!(
            matches!(
                fx.service.settings_set(&fx.owner, key, value).await,
                Err(CoreError::Validation(_))
            ),
            "{key}"
        );
    }
}

#[tokio::test]
async fn operator_reveal_totp_audit_and_backup() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let id = fx
        .item(login(
            ws,
            "Staging admin",
            Environment::Staging,
            "u",
            "zq-fake-op",
        ))
        .await;
    let revealed = fx.service.reveal_item(&fx.owner, id).await.unwrap();
    assert!(
        matches!(&revealed.payload, Payload::WebLogin { password, .. }
        if password.expose_secret() == "zq-fake-op")
    );
    assert_eq!(revealed.use_count, 0, "an operator look is not a use");
    assert!(matches!(
        fx.service.totp_preview(&fx.owner, id).await,
        Err(CoreError::NotFound)
    ));
    let reveals = fx
        .service
        .audit_query(
            &fx.owner,
            AuditQuery {
                event_type: Some("item.reveal".to_owned()),
                item_id: Some(id),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(reveals.len(), 1);
    assert_eq!(
        reveals[0].event.actor.id.as_deref(),
        Some(fx.owner.operator_id.to_string().as_str())
    );
    // Newest first and paging by `before_seq`.
    let all = fx
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
    assert!(all.windows(2).all(|w| w[0].seq > w[1].seq));
    let older = fx
        .service
        .audit_query(
            &fx.owner,
            AuditQuery {
                before_seq: Some(all[0].seq),
                limit: 1,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(older[0].seq, all[1].seq);
    assert!(matches!(
        fx.service
            .audit_query(&fx.owner, AuditQuery::default())
            .await,
        Err(CoreError::Validation(_))
    ));
    let dest = fx.dir.path().join("backup.cerberus");
    fx.service.backup_create(&fx.owner, &dest).await.unwrap();
    assert!(dest.exists());
    assert!(
        fx.service.backup_create(&fx.owner, &dest).await.is_err(),
        "no overwrite"
    );
    assert!(fx.audit_types().await.contains(&"backup.create".to_owned()));
    fx.service.record_restore(&fx.owner).await.unwrap();
    assert!(
        fx.audit_types()
            .await
            .contains(&"backup.restore".to_owned())
    );
    let stranger = OperatorContext {
        operator_id: cerberus_types::OperatorId::generate(),
        ..fx.owner.clone()
    };
    assert!(matches!(
        fx.service.record_restore(&stranger).await,
        Err(CoreError::Forbidden)
    ));
    let export = fx.dir.path().join("export.jsonl");
    fx.service.audit_export(&fx.owner, &export).await.unwrap();
    assert!(
        fx.service.audit_export(&fx.owner, &export).await.is_err(),
        "no overwrite"
    );
}

#[tokio::test]
async fn audit_query_filters_by_outcome() {
    let fx = Fx::new().await;
    fx.lock().await;
    let wrong = fx
        .service
        .unlock_with_phrase(
            fx.owner.operator_id,
            SecretString::new("pebble frozen lizard comet 4".to_owned()),
        )
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    fx.unlock().await;
    let query = |outcome| AuditQuery {
        outcome,
        limit: 1000,
        ..AuditQuery::default()
    };
    let all = fx
        .service
        .audit_query(&fx.owner, query(None))
        .await
        .unwrap();
    let failed = fx
        .service
        .audit_query(&fx.owner, query(Some(AuditOutcome::Failed)))
        .await
        .unwrap();
    let ok = fx
        .service
        .audit_query(&fx.owner, query(Some(AuditOutcome::Ok)))
        .await
        .unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].event.event_type, "vault.unlock_failed");
    assert_ne!(failed[0].event.result, "ok");
    assert!(ok.iter().all(|e| e.event.result == "ok"));
    assert_eq!(ok.len() + failed.len(), all.len());
    // The outcome filter works together with the other parts of the filter.
    let none = fx
        .service
        .audit_query(
            &fx.owner,
            AuditQuery {
                event_type: Some("vault.unlock".to_owned()),
                outcome: Some(AuditOutcome::Failed),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert!(none.is_empty());
}
