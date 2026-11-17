//! Regression tests for the T05/T09 security review (DEC-FIX5-*). All values are fake.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use cerberus_store::{OpenOptions, Store};
use cerberus_types::{LockReason, OperatorRole, VaultId, VaultStateKind};
use jiff::Timestamp;

use super::fixture::*;
use crate::audit::Actor;
use crate::error::CoreError;
use crate::vault::{
    CaIssuer, CoreConfig, CoreEvent, IssuedCa, KeyCustody, NewVault, OsEvent, OsEventSink,
    VaultService,
};

/// Waits until the vault is sealed, at most 5 s.
async fn wait_sealed(service: &VaultService) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.state() != VaultStateKind::Sealed {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok()
}

/// The audit chain as JSON lines. The vault must be unlocked.
async fn chain_lines(service: &VaultService) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    {
        let guard = service.unlocked().await.unwrap();
        guard
            .audit
            .export_jsonl(Actor::system(), &mut out)
            .await
            .unwrap();
    }
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn types_of(lines: &[serde_json::Value]) -> Vec<String> {
    lines
        .iter()
        .map(|line| line["body"]["type"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// Finding 5: an edited `key_slots.role` must not give owner rights, and a slot change must not
/// re-sign (and so hide) a header that fails its MAC.
#[tokio::test]
async fn tampered_slot_role_gives_viewer_rights_and_is_not_laundered() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let viewer = service
        .add_operator(
            &ctx,
            "Viewer".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE key_slots SET role = 'owner' WHERE id = ?1")
        .bind(viewer.to_string())
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    let vctx = service
        .unlock_with_phrase(viewer, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    assert!(!service.status().await.header_ok);
    assert_eq!(vctx.role, OperatorRole::Viewer, "no more than viewer");
    let session = service.status().await.session.unwrap();
    assert_eq!(session.role, OperatorRole::Viewer);
    let add = service
        .add_operator(
            &vctx,
            "Third".to_owned(),
            OperatorRole::Owner,
            phrase(NEW_PHRASE),
        )
        .await;
    assert!(matches!(add, Err(CoreError::RoleNotAllowed)), "{add:?}");
    // A viewer may change its own phrase, but not on a header that fails its MAC.
    let change = service
        .change_phrase(&vctx, phrase(SECOND_PHRASE), phrase(NEW_PHRASE))
        .await;
    assert!(matches!(change, Err(CoreError::Corrupt)), "{change:?}");
    service.lock(LockReason::Manual).await.unwrap();
    service
        .unlock_with_phrase(viewer, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    assert!(!service.status().await.header_ok, "evidence is kept");
}

/// Finding 5: a slot edit while unlocked is caught by the next slot change, which refuses.
#[tokio::test]
async fn slot_change_refuses_a_header_edited_while_unlocked() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let viewer = service
        .add_operator(
            &ctx,
            "Viewer".to_owned(),
            OperatorRole::Viewer,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE key_slots SET role = 'owner' WHERE id = ?1")
        .bind(viewer.to_string())
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    let add = service
        .add_operator(
            &ctx,
            "Third".to_owned(),
            OperatorRole::Viewer,
            phrase(NEW_PHRASE),
        )
        .await;
    assert!(matches!(add, Err(CoreError::Corrupt)), "{add:?}");
    service.lock(LockReason::Manual).await.unwrap();
    service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert!(!service.status().await.header_ok);
}

/// Finding 1: an OS event from a thread without a runtime, while a call holds the state, runs
/// the full lock once the call ends: keys gone, `StateChanged`, `vault.lock` in the chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn os_event_off_runtime_runs_the_full_lock() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = fixture.service.clone();
    let keys = {
        let guard = service.unlocked().await.unwrap();
        Arc::downgrade(&guard.keys)
    };
    let mut events = service.subscribe();
    let sink = service.os_event_sink();
    {
        let _held = service.unlocked().await.unwrap();
        std::thread::spawn(move || sink.send(OsEvent::ScreenLocked))
            .join()
            .unwrap();
        assert_eq!(service.state(), VaultStateKind::Locking);
    }
    assert!(wait_sealed(&service).await, "the lock did not finish");
    assert!(keys.upgrade().is_none(), "keys dropped");
    let mut changed = false;
    while let Ok(event) = events.try_recv() {
        changed |= matches!(event, CoreEvent::StateChanged(VaultStateKind::Sealed));
    }
    assert!(changed, "StateChanged(Sealed) sent");
    service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let lines = chain_lines(&service).await;
    assert!(
        lines
            .iter()
            .any(|l| l["body"]["type"] == "vault.lock"
                && l["body"]["details"]["reason"] == "os_lock"),
        "vault.lock with reason os_lock"
    );
}

/// Finding 6: a lock whose caller is cancelled still finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_lock_still_finishes() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let service = fixture.service.clone();
    let keys = {
        let guard = service.unlocked().await.unwrap();
        Arc::downgrade(&guard.keys)
    };
    {
        let _held = service.unlocked().await.unwrap();
        let r =
            tokio::time::timeout(Duration::from_millis(50), service.lock(LockReason::Quit)).await;
        assert!(r.is_err(), "the caller gave up");
    }
    assert!(wait_sealed(&service).await, "the lock did not finish");
    assert!(keys.upgrade().is_none(), "keys dropped");
}

/// Finding 1: the idle loop finishes a lock that is stuck at `Locking`.
#[tokio::test]
async fn auto_lock_loop_finishes_a_pending_lock() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    assert!(service.begin_lock(LockReason::OsLock));
    assert_eq!(service.state(), VaultStateKind::Locking);
    assert_eq!(
        service.run_auto_lock_once(fixture.clock_now()).await,
        Some(LockReason::OsLock)
    );
    assert_eq!(service.state(), VaultStateKind::Sealed);
}

/// Finding 6: turning `lock_on_os_lock` off right after an OS event does not leave the vault at
/// `Locking`.
#[tokio::test]
async fn os_setting_flip_after_the_event_still_locks() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    service.on_os_event(OsEvent::Sleep);
    let mut settings = service.inner.lock_settings.get();
    settings.lock_on_os_lock = false;
    service.inner.lock_settings.set(settings);
    assert!(wait_sealed(service).await, "stuck at {:?}", service.state());
}

/// Finding 7: a panic during a pending lock takes it over and revokes the leases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_during_a_pending_lock_revokes_leases() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = fixture.service.clone();
    let item = fixture.add_item("Leased").await;
    let (lease, _) = fixture.add_lease_and_request(item).await;
    let held = service.unlocked().await.unwrap();
    let s2 = service.clone();
    let lock = tokio::spawn(async move { s2.lock(LockReason::Idle).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(service.state(), VaultStateKind::Locking);
    let s3 = service.clone();
    let panic_ctx = ctx.clone();
    let panic = tokio::spawn(async move { s3.panic_lock(&panic_ctx).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(held);
    lock.await.unwrap().unwrap();
    let p = panic.await.unwrap();
    assert!(p.is_ok(), "{p:?}");
    assert_eq!(service.state(), VaultStateKind::Sealed);
    let row = service.store().lease(lease).await.unwrap();
    assert!(row.revoked_at.is_some(), "lease revoked");
}

/// A CA issuer that sends a screen lock while the vault is being made.
#[derive(Debug, Default)]
struct LockingCa(OnceLock<OsEventSink>);

impl CaIssuer for LockingCa {
    fn issue_ca(&self, vault_id: &VaultId, now: Timestamp) -> Result<IssuedCa, CoreError> {
        if let Some(sink) = self.0.get() {
            sink.send(OsEvent::ScreenLocked);
        }
        FakeCa.issue_ca(vault_id, now)
    }
}

/// Finding 8: a screen lock during create leaves the new vault sealed. The recovery key is still
/// returned, so it is not lost.
#[tokio::test]
async fn screen_lock_during_create_leaves_the_vault_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let clock = cerberus_types::ManualClock::new(cerberus_types::t0());
    let store = Store::open(
        OpenOptions {
            path: dir.path().join("vault.cerberus"),
            create: true,
        },
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    let ca = Arc::new(LockingCa::default());
    let config = CoreConfig::desktop(dir.path().to_path_buf(), ca.clone());
    let service = VaultService::open(store, Arc::new(clock), config)
        .await
        .unwrap();
    ca.0.set(service.os_event_sink()).unwrap();
    let created = service
        .create_vault(NewVault {
            owner_label: "Owner".to_owned(),
            phrase: phrase(OWNER_PHRASE),
            kdf: kdf(),
            host_names: Vec::new(),
        })
        .await
        .unwrap();
    assert!(!created.recovery_key.expose_secret().is_empty());
    assert_eq!(service.state(), VaultStateKind::Sealed);
    assert!(matches!(service.unlocked().await, Err(CoreError::Locked)));
    service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert_eq!(service.state(), VaultStateKind::Unlocked);
}

/// Review (b): a sealed item that fails to open is written to the chain, not only to the UI.
#[tokio::test]
async fn bad_item_blob_is_written_to_the_chain() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let item = fixture.add_item("Will break").await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let raw = fixture.raw().await;
    sqlx::query("UPDATE items SET meta_ct = X'00112233445566778899' WHERE id = ?1")
        .bind(item.to_string())
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    fixture
        .service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let lines = chain_lines(&fixture.service).await;
    let hits: Vec<_> = lines
        .iter()
        .filter(|l| {
            l["body"]["type"] == "integrity.row_mac_mismatch"
                && l["body"]["target"]["kind"] == "items"
        })
        .collect();
    assert_eq!(hits.len(), 1, "{:?}", types_of(&lines));
    assert_eq!(
        hits[0]["body"]["target"]["id"].as_str().unwrap(),
        item.to_string()
    );
}

/// Review (a): events recorded while locked join the chain before the unlock's integrity events.
#[tokio::test]
async fn pending_events_come_before_unlock_integrity_events() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let item = fixture.add_item("For agent").await;
    fixture.add_lease_and_request(item).await;
    fixture.service.lock(LockReason::Manual).await.unwrap();
    let wrong = fixture
        .service
        .unlock_with_phrase(created.owner_id, phrase(WRONG_PHRASE))
        .await;
    assert!(matches!(wrong, Err(CoreError::BadCredentials)));
    let raw = fixture.raw().await;
    sqlx::query("UPDATE agents SET created_at = created_at + 1")
        .execute(&raw)
        .await
        .unwrap();
    raw.close().await;
    fixture
        .service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let types = types_of(&chain_lines(&fixture.service).await);
    let failed = types.iter().position(|t| t == "vault.unlock_failed");
    let integrity = types.iter().position(|t| t == "integrity.row_mac_mismatch");
    assert!(
        failed.is_some() && integrity.is_some() && failed < integrity,
        "{types:?}"
    );
}

fn agent_input() -> crate::agents::AgentInput {
    crate::agents::AgentInput {
        name: "Build bot".to_owned(),
        description: "fake test agent".to_owned(),
    }
}

fn forever_key() -> crate::agents::AgentKeyInput {
    crate::agents::AgentKeyInput {
        scopes: Vec::new(),
        lifetime_days: None,
        ip_allowlist: Vec::new(),
        require_mtls: false,
    }
}

/// Finding 4: agent calls check the context against the session and use the session role.
#[tokio::test]
async fn agent_calls_use_the_session_not_the_context() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    // A context of no session, claiming owner.
    let forged = ctx_for(cerberus_types::OperatorId::generate(), OperatorRole::Owner);
    let r = service
        .create_agent(&forged, agent_input(), forever_key())
        .await;
    assert!(matches!(r, Err(CoreError::Forbidden)), "{r:?}");
    // An operator session whose context claims owner cannot make a key without expiry.
    let operator = service
        .add_operator(
            &ctx,
            "Operator".to_owned(),
            OperatorRole::Operator,
            phrase(SECOND_PHRASE),
        )
        .await
        .unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    service
        .unlock_with_phrase(operator, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    let claims_owner = ctx_for(operator, OperatorRole::Owner);
    let r = service
        .create_agent(&claims_owner, agent_input(), forever_key())
        .await;
    assert!(matches!(r, Err(CoreError::RoleNotAllowed)), "{r:?}");
    // The owner can, and the change is audited.
    service.lock(LockReason::Manual).await.unwrap();
    let owner = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let (view, key) = service
        .create_agent(&owner, agent_input(), forever_key())
        .await
        .unwrap();
    service.revoke_agent_key(&owner, key.key.id).await.unwrap();
    let types = types_of(&chain_lines(service).await);
    assert!(types.iter().any(|t| t == "agent.create"), "{types:?}");
    assert!(types.iter().any(|t| t == "agent_key.revoke"), "{types:?}");
    assert_eq!(service.list_agents(&owner).await.unwrap()[0].id, view.id);
}

/// Finding 7: a panic whose lease revoke failed is finished at the next unlock, also after a
/// restart (sealed setting).
#[tokio::test]
async fn deferred_panic_revoke_runs_at_the_next_unlock() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let item = fixture.add_item("Leased").await;
    let (lease, _) = fixture.add_lease_and_request(item).await;
    {
        let guard = fixture.service.unlocked().await.unwrap();
        fixture
            .service
            .defer_panic_revoke(&guard, created.owner_id)
            .await;
    }
    fixture.service.lock(LockReason::Manual).await.unwrap();
    assert!(
        fixture
            .service
            .store()
            .lease(lease)
            .await
            .unwrap()
            .revoked_at
            .is_none()
    );
    // A restart loses the in-memory flag; the sealed setting is still there.
    let restarted = fixture.reopen().await;
    restarted
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let row = restarted.store().lease(lease).await.unwrap();
    assert!(row.revoked_at.is_some(), "lease revoked at unlock");
    let types = types_of(&chain_lines(&restarted).await);
    assert!(types.iter().any(|t| t == "vault.panic"), "{types:?}");
    // Done once: the next unlock has nothing to do.
    restarted.lock(LockReason::Manual).await.unwrap();
    restarted
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let panics = types_of(&chain_lines(&restarted).await)
        .iter()
        .filter(|t| *t == "vault.panic")
        .count();
    assert_eq!(panics, 1);
}
