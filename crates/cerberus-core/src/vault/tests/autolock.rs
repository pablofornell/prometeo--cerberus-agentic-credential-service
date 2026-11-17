//! Idle lock, hard lock, agent activity and OS events, all on the manual clock.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use cerberus_types::{AgentId, AgentKeyId, LockReason, OperatorRole, RequestId, VaultStateKind};

use super::fixture::*;
use crate::context::{AgentContext, Surface};
use crate::error::CoreError;
use crate::vault::{CoreEvent, KeyCustody, LockSettings, OsEvent, OsEventSink, OsLockEvents};

fn agent_ctx() -> AgentContext {
    AgentContext {
        agent_id: AgentId::generate(),
        key_id: AgentKeyId::generate(),
        scopes: BTreeSet::new(),
        request_id: RequestId::generate(),
        source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        surface: Surface::Rest,
    }
}

#[tokio::test]
async fn idle_lock_fires_after_30_minutes_without_activity() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    fixture.advance(1_799);
    assert_eq!(service.run_auto_lock_once(fixture.clock_now()).await, None);
    assert_eq!(service.status().await.idle_seconds_left, Some(1));
    service.note_operator_activity();
    fixture.advance(1_000);
    assert_eq!(service.run_auto_lock_once(fixture.clock_now()).await, None);
    fixture.advance(800);
    assert_eq!(
        service.run_auto_lock_once(fixture.clock_now()).await,
        Some(LockReason::Idle)
    );
    assert_eq!(service.state(), VaultStateKind::Sealed);
}

#[tokio::test]
async fn agent_calls_count_as_activity_only_when_the_setting_is_on() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let agent = agent_ctx();
    fixture.advance(1_700);
    service.note_agent_activity(&agent);
    fixture.advance(1_700);
    assert_eq!(service.run_auto_lock_once(fixture.clock_now()).await, None);

    let off = LockSettings {
        agent_activity_keeps_unlocked: false,
        ..LockSettings::defaults(&config())
    };
    service.set_lock_settings(&ctx, off).await.unwrap();
    fixture.advance(60);
    service.note_agent_activity(&agent);
    fixture.advance(1_700);
    assert_eq!(
        service.run_auto_lock_once(fixture.clock_now()).await,
        Some(LockReason::Idle)
    );
}

#[tokio::test]
async fn hard_lock_fires_after_12_hours_even_with_activity() {
    let (fixture, _created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    let agent = agent_ctx();
    for _ in 0..(12 * 60 / 20) - 1 {
        fixture.advance(20 * 60);
        service.note_agent_activity(&agent);
        assert_eq!(service.run_auto_lock_once(fixture.clock_now()).await, None);
    }
    let status = service.status().await;
    assert!(status.hard_lock_at.is_some());
    fixture.advance(20 * 60);
    service.note_agent_activity(&agent);
    assert_eq!(
        service.run_auto_lock_once(fixture.clock_now()).await,
        Some(LockReason::MaxUnlocked)
    );
    assert_eq!(service.state(), VaultStateKind::Sealed);
}

#[tokio::test]
async fn settings_persist_and_are_checked() {
    let (fixture, created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let bad = LockSettings {
        idle_lock_seconds: Some(10),
        max_unlocked_seconds: Some(100),
        ..LockSettings::defaults(&config())
    };
    let Err(CoreError::Validation(problems)) = service.set_lock_settings(&ctx, bad).await else {
        panic!("out-of-range settings were accepted");
    };
    assert_eq!(problems.len(), 2);
    let off = LockSettings {
        idle_lock_seconds: None,
        max_unlocked_seconds: None,
        lock_on_os_lock: false,
        agent_activity_keeps_unlocked: false,
    };
    service.set_lock_settings(&ctx, off).await.unwrap();
    service.lock(LockReason::Manual).await.unwrap();
    let restarted = fixture.reopen().await;
    let ctx = restarted
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert_eq!(restarted.lock_settings(&ctx).await.unwrap(), off);
    fixture.advance(30 * 86_400);
    assert_eq!(
        restarted.run_auto_lock_once(fixture.clock_now()).await,
        None
    );
    assert!(!restarted.handle_os_event(OsEvent::Sleep).await);
    assert_eq!(restarted.state(), VaultStateKind::Unlocked);
}

#[tokio::test]
async fn os_events_lock_through_the_sink() {
    #[derive(Default)]
    struct Hook(std::sync::Mutex<Option<OsEventSink>>);
    impl OsLockEvents for Hook {
        fn start(&self, sink: OsEventSink) -> bool {
            *self.0.lock().unwrap() = Some(sink);
            true
        }
    }

    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    let hook = Hook::default();
    assert!(service.attach_os_events(&hook));
    assert!(service.status().await.os_hook_ok);
    let sink = hook.0.lock().unwrap().clone().unwrap();
    let mut events = service.subscribe();
    sink.send(OsEvent::ScreenLocked);
    // New calls are refused at once, before the lock task runs.
    assert_ne!(service.state(), VaultStateKind::Unlocked);
    assert!(matches!(service.unlocked().await, Err(CoreError::Locked)));
    let sealed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(CoreEvent::StateChanged(VaultStateKind::Sealed)) = events.recv().await {
                break;
            }
        }
    })
    .await;
    assert!(sealed.is_ok(), "the lock task did not run");
    assert_eq!(service.state(), VaultStateKind::Sealed);

    let _ctx = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    assert!(service.handle_os_event(OsEvent::Sleep).await);
    assert_eq!(service.state(), VaultStateKind::Sealed);
}

#[tokio::test]
async fn lock_settings_need_operator_role() {
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
    let viewer_ctx = service
        .unlock_with_phrase(viewer, phrase(SECOND_PHRASE))
        .await
        .unwrap();
    assert!(service.lock_settings(&viewer_ctx).await.is_ok());
    assert!(matches!(
        service
            .set_lock_settings(&viewer_ctx, LockSettings::defaults(&config()))
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
}
