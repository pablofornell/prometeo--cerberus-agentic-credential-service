//! The audit of refused token checks (`auth.failed`).

use std::net::{IpAddr, Ipv4Addr};

use cerberus_types::{LockReason, RequestId};

use super::fixture::*;
use crate::admin::AuditQuery;
use crate::audit::AuditEvent;
use crate::auth::{AuthFailure, Refusal};
use crate::context::{OperatorContext, Surface};
use crate::vault::KeyCustody;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

async fn auth_failed(fixture: &Fixture, ctx: &OperatorContext) -> Vec<AuditEvent> {
    let mut rows = fixture
        .service
        .audit_query(
            ctx,
            AuditQuery {
                limit: 100,
                event_type: Some("auth.failed".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    rows.reverse();
    rows.into_iter().map(|e| e.event).collect()
}

#[tokio::test]
async fn unlocked_failures_write_one_event_per_minute_with_the_count() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    for _ in 0..3 {
        service
            .audit_auth_failure(
                IP,
                AuthFailure::NoKeyMatch,
                RequestId::generate(),
                Surface::Rest,
            )
            .await;
    }
    fixture.advance(61);
    // Same class (a guess), so it carries the count. A failure of a real key has its own (NEW-8).
    service
        .audit_auth_failure(
            IP,
            AuthFailure::UnknownAgent,
            RequestId::generate(),
            Surface::Mcp,
        )
        .await;
    let events = auth_failed(&fixture, &ctx).await;
    assert_eq!(
        events.len(),
        2,
        "the two failures inside the window are only counted"
    );
    let detail = |event: &AuditEvent, key: &str| event.details.get(key).cloned();
    assert_eq!(detail(&events[0], "reason"), Some("no_key_match".into()));
    assert_eq!(detail(&events[0], "surface"), Some("rest".into()));
    assert_eq!(detail(&events[0], "source_ip"), Some("10.0.0.7".into()));
    assert_eq!(detail(&events[0], "suppressed_before"), Some(0.into()));
    assert_eq!(detail(&events[1], "reason"), Some("unknown_agent".into()));
    assert_eq!(detail(&events[1], "surface"), Some("mcp".into()));
    assert_eq!(detail(&events[1], "suppressed_before"), Some(2.into()));
}

#[tokio::test]
async fn failures_while_locked_join_the_chain_at_the_next_unlock() {
    let (fixture, created, _ctx) = Fixture::created().await;
    let service = &fixture.service;
    service.lock(LockReason::Manual).await.unwrap();
    service
        .audit_auth_failure(
            IP,
            AuthFailure::Malformed,
            RequestId::generate(),
            Surface::Rest,
        )
        .await;
    let ctx = service
        .unlock_with_phrase(created.owner_id, phrase(OWNER_PHRASE))
        .await
        .unwrap();
    let events = auth_failed(&fixture, &ctx).await;
    assert_eq!(events.len(), 1);
    let expected = AuthFailure::Malformed.outward().code();
    assert_eq!(events[0].result, expected.as_str());
}

/// NEW-8: a local user keeps the lockout on with bad tokens from many loopback addresses and then
/// tries a stolen revoked token. The flood writes one event (loopback is one source), and the
/// revoked token still writes its own event with the reason `key_revoked`, the result of the
/// lockout and `limit = locked_out`.
#[tokio::test]
async fn new8_a_revoked_token_during_a_lockout_flood_is_recorded() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let locked = AuthFailure::LockedOut {
        retry_after_seconds: 300,
    };
    for n in 1..=200_u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, n / 16, n % 16 + 1));
        let failure = if n < 10 {
            Refusal::from(AuthFailure::NoKeyMatch)
        } else {
            Refusal {
                failure: locked,
                cause: AuthFailure::NoKeyMatch,
            }
        };
        service
            .audit_auth_failure(ip, failure, RequestId::generate(), Surface::Rest)
            .await;
    }
    service
        .audit_auth_failure(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 77)),
            Refusal {
                failure: locked,
                cause: AuthFailure::KeyRevoked,
            },
            RequestId::generate(),
            Surface::Mcp,
        )
        .await;
    let events = auth_failed(&fixture, &ctx).await;
    assert_eq!(
        events.len(),
        2,
        "one for the flood, one for the revoked key"
    );
    let detail = |event: &AuditEvent, key: &str| event.details.get(key).cloned();
    assert_eq!(detail(&events[0], "reason"), Some("no_key_match".into()));
    assert_eq!(detail(&events[0], "limit"), None);
    assert_eq!(detail(&events[1], "reason"), Some("key_revoked".into()));
    assert_eq!(detail(&events[1], "limit"), Some("locked_out".into()));
    assert_eq!(events[1].result, locked.outward().code().as_str());
    assert_eq!(detail(&events[1], "source_ip"), Some("127.0.0.77".into()));
    // The next minute the flood's count is in the next event of the loopback source.
    fixture.advance(61);
    service
        .audit_auth_failure(
            IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3)),
            Refusal {
                failure: locked,
                cause: AuthFailure::Malformed,
            },
            RequestId::generate(),
            Surface::Rest,
        )
        .await;
    let events = auth_failed(&fixture, &ctx).await;
    assert_eq!(events.len(), 3);
    assert_eq!(detail(&events[2], "suppressed_before"), Some(199.into()));
    assert_eq!(detail(&events[2], "suppressed_other"), Some(0.into()));
}

/// NEW-8: failures from more sources than the global cap allows write at most
/// `GLOBAL_PER_WINDOW` rows a minute; the next row carries the count of the rest.
#[tokio::test]
async fn new8_failures_from_many_sources_write_a_bounded_number_of_rows() {
    let (fixture, _created, ctx) = Fixture::created().await;
    let service = &fixture.service;
    let cap = crate::vault::authlog::GLOBAL_PER_WINDOW;
    let sources = 300_u32;
    for n in 0..sources {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
        service
            .audit_auth_failure(
                ip,
                AuthFailure::NoKeyMatch,
                RequestId::generate(),
                Surface::Rest,
            )
            .await;
    }
    let events = auth_failed(&fixture, &ctx).await;
    assert_eq!(events.len(), usize::try_from(cap).unwrap());
    fixture.advance(61);
    service
        .audit_auth_failure(
            IP,
            AuthFailure::NoKeyMatch,
            RequestId::generate(),
            Surface::Rest,
        )
        .await;
    let events = auth_failed(&fixture, &ctx).await;
    let last = events.last().unwrap();
    assert_eq!(
        last.details.get("suppressed_other").cloned(),
        Some((sources - cap).into())
    );
}
