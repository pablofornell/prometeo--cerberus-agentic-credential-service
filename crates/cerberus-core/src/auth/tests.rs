#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::{IpAddr, Ipv4Addr};

use cerberus_crypto::{Key32, TokenSecret};
use cerberus_types::{Clock, ManualClock, t0};
use jiff::SignedDuration;

use super::*;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct Env {
    table: AuthTable,
    clock: ManualClock,
    agent: AgentRow,
    key: AgentKeyRow,
    token: String,
}

fn agent_row(id: AgentId) -> AgentRow {
    AgentRow {
        id,
        status: AgentStatus::Active,
        created_at: t0(),
        updated_at: t0(),
        meta_ct: Vec::new(),
        row_mac: [0; 32],
    }
}

/// A key row and its (fake) token for `agent`.
fn key_row(agent: AgentId) -> (AgentKeyRow, String) {
    let secret = TokenSecret::generate().unwrap();
    let token = secret.to_token_string(&agent).expose_secret().to_owned();
    let row = AgentKeyRow {
        id: AgentKeyId::generate(),
        agent_id: agent,
        secret_hash: token_hash(&agent, &secret),
        hint: secret.hint(),
        scopes: vec![Scope::StatusRead, Scope::SecretsRead],
        ip_allowlist: Vec::new(),
        require_mtls: false,
        client_cert_sha256: None,
        created_at: t0(),
        expires_at: None,
        revoked_at: None,
        last_used_at: None,
        row_mac: [0; 32],
    };
    (row, token)
}

fn env_with(limits: AuthLimits) -> Env {
    let id = AgentId::generate();
    let agent = agent_row(id);
    let (key, token) = key_row(id);
    let clock = ManualClock::new(t0());
    let table = AuthTable::new(limits);
    table
        .rebuild(
            std::slice::from_ref(&agent),
            std::slice::from_ref(&key),
            None,
            clock.now(),
        )
        .unwrap();
    Env {
        table,
        clock,
        agent,
        key,
        token,
    }
}

fn env() -> Env {
    env_with(AuthLimits::default())
}

fn input<'a>(token: &'a str, ip: IpAddr) -> TokenCheckInput<'a> {
    TokenCheckInput {
        raw_token: token,
        source_ip: ip,
        client_cert_sha256: None,
        request_id: RequestId::generate(),
        surface: Surface::Rest,
    }
}

fn check(env: &Env, token: &str) -> Result<AgentContext, AuthFailure> {
    env.table.check(&input(token, LOCAL), env.clock.now())
}

/// A well-formed token for an agent that is not in the table.
fn stranger_token() -> String {
    let id = AgentId::generate();
    TokenSecret::generate()
        .unwrap()
        .to_token_string(&id)
        .expose_secret()
        .to_owned()
}

#[test]
fn valid_token_gives_context() {
    let env = env();
    let ctx = check(&env, &env.token).unwrap();
    assert_eq!(ctx.agent_id, env.agent.id);
    assert_eq!(ctx.key_id, env.key.id);
    assert_eq!(ctx.source_ip, LOCAL);
    assert_eq!(ctx.surface, Surface::Rest);
    assert!(ctx.scopes.contains(&Scope::SecretsRead));
    assert!(!ctx.scopes.contains(&Scope::SshUse));
}

#[test]
fn revoked_key_fails_at_once() {
    let env = env();
    assert!(check(&env, &env.token).is_ok());
    let mut revoked = env.key.clone();
    revoked.revoked_at = Some(env.clock.now());
    env.table.apply_key(&revoked, env.clock.now());
    assert_eq!(
        check(&env, &env.token).unwrap_err(),
        AuthFailure::KeyRevoked
    );
}

#[test]
fn expired_key_fails() {
    let env = env();
    let mut key = env.key.clone();
    key.expires_at = Some(
        env.clock
            .now()
            .checked_add(SignedDuration::from_secs(60))
            .unwrap(),
    );
    env.table.apply_key(&key, env.clock.now());
    assert!(check(&env, &env.token).is_ok());
    env.clock.advance(SignedDuration::from_secs(59));
    assert!(check(&env, &env.token).is_ok());
    env.clock.advance(SignedDuration::from_secs(1));
    assert_eq!(
        check(&env, &env.token).unwrap_err(),
        AuthFailure::KeyExpired
    );
}

#[test]
fn ip_allowlist_is_enforced() {
    let env = env();
    let mut key = env.key.clone();
    key.ip_allowlist = vec!["10.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()];
    env.table.apply_key(&key, env.clock.now());
    let now = env.clock.now();
    let outside: IpAddr = "192.168.1.5".parse().unwrap();
    let inside: IpAddr = "10.2.3.4".parse().unwrap();
    let v6: IpAddr = "::1".parse().unwrap();
    let mapped: IpAddr = "::ffff:10.2.3.4".parse().unwrap();
    assert_eq!(
        env.table
            .check(&input(&env.token, outside), now)
            .unwrap_err(),
        AuthFailure::IpNotAllowed
    );
    assert!(env.table.check(&input(&env.token, inside), now).is_ok());
    assert!(env.table.check(&input(&env.token, v6), now).is_ok());
    assert!(env.table.check(&input(&env.token, mapped), now).is_ok());
}

#[test]
fn malformed_tokens_fail() {
    let env = env();
    let good = env.token.clone();
    let cases = [
        String::new(),
        "Bearer".to_owned(),
        good.replace("cvt_", "cvx_"),
        good[..good.len() - 1].to_owned(),
        format!("{good}A"),
        good.replacen('.', "_", 1),
        good.to_uppercase(),
    ];
    for case in cases {
        assert_eq!(
            check(&env, &case).unwrap_err(),
            AuthFailure::Malformed,
            "{case}"
        );
    }
}

#[test]
fn unknown_agent_and_wrong_secret_fail() {
    let env = env();
    assert_eq!(
        check(&env, &stranger_token()).unwrap_err(),
        AuthFailure::UnknownAgent
    );
    let other = TokenSecret::generate().unwrap();
    let wrong = other.to_token_string(&env.agent.id);
    assert_eq!(
        check(&env, wrong.expose_secret()).unwrap_err(),
        AuthFailure::NoKeyMatch
    );
}

#[test]
fn suspended_agent_fails_and_comes_back() {
    let env = env();
    let mut agent = env.agent.clone();
    agent.status = AgentStatus::Suspended;
    env.table.apply_agent(&agent);
    assert_eq!(
        check(&env, &env.token).unwrap_err(),
        AuthFailure::AgentInactive
    );
    agent.status = AgentStatus::Active;
    env.table.apply_agent(&agent);
    assert!(check(&env, &env.token).is_ok());
}

#[test]
fn mtls_needs_the_bound_certificate() {
    let env = env();
    let mut key = env.key.clone();
    key.require_mtls = true;
    env.table.apply_key(&key, env.clock.now());
    let now = env.clock.now();
    let mut req = input(&env.token, LOCAL);
    assert_eq!(
        env.table.check(&req, now).unwrap_err(),
        AuthFailure::MtlsMismatch
    );
    // Required but never bound: nothing can match.
    req.client_cert_sha256 = Some([7; 32]);
    assert_eq!(
        env.table.check(&req, now).unwrap_err(),
        AuthFailure::MtlsMismatch
    );
    key.client_cert_sha256 = Some([7; 32]);
    env.table.apply_key(&key, now);
    assert!(env.table.check(&req, now).is_ok());
    req.client_cert_sha256 = Some([8; 32]);
    assert_eq!(
        env.table.check(&req, now).unwrap_err(),
        AuthFailure::MtlsMismatch
    );
}

/// NEW-5: the per-source bucket counts failed checks only. A good token from the same source is
/// never refused by it.
#[test]
fn per_ip_rate_limit_gives_retry_after_and_recovers() {
    let env = env_with(AuthLimits {
        ip_per_second: 2,
        ip_burst: 3,
        failure_max: 100,
        ..AuthLimits::default()
    });
    let bad = stranger_token();
    for _ in 0..3 {
        assert_eq!(check(&env, &bad).unwrap_err(), AuthFailure::UnknownAgent);
    }
    let AuthFailure::RateLimited {
        retry_after_seconds,
    } = check(&env, &bad).unwrap_err()
    else {
        panic!("expected RateLimited");
    };
    assert_eq!(retry_after_seconds, 1);
    for _ in 0..5 {
        assert!(check(&env, &env.token).is_ok());
    }
    env.clock.advance(SignedDuration::from_secs(1));
    assert_eq!(check(&env, &bad).unwrap_err(), AuthFailure::UnknownAgent);
}

#[test]
fn per_agent_rate_limit_is_separate_from_the_ip_limit() {
    let env = env_with(AuthLimits {
        agent_per_second: 1,
        agent_burst: 2,
        ..AuthLimits::default()
    });
    let now = env.clock.now();
    let one: IpAddr = "10.0.0.1".parse().unwrap();
    let two: IpAddr = "10.0.0.2".parse().unwrap();
    let three: IpAddr = "10.0.0.3".parse().unwrap();
    assert!(env.table.check(&input(&env.token, one), now).is_ok());
    assert!(env.table.check(&input(&env.token, two), now).is_ok());
    assert!(matches!(
        env.table.check(&input(&env.token, three), now),
        Err(AuthFailure::RateLimited { .. })
    ));
}

#[test]
fn rate_limited_calls_do_not_count_as_failures() {
    let env = env_with(AuthLimits {
        agent_per_second: 1,
        agent_burst: 1,
        failure_max: 2,
        ..AuthLimits::default()
    });
    assert!(check(&env, &env.token).is_ok());
    for _ in 0..5 {
        assert!(matches!(
            check(&env, &env.token),
            Err(AuthFailure::RateLimited { .. })
        ));
    }
    env.clock.advance(SignedDuration::from_secs(1));
    assert!(check(&env, &env.token).is_ok());
}

#[test]
fn lockout_after_n_failures_and_release_after_the_window() {
    let env = env_with(AuthLimits {
        failure_max: 3,
        lockout_seconds: 60,
        ..AuthLimits::default()
    });
    let bad = stranger_token();
    for _ in 0..3 {
        assert_eq!(check(&env, &bad).unwrap_err(), AuthFailure::UnknownAgent);
    }
    // Locked: a failing token is refused, and the answer says how long.
    assert_eq!(
        check(&env, &bad).unwrap_err(),
        AuthFailure::LockedOut {
            retry_after_seconds: 60
        }
    );
    env.clock.advance(SignedDuration::from_secs(30));
    assert_eq!(
        check(&env, &bad).unwrap_err(),
        AuthFailure::LockedOut {
            retry_after_seconds: 30
        }
    );
    // The right token from the locked address still works (NEW-5).
    assert!(check(&env, &env.token).is_ok());
    // Another address is not affected.
    let other: IpAddr = "10.9.9.9".parse().unwrap();
    assert_eq!(
        env.table
            .check(&input(&bad, other), env.clock.now())
            .unwrap_err(),
        AuthFailure::UnknownAgent
    );
    env.clock.advance(SignedDuration::from_secs(30));
    assert_eq!(check(&env, &bad).unwrap_err(), AuthFailure::UnknownAgent);
}

/// NEW-5: a local user floods bad tokens from `127.0.0.1` and `::1`, the one source of every local
/// agent. The bad tokens are locked out; the agent's good token is never refused.
#[test]
fn new5_a_bad_token_flood_never_locks_out_a_good_token() {
    let env = env();
    let v6: IpAddr = "::1".parse().unwrap();
    let now = env.clock.now();
    let mut locked = 0;
    for n in 0..200 {
        for ip in [LOCAL, v6] {
            let bad = if n % 2 == 0 {
                stranger_token()
            } else {
                "x".to_owned()
            };
            match env.table.check(&input(&bad, ip), now).unwrap_err() {
                AuthFailure::LockedOut { .. } => locked += 1,
                AuthFailure::UnknownAgent | AuthFailure::Malformed => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        // Not too often: the clock is frozen, and the agent's own burst is 40.
        if n % 20 == 0 {
            for ip in [LOCAL, v6] {
                let ctx = env.table.check(&input(&env.token, ip), now).unwrap();
                assert_eq!(ctx.agent_id, env.agent.id);
            }
        }
    }
    // Ten failures per source in the window, then every further failure is refused.
    assert_eq!(locked, 400 - 20);
    // A wrong secret for the real agent is refused as well.
    let wrong = TokenSecret::generate()
        .unwrap()
        .to_token_string(&env.agent.id)
        .expose_secret()
        .to_owned();
    assert!(matches!(
        env.table.check(&input(&wrong, LOCAL), now),
        Err(AuthFailure::LockedOut { .. })
    ));
    assert!(env.table.check(&input(&env.token, LOCAL), now).is_ok());
}

/// NEW-8: while a bad-token flood holds the lockout of `127.0.0.1`, a revoked key's token is
/// refused as `LockedOut` like the others, but the refusal still says `KeyRevoked` under it.
#[test]
fn new8_a_lockout_keeps_the_reason_under_it() {
    let env = env();
    let now = env.clock.now();
    let mut revoked = env.key.clone();
    revoked.revoked_at = Some(now);
    env.table.apply_key(&revoked, now);
    for _ in 0..AuthLimits::default().failure_max {
        let refusal = env
            .table
            .check_refusal(&input(&stranger_token(), LOCAL), now)
            .unwrap_err();
        assert_eq!(refusal, Refusal::from(AuthFailure::UnknownAgent));
    }
    let refusal = env
        .table
        .check_refusal(&input(&env.token, LOCAL), now)
        .unwrap_err();
    assert!(matches!(refusal.failure, AuthFailure::LockedOut { .. }));
    assert_eq!(refusal.cause, AuthFailure::KeyRevoked);
    assert!(refusal.cause.matched_a_key());
    assert!(!AuthFailure::NoKeyMatch.matched_a_key());
    // `check` gives the same answer to the caller.
    assert_eq!(
        env.table.check(&input(&env.token, LOCAL), now).unwrap_err(),
        refusal.failure
    );
}

/// NEW-5: failures from many sources together reach the global limit; then every failed check is
/// refused, from any source, and good tokens still pass.
#[test]
fn new5_failures_from_many_sources_hit_the_global_limit() {
    let env = env_with(AuthLimits {
        global_failure_max: 30,
        ..AuthLimits::default()
    });
    let now = env.clock.now();
    let bad = stranger_token();
    for n in 0..30u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 0, n));
        assert_eq!(
            env.table.check(&input(&bad, ip), now).unwrap_err(),
            AuthFailure::UnknownAgent
        );
    }
    let fresh = IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1));
    assert!(matches!(
        env.table.check(&input(&bad, fresh), now),
        Err(AuthFailure::LockedOut { .. })
    ));
    assert!(env.table.check(&input(&env.token, fresh), now).is_ok());
    env.clock.advance(SignedDuration::from_secs(300));
    assert_eq!(
        env.table
            .check(&input(&bad, fresh), env.clock.now())
            .unwrap_err(),
        AuthFailure::UnknownAgent
    );
}

/// NEW-5: the failure state per source has a fixed size bound; sources past it share one entry.
#[test]
fn new5_the_failure_table_stays_bounded() {
    let env = env_with(AuthLimits {
        global_failure_max: u32::MAX,
        ..AuthLimits::default()
    });
    let now = env.clock.now();
    let bad = stranger_token();
    for n in 0..10_000u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
        let _ = env.table.check(&input(&bad, ip), now);
    }
    assert!(env.table.failures.tracked() <= limits::MAX_SOURCES + 1);
    assert!(env.table.ip_rate.tracked() <= limits::MAX_SOURCES + 1);
    assert!(env.table.check(&input(&env.token, LOCAL), now).is_ok());
}

#[test]
fn failures_outside_the_window_do_not_add_up() {
    let env = env_with(AuthLimits {
        failure_max: 3,
        failure_window_seconds: 100,
        ..AuthLimits::default()
    });
    let bad = stranger_token();
    for _ in 0..10 {
        assert_eq!(check(&env, &bad).unwrap_err(), AuthFailure::UnknownAgent);
        env.clock.advance(SignedDuration::from_secs(60));
    }
}

#[test]
fn ipv6_addresses_of_one_64_share_a_lockout() {
    let env = env_with(AuthLimits {
        failure_max: 2,
        ..AuthLimits::default()
    });
    let bad = stranger_token();
    let now = env.clock.now();
    for last in ["2001:db8:1:2::1", "2001:db8:1:2::2"] {
        let ip: IpAddr = last.parse().unwrap();
        assert!(env.table.check(&input(&bad, ip), now).is_err());
    }
    let third: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
    assert!(matches!(
        env.table.check(&input(&bad, third), now),
        Err(AuthFailure::LockedOut { .. })
    ));
    assert!(env.table.check(&input(&env.token, third), now).is_ok());
}

#[test]
fn outward_error_hides_the_reason() {
    for failure in [
        AuthFailure::Malformed,
        AuthFailure::UnknownAgent,
        AuthFailure::NoKeyMatch,
        AuthFailure::KeyExpired,
        AuthFailure::KeyRevoked,
        AuthFailure::AgentInactive,
        AuthFailure::IpNotAllowed,
        AuthFailure::MtlsMismatch,
    ] {
        assert!(
            matches!(failure.outward(), CoreError::BadCredentials),
            "{failure:?}"
        );
    }
    assert!(matches!(
        AuthFailure::RateLimited {
            retry_after_seconds: 4
        }
        .outward(),
        CoreError::RateLimited {
            retry_after_seconds: 4
        }
    ));
    assert_eq!(
        AuthFailure::LockedOut {
            retry_after_seconds: 9
        }
        .outward()
        .code(),
        cerberus_types::ErrorCode::TooManyFailures
    );
    assert_eq!(AuthFailure::KeyRevoked.reason(), "key_revoked");
}

#[test]
fn bad_row_mac_counts_as_revoked() {
    let vault = cerberus_types::VaultId::generate();
    let key32 = Key32::random().unwrap();
    let macs = RowMacs::new(&key32, &vault);
    let id = AgentId::generate();
    let mut agent = agent_row(id);
    macs.sign_agent(&mut agent).unwrap();
    let (mut good, good_token) = key_row(id);
    macs.sign_agent_key(&mut good).unwrap();
    let (mut forged, forged_token) = key_row(id);
    macs.sign_agent_key(&mut forged).unwrap();
    // Someone with file access adds a scope to the signed row.
    forged.scopes.push(Scope::SshUse);

    let table = AuthTable::new(AuthLimits::default());
    let issues = table
        .rebuild(
            &[agent.clone()],
            &[good.clone(), forged.clone()],
            Some(&macs),
            t0(),
        )
        .unwrap();
    assert_eq!(
        issues,
        vec![IntegrityIssue {
            table: "agent_keys",
            row_id: forged.id.to_string()
        }]
    );
    let now = t0();
    assert!(table.check(&input(&good_token, LOCAL), now).is_ok());
    assert_eq!(
        table.check(&input(&forged_token, LOCAL), now).unwrap_err(),
        AuthFailure::KeyRevoked
    );

    // A forged agent row: every key of the agent stops working.
    let mut tampered = agent;
    tampered.created_at = tampered
        .created_at
        .checked_add(SignedDuration::from_secs(1))
        .unwrap();
    let issues = table
        .rebuild(&[tampered.clone()], &[good], Some(&macs), t0())
        .unwrap();
    assert_eq!(issues[0].table, "agents");
    assert_eq!(
        table.check(&input(&good_token, LOCAL), now).unwrap_err(),
        AuthFailure::AgentInactive
    );

    // Sealed vault: no key, rows are used as stored.
    table.rebuild(&[tampered], &[forged], None, t0()).unwrap();
    assert!(table.check(&input(&forged_token, LOCAL), now).is_ok());
}

/// Counts the comparisons of one check.
fn comparisons(env: &Env, token: &str) -> usize {
    let mut count = 0;
    let mut eq = |a: &[u8], b: &[u8]| {
        count += 1;
        ct_eq(a, b)
    };
    let _ = env
        .table
        .check_with(&input(token, LOCAL), env.clock.now(), &mut eq);
    count
}

#[test]
fn every_well_formed_token_costs_the_same_comparisons() {
    let env = env();
    // Give the agent four more keys so it has five.
    for _ in 0..4 {
        let (extra, _) = key_row(env.agent.id);
        env.table.apply_key(&extra, env.clock.now());
    }
    let unknown_agent = stranger_token();
    let wrong_secret = TokenSecret::generate()
        .unwrap()
        .to_token_string(&env.agent.id)
        .expose_secret()
        .to_owned();
    let right = comparisons(&env, &env.token);
    assert_eq!(right, KEY_SLOTS);
    assert_eq!(comparisons(&env, &unknown_agent), right);
    assert_eq!(comparisons(&env, &wrong_secret), right);

    // An agent with one key and a revoked agent do the same work.
    let lone = self::env();
    assert_eq!(comparisons(&lone, &lone.token), right);
    let mut revoked = lone.key.clone();
    revoked.revoked_at = Some(t0());
    lone.table.apply_key(&revoked, t0());
    assert_eq!(comparisons(&lone, &lone.token), right);
}

#[test]
fn dead_keys_are_trimmed_before_live_ones() {
    let env = env();
    let now = env.clock.now();
    let mut dead_ids = Vec::new();
    for n in 0..12 {
        let (mut row, _) = key_row(env.agent.id);
        row.created_at = t0().checked_add(SignedDuration::from_secs(n + 1)).unwrap();
        row.revoked_at = Some(row.created_at);
        dead_ids.push(row.id);
        env.table.apply_key(&row, now);
    }
    assert!(check(&env, &env.token).is_ok());
    let agents = env.table.agents.read().unwrap();
    let keys = &agents[&env.agent.id].keys;
    assert_eq!(keys.len(), KEY_SLOTS);
    // The oldest dead keys went first.
    assert!(keys.iter().all(|k| k.id != dead_ids[0]));
    assert!(keys.iter().any(|k| k.id == dead_ids[11]));
}

#[test]
fn comparison_time_does_not_depend_on_the_agent() {
    // Wall-clock check with a very wide margin. The structural test above is the real proof;
    // this only catches a gross difference such as an early return before hashing. It compares
    // the minimum over many runs, which load on the machine hardly changes.
    use cerberus_types::Stopwatch;
    let env = env_with(AuthLimits {
        ip_per_second: u32::MAX / 2000,
        ip_burst: u32::MAX / 2000,
        failure_max: u32::MAX,
        global_failure_max: u32::MAX,
        ..AuthLimits::default()
    });
    let unknown = stranger_token();
    let wrong = TokenSecret::generate()
        .unwrap()
        .to_token_string(&env.agent.id)
        .expose_secret()
        .to_owned();
    let best = |token: &str| {
        (0..200)
            .map(|_| {
                let watch = Stopwatch::start();
                let _ = check(&env, token);
                watch.elapsed()
            })
            .min()
            .unwrap()
    };
    let a = best(&unknown).as_nanos().max(1);
    let b = best(&wrong).as_nanos().max(1);
    assert!(a < b * 10 && b < a * 10, "unknown {a} ns, wrong {b} ns");
}

/// Finding 9: the token never shows in `Debug` output.
#[test]
fn token_check_input_debug_hides_the_token() {
    let input = TokenCheckInput {
        raw_token: "cvt_fake-agent.fake-secret-value",
        source_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        client_cert_sha256: None,
        request_id: cerberus_types::ids::RequestId::generate(),
        surface: crate::Surface::Rest,
    };
    let text = format!("{input:?}");
    assert!(!text.contains("fake-secret-value"), "{text}");
    assert!(text.contains("[REDACTED]"), "{text}");
}

/// NEW-6: `key_active` turns false at once when the key is revoked or the agent is suspended.
#[test]
fn key_active_follows_revoke_and_suspend() {
    let env = env();
    let now = env.clock.now();
    assert!(env.table.key_active(&env.agent.id, &env.key.id, now));
    assert!(
        !env.table
            .key_active(&env.agent.id, &AgentKeyId::generate(), now)
    );
    assert!(!env.table.key_active(&AgentId::generate(), &env.key.id, now));
    let mut suspended = env.agent.clone();
    suspended.status = AgentStatus::Suspended;
    env.table.apply_agent(&suspended);
    assert!(!env.table.key_active(&env.agent.id, &env.key.id, now));
    env.table.apply_agent(&env.agent);
    assert!(env.table.key_active(&env.agent.id, &env.key.id, now));
    let mut revoked = env.key.clone();
    revoked.revoked_at = Some(now);
    env.table.apply_key(&revoked, now);
    assert!(!env.table.key_active(&env.agent.id, &env.key.id, now));
}
