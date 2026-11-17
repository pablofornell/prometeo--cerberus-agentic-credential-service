//! Tests of the pure policy functions (ADR-0017). All values are fake test values.

use std::sync::Mutex;

use cerberus_crypto::SecretBytes;
use cerberus_types::{
    AgentId, Environment, GrantId, GrantMode, ItemId, ItemKind, Permission, WorkspaceId, t0,
};
use jiff::civil::{Time, Weekday};
use jiff::{SignedDuration, Timestamp};
use proptest::prelude::*;

use super::testkit::ItemSpec;
use super::*;
use crate::index::GrantEntry;

const ALL_MODES: [GrantMode; 4] = [
    GrantMode::Auto,
    GrantMode::AskOnce,
    GrantMode::AskAlways,
    GrantMode::Deny,
];

fn grant(agent: AgentId, selector: Selector, perms: &[Permission], mode: GrantMode) -> Grant {
    Grant {
        id: GrantId::generate(),
        agent_id: agent,
        selector,
        permissions: perms.iter().copied().collect(),
        mode,
        conditions: Conditions::default(),
        allow_prod_auto: false,
        created_at: t0(),
        updated_at: t0(),
    }
}

fn decide(
    grants: &[Grant],
    agent: &AgentId,
    meta: &ItemMeta,
    permission: Permission,
    reason: Option<&str>,
) -> Decision {
    let input = EvalInput {
        grants,
        item: PolicyItem::of(meta),
        permission,
        reason,
        now: t0(),
    };
    evaluate(&input, agent, &NoCount)
}

fn item(env: Environment) -> ItemMeta {
    ItemSpec::new(WorkspaceId::generate(), env).meta(ItemId::generate())
}

/// A counter with a fixed answer that records how often it was asked.
#[derive(Default)]
struct CountingCounter {
    calls: Mutex<u32>,
    refuse: bool,
}

impl ReadCounter for CountingCounter {
    fn check_and_record(&self, _: &GrantId, _: &AgentId, _: u32, _: Timestamp) -> Result<(), u32> {
        *self.calls.lock().unwrap() += 1;
        if self.refuse { Err(42) } else { Ok(()) }
    }
}

#[test]
fn no_grant_and_other_agents_grants_give_nothing() {
    let (me, other) = (AgentId::generate(), AgentId::generate());
    let meta = item(Environment::Dev);
    for p in ALL_PERMISSIONS {
        assert_eq!(decide(&[], &me, &meta, p, None), Decision::NoGrant);
    }
    let theirs = grant(
        other,
        Selector::default(),
        &ALL_PERMISSIONS,
        GrantMode::Auto,
    );
    assert_eq!(
        decide(&[theirs], &me, &meta, Permission::Read, None),
        Decision::NoGrant
    );
}

#[test]
fn implication_read_and_ssh_give_find_only() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    for p in [Permission::Read, Permission::UseSsh] {
        let g = grant(agent, Selector::default(), &[p], GrantMode::Auto);
        assert!(
            decide(
                std::slice::from_ref(&g),
                &agent,
                &meta,
                Permission::Find,
                None
            )
            .is_allow()
        );
        for other in [Permission::Write, Permission::CreateSession] {
            assert_eq!(
                decide(std::slice::from_ref(&g), &agent, &meta, other, None),
                Decision::NoGrant
            );
        }
    }
    let find_only = grant(
        agent,
        Selector::default(),
        &[Permission::Find],
        GrantMode::Auto,
    );
    assert_eq!(
        decide(&[find_only], &agent, &meta, Permission::Read, None),
        Decision::NoGrant
    );
}

#[test]
fn deny_with_no_permissions_denies_all_and_beats_a_narrower_allow() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let deny = grant(agent, Selector::default(), &[], GrantMode::Deny);
    let narrow = grant(
        agent,
        Selector {
            item_ids: vec![meta.id],
            ..Selector::default()
        },
        &ALL_PERMISSIONS,
        GrantMode::Auto,
    );
    for p in ALL_PERMISSIONS {
        assert_eq!(
            decide(&[narrow.clone(), deny.clone()], &agent, &meta, p, None),
            Decision::Deny { grant_id: deny.id }
        );
    }
}

#[test]
fn deny_of_read_also_hides_the_item() {
    // `read` implies `find`, also for a deny grant (DEC-T07-2).
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let allow = grant(
        agent,
        Selector::default(),
        &[Permission::Find],
        GrantMode::Auto,
    );
    let deny = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Deny,
    );
    assert!(matches!(
        decide(
            &[allow.clone(), deny.clone()],
            &agent,
            &meta,
            Permission::Find,
            None
        ),
        Decision::Deny { .. }
    ));
    // A deny of `write` does not touch reads.
    let deny_write = grant(
        agent,
        Selector::default(),
        &[Permission::Write],
        GrantMode::Deny,
    );
    let read = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    assert!(decide(&[read, deny_write], &agent, &meta, Permission::Read, None).is_allow());
}

#[test]
fn specificity_weights_match_adr() {
    let ws = WorkspaceId::generate();
    let cases: Vec<(Selector, u32)> = vec![
        (Selector::default(), 0),
        (
            Selector {
                item_ids: vec![ItemId::generate()],
                ..Selector::default()
            },
            64,
        ),
        (
            Selector {
                workspace_ids: vec![ws],
                ..Selector::default()
            },
            16,
        ),
        (
            Selector {
                environments: vec![Environment::Dev],
                ..Selector::default()
            },
            8,
        ),
        (
            Selector {
                role_labels: vec!["admin".into()],
                ..Selector::default()
            },
            4,
        ),
        (
            Selector {
                kinds: vec![ItemKind::ApiKey],
                ..Selector::default()
            },
            2,
        ),
        (
            Selector {
                categories: vec!["x".into()],
                ..Selector::default()
            },
            2,
        ),
        (
            Selector {
                tags: vec!["t".into()],
                ..Selector::default()
            },
            1,
        ),
        (
            Selector {
                workspace_ids: vec![ws],
                environments: vec![Environment::Dev],
                tags: vec!["a".into(), "b".into()],
                ..Selector::default()
            },
            25,
        ),
    ];
    for (selector, weight) in cases {
        assert_eq!(specificity(&selector), weight, "{selector:?}");
    }
}

#[test]
fn most_specific_grant_wins() {
    let agent = AgentId::generate();
    let meta = item(Environment::Staging);
    let broad = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    let by_ws = grant(
        agent,
        Selector {
            workspace_ids: vec![meta.workspace_id],
            ..Selector::default()
        },
        &[Permission::Read],
        GrantMode::AskOnce,
    );
    let by_env_role = grant(
        agent,
        Selector {
            environments: vec![Environment::Staging],
            role_labels: vec!["ADMIN ".into()],
            ..Selector::default()
        },
        &[Permission::Read],
        GrantMode::AskAlways,
    );
    let by_item = grant(
        agent,
        Selector {
            item_ids: vec![meta.id],
            ..Selector::default()
        },
        &[Permission::Read],
        GrantMode::Auto,
    );
    let all = [
        broad.clone(),
        by_ws.clone(),
        by_env_role.clone(),
        by_item.clone(),
    ];
    assert_eq!(
        decide(&all, &agent, &meta, Permission::Read, None),
        Decision::Allow {
            mode: GrantMode::Auto,
            grant_id: by_item.id
        }
    );
    assert_eq!(
        decide(&all[..3], &agent, &meta, Permission::Read, None),
        Decision::Allow {
            mode: GrantMode::AskOnce,
            grant_id: by_ws.id
        },
        "16 beats 8 + 4"
    );
    assert_eq!(
        decide(
            &[broad.clone(), by_env_role.clone()],
            &agent,
            &meta,
            Permission::Read,
            None
        ),
        Decision::Allow {
            mode: GrantMode::AskAlways,
            grant_id: by_env_role.id
        }
    );
    // A selector that does not match is not considered, however specific.
    let other_item = grant(
        agent,
        Selector {
            item_ids: vec![ItemId::generate()],
            ..Selector::default()
        },
        &[Permission::Read],
        GrantMode::AskAlways,
    );
    assert_eq!(
        decide(
            &[broad.clone(), other_item],
            &agent,
            &meta,
            Permission::Read,
            None
        ),
        Decision::Allow {
            mode: GrantMode::Auto,
            grant_id: broad.id
        }
    );
}

#[test]
fn ties_pick_stricter_mode_then_older_then_smaller_id() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let auto = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    let ask = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::AskOnce,
    );
    assert_eq!(
        decide(
            &[auto.clone(), ask.clone()],
            &agent,
            &meta,
            Permission::Read,
            None
        )
        .grant_id(),
        Some(ask.id)
    );
    let mut older = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    older.created_at = t0() - SignedDuration::from_hours(1);
    assert_eq!(
        decide(
            &[auto.clone(), older.clone()],
            &agent,
            &meta,
            Permission::Read,
            None
        )
        .grant_id(),
        Some(older.id)
    );
    let mut a = auto.clone();
    let mut b = auto.clone();
    a.id = GrantId(uuid_of(1));
    b.id = GrantId(uuid_of(2));
    assert_eq!(
        decide(&[b, a.clone()], &agent, &meta, Permission::Read, None).grant_id(),
        Some(a.id)
    );
}

fn uuid_of(n: u8) -> uuid::Uuid {
    uuid::Uuid::from_bytes([n; 16])
}

#[test]
fn text_selectors_compare_normalized_and_tags_are_any_of() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let g = grant(
        agent,
        Selector {
            categories: vec!["WEB  LOGIN".into()],
            tags: vec!["other".into(), " Shop".into()],
            ..Selector::default()
        },
        &[Permission::Read],
        GrantMode::Auto,
    );
    assert!(decide(&[g], &agent, &meta, Permission::Read, None).is_allow());
    let no_role = ItemMeta {
        role_label: None,
        ..meta
    };
    let g = grant(
        agent,
        Selector {
            role_labels: vec!["admin".into()],
            ..Selector::default()
        },
        &[Permission::Read],
        GrantMode::Auto,
    );
    assert_eq!(
        decide(&[g], &agent, &no_role, Permission::Read, None),
        Decision::NoGrant
    );
}

#[test]
fn prod_reads_default_to_ask_always_unless_owner_allowed() {
    let agent = AgentId::generate();
    let prod = item(Environment::Prod);
    for mode in [GrantMode::Auto, GrantMode::AskOnce] {
        let g = grant(
            agent,
            Selector::default(),
            &[Permission::Read, Permission::UseSsh, Permission::Write],
            mode,
        );
        for p in [Permission::Read, Permission::UseSsh] {
            assert_eq!(
                decide(std::slice::from_ref(&g), &agent, &prod, p, None),
                Decision::Allow {
                    mode: GrantMode::AskAlways,
                    grant_id: g.id
                }
            );
        }
        assert_eq!(
            decide(
                std::slice::from_ref(&g),
                &agent,
                &prod,
                Permission::Write,
                None
            ),
            Decision::Allow {
                mode: GrantMode::Auto,
                grant_id: g.id
            },
            "mode is not used for write"
        );
        let mut owner_ok = g.clone();
        owner_ok.allow_prod_auto = true;
        assert_eq!(
            decide(&[owner_ok.clone()], &agent, &prod, Permission::Read, None),
            Decision::Allow {
                mode,
                grant_id: g.id
            }
        );
    }
    let staging = item(Environment::Staging);
    let g = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    assert_eq!(
        decide(
            std::slice::from_ref(&g),
            &agent,
            &staging,
            Permission::Read,
            None
        ),
        Decision::Allow {
            mode: GrantMode::Auto,
            grant_id: g.id
        }
    );
}

#[test]
fn expired_grant_is_ignored() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let mut g = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    g.conditions.expires_at = Some(t0());
    assert_eq!(
        decide(
            std::slice::from_ref(&g),
            &agent,
            &meta,
            Permission::Read,
            None
        ),
        Decision::NoGrant
    );
    g.conditions.expires_at = Some(t0() + SignedDuration::from_secs(1));
    assert!(decide(&[g], &agent, &meta, Permission::Read, None).is_allow());
}

fn window(days: &[Weekday], start: (i8, i8), end: (i8, i8)) -> TimeWindow {
    TimeWindow {
        days: days.to_vec(),
        start: Time::new(start.0, start.1, 0, 0).unwrap(),
        end: Time::new(end.0, end.1, 0, 0).unwrap(),
        tz: "UTC".to_owned(),
    }
}

#[test]
fn time_window_cases() {
    // t0 is Thursday 2026-01-01 00:00 UTC.
    let thu = t0();
    let at = |h: i64| thu + SignedDuration::from_hours(h);
    let office = window(&[Weekday::Thursday, Weekday::Friday], (9, 0), (17, 0));
    assert!(!in_window(&office, at(8)));
    assert!(in_window(&office, at(9)));
    assert!(in_window(&office, at(16)));
    assert!(!in_window(&office, at(17)), "end is exclusive");
    assert!(in_window(&office, at(24 + 10)), "friday");
    assert!(!in_window(&office, at(48 + 10)), "saturday");
    let night = window(&[Weekday::Wednesday], (22, 0), (6, 0));
    assert!(
        in_window(&night, at(3)),
        "thursday 03:00 belongs to wednesday's night"
    );
    assert!(
        !in_window(&night, at(23)),
        "thursday 23:00 is a thursday night"
    );
    let mut bad = office.clone();
    bad.tz = "Nowhere/Fake_Zone".to_owned();
    assert!(!in_window(&bad, at(10)), "unknown zone fails closed");

    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let mut g = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    g.conditions.time_window = Some(office);
    let input = |now| EvalInput {
        grants: std::slice::from_ref(&g),
        item: PolicyItem::of(&meta),
        permission: Permission::Read,
        reason: None,
        now,
    };
    assert_eq!(
        evaluate(&input(at(8)), &agent, &NoCount),
        Decision::ConditionFailed { grant_id: g.id }
    );
    assert!(evaluate(&input(at(10)), &agent, &NoCount).is_allow());
}

#[test]
fn reason_required_checks_presence_and_length_only() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let mut g = grant(
        agent,
        Selector::default(),
        &[Permission::Read],
        GrantMode::Auto,
    );
    g.conditions.reason_required = true;
    let grants = [g.clone()];
    for bad in [None, Some(""), Some("short"), Some("    seven  ")] {
        assert_eq!(
            decide(&grants, &agent, &meta, Permission::Read, bad),
            Decision::ReasonRequired { grant_id: g.id }
        );
    }
    assert!(decide(&grants, &agent, &meta, Permission::Read, Some("deploy fix")).is_allow());
    assert!(
        decide(&grants, &agent, &meta, Permission::Find, None).is_allow(),
        "find needs no reason"
    );
}

#[test]
fn read_limit_counts_only_allowed_secret_reads() {
    let agent = AgentId::generate();
    let meta = item(Environment::Dev);
    let mut g = grant(
        agent,
        Selector::default(),
        &[Permission::Read, Permission::Write],
        GrantMode::Auto,
    );
    g.conditions.max_reads_per_hour = Some(2);
    g.conditions.reason_required = true;
    let counter = CountingCounter::default();
    let run = |p, reason, c: &dyn ReadCounter| {
        evaluate(
            &EvalInput {
                grants: std::slice::from_ref(&g),
                item: PolicyItem::of(&meta),
                permission: p,
                reason,
                now: t0(),
            },
            &agent,
            c,
        )
    };
    run(Permission::Read, None, &counter);
    run(Permission::Write, Some("a good reason"), &counter);
    run(Permission::Find, None, &counter);
    assert_eq!(
        *counter.calls.lock().unwrap(),
        0,
        "refused, write and find use no read"
    );
    assert!(run(Permission::Read, Some("a good reason"), &counter).is_allow());
    assert_eq!(*counter.calls.lock().unwrap(), 1);
    let full = CountingCounter {
        refuse: true,
        ..CountingCounter::default()
    };
    assert_eq!(
        run(Permission::Read, Some("a good reason"), &full),
        Decision::GrantRateLimited {
            grant_id: g.id,
            retry_after_seconds: 42
        }
    );
}

#[test]
fn read_limiter_sliding_hour() {
    let limiter = ReadLimiter::new();
    let settings = PolicySettings::default();
    let (agent, grant_id, item) = (AgentId::generate(), GrantId::generate(), ItemId::generate());
    for _ in 0..3 {
        assert!(
            limiter
                .record_read(&agent, &item, Some((grant_id, 3)), t0(), &settings)
                .is_ok()
        );
    }
    let hit = limiter.record_read(&agent, &item, Some((grant_id, 3)), t0(), &settings);
    assert_eq!(
        hit,
        Err(LimitHit::Grant {
            retry_after_seconds: 3600
        })
    );
    assert_eq!(limiter.peek_grant(&grant_id, &agent, 3, t0()), Err(3600));
    let later = t0() + SignedDuration::from_secs(3600);
    assert!(limiter.peek_grant(&grant_id, &agent, 3, later).is_ok());
}

#[test]
fn secret_read_and_distinct_item_limits() {
    let limiter = ReadLimiter::new();
    let settings = PolicySettings {
        secret_reads_per_minute: 5,
        distinct_items_per_hour: 3,
        ..PolicySettings::default()
    };
    let agent = AgentId::generate();
    let items: Vec<ItemId> = (0..4).map(|_| ItemId::generate()).collect();
    for item in &items[..3] {
        assert!(
            limiter
                .record_read(&agent, item, None, t0(), &settings)
                .is_ok()
        );
    }
    assert!(matches!(
        limiter.record_read(&agent, &items[3], None, t0(), &settings),
        Err(LimitHit::DistinctItems { distinct: 3, .. })
    ));
    assert!(
        limiter
            .record_read(&agent, &items[0], None, t0(), &settings)
            .is_ok(),
        "known item is fine"
    );
    assert!(
        limiter
            .record_read(&agent, &items[1], None, t0(), &settings)
            .is_ok()
    );
    assert!(matches!(
        limiter.record_read(&agent, &items[1], None, t0(), &settings),
        Err(LimitHit::SecretReads { .. })
    ));
    let next_minute = t0() + SignedDuration::from_secs(61);
    assert!(
        limiter
            .record_read(&agent, &items[1], None, next_minute, &settings)
            .is_ok()
    );
    assert!(
        limiter
            .record_read(&AgentId::generate(), &items[3], None, t0(), &settings)
            .is_ok(),
        "per agent"
    );
}

fn entry(g: &Grant, json: &[u8]) -> GrantEntry {
    GrantEntry {
        id: g.id,
        agent_id: g.agent_id,
        expires_at: None,
        updated_at: g.updated_at,
        body: SecretBytes::new(json.to_vec()),
    }
}

#[test]
fn body_roundtrip_and_earlier_expiry() {
    let agent = AgentId::generate();
    let mut g = grant(
        agent,
        Selector {
            workspace_ids: vec![WorkspaceId::generate()],
            environments: vec![Environment::Prod],
            categories: vec!["API key".into()],
            tags: vec!["billing".into()],
            kinds: vec![ItemKind::ApiKey],
            role_labels: vec!["read-only".into()],
            item_ids: vec![ItemId::generate()],
        },
        &[Permission::Read, Permission::Find],
        GrantMode::AskOnce,
    );
    g.conditions = Conditions {
        time_window: Some(window(
            &[Weekday::Monday, Weekday::Sunday],
            (8, 30),
            (18, 45),
        )),
        max_reads_per_hour: Some(7),
        expires_at: Some(t0() + SignedDuration::from_hours(5)),
        reason_required: true,
    };
    g.allow_prod_auto = true;
    let json = encode_grant(&g).unwrap();
    let back = decode_grant(&entry(&g, &json)).unwrap();
    assert_eq!(back, g);
    let mut e = entry(&g, &json);
    e.expires_at = Some(t0() + SignedDuration::from_hours(1));
    assert_eq!(
        decode_grant(&e).unwrap().conditions.expires_at,
        e.expires_at,
        "the earlier wins"
    );
    let mut moved = entry(&g, &json);
    moved.agent_id = AgentId::generate();
    assert!(
        decode_grant(&moved).is_err(),
        "sealed agent must match the plain column"
    );
}

#[test]
fn unreadable_grant_body_denies_everything() {
    let agent = AgentId::generate();
    let allow = grant(
        agent,
        Selector::default(),
        &ALL_PERMISSIONS,
        GrantMode::Auto,
    );
    let mut index = crate::index::Index::default();
    index.upsert_grant(entry(&allow, &encode_grant(&allow).unwrap()));
    let broken = grant(agent, Selector::default(), &[], GrantMode::Deny);
    index.upsert_grant(entry(&broken, b"{\"not\":\"a grant\"}"));
    let grants = agent_grants(&index, &agent);
    let meta = item(Environment::Dev);
    for p in ALL_PERMISSIONS {
        assert!(matches!(
            decide(&grants, &agent, &meta, p, None),
            Decision::Deny { .. }
        ));
    }
}

// ---- properties ---------------------------------------------------------------------------------

fn pools() -> (Vec<WorkspaceId>, Vec<ItemId>) {
    (
        vec![WorkspaceId(uuid_of(10)), WorkspaceId(uuid_of(11))],
        vec![
            ItemId(uuid_of(20)),
            ItemId(uuid_of(21)),
            ItemId(uuid_of(22)),
        ],
    )
}

fn pick<T: Clone + std::fmt::Debug + 'static>(pool: Vec<T>) -> impl Strategy<Value = Vec<T>> {
    proptest::sample::subsequence(pool.clone(), 0..=pool.len())
}

fn env_strategy() -> impl Strategy<Value = Environment> {
    prop_oneof![
        Just(Environment::Dev),
        Just(Environment::Staging),
        Just(Environment::Prod),
        Just(Environment::Other)
    ]
}

fn selector_strategy() -> impl Strategy<Value = Selector> {
    let (ws, ids) = pools();
    (
        pick(ws),
        pick(vec![
            Environment::Dev,
            Environment::Staging,
            Environment::Prod,
        ]),
        pick(vec!["Web login".to_owned(), "API key".to_owned()]),
        pick(vec!["shop".to_owned(), "billing".to_owned()]),
        pick(vec![ItemKind::WebLogin, ItemKind::ApiKey]),
        pick(vec!["admin".to_owned(), "read-only".to_owned()]),
        pick(ids),
    )
        .prop_map(
            |(workspace_ids, environments, categories, tags, kinds, role_labels, item_ids)| {
                Selector {
                    workspace_ids,
                    environments,
                    categories,
                    tags,
                    kinds,
                    role_labels,
                    item_ids,
                }
            },
        )
}

fn grant_strategy(agent: AgentId) -> impl Strategy<Value = Grant> {
    (
        selector_strategy(),
        pick(ALL_PERMISSIONS.to_vec()),
        proptest::sample::select(ALL_MODES.to_vec()),
        any::<bool>(),
        any::<bool>(),
        0i64..5,
        any::<[u8; 16]>(),
    )
        .prop_map(
            move |(selector, perms, mode, reason_required, allow_prod_auto, age, id)| {
                let mut g = grant(agent, selector, &perms, mode);
                g.id = GrantId(uuid::Uuid::from_bytes(id));
                g.conditions.reason_required = reason_required;
                g.allow_prod_auto = allow_prod_auto;
                g.created_at = t0() - SignedDuration::from_hours(age);
                g
            },
        )
}

fn item_strategy() -> impl Strategy<Value = ItemMeta> {
    let (ws, ids) = pools();
    (
        proptest::sample::select(ws),
        proptest::sample::select(ids),
        env_strategy(),
        proptest::sample::select(vec!["Web login", "API key", "Other"]),
        pick(vec!["shop", "billing", "misc"]),
        proptest::sample::select(vec![ItemKind::WebLogin, ItemKind::ApiKey, ItemKind::Note]),
        proptest::option::of(proptest::sample::select(vec![
            "admin",
            "read-only",
            "Admin",
        ])),
    )
        .prop_map(
            |(workspace_id, id, environment, category, tags, kind, role_label)| {
                let spec = ItemSpec {
                    workspace_id,
                    kind,
                    environment,
                    category,
                    tags,
                    role_label,
                    expires_at: None,
                };
                spec.meta(id)
            },
        )
}

fn agent() -> AgentId {
    AgentId(uuid_of(1))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// No grant of this agent means no access, whatever other agents have.
    #[test]
    fn prop_no_grant_no_access(
        others in proptest::collection::vec(grant_strategy(AgentId(uuid_of(2))), 0..6),
        meta in item_strategy(),
        reason in proptest::option::of(".{0,40}"),
    ) {
        for p in ALL_PERMISSIONS {
            prop_assert_eq!(decide(&others, &agent(), &meta, p, reason.as_deref()), Decision::NoGrant);
        }
    }

    /// A matching deny grant wins over any set of other grants.
    #[test]
    fn prop_deny_always_wins(
        mut grants in proptest::collection::vec(grant_strategy(agent()), 0..8),
        meta in item_strategy(),
        deny_perms in pick(ALL_PERMISSIONS.to_vec()),
        reason in proptest::option::of(".{0,40}"),
    ) {
        let deny = grant(agent(), Selector::default(), &deny_perms, GrantMode::Deny);
        grants.push(deny);
        for p in ALL_PERMISSIONS {
            let covered = deny_perms.is_empty()
                || deny_perms.contains(&p)
                || (p == Permission::Find && (deny_perms.contains(&Permission::Read) || deny_perms.contains(&Permission::UseSsh)));
            let decision = decide(&grants, &agent(), &meta, p, reason.as_deref());
            if covered {
                prop_assert!(matches!(decision, Decision::Deny { .. }), "{:?}", decision);
            }
            prop_assert!(!(decision.is_allow() && grants.iter().any(|g| g.mode == GrantMode::Deny && g.permissions.is_empty() && selector_matches(&g.selector, &PolicyItem::of(&meta)))));
        }
    }

    /// The reason words never change a decision: two reasons that are both present (or both
    /// absent) give the same result.
    #[test]
    fn prop_reason_text_never_changes_decision(
        grants in proptest::collection::vec(grant_strategy(agent()), 0..8),
        meta in item_strategy(),
        a in ".{8,60}",
        b in ".{8,60}",
        short in ".{0,7}",
    ) {
        prop_assume!(reason_present(Some(&a)) && reason_present(Some(&b)));
        prop_assume!(!reason_present(Some(&short)));
        for p in ALL_PERMISSIONS {
            prop_assert_eq!(decide(&grants, &agent(), &meta, p, Some(&a)), decide(&grants, &agent(), &meta, p, Some(&b)));
            prop_assert_eq!(decide(&grants, &agent(), &meta, p, Some(&short)), decide(&grants, &agent(), &meta, p, None));
        }
    }

    /// The simulator gives the same decision as the evaluator for every item and permission.
    #[test]
    fn prop_simulator_matches_evaluator(
        grants in proptest::collection::vec(grant_strategy(agent()), 0..8),
        items in proptest::collection::vec(item_strategy(), 1..6),
    ) {
        let mut seen = std::collections::HashSet::new();
        let items: Vec<ItemMeta> = items.into_iter().filter(|m| seen.insert(m.id)).collect();
        let rows = simulate_rows(&grants, items.iter(), &agent(), t0(), &NoCount);
        prop_assert_eq!(rows.len(), items.len() * ALL_PERMISSIONS.len());
        for row in &rows {
            let meta = items.iter().find(|m| m.id == row.item_id).unwrap();
            prop_assert_eq!(&row.decision, &decide(&grants, &agent(), meta, row.permission, None));
        }
    }

    /// The chosen grant is never less specific than another allowing grant that matches.
    #[test]
    fn prop_choice_is_most_specific(
        grants in proptest::collection::vec(grant_strategy(agent()), 1..8),
        meta in item_strategy(),
    ) {
        let grants: Vec<Grant> = grants.into_iter().filter(|g| g.mode != GrantMode::Deny).collect();
        for p in ALL_PERMISSIONS {
            let decision = decide(&grants, &agent(), &meta, p, Some("a long enough reason"));
            if let Some(id) = decision.grant_id() {
                let chosen = grants.iter().find(|g| g.id == id).unwrap();
                let best = grants
                    .iter()
                    .filter(|g| selector_matches(&g.selector, &PolicyItem::of(&meta)))
                    .filter(|g| {
                        g.permissions.contains(&p)
                            || (p == Permission::Find && (g.permissions.contains(&Permission::Read) || g.permissions.contains(&Permission::UseSsh)))
                    })
                    .map(|g| specificity(&g.selector))
                    .max()
                    .unwrap();
                prop_assert_eq!(specificity(&chosen.selector), best);
            }
        }
    }
}
