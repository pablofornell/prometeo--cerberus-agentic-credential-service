//! Resolve tests: a table of cases over a fixed index, policy handling, and the rule that no
//! candidate output holds a secret.

use std::collections::{BTreeMap, BTreeSet};

use cerberus_types::{
    Environment, FieldProblem, ItemId, ItemKind, KeySlotId, NoMatchHints, WorkspaceId, t0,
};
use jiff::SignedDuration;
use zeroize::Zeroizing;

use super::{
    MAX_CANDIDATES, ReadAccess, Resolution, ResolveMode, ResolveOutcome, ResolvePolicy,
    ResolveRequest, resolve,
};
use crate::error::CoreError;
use crate::index::{CreatedBy, Index, ItemMeta, WorkspaceMeta};
use crate::items::tests::fixture::{Fx, input, login_payload, session_payload, totp_login_payload};
use crate::items::{Payload, generate_ed25519};

fn z(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

struct Spec {
    title: &'static str,
    ws: usize,
    kind: ItemKind,
    role: Option<&'static str>,
    env: Environment,
    target: Option<&'static str>,
    desc: &'static str,
    tags: &'static [&'static str],
    custom: &'static [(&'static str, &'static str)],
    /// Minutes after `t0`. A later item is newer.
    age: i64,
    expires_in_minutes: Option<i64>,
}

const fn spec(title: &'static str, ws: usize, kind: ItemKind, env: Environment, age: i64) -> Spec {
    Spec {
        title,
        ws,
        kind,
        role: None,
        env,
        target: None,
        desc: "",
        tags: &[],
        custom: &[],
        age,
        expires_in_minutes: None,
    }
}

fn base_specs() -> Vec<Spec> {
    use Environment::{Dev, Other, Prod, Staging};
    use ItemKind::{ApiKey, Database, SshKey, WebLogin};
    vec![
        Spec {
            role: Some("admin"),
            target: Some("https://staging.shop.example.test"),
            desc: "Admin login for the staging shop",
            ..spec("Shop staging admin", 0, WebLogin, Staging, 1)
        },
        Spec {
            role: Some("normal user"),
            target: Some("https://staging.shop.example.test"),
            ..spec("Shop staging user", 0, WebLogin, Staging, 2)
        },
        Spec {
            role: Some("SAI user"),
            target: Some("https://staging.shop.example.test"),
            ..spec("Shop staging SAI user", 0, WebLogin, Staging, 3)
        },
        Spec {
            role: Some("read-only"),
            target: Some("https://staging.shop.example.test"),
            ..spec("Shop staging reader", 0, WebLogin, Staging, 4)
        },
        Spec {
            role: Some("admin"),
            target: Some("https://shop.example.test"),
            ..spec("Shop prod admin", 0, WebLogin, Prod, 5)
        },
        Spec {
            role: Some("admin"),
            target: Some("http://localhost:3000"),
            ..spec("Shop dev admin", 0, WebLogin, Dev, 6)
        },
        Spec {
            desc: "key for the payments sandbox",
            tags: &["payments"],
            ..spec("Shop staging API key", 0, ApiKey, Staging, 7)
        },
        Spec {
            role: Some("admin"),
            ..spec("Billing staging admin", 1, WebLogin, Staging, 8)
        },
        Spec {
            role: Some("root"),
            ..spec("Billing prod database", 1, Database, Prod, 9)
        },
        Spec {
            role: Some("deploy"),
            target: Some("build-01"),
            custom: &[
                ("machine", "build-01"),
                ("host", "10.0.0.5"),
                ("user", "deploy"),
            ],
            ..spec("Build server deploy", 2, SshKey, Other, 10)
        },
        Spec {
            role: Some("deploy"),
            target: Some("build-02"),
            ..spec("Jump host maintenance", 2, SshKey, Other, 11)
        },
        Spec {
            role: Some("admin"),
            expires_in_minutes: Some(-60),
            ..spec("Shop expired admin", 0, WebLogin, Staging, 12)
        },
    ]
}

fn workspaces() -> Vec<WorkspaceMeta> {
    let make = |slug: &str, name: &str, aliases: &[&str]| WorkspaceMeta {
        id: WorkspaceId::generate(),
        slug: z(slug),
        name: z(name),
        description: z(""),
        aliases: aliases.iter().map(|a| z(a)).collect(),
        updated_at: t0(),
    };
    vec![
        make("shop-frontend", "Shop Frontend", &["shop", "storefront"]),
        make("billing-api", "Billing API", &[]),
        make("infra", "Infrastructure", &[]),
    ]
}

fn build(specs: &[Spec], ws: &[WorkspaceMeta]) -> Index {
    build_by(specs, ws, &[])
}

/// As [`build`]; the items with a title in `agent_titles` are made by an agent.
fn build_by(specs: &[Spec], ws: &[WorkspaceMeta], agent_titles: &[&str]) -> Index {
    let items = specs
        .iter()
        .map(|s| ItemMeta {
            id: ItemId::generate(),
            kind: s.kind,
            workspace_id: ws[s.ws].id,
            title: z(s.title),
            description: z(s.desc),
            role_label: s.role.map(z),
            category: z("Other"),
            tags: s.tags.iter().map(|t| z(t)).collect(),
            environment: s.env,
            target: s.target.map(z),
            created_by: if agent_titles.contains(&s.title) {
                CreatedBy::Agent(cerberus_types::AgentId::generate())
            } else {
                CreatedBy::Operator(KeySlotId::generate())
            },
            max_uses: None,
            use_count: 0,
            expires_at: s
                .expires_in_minutes
                .map(|m| t0() + SignedDuration::from_mins(m)),
            updated_at: t0() + SignedDuration::from_mins(s.age),
            has_totp: false,
            custom: s
                .custom
                .iter()
                .map(|(k, v)| ((*k).to_owned(), z(v)))
                .collect::<BTreeMap<_, _>>(),
        })
        .collect();
    Index::build(items, ws.to_vec(), Vec::new())
}

fn req(app: &str, env: Option<&str>, role: Option<&str>) -> ResolveRequest {
    ResolveRequest {
        environment: env.map(str::to_owned),
        role: role.map(str::to_owned),
        ..ResolveRequest::new(app, "run the tests")
    }
}

enum Expect {
    Best(&'static str, u32),
    Ambiguous(&'static [&'static str]),
    /// In this order.
    Candidates(&'static [&'static str]),
    NoMatch {
        app_known: bool,
        envs: &'static [Environment],
        roles: &'static [&'static str],
        kinds: &'static [ItemKind],
    },
}

use Expect::{Ambiguous, Best, Candidates, NoMatch};

fn titles(index: &Index, list: &[super::Scored]) -> Vec<String> {
    list.iter()
        .map(|s| index.item(&s.item_id).unwrap().title.to_string())
        .collect()
}

fn check(name: &str, index: &Index, request: &ResolveRequest, expect: &Expect) {
    let outcome = resolve(
        index,
        request,
        t0() + SignedDuration::from_mins(30),
        &|_| true,
    );
    match (expect, outcome) {
        (Best(title, score), ResolveOutcome::Confident(got)) => {
            assert_eq!(
                index.item(&got.item_id).unwrap().title.as_str(),
                *title,
                "{name}"
            );
            assert_eq!(got.score, *score, "{name}: score");
        }
        (Ambiguous(want), ResolveOutcome::Ambiguous(got)) => {
            let got: BTreeSet<_> = titles(index, &got).into_iter().collect();
            let want: BTreeSet<_> = want.iter().map(|t| (*t).to_owned()).collect();
            assert_eq!(got, want, "{name}");
        }
        (Candidates(want), ResolveOutcome::Candidates(got)) => {
            assert_eq!(titles(index, &got), *want, "{name}");
        }
        (
            NoMatch {
                app_known,
                envs,
                roles,
                kinds,
            },
            ResolveOutcome::NoMatch(got),
        ) => {
            let want = NoMatchHints {
                app_known: *app_known,
                environments: envs.to_vec(),
                roles: roles.iter().map(|r| (*r).to_owned()).collect(),
                kinds: kinds.to_vec(),
            };
            assert_eq!(got, want, "{name}");
        }
        (_, other) => panic!("{name}: unexpected outcome {other:?}"),
    }
}

use Environment::{Dev, Other, Prod, Staging};
use ItemKind::{ApiKey, Database, SshKey, WebLogin};

const SHOP_ROLES: &[&str] = &["SAI user", "admin", "normal user", "read-only"];

#[test]
fn table_of_resolve_cases() {
    let ws = workspaces();
    let index = build(&base_specs(), &ws);
    let kind_req = |app: &str, env: Option<&str>, kind: ItemKind| ResolveRequest {
        kind: Some(kind),
        ..req(app, env, None)
    };
    let hint_req = |app: &str, env: &str, hint: &str| ResolveRequest {
        hint: Some(hint.to_owned()),
        ..req(app, Some(env), None)
    };
    let cand = |mut r: ResolveRequest| {
        r.mode = ResolveMode::Candidates;
        r
    };
    let cases: Vec<(&str, ResolveRequest, Expect)> = vec![
        // Acceptance A2 and the app names (steps 2).
        (
            "A2 slug staging admin",
            req("shop-frontend", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "alias shop",
            req("shop", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "alias storefront",
            req("storefront", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "workspace name",
            req("Shop Frontend", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "upper case slug",
            req("SHOP-FRONTEND", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "underscore slug",
            req("shop_frontend", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "spaces around app",
            req("  shop  ", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "other workspace",
            req("billing-api", Some("staging"), Some("admin")),
            Best("Billing staging admin", 150),
        ),
        (
            "workspace name with space",
            req("Billing API", Some("staging"), Some("admin")),
            Best("Billing staging admin", 150),
        ),
        // Environments and synonyms (step 3).
        (
            "prod vs staging: prod",
            req("shop", Some("prod"), Some("admin")),
            Best("Shop prod admin", 150),
        ),
        (
            "production synonym",
            req("shop", Some("production"), Some("admin")),
            Best("Shop prod admin", 150),
        ),
        (
            "dev",
            req("shop", Some("dev"), Some("admin")),
            Best("Shop dev admin", 150),
        ),
        (
            "development synonym",
            req("shop", Some("Development"), Some("admin")),
            Best("Shop dev admin", 150),
        ),
        (
            "local synonym",
            req("shop", Some("local"), Some("admin")),
            Best("Shop dev admin", 150),
        ),
        (
            "stage synonym",
            req("shop", Some("stage"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "stg synonym",
            req("shop", Some("STG"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
        (
            "unknown environment",
            req("shop", Some("qa"), Some("admin")),
            NoMatch {
                app_known: true,
                envs: &[Dev, Staging, Prod],
                roles: SHOP_ROLES,
                kinds: &[WebLogin, ApiKey],
            },
        ),
        // The environment is never guessed.
        (
            "no environment: three admins tie",
            req("shop", None, Some("admin")),
            Ambiguous(&["Shop staging admin", "Shop prod admin", "Shop dev admin"]),
        ),
        // Role synonyms (step 4).
        (
            "administrator",
            req("shop", Some("staging"), Some("administrator")),
            Best("Shop staging admin", 150),
        ),
        (
            "root is admin",
            req("shop", Some("staging"), Some("root")),
            Best("Shop staging admin", 150),
        ),
        (
            "superuser is admin",
            req("shop", Some("staging"), Some("superuser")),
            Best("Shop staging admin", 150),
        ),
        (
            "role with spaces and case",
            req("shop", Some("staging"), Some("  ADMIN ")),
            Best("Shop staging admin", 150),
        ),
        (
            "user matches normal user",
            req("shop", Some("staging"), Some("user")),
            Best("Shop staging user", 150),
        ),
        (
            "standard is user",
            req("shop", Some("staging"), Some("standard")),
            Best("Shop staging user", 150),
        ),
        (
            "normal user exact",
            req("shop", Some("staging"), Some("normal user")),
            Best("Shop staging user", 150),
        ),
        (
            "custom label exact",
            req("shop", Some("staging"), Some("SAI user")),
            Best("Shop staging SAI user", 150),
        ),
        (
            "custom label by word",
            req("shop", Some("staging"), Some("sai")),
            Best("Shop staging SAI user", 120),
        ),
        (
            "read-only",
            req("shop", Some("staging"), Some("read-only")),
            Best("Shop staging reader", 150),
        ),
        (
            "readonly spelling",
            req("shop", Some("staging"), Some("readonly")),
            Best("Shop staging reader", 150),
        ),
        (
            "viewer is read-only",
            req("shop", Some("staging"), Some("viewer")),
            Best("Shop staging reader", 150),
        ),
        (
            "ro is read-only",
            req("shop", Some("staging"), Some("ro")),
            Best("Shop staging reader", 150),
        ),
        (
            "a wrong role is never returned",
            req("shop", Some("staging"), Some("guest")),
            NoMatch {
                app_known: true,
                envs: &[Dev, Staging, Prod],
                roles: SHOP_ROLES,
                kinds: &[WebLogin, ApiKey],
            },
        ),
        (
            "role with no labelled item",
            req("shop", Some("staging"), None),
            Ambiguous(&[
                "Shop staging admin",
                "Shop staging user",
                "Shop staging SAI user",
                "Shop staging reader",
                "Shop staging API key",
            ]),
        ),
        (
            "root synonym on a db",
            req("billing-api", Some("prod"), Some("admin")),
            Best("Billing prod database", 150),
        ),
        // Kind (step 3).
        (
            "kind api_key",
            kind_req("shop", Some("staging"), ApiKey),
            Best("Shop staging API key", 100),
        ),
        (
            "kind database",
            kind_req("billing-api", None, Database),
            Best("Billing prod database", 100),
        ),
        (
            "kind with no item",
            kind_req("shop", None, ItemKind::Note),
            NoMatch {
                app_known: true,
                envs: &[Dev, Staging, Prod],
                roles: SHOP_ROLES,
                kinds: &[WebLogin, ApiKey],
            },
        ),
        // A4 and targets (step 2, score 60).
        (
            "A4 ssh by machine name",
            req("build-01", None, None),
            Best("Build server deploy", 60),
        ),
        (
            "ssh second machine",
            req("build-02", None, None),
            Best("Jump host maintenance", 60),
        ),
        (
            "ssh by custom host",
            req("10.0.0.5", None, None),
            Best("Build server deploy", 60),
        ),
        (
            "ssh kind and workspace",
            kind_req("infra", None, SshKey),
            Ambiguous(&["Build server deploy", "Jump host maintenance"]),
        ),
        (
            "url host equals app",
            req("shop.example.test", Some("prod"), Some("admin")),
            Best("Shop prod admin", 110),
        ),
        (
            "app as whole words of a url",
            req("staging.shop.example.test", Some("staging"), Some("admin")),
            Best("Shop staging admin", 110),
        ),
        (
            "part of a name is not a match",
            req("frontend", None, None),
            NoMatch {
                app_known: false,
                envs: &[],
                roles: &[],
                kinds: &[],
            },
        ),
        (
            "unknown app",
            req("nope", Some("staging"), Some("admin")),
            NoMatch {
                app_known: false,
                envs: &[],
                roles: &[],
                kinds: &[],
            },
        ),
        // Hints (step 5).
        (
            "hint of three title words wins",
            hint_req("infra", "other", "build server deploy"),
            Best("Build server deploy", 130),
        ),
        (
            "one hint word is not enough",
            hint_req("infra", "other", "build"),
            Ambiguous(&["Build server deploy", "Jump host maintenance"]),
        ),
        (
            "hint in title, description and tag",
            hint_req("shop", "staging", "api key payments"),
            Best("Shop staging API key", 125),
        ),
        (
            "hint word in a tag only",
            hint_req("shop", "staging", "payments sandbox"),
            Ambiguous(&[
                "Shop staging admin",
                "Shop staging user",
                "Shop staging SAI user",
                "Shop staging reader",
                "Shop staging API key",
            ]),
        ),
        // Mode candidates and order (step 6).
        (
            "candidates mode with one item",
            cand(req("shop", Some("staging"), Some("admin"))),
            Candidates(&["Shop staging admin"]),
        ),
        (
            "candidates ordered by score",
            cand(req("shop", Some("staging"), Some("user"))),
            Candidates(&["Shop staging user", "Shop staging SAI user"]),
        ),
        (
            "candidates tie goes to the newest",
            cand(req("shop", Some("staging"), None)),
            Candidates(&[
                "Shop staging API key",
                "Shop staging reader",
                "Shop staging SAI user",
                "Shop staging user",
                "Shop staging admin",
            ]),
        ),
        (
            "candidates mode no match",
            cand(req("nope", None, None)),
            NoMatch {
                app_known: false,
                envs: &[],
                roles: &[],
                kinds: &[],
            },
        ),
        // Expiry: the expired admin never shows (A3 reading side).
        (
            "expired item is invisible",
            req("shop", Some("staging"), Some("admin")),
            Best("Shop staging admin", 150),
        ),
    ];
    assert!(cases.len() >= 40, "{} cases", cases.len());
    let _ = (Other, Prod);
    for (name, request, expect) in &cases {
        check(name, &index, request, expect);
    }
}

#[test]
fn confidence_needs_a_gap_of_25_points() {
    let ws = workspaces();
    let mut specs = vec![
        Spec {
            role: Some("admin"),
            ..spec("Alpha one", 0, WebLogin, Staging, 1)
        },
        Spec {
            role: Some("admin"),
            ..spec("Alpha two", 0, WebLogin, Staging, 2)
        },
    ];
    let index = build(&specs, &ws);
    let want = req("shop", Some("staging"), Some("admin"));
    assert!(matches!(
        resolve(&index, &want, t0(), &|_| true),
        ResolveOutcome::Ambiguous(_)
    ));
    // 20 points apart (two title words): ambiguous. 25 or more: confident.
    let hinted = |hint: &str| ResolveRequest {
        hint: Some(hint.to_owned()),
        ..want.clone()
    };
    specs[0].title = "Alpha uno";
    specs[1].title = "Alpha one two three";
    let index = build(&specs, &ws);
    let r = resolve(&index, &hinted("two three"), t0(), &|_| true);
    assert!(
        matches!(r, ResolveOutcome::Ambiguous(_)),
        "20 points: {r:?}"
    );
    let ResolveOutcome::Confident(got) = resolve(&index, &hinted("one two three"), t0(), &|_| true)
    else {
        panic!("30 points should be confident")
    };
    assert_eq!(got.score, 100 + 50 + 30, "three title words");
    // Description words give at most 20 points, so alone they never reach the gap.
    specs[1].title = "Alpha two";
    specs[0].title = "Alpha uno";
    specs[1].desc = "one three four five six seven";
    let index = build(&specs, &ws);
    let r = resolve(
        &index,
        &hinted("one three four five six seven"),
        t0(),
        &|_| true,
    );
    assert!(
        matches!(r, ResolveOutcome::Ambiguous(_)),
        "capped at 20: {r:?}"
    );
}

#[test]
fn at_most_twenty_candidates() {
    let ws = workspaces();
    let titles: Vec<String> = (0..25).map(|i| format!("Item number {i}")).collect();
    let leaked: Vec<&'static str> = titles
        .iter()
        .map(|t| &*Box::leak(t.clone().into_boxed_str()))
        .collect();
    let specs: Vec<Spec> = leaked
        .iter()
        .enumerate()
        .map(|(i, t)| Spec {
            role: Some("admin"),
            ..spec(t, 0, WebLogin, Staging, i64::try_from(i).unwrap())
        })
        .collect();
    let index = build(&specs, &ws);
    let ResolveOutcome::Ambiguous(list) = resolve(
        &index,
        &req("shop", None, None),
        t0() + SignedDuration::from_hours(1),
        &|_| true,
    ) else {
        panic!("wanted ambiguous")
    };
    assert_eq!(list.len(), MAX_CANDIDATES);
    let mut candidates = req("shop", None, None);
    candidates.mode = ResolveMode::Candidates;
    let ResolveOutcome::Candidates(list) = resolve(
        &index,
        &candidates,
        t0() + SignedDuration::from_hours(1),
        &|_| true,
    ) else {
        panic!("wanted candidates")
    };
    assert_eq!(list.len(), MAX_CANDIDATES);
    assert_eq!(
        index.item(&list[0].item_id).unwrap().title.as_str(),
        "Item number 24",
        "newest first"
    );
}

#[test]
fn equal_score_and_time_sort_by_id() {
    let ws = workspaces();
    let specs = vec![
        Spec {
            role: Some("admin"),
            ..spec("Twin A", 0, WebLogin, Staging, 1)
        },
        Spec {
            role: Some("admin"),
            ..spec("Twin B", 0, WebLogin, Staging, 1)
        },
    ];
    let index = build(&specs, &ws);
    let mut r = req("shop", Some("staging"), Some("admin"));
    r.mode = ResolveMode::Candidates;
    let ResolveOutcome::Candidates(list) = resolve(&index, &r, t0(), &|_| true) else {
        panic!("wanted candidates")
    };
    assert!(list[0].item_id < list[1].item_id);
}

#[test]
fn old_machine_names_match_by_whole_word_at_60_and_tie() {
    let ws = workspaces();
    let specs = vec![
        Spec {
            target: Some("build-01"),
            ..spec("Exact", 2, SshKey, Other, 1)
        },
        Spec {
            target: Some("old-build-01-box"),
            ..spec("Contains", 2, SshKey, Other, 2)
        },
        Spec {
            target: Some("build-010"),
            ..spec("Not a whole word", 2, SshKey, Other, 3)
        },
    ];
    let index = build(&specs, &ws);
    let outcome = resolve(&index, &req("build-01", None, None), t0(), &|_| true);
    let ResolveOutcome::Ambiguous(list) = outcome else {
        panic!("two matches at 60 are ambiguous: {outcome:?}")
    };
    assert_eq!(titles(&index, &list).len(), 2);
    assert!(
        titles(&index, &list)
            .iter()
            .all(|t| t != "Not a whole word")
    );
}

#[test]
fn policy_filter_hides_items_and_their_hints() {
    let ws = workspaces();
    let index = build(&base_specs(), &ws);
    let hidden_ws = ws[0].id;
    let only_visible = |m: &ItemMeta| m.workspace_id != hidden_ws;
    let r = resolve(
        &index,
        &req("shop", Some("staging"), Some("admin")),
        t0(),
        &only_visible,
    );
    assert_eq!(
        r,
        ResolveOutcome::NoMatch(NoMatchHints {
            app_known: false,
            environments: vec![],
            roles: vec![],
            kinds: vec![]
        }),
        "an app the agent cannot see looks unknown"
    );
    let hide_admin = |m: &ItemMeta| m.role_label.as_deref().map(String::as_str) != Some("admin");
    let r = resolve(
        &index,
        &req("shop", Some("staging"), Some("admin")),
        t0(),
        &hide_admin,
    );
    let ResolveOutcome::NoMatch(hints) = r else {
        panic!("wanted no match")
    };
    assert!(hints.app_known);
    assert!(!hints.roles.iter().any(|x| x == "admin"), "{hints:?}");
    assert_eq!(hints.environments, [Staging]);
    let only_api = |m: &ItemMeta| m.kind == ApiKey;
    let r = resolve(
        &index,
        &req("shop", Some("staging"), Some("admin")),
        t0(),
        &only_api,
    );
    let ResolveOutcome::NoMatch(hints) = r else {
        panic!("wanted no match")
    };
    assert_eq!((hints.roles.len(), hints.kinds), (0, vec![ApiKey]));
}

#[test]
fn request_limits() {
    let fields = |r: ResolveRequest| match r.validate() {
        Ok(()) => Vec::new(),
        Err(CoreError::Validation(list)) => list
            .into_iter()
            .map(|FieldProblem { field, .. }| field)
            .collect(),
        Err(other) => panic!("{other:?}"),
    };
    assert!(fields(req("a", None, None)).is_empty());
    assert_eq!(fields(ResolveRequest::new("", "why")), ["app"]);
    assert_eq!(fields(ResolveRequest::new("a".repeat(129), "why")), ["app"]);
    assert_eq!(fields(ResolveRequest::new("a", "")), ["purpose"]);
    assert_eq!(
        fields(ResolveRequest::new("a", "p".repeat(501))),
        ["purpose"]
    );
    let mut r = ResolveRequest::new("a", "why");
    r.hint = Some("h".repeat(257));
    assert_eq!(fields(r), ["hint"]);
    let json = r#"{"app":"a","purpose":"p","mode":"candidates","kind":"ssh_key"}"#;
    let parsed: ResolveRequest = serde_json::from_str(json).unwrap();
    assert_eq!(
        (parsed.mode, parsed.kind),
        (ResolveMode::Candidates, Some(ItemKind::SshKey))
    );
    assert!(
        serde_json::from_str::<ResolveRequest>(r#"{"app":"a","purpose":"p","extra":1}"#).is_err()
    );
    assert_eq!(
        serde_json::from_str::<ResolveRequest>(r#"{"app":"a","purpose":"p"}"#)
            .unwrap()
            .mode,
        ResolveMode::Best
    );
}

/// A policy for tests: hides some items and gives a fixed read answer.
struct FakePolicy {
    hidden: BTreeSet<ItemId>,
    read: fn() -> Result<ReadAccess, CoreError>,
}

impl ResolvePolicy for FakePolicy {
    fn can_find(&self, item: &ItemMeta) -> bool {
        !self.hidden.contains(&item.id)
    }

    fn read_access(&self, _item: &ItemMeta) -> Result<ReadAccess, CoreError> {
        (self.read)()
    }
}

fn policy(read: fn() -> Result<ReadAccess, CoreError>) -> FakePolicy {
    FakePolicy {
        hidden: BTreeSet::new(),
        read,
    }
}

#[tokio::test]
async fn service_asks_policy_about_the_winner_only() {
    let fx = Fx::new().await;
    let id = fx
        .create(input(
            fx.ws,
            "Staging admin",
            login_payload("alice", "fake-pw-1"),
        ))
        .await;
    let request = req("shop-frontend", Some("staging"), Some("admin"));
    let granted = fx
        .service
        .resolve(&request, &policy(|| Ok(ReadAccess::Granted)))
        .await
        .unwrap();
    let Resolution::Best {
        item,
        access,
        score,
    } = granted
    else {
        panic!("wanted best")
    };
    assert_eq!((item.id, access, score), (id, ReadAccess::Granted, 150));
    let ask = fx
        .service
        .resolve(&request, &policy(|| Ok(ReadAccess::NeedsApproval)))
        .await
        .unwrap();
    assert!(matches!(
        ask,
        Resolution::Best {
            access: ReadAccess::NeedsApproval,
            ..
        }
    ));
    for refusal in [
        (|| Err(CoreError::Forbidden)) as fn() -> Result<ReadAccess, CoreError>,
        || Err(CoreError::ReasonRequired),
        || Err(CoreError::ApprovalUnavailable),
    ] {
        let denied = fx.service.resolve(&request, &policy(refusal)).await;
        assert!(denied.is_err(), "{denied:?}");
    }
    let mut candidates = request.clone();
    candidates.mode = ResolveMode::Candidates;
    let never_read = policy(|| Err(CoreError::Forbidden));
    let listed = fx.service.resolve(&candidates, &never_read).await.unwrap();
    assert!(
        matches!(listed, Resolution::Candidates(ref l) if l.len() == 1),
        "candidates need no read check"
    );
}

#[tokio::test]
async fn service_filters_invisible_items_and_reports_no_match() {
    let fx = Fx::new().await;
    let hidden = fx
        .create(input(fx.ws, "Staging admin", login_payload("alice", "p")))
        .await;
    let p = FakePolicy {
        hidden: BTreeSet::from([hidden]),
        read: || Ok(ReadAccess::Granted),
    };
    let r = fx
        .service
        .resolve(&req("shop", Some("staging"), Some("admin")), &p)
        .await;
    let Err(CoreError::NoMatch(hints)) = r else {
        panic!("wanted no match: {r:?}")
    };
    assert!(!hints.app_known);
    let bad = fx.service.resolve(&ResolveRequest::new("", "x"), &p).await;
    assert!(matches!(bad, Err(CoreError::Validation(_))));
}

#[tokio::test]
async fn resolve_drops_items_the_moment_they_expire() {
    let fx = Fx::new().await;
    fx.service
        .create_item_as_operator(&fx.ctx, {
            let mut item = input(fx.ws, "QA session", session_payload("fake-token"));
            item.expires_at = Some(fx.now() + SignedDuration::from_secs(3600));
            item
        })
        .await
        .unwrap();
    let p = policy(|| Ok(ReadAccess::Granted));
    let r = req("shop", None, None);
    assert!(fx.service.resolve(&r, &p).await.is_ok());
    fx.advance(3600);
    assert!(matches!(
        fx.service.resolve(&r, &p).await,
        Err(CoreError::NoMatch(_))
    ));
}

/// No candidate, answer or hint can hold a secret: the type has no field for it, and a marker
/// test over the JSON and the `Debug` text proves it for every kind.
#[tokio::test]
async fn no_output_contains_a_secret_marker() {
    let fx = Fx::new().await;
    let seed = "MARKERSEEDMARKERSEEDMARKERSEEDMA";
    let ssh = generate_ed25519("fake@test").unwrap();
    let ssh_body = match &ssh {
        Payload::SshKey { private_key, .. } => private_key
            .expose_secret()
            .lines()
            .nth(2)
            .unwrap()
            .to_owned(),
        _ => unreachable!("ssh key"),
    };
    let secrets: Vec<(&str, Payload)> = vec![
        ("marker-pass-71", totp_login_payload(seed)),
        ("marker-token-72", session_payload("marker-token-72")),
        (
            "marker-key-73",
            Payload::ApiKey {
                key: super::super::items::tests::fixture::secret("marker-key-73"),
                key_id: None,
                header_name: None,
                base_url: None,
            },
        ),
        (
            "marker-note-74",
            Payload::Note {
                text: super::super::items::tests::fixture::secret("marker-note-74"),
            },
        ),
        (
            "marker-db-75",
            Payload::Database {
                url: Some(super::super::items::tests::fixture::secret(
                    "postgres://marker-db-75@h/d",
                )),
                engine: None,
                host: None,
                port: None,
                database: None,
                username: None,
                password: None,
                params: BTreeMap::new(),
            },
        ),
        ("ssh body", ssh),
    ];
    let mut needles = vec![seed.to_owned(), ssh_body, "marker-pass-71".to_owned()];
    for (i, (marker, payload)) in secrets.into_iter().enumerate() {
        let payload = match payload {
            Payload::WebLogin {
                username,
                url,
                totp,
                ..
            } => Payload::WebLogin {
                username,
                password: super::super::items::tests::fixture::secret(marker),
                url,
                totp,
            },
            other => other,
        };
        needles.push(marker.to_owned());
        let mut item = input(fx.ws, &format!("Item {i}"), payload);
        item.role_label = Some("admin".into());
        fx.create(item).await;
    }
    let mut r = req("shop", Some("staging"), Some("admin"));
    r.mode = ResolveMode::Candidates;
    let p = policy(|| Ok(ReadAccess::Granted));
    let answer = fx.service.resolve(&r, &p).await.unwrap();
    let Resolution::Candidates(ref list) = answer else {
        panic!("wanted candidates")
    };
    assert_eq!(list.len(), 6);
    r.mode = ResolveMode::Best;
    let ambiguous = fx.service.resolve(&r, &p).await.unwrap();
    assert!(matches!(ambiguous, Resolution::Ambiguous(_)));
    for output in [&answer, &ambiguous] {
        let (Resolution::Candidates(list) | Resolution::Ambiguous(list)) = output else {
            unreachable!("lists")
        };
        let json = serde_json::to_string(list).unwrap();
        let debug = format!("{output:?}");
        for needle in &needles {
            assert!(!json.contains(needle.as_str()), "json holds {needle}");
            assert!(!debug.contains(needle.as_str()), "debug holds {needle}");
        }
        assert!(
            json.contains("has_totp"),
            "the flag is shown, the seed is not"
        );
    }
    let hints = fx
        .service
        .resolve(&req("shop", Some("prod"), Some("admin")), &p)
        .await;
    let Err(CoreError::NoMatch(h)) = hints else {
        panic!("wanted no match")
    };
    let text = format!("{h:?}");
    assert!(needles.iter().all(|n| !text.contains(n.as_str())));
}

/// Two deploy keys of the same app, environment and role: one from an operator, one that an
/// agent made with the hint words in its title (AUD-23).
fn creator_specs() -> Vec<Spec> {
    vec![
        Spec {
            role: Some("deploy"),
            ..spec("Shop staging deploy", 0, ApiKey, Staging, 1)
        },
        Spec {
            role: Some("deploy"),
            ..spec(
                "Shop staging deploy release token pipeline",
                0,
                ApiKey,
                Staging,
                2,
            )
        },
    ]
}

/// AUD-23: hint words that an agent wrote into its own item do not make it the confident
/// winner over an operator item with the same app, environment and role.
#[test]
fn an_agent_item_does_not_win_over_an_operator_item_by_hint_words() {
    let ws = workspaces();
    let index = build_by(
        &creator_specs(),
        &ws,
        &["Shop staging deploy release token pipeline"],
    );
    let request = ResolveRequest {
        hint: Some("release token pipeline".to_owned()),
        ..req("shop", Some("staging"), Some("deploy"))
    };
    check(
        "agent hint words",
        &index,
        &request,
        &Ambiguous(&[
            "Shop staging deploy",
            "Shop staging deploy release token pipeline",
        ]),
    );
    // The same items, both from an operator: the hint words decide.
    let index = build(&creator_specs(), &ws);
    check(
        "operator hint words",
        &index,
        &request,
        &Best("Shop staging deploy release token pipeline", 180),
    );
    // An agent item alone still wins.
    let alone = build_by(
        &creator_specs()[1..],
        &ws,
        &["Shop staging deploy release token pipeline"],
    );
    check(
        "agent item alone",
        &alone,
        &request,
        &Best("Shop staging deploy release token pipeline", 180),
    );
}

/// AUD-23: on an equal score an operator item comes before a newer agent item.
#[test]
fn on_an_equal_score_the_operator_item_comes_first() {
    let ws = workspaces();
    let index = build_by(
        &creator_specs(),
        &ws,
        &["Shop staging deploy release token pipeline"],
    );
    let request = ResolveRequest {
        mode: ResolveMode::Candidates,
        ..req("shop", Some("staging"), Some("deploy"))
    };
    check(
        "equal score",
        &index,
        &request,
        &Candidates(&[
            "Shop staging deploy",
            "Shop staging deploy release token pipeline",
        ]),
    );
}
