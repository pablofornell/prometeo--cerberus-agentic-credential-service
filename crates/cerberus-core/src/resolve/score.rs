//! The scorer of ADR-0020. Plain functions over the index; no payload, no policy state.

use std::collections::BTreeSet;

use cerberus_types::{Environment, ItemKind, NoMatchHints};
use jiff::Timestamp;

use super::{CONFIDENCE_GAP, MAX_CANDIDATES, ResolveMode, ResolveOutcome, ResolveRequest, Scored};
use crate::index::{CreatedBy, Index, ItemMeta, WorkspaceMeta, words};

const APP_WORKSPACE: u32 = 100;
const APP_TARGET: u32 = 60;
const ROLE_EXACT: u32 = 50;
const ROLE_WORD: u32 = 20;
const HINT_TITLE: u32 = 10;
const HINT_TITLE_MAX: u32 = 30;
const HINT_OTHER: u32 = 5;
const HINT_OTHER_MAX: u32 = 20;

/// Role synonym classes (ADR-0020 point 4), in canonical form.
const ROLE_CLASSES: [&[&str]; 3] = [
    &["admin", "administrator", "superuser", "root"],
    &["user", "normal-user", "standard", "regular", "default"],
    &["read-only", "readonly", "ro", "viewer", "read"],
];

const ALL_KINDS: [ItemKind; 10] = [
    ItemKind::WebLogin,
    ItemKind::ApiKey,
    ItemKind::SshKey,
    ItemKind::SessionToken,
    ItemKind::BrowserSession,
    ItemKind::Database,
    ItemKind::Cloud,
    ItemKind::Certificate,
    ItemKind::EnvBundle,
    ItemKind::Note,
];

const ALL_ENVIRONMENTS: [Environment; 4] = [
    Environment::Dev,
    Environment::Staging,
    Environment::Prod,
    Environment::Other,
];

/// The canonical form of a name: its words, lower case, joined by `-`. So `Shop Frontend`,
/// `shop_frontend` and `shop-frontend` are the same name.
fn canon(text: &str) -> String {
    words(text)
        .iter()
        .map(|w| w.as_str())
        .collect::<Vec<_>>()
        .join("-")
}

fn word_list(text: &str) -> Vec<String> {
    words(text).iter().map(|w| w.to_string()).collect()
}

/// The environment named by `text`, with the synonyms of ADR-0020 point 3.
fn parse_environment(text: &str) -> Option<Environment> {
    match canon(text).as_str() {
        "prod" | "production" => Some(Environment::Prod),
        "staging" | "stage" | "stg" => Some(Environment::Staging),
        "dev" | "development" | "local" => Some(Environment::Dev),
        "other" => Some(Environment::Other),
        _ => None,
    }
}

/// The host part of a URL, or the text itself when it has no scheme.
fn host_of(target: &str) -> &str {
    let rest = target.split_once("://").map_or(target, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host)
}

/// True when `needle` appears in `hay` as a run of whole words.
fn contains_run(hay: &[String], needle: &[String]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn workspace_matches(ws: &WorkspaceMeta, app: &str) -> bool {
    std::iter::once(&ws.slug)
        .chain(std::iter::once(&ws.name))
        .chain(ws.aliases.iter())
        .any(|name| canon(name) == app)
}

/// The texts of an item that name its target: `target`, and the SSH `machine` and `host`.
fn target_names(meta: &ItemMeta) -> impl Iterator<Item = &str> {
    meta.target.iter().map(|t| t.as_str()).chain(
        ["machine", "host"]
            .iter()
            .filter_map(|k| meta.custom.get(*k).map(|v| v.as_str())),
    )
}

/// Step 2: the app score, or `None` when the item does not match the app.
fn app_score(index: &Index, meta: &ItemMeta, app: &str, app_words: &[String]) -> Option<u32> {
    if index
        .workspace(&meta.workspace_id)
        .is_some_and(|ws| workspace_matches(ws, app))
    {
        return Some(APP_WORKSPACE);
    }
    target_names(meta)
        .any(|t| {
            canon(t) == app || canon(host_of(t)) == app || contains_run(&word_list(t), app_words)
        })
        .then_some(APP_TARGET)
}

fn role_class(canonical: &str) -> Option<usize> {
    ROLE_CLASSES.iter().position(|c| c.contains(&canonical))
}

/// Step 4: +50 for the same label or class, +20 for a shared word, `None` for no match.
fn role_score(wanted: &str, label: &str) -> Option<u32> {
    let (want, have) = (canon(wanted), canon(label));
    if want == have || role_class(&want).is_some_and(|c| role_class(&have) == Some(c)) {
        return Some(ROLE_EXACT);
    }
    let have_words = word_list(label);
    word_list(wanted)
        .iter()
        .any(|w| have_words.contains(w))
        .then_some(ROLE_WORD)
}

/// Step 5: hint words in the title (+10 each, max 30) and elsewhere (+5 each, max 20).
fn hint_score(meta: &ItemMeta, hint_words: &[String]) -> u32 {
    let title = word_list(&meta.title);
    let other: Vec<String> = word_list(&meta.description)
        .into_iter()
        .chain(meta.tags.iter().flat_map(|t| word_list(t)))
        .chain(target_names(meta).flat_map(word_list))
        .collect();
    let (mut in_title, mut elsewhere) = (0, 0);
    for word in hint_words {
        if title.contains(word) {
            in_title += HINT_TITLE;
        } else if other.contains(word) {
            elsewhere += HINT_OTHER;
        }
    }
    in_title.min(HINT_TITLE_MAX) + elsewhere.min(HINT_OTHER_MAX)
}

const fn by_agent(meta: &ItemMeta) -> bool {
    matches!(meta.created_by, CreatedBy::Agent(_))
}

/// AUD-23, DEC-T27-A2-5: an agent writes the title, description and tags of its own items, so
/// hint points must not let an agent item win over an operator item. The first item of the
/// sorted list is a clear winner when an operator made it, or when its score without hint
/// points still beats every operator item by [`CONFIDENCE_GAP`]. Else the outcome is ambiguous
/// and the caller chooses.
fn agent_winner_is_clear(sorted: &[(&ItemMeta, u32, u32)]) -> bool {
    let Some((first, _, fixed)) = sorted.first() else {
        return true;
    };
    if !by_agent(first) {
        return true;
    }
    sorted
        .iter()
        .filter(|(m, _, _)| !by_agent(m))
        .all(|(_, score, _)| *fixed >= score + CONFIDENCE_GAP)
}

fn live(meta: &ItemMeta, now: Timestamp) -> bool {
    meta.expires_at.is_none_or(|at| now < at)
}

/// Hints for a 404, from the items that matched the app (all visible to the agent).
fn hints(app_known: bool, matched: &[&ItemMeta]) -> NoMatchHints {
    let roles: BTreeSet<String> = matched
        .iter()
        .filter_map(|m| m.role_label.as_ref().map(|s| s.as_str().to_owned()))
        .collect();
    NoMatchHints {
        app_known,
        environments: ALL_ENVIRONMENTS
            .into_iter()
            .filter(|e| matched.iter().any(|m| m.environment == *e))
            .collect(),
        roles: roles.into_iter().collect(),
        kinds: ALL_KINDS
            .into_iter()
            .filter(|k| matched.iter().any(|m| m.kind == *k))
            .collect(),
    }
}

/// Resolves `req` against the index (ADR-0020 steps 1 to 6 and the outcome rules).
///
/// `visible` is rule 1: true when policy gives `find`. Expired items are dropped first.
#[must_use]
pub fn resolve(
    index: &Index,
    req: &ResolveRequest,
    now: Timestamp,
    visible: &dyn Fn(&ItemMeta) -> bool,
) -> ResolveOutcome {
    let app = canon(&req.app);
    let app_words = word_list(&req.app);
    let seen: Vec<&ItemMeta> = index
        .iter_items()
        .filter(|m| live(m, now) && visible(m))
        .collect();
    let by_app: Vec<(&ItemMeta, u32)> = seen
        .iter()
        .filter_map(|m| app_score(index, m, &app, &app_words).map(|s| (*m, s)))
        .collect();
    let matched: Vec<&ItemMeta> = by_app.iter().map(|(m, _)| *m).collect();
    if matched.is_empty() {
        return ResolveOutcome::NoMatch(hints(false, &matched));
    }
    let wanted_env = req.environment.as_deref().map(parse_environment);
    let hint_words = req.hint.as_deref().map(word_list).unwrap_or_default();
    // (item, total score, score without hint points).
    let mut scored: Vec<(&ItemMeta, u32, u32)> = Vec::new();
    for (meta, base) in by_app {
        // `Some(None)` is an environment name nobody knows: it matches nothing.
        if wanted_env.is_some_and(|e| e != Some(meta.environment)) {
            continue;
        }
        if req.kind.is_some_and(|k| k != meta.kind) {
            continue;
        }
        let role = match (req.role.as_deref(), meta.role_label.as_deref()) {
            (None, _) => 0,
            (Some(wanted), Some(label)) => match role_score(wanted, label) {
                Some(points) => points,
                None => continue,
            },
            (Some(_), None) => continue,
        };
        let fixed = base + role;
        scored.push((meta, fixed + hint_score(meta, &hint_words), fixed));
    }
    if scored.is_empty() {
        return ResolveOutcome::NoMatch(hints(true, &matched));
    }
    // On an equal score an operator item comes first (AUD-23).
    scored.sort_by(|(a, sa, _), (b, sb, _)| {
        sb.cmp(sa)
            .then(by_agent(a).cmp(&by_agent(b)))
            .then(b.updated_at.cmp(&a.updated_at))
            .then(a.id.cmp(&b.id))
    });
    let list: Vec<Scored> = scored
        .iter()
        .take(MAX_CANDIDATES)
        .map(|(m, s, _)| Scored {
            item_id: m.id,
            score: *s,
        })
        .collect();
    if req.mode == ResolveMode::Candidates {
        return ResolveOutcome::Candidates(list);
    }
    let confident = match list.as_slice() {
        [only] => Some(*only),
        [first, second, ..] if first.score >= second.score + CONFIDENCE_GAP => Some(*first),
        _ => None,
    }
    .filter(|_| agent_winner_is_clear(&scored));
    confident.map_or(ResolveOutcome::Ambiguous(list), ResolveOutcome::Confident)
}
