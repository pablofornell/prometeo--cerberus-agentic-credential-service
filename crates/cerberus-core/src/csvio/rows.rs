//! One CSV row to one [`ItemInput`], or to a problem. Problems carry a code and a field name,
//! never a cell value.

use std::collections::BTreeMap;

use cerberus_crypto::SecretString;
use cerberus_types::{Environment, ItemKind, WorkspaceId};

use super::guard::unguard_cell;
use super::plan::ProblemCode;
use super::source::{Columns, CsvSource, Field};
use super::table::Row;
use super::totp_text::parse_seed;
use crate::items::{ItemInput, Payload, validate_item};

/// What the user chose for every row.
pub(crate) struct Targets<'a> {
    pub workspace_id: WorkspaceId,
    pub environment: Environment,
    pub role_label: Option<&'a str>,
}

pub(crate) struct Built {
    pub input: ItemInput,
    /// The row had notes that a login cannot hold.
    pub notes_dropped: bool,
}

pub(crate) type RowResult = Result<Built, (ProblemCode, Option<String>)>;

fn problem(code: ProblemCode) -> (ProblemCode, Option<String>) {
    (code, None)
}

fn invalid(field: &str) -> (ProblemCode, Option<String>) {
    (ProblemCode::InvalidValue, Some(field.to_owned()))
}

fn kind_from(text: &str) -> Result<ItemKind, ()> {
    let key: String = text
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c == ' ' || c == '-' { '_' } else { c })
        .collect();
    match key.as_str() {
        "login" | "web_login" | "weblogin" | "website" | "password" => Ok(ItemKind::WebLogin),
        "note" | "secure_note" | "securenote" => Ok(ItemKind::Note),
        "api_key" | "apikey" | "api" => Ok(ItemKind::ApiKey),
        "session_token" | "token" | "session" => Ok(ItemKind::SessionToken),
        "database" | "db" => Ok(ItemKind::Database),
        "env_bundle" | "env" | "environment_variables" => Ok(ItemKind::EnvBundle),
        _ => Err(()),
    }
}

fn category_of(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::WebLogin => "Web login",
        ItemKind::ApiKey => "API key",
        ItemKind::SessionToken => "Session",
        ItemKind::Database => "Database",
        _ => "Other",
    }
}

fn non_empty(text: Option<&str>) -> Option<&str> {
    text.filter(|t| !t.trim().is_empty())
}

fn http_url(text: &str) -> bool {
    (text.starts_with("https://") || text.starts_with("http://"))
        && text.len() <= 2_048
        && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The host part of a URL or a bare host, for a title when the file has none. It never holds
/// user information (AUD-25): a URL whose parts cannot be told apart gives `None`.
fn host_of(url: &str) -> Option<String> {
    let (_, host, _) = url_parts(url)?;
    let host = host.trim();
    (!host.is_empty() && !host.chars().any(char::is_whitespace)).then(|| host.to_owned())
}

/// The URL as item `target` keeps it: scheme, host and port only, because agents with
/// `catalog:read` see the target. No user name or password, no query and no fragment (AUD-25), and
/// no path either: webhook and bot URLs (`hooks.slack.com/services/...`, `.../api/webhooks/<id>/
/// <token>`, `api.telegram.org/bot<token>/...`) carry their secret in the path (NEW-9,
/// DEC-T27-F-3). The full URL stays in the sealed login payload. Empty (no target) when the parts
/// cannot be told apart safely, see [`url_parts`].
fn target_of(url: &str) -> String {
    match url_parts(url) {
        Some(("", host, _)) => host.to_owned(),
        Some((scheme, host, _)) => format!("{scheme}://{host}"),
        None => String::new(),
    }
}

/// Scheme (may be empty), host (with port) and path of a URL from an export, without user
/// information, query and fragment (DEC-T27-D1-2, DEC-T27-E-5).
///
/// Exports hold passwords that are not percent-encoded, so `/`, `?`, `#` and `@` can be in the
/// user information. When no `@` comes after the first `/`, `?` or `#`, the URL is read as RFC
/// 3986 says (the host is after the last `@` of the authority, the path is kept). Otherwise the
/// text is ambiguous, and the path is never kept:
/// - the RFC authority is not a `host[:port]` (`user:pa` in `https://user:pa/ss@host/x`): it is
///   user information. With exactly one `@` in the text, the host is after it; with more, which
///   `@` ends the user information cannot be told (one may be in a password or in the query), so
///   `None`;
/// - the RFC authority is a host name with a dot and no port (`https://site.example/login?e=a@b`):
///   only the host is kept. A dot-less name (`https://tokPart1/part2@host/`, the first part of a
///   token used as the user name) or a `host:port` (`https://user:1234/x@host/`, where `1234/x`
///   could be a password) gives `None`.
///
/// Nothing that may be user information, query or fragment is ever returned.
fn url_parts(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) if valid_scheme(scheme) => (scheme, rest),
        _ => ("", url),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    if !tail.contains('@') {
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let path = tail.split(['?', '#']).next().unwrap_or("");
        return Some((scheme, host, path));
    }
    if host_port(authority) {
        return dotted_host(authority).then_some((scheme, authority, ""));
    }
    if rest.matches('@').count() != 1 {
        return None;
    }
    let (_, after) = rest.split_once('@')?;
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    host_port(host).then_some((scheme, host, ""))
}

/// A plain host name with at least one inner dot (`site.example`, `10.0.0.1`), no port.
fn dotted_host(text: &str) -> bool {
    plain_host(text)
        && text.contains('.')
        && !text.starts_with('.')
        && !text.ends_with('.')
        && !text.contains("..")
}

fn valid_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// A host name or IPv4 address: letters, digits, `-`, `.` and `_`, not empty.
fn plain_host(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`, where a port is 1 to 5 digits.
fn host_port(text: &str) -> bool {
    let digits = |p: &str| (1..=5).contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit());
    if let Some(v6) = text.strip_prefix('[') {
        let Some((inside, after)) = v6.split_once(']') else {
            return false;
        };
        let inside_ok = !inside.is_empty()
            && inside
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'));
        return inside_ok && (after.is_empty() || after.strip_prefix(':').is_some_and(digits));
    }
    match text.split_once(':') {
        Some((host, port)) => plain_host(host) && digits(port),
        None => plain_host(text),
    }
}

fn split_tags(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tag in text.split([',', ';']) {
        let tag = tag.trim();
        if !tag.is_empty() && !out.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            out.push(tag.to_owned());
        }
    }
    out.truncate(20);
    out
}

/// `KEY=VALUE` lines or a JSON object of strings.
fn env_vars(text: &str) -> Option<BTreeMap<String, SecretString>> {
    let trimmed = text.trim();
    let mut vars = BTreeMap::new();
    if trimmed.starts_with('{') {
        let map: BTreeMap<String, String> = serde_json::from_str(trimmed).ok()?;
        for (k, v) in map {
            vars.insert(k, SecretString::new(v));
        }
    } else {
        for line in trimmed.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (k, v) = line.split_once('=')?;
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|x| x.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                .unwrap_or(v);
            vars.insert(k.trim().to_owned(), SecretString::new(v.to_owned()));
        }
    }
    (!vars.is_empty()).then_some(vars)
}

fn secret_text(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

/// Builds the item of one row.
pub(crate) fn build_row(
    cols: &Columns,
    source: CsvSource,
    row: &Row,
    targets: &Targets<'_>,
) -> RowResult {
    let cells = row.cells.as_slice();
    // A cell the export guarded for spreadsheets is restored only for Cerberus files.
    let unguard = source == CsvSource::Generic;
    let get = |field: Field| -> Option<&str> {
        cols.get(field, cells)
            .map(|c| if unguard { unguard_cell(c) } else { c })
    };
    let text = |field: Field| non_empty(get(field)).map(str::trim);

    if cells.iter().all(|c| c.trim().is_empty()) {
        return Err(problem(ProblemCode::EmptyRow));
    }
    let kind = match non_empty(get(Field::Kind)) {
        Some(value) => kind_from(value).map_err(|()| problem(ProblemCode::UnsupportedKind))?,
        None => {
            if text(Field::Username).is_some()
                || non_empty(get(Field::Password)).is_some()
                || text(Field::Url).is_some()
            {
                ItemKind::WebLogin
            } else {
                ItemKind::Note
            }
        }
    };
    let url_text = text(Field::Url);
    let title = text(Field::Title)
        .map(str::to_owned)
        .or_else(|| url_text.and_then(host_of))
        .ok_or_else(|| problem(ProblemCode::MissingTitle))?;
    let main_secret = non_empty(get(Field::Secret)).or_else(|| non_empty(get(Field::Password)));
    let notes = non_empty(get(Field::Notes));
    // Only a note or an env bundle without a secret cell keeps the notes (as its body); every
    // other row with notes drops them, and each one counts (AUD-25).
    let notes_kept = matches!(kind, ItemKind::Note | ItemKind::EnvBundle) && main_secret.is_none();
    let notes_dropped = notes.is_some() && !notes_kept;
    let payload = match kind {
        ItemKind::WebLogin => {
            let payload_url = url_text.map(|u| {
                if http_url(u) {
                    u.to_owned()
                } else if !u.contains("://") && u.contains('.') && http_url(&format!("https://{u}"))
                {
                    format!("https://{u}")
                } else {
                    String::new()
                }
            });
            let totp = text(Field::Totp).and_then(parse_seed);
            Payload::WebLogin {
                username: secret_text(get(Field::Username).unwrap_or("")),
                password: secret_text(get(Field::Password).or(get(Field::Secret)).unwrap_or("")),
                url: payload_url.filter(|u| !u.is_empty()),
                totp,
            }
        }
        ItemKind::Note => {
            let body = main_secret
                .or(notes)
                .ok_or_else(|| problem(ProblemCode::MissingSecret))?;
            Payload::Note {
                text: secret_text(body),
            }
        }
        ItemKind::ApiKey => Payload::ApiKey {
            key: secret_text(main_secret.ok_or_else(|| problem(ProblemCode::MissingSecret))?),
            key_id: None,
            header_name: None,
            base_url: None,
        },
        ItemKind::SessionToken => Payload::SessionToken {
            token: secret_text(main_secret.ok_or_else(|| problem(ProblemCode::MissingSecret))?),
            token_type: None,
            header_name: None,
        },
        ItemKind::Database => Payload::Database {
            url: Some(secret_text(
                main_secret.ok_or_else(|| problem(ProblemCode::MissingSecret))?,
            )),
            engine: None,
            host: None,
            port: None,
            database: None,
            username: None,
            password: None,
            params: BTreeMap::new(),
        },
        ItemKind::EnvBundle => {
            let body = main_secret
                .or(notes)
                .ok_or_else(|| problem(ProblemCode::MissingSecret))?;
            Payload::EnvBundle {
                vars: env_vars(body).ok_or_else(|| invalid("payload.vars"))?,
            }
        }
        _ => return Err(problem(ProblemCode::UnsupportedKind)),
    };
    let environment = match text(Field::Environment) {
        Some(value) => {
            serde_json::from_value::<Environment>(serde_json::Value::String(value.to_lowercase()))
                .map_err(|_| invalid("environment"))?
        }
        None => targets.environment,
    };
    let target = url_text
        .map(target_of)
        .filter(|u| !u.is_empty() && u.chars().count() <= 512 && !u.chars().any(char::is_control));
    let input = ItemInput {
        workspace_id: targets.workspace_id,
        title,
        description: text(Field::Description).unwrap_or("").to_owned(),
        role_label: text(Field::Role)
            .map(str::to_owned)
            .or_else(|| targets.role_label.map(str::to_owned)),
        category: text(Field::Category)
            .unwrap_or_else(|| category_of(kind))
            .to_owned(),
        tags: text(Field::Tags).map(split_tags).unwrap_or_default(),
        environment,
        target,
        custom: BTreeMap::new(),
        expires_at: None,
        max_uses: None,
        payload,
    };
    let input = crate::items::normalize_input(input);
    if let Err(problems) = validate_item(&input) {
        let field = problems
            .first()
            .map_or_else(|| "item".to_owned(), |p| p.field.chars().take(40).collect());
        return Err((ProblemCode::InvalidValue, Some(field)));
    }
    Ok(Built {
        input,
        notes_dropped,
    })
}

#[cfg(test)]
pub(crate) fn kind_of_text(text: &str) -> Option<ItemKind> {
    kind_from(text).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::csvio::plan::{DuplicatePolicy, ImportOptions, Plan, make_plan};
    use crate::csvio::table::parse_table;

    fn plan(csv: &str) -> Plan {
        let table = parse_table(csv.as_bytes()).unwrap();
        let options = ImportOptions {
            source: CsvSource::Generic,
            workspace_id: WorkspaceId::generate(),
            environment: Environment::Dev,
            role_label: Some("imported".to_owned()),
            mapping: BTreeMap::new(),
            duplicates: DuplicatePolicy::Skip,
        };
        make_plan(&table, &options, &BTreeSet::new()).unwrap()
    }

    /// The codes and fields of the problems, row by row.
    fn problems(plan: &Plan) -> Vec<(ProblemCode, Option<String>)> {
        plan.preview
            .problems
            .iter()
            .map(|p| (p.code, p.field.clone()))
            .collect()
    }

    #[test]
    fn rows_without_the_needed_parts_are_problems() {
        let p = plan(
            "title,kind,secret,notes\n\
             ,note,x,\n\
             Empty key,api_key,,\n\
             Empty token,token,,\n\
             Empty db,db,,\n\
             Empty env,env,,\n\
             Empty note,note,,\n\
             Card,card,x,\n\
             ,,,\n",
        );
        assert!(p.items.is_empty());
        let codes: Vec<ProblemCode> = problems(&p).into_iter().map(|(c, _)| c).collect();
        assert_eq!(
            codes,
            [
                ProblemCode::MissingTitle,
                ProblemCode::MissingSecret,
                ProblemCode::MissingSecret,
                ProblemCode::MissingSecret,
                ProblemCode::MissingSecret,
                ProblemCode::MissingSecret,
                ProblemCode::UnsupportedKind,
                ProblemCode::EmptyRow,
            ]
        );
    }

    #[test]
    fn kinds_are_built_from_the_row() {
        let p = plan(
            "title,kind,secret,notes,tags,environment\n\
             K,API-Key,fake-key,,\"a, b;A\",PROD\n\
             T,Session Token,fake-token,,,\n\
             D,database,postgres://fake,,,\n\
             N,secure note,,fake body,,\n",
        );
        assert_eq!(p.preview.problem_count, 0);
        let kinds: Vec<ItemKind> = p.items.iter().map(|i| i.payload.kind()).collect();
        assert_eq!(
            kinds,
            [
                ItemKind::ApiKey,
                ItemKind::SessionToken,
                ItemKind::Database,
                ItemKind::Note
            ]
        );
        assert_eq!(p.items[0].tags, ["a", "b"], "tags split and deduplicated");
        assert_eq!(p.items[0].environment, Environment::Prod);
        assert_eq!(p.items[1].environment, Environment::Dev);
        assert_eq!(p.items[1].category, "Session");
        assert_eq!(p.items[2].category, "Database");
        assert_eq!(p.items[3].category, "Other");
        assert_eq!(p.items[3].role_label.as_deref(), Some("imported"));
    }

    #[test]
    fn a_bad_environment_names_its_field() {
        let p = plan("title,secret,environment\nX,fake-key,moon\n");
        assert_eq!(
            problems(&p),
            [(ProblemCode::InvalidValue, Some("environment".to_owned()))]
        );
    }

    #[test]
    fn env_bundles_read_lines_or_json() {
        let p = plan(
            "title,kind,secret\n\
             Lines,env,\"# comment\n\nexport A=1\nB=\"\"two words\"\"\nC='three'\nD=four\"\n\
             Json,env,\"{\"\"X\"\":\"\"y\"\"}\"\n",
        );
        assert_eq!(p.preview.problem_count, 0);
        let Payload::EnvBundle { vars } = &p.items[0].payload else {
            panic!("an env bundle");
        };
        let shown: Vec<(&str, &str)> = vars
            .iter()
            .map(|(k, v)| (k.as_str(), v.expose_secret()))
            .collect();
        assert_eq!(
            shown,
            [
                ("A", "1"),
                ("B", "two words"),
                ("C", "three"),
                ("D", "four")
            ]
        );
        let Payload::EnvBundle { vars } = &p.items[1].payload else {
            panic!("an env bundle");
        };
        assert_eq!(vars["X"].expose_secret(), "y");
    }

    #[test]
    fn env_bundles_that_do_not_parse_are_invalid() {
        let p = plan(
            "title,kind,secret\n\
             No equals,env,just words\n\
             Bad json,env,\"{\"\"X\"\": 1}\"\n\
             Only comments,env,# nothing\n",
        );
        let expected = (ProblemCode::InvalidValue, Some("payload.vars".to_owned()));
        assert_eq!(problems(&p), [expected.clone(), expected.clone(), expected]);
    }

    #[test]
    fn login_urls_are_made_safe() {
        let p = plan(
            "title,url,username,password,notes\n\
             Bare host,example.com/login,u,p,a note\n\
             Full,https://example.com/a,u,p,\n\
             Odd scheme,ftp://example.com,u,p,\n\
             Spaces,https://exa mple.com,u,p,\n\
             No dot,intranet,u,p,\n",
        );
        assert_eq!(p.preview.problem_count, 0);
        let url = |n: usize| match &p.items[n].payload {
            Payload::WebLogin { url, .. } => url.clone(),
            _ => panic!("a login"),
        };
        assert_eq!(url(0).as_deref(), Some("https://example.com/login"));
        assert_eq!(url(1).as_deref(), Some("https://example.com/a"));
        assert_eq!(url(2), None);
        assert_eq!(url(3), None);
        assert_eq!(url(4), None);
        assert_eq!(p.preview.notes_dropped, 1);
        assert_eq!(p.items[2].target.as_deref(), Some("ftp://example.com"));
    }

    /// AUD-25: `target` is metadata that agents see in the catalog, so it keeps no user name,
    /// password, query or fragment of the URL. The payload URL of a login stays as it was.
    #[test]
    fn the_target_drops_user_info_query_and_fragment() {
        let p = plan(
            "title,url,username,password\n\
             Creds,https://zq-fake-user:zq-fake-pass@shop.example:8443/login?token=zq-fake-q#zq-fake-f,u,p\n\
             Bare,zq-fake-user@intranet.example/x?k=zq-fake-q,u,p\n\
             Plain,https://shop.example/a/b,u,p\n",
        );
        assert_eq!(p.preview.problem_count, 0);
        let target = |n: usize| p.items[n].target.clone();
        assert_eq!(target(0).as_deref(), Some("https://shop.example:8443"));
        assert_eq!(target(1).as_deref(), Some("intranet.example"));
        assert_eq!(target(2).as_deref(), Some("https://shop.example"));
        for item in &p.items {
            assert!(!item.target.as_deref().unwrap_or("").contains("zq-fake"));
        }
    }

    /// AUD-25 re-check (DEC-T27-D1-2, DEC-T27-E-5): passwords that are not percent-encoded (with
    /// `/`, `?`, `#` or `@`) never reach the target or the title. When an `@` comes after the
    /// first `/`, `?` or `#`, only scheme and host are kept, or nothing.
    #[test]
    fn the_target_never_keeps_an_unencoded_password() {
        for (url, want) in [
            // T27-E re-check: a token with a `/` as the user name (no `:`), and an `@` in the
            // query after an unencoded password.
            ("https://zq-fake-tokPart1/zq-fake-part2@github.com/x", ""),
            (
                "https://zq-fake-user:zq-fake/ss@shop.example/x?token=zq-fake-abc@zq-fake-def/ghi",
                "",
            ),
            (
                "https://zq-fake-user:zq-fake/pass@shop.example/x",
                "https://shop.example",
            ),
            (
                "https://zq-fake-user:zq-fake?pass@shop.example/",
                "https://shop.example",
            ),
            (
                "https://zq-fake-user:zq-fake#pass@shop.example:8443/a?b",
                "https://shop.example:8443",
            ),
            // Two `@`: which one ends the user information cannot be told.
            ("https://zq-fake-user:zq-f@ke/pa?ss@shop.example/x#y", ""),
            ("https://zq-fake-user:1234/zq-fake@shop.example/", ""),
            (
                "https://shop.example/login?email=zq-fake@mail.example",
                "https://shop.example",
            ),
            (
                "https://zq-fake-user:zq-fake/pass@[::1]:8443/x",
                "https://[::1]:8443",
            ),
            ("https://zq-fake-user:zq-fake/pass@", ""),
            (
                "zq-fake-user:zq-fake/pass@intranet.example/x",
                "intranet.example",
            ),
            (
                "https://u%40x:zq-fake-pass@shop.example/p",
                "https://shop.example",
            ),
            ("https://[::1]:8443/x?q=zq-fake", "https://[::1]:8443"),
            ("https://intranet/login?u=zq-fake@mail.example", ""),
            ("https://shop.example:8443/login?e=zq-fake@mail.example", ""),
        ] {
            assert_eq!(target_of(url), want, "{url}");
            assert!(!target_of(url).contains("zq-fake"), "{url}");
            assert!(
                !host_of(url).unwrap_or_default().contains("zq-fake"),
                "{url}"
            );
        }
        assert_eq!(
            host_of("https://zq-fake-tokPart1/zq-fake-part2@github.com/x"),
            None
        );
        let p = plan(
            "title,url,username,password\n\
             Slash,https://zq-fake-user:zq-fake/pass@shop.example/x,u,p\n\
             ,https://zq-fake-user:zq-fake/pass@shop.example/x,u,p\n\
             Odd,https://zq-fake-user:1234/zq-fake@shop.example/,u,p\n",
        );
        assert_eq!(p.preview.problem_count, 0);
        assert_eq!(p.items[0].target.as_deref(), Some("https://shop.example"));
        assert_eq!(p.items[1].title, "shop.example");
        assert_eq!(p.items[2].target, None);
        for item in &p.items {
            assert!(!item.title.contains("zq-fake"));
            assert!(!item.target.as_deref().unwrap_or("").contains("zq-fake"));
        }
    }

    /// NEW-9: webhook and bot URLs carry their secret in the path. The target keeps scheme, host
    /// and port only; the login payload keeps the whole URL (it is sealed).
    #[test]
    fn new9_the_target_never_keeps_the_url_path() {
        let rows = [
            (
                "https://hooks.slack.com/services/T000/B000/zq-fake-secret",
                "https://hooks.slack.com",
            ),
            (
                "https://discord.com/api/webhooks/1/zq-fake-token",
                "https://discord.com",
            ),
            (
                "https://api.telegram.org/botzq-fake:token/getMe",
                "https://api.telegram.org",
            ),
            (
                "https://shop.example:8443/zq-fake-path?q=1#f",
                "https://shop.example:8443",
            ),
            ("intranet.example/zq-fake-path", "intranet.example"),
        ];
        for (url, want) in rows {
            assert_eq!(target_of(url), want, "{url}");
        }
        let mut csv = String::from("title,url,username,password\n");
        for (n, (url, _)) in rows.iter().enumerate() {
            csv.push_str(&format!("Hook{n},{url},u,p\n"));
        }
        let p = plan(&csv);
        assert_eq!(p.preview.problem_count, 0);
        for (item, (url, want)) in p.items.iter().zip(rows) {
            assert_eq!(item.target.as_deref(), Some(want), "{url}");
            assert!(!item.title.contains("zq-fake"));
            if let Payload::WebLogin { url: kept, .. } = &item.payload {
                let kept = kept.as_deref().unwrap_or("");
                assert!(
                    kept.contains("zq-fake"),
                    "the payload keeps the whole URL: {kept}"
                );
            } else {
                panic!("a login");
            }
        }
    }

    /// AUD-25: every row whose notes are not kept counts in `notes_dropped`.
    #[test]
    fn every_dropped_note_is_counted() {
        let p = plan(
            "title,kind,secret,notes\n\
             Key,api_key,zq-fake-k,a note\n\
             Token,token,zq-fake-t,a note\n\
             Db,db,postgres://h/zq-fake,a note\n\
             Note,note,zq-fake-body,a second note\n\
             Env,env,A=zq-fake,a note\n\
             Kept,note,,zq-fake-only-notes\n",
        );
        assert_eq!(p.preview.problem_count, 0);
        assert_eq!(p.preview.notes_dropped, 5);
    }

    #[test]
    fn the_title_comes_from_the_url_host_when_missing() {
        let p = plan(
            "url,username,password\n\
             https://user@host.example/path?q=1,u,p\n\
             https://,u,p\n",
        );
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].title, "host.example");
        assert_eq!(problems(&p), [(ProblemCode::MissingTitle, None)]);
    }

    #[test]
    fn a_login_totp_is_read_as_uri_or_bare_seed() {
        let seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let p = plan(&format!(
            "title,username,password,totp\n\
             Uri,u,p,otpauth://totp/x?secret={seed}&digits=8\n\
             Bare,u,p,{seed}\n\
             None,u,p,\n\
             Short,u,p,JBSWY3DP\n"
        ));
        let digits = |n: usize| match &p.items[n].payload {
            Payload::WebLogin { totp, .. } => totp.as_ref().map(|t| t.digits),
            _ => panic!("a login"),
        };
        assert_eq!(digits(0), Some(8));
        assert_eq!(digits(1), Some(6));
        assert_eq!(digits(2), None);
        assert_eq!(
            problems(&p),
            [(ProblemCode::InvalidValue, Some("payload.totp".to_owned()))],
            "a seed that is too short is refused"
        );
    }

    #[test]
    fn a_value_the_validator_refuses_names_the_field() {
        let long = "t".repeat(201);
        let p = plan(&format!("title,secret\n{long},fake-key\n"));
        assert_eq!(
            problems(&p),
            [(ProblemCode::InvalidValue, Some("title".to_owned()))]
        );
    }

    #[test]
    fn guarded_cells_are_restored_for_generic_files_only() {
        let p = plan("title,kind,secret\n'=Formula,api_key,'+fake-key\n");
        assert_eq!(p.items[0].title, "=Formula");
        let Payload::ApiKey { key, .. } = &p.items[0].payload else {
            panic!("an api key");
        };
        assert_eq!(key.expose_secret(), "+fake-key");
    }
}
