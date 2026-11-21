//! RustDesk connections (DEC-RD-1): the RustDesk ID, the servers and the server key of a remote
//! machine, and its permanent password.
//!
//! The ID, the servers and the key are not secret, so they are item metadata in `custom` (like the
//! host of an SSH key): the vault list shows them, search finds the ID, and the desktop app can
//! start the RustDesk client without opening the payload. Only the password is in the payload.

use std::collections::BTreeMap;

use cerberus_types::FieldProblem;

/// `custom` key of the RustDesk ID.
pub const KEY_RUSTDESK_ID: &str = "rustdesk_id";
/// `custom` key of the ID server.
pub const KEY_ID_SERVER: &str = "id_server";
/// `custom` key of the relay server.
pub const KEY_RELAY_SERVER: &str = "relay_server";
/// `custom` key of the server public key.
pub const KEY_SERVER_KEY: &str = "server_key";

/// Fewest digits of a RustDesk ID.
const MIN_ID_DIGITS: usize = 9;
/// Most digits of a RustDesk ID.
const MAX_ID_DIGITS: usize = 20;
/// Longest server address (`host` or `host:port`).
const MAX_SERVER_CHARS: usize = 255;
/// Longest server public key. RustDesk keys are 44 Base64 characters.
const MAX_KEY_CHARS: usize = 128;

/// The RustDesk facts that live in the item metadata (`custom`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RustdeskMeta {
    /// RustDesk ID of the remote machine (digits only).
    pub rustdesk_id: Option<String>,
    /// ID server of a self-hosted RustDesk server.
    pub id_server: Option<String>,
    /// Relay server of a self-hosted RustDesk server.
    pub relay_server: Option<String>,
    /// Public key of the self-hosted server.
    pub server_key: Option<String>,
}

impl RustdeskMeta {
    /// The `custom` entries for these facts.
    #[must_use]
    pub fn into_custom(self) -> BTreeMap<String, String> {
        [
            (KEY_RUSTDESK_ID, self.rustdesk_id),
            (KEY_ID_SERVER, self.id_server),
            (KEY_RELAY_SERVER, self.relay_server),
            (KEY_SERVER_KEY, self.server_key),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key.to_owned(), v)))
        .collect()
    }

    /// Reads the facts back from `custom`.
    #[must_use]
    pub fn from_custom<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Self {
        Self {
            rustdesk_id: get(KEY_RUSTDESK_ID).map(str::to_owned),
            id_server: get(KEY_ID_SERVER).map(str::to_owned),
            relay_server: get(KEY_RELAY_SERVER).map(str::to_owned),
            server_key: get(KEY_SERVER_KEY).map(str::to_owned),
        }
    }
}

/// True for a RustDesk ID: 9 to 20 ASCII digits and nothing else. The desktop app checks this
/// again before it passes the ID to the RustDesk client.
#[must_use]
pub fn is_rustdesk_id(text: &str) -> bool {
    (MIN_ID_DIGITS..=MAX_ID_DIGITS).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_digit())
}

/// What a valid server address names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerKind {
    /// A host name or an IPv4 address.
    Name,
    /// A bracketed IPv6 address.
    Ipv6,
}

fn is_port(text: &str) -> bool {
    (1..=5).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_digit())
        && text.parse::<u32>().is_ok_and(|n| (1..=65_535).contains(&n))
}

/// Labels of letters, digits and `-`, 1 to 63 each, not starting or ending with `-`. Covers IPv4.
fn is_host_name(text: &str) -> bool {
    (1..=253).contains(&text.len())
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// `host`, `host:port`, `[ipv6]` or `[ipv6]:port`, else `None`. No scheme, path, user part,
/// query, space or control character, and never a leading `-` (DEC-RD-6).
fn server_kind(text: &str) -> Option<ServerKind> {
    if text.len() > MAX_SERVER_CHARS {
        return None;
    }
    let (host, port, kind) = if let Some(rest) = text.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let port = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix(':')?)
        };
        (inside, port, ServerKind::Ipv6)
    } else {
        match text.split_once(':') {
            Some((host, port)) => (host, Some(port), ServerKind::Name),
            None => (text, None, ServerKind::Name),
        }
    };
    if port.is_some_and(|p| !is_port(p)) {
        return None;
    }
    let host_ok = match kind {
        ServerKind::Ipv6 => host.parse::<std::net::Ipv6Addr>().is_ok(),
        ServerKind::Name => is_host_name(host),
    };
    host_ok.then_some(kind)
}

/// True for a server address: a host name, an IPv4 address or a bracketed IPv6 address, with an
/// optional port 1..65535.
#[must_use]
pub fn is_server_address(text: &str) -> bool {
    server_kind(text).is_some()
}

/// True for a server public key: Base64 (standard or URL-safe) with optional padding.
#[must_use]
pub fn is_server_key(text: &str) -> bool {
    (1..=MAX_KEY_CHARS).contains(&text.len())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
}

/// True when [`rustdesk_peer`] puts this ID server into the peer: a host name or an IPv4
/// address. An IPv6 address cannot be carried (RustDesk forwards `--connect` as a link, and a
/// link path cannot hold brackets), so the client must be set to that server itself.
#[must_use]
pub fn peer_carries_server(id_server: &str) -> bool {
    server_kind(id_server) == Some(ServerKind::Name)
}

/// The peer that the RustDesk client is asked to connect to (DEC-RD-6): `<id>`, or
/// `<id>@<id_server>` and `?key=<server_key>` for a self-hosted server. That is the form RustDesk
/// reads in `LoginConfigHandler::initialize` (`src/client.rs`): the server after `@` is the
/// rendezvous server for this one connection, and `key` is its public key. The relay comes from
/// that server, so it is not part of the peer. A key is only read together with a server, so a
/// key without a carried server is left out. `None` when the ID, the server or the key is not
/// valid, so nothing else can reach the command line.
#[must_use]
pub fn rustdesk_peer(
    id: &str,
    id_server: Option<&str>,
    server_key: Option<&str>,
) -> Option<String> {
    if !is_rustdesk_id(id) || server_key.is_some_and(|k| !is_server_key(k)) {
        return None;
    }
    let Some(server) = id_server else {
        return Some(id.to_owned());
    };
    match (server_kind(server)?, server_key) {
        (ServerKind::Ipv6, _) => Some(id.to_owned()),
        (ServerKind::Name, None) => Some(format!("{id}@{server}")),
        (ServerKind::Name, Some(key)) => Some(format!("{id}@{server}?key={key}")),
    }
}

fn push(problems: &mut Vec<FieldProblem>, key: &str, text: &str) {
    problems.push(FieldProblem {
        field: format!("custom.{key}"),
        problem: text.to_owned(),
    });
}

/// Problems of the RustDesk entries in `custom` of a `rustdesk` item. The ID is required.
pub(crate) fn check_custom(custom: &BTreeMap<String, String>, problems: &mut Vec<FieldProblem>) {
    match custom.get(KEY_RUSTDESK_ID) {
        None => push(problems, KEY_RUSTDESK_ID, "is required"),
        Some(id) if !is_rustdesk_id(id) => {
            push(
                problems,
                KEY_RUSTDESK_ID,
                "must be a RustDesk ID of 9 to 20 digits",
            );
        }
        Some(_) => {}
    }
    for key in [KEY_ID_SERVER, KEY_RELAY_SERVER] {
        if custom.get(key).is_some_and(|s| !is_server_address(s)) {
            push(
                problems,
                key,
                "must be a host name or address with an optional port, such as rd.example.com:21116",
            );
        }
    }
    if custom
        .get(KEY_SERVER_KEY)
        .is_some_and(|k| !is_server_key(k))
    {
        push(
            problems,
            KEY_SERVER_KEY,
            "must be the Base64 public key of the server",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(entries: &[(&str, &str)]) -> Vec<String> {
        let custom = entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let mut problems = Vec::new();
        check_custom(&custom, &mut problems);
        problems.into_iter().map(|p| p.field).collect()
    }

    #[test]
    fn an_id_is_nine_to_twenty_digits() {
        assert!(is_rustdesk_id("123456789"));
        assert!(is_rustdesk_id("12345678901234567890"));
        for bad in [
            "",
            "12345678",
            "123456789012345678901",
            "123 456 789",
            "12345678a",
            "-123456789",
            "123456789\n",
            "１２３４５６７８９",
            "123456789;rm",
        ] {
            assert!(!is_rustdesk_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_id_is_required_and_servers_and_key_are_checked() {
        assert_eq!(problems_of(&[]), ["custom.rustdesk_id"]);
        assert!(problems_of(&[("rustdesk_id", "123456789")]).is_empty());
        assert!(
            problems_of(&[
                ("rustdesk_id", "123456789"),
                ("id_server", "rd.example.com:21116"),
                ("relay_server", "[2001:db8::1]:21117"),
                ("server_key", "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="),
            ])
            .is_empty()
        );
        assert_eq!(
            problems_of(&[
                ("rustdesk_id", "12 34"),
                ("id_server", "https://rd.example.com"),
                ("relay_server", "rd example"),
                ("server_key", "not a key!"),
            ]),
            [
                "custom.rustdesk_id",
                "custom.id_server",
                "custom.relay_server",
                "custom.server_key"
            ]
        );
    }

    #[test]
    fn a_server_is_a_host_or_address_with_an_optional_port() {
        for good in [
            "rd.example.com",
            "rd.example.com:21116",
            "10.0.0.7",
            "10.0.0.7:21116",
            "[2001:db8::1]",
            "[2001:db8::1]:21116",
            "localhost",
        ] {
            assert!(is_server_address(good), "{good:?}");
        }
        for bad in [
            "",
            "-rd.example.com",
            "rd.example.com:0",
            "rd.example.com:65536",
            "rd.example.com:",
            "rd.example.com/path",
            "https://rd.example.com",
            "user@rd.example.com",
            "rd.example.com?key=x",
            "rd example.com",
            "rd.-x.com",
            "a:b:c",
            "[not-v6]:21116",
            "[2001:db8::1]x",
        ] {
            assert!(!is_server_address(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_peer_carries_a_named_server_and_its_key() {
        assert_eq!(
            rustdesk_peer("123456789", None, None).as_deref(),
            Some("123456789")
        );
        assert_eq!(
            rustdesk_peer("123456789", None, Some("k+e/y=")).as_deref(),
            Some("123456789"),
            "a key without a server is not read by RustDesk"
        );
        assert_eq!(
            rustdesk_peer("123456789", Some("rd.example.com:21116"), Some("k+e/y=")).as_deref(),
            Some("123456789@rd.example.com:21116?key=k+e/y=")
        );
        assert_eq!(
            rustdesk_peer("123456789", Some("rd.example.com"), None).as_deref(),
            Some("123456789@rd.example.com")
        );
        assert_eq!(
            rustdesk_peer("123456789", Some("[2001:db8::1]"), Some("key")).as_deref(),
            Some("123456789")
        );
        assert!(peer_carries_server("rd.example.com") && !peer_carries_server("[2001:db8::1]"));
        assert_eq!(rustdesk_peer("12345", None, None), None);
        assert_eq!(rustdesk_peer("123456789", Some("-oProxy"), None), None);
        assert_eq!(
            rustdesk_peer("123456789", Some("rd.example.com"), Some("a&b")),
            None
        );
    }

    #[test]
    fn meta_round_trips_through_custom() {
        let meta = RustdeskMeta {
            rustdesk_id: Some("123456789".to_owned()),
            id_server: Some("rd.example.com".to_owned()),
            relay_server: None,
            server_key: Some("abc=".to_owned()),
        };
        let custom = meta.clone().into_custom();
        assert_eq!(custom.len(), 3);
        assert_eq!(
            RustdeskMeta::from_custom(|k| custom.get(k).map(String::as_str)),
            meta
        );
    }
}
