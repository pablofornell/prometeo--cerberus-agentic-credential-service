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

/// True for a server address: a host name, an IPv4 address or a bracketed IPv6 address, with an
/// optional port. No scheme, path, space or control character.
fn is_server(text: &str) -> bool {
    (1..=MAX_SERVER_CHARS).contains(&text.len())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
}

/// True for a server public key: Base64 (standard or URL-safe) with optional padding.
fn is_server_key(text: &str) -> bool {
    (1..=MAX_KEY_CHARS).contains(&text.len())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
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
        if custom.get(key).is_some_and(|s| !is_server(s)) {
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
