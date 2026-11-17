//! Items to CSV. The file holds every secret in plain text: the owner confirms that in the UI and
//! the desktop layer writes it with mode 0600. Every cell goes through the formula guard.

use std::collections::BTreeMap;

use cerberus_crypto::SecretString;
use zeroize::Zeroizing;

use super::guard::guard_cell;
use super::totp_text::seed_uri;
use crate::error::CoreError;
use crate::items::{Payload, RevealedItem};

/// The columns of the export, in order. A Cerberus export imports again as `Generic`.
pub const EXPORT_COLUMNS: [&str; 14] = [
    "workspace",
    "title",
    "kind",
    "environment",
    "role",
    "category",
    "tags",
    "url",
    "username",
    "password",
    "secret",
    "totp",
    "description",
    "extra",
];

type Cell = Zeroizing<String>;

fn cell(text: &str) -> Cell {
    Zeroizing::new(text.to_owned())
}

fn sec(value: &SecretString) -> &str {
    value.expose_secret()
}

fn json_extra(pairs: Vec<(&str, Option<String>)>) -> Result<Cell, CoreError> {
    let map: BTreeMap<&str, String> = pairs
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();
    if map.is_empty() {
        return Ok(cell(""));
    }
    serde_json::to_string(&map)
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Corrupt)
}

/// The value columns of one payload: `username`, `password`, `url`, `secret`, `totp`, `extra`.
struct Values {
    url: Cell,
    username: Cell,
    password: Cell,
    secret: Cell,
    totp: Cell,
    extra: Cell,
}

fn values(payload: &Payload) -> Result<Values, CoreError> {
    let mut v = Values {
        url: cell(""),
        username: cell(""),
        password: cell(""),
        secret: cell(""),
        totp: cell(""),
        extra: cell(""),
    };
    let own = |o: &Option<String>| o.clone();
    let own_secret = |o: &Option<SecretString>| o.as_ref().map(|s| sec(s).to_owned());
    match payload {
        Payload::WebLogin {
            username,
            password,
            url,
            totp,
        } => {
            v.username = cell(sec(username));
            v.password = cell(sec(password));
            v.url = cell(url.as_deref().unwrap_or(""));
            v.totp = totp
                .as_ref()
                .map_or_else(|| cell(""), |t| Zeroizing::new(seed_uri(t)));
        }
        Payload::ApiKey {
            key,
            key_id,
            header_name,
            base_url,
        } => {
            v.secret = cell(sec(key));
            v.extra = json_extra(vec![
                ("key_id", own(key_id)),
                ("header_name", own(header_name)),
                ("base_url", own(base_url)),
            ])?;
        }
        Payload::SshKey {
            private_key,
            passphrase,
            public_key,
            fingerprint,
        } => {
            v.secret = cell(sec(private_key));
            v.extra = json_extra(vec![
                ("passphrase", own_secret(passphrase)),
                ("public_key", Some(public_key.clone())),
                ("fingerprint", Some(fingerprint.clone())),
            ])?;
        }
        Payload::SessionToken {
            token,
            token_type,
            header_name,
        } => {
            v.secret = cell(sec(token));
            v.extra = json_extra(vec![
                ("token_type", own(token_type)),
                ("header_name", own(header_name)),
            ])?;
        }
        Payload::BrowserSession {
            storage_state,
            origin,
        } => {
            v.secret = cell(sec(storage_state));
            v.url = cell(origin);
        }
        Payload::Database {
            url,
            engine,
            host,
            port,
            database,
            username,
            password,
            params,
        } => {
            v.secret = cell(url.as_ref().map_or("", sec));
            v.username = cell(username.as_ref().map_or("", sec));
            v.password = cell(password.as_ref().map_or("", sec));
            let params_json = if params.is_empty() {
                None
            } else {
                Some(serde_json::to_string(params).map_err(|_| CoreError::Corrupt)?)
            };
            v.extra = json_extra(vec![
                ("engine", own(engine)),
                ("host", own(host)),
                ("port", port.map(|p| p.to_string())),
                ("database", own(database)),
                ("params", params_json),
            ])?;
        }
        Payload::Cloud {
            provider,
            access_key_id,
            secret_access_key,
            session_token,
            region,
            extra,
        } => {
            v.username = cell(access_key_id.as_ref().map_or("", sec));
            v.secret = cell(secret_access_key.as_ref().map_or("", sec));
            let extra_json = if extra.is_empty() {
                None
            } else {
                let plain: BTreeMap<&String, &str> =
                    extra.iter().map(|(k, s)| (k, sec(s))).collect();
                Some(serde_json::to_string(&plain).map_err(|_| CoreError::Corrupt)?)
            };
            v.extra = json_extra(vec![
                ("provider", Some(provider.clone())),
                ("session_token", own_secret(session_token)),
                ("region", own(region)),
                ("extra", extra_json),
            ])?;
        }
        Payload::Certificate {
            cert_pem,
            key_pem,
            chain_pem,
        } => {
            v.secret = cell(key_pem.as_ref().map_or("", sec));
            v.extra = json_extra(vec![
                ("cert_pem", Some(cert_pem.clone())),
                ("chain_pem", own(chain_pem)),
            ])?;
        }
        Payload::EnvBundle { vars } => {
            let plain: BTreeMap<&String, &str> = vars.iter().map(|(k, s)| (k, sec(s))).collect();
            v.secret =
                Zeroizing::new(serde_json::to_string(&plain).map_err(|_| CoreError::Corrupt)?);
        }
        Payload::Note { text } => v.secret = cell(sec(text)),
    }
    Ok(v)
}

/// One export row. `workspace` is the workspace name.
fn row_of(workspace: &str, item: &RevealedItem) -> Result<Vec<Cell>, CoreError> {
    let s = &item.summary;
    let kind = serde_json::to_value(s.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(CoreError::Corrupt)?;
    let env = serde_json::to_value(s.environment)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(CoreError::Corrupt)?;
    let v = values(&item.payload)?;
    let url = if v.url.is_empty() {
        cell(s.target.as_deref().unwrap_or(""))
    } else {
        v.url
    };
    Ok(vec![
        cell(workspace),
        cell(&s.title),
        cell(&kind),
        cell(&env),
        cell(s.role_label.as_deref().unwrap_or("")),
        cell(&s.category),
        cell(&s.tags.join(",")),
        url,
        v.username,
        v.password,
        v.secret,
        v.totp,
        cell(&s.description),
        v.extra,
    ])
}

/// The CSV bytes of `items` (workspace name and revealed item). Zeroized on drop.
pub(crate) fn write_csv(items: &[(String, RevealedItem)]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let mut rows = Vec::with_capacity(items.len());
    for (workspace, item) in items {
        rows.push(row_of(workspace, item)?);
    }
    // One allocation that is big enough, so the buffer never moves and leaves a copy behind.
    let needed: usize = rows
        .iter()
        .flatten()
        .map(|c| c.len().saturating_mul(2).saturating_add(4))
        .sum::<usize>()
        .saturating_add(EXPORT_COLUMNS.iter().map(|c| c.len() + 3).sum::<usize>())
        .saturating_add(64);
    let mut out = Zeroizing::new(Vec::with_capacity(needed));
    {
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .from_writer(&mut *out);
        writer
            .write_record(EXPORT_COLUMNS)
            .map_err(|_| CoreError::Corrupt)?;
        for row in &rows {
            let guarded: Vec<Cell> = row.iter().map(|c| Zeroizing::new(guard_cell(c))).collect();
            writer
                .write_record(guarded.iter().map(|c| c.as_bytes()))
                .map_err(|_| CoreError::Corrupt)?;
        }
        writer.flush().map_err(|_| CoreError::Corrupt)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cerberus_crypto::SecretString;
    use cerberus_types::{Environment, ItemId, ItemKind};
    use jiff::Timestamp;

    use super::*;
    use crate::items::{ItemSummary, TotpAlgorithm, TotpSeed};

    fn secret(text: &str) -> SecretString {
        SecretString::new(text.to_owned())
    }

    fn revealed(kind: ItemKind, payload: Payload) -> (String, RevealedItem) {
        let summary = ItemSummary {
            id: ItemId::generate(),
            kind,
            title: "Fake title".to_owned(),
            description: "fake description".to_owned(),
            role_label: Some("deploy".to_owned()),
            category: "Fake".to_owned(),
            tags: vec!["one".to_owned(), "two".to_owned()],
            environment: Environment::Staging,
            workspace: "shop".to_owned(),
            target: Some("https://fallback.example".to_owned()),
            created_by: "operator:fake".to_owned(),
            expires_at: None,
            updated_at: Timestamp::UNIX_EPOCH,
            has_totp: false,
            custom: BTreeMap::new(),
        };
        let item = RevealedItem {
            summary,
            payload,
            use_count: 0,
            exhausted: false,
            ssh: None,
        };
        ("Shop".to_owned(), item)
    }

    /// The only data row of the CSV as a map from column name to cell.
    fn one_row(item: (String, RevealedItem)) -> BTreeMap<String, String> {
        let bytes = write_csv(&[item]).unwrap();
        let mut reader = csv::Reader::from_reader(bytes.as_slice());
        let headers = reader.headers().unwrap().clone();
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(reader.records().count(), 0);
        headers
            .iter()
            .zip(record.iter())
            .map(|(h, c)| (h.to_owned(), c.to_owned()))
            .collect()
    }

    fn extra(row: &BTreeMap<String, String>) -> serde_json::Value {
        serde_json::from_str(&row["extra"]).unwrap()
    }

    #[test]
    fn a_login_row_has_the_totp_uri_and_the_common_columns() {
        let seed = TotpSeed {
            secret: secret("JBSWY3DPEHPK3PXP"),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period: 60,
        };
        let row = one_row(revealed(
            ItemKind::WebLogin,
            Payload::WebLogin {
                username: secret("fake-user"),
                password: secret("fake-pass"),
                url: Some("https://login.example".to_owned()),
                totp: Some(seed),
            },
        ));
        assert_eq!(row["workspace"], "Shop");
        assert_eq!(row["kind"], "web_login");
        assert_eq!(row["environment"], "staging");
        assert_eq!(row["role"], "deploy");
        assert_eq!(row["tags"], "one,two");
        assert_eq!(row["url"], "https://login.example");
        assert_eq!(row["username"], "fake-user");
        assert_eq!(row["password"], "fake-pass");
        assert!(row["totp"].starts_with("otpauth://totp/"));
        assert!(row["totp"].contains("algorithm=SHA256&digits=8&period=60"));
        assert_eq!(row["extra"], "");
    }

    #[test]
    fn a_login_without_url_or_totp_falls_back_to_the_target() {
        let row = one_row(revealed(
            ItemKind::WebLogin,
            Payload::WebLogin {
                username: secret("u"),
                password: secret("p"),
                url: None,
                totp: None,
            },
        ));
        assert_eq!(row["url"], "https://fallback.example");
        assert_eq!(row["totp"], "");
    }

    #[test]
    fn api_key_and_token_rows_keep_only_the_set_extras() {
        let row = one_row(revealed(
            ItemKind::ApiKey,
            Payload::ApiKey {
                key: secret("fake-key"),
                key_id: Some("kid-1".to_owned()),
                header_name: None,
                base_url: Some("https://api.example".to_owned()),
            },
        ));
        assert_eq!(row["secret"], "fake-key");
        assert_eq!(
            extra(&row),
            serde_json::json!({"key_id": "kid-1", "base_url": "https://api.example"})
        );

        let row = one_row(revealed(
            ItemKind::SessionToken,
            Payload::SessionToken {
                token: secret("fake-token"),
                token_type: Some("Bearer".to_owned()),
                header_name: Some("Authorization".to_owned()),
            },
        ));
        assert_eq!(row["secret"], "fake-token");
        assert_eq!(
            extra(&row),
            serde_json::json!({"token_type": "Bearer", "header_name": "Authorization"})
        );
    }

    #[test]
    fn ssh_and_browser_session_rows() {
        let row = one_row(revealed(
            ItemKind::SshKey,
            Payload::SshKey {
                private_key: secret("fake-private-key"),
                passphrase: Some(secret("fake-phrase")),
                public_key: "ssh-ed25519 AAAA fake".to_owned(),
                fingerprint: "SHA256:fake".to_owned(),
            },
        ));
        assert_eq!(row["secret"], "fake-private-key");
        let json = extra(&row);
        assert_eq!(json["passphrase"], "fake-phrase");
        assert_eq!(json["fingerprint"], "SHA256:fake");

        let row = one_row(revealed(
            ItemKind::SshKey,
            Payload::SshKey {
                private_key: secret("fake-private-key"),
                passphrase: None,
                public_key: "ssh-ed25519 AAAA fake".to_owned(),
                fingerprint: "SHA256:fake".to_owned(),
            },
        ));
        assert!(extra(&row).get("passphrase").is_none());

        let row = one_row(revealed(
            ItemKind::BrowserSession,
            Payload::BrowserSession {
                storage_state: secret("{\"cookies\":[]}"),
                origin: "https://app.example".to_owned(),
            },
        ));
        assert_eq!(row["secret"], "{\"cookies\":[]}");
        assert_eq!(row["url"], "https://app.example");
    }

    #[test]
    fn a_database_row_has_its_fields_in_extra() {
        let row = one_row(revealed(
            ItemKind::Database,
            Payload::Database {
                url: Some(secret("postgres://fake")),
                engine: Some("postgres".to_owned()),
                host: Some("db.example".to_owned()),
                port: Some(5432),
                database: Some("shop".to_owned()),
                username: Some(secret("fake-db-user")),
                password: Some(secret("fake-db-pass")),
                params: BTreeMap::from([("sslmode".to_owned(), "require".to_owned())]),
            },
        ));
        assert_eq!(row["secret"], "postgres://fake");
        assert_eq!(row["username"], "fake-db-user");
        assert_eq!(row["password"], "fake-db-pass");
        let json = extra(&row);
        assert_eq!(json["port"], "5432");
        assert_eq!(json["engine"], "postgres");
        assert_eq!(json["params"], "{\"sslmode\":\"require\"}");

        let row = one_row(revealed(
            ItemKind::Database,
            Payload::Database {
                url: None,
                engine: None,
                host: None,
                port: None,
                database: None,
                username: None,
                password: None,
                params: BTreeMap::new(),
            },
        ));
        assert_eq!(row["secret"], "");
        assert_eq!(row["extra"], "", "no field set means no extra");
    }

    #[test]
    fn cloud_and_certificate_rows() {
        let row = one_row(revealed(
            ItemKind::Cloud,
            Payload::Cloud {
                provider: "aws".to_owned(),
                access_key_id: Some(secret("FAKEKEYID")),
                secret_access_key: Some(secret("fake-access")),
                session_token: Some(secret("fake-session")),
                region: Some("eu-west-1".to_owned()),
                extra: BTreeMap::from([("team".to_owned(), secret("fake-team"))]),
            },
        ));
        assert_eq!(row["username"], "FAKEKEYID");
        assert_eq!(row["secret"], "fake-access");
        let json = extra(&row);
        assert_eq!(json["provider"], "aws");
        assert_eq!(json["session_token"], "fake-session");
        assert_eq!(json["extra"], "{\"team\":\"fake-team\"}");

        let row = one_row(revealed(
            ItemKind::Cloud,
            Payload::Cloud {
                provider: "gcp".to_owned(),
                access_key_id: None,
                secret_access_key: None,
                session_token: None,
                region: None,
                extra: BTreeMap::new(),
            },
        ));
        assert_eq!(row["username"], "");
        assert_eq!(extra(&row), serde_json::json!({"provider": "gcp"}));

        let row = one_row(revealed(
            ItemKind::Certificate,
            Payload::Certificate {
                cert_pem: "fake-cert".to_owned(),
                key_pem: Some(secret("fake-key-pem")),
                chain_pem: None,
            },
        ));
        assert_eq!(row["secret"], "fake-key-pem");
        assert_eq!(extra(&row), serde_json::json!({"cert_pem": "fake-cert"}));
    }

    #[test]
    fn env_bundle_and_note_rows() {
        let row = one_row(revealed(
            ItemKind::EnvBundle,
            Payload::EnvBundle {
                vars: BTreeMap::from([
                    ("A".to_owned(), secret("1")),
                    ("B".to_owned(), secret("two")),
                ]),
            },
        ));
        assert_eq!(row["secret"], "{\"A\":\"1\",\"B\":\"two\"}");

        let row = one_row(revealed(
            ItemKind::Note,
            Payload::Note {
                text: secret("fake note"),
            },
        ));
        assert_eq!(row["secret"], "fake note");
    }

    #[test]
    fn an_empty_list_has_only_the_header_row() {
        let bytes = write_csv(&[]).unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(text, format!("{}\r\n", EXPORT_COLUMNS.join(",")));
    }
}
