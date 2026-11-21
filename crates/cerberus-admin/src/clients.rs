//! The admin client registry of `cerberusd` (ADR-0034 point 3.5, DEC-RM-4):
//! `<data_dir>/admin-clients.json`, mode `0600`.
//!
//! One entry per enrolled desktop: its ID, label, bound operator, the SHA-256 of its client
//! certificate, and its times. The file is plain, because a remote unlock needs it while the vault
//! is sealed; it holds no secret. A CA-signed certificate passes the admin routes only when its
//! hash is a live entry here (DEC-RM-3), so agent certificates of the same CA do not.

use std::io::{Read, Write};
use std::path::Path;

use cerberus_types::OperatorId;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// File name of the registry in the daemon's data directory.
pub const ADMIN_CLIENTS_FILE: &str = "admin-clients.json";
/// Version of the registry file.
pub const ADMIN_CLIENTS_VERSION: u32 = 1;
/// The largest registry file that is read.
pub const MAX_ADMIN_CLIENTS_BYTES: u64 = 1024 * 1024;
/// Longest enrolment label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;

cerberus_types::uuid_id!(
    /// ID of one enrolment (UUIDv7). The client certificate names it in its CN.
    EnrolmentId
);

/// Why the registry cannot be read or written.
#[derive(Debug, thiserror::Error)]
pub enum ClientsError {
    /// A file error.
    #[error("admin client registry: {0}")]
    Io(#[from] std::io::Error),
    /// Group or others may use the file (ADR-0034 point 3.5).
    #[error("admin client registry has mode {mode:o}; it must be 0600 (chmod 600 the file)")]
    Mode {
        /// The mode found.
        mode: u32,
    },
    /// The path is a link, a folder or another non-regular file.
    #[error("admin client registry is not a regular file")]
    NotAFile,
    /// The file is larger than [`MAX_ADMIN_CLIENTS_BYTES`].
    #[error("admin client registry is too large")]
    TooLarge,
    /// The file is not a registry of this version.
    #[error("admin client registry is not valid: {0}")]
    Format(&'static str),
    /// An entry with the same ID or the same certificate exists.
    #[error("admin client registry already has this enrolment or certificate")]
    Duplicate,
    /// The label is empty, too long or has control characters.
    #[error("the label must be 1 to 64 characters without control characters")]
    Label,
}

/// One enrolled desktop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminClient {
    /// Enrolment ID.
    pub id: EnrolmentId,
    /// Label chosen at enrolment (shown by `cerberusd admin list`).
    pub label: String,
    /// The operator whose phrase opens a session with this certificate (ADR-0034 point 3.3).
    pub operator_id: OperatorId,
    /// Lower-case hex SHA-256 of the client certificate (DER).
    pub cert_sha256: String,
    /// Enrolment time.
    pub created_at: Timestamp,
    /// End of validity of the certificate.
    pub not_after: Timestamp,
    /// Revocation time, if revoked.
    pub revoked_at: Option<Timestamp>,
}

impl AdminClient {
    /// The entry of a new enrolment with the certificate `cert_der`.
    ///
    /// # Errors
    /// [`ClientsError::Label`] for a bad label.
    pub fn enrolled(
        id: EnrolmentId,
        label: String,
        operator_id: OperatorId,
        cert_der: &[u8],
        not_after: Timestamp,
        now: Timestamp,
    ) -> Result<Self, ClientsError> {
        check_label(&label)?;
        Ok(Self {
            id,
            label,
            operator_id,
            cert_sha256: sha256_hex(cert_der),
            created_at: now,
            not_after,
            revoked_at: None,
        })
    }

    /// True when the entry is not revoked and its certificate has not expired at `now`.
    #[must_use]
    pub fn is_live(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && now < self.not_after
    }
}

/// Checks an enrolment label: 1 to [`MAX_LABEL_CHARS`] characters, no control characters.
///
/// # Errors
/// [`ClientsError::Label`].
pub fn check_label(label: &str) -> Result<(), ClientsError> {
    let chars = label.chars().count();
    if chars == 0 || chars > MAX_LABEL_CHARS || label.chars().any(char::is_control) {
        return Err(ClientsError::Label);
    }
    Ok(())
}

/// Lower-case hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The JSON form of the file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u32,
    clients: Vec<AdminClient>,
}

/// The registry in memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminClients {
    clients: Vec<AdminClient>,
}

impl AdminClients {
    /// Reads the registry. A missing file is an empty registry. The file must be a regular file
    /// with mode `0600` (on Unix).
    ///
    /// # Errors
    /// [`ClientsError::Mode`], [`ClientsError::NotAFile`], [`ClientsError::TooLarge`],
    /// [`ClientsError::Format`] (bad JSON, other version, bad hash, two entries with the same ID
    /// or certificate), or a file error.
    pub fn load(path: &Path) -> Result<Self, ClientsError> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        if !meta.file_type().is_file() {
            return Err(ClientsError::NotAFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(ClientsError::Mode { mode });
            }
        }
        if meta.len() > MAX_ADMIN_CLIENTS_BYTES {
            return Err(ClientsError::TooLarge);
        }
        let mut text = Vec::new();
        std::fs::File::open(path)?
            .take(MAX_ADMIN_CLIENTS_BYTES + 1)
            .read_to_end(&mut text)?;
        if text.len() as u64 > MAX_ADMIN_CLIENTS_BYTES {
            return Err(ClientsError::TooLarge);
        }
        let file: RegistryFile =
            serde_json::from_slice(&text).map_err(|_| ClientsError::Format("not registry JSON"))?;
        if file.version != ADMIN_CLIENTS_VERSION {
            return Err(ClientsError::Format("unknown registry version"));
        }
        let mut registry = Self::default();
        for client in file.clients {
            if !is_sha256_hex(&client.cert_sha256) {
                return Err(ClientsError::Format(
                    "a certificate hash is not SHA-256 hex",
                ));
            }
            if check_label(&client.label).is_err() {
                return Err(ClientsError::Format("a label is not valid"));
            }
            registry
                .add(client)
                .map_err(|_| ClientsError::Format("two entries have the same ID or certificate"))?;
        }
        Ok(registry)
    }

    /// Writes the registry: a new temporary file with mode `0600` next to `path`, then a rename,
    /// so a reader never sees half a file.
    ///
    /// # Errors
    /// A file error.
    pub fn save(&self, path: &Path) -> Result<(), ClientsError> {
        let file = RegistryFile {
            version: ADMIN_CLIENTS_VERSION,
            clients: self.clients.clone(),
        };
        let mut text = serde_json::to_vec_pretty(&file).map_err(std::io::Error::other)?;
        text.push(b'\n');
        let tmp = path.with_extension("json.tmp");
        // A stale temporary file keeps its old mode, so remove it and make a new one (AUD-30).
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut out = options.open(&tmp)?;
        out.write_all(&text)?;
        out.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// The live entry whose certificate has the SHA-256 `cert_sha256`, if any.
    #[must_use]
    pub fn find_live(&self, cert_sha256: &[u8; 32], now: Timestamp) -> Option<&AdminClient> {
        let wanted = hex(cert_sha256);
        self.clients
            .iter()
            .find(|client| client.cert_sha256 == wanted && client.is_live(now))
    }

    /// The entry with this ID, live or not.
    #[must_use]
    pub fn get(&self, id: EnrolmentId) -> Option<&AdminClient> {
        self.clients.iter().find(|client| client.id == id)
    }

    /// Adds an entry.
    ///
    /// # Errors
    /// [`ClientsError::Duplicate`] when an entry has the same ID or the same certificate.
    pub fn add(&mut self, client: AdminClient) -> Result<(), ClientsError> {
        if self
            .clients
            .iter()
            .any(|c| c.id == client.id || c.cert_sha256 == client.cert_sha256)
        {
            return Err(ClientsError::Duplicate);
        }
        self.clients.push(client);
        Ok(())
    }

    /// Revokes an entry at `now`. True when the entry exists and was not revoked yet; a second
    /// revoke keeps the first time.
    pub fn revoke(&mut self, id: EnrolmentId, now: Timestamp) -> bool {
        match self.clients.iter_mut().find(|client| client.id == id) {
            Some(client) if client.revoked_at.is_none() => {
                client.revoked_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Takes in every revoke of `other` that this registry lacks: an entry with the same ID that
    /// is revoked there and not here gets the revoke time of `other`. Nothing is ever un-revoked,
    /// and entries that are only in `other` are not added. Gives the IDs it revoked.
    ///
    /// The daemon calls it before it writes the file and when it reads it again, so neither
    /// direction undoes a revoke of the other (an offline `cerberusd admin revoke`, or a revoke
    /// whose save failed) (DEC-RM-22).
    pub fn adopt_revokes(&mut self, other: &Self) -> Vec<EnrolmentId> {
        let mut revoked = Vec::new();
        for client in &mut self.clients {
            if client.revoked_at.is_some() {
                continue;
            }
            if let Some(at) = other.get(client.id).and_then(|c| c.revoked_at) {
                client.revoked_at = Some(at);
                revoked.push(client.id);
            }
        }
        revoked
    }

    /// Every entry, in enrolment order.
    #[must_use]
    pub fn list(&self) -> &[AdminClient] {
        &self.clients
    }

    /// Number of live entries at `now`.
    #[must_use]
    pub fn live_count(&self, now: Timestamp) -> usize {
        self.clients.iter().filter(|c| c.is_live(now)).count()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use cerberus_types::t0;
    use jiff::SignedDuration;

    use super::*;

    fn entry(cert: &[u8], now: Timestamp) -> AdminClient {
        AdminClient::enrolled(
            EnrolmentId::generate(),
            "laptop".to_owned(),
            OperatorId::generate(),
            cert,
            now + SignedDuration::from_hours(24 * 90),
            now,
        )
        .unwrap()
    }

    fn digest(cert: &[u8]) -> [u8; 32] {
        Sha256::digest(cert).into()
    }

    #[test]
    fn a_missing_file_is_an_empty_registry_and_a_saved_one_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ADMIN_CLIENTS_FILE);
        assert_eq!(AdminClients::load(&path).unwrap(), AdminClients::default());
        let mut registry = AdminClients::default();
        registry.add(entry(b"cert-a", t0())).unwrap();
        registry.add(entry(b"cert-b", t0())).unwrap();
        registry.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let again = AdminClients::load(&path).unwrap();
        assert_eq!(again, registry);
        assert_eq!(again.live_count(t0()), 2);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 1"));
        assert!(text.contains(&sha256_hex(b"cert-a")));
    }

    #[cfg(unix)]
    #[test]
    fn a_wider_mode_or_a_link_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ADMIN_CLIENTS_FILE);
        AdminClients::default().save(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            AdminClients::load(&path),
            Err(ClientsError::Mode { mode: 0o644 })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            AdminClients::load(&link),
            Err(ClientsError::NotAFile)
        ));
    }

    #[test]
    fn find_live_skips_revoked_and_expired_entries() {
        let now = t0();
        let mut registry = AdminClients::default();
        let live = entry(b"live", now);
        let revoked = entry(b"revoked", now);
        let revoked_id = revoked.id;
        registry.add(live.clone()).unwrap();
        registry.add(revoked).unwrap();
        assert!(registry.revoke(revoked_id, now));
        assert!(!registry.revoke(revoked_id, now + SignedDuration::from_secs(5)));
        assert_eq!(registry.get(revoked_id).unwrap().revoked_at, Some(now));
        assert!(!registry.revoke(EnrolmentId::generate(), now));

        assert_eq!(registry.find_live(&digest(b"live"), now), Some(&live));
        assert_eq!(registry.find_live(&digest(b"revoked"), now), None);
        assert_eq!(registry.find_live(&digest(b"unknown"), now), None);
        let expired = live.not_after;
        assert_eq!(registry.find_live(&digest(b"live"), expired), None);
        assert_eq!(registry.live_count(now), 1);
    }

    /// DEC-RM-22: a revoke on one side is taken in by the other, with its time; nothing is
    /// un-revoked and nothing is added.
    #[test]
    fn adopt_revokes_takes_in_revokes_and_never_undoes_one() {
        let now = t0();
        let later = now + SignedDuration::from_secs(60);
        let (a, b, c) = (entry(b"a", now), entry(b"b", now), entry(b"c", now));
        let mut memory = AdminClients::default();
        memory.add(a.clone()).unwrap();
        memory.add(b.clone()).unwrap();
        assert!(memory.revoke(b.id, now));
        let mut disk = AdminClients::default();
        disk.add(a.clone()).unwrap();
        disk.add(b.clone()).unwrap();
        disk.add(c.clone()).unwrap();
        assert!(disk.revoke(a.id, later));
        assert_eq!(memory.adopt_revokes(&disk), vec![a.id]);
        assert_eq!(memory.get(a.id).unwrap().revoked_at, Some(later));
        assert_eq!(memory.get(b.id).unwrap().revoked_at, Some(now), "kept");
        assert!(memory.get(c.id).is_none(), "not added");
        assert!(memory.adopt_revokes(&disk).is_empty());
        assert_eq!(disk.adopt_revokes(&memory), vec![b.id]);
    }

    #[test]
    fn duplicates_and_bad_labels_are_refused() {
        let now = t0();
        let mut registry = AdminClients::default();
        let first = entry(b"same", now);
        registry.add(first.clone()).unwrap();
        assert!(matches!(
            registry.add(entry(b"same", now)),
            Err(ClientsError::Duplicate)
        ));
        let same_id = AdminClient {
            cert_sha256: sha256_hex(b"other"),
            ..first
        };
        assert!(matches!(
            registry.add(same_id),
            Err(ClientsError::Duplicate)
        ));
        for label in ["", "a\nb", &"x".repeat(65)] {
            let made = AdminClient::enrolled(
                EnrolmentId::generate(),
                label.to_owned(),
                OperatorId::generate(),
                b"c",
                now,
                now,
            );
            assert!(matches!(made, Err(ClientsError::Label)), "{label:?}");
        }
        assert!(check_label(&"é".repeat(64)).is_ok());
    }

    #[test]
    fn a_bad_file_is_a_format_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ADMIN_CLIENTS_FILE);
        let write = |text: &str| {
            let mut registry_text = text.as_bytes().to_vec();
            registry_text.push(b'\n');
            AdminClients::default().save(&path).unwrap();
            std::fs::write(&path, registry_text).unwrap();
        };
        write("not json");
        assert!(matches!(
            AdminClients::load(&path),
            Err(ClientsError::Format(_))
        ));
        write(r#"{"version":2,"clients":[]}"#);
        assert!(matches!(
            AdminClients::load(&path),
            Err(ClientsError::Format(_))
        ));
        write(r#"{"version":1,"clients":[],"extra":true}"#);
        assert!(matches!(
            AdminClients::load(&path),
            Err(ClientsError::Format(_))
        ));
        let mut bad = entry(b"x", t0());
        bad.cert_sha256 = "ABC".to_owned();
        let text = serde_json::to_string(&RegistryFile {
            version: 1,
            clients: vec![bad],
        })
        .unwrap();
        write(&text);
        assert!(matches!(
            AdminClients::load(&path),
            Err(ClientsError::Format(_))
        ));
        let one = entry(b"y", t0());
        let text = serde_json::to_string(&RegistryFile {
            version: 1,
            clients: vec![one.clone(), one],
        })
        .unwrap();
        write(&text);
        assert!(matches!(
            AdminClients::load(&path),
            Err(ClientsError::Format(_))
        ));
    }
}
