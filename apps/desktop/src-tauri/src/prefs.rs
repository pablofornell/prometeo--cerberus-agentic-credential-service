//! Desktop preferences kept outside the vault: the network bind, autostart, content protection,
//! the RustDesk client program and the remote server profiles (ADR-0034 point 1.3).
//!
//! They are not secret and they must be readable before the vault unlocks (the server starts
//! sealed), so they live in a small JSON file in the app data directory (DEC-T15-7).

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use cerberus_api::DEFAULT_PORT;
use serde::{Deserialize, Serialize};

/// File name inside the data directory.
const FILE: &str = "desktop-prefs.json";

/// The app data paths.
#[derive(Clone, Debug)]
pub struct AppPaths {
    /// The data directory.
    pub data_dir: PathBuf,
}

impl AppPaths {
    /// Paths under `data_dir`.
    #[must_use]
    pub const fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// The vault file.
    #[must_use]
    pub fn vault_file(&self) -> PathBuf {
        self.data_dir.join("vault.cerberus")
    }

    fn prefs_file(&self) -> PathBuf {
        self.data_dir.join(FILE)
    }

    /// The folder of all remote profiles (`<data_dir>/remote`).
    #[must_use]
    pub fn remote_root(&self) -> PathBuf {
        self.data_dir.join("remote")
    }
}

/// One imported enrolment bundle (ADR-0034 point 7.10). The certificate and key files are in
/// `<data_dir>/remote/<id>/`; this entry holds no key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteProfile {
    /// Enrolment ID (a UUID): also the name of the profile folder.
    pub id: String,
    /// Enrolment label.
    pub label: String,
    /// Base URL of the server, `https://host:port`.
    pub url: String,
    /// `sha256/<base64>` pin of the server CA key.
    pub ca_pin: String,
    /// Lower-case hex SHA-256 of the CA certificate.
    pub ca_sha256: String,
    /// The operator the enrolment is bound to.
    pub operator_id: String,
    /// End of validity of the client certificate.
    pub not_after: jiff::Timestamp,
}

/// The remote server profiles. `active = None` is local mode, the safe default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemotePrefs {
    /// The profile the next start uses. `None`: local mode.
    pub active: Option<String>,
    /// Every imported profile.
    pub profiles: Vec<RemoteProfile>,
}

impl RemotePrefs {
    /// The profile with this ID.
    #[must_use]
    pub fn profile(&self, id: &str) -> Option<&RemoteProfile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }
}

/// The preferences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Addresses of the HTTPS server. Default: loopback IPv4 and IPv6.
    pub bind: Vec<IpAddr>,
    /// Port of the HTTPS server.
    pub port: u16,
    /// Start the app at login. Off by default.
    pub autostart: bool,
    /// Ask the OS not to capture the window in screenshots. Off by default.
    pub content_protection: bool,
    /// The RustDesk client program the person chose (DEC-RD-3). `None`: look for it.
    pub rustdesk_path: Option<PathBuf>,
    /// The remote server profiles and the active one (ADR-0034). Files written before remote
    /// mode existed have none: local mode.
    pub remote: RemotePrefs,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            bind: vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            port: DEFAULT_PORT,
            autostart: false,
            content_protection: false,
            rustdesk_path: None,
            remote: RemotePrefs::default(),
        }
    }
}

impl Prefs {
    /// True when any bind address is not loopback (ADR-0023: needs mTLS).
    #[must_use]
    pub fn is_lan(&self) -> bool {
        self.bind.iter().any(|ip| !ip.is_loopback())
    }

    /// Reads the file. A missing or damaged file gives the defaults (a damaged file is logged).
    #[must_use]
    pub fn load(paths: &AppPaths) -> Self {
        match std::fs::read(paths.prefs_file()) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                tracing::warn!(%error, "desktop preferences are damaged; using defaults");
                Self::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(error) => {
                tracing::warn!(%error, "cannot read desktop preferences; using defaults");
                Self::default()
            }
        }
    }

    /// Writes the file: a temporary file next to it, then a rename, mode `0600`.
    ///
    /// # Errors
    /// An I/O error.
    pub fn save(&self, paths: &AppPaths) -> std::io::Result<()> {
        let target = paths.prefs_file();
        let tmp = target.with_extension("json.tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &target)
    }
}

/// Writes `bytes` to `path` (made or emptied) with mode `0600`, and syncs it. The mode applies
/// to a file that existed with a wider one too (the create mode only covers a new file), before
/// any byte is written (DEC-RM-26).
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_and_off() {
        let prefs = Prefs::default();
        assert!(!prefs.is_lan());
        assert!(!prefs.autostart && !prefs.content_protection);
        assert_eq!(prefs.port, DEFAULT_PORT);
    }

    #[test]
    fn save_and_load_round_trip_and_a_bad_file_gives_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = AppPaths::new(dir.path().to_path_buf());
        let prefs = Prefs {
            autostart: true,
            port: 8443,
            ..Prefs::default()
        };
        prefs.save(&paths).expect("save");
        assert_eq!(Prefs::load(&paths), prefs);
        std::fs::write(paths.prefs_file(), b"{ not json").expect("write");
        assert_eq!(Prefs::load(&paths), Prefs::default());
    }

    #[cfg(unix)]
    #[test]
    fn a_private_write_narrows_a_wider_existing_file_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        std::fs::write(&path, b"old").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private(&path, b"new").expect("private write");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).expect("read"), b"new");
    }

    #[test]
    fn a_file_without_remote_profiles_is_local_mode_and_profiles_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = AppPaths::new(dir.path().to_path_buf());
        std::fs::write(paths.prefs_file(), br#"{"port": 8443, "autostart": true}"#).expect("write");
        let old = Prefs::load(&paths);
        assert_eq!(old.port, 8443);
        assert_eq!(old.remote, RemotePrefs::default());
        assert!(old.remote.active.is_none());
        let profile = RemoteProfile {
            id: "0190f1e2-0000-7000-8000-000000000001".to_owned(),
            label: "laptop".to_owned(),
            url: "https://vault.example.test:8443".to_owned(),
            ca_pin: "sha256/AAAA".to_owned(),
            ca_sha256: "00".repeat(32),
            operator_id: "0190f1e2-0000-7000-8000-000000000002".to_owned(),
            not_after: "2027-02-19T00:00:00Z".parse().expect("time"),
        };
        let prefs = Prefs {
            remote: RemotePrefs {
                active: Some(profile.id.clone()),
                profiles: vec![profile.clone()],
            },
            ..old
        };
        prefs.save(&paths).expect("save");
        let back = Prefs::load(&paths);
        assert_eq!(back, prefs);
        assert_eq!(back.remote.profile(&profile.id), Some(&profile));
        assert!(back.remote.profile("other").is_none());
    }
}
