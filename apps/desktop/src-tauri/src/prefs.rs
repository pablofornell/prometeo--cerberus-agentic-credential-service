//! Desktop preferences kept outside the vault: the network bind, autostart, content protection
//! and the RustDesk client program.
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

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
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
}
