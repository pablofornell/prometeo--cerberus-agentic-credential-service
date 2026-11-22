//! Settings of `cerberusd`: a TOML file, then `CERBERUSD_*` environment variables, which win (ADR-0002 point 5).
//!
//! The file must have mode `0600`. The daemon refuses any other mode. Unknown keys and bad values stop the start,
//! and the error names the key.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cerberus_api::{AdminLimits, DEFAULT_PORT};
use cerberus_core::vault::{IDLE_LOCK_RANGE, MAX_UNLOCKED_RANGE};
use serde::Deserialize;

/// Name of the config file in the XDG config directory (`$XDG_CONFIG_HOME/cerberusd/`).
pub const CONFIG_FILE: &str = "cerberusd.toml";
/// Name of the data directory under the XDG data directory (`$XDG_DATA_HOME/cerberusd`).
pub const DATA_DIR_NAME: &str = "cerberusd";
/// The only mode the config file may have.
pub const CONFIG_MODE: u32 = 0o600;
/// Longest host name the daemon accepts in `host_names`.
const MAX_HOST_NAME: usize = 253;
/// Allowed admin session idle limits, in seconds (ADR-0034 point 2.1).
pub const ADMIN_IDLE_RANGE: std::ops::RangeInclusive<u32> = 60..=3600;
/// Allowed admin session absolute limits, in seconds (ADR-0034 point 2.1).
pub const ADMIN_MAX_RANGE: std::ops::RangeInclusive<u32> = 900..=86_400;

/// The `[admin]` table: the admin API for an enrolled desktop app (ADR-0034). Off by default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminSettings {
    /// Mount `/admin/v1` on the HTTPS listener and allow approvals (`ask_once`, `ask_always`).
    pub enabled: bool,
    /// An admin session ends after this many seconds without a call: 60 to 3600, default 900.
    pub session_idle_seconds: u32,
    /// An admin session ends this many seconds after it opened: 900 to 86400, default 43200.
    pub session_max_seconds: u32,
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            session_idle_seconds: 900,
            session_max_seconds: 43_200,
        }
    }
}

impl AdminSettings {
    /// The limits of the admin API: these session limits, the fixed ADR-0034 values otherwise.
    #[must_use]
    pub fn limits(&self) -> AdminLimits {
        AdminLimits {
            session_idle_seconds: self.session_idle_seconds,
            session_max_seconds: self.session_max_seconds,
            ..AdminLimits::default()
        }
    }
}

/// The settings the daemon runs with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Directory with `vault.cerberus`, the TLS files and the unlock socket. Absolute.
    pub data_dir: PathBuf,
    /// Addresses to listen on. A non-loopback address needs `require_mtls`.
    pub bind: Vec<IpAddr>,
    /// TCP port for every address, 1 to 65535. `status` probes this port, so it cannot be `0`.
    pub port: u16,
    /// Extra names for the TLS leaf and the allowed `Host` values. The standard names are always there.
    pub host_names: Vec<String>,
    /// Require a client certificate (mTLS) on every connection, signed by the vault CA (ADR-0023).
    pub require_mtls: bool,
    /// Idle lock in seconds. `0` is off, the daemon default (ADR-0002 point 7).
    pub idle_lock_seconds: u32,
    /// Hard limit after unlock in seconds. `0` is off, the daemon default. An admin can change it
    /// at run time with the vault settings.
    pub max_unlocked_seconds: u32,
    /// The admin API (ADR-0034). Off by default.
    pub admin: AdminSettings,
}

impl Config {
    /// The socket addresses to bind: every address with the port.
    #[must_use]
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.bind
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect()
    }

    /// The idle lock as a duration, or `None` when it is off.
    #[must_use]
    pub fn idle_lock(&self) -> Option<Duration> {
        (self.idle_lock_seconds > 0).then(|| Duration::from_secs(u64::from(self.idle_lock_seconds)))
    }

    /// The hard limit after unlock as a duration, or `None` when it is off.
    #[must_use]
    pub fn max_unlocked(&self) -> Option<Duration> {
        (self.max_unlocked_seconds > 0)
            .then(|| Duration::from_secs(u64::from(self.max_unlocked_seconds)))
    }
}

/// Why the settings are not usable.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file cannot be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// The config file has the wrong mode.
    #[error("config file {path} has mode {mode:o}; it must be 0600 (chmod 0600 {path})", path = .path.display())]
    Mode {
        /// The file.
        path: PathBuf,
        /// The mode found, permission bits only.
        mode: u32,
    },
    /// The config file is not valid TOML or has unknown keys.
    #[error("config file {path}: {message}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// The parser's message. It names the key.
        message: String,
    },
    /// A value is out of range or not allowed. The text names the key.
    #[error("{key}: {reason}")]
    Invalid {
        /// The config key or environment variable.
        key: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// The data directory is not given and no home directory is known.
    #[error("no data_dir: set data_dir, CERBERUSD_DATA_DIR, XDG_DATA_HOME or HOME")]
    NoDataDir,
}

/// The file keys. Every key is optional; missing keys take the default.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    data_dir: Option<String>,
    bind: Option<Vec<String>>,
    port: Option<i64>,
    host_names: Option<Vec<String>>,
    require_mtls: Option<bool>,
    idle_lock_seconds: Option<i64>,
    max_unlocked_seconds: Option<i64>,
    admin: Option<FileAdmin>,
}

/// The `[admin]` table of the file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAdmin {
    enabled: Option<bool>,
    session_idle_seconds: Option<i64>,
    session_max_seconds: Option<i64>,
}

/// Looks up an environment variable. `None` when it is unset.
pub type EnvFn<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The default config file: `$XDG_CONFIG_HOME/cerberusd/cerberusd.toml`, or under `$HOME/.config`.
#[must_use]
pub fn default_config_path(env: EnvFn<'_>) -> Option<PathBuf> {
    base_dir(env, "XDG_CONFIG_HOME", ".config").map(|dir| dir.join(DATA_DIR_NAME).join(CONFIG_FILE))
}

/// The default data directory: `$XDG_DATA_HOME/cerberusd`, or under `$HOME/.local/share`.
#[must_use]
pub fn default_data_dir(env: EnvFn<'_>) -> Option<PathBuf> {
    base_dir(env, "XDG_DATA_HOME", ".local/share").map(|dir| dir.join(DATA_DIR_NAME))
}

fn base_dir(env: EnvFn<'_>, xdg: &str, home_sub: &str) -> Option<PathBuf> {
    if let Some(dir) = env(xdg).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    env("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(home_sub))
}

/// Loads the settings. With `path`, that file must exist. Without it, the default file is read when it exists.
/// Environment variables override the file.
///
/// # Errors
/// [`ConfigError`] for a file that cannot be read, has the wrong mode or unknown keys, or a value out of range.
pub fn load(path: Option<&Path>, env: EnvFn<'_>) -> Result<Config, ConfigError> {
    let file = match path {
        Some(path) => read_file(path)?,
        None => match default_config_path(env) {
            Some(default) if default.exists() => read_file(&default)?,
            _ => FileConfig::default(),
        },
    };
    resolve(file, env)
}

fn read_file(path: &Path) -> Result<FileConfig, ConfigError> {
    let meta = std::fs::metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != CONFIG_MODE {
        return Err(ConfigError::Mode {
            path: path.to_path_buf(),
            mode,
        });
    }
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|error| ConfigError::Parse {
        path: path.to_path_buf(),
        message: error.message().to_owned(),
    })
}

fn resolve(file: FileConfig, env: EnvFn<'_>) -> Result<Config, ConfigError> {
    let data_dir = match env("CERBERUSD_DATA_DIR") {
        Some(value) => PathBuf::from(value),
        None => match file.data_dir {
            Some(value) => PathBuf::from(value),
            None => default_data_dir(env).ok_or(ConfigError::NoDataDir)?,
        },
    };
    let bind_text = match env("CERBERUSD_BIND") {
        Some(value) => list_from_env(&value),
        None => file
            .bind
            .unwrap_or_else(|| vec!["127.0.0.1".into(), "::1".into()]),
    };
    let bind = bind_text
        .iter()
        .map(|text| {
            text.parse::<IpAddr>().map_err(|_| ConfigError::Invalid {
                key: "bind",
                reason: format!("{text:?} is not an IP address"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let port = match env("CERBERUSD_PORT") {
        Some(value) => int_from_env(&value, "CERBERUSD_PORT")?,
        None => file.port.unwrap_or(i64::from(DEFAULT_PORT)),
    };
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| ConfigError::Invalid {
            key: "port",
            reason: format!("{port} is not a port number (1 to 65535)"),
        })?;
    let host_names = match env("CERBERUSD_HOST_NAMES") {
        Some(value) => list_from_env(&value),
        None => file.host_names.unwrap_or_default(),
    };
    let require_mtls = match env("CERBERUSD_REQUIRE_MTLS") {
        Some(value) => bool_from_env(&value, "CERBERUSD_REQUIRE_MTLS")?,
        None => file.require_mtls.unwrap_or(false),
    };
    let idle = match env("CERBERUSD_IDLE_LOCK_SECONDS") {
        Some(value) => int_from_env(&value, "CERBERUSD_IDLE_LOCK_SECONDS")?,
        None => file.idle_lock_seconds.unwrap_or(0),
    };
    let idle_lock_seconds = u32::try_from(idle).map_err(|_| ConfigError::Invalid {
        key: "idle_lock_seconds",
        reason: format!("{idle} is not a number of seconds"),
    })?;
    let max_unlocked = match env("CERBERUSD_MAX_UNLOCKED_SECONDS") {
        Some(value) => int_from_env(&value, "CERBERUSD_MAX_UNLOCKED_SECONDS")?,
        None => file.max_unlocked_seconds.unwrap_or(0),
    };
    let max_unlocked_seconds = u32::try_from(max_unlocked).map_err(|_| ConfigError::Invalid {
        key: "max_unlocked_seconds",
        reason: format!("{max_unlocked} is not a number of seconds"),
    })?;
    let admin = resolve_admin(file.admin.unwrap_or_default(), env)?;
    let config = Config {
        data_dir,
        bind,
        port,
        host_names,
        require_mtls,
        idle_lock_seconds,
        max_unlocked_seconds,
        admin,
    };
    validate(&config)?;
    Ok(config)
}

fn resolve_admin(file: FileAdmin, env: EnvFn<'_>) -> Result<AdminSettings, ConfigError> {
    let defaults = AdminSettings::default();
    let enabled = match env("CERBERUSD_ADMIN_ENABLED") {
        Some(value) => bool_from_env(&value, "CERBERUSD_ADMIN_ENABLED")?,
        None => file.enabled.unwrap_or(defaults.enabled),
    };
    let seconds = |env_key: &'static str,
                   key: &'static str,
                   from_file: Option<i64>,
                   default: u32|
     -> Result<u32, ConfigError> {
        let value = match env(env_key) {
            Some(value) => int_from_env(&value, env_key)?,
            None => from_file.unwrap_or(i64::from(default)),
        };
        u32::try_from(value).map_err(|_| ConfigError::Invalid {
            key,
            reason: format!("{value} is not a number of seconds"),
        })
    };
    Ok(AdminSettings {
        enabled,
        session_idle_seconds: seconds(
            "CERBERUSD_ADMIN_SESSION_IDLE_SECONDS",
            "admin.session_idle_seconds",
            file.session_idle_seconds,
            defaults.session_idle_seconds,
        )?,
        session_max_seconds: seconds(
            "CERBERUSD_ADMIN_SESSION_MAX_SECONDS",
            "admin.session_max_seconds",
            file.session_max_seconds,
            defaults.session_max_seconds,
        )?,
    })
}

fn validate_admin(admin: &AdminSettings) -> Result<(), ConfigError> {
    if !ADMIN_IDLE_RANGE.contains(&admin.session_idle_seconds) {
        return Err(ConfigError::Invalid {
            key: "admin.session_idle_seconds",
            reason: "must be 60 to 3600".into(),
        });
    }
    if !ADMIN_MAX_RANGE.contains(&admin.session_max_seconds) {
        return Err(ConfigError::Invalid {
            key: "admin.session_max_seconds",
            reason: "must be 900 to 86400".into(),
        });
    }
    if admin.session_idle_seconds > admin.session_max_seconds {
        return Err(ConfigError::Invalid {
            key: "admin.session_idle_seconds",
            reason: "must not be longer than admin.session_max_seconds".into(),
        });
    }
    Ok(())
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    validate_admin(&config.admin)?;
    if !config.data_dir.is_absolute() {
        return Err(ConfigError::Invalid {
            key: "data_dir",
            reason: "must be an absolute path".into(),
        });
    }
    if config.bind.is_empty() {
        return Err(ConfigError::Invalid {
            key: "bind",
            reason: "at least one address is needed".into(),
        });
    }
    if config.bind.iter().any(|ip| !ip.is_loopback()) && !config.require_mtls {
        return Err(ConfigError::Invalid {
            key: "require_mtls",
            reason: "a non-loopback bind needs require_mtls = true (ADR-0023)".into(),
        });
    }
    if config.idle_lock_seconds != 0 && !IDLE_LOCK_RANGE.contains(&config.idle_lock_seconds) {
        return Err(ConfigError::Invalid {
            key: "idle_lock_seconds",
            reason: "must be 0 (off) or 60 to 86400".into(),
        });
    }
    if config.max_unlocked_seconds != 0
        && !MAX_UNLOCKED_RANGE.contains(&config.max_unlocked_seconds)
    {
        return Err(ConfigError::Invalid {
            key: "max_unlocked_seconds",
            reason: "must be 0 (off) or 900 to 604800".into(),
        });
    }
    for name in &config.host_names {
        if !valid_host_name(name) {
            return Err(ConfigError::Invalid {
                key: "host_names",
                reason: format!("{name:?} is not a host name"),
            });
        }
    }
    Ok(())
}

fn valid_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn int_from_env(value: &str, key: &'static str) -> Result<i64, ConfigError> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| ConfigError::Invalid {
            key,
            reason: format!("{value:?} is not a whole number"),
        })
}

fn bool_from_env(value: &str, key: &'static str) -> Result<bool, ConfigError> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::Invalid {
            key,
            reason: "must be true or false".into(),
        }),
    }
}

fn list_from_env(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn xdg_paths_win_over_home() {
        let env = |key: &str| match key {
            "XDG_CONFIG_HOME" => Some("/cfg".to_owned()),
            "HOME" => Some("/home/u".to_owned()),
            _ => None,
        };
        assert_eq!(
            default_config_path(&env),
            Some(PathBuf::from("/cfg/cerberusd/cerberusd.toml"))
        );
        assert_eq!(
            default_data_dir(&env),
            Some(PathBuf::from("/home/u/.local/share/cerberusd"))
        );
    }

    #[test]
    fn defaults_are_loopback_and_no_idle_lock() {
        let env = |key: &str| match key {
            "CERBERUSD_DATA_DIR" => Some("/var/lib/cerberus".to_owned()),
            _ => None,
        };
        let config = resolve(FileConfig::default(), &env).expect("defaults");
        assert_eq!(config.port, DEFAULT_PORT);
        assert_eq!(config.bind.len(), 2);
        assert!(config.bind.iter().all(IpAddr::is_loopback));
        assert_eq!(config.idle_lock(), None);
        assert_eq!(config.max_unlocked(), None);
        assert!(!config.require_mtls);
    }

    #[test]
    fn env_overrides_the_file() {
        let file = FileConfig {
            port: Some(9000),
            ..FileConfig::default()
        };
        let env = |key: &str| match key {
            "CERBERUSD_DATA_DIR" => Some("/srv/cerberus".to_owned()),
            "CERBERUSD_PORT" => Some("9100".to_owned()),
            _ => None,
        };
        let config = resolve(file, &env).expect("config");
        assert_eq!(config.port, 9100);
        assert_eq!(config.data_dir, PathBuf::from("/srv/cerberus"));
    }

    #[test]
    fn lan_bind_without_mtls_is_refused() {
        let file = FileConfig {
            data_dir: Some("/srv/cerberus".into()),
            bind: Some(vec!["0.0.0.0".into()]),
            ..FileConfig::default()
        };
        let error = resolve(file, &no_env).expect_err("refused");
        assert!(error.to_string().starts_with("require_mtls:"), "{error}");
    }

    #[test]
    fn idle_lock_range_is_checked() {
        let file = FileConfig {
            data_dir: Some("/srv/cerberus".into()),
            idle_lock_seconds: Some(5),
            ..FileConfig::default()
        };
        let error = resolve(file, &no_env).expect_err("refused");
        assert!(
            error.to_string().starts_with("idle_lock_seconds:"),
            "{error}"
        );
    }

    #[test]
    fn max_unlocked_is_off_by_default_and_set_by_file_or_env() {
        let file = FileConfig {
            data_dir: Some("/srv/cerberus".into()),
            max_unlocked_seconds: Some(86_400),
            ..FileConfig::default()
        };
        let config = resolve(file, &no_env).expect("config");
        assert_eq!(config.max_unlocked(), Some(Duration::from_secs(86_400)));

        let file = FileConfig {
            data_dir: Some("/srv/cerberus".into()),
            max_unlocked_seconds: Some(86_400),
            ..FileConfig::default()
        };
        let env = |key: &str| (key == "CERBERUSD_MAX_UNLOCKED_SECONDS").then(|| "0".to_owned());
        let config = resolve(file, &env).expect("env turns it off");
        assert_eq!(config.max_unlocked(), None);
    }

    #[test]
    fn max_unlocked_range_is_checked() {
        for bad in [-1, 5, 899, 604_801] {
            let file = FileConfig {
                data_dir: Some("/srv/cerberus".into()),
                max_unlocked_seconds: Some(bad),
                ..FileConfig::default()
            };
            let error = resolve(file, &no_env).expect_err("refused");
            assert!(
                error.to_string().starts_with("max_unlocked_seconds:"),
                "{bad}: {error}"
            );
        }
    }

    #[test]
    fn relative_data_dir_is_refused() {
        let file = FileConfig {
            data_dir: Some("cerberus".into()),
            ..FileConfig::default()
        };
        let error = resolve(file, &no_env).expect_err("refused");
        assert!(error.to_string().starts_with("data_dir:"), "{error}");
    }

    fn data_dir_env(key: &str) -> Option<String> {
        (key == "CERBERUSD_DATA_DIR").then(|| "/srv/cerberus".to_owned())
    }

    #[test]
    fn the_admin_api_is_off_by_default() {
        let config = resolve(FileConfig::default(), &data_dir_env).expect("defaults");
        assert_eq!(config.admin, AdminSettings::default());
        assert!(!config.admin.enabled);
        assert_eq!(config.admin.limits(), AdminLimits::default());
        let file: FileConfig = toml::from_str("[admin]\n").expect("empty table");
        let config = resolve(file, &data_dir_env).expect("empty table");
        assert!(!config.admin.enabled);
    }

    #[test]
    fn the_admin_table_is_read_and_the_environment_wins() {
        let file: FileConfig = toml::from_str(
            "[admin]\nenabled = true\nsession_idle_seconds = 300\nsession_max_seconds = 3600\n",
        )
        .expect("toml");
        let config = resolve(file, &data_dir_env).expect("config");
        assert!(config.admin.enabled);
        assert_eq!(config.admin.limits().session_idle_seconds, 300);
        assert_eq!(config.admin.limits().session_max_seconds, 3600);
        let file: FileConfig =
            toml::from_str("[admin]\nenabled = true\nsession_idle_seconds = 300\n").expect("toml");
        let env = |key: &str| match key {
            "CERBERUSD_ADMIN_ENABLED" => Some("false".to_owned()),
            "CERBERUSD_ADMIN_SESSION_IDLE_SECONDS" => Some("120".to_owned()),
            "CERBERUSD_ADMIN_SESSION_MAX_SECONDS" => Some("1800".to_owned()),
            other => data_dir_env(other),
        };
        let config = resolve(file, &env).expect("config");
        assert!(!config.admin.enabled);
        assert_eq!(config.admin.session_idle_seconds, 120);
        assert_eq!(config.admin.session_max_seconds, 1800);
        let env = |key: &str| match key {
            "CERBERUSD_ADMIN_ENABLED" => Some("yes".to_owned()),
            other => data_dir_env(other),
        };
        let error = resolve(FileConfig::default(), &env).expect_err("refused");
        assert!(
            error.to_string().starts_with("CERBERUSD_ADMIN_ENABLED:"),
            "{error}"
        );
    }

    #[test]
    fn admin_session_ranges_are_checked() {
        for (text, key) in [
            ("session_idle_seconds = 59", "admin.session_idle_seconds:"),
            ("session_idle_seconds = 3601", "admin.session_idle_seconds:"),
            ("session_max_seconds = 899", "admin.session_max_seconds:"),
            ("session_max_seconds = 86401", "admin.session_max_seconds:"),
            (
                "session_idle_seconds = 3600\nsession_max_seconds = 900",
                "admin.session_idle_seconds:",
            ),
            ("session_idle_seconds = -1", "admin.session_idle_seconds:"),
        ] {
            let file: FileConfig = toml::from_str(&format!("[admin]\n{text}\n")).expect("toml");
            let error = resolve(file, &data_dir_env).expect_err(text);
            assert!(error.to_string().starts_with(key), "{text}: {error}");
        }
        for text in [
            "session_idle_seconds = 60\nsession_max_seconds = 900",
            "session_idle_seconds = 3600\nsession_max_seconds = 86400",
        ] {
            let file: FileConfig = toml::from_str(&format!("[admin]\n{text}\n")).expect("toml");
            assert!(resolve(file, &data_dir_env).is_ok(), "{text}");
        }
    }

    #[test]
    fn an_unknown_admin_key_is_refused_with_its_name() {
        let error = toml::from_str::<FileConfig>("[admin]\nenable = true\n").expect_err("refused");
        assert!(error.message().contains("enable"), "{}", error.message());
    }

    #[test]
    fn unknown_file_key_is_refused_with_its_name() {
        let error = toml::from_str::<FileConfig>("prot = 1\n").expect_err("refused");
        assert!(error.message().contains("prot"), "{}", error.message());
    }
}
