//! `cerberusd init`: makes a new vault on the server, so a headless deploy needs no desktop app.
//!
//! The command asks for the owner passphrase twice (echo off), tunes the key derivation cost to this machine (the same
//! 700 ms target as the desktop, ADR-0013), makes the vault with the core API and hands out the recovery key one time:
//! on the terminal, or into a new file of mode `0600` outside the data folder. The key is never printed when stdout is
//! not a terminal, so it does not end in a journal or a log file. The core settings are the ones `serve` uses
//! ([`core_config`]), and the TLS names are the `host_names` of the config, so the certificate and the Host check of
//! `serve` agree.
//!
//! Order, so that an interrupt or an error leaves nothing behind that blocks a second run:
//! 1. Checks that need no file: the vault and its side files do not exist, the folder modes, the recovery path.
//! 2. The passphrase (twice), the policy checks and the cost test. Nothing exists on disk yet.
//! 3. A short section that makes files: the data folder, the recovery file and the vault file (both made exclusively,
//!    `O_CREAT | O_EXCL`, mode `0600`), then the vault itself. SIGINT, SIGTERM, SIGHUP and SIGQUIT are held during it and the run
//!    finishes first, because the recovery key is shown only at the end.
//!
//! The command never removes a file it did not make: a vault file that appears after the first check makes the
//! exclusive create fail, and the command stops without touching it. When the vault cannot be made, the files that this
//! run made are removed again.

use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use cerberus_api::tls::TlsPaths;
use cerberus_core::vault::KeyCustody;
use cerberus_core::{CoreError, CreatedVault, NewVault, VaultService};
use cerberus_crypto::{
    KdfParams, SecretString, meets_phrase_policy, normalize_phrase, total_ram_bytes, tune_kdf,
};
use cerberus_store::{OpenOptions, Store, StoreError};
use cerberus_types::{Clock, LockReason, OperatorId, SystemClock};
use tokio::signal::unix::{Signal, SignalKind, signal};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::daemon::{DaemonError, VAULT_FILE, check_private, core_config};

/// Target time of one key derivation at unlock (ADR-0013, DEC-049). The desktop uses the same value.
const KDF_TARGET: Duration = Duration::from_millis(700);
/// The owner label when `--owner` is not given.
pub const DEFAULT_OWNER: &str = "owner";
/// Longest owner label (the rule of `key_slots.label`).
const MAX_LABEL_CHARS: usize = 64;
/// The SQLite side files of the vault.
const SIDE_FILES: [&str; 2] = ["-wal", "-shm"];

/// Why `cerberusd init` stopped.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// A vault file, or a side file of one, is already in the data directory. Nothing was changed.
    #[error(
        "{path} exists (the vault file or one of its -wal / -shm side files); init never replaces a vault. Use that \
         vault, or remove the vault files yourself if you really want a new one",
        path = .path.display()
    )]
    VaultExists {
        /// The file that exists.
        path: PathBuf,
    },
    /// The recovery key file exists.
    #[error("{path} exists; choose a new file name for --recovery-out", path = .path.display())]
    RecoveryFileExists {
        /// The file.
        path: PathBuf,
    },
    /// The recovery key file would be in the data folder.
    #[error(
        "{path} is inside the data folder {data_dir}; --recovery-out must be outside it (the key must not sit next \
         to the vault, and the folder holds the vault files)",
        path = .path.display(),
        data_dir = .data_dir.display()
    )]
    RecoveryInDataDir {
        /// The file.
        path: PathBuf,
        /// The data folder.
        data_dir: PathBuf,
    },
    /// The folder of the recovery key file cannot be written by this user.
    #[error(
        "cannot write in {folder}: {source}. Make a folder for the key that the user running init owns, outside the data folder",
        folder = .folder.display()
    )]
    RecoveryFolderNotWritable {
        /// The folder.
        folder: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The data folder belongs to another user.
    #[error(
        "{path} is owned by uid {owner}, but this command runs as uid {user}. Run it as the service user, for example \
         `sudo -u cerberus cerberusd ... init`",
        path = .path.display()
    )]
    DataDirOwner {
        /// The data folder.
        path: PathBuf,
        /// The owner of the folder.
        owner: u32,
        /// The user of this process.
        user: u32,
    },
    /// The folder of the recovery key file does not exist.
    #[error("the folder of {path} does not exist or is not a folder", path = .path.display())]
    RecoveryFolder {
        /// The file.
        path: PathBuf,
    },
    /// No safe place for the recovery key.
    #[error(
        "stdout is not a terminal, so the recovery key cannot be shown without it landing in a log. \
         Pass --recovery-out <FILE> to write it to a new file (mode 0600) outside the data folder instead"
    )]
    NoRecoveryTarget,
    /// The two passphrases differ.
    #[error("the two passphrases are not the same")]
    Mismatch,
    /// The passphrase cannot be read.
    #[error("cannot read the passphrase: {0}. Run this command from a local terminal.")]
    Prompt(io::Error),
    /// The data directory is open to others.
    #[error(transparent)]
    Daemon(#[from] DaemonError),
    /// The vault file cannot be made.
    #[error("cannot make the vault file: {0}")]
    Store(#[from] StoreError),
    /// The input is not valid, for example a weak passphrase.
    #[error("{0}")]
    Invalid(String),
    /// The vault service failed.
    #[error("cannot create the vault: {0}")]
    Core(CoreError),
    /// The cost test or the thread that ran it failed.
    #[error("cannot measure the key derivation cost: {0}")]
    Kdf(String),
    /// A file step failed.
    #[error("{action} {path}: {source}", path = .path.display())]
    Io {
        /// What was tried.
        action: &'static str,
        /// The path.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The vault was made but the recovery key could not be written.
    #[error(
        "the vault was made, but the recovery key could not be written to {path}: {source}. The key is lost, and the \
         server cannot replace it: remove the vault files in the data folder (vault.cerberus and its -wal / -shm \
         files) and run init again",
        path = .path.display()
    )]
    RecoveryLost {
        /// The recovery key file.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
}

impl InitError {
    fn from_core(error: CoreError) -> Self {
        match error {
            CoreError::Validation(problems) => Self::Invalid(
                problems
                    .iter()
                    .map(|p| format!("{}: {}", p.field, p.problem))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            other => Self::Core(other),
        }
    }

    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Where the recovery key goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryTarget {
    /// A new file of mode `0600`, outside the data folder. It must not exist.
    File(PathBuf),
    /// The terminal of the operator, one time.
    Terminal,
}

impl RecoveryTarget {
    /// Picks the target from `--recovery-out` and from whether stdout is a terminal. A key that has no file and no
    /// terminal has no safe place, so this refuses before anything is made.
    ///
    /// # Errors
    /// [`InitError::NoRecoveryTarget`].
    pub fn choose(out: Option<PathBuf>, stdout_is_terminal: bool) -> Result<Self, InitError> {
        match out {
            Some(path) => Ok(Self::File(path)),
            None if stdout_is_terminal => Ok(Self::Terminal),
            None => Err(InitError::NoRecoveryTarget),
        }
    }
}

/// What `cerberusd init` is asked to do. The TLS host names are the `host_names` of the config.
#[derive(Clone, Debug)]
pub struct InitRequest {
    /// Label of the first owner, 1 to 64 characters.
    pub owner_label: String,
    /// Where the recovery key goes.
    pub recovery: RecoveryTarget,
    /// The key derivation cost. `None` measures this machine (the command line never sets it). Tests give a fixed
    /// small value so they do not run the 700 ms cost test.
    pub kdf: Option<KdfParams>,
}

/// How the recovery key was handed out.
#[derive(Debug)]
pub enum RecoveryOutput {
    /// Written to this file.
    Written(PathBuf),
    /// To be shown on the terminal one time by the caller.
    Show(SecretString),
}

/// What `cerberusd init` made.
#[derive(Debug)]
pub struct InitReport {
    /// The vault file.
    pub vault_path: PathBuf,
    /// The first owner.
    pub owner_id: OperatorId,
    /// The CA pin that a client needs to pair (ADR-0023 point 6).
    pub ca_pin: String,
    /// The recovery key.
    pub recovery: RecoveryOutput,
    /// A SIGINT, SIGTERM, SIGHUP or SIGQUIT came in while the vault was made. It was held and the run finished.
    pub interrupted: bool,
}

/// Makes the vault of `config`. `read_phrase` gets a prompt text and returns what the person typed; the real caller
/// prompts with echo off. It is called twice: the passphrase and its repeat. The vault is left sealed and closed.
///
/// # Errors
/// [`InitError`]. Every error before the files are made leaves the data directory as it was. If the vault cannot be
/// made, the files that this call made are removed.
pub async fn init_with<R>(
    config: &Config,
    request: InitRequest,
    mut read_phrase: R,
) -> Result<InitReport, InitError>
where
    R: FnMut(&str) -> io::Result<String>,
{
    let vault_path = config.data_dir.join(VAULT_FILE);
    check_no_vault(&vault_path)?;
    let data_dir_existed = config.data_dir.is_dir();
    if data_dir_existed {
        check_owner(&config.data_dir)?;
        check_private(&config.data_dir, "0700")?;
    }
    if let RecoveryTarget::File(path) = &request.recovery {
        check_recovery_path(&config.data_dir, path)?;
    }

    let phrase = read_new_phrase(&mut read_phrase)?;
    check_policy(&request.owner_label, &phrase)?;
    let kdf = match request.kdf {
        Some(kdf) => kdf,
        None => measure_kdf().await?,
    };

    // From here files are made. Hold the interrupts until the recovery key is out.
    let mut interrupts = Interrupts::install();
    let mut made = Made::new(&config.data_dir);
    let result = make_files_and_vault(config, &vault_path, &request, &mut made, phrase, kdf).await;
    let (created, recovery_file) = match result {
        Ok(done) => done,
        Err(error) => {
            made.remove();
            return Err(error);
        }
    };
    let recovery = match recovery_file {
        Some((path, mut file)) => {
            let key = created.recovery_key.expose_secret();
            let written = file
                .write_all(key.as_bytes())
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.sync_all());
            if let Err(source) = written {
                let _ = std::fs::remove_file(&path);
                return Err(InitError::RecoveryLost { path, source });
            }
            RecoveryOutput::Written(path)
        }
        None => RecoveryOutput::Show(created.recovery_key),
    };
    Ok(InitReport {
        vault_path,
        owner_id: created.owner_id,
        ca_pin: created.ca_pin,
        recovery,
        interrupted: interrupts.fired().await,
    })
}

/// Refuses when the vault file or a side file of it exists, also as a dangling link.
fn check_no_vault(vault_path: &Path) -> Result<(), InitError> {
    for suffix in std::iter::once("").chain(SIDE_FILES) {
        let path = with_suffix(vault_path, suffix);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(InitError::VaultExists { path });
        }
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The data folder must belong to the user who runs the command: a vault made by another user would not be
/// readable by the service user.
fn check_owner(data_dir: &Path) -> Result<(), InitError> {
    let owner = std::fs::metadata(data_dir)
        .map_err(|source| InitError::io("cannot read", data_dir, source))?
        .uid();
    let user = rustix::process::geteuid().as_raw();
    if owner != user {
        return Err(InitError::DataDirOwner {
            path: data_dir.to_path_buf(),
            owner,
            user,
        });
    }
    Ok(())
}

/// `path` made absolute, with every part that exists resolved (links, `..`). The part that does not exist yet is
/// appended as written.
fn resolve(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut tail = Vec::new();
    let mut current = absolute.as_path();
    loop {
        if let Ok(mut resolved) = current.canonicalize() {
            resolved.extend(tail.iter().rev());
            return resolved;
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_owned());
                current = parent;
            }
            _ => return absolute,
        }
    }
}

/// The recovery file must not exist, must not be the data folder or in it, and its folder must exist and be writable
/// by this user. All of it is checked before the passphrase is asked.
fn check_recovery_path(data_dir: &Path, path: &Path) -> Result<(), InitError> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(InitError::RecoveryFileExists {
            path: path.to_path_buf(),
        });
    }
    if resolve(path).starts_with(resolve(data_dir)) {
        return Err(InitError::RecoveryInDataDir {
            path: path.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
        });
    }
    let folder = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let folder = folder
        .canonicalize()
        .ok()
        .filter(|folder| folder.is_dir())
        .ok_or_else(|| InitError::RecoveryFolder {
            path: path.to_path_buf(),
        })?;
    // The key file is made after the prompts. A folder that refuses the write must show now, not then.
    let probe = folder.join(format!(".cerberus-init-probe-{}", std::process::id()));
    create_new_private(&probe).map_err(|source| InitError::RecoveryFolderNotWritable {
        folder: folder.clone(),
        source,
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Asks for the passphrase and its repeat.
fn read_new_phrase<R>(read_phrase: &mut R) -> Result<SecretString, InitError>
where
    R: FnMut(&str) -> io::Result<String>,
{
    let first = Zeroizing::new(read_phrase("New passphrase: ").map_err(InitError::Prompt)?);
    let again = Zeroizing::new(read_phrase("Repeat passphrase: ").map_err(InitError::Prompt)?);
    if *first != *again {
        return Err(InitError::Mismatch);
    }
    Ok(SecretString::new(first.as_str().to_owned()))
}

/// The rules of `create_vault` that can be checked without a file, so a refusal leaves nothing behind. The core
/// checks them again.
fn check_policy(label: &str, phrase: &SecretString) -> Result<(), InitError> {
    let chars = label.chars().count();
    if chars == 0 || chars > MAX_LABEL_CHARS || label.trim().is_empty() {
        return Err(InitError::Invalid(
            "label: must be 1..64 characters".to_owned(),
        ));
    }
    if !meets_phrase_policy(&normalize_phrase(phrase.expose_secret()), &[label]) {
        return Err(InitError::Invalid(
            "phrase: needs 12 characters or more and a strength score of 3 or more".to_owned(),
        ));
    }
    Ok(())
}

/// The cost test of this machine, run before any file exists.
async fn measure_kdf() -> Result<KdfParams, InitError> {
    eprintln!("measuring the key-derivation cost, this takes a few seconds...");
    let ram = total_ram_bytes().unwrap_or(u64::MAX);
    let tuning = tokio::task::spawn_blocking(move || tune_kdf(KDF_TARGET, ram))
        .await
        .map_err(|error| InitError::Kdf(error.to_string()))?
        .map_err(|error| InitError::Kdf(error.to_string()))?;
    Ok(tuning.params)
}

/// What this run made, so an error removes exactly that and nothing else.
struct Made {
    data_dir: PathBuf,
    /// The folders of the data folder path that do not exist yet, the data folder first. `create` makes all of them.
    missing_dirs: Vec<PathBuf>,
    tls_dir_existed: bool,
    /// The TLS files that existed before the run: they are not removed.
    tls_kept: Vec<PathBuf>,
    data_dir_made: bool,
    vault: bool,
    recovery: Option<PathBuf>,
}

impl Made {
    fn new(data_dir: &Path) -> Self {
        let missing_dirs = data_dir
            .ancestors()
            .take_while(|dir| !dir.as_os_str().is_empty() && !dir.exists())
            .map(Path::to_path_buf)
            .collect();
        Self {
            data_dir: data_dir.to_path_buf(),
            missing_dirs,
            tls_dir_existed: data_dir.join("tls").exists(),
            tls_kept: tls_files(data_dir)
                .into_iter()
                .filter(|file| file.exists())
                .collect(),
            data_dir_made: false,
            vault: false,
            recovery: None,
        }
    }

    /// Removes the files of this run. The TLS files go unless they existed before the run, the TLS folder only when
    /// it did not exist, and the data folder and its new parent folders only when this run made them and they are empty.
    fn remove(&self) {
        if let Some(path) = &self.recovery {
            let _ = std::fs::remove_file(path);
        }
        if self.vault {
            let vault = self.data_dir.join(VAULT_FILE);
            for suffix in std::iter::once("").chain(SIDE_FILES) {
                let _ = std::fs::remove_file(with_suffix(&vault, suffix));
            }
        }
        for file in tls_files(&self.data_dir) {
            if !self.tls_kept.contains(&file) {
                let _ = std::fs::remove_file(file);
            }
        }
        if !self.tls_dir_existed {
            let _ = std::fs::remove_dir(self.data_dir.join("tls"));
        }
        // Only the folders that this run made, innermost first, and only when empty (`remove_dir` refuses others).
        if self.data_dir_made {
            for dir in &self.missing_dirs {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
}

/// The files that `issue_ca` writes in the TLS folder, and the temporary names of those writes.
fn tls_files(data_dir: &Path) -> Vec<PathBuf> {
    let tls = TlsPaths::in_data_dir(data_dir);
    // A failed write leaves its temporary file (`write_private` of the TLS code names it `<name>.tmp`).
    [tls.leaf_cert_der, tls.leaf_key_der, tls.ca_cert_der]
        .into_iter()
        .flat_map(|file| {
            let tmp = file.with_extension("tmp");
            [file, tmp]
        })
        .collect()
}

/// An open recovery key file and its path.
type RecoveryFile = (PathBuf, std::fs::File);

/// Makes the data folder, reserves the recovery file and the vault file, then makes the vault. `made` records every
/// step that succeeded.
async fn make_files_and_vault(
    config: &Config,
    vault_path: &Path,
    request: &InitRequest,
    made: &mut Made,
    phrase: SecretString,
    kdf: KdfParams,
) -> Result<(CreatedVault, Option<RecoveryFile>), InitError> {
    if !made.missing_dirs.is_empty() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.data_dir)
            .map_err(|source| InitError::io("cannot create", &config.data_dir, source))?;
        made.data_dir_made = true;
    }
    let recovery_file = match &request.recovery {
        RecoveryTarget::File(path) => {
            let file = create_new_private(path).map_err(|source| {
                if source.kind() == io::ErrorKind::AlreadyExists {
                    InitError::RecoveryFileExists { path: path.clone() }
                } else {
                    InitError::io("cannot create the recovery key file", path, source)
                }
            })?;
            made.recovery = Some(path.clone());
            Some((path.clone(), file))
        }
        RecoveryTarget::Terminal => None,
    };
    // The exclusive create is the real check that no vault is here: a file that appeared since the first check
    // stops the run, and `made.vault` stays false, so nothing of it is removed.
    drop(create_new_private(vault_path).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            InitError::VaultExists {
                path: vault_path.to_path_buf(),
            }
        } else {
            InitError::io("cannot create", vault_path, source)
        }
    })?);
    made.vault = true;
    let created = create_sealed(config, vault_path, request, phrase, kdf).await?;
    Ok((created, recovery_file))
}

/// A new file that must not exist, mode `0600` from the first byte.
fn create_new_private(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Makes the vault in the reserved file, locks it and closes the store, so nothing holds the file afterwards.
async fn create_sealed(
    config: &Config,
    vault_path: &Path,
    request: &InitRequest,
    phrase: SecretString,
    kdf: KdfParams,
) -> Result<CreatedVault, InitError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let tls = TlsPaths::in_data_dir(&config.data_dir);
    let store = Store::open(
        OpenOptions {
            path: vault_path.to_path_buf(),
            create: true,
        },
        Arc::clone(&clock),
    )
    .await?;
    let core = match VaultService::open(store.clone(), clock, core_config(config, &tls)).await {
        Ok(core) => core,
        Err(error) => {
            // A store that is not closed can still hold the file when it is removed (NEW-14).
            store.close().await;
            return Err(InitError::from_core(error));
        }
    };
    let created = core
        .create_vault(NewVault {
            owner_label: request.owner_label.clone(),
            phrase,
            kdf,
            host_names: config.host_names.clone(),
        })
        .await;
    if created.is_ok() {
        // A lock that fails changes nothing: the process ends and the keys go with it.
        let _ = core.lock(LockReason::Quit).await;
    }
    core.close_store().await;
    created.map_err(InitError::from_core)
}

/// SIGINT, SIGTERM, SIGHUP and SIGQUIT, held while the vault is made. A tokio handler replaces the default action of
/// the signal, so the run goes on and the recovery key reaches the person. The handlers stay until the process ends,
/// which is right after the output.
struct Interrupts(Vec<Signal>);

impl Interrupts {
    fn install() -> Self {
        let kinds = [
            SignalKind::interrupt(),
            SignalKind::terminate(),
            SignalKind::hangup(),
            SignalKind::quit(),
        ];
        let held: Vec<Signal> = kinds
            .into_iter()
            .filter_map(|kind| signal(kind).ok())
            .collect();
        if held.len() < kinds.len() {
            eprintln!(
                "warning: cannot hold every interrupt signal while the vault is made; an interrupt now can leave \
                 partial files (see the daemon guide)"
            );
        }
        Self(held)
    }

    /// True when a signal came in since `install`.
    async fn fired(&mut self) -> bool {
        std::future::poll_fn(|cx| {
            let mut any = false;
            for signal in &mut self.0 {
                any |= signal.poll_recv(cx).is_ready();
            }
            Poll::Ready(any)
        })
        .await
    }
}
