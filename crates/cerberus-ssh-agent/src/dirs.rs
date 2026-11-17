//! The runtime directory of the signing sockets.
//!
//! Layout: `<base>/<pid>-<n>/<lease>.sock`. `<base>` is `$XDG_RUNTIME_DIR/cerberus-ssh` (or
//! `<data dir>/run/cerberus-ssh`). Every directory has mode 0700 and is owned by this user, and
//! every socket has mode 0600. Each bridge has its own `<pid>-<n>` directory. A bridge removes
//! the directories of processes that no longer run, so sockets left by a crash do not stay.

use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Mode of every directory.
pub(crate) const DIR_MODE: u32 = 0o700;
/// Mode of every socket.
pub(crate) const SOCKET_MODE: u32 = 0o600;

/// The file whose lock marks a directory as in use.
const LOCK_FILE: &str = ".lock";

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// The user ID of this process.
pub(crate) fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn not_safe(path: &Path, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} {what}", path.display()),
    )
}

/// Makes `path` (and its parents) when missing, then checks that it is a real directory of this
/// user (not a symlink) and sets mode 0700.
fn safe_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(DIR_MODE).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_dir() {
        return Err(not_safe(path, "is not a directory"));
    }
    if meta.uid() != own_uid() {
        return Err(not_safe(path, "belongs to another user"));
    }
    fs::set_permissions(path, Permissions::from_mode(DIR_MODE))
}

/// True when the process `pid` is still running (or cannot be checked).
fn process_runs(pid: i32) -> bool {
    match rustix::process::Pid::from_raw(pid) {
        Some(pid) => match rustix::process::test_kill_process(pid) {
            Ok(()) => true,
            Err(error) => error != rustix::io::Errno::SRCH,
        },
        None => false,
    }
}

/// True when no bridge uses `dir` any more. A bridge holds a lock on the lock file in its directory
/// for as long as it runs, and the lock is visible in every PID namespace. A directory without a lock
/// file (left by a crash between making it and locking it) is stale when its process is gone.
fn is_stale(dir: &Path, pid: i32) -> bool {
    match fs::File::open(dir.join(LOCK_FILE)) {
        Ok(file) => file.try_lock().is_ok(),
        Err(_) => !process_runs(pid),
    }
}

/// Removes the socket files of one directory, then the directory when it is empty.
fn remove_sockets(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_socket = path.extension().is_some_and(|ext| ext == "sock")
                || path.file_name().is_some_and(|name| name == LOCK_FILE);
            if is_socket && let Err(error) = fs::remove_file(&path) {
                tracing::warn!(path = %path.display(), %error, "could not remove an old ssh-agent socket");
            }
        }
    }
    // Fails (and leaves the directory) when something other than sockets is in it.
    let _ = fs::remove_dir(dir);
}

/// Removes the directories of bridges whose process no longer runs.
fn remove_stale(base: &Path) {
    let own = std::process::id();
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|text| text.split_once('-'))
            .and_then(|(pid, _)| pid.parse::<i32>().ok())
        else {
            continue;
        };
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if is_dir && u32::try_from(pid).ok() != Some(own) && is_stale(&entry.path(), pid) {
            remove_sockets(&entry.path());
        }
    }
}

/// The socket directory of one bridge. Dropping it removes the sockets left in it and the
/// directory.
#[derive(Debug)]
pub(crate) struct BridgeDir {
    path: PathBuf,
    /// Holds the lock that tells other bridges this directory is in use.
    _lock: fs::File,
}

impl BridgeDir {
    /// Makes a new directory under `base` (made first when missing).
    pub(crate) fn create(base: &Path) -> io::Result<Self> {
        safe_dir(base)?;
        remove_stale(base);
        let pid = std::process::id();
        loop {
            let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("{pid}-{n}"));
            match DirBuilder::new().mode(DIR_MODE).create(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, Permissions::from_mode(DIR_MODE))?;
                    let lock = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(SOCKET_MODE)
                        .open(path.join(LOCK_FILE))?;
                    lock.lock()?;
                    return Ok(Self { path, _lock: lock });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// The directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for BridgeDir {
    fn drop(&mut self) {
        remove_sockets(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_are_private_and_stale_ones_go() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("run").join("cerberus-ssh");
        // A directory of a process that does not run (pid near the top of the range).
        fs::create_dir_all(base.join("2147483646-0")).unwrap();
        fs::write(base.join("2147483646-0").join("old.sock"), b"").unwrap();
        let dir = BridgeDir::create(&base).unwrap();
        assert!(
            !base.join("2147483646-0").exists(),
            "stale directory removed"
        );
        for path in [&base, &dir.path().to_path_buf()] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, DIR_MODE, "{}", path.display());
        }
        let other = BridgeDir::create(&base).unwrap();
        assert_ne!(dir.path(), other.path());
        let path = dir.path().to_path_buf();
        fs::write(path.join("x.sock"), b"").unwrap();
        drop(dir);
        assert!(!path.exists(), "dropped directory removed");
        assert!(other.path().exists());
    }

    /// AUD-30: a bridge in another PID namespace has a pid that this process cannot see. Its
    /// directory is still in use, and the lock file it holds says so.
    #[test]
    fn a_directory_with_a_held_lock_stays_even_when_its_pid_is_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("run").join("cerberus-ssh");
        let live = base.join("2147483646-0");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("live.sock"), b"").unwrap();
        let held = fs::File::create(live.join(LOCK_FILE)).unwrap();
        held.lock().unwrap();
        let _mine = BridgeDir::create(&base).unwrap();
        assert!(live.join("live.sock").exists(), "live bridge kept");
        // Once the other bridge ends, its lock is gone and the next bridge cleans up.
        drop(held);
        let _next = BridgeDir::create(&base).unwrap();
        assert!(!live.exists(), "ended bridge removed");
    }

    #[test]
    fn a_symlink_base_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(BridgeDir::create(&link).is_err());
    }
}
