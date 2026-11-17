//! Paths that come from the UI. A path is data from the webview, so each one is checked before the
//! backend writes or reads it (threat T-7): it must be absolute, free of `..`, and a new file
//! is never made over an existing one or through a symlink.

use std::path::{Component, Path, PathBuf};

use crate::error::{IpcError, IpcResult};
use crate::state::DesktopState;

fn absolute(field: &str, text: &str) -> IpcResult<PathBuf> {
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(IpcError::invalid(field, "must be an absolute path"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(IpcError::invalid(field, "must not contain \"..\""));
    }
    Ok(path)
}

/// A path for a new file: the directory exists and is not a symlink, and the file does not exist.
///
/// # Errors
/// `validation_failed` for a bad path, `conflict` when the file exists.
pub fn new_file(field: &str, text: &str) -> IpcResult<PathBuf> {
    let path = absolute(field, text)?;
    let name = path
        .file_name()
        .ok_or_else(|| IpcError::invalid(field, "must name a file"))?
        .to_owned();
    let dir = path
        .parent()
        .ok_or_else(|| IpcError::invalid(field, "must name a file"))?;
    let dir = dir
        .canonicalize()
        .map_err(|_| IpcError::invalid(field, "has a folder that does not exist"))?;
    if !dir.is_dir() {
        return Err(IpcError::invalid(
            field,
            "has a parent that is not a folder",
        ));
    }
    let full = dir.join(name);
    if full.symlink_metadata().is_ok() {
        return Err(IpcError::new("conflict", "the file already exists"));
    }
    Ok(full)
}

/// A folder that exists (not a symlink).
///
/// # Errors
/// `validation_failed` when the path is not an existing folder.
pub fn existing_dir(field: &str, text: &str) -> IpcResult<PathBuf> {
    let path = absolute(field, text)?;
    let meta = path
        .symlink_metadata()
        .map_err(|_| IpcError::invalid(field, "does not exist"))?;
    if !meta.is_dir() {
        return Err(IpcError::invalid(field, "is not a folder"));
    }
    Ok(path)
}

/// A file to read: one that the native dialog returned in this unlock (AUD-11), a regular file,
/// not larger than `max_bytes`. A path from the webview that the dialog did not return, a missing
/// file, a folder and a file that is too large all give the same answer, so the error text tells
/// nothing about the files of the person.
///
/// # Errors
/// `validation_failed` with the problem "cannot be used".
pub fn picked_file(
    state: &DesktopState,
    field: &str,
    text: &str,
    max_bytes: u64,
) -> IpcResult<PathBuf> {
    let refused = || IpcError::invalid(field, "cannot be used");
    let path = PathBuf::from(text);
    if !path.is_absolute() || !state.is_picked(&path) {
        return Err(refused());
    }
    let resolved = path.canonicalize().map_err(|_| refused())?;
    let meta = resolved.metadata().map_err(|_| refused())?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(refused());
    }
    Ok(resolved)
}

/// Creates a new file with mode `0600` and writes `bytes`. Fails when it exists.
///
/// # Errors
/// `conflict` when the file exists, `internal` for other I/O errors.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> IpcResult<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            IpcError::new("conflict", "the file already exists")
        } else {
            IpcError::internal(&error)
        }
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Copies `source` into a new file with mode `0600`, reading at most `max_bytes`. The file is
/// read once and only here: the copy is what the caller checks and installs afterwards.
///
/// # Errors
/// `conflict` when `dest` exists, `validation_failed` when the source is larger than `max_bytes`,
/// `internal` for other I/O errors. A failed copy leaves no file.
pub fn copy_new_private(source: &Path, dest: &Path, max_bytes: u64) -> IpcResult<()> {
    use std::io::Read;
    let mut input = std::fs::File::open(source)?.take(max_bytes.saturating_add(1));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(dest).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            IpcError::new("conflict", "the file already exists")
        } else {
            IpcError::internal(&error)
        }
    })?;
    let result = std::io::copy(&mut input, &mut output).map_err(IpcError::from);
    let result = match result {
        Ok(count) if count > max_bytes => Err(IpcError::invalid("src", "cannot be used")),
        Ok(_) => output.sync_all().map_err(IpcError::from),
        Err(error) => Err(error),
    };
    drop(output);
    if result.is_err() {
        // The file is ours: this call made it a moment ago.
        drop(std::fs::remove_file(dest));
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_and_parent_paths_are_refused() {
        assert!(new_file("dest", "relative.txt").is_err());
        assert!(new_file("dest", "/tmp/../etc/x").is_err());
        assert!(existing_dir("dir", "rel").is_err());
    }

    #[test]
    fn a_new_file_must_not_exist_and_a_symlink_counts_as_existing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("out.txt");
        let text = target.to_str().expect("utf8");
        assert!(new_file("dest", text).is_ok());
        write_new_private(&target, b"x").expect("write");
        assert_eq!(new_file("dest", text).unwrap_err().code, "conflict");
        assert_eq!(
            write_new_private(&target, b"y").unwrap_err().code,
            "conflict"
        );
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).expect("symlink");
            assert_eq!(
                new_file("dest", link.to_str().expect("utf8"))
                    .unwrap_err()
                    .code,
                "conflict"
            );
        }
    }

    #[test]
    fn copy_new_private_copies_once_and_respects_the_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("in");
        std::fs::write(&source, b"12345").expect("write");
        let copy = dir.path().join("out");
        copy_new_private(&source, &copy, 5).expect("copy");
        assert_eq!(std::fs::read(&copy).expect("read"), b"12345");
        assert_eq!(
            copy_new_private(&source, &copy, 5).unwrap_err().code,
            "conflict"
        );
        let big = dir.path().join("big");
        assert!(copy_new_private(&source, &big, 4).is_err());
        assert!(!big.exists(), "a refused copy leaves no file");
    }
}
