//! Private files and directories (ADR-0013 point 4): mode 0600 for files and 0700 for directories on Unix.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::path::Path;

/// Creates the directory and its parents. On Unix a new directory gets mode 0700.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Creates a new empty file that must not exist. On Unix it gets mode 0600 from the first byte.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// `path` with `suffix` added to the file name, for example `vault.cerberus-wal`.
pub(crate) fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Magic numbers of a SQLite WAL header: the low bit tells the byte order of the checksums.
const WAL_MAGIC: [u32; 2] = [0x377f_0682, 0x377f_0683];
/// WAL file format version.
const WAL_VERSION: u32 = 3_007_000;

fn word(bytes: &[u8], at: usize, big_endian: bool) -> u32 {
    let mut raw = [0_u8; 4];
    raw.copy_from_slice(&bytes[at..at + 4]);
    if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

/// Reads up to `len` bytes from the start of `path`. `None` when the file does not exist.
fn read_start(path: &Path, len: usize) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut out = Vec::with_capacity(len);
    file.take(len as u64).read_to_end(&mut out)?;
    Ok(Some(out))
}

/// True when the `-wal` file next to `db` is absent, shorter than a header (SQLite reads no frame
/// from it), or has a valid header for the page size of `db`: the right magic and version, the
/// page size of the main file, and a good header checksum (AUD-10, RUSTSEC-2026-0459: a crafted
/// WAL of another page size makes SQLite < 3.54 read stale memory). Call it before any connection
/// opens `db`.
pub(crate) fn wal_is_plausible(db: &Path) -> io::Result<bool> {
    let Some(header) = read_start(&with_suffix(db, "-wal"), 32)? else {
        return Ok(true);
    };
    if header.len() < 32 {
        return Ok(true);
    }
    let magic = word(&header, 0, true);
    if !WAL_MAGIC.contains(&magic) || word(&header, 4, true) != WAL_VERSION {
        return Ok(false);
    }
    // The database header holds the page size at offset 16 (big-endian u16, 1 means 65536).
    let Some(main) = read_start(db, 100)? else {
        return Ok(false);
    };
    if main.len() < 100 {
        return Ok(false);
    }
    let db_page = match u16::from_be_bytes([main[16], main[17]]) {
        1 => 65_536,
        size => u32::from(size),
    };
    if word(&header, 8, true) != db_page {
        return Ok(false);
    }
    let big_endian = magic & 1 == 1;
    let (mut s0, mut s1) = (0_u32, 0_u32);
    for at in (0..24).step_by(8) {
        s0 = s0
            .wrapping_add(word(&header, at, big_endian))
            .wrapping_add(s1);
        s1 = s1
            .wrapping_add(word(&header, at + 4, big_endian))
            .wrapping_add(s0);
    }
    Ok(word(&header, 24, true) == s0 && word(&header, 28, true) == s1)
}
