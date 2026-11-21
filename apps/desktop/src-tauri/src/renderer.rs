//! WebKitGTK renderer choice on Linux.
//!
//! WebKitGTK 2.42+ paints through its DMA-BUF renderer. On X11 with hybrid or NVIDIA graphics that path shows
//! stale or shifted tiles when the page scrolls fast (for example a free-spin mouse wheel in the Audit or Settings
//! screens). The shared-memory path does not have this defect and is fast enough for this app.
//!
//! `std::env::set_var` is `unsafe` (edition 2024) and the workspace forbids unsafe code, so the process re-executes
//! itself once with `WEBKIT_DISABLE_DMABUF_RENDERER=1`. That is a plain `execve`: the process image is replaced,
//! nothing stays behind. If the user already set the variable (to any value, `0` turns the DMA-BUF path back on),
//! nothing changes.

/// The WebKitGTK variable that selects the shared-memory renderer.
pub const DMABUF_VAR: &str = "WEBKIT_DISABLE_DMABUF_RENDERER";

/// True when the process must re-execute itself to select the shared-memory renderer.
#[must_use]
pub fn needs_reexec(current: Option<&std::ffi::OsStr>) -> bool {
    current.is_none()
}

/// True when `exe` is the ELF dynamic loader (`ld-linux-x86-64.so.2`, `ld-musl-x86_64.so.1`, `ld.so`, …).
#[must_use]
pub fn is_dynamic_loader(exe: &std::path::Path) -> bool {
    exe.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| name.starts_with("ld-") || name.starts_with("ld.so"))
}

/// On Linux, re-executes the process with the shared-memory renderer selected. Call first in `main`, before any
/// thread starts. Returns only when nothing had to change or the re-exec failed (then the app runs as before).
pub fn select_renderer() {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        if !needs_reexec(std::env::var_os(DMABUF_VAR).as_deref()) {
            return;
        }
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        // Started through the dynamic loader (`ld-linux… cerberus-desktop`): `current_exe` is the loader, and
        // re-executing it with our argv would not start the app. Keep the default renderer then.
        if is_dynamic_loader(&exe) {
            return;
        }
        let mut args = std::env::args_os();
        let arg0 = args.next().unwrap_or_else(|| exe.clone().into_os_string());
        let error = std::process::Command::new(&exe)
            .arg0(arg0)
            .args(args)
            .env(DMABUF_VAR, "1")
            .exec();
        // `exec` returns only on failure. Logging is not set up yet, so report on stderr and continue.
        eprintln!("cerberus: could not select the WebKitGTK shared-memory renderer: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexec_only_when_the_variable_is_unset() {
        assert!(needs_reexec(None));
        assert!(!needs_reexec(Some(std::ffi::OsStr::new("1"))));
        assert!(!needs_reexec(Some(std::ffi::OsStr::new("0"))));
    }

    #[test]
    fn the_dynamic_loader_is_detected() {
        use std::path::Path;
        assert!(is_dynamic_loader(Path::new("/lib64/ld-linux-x86-64.so.2")));
        assert!(is_dynamic_loader(Path::new("/lib/ld-musl-x86_64.so.1")));
        assert!(is_dynamic_loader(Path::new("/lib/ld.so")));
        assert!(!is_dynamic_loader(Path::new("/usr/bin/cerberus-desktop")));
        assert!(!is_dynamic_loader(Path::new(
            "/tmp/.mount_x/usr/bin/cerberus"
        )));
    }
}
