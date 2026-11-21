//! The RustDesk commands (DEC-RD-3): find the local RustDesk client and start it on the ID of a
//! `rustdesk` item.
//!
//! The client is started with an argument list and no shell (`Shell::launch`), and only with an ID
//! that is 9 to 20 digits, checked again here. The password never goes on the command line: it is
//! copied to the clipboard, which is cleared after 30 seconds, and the person pastes it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use cerberus_core::items::{KEY_RUSTDESK_ID, Payload, is_rustdesk_id};
use cerberus_types::{ItemKind, OperatorRole as CoreRole};
use serde_json::Value;

use crate::dto::{
    RustdeskClientKind, RustdeskClientView, RustdeskConnectView, RustdeskPasswordCopy,
    RustdeskStatusView, id,
};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

/// Settings key of the RustDesk client program (a desktop setting, kept in the preferences).
pub const RUSTDESK_PATH_KEY: &str = "rustdesk_path";

/// ID of the RustDesk Flatpak app.
const FLATPAK_APP: &str = "com.rustdesk.RustDesk";

/// File name of the client on the search path.
const PROGRAM: &str = if cfg!(windows) {
    "rustdesk.exe"
} else {
    "rustdesk"
};

/// What the search for the client may see. [`Lookup::system`] reads the real environment; tests
/// give fakes, so they never depend on what is installed.
pub(crate) struct Lookup<'a> {
    /// The `PATH` value.
    pub path_var: Option<&'a OsStr>,
    /// The home folder.
    pub home: Option<&'a Path>,
    /// The `ProgramFiles` folder (Windows).
    pub program_files: Option<&'a Path>,
    /// True for a file that can be run.
    pub is_program: &'a dyn Fn(&Path) -> bool,
    /// True for a folder.
    pub is_dir: &'a dyn Fn(&Path) -> bool,
}

/// True for a regular file that can be run (on Unix: an execute bit is set).
fn is_program_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

fn is_dir(path: &Path) -> bool {
    path.is_dir()
}

/// A client that was found: where, and the program to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Client {
    kind: RustdeskClientKind,
    program: PathBuf,
}

impl Client {
    /// The program and the arguments that open a connection to `rustdesk_id`. The ID must have
    /// passed [`is_rustdesk_id`].
    fn command(&self, rustdesk_id: &str) -> (PathBuf, Vec<String>) {
        let connect = ["--connect".to_owned(), rustdesk_id.to_owned()];
        let args = if self.kind == RustdeskClientKind::Flatpak {
            ["run", "--command=rustdesk", FLATPAK_APP]
                .into_iter()
                .map(str::to_owned)
                .chain(connect)
                .collect()
        } else {
            connect.to_vec()
        };
        (self.program.clone(), args)
    }

    fn view(&self) -> RustdeskClientView {
        RustdeskClientView {
            kind: self.kind,
            program: self.program.display().to_string(),
        }
    }
}

impl Lookup<'_> {
    fn on_path(&self, name: &str) -> Option<PathBuf> {
        std::env::split_paths(self.path_var?)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join(name))
            .find(|candidate| (self.is_program)(candidate))
    }

    /// Standard install locations of this OS, for an app started without the usual `PATH`.
    fn installed(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if cfg!(target_os = "macos") {
            out.push(PathBuf::from(
                "/Applications/RustDesk.app/Contents/MacOS/RustDesk",
            ));
            if let Some(home) = self.home {
                out.push(home.join("Applications/RustDesk.app/Contents/MacOS/RustDesk"));
            }
        } else if cfg!(windows) {
            if let Some(dir) = self.program_files {
                out.push(dir.join("RustDesk").join("rustdesk.exe"));
            }
        } else {
            for path in [
                "/usr/bin/rustdesk",
                "/usr/local/bin/rustdesk",
                "/usr/share/rustdesk/rustdesk",
            ] {
                out.push(PathBuf::from(path));
            }
        }
        out
    }

    /// `flatpak` and the RustDesk app, installed for the system or for the user.
    fn flatpak(&self) -> Option<PathBuf> {
        let flatpak = self.on_path("flatpak")?;
        let system = Path::new("/var/lib/flatpak/app").join(FLATPAK_APP);
        let user = self
            .home
            .map(|home| home.join(".local/share/flatpak/app").join(FLATPAK_APP));
        let installed = (self.is_dir)(&system) || user.is_some_and(|dir| (self.is_dir)(&dir));
        installed.then_some(flatpak)
    }

    /// The client to start. A program chosen in Settings wins and nothing else is tried, so the
    /// person always knows which one runs. Else: `rustdesk` on the search path, a standard
    /// install location, the Flatpak app.
    pub(crate) fn find(&self, custom: Option<&Path>) -> Option<Client> {
        if let Some(path) = custom {
            return (self.is_program)(path).then(|| Client {
                kind: RustdeskClientKind::Custom,
                program: path.to_path_buf(),
            });
        }
        if let Some(program) = self.on_path(PROGRAM) {
            return Some(Client {
                kind: RustdeskClientKind::Path,
                program,
            });
        }
        if let Some(program) = self.installed().into_iter().find(|p| (self.is_program)(p)) {
            return Some(Client {
                kind: RustdeskClientKind::Installed,
                program,
            });
        }
        self.flatpak().map(|program| Client {
            kind: RustdeskClientKind::Flatpak,
            program,
        })
    }
}

/// Runs `f` with the lookup of this computer.
fn with_system_lookup<T>(f: impl FnOnce(&Lookup<'_>) -> T) -> T {
    let path_var = std::env::var_os("PATH");
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
    f(&Lookup {
        path_var: path_var.as_deref(),
        home: home.as_deref(),
        program_files: program_files.as_deref(),
        is_program: &is_program_file,
        is_dir: &is_dir,
    })
}

fn find_client(state: &DesktopState) -> Option<Client> {
    let custom = state.prefs().rustdesk_path;
    with_system_lookup(|lookup| lookup.find(custom.as_deref()))
}

/// The problem of a program the person chose, or `None` when it may be used: an absolute path to
/// a file that can be run and whose name starts with `rustdesk` (any case), such as `rustdesk`,
/// `rustdesk.exe`, `RustDesk` or `rustdesk-1.4.2-x86_64.AppImage`. The name rule keeps this
/// setting from becoming a way to run any program.
fn path_problem(path: &Path, is_program: &dyn Fn(&Path) -> bool) -> Option<&'static str> {
    let named_rustdesk = path
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.to_lowercase().starts_with("rustdesk"));
    if !path.is_absolute() {
        Some("must be a full path")
    } else if !named_rustdesk {
        Some("must be a RustDesk program: its file name starts with rustdesk")
    } else if !is_program(path) {
        Some("is not a program that can be run")
    } else {
        None
    }
}

/// The new value of the `rustdesk_path` setting: `null` or an empty text goes back to looking
/// for the client.
///
/// # Errors
/// `validation_failed` for a value that is not text or not a usable RustDesk program.
pub(crate) fn parse_path_setting(value: &Value) -> IpcResult<Option<PathBuf>> {
    let text = match value {
        Value::Null => return Ok(None),
        Value::String(text) => text.trim(),
        _ => {
            return Err(IpcError::invalid(
                RUSTDESK_PATH_KEY,
                "must be a path or null",
            ));
        }
    };
    if text.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(text);
    match path_problem(&path, &is_program_file) {
        Some(problem) => Err(IpcError::invalid(RUSTDESK_PATH_KEY, problem)),
        None => Ok(Some(path)),
    }
}

/// `rustdesk_status`: any role. The program chosen in Settings and the client that a connection
/// would start. Nothing is started.
pub async fn rustdesk_status(state: &DesktopState, window: &str) -> IpcResult<RustdeskStatusView> {
    check(window, "rustdesk_status")?;
    let (core, ctx) = state.operator().await?;
    core.authorize_role(&ctx, CoreRole::Viewer).await?;
    Ok(RustdeskStatusView {
        custom_path: state
            .prefs()
            .rustdesk_path
            .map(|path| path.display().to_string()),
        client: find_client(state).map(|client| client.view()),
    })
}

/// `rustdesk_connect`: any role. Starts the RustDesk client on the ID of the item (metadata, so no
/// reveal is needed for it). With `copy_password`, the password is then read like
/// `clipboard_copy_secret` does (counted and audited, the role must allow a reveal) and copied to
/// the clipboard, which is cleared after 30 seconds. It never goes on the command line. A password
/// that cannot be copied does not undo the start: the answer says what happened to it.
pub async fn rustdesk_connect(
    state: &DesktopState,
    window: &str,
    item: String,
    copy_password: bool,
) -> IpcResult<RustdeskConnectView> {
    check(window, "rustdesk_connect")?;
    let (core, ctx) = state.operator().await?;
    let item = id("item_id", &item)?;
    let summary = core.get_item(&ctx, item).await?.summary;
    if summary.kind != ItemKind::Rustdesk {
        return Err(IpcError::invalid("item_id", "is not a RustDesk item"));
    }
    let rustdesk_id = summary
        .custom
        .get(KEY_RUSTDESK_ID)
        .filter(|text| is_rustdesk_id(text))
        .ok_or_else(|| {
            IpcError::invalid(
                "custom.rustdesk_id",
                "must be a RustDesk ID of 9 to 20 digits",
            )
        })?;
    let client = find_client(state).ok_or_else(|| {
        IpcError::unavailable(
            "RustDesk was not found on this computer: install it from rustdesk.com, or choose its program in Settings",
        )
    })?;
    let (program, args) = client.command(rustdesk_id);
    state.inner.shell.launch(&program, &args)?;
    tracing::info!(client = ?client.kind, "RustDesk client started");
    let password = if copy_password {
        copy_password_of(state, &core, &ctx, item).await
    } else {
        RustdeskPasswordCopy::Skipped
    };
    Ok(RustdeskConnectView {
        client: client.view(),
        password,
    })
}

async fn copy_password_of(
    state: &DesktopState,
    core: &cerberus_core::VaultService,
    ctx: &cerberus_core::OperatorContext,
    item: cerberus_types::ItemId,
) -> RustdeskPasswordCopy {
    let revealed = match core.reveal_item(ctx, item).await {
        Ok(revealed) => revealed,
        Err(error) => {
            tracing::warn!(%error, "the RustDesk password could not be read");
            return RustdeskPasswordCopy::NotCopied;
        }
    };
    let Payload::Rustdesk {
        password: Some(password),
    } = &revealed.payload
    else {
        return RustdeskPasswordCopy::NotStored;
    };
    match state.copy_and_clear(password.expose_secret()) {
        Ok(()) => RustdeskPasswordCopy::Copied,
        Err(error) => {
            tracing::warn!(code = %error.code, "the RustDesk password could not be copied");
            RustdeskPasswordCopy::NotCopied
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    use super::*;

    struct Fake {
        programs: BTreeSet<PathBuf>,
        dirs: BTreeSet<PathBuf>,
        path_var: OsString,
        home: PathBuf,
    }

    impl Fake {
        fn new(programs: &[&str], dirs: &[&str]) -> Self {
            Self {
                programs: programs.iter().map(PathBuf::from).collect(),
                dirs: dirs.iter().map(PathBuf::from).collect(),
                path_var: OsString::from("/opt/tools/bin:relative/bin:/usr/bin"),
                home: PathBuf::from("/home/fake"),
            }
        }

        fn find(&self, custom: Option<&str>) -> Option<Client> {
            let is_program = |p: &Path| self.programs.contains(p);
            let is_dir = |p: &Path| self.dirs.contains(p);
            Lookup {
                path_var: Some(&self.path_var),
                home: Some(&self.home),
                program_files: None,
                is_program: &is_program,
                is_dir: &is_dir,
            }
            .find(custom.map(Path::new))
        }
    }

    fn client(kind: RustdeskClientKind, program: &str) -> Option<Client> {
        Some(Client {
            kind,
            program: PathBuf::from(program),
        })
    }

    #[test]
    fn the_search_path_comes_before_flatpak_and_relative_dirs_are_skipped() {
        let fake = Fake::new(
            &[
                "/opt/tools/bin/rustdesk",
                "relative/bin/rustdesk",
                "/usr/bin/flatpak",
            ],
            &["/var/lib/flatpak/app/com.rustdesk.RustDesk"],
        );
        assert_eq!(
            fake.find(None),
            client(RustdeskClientKind::Path, "/opt/tools/bin/rustdesk")
        );
        let fake = Fake::new(&["relative/bin/rustdesk"], &[]);
        assert_eq!(fake.find(None), None);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn a_standard_install_is_found_without_the_search_path() {
        let mut fake = Fake::new(&["/usr/share/rustdesk/rustdesk"], &[]);
        fake.path_var = OsString::new();
        assert_eq!(
            fake.find(None),
            client(
                RustdeskClientKind::Installed,
                "/usr/share/rustdesk/rustdesk"
            )
        );
    }

    #[test]
    fn flatpak_needs_both_the_tool_and_the_app() {
        let user_app = "/home/fake/.local/share/flatpak/app/com.rustdesk.RustDesk";
        let fake = Fake::new(&["/usr/bin/flatpak"], &[user_app]);
        assert_eq!(
            fake.find(None),
            client(RustdeskClientKind::Flatpak, "/usr/bin/flatpak")
        );
        assert_eq!(Fake::new(&["/usr/bin/flatpak"], &[]).find(None), None);
        assert_eq!(Fake::new(&[], &[user_app]).find(None), None);
    }

    #[test]
    fn a_chosen_program_wins_and_nothing_else_is_tried_when_it_is_gone() {
        let fake = Fake::new(&["/opt/tools/bin/rustdesk", "/apps/RustDesk.AppImage"], &[]);
        assert_eq!(
            fake.find(Some("/apps/RustDesk.AppImage")),
            client(RustdeskClientKind::Custom, "/apps/RustDesk.AppImage")
        );
        assert_eq!(fake.find(Some("/apps/gone/rustdesk")), None);
    }

    #[test]
    fn the_command_is_an_argument_list_with_the_id_and_no_password() {
        let direct = client(RustdeskClientKind::Path, "/usr/bin/rustdesk").unwrap();
        assert_eq!(
            direct.command("123456789"),
            (
                PathBuf::from("/usr/bin/rustdesk"),
                vec!["--connect".to_owned(), "123456789".to_owned()]
            )
        );
        let flatpak = client(RustdeskClientKind::Flatpak, "/usr/bin/flatpak").unwrap();
        assert_eq!(
            flatpak.command("123456789").1,
            [
                "run",
                "--command=rustdesk",
                "com.rustdesk.RustDesk",
                "--connect",
                "123456789"
            ]
        );
    }

    #[test]
    fn a_chosen_program_must_be_an_absolute_rustdesk_program() {
        let yes = |_: &Path| true;
        let no = |_: &Path| false;
        assert_eq!(
            path_problem(Path::new("/opt/RustDesk-1.4.AppImage"), &yes),
            None
        );
        assert_eq!(path_problem(Path::new("/usr/bin/rustdesk"), &yes), None);
        assert!(path_problem(Path::new("rustdesk"), &yes).is_some());
        assert!(path_problem(Path::new("/usr/bin/bash"), &yes).is_some());
        assert!(path_problem(Path::new("/usr/bin/rustdesk"), &no).is_some());
        assert_eq!(parse_path_setting(&Value::Null).ok(), Some(None));
        assert_eq!(
            parse_path_setting(&Value::String("  ".to_owned())).ok(),
            Some(None)
        );
        assert!(parse_path_setting(&Value::Bool(true)).is_err());
        assert!(parse_path_setting(&Value::String("/usr/bin/sh".to_owned())).is_err());
    }
}
