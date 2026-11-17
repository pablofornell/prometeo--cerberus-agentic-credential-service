//! The `cerberus` binary against a real vault: A12 (env injection into the child only), secret
//! handling of `get`, exit codes, signals, stdin for `store`.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};

use common::real::{PASSWORD, Real, USERNAME};

const BIN: &str = env!("CARGO_BIN_EXE_cerberus");

fn command(real: &Real) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CERBERUS_URL", real.url())
        .env("CERBERUS_TOKEN", &real.token)
        .env("CERBERUS_CA_FILE", &real.ca_file)
        .env("CERBERUS_CA_PIN", &real.export.pin);
    cmd
}

/// Runs the CLI to the end on a blocking thread, so the in-process server keeps serving.
async fn cli(real: &Real, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = command(real);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let input = stdin.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let mut child = cmd.spawn().unwrap();
        if let Some(text) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_no_secret(label: &str, output: &str) {
    assert!(!output.contains(PASSWORD), "{label} shows the password");
    assert!(!output.contains(USERNAME), "{label} shows the username");
}

#[tokio::test(flavor = "multi_thread")]
async fn a12_the_child_sees_the_variable_and_the_agent_output_does_not() {
    let real = Real::start().await;
    let out_file = real.dir.path().join("child-saw.txt");
    let script = format!(
        r#"printf %s "$CERBERUS_PASSWORD" > '{}'; echo "user is $CERBERUS_USERNAME"; env"#,
        out_file.display()
    );
    let out = cli(
        &real,
        &[
            "run", "--app", "shop", "--env", "staging", "--role", "admin", "--", "sh", "-c",
            &script,
        ],
        None,
    )
    .await;
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    // The child saw the real value ...
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), PASSWORD);
    // ... and the CLI output has only the mask.
    assert_no_secret("stdout", &stdout);
    assert_no_secret("stderr", &stderr);
    assert!(stdout.contains("user is [REDACTED]"), "{stdout}");
    assert!(stdout.contains("CERBERUS_PASSWORD=[REDACTED]"), "{stdout}");
    // The token does not reach the child (ADR-0028 item 4).
    assert!(!stdout.contains("CERBERUS_TOKEN"), "{stdout}");
    assert!(!stdout.contains(&real.token));
    // The parent (this test) environment is untouched.
    assert!(std::env::var("CERBERUS_PASSWORD").is_err());
    // The lease was released: a second run works and so does a release-less state.
    let again = cli(
        &real,
        &["run", "--app", "shop", "--env", "staging", "--", "true"],
        None,
    )
    .await;
    assert_eq!(again.status.code(), Some(0));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn run_passes_the_exit_code_and_can_keep_the_token() {
    let real = Real::start().await;
    let out = cli(
        &real,
        &[
            "run", "--app", "shop", "--env", "staging", "--", "sh", "-c", "exit 7",
        ],
        None,
    )
    .await;
    assert_eq!(out.status.code(), Some(7));
    let out = cli(
        &real,
        &[
            "run",
            "--app",
            "shop",
            "--env",
            "staging",
            "--pass-token",
            "--",
            "sh",
            "-c",
            "printenv CERBERUS_TOKEN | wc -c",
        ],
        None,
    )
    .await;
    assert!(text(&out.stdout).trim().parse::<u32>().unwrap() > 10);
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn run_with_var_sets_only_the_mapped_variable() {
    let real = Real::start().await;
    let script = r#"echo "pw=$DB_PW"; echo "user=${CERBERUS_USERNAME:-unset}""#;
    let out = cli(
        &real,
        &[
            "run",
            "--app",
            "shop",
            "--env",
            "staging",
            "--var",
            "DB_PW=password",
            "--",
            "sh",
            "-c",
            script,
        ],
        None,
    )
    .await;
    let stdout = text(&out.stdout);
    assert!(stdout.contains("pw=[REDACTED]"), "{stdout}");
    assert!(stdout.contains("user=unset"), "{stdout}");
    assert_no_secret("stdout", &stdout);
    real.stop().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn run_forwards_signals_to_the_child() {
    let real = Real::start().await;
    let mut cmd = command(&real);
    cmd.args([
        "run",
        "--app",
        "shop",
        "--env",
        "staging",
        "--",
        "sh",
        "-c",
        "trap 'exit 42' TERM; echo ready; while :; do sleep 0.05; done",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let code = tokio::task::spawn_blocking(move || {
        let mut child = cmd.spawn().unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        lines.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready");
        let pid = child.id().to_string();
        let sent = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
        assert!(sent.success());
        child.wait().unwrap().code()
    })
    .await
    .unwrap();
    assert_eq!(code, Some(42));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn get_hides_the_secret_unless_asked() {
    let real = Real::start().await;
    let args = [
        "get", "--app", "shop", "--env", "staging", "--role", "admin",
    ];
    let hidden = cli(&real, &args, None).await;
    let (stdout, stderr) = (text(&hidden.stdout), text(&hidden.stderr));
    assert_eq!(hidden.status.code(), Some(0), "{stderr}");
    assert_no_secret("stdout", &stdout);
    assert_no_secret("stderr", &stderr);
    assert!(stdout.contains("[REDACTED]"));
    assert!(stdout.contains("do not print or log"));
    assert!(stdout.contains("--show-secret"));

    let shown = cli(&real, &[&args[..], &["--show-secret"]].concat(), None).await;
    let stdout = text(&shown.stdout);
    assert!(stdout.contains(PASSWORD), "{stdout}");
    assert!(stdout.contains("do not print or log"));

    let field = cli(
        &real,
        &[&args[..], &["--show-secret", "--field", "password"]].concat(),
        None,
    )
    .await;
    assert_eq!(text(&field.stdout), format!("{PASSWORD}\n"));

    let wrong = cli(&real, &[&args[..], &["--field", "password"]].concat(), None).await;
    assert_ne!(wrong.status.code(), Some(0), "--field needs --show-secret");
    assert_no_secret("stdout", &text(&wrong.stdout));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn find_shows_metadata_only() {
    let real = Real::start().await;
    let out = cli(&real, &["find", "--app", "shop", "--env", "staging"], None).await;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(stdout.contains("Shop admin"), "{stdout}");
    assert_no_secret("stdout", &stdout);
    let status = cli(&real, &["status"], None).await;
    assert!(text(&status.stdout).contains("qa-agent"));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn store_reads_the_value_from_stdin_and_delete_removes_it() {
    let real = Real::start().await;
    let value = "canary-stdin-value-9911";
    let out = cli(
        &real,
        &[
            "store",
            "--workspace",
            "shop",
            "--title",
            "CLI key",
            "--env",
            "staging",
            "--kind",
            "api_key",
        ],
        Some(&format!("{value}\n")),
    )
    .await;
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!stdout.contains(value));
    let created: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let id = created["item"]["id"].as_str().unwrap().to_owned();
    let got = cli(
        &real,
        &["get", "--id", &id, "--show-secret", "--field", "key"],
        None,
    )
    .await;
    assert_eq!(
        text(&got.stdout),
        format!("{value}\n"),
        "the newline is trimmed on store"
    );
    let del = cli(&real, &["delete", &id], None).await;
    assert_eq!(del.status.code(), Some(0));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_print_code_and_request_id_and_use_exit_codes() {
    let real = Real::start().await;
    let none = cli(&real, &["run", "--app", "nothing-here", "--", "true"], None).await;
    assert_eq!(none.status.code(), Some(73));
    let stderr = text(&none.stderr);
    assert!(
        stderr.contains("no_match") && stderr.contains("request "),
        "{stderr}"
    );
    real.lock().await;
    let locked = cli(&real, &["status"], None).await;
    assert_eq!(locked.status.code(), Some(71));
    real.unlock().await;
    let mut bad = command(&real);
    bad.env(
        "CERBERUS_TOKEN",
        "cvt_00000000-0000-0000-0000-000000000000.nope",
    )
    .args(["status"])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let out = tokio::task::spawn_blocking(move || bad.output().unwrap())
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(70));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_is_never_an_argument_and_a_loose_token_file_is_refused() {
    let real = Real::start().await;
    let out = cli(&real, &["--token", "cvt_x.y", "status"], None).await;
    assert_eq!(out.status.code(), Some(2), "clap refuses an unknown flag");

    let file = real.dir.path().join("token");
    std::fs::write(&file, &real.token).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut cmd = command(&real);
    cmd.env_remove("CERBERUS_TOKEN")
        .args(["--token-file", file.to_str().unwrap(), "status"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let loose = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert_eq!(loose.status.code(), Some(74));
    assert!(text(&loose.stderr).contains("chmod 600"));
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut cmd = command(&real);
    cmd.env_remove("CERBERUS_TOKEN")
        .args(["--token-file", file.to_str().unwrap(), "status"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let ok = tokio::task::spawn_blocking(move || cmd.output().unwrap())
        .await
        .unwrap();
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok.stderr));
    real.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn completions_are_printed() {
    let real = Real::start().await;
    for shell in ["bash", "zsh", "fish"] {
        let out = cli(&real, &["completions", shell], None).await;
        assert_eq!(out.status.code(), Some(0));
        assert!(text(&out.stdout).contains("cerberus"));
    }
    real.stop().await;
}

/// AUD-19: the child runs as the same user and could read the token from the environment of the
/// `cerberus` process in `/proc`. `cerberus run` makes itself not dumpable, so that read fails.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn aud19_the_child_cannot_read_the_token_from_the_parent_environment() {
    let real = Real::start().await;
    let script = r#"if cat /proc/$PPID/environ > /dev/null 2>&1; then echo parent-environ-readable; else echo parent-environ-denied; fi"#;
    let out = cli(
        &real,
        &[
            "run", "--app", "shop", "--env", "staging", "--", "sh", "-c", script,
        ],
        None,
    )
    .await;
    let stdout = text(&out.stdout);
    assert!(stdout.contains("parent-environ-denied"), "{stdout}");
    assert!(!stdout.contains(&real.token));
    real.stop().await;
}

/// AUD-30: `get --show-secret` ends its lease once the value is printed.
#[tokio::test(flavor = "multi_thread")]
async fn aud30_get_show_secret_releases_its_lease() {
    let real = Real::start().await;
    let shown = cli(
        &real,
        &[
            "get",
            "--app",
            "shop",
            "--env",
            "staging",
            "--role",
            "admin",
            "--show-secret",
        ],
        None,
    )
    .await;
    assert!(text(&shown.stdout).contains(PASSWORD));
    let leases = real.core.list_leases(&real.owner).await.unwrap();
    assert!(leases.is_empty(), "{} lease(s) still active", leases.len());
    real.stop().await;
}
