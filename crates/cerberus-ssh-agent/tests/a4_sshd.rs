//! Acceptance A4 with the signing socket (T22): a real `ssh` logs in to a real `sshd` with the
//! vault key, through `IdentityAgent=<socket>`. `sshd` runs as this user on an ephemeral port of
//! 127.0.0.1, with a host key made at run time. The test is skipped (with a message) only when
//! `ssh` or `sshd` is missing or `sshd` cannot run as a normal user here.
#![cfg(unix)]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::fs;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use cerberus_types::GrantMode;
use common::{Fx, gone};
use ssh_key::{Algorithm, LineEnding, PrivateKey};

const SSHD: &str = "/usr/sbin/sshd";

/// Kills `sshd` when the test ends, also on a failed assert.
struct Sshd(Child);

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find_ssh() -> Option<PathBuf> {
    ["/usr/bin/ssh", "/usr/local/bin/ssh", "/bin/ssh"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

fn current_user() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Starts `sshd` and waits until it listens. `Err` holds its log when it could not start.
fn start_sshd(dir: &Path, port: u16, authorized: &str) -> Result<Sshd, String> {
    let host_key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let host_key_path = dir.join("host_key");
    write_private(
        &host_key_path,
        &host_key.to_openssh(LineEnding::LF).unwrap(),
    );
    let keys_path = dir.join("authorized_keys");
    write_private(&keys_path, authorized);
    let config = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\n\
         StrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
         PubkeyAuthentication yes\nPermitRootLogin no\n",
        host_key_path.display(),
        keys_path.display(),
        dir.join("sshd.pid").display(),
    );
    let config_path = dir.join("sshd_config");
    fs::write(&config_path, config).unwrap();
    let log_path = dir.join("sshd.log");
    let log = fs::File::create(&log_path).unwrap();
    let child = Command::new(SSHD)
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|error| format!("cannot start {SSHD}: {error}"))?;
    let mut sshd = Sshd(child);
    for _ in 0..100 {
        if let Ok(Some(status)) = sshd.0.try_wait() {
            let text = fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!("sshd exited with {status}: {text}"));
        }
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Ok(sshd);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("sshd did not listen within 5 s".to_owned())
}

/// Runs `ssh -o IdentityAgent=<socket> -p <port> user@127.0.0.1 true` with only the vault key.
async fn ssh_true(
    ssh: PathBuf,
    socket: PathBuf,
    identity: PathBuf,
    port: u16,
    user: String,
) -> (bool, String) {
    tokio::task::spawn_blocking(move || {
        let out = Command::new(ssh)
            .env_remove("SSH_AUTH_SOCK")
            .args(["-F", "/dev/null"])
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "LogLevel=ERROR"])
            .args(["-o", "ConnectTimeout=10"])
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "KbdInteractiveAuthentication=no"])
            .args(["-o", "IdentitiesOnly=yes"])
            .arg("-o")
            .arg(format!("IdentityAgent={}", socket.display()))
            .arg("-i")
            .arg(&identity)
            .arg("-p")
            .arg(port.to_string())
            .arg(format!("{user}@127.0.0.1"))
            .arg("true")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a4_ssh_logs_in_through_the_signing_socket() {
    let Some(ssh) = find_ssh() else {
        eprintln!("SKIPPED a4_ssh_logs_in_through_the_signing_socket: no ssh client installed");
        return;
    };
    if !Path::new(SSHD).exists() {
        eprintln!("SKIPPED a4_ssh_logs_in_through_the_signing_socket: {SSHD} is not installed");
        return;
    }
    let user = current_user();
    let port = free_port();
    let fx = Fx::with(port, &user, GrantMode::Auto).await;
    let ready = fx.prepare().await;
    assert_eq!(ready.ssh.port, Some(port));
    assert_eq!(ready.ssh.user.as_deref(), Some(user.as_str()));
    assert_eq!(ready.ssh.host.as_deref(), Some("127.0.0.1"));

    let work = fx.dir.path().join("sshd");
    fs::create_dir(&work).unwrap();
    let _sshd = match start_sshd(&work, port, &format!("{}\n", ready.public_key)) {
        Ok(sshd) => sshd,
        Err(why) => {
            eprintln!(
                "SKIPPED a4_ssh_logs_in_through_the_signing_socket: sshd cannot run as non-root here: {why}"
            );
            return;
        }
    };
    // `-i` with only the public key: ssh asks the agent to sign with that key.
    let identity = work.join("id.pub");
    write_private(&identity, &format!("{}\n", ready.public_key));

    let (ok, stderr) = ssh_true(
        ssh.clone(),
        ready.socket_path.clone(),
        identity.clone(),
        port,
        user.clone(),
    )
    .await;
    let log = fs::read_to_string(work.join("sshd.log")).unwrap_or_default();
    assert!(ok, "ssh login failed: {stderr}\nsshd log:\n{log}");
    assert!(log.contains("Accepted publickey"), "sshd log:\n{log}");
    assert!(
        log.contains(&ready.fingerprint),
        "sshd saw the vault key:\n{log}"
    );

    let audit = fx.audit_export_text().await;
    assert!(audit.contains("\"ssh.sign\""));
    assert!(audit.contains("\"userauth\""));
    for marker in &fx.markers {
        assert!(
            !audit.contains(marker.as_str()),
            "no key text in the audit export"
        );
        assert!(!stderr.contains(marker.as_str()));
    }

    // After release the socket is gone and the same login fails.
    fx.core
        .agent_api()
        .release_lease(&fx.agent, ready.lease.id)
        .await
        .unwrap();
    assert!(gone(&ready.socket_path).await);
    let (ok, _) = ssh_true(ssh, ready.socket_path.clone(), identity, port, user).await;
    assert!(!ok, "no login without the socket");
}
