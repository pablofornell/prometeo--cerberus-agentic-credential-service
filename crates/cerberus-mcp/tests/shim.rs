//! The stdio shim against the real server, driven by the sample config of
//! `docs/guides/mcp-client-config.md`. All token and secret values are fake test values.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::process::Stdio;

use cerberus_api::CaExport;
use common::{Fixture, PASSWORD};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// The first JSON example of the "Claude Code" section of the guide.
fn guide_config() -> Value {
    let guide = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/guides/mcp-client-config.md"
    ))
    .expect("guide");
    let from = guide.find("## Claude Code").expect("section");
    let start = from + guide[from..].find("```json\n").expect("block") + 8;
    let end = start + guide[start..].find("```").expect("end");
    serde_json::from_str(&guide[start..end]).expect("valid JSON in the guide")
}

struct Shim {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Shim {
    /// Starts the shim as the guide config says, with the values of this test in place of the
    /// placeholders. `edit` can change the environment.
    fn start(fx: &Fixture, token: &str, edit: impl FnOnce(&mut Vec<(String, String)>)) -> Self {
        let config = guide_config();
        let server = &config["mcpServers"]["cerberus"];
        assert_eq!(server["command"], "cerberus-mcp");
        let token_file = fx.dir.path().join("token");
        std::fs::write(&token_file, token).expect("token file");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
        }
        let export = CaExport::from_der(&fx.ca_der).expect("ca");
        let pin = export.pin.clone();
        let ca_file = fx.dir.path().join("ca.pem");
        std::fs::write(&ca_file, &export.pem).expect("ca file");
        let mut env: Vec<(String, String)> = server["env"]
            .as_object()
            .expect("env")
            .iter()
            .map(|(name, value)| {
                let value = match name.as_str() {
                    "CERBERUS_URL" => format!("https://localhost:{}", fx.addr.port()),
                    "CERBERUS_CA_PIN" => pin.clone(),
                    "CERBERUS_CA_FILE" => ca_file.display().to_string(),
                    "CERBERUS_TOKEN_FILE" => token_file.display().to_string(),
                    _ => value.as_str().expect("text").to_owned(),
                };
                (name.clone(), value)
            })
            .collect();
        edit(&mut env);
        let mut child = Command::new(env!("CARGO_BIN_EXE_cerberus-mcp"))
            .env_clear()
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            stdout,
        }
    }

    async fn send(&mut self, message: &Value) {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await.expect("write");
        self.stdin.flush().await.expect("flush");
    }

    /// The next message with an `id` (skips notifications such as progress).
    async fn reply(&mut self) -> Value {
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                self.stdout.read_line(&mut line),
            )
            .await
            .expect("a reply in time")
            .expect("read");
            assert!(read > 0, "the shim closed stdout");
            let message: Value = serde_json::from_str(&line).expect("one JSON value per line");
            if message.get("id").is_some() {
                return message;
            }
        }
    }

    async fn call(&mut self, id: u32, method: &str, params: Value) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        self.reply().await
    }

    async fn handshake(&mut self) {
        let init = self
            .call(
                1,
                "initialize",
                json!({"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "host", "version": "0"}}),
            )
            .await;
        assert!(
            init["result"]["capabilities"]["tools"].is_object(),
            "{init}"
        );
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
    }
}

#[tokio::test]
async fn round_trip_with_the_guide_config() {
    let fx = Fixture::new().await;
    let mut shim = Shim::start(&fx, &fx.token, |_| {});
    shim.handshake().await;
    let tools = shim.call(2, "tools/list", json!({})).await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, cerberus_mcp::TOOL_NAMES);
    let secret = shim
        .call(
            3,
            "tools/call",
            json!({"name": "get_credential",
                   "arguments": {"id": fx.item.to_string(), "purpose": "Check the checkout page"}}),
        )
        .await;
    assert_eq!(
        secret["result"]["structuredContent"]["secret"]["password"],
        PASSWORD
    );
    // Locked: the session stays, the tool says so.
    fx.lock().await;
    let locked = shim
        .call(
            4,
            "tools/call",
            json!({"name": "vault_status", "arguments": {}}),
        )
        .await;
    assert_eq!(
        locked["result"]["structuredContent"],
        json!({"vault": "locked"})
    );
    fx.unlock().await;
    let again = shim
        .call(
            5,
            "tools/call",
            json!({"name": "vault_status", "arguments": {}}),
        )
        .await;
    assert_eq!(again["result"]["structuredContent"]["vault"], "unlocked");
    // Resource read goes through too.
    let catalog = shim
        .call(6, "resources/read", json!({"uri": "cerberus://catalog"}))
        .await;
    assert!(
        catalog["result"]["contents"][0]["text"].is_string(),
        "{catalog}"
    );
    drop(shim.stdin);
    let status = shim.child.wait().await.expect("exit");
    assert!(status.success());
    fx.stop().await;
}

#[tokio::test]
async fn a_bad_token_becomes_a_json_rpc_error() {
    let fx = Fixture::new().await;
    let mut shim = Shim::start(&fx, &format!("{}x", fx.token), |_| {});
    let reply = shim
        .call(
            1,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "host", "version": "0"}}),
        )
        .await;
    assert_eq!(reply["error"]["message"], "unauthenticated", "{reply}");
    assert_eq!(reply["error"]["data"]["error"]["code"], "unauthenticated");
    fx.stop().await;
}

#[tokio::test]
async fn garbage_gets_a_parse_error_and_the_shim_goes_on() {
    let fx = Fixture::new().await;
    let mut shim = Shim::start(&fx, &fx.token, |_| {});
    shim.stdin.write_all(b"not json\n").await.expect("write");
    let reply = shim.reply().await;
    assert_eq!(reply["error"]["code"], -32700);
    shim.handshake().await;
    fx.stop().await;
}

#[tokio::test]
async fn it_refuses_to_start_without_a_ca_or_pin() {
    let fx = Fixture::new().await;
    let mut shim = Shim::start(&fx, &fx.token, |env| {
        env.retain(|(name, _)| !name.starts_with("CERBERUS_CA_"));
    });
    let status = shim.child.wait().await.expect("exit");
    assert_eq!(status.code(), Some(2));
    fx.stop().await;
}

#[tokio::test]
async fn a_ca_file_that_does_not_match_the_pin_stops_the_shim() {
    let fx = Fixture::new().await;
    let mut shim = Shim::start(&fx, &fx.token, |env| {
        for (name, value) in env.iter_mut() {
            if name == "CERBERUS_CA_PIN" {
                *value = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
            }
        }
    });
    // A CA file that does not match its pin stops the shim before any connection.
    let status = shim.child.wait().await.expect("exit");
    assert_eq!(status.code(), Some(1));
    fx.stop().await;
}
