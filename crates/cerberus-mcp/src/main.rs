//! `cerberus-mcp`: the stdio shim for agent hosts that only speak stdio (ADR-0029).
//!
//! Settings come from the environment (`CERBERUS_URL`, `CERBERUS_TOKEN` or `CERBERUS_TOKEN_FILE`,
//! `CERBERUS_CA_FILE` and/or `CERBERUS_CA_PIN`). Messages go on stdin and stdout; the log goes to
//! stderr and never holds a message body.

use std::process::ExitCode;

use cerberus_mcp::shim::{ShimConfig, run_stdio};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .init();
    let config = match ShimConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cerberus-mcp: {error}");
            return ExitCode::from(2);
        }
    };
    match run_stdio(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cerberus-mcp: {error}");
            ExitCode::FAILURE
        }
    }
}
