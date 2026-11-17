//! Log filter of the daemon. `rmcp` logs full MCP message bodies, which can hold secrets, at debug and trace level.
//! The filter therefore always carries `cerberus_mcp::LOG_DIRECTIVE` (ADR-0029 item 9).

use tracing_subscriber::EnvFilter;

/// The filter text: `info` for everything, then the MCP directive.
#[must_use]
pub fn directives() -> String {
    format!("info,{}", cerberus_mcp::LOG_DIRECTIVE)
}

/// Installs the stderr log subscriber with [`directives`]. Call it once per process.
pub fn init() {
    let filter = EnvFilter::try_new(directives()).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
}
