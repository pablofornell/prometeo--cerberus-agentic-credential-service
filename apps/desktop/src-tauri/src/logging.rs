//! Log setup. The level is `info`, and `rmcp` is cut to `warn` because it logs message bodies,
//! which hold secrets, at `debug` and `trace` (ADR-0029 item 9).

use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The log filter: `info` for everything plus [`cerberus_mcp::LOG_DIRECTIVE`].
#[must_use]
pub fn filter() -> Targets {
    format!("info,{}", cerberus_mcp::LOG_DIRECTIVE)
        .parse()
        .unwrap_or_else(|_| Targets::new().with_default(tracing::Level::INFO))
}

/// Starts logging to stderr.
pub fn init() {
    if let Err(error) = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(filter())
        .try_init()
    {
        eprintln!("logging is off: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::Level;

    #[test]
    fn rmcp_is_cut_to_warn_and_the_rest_logs_info() {
        let filter = filter();
        assert!(!filter.would_enable("rmcp::transport", &Level::DEBUG));
        assert!(!filter.would_enable("rmcp", &Level::TRACE));
        assert!(!filter.would_enable("rmcp::service", &Level::INFO));
        assert!(filter.would_enable("rmcp::service", &Level::WARN));
        assert!(filter.would_enable("cerberus_core", &Level::INFO));
        assert!(!filter.would_enable("cerberus_core", &Level::DEBUG));
    }
}
