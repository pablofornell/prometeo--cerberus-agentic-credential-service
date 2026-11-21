//! The headless Cerberus daemon `cerberusd` (ADR-0002): settings, the serve loop, the local unlock socket, the
//! status check and the admin client commands (ADR-0034). The binary in `main.rs` is a thin command line over this library, so the tests drive the same code.

pub mod admin;
pub mod config;
pub mod daemon;
pub mod https;
pub mod logging;
pub mod status;
pub mod unlock;
