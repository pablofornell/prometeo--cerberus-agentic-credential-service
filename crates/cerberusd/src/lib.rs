//! The headless Cerberus daemon `cerberusd` (ADR-0002): settings, the serve loop, the local unlock socket and the
//! status check. The binary in `main.rs` is a thin command line over this library, so the tests drive the same code.

pub mod config;
pub mod daemon;
pub mod https;
pub mod logging;
pub mod status;
pub mod unlock;
