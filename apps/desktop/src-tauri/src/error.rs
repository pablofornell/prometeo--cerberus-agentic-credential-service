//! The one error shape of the IPC layer. It lives in `cerberus-admin`, so the admin API of
//! `cerberusd` uses the same type (ADR-0034, DEC-RM-6); this module keeps the `crate::error` paths.

pub use cerberus_admin::error::*;
