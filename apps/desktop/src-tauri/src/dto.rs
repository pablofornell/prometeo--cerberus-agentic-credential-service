//! The data types of the IPC layer. They live in `cerberus-admin`, so the admin API of `cerberusd`
//! uses the same types (ADR-0034, DEC-RM-6); this module keeps the `crate::dto` paths.

pub use cerberus_admin::dto::*;
