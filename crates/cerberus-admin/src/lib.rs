//! Cerberus admin contract (ADR-0034, DEC-RM-6).
//!
//! The data types of the IPC layer and its one error type. The desktop app uses them for Tauri
//! IPC; the admin API of `cerberusd` uses the same types on the wire, so a command has one shape
//! in both modes. The crate has no transport: no Tauri, no HTTP.
//!
//! - [`dto`]: the IPC types (they carry `specta::Type`, so `bindings.ts` has the same shape) and
//!   their conversions from and to the core types.
//! - [`error`]: [`error::IpcError`], the error every command returns.

#![forbid(unsafe_code)]

pub mod dto;
pub mod error;
