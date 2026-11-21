//! Cerberus admin contract (ADR-0034, DEC-RM-6).
//!
//! The data types of the IPC layer and its one error type. The desktop app uses them for Tauri
//! IPC; the admin API of `cerberusd` uses the same types on the wire, so a command has one shape
//! in both modes. The crate has no transport: no Tauri, no HTTP.
//!
//! - [`dto`]: the IPC types (they carry `specta::Type`, so `bindings.ts` has the same shape) and
//!   their conversions from and to the core types.
//! - [`error`]: [`error::IpcError`], the error every command returns.
//! - [`handlers`]: one handler per command of the remote allowlist. The desktop `ops` and the
//!   admin API call the same handler, so a command does the same work in both modes.
//! - [`remote`]: the remote allowlist and the admin protocol version.
//! - [`rpc`]: the arguments of each remote command, the zeroizing JSON body, and the dispatch.
//! - [`events`]: the live UI events as they go on the wire.
//! - [`clients`]: the registry of enrolled desktops (`admin-clients.json`) of `cerberusd`.
//! - [`bundle`]: the enrolment bundle that `cerberusd admin enroll` writes and the desktop reads.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod clients;
pub mod dto;
pub mod error;
pub mod events;
pub mod handlers;
pub mod remote;
pub mod rpc;
