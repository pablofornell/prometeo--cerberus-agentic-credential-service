//! Cerberus storage: one SQLite file, embedded migrations, and a repository for every table.
//!
//! The store keeps no key. It reads and writes sealed bytes (ADR-0005) and plain columns. Three helpers
//! use the crypto crate on the caller's keys:
//! - [`Blobs`] seals and opens each encrypted column with the right purpose and AAD (ADR-0014).
//! - [`RowMacs`] makes and checks the row MACs of `agents`, `agent_keys`, `leases` and `access_requests` (ADR-0033).
//! - [`header_mac`] and [`verify_header_mac`] cover the vault header (ADR-0013).
//!
//! Everything that must work while the vault is locked needs no key: the schema check, token rows,
//! the unlock failure counter, pending audit events, backup, and the expiry [`Sweeper`].

mod backup;
mod blobs;
mod convert;
mod error;
mod fsutil;
mod macs;
mod rows;
mod store;
mod sweeper;
mod tx;

pub use backup::{linked_vault_file, restore_backup, retire_replaced, stranded_vaults};
pub use blobs::{Blobs, SealedPayload};
pub use error::StoreError;
pub use macs::{RowMacs, header_mac, verify_header_mac};
pub use rows::{
    AccessRequestRow, AgentKeyRow, AgentRow, AgentStatus, AuditHeadRow, AuditPendingRow, AuditRow,
    BackupInfo, FORMAT_VERSION, GrantRow, HeaderRow, IndexRows, ItemRow, ItemVersionRow,
    KeySlotRow, LeaseRow, LeaseSource, MAGIC, SettingRow, SlotKind, TlsCaRow, WorkspaceRow,
};
pub use store::{APPLICATION_ID, OpenOptions, Store, schema_version};
pub use sweeper::{AUDIT_PENDING_CAP, SweepReport, Sweeper};
pub use tx::{CancelReport, PendingTake, RevokeReport, Tx};

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
