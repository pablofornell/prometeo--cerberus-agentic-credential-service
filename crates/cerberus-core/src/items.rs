//! Items: typed payloads, validation, versions, expiry, TOTP and SSH keys (ADR-0027, ADR-0007).
//!
//! A payload is the secret part of an item. It is sealed with its own key (ADR-0014) and exists in
//! plain form only inside the call that needs it. The metadata (title, role, environment, ...) is
//! in the index ([`crate::index::ItemMeta`]) and is what resolve and the catalog use.

pub(crate) mod batch;
mod payload;
mod service;
mod settings;
mod ssh;
mod summary;
mod totp;
mod validate;

#[cfg(test)]
pub(crate) mod tests;

pub use payload::{Payload, TotpAlgorithm, TotpSeed};
pub use service::{
    ItemDetail, ItemFilter, ItemInput, ItemUpdate, ItemVersionInfo, PayloadChange, RevealedItem,
};
pub use settings::{ItemSettings, setting_keys};
#[cfg(test)]
pub(crate) use ssh::encrypted_key_with_rounds;
pub(crate) use ssh::{KDF_ROUNDS_PROBLEM, allows_sshsig, kdf_cost_ok};
pub use ssh::{
    KEY_SSHSIG_NAMESPACES, MAX_SSH_KDF_ROUNDS, SshMeta, generate_ed25519, import_private_key,
    ssh_fingerprint,
};
pub use summary::ItemSummary;
pub use totp::{TotpCode, totp_now};
pub use validate::{MAX_PAYLOAD_BYTES, MAX_SESSION_PAYLOAD_BYTES, validate_item, validate_payload};
pub(crate) use validate::{agent_payload_problems, normalize_input};
