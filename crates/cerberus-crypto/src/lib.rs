//! Cerberus cryptography: secret types, KDF, key slots, key tree, AEAD envelope, recovery key,
//! MACs, agent tokens, passphrase checks, Diceware and locked memory.
//!
//! Primitives come from reviewed crates (RustCrypto `argon2`, `chacha20poly1305`, `hkdf`, `hmac`,
//! `sha2`; `subtle`, `zeroize`, `secrecy`). This crate only combines them in the formats of
//! ADR-0013, ADR-0014, ADR-0016 and ADR-0033.
//!
//! The crate lint table denies raw OS code (ADR-0012). Only the `memlock` module allows it, with
//! an inner `allow` attribute at the top of `memlock/mod.rs`. So the word that the ADR-0012 CI
//! grep looks for appears only in that module.

pub mod memlock;

mod envelope;
mod error;
mod kdf;
mod keytree;
mod mac;
mod phrase;
mod random;
mod recovery;
mod secret;
mod slots;
mod token;

#[cfg(test)]
mod tests;

pub use envelope::{
    AAD_CONTEXT, Aad, ENVELOPE_VERSION, NONCE_LEN, PAD_BLOCK, Purpose, TAG_LEN, open, seal,
};
pub use error::CryptoError;
pub use kdf::{
    ARGON2_VERSION, KdfParams, KdfTuning, RECOVERY_KEK_INFO, derive_passphrase_kek,
    derive_recovery_kek, normalize_phrase, total_ram_bytes, tune_kdf,
};
pub use keytree::{KeyTree, labels, new_dek, unwrap_dek, wrap_dek};
pub use mac::{
    HeaderMacInput, MacField, ROW_MAC_LABEL, SlotMacInput, ct_eq, header_mac, hmac_sha256,
    length_prefixed, row_mac, sha256, verify_hmac_sha256, verify_row_mac,
};
pub use phrase::{
    DICEWARE_DEFAULT_WORDS, DICEWARE_MAX_WORDS, EFF_WORD_COUNT, MIN_PHRASE_CHARS, MIN_PHRASE_SCORE,
    Strength, diceware, meets_phrase_policy, phrase_strength,
};
pub use recovery::{RECOVERY_PREFIX, RecoveryKey};
pub use secret::{Key32, SecretBytes, SecretString, Vmk};
pub use slots::{
    KDF_ARGON2ID, KDF_HKDF_SHA256, KIND_PASSPHRASE, KIND_RECOVERY, KeySlot, KeySlotSet, SlotKdf,
    SlotMaterial, create_passphrase_slot, create_recovery_slot, open_passphrase_slot,
    open_recovery_slot,
};
pub use token::{
    ParsedToken, TOKEN_HASH_LABEL, TOKEN_PREFIX, TOKEN_SECRET_CHARS, TokenSecret, parse_token,
    token_hash,
};

/// Version of this crate, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
