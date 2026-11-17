//! Crypto error type. Messages are fixed text and never hold secret data.

/// Errors of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// AEAD open failed: wrong key (for example a wrong phrase), wrong AAD, or changed bytes.
    #[error("integrity check failed")]
    Integrity,
    /// KDF parameters are out of the accepted range (ADR-0013).
    #[error("invalid KDF parameters")]
    InvalidKdfParams,
    /// The key derivation function failed.
    #[error("key derivation failed")]
    Kdf,
    /// The OS random generator failed.
    #[error("random generator failed")]
    Rng,
    /// Text or bytes have the wrong form or length.
    #[error("invalid encoding")]
    Encoding,
    /// The recovery key checksum does not match: a typing error (ADR-0013).
    #[error("recovery key checksum mismatch")]
    ChecksumMismatch,
    /// The envelope version byte is not known.
    #[error("unsupported envelope version")]
    EnvelopeVersion,
    /// The phrase is shorter than 12 characters or its zxcvbn score is below 3 (ADR-0013).
    #[error("passphrase too weak")]
    WeakPhrase,
    /// A key slot rule failed: unknown slot, wrong slot kind, or the last owner slot.
    #[error("key slot rule violated")]
    SlotRule,
}
