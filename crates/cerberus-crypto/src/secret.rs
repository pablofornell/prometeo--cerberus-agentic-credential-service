//! Secret types (ADR-0032 point 2).
//!
//! Rules for every type here:
//! - `Debug` prints `[REDACTED]`.
//! - No `Display`, no `Serialize` (this crate does not depend on `serde`).
//! - The memory is zeroized on drop.
//! - Read access only through `expose_secret()`.

use std::fmt;

use secrecy::ExposeSecret;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::memlock::LockedBox;
use crate::random;

const REDACTED: &str = "[REDACTED]";

/// Heap bytes, zeroized on drop.
#[derive(Clone)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of `bytes`. No copy is made.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Number of bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl ZeroizeOnDrop for SecretBytes {}

/// UTF-8 secret text (phrases, passwords, the recovery key text). Same rules as [`SecretBytes`].
#[derive(Clone)]
pub struct SecretString(secrecy::SecretString);

impl SecretString {
    /// Takes ownership of `value`.
    #[must_use]
    pub fn new(mut value: String) -> Self {
        // `secrecy` shrinks the string to a boxed `str`. A shrink can reallocate and free the old
        // buffer without a wipe, so copy to an exact-size buffer first and wipe the original.
        if value.capacity() != value.len() {
            let mut exact = String::with_capacity(value.len());
            exact.push_str(&value);
            value.zeroize();
            value = exact;
        }
        Self(secrecy::SecretString::from(value))
    }

    /// The secret text.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl ZeroizeOnDrop for SecretString {}

/// A 32-byte key in locked memory (ADR-0012).
pub struct Key32(LockedBox<[u8; 32]>);

impl Key32 {
    /// A new key from the OS random generator, written straight into locked memory.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the OS random generator fails.
    pub fn random() -> Result<Self, CryptoError> {
        Self::try_fill(|out| random::fill(out))
    }

    /// Copies `bytes` into locked memory and zeroizes the by-value argument.
    ///
    /// `[u8; 32]` is `Copy`, so the caller's own array is not touched: the caller must wipe its
    /// copy. To avoid any plain copy, write straight into locked memory with `Key32::try_fill`.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let key = Self(LockedBox::new_with(|target: &mut [u8; 32]| *target = bytes));
        bytes.zeroize();
        key
    }

    /// Lets `fill` write the key in place. On error the memory is zeroized.
    pub(crate) fn try_fill(
        fill: impl FnOnce(&mut [u8; 32]) -> Result<(), CryptoError>,
    ) -> Result<Self, CryptoError> {
        LockedBox::try_new_with(fill).map(Self)
    }

    /// The key bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.get()
    }

    /// True when the key pages are locked in RAM.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl ZeroizeOnDrop for Key32 {}

/// The vault master key (ADR-0014). Only the key tree and the slot functions read it.
pub struct Vmk(pub(crate) Key32);

impl Vmk {
    /// A new random VMK.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the OS random generator fails.
    pub fn generate() -> Result<Self, CryptoError> {
        Key32::random().map(Self)
    }

    /// Constant-time check that two handles hold the same key (for example after a rewrap).
    #[must_use]
    pub fn same_key(&self, other: &Self) -> bool {
        crate::mac::ct_eq(self.0.expose_secret(), other.0.expose_secret())
    }
}

impl fmt::Debug for Vmk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl ZeroizeOnDrop for Vmk {}
