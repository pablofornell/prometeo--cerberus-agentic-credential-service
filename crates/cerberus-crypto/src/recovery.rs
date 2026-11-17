//! Recovery key: 32 random bytes with a text form for people (ADR-0013).
//!
//! Text: `CRK1-` + 14 groups of 4 characters (RFC 4648 Base32, no padding). The 35 encoded bytes
//! are the key and the first 3 bytes of SHA-256(key) as a checksum.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::mac::{ct_eq, sha256};
use crate::secret::{Key32, SecretString};

/// Text prefix of the current recovery key format.
pub const RECOVERY_PREFIX: &str = "CRK1";
const GROUPS: usize = 14;
const GROUP_LEN: usize = 4;
const BODY_LEN: usize = GROUPS * GROUP_LEN;
const CHECKSUM_LEN: usize = 3;

/// A 256-bit recovery key in locked memory.
pub struct RecoveryKey(Key32);

impl RecoveryKey {
    /// A new random recovery key.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the OS random generator fails.
    pub fn generate() -> Result<Self, CryptoError> {
        Key32::random().map(Self)
    }

    /// Parses the text form. Lenient for typing: any case, spaces and `-` are ignored,
    /// `0`→`O`, `1`→`I`, `8`→`B`. The `CRK1` prefix is optional.
    ///
    /// # Errors
    /// [`CryptoError::Encoding`] for a wrong length or character, and
    /// [`CryptoError::ChecksumMismatch`] for a bad checksum. Both are typing errors and must not
    /// count as a failed unlock (ADR-0013). The KDF does not run for them.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let mut cleaned = Zeroizing::new(String::with_capacity(text.len()));
        cleaned.extend(
            text.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase()),
        );
        let body = match cleaned.len() {
            BODY_LEN => cleaned.as_str(),
            n if n == RECOVERY_PREFIX.len() + BODY_LEN && cleaned.starts_with(RECOVERY_PREFIX) => {
                &cleaned[RECOVERY_PREFIX.len()..]
            }
            _ => return Err(CryptoError::Encoding),
        };
        let mut mapped = Zeroizing::new(Vec::with_capacity(BODY_LEN));
        mapped.extend(body.bytes().map(|b| match b {
            b'0' => b'O',
            b'1' => b'I',
            b'8' => b'B',
            other => other,
        }));
        let mut decoded = Zeroizing::new([0u8; 35]);
        let len = BASE32_NOPAD
            .decode_len(mapped.len())
            .map_err(|_| CryptoError::Encoding)?;
        if len != decoded.len() {
            return Err(CryptoError::Encoding);
        }
        BASE32_NOPAD
            .decode_mut(&mapped, &mut decoded[..])
            .map_err(|_| CryptoError::Encoding)?;
        let (key, checksum) = decoded.split_at(32);
        if !ct_eq(&sha256(&[key])[..CHECKSUM_LEN], checksum) {
            return Err(CryptoError::ChecksumMismatch);
        }
        // Straight into locked memory: no plain copy of the key is left on the stack.
        Ok(Self(Key32::try_fill(|out| {
            out.copy_from_slice(key);
            Ok(())
        })?))
    }

    /// The text form `CRK1-XXXX-…-XXXX`, shown to the person one time.
    #[must_use]
    pub fn to_display(&self) -> SecretString {
        let mut raw = Zeroizing::new([0u8; 35]);
        raw[..32].copy_from_slice(self.0.expose_secret());
        raw[32..].copy_from_slice(&sha256(&[self.0.expose_secret()])[..CHECKSUM_LEN]);
        let mut body = Zeroizing::new([0u8; BODY_LEN]);
        BASE32_NOPAD.encode_mut(&raw[..], &mut body[..]);
        let mut out = String::with_capacity(RECOVERY_PREFIX.len() + GROUPS * (GROUP_LEN + 1));
        out.push_str(RECOVERY_PREFIX);
        for group in body.chunks(GROUP_LEN) {
            out.push('-');
            out.extend(group.iter().map(|b| char::from(*b)));
        }
        SecretString::new(out)
    }

    /// The key bytes (used by the recovery KDF).
    pub(crate) fn key(&self) -> &Key32 {
        &self.0
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl ZeroizeOnDrop for RecoveryKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_form_has_14_groups_and_roundtrips() {
        let key = RecoveryKey::generate().unwrap();
        let text = key.to_display();
        let text = text.expose_secret();
        assert!(text.starts_with("CRK1-"));
        let groups: Vec<&str> = text["CRK1-".len()..].split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
        let back = RecoveryKey::parse(text).unwrap();
        assert_eq!(back.key().expose_secret(), key.key().expose_secret());
    }

    #[test]
    fn known_vector() {
        // Fake key 00 01 .. 1f. SHA-256 of it starts with 63 0d cd (checked with Python hashlib).
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let key = RecoveryKey(Key32::from_bytes(bytes));
        let text = key.to_display();
        assert_eq!(
            text.expose_secret(),
            "CRK1-AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPW-GDON"
        );
    }

    #[test]
    fn parse_is_lenient_for_typing() {
        let key = RecoveryKey::generate().unwrap();
        let text = key.to_display().expose_secret().to_owned();
        let body: String = text["CRK1-".len()..]
            .chars()
            .filter(|c| *c != '-')
            .collect();
        let variants = [
            text.to_lowercase(),
            text.replace('-', " "),
            body.clone(),
            format!("  {}  ", text),
            format!(
                "CRK1-{}",
                body.replace('O', "0").replace('I', "1").replace('B', "8")
            ),
        ];
        for variant in variants {
            let back = RecoveryKey::parse(&variant).unwrap();
            assert_eq!(back.key().expose_secret(), key.key().expose_secret());
        }
    }

    #[test]
    fn typing_errors_are_detected() {
        let key = RecoveryKey::generate().unwrap();
        let text = key.to_display().expose_secret().to_owned();
        // Change one body character to another valid Base32 character.
        let pos = text.len()
            - 1
            - text
                .chars()
                .rev()
                .position(|c| c.is_ascii_alphabetic())
                .unwrap();
        let mut chars: Vec<char> = text.chars().collect();
        chars[pos] = if chars[pos] == 'A' { 'C' } else { 'A' };
        let changed: String = chars.into_iter().collect();
        // A valid character in the wrong place decodes, so only the checksum can catch it.
        assert_eq!(
            RecoveryKey::parse(&changed).err(),
            Some(CryptoError::ChecksumMismatch)
        );
        let mut first: Vec<char> = text.chars().collect();
        first[5] = if first[5] == 'Z' { 'Y' } else { 'Z' };
        let first: String = first.into_iter().collect();
        assert_eq!(
            RecoveryKey::parse(&first).err(),
            Some(CryptoError::ChecksumMismatch)
        );
        for bad in [
            "",
            "CRK1",
            "CRK1-AAAA",
            &text[..text.len() - 1],
            &format!("{text}A"),
            &format!("{}!{}", &text[..5], &text[6..]),
        ] {
            assert!(RecoveryKey::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let key = RecoveryKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "[REDACTED]");
    }
}
