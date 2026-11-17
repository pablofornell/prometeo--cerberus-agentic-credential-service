//! Password generation. It draws from the OS random generator and avoids modulo bias.

use serde::{Deserialize, Serialize};
use specta::Type;
use zeroize::Zeroizing;

use crate::error::{IpcError, IpcResult};

/// A class of characters for `password_generate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum CharClass {
    /// `a` to `z`.
    Lower,
    /// `A` to `Z`.
    Upper,
    /// `0` to `9`.
    Digits,
    /// Punctuation.
    Symbols,
}

impl CharClass {
    const fn chars(self) -> &'static [u8] {
        match self {
            Self::Lower => b"abcdefghijklmnopqrstuvwxyz",
            Self::Upper => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Self::Digits => b"0123456789",
            Self::Symbols => b"!@#$%^&*()-_=+[]{};:,.<>?/~",
        }
    }
}

/// Shortest and longest generated password.
pub const MIN_LENGTH: u32 = 8;
/// Longest generated password.
pub const MAX_LENGTH: u32 = 128;

fn random_below(limit: usize) -> IpcResult<usize> {
    // Rejection sampling over one byte: values at or above the largest multiple of `limit` are
    // dropped, so every index is equally likely. `limit` is at most 100 here.
    let zone = 256 - (256 % limit);
    loop {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).map_err(|e| IpcError::internal(&e))?;
        let value = usize::from(byte[0]);
        if value < zone {
            return Ok(value % limit);
        }
    }
}

/// A random password of `length` characters with at least one character of each chosen class.
///
/// # Errors
/// `validation_failed` for a bad length or no class; `internal` when the OS random source fails.
pub fn password(length: u32, classes: &[CharClass]) -> IpcResult<Zeroizing<String>> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(IpcError::invalid("length", "must be 8 to 128"));
    }
    // Each class counts once, whatever the order (`dedup` removes only neighbours).
    let mut unique: Vec<CharClass> = Vec::with_capacity(classes.len());
    for class in classes {
        if !unique.contains(class) {
            unique.push(*class);
        }
    }
    let classes = unique;
    if classes.is_empty() {
        return Err(IpcError::invalid("classes", "needs at least one class"));
    }
    let pool: Zeroizing<Vec<u8>> = Zeroizing::new(
        classes
            .iter()
            .flat_map(|c| c.chars().iter().copied())
            .collect(),
    );
    let len = usize::try_from(length).unwrap_or(usize::MAX);
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(len));
    for class in &classes {
        let set = class.chars();
        out.push(set[random_below(set.len())?]);
    }
    while out.len() < len {
        out.push(pool[random_below(pool.len())?]);
    }
    // Fisher-Yates, so the guaranteed characters do not sit at the front.
    for i in (1..out.len()).rev() {
        let j = random_below(i + 1)?;
        out.swap(i, j);
    }
    Ok(Zeroizing::new(String::from_utf8_lossy(&out).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_the_length_and_every_class() {
        let all = [
            CharClass::Lower,
            CharClass::Upper,
            CharClass::Digits,
            CharClass::Symbols,
        ];
        for _ in 0..50 {
            let pw = password(20, &all).expect("password");
            assert_eq!(pw.len(), 20);
            assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(pw.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(pw.bytes().any(|b| b.is_ascii_digit()));
            assert!(pw.bytes().any(|b| !b.is_ascii_alphanumeric()));
        }
    }

    /// AUD-30: `dedup()` removes only neighbours, so [Lower, Digits, Lower] kept Lower twice and
    /// made lower-case letters twice as likely. Each class counts once, whatever the order.
    #[test]
    fn a_repeated_class_does_not_change_the_mix() {
        let classes = [CharClass::Lower, CharClass::Digits, CharClass::Lower];
        let (mut digits, mut total) = (0usize, 0usize);
        for _ in 0..400 {
            let pw = password(128, &classes).expect("password");
            digits += pw.bytes().filter(u8::is_ascii_digit).count();
            total += pw.len();
        }
        // The pool is 26 letters and 10 digits: a share of 10/36 = 0.278. With the bug it was 10/62.
        let share = digits as f64 / total as f64;
        assert!((0.25..0.31).contains(&share), "digit share {share}");
    }

    #[test]
    fn password_rejects_bad_input() {
        assert!(password(7, &[CharClass::Lower]).is_err());
        assert!(password(129, &[CharClass::Lower]).is_err());
        assert!(password(20, &[]).is_err());
        let digits = password(30, &[CharClass::Digits]).expect("digits");
        assert!(digits.bytes().all(|b| b.is_ascii_digit()));
    }
}
