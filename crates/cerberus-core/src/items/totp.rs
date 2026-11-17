//! TOTP codes (RFC 6238) from a stored seed. The seed never leaves the vault (ADR-0027).

use cerberus_crypto::SecretString;
use jiff::Timestamp;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

use super::payload::{TotpAlgorithm, TotpSeed};
use crate::error::CoreError;

/// One code and how long it stays valid.
#[derive(Debug)]
pub struct TotpCode {
    /// The code. A secret: it opens an account for a short time.
    pub code: SecretString,
    /// Length of one step in seconds.
    pub period: u32,
    /// Seconds until the code changes (1..=period).
    pub expires_in_seconds: u32,
}

/// Cleans a Base32 seed as people paste it: spaces, dashes, padding and lower case are accepted.
fn clean_base32(text: &str) -> Zeroizing<String> {
    Zeroizing::new(
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .flat_map(char::to_uppercase)
            .collect(),
    )
}

const fn algorithm(value: TotpAlgorithm) -> Algorithm {
    match value {
        TotpAlgorithm::Sha1 => Algorithm::SHA1,
        TotpAlgorithm::Sha256 => Algorithm::SHA256,
        TotpAlgorithm::Sha512 => Algorithm::SHA512,
    }
}

/// Builds the generator. The error text says what is wrong, never the seed.
pub(crate) fn build(seed: &TotpSeed) -> Result<Totp, &'static str> {
    let secret = Secret::try_from_base32(clean_base32(seed.secret.expose_secret()).as_str())
        .map_err(|_| "must be a Base32 text")?;
    if !matches!(seed.digits, 6 | 8) {
        return Err("digits must be 6 or 8");
    }
    if !(15..=120).contains(&seed.period) {
        return Err("period must be 15..120 seconds");
    }
    Builder::new()
        .with_algorithm(algorithm(seed.algorithm))
        .with_digits(seed.digits)
        .with_step_duration(u64::from(seed.period))
        .with_secret(secret)
        .build()
        .map_err(|_| "seed is too short (at least 128 bits)")
}

/// Checks a seed for the validator. `None` means it is fine.
pub(crate) fn check(seed: &TotpSeed) -> Option<&'static str> {
    build(seed).err()
}

/// The code of `seed` at `now`, and the seconds left in its step.
///
/// # Errors
/// [`CoreError::Corrupt`] when the stored seed does not build (the validator refuses such seeds
/// at create time), or when `now` is before 1970.
pub fn totp_now(seed: &TotpSeed, now: Timestamp) -> Result<TotpCode, CoreError> {
    let totp = build(seed).map_err(|_| CoreError::Corrupt)?;
    let time = u64::try_from(now.as_second()).map_err(|_| CoreError::Corrupt)?;
    let step = totp.step();
    let left = step - (time % step);
    Ok(TotpCode {
        code: SecretString::new(totp.generate(time).to_string()),
        period: seed.period,
        expires_in_seconds: u32::try_from(left).map_err(|_| CoreError::Corrupt)?,
    })
}
