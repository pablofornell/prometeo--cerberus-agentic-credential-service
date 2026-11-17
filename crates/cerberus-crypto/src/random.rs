//! OS random generator (ADR-0014: nonces and keys come from the OS RNG).

use crate::error::CryptoError;

/// Fills `buf` from the OS random generator.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)
}

/// A uniform random number in `0..bound` without modulo bias (rejection sampling).
pub(crate) fn below(bound: u32) -> Result<u32, CryptoError> {
    if bound == 0 {
        return Err(CryptoError::Encoding);
    }
    // Accept only values under the largest multiple of `bound`, so each result is equally likely.
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let value = getrandom::u32().map_err(|_| CryptoError::Rng)?;
        if value < zone {
            return Ok(value % bound);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_stays_in_range_and_hits_every_value() {
        let mut seen = [false; 6];
        for _ in 0..2000 {
            let v = below(6).unwrap();
            assert!(v < 6);
            seen[v as usize] = true;
        }
        assert!(seen.iter().all(|s| *s));
        assert_eq!(below(1).unwrap(), 0);
        assert_eq!(below(0), Err(CryptoError::Encoding));
    }

    #[test]
    fn fill_changes_the_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
