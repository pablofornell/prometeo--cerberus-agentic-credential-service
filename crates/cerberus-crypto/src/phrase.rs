//! Passphrase strength (zxcvbn) and the Diceware generator (ADR-0013).

use std::sync::OnceLock;

use crate::error::CryptoError;
use crate::mac::{ct_eq, sha256};
use crate::random;
use crate::secret::SecretString;

/// Lowest accepted zxcvbn score (0..=4).
pub const MIN_PHRASE_SCORE: u8 = 3;
/// Lowest accepted length in characters (Unicode scalar values after NFKC).
pub const MIN_PHRASE_CHARS: usize = 12;
/// Default Diceware word count (about 90 bits).
pub const DICEWARE_DEFAULT_WORDS: usize = 7;
/// Highest Diceware word count.
pub const DICEWARE_MAX_WORDS: usize = 64;
/// Number of words in the EFF large list (6^5).
pub const EFF_WORD_COUNT: usize = 7776;

/// The EFF large wordlist, vendored unchanged (see `data/eff_large_wordlist.NOTICE`).
const EFF_LARGE: &str = include_str!("../data/eff_large_wordlist.txt");
/// SHA-256 of the vendored list.
const EFF_LARGE_SHA256: [u8; 32] = [
    0xad, 0xdd, 0x35, 0x53, 0x65, 0x11, 0x59, 0x7a, 0x02, 0xfa, 0x0a, 0x9f, 0xf1, 0xe5, 0x28, 0x46,
    0x77, 0xb8, 0x88, 0x3b, 0x83, 0xe9, 0x86, 0xe4, 0x3f, 0x15, 0xa3, 0xdb, 0x99, 0x6b, 0x90, 0x3e,
];

/// zxcvbn result. Holds feedback text only, never the phrase.
#[derive(Clone, Debug)]
pub struct Strength {
    /// 0 (weak) ..= 4 (strong).
    pub score: u8,
    /// log10 of the estimated guesses.
    pub guesses_log10: f64,
    /// Main warning, if any (English).
    pub warning: Option<String>,
    /// Suggestions (English).
    pub suggestions: Vec<String>,
}

/// zxcvbn estimate of `phrase`. `user_inputs` are words the guesser may know (labels, names).
///
/// Note: zxcvbn makes internal copies of parts of the phrase that are not zeroized.
#[must_use]
pub fn phrase_strength(phrase: &SecretString, user_inputs: &[&str]) -> Strength {
    let entropy = zxcvbn::zxcvbn(phrase.expose_secret(), user_inputs);
    let feedback = entropy.feedback();
    Strength {
        score: u8::from(entropy.score()),
        guesses_log10: entropy.guesses_log10(),
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback
            .map(|f| f.suggestions().iter().map(ToString::to_string).collect())
            .unwrap_or_default(),
    }
}

/// True when `phrase` has at least 12 characters and a zxcvbn score of at least 3.
/// Pass the phrase after [`crate::normalize_phrase`]. There is no override (DEC-010).
#[must_use]
pub fn meets_phrase_policy(phrase: &SecretString, user_inputs: &[&str]) -> bool {
    phrase.expose_secret().chars().count() >= MIN_PHRASE_CHARS
        && phrase_strength(phrase, user_inputs).score >= MIN_PHRASE_SCORE
}

/// The 7776 words, after the checksum and format checks. `None` if the vendored file is wrong.
fn eff_words() -> Option<&'static [&'static str]> {
    static WORDS: OnceLock<Option<Vec<&'static str>>> = OnceLock::new();
    WORDS.get_or_init(parse_eff_list).as_deref()
}

fn parse_eff_list() -> Option<Vec<&'static str>> {
    if !ct_eq(&sha256(&[EFF_LARGE.as_bytes()]), &EFF_LARGE_SHA256) {
        return None;
    }
    let mut words = Vec::with_capacity(EFF_WORD_COUNT);
    for line in EFF_LARGE.lines() {
        let (dice, word) = line.split_once('\t')?;
        let digits_ok = dice.len() == 5 && dice.bytes().all(|b| (b'1'..=b'6').contains(&b));
        if !digits_ok || word.is_empty() {
            return None;
        }
        words.push(word);
    }
    (words.len() == EFF_WORD_COUNT).then_some(words)
}

/// A Diceware phrase of `words` words from the EFF large list, separated by one space.
/// Each word adds log2(7776) ≈ 12.9 bits; 7 words ≈ 90 bits.
///
/// # Errors
/// [`CryptoError::Encoding`] when `words` is 0 or more than 64, or the vendored list is damaged;
/// [`CryptoError::Rng`] when the OS random generator fails.
pub fn diceware(words: usize) -> Result<SecretString, CryptoError> {
    if words == 0 || words > DICEWARE_MAX_WORDS {
        return Err(CryptoError::Encoding);
    }
    let list = eff_words().ok_or(CryptoError::Encoding)?;
    let bound = u32::try_from(list.len()).map_err(|_| CryptoError::Encoding)?;
    // Longest EFF word is 9 characters: reserve once so the buffer never moves.
    let mut out = String::with_capacity(words * 10);
    for i in 0..words {
        if i > 0 {
            out.push(' ');
        }
        let index = usize::try_from(random::below(bound)?).map_err(|_| CryptoError::Encoding)?;
        out.push_str(list.get(index).ok_or(CryptoError::Encoding)?);
    }
    Ok(SecretString::new(out))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn vendored_list_is_the_eff_large_list() {
        assert_eq!(sha256(&[EFF_LARGE.as_bytes()]), EFF_LARGE_SHA256);
        let words = eff_words().unwrap();
        assert_eq!(words.len(), 7776);
        assert_eq!(words.iter().collect::<HashSet<_>>().len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[7775], "zoom");
        // The dice index runs 11111..=66666 in order.
        let dice: Vec<&str> = EFF_LARGE.lines().map(|l| &l[..5]).collect();
        let mut expected = Vec::new();
        for a in 1..=6 {
            for b in 1..=6 {
                for c in 1..=6 {
                    for d in 1..=6 {
                        for e in 1..=6 {
                            expected.push(format!("{a}{b}{c}{d}{e}"));
                        }
                    }
                }
            }
        }
        assert_eq!(dice, expected);
        assert!(
            words
                .iter()
                .all(|w| w.len() <= 9 && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
    }

    #[test]
    fn diceware_shape_and_strength() {
        let words = eff_words().unwrap();
        let mut seen = HashSet::new();
        for _ in 0..20 {
            let phrase = diceware(DICEWARE_DEFAULT_WORDS).unwrap();
            let parts: Vec<&str> = phrase.expose_secret().split(' ').collect();
            assert_eq!(parts.len(), 7);
            assert!(parts.iter().all(|p| words.contains(p)));
            assert!(meets_phrase_policy(&phrase, &[]));
            seen.insert(phrase.expose_secret().to_owned());
        }
        assert_eq!(seen.len(), 20);
    }

    #[test]
    fn diceware_limits() {
        assert_eq!(diceware(0).err(), Some(CryptoError::Encoding));
        assert_eq!(diceware(65).err(), Some(CryptoError::Encoding));
        assert_eq!(diceware(1).unwrap().expose_secret().split(' ').count(), 1);
        assert_eq!(diceware(64).unwrap().expose_secret().split(' ').count(), 64);
    }

    #[test]
    fn policy_refuses_short_or_weak_phrases() {
        let weak = SecretString::new("password1234".to_owned());
        assert!(!meets_phrase_policy(&weak, &[]));
        assert!(phrase_strength(&weak, &[]).score < MIN_PHRASE_SCORE);
        let short = SecretString::new("Zq#8v!Lp2&k".to_owned());
        assert_eq!(short.expose_secret().chars().count(), 11);
        assert!(!meets_phrase_policy(&short, &[]));
        let strong = SecretString::new("orbit-velvet-cactus-lantern-91".to_owned());
        assert!(meets_phrase_policy(&strong, &[]));
        // A phrase built from the user's own label is weaker.
        let label = SecretString::new("ownerlabelowner".to_owned());
        assert!(!meets_phrase_policy(&label, &["ownerlabel"]));
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // 11 characters, 22 bytes: too short.
        let accents = SecretString::new("ééééééééééé".to_owned());
        assert!(!meets_phrase_policy(&accents, &[]));
    }

    #[test]
    fn strength_has_feedback_for_weak_phrases() {
        let s = phrase_strength(&SecretString::new("qwertyuiop".to_owned()), &[]);
        assert!(s.warning.is_some() || !s.suggestions.is_empty());
        assert!(format!("{s:?}").contains("score"));
    }
}
