//! Text normalization for the index (ADR-0006 point 5).
//!
//! Results are `Zeroizing`, because titles and tags are protected metadata (ADR-0005).

use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Appends `c` to `out` and never leaves a copy of the text in freed memory: when `out` is full,
/// the text moves to a buffer of twice the size, and the old buffer is zeroized on drop.
fn push_zeroizing(out: &mut Zeroizing<String>, c: char) {
    if out.capacity() - out.len() < c.len_utf8() {
        let size = out.capacity().saturating_mul(2).max(out.len() + 4).max(16);
        let mut bigger = Zeroizing::new(String::with_capacity(size));
        bigger.push_str(out);
        *out = bigger;
    }
    out.push(c);
}

/// Unicode NFKC, lower case, trim, and one space for each run of white space.
///
/// The text buffers are `Zeroizing` and grow without a plain realloc (DEC-FIX5-8). The small
/// reorder buffer inside the NFKC iterator is not zeroized.
#[must_use]
pub fn normalize(text: &str) -> Zeroizing<String> {
    let mut lowered = Zeroizing::new(String::with_capacity(text.len().saturating_add(16)));
    for c in text.nfkc().flat_map(char::to_lowercase) {
        push_zeroizing(&mut lowered, c);
    }
    let mut out = Zeroizing::new(String::with_capacity(lowered.len()));
    for part in lowered.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(part);
    }
    out
}

/// The words of `text` after [`normalize`]. Words split on every character that is not a letter
/// or a digit. Empty words are dropped.
#[must_use]
pub fn words(text: &str) -> Vec<Zeroizing<String>> {
    normalize(text)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| Zeroizing::new(w.to_owned()))
        .collect()
}

/// A map key that zeroizes its text on drop. It borrows as `str`, so lookups need no copy.
#[derive(Clone)]
pub struct Word(Zeroizing<String>);

impl PartialEq for Word {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Word {}

impl PartialOrd for Word {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Word {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Word {
    /// Wraps a normalized word.
    #[must_use]
    pub fn new(text: Zeroizing<String>) -> Self {
        Self(text)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Hash for Word {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Borrow<str> for Word {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Word {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Word([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_folds_case_width_and_space() {
        assert_eq!(
            normalize("  Shop   ＦＲＯＮＴ\tEnd ").as_str(),
            "shop front end"
        );
        assert_eq!(normalize("ÅNGSTRÖM").as_str(), "ångström");
        assert_eq!(normalize("").as_str(), "");
    }

    #[test]
    fn words_split_on_non_alphanumeric() {
        let got: Vec<String> = words("SAI-user / Admin_2, prod.example.com")
            .iter()
            .map(|w| w.to_string())
            .collect();
        assert_eq!(got, ["sai", "user", "admin", "2", "prod", "example", "com"]);
    }

    #[test]
    fn normalize_handles_text_that_grows() {
        // NFKC expands U+FDFA to 18 characters; the buffer must grow many times.
        let text = "\u{FDFA}".repeat(40);
        let out = normalize(&text);
        let plain: String = text.nfkc().flat_map(char::to_lowercase).collect();
        let expected = plain.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(out.as_str(), expected);
        assert_eq!(out.chars().count(), 40 * 18);
    }

    #[test]
    fn word_debug_is_redacted() {
        let word = Word::new(Zeroizing::new("hidden".to_owned()));
        assert!(!format!("{word:?}").contains("hidden"));
    }
}
