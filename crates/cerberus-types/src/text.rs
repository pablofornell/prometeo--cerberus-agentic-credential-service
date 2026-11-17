//! Hidden format characters in untrusted text (AUD-24).
//!
//! `char::is_control` finds only the `Cc` characters. Text that an agent writes (reasons, item
//! titles) can also hold `Cf` characters: bidi controls that change the display order (so `prod`
//! can look like `dorp`), zero-width characters, and the tag characters that can hide text from
//! a person but not from a model. Core removes them; clients can use the same test.

/// The `Cf` (format) characters of Unicode 16, as inclusive ranges.
const FORMAT_RANGES: &[(char, char)] = &[
    ('\u{00AD}', '\u{00AD}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// True for a `Cf` (format) character: bidi controls, zero-width characters, tag characters.
#[must_use]
pub fn is_format_char(c: char) -> bool {
    FORMAT_RANGES
        .iter()
        .any(|(lo, hi)| (*lo..=*hi).contains(&c))
}

/// True for a character that untrusted text must not keep: a control (`Cc`) or a format (`Cf`)
/// character.
#[must_use]
pub fn is_hidden_char(c: char) -> bool {
    c.is_control() || is_format_char(c)
}

/// `text` without format characters. Control characters stay, so a check that refuses them
/// still sees them.
#[must_use]
pub fn strip_format(text: &str) -> String {
    text.chars().filter(|c| !is_format_char(*c)).collect()
}

/// `text` without control and format characters.
#[must_use]
pub fn strip_hidden(text: &str) -> String {
    text.chars().filter(|c| !is_hidden_char(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::{is_format_char, strip_format, strip_hidden};

    #[test]
    fn bidi_zero_width_and_tag_characters_are_format_characters() {
        for c in [
            '\u{202E}',
            '\u{202A}',
            '\u{2066}',
            '\u{2069}',
            '\u{200B}',
            '\u{200D}',
            '\u{FEFF}',
            '\u{061C}',
            '\u{E0041}',
            '\u{00AD}',
        ] {
            assert!(is_format_char(c), "U+{:04X}", u32::from(c));
        }
        for c in ['a', 'é', ' ', '\u{1F600}', '-'] {
            assert!(!is_format_char(c));
        }
    }

    #[test]
    fn strip_removes_controls_and_format_characters() {
        assert_eq!(
            strip_hidden("p\u{202E}dor\u{202C}d\u{200B}\n\u{E0041}"),
            "pdord"
        );
        assert_eq!(strip_hidden("plain text"), "plain text");
        assert_eq!(strip_format("a\u{202E}b\n"), "ab\n");
    }
}
