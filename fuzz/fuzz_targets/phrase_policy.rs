//! Passphrase policy: zxcvbn strength and the 12-character rule on arbitrary text.
#![no_main]

use cerberus_crypto::{SecretString, meets_phrase_policy, normalize_phrase, phrase_strength};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let phrase = normalize_phrase(text);
    let strength = phrase_strength(&phrase, &["cerberus"]);
    assert!(strength.score <= 4);
    let _ = meets_phrase_policy(&SecretString::new(text.to_owned()), &[]);
});
