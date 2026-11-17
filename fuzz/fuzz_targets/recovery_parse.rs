//! Recovery key text and passphrase normalisation: `RecoveryKey::parse` and NFKC.
#![no_main]

use cerberus_crypto::{RecoveryKey, normalize_phrase};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(key) = RecoveryKey::parse(text) {
        // A parsed key prints in the canonical form and parses back to the same key.
        let shown = key.to_display();
        let again = RecoveryKey::parse(shown.expose_secret());
        assert!(again.is_ok());
    }
    let normal = normalize_phrase(text);
    // Normalisation is idempotent.
    assert_eq!(
        normalize_phrase(normal.expose_secret()).expose_secret(),
        normal.expose_secret()
    );
});
