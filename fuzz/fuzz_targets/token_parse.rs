//! Agent token text from the `Authorization` header (ADR-0016).
#![no_main]

use cerberus_crypto::{parse_token, token_hash};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = parse_token(text) {
        // Strict form: the same agent and secret print back to the same text.
        let again = parsed.secret.to_token_string(&parsed.agent_id);
        assert_eq!(again.expose_secret(), text);
        std::hint::black_box(token_hash(&parsed.agent_id, &parsed.secret));
    }
});
