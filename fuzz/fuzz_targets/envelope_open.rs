//! Envelope decode (ADR-0014): arbitrary bytes, and a valid envelope with arbitrary damage.
#![no_main]

use cerberus_crypto::{Aad, Key32, Purpose, open, seal};
use cerberus_types::VaultId;
use libfuzzer_sys::fuzz_target;

thread_local! {
    static KEY: Key32 = Key32::from_bytes([7u8; 32]);
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let vault = VaultId([1u8; 16]);
    let purpose = Purpose::ALL[usize::from(mode >> 4) % Purpose::ALL.len()];
    let aad = Aad {
        purpose,
        vault_id: &vault,
        record_id: b"fuzz-record",
        version: u32::from(mode & 3),
    };
    KEY.with(|key| {
        if mode & 8 == 0 {
            // Raw bytes as an envelope.
            let _ = open(key, &aad, rest);
            return;
        }
        // A valid envelope of `rest`, then damage: truncate, flip, append.
        let Ok(mut sealed) = seal(key, &aad, rest) else {
            return;
        };
        let opened = open(key, &aad, &sealed);
        assert_eq!(opened.as_ref().map(|s| s.expose_secret()), Ok(rest));
        let cut = usize::from(mode & 4) * rest.len() % (sealed.len() + 1);
        if mode & 4 != 0 {
            sealed.truncate(cut);
        } else if let Some(byte) = sealed.get_mut(rest.len() % 97) {
            *byte ^= 0x80;
        }
        assert!(open(key, &aad, &sealed).is_err());
    });
});
