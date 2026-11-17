//! Golden vectors of the audit chain links (ADR-0025), version 1.
//!
//! `vectors/audit_chain_v1.txt` was computed with Python (`hashlib`, `hmac`), not with this code,
//! from the rules of ADR-0025. The test rebuilds three linked entries and checks every hash. A
//! change in the label, the length prefix, the field order or the genesis rule breaks it. The
//! audit key and the bodies are fake test values.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::HashMap;

use cerberus_core::audit::{entry_hash, genesis_prev_hash};
use cerberus_crypto::{Key32, hmac_sha256};
use cerberus_types::VaultId;

const FILE: &str = include_str!("vectors/audit_chain_v1.txt");

fn table() -> HashMap<&'static str, &'static str> {
    FILE.lines()
        .filter_map(|line| line.split_once(" = "))
        .collect()
}

fn bytes(table: &HashMap<&'static str, &'static str>, name: &str) -> Vec<u8> {
    let hex = table.get(name).copied().expect("vector exists");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn array(table: &HashMap<&'static str, &'static str>, name: &str) -> [u8; 32] {
    bytes(table, name).try_into().expect("32 bytes")
}

#[test]
fn chain_links_match_the_vectors() {
    let t = table();
    let vault = VaultId(bytes(&t, "vault_id").try_into().expect("16 bytes"));
    let audit_key = Key32::from_bytes(array(&t, "audit_key"));
    let mut prev = genesis_prev_hash(&vault);
    assert_eq!(prev, array(&t, "genesis_prev_hash"));
    for n in 1..=3 {
        let name = |field: &str| format!("link{n}_{field}");
        let seq: u64 = t[name("seq").as_str()].parse().expect("number");
        let at: i64 = t[name("occurred_at_ms").as_str()].parse().expect("number");
        assert_eq!(prev, array(&t, &name("prev_hash")));
        let body = bytes(&t, &name("body_ct"));
        let hash = entry_hash(seq, at, &prev, &body);
        assert_eq!(
            hash,
            array(&t, &name("entry_hash")),
            "entry hash of link {n}"
        );
        // The row HMAC is HMAC-SHA256(audit_key, entry_hash).
        assert_eq!(
            hmac_sha256(&audit_key, &[&hash]),
            array(&t, &name("row_hmac")),
            "row HMAC of link {n}"
        );
        prev = hash;
    }
}
