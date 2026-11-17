//! Hash and HMAC rules of the chain (ADR-0025). Pure functions, no I/O.

use cerberus_crypto::{Key32, hmac_sha256, length_prefixed, sha256};
use cerberus_store::AuditHeadRow;
use cerberus_types::VaultId;

const ENTRY_LABEL: &[u8] = b"cerberus/v1/audit";
const GENESIS_LABEL: &[u8] = b"cerberus/v1/audit-genesis";
const HEAD_LABEL: &[u8] = b"cerberus/v1/audit-head";

/// `SHA-256(lp("cerberus/v1/audit") || lp(seq) || lp(occurred_at) || lp(prev_hash) || lp(body_ct))`.
#[must_use]
pub fn entry_hash(seq: u64, occurred_at_ms: i64, prev_hash: &[u8; 32], body_ct: &[u8]) -> [u8; 32] {
    let input = length_prefixed(&[
        ENTRY_LABEL,
        &seq.to_be_bytes(),
        &occurred_at_ms.to_be_bytes(),
        prev_hash,
        body_ct,
    ]);
    sha256(&[&input])
}

/// `prev_hash` of the first row: `SHA-256("cerberus/v1/audit-genesis" || vault_id)`.
#[must_use]
pub fn genesis_prev_hash(vault: &VaultId) -> [u8; 32] {
    sha256(&[GENESIS_LABEL, vault.as_bytes()])
}

/// `HMAC-SHA256(audit_key, entry_hash)`.
pub(crate) fn row_hmac(audit_key: &Key32, entry_hash: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(audit_key, &[entry_hash])
}

/// HMAC over the four values of the head (ADR-0025).
pub(crate) fn head_hmac(
    audit_key: &Key32,
    last_seq: u64,
    last_entry_hash: &[u8; 32],
    anchor_seq: u64,
    anchor_prev_hash: &[u8; 32],
) -> [u8; 32] {
    let input = length_prefixed(&[
        HEAD_LABEL,
        &last_seq.to_be_bytes(),
        last_entry_hash,
        &anchor_seq.to_be_bytes(),
        anchor_prev_hash,
    ]);
    hmac_sha256(audit_key, &[&input])
}

/// A signed head row.
pub(crate) fn make_head(
    audit_key: &Key32,
    last_seq: u64,
    last_entry_hash: [u8; 32],
    anchor_seq: u64,
    anchor_prev_hash: [u8; 32],
) -> AuditHeadRow {
    AuditHeadRow {
        last_seq,
        last_entry_hash,
        anchor_seq,
        anchor_prev_hash,
        head_hmac: head_hmac(
            audit_key,
            last_seq,
            &last_entry_hash,
            anchor_seq,
            &anchor_prev_hash,
        ),
    }
}
