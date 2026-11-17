# ADR-0014: Key hierarchy, AEAD envelope and AAD format

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.1 (gap: exact derivation labels, blob layout, AAD layout)
- Related: ADR-0005, ADR-0009, ADR-0013, ADR-0025, ADR-0027

## Context

The plan names the keys and the cipher. Implementers need exact labels and byte layouts, so the file format is stable
and test vectors are possible (T25).

## Decision

### Keys
```
phrase ──Argon2id(slot params)──► KEK ─┐
recovery key ──HKDF(slot salt)──► KEK ─┤ unwrap (XChaCha20-Poly1305)
                                       ▼
                                 VMK (32 random bytes)
                                       │ HKDF-SHA256(ikm = VMK, salt = vault_id)
      ┌────────────┬───────────┬───────┴─────┬────────────┬──────────────┐
   item_kek     meta_key    audit_key      ca_key      header_key    row_mac_key
      │
   wraps each item-version DEK (32 random bytes)
```
HKDF `info` labels (ASCII): `cerberus/v1/item-kek`, `cerberus/v1/meta-key`, `cerberus/v1/audit-key`,
`cerberus/v1/ca-key`, `cerberus/v1/header-key`, `cerberus/v1/row-mac-key`. Output length 32 bytes each.
`row_mac_key` authenticates plain security columns (ADR-0033).

### Envelope (every encrypted BLOB column)
```
byte 0      : envelope version = 0x01
bytes 1..25 : nonce (24 random bytes from the OS RNG)
bytes 25..  : ciphertext || Poly1305 tag (16 bytes)
```
- A new random nonce for each seal. Random 192-bit nonces make reuse negligible.
- Plaintext before seal: `u32 BE length || data || zero padding` to the next multiple of 64 bytes.
  This hides exact lengths (for example password length).
- Plaintext encoding for structured data: JSON (`serde_json`) into a `Zeroizing<Vec<u8>>`.

### AAD
AAD = concatenation of length-prefixed fields (u16 BE length, then bytes):
1. `cerberus/v1`
2. purpose label (table below)
3. `vault_id` (16 bytes)
4. record ID bytes (UUID = 16 bytes; audit sequence = u64 BE; settings = the key name)
5. version (u32 BE; 0 when the record has no versions)

| Purpose label | Key | Column |
|---|---|---|
| `slot.vmk` | slot KEK | `key_slots.wrapped_vmk` (record ID = slot ID) |
| `item.dek` | `item_kek` | `item_versions.wrapped_dek` |
| `item.payload` | item DEK | `item_versions.payload_ct` |
| `item.meta` | `meta_key` | `items.meta_ct` (current metadata; version = `items.current_version`) |
| `item.meta_snapshot` | `meta_key` | `item_versions.meta_ct` (metadata as it was in that version) |
| `workspace.meta` | `meta_key` | `workspaces.meta_ct` |
| `agent.meta` | `meta_key` | `agents.meta_ct` |
| `grant.body` | `meta_key` | `grants.body_ct` |
| `request.reason` | `meta_key` | `access_requests.reason_ct` |
| `audit.body` | `meta_key` | `audit_events.body_ct` |
| `settings.value` | `meta_key` | `settings.value_ct` |
| `ca.key` | `ca_key` | `tls_ca.ca_key_ct` |

Binding the purpose, vault, record and version stops a copy of a ciphertext into another row, another column,
another vault or another version. Open fails with `IntegrityError`, which the service reports as `vault_corrupt`
and audits.

### Phrase change and key rotation
- Phrase change re-wraps the VMK in that one slot with a new salt and new costs. No item is re-encrypted.
- Each new item version gets a new DEK.
- Full VMK rotation is not in version 1 (see consequences).

## Consequences

- T25 publishes test vectors for the KDF, HKDF labels, AAD bytes and envelope.
- Removing an operator does not rotate the VMK. A removed operator who kept an old copy of the file and knows the old
  phrase can open that copy, and can use the VMK from it to read later copies. This is an accepted risk (threat model E-4).

## Alternatives considered

- **AES-256-GCM.** Rejected. 96-bit nonces make random nonces risky at scale. XChaCha20-Poly1305 is constant-time
  without AES-NI.
- **One key for everything.** Rejected. Separate keys limit the damage of one bug and make audit HMAC independent.
