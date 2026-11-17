# ADR-0033: Row MACs protect security-relevant plain columns

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.1, 4.4, 4.5 (gap found in the T01 threat model, T-5)
- Related: ADR-0005, ADR-0014, ADR-0016, ADR-0019, ADR-0018, `docs/schema.sql`, `docs/security/threat-model.md`

## Context

Some columns must be plain so the service works while locked (ADR-0005, ADR-0016): agent status, agent key hashes,
scopes and expiry, lease rows, access request state. AEAD protects only the encrypted columns. A person with write
access to the file could, without any key:
- insert an `agent_keys` row with the hash of a token they made, or add scopes to a key;
- clear `revoked_at`, extend `expires_at`;
- set an access request to `approved`, or extend a lease, or reset `uses`.

## Decision

1. New HKDF key: `row_mac_key` (info `cerberus/v1/row-mac-key`, ADR-0014 key tree).
2. Tables `agents`, `agent_keys`, `leases` and `access_requests` get a column `row_mac BLOB(32)`.
3. `row_mac = HMAC-SHA256(row_mac_key, lp("cerberus/v1/row") || lp(table name) || lp(vault_id) || lp(col_1) || …)`,
   with `lp` = u16 BE length prefix and NULL encoded as an empty field with a one-byte `0x00` marker before it
   (non-NULL fields get `0x01`). MACed columns:
   - `agents`: `id`, `status`, `created_at`.
   - `agent_keys`: all columns except `last_used_at` and `row_mac`.
   - `leases`: all columns except `row_mac`.
   - `access_requests`: all columns except `reason_ct` (AEAD-bound already) and `row_mac`.
4. Every write of these tables happens while unlocked and sets `row_mac`. (`last_used_at` is not in the MAC, so it can
   change on any call.)
5. Checks:
   - At unlock, `AuthTable` is rebuilt from the DB and every `agents` and `agent_keys` row MAC is verified. A row with a
     bad MAC is disabled (treated as revoked), the UI shows a red integrity alert, and `integrity.row_mac_mismatch` is
     audited. While sealed, the unverified table is used only to choose between `401` and `423`; no data flows.
   - Every read of a `leases` or `access_requests` row for a decision verifies the MAC first. A bad MAC means "no lease"
     or "request not approved", plus the same alert and audit event.
6. Plain `expires_at` copies: `items` and `grants` also store `expires_at` inside their encrypted blob. The effective
   expiry is the **earlier** of the two values. Changing the plain value can only make an item expire sooner (the sweeper
   uses the plain value while locked), which is a denial of service, not a gain.
7. The CA certificate (`tls_ca.ca_cert_der`, plain) is checked at unlock: its public key must match the sealed CA key.
   A mismatch stops leaf renewal and raises the integrity alert.

## Consequences

- Forging new states (new key, more scopes, later expiry, approval) needs `row_mac_key`, so it needs the VMK.
- A MAC does not stop **rollback** of a row to an older genuine state (for example an older `agent_keys` row from
  before a revoke), or deletion of rows. This belongs to the same class as a full-file rollback (accepted risk AR-1).
  Deleting rows can only remove access or remove a revoke-block of an auto lease (ADR-0019 item 7).

## Alternatives considered

- **Encrypt these columns too.** Rejected. Token checks and the sweeper must work while locked (D8, D5).
- **Trusted monotonic counter (TPM, OS keystore) against rollback.** Deferred. Not portable across the three desktop OSs
  and headless servers in version 1.
