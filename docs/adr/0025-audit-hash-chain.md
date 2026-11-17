# ADR-0025: Audit log with hash chain and HMAC

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.5, A9, T08
- Related: ADR-0005, ADR-0008, ADR-0014, ADR-0015, ADR-0032

## Context

Every call needs an audit event. The log must be append-only and show where a change was made. It must never hold a
secret. Hermes audits only changes (T00, section 7); Cerberus audits reads too.

## Decision

### Row (table `audit_events`)
Plain: `seq` (INTEGER, 1, 2, 3, …), `occurred_at` (Unix ms), `prev_hash` (32 bytes), `hmac` (32 bytes).
Encrypted: `body_ct` (purpose `audit.body`, record ID = `seq` as u64 BE).

Body (JSON before sealing):
```
{ "type": "item.reveal", "actor": {"kind": "agent|operator|system", "id": "…"},
  "target": {"kind": "item|agent|agent_key|grant|lease|request|operator|vault|settings", "id": "…"},
  "result": "ok" | "<error code>", "request_id": "…", "details": { … no secret values … } }
```

### Chain
```
entry_hash(n) = SHA-256( lp("cerberus/v1/audit") || lp(seq_n u64 BE) || lp(occurred_at_n i64 BE)
                         || lp(prev_hash_n) || lp(body_ct_n) )          lp = u16 BE length prefix
prev_hash(n)  = entry_hash(n-1);  prev_hash(first) = SHA-256("cerberus/v1/audit-genesis" || vault_id)
hmac(n)       = HMAC-SHA256(audit_key, entry_hash(n))
```
Table `audit_head` (one row): `last_seq`, `last_entry_hash`, `anchor_seq`, `anchor_prev_hash`, `head_hmac`
(HMAC over the four values). It is updated in the same transaction as each insert.

### Verify
Walk from `anchor_seq` to the end. Report the first problem:
`hmac_mismatch(seq)`, `prev_hash_mismatch(seq)`, `missing_row(seq)` (gap in `seq`), `head_mismatch` (tail cut or head
changed). Result `ChainOk { count, first_seq, last_seq }` or `ChainBroken { seq, kind }`. A9 passes when one changed
byte in any row gives the exact `seq`.

### While locked
No `audit_key` exists. The service writes to `audit_pending` (plain: `occurred_at`, `agent_id`, `event_type`,
`result_code`, `request_id`, `route`). At most 10,000 rows; after that it increments `audit_pending_overflow.count`.
At unlock it adds them to the chain in order with `details.recorded_while_locked = true`, then deletes them.
These rows are not authenticated while they wait (accepted risk AR-6 in the threat model).

### Event catalog (T08 keeps the full list in code; minimum set)
`vault.create`, `vault.unlock`, `vault.unlock_failed`, `vault.unlock_recovery`, `vault.lock` (details.reason),
`vault.panic`, `vault.header_mismatch`, `operator.add|remove|role_change|phrase_change`, `recovery.rotate`,
`workspace.create|update|delete`, `item.create|update|delete|reveal|totp|expire|version_restore`,
`agent.create|update|suspend|resume|revoke`, `agent_key.create|rotate|revoke`, `grant.create|update|delete`,
`request.create|approve|deny|expire|cancel`, `lease.create|use|release|revoke|expire`, `auth.failed`,
`auth.lockout`, `api.locked_call`, `api.resolve`, `api.catalog`, `settings.change`, `network.bind_change`,
`tls.renew|custom_load`, `backup.create|restore`, `audit.export|prune|verify`, `ssh.prepare`.

### Rules
- `AuditEvent` has no field type that can hold a `cerberus_crypto::Secret*` value (those types do not implement
  `Serialize`). A test scans the DB and export for fake secret values after all A-scenarios.
- Reason and purpose text are stored inside the encrypted body, cut to 500 chars.
- Retention: default 365 days (setting). Prune runs at unlock once per day: delete rows older than the limit, set
  `anchor_seq`/`anchor_prev_hash` to the first kept row, write `audit.prune`.
- Export: JSON Lines with `seq`, `occurred_at`, `prev_hash`, `hmac` (hex) and the opened body. The export holds metadata
  (titles), so the UI warns before export.
- A write error in the audit writer fails the caller's action for secret reads (no reveal without audit). For
  other actions it is logged and the action still succeeds (Hermes pattern), because the change is already done.

## Consequences

- The chain proves order and integrity against a person without `audit_key`. It does not stop a full rollback of the
  file to an older copy (accepted risk AR-1).

## Alternatives considered

- **Plain audit rows.** Rejected. Titles and agent names would leak (D5).
- **Signature (Ed25519) instead of HMAC.** Rejected. Only the vault itself verifies; HMAC is enough and simpler.
