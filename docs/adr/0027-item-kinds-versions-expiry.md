# ADR-0027: Item kinds, payloads, versions, expiry and the sweeper

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 3, 4.5, T04, T06, A3
- Related: ADR-0005, ADR-0007, ADR-0014, ADR-0019, ADR-0022

## Context

The plan lists ten kinds. Each needs a typed payload, limits and a rule for what an agent may receive.

## Decision

### Payloads (JSON inside `payload_ct`; Rust enum `Payload`)
| Kind | Fields (`?` = optional) | Never sent to agents |
|---|---|---|
| `web_login` | `username`, `password`, `url?`, `totp?` {`secret` Base32, `algorithm` SHA1/SHA256/SHA512, `digits` 6/8, `period` 15..120} | `totp.secret` |
| `api_key` | `key`, `key_id?`, `header_name?`, `base_url?` | — |
| `ssh_key` | `private_key` (OpenSSH), `passphrase?`, `public_key`, `fingerprint` (SHA256) | — (with T22 the agent should use `ssh-prepare`) |
| `session_token` | `token`, `token_type?`, `header_name?` | — |
| `browser_session` | `storage_state` (Playwright JSON object), `origin` | — |
| `database` | `url?` or (`engine`, `host`, `port`, `database`, `username`, `password`, `params?`) | — |
| `cloud` | `provider`, `access_key_id?`, `secret_access_key?`, `session_token?`, `region?`, `extra?` (map) | — |
| `certificate` | `cert_pem`, `key_pem?`, `chain_pem?` | — |
| `env_bundle` | `vars` (map name → value; names `[A-Z_][A-Z0-9_]*`) | — |
| `note` | `text` | — |

SSH metadata (machine name, host, port, user, fingerprint) is in the encrypted metadata (`target`, `custom`), so
search and resolve can use it.

### Metadata (JSON inside `items.meta_ct`)
`workspace_id`, `title` (1..200), `description` (0..2000), `role_label?` (0..64), `category`, `tags` (max 20,
each 1..50), `environment` (`dev`|`staging`|`prod`|`other`), `target?` (0..512), `created_by`
(`operator:<id>`|`agent:<id>`), `max_uses?`, `use_count`, `custom` (map, max 20 entries).
Title is unique per workspace (normalized). Duplicate gives `409 conflict`.

### Limits
Payload max 1 MiB for `browser_session`, 64 KiB for other kinds.

### Versions
- Every change of payload or metadata creates a new `item_versions` row with a new DEK and a metadata snapshot.
- Keep the last 10 versions (setting 1..100). Kinds `session_token` and `browser_session` keep 1.
- "Restore version N" creates a new version with the content of N.

### Expiry and uses
- `expires_at` plain (ADR-0005). Expired = `now >= expires_at`; invisible at once in every read.
- `max_uses`: each successful reveal adds 1 to `use_count`. When `use_count == max_uses` after a reveal, the item is
  deleted in the same transaction, after the response body is built.
- Delete is a hard delete of the item, its versions and its leases (with `secure_delete=ON`).

### Sweeper (`cerberus-store::Sweeper`, every 60 s, works while locked)
1. Delete items with `expires_at <= now` and their versions (cascade). Count them.
2. Delete leases inactive for more than 1 h, and access requests in a terminal state for more than 7 days.
3. Write the counts to `audit_pending` as `item.expire` events when locked, or to the chain when unlocked.
4. `PRAGMA wal_checkpoint(TRUNCATE)` after any delete; `PRAGMA incremental_vacuum` after more than 100 deleted rows.
5. Full `VACUUM` once per 24 h when at least one row was deleted that day.

### TOTP
`totp-rs`. `POST /v1/credentials/{id}/totp` returns `code`, `period`, `expires_in_seconds`. The seed never leaves the vault.

### Categories
Built-in: Web login, API key, SSH, Session, Database, Cloud, Certificate, Other. Custom categories are a setting list.

## Consequences

- An agent cannot clone a TOTP generator. It must call the TOTP route each time, which is audited.

## Alternatives considered

- **Soft delete with a trash bin.** Rejected for version 1. Deleted secrets should not linger.
