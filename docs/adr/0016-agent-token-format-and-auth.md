# ADR-0016: Agent token format, storage, scopes and checks

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.4
- Related: ADR-0004, ADR-0008, ADR-0015, ADR-0017, ADR-0030

## Context

Agents authenticate with a bearer token. Checks must work while the vault is locked (ADR-0008). A revoked key must
fail at once (A10).

## Decision

### Format
`cvt_<agent_id>.<secret>`
- `agent_id`: the agent UUID, lower-case hyphenated.
- `secret`: 32 bytes from the OS RNG, Base64url without padding (43 characters).
- Example shape (not a real token): `cvt_01890000-0000-7000-8000-000000000000.AAAA…` (43 characters after the dot).
- The prefix `cvt_` lets secret scanners find leaked tokens.

### Storage (table `agent_keys`, plain columns)
- `secret_hash` = SHA-256( `cerberus/v1/agent-token` || agent_id (16 bytes) || secret (32 bytes) ).
  A fast hash is correct here: the secret has 256 random bits (T00 note 5).
- `hint`: last 4 characters of the secret, for display.
- `scopes`, `expires_at`, `revoked_at`, `ip_allowlist`, `require_mtls`, `client_cert_sha256`, `created_at`,
  `last_used_at`. These are plain so checks work while locked.
- The token is shown one time in the UI (screen 6). It is never stored and never logged.

### Check order
1. Parse `Authorization: Bearer <token>` (scheme case-insensitive). Malformed: `401 unauthenticated`.
2. Load the agent's non-revoked keys from the in-memory `AuthTable` (loaded at start from plain columns, changed
   in the same transaction as the DB). Maximum 5 keys per agent.
3. Compute the hash. Compare with **every** key hash of that agent with `subtle::ConstantTimeEq`, no early exit.
4. Fail if: no match, key expired, key revoked, agent `status != active`, source IP not in `ip_allowlist`,
   `require_mtls` and the client certificate fingerprint does not match.
   All of these give the same `401 unauthenticated` to the caller. The audit event stores the exact reason.
5. If the vault is not unlocked: `423 vault_locked` (ADR-0008).
6. Scope check for the route: `403 insufficient_scope`.

There is no result cache. Revocation changes the `AuthTable` before the IPC command returns, so A10 holds.
At unlock, the `AuthTable` is rebuilt and each row MAC is checked (ADR-0033). A row with a bad MAC is treated as revoked.

### Scopes (on each key)
| Scope | Routes / MCP tools |
|---|---|
| `status:read` | `GET /v1/status`, `vault_status` |
| `catalog:read` | `GET /v1/credentials`, `POST /v1/credentials/resolve` (candidates), `find_credentials`, `cerberus://catalog` |
| `secrets:read` | `POST /v1/credentials/resolve` (best), `POST /v1/credentials/{id}/reveal`, `POST /v1/credentials/{id}/totp`, `get_credential`, `get_totp` |
| `secrets:write` | `POST /v1/credentials`, `DELETE /v1/credentials/{id}` (other kinds), `store_secret` (kinds other than sessions) |
| `sessions:write` | `POST /v1/sessions`, `DELETE /v1/credentials/{id}` (kinds `session_token`, `browser_session`), `store_secret` (session kinds) |
| `requests` | `POST /v1/requests`, `GET /v1/requests/{id}`, `GET /v1/requests/{id}/events`, `POST /v1/leases/{id}/release`, `request_access`, `release_credential` |
| `ssh:use` | `POST /v1/credentials/{id}/ssh-prepare`, `ssh_prepare` |

Default scopes for a new key: `status:read`, `catalog:read`, `secrets:read`, `requests`.
Scopes limit the token. Grants (ADR-0017) limit the items. A call needs both.

### Expiry and rotation
- Default key lifetime 90 days. Range 1 day to 365 days, or "no expiry" (owner only).
- Rotate: create a new key; the old key gets `expires_at = now + overlap`. Default overlap 24 h, range 0 to 7 days.
- Revoke: sets `revoked_at` at once.

### Optional mTLS
- The owner can issue a client certificate from the Cerberus CA for an agent (IPC `agent_issue_client_cert`).
- `require_mtls = 1` binds the key to that certificate's SHA-256 fingerprint. Required when the server binds to a
  non-loopback address (ADR-0023).

## Consequences

- A stolen DB file gives token hashes only. They cannot be reversed.
- The agent ID in the token is not secret. It only selects the keys to compare.

## Alternatives considered

- **Key ID instead of agent ID in the token.** Rejected. The plan fixes the format. Comparing at most 5 keys is cheap.
- **JWT.** Rejected. Revocation needs state anyway, and JWT adds algorithm-confusion risk.
- **403 for IP allowlist failures.** Rejected. A 403 confirms the token is valid.
