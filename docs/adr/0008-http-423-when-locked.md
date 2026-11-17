# ADR-0008: The API returns HTTP 423 when the vault is locked

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D8
- Related: ADR-0016, ADR-0021, ADR-0025, ADR-0026, ADR-0029

## Context

Agents call the API while the person is away and the vault is locked. They need a clear and safe answer.

## Decision

1. While the vault state is not `Unlocked`, every REST route except `GET /v1/health` returns
   `423 vault_locked` with `retryable: true` and no data.
2. Order of checks for a REST call: rate limit by IP, then token check, then lock check.
   - Invalid, expired or revoked token: `401 unauthenticated`, also while locked. Token checks use only plain columns
     of `agent_keys` (ADR-0016), so they work without vault keys.
   - Valid token while locked: `423 vault_locked`.
3. `GET /v1/health` returns `200` with `{"status":"ok","vault":"locked"}` or `"unlocked"`. It has no auth and shows
   no other data.
4. MCP (`/mcp`) keeps the transport up while locked. `initialize`, `tools/list` and `resources/list` work.
   Each tool call returns a tool error with code `vault_locked` (same error shape). `vault_status` returns
   `{"vault":"locked"}` (no agent data). `resources/read` returns JSON-RPC error with the same code in `data`.
5. While locked, the service cannot HMAC audit events (no `audit_key`). It writes a minimal row to
   `audit_pending` (time, agent ID, route, result code, request ID). At the next unlock it moves these rows into the
   chain (ADR-0025).

## Consequences

- A5 passes: any REST call while locked gives 423 and no body data except the error object.
- Agents can poll `/v1/health` to learn when the vault opens.
- The MCP rule differs from REST at the HTTP layer, because MCP clients drop the session on HTTP errors.
  The result for the agent is the same: no data and the code `vault_locked`.

## Alternatives considered

- **401 or 503 while locked.** Rejected. 401 makes agents think the token is bad. 503 suggests a crash.
- **Queue the call until unlock.** Rejected. It holds connections and hides state.
