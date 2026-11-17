# ADR-0004: Agents use only the Agent API (HTTPS REST and MCP)

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D4
- Related: ADR-0003, ADR-0016, ADR-0017, ADR-0029, `docs/api/openapi-draft.yaml`, `docs/api/mcp-tools.md`

## Context

Agents can be prompt-injected. An agent must get credentials, but it must not manage the vault.

## Decision

1. Agents have two surfaces: REST under `/v1` and MCP at `/mcp`. Both are on the same HTTPS listener.
2. Both surfaces call the same `cerberus-core` functions (`AgentApi` trait). The MCP layer adds no new power.
3. The Agent API can: check status, find and list visible items (metadata), reveal a secret, get a TOTP code,
   create items (with `write`), store session tokens (with `create_session`), delete items the agent created,
   ask for access, poll and stream approval state, release a lease, and prepare an SSH signing socket (T22).
4. The Agent API cannot: change grants, approve requests, create or change agents or keys, change settings,
   read the audit log, lock or unlock the vault.
5. An agent may delete or replace only items it created (`created_by = agent:<own id>`).
6. Every Agent API call needs a bearer token (ADR-0016), except `GET /v1/health`.

## Consequences

- A prompt-injected agent can at most use its own grants. Grants, approvals, rate limits and audit limit the damage.
- REST and MCP stay equal. A tool exists in MCP only if a REST route with the same core function exists
  (`docs/api/mcp-tools.md` maps each tool to its route).

## Alternatives considered

- **Let agents ask for new grants through the API.** Rejected. `request_access` creates an access request
  that a person decides. It never creates a grant.
