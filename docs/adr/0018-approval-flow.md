# ADR-0018: Approval flow (access requests)

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 3 (AccessRequest), 5.1 (`/requests`), 7 screen 8, A6
- Related: ADR-0002, ADR-0017, ADR-0019, ADR-0026, ADR-0029

## Context

Modes `ask_once` and `ask_always` (and every `prod` read) need a person to decide. Agents must learn the result
without holding a connection forever. Agents can spam requests to tire the person.

## Decision

### Creation
An access request is created when:
- `reveal`, `totp`, `ssh-prepare` or `resolve` (mode `best`, confident match) needs approval and no valid lease exists; or
- the agent calls `POST /v1/requests` (`request_access` in MCP) to ask before it needs the secret.

The response is `202 Accepted` with the request object and a `Location: /v1/requests/{id}` header.

### Request object
`id`, `agent_id`, `item_id`, `permission` (`read` or `use_ssh`), `reason` (encrypted, untrusted, max 500 chars),
`requested_ttl_seconds`, `status`, `created_at`, `expires_at`, `decided_at`, `decided_by`, `lease_id`, `deny_code`.

### States
```
pending ──approve──► approved   (lease created)
   │──────deny─────► denied
   │──timeout──────► expired    (default 120 s, setting 30..600 s)
   └──lock/panic───► cancelled
```
Terminal states do not change.

### Rules
1. **Dedupe**: if a `pending` request exists for the same (agent, item, permission), the service returns it.
2. **Cap**: at most 5 pending requests per agent. More gives `429 rate_limited`.
3. **Deny cool-down**: after a deny, new requests for the same (agent, item) give `403 approval_denied` for 600 s
   (setting) without a new prompt.
4. **Headless**: on `cerberusd`, no request is created. The call gives `403 approval_unavailable` (ADR-0002).
5. **Lock**: pending requests become `cancelled`. Lock means no person is there to decide.

### Decision UI
- Window label `approval`: small, always on top, plus a tray badge. Only `request_approve` and `request_deny` IPC
  commands are allowed from this window, plus read of the pending list.
- It shows: agent name and ID (from the token, never from the request text), item title, workspace, environment
  (red `prod` badge), permission, requested TTL, and the reason as **untrusted text** (plain text, control characters
  removed, labelled "Reason given by the agent — not verified").
- Options:
  | Option | Lease |
  |---|---|
  | Approve once | `max_uses = 1`, TTL 300 s |
  | Approve for 15 minutes | TTL 900 s |
  | Approve for the session | TTL until the next lock, at most `min(8 h, session_ttl_max_seconds)` |
  | Deny | no lease; starts the cool-down |
- The UI preselects nothing. The person must click. Keyboard shortcut needs a hold of 600 ms to stop accidental approval.
- If one agent creates more than 3 requests in 60 s, the window groups them and shows a warning.
- A `viewer` cannot approve (ADR-0009).

### Agent side
- Poll `GET /v1/requests/{id}`, or stream `GET /v1/requests/{id}/events` (SSE, ADR-0021 for codes).
- SSE events: `event: status` with the request object as JSON. A comment line `: keep-alive` every 15 s.
  The server closes the stream after a terminal state, or at `expires_at`.
- After `approved`, the agent calls the original route again (for example `reveal`). The service finds the lease.
  The agent can pass `lease_id` to choose a lease.
- MCP `request_access` and `get_credential` wait up to `wait_seconds` (default 60, max 120) and send MCP progress
  notifications every 10 s when the client gave a progress token. Then they return `pending`.

## Consequences

- A6 passes: `prod` read creates a request; deny gives 403 `approval_denied`; approve gives a lease.
- No secret travels through the request objects. Secrets come only from secret routes.

## Alternatives considered

- **Return the secret in the request poll.** Rejected. It adds a second secret path to audit and protect.
- **Long-poll on reveal.** Rejected. It holds HTTP connections and fails behind short client timeouts.
