# ADR-0021: One error shape and a fixed list of error codes

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 1.1, 5.1 ("Error JSON")
- Related: ADR-0008, ADR-0015, ADR-0016, ADR-0029, `docs/api/openapi-draft.yaml` (`ErrorResponse`)

## Context

Agents must react to errors by code, not by message text. Hermes has `{error:{code,message}}` without
`request_id` and `retryable` (T00).

## Decision

### Shape
```json
{ "error": { "code": "vault_locked", "message": "The vault is locked.", "request_id": "…uuid…",
             "retryable": true, "details": { } } }
```
- `code`: a value from the table below. Stable. New codes need a new ADR.
- `message`: short English text for people. It never contains a secret, a token, a reason text or an item title
  that the caller cannot see.
- `request_id`: ADR-0015.
- `retryable`: true when the same call can succeed later without a change by the agent.
- `details`: optional. Only these keys are allowed: `retry_after_seconds` (429, 503), `fields` (422: list of
  `{field, problem}`), `hints` (404 `no_match`), `request` (403 `approval_denied`: the access request ID).
- Internal errors log the cause with the request ID and return the fixed message "Internal error.".

### Codes
| HTTP | code | retryable | When |
|---|---|---|---|
| 400 | `invalid_request` | false | Malformed JSON, unknown field, bad path ID |
| 400 | `reason_required` | false | Grant needs a reason; `purpose`/`reason` missing or shorter than 8 chars |
| 401 | `unauthenticated` | false | Token missing, malformed, unknown, expired, revoked; agent not active; IP or mTLS check failed |
| 403 | `forbidden` | false | Item visible but the permission is not granted, or a `deny` grant, or delete of an item the agent did not create |
| 403 | `insufficient_scope` | false | Token lacks the route scope |
| 403 | `approval_denied` | false | A person denied the request, or the deny cool-down is active |
| 403 | `approval_unavailable` | false | Approval needed on a headless daemon |
| 403 | `condition_failed` | true | Outside the grant time window |
| 403 | `origin_refused` | false | Request has an `Origin` header or a not-allowed `Host` |
| 404 | `not_found` | false | Unknown or invisible item, request or lease, or an expired item |
| 404 | `no_match` | false | Resolve found nothing |
| 404 | `route_not_found` | false | Unknown path |
| 405 | `method_not_allowed` | false | Wrong method |
| 409 | `conflict` | false | Lease already released or revoked; duplicate title in the same workspace on create |
| 413 | `payload_too_large` | false | Body over the route limit |
| 415 | `unsupported_media_type` | false | Body is not `application/json` |
| 422 | `validation_failed` | false | Field rules failed (details.fields) |
| 423 | `vault_locked` | true | Vault not unlocked |
| 429 | `rate_limited` | true | Agent, IP or pending-request limit |
| 429 | `grant_rate_limited` | true | Grant `max_reads_per_hour` reached |
| 429 | `too_many_failures` | true | IP lockout after repeated auth failures |
| 500 | `internal` | false | Bug or I/O failure |
| 500 | `vault_corrupt` | false | AEAD open failed or header values out of range |
| 503 | `unavailable` | true | Server is shutting down or starting |

`Retry-After` header (seconds) is set for every 429 and 503, and equals `details.retry_after_seconds`.
423 has no `Retry-After` (unlock time is unknown).

### Success codes
`200` read or action done, `201` item created, `202` access request pending, `204` delete done.

### MCP
Tool errors use `isError: true`. `structuredContent` holds the same object (`{"error": {...}}`) and the text content
holds the same JSON. JSON-RPC protocol errors (bad method) use JSON-RPC codes; `data` then holds the same object.

### Rust
`cerberus-types::ErrorCode` is the enum of codes with `http_status()` and `retryable()`. `cerberus-core::CoreError`
maps to `ErrorCode` in one function. `cerberus-api::ApiError` has the one `IntoResponse` implementation.

## Consequences

- Clients can switch on `code`. The SDK has a typed enum.
- An agent cannot tell "invisible" from "does not exist" (both `404 not_found`).

## Alternatives considered

- **RFC 9457 problem details.** Rejected. The plan fixes the shape, and agents parse one shape more easily.
