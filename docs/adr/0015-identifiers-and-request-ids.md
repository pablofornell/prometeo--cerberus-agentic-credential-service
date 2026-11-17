# ADR-0015: Identifier format and request IDs

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 1.1 ("every call has a request ID"); gap: ID format
- Related: ADR-0016, ADR-0021, ADR-0025

## Context

Hermes has no request IDs (T00). The plan requires one per call. All tables need an ID format.

## Decision

1. All entity IDs (vault excluded) are **UUIDv7** (`uuid` crate, feature `v7`). Text form: lower-case hyphenated,
   36 characters. SQLite column type `TEXT`. The vault ID is UUIDv4 bytes (ADR-0013).
2. UUIDv7 contains the creation time. This is fine: `created_at` is plain anyway.
3. Rust has one newtype per ID (`ItemId`, `AgentId`, `AgentKeyId`, `WorkspaceId`, `GrantId`, `LeaseId`,
   `AccessRequestId`, `OperatorId`, `KeySlotId`, `RequestId`). A function cannot take the wrong kind of ID.
4. **Request ID**:
   - The server makes a new UUIDv7 for every HTTP request and every MCP tool call.
   - It ignores any incoming `X-Request-Id` (no log injection, no ID collision tricks).
   - It returns the ID in the `X-Request-Id` response header, in every error body (`request_id`), and in every
     success body that carries a secret.
   - The audit event of the call stores the same ID.
5. Audit events use an integer sequence (`seq`) as their primary key, because the chain needs a total order.

## Consequences

- IDs sort by creation time. Index pages stay compact.
- A support case can find the audit event from the `request_id` an agent prints.

## Alternatives considered

- **ULID.** Rejected. Same properties, but UUID has wider tool support (SQLite tools, `uuid` crate, OpenAPI `format: uuid`).
- **Use the client request ID.** Rejected (see 4).
