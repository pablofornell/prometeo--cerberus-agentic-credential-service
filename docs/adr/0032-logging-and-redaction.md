# ADR-0032: Logging and redaction

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.2 ("Logs never contain secrets. A test checks this."), 2 (`tracing` with redaction)
- Related: ADR-0025, ADR-0028, ADR-0029

## Context

Logs are often copied into tickets and chats. They must not hold secrets, tokens or metadata that D5 protects.

## Decision

1. `tracing` + `tracing-subscriber` (JSON format) to a file in the OS log dir, mode `0600`, daily rotation, 7 files.
   `cerberusd` also logs to stderr (journald).
2. Secret types in `cerberus-crypto` (`SecretBytes`, `SecretString`, `Key32`, payload types) implement `Debug` as
   `[REDACTED]`, do **not** implement `Display` or `Serialize`, and zeroize on drop. Exposure needs `.expose_secret()`.
3. HTTP trace layer records only: method, matched route template (for example `/v1/credentials/{id}/reveal`),
   status, latency, request ID, agent ID. Never headers, query strings or bodies.
4. Never logged: tokens, token hashes, phrases, recovery keys, payloads, titles, descriptions, reason and purpose text,
   TOTP codes. Item and agent IDs are allowed.
5. Log levels: default `info`. `rmcp` capped at `warn`. `sqlx` statements at `warn` (no bind values).
6. **Canary test** (T24): run all A-scenarios with unique fake values (for example `canary-pw-<random>`), then search
   the log files, the DB file, the audit export and stdout/stderr of the CLI for each canary. Any hit fails the build.
   The DB check excludes values that the scenario expects in the DB in encrypted form (they must not appear as plain bytes).
7. A refused token logs one warning per source IP per minute, without the token (Hermes pattern).

## Consequences

- Debugging uses request IDs and audit events, not body dumps.

## Alternatives considered

- **A redaction filter on log output (regex).** Rejected as the main control. Types that cannot print are stronger.
  A regex filter for `cvt_` tokens is added as a second layer.
