# ADR-0007: Session TTL default 60 minutes, maximum 24 hours

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D7
- Related: ADR-0019, ADR-0022, ADR-0027

## Context

Agents store short-lived session tokens and browser sessions. "60 active" in the brief means 60 minutes.
Session items must expire and disappear without a person.

## Decision

1. Settings (owner only, stored encrypted in `settings`):
   - `session_ttl_default_seconds`: default 3600. Range 60 to `session_ttl_max_seconds`.
   - `session_ttl_max_seconds`: default 86400 (24 h). Range 300 to 604800 (7 days).
2. Kinds `session_token` and `browser_session` always have `expires_at`.
   - `POST /v1/sessions` without `ttl_seconds` uses the default.
   - A `ttl_seconds` above the max gives `422 validation_failed` with field `ttl_seconds`. The service does not clamp in silence.
3. Other kinds created by an agent may have `ttl_seconds` (any value from 60 to 31,536,000) or no expiry.
4. `expires_at = clock.now() + ttl_seconds`, stored as Unix milliseconds (ADR-0022).
5. An item is expired when `now >= expires_at`. Expired items are invisible at once in every read path,
   before the sweeper deletes them (ADR-0027).

## Consequences

- Acceptance test A3 uses the manual clock: store with 3600 s, move the clock 3600 s, the item is not found,
  and the next sweeper run deletes the row.
- An agent that needs a longer session must refresh it (store a new item).

## Alternatives considered

- **Clamp silently to the max.** Rejected. Agents must know the real expiry.
- **Sliding TTL (extend on use).** Rejected. It lets a stolen session live forever.
