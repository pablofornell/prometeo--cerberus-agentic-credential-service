# ADR-0019: Lease semantics

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 3 (Lease), 5.1 (`reveal`, `/leases/{id}/release`), 4.2 (panic button)
- Related: ADR-0017, ADR-0018, ADR-0022, ADR-0026, ADR-0027

## Context

The plan says "reveal creates a lease" and "approval creates a lease". A lease cannot take back a secret that the
agent already has. The meaning of a lease must be exact.

## Decision

1. A **lease** is a time-limited right of one agent to use one item with one permission (`read` or `use_ssh`).
   It is also the record that the item was exposed to that agent.
2. Fields: `id`, `agent_id`, `item_id`, `permission`, `source` (`auto` | `approval`), `request_id?`, `created_at`,
   `expires_at`, `max_uses?`, `uses`, `released_at?`, `revoked_at?`, `revoked_by?`.
   These are plain columns (IDs and numbers only).
3. A lease is **active** when `now < expires_at`, it is not released or revoked, and `max_uses` is null or `uses < max_uses`.
4. `expires_at` is never later than the item `expires_at`.
5. How leases are made:
   - **auto** mode: the first allowed reveal creates a lease with TTL `lease_ttl_auto_seconds` (default 900).
     Later reveals in the TTL reuse it and add to `uses`.
   - **ask_once**: an approval creates a lease with the TTL of the chosen option. Reveals in the TTL need no new approval.
   - **ask_always** (and `prod` without `allow_prod_auto`): an approval creates a lease with `max_uses = 1`.
     The next reveal uses it. Each later reveal needs a new approval.
6. **Release** (`POST /v1/leases/{id}/release`, agent): sets `released_at`. The agent promises to forget the value.
   The lease cannot be used again. Release of a lease of another agent gives `404 not_found`.
7. **Revoke** (IPC, operator): sets `revoked_at`. For `auto` mode, a revoked lease also blocks new auto leases for that
   (agent, item) until the original `expires_at`. Otherwise revoke would be useless in `auto` mode.
8. **Revoke all / panic button**: revokes every active lease, cancels every pending request, then locks the vault.
9. Lock does **not** revoke leases. Time keeps running. A lease is usable again after unlock if still active.
10. Revoking a lease does not undo exposure. The UI marks the item "exposed to agent X at time T" and suggests rotation.
11. The sweeper deletes leases one hour after they stop being active. The audit log keeps their history.
12. Every create, use, release, revoke and expiry writes an audit event.

## Amendment (2026-11-17, DEC-FIX7-1, DEC-FIX7-4)

- Point 5 is checked at each use with the **effective** mode: `ask_always` (and the `prod` default) is served only by a
  one-use approval lease made for a request. A session or 15-minute approval given under `ask_once` does not serve a grant
  later tightened to `ask_always`.
- Moving an item to another environment or workspace revokes its active approval leases.
- Point 11: a revoked auto lease is deleted one hour after its original `expires_at`, so the point 7 block is kept.

## Consequences

- The Leases screen (screen 9) shows real exposure, also for `auto` grants.
- `reveal` responses include `lease: { id, expires_at, uses_left }`.

## Alternatives considered

- **No lease for auto mode.** Rejected. Then the panic button and the leases screen would miss most exposures.
