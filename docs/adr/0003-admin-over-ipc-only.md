# ADR-0003: Admin actions use Tauri IPC only

- Status: Accepted. Amended by ADR-0034: points 1 and 2 hold for the desktop's own vault and for every daemon with the admin API off; a `cerberusd` with the admin API on serves allowlisted admin commands under `/admin/v1` behind an enrolled client certificate and an operator session.
- Date: 2026-11-16
- Plan reference: D3
- Related: ADR-0001, ADR-0004, ADR-0009, ADR-0023, `docs/interfaces.md` (IPC command list)

## Context

Admin actions (create item, grant, approve, manage agents, change settings) are the most dangerous actions.
If they are on the network, a stolen agent token or a local process could try them.

## Decision

1. Admin actions exist only as Tauri IPC commands. The HTTPS server has no admin route.
2. The router of `cerberus-api` is built from the Agent API route list only. A test lists all routes and
   fails if a route is not in the allowed list (`docs/api/openapi-draft.yaml`).
3. Each IPC command:
   - checks the calling window label against an allow list (`main` for most commands, `approval` for
     approve/deny only);
   - checks the role of the current operator (owner, operator, viewer; ADR-0009);
   - returns a typed result through `tauri-specta`;
   - writes an audit event with actor `operator:<id>`.
4. Tauri capabilities give each window only the commands in its allow list. No `shell` plugin.
   No remote URL can load in any window (ADR-0023 covers CSP).
5. The full command list is in `docs/interfaces.md`, section "Tauri IPC commands".

## Consequences

- An attacker on the network or with an agent token cannot change policy, approve a request or add an agent.
- The headless daemon has no admin path (ADR-0002).
- Automation of admin tasks (for example "create 50 agents from a script") is not possible in version 1.

## Alternatives considered

- **Admin REST routes with a separate admin token.** Rejected. Hermes uses this pattern (`/api/*` with an admin token),
  but it puts the highest privilege on the network.
- **Admin REST bound to a Unix socket.** Deferred (ADR-0002).
