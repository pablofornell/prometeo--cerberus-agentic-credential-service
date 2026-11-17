# ADR-0002: Headless daemon `cerberusd` uses the same library

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D2
- Related: ADR-0001, ADR-0003, ADR-0018, ADR-0024, ADR-0031

## Context

Some agents run on servers without a screen. They need the same Agent API.
The vault logic must not be written two times.

## Decision

1. `cerberusd` is a binary crate. It links `cerberus-core`, `cerberus-api` and `cerberus-mcp`.
   It uses the same `VaultService`, the same router and the same TLS code as the desktop app.
2. `cerberusd` is **serve-only** in version 1:
   - It unlocks from a TTY prompt (`cerberusd unlock` reads the phrase with echo off), or it starts locked.
   - It serves the Agent API (REST and MCP).
   - It has **no admin interface**. It does not open an admin socket and has no admin REST route.
3. The person prepares the vault (items, agents, grants) in the desktop app.
   The person copies the backup file to the server and uses `cerberusd restore <file>` from a TTY (ADR-0031).
4. Approval modes on `cerberusd`: there is no person to approve. A grant with mode `ask_once` or
   `ask_always` gives `403 approval_unavailable`. Only `auto` grants work. The daemon logs this at startup
   for each such grant.
5. Config: TOML file `cerberusd.toml` plus env vars with the `CERBERUSD_` prefix. Env wins over the file.
   Startup fails on unknown keys and on invalid values. The error names the key.
6. Systemd: unit file with `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
   `MemoryDenyWriteExecute=yes`, `LimitCORE=0`, `Type=notify` (`sd-notify`). SIGTERM locks the vault and stops
   the server in a graceful way (drain 10 s).
7. Idle auto-lock is off by default on `cerberusd` (an agent server must stay up). The owner can set it in the config.

## Consequences

- One code path for vault logic and API. Tests run once for both binaries.
- No network admin path exists anywhere. D3 stays true on servers.
- Items that agents create on the server (for example session tokens) exist only in the server copy.
  A later restore from the desktop replaces them. This is documented in the daemon guide (T13, T28).
- Approvals do not work on headless servers. The owner must use `auto` grants with tight selectors and conditions there.

## Alternatives considered

- **Admin over a Unix socket with peer-credential check.** Rejected for version 1. It adds a second admin
  surface and a second authentication path. It can come later as a new ADR.
- **Remote approval through the desktop app.** Rejected. It needs a network admin channel (against D3).
