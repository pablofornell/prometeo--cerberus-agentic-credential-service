# ADR-0024: Workspace crate layout and dependency rules

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 6 (repository layout)
- Related: ADR-0001, ADR-0002, ADR-0011, ADR-0012, ADR-0022, `docs/interfaces.md`

## Context

The plan lists the crates but not the allowed dependencies between them. The client SDK must stay small and must not
contain vault code. Wire types are needed by both the server and the client.

## Decision

### Crates
| Crate | Kind | Holds |
|---|---|---|
| `cerberus-types` | lib | **New.** IDs, enums (kinds, environments, permissions, modes, roles, scopes), `ErrorCode`, `Clock`, wire DTOs with `serde` + `utoipa` derives. No crypto, no I/O. |
| `cerberus-crypto` | lib | Secret types, KDF, key slots, HKDF tree, AEAD envelope, recovery key, Diceware, zxcvbn check, `memlock`. |
| `cerberus-store` | lib | SQLite pool, migrations, repositories, sweeper, backup. Stores and returns sealed blobs; does not know plaintext types except plain columns. |
| `cerberus-core` | lib | `VaultService`, index, items and payloads, resolve, policy, approvals, leases, audit, agents and token checks, settings. |
| `cerberus-api` | lib | axum router `/v1`, TLS listener, local CA, auth middleware, rate limits, request ID, error mapping, SSE, OpenAPI. |
| `cerberus-mcp` | lib + bin `cerberus-mcp` | MCP server (rmcp) mounted at `/mcp`; the bin is the stdio shim. |
| `cerberus-client` | lib + bin `cerberus` | HTTPS SDK with CA pin, CLI (`cerberus run`, `resolve`, `status`). |
| `cerberusd` | bin | Headless daemon. |
| `cerberus-ssh-agent` | lib | ssh-agent protocol bridge (T22). |
| `apps/desktop/src-tauri` (`cerberus-desktop`) | bin | Tauri shell, IPC commands, tray, OS lock hooks. |

### Allowed dependencies (arrow = "may depend on")
```
cerberus-types      ◄── every crate below may use it
cerberus-crypto     ──► types
cerberus-store      ──► crypto, types
cerberus-core       ──► store, crypto, types
cerberus-ssh-agent  ──► core, crypto, types
cerberus-api        ──► core, crypto, types, ssh-agent
cerberus-client     ──► types                      (never crypto, store, core, api)
cerberus-mcp        ──► api, core, client, types   (client only for the stdio shim bin)
cerberusd           ──► api, mcp, core, store, crypto, types
cerberus-desktop    ──► api, mcp, core, store, crypto, types
```
Rules:
1. No cycles. No crate depends on a crate above it in this list except as drawn.
2. Only `cerberus-core` may call `cerberus-store` repositories that hold encrypted data. `cerberus-api` and
   `cerberus-mcp` reach data only through `cerberus-core` traits. Binaries use `cerberus-store` only to open the file.
3. `cerberus-api` never imports `axum` types into `cerberus-core`. Core is transport-free.
4. `cerberus-client` builds without `sqlx`, `argon2`, `tauri`, `axum`. CI checks `cargo tree -p cerberus-client`.
5. A CI script (`just deps-check`) reads `cargo metadata` and fails on any edge that is not in the table.
6. Each lib crate has `#![forbid(unsafe_code)]` except `cerberus-crypto` (ADR-0012), plus
   `#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]` outside tests.

## Consequences

- One extra crate (`cerberus-types`) compared with the plan. It is the only way the client can share DTOs without
  pulling the server.
- The MCP router is composed with the REST router in the binaries: `cerberus_api::serve(config, extra_routes)`.

## Alternatives considered

- **DTOs inside `cerberus-api` behind a feature flag.** Rejected. Feature unification in a workspace would pull axum
  into the client build.
