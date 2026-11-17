# ADR-0028: Secret responses, the `handling` field and env injection

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.6, 5.1, A2, A12
- Related: ADR-0019, ADR-0021, ADR-0029, ADR-0032

## Context

Agents print and log what they get. A secret in an agent transcript is a leak. The plan gives three controls:
the `handling` flag, env injection and the SSH signing socket.

## Decision

### Secret responses
1. Only these responses carry secret values: `POST /v1/credentials/{id}/reveal`, `POST /v1/credentials/resolve`
   (`outcome: "secret"`), `POST /v1/credentials/{id}/totp`, and their MCP tools (`get_credential`, `get_totp`).
2. Each such body has a top-level `"handling": "secret — do not print or log"` (U+2014 em dash, exact text).
   Constant `cerberus_types::HANDLING_SECRET`.
3. Secret values are under one key `secret`. Metadata is under `item`. Lease under `lease`.
4. Headers: `Cache-Control: no-store` (all responses, ADR-0023).
5. MCP tool results that carry a secret also start the text content with the line
   `HANDLING: secret — do not print or log.`

### `cerberus run` (in `cerberus-client`)
```
cerberus run --app shop --env staging --role admin [--kind web_login] [--id <item id>]
             [--var NAME=field ...] [--no-mask] -- <command> [args...]
```
1. Token from `CERBERUS_TOKEN` or `--token-file`. Never from a command-line argument (visible in `ps`).
2. The CLI calls resolve (`mode: best`). If the result is `pending`, it waits on SSE (max 120 s) and then reveals.
3. Default env names by kind: `web_login` → `CERBERUS_USERNAME`, `CERBERUS_PASSWORD`, `CERBERUS_URL`;
   `api_key` → `CERBERUS_API_KEY`; `session_token` → `CERBERUS_SESSION_TOKEN`; `database` → `DATABASE_URL`;
   `cloud` → provider-standard names (for example `AWS_ACCESS_KEY_ID`); `env_bundle` → its own names;
   `browser_session` → writes storage state to a `0600` temp file and sets `CERBERUS_STORAGE_STATE` to its path,
   deleted when the child exits. `--var` overrides.
4. The child gets the variables. The CLI removes `CERBERUS_TOKEN` from the child env unless `--pass-token`.
5. **Output masking** (default on): the CLI pipes child stdout and stderr and replaces each secret value (and its
   Base64 and URL-encoded forms) with `[REDACTED]`. It keeps a window of the longest secret length so values split
   across reads are caught. `--no-mask` turns this off (for binary output).
6. The CLI never prints a secret. Errors print only `code` and `request_id`. Exit code = child exit code, or 70+ for
   CLI errors (`70` auth, `71` locked, `72` denied, `73` no match, `74` other).
7. When the child exits, the CLI releases the lease.

### SSH
With T22, agents use `ssh-prepare` and get an ssh-agent socket. The private key stays in the vault.

## Consequences

- A12 passes: the child sees the variable; the CLI output does not show it.
- A child that writes the secret to a file, or sends it on the network, is not stopped (accepted risk AR-3).

## Alternatives considered

- **Return secrets only through `cerberus run`.** Rejected. MCP agents need values for tools like Playwright.
