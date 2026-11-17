# ADR-0029: MCP transport and the stdio shim

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 5.2, T11
- Related: ADR-0004, ADR-0008, ADR-0016, ADR-0021, ADR-0028, `docs/api/mcp-tools.md`

## Context

Many agent hosts (for example Claude Code) use MCP. Some support remote HTTP servers, some only stdio.

## Decision

1. `cerberus-mcp` uses `rmcp` 3.10.0, Streamable HTTP server transport, mounted at `/mcp` on the same TLS listener as
   `/v1`. It is not under `/v1`.
2. Auth: the same bearer-token middleware as REST (ADR-0016), applied to every `/mcp` HTTP request. The tool layer
   gets the `AgentContext` (agent ID, key ID, scopes, request ID) from request extensions.
3. Locked vault: see ADR-0008 item 4.
4. Each tool calls the same `cerberus-core` `AgentApi` function as its REST route. The mapping table is in
   `docs/api/mcp-tools.md`. Each tool needs the scope of its REST route.
5. Each tool call gets its own request ID and audit event.
6. Tool results: `structuredContent` = the same JSON as the REST response body; text content = the same JSON (with the
   handling line first for secret results, ADR-0028). `outputSchema` is declared for each tool.
7. Tool annotations: `readOnlyHint: true` for `vault_status`, `find_credentials`, `get_totp`;
   `destructiveHint: true` for `release_credential`; `openWorldHint: false` for all.
8. Resource `cerberus://catalog` (`application/json`): metadata of visible items, same as `GET /v1/credentials`
   without filters (first 500 items; field `truncated`). No subscription in version 1.
9. `rmcp` log level is capped at `warn`, because it can log message bodies (Hermes lesson, T00 section 7).

### Stdio shim `cerberus-mcp`
- Reads JSON-RPC messages on stdin, sends them to `https://<host>/mcp` with `cerberus-client`, writes replies on stdout.
- Config from env: `CERBERUS_URL` (default `https://127.0.0.1:7373`), `CERBERUS_TOKEN` or `CERBERUS_TOKEN_FILE`,
  `CERBERUS_CA_CERT` (PEM path) and/or `CERBERUS_PIN` (`sha256/…`). Without a CA or pin it refuses to start.
- It logs only to stderr, never message bodies.
- Example host config (Claude Code `.mcp.json`; the token comes from the environment):
  ```json
  { "mcpServers": { "cerberus": { "command": "cerberus-mcp",
      "env": { "CERBERUS_URL": "https://127.0.0.1:7373", "CERBERUS_PIN": "sha256/<pin from the app>" } } } }
  ```

## Consequences

- One auth path and one policy path for REST and MCP.

## Alternatives considered

- **Stdio server that opens the vault file itself.** Rejected. It would hold keys in a second process (against D1).
