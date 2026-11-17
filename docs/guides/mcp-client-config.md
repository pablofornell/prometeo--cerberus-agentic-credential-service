# Connect an MCP client to Cerberus

Cerberus speaks MCP in two ways (ADR-0029):

- **Streamable HTTP** at `https://127.0.0.1:7373/mcp`, for hosts that can call a remote MCP server.
- **The stdio shim** `cerberus-mcp`, for hosts that only start local commands. The host starts the shim. The shim sends
  every message to `/mcp` over pinned HTTPS and writes the replies back. It holds no vault data.

Both need an agent token (`cvt_...`). Make one in the Cerberus app (Agents, New key). The app shows it one time. Never
put the token in a command line.

## What the shim reads

| Variable | Meaning |
|---|---|
| `CERBERUS_URL` | Service URL. Default `https://127.0.0.1:7373`. Must be `https`. |
| `CERBERUS_TOKEN_FILE` | File with the token. Mode `0600`. Better than `CERBERUS_TOKEN`. |
| `CERBERUS_TOKEN` | The token itself. Use only when the host cannot read a file. |
| `CERBERUS_CA_FILE` | PEM file of the Cerberus CA (export it from the app). Also read as `CERBERUS_CA_CERT`. |
| `CERBERUS_CA_PIN` | `sha256/...` pin of the CA key (shown in the app). Also read as `CERBERUS_PIN`. |

You must give a CA file, a pin, or both. Without one the shim refuses to start: it never trusts a public CA. A pin
alone works only when the server sends the CA certificate after the leaf; prefer the CA file.

## Claude Code

`.mcp.json` in your project (or `claude mcp add-json`). The token is in a file, and the CA file is the one you exported
from the app (the pin is optional with a CA file):

```json
{
  "mcpServers": {
    "cerberus": {
      "command": "cerberus-mcp",
      "env": {
        "CERBERUS_URL": "https://127.0.0.1:7373",
        "CERBERUS_CA_FILE": "/home/you/.config/cerberus/ca.pem",
        "CERBERUS_CA_PIN": "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "CERBERUS_TOKEN_FILE": "/home/you/.config/cerberus/token"
      }
    }
  }
}
```

If the host cannot read a file, put the token in the environment of the host process and pass it through. This example
uses a fake token; replace it, and do not commit a real one:

```json
{
  "mcpServers": {
    "cerberus": {
      "command": "cerberus-mcp",
      "env": {
        "CERBERUS_URL": "https://127.0.0.1:7373",
        "CERBERUS_CA_FILE": "/home/you/.config/cerberus/ca.pem",
        "CERBERUS_TOKEN": "cvt_00000000-0000-0000-0000-000000000000.fake-token-for-docs-only"
      }
    }
  }
}
```

## Other hosts

Any host that starts a stdio MCP server takes the same `command` and `env`. A host that supports remote HTTP servers can
use `https://127.0.0.1:7373/mcp` with the header `Authorization: Bearer <token>`; it must trust the Cerberus CA.

## What the agent sees

Eight tools: `vault_status`, `find_credentials`, `get_credential`, `request_access`, `get_totp`, `store_secret`,
`release_credential`, `ssh_prepare` (returns the path of an SSH agent socket, the key stays in the vault), and the resource
`cerberus://catalog` (metadata only). The schemas are in `docs/api/mcp-tools.md`. The agent-facing rules are in the
[agent integration guide](agent-integration.md#mcp).

- A locked vault does not close the session. Each tool returns the error `vault_locked`; `vault_status` returns
  `{"vault": "locked"}`. Unlock the vault in the app and call again.
- A secret result starts its text with `HANDLING: secret — do not print or log.` The agent must not print the value.
- `get_credential` and `request_access` wait up to `wait_seconds` (default 60, at most 120) for a person to approve in
  the app, then return `pending`. Call again later.

## Logs

The shim logs to stderr, warnings only, never message bodies. If you embed the server in your own process, cap the
`rmcp` log target at `warn` (`cerberus_mcp::LOG_DIRECTIVE`): `rmcp` logs message bodies at `debug` level.
