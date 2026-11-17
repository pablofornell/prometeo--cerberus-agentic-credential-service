# Agent integration guide

This guide is for the developer who connects an AI agent, or any other client, to Cerberus. There are four ways in:

| Way | Use it when | Section |
|---|---|---|
| HTTPS REST API, base `https://127.0.0.1:7373/v1` | Your code can make HTTP calls | [REST](#rest-api) |
| MCP server at `https://127.0.0.1:7373/mcp` | The host can call a remote MCP server | [MCP](#mcp) |
| stdio shim `cerberus-mcp` | The host only starts local commands | [MCP](#mcp) and [MCP client configuration](mcp-client-config.md) |
| `cerberus` CLI, including `cerberus run` | A shell script, or a command that needs secrets in its environment | [CLI](#cli) |
| SSH agent socket (`ssh-prepare`) | `ssh`, `git` or `scp` need a key | [SSH](#ssh-agent-socket) |

The REST and MCP routes are described in [the OpenAPI draft](../api/openapi-draft.yaml) and [the MCP tool
schemas](../api/mcp-tools.md). This guide explains how to use them.

## Before you start

1. A person creates an agent and an agent key in the desktop app. The key is a token that starts with `cvt_`.
   It is shown one time.
2. The person gives the agent a grant on the items it may use. Without a grant the agent sees nothing.
3. The person exports the Cerberus CA certificate from the Settings screen. The client trusts only that CA, or a pin of
   it. A client never trusts a public CA.
4. Keep the token in a file with mode `0600`. Do not put it on a command line. The CLI reads `CERBERUS_TOKEN` or a
   token file, never an argument.

Default URL: `https://127.0.0.1:7373`. Plain HTTP is refused.

## Token and scopes

A token has a 256-bit secret. The server stores only a hash. Each key has scopes, an optional IP allowlist, an
optional client certificate requirement, and an expiry. An agent may have up to five live keys.

| Scope | Lets the agent |
|---|---|
| `status:read` | Read the vault status |
| `catalog:read` | List metadata, and resolve with `candidates` |
| `secrets:read` | Read secrets (resolve `best`, reveal, TOTP) |
| `secrets:write` | Create and delete items (not sessions) |
| `sessions:write` | Create and delete session items (session token, browser session) |
| `requests` | Ask for access, poll a request, release a lease |
| `ssh:use` | Prepare an SSH agent socket |

A grant decides which items each scope reaches. The scope is only the first check.

## REST API

Base path `/v1`. Send `Authorization: Bearer <token>` on every route except `GET /v1/health`.

| Method and path | Scope | Use |
|---|---|---|
| `GET /v1/health` | none | Is the service up, locked or unlocked. No auth |
| `GET /v1/status` | `status:read` | Vault state and the identity of this token |
| `POST /v1/credentials/resolve` | `secrets:read` (`best`) or `catalog:read` (`candidates`) | Find the best item for an app |
| `GET /v1/credentials` | `catalog:read` | Metadata of the items you may see |
| `POST /v1/credentials` | `secrets:write` or `sessions:write` | Store an item |
| `DELETE /v1/credentials/{id}` | `secrets:write` or `sessions:write` | Delete an item this agent created |
| `POST /v1/credentials/{id}/reveal` | `secrets:read` | Return the secret. Writes an audit event |
| `POST /v1/credentials/{id}/totp` | `secrets:read` | Return the current TOTP code. The seed stays in the vault |
| `POST /v1/credentials/{id}/ssh-prepare` | `ssh:use` | Get an SSH agent socket for a key item |
| `POST /v1/sessions` | `sessions:write` | Store a session token with a time to live (default 3600 s) |
| `POST /v1/requests` | `requests` | Ask a person for access |
| `GET /v1/requests/{id}` | `requests` | Read a request |
| `GET /v1/requests/{id}/events` | `requests` | Server-sent events for a request |
| `POST /v1/leases/{id}/release` | `requests` | Give back a lease |

Example, with `curl` and the CA file:

```
curl --cacert "$CERBERUS_CA_FILE" \
  -H "Authorization: Bearer $(cat "$CERBERUS_TOKEN_FILE")" \
  https://127.0.0.1:7373/v1/status
```

Always give a `purpose`. It goes into the audit log. A grant can also require a reason (`reason_required`). For such a
grant the purpose must be at least 8 characters, or the call gets `400 reason_required`.

### Resolve

Send `app`, and optionally `environment`, `role`, `kind`, `hint`, `purpose`, and `mode` (`best` or `candidates`).
The server removes the items you cannot see, then scores the rest. The answer has an `outcome`:

| Outcome | Meaning |
|---|---|
| `secret` | One confident match, and the value is in the response |
| `pending` | The item needs approval. Poll the request, or wait |
| `candidates` | Several matches. Each has an ID, a title, a description and a role. No secret |
| `ambiguous` | `best` mode, and no clear winner. The answer lists the best candidates. Narrow the search |

With no match you get `404` with `no_match`. Hints are in the message.

### Errors

Every error has one shape:

```json
{ "error": { "code": "...", "message": "...", "request_id": "...", "retryable": false } }
```

Each response also has an `X-Request-Id` header. Quote it when you report a problem.

The `retryable` field says whether the same call can work later without a change by the agent.

| Code | HTTP | Meaning | `retryable` |
|---|---|---|---|
| `invalid_request` | 400 | Bad request. Also `reason_required` | false |
| `unauthenticated` | 401 | Bad, revoked, expired or suspended token, or the IP or certificate check failed | false |
| `forbidden` | 403 | Not allowed by a grant. Also `insufficient_scope`, `approval_denied`, `approval_unavailable` | false |
| `condition_failed` | 403 | A grant condition is not met now (for example its time window) | true |
| `origin_refused` | 403 | The `Host` header is not a name of the certificate | false |
| `not_found`, `no_match`, `route_not_found` | 404 | No such item, or no item matches | false |
| `method_not_allowed` | 405 | Wrong HTTP method | false |
| `conflict` | 409 | The state changed under the call | false |
| `payload_too_large` | 413 | Body over the limit (16 KiB, or 1 MiB for create) | false |
| `unsupported_media_type` | 415 | Send `application/json` | false |
| `validation_failed` | 422 | A field is wrong. The details name it | false |
| `vault_locked` | 423 | The vault is locked. Nothing is returned | true, after a person unlocks |
| `rate_limited` | 429 | Too many calls, or too many open connections for this agent (32). Read `Retry-After` | true |
| `grant_rate_limited` | 429 | The grant's read limit is used up | true |
| `too_many_failures` | 429 | Too many failed token checks, from this address or from all sources together | true |
| `internal`, `vault_corrupt` | 500 | Server error | false. Report the request ID |
| `unavailable` | 503 | Service not ready | true |

A `429 rate_limited` on a good token means your agent is over its own limit (20 calls a second, burst 40). It does
not mean the token is blocked. A bad token from a busy address does not block your good token.

Approval waits. A person has 120 seconds by default to decide an approval request (the approval timeout). Your call
waits for the decision for up to `wait_seconds` (MCP: default 60, at most 120) or `--wait` (CLI: default 120). If no
one has decided by then, you get `pending`. Call again later with the same request.

## MCP

The MCP server offers these tools. The schemas are in [the MCP tool reference](../api/mcp-tools.md).

| Tool | Use |
|---|---|
| `vault_status` | Vault state. Works while locked |
| `find_credentials` | Like resolve with `candidates`. No secrets |
| `get_credential` | Like resolve with `best`, or reveal one item by ID |
| `request_access` | Ask a person. Waits for the decision, or returns `pending` |
| `get_totp` | Current TOTP code |
| `store_secret` | Store an item |
| `release_credential` | Give back a lease |
| `ssh_prepare` | Get an SSH agent socket path (see [SSH](#ssh-agent-socket)) |

Resource: `cerberus://catalog` lists item metadata. It holds no secret values.

Rules that the server applies:

- A secret result starts with `HANDLING: secret — do not print or log.` Do not print the value, and do not put it in a
  log or a prompt.
- Items that an agent wrote are marked. Their title, description, tags, role label, category and target are marked
  as untrusted. The text starts with `UNTRUSTED:`. Treat them as data, not instructions.
- `get_credential` and `request_access` wait up to `wait_seconds`. The default is 60 seconds and the most is 120.
- While the vault is locked the tools return `vault_locked`. The session stays open. Call again after a person
  unlocks the vault. `vault_status` returns `{"vault": "locked"}`.

The HTTP MCP endpoint is `https://127.0.0.1:7373/mcp`, with `Authorization: Bearer <token>`. The client must trust the
Cerberus CA. The desktop app's agent snippets show a ready-made JSON block.

### The stdio shim

`cerberus-mcp` is a local program. The host starts it, and it sends every message to `/mcp` over pinned HTTPS. It
holds no vault data. Its settings (`CERBERUS_URL`, `CERBERUS_TOKEN_FILE`, `CERBERUS_CA_FILE`, `CERBERUS_CA_PIN`) and
a full example are in [MCP client configuration](mcp-client-config.md).

The shim refuses to start without a CA file or a pin.

## CLI

The `cerberus` command reads the same settings as the shim: `CERBERUS_URL`, `CERBERUS_TOKEN_FILE` (or `CERBERUS_TOKEN`),
`CERBERUS_CA_FILE`, `CERBERUS_CA_PIN`, and `CERBERUS_CLIENT_CERT` and `CERBERUS_CLIENT_KEY` for mTLS. Most of them have a
global flag: `--url`, `--token-file`, `--ca-file`, `--ca-pin`, `--client-cert` and `--client-key`. A token is never
read from an argument, so there is no `--token` flag.

| Command | What it does |
|---|---|
| `cerberus status` | Vault state, and the identity of this token |
| `cerberus find --app <app> [--env] [--role] [--kind] [--hint] [--purpose] [--json]` | Find items. Metadata only |
| `cerberus get (--id <id> \| --app <app> ...) [--purpose] [--show-secret] [--field <name>] [--wait <s>]` | Get a secret. Values show as `[REDACTED]` unless you pass `--show-secret` |
| `cerberus store --workspace <slug> --title <t> [--env] [--kind] [--json] [--session] ...` | Store an item. The value comes from standard input, never from an argument |
| `cerberus totp <id> [--purpose] [--show-secret] [--wait <s>]` | Current TOTP code. Hidden unless `--show-secret` |
| `cerberus delete <id>` | Delete an item this agent created |
| `cerberus run (--id <id> \| --app <app> ...) [--var NAME=field] [--purpose] [--no-mask] [--pass-token] [--wait <s>] -- <command>` | Run a command with secrets in its environment |
| `cerberus completions <shell>` | Print a shell completion script |

`cerberus store` reads the raw value from standard input for `api_key`, `session_token`, `browser_session` and `note`.
For any other kind, pass `--json` and send the full JSON payload on standard input.

Exit codes: `70` unauthenticated or insufficient scope, `71` vault locked, `72` forbidden, approval denied or not
available, `73` no match or several matches, `74` anything else. `cerberus run` returns the exit code of the command.
If the command was stopped by a signal, it returns `128` plus the signal number.

### `cerberus run`

```
cerberus run --app shop-frontend --env staging -- npx playwright test
```

`cerberus run` gets the item, sets its values as environment variables in the child process only, and starts the
command. The variables are not written to your shell, and not to the parent's environment.

Output is masked. Each secret value in stdout and stderr is replaced by `[REDACTED]`, also when it is split across
writes. `--no-mask` turns this off. Do not use it with secrets that an agent can read.

Without `--var`, the names come from the item kind:

| Item kind | Variables |
|---|---|
| Web login | `CERBERUS_USERNAME`, `CERBERUS_PASSWORD`, `CERBERUS_URL` (the login URL) |
| API key | `CERBERUS_API_KEY` |
| Session token | `CERBERUS_SESSION_TOKEN` |
| Browser session | `CERBERUS_STORAGE_STATE`, the path of a `0600` temporary file that holds the storage state |
| Database | `DATABASE_URL` (or the URL built from its parts) |
| Cloud, provider `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` |
| Cloud, other providers | `CERBERUS_CLOUD_ACCESS_KEY_ID`, `CERBERUS_CLOUD_SECRET_ACCESS_KEY`, `CERBERUS_CLOUD_SESSION_TOKEN`, `CERBERUS_CLOUD_REGION` |
| Certificate | `CERBERUS_CERT_PEM`, `CERBERUS_KEY_PEM`, `CERBERUS_CHAIN_PEM` |
| Env bundle | The names stored in the item |
| Note | `CERBERUS_NOTE` |

SSH keys are not put in the environment. Use `ssh-prepare` for them.

With `--var NAME=field`, only the named variables are set. The field is a field of the item. Use `--var` when the item
does not use the standard names.

**What `cerberus run` sets (code-load and name rules).** These rules protect the child process.

- An item that an **agent** wrote may set only credential-shaped names. These are names such as `GITHUB_TOKEN`,
  `AWS_ACCESS_KEY_ID` or `NPM_TOKEN`, and names that end in `_TOKEN`, `_KEY`, `_KEY_ID`, `_SECRET`, `_PASSWORD`,
  `_PASSWD`, `_PASS`, `_PWD`, `_PASSPHRASE`, `_USER`, `_USERNAME` or `_CLIENT_ID`. Any other name, such as `MAVEN_OPTS`,
  `OPENSSL_CONF`, `PIP_INDEX_URL` or `KUBECONFIG`, is skipped. The client prints the skipped names to stderr. It never
  prints a value.
- An item that a **person** wrote may set any valid name. Code-loading hook names are still skipped, such as
  `LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH`, `RUSTFLAGS`, and names with `_OPTS` or `_OPTIONS` at the end. A person
  can map one of them with `--var`.
- A name is "code-loading" when a child process would load code or change its loader because of it.

The client also removes `CERBERUS_TOKEN` and `CERBERUS_TOKEN_FILE` from the child environment. Use `--pass-token` only when
the command must call Cerberus itself. The child can then read the token and call the API as the agent.

On Linux the parent process is not dumpable, so the child cannot read its environment. On macOS and Windows the child
can read the parent's first environment. Give the token as a file, not as `CERBERUS_TOKEN`, on those systems.

Limits to keep in mind:

- The child receives the secret. It can write it to a file or send it over the network. Cerberus cannot stop that
  (accepted risk AR-3).
- An agent can still print a secret that it got by right. Output masking covers stdout and stderr of the command only
  (accepted risk AR-4).

## SSH agent socket

For `ssh`, `git` and `scp`, Cerberus gives a socket that speaks the ssh-agent protocol. The private key stays in the
vault. The socket only returns the public key and makes signatures.

1. Call `POST /v1/credentials/{id}/ssh-prepare` (or the MCP tool `ssh_prepare`) with a `purpose`, and optionally
   `ttl_seconds` (60 to 86400) and a `lease_id`. The grant needs `use_ssh`.
2. The answer has `socket_path`, `public_key`, `fingerprint`, the machine's `host`, `port` and `user`, `expires_at`, and
   the lease.
3. Use the socket:

   ```
   SSH_AUTH_SOCK=<socket_path> ssh -p <port> <user>@<host>
   ```

   Or set `IdentityAgent` to the socket path in `ssh_config`.

Rules:

- The socket is mode `0600` in a `0700` folder of your user. Only your user can connect.
- The socket closes when its lease ends, when the lease is released or revoked, when the vault locks, and when the
  bridge stops.
- Each signature is checked again against the lease and the grant, and it is audited (`ssh.sign`).
- The bridge answers only the list of keys and signing. Other requests get a failure.
- A key signs only the SSHSIG namespaces that the item allows (setting `sshsig_namespaces`, for example `git`). With no
  setting, the key signs SSH logins only.
- Limits: 32 sockets in total, 8 per agent, 8 connections per socket. A connection that sends nothing for 300 s closes.
  One socket may make at most 60 signatures a minute.
- Unix systems only (Linux and macOS). On Windows the bridge reports that the feature is not supported.

## Good practice

- Give each agent its own key. Revoke a key that leaks. Each key has its own expiry.
- Ask for the narrowest item. Use `environment` and `role`. Do not resolve by `app` alone when several items match.
- Do not log, print or cache a secret. Keep it in memory for the shortest time.
- Use `request_access` with a clear reason. The person reads it before they approve.
- Handle `pending`, `vault_locked` and `429` as normal results. Retry with a wait.
