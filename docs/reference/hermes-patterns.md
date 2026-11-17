# Hermes patterns for Cerberus (task T00)

Status: read-only study. Nothing in the reference repo was changed.

## Scope and method

- Reference repo: `/home/pablo/Documents/workbench/repos/hermes--centralized-notification-service`.
  The product is called **Iris**. The core crate is `crates/iris-core`.
- All file paths below are relative to that repo root. Line numbers were read from the files.
- Search depth: medium. I read the auth, error, API, service, DB, MCP, config, logging and test code,
  plus `docs/API.md`, `docs/ARCHITECTURE.md`, `README.md`, `CLAUDE.md` and `Makefile`.
- I did not run the tests or the server. Claims are from reading the code.
- Test secrets in `crates/iris-core/tests/common/mod.rs` are not copied here.
- The Cerberus defaults in item 8 come from the task brief. The Cerberus repo has only a `LICENSE` file, so I could not check them.

## 1. Tenant model

- **No tenant or workspace concept.** A search for tenant, workspace (as a business unit) and org found no data model for them.
  The only "Workspace" hits are the Cargo workspace (`docs/ARCHITECTURE.md:26`).
- **One trust domain per process.** Access to the admin side uses one admin token from the env file:
  `IRIS_ADMIN_TOKEN` (`crates/iris-core/src/config.rs:107-108`). There is no per-user admin account.
- **Main objects:**
  - Client: an app that sends notices. Id is lowercase (`crates/iris-core/src/config.rs:169`, `docs/API.md:347`). Table `clients` (`crates/iris-core/migrations/0002_agents.sql:20-27`).
  - Agent: an MCP caller that owns clients. Table `agents` (`crates/iris-core/migrations/0002_agents.sql:4-17`).
  - Recipient: a notice target linked to Telegram (`crates/iris-core/src/model.rs:306`, `README.md`, section "How it works").
  - Message and delivery rows (`crates/iris-core/src/db/messages.rs`, `crates/iris-core/src/db/deliveries.rs`).
- **How data is scoped:**
  - Only agent-owned clients are scoped. The SQL includes the owner id: `WHERE id = ? AND owner_agent_id = ?` (`crates/iris-core/src/db/clients.rs:69-76`), and `list_owned` filters the same way (`crates/iris-core/src/db/clients.rs:95`).
  - Another agent's app gives `not_found`, not `forbidden` (`crates/iris-core/src/mcp/errors.rs:40-41`).
  - Everything under `/api/*` is admin-only through one middleware (`crates/iris-core/src/api/mod.rs:274-315`, `crates/iris-core/src/api/mod.rs:56-62`).
  - Recipient ownership of a source only affects routing (`crates/iris-core/src/router.rs:1-4`, `crates/iris-core/src/router.rs:167-177`).

## 2. API key and token format, storage, rotation, scopes

| Credential | Format | Storage | Shown once? | Rotation |
|---|---|---|---|---|
| Admin token | Plain string from env, min 16 chars (`crates/iris-core/src/config.rs:19-20`, `:213-216`) | Env file (`crates/iris-core/src/config.rs:107-108`). In memory only as SHA-256 (`crates/iris-core/src/auth.rs:165-181`) | Not applicable | No rotate route in `crates/iris-core/src/api/mod.rs:274-305`. Change means editing the env file and restarting (`CLAUDE.md`, step 1) |
| Admin session | 32 random bytes as hex (`crates/iris-core/src/auth.rs:196-201`) | Memory only, keyed by SHA-256 of the id (`crates/iris-core/src/auth.rs:184-203`). Lost on restart (`crates/iris-core/src/auth.rs:184-185`) | Not applicable. Made by `POST /api/session` with the admin token (`crates/iris-core/src/api/session.rs:33-40`) | Expires after 30 days (`crates/iris-core/src/auth.rs:18-19`). No rotation |
| Client token, env client | 64 hex chars = 32 random bytes (`crates/iris-core/src/auth.rs:36-39`) | Plain text in `iris.env` (`crates/iris-core/src/service/clients.rs:190-200`). Memory keeps SHA-256 (`crates/iris-core/src/auth.rs:87-96`) | Yes. Create response only (`crates/iris-core/src/service/clients.rs:222`, `docs/API.md:340`) | Admin `POST /api/clients/{id}/rotate` (`crates/iris-core/src/api/mod.rs:287`, `crates/iris-core/src/service/clients.rs:277-314`) |
| Client token, agent client | Same as above | SHA-256 only, in `clients.token_hash` (`crates/iris-core/migrations/0002_agents.sql:23`, `crates/iris-core/src/service/clients.rs:594-601`) | Yes (`docs/API.md:340`) | Admin route, or MCP `rotate_credential` (`crates/iris-core/src/mcp/tools.rs:548-561`). Old token stops at once (`crates/iris-core/src/service/clients.rs:289-299`) |
| Agent token | `iris_agent_` plus 32 random bytes as hex (`crates/iris-core/src/auth.rs:21-22`, `:41-44`) | SHA-256 only, `agents.token_hash` (`crates/iris-core/src/db/agents.rs:1-5`, `crates/iris-core/migrations/0002_agents.sql:11`) | Yes (`crates/iris-core/src/service/agents.rs:59-64`, `docs/API.md:437`) | None. Re-enroll with a new name (`docs/API.md:440`, `README.md:324`) |

- **Hint:** the last 4 characters are kept for display, as `…abcd` (`crates/iris-core/src/auth.rs:51-62`).
- **Hash function:** plain SHA-256 with no salt (`crates/iris-core/src/auth.rs:24-27`). This is fine for the random 256-bit tokens that Iris makes. It is weak for user-chosen values (see section 8).
- **Lookup:**
  - In memory, all entries are compared in constant time, with no early exit (`crates/iris-core/src/auth.rs:113-124`).
  - For agent tokens, a direct index lookup by hash (`crates/iris-core/src/db/agents.rs:113-121`). The file says this is safe because the token has 256 random bits (`crates/iris-core/src/db/agents.rs:3-5`).
- **Token expiry:** none for API tokens. Sessions expire (`crates/iris-core/src/auth.rs:18-19`).
- **Scopes:** none. A search for scope, role, grant and permission found only file-mode code (`crates/iris-core/src/envfile.rs:125-129`) and MCP protocol types.
- **Token kinds are fixed to one surface each:**
  - Admin token works on `/api/*` only (`docs/API.md:31`).
  - Client token works on `POST /notify` only (`docs/API.md:31`, `crates/iris-core/src/api/notify.rs:19-49`).
  - Agent token works on `/mcp` only (`docs/API.md:32`, `crates/iris-core/src/mcp/auth.rs:9-14`).
- **Bearer parsing:** the scheme is case-insensitive (`crates/iris-core/src/auth.rs:220-227`).
- **Revocation:**
  - Suspend stops the client tokens of an agent. The rows stay (`crates/iris-core/src/service/agents.rs:267-269`, `docs/API.md:379`).
  - Revoke removes the agent token hash and soft-deletes its clients (`crates/iris-core/src/service/agents.rs:281-283`, `docs/API.md:381`).

## 3. Permission model

- **Actors** are recorded in the audit log. There are four: `Admin`, `Agent { id, name }`, `Anonymous`, `System` (`crates/iris-core/src/service/mod.rs:15-26`).
- **Roles:** none stored. Access depends on the kind of token and on the agent status.
- **Route checks:**
  - `/api/*` (except session): `require_admin` accepts the admin session cookie or the admin bearer token (`crates/iris-core/src/api/mod.rs:34-62`, route layer at `:305`).
  - `POST /notify`: client token lookup (`crates/iris-core/src/api/notify.rs:19-49`).
  - `/mcp`: the middleware sets a `Caller` value. It is `Anonymous`, `BadToken`, or `Agent` (`crates/iris-core/src/mcp/auth.rs:73-84`, `:128-139`).
- **Agent status gate:** creating a client needs an approved agent (`crates/iris-core/src/service/clients.rs:515-526`). The status transition table is at `crates/iris-core/src/service/agents.rs:1-13`.
- **Ownership gate:** every agent action runs with `Actor::agent_id()`. A non-agent actor gets `forbidden` (`crates/iris-core/src/service/mod.rs:47-53`).
- **Quota gates:** max apps per agent (`crates/iris-core/src/service/clients.rs:539-547`). Max pending agents (`crates/iris-core/src/service/agents.rs:147-149`). Global enroll bucket (`crates/iris-core/src/service/agents.rs:129-139`).
- **Browser protection:** `csrf_guard` checks `Sec-Fetch-Site`, `Origin` and `Content-Type` on every non-GET `/api/*` call (`crates/iris-core/src/api/mod.rs:162-211`). Session cookie is `HttpOnly; SameSite=Strict` (`crates/iris-core/src/api/session.rs:21-23`).

## 4. Error response shape and request IDs

- **Shape:** `{"error":{"code":"...","message":"..."}}` (`crates/iris-core/src/error.rs:1-2`, `:124-127`). Same shape in `docs/API.md:11-15`.
- **Error codes and HTTP status** (`crates/iris-core/src/error.rs:32-99`):
  - `invalid_body` 400, `unauthorized` 401, `forbidden` 403, `not_found` 404, `conflict` 409.
  - `not_approved` 403, `limit_reached` 409, `payload_too_large` 413, `unsupported_media_type` 415.
  - `rate_limited` 429, `telegram_unreachable` 503, `internal` 500.
- **Internal errors:** the cause goes to the log. The caller gets the fixed text `internal server error` (`crates/iris-core/src/error.rs:101-109`).
- **Retry info:** `Retry-After` header, set only for `rate_limited` (`crates/iris-core/src/error.rs:128-132`). There is no `retryable` field.
- **MCP tool errors** use the same idea, with a different text body (`crates/iris-core/src/mcp/errors.rs:1-9`):
  - Body: `{"error":{"code","message","retry_after_secs"}}`.
  - Sent as a tool result with `isError: true` and no `structuredContent` (`crates/iris-core/src/mcp/errors.rs:11-19`).
  - Codes are in `crates/iris-core/src/mcp/errors.rs:30-52`.
- **Request IDs: none.** A search of `crates/`, `src-tauri/` and `docs/` for request id, `x-request-id`, `request_id`, trace id and correlation found nothing. The router uses `TraceLayer::new_for_http()` (`crates/iris-core/src/lib.rs:62`, `:90`). That layer makes HTTP log lines but no ID is added to the response or the error body.

## 5. Config style

- **Source:** one env file, `iris.env`. Default path `./iris.env` (`crates/iris-core/src/config.rs:42-43`). Path can come from `--env-file` or `IRIS_ENV_FILE` (`crates/iris-core/src/config.rs:184-187`).
- **Precedence:** process env wins over the file for non-token keys (`crates/iris-core/src/config.rs:3-5`, `docs/ARCHITECTURE.md:66`). The lookup reads the process map first (`crates/iris-core/src/config.rs:199-204`).
- **Client tokens** come from the file and the process env. The server reads them itself (`crates/iris-core/src/config.rs:3-6`).
- **Naming:** every key has the `IRIS_` prefix. Client keys are `IRIS_TOKEN_<NAME>` (`iris.env.example:21-25`).
- **Defaults:** set in code.
  - Server: `Config::defaults` (`crates/iris-core/src/config.rs:320`).
  - MCP: `impl Default for McpConfig` (`crates/iris-core/src/config.rs:73-88`).
  - The same defaults are in the docs table (`docs/ARCHITECTURE.md:72-94`, `README.md`, section "Env file").
- **Typed parsing:** numbers via `parse_num` (`crates/iris-core/src/config.rs:159`). On/off switches accept `on/off/true/false/1/0/yes/no` (`crates/iris-core/src/config.rs:92-98`). Errors name the key (`crates/iris-core/src/config.rs:96`).
- **Startup checks:**
  - Admin token min length (`crates/iris-core/src/config.rs:213-216`).
  - Placeholder check: any token that contains `change-me`, in any case, stops startup (`crates/iris-core/src/config.rs:22-40`).
  - Cross-field checks, e.g. retry max secs must not be below base secs (`crates/iris-core/src/config.rs:297-303`).
- **File safety:** the env file is written to a temp file and renamed (`crates/iris-core/src/envfile.rs:118-135`). New files get mode `0600` (`crates/iris-core/src/envfile.rs:126-128`). A test checks this (`crates/iris-core/src/envfile.rs:230-234`).
- **No other config file format** was seen in the load path (`crates/iris-core/src/config.rs:184-191`).

## 6. Test style

- **Framework:** built-in Rust test harness. `#[tokio::test]` for async (example: `crates/iris-core/tests/agents_api.rs:62`). `tower::ServiceExt` drives the router in process (`crates/iris-core/tests/common/mod.rs:23`). `tempfile` gives a temp dir per test (`crates/iris-core/Cargo.toml`, dev-dependencies).
- **Layout:**
  - Unit tests: inline `#[cfg(test)] mod tests` (`crates/iris-core/src/auth.rs:237-316`, `crates/iris-core/src/api/mod.rs:317-356`). Also `crates/iris-core/src/tests.rs`, registered at `crates/iris-core/src/lib.rs:216`.
  - Integration tests: black-box, one file per feature, in `crates/iris-core/tests/` (`agents_api`, `api`, `delivery`, `dedupe`, `janitor`, `mcp_security`, `mcp_tools`, `mcp_transport`, `ratelimit`, `server`).
  - Shared helpers: `crates/iris-core/tests/common/mod.rs`. Its header says the tests use only the public API and each test has its own state (`:1-5`).
  - Telegram crate: `crates/iris-telegram/src/tests.rs`.
- **Naming:** descriptive snake_case sentences, no `test_` prefix. Examples: `migration_from_a_v1_db_keeps_env_clients_active` (`crates/iris-core/tests/agents_api.rs:63`), `agent_token_requests_have_an_http_limit` (`crates/iris-core/tests/mcp_security.rs:35`), `token_lookup` (`crates/iris-core/src/auth.rs:242`).
- **Determinism:** injected clock. `ManualClock` (`crates/iris-core/tests/common/mod.rs:19`), fixed start time `t0()` (`crates/iris-core/tests/common/mod.rs:33-35`).
- **Count:** about 305 test attributes across the Rust crates (grep count, not run).
- **Gates:** `make test` runs `cargo test --workspace` (`Makefile:74-76`). `make lint` runs clippy with `-D warnings` and a UI check (`Makefile:78-82`). `make fmt-check` (`Makefile:88-90`). `make check` runs all of them (`Makefile:92`).
- **CI:** no `.github` folder in the repo. Not verified whether CI runs `make check` elsewhere.
- **UI tests:** not verified. I did not read `ui/package.json`.

## 7. Audit and logging conventions

- **Audit table:** `audit_log` with `id, at, actor_kind, actor_id, action, target_kind, target_id, detail` (JSON text) (`crates/iris-core/migrations/0002_agents.sql:29-38`).
- **Writer:** `service::audit::record` (`crates/iris-core/src/service/audit.rs:41-77`). It writes a `tracing::info!` line named `audit` and one DB row. A DB error is logged and not returned (`crates/iris-core/src/service/audit.rs:74-76`), because the change is already done.
- **Targets:** agent by id, or client by id (`crates/iris-core/src/service/audit.rs:12-19`).
- **Actions recorded** (grep of `audit::record` and action strings):
  - Agent: `agent.enroll`, `agent.approve`, `agent.reject`, `agent.suspend`, `agent.reinstate`, `agent.revoke`, `agent.expire` (`crates/iris-core/src/service/agents.rs:177-184` for enroll).
  - Client: `client.create`, `client.update`, `client.rotate`, `client.delete`, `client.approve`, `client.reject`, `client.restore`, `client.test_notice`.
  - Callers: 5 in `service/agents.rs`, 9 in `service/clients.rs`, 1 in `mcp/tools.rs`.
- **Not audited:** notice acceptance, reads, and failed logins. `api/session.rs` and `intake.rs` have no `audit::record` call.
- **Secrets rule:** `detail` must not hold a token, a hash or a session id (`crates/iris-core/src/service/audit.rs:3-4`, `crates/iris-core/src/db/audit.rs:16`). Example: `client.create` logs only `origin` (`crates/iris-core/src/service/clients.rs:219`).
- **Actor identity:** `Admin` has no id, so `actor_id` is empty for every admin action (`crates/iris-core/src/service/mod.rs:40-44`). Admins share one token, so the log cannot tell admins apart.
- **Caller address:** the agent enroll row stores the caller address (`crates/iris-core/src/service/agents.rs:182`, field `addr`). Treat as personal data when you port this.
- **Read API:** `GET /api/audit`, newest first, cursor `before`, max 200 rows (`crates/iris-core/src/api/audit.rs:13-16`, `:70-81`, `crates/iris-core/src/db/audit.rs:62-112`).
- **Retention:** the janitor deletes rows older than `IRIS_AUDIT_RETENTION_DAYS`, default 365 (`crates/iris-core/src/janitor.rs:41-55`, `crates/iris-core/src/config.rs:338`).
- **Logging:**
  - `tracing` with `fmt` to stderr (`crates/iris-core/src/logging.rs:48-58`). Default filter `info` (`crates/iris-core/src/logging.rs:19`).
  - `rmcp` is capped at `warn` because it logs MCP messages that hold tokens (`crates/iris-core/src/logging.rs:1-5`, `:40-44`).
  - A refused agent token logs a warning at most once a minute, and the log never holds the token (`crates/iris-core/src/mcp/auth.rs:100-111`).

## 8. Differences from Cerberus defaults

| # | Cerberus default | Hermes (Iris) | Gap or note | Evidence |
|---|---|---|---|---|
| 1 | Workspace = tenant | No tenant. One process, one admin token. Owner id scopes agent apps only. | Gap. Iris gives no tenant pattern to copy. Cerberus needs the tenant column on every row and every query. | `config.rs:107-108`, `db/clients.rs:69-76`, `api/mod.rs:274-305` |
| 2 | Agent = client with API keys that have scopes | Two kinds. An agent owns apps and holds one agent token (MCP). A client is an app that sends notices with its own token. Neither has scopes. Each token works on one surface only. | Gap on scopes. Naming clash: Iris "agent" owns clients, while Cerberus "agent" is the client itself. | `docs/API.md:31-32`, `mcp/auth.rs:9-14`, `service/agents.rs:1-13` |
| 3 | Grant = permission on a set of items | No grants. Access = token kind + agent status + owner id. | Gap. Cerberus grants need a new table and check. Iris has no pattern to reuse. | `service/clients.rs:515-526`, `db/clients.rs:69-76` |
| 4 | Keys shown once, only hash stored | Matches for agent tokens and agent-owned client tokens. Does not match for env client tokens and the admin token, which are plain text in `iris.env`. | Gap. Plain text at rest. Mode `0600` helps. | `service/agents.rs:59-64`, `service/clients.rs:594-601`, `service/clients.rs:190-200`, `envfile.rs:126-128` |
| 5 | Keys hashed with a fast hash | Plain SHA-256 with no salt. Safe for random 256-bit tokens. Env tokens may be chosen by the user, and only a 16-char minimum is checked. | Risk. For Cerberus, use random keys only, or a slow hash for any user-chosen secret. | `auth.rs:24-27`, `config.rs:19-20`, `config.rs:213-216` |
| 6 | Every call has a request ID | No request ID anywhere. HTTP trace logs exist but no ID is shared with the caller. | Gap. | Section 4; `lib.rs:62`, `:90` |
| 7 | Every call has an audit event | Audit rows only for changes by admin, agent or system. Not for notice sends, reads or failed logins. Admin rows have no admin id. | Gap. | `service/audit.rs:41-77`, `service/mod.rs:40-44` |
| 8 | Error shape `{error:{code,message,request_id,retryable}}` | Shape is `{error:{code,message}}`. No `request_id`, no `retryable`. Retry info is the `Retry-After` header (HTTP) or `retry_after_secs` (MCP). | Gap on two fields. Easy to add in one place: `error.rs:124-134`. | `error.rs:124-134`, `mcp/errors.rs:4-9` |
| 9 | Not in the brief: key rotation | Client tokens rotate. Agent tokens cannot rotate. Admin token has no rotate route. | Note. Cerberus should decide whether agents rotate. | `api/mod.rs:287`, `mcp/tools.rs:548-561`, `docs/API.md:440` |
| 10 | Not in the brief: token expiry | No expiry for API tokens. Sessions last 30 days. | Note. | `auth.rs:18-19` |
| 11 | Not in the brief: config | Env file with `IRIS_` prefix, defaults in code, typed parse, startup checks. | Reusable style. | Section 5 |
| 12 | Not in the brief: tests | Black-box integration tests per feature, `ManualClock`, snake_case names. | Reusable style. | Section 6 |

## Reuse candidates

- Constant-time token lookup and hashing helpers (`crates/iris-core/src/auth.rs`).
- One error type with one `IntoResponse` (`crates/iris-core/src/error.rs`). Add `request_id` and `retryable` there.
- Single audit writer that logs and stores in one call, and never fails the caller (`crates/iris-core/src/service/audit.rs`).
- Env file writer with atomic replace and mode `0600` (`crates/iris-core/src/envfile.rs`).
- Startup refusal of placeholder secrets (`crates/iris-core/src/config.rs:22-40`).

## Not verified

- Cerberus defaults beyond the list in the brief (the Cerberus repo has only `LICENSE`).
- Whether CI runs `make check` (no `.github` folder found).
- UI test runner (`ui/package.json` not read).
- Runtime behavior. Nothing was run.
