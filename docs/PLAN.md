# PLAN: CERBERUS — A VAULT FOR AI AGENTS (Rust + Tauri)

## 0. Summary

Cerberus is a credential vault for AI agents.
A person unlocks the vault one time with a master phrase.
After that, agents ask for credentials through MCP or REST (HTTPS).

Example: the QA agent must test the frontend with Playwright.
It asks for "app shop-frontend, env staging, role admin".
It does not need to know the user name.
Cerberus finds the best item and returns it, or it asks the person for approval.

Cerberus stores:
- web logins (user + password + URL + optional TOTP seed)
- API keys
- SSH keys (with machine name, host, port, user, fingerprint)
- session tokens with a time to live (TTL), for example 60 minutes
- Playwright browser sessions (storage state)
- database URLs, cloud keys, certificates, notes

Name: **Cerberus**. The guard dog keeps the gate. Agents ask. The dog decides.

## 1. Important notes and decisions

### 1.1 Hermes reference repo
- T00 read the repo (see `docs/reference/hermes-patterns.md`). Hermes ("Iris") has no tenant model, no
  request IDs, no scopes. The default patterns below therefore stay as the decisions.

Default patterns:
- A **Workspace** is a tenant (an application or project).
- An **Agent** is a client. It has API keys. Each key has scopes.
- A **Grant** gives an agent a permission on a set of items.
- Keys are shown one time. The service stores only a hash.
- Every call has a request ID and an audit event.
- Errors use one JSON shape.

### 1.2 Decisions made by the planner
| # | Decision | Reason |
|---|----------|--------|
| D1 | The app is one Tauri v2 process. It holds the vault in memory and runs the HTTPS server. *Amended by ADR-0034: in remote mode the app holds no vault and runs no server; it is a client of `cerberusd`.* | One process keeps the keys in one place. |
| D2 | A headless daemon `cerberusd` uses the same library. | Servers without a screen need it. |
| D3 | Admin actions (create item, grant, approve) use Tauri IPC only. They are NOT on the network. *Amended by ADR-0034: a `cerberusd` whose owner turns on the opt-in admin API serves an allowlist of admin commands under `/admin/v1`, behind an enrolled client certificate and an operator session (DEC-RM-1 to DEC-RM-14, `docs/remote-mode-plan.md`).* | A smaller attack surface. |
| D4 | Agents use only the Agent API (HTTPS REST and MCP). | Agents must not manage the vault. |
| D5 | Item content AND item metadata are encrypted. Only ID, kind, expiry and timestamps are plain text. | A stolen DB file shows nothing. The sweeper can delete expired rows while the vault is locked. |
| D6 | Search runs on an in-memory index. It is built at unlock and erased at lock. | Search works on encrypted metadata. |
| D7 | Session TTL default is 60 minutes. The maximum is 24 hours. Both are settings. | "60 active" is read as 60 minutes. |
| D8 | When the vault is locked, the API returns HTTP 423 and no data. | Safe and clear for agents. |
| D9 | Several operators can have their own master phrase (key slots). Roles: owner, operator, viewer. | Multi-user. |
| D10 | The UI uses React + TypeScript + Vite + Tailwind + shadcn/ui. UI languages: English and Spanish. | Best fit for a modern UI in Tauri. |
| D11 | Rust edition 2024. Use the latest stable versions. Each agent checks versions on crates.io and in the docs. | Versions change. Do not guess them. |
| D12 | "Do not use unsafe" is a rule. Only the `memlock` module can use `unsafe`. | Memory safety. |

## 2. Technology stack

Backend (Rust):
- `tokio`, `axum`, `tower`, `tower-http`
- TLS: `rustls` (TLS 1.3 only) + `rcgen` for the local CA and leaf certificates
- Crypto: `argon2` (Argon2id), `chacha20poly1305` (XChaCha20-Poly1305), `hkdf`, `sha2`, `hmac`, `rand`/`getrandom`, `zeroize`, `secrecy`, `subtle`
- Memory lock: `memsec` or `region` (inside `memlock` only)
- Storage: `sqlx` with SQLite and migrations
- MCP: `rmcp` (official Rust SDK for MCP)
- API docs: `utoipa`
- TOTP: `totp-rs`. SSH keys: `ssh-key`.
- Quality: `tracing` (with redaction), `thiserror`, `proptest`, `cargo-fuzz`, `cargo-deny`, `cargo-audit`, `cargo-cyclonedx`
- Passphrase strength: `zxcvbn`. Word list: EFF large list (for Diceware).

Desktop and UI:
- Tauri v2 with `tauri-specta` (typed IPC), tray, single instance, autostart
- React, TypeScript, Vite, Tailwind, shadcn/ui, TanStack Query, Zustand, Framer Motion, Lucide icons
- Fonts: Geist (text) and Geist Mono (secrets). Superseded 2026-11-19 (0.3.0): this was Inter and JetBrains Mono until 0.2.0.
- Tests: Vitest, Playwright

## 3. Domain model

```
Vault (one file) ── KeySlot[]  (one per operator: owner | operator | viewer)
  └─ Workspace  (application / tenant, for example "shop-frontend")
       └─ Item
            id, workspace_id, kind, title, description,
            role_label   ("SAI user", "admin", "normal user", "read-only", custom),
            category, tags[], environment (dev | staging | prod | other),
            target (URL / host / app name), payload (typed, encrypted),
            expires_at?, max_uses?, version history, created_by (human | agent)
Agent ── AgentKey[]  (hash only, scopes, expiry, IP allowlist, last_used)
Grant  agent -> selector -> permissions -> mode -> conditions
Lease  short permission made by an approval (TTL)
AccessRequest  pending approval (agent, item, reason, TTL asked)
AuditEvent  hash chain; never contains a secret value
```

Item kinds: `web_login`, `api_key`, `ssh_key`, `session_token`, `browser_session`,
`database`, `cloud`, `certificate`, `env_bundle`, `note`.

Built-in categories: Web login, API key, SSH, Session, Database, Cloud,
Certificate, Other. The person can add more.

Grant fields:
- selector: workspace, environment, category, tags, kinds, role labels, item IDs
- permissions: `find`, `read`, `create_session`, `write`, `use_ssh`
- mode: `auto`, `ask_once` (lease), `ask_always`, `deny`
- conditions: time window, reads per hour, expiry, "reason required"
- rule: `prod` items use `ask_always` unless the owner changes it

## 4. Security design

### 4.1 Keys
- Master phrase → Argon2id → KEK. Default 256 MiB, t=3, p=4 if RAM is 4 GiB or more. Else 64 MiB.
  The app measures the time at creation. It tunes the cost to about 0.7 s. The cost is stored in the header.
- KEK wraps a random 256-bit Vault Master Key (VMK). One wrapped copy exists per key slot.
- VMK → HKDF-SHA256 → `item_kek`, `meta_key`, `audit_key`, `ca_key`.
- Each item has a random DEK. `item_kek` wraps it.
- Cipher: XChaCha20-Poly1305. The additional data (AAD) contains vault ID, item ID and version.
  This stops a copy of one ciphertext into another row.
- A recovery key (256-bit, Base32 groups) opens one extra key slot. It is shown one time.
- Change of phrase: the app wraps the VMK again. It does not encrypt the items again.

### 4.2 Memory and process
- Keys use `secrecy` and `zeroize`. The `Debug` output of a secret type prints `[REDACTED]`.
- Key pages use `mlock`. The process sets "no core dump" and "not dumpable".
- The vault locks on: manual lock, idle timeout (default 30 minutes), OS sleep or screen lock,
  quit, and panic. Lock erases keys and the search index.
- A "panic button" locks the vault and revokes all leases.
- Logs never contain secrets. A test checks this.

### 4.3 Transport
- HTTPS only. TLS 1.3 only. Plain HTTP is refused.
- Default bind: `127.0.0.1`. A LAN bind needs an owner action and mTLS.
- At first start, the app makes a local CA and a leaf certificate (`localhost`, `127.0.0.1`, `::1`, host name).
  The CA private key stays inside the vault.
- The app shows the certificate fingerprint. It exports the CA certificate for agents
  (for example `NODE_EXTRA_CA_CERTS`).
- The client SDK can pin the fingerprint.
- Optional: the owner can load his own certificate.

### 4.4 Agent authentication
- Token format: `cvt_<agent_id>.<256-bit random, base64url>`.
- The service stores SHA-256 of the secret part. It compares with constant time.
- Token checks work while the vault is locked. The result is then 423, not 401.
- Tokens have scopes, expiry, IP allowlist and rotation with overlap time.
- Rate limits per agent and per IP. Repeated failures cause a short lockout.
- Optional: mTLS client certificate as a second factor.

### 4.5 Storage
- SQLite with `secure_delete=ON`. The expiry sweeper deletes expired rows and runs `VACUUM` often.
- Backup file = a copy of the encrypted DB with its header. It is safe to store anywhere.
- The audit log is append-only. Each event has `prev_hash` and an HMAC (`audit_key`).
  The UI verifies the chain and shows "chain OK" or "chain broken".

### 4.6 Prompt-injection and agent abuse
- Policy depends on the agent identity. It never depends on the reason text.
- The UI shows the reason text as untrusted text.
- Responses for secrets carry `"handling": "secret — do not print or log"`.
- Env injection: `cerberus run --app shop --env staging --role admin -- <command>`
  puts the secret into the child process only. The agent never sees the value.

### 4.7 Tauri hardening
- Strict CSP. No remote content. No `shell` plugin. Minimum capabilities.
- Devtools are off in release builds.
- Each IPC command checks the window label.
- Optional "content protection" (no screenshots of secret screens).
- Clipboard clears after 30 seconds. A revealed secret hides after 15 seconds.

## 5. Interfaces

### 5.1 REST (Agent API, base `/v1`)
| Method + path | Use |
|---|---|
| `GET /health` | Service up. Shows locked or unlocked. No auth. |
| `POST /credentials/resolve` | Find the best item. Body: `app`, `environment?`, `role?`, `kind?`, `hint?`, `purpose`, `mode: "best" or "candidates"`. |
| `GET /credentials` | Catalog. Metadata only. No secret values. |
| `POST /credentials/{id}/reveal` | Return the secret. Creates a lease and an audit event. |
| `POST /credentials/{id}/totp` | Return the current TOTP code. The seed stays in the vault. |
| `POST /credentials` | Agent creates an item. Needs `write`. Optional `ttl_seconds`. |
| `POST /sessions` | Shortcut: save a session token with TTL (default 3600 s). |
| `DELETE /credentials/{id}` | Delete an item the agent created. |
| `GET /requests/{id}` | Poll an approval. SSE stream: `GET /requests/{id}/events`. |
| `POST /leases/{id}/release` | The agent gives back a lease. |

Resolve rules:
1. Remove items the agent cannot see (grants).
2. Score the rest: workspace match, environment, role label, kind, text match on title and description.
3. One confident match and `mode=best`: return the secret (or start approval).
4. Many matches: return candidates (ID, title, description, role). No secrets.
5. No match: return a clear 404 with hints.

Error JSON: `{ "error": { "code", "message", "request_id", "retryable" } }`.

### 5.2 MCP tools (HTTP at `/mcp`, and a stdio shim `cerberus-mcp`)
- `vault_status`
- `find_credentials` (like resolve with `candidates`)
- `get_credential` (resolve with `best`, or reveal by ID)
- `request_access` (reason, ttl; waits for the human or returns `pending`)
- `get_totp`
- `store_secret` (kind, title, description, value, ttl)
- `release_credential`
- `ssh_prepare` (returns an ssh-agent socket path; stretch task T22)
- MCP resource `cerberus://catalog` (metadata only)

## 6. Repository layout

```
cerberus/
  Cargo.toml                 (workspace)
  rust-toolchain.toml  deny.toml  justfile  .github/workflows/
  crates/
    cerberus-crypto/         key slots, KDF, AEAD, zeroize, memlock
    cerberus-store/          SQLite, migrations, encrypted repos, sweeper
    cerberus-core/           vault service, items, resolve, policy, leases, audit, agents
    cerberus-api/            axum REST, TLS, CA, rate limit, OpenAPI
    cerberus-mcp/            MCP server + stdio shim binary
    cerberus-client/         SDK (pinning) + CLI `cerberus` (incl. `run`)
    cerberusd/               headless daemon
    cerberus-ssh-agent/      ssh-agent bridge (T22)
  apps/desktop/
    src-tauri/               Tauri shell, IPC, tray
    ui/                      React app
  docs/  adr/  reference/  ux/  security/  guides/
  tests/e2e/
```

## 7. UX/UI requirements (for the UX/UI agent, T14)

Look and feel: professional, cool, modern, detailed, efficient.
- Dark first, with a light theme. A calm security feel. A strong brand idea (a three-ring gate motif).
  Do not use a generic template look.
- Secrets use the mono font. They are masked. Hold to reveal. Auto-hide.
- Keyboard first: a command palette (Ctrl/Cmd+K), shortcuts, focus rings.
- WCAG 2.2 AA. Respect reduced motion. Subtle motion only.
- Full empty, loading, error and locked states for each screen.
- Design tokens in JSON: color, type, space, radius, shadow, motion.

Screens:
1. **Create vault.** Steps: name, master phrase (strength meter, Diceware generator), recovery key (print, copy, confirm), KDF test.
2. **Unlock.** Calm, large. Shows failed attempts and a countdown after many failures.
3. **Dashboard.** Lock state with auto-lock countdown. Live agent feed. Pending approvals. Sessions that expire soon. Health: certificate expiry, KDF cost, audit chain.
4. **Vault browser.** Sidebar with workspaces, categories and tags. List and grid views. Filters (kind, environment, role). Badges for `prod`. TTL rings for session items. Detail drawer.
5. **Item editor.** One form for each kind. Role label chips ("admin", "normal user", "read-only", "SAI user", custom). Description. Environment. SSH key import and generate (ed25519). TOTP live preview. Password generator. Drag and drop for key files.
6. **Agents.** List, create, one-time token reveal, integration snippets (Claude Code MCP JSON, curl, env), last seen, rotate, revoke.
7. **Policies.** A visual grant builder in plain words: "Agent X can read items in workspace Y, env staging, category Web login, and I approve: never / once / always."
   A simulator: "What can agent X see?"
8. **Approval prompt.** A small always-on-top window and a tray badge. Shows agent, item, reason (untrusted), risk (prod), TTL options. Approve once, approve for 15 minutes, approve for the session, deny.
9. **Leases and sessions.** Active leases with revoke. A red "Lock and revoke all" button.
10. **Audit.** Timeline, filters, chain check badge, export.
11. **Settings.** Security (auto-lock, KDF, change phrase, operators, rotate recovery key), network (bind, port, fingerprint, CA export), appearance (theme, density, language), backup and restore, about.

## 8. Subagent roster

The orchestrator is the main agent. It starts the subagents, checks their work and keeps the task list.
Cost rule: the smallest agent that can do the task correctly does the task.

| Role | Agent type | Model | Used for |
|---|---|---|---|
| Scout | `Explore` | haiku | Read and search code. No writes. |
| Architect | `Plan` | opus | Design, ADRs, threat model. |
| Crypto Smith | `general-purpose` | opus | Crypto, key custody, policy engine. High risk. |
| Rust Builder | `general-purpose` | sonnet | Normal Rust work: storage, API, MCP, client. |
| Tauri Builder | `general-purpose` | sonnet | Tauri shell and IPC. |
| UX Designer | `general-purpose` (uses the `frontend-design` skill) | opus | UX/UI design and final polish. |
| UI Builder | `general-purpose` (uses the `frontend-design` skill) | sonnet | React screens. |
| Test Engineer | `general-purpose` | sonnet | Tests, fuzzing, vectors. |
| Auditor | `general-purpose` (fresh context) | opus | Security review. It did not write the code. |
| Scribe | `general-purpose` | haiku | Docs and simple files. |
| Janitor | `general-purpose` | haiku | Scaffold, config, formatting, simple tools. |
| Release Engineer | `general-purpose` | sonnet | CI, packaging, SBOM. |
| Verifier | `general-purpose` (fresh context) | sonnet | Final acceptance check. |

Note: the `Plan` type cannot write files. For Architect tasks that must write docs, use `general-purpose` on opus.

## 9. Rules for EVERY subagent

1. Work until your task is complete AND checked. Do not stop after a partial result.
2. If a detail is not clear, decide. Write the decision in `docs/decisions.md`. Continue.
3. Ask the orchestrator only if you need information that only the user has.
4. Check your work: build, run the tests, run `cargo clippy -D warnings`, run `cargo fmt --check`
   (and `tsc`, `eslint`, `vitest` for UI). Fix all errors.
5. Leave no `TODO`, no placeholder, no dead code, no `unwrap()` in non-test code.
6. Never write a secret in a log, an error message, a test name, or a file in the repo.
   Use fake test values only.
7. Use the latest stable crate and package versions. Check them first.
8. Keep your changes inside your task scope. Write a short report at the end:
   what you built, what you tested, what is left (must be "nothing"), and the decisions you made.
9. Write short, plain English in code comments and docs (ASD-STE100 style).

## 10. Tasks

Format: **Agent** (model) / **In** / **Out** / **After** / **Done when**.

### Phase 0 — Discovery and design
- **T00** Study the Hermes repo. Scout. Out: `docs/reference/hermes-patterns.md`. DONE.
- **T01** Architecture, ADRs, threat model, API contract. Architect (opus). In: this plan, T00 report.
  Out: `docs/adr/0001..00NN.md`, `docs/security/threat-model.md` (STRIDE table, assets, attackers),
  `docs/api/openapi-draft.yaml`, `docs/schema.sql` (draft), module interfaces (Rust trait signatures in `docs/`).
  Done when: each decision D1–D12 has an ADR; each threat has a control or accepted risk; each REST route and MCP tool has a schema.

### Phase 1 — Core
- **T02** Scaffold the workspace. Janitor (haiku). After T01. Out: Cargo workspace, empty crates that compile,
  `rust-toolchain.toml`, `deny.toml`, `justfile` (`just check`, `just test`, `just dev`), CI skeleton, `.editorconfig`,
  Tauri + Vite skeleton that starts. Done when: `just check` passes; desktop skeleton opens a window.
- **T03** Crypto crate. Crypto Smith (opus). After T01, T02. Out: `cerberus-crypto`: Argon2id with tuning, key slots
  (create, add, remove, rewrap), recovery key, HKDF key tree, XChaCha20-Poly1305 seal/open with AAD, secret types with
  redacted `Debug`, `memlock` module, zeroize on drop, zxcvbn check, Diceware generator. KAT + property tests.
- **T04** Storage crate. Rust Builder (sonnet). After T03. Out: `cerberus-store`: migrations, repositories (vault header,
  key slots, workspaces, items, versions, agents, keys, grants, leases, requests, audit), encrypted blob IO via T03,
  expiry sweeper, `secure_delete`, backup/restore, schema version check. Done when: DB file has no plain text of any
  secret or metadata; expired rows deleted while locked.
- **T05** Vault service (key custody). Crypto Smith (opus). After T03, T04. Out: in `cerberus-core`: state machine
  (Sealed, Unlocked, Locking), unlock by phrase or recovery key, attempt limits with back-off, idle auto-lock, OS lock
  callback hook, in-memory index, operator slots and roles, change phrase, rotate recovery key.
- **T06** Item kinds and resolve engine. Rust Builder (sonnet). After T04, T05. Out: typed payloads per kind, validation,
  versions, TTL and max_uses, TOTP, resolve scorer, candidate output without secrets. Done when: 40+ table cases pass.
- **T07** Policy, approval and lease engine. Crypto Smith (opus). After T04, T05. Out: grant evaluation (deny wins, then
  most specific), modes, conditions, `prod` default, approval queue with timeout, leases with TTL and revoke, simulator.
- **T08** Audit log. Rust Builder (sonnet). After T03, T04. Out: append-only writer, HMAC chain, verify (exact broken
  position), JSON-lines export, event catalog.
- **T09** Agent identity and token auth. Rust Builder (sonnet). After T04. Out: agent/key CRUD, token create (shown once),
  hash store, constant-time check, scopes, expiry, IP allowlist, rotation with overlap, rate limiter, failure lockout.

### Phase 2 — Interfaces
- **T10** HTTPS REST server. Rust Builder (sonnet). After T05–T09. Out: `cerberus-api`: local CA + leaf (rcgen), TLS 1.3,
  all Section 5.1 routes, 423 when locked, request IDs, security headers, body limits, rate limits, SSE, OpenAPI from code,
  cert export, optional mTLS.
- **T11** MCP server and stdio shim. Rust Builder (sonnet). After T10.
- **T12** Client SDK and CLI. Rust Builder (sonnet). After T10. `cerberus run -- env` injects into child only.
- **T13** Headless daemon. Janitor (haiku). After T10. `cerberusd`: config, TTY unlock, systemd unit, graceful shutdown.

### Phase 3 — Desktop app
- **T14** UX/UI design. UX Designer (opus). After T01. Out: `docs/ux/` brief, flows, IA, brand, `tokens.json`, components,
  states, motion, a11y, clickable HTML prototypes for screens 1–11. AA contrast.
- **T15** Tauri shell and IPC. Tauri Builder (sonnet). After T05, T07, T10.
- **T16** UI foundation. UI Builder (sonnet). After T14, T15.
- **T17** UI: create vault, unlock, settings (screens 1, 2, 11). After T16.
- **T18** UI: vault browser and item editor (screens 4, 5). After T16.
- **T19** UI: agents, policies, approvals, leases (screens 6, 7, 8, 9). After T16.
- **T20** UI: dashboard, audit, integration guide (screens 3, 10). After T16.
- **T21** UI polish. UX Designer (opus). After T17–T20.

### Phase 4 — Extras
- **T22** SSH agent bridge. Crypto Smith (opus). After T06, T07, T10.
- **T23** CSV import/export. Janitor (haiku). After T18.

### Phase 5 — Quality and release
- **T24** Test suite. Test Engineer (sonnet). After T10, T11, T12, T20, T22, T23. Scenarios A1–A12 pass; 90% coverage on crypto+core.
- **T25** Fuzzing and test vectors. Test Engineer (sonnet). After T03, T10.
- **T26** Security audit. Auditor (opus, fresh). After T21, T22, T24, T25. Out: `docs/security/audit-report.md`.
- **T27** Fix findings. Original author role. After T26. Auditor re-checks each fix.
- **T28** Documentation. Scribe (haiku). After T21, T22, T27.
- **T29** Packaging and CI/CD. Release Engineer (sonnet). After T27.
- **T30** Final acceptance check. Verifier (sonnet, fresh). After T27, T28, T29. Out: `docs/acceptance-report.md`.

## 11. Acceptance scenarios

| ID | Scenario | Pass when |
|----|----------|-----------|
| A1 | Create vault, lock, unlock. Try a wrong phrase. Use the recovery key. | Wrong phrase fails. Recovery key unlocks. |
| A2 | QA agent asks `resolve {app: "shop-frontend", environment: "staging", role: "admin"}`. | The agent gets user and password in one response. An audit event exists. |
| A3 | Agent stores a session token with `ttl_seconds: 3600`. | The item exists. After 3600 s (test clock) it is gone. |
| A4 | Agent asks for the SSH key of machine "build-01". | It gets the key, or a signing socket after T22. |
| A5 | The vault is locked. Agent calls any route. | HTTP 423. No data. |
| A6 | Agent asks for a `prod` item. | An approval window opens. Deny gives 403. Approve gives a lease. |
| A7 | Read the DB file as text. | No secret, no title, no description in plain text. |
| A8 | Connect with TLS 1.2. Connect with plain HTTP. | Both fail. |
| A9 | Change one audit row in the file. | Verify reports the broken position. |
| A10 | Revoke an agent key. | The next call returns 401 at once. |
| A11 | Agent without `write` stores a secret. | HTTP 403. |
| A12 | `cerberus run --app shop -- env`. | The child sees the variable. The agent output does not. |

## 12. Execution order (waves)

| Wave | Tasks |
|------|-------|
| 0 | T00 |
| 1 | T01 |
| 2 | T02, T14 |
| 3 | T03 |
| 4 | T04 |
| 5 | T05, T08, T09 |
| 6 | T06, T07 |
| 7 | T10 |
| 8 | T11, T12, T13, T15, T22 |
| 9 | T16 |
| 10 | T17, T18, T19, T20 |
| 11 | T21, T23 |
| 12 | T24, T25 |
| 13 | T26 |
| 14 | T27 |
| 15 | T28, T29 |
| 16 | T30 |

Orchestrator duties: keep the task list; give each subagent its task text, inputs and Section 9 rules; read each report;
run `just check` and `just test` after each wave; if a task fails, send it back to the same role; do not stop until T30 passes.

## 13. Definition of done

- All tasks T00–T30 complete and checked. All scenarios A1–A12 pass.
- `cargo clippy -D warnings`, `cargo fmt --check`, `cargo audit`, `cargo deny`, `tsc`, `eslint`, all tests pass.
- No `TODO` or placeholder in code, docs or this plan.
- The UI matches the design. The audit has no open medium or higher finding.

## 14. Risks and controls

| Risk | Control |
|------|---------|
| Prompt-injected agent asks for many secrets | Grants by agent identity, rate limits, `prod` approval, audit, panic button. |
| Stolen DB file | Encrypted items and metadata, Argon2id, AAD binding. |
| Weak master phrase | Strength meter, Diceware generator, minimum score. |
| Local malware reads memory | `mlock`, no core dump, short unlock time, auto-lock. Partly accepted. Document it. |
| Another local user uses the port | Token needed. Bind to `127.0.0.1`. Optional mTLS. |
| Secret in agent logs | `handling` flag, `cerberus run` env injection, SSH signing socket. |
| Lost phrase and recovery key | Data cannot be restored. State this clearly at creation and in the docs. |
| Crate or API changes | Check versions at the start of each task. Pin in `Cargo.lock`. |

## 15. Future ideas (not in scope now)

- Browser extension for the human operator. Hardware key (FIDO2 hmac-secret) as a key slot.
- Secret rotation hooks for cloud providers. Mobile app that approves requests by push.
