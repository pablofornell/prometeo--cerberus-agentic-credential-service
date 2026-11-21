# Cerberus acceptance report (T30)

- Date: 2026-11-17
- Role: Verifier (fresh context; did not build any of this)
- Code state: working tree on `main` (commit `f729a30` plus untracked work). Nothing was edited except this file.
- Method: I read `docs/PLAN.md` (sections 10 to 14), `docs/orchestration-status.md` and `docs/security/audit-report.md`
  (sections 1 to 9 and every "T27" fix note). I ran every gate myself, one cargo/just command at a time, and read
  the code behind each acceptance scenario and each security claim.

## 1. Verdict

**PASS, with one deviation that the owner must accept or schedule (Spanish UI, section 7) and three Low documentation drifts.**

Every criterion of PLAN section 13 that can be checked on this machine is met:

- `just check`, `just test`, `just acceptance`, `just coverage` and `just fuzz-smoke` all exit 0.
- A1 to A12 pass, and I read each test: each one proves its "Pass when" text.
- No finding of Medium or higher is open. I confirmed this from the audit report (sections 6 to 9) and by reading the
  fix code for AUD-1 to AUD-5 and NEW-5.
- No `TODO`, `FIXME`, `todo!` or `unimplemented!` in code, docs or the plan.
- All deliverables of T00 to T29 exist. Packaging files in `dist/` match `SHA256SUMS`.

Nothing FAILS an explicit definition-of-done line. What I could not verify (CI on GitHub, macOS and Windows builds,
signing, the desktop window itself) is in section 9.

## 2. Definition of done (PLAN section 13)

| Criterion | Evidence | Result |
|---|---|---|
| All tasks T00 to T30 complete and checked | `docs/orchestration-status.md` lists T00 to T29 done and re-verified by the orchestrator. Deliverables re-checked by me in section 6. T30 is this report. | PASS |
| All scenarios A1 to A12 pass | `just acceptance`: 12 passed, 0 failed (section 3, 4) | PASS |
| `cargo clippy -D warnings` | `just check` exit 0 (clippy with `--workspace --all-targets -D warnings`) | PASS |
| `cargo fmt --check` | `just check` exit 0 | PASS |
| `cargo audit` | `just check` exit 0. 0 vulnerabilities. 7 allowed warnings, all "unmaintained" (chrono, paste, proc-macro-error, unsafe-libyaml, zbus_names, zvariant, zvariant_derive). 4 ignored advisories with reasons in `.cargo/audit.toml` | PASS |
| `cargo deny` | `just check`: "advisories ok, bans ok, licenses ok, sources ok" (only duplicate-crate warnings for `thiserror`) | PASS |
| `tsc`, `eslint` | `just check`: `tsc -b` clean, `eslint . --max-warnings 0` clean, tokens up to date | PASS |
| All tests pass | `just test`: 837 Rust tests passed, 0 failed, 1 ignored (a doc example in `cerberus-mcp/src/lib.rs`); 283 UI tests passed | PASS |
| Coverage gate (T24: 90% on crypto + core) | `just coverage`: crypto 97.54%, core 92.35% (both at least 90%) | PASS |
| No `TODO` or placeholder in code, docs or plan | Grep over `*.rs *.ts *.tsx *.md *.yml *.toml *.json *.sql justfile` (no `node_modules`, `target`, `dist`): no `TODO`, `FIXME`, `todo!(`, `unimplemented!`. The only "placeholder" hits are HTML input placeholders, a UI loading state, a generated window icon note in `docs/decisions.md`, a `mem::replace` comment, and the plan's own rule text | PASS |
| UI matches the design | 11 screens built (`apps/desktop/ui/src/screens/*`), tokens generated from `docs/ux/tokens.json` and checked by `pnpm lint`, axe 0 issues on 27 states and 136 final screenshots per `docs/ux/polish-report.md`. **Deviation:** English only, no Spanish catalog (section 7, item 1) | PASS with deviation |
| Audit has no open medium or higher finding | Audit report section 9: "Still open at Medium or higher (whole report): none". I spot-checked the code (section 5) | PASS |
| Unsafe only in `memlock` (D12) | Workspace `unsafe_code = "forbid"`; `cerberus-crypto` denies it and only `memlock/mod.rs` has `#![allow(unsafe_code)]` with the three `unsafe` blocks; `cerberus-ssh-agent` has `#![forbid(unsafe_code)]` | PASS |
| No `unwrap`/`expect`/`panic` in non-test code | Workspace lints `unwrap_used`, `expect_used`, `panic` are `deny` and clippy passes | PASS |
| Docs (T28), packaging and CI (T29) | Section 8 | PASS |

## 3. Gate results

Run on this machine in the foreground, one at a time, with Node 22 (`$HOME/.nvm/versions/node/v22.23.5/bin` first in PATH).

| Gate | Exit | Key numbers | Time |
|---|---|---|---|
| `just check` | 0 | fmt, clippy (all targets, `-D warnings`), deny, audit (1527 advisories loaded, 764 crates scanned), `deps-check` (ADR-0024 edges), `client-deps-check`, `tsc -b`, eslint, token check: all pass | 44 s |
| `just test` | 0 | 54 Rust test suites, **837 passed, 0 failed, 1 ignored**; UI vitest 23 files, **283 passed** | 3 min 30 s |
| `just acceptance` | 0 | 12 passed, 0 failed (`cerberus-acceptance`) | 34 s |
| `just coverage` | 0 | `cerberus-crypto` **97.54%**, `cerberus-core` **92.35%** lines; 471 tests ran under instrumentation, 0 failed | 39 s |
| `just fuzz-smoke` | 0 | 10 targets x 30 s on nightly: envelope_open, key_slot, recovery_parse, token_parse, rest_json, resolve_query, mcp_args, ssh_frames, phrase_policy, csv_import. "fuzz-smoke: no crash" | 7 min 19 s |
| Link check (`linkcheck.py` over `docs/guides/*.md` and `README.md`) | 0 | 83 relative links in 10 files, 0 problems | instant |
| `sha256sum --check SHA256SUMS` in `dist/` | 0 | 8 of 8 files OK | instant |

Notes: the `check` log shows `cargo audit` prints 7 "allowed warnings" (unmaintained crates). Under `informational_warnings =
["unmaintained"]` in `.cargo/audit.toml` they do not fail the run; "unsound" and "yanked" do fail it, and none are present.

## 4. Acceptance scenarios A1 to A12

All twelve tests are in `tests/acceptance/tests/acceptance.rs`. They use a real vault on a temporary directory, the real
TLS 1.3 server of `cerberus-api` with `/mcp` mounted, an HTTPS client, an MCP client, and the real `cerberus` binary (A12).
The clock is a `ManualClock`. I read all of the code (harness included for A9).

| ID | Scenario (plan) | Test | Proves it? | Result |
|---|---|---|---|---|
| A1 | Create vault, lock, unlock. Wrong phrase. Recovery key. | `a01_wrong_phrase_fails_and_the_recovery_key_unlocks` | Yes. Locks, checks `/v1/health` says `locked`, wrong phrase gives `BadCredentials` and the vault stays locked (423), right phrase unlocks, a random recovery key is refused, the real recovery key unlocks and the agent route answers 200. Vault creation is done by the shared `Env::new()` fixture | PASS |
| A2 | `resolve {shop-frontend, staging, admin}` gives user and password in one response; audit event exists | `a02_resolve_gives_user_and_password_in_one_response_and_audits` | Yes. REST `POST /v1/credentials/resolve` returns `secret.username` and `secret.password`, and one `item.reveal` audit row exists. The same over MCP `get_credential`, which makes a second row | PASS |
| A3 | Session token with `ttl_seconds: 3600` exists, and is gone after 3600 s (test clock) | `a03_session_with_ttl_is_gone_after_the_ttl` | Yes. `POST /v1/sessions` returns 201. At +3599 s the reveal gives 200 and the token; at +3600 s it gives 404 and the title is gone from the catalog. (The physical delete by the sweeper, also while sealed, is covered by `cerberus-store/tests/sweeper.rs`.) | PASS |
| A4 | Agent asks for the SSH key of "build-01": key or signing socket | `a04_ssh_key_of_build_01_gives_a_signing_socket` | Yes (the "socket after T22" option). Agent finds the machine by name over MCP, calls `ssh_prepare`, gets `outcome: ready` and a socket path, connects to the Unix socket, sends `REQUEST_IDENTITIES` and gets `IDENTITIES_ANSWER` with one key. The response holds no private key text. `cerberus-ssh-agent/tests/a4_sshd.rs` also runs a real `sshd` signing test. Unix only | PASS |
| A5 | Vault locked, any route: 423, no data | `a05_locked_vault_gives_423_and_no_data` | Yes. Five REST routes (status, catalog, resolve, reveal, create session) and MCP all give 423 `vault_locked`, and the body holds neither the password nor the user name. The token is valid, so this is the locked state, not 401 | PASS |
| A6 | `prod` item: approval opens; deny gives 403; approve gives a lease | `a06_prod_item_needs_approval_deny_gives_403_approve_gives_a_lease` | Yes. The first reveal gives 202 `pending` with no secret, the request is in the owner's pending list, `deny_request` then gives 403 `approval_denied`. For a second item `approve_request` then gives 200 with a `lease.id` and the secret. A third run goes over MCP with a waiting agent approved by a person. (The always-on-top window itself is a desktop UI; the test proves the pending queue that the window reads.) | PASS |
| A7 | Read the DB file as text: no secret, title or description | `a07_the_database_file_has_no_plaintext` | Yes. Creates an item with canary title, description, user and secret, uses it through the agent (so audit rows and leases exist), locks, then scans the raw bytes of `vault.cerberus`, `-wal` and `-shm` (over 4096 bytes read) for 7 needles. None found. `cerberus-store/tests/privacy.rs` adds store-level checks | PASS |
| A8 | TLS 1.2 fails. Plain HTTP fails. | `a08_tls12_and_plain_http_both_fail` | Yes. A TLS 1.2-only handshake fails, a TLS 1.3 handshake on the same port works (so the version is the cause). Plain `GET` bytes get no HTTP answer and the connection closes. A `reqwest` call to `http://` gives no success | PASS |
| A9 | Change one audit row in the file: verify reports the broken position | `a09_a_changed_audit_row_is_reported_at_its_position` | Yes. Verify is `Ok` first. The harness opens the vault file with raw SQLite, drops the two append-only triggers, and edits one real `audit_events` row (`occurred_at + 1`). Verify then returns `Broken { seq }` with `seq` equal to the edited row | PASS |
| A10 | Revoke an agent key: next call 401 at once | `a10_a_revoked_key_gives_401_on_the_next_call` | Yes. 200 before. After `revoke_agent_key`, `GET /v1/status` and resolve give 401 `unauthenticated` immediately, and a new MCP session with that token does not open | PASS |
| A11 | Agent without `write` stores a secret: 403 | `a11_an_agent_without_write_gets_403` | Yes. REST `POST /v1/credentials` gives 403 `forbidden`, nothing is stored (not in the catalog). MCP `store_secret` gives `forbidden` | PASS |
| A12 | `cerberus run --app shop -- env`: child sees the variable, agent output does not | `a12_the_child_sees_the_variable_and_the_agent_output_does_not` | Yes. Runs the real binary. The child writes `$CERBERUS_PASSWORD` to a file and equals the secret. stdout and stderr contain neither the password nor the user name; stdout has `CERBERUS_PASSWORD=[REDACTED]`; the agent token is not in the child output. Unix only | PASS |

The tests are strong. Two limits of what they prove, none of which fails the scenario text: A6 proves the approval queue
and the HTTP result, not the Tauri window (a UI matter, covered by UI tests); A3 uses reveal-gives-404 as the observable
"gone" after the TTL, while the physical row deletion is proven in the store tests.

## 5. Security status

### 5.1 Medium or higher

| ID | Original | Final status in the audit report | My code spot-check |
|---|---|---|---|
| AUD-1 audit head re-sign / truncation | Medium | closed (section 6) | `audit/writer.rs:247-314` `chain_position` checks head HMAC, newest row `seq` and entry hash before each append, and chains a break mark on a mismatch. Tests `aud1_*` pass inside the 837 |
| AUD-2 `items.kind` has no MAC | Medium | closed (section 6) | `index/meta.rs:247-270`: sealed kind must equal plain `items.kind`, a mismatch is `Corrupt`; legacy metadata only accepted when the authenticated payload agrees |
| AUD-3 `ssh_prepare` bcrypt cost under write guard | Medium | closed (section 6) | `MAX_SSH_KDF_ROUNDS = 1024` in `items/ssh.rs:29`, checked at import, validation, prepare and sign; decrypt after `drop(guard)` on `spawn_blocking` |
| AUD-4 silent TLS connection never times out | Medium | closed (section 7; residual NEW-6 Low) | `ApiLimits` defaults in `cerberus-api/src/config.rs:62-76`: header 10 s, auth 30 s, idle 60 s, 64 unauthenticated, 256 total, 32 per agent. Real-TLS tests `aud4_*` pass |
| AUD-5 `cerberus run` env hooks | Medium | closed (section 7) | `cerberus_types::env::{is_forbidden_env_name, is_agent_env_name_allowed}`, used by core on create and by `cerberus-client/src/run.rs:233-243` on every item not written by `operator:` |
| NEW-5 bad-token lockout locks out loopback agents | Medium (found in re-check) | closed (section 8) | `auth.rs` verifies the token before any source limit; the global lockout (100 in 300 s) applies to failing checks only. Test `new5_*` passes |

Section 9 of the audit report ends with "Still open at Medium or higher (whole report): none". The header of the report
(section 1) still says "That condition is not met"; it is the original T26 text, superseded by sections 6 to 9 (see
section 7, item 5).

One point of process: the T27-H fixes (NEW-11, NEW-12, NEW-14a, NEW-14b; all Low or Info) were written after the last
fresh re-check (section 9). Their tests are in the suite and pass (`t27h_*`, 9 tests in `just test`), and the guides
describe them, but no fresh auditor re-read the H code. They cannot change the Medium-or-higher result.

### 5.2 Open Low and Info items (known limitations)

Taken from the final state of the audit report (sections 6 to 9) and the guides' security-model section.

| ID | Sev | What is left |
|---|---|---|
| AUD-16 | Low, accepted | OS lock hooks are partial on Linux and missing on macOS and Windows (ADR-0026). Idle lock and manual lock still work |
| AUD-19 | Low, partial | On macOS and Windows the child of `cerberus run` can still read the parent's first environment, which holds `CERBERUS_TOKEN` when the token was given that way. Use a token file there. Linux is not dumpable |
| AUD-25 / NEW-9 | Low, accepted | CSV import `target` keeps scheme, host and port only. A dotted user name before a `/` (`https://abc.def/ghi@host/`) can still show `abc.def` |
| AUD-26 | Info, accepted | Operator role is not in the key-slot wrap AAD (AR-9): roles do not limit a person who can read the vault file |
| AUD-30 | Info | Audit prune is never called. The `.pre-migrate-vN` part is closed (DEC-RD-5): migration 0002 made it live, and an existing copy now gets a `-2`, `-3` ... sibling instead of blocking the open, so a failed migration can run again and an older backup restored after an upgrade opens |
| AUD-3 residual | Info | Each `ssh` sign of an encrypted key can use up to 1024 bcrypt rounds (about 6 s CPU) on the blocking pool. It does not stall the lock. No test drives a stored over-limit key through `ssh_prepare` |
| NEW-1 | Low, accepted | A local flood of plain TCP connects can evict unauthenticated connections of an agent during its handshake window |
| NEW-2 rest | Info | A second tail cut after an earlier break mark is not shown again by `verify_chain` (first mark returned); the writer's alert shows it |
| NEW-6 rest | Low | Six tokens can still fill the 192 authenticated slots; a refusal by the per-agent cap is not audited |
| NEW-7 rest | Info | A waiting connection can be evicted by the other listener |
| NEW-13 | Low, accepted | `auth.failed` rows do not name the agent or key that matched, and counts are not kept for a sealed-time flood |
| NEW-14 (c, d, e) | Info | An orphan `-wal` moved aside leaves a later roll-back `unavailable` until restart; `backup.recover` has no `target`; UI guard for stranded state is cosmetic (backend refuses anyway) |
| NEW-4 | Info | `panic = "abort"` in release also ends `cerberusd` and the API server on a panic (by design: a panic wipes keys) |
| RUSTSEC-2026-0459 | advisory, ignored | `libsqlite3-sys` 0.37 (crafted `-wal`). `sqlx` 0.9 caps the version below 0.38, fix is in 0.39. Partly mitigated (`-wal` header check before open, backups read `immutable`). Remove the ignore when sqlx allows 0.39 |
| RUSTSEC-2024-0429 | advisory, ignored | `glib` 0.18 `VariantStrIter` unsound; required by Tauri 2 / GTK3 on Linux; no Cerberus code uses it. Tauri and GTK paths were not audited (AR-16) |
| RUSTSEC-2023-0071, -2026-0387 | advisory, ignored | `rsa` and `crypto-bigint` 0.5 are in `Cargo.lock` only, not compiled (`cargo tree -i` prints nothing) |

### 5.3 The open question: `cerberus run` sets `CERBERUS_URL` in the child

**What the code does.** For a web login item, `cerberus run` sets `CERBERUS_URL` in the child to the login URL of the item
(`crates/cerberus-client/src/run.rs:257`, documented in `docs/guides/agent-integration.md:209`). The `cerberus` CLI reads
the same name for the URL of the Cerberus service (`crates/cerberus-client/src/config.rs:97`, and clap
`env = "CERBERUS_URL"` in `main.rs:34`). So a `cerberus` (or `cerberus-mcp`) started by the child would aim at the web
site.

**Is it a security problem?** I judge it **Low (hardening and robustness), not Medium**, for these reasons:

1. The client never trusts a public CA. `tls.rs` builds the verifier from the pinned certificate or the CA file only
   (`Trust::Pin`, `Trust::CaFile`, `Trust::CaFileAndPin`; roots are the pinned certificate alone for the pin modes).
   A web site's certificate will not chain to the Cerberus CA and will not match the pin, so the TLS handshake fails
   before any request or `Authorization` header is sent. The token is not sent to the web site.
2. `cerberus run` removes `CERBERUS_TOKEN` and `CERBERUS_TOKEN_FILE` from the child (`run.rs:713-714`) unless
   `--pass-token` is set, so by default a child CLI has no token source except the default file
   `~/.config/cerberus/token` (which still has to pass the pin check above).
3. `parse_base_url` refuses anything but `https`, so a login URL such as `http://...` cannot downgrade.
4. The child already holds the real secret (password) in its environment. Cerberus cannot stop a child from sending it
   anywhere (accepted risk AR-3), so redirecting a child CLI is not a new capability.

**Residual risk.** (a) If an operator points `CERBERUS_CA_FILE` at a system CA bundle with no pin, then a child CLI with a
token source (`--pass-token`, or a default token file) would trust a public site and send the agent token to the URL of
the item. That needs an unusual set-up plus a hostile item URL (an agent can create `web_login` items; resolve prefers
operator items since AUD-23). (b) Functional collision: a child script that runs `cerberus` itself fails with a
connect or pin error, because `CERBERUS_URL` is the login page. Suggested fix (not done, outside my scope): name the
variable `CERBERUS_LOGIN_URL`, or stop the client from reading `CERBERUS_URL` when it runs with `CERBERUS_USERNAME`
set, or have `run` also set `CERBERUS_URL` to the real service URL only with `--pass-token`.

## 6. Deliverables by task

Paths are relative to the repository root. "Present" means I listed the path or file; for code, I also ran the tests above.

| Task | Planned output | Path | Present |
|---|---|---|---|
| T00 | Hermes study | `docs/reference/hermes-patterns.md` | present |
| T01 | ADRs 0001 to 00NN (D1 to D12 each have one) | `docs/adr/0001` to `0033` + `README.md` (34 files); ADR-0001..0012 are D1..D12 | present |
| T01 | Threat model | `docs/security/threat-model.md` | present |
| T01 | API contract | `docs/api/openapi-draft.yaml`, `docs/api/mcp-tools.md` | present |
| T01 | Schema draft, interfaces | `docs/schema.sql`, `docs/interfaces.md` | present |
| T02 | Workspace, toolchain, deny, justfile | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `clippy.toml`, `justfile`, `.cargo/` | present |
| T02 | CI skeleton, editorconfig, Tauri + Vite skeleton | `.github/workflows/ci.yml`, `.editorconfig`, `.gitignore`, `.nvmrc`, `apps/desktop/src-tauri`, `apps/desktop/ui` | present |
| T03 | `cerberus-crypto` (+ `cerberus-types`) | `crates/cerberus-crypto` (kdf, slots, recovery, keytree, envelope, secret, phrase, memlock, EFF wordlist, vectors), `crates/cerberus-types` | present |
| T04 | `cerberus-store` (migrations, repos, sweeper, backup) | `crates/cerberus-store` (`migrations/0001_initial.sql`, `src/sweeper.rs`, `src/backup.rs`, tests) | present |
| T05 | Vault service, key custody | `crates/cerberus-core/src/vault/` (custody, autolock, backoff, ca), `index/` | present |
| T06 | Item kinds and resolve | `crates/cerberus-core/src/items/`, `resolve/` | present |
| T07 | Policy, approvals, leases | `crates/cerberus-core/src/policy/`, `approvals/`, `leases/` | present |
| T08 | Audit log | `crates/cerberus-core/src/audit/`, `docs/reference/audit-events.md` | present |
| T09 | Agent identity, token auth | `crates/cerberus-core/src/agents/`, `auth/` | present |
| T10 | HTTPS REST server | `crates/cerberus-api` (tls, server, routes, sse, openapi, idle, layers) | present |
| T11 | MCP server and stdio shim | `crates/cerberus-mcp` (`src/tools`, `src/shim.rs`, `src/main.rs`) | present |
| T12 | Client SDK and CLI | `crates/cerberus-client` (config, tls, run, `main.rs`) | present |
| T13 | Headless daemon, systemd unit | `crates/cerberusd`, `packaging/systemd/cerberusd.service`, `cerberusd.toml.example` | present |
| T14 | UX docs, tokens, prototypes 1 to 11 | `docs/ux/` (design-brief, user-flows, information-architecture, components, a11y-contrast-report, `tokens.json`, polish-report, `prototypes/01..11-*.html` + `index.html`, screenshots) | present |
| T15 | Tauri shell and IPC | `apps/desktop/src-tauri` (src, `capabilities/`, `permissions/`, `tauri.conf.json`, tests) | present |
| T16 | UI foundation | `apps/desktop/ui/src/{shell,ui,ipc,i18n,state,styles}` | present |
| T17 | Create vault, unlock, settings | `apps/desktop/ui/src/screens/{create,unlock,settings}` | present |
| T18 | Vault browser, item editor | `apps/desktop/ui/src/screens/{vault,editor}` | present |
| T19 | Agents, policies, approvals, leases | `apps/desktop/ui/src/screens/{agents,policies,approval,leases}` | present |
| T20 | Dashboard, audit, integration guide | `apps/desktop/ui/src/screens/{dashboard,audit}` (`ConnectGuide.tsx`) | present |
| T21 | UI polish | `docs/ux/polish-report.md`, `docs/ux/screenshots/final/` | present |
| T22 | SSH agent bridge | `crates/cerberus-ssh-agent` (+ tests `bridge.rs`, `a4_sshd.rs`) | present |
| T23 | CSV import and export | `crates/cerberus-core/src/csvio/` + desktop tests `csv.rs` + `fuzz/fuzz_targets/csv_import.rs` | present |
| T24 | Test suite, A1 to A12, 90% coverage | `tests/acceptance` (`Cargo.toml`, `tests/acceptance.rs`, `tests/harness/mod.rs`), `just acceptance`, `just coverage` | present |
| T25 | Fuzzing and vectors | `fuzz/` (10 targets in `fuzz/fuzz_targets`, `fuzz/corpus/<target>`), `crates/cerberus-crypto/tests/vectors*`, `crates/cerberus-core/tests/audit_vectors.rs`, `just fuzz`, `just fuzz-smoke` | present |
| T26 | Audit report | `docs/security/audit-report.md` (1161 lines, sections 1 to 9) | present |
| T27 | Fixes, fix notes, DEC entries | "T27 fix" notes in the audit report, `docs/decisions.md` (DEC-T27-*) | present |
| T28 | README and guides | `README.md`; `docs/guides/{user-guide,operator-guide,agent-integration,mcp-client-config,security-model,backup-and-restore,troubleshooting,cerberusd,packaging-and-release}.md` | present |
| T29 | CI, release, packaging, SBOM | `.github/workflows/{ci,release}.yml`; `justfile` recipes `package`, `package-binaries`, `sbom`, `checksums`; `packaging/`; `dist/` (section 8) | present |
| T30 | Acceptance report | `docs/acceptance-report.md` (this file) | present |

Note on layout: the plan section 6 lists `tests/e2e/`. The project made the acceptance suite the workspace crate
`tests/acceptance` instead (DEC-T24-1). That is a recorded decision, not a gap. The plan's stack list also mentions
Playwright for UI tests; the UI uses Vitest and axe, and `docs/ux/verify-prototypes.mjs` drives the prototypes. There is no
Playwright end-to-end run of the real desktop app.

## 7. Deviations and failures to report

Nothing fails a section 13 line item. These are the items a reviewer or the owner must see.

1. **Spanish UI is not delivered (plan decision D10, ADR-0010 item 3).** The plan and ADR-0010 say "UI languages: English
   and Spanish". The UI has only `apps/desktop/ui/src/i18n/en.ts`; there is no `es` catalog. The settings screen says
   "English is the only language in this version." (`screens/settings/messages.ts:201`), and DEC-T16-5 records that a
   second language was left for later. The T14 prototypes did cover Spanish (DEC-040). No guide or README tells a user
   this. This is the main gap between "the UI matches the design" and the shipped UI. **Owner action:** accept it as a
   known limitation (and say so in the README), or schedule an `es` catalog.
2. **UI stack differs from D10 and plan section 2.** DEC-T16-4 chose plain CSS on generated design tokens instead of
   Tailwind and shadcn/ui. `zustand`, `framer-motion` and `@playwright/test` are not dependencies in
   `apps/desktop/ui/package.json` (the app uses React Query, Radix Dialog, wouter and small own stores). Recorded and
   reasoned in decisions, no effect on security or tests. Info.
3. **README is stale about installers.** `README.md:12-13` says the Tauri bundle is off (`"active": false`) and "there are
   no installers yet". `tauri.conf.json` now has `"bundle": {"active": true, ...}` and T29 built a `.deb`, `.rpm`,
   `.AppImage` and a tarball in `dist/`. The README also does not link `docs/guides/packaging-and-release.md`. Low (docs).
4. **Backup file name in the guides does not match the UI.** `docs/guides/backup-and-restore.md:21` and ADR-0031 say the
   default is `cerberus-<vault short id>-<UTC date>.cerberus-backup`. The UI proposes `cerberus-<YYYY-MM-DD>.cerb`
   (`apps/desktop/ui/src/screens/settings/files.ts:3`; the command palette uses `cerberus-backup.cerb`). The `0600` mode in
   the guide is correct (`cerberus-store/src/fsutil.rs`). Low (docs).
5. **Audit report header is stale.** Section 1 of `docs/security/audit-report.md` still says the "no open medium"
   condition "is not met". Sections 6 to 9 supersede it and end with "none open". A one-line note at the top would avoid a
   misread. Info (docs).
6. **No fresh re-check of the T27-H code** (section 5.1). Low or Info scope only.

I also checked about twenty concrete guide claims against the code. All matched, apart from item 4 above:

| Claim (guide) | Code | Result |
|---|---|---|
| CLI exit codes 70 to 74 (`agent-integration.md`) | `cerberus-client/src/error.rs:106-124` | match |
| CLI flags `--show-secret --field --wait --var --no-mask --pass-token` | `cerberus-client/src/main.rs:101-194`; `cerberus --help` of the packaged binary lists status, find, get, store, totp, delete, run, completions | match |
| MCP wait: default 60 s, most 120 s | `cerberus-mcp/src/tools/mod.rs:24-26` | match |
| `ssh_prepare` TTL 60 to 86400 s | `cerberus-core/src/agent_api/ssh.rs:55,510` | match |
| `cerberus run` removes `CERBERUS_TOKEN` / `_FILE` from the child unless `--pass-token` | `cerberus-client/src/run.rs:710-714` | match |
| Env rules: agent items credential-shaped only; deny list for all | `cerberus-types/src/env.rs`, `run.rs:233-243` | match |
| Connection limits 256 / 64 / 32; deadlines 10, 30, 60 s; bodies 16 KiB and 1 MiB | `cerberus-api/src/config.rs:62-76` | match |
| Failed-token limits 30/s burst 60; per agent 20/s burst 40; global lockout 100 in 300 s | `cerberus-core/src/auth/limits.rs:56-63` | match |
| Unlock back-off `2^(n-5)`, up to 900 s | `cerberus-core/src/vault/backoff.rs:11-13` | match |
| Idle lock default 30 minutes, range 60 to 86400 s | `cerberus-core/src/vault/autolock.rs:22-26` | match |
| Backup needs a non-viewer role (Operator or owner); restore owner only | `admin/audit_ops.rs:57-58` | match |
| Backup file has mode `0600` | `cerberus-store/src/fsutil.rs:20-30` (`create_private_file`) | match |
| Restore refuses a symlinked vault; successful restore leaves `.replaced-<t>`, failed leaves `.pre-restore-<t>` | `cerberus-store/src/backup.rs:204,210,298` | match |
| `cerberusd` has only `serve`, `unlock`, `status` | `cerberusd --help` of the packaged binary | match |
| Default bind `127.0.0.1` port 7373; `https` required for `CERBERUS_URL` | `config.rs`, `parse_base_url` (`config.rs:152-163`) | match |
| `NEW-8` text: at most 20 `auth.failed` rows a minute | `security-model.md:132`, `operator-guide.md:169`, audit section 8 | match (the doc-drift items 1, 2, 3, 4, 5, 6, 7, 8 of audit section 9 are all fixed in the guides) |

## 8. Packaging and CI

| Item | Evidence | Result |
|---|---|---|
| `.github/workflows/ci.yml` | Parses (PyYAML). Jobs: fmt, clippy, deny, audit, deps, ui, test, acceptance, coverage, fuzz-smoke, cross-platform-build (macOS and Windows `cargo check`). Triggers: PR, push to main, weekly schedule, `workflow_call` | PASS |
| `.github/workflows/release.yml` | Parses. Tag trigger `v[0-9]+.[0-9]+.[0-9]+*`. Jobs: preflight (tag equals both versions), ci, linux, desktop (macOS, Windows; signing optional by secrets), publish (SHA256SUMS, provenance attestation, draft release) | PASS |
| Actions pinned by SHA | Every `uses:` is a 40-character commit SHA with a tag comment (9 distinct actions, none unpinned; the one local `./.github/workflows/ci.yml` call is exempt). I resolved each of the 9 SHAs on GitHub with `gh api repos/<r>/commits/<sha>`: all exist | PASS |
| Packaging recipes | `justfile`: `package`, `package-binaries`, `sbom`, `checksums`, `release-local`. `packaging/systemd/{cerberusd.service,cerberusd.toml.example}` | PASS |
| `dist/` artifacts | `Cerberus_0.1.0_amd64.deb` (13.8 MB), `Cerberus-0.1.0-1.x86_64.rpm`, `Cerberus_0.1.0_amd64.AppImage` (93 MB), `cerberus-0.1.0-x86_64-unknown-linux-gnu.tar.gz` (11.7 MB), 4 SBOMs, `SHA256SUMS`. `sha256sum --check`: 8 of 8 OK | PASS |
| SBOMs | All 4 are `CycloneDX` 1.5 (components: cerberus 135, cerberusd 358, cerberus-desktop 593, cerberus-mcp 348) | PASS |
| Tarball content and smoke | Holds `cerberus`, `cerberus-mcp`, `cerberusd`, `systemd/`, `README.md`, `LICENSE`. I unpacked it into an empty scratch folder: `cerberus --version` gives `0.1.0`, `--help` of `cerberus` and `cerberusd` work, `cerberus-mcp` refuses to start without a token ("no token: set CERBERUS_TOKEN or CERBERUS_TOKEN_FILE"). `systemd-analyze verify` only complains that `/usr/local/bin/cerberusd` is not installed here | PASS |
| `.deb` content | `usr/bin/cerberus-desktop`, `.desktop` entry, icons | PASS |
| `LICENSE` | Present (MIT); copied into the tarball by the recipe | PASS |
| Docs and links | `README.md` and 9 guides in `docs/guides/`; 83 relative links, 0 broken | PASS |

I did not rebuild the release bundles (`dist/` is present and verifies).

## 9. Not verified (honest limits of this check)

- **CI on GitHub was never run.** The workflows parse and their action pins resolve, but no run, no `cargo install` of
  `cargo-fuzz` / `tauri-cli` in CI, and no result from GitHub-hosted runners exists.
- **macOS and Windows were never built or run.** `cross-platform-build`, the `.dmg`, the NSIS installer, and the OS lock
  hooks for those systems (a known gap, AUD-16) are untested. `cerberusd`, A4 and A12 are Unix-only by design.
- **Signing and notarization were never exercised.** `release.yml` signs on macOS only if the Apple secrets exist; the
  Linux packages and the installers are unsigned. Integrity rests on `SHA256SUMS` and the keyless provenance
  attestation, neither of which has run.
- **The desktop window was not opened.** I had no display session in this check. The Tauri shell is covered by 70
  desktop Rust tests (IPC contract, window guard, restore) and 283 UI tests with axe, and the `.deb`/AppImage were
  built, but I did not start the app. The real webview and Tauri runtime are out of the audit scope (AR-16).
- **Coverage figures are line coverage of `cerberus-crypto` and `cerberus-core` only**, with `testkit.rs` and
  `regressions.rs` left out of the numbers (DEC-T24-6); other crates have no gate.
- **Fuzzing in this check was the 30 s smoke run** (10 targets, no crash). The 180 s per target campaign (about 40 M
  executions) is reported in the orchestration status, not re-run here.
- **Flaky tests.** `just test` passed on the first run here. Earlier notes list load-dependent flakes (fixed or not
  reproduced, DEC-T24 and T27-E). I ran the whole suite once, not repeatedly.

## 10. Known limitations to publish with the release

1. Spanish UI is not available (section 7, item 1); the UI is English only.
2. Loss of both the phrase and the recovery key means the data cannot be restored (by design, plan section 14).
3. Roles are not a crypto boundary against someone who can read the vault file (AR-9).
4. Local malware with the same OS account can read memory of an unlocked vault; mitigations are partial (plan section 14).
5. Lock-on-sleep and screen-lock hooks exist for Linux only; on macOS and Windows use the idle lock (AUD-16).
6. On macOS and Windows, give the agent token to `cerberus run` as a file, not as `CERBERUS_TOKEN` (AUD-19).
7. `cerberus run` sets `CERBERUS_URL` to the login URL of a web item in the child (section 5.3, Low).
8. Four advisories are ignored with reasons (`glib`, `libsqlite3-sys`, `rsa`, `crypto-bigint`) and 7 crates are
   "unmaintained" warnings (`chrono`, `paste`, `proc-macro-error`, `unsafe-libyaml`, `zbus_names`, `zvariant`,
   `zvariant_derive`). Revisit at each `sqlx` and Tauri upgrade.
9. Packages for macOS and Windows, signing, and GitHub CI are untested (section 9).
10. All other open Low and Info findings are in section 5.2.
