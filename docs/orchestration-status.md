# Orchestration status (handoff)

Last update: 2026-11-17 (session 2). BUILD COMPLETE: T27 (rounds A-H), T28, T29, T30 done. T30 verdict PASS (docs/acceptance-report.md). Open owner decisions: Spanish UI (D10/ADR-0010) not built; backup default file name doc mismatch; rename CERBERUS_URL in `cerberus run` child (Low). Committed and pushed to main.
Plan: `docs/PLAN.md`. Decision log: `docs/decisions.md`. Nothing is committed yet (all files untracked).

## Done and verified by the orchestrator
| Task | Result |
|---|---|
| T00 | `docs/reference/hermes-patterns.md`. Hermes has no tenant model, request IDs or scopes. Plan defaults stand. |
| T01 | 33 ADRs (`docs/adr/`), threat model, OpenAPI draft, MCP schemas, `docs/schema.sql`, `docs/interfaces.md`. |
| T02 | Workspace scaffold. `just check` and `just test` passed (orchestrator re-ran both, exit 0). |
| T03 | Crypto + types foundation. 92 crypto + 19 types tests pass; `just check`/`just test` exit 0 (orchestrator re-ran). Unsafe only in memlock. Fresh opus review: 0 crit/high/med, 2 low + 1 test gap -> fix agent running. |
| T04 | Store: 13+3 tests; `just check`/`just test` pass (orchestrator ran 12x). One unreproduced flaky failure under load avg 24 -> T24 must hunt it. RUSTSEC-2026-0459 ignored (sqlx 0.9 caps libsqlite3-sys <0.39); mitigation: refuse backups with -wal. Remove ignore when sqlx allows 0.39. |
| T05/T08/T09 | Vault service, audit chain, token auth. `just check`/`just test` exit 0 (orchestrator); 95 core tests; no non-test unwrap. Open: fresh review of T05+T09 running; wiring fix (atomic audit drain, integrity.row_mac_mismatch event) running. Rule: never hold vault state guard across long awaits. |
| T06/T07 + FIX5 | Items/resolve (50-case table), policy/approvals/leases (property tests), all 10 T05/T09 review findings fixed with fail-before/pass-after regressions. Combined tree: `just check`/`just test` exit 0, 210 core tests (orchestrator). Open: DEC-FIX5-4 role not bound into slot wrap AAD (format change) -> T26/T27. |
| WIRE6 | One Agent API facade (`VaultService::agent_api()`), admin methods for every IPC command (session role). 227 core tests incl. core-level A2-A6, A10, A11; `just check`/`just test` exit 0 (orchestrator). |
| T10 + FIX7 | HTTPS server (TLS 1.3 only, all routes, SSE, OpenAPI == draft, 48 api tests over real TLS incl. A2,A5,A6,A8,A10,A11). Review-2 findings (1 high, 3 med, 4 low) fixed with fail-before regressions; core 239 tests. CA material + auth-failure audit + leaf renewal added. `just check`/`just test` exit 0 (orchestrator). Open: host binaries must start `spawn_leaf_renewal`; owner custom cert (ADR-0023 p8) not built. |
| T14 | UX: docs, tokens, 11 prototypes. Orchestrator re-ran contrast (154 pairs, 0 fail); 204 screenshots; 0 axe issues; no remote content. |
| Wave 8 (T11,T12,T13,T15,T22) | MCP server + stdio shim, CLI client with CA pinning, cerberusd (MCP mounted, leaf renewal, rmcp=warn), Tauri shell (65 IPC commands, window guard, session role), SSH agent bridge. `just check`/`just test` exit 0 (orchestrator, 588 Rust tests). Non-test unwrap scan clean. Linux-only OS lock hooks (no unsafe FFI outside crypto). |
| T16 | UI foundation: tokens, shell, router guard, IPC wrapper + EventBridge, component library, palette, mock backend. tsc/eslint/vitest (47) pass (orchestrator). Screen folder convention DEC-T16-1. |
| FIX8 | Server sends [leaf, CA]; backup.restore audit; review M1 (restore locks old vault first, shutdown grace actually waits/cuts), M2 (ssh sign decrypt off the guard), L3 (held values tagged + cleared on lock), L4 (rate window carried). Accepted: ssh_prepare decrypts under guard (atomic, once per lease use). Full check pending T25. |
| T25 | 9 fuzz targets x 180 s, ~40M execs, 0 crashes; HMAC/SHA KATs; golden format + audit chain vectors; `just fuzz`, `just fuzz-smoke`. fuzz/ excluded from workspace. |
| FIX9 | Owner custom TLS cert (sealed in vault settings, live swap, renewal skips it, revert to local CA, audit). 6 real-TLS tests. |
| T17-T20 | All 11 screens built (create/unlock/settings, vault/editor, agents/policies/approval/leases, dashboard/audit/guide); ~150 screen tests + axe; screenshots in docs/ux/screenshots/t17..t20. Orchestrator: `just check` exit 0, Rust tests all pass, UI 199/200 on Node 22 (1 expected stale shell test -> INT10). |
| INT10 + T23 | 13 cross-screen fixes (edit keeps payload, no reveal; KDF/lock reason/fail count/audit outcome in IPC; routing; shared mocks; mTLS cert UI; Node 22 guard). CSV import (6 sources, preview, all-or-nothing) + export (owner, 0600, formula guard); csv_import fuzz 858k runs, 0 crash. Orchestrator: `just check`/`just test` exit 0, 647 Rust + 259 UI tests. T26 must check INT10 Keep rewriting the current version's history snapshot (DEC-INT10). |
| T21 | UI polish: drift fixed on all screens, axe 0 issues on 27 states, 136 final screenshots, polish-report.md. Backend asks -> T27: AccessRequestView item_kind/role_label; audit_query text filter. |
| T24 | Acceptance crate tests/acceptance a01..a12 all pass; coverage crypto 97.5%, core 92.1% (`just coverage` gate 90%); 4 flaky tests root-caused + fixed, 50/50 under load; T04 store flake not reproduced (600 runs). Orchestrator: check/test/acceptance/coverage all exit 0, UI 275 tests. Low race (repeat request_access during approve) -> T26 judge. |
| T26 | Audit report docs/security/audit-report.md: 0 crit, 0 high, 5 medium (AUD-1 audit head re-sign/truncation, AUD-2 items.kind no MAC, AUD-3 ssh_prepare bcrypt cost under guard, AUD-4 silent TLS conn no timeout, AUD-5 cerberus run env LD_PRELOAD), 20 low, 7 info. |

## Running (Wave 14 = T27) — STOPPED, resume here
State on disk at stop:
- T27-B: DONE except final gates (fixes AUD-4,5c,17,18,19,20,23,28,29,30 with tests; DEC-T27-B-1..11; notes in audit report). Its own crate tests + mcp passed; workspace gates not confirmed.
- T27-A2: fix notes for AUD-3,5,21,22,23,24,25 + DEC-T27-A2-*; check T21 asks (AccessRequestView item_kind/role_label, audit_query text filter) and its gates.
- T27-C: fix notes for AUD-10..16,24,30,31 + DEC-T27-C-*; check T21 UI asks (approval rows kind/role, audit search box) and its gates.
- T27-A1: IN PROGRESS, NOT DONE. No DEC-T27-A1 entries, no fix notes for AUD-1,2,6,7,8,9,26,27. Core currently fails clippy (`crates/cerberus-core/src/vault/checks.rs:183` collapsible if, 2 errors). Must finish: AUD-1 (audit head check before re-sign), AUD-2 (items.kind MAC + store migration + old-vault upgrade test), AUD-6,7,8,9, AUD-10 store part, AUD-26/27 docs.
Next steps:
1. New agent for T27-A1 (opus, same brief as before: read audit report, fail-before/pass-after test per finding, DEC-T27-A1-<n>, 'T27 fix' notes). Tell it to inspect disk state first.
2. Short check agents (or SendMessage-free new agents) for A2 and C to confirm their items + gates.
3. Orchestrator: just check, just test, just acceptance, just coverage.
4. Re-check by a fresh opus auditor: each T27 fix in docs/security/audit-report.md; must leave 0 open medium+.
5. Wave 15: T28 docs (haiku) + T29 packaging/CI (sonnet) in parallel. Wave 16: T30 final acceptance (fresh sonnet) -> docs/acceptance-report.md.
- Node: use Node 22 (`$HOME/.nvm/versions/node/v22.23.5/bin` first in PATH); /usr/bin/node 20 breaks vitest reporter. `.nvmrc` added.
- Flaky candidates for T24: cerberus-mcp `request_access_waits_then_returns_the_decided_request`, api `rate_limit_gives_429_with_retry_after`, client `a_failed_connect_is_retryable_for_every_call`, T04 store flake. All pass alone; fail under load ~20.
- MEMORY RULE (session 2): systemd-oomd killed the terminal 4x (user slice >50% pressure 20s) when several agents ran cargo at once. Now: .cargo/config.toml jobs=6, dev/test debug=line-tables-only, and only ONE agent runs cargo at a time.
- Session 2: F/G re-check (section 9): none Medium+. New lows NEW-11 (symlink vault / listing error -> empty vault), NEW-12 (successful-restore leftover counts as stranded, revives unrevoked keys), NEW-13 (auth.failed info loss, accepted), NEW-14 info. T29 DONE (ci.yml, release.yml, just package/package-binaries/sbom/checksums, packaging-and-release.md, DEC-T29-1..6; local deb/rpm/AppImage/tarball + SHA256SUMS ok; GH/macOS/Windows not run). Running: doc-drift fixer (sonnet medium, no cargo, guides only) and T27-H (opus, cargo: NEW-11, NEW-12, NEW-14a/b; no guide edits, reports wording). Then: apply H guide wording, gates incl coverage, T30 (fresh, high).
- Session 2: T27-G DONE (DEC-T27-G-1; stranded-vault guard + vault_recover_stranded + backup.recover event; agent gates check/test 0, UI 283). Running in parallel: fresh opus re-check of F+G (NO cargo, -> section 9 + doc drift list) and T29 (sonnet medium, sole cargo user). Then: fix doc drift/any finding, gates, T30.
- Session 2: T27-F DONE (DEC-T27-F-1..3). Orchestrator gates 0: 823 Rust + 280 UI, acceptance 12/12. T27-G (sonnet impl, high) running: startup must not create empty vault when only .pre-restore-* exists + recover command; also fixes CSV target wording in guides. Next: fresh opus re-check of F+G (read-only, no cargo) in parallel with T29 (sonnet, medium, sole cargo user), then T30.
- Session 2: T28 DONE (README + docs/guides/{user-guide,operator-guide,agent-integration,security-model,backup-and-restore,troubleshooting}.md, interfaces.md limits, ADR-0030 amendment; link check 81/0). TODO after T27-F: update CSV-target wording in guides (NEW-9 change); T30 should look at `cerberus run` setting CERBERUS_URL in child (same name CLI reads).
- Session 2: E re-check (section 8): NEW-5 closed; NO open Medium+ in whole report. New lows NEW-8 (auth.failed audit growth / raw-IP throttle), NEW-9 (CSV target keeps webhook path), NEW-10 (restore doesn't close store before swap -> likely flake cause; error branch may create empty vault). Running in parallel: T27-F (opus, cargo: NEW-10/8/9) and T28 docs (haiku, medium effort, NO cargo). Next: gates, short re-check of F, T29 (sonnet medium), T30.
- Session 2: T27-E DONE (DEC-T27-E-1..5). Orchestrator gates all 0: 810 Rust + 280 UI, acceptance 12/12, coverage 97.49/92.82. One-off flake seen by T27-E: desktop ops backup_and_restore_round_trip 'store error'. Fresh opus re-check of E running -> section 8 (also judges the flake).
- Session 2: D re-check (section 7): AUD-4, AUD-5 closed. NEW-5 MEDIUM open (bad-token per-IP lockout locks out loopback agents). Lows: NEW-6 (agent holds 256 conns via h2 window 0), NEW-3 residual (deleted parent row), AUD-25 variants, NEW-7 clamp panic. T27-E (opus) fixing all; then gates + fresh re-check (section 8).
- Session 2: T27-D2 DONE (DEC-T27-D2-1..2: header/auth/idle deadlines, unauth budget 64 + eviction, per-IP cap removed). Orchestrator gates all 0: 796 Rust + 280 UI, acceptance 12/12, coverage 97.49/92.71. Fresh opus re-check of D round running -> section 7.
- User decision (session 2): T28 and T29 implementers run at effort=medium (pass per launch); security fixes, reviewers and T30 stay high. Profiles unchanged.
- Session 2: T27-D1 DONE (DEC-T27-D1-1..4; agent gates check/test/acceptance exit 0; strict agent env allow rule, see its notes). T27-D2 (AUD-4 + NEW-1, cerberus-api) running. Then: orchestrator gates, fresh re-check of D fixes, T28/T29, T30.
- Session 2: re-audit (section 6 of audit-report): AUD-4 + AUD-5 still MEDIUM (partial). New lows NEW-1 (per-IP cap 64 cheaper loopback lockout), NEW-2 (verify stops at first mark), NEW-3 (bad lease row blocks revoke-all); AUD-25 worse than thought. T27-D1 (opus: AUD-5 allow rule, AUD-25, NEW-3, NEW-2) running; then T27-D2 (AUD-4 trickle/H2 PING + NEW-1, cerberus-api); then gates + re-check of D fixes.
- Session 2: T27-C gaps DONE (DEC-T27-C-10). Orchestrator gates all exit 0: check, test (776 Rust/54 suites + 280 UI), acceptance 12/12, coverage crypto 97.49% core 92.64%. Fresh opus re-auditor running -> writes section 6 in audit-report.md.
- Session 2: T27-A1 DONE (agent report: check/test/acceptance exit 0; DEC-T27-A1-1..9; AUD-26 accepted; open: AUD-30 store items, T28 must repeat AR-9 in operator guide). Next: C gap fixer resumed (alone), then orchestrator gates, then re-audit.
- Session 2: A2 confirmed done (reviewer). C confirmed done; a C gap-fix agent (restore rollback when open_service fails, picked-path clear test, content_protected(true) check, deterministic 2nd-restore test) was killed mid-work -> resume after A1.
- Lesson: never poll with `pgrep -f "<text>"` from a shell whose own command line contains that text, nor `pgrep -x cargo` (other agents/projects).

Decision-log IDs collided between parallel agents. From now on agents append entries as `DEC-T<task>-<n>` (e.g. DEC-T04-1). Old DEC-nnn IDs stay as they are.

## Old notes
**T03 — crypto crate (Crypto Smith, opus).**
- Files exist: `crates/cerberus-types/src/{clock,enums,error,ids}.rs`; `crates/cerberus-crypto/src/`
  `{envelope,error,kdf,keytree,mac,memlock,phrase,random,recovery,secret,slots,token}.rs`, tests `{kat,leaks,props,slots}.rs`, EFF wordlist.
- Last step in progress: the leak tests (Debug / format! / tracing / no Display).
- Not yet verified: build, tests, clippy, `just check`, `just test`. Treat all of it as unreviewed.
- Scope also includes the `cerberus-types` foundation (IDs, request ID, `Clock` + manual clock, clippy
  `disallowed-methods`, error codes + error shape) because T02 left that crate empty.

**T14 — UX/UI design (UX Designer, opus).**
- Files exist: all docs in `docs/ux/`, prototypes 01–11 + `index.html`, tokens, contrast/verify scripts.
- Screenshots exist for 01–05 and index only. Missing: screenshots for 06–11 and the light-theme run of all states.
- Last step in progress: a small i18n fix, then the final full verify run (light screenshots of all states, narrow check).
- Not yet verified by the orchestrator: contrast report results, axe check.

## Next
1. Resume T03 and T14 (new agents, same briefs, told to inspect disk state first).
2. Verify both. Run `just check` and `just test`.
3. Wave 4: T04 (storage). Then follow `docs/PLAN.md` section 12.
