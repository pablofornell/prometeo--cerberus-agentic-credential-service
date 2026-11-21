# Decisions log

Running log of decisions that agents made where the plan was not clear (plan section 9, rule 2).
Large decisions have an ADR; this log points to it. Newest entries go at the end. Format:
`DEC-NNN — date — task — decision. Reason. (Where it is written.)`

## T01 — Architecture (2026-11-16)

- **DEC-001** — T01 — Hermes has no tenant model, request IDs or scopes (T00). The plan defaults stay: workspace = tenant,
  agent = client with scoped keys, grants, hash-only keys, request IDs, one error shape. (ADR-0004, ADR-0015, ADR-0016, ADR-0021)
- **DEC-002** — T01 — New crate `cerberus-types` for IDs, enums, `ErrorCode`, `Clock` and wire DTOs. The client SDK must
  share DTOs without pulling server code. (ADR-0024)
- **DEC-003** — T01 — Three REST routes added for parity with MCP: `GET /v1/status` (`vault_status`), `POST /v1/requests`
  (`request_access`), `POST /v1/credentials/{id}/ssh-prepare` (`ssh_prepare`, T22). Every MCP tool must have a REST route
  with the same core function. (ADR-0004, `docs/api/openapi-draft.yaml`)
- **DEC-004** — T01 — `/mcp` is at the root, not under `/v1`. While locked, the MCP transport stays up and tools return
  `vault_locked`; REST returns HTTP 423. MCP clients drop sessions on HTTP errors. (ADR-0008, ADR-0029)
- **DEC-005** — T01 — `cerberusd` is serve-only in v1: no admin surface; vault prepared on the desktop and restored on the
  server; `ask_*` grants give `403 approval_unavailable` there. Keeps D3 true everywhere. (ADR-0002)
- **DEC-006** — T01 — Operator labels and roles are plain in `key_slots` so the unlock screen can list operators.
  Accepted leak (AR-2). (ADR-0009)
- **DEC-007** — T01 — The operator ID is the ID of the operator's passphrase key slot. No separate operators table. (`docs/schema.sql`)
- **DEC-008** — T01 — Recovery key: 32 bytes + 3-byte SHA-256 checksum, Base32, `CRK1-` + 14 groups of 4; KEK by HKDF
  (no Argon2, 256-bit entropy). Typing errors do not count as failed unlocks. (ADR-0013)
- **DEC-009** — T01 — KDF parameter ranges are checked before use (m 19456..4194304 KiB, t 1..20, p 1..16). (ADR-0013)
- **DEC-010** — T01 — Phrase minimum: 12 characters and zxcvbn score ≥ 3, no override. Diceware default 7 words. (ADR-0013)
- **DEC-011** — T01 — HKDF labels `cerberus/v1/<name>`, salt = vault ID. Envelope `0x01 || nonce(24) || ct+tag`.
  AAD = length-prefixed fields. Plaintext padded to 64-byte blocks. JSON inside envelopes. (ADR-0014)
- **DEC-012** — T01 — Extra key `row_mac_key` and `row_mac` columns on `agents`, `agent_keys`, `leases`,
  `access_requests`; encrypted copies of `expires_at` for items and grants. Found by the threat model (T-5). (ADR-0033)
- **DEC-013** — T01 — All IDs are UUIDv7 text; vault ID is UUIDv4 bytes. Server makes every request ID and ignores
  incoming `X-Request-Id`. (ADR-0015)
- **DEC-014** — T01 — Token hash = SHA-256 with domain label, agent ID and secret. Every token failure (including IP
  allowlist and mTLS) gives the same `401`; the audit keeps the reason. Max 5 keys per agent. Key default life 90 days,
  rotation overlap default 24 h. (ADR-0016)
- **DEC-015** — T01 — Scope list: `status:read`, `catalog:read`, `secrets:read`, `secrets:write`, `sessions:write`,
  `requests`, `ssh:use`. Delete of session kinds needs `sessions:write`. (ADR-0016)
- **DEC-016** — T01 — Grant specificity weights: item_ids 64, workspace 16, environment 8, role_labels 4, kinds 2,
  categories 2, tags 1; tie → stricter mode → older grant. `read` and `use_ssh` imply `find`. The `prod` rule forces
  `ask_always` for `read`/`use_ssh` unless the owner sets `allow_prod_auto`. Mode matters only for `read`/`use_ssh`. (ADR-0017)
- **DEC-017** — T01 — Approval: timeout 120 s, max 5 pending per agent, dedupe, deny cool-down 600 s, options once (300 s,
  1 use) / 15 min / session (max 8 h). Lock cancels pending requests. The agent repeats the original call after approval;
  secrets never travel in request objects. (ADR-0018)
- **DEC-018** — T01 — `auto` reveals also create leases (default 900 s), so exposure is visible and the panic button
  covers it. Revoking an auto lease blocks new auto leases for that pair until the old expiry. Lock does not revoke
  leases; the panic button does. (ADR-0019)
- **DEC-019** — T01 — Resolve: app match 100 (workspace) or 60 (target); role exact/synonym +50, word overlap +20, no
  role match = removed; hint words +10 title (max 30), +5 others (max 20); confident when the only item or 25 points ahead;
  no environment guessing. (ADR-0020)
- **DEC-020** — T01 — Error code list fixed in ADR-0021. Optional `details` allows only `retry_after_seconds`, `fields`,
  `hints`, `request`. 423 has no `Retry-After`. (ADR-0021)
- **DEC-021** — T01 — Time crate is `jiff`; storage is Unix ms; `Clock` trait in `cerberus-types`; wall-clock calls
  banned by clippy `disallowed-methods` outside `SystemClock`. (ADR-0022)
- **DEC-022** — T01 — Default port 7373 on `127.0.0.1` and `::1`. ECDSA P-256 local CA (10 years) and leaf (90 days).
  Leaf key in a 0600 file outside the DB so TLS works while locked. Pin = SHA-256 of the CA SPKI. `Host` must be a SAN;
  `Origin` refused; no CORS. Max 256 concurrent connections. (ADR-0023)
- **DEC-023** — T01 — Audit bodies are encrypted; plain only seq, time and hashes. While locked, events go to
  `audit_pending` and join the chain at unlock. A secret read fails if its audit write fails; other actions only log the
  audit error. Export is offered before a prune. (ADR-0025)
- **DEC-024** — T01 — Idle lock counts agent API calls as activity (setting, default on), plus a hard limit of 12 h
  after unlock. Otherwise agents would get 423 30 minutes after the person stops typing. Release builds use
  `panic = "abort"` with a sync key wipe in the panic hook. (ADR-0026)
- **DEC-025** — T01 — Items are hard-deleted. Keep 10 versions (setting); session kinds keep 1. `max_uses` reached →
  item deleted after the response is built. Sweeper every 60 s, WAL checkpoint after deletes, full VACUUM at most once
  per day. Journal mode WAL. (ADR-0027, ADR-0013)
- **DEC-026** — T01 — `cerberus run`: default env names per kind, output masking on by default, `CERBERUS_TOKEN`
  removed from the child env, token never from argv, exit codes 70–74 for CLI errors, lease released at child exit. (ADR-0028)
- **DEC-027** — T01 — MCP results always have an `outcome` field (`secret`, `pending`, `candidates`, `ambiguous`,
  `code`, `ready`). Secret results start the text content with a handling line. `ssh_prepare` is not listed before T22.
  `store_secret` cannot store TOTP seeds (REST `POST /v1/credentials` can). (ADR-0029, `docs/api/mcp-tools.md`)
- **DEC-028** — T01 — Rate limits: IP 30/s burst 60; agent 20/s burst 40; secret reads 60/min; distinct items 30/h with
  a dashboard alert; auth failures 10 per 5 min → 300 s lockout. In memory (`governor`). (ADR-0030)
- **DEC-029** — T01 — Backups use `VACUUM INTO`, exclude the TLS leaf key, and restore revokes all leases and cancels
  requests. The pre-restore file is kept. (ADR-0031)
- **DEC-030** — T01 — Memory lock crate `region` (updated 2026) instead of `memsec` (last release 2024). Process hardening
  also lives in `memlock`. (ADR-0011, ADR-0012)
- **DEC-031** — T01 — Client HTTP crate `reqwest` 0.13 with rustls only; the client parses SSE itself (no extra SSE
  crate; the SSE crates on crates.io had no release since 2022–2024). (`docs/interfaces.md` section 7)
- **DEC-032** — T01 — Every timestamp field in `utoipa` schemas needs `value_type = String, format = DateTime`
  because `utoipa` has no built-in `jiff` support. (`docs/interfaces.md` section 1.1)
- **DEC-033** — T01 — Agent-created items of non-session kinds may have `ttl_seconds` 60..31,536,000 or no expiry.
  Session kinds always expire (DB CHECK). (ADR-0007, `docs/schema.sql`)
- **DEC-034** — T01 — T29 is expected to add `npm audit`, SBOM and signed release artifacts with checksums; the threat
  model (T-11) relies on them. (`docs/security/threat-model.md`)

## T14 — UX/UI design (2026-11-16)

- **DEC-035** — T14 — Create-vault steps are Name → Master phrase → Unlock cost test → Recovery key (plan section 7 lists
  the recovery key before the KDF test). `vault_create` needs the KDF params and returns the recovery key, so the test
  must come first. (`docs/ux/user-flows.md` F1)
- **DEC-036** — T14 — Interface gap for T15: the recovery key (create, `recovery_rotate`) and a new agent token need a
  copy with the 30 s clipboard clear, but `clipboard_copy_secret` takes an `item_id`. T15 adds a command (for example
  `clipboard_copy_once { kind }` that copies the last one-time value held in the backend) or extends the existing one.
  Until then the UI offers Print / Save to file first. (`docs/ux/information-architecture.md` section 3)
- **DEC-037** — T14 — Grant modes use plain words in the UI: never = `auto`, once = `ask_once`, always = `ask_always`,
  block it = `deny`. Approval options: Approve once = `once`, For 15 minutes = `minutes15`, For this session = `session`.
  (`docs/ux/components.md`, prototype 07 and 08)
- **DEC-038** — T14 — Hold times: reveal a secret 500 ms, keyboard approve 600 ms (ADR-0018), panic confirm 1000 ms.
  Pointer clicks on approval choices act at once (ADR-0018 asks for the hold on keys only). `D` denies without a hold
  because deny is the safe side. (`docs/ux/tokens.json` motion.hold)
- **DEC-039** — T14 — Brand color is brass (`#E0AE55` dark, `#875800` text / `#93610A` button in light) for the gate
  motif and primary actions; red is kept for `prod`, danger and integrity only. Dark theme is the default; "System"
  is a setting option. (`docs/ux/design-brief.md`, `docs/ux/tokens.json`)
- **DEC-040** — T14 — Spanish copy uses "tú" and neutral vocabulary. Wire values (`prod`, `staging`, role labels sent by
  agents, scope names) and user data (item titles, agent names) are not translated. (`docs/ux/design-brief.md` section 6)
- **DEC-041** — T14 — Fonts are vendored as WOFF2 (Inter and JetBrains Mono, SIL OFL 1.1, from `@fontsource-variable`
  5.3.0, latin + latin-ext only). T16 copies them into the app bundle. (`docs/ux/prototypes/assets/fonts/`)
  Superseded 2026-11-19 (0.3.0): Geist + Geist Mono (SIL OFL 1.1, same `@fontsource-variable` source, latin + latin-ext).
- **DEC-042** — T14 — Settings "empty" state = defaults on a new vault (no backup yet, only one owner) with a prompt to
  add a backup and a second owner; the other screens have a true empty list state. (`docs/ux/information-architecture.md` section 4)

## T02 — Workspace scaffold (2026-11-16)

- **DEC-035** — T02 — `cerberus-types` has no code yet. T01 left docs only and no `crates/` existed, so the crate is a scaffold
  (doc comment and `VERSION` only). The `Clock` trait and DTOs (ADR-0022, ADR-0024) are the first work of the next crate task.
  (`crates/cerberus-types/src/lib.rs`)
- **DEC-036** — T02 — Rust is pinned to `1.100.0` as ADR-0011 says, not a floating `stable` as the T02 brief said. ADR wins. (`rust-toolchain.toml`)
- **DEC-037** — T02 — Lint policy lives in `[workspace.lints]`, not in a `#![forbid(...)]` attribute per crate as ADR-0024 point 6
  says. Same effect, one place to change. `cerberus-crypto` copies the lint table and sets `unsafe_code = "deny"` (ADR-0012),
  because Cargo rejects overrides on top of `lints.workspace = true`. (`Cargo.toml`, `crates/cerberus-crypto/Cargo.toml`)
- **DEC-038** — T02 — TypeScript is `6.0.3`, not `7.0.2` as ADR-0010 says. `typescript-eslint` 8.72.2 declares a peer range of
  `typescript <6.1.0`, so TypeScript 7 would break ESLint. Revisit when typescript-eslint supports 7. (`apps/desktop/ui/package.json`)
- **DEC-039** — T02 — `jsdom` is `27.4.0`, not `31.0.1`. jsdom 31 needs Node 22.22+. Vitest 5.1.0 declares `^22.12`, but the
  smoke suite passes on Node 20.20.2 (this machine). CI uses Node 22. UI `engines` is `>=20.19.0`, the floor that Vite 8 and
  jsdom 27 both support. (`apps/desktop/ui/package.json`)
- **DEC-040** — T02 — `cargo audit` ignores `RUSTSEC-2024-0429` (glib 0.18 `VariantStrIter` unsound). Tauri 2 on Linux needs the
  GTK3 binding stack, and glib 0.18 is the only line it uses. No patched version exists on that line. Cerberus does not call
  `VariantStrIter`. Re-check on every Tauri upgrade. (`justfile`, recipe `audit`)
- **DEC-041** — T02 — `cargo-deny` setup: `unmaintained = "workspace"` (Tauri's GTK3 crates are transitive and would fail the check),
  `multiple-versions = "warn"` (Tauri pulls duplicate platform crates), license allowlist limited to permissive licenses and MPL-2.0
  (for `cssparser`, a transitive Tauri dependency). Unused allowances were removed. Add a license only when a dependency needs it. (`deny.toml`)
- **DEC-042** — T02 — `just deps-check` implements ADR-0024 rule 5 with `cargo metadata` and `jq`. A negative test (a forbidden
  edge `cerberus-client -> cerberus-crypto`) failed the check, then the edge was removed. (`justfile`)
- **DEC-043** — T02 — Scaffold bins are stubs. `cerberusd` prints its version. `cerberus-desktop` opens the window. ADR-0024 wants
  bins for `cerberus-mcp` and `cerberus-client` too. Those come with T11 and T12, so only libs exist for now.
- **DEC-044** — T02 — Tauri CSP: production allows only `'self'` and IPC. The dev CSP adds `'unsafe-inline'` for styles
  (Vite HMR) and `ws://localhost:1420` (HMR socket). Bundling is off (`bundle.active = false`); packaging and signing belong to T29.
  The window icon is a generated placeholder. The brand icon belongs to T14. (`apps/desktop/src-tauri/tauri.conf.json`)
- **DEC-045** — T02 — `tauri::Builder::run` returns a `Result`. The app prints the error and exits 1, because `expect`, `unwrap` and
  `panic` are denied in workspace lints. (`apps/desktop/src-tauri/src/main.rs`)
- **DEC-046** — T02 — Not added yet: `clippy.toml` with `disallowed-methods` for wall-clock calls (ADR-0022 point 3), `tests/e2e/`,
  `rustfmt.toml` (defaults are fine), and an `@tauri-apps/api` dependency (no IPC until T15). Each comes with the task that needs it.
- **DEC-047** — T02 — CI (`.github/workflows/ci.yml`) runs one job per check on `ubuntu-24.04`, each calling a `just` recipe. Actions are pinned to
  the latest release tags seen on GitHub on 2026-11-16 (checkout v7.0.1, setup-node v7.1.0, pnpm/action-setup v6.1.1, taiki-e/install-action v2.90.5).
  Pinning to commit SHAs is a Release Engineer task (T29).
- **DEC-048** — T02 — Resolved versions in `Cargo.lock`: tauri 2.12.6, tauri-build 2.7.5 (ADR-0011 listed 2.12.5 and 2.7.4; the
  requirement `2.12.5` resolves to the newest 2.12.x). Rust `1.100.0`. Node 20.20.2 locally, Node 22 in CI.

## T03 — Crypto crate and `cerberus-types` foundation (2026-11-16)

- **DEC-049** — T03 — `argon2` feature `parallel` (adds `rayon`, `rayon-core`, `crossbeam-deque`, `crossbeam-epoch`). The p = 4
  lanes then run on threads, so the same 0.7 s buys more work: measured on this machine (release, 16 GiB) the tuning picks
  256 MiB t = 5 (0.61 s) instead of t = 2 (0.85 s). The output is the same (RFC 9106 KAT passes). (`Cargo.toml`)
- **DEC-050** — T03 — `KdfParams` fields are private. `KdfParams::new(m, t, p)` is the only constructor for values from a file
  and always applies the ADR-0013 range, in every build. Fast test costs (64 KiB, t 1, p 1) come only from
  `KdfParams::insecure_fast_for_tests()`, which exists only under `cfg(test)` or feature `insecure-test-kdf`; a release build
  with that feature fails to compile, and `new` refuses those values even in test builds. Other crates enable the feature
  only in `[dev-dependencies]`. The fast values are below the `key_slots` CHECK ranges, so storage tests (T04, T05) use the
  floor `KdfParams::new(19_456, 1, 1)` (about 0.3 s per derive in a debug build). (`crates/cerberus-crypto/src/kdf.rs`)
- **DEC-051** — T03 — Changes to `docs/interfaces.md` section 2, kept because they are safer or simpler:
  `Key32::from_bytes` returns `Key32` (it cannot fail; memory lock is best effort). `CryptoError` has no `MemLock`
  (a failed lock is not an error: `Key32::is_locked()` and `memlock::lock_failed()` report it, ADR-0012 point 6) and adds
  `WeakPhrase` and `SlotRule`. `HardeningReport` adds `crash_dialog_off` (Windows). New: `KeySlot`, `KeySlotSet`
  (create, add, remove, set role, set/rotate recovery, rewrap, change phrase, unlock), `Vmk::same_key`, `meets_phrase_policy`,
  `total_ram_bytes`, `LockedBox::new_with` / `try_new_with` (write keys in place). (`crates/cerberus-crypto/src/lib.rs`)
- **DEC-052** — T03 — Slot rules in `KeySlotSet`: at least one owner passphrase slot (the recovery slot does not count),
  at most one recovery slot, the recovery slot has role owner and cannot change role or be rewrapped with a phrase, IDs unique.
  `create_passphrase_slot` itself refuses a phrase under 12 characters or zxcvbn score < 3 (`WeakPhrase`), so no caller can
  skip the policy (DEC-010). Characters are counted after NFKC. (`crates/cerberus-crypto/src/slots.rs`)
- **DEC-053** — T03 — Total RAM is read on Linux only (`rustix::system::sysinfo`, no unsafe). Elsewhere `total_ram_bytes()`
  is `None` and the caller passes `u64::MAX`, so tuning starts at 256 MiB; the halving step (ADR-0013 step 3) still covers
  slow machines. (`crates/cerberus-crypto/src/kdf.rs`)
- **DEC-054** — T03 — `length_prefixed`: a part of 65535 bytes or more is written as `0xFFFF || u64 BE length || bytes`, so the
  encoding stays unambiguous. The ADRs only define u16 lengths; no version 1 input is that long. (`crates/cerberus-crypto/src/mac.rs`)
- **DEC-055** — T03 — Header MAC: each field is length-prefixed; per slot the KDF numbers are one field `0x00` (none) or `0x01`
  followed by `m_cost_kib`, `t_cost`, `p_cost` (u32 BE each). Slots are sorted by ID bytes (same order as the text IDs).
  `argon2_version` is not in the MAC: the schema CHECK fixes it to 19. Row MAC follows ADR-0033 exactly (marker byte, then the
  length-prefixed value; INTEGER as i64 BE). (`crates/cerberus-crypto/src/mac.rs`)
- **DEC-056** — T03 — The `allow(unsafe_code)` is an inner attribute at the top of `memlock/mod.rs`, not on the `mod` line in
  `lib.rs` (ADR-0012 point 2). Same effect, and the ADR-0012 point 5 grep then matches only files under `memlock/`. `memlock`
  keeps a per-page count, because one `munlock` would unlock a page for every key on it. On Linux, `ptrace_denied` is true when
  the process is not dumpable (the kernel then refuses same-UID attach). (`crates/cerberus-crypto/src/memlock/mod.rs`)
- **DEC-057** — T03 — `cerberus-types` adds `Stopwatch` (monotonic time, for the KDF cost test); `clippy.toml` bans
  `Instant::now` too, and only `Stopwatch::start` and `SystemClock::now` carry an `#[allow]`. IDs parse only the canonical
  lower-case hyphenated form. `ErrorCode::default_message` gives the fixed messages. `ApprovalOption::Minutes15` is
  `minutes_15` on the wire, as in `docs/schema.sql`. `WireSecret`, `HANDLING_SECRET` and the wire DTOs are not added here;
  they come with the API task. (`crates/cerberus-types/src/`)
- **DEC-058** — T03 — Recovery key parse accepts the text with or without the `CRK1` prefix. Agent token parse is strict:
  canonical agent ID and canonical Base64url trailing bits, so one token has one text form. (`recovery.rs`, `token.rs`)
- **DEC-059** — T03 — Internal workspace dependencies name a version next to the path
  (`cerberus-types = { path = "...", version = "0.1.0" }`). `cargo deny` (`wildcards = "deny"`) treats a bare path dependency
  as a wildcard. This keeps `deny.toml` unchanged. Later tasks add their internal crates the same way. (`Cargo.toml`)

## T14 — UX/UI design, resumed (2026-11-17)

Note: the first T14 run used DEC-035 to DEC-042, and T02 used the same numbers. The T14 entries keep their numbers
and the "T14" tag tells them apart. T03 was adding entries at the same time, so these new T14 entries start at DEC-070.

- **DEC-070** — T14 — The prototypes are checked at 390 px wide, although the `main` window has a minimum of
  960 × 640. The approval window is 400 px wide, and a narrow layout keeps the shell sound when the user zooms text
  to 200 %. All app screens now fit with no sideways scroll. (`docs/ux/prototypes/assets/app.css`)
- **DEC-071** — T14 — `verify-prototypes.mjs` is the single check for the prototypes: screenshots of every state in
  both themes, every variant and dialog, narrow width, axe-core, Spanish coverage (states and variants), no network
  and 11 scripted keyboard checks. A partial run (`--only`, `--shots` …) overwrites the report, so the last run must
  be the full one. (`docs/ux/verify-prototypes.mjs`, `docs/ux/screenshots/verify-report.json`)
- **DEC-072** — T14 — Health rows link with a verb that says where they go ("Open settings"), not "Fix", because the
  fix happens on another screen. (`docs/ux/prototypes/03-dashboard.html`)

## T03 — security review fixes (2026-11-17)

- **DEC-073** — T03 — KDF read-path cap. A vault file can carry any cost inside the ADR-0013 range (up to 4 GiB, t = 20), so
  an edited header could force an out-of-memory or very slow unlock. The cap lives in the key derivation
  (`KdfParams::argon2`, so `derive_passphrase_kek` and every slot open): `m_cost` must be at most half of
  `total_ram_bytes()` (not checked when the RAM size is unknown) and `t_cost` at most the tuning maximum, 10. A value above
  the cap gives `CryptoError::InvalidKdfParams`. `KdfParams::new` is unchanged: it stays a pure range check that does not
  depend on the machine, so a vault made on a big machine can still be read and rewrapped on a small one by code that only
  parses the header, and tests do not depend on the host RAM. Tuned costs never reach the cap (m <= 256 MiB when RAM >= 4
  GiB, 64 MiB otherwise, t <= 10). Same review: `RecoveryKey::parse` writes the key straight into locked memory (no plain
  `[u8; 32]` copy on the stack), and the header MAC test now changes every MAC field one at a time.
  (`crates/cerberus-crypto/src/kdf.rs`, `recovery.rs`, `secret.rs`, `mac.rs`)

## T04 — Storage crate `cerberus-store` (2026-11-17)

- **DEC-T04-1** — T04 — Versions checked on crates.io on 2026-11-17: `sqlx` 0.9.0 (features `runtime-tokio`, `sqlite`, `migrate`,
  `macros`; bundled SQLite), `ipnet` 2.12.2, `tokio` 1.54.1, `tempfile` 3.27.0. `insecure-test-kdf` is only in `[dev-dependencies]`.
  (`Cargo.toml`, `crates/cerberus-store/Cargo.toml`)
- **DEC-T04-2** — T04 — Migration 0001 is `docs/schema.sql` with two fixes: `access_requests.decided_by` and `leases.request_id` lose
  their foreign keys with `ON DELETE SET NULL`. That action would change a MAC-covered column without a new MAC and break
  the row MAC (ADR-0033). The IDs now stay as dangling references, which is also better for audit. The migration sets
  `application_id` and `user_version` itself. `docs/schema.sql` was left unchanged (outside T04 scope); the migration is the source of truth.
  (`crates/cerberus-store/migrations/0001_initial.sql`)
- **DEC-T04-3** — T04 — Interface changes to `docs/interfaces.md` section 3: (a) the store keeps no key, but ships helpers on the
  caller's keys: `Blobs` (one seal/open pair per ADR-0014 purpose, so AAD is built in one place), `RowMacs` (make and verify the four
  row MACs), `header_mac` / `verify_header_mac`. (b) `revoke_all_leases` and `cancel_pending_requests` take `&RowMacs`, because
  changing `revoked_at` or `status` needs a new row MAC. (c) `StoreError` adds `Crypto(CryptoError)`; engine constraint errors map to
  `Conflict`, `RowNotFound` to `NotFound`. (d) New reads: `item`, `lease`, `pending_access_requests`, `setting`, `settings`, `tls_ca`.
  (e) New `restore_backup(backup, vault_path, clock)` and `Store::inspect_backup` (ADR-0031 steps 1, 4, file swap).
  (f) `schema_version()` and `APPLICATION_ID` are exported.
- **DEC-T04-4** — T04 — `Store::open` probes the file through a read-only connection first, so a file that is not ours is never
  switched to WAL or written. It migrates on open (no key is needed for structure) and writes `<file>.pre-migrate-v<N>` with
  `VACUUM INTO` before migrating an older schema. A newer schema gives `TooNew`. This replaces "migrated after unlock" of ADR-0013.
- **DEC-T04-5** — T04 — The sweeper writes an `item.expire` row to `audit_pending` in the same transaction that deletes the item,
  locked or not. The vault service drains `audit_pending` into the chain (ADR-0025). This loses no event and the store needs no
  lock state. Finished requests are deleted 7 days after `decided_at` (or `expires_at`); a `pending` request is deleted 7 days after
  its expiry (the sweeper has no key, so it cannot mark it `expired`). Full `VACUUM` runs at most once in 24 h after a delete;
  `spawn` sends a report only when a sweep did something. (`crates/cerberus-store/src/sweeper.rs`)
- **DEC-T04-6** — T04 — Items and grants whose plain `expires_at` has passed are hidden in every store read (`item`, `item_version`,
  `load_all_for_index`) by the store's `Clock`, before the sweeper runs (ADR-0027: invisible at once).
- **DEC-T04-7** — T04 — Write transactions use `BEGIN IMMEDIATE` to avoid lock-upgrade `SQLITE_BUSY` in WAL mode; busy timeout 5 s;
  pool of 4 connections. `ca.key` AAD record ID is the fixed text `tls_ca` (ADR-0014 gives none).
- **DEC-T04-8** — T04 — `cargo deny` and `cargo audit` ignore RUSTSEC-2026-0459 (bundled SQLite < 3.54 can return stale memory when a
  database opens with a crafted `-wal` file of another page size). `sqlx-sqlite` 0.9.0 (latest) allows `libsqlite3-sys` below 0.38 only;
  the fix is in 0.39. Mitigation: Cerberus opens only its own vault file, and `Store::inspect_backup` refuses a backup with a sibling
  `-wal` file. Remove the ignore when sqlx allows 0.39. This edits `deny.toml` and `justfile`, outside the T04 paths, because the
  check cannot pass otherwise. (`deny.toml`, `justfile`, `crates/cerberus-store/src/backup.rs`)
- **DEC-T08-1** — T08 — Event names follow ADR-0025, not the informal plan names (`item.read` is `item.reveal`, `request.timeout` is
  `request.expire`, `unlock.fail` is `vault.unlock_failed`). Added: `workspace.*` (target kind `workspace`) and `audit.pending_overflow`
  (written at drain when the locked list overflowed; `details.dropped` holds the count). The catalog is the `EventType` enum in
  `crates/cerberus-core/src/audit/catalog.rs`; a test checks `docs/reference/audit-events.md` lists every type.
- **DEC-T08-2** — T08 — The writer needs the whole `Arc<KeyTree>`: `audit_key` for the chain and `meta_key` for the sealed bodies
  (`Blobs`). `AuditWriter::new(store, keys, vault_id, clock)`. Dropping the writer drops its share; the key is erased when the last
  share is dropped, so T05 must not keep other `Arc` clones after lock. Appends are serialized by one async mutex; the head is read
  from the store inside it. `head_hmac` = HMAC(audit_key, lp("cerberus/v1/audit-head") || lp(last_seq) || last_entry_hash ||
  lp(anchor_seq) || anchor_prev_hash), with the label and u64 values length-prefixed (ADR-0025 does not give the exact encoding).
  Times are cut to whole milliseconds before hashing, so stored and hashed values agree.
- **DEC-T08-3** — T08 — Verify order: head HMAC, then per row gap (`MissingRow` at the expected `seq`), `prev_hash`, HMAC, body
  decrypt, then head against the last row. A cut tail reports `HeadMismatch` at the first missing `seq`. An empty log is
  `Ok { count: 0, first_seq: 0, last_seq: 0 }`. `prune` verifies first and returns `CoreError::Corrupt` on a broken chain, so a prune
  cannot launder a break; it always keeps the newest row and writes `audit.prune`. `export_jsonl` writes `audit.export` after it.
- **DEC-T08-4** — T08 — Drain: `Store::take_audit_pending` clears the list in its own transaction (the in-transaction version is
  `pub(crate)` in the store), then all events are chained in one transaction. On failure the rows are pushed back. A crash between
  the two steps can lose pending events. Closed by DEC-WIRE-1 (drain inside the append transaction).
- **DEC-T08-5** — T08 — `cerberus-core` gains `tokio` and `tracing` as dependencies and `sqlx` as a dev-dependency (tests change
  rows around the append-only triggers on a raw connection).

## T09 — Agent identity and token auth (2026-11-17)

- **DEC-T09-1** — T09 — `AuthFailure` has two more variants than `docs/interfaces.md` section 4: `RateLimited { retry_after_seconds }` and
  `LockedOut { retry_after_seconds }`, so `AuthTable::check` returns every outcome in one `Result`. `AuthFailure::outward()` gives the
  caller error: all credential failures are `CoreError::BadCredentials` (one `401`, DEC-014), rate limit is `CoreError::RateLimited`, a
  lockout is `CoreError::UnlockBackoff` (it maps to wire code `too_many_failures`; `CoreError` has no better variant and T05 owns it).
  `AuthFailure::reason()` gives the short text for the audit event. (`crates/cerberus-core/src/auth.rs`)
- **DEC-T09-2** — T09 — Own token-bucket limiter, no `governor` dependency. It is ~100 lines, takes time from the `now` the caller passes
  (from the `Clock`), so tests use `ManualClock` and never sleep, and it avoids a new dependency to audit. Same GCRA-like behaviour as
  ADR-0030: per-IP 30/s burst 60 (before auth), per-agent 20/s burst 40 (after a good token, so an attacker cannot drain a victim's
  bucket), 10 failures per 5 min per IP gives a 300 s lockout (a locked IP is refused even with a good token). Rate-limited calls are not
  counted as failures. IPv6 addresses share one key per /64. Idle map entries are dropped when a map passes 4096 entries.
  The other ADR-0030 limits (secret reads, distinct items, access requests, grant reads) belong to later tasks. (`auth/limits.rs`)
- **DEC-T09-3** — T09 — Constant work. Every well-formed token is hashed once and compared with exactly `KEY_SLOTS` (10) slots with no
  early exit; unused slots (and unknown agents) compare against a dummy all-zero hash. The table keeps revoked and expired keys, so the
  audit can say "revoked" or "expired"; when an agent passes 10 keys, dead keys are dropped first (oldest first), then the oldest live
  ones. Max 5 live keys per agent is enforced at create and rotate. A malformed token returns before hashing (nothing secret to protect).
  The structural test counts the comparisons through a test hook; a wall-clock test only guards against a gross difference.
- **DEC-T09-4** — T09 — "Delete agent" is `AgentStatus::Revoked`, which is final and also revokes every key in the same transaction.
  `cerberus-store` has no agent row delete and T09 does not edit it. The encrypted name stays, which keeps the audit trail readable.
  `set_agent_status(Revoked)` and `delete_agent` do the same; a revoked agent cannot be renamed, re-activated or given keys (`Conflict`).
- **DEC-T09-5** — T09 — `agent_keys` has `CHECK (require_mtls = 0 OR client_cert_sha256 IS NOT NULL)`, so a key cannot start with
  `require_mtls`. `AgentKeyInput.require_mtls = true` is refused (`Validation`); `AgentService::bind_client_cert(key, sha256)` sets both
  together (the IPC `agent_issue_client_cert` calls it after it makes the certificate). Rotation copies the binding.
- **DEC-T09-6** — T09 — Key lifetime: `lifetime_days = None` means no expiry and needs the owner role; `Some(1..=365)` otherwise (the UI
  pre-fills 90, ADR-0016). Empty `scopes` means the four default scopes; scopes are sorted and de-duplicated. IP allowlist max 32 entries.
  Rotation: the new key copies scopes, allowlist and mTLS binding, and gets the same lifetime as the old key (counted from now; none for
  a no-expiry key, which then needs the owner). The old key ends at `min(old expiry, now + overlap)`; overlap 0 to 7 days.
  Roles: viewer lists; operator and owner change.
- **DEC-T09-7** — T09 — Integrity. `AuthTable::rebuild(agents, keys, Some(&RowMacs), now)` returns the `IntegrityIssue`s (table, row ID)
  for T05 to raise `IntegrityAlert` and the audit event. A bad agent row loads as `Revoked`; a bad key row loads revoked
  (`revoked_at` = its `created_at` if empty). `rebuild(.., None, ..)` is for the sealed vault (rows as stored, ADR-0033 item 5).
  `list_agents` shows bad rows the same way. Every change through `AgentService` refuses a row with a bad MAC (`Corrupt`) instead of
  re-signing it, so tampering cannot be healed by accident.
- **DEC-T09-8** — T09 — New dependencies of `cerberus-core`: `ipnet`, `jiff`, `serde`, `serde_json` (versions are the workspace ones,
  checked by T04 on 2026-11-17); dev: `tempfile`, `tokio` (`macros`, `rt-multi-thread`). The table is updated after the DB commit and
  before the call returns (no await between), so a revoke is visible to the next check. `last_used_at` is not written here; the caller
  uses `Tx::touch_agent_key` (not in the row MAC, works while locked).

## T05 — Vault service, key custody (2026-11-17)

- **DEC-T05-1** — T05 — `Store::initialize` needs the `tls_ca` row, and the CA key must be sealed with `ca_key`, which exists
  only inside `create_vault`. Certificate code belongs to the API layer (`rcgen`, ADR-0023). So `CoreConfig` carries
  `ca_issuer: Arc<dyn CaIssuer>`; `create_vault` calls it, seals the key and drops it. `CoreConfig::desktop(data_dir, issuer)` gives
  the desktop defaults. The `host_names` of `NewVault` are stored sealed in setting `tls_host_names` (JSON list) for the leaf.
  (`crates/cerberus-core/src/vault/ca.rs`, `events.rs`, `custody.rs`)
- **DEC-T05-2** — T05 — DEC-073 follow-up: `InvalidKdfParams` from a key derivation maps to the new `CoreError::UnsupportedKdfCost`
  (wire code `unavailable`), never to `BadCredentials`, and it does not count as a failed unlock. The same variant is used when a new
  slot (create, add operator, phrase change) asks for a capped cost. (`error.rs`, `vault/custody.rs`)
- **DEC-T05-3** — T05 — Lock: a lock request sets the state flag to `Locking` and bumps a lock epoch, then waits for the write lock of
  the fair `tokio` `RwLock`. In-flight calls finish; there is no "cut after 2 s" (ADR-0026), because a borrowed read guard cannot be
  taken away safely. Rule for later tasks: never hold the state guard across a long await (SSE streams, approval waits). An unlock
  that started before a lock request does not install its keys (`Locked`). Lock always ends `Sealed`, also when a clean-up step fails.
- **DEC-T05-4** — T05 — Failed unlock counting: a wrong phrase, a wrong recovery key, an unknown or removed operator ID and a missing
  recovery slot all count (the last two without running the KDF). Recovery key typing errors never reach the service
  (`RecoveryKey::parse`). A wrong current phrase in `change_phrase` gives `BadCredentials` and does not count. During back-off the KDF
  does not run, also for the right phrase. A failed unlock writes `vault.unlock_failed` to `audit_pending`.
- **DEC-T05-5** — T05 — Role checks use the role of the unlocked session, not `OperatorContext.role`; a context whose `operator_id`
  is not the session's gives `Forbidden`. Demoting oneself (allowed when another owner exists) changes the session role at once.
- **DEC-T05-6** — T05 — Operator rules: labels 1..64 characters and unique among operators; an owner cannot remove the own slot
  (`Conflict`); the last owner cannot be removed or demoted (`Conflict`); the recovery slot is not an operator (`NotFound`).
  `add_operator` has no KDF argument in the interface, so the new slot gets the cost of the caller's slot (after a recovery unlock:
  the first owner slot). `change_phrase_with_kdf` can set a new cost (IPC `phrase_change { kdf? }`).
- **DEC-T05-7** — T05 — `change_phrase` checks that the current phrase opens the same VMK as the one in memory (`Vmk::same_key`), then
  wraps the VMK in memory again. After a recovery unlock, `change_phrase` gives `Conflict` (that slot has no phrase); the owner uses
  the new `reset_phrase_after_recovery(ctx, operator, new, kdf?)`, allowed only in a recovery session (ADR-0009 point 4).
- **DEC-T05-8** — T05 — Lock settings are four sealed settings rows with JSON values: `idle_lock_seconds` (60..86400 or `null` = off),
  `max_unlocked_seconds` (900..604800 or `null`), `lock_on_os_lock`, `agent_activity_keeps_unlocked`. Missing rows use the defaults
  (`CoreConfig.idle_lock_default`, `None` = off; 12 h; on; on). A row that fails to open gives the default and an integrity alert.
  Read: any role; write: operator or owner (ADR-0009 lists them as not owner-only). They are cached in atomics, so
  `note_agent_activity` and `on_os_event` stay sync.
- **DEC-T05-9** — T05 — Index (ADR-0006, structure only): `ItemMeta`, `WorkspaceMeta` and `CreatedBy` live in `cerberus_core::index`
  for now (T06 may move them to `items`), with `Zeroizing<String>` text and `Debug` that shows IDs only. JSON inside `items.meta_ct`:
  `workspace_id, title, description, role_label, category, tags, environment, target, created_by, max_uses, use_count,
  expires_at_ms, has_totp` (unknown fields refused); inside `workspaces.meta_ct`: `slug, name, description, aliases`. The effective
  expiry is the earlier of the plain and the sealed value (ADR-0033 point 6). Grants are kept as opened JSON bodies (`GrantEntry`)
  for T07 to parse. `normalize` and `words` return `Zeroizing` text (interfaces said `String`). A row that fails to open or parse is
  left out with an `IntegrityAlert`. Agent metadata is not indexed (T09 reads it).
- **DEC-T05-10** — T05 — Every lock cancels pending access requests (new row MACs) and writes `vault.lock` (`details.reason`, actor
  system). The panic button also revokes all leases (`revoked_by` = operator ID) and writes `vault.panic`. Panic while sealed gives
  `Locked`. `emergency_wipe` uses `try_write`: if a call holds the state, the keys go with the aborting process (accepted).
  `on_os_event` marks `Locking` at once and locks in a task; without a tokio runtime it wipes synchronously.
- **DEC-T05-11** — T05 — Integration: the audit writer lives inside the unlocked state and shares its `Arc<KeyTree>`, so lock drops
  both. Unlock drains `audit_pending` into the chain. The token table is rebuilt without MAC checks at open and with MAC checks at
  unlock (bad rows count as revoked, `IntegrityAlert`). It is not cleared at lock: it holds no secret, and keeping the verified
  table keeps bad rows disabled while sealed. The audit catalog has no `integrity.row_mac_mismatch` type yet (ADR-0033 point 5), so
  only the event is sent.
- **DEC-T05-12** — T05 — `create_vault` never fails after `Store::initialize` wrote the file (a failed host-name write is logged),
  so the recovery key cannot get lost. `spawn_background` starts the idle check (5 s) and the expiry sweeper (60 s), whose reports
  remove expired items from the index. Approval expiry and audit prune loops belong to T07 and T08.

## Wiring fixes after Wave 5 (2026-11-17)

- **DEC-WIRE-1** — Wave 5 — Closes the open gap of DEC-T08-4. `Tx::take_audit_pending` is now `pub`, and `AuditWriter::drain_pending`
  takes the pending rows and chains them inside one transaction (`BEGIN IMMEDIATE`, take, append, commit). An error or a crash
  before the commit rolls back the take: the rows and the overflow counter stay pending and the chain is unchanged, so the put-back
  code is gone. `Store::take_audit_pending` stays for callers that only read the list (own transaction, not crash-safe).
- **DEC-WIRE-2** — Wave 5 — New catalog event `integrity.row_mac_mismatch` (target kind none; `target.kind` is the table and
  `target.id` the row; actor system; result `vault_corrupt`; no details). `rebuild_auth_verified` writes one per `IntegrityIssue`
  from `AuthTable::rebuild`, next to the `IntegrityAlert` UI event (ADR-0033 point 5; closes the note in DEC-T05-11). It runs before
  the pending drain in the unlock sequence, so these events come before the drained `recorded_while_locked` ones in the chain.
  Integrity alerts for items and settings rows (`custody.rs`, `autolock.rs`) do not write this event yet.
- **DEC-T06-1** — T06 — Versions checked on crates.io on 2026-11-17: `totp-rs` 6.0.0 (feature `zeroize`), `ssh-key` 0.6.7 (features `std`, `ed25519`, `getrandom`; 0.7 is still a release candidate). `jiff` gets the `serde` feature in `cerberus-core` for the candidate types.
- **DEC-T06-2** — T06 — `cerberus_types::wire` does not exist yet, so the resolve request, `ItemSummary` and `Candidate` live in `cerberus_core::resolve` and `cerberus_core::items` (serde derives; the request refuses unknown fields). T10 may re-export or move them. `ItemInput` has no `kind` field: the kind is the kind of `payload` (no mismatch is possible). `ItemDetail` has no `exposed_to` (needs leases, T07).
- **DEC-T06-3** — T06 — `ItemMeta` gets `custom: BTreeMap<String, Zeroizing<String>>` (ADR-0027). It is optional in the JSON (`#[serde(default)]`), so old rows open. SSH facts are `custom` keys `machine`, `host`, `port`, `user` (`SshMeta`). Resolve also matches the app against `machine` and `host`. Two literals of `ItemMeta` in tests (`index/mod.rs`, `vault/tests/fixture.rs`) got `custom: BTreeMap::new()`.
- **DEC-T06-4** — T06 — Payload JSON goes through a private mirror type with zeroizing strings, so `Payload` stays non-`Serialize` (it cannot reach an audit event by accident). `browser_session.storage_state` is stored as JSON text inside the payload JSON (a `SecretString`, as interfaces.md says), and validated as an object with optional `cookies` and `origins` arrays.
- **DEC-T06-5** — T06 — TOTP: Base32 seeds may be pasted with spaces, dashes, padding or lower case. 6 or 8 digits, period 15..120, seed at least 128 bits (totp-rs rule). A TOTP code does not count as a reveal for `max_uses` (ADR-0027 counts reveals). `expires_in_seconds` is computed from the injected clock, never from system time.
- **DEC-T06-6** — T06 — Expiry rules in `ItemSettings`: session kinds always get an expiry (default TTL when none given); an operator `expires_at` above the max TTL, or in the past, is a validation error; `expiry_from_ttl` is the agent form (field `ttl_seconds`; other kinds 60..31,536,000 or none). Settings keys: `session_ttl_default_seconds` (60..max), `session_ttl_max_seconds` (300..604800), `item_versions_keep` (1..100), written by the owner only. Stored values out of range fall back to the defaults.
- **DEC-T06-7** — T06 — Item writes hold the state write guard for the whole call (short DB work, no waits on people), check the operator role with the session role (`Session::authorize`, DEC-T05-5), and run in one transaction. A row that vanished (sweeper) makes the store `UPDATE` fail with `NotFound`, so an update cannot bring a deleted item back; a test races update, delete and a sweeper-style delete. `StoreError::NotFound` from item reads maps to `CoreError::NotFound`.
- **DEC-T06-8** — T06 — `max_uses`: `read_payload(id, count_use = true)` is the reveal. It adds 1 to `use_count`, re-seals the metadata at the same version, and deletes the item in the same transaction when the count reaches `max_uses`; the secret is returned only after the commit. `count_use = false` is for an operator looking in the UI. `update_item` refuses `max_uses` not above the uses so far. Restore keeps the current limits and expiry. Retention: last N versions (default 10); session kinds keep 1.
- **DEC-T06-9** — T06 — Resolve: names compare in canonical form (words joined by `-`, so `Shop Frontend`, `shop_frontend` and `shop-frontend` are equal). A role scores +50 for the same label or class, else +20 for a shared word, else the item is dropped (an item without a role label is dropped when a role is asked). Hint words: title +10 (max 30), description/tags/target +5 (max 20), a word counts once. Policy gets two calls through `ResolvePolicy`: `can_find` before everything, `read_access` for the winner only (never for `candidates`).
- **DEC-T06-10** — T06 — Category is free text of 1..64 characters (the built-in list and custom categories as a setting are not enforced yet). Custom keys are `[a-z0-9_]`, max 20 entries.

## T07 — Policy, approval and lease engine (2026-11-17)

- **DEC-T07-1** — T07 — Shape. `cerberus_core::policy` has the pure `evaluate` (ADR-0017 steps 1–8, as in `docs/interfaces.md`)
  and `PolicyEngine` (`PolicyEngine::new(VaultService)`, cheap clone). The engine holds the in-memory state (read and request
  limits, a settings cache, the lease and request gates) and runs grant CRUD, the simulator, the secret read path
  (`authorize_secret`), leases (`crate::leases`) and approvals (`crate::approvals`). No `vault/**` file was changed; the engine
  uses `unlocked()`, `unlocked_mut()`, `authorize()`, `audit()` and `emit()`. Views (`LeaseView`, `AccessRequestView`,
  `AccessRequestDetail`, `LeaseDetail`) live in core for now; the wire DTOs of T10 map them.
- **DEC-T07-2** — T07 — Evaluation details the ADR leaves open: (a) implication applies to deny grants too: a deny of `read`
  or `use_ssh` also hides the item (`find`); (b) a deny grant ignores its time window and reason rule (deny is never weakened),
  only its expiry counts; (c) the time window applies to every permission, the reason rule to every permission except `find`;
  (d) order of the chosen grant's checks: time window, reason, then `max_reads_per_hour` (so a refused call uses no read);
  (e) `max_reads_per_hour` counts only `read` and `use_ssh`; (f) for `find`, `write`, `create_session` an allow always
  reports mode `auto`; (g) a window with `start > end` runs over midnight and belongs to the day it opened; an unknown time
  zone counts as outside (fail closed); windows are whole minutes; (h) the reason counts as present at 8 or more characters
  after trim; its words are never read.
- **DEC-T07-3** — T07 — Fail closed: a grant body that does not parse (or whose sealed `agent_id` differs from the plain column)
  becomes a deny-all grant for that agent, so a broken deny grant can never turn into access. Grant JSON (`grants.body_ct`):
  `v, agent_id, selector{…}, permissions, mode, conditions{time_window{days 1–7, start_minute, end_minute, tz},
  max_reads_per_hour, expires_at_ms, reason_required}, allow_prod_auto, created_at_ms, updated_at_ms`, unknown fields refused.
  `created_at` is in the sealed body (the plain column is not MACed); the tie-break uses it. Effective expiry = earlier of
  the sealed and the plain value (ADR-0033 point 6).
- **DEC-T07-4** — T07 — Limits are counted only when a secret is handed out: the evaluator gets a check-only counter, and
  `ReadLimiter::record_read` checks and counts grant reads/hour, secret reads/min (60) and distinct items/hour (30) in one
  step. Over the distinct limit gives `429 rate_limited` and one `MassReadAlert` per agent per hour. Access requests: 10 per
  10 min per agent (in memory) and at most 5 pending (from the DB). All are owner settings in one sealed row
  `policy_settings` (JSON `PolicySettings`, ranges in `policy/settings.rs`): approval timeout 120 s (30..600), deny cool-down
  600 s, auto lease TTL 900 s, session approval max 8 h, the five limits. Own sliding windows, no `governor` (as DEC-T09-2).
- **DEC-T07-5** — T07 — Lease choice (`leases::check`, which also takes the permission): only approval leases serve
  `ask_once`/`ask_always` (a grant changed from `auto` to an ask mode takes effect at once); any lease serves `auto`. A wanted
  `lease_id` that cannot serve falls back to the normal choice (the usable lease that ends first). An extra variant `NewAuto`
  tells the caller to make an auto lease. A new auto lease starts with `uses = 1` and writes `lease.create` and `lease.use`.
- **DEC-T07-6** — T07 — Approval TTL (`leases::ttl_for`, which also takes the mode and the requested TTL): once 300 s and 1 use;
  15 min 900 s; session = `session_approval_max_seconds` and not past the hard lock. `ask_always` (and `prod` without
  `allow_prod_auto`) always gives 1 use. A requested TTL can only shorten. Never past the item expiry. "Until the next lock":
  a lease from a session approval made before the current unlock is not used (the engine reads its request's option); when
  that request row is missing or bad the lease is not used (fail closed). Other leases survive a lock (ADR-0019 point 9).
- **DEC-T07-7** — T07 — Row safety (orchestrator rule after the T05/T09 review): every change of a lease or a request reads the
  row again inside one `BEGIN IMMEDIATE` transaction (new `Tx::lease`, `Tx::access_request`), checks its MAC and state there,
  then writes it; a stale copy is never written back. A request leaves `pending` only once: approve, deny, timeout and lock
  cancel race to one winner (`Conflict` for the others). Lease use and revoke also hold an engine gate. Audit writes happen
  after the commit. A row with a bad MAC is never signed again (revoke gives `Corrupt`; release gives `NotFound`); for decisions
  it means "no lease" / "not approved", with `IntegrityAlert` and `integrity.row_mac_mismatch`.
- **DEC-T07-8** — T07 — Approvals: `approve_request` checks policy again (with the stored reason's presence) and refuses with
  `Conflict` when it no longer allows; it reads the hard lock time before it takes the guard (no nested guard). Explicit
  `request_access` (`POST /v1/requests`) gives `409 conflict` when no approval is needed (mode `auto`, or an approved lease is
  active). Waits (`wait_access_request`, max 120 s) read the row under a short guard and sleep on the event channel with the
  guard released; a lock ends the wait with `Locked`. A poll of a pending request past its time sets it `expired`, so results
  never depend on the 1 s loop (`spawn_expiry_loop`, body `expire_due(now)`). SSE can be built on `wait_access_request` (the
  only change is pending to terminal), so core has no stream type and no `futures-core` dependency.
- **DEC-T07-9** — T07 — Audit: refusals of a secret read write `item.reveal` (or `ssh.prepare` for `use_ssh`) with the error code
  as result and `details.decision`/`grant_id`; the caller writes the successful `item.reveal` after it reads the payload. `find`
  checks are not audited one by one (`api.resolve`/`api.catalog` cover them). `lease.expire` is written by `expire_due` for
  leases whose end passed since the previous run of this process (the first run starts at that time; ends while the process
  was down are not reported). Reason text never goes to the audit log.
- **DEC-T07-10** — T07 — Store additions (narrow reads, T04 crate): `Store::access_requests_for`, `leases_for`, `live_leases`,
  `leases_expired_between`, `Tx::lease`, `Tx::access_request`. Dev-dependencies of `cerberus-core`: `proptest`, `uuid`
  (workspace versions).
- **DEC-T07-11** — T07 — Roles: all operator methods use `VaultService::authorize` (session role, DEC-T05-5): any role lists grants,
  leases, pending requests, settings and the simulator; operator or owner changes grants, approves, denies and revokes; owner
  sets `allow_prod_auto` (new or on the grant changed or deleted) and policy settings. `revoke_all_leases` (no lock) returns the
  rows changed, which includes leases past their end that were never released.
- **DEC-FIX5-1** — Fix of the T05/T09 review — Lock: `VaultService` keeps the tokio `Handle` of `open`. Every lock runs its
  erase in a detached task on it (`lock_inner` awaits the task), so a cancelled caller cannot leave `Locking` with keys
  alive. `on_os_event` reads `lock_on_os_lock` once, then `spawn_lock(OsLock)` runs the full lock from any thread (no
  re-check of the setting, so turning it off cannot strand the lock). `emergency_wipe` stays for the panic hook only.
  `run_auto_lock_once` finishes a lock left at `Locking` with the reason of the first request. `install` checks the
  epoch again after it sets `Unlocked` and drops the keys at once if a lock came in between. A join error of the lock
  task maps to `Crypto(Kdf)` (wire code `internal`), like the other join errors.
- **DEC-FIX5-2** — Fix of the T05/T09 review — Agent and key changes run under one async write lock in `AuthTable`
  (read, DB write and table update), and every row update is a compare and set: new `Tx::update_live_agent_key`
  (`WHERE revoked_at IS NULL`, changes only `require_mtls`, `client_cert_sha256`, `expires_at`, `revoked_at`, `row_mac`)
  and `Tx::update_agent_if_status` (`WHERE status = <read status>`). A stale row can never undo a revoke or a suspend;
  rotate and bind give `Conflict` when the key was revoked meanwhile. Reads stay outside the transaction: one process
  owns the vault file and all writers of these rows take the lock (`last_used_at` is not in the MAC and is not written).
- **DEC-FIX5-3** — Fix of the T05/T09 review — `AgentService` is crate-private and takes the session role, never
  `OperatorContext.role`. The IPC path is the `VaultService` agent methods (`list_agents`, `create_agent`, `update_agent`,
  `set_agent_status`, `delete_agent`, `create_agent_key`, `rotate_agent_key`, `revoke_agent_key`, `bind_client_cert`):
  each calls `authorize(ctx, min_role)` (viewer for list, operator for changes) and writes the `agent.*` / `agent_key.*`
  audit event. Binding a client certificate writes `agent.update` with target `agent_key` (no own event type).
  `update_agent` writes only `meta_ct`, `updated_at` and the new MAC.
- **DEC-FIX5-4** — Fix of the T05/T09 review — When the header MAC fails at unlock the session role is `viewer`
  (also for the recovery key), because `key_slots.role` is covered only by that MAC. `save_slots` checks the stored header
  MAC against the stored slots (under the gate) and refuses with `Corrupt` (plus `vault.header_mismatch` and the UI event)
  instead of signing an edited file again. Follow-up, not done: binding the role into the slot wrap AAD would change the
  slot format in `cerberus-crypto` (`KeySlot::mac_input` and the wrap AAD) and needs a migration; the header MAC check
  plus the viewer downgrade closes the escalation now. Repair of such a vault is a backup restore. Closed by
  DEC-T27-A1-8 (AUD-26): the AAD binding is not needed and will not be done.
- **DEC-FIX5-5** — Fix of the T05/T09 review — Panic button during a pending lock: the lock side keeps the session
  operator, so `panic_lock` can check `ctx.operator_id` while `Locking`; it sets a panic request, and the first erase that
  runs takes it and revokes all leases (`vault.panic`). If the revoke transaction fails, the request is kept in memory
  and in the sealed setting `panic_revoke_pending` (operator ID, or `null`); the next unlock revokes all leases and
  cancels requests before it installs, writes `vault.panic` with `details.deferred = true` and clears the setting.
- **DEC-FIX5-6** — Fix of the T05/T09 review — `create_vault` takes the epoch at its start. A lock request during create
  leaves the vault `Sealed` (state and flag), but `create_vault` still returns the recovery key and CA pin, because the
  file is already a vault and the key would be lost otherwise.
- **DEC-FIX5-7** — Fix of the T05/T09 review — Audit order at unlock: `audit_pending` rows are drained into the chain first,
  then the integrity events of the unlock. A sealed item, workspace, grant or setting that fails to open now also writes
  `integrity.row_mac_mismatch` (target = table and row ID; `settings` uses the key) next to the UI alert. Alerts raised by
  T06/T07 code (`items/service.rs`, `policy/engine.rs`) are theirs to wire.
- **DEC-FIX5-8** — Fix of the T05/T09 review — Memory: `TokenCheckInput` has a manual `Debug` (`raw_token: "[REDACTED]"`,
  cert hash shown as a bool). `index::text::normalize` grows its `Zeroizing` buffer by moving to a new one (the old one is
  zeroized) instead of a plain realloc. Item and workspace meta decode into `ZText` (zeroizing) fields, so a decode error
  half way leaves no plain copy. Left as is: serde_json's scratch buffer for strings with escapes, and the small reorder
  buffer inside the NFKC iterator; neither is reachable without a fork of those crates.

## Wave 6 wiring pass (2026-11-17)

- **DEC-WIRE6-1** — Wave 6 — The engine state (read limiter, settings cache, lease and request gates, expiry mark) moved
  from `PolicyEngine` into `VaultService` (`EngineState`). `PolicyEngine` is now only a service handle; get it with
  `VaultService::policy()` (or `PolicyEngine::new(service)`, same state). No `Arc` cycle, no `Weak`. `spawn_background`
  also starts `spawn_expiry_loop` (4 handles now).
- **DEC-WIRE6-2** — Wave 6 — The Agent API is the concrete struct `cerberus_core::AgentApi` from
  `VaultService::agent_api()`, not a trait: a trait on `VaultService` would clash with the inherent `status` and
  `resolve`, and there is one implementation. Method names follow `docs/interfaces.md` section 4, except
  `watch_access_request` is `wait_access_request(ctx, id, max_wait)` (no stream type, DEC-T07-8; SSE loops on it) and
  `ssh_prepare` is left to T22. Results are core types (`SecretResult`, `ResolveResult`, `RevealOutcome`,
  `TotpOutcome`, `PendingResult`, `CatalogPage`, `CreatedItem`, `AgentStatusView`); T10/T11 map them to wire DTOs.
  The `handling` marker is in the core result (`handling: &'static str` = new constant
  `cerberus_types::HANDLING_SECRET`), so T10/T11 only copy it.
- **DEC-WIRE6-3** — Wave 6 — A lock (and the deferred panic at unlock) sends `CoreEvent::AccessRequestResolved
  { status: Cancelled }` for each request it cancels; `Tx::cancel_pending_requests` returns the IDs. A wait that can no
  longer read the row (vault sealing) returns the last view with that terminal status, so SSE ends with a final
  `cancelled` event; without the event it returns `Locked`.
- **DEC-WIRE6-4** — Wave 6 — Check order of every Agent API call: vault state (`Locked`; `NoVault` is also `Locked` for
  agents; writes `api.locked_call` with the route name, so T10 must not write it again), then the token scope
  (`InsufficientScope`, writes `auth.failed` with `details.reason = "insufficient_scope"`), then policy. Scopes:
  resolve `best` = `secrets:read`, `candidates` = `catalog:read`; `create_item` by payload kind (session kinds
  `sessions:write` + permission `create_session`, other kinds `secrets:write` + `write`); `create_session` =
  `sessions:write`; delete needs one of the two write scopes, then the one of the item kind. Delete of an item the
  agent neither created nor can find is `NotFound`; of a visible item of someone else `Forbidden`.
- **DEC-WIRE6-5** — Wave 6 — One source of truth for session lengths: `PolicySettings.session_approval_max_seconds` is
  removed. An "approve for the session" lease lasts `min(8 h, session_ttl_max_seconds)` (item settings, ADR-0018),
  constant `approvals::SESSION_APPROVAL_CAP_SECONDS`. Replaces that part of DEC-T07-4/DEC-T07-6. A stored policy row
  with the old field no longer parses and gives the defaults plus an integrity alert (no vault exists yet).
- **DEC-WIRE6-6** — Wave 6 — `lease.expire` for ends while the process was down: the scan mark is also in the sealed
  setting `lease_expiry_mark` (Unix ms), written after each scan that wrote events (an empty range can never get an
  ended lease later). The first scan of a process starts at the stored mark (none = Unix epoch). The scan runs right
  after every unlock (`after_unlock`) and in the 1 s loop, one at a time (lease gate). At least once: a crash between
  the events and the mark write repeats events. Limit: the sweeper deletes lease rows one hour after they end, also
  while sealed, so a lease that ended more than one hour before the next unlock gets no `lease.expire` (its
  `lease.create`/`lease.use` stay). Replaces the last sentence of DEC-T07-9.
- **DEC-WIRE6-7** — Wave 6 — Agent audit content: `api.resolve` (mode, outcome, count or target item, the purpose as
  ADR-0020/0025 say, cut to 500); `item.reveal` (lease, grant, route, purpose, use count, exhausted) and `item.totp` are
  written with `audit_strict` on the same guard as the payload read, and the secret is returned only after that write
  (ADR-0025); `api.catalog` (count, offset); a refused create writes `item.create` with the error code and
  `details.decision`; a refused delete writes `item.delete` (`not_creator`). No event holds a secret value (test scans
  the export and the vault file for the fake marker).
- **DEC-WIRE6-8** — Wave 6 — The only agent path to secrets is `AgentApi`: `read_payload` and `totp_code` are test
  helpers now (`#[cfg(test)]`); `create_item_as_agent`, `delete_item_as_agent`, `read_payload_in` and `totp_code_in`
  are crate-private. `create_item_as_agent` takes the policy check as a closure that runs under the item write guard
  on the proposed metadata, so the check and the insert cannot interleave with a grant change.
- **DEC-WIRE6-9** — Wave 6 — `ItemDetail.exposed_to`: per agent, the newest `created_at` of its lease rows on the item
  that are active (can read now) or were used at least once; newest first; rows with a bad MAC are left out with an
  integrity event. Revoked leases stay in the list (the value may still be with the agent). New store read
  `Store::leases_of_item`. Swept leases (one hour after the end) drop out; the audit log keeps the history.
- **DEC-WIRE6-10** — Wave 6 — Integrity events: the item settings reader (`items/service.rs`), the policy settings
  reader (`policy/engine.rs`) and the lease expiry mark go through `VaultService::integrity_issue` (chain event
  `integrity.row_mac_mismatch` plus the UI alert). `PolicyEngine::mac_alert` now delegates to it.
- **DEC-WIRE6-11** — Wave 6 — `revoke_lease` and `revoke_all_leases` need only the viewer role (ADR-0009 table "Revoke
  leases: viewer yes", IPC table). This corrects DEC-T07-11, which said operator.
- **DEC-WIRE6-12** — Wave 6 — Catalog paging: items sorted by normalized title then ID; `cursor` is the decimal offset
  of the next page; `limit` 1..500, default 100; an unknown workspace gives an empty page (no existence leak); a bad
  cursor is `Validation`.
- **DEC-WIRE6-13** — Wave 6 — IPC coverage: new `VaultService` methods `list_workspaces`, `put_workspace`,
  `delete_workspace` (slug `a-z0-9-` 1..64, slug and aliases unique after normalize, 409 when items exist),
  `reveal_item` (operator, not a use, strict `item.reveal`), `totp_preview`, `audit_query` (newest first, `before_seq`
  paging, limit 1..1000), `audit_verify` (writes `audit.verify`), `audit_export` (new 0600 file, never overwrites),
  `backup_create` (operator; the copy runs without the vault guard), `authorize_restore` (role check only: NoVault or
  owner; the desktop swaps the file and opens a new service, because a live service cannot swap its store),
  `settings_get`/`settings_set` (one key at a time over the three groups; each group keeps its own role and audit),
  `authorize_role` (role check for IPC commands without vault data), and thin delegations to the engine (grants,
  simulate, requests, leases, policy settings). `bind_client_cert` is now owner only (IPC `agent_issue_client_cert`
  is owner). `settings_set` reads and writes a group in two steps; two desktop calls at the same time can lose one
  change (one UI, accepted).

## T10 — HTTPS REST server `cerberus-api` (2026-11-17)

- **DEC-T10-1** — T10 — Crypto provider and versions. `rustls` 0.23.46 with `ring` and **no `tls12` feature**: TLS 1.2 code is
  not compiled into the server, and the config also names `TLS13` only (ADR-0023). `tokio-rustls` 0.26.6, `rcgen` 0.14.10
  (`ring`, `x509-parser`, `zeroize`), `axum` 0.8.9, `hyper` 1.12.0, `hyper-util` 0.1.21, `utoipa` 6.0.0, `x509-parser` 0.18.1,
  `gethostname` 1.1.0, `time` 0.3.55 (rcgen's date type), all checked on crates.io on 2026-11-17. `rustls` 0.24 is only a dev
  release, so the 0.23 line is the latest stable. No `tower-http`: the layers are small and written in `layers.rs` (they need
  the route template and the one error shape). `ISC` is added to `deny.toml` (ring, rustls-webpki, untrusted).
- **DEC-T10-2** — T10 — Layer order (outer to inner): `envelope` (request ID, security headers, log line), `guard` (Host and
  Origin, `403 origin_refused`), routing, `authenticate` (`auth().check`, which does IP limit, lockout, credential, agent limit),
  `locked_gate` (`423`, audited with core `audit_locked_call`), handler (`AgentApi`). A locked vault never reads a body.
  Unknown paths and wrong methods get `404 route_not_found` and `405 method_not_allowed` without a token (they leak nothing).
  `GET /v1/health` is open. A request with no `Authorization` header still goes through `check` (empty token), so it counts
  toward the IP limit and the lockout.
- **DEC-T10-3** — T10 — The server makes the request ID for every call and ignores `X-Request-Id` (ADR-0015). It is a UUIDv7 in
  the `X-Request-Id` header, in every error body and in the audit event (core gets it in `AgentContext`).
- **DEC-T10-4** — T10 — Wire DTOs live in `cerberus-api::wire` (not in `cerberus-types`, which has none yet), with `utoipa`
  schemas. Types of `cerberus-types` and core that have no `ToSchema` are mirrored by small enums (`mirror_enum!`) with `From`
  both ways. Secret text on the wire is `WireSecret`: zeroized on drop, `Debug` prints `[REDACTED]`. `T12` (client SDK, which
  must not depend on the API crate, ADR-0024) will need these DTOs: move `wire` to `cerberus-types` then (it needs `serde`
  and `utoipa` only).
- **DEC-T10-5** — T10 — Status codes of success: `200` for secret, candidates, ambiguous, TOTP, status, catalog, release and for a
  request that is already decided; `201` with `Location: /v1/credentials/{id}` for creates; `202` with
  `Location: /v1/requests/{id}` for a pending approval (also `POST /requests` while `pending`); `204` for delete.
  `outcome` is a tag inside the resolve body (`secret`, `pending`, `candidates`, `ambiguous`).
- **DEC-T10-6** — T10 — `POST /credentials/{id}/ssh-prepare` before T22: the scope `ssh:use` is checked (`403 insufficient_scope`),
  then the answer is `503 unavailable` with `Retry-After: 3600`. The route, its schemas and its OpenAPI entry exist, so T22 only
  replaces the handler body (`routes::ssh_prepare`).
- **DEC-T10-7** — T10 — SSE (`sse.rs`): the first event is the current state (read with `get_access_request`, so a missing or foreign
  request is a normal JSON `404`). Then `wait_access_request(30 s)` in a loop, with no guard held. A terminal status, a shutdown or
  `CoreError::Locked` (sent as a final `cancelled` event) ends the stream. Any other error is sent as one `event: error` with
  the `ErrorResponse` and the stream ends. axum sends the `: keep-alive` comment every 15 s. Event `id` is a counter.
- **DEC-T10-8** — T10 — OpenAPI is generated from the handlers (`openapi::openapi()`). `tests/openapi.rs` compares it with
  `docs/api/openapi-draft.yaml` (paths, methods, operation IDs, tags, status codes, request body schema names, server URL, security
  scheme, schema names, properties, required lists, enums). The draft was changed to match code. Differences from the first draft:
  (a) the `kind` property is not inside the ten `*Secret` schemas; it sits next to their fields (`SecretPayload` and
  `SessionPayload` are internally tagged objects); (b) `ResolveResponse` is `oneOf` SecretResponse, PendingResponse and the new
  `CandidatesBody`, with `outcome` added next to the fields (the `SecretOutcome`, `PendingOutcome`, `CandidatesOutcome` wrappers are
  gone); (c) new named schemas `AccessPermission` (read, use_ssh), `ResolveMode`, `TotpAlgorithmWire`, `SessionPayload`,
  `StatusAgent` replace inline definitions; (d) the unused `Permission`, `Handling` and `Timestamp` schemas are gone (inline
  `type: string, format: date-time`); (e) `ssh-prepare` lists `503`; (f) `SshKeySecret.host/port/user` are also accepted on
  create and stored as item metadata (`machine`, `host`, `port`, `user`); (g) the `x-required-scope` and `x-permission`
  extensions stay in the draft only (the code does not emit them); (h) error responses are inlined, not `$ref`
  components, in the generated paths, and their headers (`X-Request-Id`, `Location`, `Retry-After`) are in the draft only.
  The test does not compare property types, descriptions, examples or headers.
- **DEC-T10-9** — T10 — Timeouts: TLS handshake 10 s; request headers 10 s, which hyper also applies to an idle keep-alive
  connection (so idle ends after 10 s, stricter than the 60 s of ADR-0023); request body 30 s; at most 256 connections (the
  semaphore is taken before `accept`, so more wait in the backlog). Body limits 16 KiB, and 1 MiB on `POST /v1/credentials` and
  `POST /v1/sessions`: a `Content-Length` above the limit is refused before reading; a chunked body is cut at the limit (`413`).
  The body buffer and the response buffer of a secret are not zeroized after hand-over to hyper (the value has just left the vault
  for the agent; TLS and hyper copy it anyway).
- **DEC-T10-10** — T10 — Repository checks: `just deps-check` now ignores dev-dependencies, so tests of `cerberus-api` may use
  `cerberus-store` to open a vault file (ADR-0024 rules apply to normal and build dependencies). `deny.toml` allows `ISC`.
- **DEC-T10-11** — T10 — Local CA and leaf. `LocalCaIssuer` (core `CaIssuer`, DEC-T05-1) makes the CA (P-256, 10 years, path length
  0, `keyCertSign`, `cRLSign`, `CN = Cerberus Local CA <8 hex of the vault ID>`) and the first leaf (P-256, 90 days, EKU
  serverAuth, SAN `localhost`, `127.0.0.1`, `::1`, host name, owner names), and writes the leaf to `<data_dir>/tls/leaf-cert.der` and
  `leaf-key.der` (key `0600`, directory `0700`, atomic rename). `LeafResolver` serves the current leaf and `reload()` swaps it
  with no restart. `renew_leaf_if_needed(ca, ...)` renews when less than 30 days are left or the names changed. Client
  certificates (`LocalCa::issue_client`): P-256, 365 days, EKU clientAuth; its SHA-256 goes to core `bind_client_cert`. The CA
  export (`CaExport::from_der`) needs only the CA certificate (plain in `tls_ca`), so it works while locked.
- **DEC-T10-12** — T10 — mTLS: with `ApiConfig.client_ca_der` set, rustls verifies a client certificate (it must be signed by the CA
  and have EKU clientAuth, so a leaf cannot be used as one). `require_client_cert = false` allows no certificate (a key with
  `require_mtls` then fails the token check, `401`); `true` fails the handshake without one. A non-loopback bind needs
  `require_client_cert` and a CA, else `ServerError::LanBindNeedsMtls`. The owner check "every active key has mTLS" belongs to
  the caller (T13, T15), who changes the bind (ADR-0023 point 2).
- **DEC-T10-13** — T10 — Logging: one `info` line per request with method, route template (`unmatched` when no route matched),
  status, latency, request ID and agent ID. No header, query, body or raw path. A refused token logs one `warn` per IP per
  minute with the reason (`AuthFailure::reason`) and never the token. The test `logs_of_a_reveal_hold_no_secret_and_no_token`
  captures all levels during a reveal, a resolve, bad tokens and a locked call.
- **DEC-T10-14** — T10 — `AgentApi::resolve` returns a future that is not `Send` (core trait `ResolvePolicy` is not `Sync`), so
  axum cannot run it. `routes::resolve_on_blocking_thread` runs it on a blocking thread with `Handle::block_on`. Core fix: make
  the trait `Sync` (`pub trait ResolvePolicy: Sync`), then call `resolve` directly and delete that function.

## Fixes of the second core security review (2026-11-17)

- **DEC-FIX7-1** — Second core review — Lease fit by effective mode (ADR-0017 step 6, ADR-0019 point 5, amended): `ask_always`
  (also the `prod` default) is served only by an approval lease with `max_uses = 1` and a `request_id`; `ask_once` by any
  approval lease; `auto` by any lease. The mode is checked at each use (`leases::serves`), and the resolve snapshot uses the
  same rule. So a grant tightened from `ask_once` to `ask_always` needs a new approval for each read at once. An operator
  change (update or version restore) that moves an item to another environment or workspace revokes its active approval
  leases in the same transaction (`lease.revoke`, `details.reason = "item_moved"`); auto leases stay (they serve only `auto`).
- **DEC-FIX7-2** — Second core review — Reveal and resolve-with-value take the vault write guard once and run
  `authorize_secret_in` and the payload read on it; TOTP does the same on one read guard (the code changes nothing, and every
  policy change, item edit and lock needs the write guard). So a deny, edit or lock lands either before the check or after the
  secret is audited, and a lock can no longer burn a one-use lease between check and read. A lease use is still spent when the
  payload read or its strict audit write fails after the check (storage or audit error); that read is refused, not delivered.
  `PolicyEngine::authorize_secret` (own guard) stays for other callers.
- **DEC-FIX7-3** — Second core review — Agent create is no oracle. An unknown workspace slug is `403 forbidden` (audited as
  `item.create`, decision `unknown_workspace`), the same as no grant. The policy check runs before any title check. A title
  clash is `409 conflict` only with an item the agent can `find`; a clash with a hidden item is allowed (a duplicate title).
  Operator update and restore give `409` only when the change moves the item to a used title or workspace, so an operator
  can still edit either twin.
- **DEC-FIX7-4** — Second core review — The sweeper keeps a revoked auto lease until one hour after its original
  `expires_at` (not after `revoked_at`), so the ADR-0019 point 7 block lasts to the old end.
- **DEC-FIX7-5** — Second core review — `request_access` drops session approval leases of an earlier unlock, like the read
  path, so it opens a request instead of `409` when that old lease no longer serves.
- **DEC-FIX7-6** — Second core review — Every `purpose` that enters an audit body (`api.resolve`, `item.reveal`, `item.totp`)
  is trimmed and cut to 500 characters (`audit_purpose`), also when the call fails its length check.
- **DEC-FIX7-7** — Second core review — The policy settings cache has a save counter. A load notes it before it reads the row
  and stores its value only when no save came in between; else the saved value is used.
- **DEC-FIX7-8** — Second core review — A counted agent reveal writes `item.reveal` (strict, with `use_count` and `exhausted`)
  before the transaction that counts the use or deletes the item at `max_uses`. A failed audit write changes nothing; a failed
  count after the event writes a second `item.reveal` with the error code and `stage = "count_use"`.
- **DEC-FIX7-9** — Core additions after T10 — `pub trait ResolvePolicy: Sync`, so `AgentApi::resolve` returns a `Send`
  future (test `fix7_resolve_future_is_send`). `cerberus-api` calls it directly; `routes::resolve_on_blocking_thread`
  (DEC-T10-14) is deleted.
- **DEC-FIX7-10** — Core additions after T10 — `VaultService::tls_ca_cert()` gives the CA certificate DER from the plain
  `tls_ca` column (works while locked; `NoVault` before a vault exists). `VaultService::tls_ca_material()` gives the
  certificate, the CA key (`SecretBytes`, `Debug` redacted) and the vault host names; unlocked only. It is for the TLS layer
  of the same process (leaf renewal, agent client certificates); it is not on `AgentApi` and no IPC command returns it.
- **DEC-FIX7-11** — Core additions after T10 — `VaultService::audit_auth_failure(source_ip, failure, request_id, surface)`
  writes `auth.failed` (actor system, outward error code, `reason`, `source_ip`, `surface`, `suppressed_before`) at most once
  per source IP per minute; failures in between are counted and the next event of that IP carries the count. At most 4096
  IPs are tracked; past that new IPs share one bucket. While locked the event goes to `audit_pending` with the IP as target
  and the outward code only (that table has no details). The `cerberus-api` token layer calls it on every refusal, besides
  its rate-limited `warn` log.
- **DEC-FIX7-12** — `cerberus-api` after T10 — `RunningServer::renew_leaf(core, tls, extra_names)` renews the leaf with the
  vault CA when it is near its end or its names changed (names: standard ones, vault host names, `extra_names`) and reloads
  it. `RunningServer::spawn_leaf_renewal(core, tls, extra_names)` runs it now when unlocked and at every
  `StateChanged(Unlocked)` (also after a lagged event channel). The host binary starts that task after `start`. Test:
  `the_leaf_is_renewed_at_unlock`. The test harness reads the CA with `tls_ca_cert()` instead of `store().tls_ca()`.
- **DEC-WIRE8-1** — Wave 8 — The agent-API wire DTOs moved from `cerberus_api::wire` to `cerberus_types::wire`, so the client SDK uses
  the same types (ADR-0024 rule 4). `utoipa::ToSchema` is behind the optional `openapi` feature of `cerberus-types` (only
  `cerberus-api` enables it). `WireSecret` has `new`, `expose` and `into_string` (no `SecretString`); `cerberus-types` gains
  `zeroize` and the serde features of `jiff` and `uuid`. Conversions to and from `cerberus-core` types are now free functions in
  `cerberus_api::convert` (both sides are foreign there, so no `From` impls). No wire or OpenAPI change.

## T13 — Headless daemon `cerberusd` (2026-11-17)

- **DEC-T13-1** — T13 — Unlock is a local socket, not a prompt inside `serve`. `cerberusd unlock` reads the phrase from the
  terminal with echo off (`rpassword`, which uses `/dev/tty`) and sends it as one JSON line to `<data_dir>/cerberusd.sock`
  (mode `0600`). The server accepts only the uid it runs as (`SO_PEERCRED`) and calls the same `unlock_with_phrase` as the
  desktop app. Reason: a systemd service has no terminal, and the phrase must never be in argv or an environment variable.
  `serve` never prompts. The phrase lives in `Zeroizing` buffers on both sides of the socket. (ADR-0002 point 2, ADR-0026)
- **DEC-T13-2** — T13 — The daemon starts sealed. If the vault has no TLS leaf (a backup from the desktop has none, ADR-0031
  point 2), the HTTPS listener starts at the first unlock, because the CA key is sealed until then. `Ready.addrs` is empty
  before that. `systemd` gets `READY=1` once the unlock socket is up, so the unit starts while sealed. Test:
  `no_tls_leaf_yet_means_https_starts_at_the_first_unlock`.
- **DEC-T13-3** — T13 — Settings: TOML file (default `$XDG_CONFIG_HOME/cerberusd/cerberusd.toml`, `--config` overrides) and
  `CERBERUSD_*` environment variables, which win (ADR-0002 point 5). The file must be mode `0600` (any other mode is refused),
  unknown keys are refused, and every error names its key. Port `0` is refused, because `status` must find the port.
  Keys: `data_dir`, `bind`, `port`, `host_names`, `require_mtls`, `idle_lock_seconds`.
- **DEC-T13-4** — T13 — A non-loopback bind needs `require_mtls = true` (ADR-0023 point 2). The daemon then uses the vault CA
  as the client CA. Gap: the rule "every active key has mTLS" is not checked. The core has no accessor for key settings while
  sealed, and the daemon has no admin surface (ADR-0002). TLS still rejects every client without a CA-signed certificate.
- **DEC-T13-5** — T13 — Idle lock is off by default on the daemon (ADR-0002 point 7). The vault's hard limit of 12 h
  (`max_unlocked_seconds`, ADR-0026) still applies: the daemon cannot change it, because the daemon has no admin surface.
  To change it, set it on the desktop app and make a new backup.
- **DEC-T13-6** — T13 — At each start the daemon writes the CA certificate (public, PEM, mode `0644`) to
  `<data_dir>/tls/ca-cert.pem`, atomically, and logs its pin and fingerprint. Agents need this file to trust the server
  (`NODE_EXTRA_CA_CERTS`). `status` reads it too. It works while sealed, because `tls_ca_cert()` reads the plain column.
- **DEC-T13-7** — T13 — `cerberusd status` connects to loopback (or the same family loopback for a wildcard bind), uses
  SNI and `Host` `localhost`, trusts only the CA file, and calls `GET /v1/health`. Gap: it sends no client certificate, so
  with `require_mtls` it reports that no daemon answered. A client identity for `status` is future work.
- **DEC-T13-8** — T13 — Stop: SIGTERM or SIGINT first stops the unlock socket (so no unlock can start after the lock), then
  calls `VaultService::lock(LockReason::Quit)`, then aborts the background tasks, then stops the listener with the 10 s drain
  of ADR-0023, and removes the socket file. The lock comes before the server stops (ADR-0002 point 6).
  The function `serve` returns the service locked, so tests can check it. Test:
  `daemon_unlocks_serves_ask_grants_as_403_and_stops_locked`.
- **DEC-T13-9** — T13 — `/mcp` is mounted with `cerberus_api::app(&state, cerberus_mcp::mcp_router(&state))`. The MCP router
  already has the token check (ADR-0029). Without a token the test gets `401`. The log level is fixed at `INFO`, which also
  keeps `rmcp` debug output (which can hold secrets, `LOG_DIRECTIVE`) out of the logs. Added the `cerberus-mcp` workspace
  entry (path + version), as the other internal crates have.
- **DEC-T13-10** — T13 — Only the passphrase unlocks on the daemon. The recovery key is not accepted yet (gap). Operators are
  picked by label; with no label, the one owner is used, and two owners need `--operator <label>`.
- **DEC-T13-11** — T13 — After each unlock the daemon logs every `ask_once` and `ask_always` grant, with a warning that it
  answers `403 approval_unavailable`. Grants are encrypted, so they can be listed only after an unlock, not at start
  (ADR-0002 point 4 said "at startup").
- **DEC-T13-12** — T13 — No `cerberusd restore` command yet (ADR-0002 point 3, ADR-0031 point 3). A backup file is a vault
  file made by `VACUUM INTO`, so the guide says to copy it to `<data_dir>/vault.cerberus` with mode `0600`. The
  `serve` error says the same.
- **DEC-T13-13** — T13 — One package, a library and a binary. The binary is a thin command line over the library, so the
  tests run the same code (ADR-0002 "one code path"). ADR-0024 says "bin"; this keeps that rule and adds the library target.
- **DEC-T13-14** — T13 — Test-only `insecure-test-kdf` on `cerberus-crypto` as a dev-dependency (DEC-050). Tests use a real
  TLS listener on a free loopback port and a real unlock socket. `harden_process()` runs first in `main` (ADR-0012).
- **DEC-T13-15** — T13 — Service unit (`packaging/systemd/cerberusd.service`): `Type=notify`, a `cerberus` user, state dir
  `/var/lib/cerberus` (mode `0700`), the hardening list of ADR-0002 point 6, `LimitCORE=0`, `LimitMEMLOCK=64M`, and
  `CapabilityBoundingSet=` (empty). Example config: `packaging/systemd/cerberusd.toml.example`.
- **DEC-T12-1** — T12 — Transport: `hyper` 1 (http1 client) over `tokio-rustls` with the `ring` provider, not `reqwest`. One TLS
  connection per call, HTTP/1.1 (ALPN `http/1.1`). Reasons: a custom certificate verifier and a streaming body (SSE, MCP shim)
  are direct, TLS 1.3 only is explicit (`with_protocol_versions(&[TLS13])`), and the tree stays small. Loopback handshakes cost
  about a millisecond. The public layer is `cerberus_client::transport::PinnedHttps` (T11 uses it); `Client` is built on it.
- **DEC-T12-2** — T12 — Trust: the Cerberus CA is the only trust anchor; no system roots, and no default (a missing trust setting
  is a config error). `Trust::CaFile` verifies the chain with webpki against the CA PEM. `Trust::CaFileAndPin` also requires that
  the CA in the file has the pinned SPKI hash (checked when the client is built: `PinMismatch`). `Trust::Pin` (pin only) takes
  the certificate in the presented chain whose SPKI SHA-256 equals the pin and uses it as the only anchor for that handshake;
  no match gives `PinMismatch`. The SPKI hash is the one the app shows (test `our_pin_matches_the_pin_the_app_shows`).
  Gap: the server today sends only the leaf, so pin-only does not work against `cerberus-api` until the server also sends the
  CA certificate after the leaf. Until then agents use `CERBERUS_CA_FILE` (the app exports it) together with `CERBERUS_CA_PIN`.
- **DEC-T12-3** — T12 — Settings: `CERBERUS_URL` (default `https://127.0.0.1:7373`, `https` only), `CERBERUS_TOKEN`, else
  `CERBERUS_TOKEN_FILE`, else `$XDG_CONFIG_HOME/cerberus/token` (or `~/.config/cerberus/token`). The token file must be mode
  `0600` on Unix, else a config error. `CERBERUS_CA_FILE`, `CERBERUS_CA_PIN`, `CERBERUS_CLIENT_CERT`, `CERBERUS_CLIENT_KEY` (mTLS).
  The CLI has flags for all of these except the token itself, so a token never appears in `ps`. `ClientConfig` is not `Clone`
  (the token has one owner). The token type is `WireSecret` (zeroized, `Debug` prints `[REDACTED]`).
- **DEC-T12-4** — T12 — Retry (`RetryPolicy`: 3 tries, 250 ms doubling, 4 s cap, `retry_after_seconds` honoured up to the cap).
  A call is repeated only when the server marks the error `retryable`, or when the TCP connect failed (nothing was sent).
  Reveal, totp, resolve, create, delete, release and ssh-prepare may be counted by the server, so after a timeout or a broken
  connection they are not repeated. Reads (health, status, catalog, get request, event stream) are also repeated after those.
- **DEC-T12-5** — T12 — Wire DTOs (additive, JSON unchanged): responses got `Deserialize`, requests got `Serialize`.
  `&'static str` fields of `HealthResponse`, `SecretResponse` and `TotpResponse` are `Cow<'static, str>`; `cerberus-api` changed
  three lines (`.into()`). `tests/openapi.rs` passes.
- **DEC-T12-6** — T12 — `watch_request` returns `RequestEvents` with `async fn next()`, not a `futures_core::Stream` (one dependency
  less). `wait_request` reads the stream, falls back to polling every 2 s, and returns the current view when the time is up
  (it may still be `pending`). `mcp_post` is not in `Client`: the MCP shim uses `PinnedHttps` directly.
- **DEC-T12-7** — T12 — `cerberus get` hides secret values by default: it prints JSON with the `handling` text, the item, the field
  names with `[REDACTED]` for secret fields, the lease and a note, then releases the lease (the values are not in use). With
  `--show-secret` it prints the full response; `--show-secret --field NAME` prints one value raw. `cerberus totp` works the same.
  `get`, `totp`, `find` and `run` use `--purpose` or a default text of at least 8 characters.
- **DEC-T12-8** — T12 — `cerberus run`: `--var NAME=field` (alias `--map`) sets only the mapped variables; without it the ADR-0028
  defaults apply (cloud `aws` uses the AWS names, other providers `CERBERUS_CLOUD_*`, certificate `CERBERUS_CERT_PEM`,
  `CERBERUS_KEY_PEM`, `CERBERUS_CHAIN_PEM`, note `CERBERUS_NOTE`, a database without `url` builds `DATABASE_URL` from its parts with
  percent-encoding). An SSH key is refused (use `ssh-prepare`). The child gets `CERBERUS_TOKEN` and `CERBERUS_TOKEN_FILE` removed
  unless `--pass-token`. Output masking covers raw, Base64 (4 forms), URL-encoded and JSON-escaped values; values under 4 bytes
  are not masked. SIGINT, SIGTERM, SIGHUP and SIGQUIT are forwarded to the child (`rustix`, no `unsafe`); a signal death gives
  128 plus the signal. After the child ends the lease is released (error printed as code only). Exit codes 70 to 74 (ADR-0028);
  `Ambiguous` gives 73 and `NotApproved` gives 72.
- **DEC-T12-9** — T12 — `cerberus store` reads the secret from standard input only. Kinds `api_key`, `session_token` and `note` take
  the raw value (one trailing newline is removed); `--json` takes the full payload for any kind; `--session` uses
  `POST /v1/sessions` (`browser_session` also needs `--origin`).
- **DEC-T12-10** — T12 — Checks: `just client-deps-check` (also in `just check`) and the test `tests/deps.rs` run
  `cargo tree -p cerberus-client -e normal` and fail on axum, sqlx, argon2, tauri, utoipa, rcgen, x509-parser, and the
  api, core, store, crypto and mcp crates. Dev-dependencies of the client use api, core, store and crypto for the real-server tests
  (`just deps-check` ignores dev edges, DEC-T10-10). `rustls` has the `tls12` feature as a dev-dependency only, to build a
  TLS 1.2-only test server.

## T11 — MCP server and stdio shim `cerberus-mcp` (2026-11-17)

- **DEC-T11-1** — T11 — `rmcp` 3.10.0 (latest stable on crates.io, 2026-11-17), features `server` and
  `transport-streamable-http-server` only: no `#[tool]` macros. The handler implements `ServerHandler` by hand and the tool
  schemas are the JSON of `docs/api/mcp-tools.md`, embedded as `src/schemas.json`. A unit test parses the document and fails
  when a schema, description, annotation or `$defs` entry differs. Tests use the `rmcp` client with `reqwest` 0.13.5 and
  `rustls-no-provider` (dev only, so no `aws-lc` in the tree). The server uses the default `legacy_session_mode`: a client that
  negotiates an older protocol gets a session (`Mcp-Session-Id`), one that negotiates `2026-07-28` is served statelessly. The
  lock never ends either (ADR-0029 item 3).
- **DEC-T11-2** — T11 — Public API for hosts: `cerberus_mcp::mcp_router(&AppState) -> Router`, already wrapped by
  `cerberus_api::agent_layers` (token, rate limits, request ID; Host and Origin run in `cerberus_api::app`). Pass it as the
  `extra` argument of `cerberus_api::app`. `rmcp`'s own Host check is off (the leaf names come from the vault and `cerberus-api`
  already checks Host and Origin); the body limit is 1 MiB. `CerberusMcp::new(VaultService)` is the handler. `LOG_DIRECTIVE`
  (`rmcp=warn`) must be in the host's log filter: `rmcp` logs message bodies, with secrets, at `debug` and `trace` (the test
  `logs_hold_no_secret_and_no_token` applies the cap and shows the rest of the logs are clean).
- **DEC-T11-3** — T11 — `ssh_prepare` is listed in `tools/list` and lives alone in `src/tools/ssh.rs`. Until T22 it answers as the REST
  route does: lock (`vault_locked`, audited with the REST route name), then scope `ssh:use` (`insufficient_scope`), then
  `unavailable` with `retry_after_seconds = 3600`. This replaces "not listed before T22" in `docs/api/mcp-tools.md`.
- **DEC-T11-4** — T11 — The catalog resource keeps the core order (normalized title), first 500 items, `truncated` when a next
  cursor exists. The document said "newest `updated_at` first"; sorting after a title-ordered cut would be wrong, and a full
  scan is not worth it for a metadata list. The document is changed.
- **DEC-T11-5** — T11 — Every `outputSchema` has `"type": "object"` at its root (added to the `oneOf` and `$ref` roots): MCP clients
  want an object schema. The document says so. Each tool schema carries only the `$defs` it uses (transitively).
- **DEC-T11-6** — T11 — Tool errors are results with `isError: true` and the ADR-0021 object in `structuredContent` and in the text.
  Only an unknown tool name is a JSON-RPC error (`-32602`). A resource read error is JSON-RPC code `-32000` with the ADR-0021 object
  in `data`. Bad arguments (unknown field, wrong type, `id` and `app` together, `wait_seconds` above 120) are `invalid_request`
  with the fixed message: serde text can quote a secret field, so it is never sent. `vault_status` while locked is the success
  `{"vault": "locked"}`; every other tool is `vault_locked` (core writes `api.locked_call`; `ssh_prepare` writes it itself).
- **DEC-T11-7** — T11 — Waiting (`get_credential`, `get_totp`, `request_access`): the first call goes to core; when it is `pending` and
  `wait_seconds > 0` (default 60, max 120) the tool loops on `wait_access_request` in 10 s slices with no guard held, sends
  `notifications/progress` after each slice when the client gave a progress token, and stops when the client cancels. `approved`
  repeats the first call with the lease ID. `denied` is `approval_denied`. `expired`, `cancelled` or a timeout return the
  `pending` object with the latest status (for `request_access`, the request view as it is). A lock during the wait is
  `vault_locked`. The `request_id` of every result and audit event is the one of the HTTP request (one tool call is one request).
- **DEC-T11-8** — T11 — `store_secret`: `value` as a string stands for the single text field of `api_key` (`key`), `session_token`
  (`token`) and `note` (`text`); an object holds the payload fields. `session_token` and `browser_session` go to `create_session`, the
  rest to `create_item`. A TOTP seed cannot be sent (the wire payloads have no field for it, so it is an `invalid_request`).
  Result JSON and text copies of a secret are plain `String`s while the answer is built (not zeroized), as REST (DEC-T10-9).
- **DEC-T11-9** — T11 — Stdio shim (feature `shim`, on by default for the bin; the workspace entry has `default-features = false`, so
  a host that takes only the server does not link the client SDK). One JSON value per line. Each message is one `POST /mcp` over
  `cerberus_client::PinnedHttps` (no retry), as a task of its own so a long approval wait does not block the host. The shim copies
  `Mcp-Session-Id` and the negotiated `MCP-Protocol-Version` into later requests and adds `Mcp-Method` and `Mcp-Name` for
  protocol `2026-07-28` and later. JSON and SSE replies are written as lines. An HTTP error or a transport error for a request
  becomes a JSON-RPC error (`-32000`, message = the Cerberus error code, `data` = the error object); a line that is not JSON gets
  `-32700`. At the end of stdin it cancels the calls in flight and sends `DELETE /mcp`. It reads `CERBERUS_URL`,
  `CERBERUS_TOKEN` / `CERBERUS_TOKEN_FILE`, `CERBERUS_CA_FILE` and `CERBERUS_CA_PIN` (T12 names), and also `CERBERUS_CA_CERT` and
  `CERBERUS_PIN` (the ADR-0029 names). Without a CA file or pin it exits with code 2. Its stderr log is `warn` only, no bodies.
  Open point for the orchestrator: a pin alone fails against the current server because the leaf chain does not carry the CA;
  the tests and `docs/guides/mcp-client-config.md` use a CA file.

## T22 — SSH agent bridge `cerberus-ssh-agent` (2026-11-17)

- **DEC-T22-1** — T22 — Shape. Core module `cerberus_core::agent_api::ssh` holds the signing path: `AgentApi::ssh_prepare`
  (scope `ssh:use`, policy `use_ssh`, lease or approval through `authorize_secret_in`, one write guard as DEC-FIX7-2),
  `AgentApi::ssh_sign` and `AgentApi::ssh_ticket_open`. Prepare gives an `SshTicket`: IDs and the public key only, made only by
  core, with no private key material. The bridge crate holds the sockets (`SshBridge`), speaks the protocol and calls core for
  every signature, so the private key never leaves core memory. `SshBridge::shared(core)` gives one bridge per vault service
  (identity = the address of its `CoreConfig`, kept weakly in a static list), so REST and MCP use the same socket for a lease
  without a change to the MCP call context; `AppState` holds it (field `ssh`, accessor `ssh_bridge()`), so it lives as long as
  the server. `cerberus_api::routes::prepare_ssh(core, ctx, item, body)` is the one function REST and MCP call. MCP adds
  `outcome: "ready"`; the other fields are the REST `SshPrepareResponse`. Core now writes `api.locked_call` for the MCP tool
  (replaces the last words of DEC-T11-6).
- **DEC-T22-2** — T22 — Keys: ed25519 only. RSA is not built (the `rsa` crate has RUSTSEC-2023-0071) and ECDSA is not enabled;
  another key type gives `422 validation_failed` at prepare. `ssh-key` in core gets the `encryption` feature (bcrypt-pbkdf, AES),
  so a key imported with a passphrase signs (the passphrase is in the payload). The key is opened for one signature and dropped
  (ssh-key zeroizes its key bytes on drop); no key is cached between signatures.
- **DEC-T22-3** — T22 — Leases. Prepare spends one lease use like a reveal (it is the exposure record) and counts in the read
  limits; it is not a reveal for the item `max_uses` (as TOTP, DEC-T06-5). Each signature adds one more use to the lease row
  (new row MAC, under the lease gate, in one transaction) and needs the row open: same agent, item and `use_ssh`, not released,
  not revoked, before `expires_at`, and still fitting the effective grant mode (`leases::serves` without the use count). A lease
  with a use limit (approval `once` or `ask_always`) was spent by the prepare, so its ticket gets a budget of one signature
  (one SSH login), then the socket closes. `ttl_seconds` (60..86400) can only shorten the socket against the lease end. A lock
  ends every ticket: the ticket keeps the unlock time of its session, and the next unlock is a new session.
- **DEC-T22-4** — T22 — Checks at each signature, in this order, on one vault write guard: unlocked (else `api.locked_call`),
  same session, ticket end, data kind, ticket budget and 60 signatures per minute per ticket, agent active and key not revoked
  or expired with scope `ssh:use` (rows read from the store with MAC check, so a revoke stops signing at once), policy (`find`
  and `use_ssh` allowed with the prepare purpose as reason), the lease (above), the same public key in the item, then `ssh.sign`
  (strict) and only then the signature. Only two data kinds are signed: an SSH user authentication request for this key
  (`publickey` or `publickey-hostbound-v00@openssh.com`) and an `SSHSIG` blob (`ssh-keygen -Y sign`, git signing). Anything else
  is refused, so the socket is not a general signing oracle. A refusal writes `ssh.sign` with the error code and
  `details.decision`. New catalog event `ssh.sign` (target item; details lease, grant, fingerprint, data size, flags, uses,
  `data_kind`, user name cut to 64 characters); no data bytes and no key material.
- **DEC-T22-5** — T22 — Sockets. Base `$XDG_RUNTIME_DIR/cerberus-ssh` (an absolute existing directory) or
  `<data dir>/run/cerberus-ssh`; each bridge makes `<pid>-<n>` in it; socket `<lease uuid simple>.sock`. Every directory is 0700,
  owned by this user and not a symlink (checked); each socket is chmod 0600 right after bind (the 0700 directory covers the
  moment between). Paths longer than 100 bytes are refused (`sun_path` limits). A new bridge removes the socket files and the
  directory of every `<pid>-<n>` whose process no longer runs (`kill(pid, 0)` = ESRCH), so a crash leaves nothing behind for
  long. Peer check through tokio `peer_cred` (`SO_PEERCRED`, `getpeereid` on macOS): another user ID is dropped without an
  answer. Limits: 32 sockets per bridge, 8 per agent (over the limit gives `429 rate_limited`, Retry-After 60, checked before the
  lease use is spent), 8 connections per socket, 300 s idle per connection, frames 1..256 KiB (else the connection closes).
  `rustix` (process feature) gives `getuid` and `kill(pid, 0)` without unsafe; the crate has `#![forbid(unsafe_code)]`.
- **DEC-T22-6** — T22 — Protocol: only `REQUEST_IDENTITIES` (11) and `SIGN_REQUEST` (13). Every other type, including add,
  remove, remove all, lock, unlock, smartcard, constrained add, extension (27, also `session-bind@openssh.com`) and SSH1 types,
  gets `SSH_AGENT_FAILURE` and the connection stays open. A sign request for another key blob gets the failure without a core
  call. The identity comment is `cerberus:<item id>`. When the ticket is no longer open the identity list is empty.
- **DEC-T22-7** — T22 — Socket end. A watcher task (weak reference to the bridge) closes a socket on `StateChanged` to any state
  but unlocked (lock, panic), on `LeaseChanged` of its lease when core says the ticket is not open (release, revoke, revoke all,
  expiry, budget used), after a refused signature, every second for tickets past their end, and every 5 s for all tickets (a
  lagged event channel also checks all). Closing aborts the listener task and every connection, and removes the file. Dropping
  the last bridge clone (server shutdown, process exit) closes all sockets and removes the directory; `close_all()` is there for
  hosts. Unix only: on other targets `prepare` gives `503 unavailable`.
- **DEC-T22-8** — T22 — Tests. Core: prepare and sign (SSHSIG verified with the public key, user auth plain and host-bound),
  refused data, scope, kind and policy, short TTL, release, revoke and lock end the ticket, a deny grant and a revoked agent key
  stop signing, one signature for an `ask_always` approval, the rate limit, an encrypted key, and a marker scan (Base64 lines of
  the private key text and the seed hex) of results and the audit export. Bridge: a raw ssh-agent client lists the key and gets
  a signature verified with `signature::Verifier` (dev-dependency `signature` 2.2.0, the line of `ssh-key` 0.6), refused types,
  frame limits, modes 0600/0700, the socket file gone after release, revoke, lock and drop, the socket limit, and A4 end to end:
  `ssh -o IdentityAgent=<socket> -i <public key> -p <port> user@127.0.0.1 true` against an unprivileged `/usr/sbin/sshd` with a
  host key made at run time (the test prints SKIPPED only when ssh or sshd is missing or sshd cannot start as this user). The
  T10 test `ssh_prepare_is_not_available_until_t22` and the T11 test `ssh_prepare_is_unavailable_like_rest` tested the stubs and
  are replaced by `cerberus-api/tests/ssh.rs` and `cerberus-mcp/tests/ssh.rs` (REST and MCP give the same fields and socket).

## T15 — Tauri shell and typed IPC (2026-11-17)

- **DEC-T15-1** — T15 — Versions. Tauri 2.12.6 (workspace). `tauri-specta` has only release candidates for Tauri 2 (the 1.0.x line is
  Tauri 1), so `=2.0.0-rc.29` with `specta =2.0.0-rc.28` and `specta-typescript 0.0.15` (pinned with `=`, as the crate asks).
  `tauri-plugin-single-instance` 2.5.5, `-clipboard-manager` 2.5.0, `-autostart` 2.7.0, `-dialog` 2.8.4, `zbus` 5 (the same major
  as single-instance, so one copy). Checked on crates.io on 2026-11-17. Bindings use `ErrorHandlingMode::Result` (the UI gets
  `{ status, data | error }` with a typed `IpcError`) and 64-bit counters export as `number` (row counts, far below 2^53).
- **DEC-T15-2** — T15 — Layers. `commands.rs` holds thin `#[tauri::command]` wrappers (one macro) that pass `window.label()` and the
  state to `ops::<same name>`. `ops` does: label check (first statement, a test checks it for all 65), `DesktopState::operator()`
  (the `OperatorContext` comes from `VaultService::status().session`, so operator and role are never read from the UI), then one
  `VaultService` method that runs `authorize` with the session role. Tests call `ops` with fake labels and a fake `Shell`.
- **DEC-T15-3** — T15 — `deny.toml` allows `BSD-2-Clause` (Inflector, from tauri-specta macros) and `BSL-1.0` (clipboard-win,
  error-code, from the clipboard plugin on Windows). Both are OSI-approved and permissive.
- **DEC-T15-4** — T15 — `cerberus-desktop` depends on `cerberus-store`, and so does `cerberusd`: the app must open the vault file
  (`Store::open`, `restore_backup`), and core has no open-by-path helper. ADR-0024 rule 2 allows this ("binaries use the store only
  to open the file"); the table line and the `deps-check` edge list now say it for the desktop too. The IPC mirror types also name
  `cerberus_store::AgentStatus` and `LeaseSource` because core returns them. Core change that would remove the edge:
  `VaultService::open_path(path, clock, config)` and re-exports of those two enums.
- **DEC-T15-5** — T15 — Error shape: `IpcError { code, message, retry_after_seconds?, fields[] }`, a superset of the `{ code, message }` of
  interfaces.md (the unlock screen needs the back-off seconds and the editor needs field problems). Codes are the ADR-0021 codes plus
  `no_vault`, `role_not_allowed`, `bad_credentials`, `window_not_allowed` and `unavailable`.
- **DEC-T15-6** — T15 — Window rules: `main` may call all commands; `approval` only `vault_status`, `vault_lock`, `vault_panic`,
  `request_list_pending`, `request_approve`, `request_deny`, `ui_activity`; any other label nothing. Tauri enforces the same list a
  second time: `build.rs` makes `allow-<command>` permissions, `capabilities/main.json` and `approval.json` grant them, and a test
  compares both files with the guard. The `shell` and `fs` plugins are not used.
- **DEC-T15-7** — T15 — Desktop preferences (bind addresses, port, autostart, content protection) are not secret and must be known
  before unlock, so they live in `<data dir>/desktop-prefs.json` (0600). `autostart` and `content_protection` appear in
  `settings_get` and change with `settings_set` (role operator); both are off by default. Content protection has no effect on Linux.
- **DEC-T15-8** — T15 — OS hooks. Linux: logind over D-Bus (`PrepareForSleep`, session `Lock`) with `zbus` blocking proxies on two
  threads. No delay inhibitor is taken, so a very fast sleep can start before the lock task finishes. macOS and Windows: not built.
  They need unsafe FFI (`NSWorkspace`, `WTSRegisterSessionNotification`), which ADR-0012 forbids outside `cerberus-crypto`; the hook
  reports off (`os_hook_ok = false`) and the idle and hard locks still apply.
- **DEC-T15-9** — T15 — The HTTPS server needs the leaf files, which `vault_create` writes. It starts at boot when they exist and right
  after `vault_create`. After each unlock `after_unlock` makes a missing leaf (after a restore) and restarts the server when the owner
  host names changed (the `Host` allow list is fixed at start). A failed start (port in use) shows in `network_status.error`.
- **DEC-T15-10** — T15 — `backup_restore`: role check (`authorize_restore`), `inspect_backup`, then the credential is proved on a
  private copy of the backup opened as a second service (a broken audit chain only logs a warning). Then everything stops, the old
  leaf is removed (it belongs to the old CA), `restore_backup` swaps the file, the new service opens, and one unlock, `lease_revoke_all`
  and lock (reason `restore`) apply ADR-0031 step 3.5. The event pump follows the new service. Gap: core has no way to write the
  `backup.restore` audit event from outside; the lock event with reason `restore` is the only trace. Core change wanted:
  `VaultService::record_restore(ctx)`.
- **DEC-T15-11** — T15 — Not built, returned as `unavailable` after the role and argument checks: `tls_load_custom` (the API crate has
  no loader for an owner certificate, ADR-0023 point 8), `csv_import` and `csv_export` (task T23).
- **DEC-T15-12** — T15 — Added command `clipboard_copy_once { kind: recovery_key | agent_token }` (DEC-036): the backend keeps the last
  one-time value (zeroizing, dropped at lock) and copies it with the 30 s clear. Also: SSH keys made or imported stay in a backend draft
  (`SshKeyDraft.draft_id`, max 8, dropped at lock); `item_create` and `item_update` take the payload kind `ssh_key_draft` for them.
  Argument names differ from interfaces.md only where TypeScript needs it (`phrase_change` takes `current_phrase` and `new_phrase`,
  `new` is reserved) and where `id` became `item`, `workspace`, `agent`, `grant`, `request`, `lease`, `operator` for clarity.
- **DEC-T15-13** — T15 — Clipboard: `copy_and_clear` writes the text, remembers its SHA-256 only, and after 30 s clears the clipboard if
  it still holds the same text; a newer copy cancels the older timer. Paths from the UI (`dest`, `src`, `dest_dir`, key files) must be
  absolute, free of `..`, new files must not exist (a symlink counts as existing), and are written with mode 0600.
- **DEC-T15-14** — T15 — Approval window: label `approval`, 440x640, always on top, not focused on open (it asks for attention), made
  on `AccessRequestCreated` or when the pending count is above 0, destroyed when it reaches 0 or at lock. The tray shows state and a
  count only. Closing the main window hides it when a tray exists; quit locks first (reason `quit`), stops the server, then exits
  (10 s limit). The panic hook calls `emergency_wipe` on the current service, then the previous hook.
- **DEC-T15-15** — T15 — MCP mounted: `cerberus_api::app(&state, cerberus_mcp::mcp_router(&state))`. Log filter is `info` plus
  `cerberus_mcp::LOG_DIRECTIVE` (`rmcp=warn`), tested in `logging.rs`.
- **DEC-T15-16** — T15 — `apps/desktop/ui`: added `@tauri-apps/api` 2.12.5 (the bindings import it) and `src/bindings.ts` to the ESLint ignore
  list (generated file). `bindings.ts` is rewritten by every debug run and checked by `tests/contract.rs`; update it with
  `CERBERUS_UPDATE_BINDINGS=1 cargo test -p cerberus-desktop --test contract`.
- **DEC-FIX8-1** — FIX8 — TLS chain. The server sends `[leaf, CA]`. `TlsPaths` has a new file `tls/ca-cert.der` (the CA
  certificate, public). `LocalCaIssuer` writes it at vault creation; `renew_leaf_if_needed` rewrites it when it is missing or
  differs from the vault CA (also for vaults made before FIX8) and then the resolver reloads, so renewal keeps the chain.
  `read_leaf` adds it to the chain when the file exists. The desktop restore also removes it with the old leaf. Client pinning
  (ADR-0023 point 6: CA SPKI hash, CA must have signed the leaf) is unchanged; tests show a pin-only client works with the real
  server and a pin of another CA is rejected.
- **DEC-FIX8-2** — FIX8 — Restore audit. `VaultService::record_restore(ctx)` appends `backup.restore` (target `vault:<id>`, no
  path, no detail) with `authorize(ctx, Viewer)`: the role comes from the session of the restored vault, never `ctx.role`.
  The desktop calls it in `finish_restore`, after the restored vault is unlocked and verified, before it locks. Reason: before
  the swap the event would go into the old chain that the restore replaces; after the unlock it is in the restored chain, which
  is the vault that exists afterwards. Minimum role is Viewer because the restore was already authorized as owner on the old
  vault, and the restored vault may only have an operator slot for the given credential. The audit write is strict: if it fails
  the vault is still locked, then the command returns the error.
- **DEC-FIX8-3** — FIX8 M1 — Server shutdown. `ApiLimits.shutdown_grace` (default 10 s). `serve_connection` no longer keeps an
  `Arc<GracefulShutdown>` while a request runs, so `RunningServer::shutdown` can own the handle and really wait. After the grace
  time every connection that is still open is cut (a `watch` channel that each connection task selects on). Before, an in-flight
  request kept the Arc, `try_unwrap` failed, there was no wait and the connection stayed open. Test:
  `shutdown_cuts_a_connection_with_a_request_in_flight`.
- **DEC-FIX8-4** — FIX8 M1 — Restore order in `backup_restore`: (1) check role, backup and credential, (2) lock the old vault with
  `LockReason::Restore` (this closes the SSH bridge sockets, cancels pending requests, drops the keys), (3) `clear_held`, (4)
  `stop_all`, (5) swap the file, open the new service, unlock, revoke leases, `record_restore`, lock. `record_restore` stays in
  step 5 (DEC-FIX8-2), so it lands in the restored chain and the lock of step 2 lands in the old chain. Test: the old
  vault emits `Sealed` before the swap (`backup_and_restore_round_trip`).
- **DEC-FIX8-5** — FIX8 M2 — `ssh_sign` opens the key and signs after it drops the vault write guard, on `spawn_blocking`. Under the
  guard it parses the key (an encrypted key keeps its public part), checks ed25519 and that a passphrase exists, compares the key
  blob, writes the strict `ssh.sign` event, and returns a `SignJob`. A failed open after that writes a second `ssh.sign` event with
  the error code. `ssh_prepare` still decrypts under its write guard: it must keep check, key read and audit atomic (DEC-FIX7-2) and
  runs once per lease use, not once per signature; left as is.
- **DEC-FIX8-6** — FIX8 L3 — Held one-time values and SSH drafts carry a tag: operator id and unlock time. `one_time`, `draft` and
  `put_draft` are async, compare the tag with the current session, drop stale values, and refuse on mismatch (a lock and unlock
  during an event lag cannot serve an old value to another operator). `vault_lock` and `vault_panic` call `clear_held` directly;
  the pump on lag clears them when the vault is not unlocked. A value cannot be stored with no unlocked session.
- **DEC-FIX8-7** — FIX8 L4 — `SshTicket::carry_rate_window(previous)`: `Socket::replace_ticket` copies the per-minute sign window of
  the old ticket into the new one, so a second prepare on the same lease cannot reset `SIGNS_PER_MINUTE`. The total sign budget is
  not copied (the new prepare spent a new lease use). Edit outside the first scope list: `crates/cerberus-ssh-agent/src/socket.rs`,
  asked by the orchestrator.

## T16 — UI foundation (2026-11-17)

- **DEC-T16-1** — T16 — Screen folder convention (T17–T20 follow it; no shared file is edited). One folder per screen id:
  `apps/desktop/ui/src/screens/<id>/`, ids `create unlock dashboard vault editor agents policies approval leases audit settings`.
  The router loads `src/screens/<id>/route.tsx` by name with `import.meta.glob` (`shell/registry.tsx`), so a screen task only
  replaces that file. `route.tsx` must `export default` the screen component. The folder may hold any other files (components,
  hooks, `queries.ts`, tests). Optional fixed names: `messages.ts` (strings, `defineMessages` + `useScreenT` from `src/i18n`)
  and `mock.ts` (`export const handlers: MockHandlers`, merged into the dev mock by `ipc/mock/dev.ts`). Do NOT edit
  `shell/screens.ts` (routes, nav, `G` keys), `shell/*`, `ui/*`, `i18n/en.ts`, `ipc/*` (except new query keys inside your own
  folder), `styles/*`, `package.json`. Missing shared piece: put the request in your report. Screen CSS goes in a CSS file
  inside the screen folder, imported by `route.tsx`, using only `var(--c-*)` tokens and the classes of `styles/app.css`.
- **DEC-T16-2** — T16 — Routing. `wouter` 3 with hash location (`index.html#/vault`): one HTML file, no server fallback, and the
  backend opens the approval window at `#approval` (normalised to `/approval`). `Router base` is set to the screen path, so
  inside a screen `<Route path="/new">` means `/vault/new`; use `navigate("~/agents")` for an absolute path. Paths: `/create
  /unlock /dashboard /vault /editor /agents /policies /approvals /leases /audit /settings`. Editor sub-paths: `/editor/new`,
  `/editor/:id`. Deep links the palette uses (screens should read them): `/vault?item=<id>`, `/agents?agent=<id>`, `/agents?new=1`,
  `/policies?new=1`. Guard table in `shell/guard.ts` (IA section 1). The window label picks the layout: `approval` shows the
  approval screen alone, with no rail.
- **DEC-T16-3** — T16 — Data and events. TanStack Query 5 with one client per window. `ipc` (`ipc/client.ts`) mirrors every
  generated command but returns data and throws `IpcFailure` with `UiError { code, message, command, retryAfterSeconds, fields }`;
  a transport failure becomes code `ipc_unreachable`. Any `vault_locked` / `no_vault` error re-reads `vault_status`, so the guard
  moves to unlock. Query keys are in `ipc/keys.ts`; event invalidation by prefix. `EventBridge` handles all 10 events and writes
  `state/live.ts` stores (`autolockStore`, `agentFeedStore`, `alertsStore`, `vaultStateStore`). When the vault leaves `unlocked`
  every query except `["vault", …]` is removed and the live stores are reset (I-16). Hooks for screens: `useVaultStatus`, `useRole`,
  `useCan(role)`, `useAutolockSeconds`, `useTauriEvent(events.x, fn)`, `useCountdown`.
- **DEC-T16-4** — T16 — Styling. Plain CSS on the generated tokens, not Tailwind: the prototypes (`docs/ux/prototypes/assets/app.css`)
  are the target and port 1:1, and the Tailwind map in `tokens.json` stays unused. `pnpm tokens` writes `src/styles/tokens.css`
  from `docs/ux/tokens.json` (`pnpm lint` fails when it is stale). Fonts Inter and JetBrains Mono are bundled from
  `src/assets/fonts` (OFL licences kept; superseded 2026-11-19 (0.3.0): Geist + Geist Mono, same folder); no remote content, CSP `style-src 'self'` holds (no inline style attributes except the
  CSSOM variable `--hold-ms`). Density is `data-density="comfortable|compact"` on `<html>` (variables `--ctl-md`, `--ctl-sm`,
  `--row-y`); theme is `data-theme` (none = follow the OS). Both come from `usePrefs()` and live in localStorage.
- **DEC-T16-5** — T16 — SecretField takes callbacks, not item IDs: `onReveal` (call `item_reveal`) and `onCopy` (call
  `clipboard_copy_secret` or `clipboard_copy_once`). The backend clears the clipboard after 30 s; the UI shows a toast with a 30 s
  ring. Auto-hide 15 s, hold 500 ms, value dropped on hide, unmount and lock. Radix Dialog is used for dialog, drawer and palette
  (focus trap and return). Only English is in the catalog; `usePrefs().language` exists so a second language needs no refactor, and
  the palette has no language switch until then.
- **DEC-T16-6** — T16 — Dev mock. In `pnpm dev` without Tauri, `ipc/mock/dev.ts` installs `mockIPC` with fake data (URL
  `?mock=unlocked|sealed|no_vault|locking&role=viewer`, console `__cerberusMock.setState("sealed")`). It is behind
  `import.meta.env.DEV`, so it is not in the release bundle. Tests use `test/renderApp.tsx` (app on the mock) and
  `test/renderUi.tsx` (component with toasts).
- **DEC-T25-1** — T25 — Fuzz crate `fuzz/` (package `cerberus-fuzz`) is outside the main workspace: it has its own empty
  `[workspace]` and the root `Cargo.toml` lists it in `exclude`. So `cargo test --workspace`, clippy and `cargo deny` stay stable-only.
  Targets (nine): `envelope_open`, `key_slot` (also the vault header MAC input), `recovery_parse`, `phrase_policy`, `token_parse`,
  `rest_json` (all wire request DTOs and their `convert::*` functions), `resolve_query`, `mcp_args`, `ssh_frames` (frame reader and
  request parser). Not fuzzed: CSV (not built), the SQLite row decoders (they take a database row, not bytes; the values they read go
  through `KdfParams::new`, `bytes32` and serde enums, which `key_slot` and `rest_json` cover). The fuzz crate uses no `unsafe`.
- **DEC-T25-2** — T25 — The MCP tool inputs are private structs. One `#[doc(hidden)]` function, `cerberus_mcp::arguments_parse(tool, args)`,
  parses the arguments of a tool by name and returns whether they are valid (each tool file has a `pub(super)` helper next to its
  `Input`). It is the only change outside the fuzz crate, tests and vectors. No other parser needed an extra entry point.
- **DEC-T25-3** — T25 — Corpora: `fuzz/corpus/<target>/` holds small hand-made seeds (fake values only) and is read only. The
  recipes `just fuzz-smoke` and `just fuzz` pass `fuzz/work/<target>` first, so new inputs go to that ignored directory and the
  committed seeds do not grow. `fuzz/artifacts/` and `fuzz/target/` are ignored: a crash file may hold fuzzer-built secrets-like
  text, so review it before you commit it as a regression test. Fuzz is not part of `just check` or `just test`.
- **DEC-T25-4** — T25 — Result of the first full run (180 s per target, no seed crash, no hang, no out-of-memory): no crash was found,
  so no code under test changed and no regression test was needed. Argon2id is opened by `key_slot` only at the lowest accepted cost
  (19 MiB, t = 1, p = 1), because `KdfParams::new` already refuses every other cost the fuzzer builds from stored numbers.
- **DEC-T25-5** — T25 — Known answers added to `cerberus-crypto` `src/tests/kat.rs`: HMAC-SHA-256 from RFC 4231 cases 1 to 4 and 6
  (through the `hmac` crate and, for the keys of 32 bytes or less, through `hmac_sha256`: HMAC pads a short key with zero bytes, so
  the same key padded to 32 bytes gives the same tag), and SHA-256 from FIPS 180-4 ("abc", empty). XChaCha20-Poly1305, HKDF-SHA256
  and Argon2id vectors were already there (draft-irtf-cfrg-xchacha-03 A.3.1, RFC 5869 A.1 and A.3, RFC 9106 5.3).
- **DEC-T25-6** — T25 — Golden vectors of the formats, one text file of `name = hex` lines per crate, decoded by an integration test:
  `crates/cerberus-crypto/tests/vectors/format_v1.txt` with `tests/vectors.rs` (passphrase slot at the lowest Argon2id cost, recovery
  slot, key tree keys, header MAC, item DEK wrap, payload envelope, row MAC) and
  `crates/cerberus-core/tests/vectors/audit_chain_v1.txt` with `tests/audit_vectors.rs` (genesis hash, three linked entry hashes and
  row HMACs). The audit vectors were computed with Python from ADR-0025, not with Cerberus code. The crypto vectors were made once
  with the crate (the envelope nonce is random). All phrases, keys and payloads in them are fake. A format change must break these
  tests; the fix is a new format version and a migration (ADR-0013), never a regenerated file.
- **DEC-FIX9-1** — FIX9 — Custom certificate storage. The chain and the key are sealed in one vault setting `tls_custom`
  (`seal_setting`, vault keys), as ADR-0023 point 8 says; the local CA key is sealed in the DB the same way (`ca_key`). Nothing is
  written to `tls/`, so no key file exists on disk. The server needs an unlock to serve it. Core API:
  `tls_custom_store`, `tls_custom_clear`, `tls_custom_material`; owner only from the session via `authorize`. The
  pin changes: `pin` and `ca_fingerprint` of the network view are those of the top certificate of the served chain (the local CA,
  or the last certificate of the custom chain). Clients that pin the local CA must pin the new value. The agent client CA (mTLS)
  stays the local CA.
- **DEC-FIX9-2** — FIX9 — Checks at load (`parse_custom_pem`): PEM parses; at most 8 certificates, leaf first, each followed by
  its issuer; no certificate expired or not yet valid; leaf is not a CA; EKU allows `serverAuth`; no MD5/SHA-1 signature; key is
  PKCS#8, SEC1 or PKCS#1, not encrypted, a type that rustls/ring signs (P-256, P-384, Ed25519, RSA of 2048 bits or more) and
  matches the leaf (`keys_match`). SAN rule: the leaf must have a SAN for every owner host name (vault host names); when there are
  none, for at least one standard name (`localhost`, `127.0.0.1`, `::1`, the host name). A wildcard covers one label.
  Reason: a public certificate never holds `127.0.0.1`, so the full local name list cannot be required.
- **DEC-FIX9-3** — FIX9 — Live switch. `LeafResolver` holds the active certificate and a `custom` flag. `RunningServer::apply_tls`
  (and the renewal task, at start and at every unlock) puts the stored custom certificate in the resolver, or reloads the local
  leaf when there is none. `reload` and `renew_leaf` do nothing while custom, so renewal never overwrites it. Dates are
  not checked again when the stored certificate is served: an expired custom certificate is still served (the UI shows
  `leaf_not_after`), because falling back to the local CA without notice would change the pin.
- **DEC-FIX9-4** — FIX9 — Audit. `tls.custom_load` (written by `tls_custom_store`, detail `chain_len`) and the new
  `tls.custom_revert` (written by `tls_custom_clear` only when a custom certificate existed). Target `settings`/`tls`. No
  content, no path.
- **DEC-FIX9-5** — FIX9 — Desktop. `tls_load_custom(chain_path, key_path) -> NetworkView` is real; new
  `tls_use_local_ca() -> NetworkView` (owner). A bad certificate gives `validation_failed` with field `certificate` and a plain
  reason. Only file names are logged. `NetworkView` has a new field `custom_cert: bool`. `tls_export_ca` exports the top
  certificate of the active chain.
- **DEC-FIX9-6** — FIX9 — cerberusd. The config cannot point at a custom certificate; loading is desktop only. A daemon whose vault
  holds a custom certificate (for example restored from a desktop backup) serves it after unlock, because the renewal task
  applies it. `ca-cert.pem` that the daemon writes stays the local CA; see `docs/guides/cerberusd.md`.

## T20 — Dashboard, Audit and integration guide (2026-11-17)

- **DEC-T20-1** — T20 — The integration guide is a wide dialog ("Connect an agent") inside `screens/dashboard` (`ConnectGuide.tsx`), opened from the dashboard band and from the empty state. It has three steps (create a token in Agents, export the CA, add the connection) and tabs MCP, REST and CLI. Snippets are built in `snippets.ts` from `network_status` (address, CA fingerprint, pin). No token is ever shown: snippets use a token file or `$CERBERUS_TOKEN`. A viewer can read the guide but the "create a token" button is disabled.
- **DEC-T20-2** — T20 — The dashboard band has no Lock and no "Lock and revoke all" button. The shell collar already has both on every screen, and a second "Lock" button would duplicate the control (and break the shell tests that look for one). The band keeps the auto-lock countdown, hard-lock time, activity trace and "Connect an agent".
- **DEC-T20-3** — T20 — KDF cost is not in any IPC view (`vault_status`, `settings_get`, `network_status` do not carry it; `kdf_benchmark` measures the machine, not the vault). The health row says the cost is set at vault creation and links to Settings. Request to the backend: add the vault KDF params (`m_cost_kib`, `t_cost`, `p_cost`, measured ms) to `vault_status` or `settings_get`; then the row can show "256 MiB, 3 passes".
- **DEC-T20-4** — T20 — The live feed is seeded with the last agent events from `audit_query` (limit 40, `actor_kind = agent`) and then fed by `agent-activity` events. Events are merged and de-duplicated by time, agent, type and item. Metadata only.
- **DEC-T20-5** — T20 — Audit filters: time range, event type (exact type, all 63 catalog types) and agent go to `audit_query`; outcome (ok or failed) is applied to the loaded pages because `audit_query` has no result filter. The default range is "All time" so a clear-filters reset and an empty log do not loop. Pages are 100 events with a `before_seq` cursor.
- **DEC-T20-6** — T20 — Chain check: the dashboard and the audit screen share the query key `["audit","verify"]`, so both show one answer. When the chain is broken, the audit screen marks the event at `broken_seq` ("Chain breaks here"), shades every event from there on (newest first, so higher `seq`), and offers "Load back to event N" when that event is older than the loaded pages. `break_kind` (the Rust variant name) maps to a plain sentence.
- **DEC-T20-7** — T20 — Untrusted data: in the audit details, every string of an agent event, and any `reason` key, goes through `UntrustedText`. Agent and item names are plain React text. Dev mock scenarios by URL: dashboard `?scenario=empty|error|quiet|cert-soon`, audit `?scenario=broken|empty|error|slow`.
- **DEC-T20-8** — T20 — Inside screens, navigation to another screen uses `navigate("~/agents?new=1")` (the router base is the screen path, DEC-T16-2).

## T19 — Agents, Policies, Approval and Leases (2026-11-17)

- **DEC-T19-1** — T19 — Token handling. `agent_create`, `agent_key_create` and `agent_key_rotate` are called straight from the dialog code (not `useMutation`), so the reply with the token never enters the TanStack mutation cache. The token lives in one `useState` of the agents screen, is shown in a non-dismissible dialog, and is cleared on Done, on unmount and when `vault-state-changed` leaves `unlocked`. Copy uses `clipboard_copy_once("agent_token")` with the 30 s clipboard toast. Done stays off until the person confirms the token is stored.
- **DEC-T19-2** — T19 — The approval screen has two layouts chosen by `windowLabel()`: the small window (one card, queue count, result panel, burst view) and the `/approvals` page in the main window (all cards, toasts, burst notice with "Deny all" and "Suspend agent"). The approval window can call only 7 commands, so Suspend exists only in the page. Approve by mouse click is at once; by keyboard it is a 0.6 s hold (Enter or Space on the button, or A, F, S anywhere in the window). D and the Deny button deny at once. Deny takes focus when a request shows, so Enter never approves.
- **DEC-T19-3** — T19 — "Lock and revoke all" on Leases opens the shell panic dialog (`openOverlay("panic")`, 1 s hold, `vault_panic`) instead of a second implementation. "Revoke all leases" is a danger confirm dialog with Cancel focused (`lease_revoke_all`). Both work for every role (DEC-WIRE6-11).
- **DEC-T19-4** — T19 — Grant builder maps the sentence to one value per slot (workspace, env, category, permission). A saved grant that has several values shows "several" in that slot until changed, and saving keeps them if untouched. Mode words: never = `auto`, once = `ask_once`, always = `ask_always`, "block it" = `deny`. The "allow prod without asking" switch is shown for env prod or any env with mode never, and is disabled unless the role is owner.
- **DEC-T19-5** — T19 — Leases rows join `agent_list` and `item_list` for names (a failed join shows "Unknown agent" or the item ID). Session items are `item_list` with kind `session_token` and `browser_session`; the ring total is `expires_at - updated_at` (the summary has no creation time). Lease queries sit under the `["leases", …]` prefix so `lease-changed` refreshes them.
- **DEC-T19-6** — T19 — Fixtures (`agents/fixtures.ts`) use the dashboard IDs (`agent-qa`, `it-admin` …) so merged dev mocks stay consistent. Each `mock.ts` exports `handlers` for the dev merge and a factory (`agentHandlers()` …) for tests with fresh state. Dev switches: `?mock_agents|mock_policies|mock_approval|mock_leases=empty|error|slow` (approval also `burst|expired|noreason`). Because `ipc/mock/dev.ts` merges with `Object.assign`, the dashboard mock wins `agent_list` and `request_list_pending` in `pnpm dev`; the leases mock wins `item_list` and `lease_list` over it. Screenshots inject the T19 handlers over the dev mock.
- **DEC-T19-7** — T19 — Deep links `?agent=`, `?new=1` are read from `window.location.hash` after the `?` (the hash location hook keeps the query in the path).

## T17 — Create, Unlock, Settings screens (2026-11-17)

- **DEC-T17-1** — T17 — Create wizard keeps the screen while the vault is already open. `vault_create` leaves the vault `unlocked`, and the guard (`shell/guard.ts`) sends a solo screen to the dashboard at once, which would drop the recovery key before it is saved. `create/hooks.ts` `useStatusPin` writes any non-`no_vault` status back as `no_vault` in the query cache from the start of creation until "Open the vault" (then it reads the real status). Proper fix for the shell owner: let the guard keep `create` while a wizard is on its recovery step. Step order follows the prototype (name, phrase, cost test, create, recovery key), not the plan list: `vault_create` needs the KDF cost and returns the key.
- **DEC-T17-2** — T17 — The recovery key is shown in a numbered plain grid (`create/RecoveryKeyGrid.tsx`, shared with the Settings rotate dialog), not in `SecretField`: a person must read and transcribe 15 groups, and a 15 s auto-hide would block that. The key is a prop of the wizard/dialog, cleared on finish, never in `title`/`aria-label`. Copy uses `clipboard_copy_once("recovery_key")` (the page never writes the key to the clipboard). Phrases are native password inputs in component state, cleared after success or failure.
- **DEC-T17-3** — T17 — Unlock counts failed tries in the window only (the backend sends no count); the wait comes from `too_many_failures.retry_after_seconds`. "After 5 in a row" mirrors `FREE_UNLOCK_FAILURES`. A recovery key format error is a field error and is not counted (DEC-008). `unavailable` (unsupported KDF cost) has its own notice. No lock reason (idle, panic) is shown: `vault_status` carries none.
- **DEC-T17-4** — T17 — Settings uses the real command set. Unlock cost: "Test this device" runs `kdf_benchmark`; the new cost applies through `phrase_change(kdf)` (there is no command to read the vault's current cost). Custom TLS certificate (FIX9) is wired: `tls_load_custom` (two file pickers, reason on the chain field), warning while `custom_cert` is true, `tls_use_local_ca` behind a confirm. CSV import/export stay disabled with a reason (stubs). Theme, density, language come from `usePrefs`; language lists English only. "Last backup" is not shown (no source for it). Restore (`RestoreDialog`) is shared with the unlock screen's no-vault state; it uses the dialog plugin `open` directly (permission `dialog:allow-open` exists), because `ipc/dialogs.ts` has only `save`.
- **DEC-T17-5** — T17 — Dev mocks: `settings/mock.ts` also answers `network_status`, which `dashboard/mock.ts` answers too; the glob merge is alphabetical, so settings wins in `pnpm dev`.

## T18 — Vault browser and item editor (2026-11-17)

- **DEC-T18-1** — T18 — Data. The vault screen loads every item once (`item_list {}`, metadata only) and runs the workspace, category, tag, kind, environment and role filters and all facet counts in the browser, because the filter has no role or category and the counts must not change while filtering. Free text goes to the backend (`item_list { q }`, so synonyms work) and the answer is intersected with the list. Keys sit under `["items", ...]` and `["workspaces"]`, so a lock removes them (DEC-T16-3). TTL rings show for session kinds only; the span is `updated_at` to `expires_at` because the summary has no creation time.
- **DEC-T18-2** — T18 — Secrets in the drawer. Each secret field is a `SecretField` that calls `item_reveal` on its own hold (one audited reveal per field) and `clipboard_copy_secret` to copy. The one-time code reveals through `item_totp_preview` and copies with field `totp`. SSH items show no private key in the drawer. Viewers get `denied` fields and no call is made. Env bundles show `NAME=value` pairs in one field with no copy button (field names are unknown before a reveal).
- **DEC-T18-3** — T18 — Editing reads the secret. `item_update` needs the full payload and `ItemSummaryView` has no payload, so the editor calls `item_reveal` once to fill the form (audited, `gcTime: 0`). An item with a reveal limit asks first, because the read uses one reveal. Kind is locked when editing. For an SSH item the existing key goes back unchanged inside the payload unless the person imports or generates a new one (draft ID). Gap: a metadata-only update would need an IPC option to keep the payload. Also `custom` values other than the SSH `machine`, `host`, `port`, `user` are not returned by any command, so they are lost on update.
- **DEC-T18-4** — T18 — SSH files. The native dialog (`dialog:allow-open`) and the shell's drag-drop event give a path that goes only to `ssh_key_import { kind: "path" }`. In a plain browser the file text is read once and sent as `{ kind: "pem" }` (limit 64 KiB checked first). Paths and text are never logged, stored in state or shown in toasts. The native drop handler takes a drop anywhere on the window while the SSH panel is open.
- **DEC-T18-5** — T18 — TOTP preview. `item_totp_preview` works on a saved item, but the form needs a preview while typing. The preview computes RFC 6238 codes with Web Crypto in the form (the seed is already in the form state), with a test on the RFC vectors. A missing `crypto.subtle` shows a plain "cannot preview" line.
- **DEC-T18-6** — T18 — Hand-off and deep links. The hash location keeps `?item=` inside the path, so `screenForPath` does not match `/vault?item=<id>` and the shell redirects (reported to T16). The vault reads `?item=` from `useSearch()` and from the hash, and the editor hands the saved item ID to the vault through `vault/selection.ts` (a module variable), not through the URL.
- **DEC-T18-7** — T18 — Slots for T23. `vault/slots.tsx` holds `TOP_BAR_SLOTS` and `EMPTY_STATE_SLOTS`: arrays of `{ id, visible, render }`. T23 adds entries there. There is no placeholder button. Workspaces can be created (dialog from the sidebar, the empty state and the editor); rename and delete are not part of this task.
- **DEC-T18-8** — T18 — Dev mock. `vault/mockData.ts` has an in-memory vault for every command the two screens use and tests import it. `vault/mock.ts` installs it in `pnpm dev` (`?items=empty|error|slow` for states). Its handlers answer `item_list`, `workspace_list` and `settings_get`, and load after other screens' mocks, so they win for those commands.

## INT10 — Shell fixes after the screens (2026-11-17)

- **DEC-INT10-1** — INT10 — Hash query. `useHashLocation` (`shell/location.ts`) returns the path only (`/agents`) and has a `searchHook`, so wouter `useSearch()` and the new `useHashQuery()` return the query of `#/agents?new=1`. `useHashQuery(): URLSearchParams` updates on `hashchange` and also works under `memoryLocation` in tests. `screenForPath` ignores a `?query` too (`splitQuery`). This replaces the `window.location.hash` parsing in DEC-T18-6 and DEC-T19-7: vault, agents and policies read `?item=`, `?agent=` and `?new=1` with `useHashQuery()` (initial state only, as before). `hashParam` is removed.
- **DEC-INT10-2** — INT10 — Create flow. `shell/createFlow.ts` exports `createFlowStore` (a boolean store). The wizard sets it to true before `vault_create` and to false on failure, on "Open the vault" and on unmount. `resolveRoute(state, screen, creating)` keeps the `create` screen while the vault is `unlocked` and `creating` is true; the other rows are unchanged. This replaces the `useStatusPin` workaround of DEC-T17-1, which is removed.
- **DEC-INT10-3** — INT10 — Dialogs. `ipc/dialogs.ts` also has `openFile`, `openFiles` and `pickDirectory` (title and filters; `string | null`, `string[] | null`, `string | null`). Screens switch to them later; the plugin `open` calls in settings and editor stay for now.
- **DEC-INT10-4** — INT10 — Test timeouts. `vite.config.ts` sets `testTimeout` and `hookTimeout` to 30 s, and `test/setup.ts` sets the Testing Library `asyncUtilTimeout` to 8 s, because axe and the first render are slow when suites run in parallel. Per-file `vi.setConfig`, `configure`, `{ timeout }` and per-test timeout arguments are removed from the screen tests.
- **DEC-INT10-5** — INT10 — `just node-check` fails with a clear message when Node is missing or older than 22 (see `.nvmrc`). `check`, `test`, `dev`, `ui-install` and `ui-check` depend on it, so a wrong Node stops the run before any slow Rust step.
- **DEC-INT10-6** — INT10 backend — Keep payload on `item_update`. Core: `update_item(ctx, id, impl Into<ItemUpdate>)`, with `ItemUpdate = ItemInput<PayloadChange>` and `PayloadChange { Keep, Replace(Payload) }`; an `ItemInput` converts to `Replace`, so create and the old callers are unchanged. `Keep` is a metadata-only update done in place: the version number, the payload ciphertext and the wrapped DEK are not touched (the payload AAD holds the version, so a new version would force a re-seal). The `items.meta_ct` and the `item_versions.meta_ct` snapshot of the current version are re-sealed (new store call `Tx::update_version_meta`), so the history shows the new title. `use_count`, `has_totp` and the kind come from the stored item. Metadata rules, title clash, `max_uses`, expiry and the end of approval leases on a move to another environment or workspace are the same as for a replace. No `item.reveal` is written; `item.update` carries `version` and `payload: "kept"`. A past metadata value of the current version is not kept in the history (accepted). IPC: no new argument. `PayloadView` gets the input-only kind `keep` (`{ kind: "keep" }` in TS) next to `ssh_key_draft`; `item_create` answers `validation_failed` for it. This closes the gap of DEC-T18-3: the editor can save metadata without `item_reveal`.
- **DEC-INT10-7** — INT10 backend — `custom` in item views. All `custom` values are non-secret metadata (they live in the item metadata blob, not in the payload; secret extras are in the payload: `cloud.extra`, `database.params`, env vars). `ItemSummary` (core) and `ItemSummaryView` (IPC: `item_list`, `item_get.summary`, `item_reveal.summary`, `item_create/update` results) get `custom: Record<string, string>`. The core field is `#[serde(skip)]` and the Agent API wire types are built field by field, so agents do not get it. This closes the second gap of DEC-T18-3: the editor can fill `custom` and send it back.
- **DEC-INT10-8** — INT10 backend — KDF cost of the vault. `vault_status.kdf = { m_cost_kib, t_cost, p_cost } | null`. The cost is per passphrase slot (each operator has one, `phrase_change` can change it), so it is the cost of the slot of the session operator, read from the key slot table. `null` while sealed and for a recovery session (the recovery slot uses HKDF). No measured time exists in the vault (the benchmark is a device test), so `measured_ms` is not returned. Answers DEC-T20-3 and the "current cost" gap of DEC-T17-4.
- **DEC-INT10-9** — INT10 backend — Lock reason. `vault_status.last_lock_reason` is the reason of the latest lock that dropped the keys in this process: `manual | idle | max_unlocked | os | quit | panic | restore`, or `null` when the vault was not locked in this run. `panic` covers the panic button and the process panic hook. The value is memory only and stays after the next unlock (the UI reads it while `sealed`); a restart resets it to `null`. A lock request that finds the vault already sealed does not change it. Answers DEC-T17-3 (lock reason).
- **DEC-INT10-10** — INT10 backend — Unlock failures in the backend. `vault_status` has `failed_unlocks` (the header counter, kept across restarts and windows), `free_unlock_tries_left = max(0, FREE_UNLOCK_FAILURES - failed_unlocks)` and `retry_after_seconds` (`null` when no wait runs, else the seconds until the next try, from the header time of the last failure and the same wait function as the unlock check). A recovery key format error is still not a failed unlock (DEC-008). The counters work while sealed; a good unlock resets them. Answers DEC-T17-3 (window-local count).
- **DEC-INT10-11** — INT10 backend — Audit outcome filter. `AuditQuery.outcome: Option<AuditOutcome { Ok, Failed }>`; `audit_query` takes `outcome?: "ok" | "failed"`. `ok` matches events whose result is `ok`, `failed` every other result (an error code). The filter runs with the other parts, before the page limit, so pages are full and `before_seq` paging stays right. The key may be left out in IPC (serde default). Answers DEC-T20-5: the audit screen can drop its page-local filter.
- **DEC-T23-1** — T23 — Parser. `csv` 1.4.0 (latest stable, checked 2026-11-17), used in `cerberus-core::csvio` only; the UI and the desktop layer never parse. The core takes bytes and does no file I/O. Limits: file 8 MiB (`MAX_FILE_BYTES`, also checked by the desktop layer before it reads and again after, so a growing file is caught), 20000 data rows, 64 columns, 128 KiB per cell. A UTF-8 byte order mark is dropped; invalid UTF-8 and UTF-16 (BOM) are refused with a clear message ("save it as CSV UTF-8"). CRLF, LF, quoted new lines, doubled quotes and ragged rows work (`flexible`); the delimiter (comma, semicolon or tab) comes from the header line; empty lines are skipped. A row with more cells than the header is a row problem, a shorter row has empty cells. Cells are `Zeroizing<String>`, the file bytes are `Zeroizing<Vec<u8>>` in the desktop layer, and an export is built in one pre-sized `Zeroizing` buffer. The `csv` crate keeps its own 8 KiB read buffer and one reused record, which cannot be zeroized (accepted: process memory is not dumpable and mlock covers keys only).
- **DEC-T23-2** — T23 — Formats. `CsvSource`: `auto` (detect from the header), `bitwarden` (`login_uri`, `login_username`, `login_password`, `login_totp`, `type`, `folder`), `onepassword` (v7 `Title,Website,...,Type,Folder` and v8 `Title,Url,...,OTPAuth,Archived,Tags,Notes`), `keepassxc` (`Group,Title,...,TOTP`), `chrome` (also Edge, Brave, Opera: `name,url,username,password,note`), `firefox` (no title: the host of the URL is the title), `generic` (Cerberus export or any file; a column mapping, field name to header name, on top of name aliases). Imported kinds: `web_login`, `note`, `api_key`, `session_token`, `database` (secret = URL), `env_bundle` (secret = JSON object or `KEY=VALUE` lines). A row without a kind column is a login when it has a user, password or URL, else a note. Cards, identities, SSH keys, cloud, certificates and browser sessions are `unsupported_kind` row problems (they are exported, but a CSV cell cannot carry them safely back; use the editor).
- **DEC-T23-3** — T23 — Row rules. The row title is the title column or the host of the URL. A URL that is not http(s) (for example `android://...`) stays only in `target` (metadata, 512 characters), a bare host gets `https://`. A login has no notes field, so notes of a login are left out and counted (`notes_dropped`, shown in the preview): notes in `description` would reach the agent catalog and could hold secrets. The folder, group or tags column becomes tags (split on `,` or `;`, 20 at most). Environment and role label come from the user's target unless the row has its own. A row is checked with `validate_item` like an editor save; a failure is `invalid_value` with the field name, never the value. Preview rows hold row numbers, codes and titles of duplicates (metadata), never a cell.
- **DEC-T23-4** — T23 — Preview and commit. `csv_preview` and `csv_import` both read the file (no server cache of parsed rows: nothing secret waits between the two calls), plan it the same way, and the commit runs `insert_items_batch`: all items are validated and sealed first, then one database transaction inserts them, and the index changes only after the commit, so any failure adds nothing. A title that is already in the workspace is skipped (`skip`, default: a second import adds nothing) or gets a number (`rename`, `Title (2)`); a title repeated inside the file always gets a number. If the vault changes between preview and commit and a title clashes, the batch fails with `conflict` and nothing is written. Role: operator, from the session (`authorize`), never `ctx.role`; a viewer is refused before the file is read.
- **DEC-T23-5** — T23 — Audit. Two new event types, in `docs/reference/audit-events.md` and the catalog: `items.import` (target workspace; details `source`, `imported`, `skipped_problems`, `skipped_duplicates`, `renamed`) and `items.export` (target vault; `count`, and `workspace_id` when scoped). One event per call, counts only, no titles, no paths, no values; imported items do not write one `item.create` each. The import event is written after the commit (best effort like `item.create`); the export event is written strictly before the bytes leave the core, so no secret export exists without its event. If the file write fails after that, the event stays and the half file is removed. The audit screen shows the raw type name for these two until it gets a phrase (`screens/audit/catalog.ts` was outside this task).
- **DEC-T23-6** — T23 — Export. Owner only (session role, checked in the desktop layer before the path is used and in the core before any item is read). Columns: `workspace,title,kind,environment,role,category,tags,url,username,password,secret,totp,description,extra`; every kind is exported (`secret` is the main secret, `extra` is JSON for the rest, TOTP is an `otpauth://` URI) and a Cerberus export imports again as `generic` for the importable kinds. Every cell goes through the OWASP guard: a cell starting with `=`, `+`, `-`, `@`, tab or CR gets a leading `'`; a cell that starts with `'` plus such a character gets one more `'`, so the `generic` import undoes it exactly (other sources are not un-guarded). The file is made by `write_new_private` (`create_new`, mode 0600, never over an existing file or symlink), the path comes from the native save dialog and is checked by `files::new_file`. Not exported: custom fields, expiry, use limits, version history.
- **DEC-T23-7** — T23 — IPC. New command `csv_preview { request } -> ImportPreviewView` (main window, operator); `csv_import { request } -> ImportReport` replaces the stub that took `path, workspace_id, mapping` (the request adds `source`, `environment`, `role_label`, `duplicates`); `csv_export { dest, workspace_id? } -> u64` as stubbed. `ImportReport` now has `imported, skipped_problems, skipped_duplicates, renamed, notes_dropped`. `allow-csv-preview` is in `capabilities/main.json`; the dialog permissions (`dialog:allow-open`, `dialog:allow-save`) were already there. Desktop file I/O is in `ops/csv.rs`; `docs/interfaces.md` section 9 lists the new row (66 commands).
- **DEC-T23-8** — T23 — UI. Components are in `screens/vault/csv/`: `ImportWizard` (file, format and mapping, target, preview, result), `ExportDialog` (plain-text warning, confirmation box, scope, native save dialog), `CsvButtons` (`ImportButton`, `ExportButton`). The vault screen adds them through `slots.tsx` (`csv-import` for operators with a workspace, `csv-export` for owners with items; the empty state has the import button) and Settings > Backup uses the same buttons (two rows, each with its own role note). The wizard reads the header with a first `csv_preview` call against the first workspace (dry run), guesses a column mapping from the header names, and offers the mapping table when the header is unknown or `generic` is chosen. The path is typed or chosen with `openFile` from `ipc/dialogs.ts`; only the path is sent, never the file text. The dev mock (`csv/mock.ts`) picks the answer from words in the path.
- **DEC-INT10-12** — INT10 UI — Shared dev fixtures. `src/ipc/mock/fixtures.ts` is the one fake data set: workspaces (`ws-shop`, `ws-billing`, `ws-infra`), agents (`agent-qa`, `agent-rel`, `agent-docs`, `agent-price`, `agent-old`), 12 items (`it-stage`, `it-admin`, `it-deploy` …), leases (`lse_1` to `lse_6`), pending requests (`req_1`, `req_2`), settings, network, and the unlock cost. Every lease, request and grant points at an agent, item and workspace that exist there. `installMock` answers the shared reads (`vault_status` with the new fields, `agent_list`, `item_list`, `workspace_list`, `lease_list`, `request_list_pending`, `settings_get`, `network_status`) from it, so a test with no screen mock gets coherent data. Each command has one owner in the screen mocks: agents (`agent_*`), vault (`item_*`, `workspace_*`, CSV), leases, approval, policies, settings (`settings_*`, `network_*`, TLS, operators), audit, unlock, create. `dashboard/mock.ts` is removed, because the dashboard only reads. `mergeHandlers` in `ipc/mock/dev.ts` throws when two screen mocks answer one command, and `ipc/mock/dev.test.ts` checks the merge and the cross references. `?scenario=empty|quiet|error|cert-soon` is read by the factories and by the owners of the data. This removes the reasons for the "wins" notes in DEC-T17-5, DEC-T18-8 and DEC-T19-6. The dev switch `?lock_reason=idle` sets the last lock reason.
- **DEC-INT10-13** — INT10 UI — Editor keeps the secret. Editing does not call `item_reveal`. The form fills from `item_get` only, shows "The secret is unchanged" and saves `payload: { kind: "keep" }`. "Replace secret" shows the empty fields of the kind; the person enters the whole new secret (the payload is replaced as a unit, so the TOTP seed, the env rows and the other fields are included), and "Keep the current secret" goes back. For an SSH item the key stays unless the person imports or generates one (draft ID). `custom` comes from `item_get.summary.custom` and goes back on save; for SSH only machine, host, port and user are edited. The reveal-first read, the reveal-limit question and the "custom is lost on update" note of DEC-T18-3 are removed.
- **DEC-INT10-14** — INT10 UI — Unlock cost shown. Settings (security) and the dashboard health row show `vault_status.kdf` as "256 MiB, 3 passes, 4 lanes" (`costSummary`). With `kdf: null` (a recovery session) they say there is no passphrase cost to show. The "set when you make the vault" text (DEC-T20-3) is removed.
- **DEC-INT10-15** — INT10 UI — Unlock reads the backend. The unlock screen shows a sentence for `last_lock_reason` (manual, idle, max_unlocked, os, quit, panic, restore) and nothing when it is `null`. The failed tries come from `failed_unlocks` and `free_unlock_tries_left`. The wait comes from `retry_after_seconds` and the time of the status read, so it also shows when the screen opens during a wait. After a failed unlock the screen reads the status again. The window-local counter and the `FREE_TRIES` constant of DEC-T17-3 are removed. The unlock mock keeps the counters in the mock controller.
- **DEC-INT10-16** — INT10 UI — Audit outcome is sent to the backend. `AuditFilter.outcome` (`all`, `ok`, `failed`) goes to `audit_query` as `outcome` (`null` for `all`) with the time, type and agent filters, so pages stay full. The filter on the loaded pages (DEC-T20-5) is removed.
- **DEC-INT10-17** — INT10 UI — Dialogs and client certificates. Settings (restore, custom TLS files) and the SSH key panel use `openFile` from `ipc/dialogs.ts`; only that file imports the dialog plugin. `agents/AgentDetail` has "Client certificate" for each live key (PLAN 4.4, mTLS). It is for the owner: an operator sees it disabled with the reason, a viewer does not see it. The button asks for a folder with `pickDirectory`, calls `agent_issue_client_cert(keyId, destDir)`, and shows a toast that names the folder, or the error. The paths and the key text are never shown. The dev mock answers `agent_issue_client_cert` with fake paths.

## T21 — UI polish (2026-11-17)

- **DEC-T21-1** — T21 — One place for the lock state. The top bar no longer shows "Unlocked, Auto-lock in" (it said the same as the rail collar and the dashboard band, and it wrapped on narrow windows). The rail collar is the one lock indicator: it shows "Vault locking" or "Vault locked" with a closed gate and hides Lock and panic when the vault is not open; the rail is dimmed while it is inert. The top bar keeps the title, the page actions and the palette trigger.
- **DEC-T21-2** — T21 — Label in name (WCAG 2.5.3). The palette trigger has no `aria-label`; its name is its visible text "Search or run a command" (the key cap is `aria-hidden`, the shortcut is in `aria-keyshortcuts`, and the text stays for screen readers on narrow windows). "Delete now" in Leases is named "Delete now: {title}". Grant edit and delete buttons get the grant sentence through `aria-describedby`.
- **DEC-T21-3** — T21 — Durations in words. A time span that does not count down (a requested TTL) uses `formatDuration` (`state/time.ts`): "15 minutes", "1 hour", "2 h 30 min". `formatLeft` ("15:00") stays for countdowns. The dashboard queue and the approval card say "wants to read for 15 minutes" and "use SSH", not "15:00" and `use_ssh`.
- **DEC-T21-4** — T21 — Grant sentences. Permission words carry their object ("read items", "create sessions", "use SSH keys") and the fixed text is "in workspace", so the builder and the list read "Can create sessions in workspace shop-frontend, any env, any category." An empty slot is "any env" / "in any workspace" / "from any workspace", never "env any env". The simulator shows the same words, not the raw permission.
- **DEC-T21-5** — T21 — Vault browser width. The detail column is `clamp(340px, 30vw, 420px)` and 280 px while nothing is selected (hidden below 1200 px). When the list column is under 500 px (container query) the badges move under the title, so titles are not cut to "Chec…". The CSV buttons in the vault top bar are quiet ghost buttons; Export stays red in Settings and the export dialog carries the plain-text warning.
- **DEC-T21-6** — T21 — Palette coverage. Two actions added: "Import items from CSV" (`/vault?import=1` opens the wizard for operators and owners) and "Connect an agent" (`/dashboard?connect=1` opens the guide). The other IA section 6 actions were already there.
- **DEC-T21-7** — T21 — Audit catalog. Phrases for `items.import`, `items.export` (DEC-T23-5) and `tls.custom_revert`. A test reads `docs/reference/audit-events.md` (Vite `?raw`; `server.fs.allow` adds `docs/reference`) and fails when a documented type has no phrase or the catalog has a type the reference does not list.
- **DEC-T21-8** — T21 — Smaller consistency fixes: item titles in the audit timeline and the live feed are plain medium text, not mono (mono is for codes, hosts and secrets); the audit "Details" toggle sits on the event line; operators have a person node; Suspend uses a pause icon; "Lock and revoke all" uses the siren icon everywhere; the rail Vault icon is an archive box and workspaces use a layers icon, as in the prototypes; masked values use 12 "●" like the prototype; editor kind tiles have one height; the client certificate action on a key is an icon button (name unchanged) so the key row fits; approval cards sit side by side on the page.
- **DEC-T21-9** — T21 — Error text and test timing. `errorText` shows a backend message that has no UI text as a sentence (first letter upper case, full stop), because it is followed by "Your items are safe in the vault file." The editor axe test runs one kind per test (`it.each`) instead of four axe runs in one test, which passed the 30 s limit on a loaded machine.

## T24 — Test suite (2026-11-17)

- **DEC-T24-1** — T24 — Acceptance suite. It is the workspace member `tests/acceptance` (crate `cerberus-acceptance`, tests only, no library code). One file, `tests/acceptance/tests/acceptance.rs`, has one test per scenario of PLAN section 11: `a01_...` to `a12_...`; the fixture is in `tests/harness/mod.rs`. Each test asserts the "Pass when" column through the public surface: a real vault on a temporary directory, the real TLS server of `cerberus-api` with `/mcp` mounted, REST over HTTPS, an MCP client, the `cerberus` binary (A12), raw sockets (A8, A4) and the database file (A7, A9). The vault runs on a `ManualClock` (A3 moves it by 3600 s). A separate crate was chosen because the suite needs `cerberus-api`, `cerberus-mcp` and `cerberus-client` together, and a test of one of them would need a dev-dependency cycle on another. It has no normal dependencies, so `deps-check` lists it with an empty set (`"cerberus-acceptance": []`). Run: `just acceptance` (also part of `cargo test --workspace`). The piecewise tests in the crates (core `a2_` to `a11_`, api, mcp, client, ssh-agent) stay: they test the same rules at a lower level.
- **DEC-T24-2** — T24 — The `cerberus` binary in the suite. `CARGO_BIN_EXE_cerberus` exists only in the package that owns the binary, so the harness runs `cargo build -p cerberus-client --bin cerberus --message-format=json-render-diagnostics` once and reads the executable path from the JSON messages. This works for any target directory layout and for `cargo test -p cerberus-acceptance` alone.
- **DEC-T24-3** — T24 — Flaky `a_failed_connect_is_retryable_for_every_call` (client). Root cause: a port race. The test bound `127.0.0.1:0`, dropped the listener, and connected to the freed port. Other tests of the same binary start TLS servers on ephemeral ports at the same time, so the kernel could give the freed port to one of them; the connect then worked and the error was a TLS or pin error, not `Connect`. Fix: the test keeps a socket that is bound but never listens until the end of the test. The port cannot go to anyone else, and a connect to it is always refused. Not reproduced in 15 runs before the fix (the cause is by reading); 50 of 50 passes after it under load.
- **DEC-T24-4** — T24 — Flaky `rate_limit_gives_429_with_retry_after` (api). Root cause: the limiter is a token bucket on the vault clock (ADR-0030, 30 calls per second per IP, burst 60; 20 per second and burst 40 per agent). The test used the system clock and expected a 429 within 120 calls. Each call opens a new TLS connection, so on a loaded machine the calls are slower than the refill rate and the bucket never runs empty: 10 of 15 runs passed under load, and it was also timing dependent on a quiet machine. Fix: the api fixture has `Options::manual_clock` (a `ManualClock` in `Fixture::clock`). The test freezes time, so the 429 comes at call number `min(ip_burst, agent_burst)` = 40 exactly, and then moves the clock by `Retry-After` and checks that the next call works. No production change.
- **DEC-T24-5** — T24 — Flaky `request_access_waits_then_returns_the_decided_request` (mcp), and the same pattern in `a6_prod_item_pending_then_approved_by_a_person` and `a6_deny_gives_approval_denied_and_a_short_wait_returns_pending`. Root cause: a race between the helper `decide_later` (a 50 ms polling loop that decides the first pending request) and the second call of the agent for the same item. If the person decides in the short window between the lease check and the pending check of the second call, the call finds no pending request and no lease and opens a second request that nobody decides; it then waits 20 s and returns `pending` (reproduced 1 of 15 under load). Fix in the tests: the "pending at once" check and the "waits for a person" check now use two different items, and `decide_later` subscribes to the core events before the call and decides the request of the `AccessRequestCreated` event (no timer, no polling limit). Production: the window is a few microseconds, a person approving the same instant the agent asks again; the effect is one extra pending request (no data is shown, nothing is granted). Left as is; if it is closed later, the decision and the lease check of `request_access` must share the `request_gate`.
- **DEC-T24-6** — T24 — Coverage rules. `just coverage` runs `cargo llvm-cov` for `cerberus-crypto` and `cerberus-core` and fails when the line coverage of either crate is under 90 percent. Each crate is checked on its own (jq over the JSON summary). The two test-support files `policy/testkit.rs` and `agent_api/regressions.rs` are left out of the numbers, so test helpers do not raise the figure. New tests: core `vault/tests/ca.rs` (custom TLS material: round trip, role and lock checks, corrupt blobs), `vault/tests/authlog.rs`, and test modules in `csvio/export.rs`, `csvio/rows.rs` and `csvio/totp_text.rs`.
- **DEC-T24-7** — T24 — Store flake from T04. Not reproduced: every store test binary passed 20 of 20 runs at a load average of about 30, then 4 parallel workers by 25 runs each (600 runs) at about 50, with no failure. The time-sensitive code was reviewed: only `sweeper.rs::spawned_sweeper_reports_work_and_ends_with_its_receiver` uses a real timer (20 ms period, 10 s limits; the sweep time comes from a `ManualClock`), and the restore stamp comes from the clock. Neither has a race that the review can name, so nothing was changed.
- **DEC-T24-8** — T24 — Flaky `vault_status_carries_cost_lock_reason_and_unlock_failures` (desktop, INT10). Root cause: the unlock back-off after 5 wrong phrases lasts 1 s from the last failure on the real clock; under load more than 1 s passed before the test read `vault_status`, so `retry_after_seconds` was already null. Fix: `StateOptions` has a new `clock: Option<Arc<dyn Clock>>` (`None` = system clock, the app default), kept in the state and used for the store and the service. The ops fixture passes a `ManualClock`, and the test moves it by 1.2 s instead of sleeping. 50 of 50 passes at a load average of about 55. `StateOptions` is no longer `Copy`.

## T27-B — Audit fixes, network and client side (2026-11-17)

- **DEC-T27-B-1** — AUD-4 (cerberus-api). hyper's `header_read_timeout` starts after the protocol is known, so a TLS client that sends nothing was never timed out. Fix: each connection has an `Activity` (`idle.rs`): the TLS stream is wrapped in `Tracked`, which records the time of the last read or write that moved bytes and whether the client sent a first byte. A watcher future runs next to the hyper connection and ends it (the connection is dropped) when it is silent for `header_timeout` (10 s) before the first byte, or for the new `idle_timeout` (60 s) after it. The watcher never ends a connection while a request runs (a counter in the service function), and an SSE stream is kept by its heartbeat writes. This covers HTTP/1 keep-alive and HTTP/2 with one rule, so no h2 timer settings are needed. New `ApiLimits` fields: `idle_timeout` (60 s) and `max_connections_per_ip` (64): the accept loop counts open connections per IP (IPv4-mapped IPv6 is normalised) and closes an extra one at once, so one local user cannot hold all 256 slots. Tests: `aud4_a_silent_tls_connection_is_closed`, `aud4_an_idle_keep_alive_connection_is_closed_but_a_running_request_is_not`, `aud4_one_ip_cannot_hold_every_connection`.
- **DEC-T27-B-2** — AUD-17 (client TLS). With `CaFileAndPin` only the certificates of the file that have the pinned key are roots. A file with other certificates (a system bundle) no longer widens trust. A file with no certificate of the pin is still `PinMismatch`. Test: `aud17_a_pin_trusts_only_the_pinned_certificate_of_a_bundle`.
- **DEC-T27-B-3** — AUD-5 client part. `cerberus run` does not set a variable from an `env_bundle` name or a `cloud` `extra` key when `cerberus_types::is_forbidden_env_name` is true (the one shared list of T27-A2; no second list). It prints one line to stderr that names the skipped variables (names only, never values) and runs the command. Fixed names that the client makes itself (`CERBERUS_USERNAME`, `AWS_*` ...) are not checked, and an explicit `--var NAME=field` by the person may set any valid name (the audit allows this). Tests: `aud5_loader_and_interpreter_names_from_an_item_are_not_set`, `aud5_skipped_names_are_reported_by_name_only`, `aud5_an_explicit_var_mapping_may_set_such_a_name`.
- **DEC-T27-B-4** — AUD-18. The masker holds back output while a longer secret could still match (a short secret never wins over the start of a longer one), tries the longest secret first, and masks the held tail at the end of the stream. The needle set now holds every secret field of the item, not only the injected variables, so the user name and password of a built `DATABASE_URL` are masked one by one. Tests: `aud18_a_longer_secret_that_starts_with_a_shorter_one_is_fully_masked`, `aud18_the_parts_of_a_built_database_url_are_masked_one_by_one`.
- **DEC-T27-B-5** — AUD-19. `cerberus run` calls `prctl(PR_SET_DUMPABLE, 0)` (rustix `set_dumpable_behavior`, Linux) before the spawn, so the child cannot read `/proc/<ppid>/environ`. The client crate may not depend on `cerberus-crypto` (ADR-0024), so it does not call `harden_process`; the memory lock and core limit parts of it are not needed here. The flag is not inherited by the child. `CERBERUS_TOKEN` and `CERBERUS_TOKEN_FILE` were already removed from the child environment, and the token file is read and closed before the spawn (no inherited descriptor). A token file stays readable by the same user (AR-3, written in the threat model, I-18). Test: `aud19_the_child_cannot_read_the_token_from_the_parent_environment`.
- **DEC-T27-B-6** — AUD-20. The unlock socket reads the request line with a fixed-size `Zeroizing<Vec<u8>>` (no `BufReader`), parses it into a `Request` whose phrase is `Zeroizing<String>`, and drops the line before the unlock starts. The phrase moves into `SecretString` with `mem::take`. The client builds its JSON in a `Zeroizing` buffer sized for the worst case (6 bytes per character), so it never grows and leaves no copy. One copy stays outside our control: `serde_json` keeps a scratch buffer while it unescapes a string, which happens only for a phrase with a quote, a backslash or a control character (accepted; process memory is not dumpable, AR-8). Tests: `aud20_*` in `crates/cerberusd/src/unlock.rs`.
- **DEC-T27-B-7** — AUD-23 MCP part. Every item object with `created_by` = `agent:...` in a tool result or in the catalog resource gets `untrusted_fields` (title, description, tags, role_label, category, target). The text content of such a result starts with `UNTRUSTED: ...` (after the `HANDLING` line when both apply), and the catalog has a top-level `notice`. Items of a person have no mark. `docs/api/mcp-tools.md` and `schemas.json` list the new optional field. The resolve part (prefer operator items) is for T27-A2. Test: `aud23_agent_written_item_text_is_marked_untrusted`.
- **DEC-T27-B-8** — AUD-28. `.cargo/audit.toml` has the four ignores with their reasons, `informational_warnings = ["unmaintained"]` and `deny = ["unsound", "yanked"]`. `just audit` is now plain `cargo audit`, so both give one result (checked: removing the glib ignore makes both fail). Claims checked again: `rsa` and `crypto-bigint` are not in the resolved graph (no output of `cargo tree -i`, with `--target all` and with all edge kinds); `glib` 0.18.5 is compiled on Linux through gtk, tray-icon and tauri and no Cerberus code names it; `libsqlite3-sys` 0.37.0 is compiled and reachable. The text of the sqlite ignore (`deny.toml`, `.cargo/audit.toml`) now says "partial mitigation" and names AUD-10.
- **DEC-T27-B-9** — AUD-29. The unit adds `SystemCallFilter=@system-service` and `~@privileged @resources` (`@system-service` has `mlock` in `@memlock`, checked with `systemd-analyze syscall-filter`), `ProtectProc=invisible`, `ProcSubset=pid`, `RemoveIPC=yes`, `PrivateUsers=yes`, and `IPAddressDeny=any` with `IPAddressAllow=localhost` for the loopback default. A LAN bind must remove the two IP lines; `docs/guides/cerberusd.md` says so.
- **DEC-T27-B-10** — AUD-30 items of Rust Builder. (a) `write_private` removes a stale `.tmp` and uses `create_new`, so the key file always gets mode 0600 (`aud30_a_stale_loose_temp_file_does_not_set_the_key_mode`). (b) ssh-agent: each bridge directory has a `.lock` file with an exclusive `flock` held while the bridge runs; the stale clean-up removes a directory only when it can take that lock, so a live bridge in another PID namespace is kept (the pid test stays as the fallback for a directory with no lock file). (c) `cerberus get --show-secret` releases its lease after it prints (`aud30_get_show_secret_releases_its_lease`). (d) `cerberusd` refuses to start when the data directory or the vault file is open to group or others (`DaemonError::Mode`; `aud30_a_vault_file_or_data_dir_open_to_others_stops_the_start`). (e) The token `hint` item needs no change (the report accepts it). (f) The `.pre-migrate-vN` and audit prune items are in `cerberus-store` and the core, which T27-A1 owns; they are not changed here.

## T27-C — Audit fixes, desktop app (2026-11-17)

- **DEC-T27-C-1** — AUD-10 (desktop restore). `backup_restore` copies the backup once, with `files::copy_new_private`, into a private folder (`restore-check-<id>`, mode 0700, file 0600) in the data directory. That copy (`candidate.cerberus`) is the only file that is opened: `Store::inspect_backup` runs on it, the credential is proved on a second copy of it (`probe/vault.cerberus`, opened as a second service, then removed), and `restore_backup` installs it. The path of the person is read one time, so a file that is swapped in a synced folder after the copy has no effect. The store API was used as it is: `restore_backup` still copies the file once more and inspects it again, but from the private folder that only this process can write. A store change that would remove those two steps (an `install_backup` that renames the checked copy) is optional. A mutex (`restore_gate`, `try_lock`) refuses a second restore with `conflict`. When `finish_restore` (unlock, revoke, record, lock) fails after the swap, `roll_back` locks and drops the service, removes the installed file and its `-wal` and `-shm`, renames the `.pre-restore-*` file back, and opens the old vault again; with no old file it only removes the installed one. Tests: `the_staged_copy_does_not_follow_the_original`, `a_failed_restore_puts_the_old_vault_back`, `a_file_that_is_not_a_backup_is_refused_at_staging`, `undoing_a_swap_with_no_old_file_only_removes_the_new_one` (in `ops/restore.rs`), `a_second_restore_is_refused_while_the_gate_is_held` (see DEC-T27-C-10). Left for the store (T27-A1): the check of an unexpected `-wal` before the live vault opens, and the text of `deny.toml` and `justfile`.
- **DEC-T27-C-2** — AUD-11 (paths from the webview). A path that the backend reads must come from the OS. New command `file_pick_open(title, extensions) -> Option<String>` (main window only): the dialog runs in Rust (`tauri-plugin-dialog`, `Shell::pick_file`, in a blocking task) and the backend keeps the canonical path in a list of 16 (`DesktopState::picked`). A file dropped on the main window arrives as a native `WindowEvent::DragDrop` and goes in the same list (`note_dropped`), so the webview cannot make that event. `files::picked_file` is the one reader: `csv_preview`, `csv_import`, `ssh_key_import` (path), `tls_load_custom` (two files) and `backup_restore` use it. A path that is not in the list, a missing file, a folder, a relative path and a file that is too large all give the same error: `validation_failed`, field problem "cannot be used". The list is cleared at every lock (`clear_held`). The UI `openFile` calls `file_pick_open`; the typed-path field still works in a plain browser, but on the desktop a typed path is refused. Paths to write stay as they were (the JS save and folder dialogs, `dialog:allow-save` and `dialog:allow-open`): a write makes a new file with mode 0600 and never overwrites. `file_pick_open` is not in the table of `docs/interfaces.md` section 9 (the contract test lists it as an added command, like `clipboard_copy_once`). Tests: `aud11_csv_preview_refuses_a_path_the_dialog_did_not_return`, `aud11_other_readers_refuse_unpicked_paths`, `aud11_a_picked_path_works_until_the_vault_locks`, `copy_new_private_copies_once_and_respects_the_limit`.
- **DEC-T27-C-3** — AUD-12 (capabilities). `core:default` is gone from both windows. The main window has `core:event:allow-listen`, `core:event:allow-unlisten` and `core:app:allow-version` (the About screen) next to its own `allow-*` command permissions and the two dialog permissions; the approval window has only the two event permissions. No tray, image, menu, path, resources or emit permission. Test: `capabilities_list_exact_core_permissions` (also checks that the set does not drift to the risky names).
- **DEC-T27-C-4** — AUD-13 (LAN bind and new keys). The core schema allows `require_mtls` only with a fingerprint (DEC-T09-5), and the certificate needs the key ID, so a key cannot be made bound. While the bind is not loopback, `agent_create` and `agent_key_create` are refused with `validation_failed` (field `bind`, "make it while the server listens on loopback only"), and `agent_key_rotate` is refused for a key that has no binding (a rotated key copies the binding of the old one). The person makes the key on loopback, issues its certificate, and binds to the LAN (`network_set_bind` already checks every key). The invariant "every active key on a LAN bind has a binding" holds in both directions now. For core (T27-A2 or Crypto Smith, `auth.rs`): the token check could also refuse a key with no `require_mtls` when the peer is not loopback (the second option of the audit). It is a second layer, not needed for this fix. Test: `aud13_no_new_key_without_a_binding_on_a_lan_bind`.
- **DEC-T27-C-5** — AUD-14 (clipboard, panic). `DesktopState` keeps the SHA-256 of the last text it copied (`last_copy`). `clear_held` (every lock path, the lock pump, quit, restore) and `emergency_wipe` (the panic hook) call `clear_clipboard_if_ours`: it clears the clipboard only when it still holds that text, and it cancels the timer of that copy. The panic hook now also clears the SSH drafts, the one-time values and the picked files, and the clipboard, with `try_lock` / `try_read` only (a busy lock is skipped, never waited on). The root `Cargo.toml` has `[profile.release] panic = "abort"`; the test profile is not changed, so tests still unwind (`just test` passes). With abort, the hook runs, then the process ends. Tests: `aud14_lock_panic_and_quit_clear_our_clipboard_value`, `aud14_lock_keeps_a_clipboard_value_we_did_not_copy`, `aud14_the_emergency_wipe_clears_held_values_and_the_clipboard`.
- **DEC-T27-C-6** — AUD-15. The approval window builder sets `.content_protected(prefs.content_protection)` when it makes the window. Test: `approval_window_is_built_with_content_protection` (a source check: no window can be made in a test).
- **DEC-T27-C-7** — AUD-24 UI part. `UntrustedText` and the new `InlineUntrusted` write each character of the general categories Cf, Zl, Zp and Cc (except a line break and a tab) as a visible code, for example `‹U+202E›`, and put the text in `<bdi>`. `showInvisible` does the same for a string that goes into a translated sentence. The approval card uses them for the agent name, the item title and the workspace name. Test: `ui/Untrusted.test.tsx`.
- **DEC-T27-C-8** — AUD-30 generator and AUD-31. `password` removes a repeated class with a seen-list (`dedup` only removed neighbours, so `[lower, digits, lower]` made letters twice as likely; the digit share was 0.165 and is 0.278 now). Test: `a_repeated_class_does_not_change_the_mix`. The custom certificate dialog shows a second warning, "The pin moves to the top of your chain", and the in-use notice says the pin is the top certificate of the chain and that a public intermediate CA lets anyone with a certificate for the same host name pass the check. Test: `loads your own certificate, ...` in `settings.test.tsx`.
- **DEC-T27-C-9** — AUD-16 (OS hooks). Linux: the logind watcher has three threads now: `PrepareForSleep`, session `Lock`, and `PropertiesChanged` of `LockedHint` (only `true` locks). The sleep thread takes a logind `delay` inhibitor at start and after each wake. On `PrepareForSleep(true)` it sends the sleep event, polls `IsLocked` (the vault is not unlocked) every 25 ms for at most 3.5 s, and then drops the descriptor. `platform_source` takes that `IsLocked` closure. If the setting "lock on OS lock" is off, the vault stays unlocked and the suspend is delayed by 3.5 s (logind forces it at 5 s anyway); this is accepted. Tests: `a_locked_hint_locks_and_an_unlocked_hint_does_not`, `the_inhibitor_wait_ends_when_the_vault_is_locked`, `the_inhibitor_wait_is_bounded`; the D-Bus calls need a logind and are not tested here. macOS and Windows: checked `tao` 0.37 (events of the Tauri runtime) and the crates the desktop uses; none gives a sleep or screen-lock event (tao has suspend events on mobile only), and a hook needs unsafe FFI (`NSWorkspace`, `WTSRegisterSessionNotification`) that ADR-0012 allows only in `cerberus-crypto`. Accepted risk, owner Tauri Builder: only the idle lock (30 min) and the hard lock (12 h) apply there, and the status view shows the hook as off. Written as an amendment of ADR-0026 and in the threat model (I-8, E-2).
- **DEC-T27-C-10** — Review gaps in the T27-C fixes. (1) `backup_restore` rolls back on every failure after the swap: the open of the restored file (`open_service`) is now inside the same guard as `finish_restore`, so `roll_back` runs for both. If the swap itself fails, the old file is still the vault file, so there is no roll back; the old vault is opened again and the swap error is returned. Test `a_restored_file_that_does_not_open_is_rolled_back` uses a `cfg(test)` flag in `DesktopState` (`fail_next_open`) that makes the next `open_service` fail once; the production build has no such code. Before the fix the restored file stayed installed and three `.pre-restore-*` files (vault, wal, shm) were left. (2) `aud11_the_lock_clears_the_picked_paths` unlocks again after the lock and shows that a picked and a dropped path are refused (`vault_locked` after the lock came from the operator check and did not prove the clear). (3) The AUD-15 contract test reads the builder chain of the approval window: one `.content_protected(protected)` call, and `protected` is bound from `try_state::<DesktopState>().prefs().content_protection`, with no constant. The window builder has no getter and the mock runtime ignores the flag, so a behaviour test is not possible; `.content_protected(false)` now fails the test. (4) The second-restore test moved from `tests/audit_t27c.rs` (a `join!` race that could pass for the wrong reason) to `ops/restore.rs`: it holds `restore_gate`, so the second call must see the first in progress, then drops the gate and shows that the restore runs. Open point: if `restore_backup` fails half way (old file moved, copy not renamed), the moved path is not returned by the store (store API), so the old vault is not found by `roll_back`; that is a store change.

## T27-A2 — Audit fixes, core Agent API (2026-11-17)

- **DEC-T27-A2-1** — AUD-5 core part. One deny list for environment names, in `cerberus_types::env` (no I/O, used by core and the client): `is_forbidden_env_name(&str) -> bool` (ASCII case is ignored, for Windows) over `FORBIDDEN_ENV_NAMES` (shell start-up `PATH`, `BASH_ENV`, `ENV`, `IFS`, `SHELL`, `HOME`, `PS4`, `PROMPT_COMMAND` ...; tools that start commands `EDITOR`, `PAGER`, `LESSOPEN` ...; libc hooks `GCONV_PATH`, `GLIBC_TUNABLES` ...; runtime hooks `RUBYOPT`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`, `RUSTC_WRAPPER` ...; trust anchors `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` ...; proxies `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`), `FORBIDDEN_ENV_PREFIXES` (`LD_`, `DYLD_`, `PYTHON`, `PERL`, `BASH_FUNC_`, `GIT_`, `SSH_`, `NPM_CONFIG_`, `MALLOC_`, `XDG_`, `CERBERUS_`) and `FORBIDDEN_ENV_SUFFIXES` (`_OPTIONS`: `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS` ...). `NODE_ENV`, `CARGO_REGISTRY_TOKEN`, `AWS_*`, `GITHUB_TOKEN` stay allowed. Core refuses such a name in an `env_bundle` var or a `cloud` `extra` key of an item that an **agent** creates (`422`, field `payload.vars.<NAME>` / `payload.extra.<NAME>`, `item.create` audited with decision `forbidden_env_name`). A person may still store such a name (IPC, CSV import): the client does not set it unless the person maps it with `--var` (DEC-T27-B-3). Reveal does not filter: the client is the one place that sets variables. Test: `agent_items_cannot_set_forbidden_env_names`.
- **DEC-T27-A2-2** — AUD-3 limit. `MAX_SSH_KDF_ROUNDS = 1024` bcrypt rounds (OpenSSH default 16; `ssh-keygen -a 100` is common). Import (`import_private_key`), item validation (`check_payload`, so agent create, IPC create and update) and the prepare and sign paths refuse a larger count with `validation_failed` on `private_key` / `payload.private_key`. Reading the count does not decrypt. Test: `an_encrypted_key_with_too_many_kdf_rounds_is_refused` (the test patches the count of a real key, so no slow decrypt runs).
- **DEC-T27-A2-3** — AUD-3 guard. Replaces the last sentence of DEC-FIX8-5. `ssh_prepare` does on one write guard: policy check and lease use, payload read, key parse, the cheap checks (ed25519, passphrase present, round limit), the public facts and the strict `ssh.prepare` event. It then drops the guard and opens an encrypted key on `spawn_blocking` (the passphrase must open it, so a bad item fails at prepare, not at the first signature). A failed open writes a second `ssh.prepare` event with the error code and decision `key_open`, like `ssh.sign` (DEC-FIX8-5). Then it takes the guard again and gives the ticket only when the session is the same (a lock, or a lock and a new unlock, during the decrypt gives `Locked` and no ticket); grant, lease and key are checked again at each sign. So no lock path (manual, idle, hard, OS, panic) waits for bcrypt. The blocking thread holds a copy of the key text until the decrypt ends (at most 1024 rounds); it zeroizes on drop. Test: `a_lock_does_not_wait_for_the_key_decrypt_of_a_prepare` (lock and panic button).
- **DEC-T27-A2-4** — AUD-22. Closes the race of DEC-T24-5. `request_access` takes `request_gate` before its lease check, and `authorize_secret_in` takes it before `lease_gate` (gate order: request, then lease; no path takes them the other way). `open_request` no longer takes the gate; it needs the caller's guard as a parameter, so a call without the gate does not compile. Approve and deny already take the gate, so an approval lands before the lease check or after the pending check. Test: `an_approval_during_a_repeated_request_opens_no_second_request` (holds the gate, queues the approval and then the repeated call).
- **DEC-T27-A2-5** — AUD-23 resolve. On an equal score an operator item sorts before an agent item. An agent item is the confident `best` winner only when its score without hint points (app and role only, the parts an agent cannot write for itself in a workspace) beats the full score of every operator candidate by the confidence gap (25); else the outcome is `ambiguous` and the caller picks. Items of one creator kind are scored as before. AR-15 in the threat model names the two effects. Tests: `an_agent_item_does_not_win_over_an_operator_item_by_hint_words`, `on_an_equal_score_the_operator_item_comes_first`.
- **DEC-T27-A2-6** — AUD-21. New item setting in `custom`: `sshsig_namespaces` (const `KEY_SSHSIG_NAMESPACES`), a comma list of names (1..64 of ASCII letters, digits, `.`, `-`, `_`, `@`; a bad list is `validation_failed` on `custom.sshsig_namespaces`). Without it a key signs SSH logins only. `ssh_sign` parses the `SSHSIG` signed data strictly (namespace, empty reserved, `sha256`/`sha512` with a hash of that length, nothing after it; else `validation_failed`, decision `data_kind`) and refuses a namespace that is not in the list with `forbidden` (decision `sshsig_namespace`) before a signature is taken from the ticket budget. Every `ssh.sign` event of an `SSHSIG` blob has `details.namespace` (cleaned, 64 characters). This changes DEC-T22-4: git signing needs `sshsig_namespaces = git` on the item (the UI can set it as a custom field). Tests: `sshsig_signs_only_the_namespaces_that_the_item_allows`, `a_bad_sshsig_namespace_setting_is_refused`.
- **DEC-T27-A2-7** — T21 ask. `AccessRequestDetail` (core) and the IPC `AccessRequestView` (`request_list_pending`) have `item_kind` (`ItemKind`) and `role_label` (`Option<String>`) of the item: metadata only, read from the index. The agent wire `AccessRequestView` is not changed. Test: `prod_read_asks_and_approve_once_gives_one_read` checks both fields.
- **DEC-T27-A2-8** — T21 ask. `AuditQuery.text` / IPC `AuditQueryView.text` (`Option<String>`, 1..200 characters after trim, more is `validation_failed` on `text`, empty means no filter): a case-free substring match over the event type, the target kind and ID, the actor ID, the agent name (of the actor, the agent target or `details.agent_id`) and the item title (of the item target or `details.item_id`, from the index). Other detail values (purpose, user, counts) are never matched, so the filter cannot be used to probe text that is not shown as metadata. Only the read side of the audit is changed. Test: `the_audit_text_filter_matches_metadata_only`.
- **DEC-T27-A2-9** — AUD-24 core part. `cerberus_types::text` has `is_format_char` (the `Cf` set of Unicode 16: bidi controls, zero-width characters, the soft hyphen, tag characters and the others), `is_hidden_char` (`Cc` or `Cf`), `strip_format` and `strip_hidden`. `clean_reason` removes `Cc` and `Cf`. Agent create removes `Cf` from the title, description, role label, category, tags, target and custom entries; `Cc` stays there, so validation still refuses it. Agent names and descriptions (operator input, shown inline next to agent text) lose `Cf` before the checks. The SSH user and the `SSHSIG` namespace in `ssh.sign` lose both. Emoji with a zero-width joiner in agent text lose the joiner (accepted). Test: `hidden_format_characters_are_removed_from_untrusted_text`.
- **DEC-T27-A2-10** — AUD-25. CSV import puts the URL into `target` without user name, password, query and fragment (scheme, host, port and path stay; the login payload keeps the full URL, it is secret). `notes_dropped` counts every built row whose notes are not kept: all kinds except a note or env bundle that takes its body from the notes. Tests: `the_target_drops_user_info_query_and_fragment`, `every_dropped_note_is_counted`.

## T27-A1 — Audit fixes, core integrity and store (2026-11-17)

- **DEC-T27-A1-1** — AUD-1. The audit writer checks where it appends, inside the write transaction (`AuditWriter::chain_position`): it uses the head only when its HMAC is good and the newest row agrees with it (same `seq` as `last_seq`, same entry hash). It uses an empty log (no head, no row) only for a writer made at create; a writer made at unlock is `expecting_log()`, so a wiped log is a break too (`log_missing`). On any other state (`head_missing`, `head_hmac`, `tail`) it chains a **break mark** first: `integrity.row_mac_mismatch` on target `audit_head`, result `vault_corrupt`, with `problem`, `head_last_seq` and `found_last_seq`, after the newest row there is, and it keeps a signed anchor (or the oldest row as the anchor). Then the events are chained and the head is signed again. `verify_chain` reports a break mark as `HeadMismatch` at its `seq`, so a cut never reads as "chain OK" again. The append is not refused: a secret read must not be blocked by a file attacker, and the mark makes the cut visible for good. The cost: after a real cut the chain stays `Broken` and prune refuses to run (prune hides nothing); the person sees the alert and keeps the export. Each mark raises `IntegrityAlert { table: "audit_head" }` after the append. After each unlock a background walk of the chain (one page per read guard, so a lock never waits for it) writes `audit.verify` with `chain = broken` and raises `IntegrityAlert { table: "audit_events" }` on a break. False alarm accepted: if `vault.create` failed to append at create (it is logged and the create goes on), the first unlock marks `log_missing`. Tests: `aud1_a_cut_tail_with_an_edited_head_is_found_at_unlock`, `aud1_a_wiped_log_is_found_at_unlock`, `a_cut_tail_with_an_edited_head_is_not_signed_again`, `a_deleted_head_does_not_restart_the_chain`, `a_cut_tail_under_a_good_head_is_not_hidden`.
- **DEC-T27-A1-2** — AUD-2. The sealed item metadata (`items.meta_ct` and the version snapshot) holds `kind`. `decode_item_meta` refuses a sealed kind that is not the plain `items.kind` (`Corrupt`; at unlock the row is left out of the index with an integrity alert). The index keeps the sealed kind, and every read compares the plain row with it (`checked_item`); `open_current` also refuses a payload whose kind is not the indexed kind. **Upgrade of an existing vault, no SQL migration:** the change is inside sealed blobs, which a SQL migration cannot write (it has no key), so the schema version stays 1 and no `.pre-migrate` file is made. Metadata without `kind` (written before T27) is accepted at unlock only when the authenticated payload of the current version has the plain kind, and then it is sealed again with the kind, in one transaction, with a compare and set on `(kind, current_version, meta_ct)` (`Tx::replace_item_meta_if`). A failed upgrade is logged and tried again at the next unlock. A replayed old kindless `meta_ct` (same item and version) gives no bypass: it goes through the same payload check. A history snapshot from before T27 takes the kind of the checked current item when it is restored, and the restored payload must have it. Tests: `aud2_a_changed_plain_kind_is_refused_at_unlock`, `aud2_a_changed_plain_kind_is_refused_at_reveal`, `aud2_a_vault_from_before_t27_gets_sealed_kinds_at_first_unlock` (old-format vault upgrades), `aud2_a_legacy_row_with_a_changed_plain_kind_is_refused`.
- **DEC-T27-A1-3** — AUD-6. The index keeps, per item, the version whose sealed metadata opened at unlock (or that the service wrote last). `checked_item` refuses a row whose `current_version` is not that version with `Corrupt` and an integrity alert (`items`), before a payload is opened or a use is counted, so a moved-back pointer is never sealed again under the old version. Test: `aud6_a_moved_back_current_version_is_refused`.
- **DEC-T27-A1-4** — AUD-7. `Tx::revoke_all_leases` and `Tx::cancel_pending_requests` verify each row MAC before the change. A bad row is left as it is and returned in `RevokeReport::bad_mac` / `CancelReport::bad_mac`. Callers (panic lock, deferred panic at unlock, restore) raise `integrity.row_mac_mismatch` and the alert for each (`report_bad_macs`). No store function signs a row again without a verify now (checked: these were the only two `sign_*` calls in `tx.rs`). Tests: `revoke_all_leases_never_signs_a_forged_row`, `cancel_pending_requests_never_signs_a_forged_row` (store), `aud7_panic_revoke_leaves_a_forged_lease_and_raises_the_alert` (core).
- **DEC-T27-A1-5** — AUD-8. The sweeper still deletes by the plain column (it runs with no key). The vault service deletes, while unlocked, every item whose effective expiry in the index (the earlier of the plain and the sealed value) has passed (`delete_sealed_expired`): after each unlock and after every sweep. The sweeper sends every report now, also an empty one, so this pass runs each period. Each delete writes `item.expire` with `reason = sealed_expiry`, then the WAL is truncated. The write guard is dropped before the WAL checkpoint. Test: `aud8_an_item_with_a_cleared_plain_expiry_is_deleted_after_its_sealed_end`.
- **DEC-T27-A1-6** — AUD-9. `Tx::take_audit_pending` deletes and counts a row it cannot parse (`PendingTake::malformed`) instead of failing the whole take. The writer accepts only the types that code writes while locked (`vault.unlock_failed`, `api.locked_call`, `auth.failed`, `item.expire`), and counts any other row as malformed. The `audit.pending_overflow` note has `malformed` next to `dropped` and is written when either is above 0. A drain that still fails raises `IntegrityAlert { table: "audit_pending" }` (the rows stay pending). Tests: `a_malformed_pending_row_is_skipped_and_counted` (store and core writer), `aud9_a_malformed_pending_row_does_not_block_the_others`, `aud9_a_failed_drain_raises_the_alert`.
- **DEC-T27-A1-7** — AUD-10 store part. (a) `Store::open` checks a `-wal` next to the vault before any connection (`fsutil::wal_is_plausible`): a file shorter than a header is fine (SQLite reads no frame); otherwise the magic, the version, the page size of the main file and the header checksum must be right, else `Corrupt`, and the `-wal` is not changed. (b) `inspect_backup` reads the backup with one read-only `immutable` connection, so SQLite never reads a `-wal` or `-shm` next to it (the sibling check stays as a second guard). (c) `restore_backup` copies the backup once to `<vault>.restore-tmp` (new file, 0600), inspects that copy, and renames that same copy into place; the backup path is not opened again. The desktop flow (DEC-T27-C-1) adds the private staging folder, the rollback and the mutex. The `deny.toml` and `.cargo/audit.toml` text says what is and is not covered. Not covered (written there): a `-wal` swapped between the check and the open, or changed while the vault is open, by a same-UID attacker who can damage the file in other ways too. Tests: `open_refuses_a_wal_file_of_another_page_size`, `the_backup_check_never_reads_a_sibling_wal`, `a_backup_with_a_sibling_wal_file_is_refused`.
- **DEC-T27-A1-8** — AUD-26 accepted, no code change. The role is not bound in the slot wrap AAD, and that stays so: anyone who can unwrap a slot has the VMK, can derive `header_key` and sign an edited header, so an AAD binding adds nothing. The control stays as it is: a header MAC failure makes the session `viewer`, and `save_slots` refuses to sign an edited file. Roles limit people without file access; an operator who shares the OS account and the vault file is not limited by the role (AR-9, threat model). This closes the "follow-up, not done" of DEC-FIX5-4. T28 should repeat the AR-9 sentence in the operator guide.
- **DEC-T27-A1-9** — AUD-27 fixed. `item.update` details have `changed` (the names of the changed metadata fields, never their values), `old_environment`, `new_environment`, `old_workspace_id` and `new_workspace_id`, for a replace and for `Keep`. With `Keep` the history snapshot of the current version is still rewritten (DEC-INT10-6); the audit chain now holds what the snapshot lost. Test: `aud27_item_update_names_the_changed_fields`.

## T27-D1 — Audit re-check fixes (2026-11-17)

- **DEC-T27-D1-1** — AUD-5 (re-check: partially closed, Medium). A deny list cannot be complete, so names in an item that an **agent** wrote need an allow rule: `cerberus_types::env::is_agent_env_name_allowed`. The name, read without ASCII case (so `maven_opts` and `OpenSSL_Conf` are the same as the upper-case form), must be `[A-Z_][A-Z0-9_]*` (at most 128), must not be on the deny list, and must be in `AGENT_ENV_NAMES` (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `PGUSER`, `PGPASSWORD`, `MYSQL_PWD`, `DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `SENTRY_DSN`) or end in one of `AGENT_ENV_SUFFIXES` after a non-empty part (`_TOKEN`, `_KEY`, `_KEY_ID`, `_SECRET`, `_PASSWORD`, `_PASSWD`, `_PASS`, `_PWD`, `_PASSPHRASE`, `_USER`, `_USERNAME`, `_CLIENT_ID`). No suffix such as `_URL`, `_FILE`, `_CONFIG`, `_HOME`, `_PATH` or `_CREDENTIALS` is allowed: those name files, hosts or programs (`PIP_INDEX_URL`, `AWS_CONFIG_FILE`, `GOOGLE_APPLICATION_CREDENTIALS`). Where it applies: (a) core refuses any other `env_bundle` var or `cloud` `extra` key in an agent create (`agent_payload_problems`, the same `422` and `payload.vars.<NAME>` / `payload.extra.<NAME>` field and the same `item.create` audit with decision `forbidden_env_name` as DEC-T27-A2-1, so the audit vocabulary does not change); (b) `cerberus run` applies the same rule when the revealed item's `created_by` is not `operator:...` (an unknown writer counts as an agent). So an agent item stored before this change cannot set `MAVEN_OPTS` either, and the skipped names are printed by name as in DEC-T27-B-3. `--var NAME=field` by the person still sets any valid name. The deny list stays as the second layer and is still the only check for an item that a person wrote. It now also holds the code-load hooks that the re-check named: `RUSTFLAGS`, `RUSTDOCFLAGS`, `GOFLAGS`, `CC`, `CXX`, `LD`, `LUA_INIT`, `PHPRC`, `PHP_INI_SCAN_DIR`, `DOTNET_STARTUP_HOOKS`, `VIMINIT`, `EXINIT`, `SUDO_ASKPASS`, `CLOUDSDK_PYTHON`, `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`, `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, `SSLKEYLOGFILE`, `COMSPEC`, `PATHEXT`, `PSMODULEPATH`; prefixes `LUA_INIT_`, `CORECLR_`, `COR_PROFILER`, `CARGO_BUILD_`, `CARGO_TARGET_`, `CARGO_ENCODED_`; suffix `_OPTS`. Not `CARGO_` as a whole (`CARGO_REGISTRY_TOKEN` stays usable). Config and redirect names (`KUBECONFIG`, `AWS_CONFIG_FILE`, `DOCKER_HOST`, `JAVA_HOME`, `PIP_INDEX_URL` ...) are not on the deny list: a person may have a real reason to put them in an env bundle, and for agent items the allow rule already refuses them. Change for a person's item: `cerberus run` now also skips the added hook names (with the stderr line) unless the person maps them with `--var`; storing them is unchanged. Tests: `the_recheck_code_load_hooks_are_forbidden`, `agent_items_may_set_only_credential_names` (types), `agent_items_may_set_only_credential_env_names` (core), `aud5_an_agent_item_sets_only_credential_names` (client). Existing tests and the acceptance scenarios needed no change (no acceptance scenario stores an env bundle or a cloud `extra` key).
- **DEC-T27-D1-2** — AUD-25 (re-check: partially closed). CSV import splits the URL with `csvio::rows::url_parts`, used for `target` and for the title that `host_of` makes when the file has none (the title had the same leak: `https://user:pa/ss@host/x` gave the title `user:pa`). Exports hold passwords that are not percent-encoded, so `/`, `?`, `#` and `@` can be in the user information. When no `@` comes after the first `/`, `?` or `#`, the URL is read as RFC 3986 says (host after the last `@` of the authority). Otherwise: if the RFC authority is not a `host[:port]` (`user:pa`), it is user information and the host is after the last `@` of the whole text (path kept, query and fragment cut); if it is a plain host with no `:` (`https://site.example/login?email=a@b`), only scheme and host are kept (the path could hold the rest of a user name); else (`https://user:1234/x@host/`, where `1234/x` could be a password) there is no target and the title is not taken from the URL (the row needs a title cell, as for a URL with no host). An invalid scheme text before `://` is not taken as a scheme. The `url` crate is not a core dependency, and a standard parser reads `https://user:pa/ss@host/x` as host `user` with the invalid port `pa` and fails, so it would not tell the parts apart either. The login payload still keeps the full URL (it is secret). Test: `the_target_never_keeps_an_unencoded_password`.
- **DEC-T27-D1-3** — NEW-3. `Tx::revoke_all_leases` and `Tx::cancel_pending_requests` skip a row that `from_sql` cannot read (bad ID, time or enum text) and count it in `RevokeReport::malformed` / `CancelReport::malformed`, the AUD-9 pattern (DEC-T27-A1-6). The row is left as it is (not deleted, not signed): it cannot be used for access, because every lease read parses it first. The other rows are revoked and cancelled, so the panic (`before_erase`), the deferred panic at unlock and restore no longer fail on one bad row. `report_bad_macs` and the operator "revoke all" (`leases/ops.rs`) call `VaultService::unreadable_rows`: one `integrity.row_mac_mismatch` per table with `malformed` = count and an empty target ID, plus `IntegrityAlert { table, row_id: "" }` (the ID itself may be what is broken). The operator "revoke all" also no longer fails when the list of live leases (only used for the change events) cannot be read; it logs a warning and sends no `LeaseChanged` events. Tests: `an_unreadable_row_does_not_stop_revoke_all_or_cancel_pending` (store), `new3_an_unreadable_lease_row_does_not_block_the_panic_revoke` (core).
- **DEC-T27-D1-4** — NEW-2. `ChainWalk` goes on past a break mark (it is a good, chained row) and remembers the report for the first mark: the mark's `HeadMismatch` at its `seq`, or, when the mark comes right after a gap in `seq` (the writer chains the mark after a cut tail at the old head `seq` + 1), the `MissingRow` at the first missing `seq` as before. A gap that does not end at a good mark still ends the walk. The walk then reports the first later problem that is not a mark (`HmacMismatch`, `PrevHashMismatch`, `MissingRow`, `UnreadableBody`, end against the head); only when there is none is the first-mark report returned. So with only marks the report is the same as before (prune stays refused, DEC-T27-A1-1), and an edit or a delete after a mark now shows as a new `seq` and kind in "Verify chain", in `audit.verify` and in the `IntegrityAlert { table: "audit_events" }` after unlock. A real break that is not a mark still ends the walk (it is permanent too, but it is not a known mark, and the auditor's finding is about marks). Tests: `new2_a_break_mark_does_not_hide_a_later_break` (cut tail and gap), `new2_an_edit_after_a_head_mark_is_reported` (changed head, no gap).

## T27-D2 — Audit re-check fixes, API connections (2026-11-17)

- **DEC-T27-D2-1** — AUD-4 (re-check: partially closed, Medium). Progress on a connection now means a request, never bytes: the byte watcher of DEC-T27-B-1 (`Tracked`) is gone, so a byte trickle, a 24-byte h2 preface sent one byte at a time and h2 PING frames no longer move any deadline. `idle.rs` keeps an `Activity` per connection, made at accept, and `watch` applies three rules. (1) The first complete request head (the hyper service is called; for h2 that is a HEADERS frame that opens a stream) must arrive within `header_timeout` (10 s) after the TLS handshake, which itself has `handshake_timeout` (10 s). (2) A connection that has had no authenticated request is closed `auth_timeout` (new, 30 s) after accept, even while a request runs: no route without a token takes long, and a running request could otherwise be held open by the client (h2 flow-control window 0 on a `401` body). (3) After an authenticated request, the connection is closed when no authenticated request has run for `idle_timeout` (60 s); unauthenticated requests do not reset it, so a revoked token does not keep a slot. "Authenticated" is set by `layers::authenticate` when `auth().check` passes, through a crate-private request extension (`ConnActivity`), before the handler runs. The request counts as running until hyper has sent or dropped the whole response body (`hold_until_sent` wraps the body), so an SSE stream (and an MCP stream, which uses the same check) is kept with no heartbeat at all; the 15 s heartbeat is no longer what keeps it. hyper's HTTP/1 `header_read_timeout` stays as a second layer for later requests. No h2 keep-alive setting is needed: the rules do not depend on the protocol, and a server PING would only find dead peers. Tests (real TLS): `aud4_a_byte_trickling_client_is_closed`, `aud4_an_http2_client_that_only_sends_pings_is_closed`, `aud4_a_connection_without_an_authenticated_request_is_closed_at_the_auth_deadline` (health every 100 ms, a pending unauthenticated route, and the same pattern with a token kept), `aud4_an_event_stream_outlives_the_idle_time` (idle 300 ms, approval after 1.5 s). `aud4_an_idle_keep_alive_connection_is_closed_but_a_running_request_is_not` now uses a route behind the token check, because the idle rule applies to authenticated connections.
- **DEC-T27-D2-2** — NEW-1. The per-IP cap (`max_connections_per_ip`, 64) is removed. On loopback every agent shares one source with any local attacker, so a per-source cap is a lockout tool (the finding), and `127.0.0.0/8` made it easy to dodge; normalising loopback to one key would only make the lockout exact. Chosen instead: unauthenticated connections have their own budget, `max_unauthenticated` (new, 64), and an authenticated connection is never evicted, so authenticated connections keep at least `max_connections - max_unauthenticated` (192) slots. When the budget is full, or no connection slot is free, a new connection evicts an unauthenticated one at accept, before its handshake, instead of waiting (`idle::Pending`): the oldest connection of the source that holds the most unauthenticated connections (ties: the oldest). A source is the IP with IPv4-mapped forms made plain, all of loopback (`127.0.0.0/8`, `::1`) as one source, and an IPv6 address by its `/64`. So silent or trickling clients cannot keep an agent out: the agent's new connection takes the slot of the oldest of them, finishes its handshake and first request in milliseconds, and is then safe. On a LAN bind (mTLS) a flood from one host only cycles its own connections. Only when every slot is authenticated does a new connection wait in the backlog, as before. Authenticated and evicted are final states of one atomic, so a connection cannot be both. Rejected: refusing the new connection when the budget is full (the attacker keeps the budget by reconnecting at once); a per-source cap kept with eviction inside the source (on loopback it is the same as the global budget, and a second number that means nothing there). Residual, accepted: a local user who floods new connections without pause can still evict an agent's connection before it authenticates (a race that costs the attacker a busy CPU, like any local flood, not one byte per minute), and a token holder can still fill the authenticated slots (it is rate limited in core, and the person can revoke its key). Tests: `aud4_an_agent_gets_in_while_unauthenticated_clients_hold_every_slot` (four slots held by silent and trickling clients with 30 s deadlines; the agent is served within 3 s, and four more silent clients do not push it out), `new1_another_loopback_address_gets_no_separate_budget` (Linux: a connection from `127.0.0.2` is the oldest of the one loopback source and gives way first). Unit tests in `idle.rs`: `every_loopback_address_is_one_source`, `an_ipv6_source_is_its_64_prefix`, `a_full_budget_evicts_the_oldest_of_the_busiest_source`, `an_authenticated_connection_is_never_evicted`, `an_evicted_connection_does_not_become_authenticated`, `a_freed_slot_leaves_the_table`. `aud4_one_ip_cannot_hold_every_connection` is removed with the cap.

## T27-E — Audit re-check fixes, section 7 (2026-11-17)

- **DEC-T27-E-1** — NEW-5 (Medium). `AuthTable::check` now verifies the token first (parse, SHA-256 hash, constant-time compare over `KEY_SLOTS` slots, the same cost for every token) and only then applies limits. A good token is limited per agent only (20/s, burst 40); the source IP has no say in it. The source limits apply to failed checks only: a failure from a source that is locked out, or while all sources are locked out, is `LockedOut` (`429 too_many_failures`); past the per-source bucket (`ip_per_second`/`ip_burst`, now counting failed checks only) it is `RateLimited`; else it keeps its reason (`401`) and counts toward the per-source lockout (10 in 300 s, then 300 s) and toward a new global lockout (`AuthLimits::global_failure_max`, 100 failures from all sources together in the same window, then the same lockout length for every failing check). Memory is bounded: past `MAX_SOURCES` (4096) tracked sources (after idle ones are dropped), new sources share one overflow entry, in the failure table and in the bucket table; the global queue holds at most `global_failure_max` entries. Why: on loopback every agent shares `127.0.0.1` (and `::1`) with any local user, so any per-source limit on good tokens is a lockout tool (same reasoning as DEC-T27-D2-2). The lockout cannot protect a correct token anyway: whatever the limit answers to a wrong token, a right one must be served, so a guesser learns nothing more or less from the refusal. Guessing stays impractical because the secret has 256 bits (ADR-0016), and every refused attempt (lockout included) still goes to `auth.failed` once per IP per minute with `suppressed_before` (DEC-FIX7-11), so a flood is visible. Rejected: keying the lockout by the claimed agent ID on loopback (a local user who knows or reads an agent ID would lock that agent out); a delay (tarpit) on failures (holds unauthenticated slots for no gain at 256 bits). Same review of other pre-auth per-IP limits: the per-IP bucket was the only other one (now failed checks only); the API's per-IP warn table only rate limits a log line. Tests: core `new5_a_bad_token_flood_never_locks_out_a_good_token` (200 rounds of bad tokens from `127.0.0.1` and `::1`, the good token passes every time, 380 of 400 bad ones locked out), `new5_failures_from_many_sources_hit_the_global_limit`, `new5_the_failure_table_stays_bounded`; `lockout_after_n_failures_and_release_after_the_window`, `ipv6_addresses_of_one_64_share_a_lockout` and `per_ip_rate_limit_gives_retry_after_and_recovers` changed to the new meaning (a good token from a locked or drained source passes). API: `repeated_bad_tokens_lock_the_ip_out` now asserts `200` for the good token after the lockout; `new5_a_bad_token_flood_from_loopback_does_not_lock_out_an_agent` (frozen clock, 70 bad tokens from `127.0.0.1`: 10 × `401`, then `429 too_many_failures`, the agent gets `200` after every 10; one minute later the next refused attempt writes `auth.failed` with result `too_many_failures` and `suppressed_before` 69). `rate_limit_gives_429_with_retry_after` uses the agent burst only. ADR-0030's first table row ("requests per source IP, before auth") now means failed checks per source IP; the ADR text is not changed here.
- **DEC-T27-E-2** — NEW-6 (Low). Three rules in `cerberus-api` (`idle.rs`, `layers.rs`, `server.rs`). (1) Per-agent cap: `ApiLimits::max_connections_per_agent` (new, 32). A connection belongs to the agent and key of its first authenticated request (`idle::Owners::bind`, under one lock, so two requests on one connection bind once). When that agent (all its keys together) already has 32 open bound connections, the request gets `429 rate_limited` (`Retry-After: 1`) and the connection is not marked authenticated, so the unauthenticated deadline and eviction still apply to it. A closed connection leaves the count at once (`Activity::close` at the end of the connection task; the table holds `Weak` references). With 256 connections and 64 for unauthenticated ones, one token can hold at most 32 of the 192 authenticated slots. (2) Send stall: `ApiLimits::send_timeout` (new, 30 s). The response body wrapper (`Held`) records when it was handed to hyper and when hyper last pulled it: hyper pulls → no longer waiting; the body gives a frame → waiting for hyper again from now; the body itself is pending (an SSE stream between events) → not waiting. If the oldest waiting response of an authenticated connection has waited `send_timeout`, the connection is closed (`Closed::SendStalled`). In hyper's h2 server the body is not even polled while the stream has no window (`PipeToSendStream` waits in `poll_capacity` first), so the hand-over time counts, and a client with `SETTINGS_INITIAL_WINDOW_SIZE = 0` is closed after 30 s. Progress is a pull of the body, not bytes; a single body chunk must be taken within 30 s, which is far above the size of any response here. A handler that is still running (no response yet) is not a stall. (3) Key revoke: `watch` asks core `AuthTable::key_active(agent, key, now)` (new) at least every second (`OWNER_CHECK_MS`; every sleep is capped at it, so a connection that authenticates during a long sleep is covered) and closes the connection (`Closed::OwnerGone`) when the key is revoked or expired or the agent is not active. A plain read lock, no vault guard. Rejected: a core event for key changes (no such event exists, and a 1 s poll per connection is cheap); a per-key cap (one agent has up to 5 live keys, so it would allow 5 × the cap). Tests (real TLS): `new6_a_response_the_client_never_takes_closes_the_connection` (h2 client with stream window 0, idle 30 s, send 600 ms: no body frame arrives, the connection ends after about 600 ms; it is kept with the old rule), `new6_one_agent_cannot_hold_every_connection` (cap 2: `200`, `200`, `429`; after one closes the third is served), `new6_revoking_a_key_closes_its_connections` (idle 30 s; closed within about 1 s of the revoke). Unit: `one_agent_binds_at_most_max_connections`, `a_response_waits_for_the_client_only_between_frames`; core `key_active_follows_revoke_and_suspend`.
- **DEC-T27-E-3** — NEW-7 (Info). (a) `watch` sleeps `wait.clamp(MIN_WAIT_MS, step)` with `step` floored at `MIN_WAIT_MS` (5 ms), so a limit under 5 ms (or 0) can no longer make `clamp` panic; such a limit just acts as 5 ms. (b) `Activity::admitted` (new): a connection that waited for a slot (every slot authenticated) gets its `auth_timeout` from the moment it got the slot, not from accept, so a long wait no longer closes it right after its handshake. (c) `Pending::admit` evicts through `evict_any`, which tries the next victim when the chosen one authenticated between the prune and the eviction (each try removes one entry, so it ends). Not changed: a connection that waits for a permit can still be evicted by the other listener's accept loop (it then ends at once when it gets the permit; nothing is held). Tests: `tiny_limits_do_not_panic` (0, 1 and 4 ms; panicked with `min > max` before), `the_auth_time_starts_when_the_slot_is_free`, `a_victim_that_authenticated_does_not_stop_the_eviction`.
- **DEC-T27-E-4** — NEW-3 rest (Low). `Tx::revoke_all_leases` and `Tx::cancel_pending_requests` no longer write with the UPSERT (`put_lease` / `put_access_request`), which sets `agent_id` and `item_id` and so runs the foreign-key check. They run `UPDATE leases SET revoked_at, revoked_by, row_mac WHERE id = <stored id text>` and `UPDATE access_requests SET status, decided_at, row_mac WHERE id = ...`. SQLite checks a child foreign key on UPDATE only when a key column is in the SET list, so a genuine lease (or pending request) whose `items` or `agents` row a file attacker deleted with foreign keys off is now revoked (or cancelled) and signed like the others, instead of failing the whole panic revoke at lock and at every unlock. Revoking it is better than skipping it: the lease is genuine (good MAC), and revoked is the safe state. The `WHERE` uses the `id` text as stored, so the update finds the row that was read; if it changes no row, the row is counted in `malformed` (the existing alert path, DEC-T27-D1-3). Test: `a_lease_whose_parent_row_is_gone_is_still_revoked` (store; an item and an agent deleted with `PRAGMA foreign_keys = OFF`; before: `Conflict` from `revoke_all_leases`; after: three leases revoked and signed, both requests cancelled).
- **DEC-T27-E-5** — AUD-25 rest (Low). Supersedes the ambiguous-case rules of DEC-T27-D1-2. When no `@` comes after the first `/`, `?` or `#`, the URL is still read as RFC 3986 says (path kept). Otherwise the path, query and fragment are never kept, and only scheme and host are, when the host is safe: (a) the RFC authority is a `host[:port]` → kept only if it is a plain host name with an inner dot and no port (`https://site.example/login?email=a@b` → `https://site.example`); a dot-less name (`https://tokPart1/part2@github.com/x`, the first part of a token used as the user name) or a `host:port` (`https://user:1234/x@host/`) gives no target; (b) the authority is user information (`user:pa`) → only with exactly one `@` in the whole text is the host after it (`https://user:pa/ss@host/x` → `https://host`); with two or more (`https://user:pa/ss@host/x?token=abc@def/ghi`, or an `@` in the password) which `@` ends the user information cannot be told, so no target. No target also means no title from the URL (the row needs a title cell, as before). Accepted rest: a user name that is itself a dotted name followed by an unencoded `/`, `?` or `#` and no password (`https://john.doe/x@host/`) shows `john.doe` as the host; it is a user name, not a secret, since a password would need a `:` and then case (a) does not apply. Test: `the_target_never_keeps_an_unencoded_password` (both re-check inputs first; plus `https://intranet/login?u=a@b` and `https://shop.example:8443/login?e=a@b` give no target, and the earlier inputs now give scheme and host only).

## T27-F — Audit re-check fixes, section 8 (2026-11-17)

- **DEC-T27-F-1** — NEW-10 (Low, product bug) and the AUD-10 rest. (1) The desktop restore closes the old store, and waits for it, before any file moves: after the lock, `close_service` stops the server and the core tasks (`stop_all`; `stop_server` now awaits the aborted leaf-renewal handle, which holds a service clone), takes the service out of the state and calls `VaultService::close_store` (new: `Store::close` on the shared pool, which waits until every connection, also one still in use by a cut request, is closed; every later store call of any clone fails, so a late task cannot open a new connection). So no SQLite connection of the old vault can unlink `vault.cerberus-wal` or `-shm` by name during the swap. The probe service of the credential proof and the restored service in `roll_back` are closed the same way. The API connection tasks are not awaited one by one: the pool close waits for the connections they hold, which is what matters. (2) `swap_files` (store) never stops half way: a `-wal` or `-shm` that is gone at its rename counts as already moved (no `exists()` check before the rename); when any rename fails (a side file or the final rename of the checked copy), every file moved so far is moved back in reverse order and the error is returned, so after any error the old vault is the vault file again. Only when a file cannot be moved back is the error the new `StoreError::RestoreStranded { moved }`, with the path of the old vault. An orphan `-wal` or `-shm` with no main file is moved aside too, so it is never replayed into the restored file. The `.pre-restore-<time>` name gets `-2`, `-3` ... when a file of that name exists (two restores in one second no longer overwrite the first old vault). (3) The desktop never makes a new vault on a failed restore: after a swap error it first tries once more to put a stranded old file back (`put_back`, never over an existing file), then opens the vault path with `create: false` (`DesktopState::reopen_service`, new). The installed file after a good swap and the old file after `roll_back` are opened the same way. `create: true` is kept only when there was no vault file before the restore. If the old file cannot be opened, no service runs (`unavailable`) and the log names the `.pre-restore-*` path; the person does not see an empty vault. Rejected: an `install_backup` that renames the probe-checked copy (not needed for this bug). Residual: a pooled connection whose return ping fails is dropped (`close_hard`) and its worker thread closes the handle a moment later, so the pool close cannot wait for that one; with (2) a late unlink of a side file before the swap no longer breaks it, and it is only a risk if it lands after the restored file was installed. cerberusd and the CLI have no restore (the core `authorize_restore` comment names only the desktop), so nothing to change there. Tests: store `a_swap_that_fails_after_the_move_puts_the_old_vault_back` (the checked copy is missing at the final rename: main file, `-wal` and `-shm` come back unchanged and the old vault opens; before: they stayed at `.pre-restore-*`), `missing_side_files_do_not_stop_the_swap`, `a_second_restore_in_the_same_second_keeps_the_first_old_file` (before: the first old file was overwritten); desktop `new10_the_old_store_is_closed_before_the_swap` (a `cfg(test)` swap hook in `DesktopState` records, right before the swap, that the old `Store` is closed and its `-wal` is gone; before: open), `new10_a_stranded_old_vault_is_put_back_not_replaced_by_an_empty_one` (before: a new empty vault, unlock failed), `new10_a_failed_swap_never_makes_a_new_vault` (the vault file is gone after the failed swap: the vault path stays empty and no service runs; before: a new empty vault file). The hook and `fail_next_open` are test only.
- **DEC-T27-F-2** — NEW-8 (Low). The `auth.failed` throttle (`vault/authlog.rs`) keys by source and class, not by raw IP. Source: the API's mapping (`idle::source_of`, DEC-T27-D2-2), all of loopback (`127.0.0.0/8`, `::1`, IPv4-mapped forms) as one source and an IPv6 address by its `/64`; the core lockout key (`auth/limits.rs` `ip_key`) is not changed here. Class: whether the secret matched a real key (`AuthFailure::matched_a_key`: expired or revoked key, inactive agent, IP or mTLS rule) or was a guess (malformed, unknown agent, no key match), so a bad-token flood cannot hide a stolen revoked token. Per class, at most `GLOBAL_PER_WINDOW` (10) events a minute are written from all sources together; failures past that, and the counts of entries dropped by the 4096-source bound, are counted and the next event of the class carries them as `suppressed_other` (next to `suppressed_before`, the count of the same source and class). So the chain grows by at most 20 `auth.failed` rows a minute whatever the number of addresses (before: one per raw IP, about 4,097 a minute). The underlying reason survives a limit: `AuthTable::check_refusal` (new; `check` is unchanged and maps to it) returns a `Refusal { failure, cause }`, the API audits that, and the event has `reason` = the cause (`key_revoked` during a lockout), `result` = what the caller got (`too_many_failures`) and `limit` = `locked_out` or `rate_limited` when a limit refused it. `audit_auth_failure` takes `impl Into<Refusal>`, so callers with a plain `AuthFailure` still work. Not changed: while locked the row goes to `audit_pending`, which has no details, so the reason under a lockout is lost there (the outward code is kept, as before). The existing test `unlocked_failures_write_one_event_per_minute_with_the_count` now uses a guess for its second failure (a `key_expired` there is a different class and gets its own count). Tests: core `new8_loopback_is_one_source_and_ipv6_counts_by_its_64`, `new8_a_flood_from_many_sources_is_capped_and_counted`, `new8_a_matched_key_is_not_hidden_by_a_guess_flood` (unit), `new8_a_lockout_keeps_the_reason_under_it` (auth), `new8_a_revoked_token_during_a_lockout_flood_is_recorded` (200 loopback addresses: one flood row, plus one `key_revoked` row with `limit = locked_out`; a minute later the flood row carries 199), `new8_failures_from_many_sources_write_a_bounded_number_of_rows` (300 sources: 10 rows, then `suppressed_other` = 290).
- **DEC-T27-F-3** — NEW-9 (Low). CSV import keeps only scheme, host and port in the item `target` (`csvio::rows::target_of`); the path is dropped like the query and fragment (AUD-25). Webhook and bot URLs (`https://hooks.slack.com/services/...`, `https://discord.com/api/webhooks/<id>/<token>`, `https://api.telegram.org/bot<token>/...`) carry their secret in the path, and any agent with `catalog:read` reads `target`. A list of known webhook hosts was rejected: it can never be complete, and a path is rarely needed to match an item. What uses `target`: `resolve` (`resolve/score.rs`) matches the app name against the whole target, its host and its word runs, and adds hint words from it; the host is still there, so matching by host is unchanged, and only words that were in an imported path no longer count. The index search text and the UI show the shorter target. The full URL stays in the sealed login payload (`Payload::WebLogin.url`), and a person can still type a path into `target` by hand (that is the person's choice). The title from the URL already used the host only. The two older target tests now expect no path (`the_target_drops_user_info_query_and_fragment`, `the_target_never_keeps_an_unencoded_password`). Test: `new9_the_target_never_keeps_the_url_path` (Slack, Discord, Telegram, a port with a path, a bare host with a path: target is scheme, host and port; the payload URL still holds the whole text).

## T27-G — A stranded vault is never replaced by a new one (2026-11-17)

- **DEC-T27-G-1** — NEW-10 rest (Low). If a restore fails badly and the real vault stays only as `<vault>.pre-restore-*`, the next start of the desktop app used to run `DesktopState::open` with `create: true` and made a new empty vault, so the person thought the data was gone. Now `DesktopState::open` first checks (`note_stranded`): the vault file does not exist (not even as a symlink) and `cerberus_store::stranded_vaults` finds one or more `<vault file name>.pre-restore-*` main files (not `-wal`/`-shm`, regular files only, newest first by the stamp and then the `-N` of `free_name`). If so it makes no vault and starts no service; it keeps the paths in `Inner::stranded`, logs an error with them, and returns the state. `core()` then fails with the new typed error code `stranded_restore` (before: `unavailable`), so `vault_create`, `backup_restore` and every other command that needs the service are refused, and nothing can hide the old file. `vault_status` answers without a service: state `no_vault` and the new field `stranded_restore: string[]` (empty in every normal run; the paths, newest first). The same list is set when a failed restore cannot reopen the vault and the vault file is gone (`reopen_after_failed_swap`, `roll_back`), so the person sees it at once, not only at the next start. `attach_os_events` keeps the OS source when no service runs because of this, and the recovery gives it to the service it opens. New IPC command `vault_recover_stranded` (main window; `names.rs`, capability, bindings): under the restore gate it refuses with `conflict` when any of `vault`, `-wal`, `-shm` exists at the vault path or a service runs (nothing is moved, nothing is replaced), with `not_found` when no old file is left; else it moves the newest old file with its `-wal` and `-shm` to the vault path (`move_files`: checks every target first, never replaces, moves back what it moved when a rename fails; `put_back` uses it too, so it no longer stops half way either) and opens it with `create: false`. If it does not open, the files go back to their old name and the error is returned. The vault is sealed afterwards. Audit and log: a `warn` log line with the old path, and the new event `backup.recover` (catalog, `docs/reference/audit-events.md`, UI phrase list) written to `audit_pending` by `VaultService::record_stranded_recovery` (no key needed: the vault is sealed, so the event joins the chain at the next unlock with `recorded_while_locked`; no path, no secret; `LOCKED_TYPES` accepts it). Older `.pre-restore-*` files from earlier restores are left alone. UI (unlock screen, minimal): in state `no_vault` with `stranded_restore` not empty the screen shows "Your vault was found, but it is not in place", the newest path, the count of older files and one button "Put the vault back" (the create and restore buttons are not shown); the guard (`resolveRoute`, new `stranded` argument) sends every route in this state to `/unlock`, so the create wizard cannot start; success invalidates `vault_status`, which then reads `sealed`; an error is shown with its `command: code` line (`conflict` has its own text). Messages in `screens/unlock/messages.ts`, error code text `error.code.stranded_restore`. Rejected: a new vault state kind (`VaultState` is a closed enum used by the pump, the tray and the guard; a field on the status changes nothing for them, and the state is `no_vault` in fact); picking the newest file by mtime (a renamed file keeps the mtime of its last write, not of the restore; the stamp in the name is the restore time); restoring from an old file that is not the newest (the person can rename by hand, the guide says how); moving the stranded file back at start without asking (the person may want to look at the folder first, and a restart loop could hide a problem). cerberusd: it never creates a vault (`create: false`, and `DaemonError::NoVault` when the file is missing) and has no restore, so nothing changes there. Tests: store `stranded_vaults_lists_main_files_newest_first`; desktop `t27g_start_with_only_a_pre_restore_file_makes_no_vault` (no vault file, the path is reported by `vault_status`, `vault_create` is refused with `stranded_restore`; before: a new empty vault), `t27g_recover_puts_the_stranded_vault_back` (the file is back, state `sealed`, the vault unlocks with its note, one `backup.recover` row; before: the start made a new vault, so the recovery was refused), `t27g_recover_refuses_when_a_vault_file_exists` (a file at the vault path stays as it is, the old file does not move; before the check: the old file replaced it), `move_files_takes_the_side_files_and_never_replaces`; `new10_a_failed_swap_never_makes_a_new_vault` now also expects `stranded_restore` and the path in the status; UI `says where a stranded vault is and puts it back instead of offering a new one (T27-G)`, `shows the error when the stranded vault cannot be put back`, guard test `closes the create screen while a failed restore stranded the vault (T27-G)`. Docs: `backup-and-restore.md` and `troubleshooting.md` ("If a restore fails"), and the CSV import `target` wording of DEC-T27-F-3 (scheme, host and port only; the full URL stays in the sealed login) in `user-guide.md`, `operator-guide.md` and `security-model.md` (`agent-integration.md` does not mention it). Residual: a restore that fails with the old file moved and an error that leaves the vault file present but unreadable is not "stranded" (the file is there); the person sees `vault_corrupt` or `internal` as before.

## T27-H — Restore leftovers, linked vault paths, close and unlock order (2026-11-17)

- **DEC-T27-H-1** — NEW-12 (Low). Two layers. (1) A `.pre-restore-*` name now means only "a restore did not finish": when `backup_restore` went through (the restored file opened and `finish_restore` revoked its leases), the desktop calls the new store function `retire_replaced`, which renames the old file, with its `-wal` and `-shm`, from `<vault>.pre-restore-<stamp>` to `<vault>.replaced-<stamp>` (`free_name` adds `-2` ... when taken, never replaces; side files first and the main file last, and moved side files go back when a rename fails). `stranded_vaults` matches only `.pre-restore-`, so a successful restore's leftover no longer starts the stranded state when the vault file is missing later: the start is a normal start. The file is still kept, as before. A failed rename is only a `warn` (the restore did succeed), and the file keeps its `.pre-restore-*` name: that case, a crash between the swap and the end of the restore, and `.pre-restore-*` files written by older versions are covered by (2). (2) Every vault that `vault_recover_stranded` puts back loses its agent keys and leases at its first unlock, before it serves any call. The `backup.recover` row in `audit_pending` is the marker (written with no key while sealed, persists across restarts, also seen by cerberusd if it opens the file): `unlock_impl` checks it (`Store::has_audit_pending`, read only) after the keys are derived and before the pending drain, and `revoke_after_recovery` revokes every live agent key (MAC checked, `revoked_at` set, signed again, `update_live_agent_key`), revokes every lease and cancels every pending request, in one transaction. Only after that commit is the row drained into the chain, so a crash in between runs the revoke again (a revoked key stays revoked). After the drain the new event `backup.recover_revoke` (catalog, `docs/reference/audit-events.md`, UI phrase list) records the counts, and waiters of cancelled requests are told. A row with a bad MAC is left as it is (the token table treats such a key as revoked) and the alert is raised. A failed revoke fails the unlock: the old keys are never served. `record_stranded_recovery` now returns its error and ignores the pending cap (a full list must not drop the marker); when it fails, the recovery closes the service, moves the file back and reports the error. No unlock can run between the reopen and the marker: `vault_unlock` waits for the restore gate that the recovery holds (DEC-T27-H-3). The stranded screen says that the agent keys and leases are revoked at the next unlock. Why revoke for every recovery, also of a genuine failed-restore file: the person had asked to replace that vault, the app cannot prove which kind of file it is (old versions, a failed rename, a crash), and a revoked key costs a new token while a revived leaked token costs secrets. Rejected: a journal file next to the vault, written before the swap and cleared on success (a second file that can be lost or left behind, and it says nothing about files of older versions); asking for a credential in `vault_recover_stranded` and revoking at once (no operator list exists without a service, and the UI would need a second unlock form); revoking also in `roll_back` and `put_back` inside the same restore (the vault never stopped being the current one there, and the person sees that the restore failed). Not done: the age of the file on the stranded screen and a "start a new vault" choice behind a confirmation (the auditor's UI hints); with (1) a successful restore no longer leads there. Tests: store `t27h_a_replaced_vault_is_not_listed_as_stranded`; desktop `t27h_a_successful_restore_leaves_no_stranded_file` (before: the leftover was `.pre-restore-*`), `t27h_a_recovered_vault_loses_its_agent_keys_at_unlock` (the key is revoked, one `backup.recover_revoke`, and a second unlock revokes nothing again; before: the key was live).
- **DEC-T27-H-2** — NEW-11 (Low). (a) A restore over a vault path that is a symbolic link is refused, not followed. `cerberus_store::linked_vault_file` reports the first of `vault`, `-wal`, `-shm` that is a link; `backup_restore` checks it right after the owner check, before the backup is read, the vault locked or any file moved, and answers `unavailable` ("the vault file is a symbolic link; put the real file at the vault path, then restore"). `restore_backup` checks it too (`StoreError::Io(InvalidInput)`), as a guard for any other caller. Why refuse and not resolve: resolving moves files in the folder the link points to (often a synced folder), the `-wal` and `-shm` names then depend on how SQLite resolves the link, and a link that changes between the check and the rename would aim the swap at another file; a refusal changes nothing and the person can fix the layout. `stranded_vaults` now also lists a `.pre-restore-*` main file that is a symbolic link (folders are still skipped), so a link that an older version moved is seen and the start makes no vault (the recovery renames the link back). (b) `note_stranded` fails closed: when the vault path cannot be checked (a `symlink_metadata` error other than not found) or the folder cannot be listed, it logs an error, sets `stranded_check_failed`, and the start makes and opens no vault. `core()` then answers `unavailable` ("the data folder could not be read, so no vault was opened or made; restart Cerberus"), so `vault_status` shows the status error screen with retry, and `vault_create` and `backup_restore` are refused. `attach_os_events` keeps the OS source in this state too. `vault_recover_stranded` still works once the folder reads again, and clears the state. Tests: store `t27h_a_linked_vault_path_is_not_restored` (before: the restore went through and returned the moved link at `.pre-restore-*`), `t27h_a_linked_old_vault_file_is_listed_as_stranded` (before: not listed); desktop `t27h_a_restore_over_a_linked_vault_path_is_refused` (refused while still unlocked; before: the restore went through over the link), `t27h_a_folder_read_error_at_start_makes_no_vault` (data folder mode 0300, so `read_dir` fails; skipped when the mode is not enforced, as for root; before: a new vault file was made).
- **DEC-T27-H-3** — NEW-14 (a) and (b) (Info). (a) `DesktopState::open_service_with` closes the store, and waits for it, when `VaultService::open` fails after `Store::open` succeeded, so a recovery or a roll back that moves the files right after the error cannot race a closing connection that removes `-wal` or `-shm` by name. `Store::open` does the same when the pre-migrate backup, a migration or the version check fails after the pool exists (the steps moved into `Store::migrate`). (b) `vault_unlock` and `vault_unlock_recovery` wait for the restore gate (`lock().await`, not `try_lock`): an unlock can no longer run between the restore's `lock` and `take_core` and start a server on the old service, and an unlock during a recovery runs after the revoke marker is written. A waiting unlock then unlocks whatever vault is in place. Two unlocks now run one after the other. A restore that starts while an unlock runs gets `conflict`, as for two restores. The gate is a tokio mutex held only across these awaits; no vault guard is held. (c) and (d) of NEW-14 are not changed. Tests: desktop `t27h_a_store_whose_service_does_not_open_is_closed` (a `cfg(test)` flag fails `VaultService::open` after the store opened and keeps the store; before: not closed), `t27h_an_unlock_waits_for_the_restore_gate` (with the gate held the unlock does not finish in 3 s and the vault stays sealed, then it unlocks; before: it unlocked while the gate was held). The `Store::open` part has no test of its own.

## T29 — Packaging and CI/CD (2026-11-17)

- **DEC-T29-1** — CI pins every action to a commit SHA (tag in a comment), uses `permissions: contents: read` at the top level and `persist-credentials: false`, caches cargo with `Swatinem/rust-cache` and pnpm with `setup-node`, and reads Node from `.nvmrc`. The previous workflow used floating tags. `ci.yml` gained `acceptance`, `coverage` (90 % gate), `fuzz-smoke` (push and schedule only, nightly), `cross-platform-build` (macOS, Windows `cargo check`), a weekly schedule (new advisories) and `workflow_call`, so the release workflow reuses the gates. `client-deps-check` now runs in the `deps` job, as in `just check`. Not in install-action: `tauri-cli` and `cargo-fuzz` are installed with `cargo install --locked --version`, kept by rust-cache.
- **DEC-T29-2** — `tauri.conf.json` `bundle.active` is now true, targets `deb`, `rpm`, `appimage`, `dmg`, `nsis` (Tauri skips the kinds a host cannot build). Icons for all platforms (`icon.ico`, `icon.icns`, sizes) were made from the existing `icon.png` with `cargo tauri icon`; only the files the bundle list names were kept. `licenseFile`, category and descriptions were added. No `externalBin`: the daemon and CLI are separate tarballs, so the desktop installer does not carry a second copy of the vault code.
- **DEC-T29-3** — `cerberusd` is built and shipped for Linux only (it uses `std::os::unix` sockets and modes without `cfg`). `cerberus` and `cerberus-mcp` ship on every OS. The macOS and Windows CI jobs exclude `cerberusd` and `cerberus-acceptance`. Only Apple silicon macOS (`macos-15`; `macos-14` was retired by GitHub) and x64 Windows are built.
- **DEC-T29-4** — Signing: macOS signing and notarization use Tauri's `APPLE_*` variables, only when `APPLE_CERTIFICATE` is set (the secrets are named in the guide, no value anywhere). Windows has no signing step. Integrity for every file comes from `SHA256SUMS` and, on a public repository, a GitHub build provenance attestation (`actions/attest-build-provenance`, keyless; not offered for private user repositories). The release is built as a draft and published by the workflow once every platform's files and SHA256SUMS are attached (DEC-REL-1, 2026-11-17: owner asked for automatic releases; a published release is never rebuilt in place).
- **DEC-T29-5** — No auto-updater (no updater plugin or signing key exists in the app, and the plan has no update channel). Updates are manual installs. Revisit with a signed update channel in a later version.
- **DEC-T29-6** — Release recipes in the `justfile` (`package`, `package-binaries`, `sbom`, `checksums`, `release-local`) are the single build path for local and CI; the workflow only calls them. SBOM: `cargo-cyclonedx` 1.5 JSON per binary; the UI (pnpm) dependencies are not included. `dist/` and `*_bin.cdx.json` are git-ignored. The systemd unit already holds the AUD-29 hardening (DEC-T27-B-9); it is shipped in the Linux tarball unchanged. `systemd-analyze verify` only complains that `/usr/local/bin/cerberusd` is absent; `systemd-analyze security --offline` gives 0.9 SAFE.

## RM — Remote backend mode, design (2026-11-21)

- **DEC-RM-1** — RM — The owner asked for the desktop app to work against a deployed backend. New ADR-0034 amends D1, D2
  and D3 (ADR-0001, ADR-0002 points 2–4, ADR-0003 points 1–2, ADR-0023, ADR-0024); the old text stays, the status lines
  say what changed. Local mode stays the default and does not change. (ADR-0034, `docs/PLAN.md` 1.2)
- **DEC-RM-2** — RM — The admin API is part of `cerberusd` only, off by default (`[admin] enabled = false`,
  `CERBERUSD_ADMIN_ENABLED`). Off means no `/admin` route is mounted, so `/admin/...` gives `404 route_not_found` like
  any unknown path. On means `/admin/v1` on the same TLS 1.3 listener and HTTP rules as the Agent API; the listener then
  asks every client for a CA-signed certificate but still lets agents without one in on a loopback bind. The desktop's
  own vault never gets an admin route. Rejected: a second listener (more config, no gain now). (ADR-0034 point 2)
- **DEC-RM-3** — RM — Two factors on every admin call: an **enrolled** client certificate (its SHA-256 in
  `admin-clients.json`, not revoked, not expired; checked per request) and an operator **session** opened with a
  passphrase. "Signed by the vault CA" is not enough, because agent mTLS certificates (DEC-T09-5) come from the same CA.
  Agent `cvt_` tokens never pass on `/admin`, and `cas_` session tokens never pass on `/v1` or `/mcp`. (ADR-0034 point 4)
- **DEC-RM-4** — RM — Enrolment is local to the server: `cerberusd admin enroll --label --url [--operator] --out` talks
  to the daemon over the unlock socket (same-UID check, DEC-T13-1), needs the vault unlocked (CA key) and an owner
  phrase, binds the enrolment to one operator, and writes a JSON bundle (URL, CA pin and PEM, client cert and PKCS#8 key,
  mode 0600, created new). Client certificate 90 days, CN `cerberus-admin <enrolment id>`. The registry is plain JSON,
  mode 0600, because a remote unlock needs it while sealed (AR-19). `cerberusd admin revoke <id>` needs no phrase (it
  only removes power) and works with or without a running daemon. Rejected: an encrypted bundle with a one-time code
  (more UX, little gain: the bundle alone opens no session); deferred to DEC-RM-14. (ADR-0034 point 3)
- **DEC-RM-5** — RM — Sessions: token `cas_<uuidv7>.<32 random bytes, base64url>`, SHA-256 kept in daemon memory only;
  bound to the client certificate, the operator and the unlock epoch; idle 900 s (60–3600), absolute 12 h (900–86400,
  never past the hard lock); at most 4 per daemon and 2 per enrolment. Open on a sealed vault = `unlock_with_phrase`;
  on a vault unlocked by the same operator = new core `verify_operator_phrase` (KDF on the slot, constant-time VMK
  compare, no state change); unlocked by another operator = `409 conflict`, because core has one session
  (`Session::authorize`, `vault/state.rs:58`). Failures count in the ADR-0026 back-off and in a per-enrolment limit
  (5 / 15 min → 15 min refusal before the KDF). The recovery key is never accepted remotely. (ADR-0034 point 6)
- **DEC-RM-6** — RM — The admin wire **is** the IPC contract: `POST /admin/v1/rpc/{command}` with the IPC arguments as
  JSON (Rust argument names) and the IPC result DTO as the answer. The DTOs and `IpcError` move from the desktop crate to
  a new transport-free crate `cerberus-admin` (names unchanged, so `bindings.ts` does not change), with one handler per
  allowlisted command that both the desktop `ops` and the server call. MVP allowlist: 25 commands (2 pre-session,
  `vault_unlock` through the session route, 22 with a session). Admin errors are `{ request_id, error: IpcError }`, not
  the ADR-0021 agent shape, so the UI error handling is the same in both modes; `ErrorCode` and the agent OpenAPI do not
  change. Rejected: a resource-style admin REST API (duplicates about 60 DTO shapes). (ADR-0034 point 5)
- **DEC-RM-7** — RM — With the admin API on, `cerberusd` builds its core with `approvals_available = true` (decided at
  start, not per connected desktop). An `ask_*` request that no desktop decides expires after its timeout (default
  120 s, ADR-0018). With it off, ADR-0002 point 4 (`403 approval_unavailable`) stays. (ADR-0034 point 2.3)
- **DEC-RM-8** — RM — "Disconnect" is not "lock". A closed, expired or lost session, the desktop quitting, and OS sleep
  or screen lock on the desktop end only the remote session; the server vault stays unlocked for its agents. Only
  `vault_lock`, `vault_panic` or the daemon's own lock rules lock it. The UI shows the two actions apart. Reason: the
  server exists to serve agents. (ADR-0034 points 6.6, 7.5)
- **DEC-RM-9** — RM — The desktop proxy lives in Rust (`ipc!` macro → `cerberus-client` `PinnedHttps` with CA pin and
  client certificate). The webview CSP stays `connect-src ipc: http://ipc.localhost`. The session token never reaches
  the webview. The mode is a desktop preference; switching restarts the app, so a local service and a remote backend
  never run together; switching to remote is refused while a local vault is unlocked. In remote mode no local vault is
  opened and no local HTTPS server runs. (ADR-0034 points 1, 7)
- **DEC-RM-10** — RM — In remote mode `vault_status.state` is `unlocked` only while this desktop holds a live session,
  else `sealed`, so the router guard and the screens need no new state. A new field `VaultStatusView.remote` (null in
  local mode) carries profile, URL, the server's real state, reachability and version. An unreachable server is a normal
  answer (`remote.reachable = false`), not an error, so the unlock screen can offer "Retry" and "Use the local vault".
  (ADR-0034 point 7.3)
- **DEC-RM-11** — RM — Commands off the allowlist answer `remote_unsupported` on the desktop before any network call,
  and the UI hides or greys them ("Not available for a remote server"). Local UI preferences that touch no vault (UI
  scale and zoom keys, language, theme) keep working in remote mode; the request listed zoom among the disabled
  commands, but it never reaches a backend, so disabling it would protect nothing. Item payloads that point at a
  desktop-held SSH draft are refused in remote mode. (ADR-0034 points 5.6, 7.7, 7.8)
- **DEC-RM-12** — RM — The admin routes are not in `docs/api/openapi-draft.yaml` (the agent contract). They get their own
  route-list test (exactly five routes), and a new test checks that the generated agent OpenAPI has no `/admin` path.
  (ADR-0034 point 5.5)
- **DEC-RM-13** — RM — Doc drift: ADR-0002 point 3 and ADR-0031 point 3 name `cerberusd restore <file>`, which was never
  built (`cerberusd` has `serve`, `unlock`, `status`; `docs/guides/cerberusd.md` says there is no restore command).
  Notes were added to both status lines; the text is not rewritten. Remote mode does not add a restore: on a server the
  restore stays a file copy. (ADR-0002, ADR-0031)
- **DEC-RM-14** — RM — Deferred, not in the MVP: copy-to-clipboard in remote mode (reveal over RPC, then the local
  clipboard timer); more commands on the allowlist (`item_versions`, `item_restore_version`, agent create, keys and
  status, `lease_revoke_all`, `audit_verify`, vault settings); switching the session operator on an unlocked vault; a
  sealed mirror of `admin-clients.json` checked at unlock (AR-19); the client key in the OS keychain (AR-20); a separate
  `admin.bind`; an encrypted bundle. Each needs only an allowlist entry or a small change on top of the MVP.
  (`docs/remote-mode-plan.md`, "Follow-ups")

## RM — Remote backend mode, build (2026-11-21)

- **DEC-RM-15** — RM — The two RustDesk commands (`rustdesk_status`, `rustdesk_connect`, DEC-RD-3) are local-only and
  not on the remote allowlist: they look for the RustDesk client on this machine, start it, and put the password on the
  local clipboard. A `rustdesk` item itself needs no remote work: it flows through the shared DTOs and `item_*`
  commands. Connect in remote mode is the same follow-up as clipboard copy (DEC-RM-14): reveal over RPC, then the local
  launch and clipboard timer. (`docs/remote-mode-plan.md` step 0)
- **DEC-RM-16** — RM — RPC argument errors: a body that is not the JSON object of the command's arguments (bad shape,
  wrong type, missing field, unknown field, empty body) is `invalid_request`, as ADR-0034 point 5.2 says; the plan's
  step 2 test said `validation_failed` and was corrected. A bad ID or time inside well-formed arguments stays
  `validation_failed` with the field name, as in local IPC. The message never quotes the input (it can hold a phrase).
  Commands with no arguments take `{}`. `vault_unlock` through `rpc` is `remote_unsupported`: it opens a session and
  only goes to `POST /admin/v1/session`, whose body is parsed as the same `VaultUnlockArgs`. Shared handler shapes that
  differ from the plan sketch: `vault_lock(core)` takes no context (core `lock` needs none, as the local command), and
  `ui_activity(core)` is synchronous (the caller rate-limits it); `handlers::take_payload` and
  `handlers::payload_for_create` hold the payload split that both callers need. (`crates/cerberus-admin/src/rpc.rs`)

- **DEC-RM-17** — RM — Core phrase check and admin audit, as built (plan step 3). (a) No new `Vmk::ct_eq`:
  `Vmk::same_key` already compares in constant time (`mac::ct_eq`), so `cerberus-crypto` does not change.
  (b) `verify_operator_phrase` order: `Locked`/`NoVault` → back-off (`UnlockBackoff`, before any KDF) → unknown
  operator or the recovery slot (a failed try without the KDF, as in `unlock_impl`) → another operator (`Conflict`, not a
  failed try) → KDF → constant-time compare with the live VMK (a different key is a failed try plus an
  `IntegrityAlert` on `key_slots`) → reset of the counter → the session must still be the same (epoch and session
  unchanged, else `Locked`). The plan put `Conflict` before the back-off; then the recovery slot ID would have been a
  `Conflict`, not the `BadCredentials` its test asks for, and the recovery key must never pass over the network. No
  state guard is held during the KDF (only the unlock gate, as an unlock does), so a lock is not delayed. (c) A failed
  try on an unlocked vault writes `vault.unlock_failed` straight to the chain (target the vault, `details.operator`),
  not to `audit_pending`, so the admin sees it before the next unlock; the back-off counter is the same header field.
  (d) `record_admin_event(ctx, AdminAudit) -> Result<(), CoreError>`: actor `operator:<id>` with a context, else
  `system`; target `admin_client:<enrolment>`; details `label`, `operator`, `reason`, `unlocked`. While sealed only
  `admin.api_start`, `admin.session_close` and `admin.client_revoke` are kept (in `audit_pending`, target only: the
  pending row has no details); `session_open` and `client_enroll` give `Locked`, because the drain would count them as
  malformed rows. (`crates/cerberus-core/src/vault/custody.rs`, `integration.rs`, tests `vault/tests/admin_verify.rs`)

- **DEC-RM-18** — RM — Admin certificate, registry and bundle, as built (plan step 4). (a) `LocalCa::issue_admin_client`
  and `ADMIN_CLIENT_DAYS = 90` in `cerberus-api` `tls.rs`; the client check of `server_config` is now the private
  `client_verifier`, so the test verifies the new certificate with the same verifier the listener uses. (b) Enrolment
  IDs are a typed `EnrolmentId` (UUIDv7 via `uuid_id!`). (c) `admin-clients.json` carries a `version` (1) around the
  entry list, so a later format change is detected instead of misread; `load` also refuses a link or other non-regular
  file, more than 1 MiB, a hash that is not 64 lower-case hex digits, a bad label and two entries with the same ID or
  certificate. Labels are 1 to 64 characters without control characters (as operator labels). (d) The bundle key is a
  `cerberus_types::wire::WireSecret` rather than a bare `Zeroizing<String>`: same zeroizing and `[REDACTED]` `Debug`,
  and it has serde, which `Zeroizing` has only with a feature the workspace does not turn on. (e)
  `AdminBundle::read(path, now)` takes the time, because the client certificate is checked with the rustls client
  verifier (CA, clientAuth, validity at `now`). Beyond the plan it also refuses a CN other than
  `cerberus-admin <id>`, a `not_after` that differs from the certificate, more than one certificate in a PEM field, a
  URL with a user, query, fragment or path, and a key that does not match the certificate. Errors never quote the file.
  (f) New `cerberus-admin` dependencies, all already in the workspace: `rustls`, `x509-parser`, `sha2`,
  `data-encoding`, `url`, `uuid`; `rcgen` for tests only. Residual: serde_json unescapes the key PEM through its own
  scratch buffer, which is not zeroized (the same as every IPC secret). (`crates/cerberus-admin/src/clients.rs`,
  `bundle.rs`)

- **DEC-RM-19** — RM — Admin HTTP module, as built (plan step 5). (a) Core gets `VaultService::lock_epoch()` (the
  existing epoch that grows at every lock request): a session stores the epoch read **before** its phrase check, the
  open fails `vault_locked` when the epoch moved or the vault is not unlocked after it, and every check wants the vault
  unlocked at the same epoch, so no session survives a lock or a new unlock. (b) The answers that are not IPC DTOs live
  in `cerberus-admin` `wire.rs`, so the desktop (step 8) decodes the same types: route paths, `HelloView {
  server_version, admin_protocol, vault_state, remote_commands }`, `SessionOpenedView { token, session, idle_seconds,
  max_seconds }`, `AdminErrorBody { request_id, error }`, `SESSION_TOKEN_PREFIX`; plus `IpcError::admin_cert_required`.
  (c) `AdminState::new(clients, limits)` + `with_registry_file(path)`; `enroll`, `revoke(core, id)` (ends the
  enrolment's sessions, audits `admin.session_close` `revoked` and `admin.client_revoke`; a failed save keeps the revoke
  in memory and returns the error), `reload_clients(core)`, `session_live(core, id)` (also wants the enrolment live, so
  an expiring certificate ends its stream and connections), `sweep(core)`. A sweeper task, started by `start` and
  stopped by `shutdown`, sweeps at every vault state change and every 15 s; a request also ends a session it finds
  past a limit. The failure limit is in `admin/mod.rs` (no separate file). (d) Caps: at the enrolment cap the oldest
  session of that enrolment ends; at the daemon cap the oldest session of all ends (reason `closed`), so a new login
  always works. (e) Idle: every session `rpc` call and `DELETE` resets the idle limit and counts as operator activity,
  except `request_list_pending` (the desktop reads it in the background) and the event stream, so an unattended
  desktop still reaches its idle limit. (f) Status table as the plan, plus `payload_too_large` 413 and
  `unsupported_media_type` 415, then the ADR-0021 status of an agent code with the same name, else 500. `rpc` and
  `session` bodies must be `application/json`. (g) Session open order: device limit (429 before any body or KDF;
  also one open in flight per enrolment, a parallel one is `429 rate_limited`, so parallel tries cannot all pass the
  check before the first failure counts) →
  body (8 KiB, zeroizing buffer that never grows) → `operator_id` must be the enrolment's (`403 forbidden`) → sealed:
  `unlock_with_phrase`, unlocked: `verify_operator_phrase`, locking: `vault_locked`. Only `bad_credentials` counts in
  the device limit; a success clears it. A token over another certificate is refused but does not end the session.
  (h) `DELETE` answers 204 and unbinds its own connection, so the answer is not cut. A connection is marked
  authenticated (and bound to the session, `idle::ConnOwner::Admin`) only by requests with a live session and by a
  successful open; device-only calls keep the unauthenticated deadlines. (i) The event stream sends the core events
  through `events::from_core` only; `PendingCountChanged` is not sent by the server (core has no such event; the
  desktop counts with `request_list_pending`, as its local pump does). A third stream of a session is `429
  rate_limited`. (j) `admin.session_close` rows written while sealed (reason `lock`) keep no details (DEC-RM-17 d).
  (`crates/cerberus-api/src/admin/`, `tests/admin.rs`, `tests/admin_logging.rs`)

- **DEC-RM-20** — RM — `cerberusd` admin config, enrolment and approvals, as built (plan step 6). (a) The socket
  request is one flat struct: `op` (`unlock` by default, `admin_enroll`, `admin_list`, `admin_revoke`) and optional
  `operator`, `phrase`, `owner`, `label`, `url`, `id`; it now refuses unknown fields. An old
  `{"operator","phrase"}` line is still an unlock. `accept_loop` takes a `SocketContext { core, admin, data_dir }`.
  (b) `admin_enroll` order: admin API on (else `unavailable`) → label → vault unlocked (else `vault_locked`) → the
  owner (by `select_operator`) must have the owner role (`forbidden`) → `verify_operator_phrase` (`bad_credentials`;
  `conflict` when another operator unlocked the vault) → bound operator by label → sign, build the bundle and run
  `AdminBundle::check` (so a bad URL is `invalid_request` before anything is stored) → registry saved, then the
  memory → `admin.client_enroll`. (c) `admin_list` and `admin_revoke` also work over the socket with the admin API
  off (they use the file; the revoke is audited through the running core). With no daemon, `cerberusd admin list`
  reads the file and `revoke` edits it; that offline revoke writes **no** `admin.client_revoke`, because the vault is
  not open (ADR-0034 point 3.6 names the event; the guide says so). (d) `Reply` gets `bundle: Option<Box<AdminBundle>>`
  and `clients`; the server writes every reply from a zeroizing buffer (`rpc::to_body`, newline written apart) and the
  client reads it into a fixed 64 KiB zeroizing buffer. (e) `start_http` sets `client_ca_der` when the admin API or
  `require_mtls` is on, `require_client_cert = require_mtls`, and `admin = Some(AdminConfig)`. When the vault has no
  leaf yet, the admin API comes up with the listener at the first terminal unlock (ADR-0034 point 8). (f) `cerberusd
  status` also prints the CA pin and SHA-256 fingerprint (what the desktop shows at import) and "admin API: on/off, N
  enrolled clients" from the config and the registry file. (g) New `https::request_as` with an optional client
  identity (tests and checks; the key copy is not zeroized). (h) The unlock log line for ask grants says an enrolled
  desktop decides them when approvals are on. (i) Residual: `IssuedCert::key_pem` builds the PEM in a plain `String`
  that moves into the bundle's `WireSecret`; the base64 encoder's scratch is not zeroized (as DEC-RM-18 f).
  (`crates/cerberusd/src/{config,daemon,unlock,admin,status,https,main}.rs`, `tests/daemon.rs`)

- **DEC-RM-21** — RM — `cerberus-client` admin transport, as built (plan step 7). (a)
  `PinnedHttps::with_client_cert(base_url, trust, (cert, key), timeout)` builds a transport with no token;
  `send_bearer(request, Some(token))` sets a sensitive `Authorization` for that request only, and `None` sends no
  `Authorization` (the pre-session calls); `send` and the typed `Client` are unchanged. A caller-set `Authorization`
  in `Request::headers` is still dropped. The formatted `Bearer ...` text is zeroized after the header copy. (b) Two
  additions the plan did not list, for the desktop's phrase and reveal traffic: `zeroizing_body` (a request body over a
  zeroizing buffer, wiped when the send is done) and `Response::bytes_zeroizing(limit)` (grows into new zeroizing
  buffers only). rustls still copies what it encrypts and decrypts. (c) `sse::EventStream::new(response)` and `next()
  -> Option<Result<(String, Vec<u8>), ClientError>>`: the name is `message` without an `event:` line, several `data:`
  lines are joined with `\n`, `\r` is dropped, comment lines and blocks without data (`id:` / `retry:` only) are
  skipped, a block over 1 MiB ends the stream. `RequestEvents` keeps its behaviour on top of it. The client still links
  no vault or server crate (`just client-deps-check`). (`crates/cerberus-client/src/{transport,sse}.rs`,
  `tests/pinning.rs`)

- **DEC-RM-22** — RM — Fixes of the security review of the remote admin API (a2ccc61..476f77d). (a) **Revoke whose
  save failed** (medium): `AdminState` keeps an `unsaved` flag (set when a registry save fails, cleared by the next
  good save of the whole registry). A revoke of an enrolment that is revoked in memory while `unsaved` is set saves
  again and answers as a first revoke (true, or the save error); it does not end sessions or audit again. Before, it
  answered "revoked already" (`not_found` on the socket), so the save was never retried and the device was live after
  a restart. The socket error text says to revoke again. (b) **Revoke during a session open**: `open_session` checks,
  after the phrase check, that the enrolment is still the live entry of the connection's certificate, with the
  registry read lock held while the session goes in (lock order: registry, then sessions), so a revoke is either seen
  or ends the new session itself. A refused open answers `403 admin_cert_required` and is audited as
  `admin.session_open` (with `unlocked`) then `admin.session_close` `revoked`. A sealed vault that the phrase unlocked
  **stays unlocked**: the same result as an open that ends just before the revoke, and a revoke never locks
  (invariant 10). The session starts at the time of that check, not of the request. The sweep also ends sessions
  whose enrolment is no longer live (revoked, or its certificate expired; reason `revoked`), with the registry lock
  held so an enrolment made meanwhile cannot look dead. (c) **CLI and daemon on the registry file**: `cerberusd admin
  list|revoke` falls back to the file only on `ENOENT` or `ECONNREFUSED` (any other connect error, e.g. a denied
  permission, is a socket error); after a file revoke it tries the socket once more and, if a daemon answers, sends it
  the revoke (it may have read the file before the edit). The daemon reads the registry again right after it binds the
  socket (`AdminState::reload_clients`), so a file revoke from the window between the first read and the bind is in
  memory. Every registry write first reads the file and takes in its revokes (`AdminClients::adopt_revokes`: never
  un-revokes, never adds), and a reload keeps memory revokes the file lacks (and marks them unsaved), so neither side
  undoes the other's revoke; an unreadable file fails the write (fail closed). (d) **Enrolment owner check**:
  `admin_enroll` also wants `ctx.role == owner` from `verify_operator_phrase` (the live session role, which a header MAC
  failure makes `viewer`, DEC-FIX5-4); the stored-role check stays in front so a viewer spends no KDF. (e) **serde_json
  scratch** (not fixed, accepted as AR-21): serde_json decodes a string with an escape in a private scratch `Vec<u8>`
  that is freed unwiped, so a phrase with a quote, backslash or control character and every PEM leave copies in freed
  heap. Not fixable without new crates: the `Read` trait is sealed and the scratch private; `RawValue` needs a feature
  that is off and fails inside the internally tagged `PayloadView`; a second JSON parser adds more risk. I-20, the
  `rpc` and `read_body` docs now state this residual instead of "no copy". Tests: `g12_*` in
  `crates/cerberus-api/tests/admin.rs`; `a_session_is_not_opened_for_an_enrolment_revoked_during_the_phrase_check`
  (`admin/mod.rs`), `the_sweep_ends_sessions_of_an_enrolment_that_is_no_longer_live` (`admin/session.rs`),
  `adopt_revokes_takes_in_revokes_and_never_undoes_one` (`cerberus-admin` `clients.rs`),
  `an_enrolment_needs_the_owner_role_of_the_session_not_of_the_slot` (`cerberusd` `unlock.rs`),
  `revoke_edits_the_file_only_when_no_daemon_can_answer` (`admin.rs`),
  `a_file_revoke_before_the_socket_exists_is_in_memory_after_the_bind` (`daemon.rs`).

- **DEC-RM-23** — RM — Desktop remote backend, as built (plan step 8). (a) The `ipc!` macro has three arms:
  `@remote` (20 commands: in remote mode the label check, a borrowed `Args<'a>` with the IPC argument names written by
  `rpc::to_body`, then `RemoteBackend::forward`), `@both` (`vault_status`, `vault_unlock`, `vault_lock`,
  `vault_panic`, `file_pick_open` and the `remote_*` commands: their `ops` function handles both modes) and the plain
  arm (local only: label check, then `remote_unsupported`; the arguments are never serialized). `ui_activity` is the
  session keep-alive in `DesktopState::ui_activity`; `kdf_benchmark` and `passphrase_*` refuse too (DEC-RM-11).
  `remote::CUSTOM_REMOTE_COMMANDS` plus the `@remote` set equal `REMOTE_COMMANDS` (contract test
  `remote_arm_matches_the_allowlist`). Tests drive the forward through `RemoteBackend::forward` with the same names.
  (b) A session command with no session is `vault_locked` with no network call. An answer `admin_session_required`,
  `vault_locked` or `admin_cert_required` to a session call drops the token (only the session that sent it: each
  session has a serial). Error bodies that are not the admin shape map by status (401 `admin_session_required`, 403
  `forbidden`, 404 `remote_protocol_mismatch` "no admin API", 413 `payload_too_large`, 423 `vault_locked`, 429
  `rate_limited`, else `internal`); transport failures are `remote_unreachable`, `remote_pin_mismatch` or (bad JSON)
  `remote_protocol_mismatch`; a bad bundle is `invalid_bundle`. Answers are read into zeroizing buffers (8 MiB cap,
  64 KiB for `hello`, the session and errors); the call timeout is 30 s, also the stream idle limit (heartbeat 15 s).
  (c) `vault_status` in remote mode: `hello` when the version is unknown or the last contact failed, then
  `rpc/vault_status`; the server's last answer is kept for the view while it cannot be reached. `idle_seconds_left`
  is the smaller of the server idle lock and a local estimate of the session idle limit (from the last session call
  that resets it: all but `request_list_pending`). `os_hook_ok` is the desktop's hook. `RemoteStatusView` also carries
  `operator_id` (the bound operator, so the unlock screen can preselect it), `not_after` and `problem` (the code of
  the last failed contact). A server state `sealed` drops a session the desktop still holds. (d) `vault_lock` with a
  session forwards and drops the token; without one it does nothing (the desktop shows sealed already).
  `vault_panic` forwards. (e) New DTOs in `cerberus-admin` `dto/remote.rs`: `BackendMode`, `RemoteStatusView`,
  `RemoteProfileView` (adds `ca_sha256` and `active`), `RemoteOverview`. (f) Profiles: `prefs.remote = { active,
  profiles: [{ id, label, url, ca_pin, ca_sha256, operator_id, not_after }] }` (`serde(default)`: old files are local
  mode); files in `<app_data_dir>/remote/<enrolment id>/` (`0700`; `cert.pem`, `key.pem`, `ca.pem` `0600`); the folder
  name must parse as an `EnrolmentId`, so a profile ID can never name another folder. Trust is `CaFileAndPin`. A
  profile with a missing file or a key readable by others starts the app in local mode with `active` cleared (logged).
  Import replaces a profile of the same enrolment. (g) Mode switch: `ops::remote_activate` refuses while a local vault
  is unlocked (`conflict`), checks the profile files, closes a remote session and saves the choice; the command then
  runs the quit work (`shutdown`, at most 10 s) and calls `AppHandle::request_restart`. Checked in the source of
  `tauri-plugin-single-instance` 2.5.5: the D-Bus name is a resource that `cleanup_before_exit` closes, and Tauri runs
  that before `process::restart` starts the new process, so the new instance does not find the old one and quit.
  `request_restart`, not `restart`: called off the main thread `restart` parks the worker forever, and
  `prevent_exit` is ignored for the restart code, so the quit handler cannot hold the exit (hence the shutdown first).
  No Linux GUI run was made (no window may open on the person's desktop); the source reading is the check.
  (h) Event pump: `remote::pump::drive` has no Tauri (tests run it): it follows the session, opens one stream per
  session, reconnects after 1 s doubling to 30 s, sends `VaultStateChanged` `unlocked`/`sealed` when the session opens
  or ends, `Locking` from the server, and `PendingCountChanged` from `request_list_pending` after each request event and
  each (re)connect; a server `sealed` event drops the session. The Tauri half emits through the new shared
  `pump::emit_wire` and runs the tray, approval window and held-value side effects of the local pump. (i) OS hooks:
  `os_hooks::OsWatcher` (a watcher that calls any callback) lets remote mode get sleep and screen lock without a core;
  each event closes the session, and the sleep inhibitor waits until the token is dropped. (j) Tray in remote mode:
  "Connected to the server" / "Not connected to the server", and Lock is **Disconnect** (DEC-RM-8); "Lock and revoke
  all" is `vault_panic` on the server. (k) Server fix found by the desktop test: `rpc/vault_lock` and `rpc/vault_panic`
  no longer bind the connection to the session (and unbind a keep-alive connection that an earlier call bound): the
  lock ends the session at once and the idle watcher closed the bound connection before the answer was sent, so the
  desktop saw `remote_unreachable` after a lock that worked. (l) Tests: `desk/tests/remote.rs` runs a real `cerberusd`
  in this process (`cerberusd` is a dev-dependency of the desktop) instead of a hand-made `cerberus-api` server, so the
  bundle is a real enrolment; session idle and absolute expiry stay covered by `api/tests/admin.rs` group 7 with a
  manual clock. The log capture (TRACE, all targets) of that binary holds no phrase, password, `cas_` token or key.
  (`apps/desktop/src-tauri/src/{remote,ops/remote.rs,commands.rs,state.rs,os_hooks.rs,pump.rs,tray.rs,prefs.rs}`,
  `tests/remote.rs`, `tests/contract.rs`, `crates/cerberus-api/src/admin/routes.rs`)

- **DEC-RM-24** — RM — UI of remote mode, as built (plan step 9). (a) The shared pieces live in `ui/src/remote/`
  (`ConnectRemoteDialog`, `ProfileFacts`, `LocalOnlyNotice`, strings and CSS), not in a screen folder, because the
  unlock screen, Settings and the shell all use them. `state/backendMode.ts` has `useRemote`, `useBackendMode` and
  `useRemoteUnsupported(command)`; the last reads the allowlist from `remote_status` (true for every command until the
  list is read, so a local-only action never flashes on). (b) Unlock: the compact card does not change. "Connect to a
  remote server" (local mode) and "Use the local vault" (remote mode) are a quiet ghost link **under** the card, on
  the canvas, last in the tab order (radios → phrase → Unlock → recovery switch → link). In remote mode the card offers
  only the bound operator, has no recovery switch (the recovery key never crosses the network), names the server and
  host, says when the server vault is locked that the phrase unlocks it for its agents too, and its button reads
  Connect when the server vault is open. `conflict` (another operator has the server vault open) gets its own text. A
  server that cannot be used (`remote_unreachable`, `remote_pin_mismatch`, `remote_protocol_mismatch`,
  `admin_cert_required`) replaces the form with a card that names the problem, the profile facts and Try again; there
  is no way to connect past a pin mismatch. (c) The connect dialog imports through `file_pick_open` (extensions
  `cerberus-admin`, `json`), shows Server, Address, `CA pin` and `CA SHA-256` (the labels `cerberusd status` prints),
  bound operator and certificate expiry (warning under 14 days) with a "compare before you connect" warning, then
  Connect (`remote_activate`, the app restarts). A bundle imported in the dialog and then cancelled is forgotten again.
  (d) Settings: a new section **Remote server** (`nav.server`; the existing `remote` section is the RustDesk client
  and keeps its ID). Local mode: Connect to a server (locks the local vault first, as the backend asks), the imported
  servers with Lock and connect / Forget. Remote mode: the section comes first; facts with pin, fingerprint and server
  version, Test connection, Disconnect, Lock the server vault (behind a confirm), Use the local vault, other servers.
  `settings_get` is not called; Security, Network, Remote desktop and Backup show one `LocalOnlyNotice`; Appearance
  (UI scale) and About stay. (e) Shell: a "Remote: <label>" badge in the top bar (info tint, warning tint when the
  server is not reachable) links to Settings. In the collar, Lock is **Disconnect** (and so is Ctrl+L and the palette
  lock), the panic button and dialog name the server vault, the locked state says that a disconnect does not lock the
  server vault. The palette leaves out its local-only actions. (f) Local-only actions in remote mode: hidden with a
  `LocalOnlyNotice` where a whole area is affected (agent changes, keys, certificates and snippets; the policy
  simulator; the audit chain check and export; SSH key generate and import; RustDesk Connect), or simply not shown
  where one button is affected (copy, versions, password generator, CSV import and export, lease revoke all, the
  approval window's Suspend). The dashboard Health panel replaces the chain and TLS rows with one row about the
  server, and hides "Connect an agent". (g) The mock IPC knows remote mode (`installMock({ remote, profiles })`, dev
  URL `&backend=remote` and `&remote_problem=...`); it refuses commands off its copy of the allowlist with
  `remote_unsupported`, as the desktop does. (h) Not done: the plan's Xvfb smoke run of the real app against a local
  `cerberusd`. Starting the Tauri app (even under Xvfb) is out of bounds for this build (no GUI launch, no `tauri
  dev`/`build`); the Rust side is covered by `desk/tests/remote.rs` and `remote_daemon.rs`, the UI by vitest and
  headless Playwright screenshots against the mock. (`apps/desktop/ui/src/{remote,state/backendMode.ts,
  screens/unlock,screens/settings/ServerSection.tsx,shell}`, `src/remote/remote.test.tsx`)

## RD — RustDesk connections (2026-11-21)

- **DEC-RD-1** — New item kind `rustdesk` (Rust `ItemKind::Rustdesk`, wire value `rustdesk`) for a machine reached with
  RustDesk. The RustDesk ID, the ID server, the relay server and the server public key are not secret, so they are
  item metadata in `custom` (`rustdesk_id`, `id_server`, `relay_server`, `server_key`), as the host of an SSH key is;
  only the permanent password is in the payload (`Payload::Rustdesk { password: Option<SecretString> }`, at most
  1024 characters). Why metadata: the share card and **Connect** need no reveal (no use count, no audit read, nothing
  exhausted by `max_uses`), and the connection can be edited while the password is kept (`{ kind: "keep" }`).
  Rules (`items/rustdesk.rs`, checked by `validate_fields` for this kind, so also on a metadata-only update):
  `rustdesk_id` is required, 9 to 20 ASCII digits and nothing else (the brief's choice; RustDesk custom IDs with
  letters are not accepted); servers are `host`, IPv4 or `[IPv6]` with an optional port (`[A-Za-z0-9.-_:[]]`, 1 to
  255); the key is Base64 (standard or URL-safe), 1 to 128. Search: the index adds the `rustdesk_id` of a `rustdesk`
  item to its words (`index::item_words`), so `item_list { q }` and the agent catalog query find it by ID (SSH host
  metadata is still not a search word; not changed here). Agents: no new permission; a `read` grant gives the item
  like any other. The wire `RustdeskSecret` carries all five fields: on create the four plain ones become metadata
  (`convert::create_item_input`, as for SSH), and a read fills them back from the metadata
  (`convert::fill_rustdesk_meta`), so an agent gets the whole connection in one answer. `ItemSummary` on the wire
  still has no `custom` (DEC-INT10-7): an agent with only `find` sees no ID. Default category of agent items:
  `Remote desktop` (also a new built-in category in the UI, icon `monitor`). `cerberus run` maps
  `CERBERUS_RUSTDESK_ID`, `_PASSWORD`, `_ID_SERVER`, `_RELAY_SERVER`, `_KEY`. CSV export writes the password in
  `password` and the connection as JSON in `extra`; CSV import does not make `rustdesk` items (like `ssh_key`,
  `cloud` and `certificate`). Resolve `ALL_KINDS` and the MCP/OpenAPI `ItemKind` enums list the kind. Tests: core
  `an_id_is_nine_to_twenty_digits`, `the_id_is_required_and_servers_and_key_are_checked`,
  `meta_round_trips_through_custom`, `a_rustdesk_item_needs_its_id_in_the_metadata`,
  `the_rustdesk_id_is_a_search_word_of_a_rustdesk_item_only`,
  `a_rustdesk_row_has_the_password_and_the_connection_from_the_metadata`; api
  `a_rustdesk_create_keeps_the_connection_as_metadata_and_the_password_as_payload`,
  `a_rustdesk_read_gets_the_connection_back_from_the_metadata`; client
  `rustdesk_defaults_hold_the_id_and_the_password_only_as_secret`.
- **DEC-RD-2** — Schema version 2: migration `0002_rustdesk_kind.sql` adds `'rustdesk'` to the `items.kind` CHECK.
  SQLite cannot alter a CHECK, so the table is rebuilt (new table, copy every row with its rowid, drop, rename, index
  again). `0001` is not edited (its checksum is recorded in every vault). Foreign keys must be off for the drop
  (with them on, `DROP TABLE` runs an implicit `DELETE` that cascades to `item_versions`, `access_requests` and
  `leases`), and `PRAGMA foreign_keys` is ignored inside a transaction, so the file starts with `-- no-transaction`
  (sqlx then runs it without its own transaction) and opens `BEGIN IMMEDIATE` … `COMMIT` itself, with
  `user_version = 2` inside it. A temporary table with `CHECK (violations = 0)` fed from `pragma_foreign_key_check`
  fails the migration if any reference broke. A failure rolls back everything; the pre-migrate copy
  (`<vault>.pre-migrate-v1`, ADR-0013) is written before. A second run (crash between `COMMIT` and the sqlx
  bookkeeping row) is the same rebuild again and keeps the data. Rejected: `PRAGMA writable_schema` to edit the stored
  SQL in place (documented as dangerous, and it needs a manual `schema_version` bump); renaming the old table first
  (with `legacy_alter_table` off, SQLite rewrites the child foreign keys to the renamed old table).
  `docs/schema.sql` shows the new list. Older builds refuse a version 2 file (`TooNew`), as for any newer schema.
  Tests: store `migration_0002_allows_rustdesk_and_keeps_every_row` (a version 1 file with items and versions:
  every row and rowid kept, `rustdesk` accepted and `bogus` refused, foreign keys on and enforced, the cascade points
  at the new table, the index exists, the pre-migrate copy exists, a second run changes nothing);
  `older_schema_is_migrated_after_a_pre_migrate_copy` now builds on all migrations of this build; the version
  assertions of the store tests read `schema_version()` or expect 2.
- **DEC-RD-3** — Desktop: two new IPC commands (main window only, `names.rs`, capability, bindings; listed as added
  commands in the contract test, not in interfaces.md section 9). `rustdesk_status` (any role): the program chosen in
  Settings and the client that would start; nothing runs. `rustdesk_connect(item, copy_password)` (any role): reads
  the item summary (no reveal), refuses another kind and an ID that is not 9 to 20 digits (checked again here, before
  anything starts), finds the client, and starts it through the new `Shell::launch(program, args)`:
  `std::process::Command` with an argument list, no shell, stdin/stdout/stderr null, a thread that waits for the
  child so it leaves no zombie. Arguments: `--connect <id>`, or for Flatpak `flatpak run --command=rustdesk
  com.rustdesk.RustDesk --connect <id>` (matches `core_main_invoke_new_connection` of RustDesk). The password is
  never an argument (RustDesk accepts `--password`, but argv is readable by other processes of the user and shows in
  process lists): with `copy_password` the item is revealed like `clipboard_copy_secret` (counted,
  audited, the role must allow it) and copied with the 30 s clear. The answer says `copied`, `not_stored`,
  `not_copied` (a failed read or copy does not undo the start; it is logged without the value) or `skipped`; the UI
  shows the toast "Password copied — paste it in RustDesk". The client is started first, so a missing client costs no
  reveal. Lookup order: the chosen program only (no fallback, so the person knows what runs); else `rustdesk` on
  `PATH` (absolute directories only); else standard locations (Linux `/usr/bin`, `/usr/local/bin`,
  `/usr/share/rustdesk`; macOS `/Applications/RustDesk.app` and `~/Applications`; Windows
  `%ProgramFiles%\RustDesk\rustdesk.exe`); else Flatpak when `flatpak` is on `PATH` and the app folder exists in
  `/var/lib/flatpak/app` or `~/.local/share/flatpak/app`. Not found: `unavailable` with an install hint, and the UI
  shows a notice and disables Connect. The chosen program is the desktop preference `rustdesk_path`
  (`desktop-prefs.json`, settings key `rustdesk_path`, operator role like `autostart`); `null` or an empty text goes
  back to the lookup. A value must be an absolute path to a runnable file whose name starts with `rustdesk` (any
  case), so a compromised webview cannot point Connect at an arbitrary program by name. Tests run no program: the
  default `Shell::launch` refuses, the fakes record. Tests: desktop unit `ops::rustdesk::tests::*` (lookup order,
  relative `PATH` entries skipped, Flatpak needs tool and app, a missing chosen program finds nothing, the argument
  list, the path rule) and `tests/rustdesk.rs` (`connect_starts_the_chosen_client_with_the_id_and_copies_the_password`,
  `an_item_without_a_password_says_so_and_other_kinds_are_refused`,
  `a_missing_client_starts_nothing_and_a_bad_program_is_refused`, `the_id_is_required_checked_and_searchable`).
- **DEC-RD-4** — UI. Editor: kind **RustDesk** with its own panel (like SSH): the connection fields are always
  editable (spaces are removed from the ID, a local check asks for 9 to 20 digits), the password is kept until
  **Replace password** and an empty replacement removes it. Item details: a **Connection** card with the ID, servers,
  key, the link `rustdesk://<id>` plus `?key=<encodeURIComponent(key)>` when there is a key (RustDesk reads `key` from
  the query; `+` must be encoded because a query decoder turns it into a space), a **To share** text block with
  **Copy all** (ID, servers, key, link), and **Connect**. The link and the text never hold the password; they are not
  secret, so they use the page clipboard API, while the password row is the usual `SecretField` with
  `clipboard_copy_secret` (30 s clear). A viewer can connect without the password. Settings: section
  **Remote desktop** with the program path (text or the native file dialog, Save, Find automatically) and what the
  lookup found. Mock and fixtures: one `rustdesk` item (`it-laptop`), handlers for both commands, a `missing` mode.
  Tests: vault (share text and link without password, axe, connect and toast, viewer, not installed), editor (create,
  local ID check, edit with keep, remove the password), settings (found, choose, back to automatic, not found,
  viewer), helpers (`rustdesk.test.ts`).
- **DEC-RD-5** — Review fix (High). Migration 0002 made the pre-migrate copy live (AUD-30), and `backup_to`
  creates its file with `create_new`, so an existing `<vault>.pre-migrate-v1` failed every later migration from
  version 1 with `AlreadyExists`: (a) after an upgrade, a restore of any version 1 backup failed at the reopen
  (`ops/restore.rs`), and (b) a migration that failed or was killed after its copy could never run again. Now
  `Store::migrate` writes the copy at `backup::free_name(vault, ".pre-migrate-v", N)`: `<vault>.pre-migrate-vN`, or
  `-2`, `-3` ... added when a vault file of that name (or its `-wal`/`-shm`) exists. An existing copy is never
  replaced (it may be the only copy of an older vault) and never blocks the open. Old copies are kept; nothing
  prunes them. Also, the foreign key check of 0002 now counts only references to `items`
  (`pragma_foreign_key_check WHERE parent = 'items'`, which covers `item_versions`, `access_requests` and `leases`
  and any later table that points at items), so an older broken reference elsewhere (for example a grant of a
  deleted agent) does not block the upgrade. This edits 0002 after commit 95c58d4: a vault that was already opened
  by that build has the old checksum recorded and sqlx refuses it (`VersionMismatch`); nothing was released with
  it. Tests: store `a_failed_migration_can_run_again_and_keeps_the_first_copy` (the first copy is byte for byte
  unchanged, the second is `-v1-2`), `an_older_backup_restored_after_an_upgrade_opens_and_migrates` (through
  `restore_backup`), and `migration_0002_allows_rustdesk_and_keeps_every_row` now also keeps access requests and
  leases (and they still cascade) and passes with an orphan grant. All three fail on the code before the fix.
  `docs/acceptance-report.md` and `guides/security-model.md` (AUD-30) say so.
- **DEC-RD-6** — Review fix (Medium): Connect and the share link use the stored ID server and key. Verified in the
  RustDesk source (read only): `src/client.rs:2921-2948` (`LoginConfigHandler::initialize`) reads a peer
  `<id>@<server>?key=<key>`, keeps `(id, server, key)` as `other_server`, and `src/client.rs:470-489` uses that
  server as the rendezvous server of this one connection instead of the configured one. The relay comes from the
  rendezvous answer (`src/client.rs:1028`, `:1057`), so there is no relay syntax and the relay is not passed.
  `--connect <peer>` is forwarded to a running client as `rustdesk://connect/<peer>` by plain concatenation
  (`src/core_main.rs:766-806`), and the Flutter side maps that link back to `--connect <id>` with `?key=` added from
  the query (`flutter/lib/common.dart:2469-2473`, `:2494-2499`). A key without `@server` stays in the ID
  (`src/client.rs:2949-2955`), so the old link `rustdesk://<id>?key=...` was broken; a key now goes only with a
  server. One builder, `cerberus_core::items::rustdesk_peer(id, id_server, server_key)`: `<id>`, `<id>@<server>` or
  `<id>@<server>?key=<key>`, or `None` when a part is not valid. Connect passes it as the one argument after
  `--connect`; it starts with a digit, so it cannot read as an option. The UI link is `rustdesk://<id>` for the
  public servers and `rustdesk://connect/<id>@<server>?key=<encodeURIComponent(key)>` with an ID server (the form
  RustDesk makes itself). Server addresses are now checked strictly (`is_server_address`): host name labels of
  letters, digits and `-` (no leading or trailing `-`, so no leading `-` at all), IPv4, or `[IPv6]`, with an
  optional port 1..65535; no `@ ? & /`, space, scheme or user part. An IPv6 ID server is stored but not carried (a
  link path cannot hold the brackets, and the running-client path goes through a link): Connect and the link use the
  ID alone and the card asks the person to set that ID server in the client. Residual: RustDesk's link parser turns
  `+` in a query into a space, so when a client is already running, a key with `+` reaches it wrong; the key is
  passed raw because the first-start path reads the argument without decoding. The card says to close RustDesk
  first for such a key; the copied link encodes it and is not affected. Not verified and not used: `/r@server`
  (it forces the relay, `src/ui_interface.rs:1676`) and a `relay` query. Tests: core
  `a_server_is_a_host_or_address_with_an_optional_port`, `the_peer_carries_a_named_server_and_its_key`; desktop
  `a_self_hosted_server_and_its_key_go_into_the_one_peer_argument`,
  `the_key_goes_with_a_named_server_and_an_ipv6_server_stays_out`, `a_server_that_could_read_as_an_option_is_refused_at_save`,
  and the connect test now expects `<id>@rd.example.test`; UI helpers (link forms) and vault card (link with
  server, relay note, `+` note, IPv6 notice). This replaces the Connect arguments of DEC-RD-3 and the link of DEC-RD-4.
