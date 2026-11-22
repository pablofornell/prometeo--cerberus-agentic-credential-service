# Cerberus threat model (T01)

- Status: Accepted (design baseline). T26 (audit) reviews it against the code. TB-10 (remote mode, ADR-0034) is
  **built** (RM steps 1–10, DEC-RM-15 to DEC-RM-24) and tested end to end: `a13_remote_admin_through_cerberusd`
  (`tests/acceptance`), `r1_desktop_state_in_remote_mode_against_cerberusd` and
  `remote_mode_proxies_the_allowlist_and_follows_the_server` (`apps/desktop/src-tauri/tests/`), the admin groups of
  `crates/cerberus-api/tests/admin.rs` and `tests/admin_logging.rs`, and `admin_api_enrolment_approvals_and_revoke`
  (`crates/cerberusd/tests/daemon.rs`).
- Date: 2026-11-16. Updated 2026-11-21 for remote backend mode (ADR-0034): TB-10, AS-11, AS-12, ATK-11, S-9 to S-11,
  T-12, R-6, I-20 to I-22, D-9, E-1 (changed), E-14 to E-16, invariants 8 to 10, AR-19 to AR-21.
- Method: assets → attackers → trust boundaries → STRIDE per boundary. Each threat has a **control** (with the task and
  crate that build it) or an **accepted risk** (AR-n, section 7). Plan section 14 and scenarios A1–A13 are mapped in
  sections 8 and 9.

## 1. System summary

One process (desktop app or `cerberusd`) holds the unlocked vault in memory (ADR-0001, ADR-0002). Agents call the
Agent API over HTTPS (REST `/v1`, MCP `/mcp`) with bearer tokens (ADR-0004, ADR-0016). People manage the vault only
through Tauri IPC (ADR-0003), or, on a `cerberusd` whose owner turned on the opt-in admin API, from an enrolled desktop
app in remote mode over `/admin/v1` (ADR-0034, TB-10). The vault is one SQLite file: items and metadata are encrypted; a few plain columns
support work while locked (ADR-0005, ADR-0033).

```
            (TB-2) TLS 1.3, bearer token                    (TB-4) Tauri IPC
 Agent ─────────────────────────────────► cerberus-api ◄────────────────────── Webview UI ◄── Person
 (LLM, CLI, MCP shim)                     cerberus-mcp        window label + role     (TB-5) display
                                               │
                                         cerberus-core (keys, index, policy)   ◄── OS events (sleep, lock)
                                               │
                                    (TB-3) cerberus-store ──► vault.cerberus (SQLite) ──► backups
                                                                    (TB-6) disk / backup media
 Child process ◄── env vars ── cerberus run (TB-7)        ssh-agent socket (TB-8, T22)

 Remote mode (ADR-0034, only when cerberusd has [admin] enabled = true):
            (TB-10) TLS 1.3, CA pin, enrolled client cert + operator session          (TB-4) Tauri IPC
 cerberusd /admin/v1 ◄──────────────────────────────────────── desktop Rust proxy ◄────────────── Webview UI ◄── Person
 (same listener as TB-2)                                        (no local vault)
```

## 2. Assets

| ID | Asset | Where | Why it matters |
|---|---|---|---|
| AS-1 | Secret payloads (passwords, keys, tokens, sessions, TOTP seeds) | `item_versions.payload_ct`; memory on reveal | Main value |
| AS-2 | Item metadata (titles, descriptions, targets, roles, tags) | `items.meta_ct`; in-memory index | Shows what exists and where (D5) |
| AS-3 | Master phrases and the recovery key | Person; memory during unlock | Open the VMK |
| AS-4 | VMK and derived keys | Memory while unlocked (`LockedBox`) | Open everything |
| AS-5 | Agent tokens | Agent side; hash in `agent_keys` | Agent identity |
| AS-6 | Grants and policy | `grants.body_ct`; index | Decide who gets what |
| AS-7 | Audit log | `audit_events`, export files | Accountability |
| AS-8 | TLS CA key and leaf key | CA sealed in DB; leaf in `tls/leaf-key.der` | Server identity for agents |
| AS-9 | Availability of the vault | Process, DB file, backups | Agents need credentials to work |
| AS-10 | Approval decisions | Approval window, `access_requests`, `leases` | Gate for `prod` and `ask_*` items |
| AS-11 | Admin client bundle and the enrolled client key (ADR-0034) | Bundle file in transit; `<app_data_dir>/remote/<id>/` (key 0600) on the desktop; hash in `admin-clients.json` on the server | First factor of the admin API |
| AS-12 | Admin session tokens (`cas_...`) | Desktop Rust memory; SHA-256 in daemon memory | Live admin power until idle or absolute expiry |

## 3. Attackers

| ID | Attacker | Can | Cannot (assumed) |
|---|---|---|---|
| ATK-1 | **Prompt-injected or buggy agent** with a valid token | Call the Agent API within its scopes; write any reason text; spam requests | Use IPC; read memory |
| ATK-2 | **Thief of a token** (leaked log, repo, transcript) | Same as ATK-1 from a reachable address | Pass mTLS if required; pass IP allowlist |
| ATK-3 | **Other local OS user** (different UID) | Connect to the loopback port; read world-readable files | Read files with mode 0600 of our UID; ptrace our process |
| ATK-4 | **Same-UID malware** or a root user | Read files, process memory (unless blocked by non-dumpable), clipboard, screen | — (strongest local attacker) |
| ATK-5 | **Thief of the DB file or a backup** (offline) | Unlimited offline work; change and put back the file | Know a phrase |
| ATK-6 | **Network attacker** (LAN, when bound to LAN) | See and change traffic; connect | Break TLS 1.3 |
| ATK-7 | **Malicious web page** in the person's browser | Send requests to `127.0.0.1` (CSRF, DNS rebinding) | Read cross-origin responses; know a token |
| ATK-8 | **Malicious or careless operator** (another person with a slot) | Act within their role; keep old file copies | Bypass audit |
| ATK-9 | **Supply-chain attacker** | Ship a bad crate, npm package, or release binary | Change pinned `Cargo.lock` without review |
| ATK-10 | **Shoulder surfer / screen recorder** | See the screen | Use the keyboard |
| ATK-11 | **Thief of an admin bundle** (copied file, backup of the desktop data folder, lost laptop) | Present the enrolled client certificate to the daemon; try passphrases online | Know an operator passphrase; pass the per-enrolment limit and the unlock back-off |

## 4. Trust boundaries

| ID | Boundary | Crossing data |
|---|---|---|
| TB-1 | Person ↔ app (unlock and decisions) | Phrase, recovery key, approvals |
| TB-2 | Agent ↔ HTTPS listener (REST and MCP) | Tokens, queries, reason text, secrets out |
| TB-3 | Process ↔ vault file (store) | Sealed blobs, plain columns |
| TB-4 | Webview ↔ Rust backend (IPC) | Admin commands, revealed secrets to UI |
| TB-5 | App ↔ screen, clipboard, OS (sleep, crash dumps, swap) | Displayed secrets, memory pages |
| TB-6 | Vault file ↔ disk, backup media, other machines | Whole file |
| TB-7 | `cerberus run` ↔ child process | Env vars with secrets |
| TB-8 | ssh-agent socket ↔ local clients (T22) | Sign requests |
| TB-9 | Build and release pipeline ↔ users | Binaries, dependencies |
| TB-10 | Desktop in remote mode ↔ `cerberusd` admin API (ADR-0034; exists only with `[admin] enabled = true`) | Client certificate, operator phrase (session open only), session token, admin DTOs, revealed secrets, live events |
| TB-11 | First client ↔ the setup listener of a `cerberusd` with no vault (DEC-SRV-3; exists only while there is no vault) | Setup token, owner label and passphrase (in), recovery key and admin bundle (out), once, over TLS 1.3 pinned to the setup certificate |

## 5. STRIDE table

Legend: **Ctrl** = control and where it is built (task, crate). **AR** = accepted risk (section 7).

### 5.1 Spoofing

| ID | Threat | TB | Control / accepted risk |
|---|---|---|---|
| S-1 | Stolen or leaked agent token used by ATK-2 | TB-2 | Ctrl: scopes + grants limit use; key expiry (default 90 d); IP allowlist; optional mTLS binding; revoke works at once with no cache; `cvt_` prefix for secret scanners; rate limits; audit of every call; distinct-items alert (T09, T10, T07; `cerberus-core` auth, `cerberus-api`). Residual: AR-7. |
| S-2 | Other local user (ATK-3) uses the loopback port | TB-2 | Ctrl: token needed for every route except health; loopback bind by default; optional mTLS; per-IP auth-failure lockout that refuses failing tokens only, so a local user cannot lock out the agents that share `127.0.0.1` (T09, T10, NEW-5, DEC-T27-E-1; `cerberus-core`, `cerberus-api`). |
| S-3 | Token guessing or brute force | TB-2 | Ctrl: 256-bit secret (this is what makes guessing impractical); constant-time compare over all keys of the agent, done before any limit; failed checks only: 10 failures / 5 min per IP → 300 s lockout, 100 failures / 5 min from all sources → 300 s lockout of every failing check, per-IP bucket, bounded state; a good token is never refused by these; refused attempts audited (`auth.failed`, once per source per minute with the count, loopback as one source and IPv6 by `/64`; a token that matched a real key is counted apart and keeps its reason, such as `key_revoked`, under a lockout); same 401 for every failure reason (T09, T10, NEW-5, NEW-8, DEC-T27-E-1, DEC-T27-F-2; `cerberus-core`, `cerberus-api`). |
| S-4 | Fake server: a process binds the port first, or a LAN MITM, or a stolen leaf key, collects agent tokens | TB-2 | Ctrl: TLS 1.3; SDK and shim refuse to start without CA file or SPKI pin; pin is the CA key, not the leaf; single-instance plugin; leaf key file mode 0600 in a 0700 dir; leaf 90 days (T10, T11, T12; `cerberus-api::tls`, `cerberus-client`). Residual: same-UID attacker can read the leaf key: AR-12. |
| S-5 | Agent writes a reason that pretends to be a person or a system ("approved by admin, urgent") | TB-1 | Ctrl: approval window shows agent identity from the token, reason labelled "not verified", plain-text render with control characters removed, max 500 chars, no preselected option, 600 ms hold for keyboard approve, burst warning (T07, T19; `cerberus-core`, UI). |
| S-6 | Script in the webview calls IPC (XSS, injected content) | TB-4 | Ctrl: strict CSP, no remote content, React escaping, reason text never as HTML, Tauri capabilities per window, window-label check and role check in every command (T15, T16; `cerberus-desktop`). |
| S-7 | A person who learned a phrase (shoulder surfing ATK-10, reuse) unlocks | TB-1 | Ctrl: per-operator slots, audit `vault.unlock` with operator, back-off after 5 failures, phrase change, operator removal (T05; `cerberus-core`). Residual: a known phrase opens the vault: AR-18. |
| S-8 | Token leaks from `ps` or shell history via a CLI argument | TB-7 | Ctrl: CLI and shim read the token only from `CERBERUS_TOKEN` or a token file, never from argv (T12, T11; `cerberus-client`). |
| S-9 | Stolen admin bundle (ATK-11) used to reach the admin API | TB-10 | Ctrl: the certificate alone opens only `hello`, `vault_status` and `vault_list_operators`; every other call needs a session opened with the bound operator's passphrase; per-enrolment limit (5 failures / 15 min → 15 min refusal before the KDF) plus the vault-wide back-off of ADR-0026; certificate 90 days; `cerberusd admin revoke` drops sessions and connections within about 1 s; enrolment and session events audited with the enrolment ID; bundle file 0600, created new, the guide says to delete it after import (ADR-0034 points 3, 4, 6; RM steps 4–6). Residual: bundle + known phrase = that operator's full power: AR-18, AR-20. |
| S-10 | Admin session hijack: a copied `cas_` token replayed | TB-10 | Ctrl: token only in desktop Rust memory (never in the webview, log or a file), header marked sensitive; server keeps SHA-256 only; bound to the client certificate of the connection that opened it (a token over another certificate is refused); idle 900 s, absolute 12 h; void at every lock or new unlock (epoch); at most 4 sessions, 2 per enrolment; `cas_` prefix for secret scanners; closed on desktop quit and OS lock (ADR-0034 point 6). |
| S-11 | Fake admin server collects the operator phrase (DNS spoof, LAN MITM, wrong URL in a bundle) | TB-10 | Ctrl: the desktop trusts only the CA pin from the bundle (SPKI pin, survives leaf renewal), TLS 1.3 only; the person compares URL, pin and fingerprint with `cerberusd status` at import; the phrase is sent only after the pinned handshake and a matching `admin_protocol` in `hello` (ADR-0034 point 7.10; `cerberus-client` `PinnedHttps`). Residual: a stolen server leaf key: AR-12. |

### 5.2 Tampering

| ID | Threat | TB | Control / accepted risk |
|---|---|---|---|
| T-1 | ATK-5 changes ciphertext, or moves a blob to another row, column, version or vault | TB-3, TB-6 | Ctrl: XChaCha20-Poly1305 with AAD = purpose + vault ID + record ID + version; open failure → `vault_corrupt` + audit (T03, T04; `cerberus-crypto`, `cerberus-store`). |
| T-2 | ATK-5 changes KDF parameters or slot data in the header (downgrade, DoS) | TB-6 | Ctrl: parameter ranges checked before the KDF; `header_mac` checked after unlock with a red alert; a lower cost cannot open the VMK because the wrap used the real KEK (T03, T05; `cerberus-crypto`, `cerberus-core`). |
| T-3 | ATK-5 or ATK-8 edits, deletes or reorders audit rows, or cuts the tail | TB-3 | Ctrl: hash chain + HMAC per row + MACed head with anchor; SQLite triggers block UPDATE and unguarded DELETE; verify reports the exact `seq` (A9) (T08; `cerberus-core::audit`, `cerberus-store`). |
| T-4 | ATK-5 puts back an older copy of the whole file (old grants, a revoked token works again) | TB-6 | AR-1. Partial ctrl: the restored chain does not contain later events, and backups are audited (T08, ADR-0031). |
| T-5 | ATK-5 forges plain security columns: inserts a token hash, adds scopes, clears `revoked_at`, marks a request approved, extends a lease | TB-3 | Ctrl: row MAC with `row_mac_key` on `agents`, `agent_keys`, `leases`, `access_requests`; checked at unlock and before each decision; encrypted copies of `expires_at` for items and grants, effective = earlier value (ADR-0033; T04, T05, T07, T09). Residual: row rollback to an older genuine state: AR-1. |
| T-6 | Host clock moved back to extend TTLs, leases or key expiry | TB-5 | AR-11. |
| T-7 | Webview sends forged IPC arguments (other operator ID, `allow_prod_auto`, file paths) | TB-4 | Ctrl: backend ignores client-side role data; role from the unlocked session; owner check for `allow_prod_auto`; paths from native dialogs, canonicalized, no symlink follow for writes (T15; `cerberus-desktop`). |
| T-8 | ATK-6 changes traffic | TB-2 | Ctrl: TLS 1.3 only, CA pin, mTLS required for non-loopback binds (T10; `cerberus-api`). |
| T-9 | Agent poisons the vault: stores a fake "admin" item that another agent later uses | TB-2 | Ctrl: `write` only through grants on the proposed metadata; `created_by` shown in candidates and as a UI badge; agent-created items are audited with the agent ID (T06, T07, T18). Residual: AR-15. |
| T-10 | Changed CA certificate (plain) in the DB to trick leaf renewal | TB-3 | Ctrl: CA public key must match the sealed CA key at unlock (ADR-0033; T10). |
| T-11 | Bad dependency or release binary (ATK-9) | TB-9 | Ctrl: `Cargo.lock` and `package-lock` committed; `cargo deny`, `cargo audit`, npm audit in CI; SBOM (`cargo-cyclonedx`); signed release artifacts and checksums (T02, T29). Residual: AR-16. |
| T-12 | Same-UID attacker on the server adds a certificate hash to `admin-clients.json` | TB-10 | AR-19. Ctrl: file mode 0600 checked at start, every enrolment and revoke audited in the chain, a session still needs an operator passphrase. |

### 5.3 Repudiation

| ID | Threat | TB | Control / accepted risk |
|---|---|---|---|
| R-1 | Agent denies it read a secret | TB-2 | Ctrl: `item.reveal` / `item.totp` / `ssh.prepare` audit event with agent ID, key ID, request ID, lease ID; a secret read fails if the audit write fails (T08, T10). |
| R-2 | Operator denies an approval or a change | TB-4 | Ctrl: per-operator slots (not one shared admin, unlike Hermes); every IPC action audited with operator ID (T05, T08, T15). |
| R-3 | Events while locked cannot be authenticated | TB-3 | Ctrl: `audit_pending` folded into the chain at unlock with `recorded_while_locked`; cap and overflow counter (T08; ADR-0025). Residual: AR-6. |
| R-4 | Audit history lost to retention | TB-3 | Ctrl: retention setting (default 365 d), `audit.prune` event, anchor in the MACed head, export before prune is offered (T08). |
| R-5 | Request IDs forged to confuse audit | TB-2 | Ctrl: server makes every request ID; incoming `X-Request-Id` ignored (T10; ADR-0015). |
| R-6 | Remote operator denies an admin action | TB-10 | Ctrl: every admin call runs the same core function as the local IPC command and is audited with actor `operator:<id>`; `admin.session_open` / `admin.session_close` record the enrolment ID, so each action maps to a device and a phrase (ADR-0034 point 6.7). |

### 5.4 Information disclosure

| ID | Threat | TB | Control / accepted risk |
|---|---|---|---|
| I-1 | ATK-5 guesses the phrase offline from a stolen file or backup | TB-6 | Ctrl: Argon2id (256 MiB, tuned to about 0.7 s); minimum length 12 and zxcvbn score ≥ 3, no override; Diceware generator (7 words); recovery key 256 bits (T03, T17; `cerberus-crypto`). |
| I-2 | ATK-5 reads secrets, titles or descriptions from the file (A7) | TB-6 | Ctrl: D5 encryption of content and metadata; A7 byte scan test (T04, T24; `cerberus-store`). |
| I-3 | ATK-5 reads plain columns: item count, kinds, expiry and timestamps, agent status, token hashes/hints/scopes/IP lists, lease links agent→item, operator labels and roles, audit row count and times, `audit_pending` rows | TB-6 | AR-2. |
| I-4 | Secret in log files | TB-5 | Ctrl: secret types without `Display`/`Serialize` and with redacted `Debug`; trace layer logs no headers or bodies; `rmcp` capped at `warn`; canary test over logs, DB, exports, CLI output (T03, T10, T24; ADR-0032). |
| I-5 | Secret in agent transcripts or agent logs | TB-2 | Ctrl: `handling` field and MCP handling line; `cerberus run` env injection with output masking; SSH signing socket; TOTP seed never leaves (T10, T11, T12, T22). Residual: AR-3, AR-4. |
| I-6 | Prompt-injected agent (ATK-1) collects many secrets | TB-2 | Ctrl: grants by agent identity; `prod` needs approval; rate limits (60 reads/min); distinct-items alert (30/h); leases visible; panic button; audit (T07, T09, T10, T20). Residual: AR-5. |
| I-7 | Agent learns which items exist (enumeration through 403/404 or hints) | TB-2 | Ctrl: invisible = `404 not_found` like unknown; `no_match` hints only from visible items; candidates only visible items (T06, T07). |
| I-8 | Keys in swap, hibernation file or core dump | TB-5 | Ctrl: `mlock` (`LockedBox`), not dumpable, `RLIMIT_CORE=0`, `panic = "abort"` with wipe, lock on OS sleep (keys erased before suspend; Linux only, with a logind delay inhibitor; on macOS and Windows no hook exists, an accepted risk with the idle and hard lock as the control, ADR-0026 amendment, DEC-T27-C-9) (T03, T05; `cerberus-crypto::memlock`). Residual: AR-8. |
| I-9 | Clipboard history keeps a copied secret | TB-5 | Ctrl: copy only on explicit action; clear after 30 s if unchanged (T15, T18). Residual: AR-14. |
| I-10 | Screen capture or shoulder surfing (ATK-10) | TB-5 | Ctrl: masked by default, hold to reveal, auto-hide 15 s, content protection on macOS/Windows (T18, T21). |
| I-11 | Error messages leak titles, reasons or secrets | TB-2 | Ctrl: fixed messages per code; internal causes only in the log (T10; ADR-0021). |
| I-12 | Plain HTTP or TLS 1.2 sniffing/downgrade (A8) | TB-2 | Ctrl: TLS 1.3 only; no HTTP listener (T10; `cerberus-api::tls`). |
| I-13 | Web page (ATK-7) calls the API (CSRF, DNS rebinding) | TB-2 | Ctrl: bearer token (no cookies); `Host` must be a SAN name; requests with `Origin` or cross-site `Sec-Fetch-Site` refused; no CORS headers (T10). |
| I-14 | Timing leak in token check | TB-2 | Ctrl: `subtle` constant-time compare, no early exit (T09). |
| I-15 | Backup, CSV export or audit export copied in plain form | TB-6 | Ctrl: backups stay encrypted; CSV export owner-only with a plain-text warning; audit export warns about metadata; all export files mode 0600 (T23, T08, ADR-0031). |
| I-16 | Revealed secret stays in webview memory | TB-4 | Ctrl: secrets only in component state, never in caches or stores; cleared on hide (T16, T18). Residual: JS strings cannot be zeroized: AR-8. |
| I-17 | Approval objects or SSE events carry secrets | TB-2 | Ctrl: secrets only on secret routes; request and lease views hold IDs and metadata only (T07, T10). |
| I-18 | Child process of `cerberus run` gets the agent token | TB-7 | Ctrl: `CERBERUS_TOKEN` and `CERBERUS_TOKEN_FILE` removed from the child env unless `--pass-token`; `cerberus run` is not dumpable on Linux, so the child cannot read the token from `/proc/<ppid>/environ` (T12, AUD-19). A token file stays readable by the same user (AR-3). |
| I-19 | Item titles leak through IPC events or tray badge | TB-5 | Ctrl: events carry IDs; the tray badge shows a count only (T15, T19). |
| I-20 | Operator passphrase crosses the network at session open | TB-10 | Ctrl: sent only in the body of `POST /admin/v1/session`, never in a URL or header; only after a pinned TLS 1.3 handshake with an enrolled client certificate; read into a zeroizing buffer on both sides (as the unlock socket, AUD-20); request bodies are never logged (I-4, ADR-0032); the recovery key is never accepted over the network (ADR-0034 point 6.3). Residual: a compromised server process sees the phrase, as it sees the VMK: AR-8. Residual: the JSON parse is not wiped for a phrase with an escape (a quote, a backslash or a control character): serde_json decodes it in an internal scratch buffer that is freed without a wipe (AR-21, DEC-RM-22). |
| I-21 | Live events (SSE) leak data to a listener | TB-10 | Ctrl: `/admin/v1/events` needs certificate + session; events hold IDs and counts only (same structs as I-19); `Cache-Control: no-store`; the stream ends with the session, at lock and at revoke; at most 2 streams per session (ADR-0034 point 6.8). |
| I-22 | Revealed secrets and item metadata travel to a remote desktop | TB-10 | Ctrl: TLS 1.3 with CA pin and client certificate; same reveal audit (`item.reveal`) and role checks as local; the desktop keeps no copy outside component state (I-16); clipboard copy is not offered in remote mode in the MVP. |

### 5.5 Denial of service

| ID | Threat | TB | Control / accepted risk |
|---|---|---|---|
| D-1 | Request flood or slow clients | TB-2 | Ctrl: per-agent limits, per-IP limits on failed token checks only; body limits (16 KiB / 1 MiB); handshake, first-request, unauthenticated-lifetime (30 s), idle (counts authenticated requests, not bytes or PINGs), send-stall (30 s with no pull of a response, e.g. h2 window 0), header and body timeouts; max 256 concurrent connections, of which at most 64 unauthenticated, oldest unauthenticated evicted first when full, authenticated never evicted; at most 32 authenticated connections per agent; a connection is closed within about 1 s when its key is revoked or expires (T10, AUD-4, NEW-1, NEW-5, NEW-6, DEC-T27-D2-1/2, DEC-T27-E-1/2; ADR-0030, ADR-0023). |
| D-2 | Approval spam to tire the person | TB-1 | Ctrl: max 5 pending per agent; dedupe; 10 requests / 10 min; deny cool-down 600 s; burst grouping and warning (T07, T19). |
| D-3 | Tampered KDF parameters cause huge memory use | TB-6 | Ctrl: range checks before any KDF (T03). |
| D-4 | Flood of locked-state events fills the disk | TB-3 | Ctrl: `audit_pending` cap 10,000 + overflow counter; per-agent limits and the limits on failed token checks apply while locked; `auth.failed` is written at most once per source and class per minute, and at most 10 rows per class per minute from all sources together, with the counts of the rest (T08, T10, DEC-T27-E-1, DEC-T27-F-2). |
| D-5 | DB file deleted or corrupted | TB-6 | Ctrl: backup and restore; pre-migrate and pre-restore copies (T04, ADR-0031). A restore closes the old store before any file moves, a failed swap puts the old files back, and a failed restore never makes a new empty vault in place of the old one (NEW-10, DEC-T27-F-1). A restore over a symbolic link is refused, and a folder read error at start makes no vault (NEW-11). A restore that went through leaves the old file as `.replaced-*`, and a vault put back loses its agent keys and leases at its next unlock (NEW-12, DEC-T27-H-1, DEC-T27-H-2). Residual: AR-17. |
| D-6 | Expensive queries (large catalog pages, long hints) | TB-2 | Ctrl: `limit` ≤ 500, input length limits, candidates ≤ 20 (T06, T10). |
| D-7 | Someone at the keyboard triggers unlock back-off | TB-1 | Ctrl: max delay 900 s; recovery key typing errors do not count (T05). Residual: needs physical access; part of AR-18. |
| D-8 | Plain-column change makes items expire early (sweeper) | TB-3 | Ctrl: only a loss of availability, never a gain (ADR-0033). Residual: AR-17. |
| D-9 | ATK-11 drives the shared unlock back-off with wrong phrases, so the owner cannot unlock | TB-10 | Ctrl: per-enrolment limit before the KDF (5 failures / 15 min); revoke the enrolment; the back-off is capped at 900 s (ADR-0026); an unlocked vault keeps serving agents (back-off blocks new unlocks and session opens only) (ADR-0034 point 6.3). |

### 5.6 Elevation of privilege

| ID | Threat | TB | Control / accepted risk |
|---|---|---|---|
| E-1 | Agent reaches admin functions | TB-2, TB-10 | Ctrl: the Agent API router has no admin route, and the route-list test keeps it equal to the OpenAPI file, which has no `/admin` path (test). The desktop's own vault has no admin route in any mode. On `cerberusd`, `/admin` routes exist only with `[admin] enabled = true` (default off: `404 route_not_found`, ADR-0034). When they exist: agent tokens (`cvt_`) are not accepted there; an agent's CA-signed client certificate is refused because only enrolled certificate hashes pass (E-15); every call also needs an operator session opened with a passphrase; the admin route list is fixed by its own test (T10, T13; RM step 5). Changed by ADR-0034; before, "no admin route exists anywhere". |
| E-2 | Same-UID malware or root (ATK-4) reads keys from process memory while unlocked | TB-5 | Ctrl: not dumpable (blocks same-UID ptrace on Linux), `PT_DENY_ATTACH` on macOS, `mlock`, idle lock 30 min, hard lock 12 h (desktop; off by default on `cerberusd`, DEC-SRV-1), lock on OS lock (Linux only, see I-8) (T03, T05). Residual: AR-8 (plan 14: "partly accepted"). |
| E-3 | Viewer or operator extracts the VMK and reads beyond their role | TB-4 | AR-9. Ctrl for normal use: role checks in every IPC command (T15). |
| E-4 | Removed operator keeps an old file copy and the VMK from it | TB-6 | AR-10. |
| E-5 | Reason or purpose text changes policy (prompt injection) | TB-2 | Ctrl: policy reads only identity, grants and metadata; reason checked for presence only (T07; ADR-0017). |
| E-6 | MCP tool has more power than its REST route | TB-2 | Ctrl: tools call the same `AgentApi` functions; same scopes; mapping test (T11; `cerberus-mcp`). |
| E-7 | Agent with `write` creates an item outside its area (for example a `prod` workspace) | TB-2 | Ctrl: `write` evaluated on the proposed metadata (T07). |
| E-8 | Agent deletes or replaces items of others | TB-2 | Ctrl: delete only when `created_by = agent:<self>` (T06, T10). |
| E-9 | Memory-safety bug in our code | TB-2, TB-4 | Ctrl: `forbid(unsafe_code)` except `memlock`; fuzzing of parsers, token parse, envelope open, JSON bodies (T25). |
| E-10 | LAN bind without mTLS | TB-2 | Ctrl: bind change refused unless every active key requires mTLS (T10, T15). |
| E-11 | Other local user uses the ssh-agent socket | TB-8 | Ctrl: socket 0600 in a 0700 runtime dir; lifetime bound to lease and lock; one key per socket (T22). Residual: same UID: AR-8. |
| E-12 | Approval window commands called from the main window by injected script, or the other way | TB-4 | Ctrl: per-command window allow list; approve/deny need role operator (T15). |
| E-13 | Agent skips approval by reusing another agent's lease | TB-2 | Ctrl: leases and requests are bound to the agent ID; other agent's IDs give 404; row MAC (T07; ADR-0033). |
| E-14 | Admin API left on, or turned on by mistake | TB-10 | Ctrl: since DEC-SRV-3 the admin API is **on by default** (`[admin] enabled`; `enabled = false` or `CERBERUSD_ADMIN_ENABLED=false` turns it off). It exposes nothing by itself: every admin route needs the client certificate of an enrolled desktop (hash in `admin-clients.json`, not revoked or expired) **and** a session opened with an operator passphrase. An enrolment is made either by `cerberusd admin enroll` (a terminal on the server, the daemon user and an owner phrase) or, once, by the first-time setup of a server with no vault (E-17, which exists only while there is no vault). Each start with it on logs a `warn` line and writes `admin.api_start` to the audit chain; `cerberusd status` shows it and the enrolment count (ADR-0034 points 2 and 9). A config without the `enabled` key changed behaviour when the default changed (admin routes, client-certificate request, approvals on): the daemon guide says so. |
| E-15 | Agent uses its own CA-signed mTLS certificate, or a `cvt_` token, on `/admin` | TB-10 | Ctrl: the device check accepts only certificate hashes in `admin-clients.json` that are not revoked or expired, on every request; admin certificates have their own CN form; `cvt_` tokens never parse as `cas_` sessions and the reverse; tests for both (ADR-0034 point 4). |
| E-16 | A remote caller runs a command beyond the allowlist, or more power than the same local command | TB-10 | Ctrl: one shared allowlist constant (25 commands); any other name gives `404 remote_unsupported`; every allowlisted command calls the same handler and core function as the local IPC command, so core role checks apply unchanged; unknown JSON fields refused; recovery-key unlock, operator and phrase management, backup, restore, TLS, network and CSV are not remote (ADR-0034 point 5). |
| E-17 | A network attacker uses the first-time setup listener of a `cerberusd` that has no vault: creates the vault with a passphrase of its own, guesses the token, floods the listener, or impersonates it | TB-11 | Ctrl (ADR-0034 point 9, DEC-SRV-3): the listener exists only while there is no `vault.cerberus` and the admin API is on, on the configured addresses (also a non-loopback `bind`: it cannot ask for client certificates, because the vault CA does not exist yet, so on a LAN the token and the pin are the only protection). Its certificate is self-signed, not a CA, made in memory at each start, never stored. The one-time setup code (256-bit random token, URL, SPKI pin) is in `<data_dir>/setup-code` (0600) and is shown by `cerberusd setup-code`; the log has the path and the pin, never the token. The client pins the key of the setup certificate (TLS 1.3, no system roots), so the passphrase goes only to the holder of the code. The token is compared in constant time; wrong tokens make their peer wait 2, 4, 8 ... up to 300 s after 5 free tries (peer = IPv4 address or IPv6 /64; the table keeps the 1024 most recent, so a flood from many addresses can slow the owner, not lock the owner out); one request per connection, 4 connections per peer, 16 in all, 40 s for a connection that starts no setup, 10 s for the body; only `GET /v1/health` and `POST /v1/setup` answer, the rest is `503`; one setup at a time and only one that works; the listener closes when the vault exists. A failed or abandoned setup removes its files. Residual: whoever has the code (a reader of the file or of a terminal, a shoulder surfer) can create the vault until the first client does; a new start makes a new code; the code is a secret until the vault exists (AR-22). |

## 6. Security invariants (tests must prove these)

1. No REST route except `/v1/health` returns data while the vault is not `Unlocked` (A5).
2. No secret value, phrase, recovery key or token appears in logs, DB plain bytes, audit bodies or CLI output (canary test, A7, A12).
3. Policy output does not change when only the reason or purpose text changes (property test, T07).
4. A changed byte in any audit row gives `ChainBroken` at that `seq` (A9).
5. A revoked key fails on the next call (A10).
6. A forged plain row (insert or change without `row_mac_key`) never grants access (T-5 test, T09/T07).
7. TLS 1.2 and plain HTTP fail (A8).
8. With `[admin] enabled = false` every `/admin` path gives `404 route_not_found`; the agent OpenAPI has no `/admin` path (ADR-0034).
9. No admin call other than `hello`, `vault_status` and `vault_list_operators` succeeds without an enrolled, unrevoked client certificate **and** a live session opened with a passphrase; an agent certificate or token never passes (ADR-0034).
10. Closing or losing an admin session never locks the server vault, and no session survives a lock, a new unlock or a revoke (ADR-0034).

## 7. Accepted risks

| ID | Risk | Why accepted | Owner of the follow-up |
|---|---|---|---|
| AR-1 | Rollback of the whole file, or of single rows, to an older genuine state (T-4, T-5) | Needs a trusted monotonic counter that is not portable in v1. The attacker needs write access to the file. | Future ADR (TPM / OS keystore) |
| AR-2 | Plain metadata leak (I-3): counts, kinds, times, agent and key plain fields, lease links, operator labels | Needed for locked-state work (sweeper, 401/423) and slot selection. No names, titles or secrets leak. | — |
| AR-3 | Child process of `cerberus run` writes or sends the secret | The child must get the value to work. Output masking covers stdout/stderr only. | Docs (T28) |
| AR-4 | An agent prints a secret it got by right, against the `handling` flag | Cerberus cannot control the agent host. Env injection and SSH socket are the safer paths. | Docs (T28) |
| AR-5 | A prompt-injected agent exfiltrates within its grants and under the limits | Grants are the owner's choice. Limits, alerts and audit make it slow and visible. | Owner (narrow grants) |
| AR-6 | `audit_pending` rows are not authenticated while they wait (fake or removed events) | No `audit_key` while locked by design (D8). Rows are marked `recorded_while_locked`. | — |
| AR-7 | A stolen token works until it expires or is revoked | Normal bearer-token property. Scopes, IP allowlist, mTLS and short lifetimes reduce it. | Owner |
| AR-8 | Same-UID malware, root or kernel code reads memory while unlocked; hibernation images; JS strings in the webview; same-UID access to sockets | No user-space program can stop this. Plan 14 says "partly accepted". Short unlock time limits it. | Docs (T28) |
| AR-9 | Roles are not a crypto boundary (viewer could extract the VMK with memory access). An operator who shares the OS account with the vault file is not limited by the role: with the file and the own phrase, the VMK can be unwrapped offline, the header signed again, or every item read (AUD-26). | All slots wrap one VMK (ADR-0009). Roles limit people without file access. A header MAC failure makes the session `viewer` (DEC-FIX5-4). Binding the role in the slot wrap AAD would add nothing (DEC-T27-A1-8). Per-role key trees are a future option. | Future ADR, docs (T28) |
| AR-10 | Operator removal does not rotate the VMK | Full rekey needs every slot's KEK. | Future ADR |
| AR-11 | Host clock manipulation changes TTL behaviour | The person who controls the clock controls the host. | — |
| AR-12 | Same-UID attacker reads the TLS leaf key and impersonates the server | That attacker can already read memory and files (AR-8). Leaf lives 90 days. | — |
| AR-13 | Lost phrase and lost recovery key = data cannot be restored (plan 14) | No backdoor by design. Shown at creation and in docs. | UI (T17), docs (T28) |
| AR-14 | Clipboard managers keep history | OS feature outside our control. The UI warns once. | UI (T18) |
| AR-15 | Agent-created items can mislead other agents inside the same grants. Two effects are named (AUD-23): the title, description and tags of an agent item reach the model context of other agents (a prompt-injection channel), and hint words in them could make an agent item win a resolve over an operator item. | `write` is a grant the owner gives; `created_by` is visible; MCP marks agent-written fields as untrusted (DEC-T27-B-7); resolve prefers operator items on an equal score and never lets hint points make an agent item the confident winner over an operator item (DEC-T27-A2-5); agent text loses bidi and zero-width characters (DEC-T27-A2-9); an agent item cannot set loader or interpreter variables (DEC-T27-A2-1). | Owner |
| AR-16 | Unsafe code and bugs in Tauri, the OS webview, SQLite and other dependencies | Not our code. Audit, deny, updates and SBOM reduce it. | Release (T29) |
| AR-17 | Loss of availability by file deletion or early expiry through plain columns | Availability is lower priority than secrecy. Backups exist. | Person |
| AR-18 | A person with a known phrase, or physical access, can unlock or cause back-off | A credential is a credential. Audit records it. | Person |
| AR-19 | `admin-clients.json` is plain and has no MAC: a same-UID attacker on the server can add an enrolment (T-12) | It must be readable while sealed for a remote unlock. That attacker can already read daemon memory and the vault file (AR-8). A session still needs a passphrase; enrolments are audited. A sealed mirror checked at unlock is a follow-up. | Future change (RM follow-up) |
| AR-20 | The desktop keeps the enrolled client key as a 0600 file, not in an OS keychain | Same-UID malware on the desktop can copy it (AR-8), but still needs an operator passphrase (S-9). OS keychain storage is a follow-up. | Future change (RM follow-up) |
| AR-21 | serde_json decodes every JSON string that has an escape (`\"`, `\\`, `\n`, `\uXXXX`, ...) in its own scratch `Vec<u8>`, which grows by reallocation and is freed without a wipe. A phrase with a quote, a backslash or a control character, and every PEM (its line breaks are escaped), so leaves unwiped copies in freed heap memory of the process that parsed it: `cerberusd` for admin request bodies (I-20) and the unlock socket (AUD-20), the desktop for IPC arguments and admin answers. A string without an escape is read in place from the zeroizing body. | serde_json's reader trait is sealed and the scratch is private, so no caller-side buffer can replace it; `RawValue` cannot be used inside the internally tagged payload type that carries most secrets; a fork or a second JSON parser would add more risk than it removes (DEC-RM-22). Freed heap is readable only by the attacker of AR-8, who can read live memory anyway; on Linux both processes are not dumpable. | — |
| AR-22 | The setup code is a bearer secret until the vault exists, and a kill or a lost connection near the end of a first-time setup can leave a new, empty vault whose client has no recovery key | The code is the only proof of who may make the vault on a server that has none; it is in a 0600 file under a 0700 folder and in no log. The window is milliseconds, the vault is empty, and the owner can keep it without a recovery key or remove it and set up again (daemon guide, section 2) | Owner |

## 8. Plan section 14 mapping

| Plan risk | Threats | Controls (task) | Accepted risk |
|---|---|---|---|
| Prompt-injected agent asks for many secrets | I-6, E-5, S-5, D-2 | Grants by identity, rate limits, distinct-items alert, `prod` approval, audit, panic button (T07, T09, T10, T19, T20) | AR-5 |
| Stolen DB file | I-1, I-2, I-3, T-1, T-2, T-5 | Encrypted items and metadata, Argon2id, AAD binding, row MACs (T03, T04, T05) | AR-1, AR-2 |
| Weak master phrase | I-1, S-7 | Strength meter, Diceware, minimum score 3 and 12 chars (T03, T17) | AR-18 |
| Local malware reads memory | E-2, I-8, I-16 | `mlock`, no core dump, not dumpable, short unlock, auto-lock, lock on sleep (T03, T05) | AR-8 (partly accepted, documented) |
| Another local user uses the port | S-2, S-3 | Token, loopback bind, optional mTLS, lockout of failing tokens only (T09, T10, DEC-T27-E-1) | — |
| Secret in agent logs | I-5, I-18 | `handling` flag, `cerberus run` with masking, SSH signing socket (T10, T12, T22) | AR-3, AR-4 |
| Lost phrase and recovery key | — (availability) | Clear warning at creation and in docs (T17, T28) | AR-13 |
| Crate or API changes | T-11 | Version checks per task, `Cargo.lock`, deny/audit (T02, T29; ADR-0011) | AR-16 |

## 9. Acceptance scenarios A1–A13 mapping

| Scenario | Threats covered | Controls under test |
|---|---|---|
| A1 Create, lock, unlock, wrong phrase, recovery key | S-7, I-1, D-7 | Key slots, back-off, recovery slot (T03, T05) |
| A2 Resolve shop-frontend / staging / admin | I-7, E-5, R-1 | Resolve scoring, policy, audit `api.resolve` + `item.reveal` (T06, T07, T08) |
| A3 Session token with 3600 s TTL disappears | I-3 (expiry), D-8 | TTL, effective expiry, sweeper, manual clock (T04, T06; ADR-0022) |
| A4 SSH key for build-01 | I-5, E-11 | Resolve by target; T22 signing socket |
| A5 Locked vault → 423, no data | Invariant 1 | Lock check order (T10; ADR-0008) |
| A6 `prod` item → approval; deny 403, approve lease | S-5, D-2, E-13 | Approval flow, leases (T07, T19) |
| A7 DB file as text shows nothing | I-2 | D5 encryption (T04, T24) |
| A8 TLS 1.2 and plain HTTP fail | I-12, T-8 | TLS 1.3 only (T10) |
| A9 Changed audit row → broken position | T-3 | Hash chain verify (T08) |
| A10 Revoked key → 401 at once | S-1 | AuthTable without cache (T09) |
| A11 Agent without `write` stores → 403 | E-7 | Scope and grant checks (T07, T10) |
| A12 `cerberus run` child sees var, output does not | I-5, I-18, S-8 | Env injection, masking (T12) |
| A13 Remote admin through `cerberusd` | S-9, S-10, E-1, E-14, E-15, E-16, I-20, I-21, invariants 8–10 | Admin off gives 404; no certificate and an agent certificate give 403; no session 401, wrong phrase 401; items and their audit as `operator:<id>`; an agent request seen on the event stream through `PinnedHttps` and approved over the admin channel; closing a session leaves agents working; revoke gives 403 at once; a remote `vault_lock` gives agents 423 (ADR-0034, `a13_remote_admin_through_cerberusd`) |

## 10. Review triggers

Update this model when: a new route, tool or IPC command is added; a plain column is added; a new bind mode or
transport is added; a crate in the crypto path changes major version; T26 reports a finding.
