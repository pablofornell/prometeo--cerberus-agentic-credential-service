# Cerberus security audit (T26)

- Date: 2026-11-17
- Auditor role: Auditor (did not write the code under review)
- Code state: working tree on `main` (commit `f729a30` plus untracked work), as it was on 2026-11-17
- Input documents: `docs/PLAN.md` (sections 4, 11, 13), `docs/security/threat-model.md`, `docs/adr/*`,
  `docs/interfaces.md`, `docs/decisions.md`

## 1. Summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 5 | AUD-1 to AUD-5 |
| Low | 20 | AUD-6 to AUD-25 |
| Info | 7 | AUD-26 to AUD-32 |

PLAN section 13 says: "The audit has no open medium or higher finding". At the time of T26 that condition was not met.
**Update after T27:** sections 6 to 9 below re-check every fix; AUD-1 to AUD-5 and all later Medium findings are
closed, and no finding at Medium or higher is open. The table above is the original T26 count.

The cryptographic core is sound: the envelope, the key tree, key slots, the recovery key, the token format and the
memory lock code have no finding above Info. The medium findings are in these places:

- the audit chain writer (a tail cut is signed again and then reads as "chain OK"),
- one unauthenticated plain column that policy reads (`items.kind`),
- an attacker-chosen KDF cost that runs while the vault write guard is held (the vault cannot lock),
- the HTTPS listener (an idle connection with no request never times out),
- `cerberus run` (an item can set any environment variable, such as `LD_PRELOAD`, in the child).

## 2. Scope and method

**Scope:** all crates and apps. These are `cerberus-crypto`, `cerberus-store`, `cerberus-core`, `cerberus-api`,
`cerberus-mcp` (server and stdio shim), `cerberus-client` (SDK and CLI), `cerberusd`, `cerberus-ssh-agent`,
`apps/desktop/src-tauri`, `apps/desktop/ui`, `deny.toml`, the `justfile` audit ignores and `packaging/systemd`.

**Method:**

- I read the design documents and judged each DEC entry that is a security trade-off. I did not accept a trade-off
  only because a DEC entry records it.
- I traced secrets from input to memory, disk, output and logs. I checked each authorization point: the token check,
  scopes, policy evaluation, leases, approvals, IPC window labels and session roles.
- I tried to break invariants with concrete inputs. Where a proof was cheap, I ran it in a scratch crate outside the
  repository (section 5).
- Three read-only reviewer helpers covered the desktop and UI, the client, daemon and ssh-agent, and the store, the
  audit chain and the items. I checked their medium and higher claims in the code before I put them in this report.
  A claim that I could not confirm is marked **plausible**.
- I ran the tools: `cargo audit` (with and without the `justfile` ignores), `cargo deny check`, and
  `cargo tree -e normal,build -i <crate>` (also with `--target all`) for each ignored advisory.

**Not in scope:** dynamic testing of the release desktop binary, and the OS webview and Tauri runtime (AR-16).

**Owner roles for T27:** Crypto Smith (crypto, core key custody, policy, audit), Rust Builder (store, api, mcp,
client, cerberusd, ssh-agent), Tauri Builder (`src-tauri`), UI Builder (`ui`).

## 3. Findings

### AUD-1 — Medium — An edited audit head is signed again at the next append, so a cut in the log is not detected

- **Component:** `cerberus-core` audit writer
- **Location:** `crates/cerberus-core/src/audit/writer.rs:72-86` (`drain_pending`), `:194` and `:203-235`
  (`write_batch`, `chain_events`); `crates/cerberus-core/src/vault/custody.rs:404` (drain at unlock)
- **Description:** `chain_events` reads `audit_head` from the store and appends after its `last_seq`,
  `last_entry_hash`, `anchor_seq` and `anchor_prev_hash`. It does not check `head_hmac`. It does not check that the
  head agrees with the last row. Then `make_head` signs a new head over the values it read. Nothing verifies the chain
  at unlock. Only an operator request (`admin/audit_ops.rs:184`) and prune run `verify_chain`. `entry_hash` is a
  plain SHA-256 over public fields (`audit/chain.rs:13-22`), so anyone who can read the file can compute it.
- **Exploit:** Same-UID malware (ATK-4) used a stolen agent token to reveal secrets. It now wants to hide this.
  1. It stops the app or waits until the vault is sealed. It opens `vault.cerberus` with any SQLite tool. It sets
     the prune guard or drops the `audit_events` delete trigger.
  2. It deletes the rows 90 to 100 (its `item.reveal` events). It sets `audit_head.last_seq = 89` and
     `last_entry_hash` to the `prev_hash` of the deleted row 90 (plain text). It leaves the head MAC as it is.
  3. At the next unlock, `drain_pending` or the `vault.unlock` event appends a new row 90 after row 89, and writes a
     correctly signed head.
  4. "Verify chain" now reports `Ok`. A move of `anchor_seq` / `anchor_prev_hash` in the same way hides a cut at the
     start of the log.
  This defeats the T-3 control "MACed head with anchor ... cuts the tail" without any key.
- **Fix:** In `chain_events`, check the head HMAC before an append. Also check that the stored last row has
  `seq == last_seq` and that its entry hash equals `last_entry_hash`. On a mismatch, refuse the append, raise
  `IntegrityAlert`, and write the event only after the person sees the alert (or start a new, marked segment).
  Run `verify_chain` once after each unlock and show the result on the dashboard. Add a test that cuts the tail,
  edits the head and then unlocks.
- **Owner:** Crypto Smith
- **T27 fix (T27-A1):** The writer checks the head HMAC and that the newest row has `seq == last_seq` and the head's entry hash, inside the write. A writer made at unlock also treats an empty log as cut. On a mismatch it chains a break mark (`integrity.row_mac_mismatch` on `audit_head`) before the event; `verify_chain` reports that mark as `HeadMismatch` for good, and the alert is raised. The append is not refused, so a secret read is never blocked. After each unlock a background walk of the chain writes `audit.verify` and raises the alert on a break. Tests: `aud1_a_cut_tail_with_an_edited_head_is_found_at_unlock`, `aud1_a_wiped_log_is_found_at_unlock`, `a_cut_tail_with_an_edited_head_is_not_signed_again`, `a_deleted_head_does_not_restart_the_chain`. DEC-T27-A1-1.

### AUD-2 — Medium — `items.kind` is a plain column with no MAC, and policy decisions use it

- **Component:** `cerberus-core` index and policy; `cerberus-store` schema
- **Location:** `crates/cerberus-core/src/index/meta.rs:242` (`kind: row.kind`); `crates/cerberus-core/src/policy.rs:310`
  (`selector.kinds`); `crates/cerberus-core/src/items/service.rs:1112-1131` (`open_current` does not compare the
  payload kind with `meta.kind`); `crates/cerberus-core/src/agent_api.rs:899-903` (delete scope by kind)
- **Description:** The sealed item metadata (`items.meta_ct`) does not hold the kind. The AAD does not hold it
  either. The index takes the kind from the plain `items.kind` column. Grant selectors (`kinds`), deny grants, the
  delete scope check and `ssh_prepare` all read it. No code checks that the kind of the opened payload is the same as
  the indexed kind. Threat-model invariant 6 says: "A forged plain row ... never grants access". This column breaks
  that invariant.
- **Exploit:** The owner has a deny grant `deny read, kinds = [ssh_key]` and an allow grant `read` on workspace
  `infra` (the policy is "SSH keys are used only through the signing socket"). An attacker with write access to the
  file (ATK-5 together with ATK-2, or ATK-4) changes `items.kind` of the `build-01` SSH key row from `ssh_key` to
  `api_key`. After the next unlock, the deny grant does not match. `POST /v1/credentials/{id}/reveal` returns the raw
  OpenSSH private key. A grant with `kinds = [api_key]` also gives the key.
- **Fix:** Put `kind` in the sealed meta JSON (or in the meta AAD) and refuse the row at index build when the sealed
  kind and the plain kind differ (integrity alert, as for a bad blob). In `open_current`, refuse a payload whose kind
  is not the indexed kind. Add an ADR-0033 test that changes `items.kind`. The same rule must cover
  `items.current_version` (AUD-6).
- **Owner:** Crypto Smith (core); Rust Builder for the store migration
- **T27 fix (T27-A1):** `kind` is in the sealed item metadata and snapshot. A sealed kind that is not the plain `items.kind` is refused at index build (row left out, integrity alert); every read compares the row with the indexed kind, and `open_current` refuses a payload of another kind. An existing vault is upgraded at its first unlock, with no SQL migration (the blobs need the key): metadata without `kind` is accepted only when the authenticated payload has the plain kind, and is then sealed again with it (compare and set). Tests: `aud2_a_changed_plain_kind_is_refused_at_unlock`, `aud2_a_changed_plain_kind_is_refused_at_reveal`, `aud2_a_vault_from_before_t27_gets_sealed_kinds_at_first_unlock`, `aud2_a_legacy_row_with_a_changed_plain_kind_is_refused`. DEC-T27-A1-2.

### AUD-3 — Medium — `ssh_prepare` runs an attacker-chosen bcrypt cost while it holds the vault write guard; the vault cannot lock

- **Component:** `cerberus-core` Agent API (SSH)
- **Location:** `crates/cerberus-core/src/agent_api/ssh.rs:473` (write guard), `:488-491` (`signing_key` on the guard),
  `:354-362` (`open_key` calls `PrivateKey::decrypt`); `crates/cerberus-core/src/items/ssh.rs:137-158` (create checks
  only that the key parses); `crates/cerberus-core/src/vault/mod.rs:462` (lock waits for the write guard);
  DEC-FIX8-5 accepted the decrypt on the guard
- **Description:** An encrypted OpenSSH key stores its bcrypt-pbkdf round count in the file, in clear text. The create
  path (agent `POST /v1/credentials` with kind `ssh_key`, or IPC import) only parses the key. It does not decrypt the
  key and does not limit the rounds. `ssh_prepare` decrypts the key inline: the decrypt is not in `spawn_blocking`
  and it runs while the vault **write** guard is held. Every lock (manual, idle, hard limit, OS event, panic button)
  waits for that guard (`erase`, `vault/mod.rs:462`). DEC-FIX8-5 said "runs once per lease use", but it did not
  think about an attacker who chooses the cost.
- **Proof (run):** In a scratch crate with `ssh-key` 0.6.7 (the same version and features), I patched the rounds field
  of an encrypted ed25519 key. `PrivateKey::from_openssh` accepts every value, and the public key does not change.
  The decrypt time is linear: 16 rounds 0.10 s, 256 rounds 1.6 s, 1024 rounds 6.6 s. So `u32::MAX` rounds is about
  300 days. A wrong passphrase still spends the full time, so the attacker does not need a valid key.
- **Exploit:** A prompt-injected agent has `secrets:write` + `write` and `ssh:use` + `use_ssh` on one workspace (a
  normal "agent manages its deploy keys" set-up). It stores an `ssh_key` item that has a patched round count and any
  passphrase, then calls `ssh_prepare`. One tokio worker spins. The write guard is held. The vault goes to `Locking`
  and stays there. The idle lock, the hard lock, the OS lock and the panic button cannot drop the keys or revoke the
  leases, so the keys stay in memory past every lock rule. Only a process kill ends it. A second agent with a broad
  `use_ssh` grant can trigger it without knowing.
- **Fix:** Limit the rounds at create and import (for example to 1024 or less, the OpenSSH default is 16). Refuse a
  larger value with `validation_failed`. Do the check in `check_payload`. Do not run the decrypt on the vault guard:
  do the check, the key read and a strict audit "prepare started" on the guard, then decrypt in `spawn_blocking` with
  no guard held, then take the guard again to confirm. Keep `ssh_sign` in `spawn_blocking` and apply the same round
  limit. Add a test with a patched round count.
- **Owner:** Crypto Smith
- **T27 fix (T27-A2):** Import, item validation, prepare and sign refuse more than `MAX_SSH_KDF_ROUNDS` (1024) bcrypt rounds with `validation_failed` (the count is read without a decrypt). `ssh_prepare` writes its strict `ssh.prepare` event on the guard, drops it, opens the key on `spawn_blocking`, then takes the guard again and gives a ticket only in the same session; no lock path waits for bcrypt. Tests: `an_encrypted_key_with_too_many_kdf_rounds_is_refused`, `a_lock_does_not_wait_for_the_key_decrypt_of_a_prepare` (lock and panic button). DEC-T27-A2-2, DEC-T27-A2-3.

### AUD-4 — Medium — A TLS connection that sends no request is never timed out, so anyone without a token can fill all 256 connection slots

- **Component:** `cerberus-api` server
- **Location:** `crates/cerberus-api/src/server.rs:384-389` (only `http1().header_read_timeout` is set);
  `hyper-util` 0.1.21 `server/conn/auto/mod.rs:305-320` (`read_version` has no timeout); the 256-permit semaphore is
  taken before `accept` (DEC-T10-9)
- **Description:** The auto builder first reads the first bytes to choose between HTTP/1 and HTTP/2. That read has no
  timeout. The HTTP/1 `header_read_timeout` starts only after the version is known. HTTP/2 has no idle or keep-alive
  timeout configured. The TLS handshake timeout (10 s) ends when the handshake ends. A client can complete the TLS
  handshake (no client certificate is needed on loopback) and then send nothing. The connection keeps its permit
  for as long as the client wants.
- **Proof (run):** A scratch server with the same `hyper-util` builder and `header_read_timeout(1 s)`: a silent
  connection was still open after 5 s. A connection that sent half a request line was closed at once by the timeout.
- **Exploit:** Any other local OS user (ATK-3), with no token, opens 256 TLS connections to `127.0.0.1:7373` and stays
  silent. New agent connections wait in the backlog for ever. Agents cannot read credentials, and approvals cannot
  reach them. D-1 ("handshake, header and body timeouts; max 256 concurrent connections") lists this as a control, and
  the attack defeats that control. The per-IP limits do not help, because they run only after a request arrives.
- **Fix:** Wrap the whole `serve_connection` future in a first-request deadline (for example 10 s from the end of the
  handshake to the first complete request head), and an idle deadline between requests. For HTTP/2, set
  `http2().timer(..)`, `keep_alive_interval` and `keep_alive_timeout`, and limit `max_concurrent_streams`. Or offer
  only `http/1.1` in ALPN and serve with `http1_only`. Add a test that holds a silent connection.
- **Owner:** Rust Builder
- **T27 fix (T27-B):** A watcher per connection (`crates/cerberus-api/src/idle.rs`) closes a connection that is silent for `header_timeout` before its first byte, or for `idle_timeout` (60 s) after it, and never while a request runs. Also `max_connections_per_ip` (64). Tests: `aud4_a_silent_tls_connection_is_closed` (real TLS), `aud4_an_idle_keep_alive_connection_is_closed_but_a_running_request_is_not`, `aud4_one_ip_cannot_hold_every_connection`. DEC-T27-B-1.
- **T27-D fix (T27-D2, after the re-check):** Progress now means a request, never bytes: the byte watcher is gone, so a trickle, a slow h2 preface or h2 PINGs move no deadline. The first request head is due `header_timeout` (10 s) after the handshake; a connection with no authenticated request is closed `auth_timeout` (30 s) after accept, even while a request runs; after an authenticated request, the idle limit (60 s) counts only authenticated requests, and a response still being sent (SSE) counts as running. Unauthenticated connections have their own budget (`max_unauthenticated`, 64); when it or the server is full, a new connection evicts the oldest unauthenticated one of the busiest source, and an authenticated connection is never evicted (see NEW-1). Tests (real TLS): `aud4_a_byte_trickling_client_is_closed`, `aud4_an_http2_client_that_only_sends_pings_is_closed`, `aud4_a_connection_without_an_authenticated_request_is_closed_at_the_auth_deadline`, `aud4_an_event_stream_outlives_the_idle_time`, `aud4_an_agent_gets_in_while_unauthenticated_clients_hold_every_slot`. DEC-T27-D2-1, DEC-T27-D2-2.

### AUD-5 — Medium — `cerberus run` lets an item set any environment variable in the child, including loader and interpreter hooks

- **Component:** `cerberus-client` (`cerberus run`); `cerberus-core` item validation
- **Location:** `crates/cerberus-client/src/run.rs:221-227` (`valid_name` accepts any `[A-Za-z_][A-Za-z0-9_]*`),
  `:286-295` (cloud `extra` keys), `:302-313` (env bundle keys), `:618-631` (vars set after `env_remove`, so they win);
  `crates/cerberus-core/src/items/validate.rs:98-104` (`valid_env_name` accepts any upper-case name)
- **Description:** The names of an `env_bundle` item and the `extra` keys of a `cloud` item go straight into the
  environment of the child. No name is refused. `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `PATH`,
  `BASH_ENV`, `ENV`, `NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT`, `GIT_SSH_COMMAND` and `CERBERUS_TOKEN` are all
  accepted. An agent with `write` can create such an item (`POST /v1/credentials`, `cerberus store --json`). Resolve
  does not use `created_by` in its score (`crates/cerberus-core/src/resolve.rs`, no reference to `created_by`). So the
  item of an agent can be the winner for the `cerberus run --app X` call of another agent or of a person.
- **Exploit:** Agent A (prompt-injected) has `write` in workspace `shop`. It creates the env bundle "shop staging
  deploy" with `NODE_OPTIONS=--require /tmp/a.js` (or `LD_PRELOAD=/tmp/a.so`) and a title that matches the hint
  words. The CI agent B runs `cerberus run --app shop --env staging -- npm run deploy`. B's child process loads A's
  code with B's privileges and with every real secret that the run injected. AR-15 accepts that an agent item can
  "mislead". It does not accept code execution in the process of another principal.
- **Fix:** In `cerberus run`, refuse (or skip with a warning) names on a deny list: `LD_*`, `DYLD_*`, `PATH`,
  `BASH_ENV`, `ENV`, `IFS`, `*_OPTIONS`, `PYTHON*`, `PERL5*`, `RUBYOPT`, `GIT_*`, `SSH_*`, `CERBERUS_*`. A person can
  still set such a name with an explicit `--var NAME=field`. Also refuse the same names in `validate.rs` for items
  that an agent creates. Optionally, let resolve prefer operator items over agent items when the score is equal, and
  mark agent items in the `run` output.
- **Owner:** Rust Builder (client); Crypto Smith (core validation and resolve)
- **T27 fix (T27-B, client part):** `cerberus run` skips `env_bundle` names and `cloud` extra keys that `cerberus_types::is_forbidden_env_name` refuses, and prints their names (never values) on stderr. `--var NAME=field` by the person still works. Tests: `aud5_*` in `crates/cerberus-client/src/run.rs`. DEC-T27-B-3. The core validation part is T27-A2.
- **T27 fix (T27-A2, core part):** One shared list, `cerberus_types::env::is_forbidden_env_name` (the client uses the same function). Core refuses such a name in the `env_bundle` vars or `cloud` `extra` keys of an item that an agent creates (`422`, `payload.vars.<NAME>`, audited). Resolve prefers operator items (see AUD-23). Test: `agent_items_cannot_set_forbidden_env_names`. DEC-T27-A2-1.
- **T27-D fix (T27-D1, after the re-check):** The re-check showed that the deny list misses `OPENSSL_CONF`, `MAVEN_OPTS`, `RUSTFLAGS`, `KUBECONFIG` and many more. Names in an item that an agent wrote now need an allow rule, `cerberus_types::env::is_agent_env_name_allowed`: credential-shaped names only (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_USER` ... and a short list such as `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, `DATABASE_URL`), never a deny-list name, compared without case. Core refuses any other name in an agent create; `cerberus run` applies the same rule to every item whose `created_by` is not `operator:...` (so agent items stored before the fix are covered). The deny list stays as the second layer, the only check for a person's item, and now also has the code-load hooks of the re-check (`OPENSSL_*`, `*_OPTS`, `GOFLAGS`, `RUSTFLAGS`, `CARGO_BUILD_*` ...). Tests: `agent_items_may_set_only_credential_names`, `the_recheck_code_load_hooks_are_forbidden` (types), `agent_items_may_set_only_credential_env_names` (core), `aud5_an_agent_item_sets_only_credential_names` (client). DEC-T27-D1-1.

### AUD-6 — Low — `items.current_version` is a plain pointer that a live file edit can move back

- **Component:** `cerberus-core` items
- **Location:** `crates/cerberus-core/src/items/service.rs:1119-1131` (version from the plain row), `:1158-1161`
  (`count_reveal` seals the meta again under that version)
- **Description:** While the vault is unlocked, the reveal path reads `current_version` from the plain row. It opens
  the payload of that version. The payload opens, because its AAD holds that version. A count of a use then seals
  `meta_ct` under the old version, so the next unlock shows no alert.
- **Exploit:** Same-UID malware changes `current_version` to an older version that is still kept (a password that was
  changed because it leaked). Agents then get the old value.
- **Fix:** Keep the current version in the index (from the sealed meta) and compare it with the row at each read.
  Refuse a mismatch with `Corrupt` and an integrity event. Do this together with AUD-2.
- **Owner:** Crypto Smith
- **T27 fix (T27-A1):** The index keeps the version whose sealed metadata opened. Each read refuses a row whose `current_version` differs (`Corrupt`, integrity alert on `items`), before a payload opens or a use is counted. Test: `aud6_a_moved_back_current_version_is_refused`. DEC-T27-A1-3.

### AUD-7 — Low — Revoke-all and cancel-pending sign rows again without a MAC check first

- **Component:** `cerberus-store`
- **Location:** `crates/cerberus-store/src/tx.rs:579-598` (`revoke_all_leases`), `:643-660` (`cancel_pending_requests`)
- **Description:** Both functions read rows, change them and call `sign_*` with no `verify_*` first. A forged row
  becomes a row with a valid MAC, and no integrity event is written. This is against DEC-T07-7 ("a row with a bad MAC
  is never signed again").
- **Exploit:** A file attacker inserts an auto lease row with `expires_at` far in the future and a junk MAC. After the
  next lock with panic, or a restore, it is a validly signed revoked auto lease. It blocks auto leases for that
  agent and item until that date (ADR-0019 point 7), and it shows a false exposure. Only availability is lost.
- **Fix:** Verify each row before the change. Skip a bad row, and report it to the caller for
  `integrity.row_mac_mismatch`.
- **Owner:** Rust Builder
- **T27 fix (T27-A1):** Both functions verify each row MAC first. A bad row is left as it is and returned (`bad_mac`), and the callers write `integrity.row_mac_mismatch` and raise the alert. Tests: `revoke_all_leases_never_signs_a_forged_row`, `cancel_pending_requests_never_signs_a_forged_row`, `aud7_panic_revoke_leaves_a_forged_lease_and_raises_the_alert`. DEC-T27-A1-4.

### AUD-8 — Low — The sweeper deletes items only by the plain `expires_at`

- **Component:** `cerberus-store` sweeper
- **Location:** `crates/cerberus-store/src/tx.rs:795-808`
- **Description:** The effective expiry is the earlier of the plain and the sealed value (ADR-0033 point 6). Reads
  hide the item correctly. But the sweeper deletes by the plain column only. If the plain value is set to `NULL`,
  the ciphertext stays in the file for ever. ADR-0027 promises a hard delete.
- **Exploit:** A file attacker clears `expires_at` on a session token row. The token is hidden after its sealed end,
  but if the phrase is lost later, the old file still gives the token.
- **Fix:** While unlocked, also delete items whose effective expiry from the index has passed.
- **Owner:** Rust Builder (store), Crypto Smith (index call)
- **T27 fix (T27-A1):** While unlocked, after each unlock and after every sweep (the sweeper now sends empty reports too), the vault service deletes the items whose effective expiry in the index has passed, writes `item.expire` (`reason = sealed_expiry`) and truncates the WAL. Test: `aud8_an_item_with_a_cleared_plain_expiry_is_deleted_after_its_sealed_end`. DEC-T27-A1-5.

### AUD-9 — Low — One malformed `audit_pending` row stops every pending event from reaching the chain

- **Component:** `cerberus-store`, `cerberus-core` audit
- **Location:** `crates/cerberus-store/src/tx.rs:780-783` (one bad row makes the whole take fail);
  `crates/cerberus-core/src/vault/custody.rs:404-406` (failure only logged)
- **Description:** `take_audit_pending` parses all rows and fails on the first bad one. The drain then fails at
  every unlock, and only a warning goes to the log. The rows are not authenticated (AR-6) and the event type is not
  checked against the locked-time list.
- **Exploit:** A file attacker inserts one row with a bad UUID. From then on, `vault.unlock_failed`, `auth.failed` and
  `item.expire` events written while locked never reach the chain.
- **Fix:** Skip and count a bad row (add the count to the overflow note). Accept only the event types that code
  writes while locked. Show a drain failure as an integrity alert.
- **Owner:** Rust Builder (store), Crypto Smith (audit)
- **T27 fix (T27-A1):** A row that cannot be parsed is deleted and counted (`malformed`). Only the event types written while locked are accepted, and other rows are counted the same way. The count is in the overflow note. A drain that still fails raises `IntegrityAlert { table: "audit_pending" }`. Tests: `a_malformed_pending_row_is_skipped_and_counted` (store and core), `aud9_a_malformed_pending_row_does_not_block_the_others`, `aud9_a_failed_drain_raises_the_alert`. DEC-T27-A1-6.

### AUD-10 — Low — Restore opens the backup three times, and the RUSTSEC-2026-0459 mitigation has gaps

- **Component:** `cerberus-store` backup; desktop restore
- **Location:** `crates/cerberus-store/src/backup.rs:43-46` (path check for `-wal`), `:126` and `:142-147` (second
  inspect and copy); `apps/desktop/src-tauri/src/ops/restore.rs:78-85` (probe copy), `:132-136` and `:155-176`
  (swap and finish); `deny.toml:21-25`
- **Description:**
  - The `-wal` check is a path check before separate opens (a check-then-use gap).
  - The desktop flow proves the credential on a probe copy, then `restore_backup` inspects and copies the original
    path again. The file that is installed is not the file that was proved.
  - If `finish_restore` fails, the unproved file stays live, and the old vault stays in `.pre-restore-*`. No code
    puts it back. Two restores can run at the same time.
  - `deny.toml` says "Cerberus opens only its own vault file". That does not cover a file attacker who puts a
    crafted `vault.cerberus-wal` next to the live vault (plausible: the advisory impact is a stale memory read during
    WAL replay).
- **Exploit:** The person restores from a synced folder. An attacker who can write that folder swaps the file after
  the proof. The live vault becomes the attacker's file. Unlock fails, and the person must find `.pre-restore-*` by
  hand.
- **Fix:** Copy the backup once into the private 0700 probe folder. Inspect, prove and install that same copy. Roll
  back to `.pre-restore-*` on any later failure. Hold a restore mutex. Before the live vault opens, refuse an
  unexpected `-wal` whose header does not match. Correct the text in `deny.toml` and `justfile`.
- **Owner:** Rust Builder (store); Tauri Builder (restore flow)
- **T27 fix (T27-C, desktop part):** The restore reads the chosen file once into a private 0700 folder. The inspect, the proof of the credential (on a copy of it) and the install all use that copy. A mutex refuses a second restore. If any step after the swap fails, including the open of the restored file, the old vault file is put back and opened again. Tests: `the_staged_copy_does_not_follow_the_original`, `a_failed_restore_puts_the_old_vault_back`, `a_restored_file_that_does_not_open_is_rolled_back`, `a_second_restore_is_refused_while_the_gate_is_held` (the test holds the gate, so there is no race). DEC-T27-C-1, DEC-T27-C-10. The `-wal` header check and the `deny.toml` and `justfile` text are store and packaging items.
- **T27 fix (T27-A1, store part):** `Store::open` refuses a `-wal` next to the vault whose header does not fit the vault (magic, version, page size of the main file, checksum) before any connection. `inspect_backup` reads with one `immutable` connection, so a sibling `-wal` is never read. `restore_backup` copies once, inspects that copy and installs that copy. The `deny.toml` and `.cargo/audit.toml` text names what is covered and what is not (a swap between check and open, or a change while open); the `justfile` has no such claim. Tests: `open_refuses_a_wal_file_of_another_page_size`, `the_backup_check_never_reads_a_sibling_wal`. DEC-T27-A1-7.
- **T27-F fix (rest of section 6 and 8):** `swap_files` moves the old files back when a later rename fails. Only
  when that is not possible does it return the old vault path, as `StoreError::RestoreStranded`. The desktop closes
  the old store before the swap and never makes a new vault after a failed restore. See NEW-10, DEC-T27-F-1.

### AUD-11 — Low — The webview can make the backend read any file of the user

- **Component:** desktop IPC
- **Location:** `apps/desktop/src-tauri/src/ops/files.rs:68-80` (`existing_file`: any absolute path, follows
  symlinks); `ops/csv.rs:19-31`; `ops/items.rs:338-345` (`ssh_key_import { kind: "path" }`);
  `crates/cerberus-core/src/csvio/plan.rs:168-173` (preview returns the header cells)
- **Description:** File paths come from the webview as text. The backend cannot know whether the native dialog gave
  the path or a script did. `csv_preview` sends back up to 64 header cells of any file. `csv_import` with a generic
  mapping can turn any text file into items. `ssh_key_import` can store `~/.ssh/id_ed25519`. The error texts tell
  whether a path exists.
- **Exploit:** This needs script execution in the main window first (no XSS was found; CSP is strict). With it, the
  script can already reveal every item, but it can also read files outside the vault, for example the first line of
  `~/.git-credentials` through `csv_preview`.
- **Fix:** Open the file dialogs from Rust (`DialogExt`) and give the UI a handle that cannot be guessed, or keep a
  backend set of the paths that the dialog returned. Use one error text for all path problems.
- **Owner:** Tauri Builder
- **T27 fix (T27-C):** The open dialog runs in Rust (`file_pick_open`). The backend reads only a path that the dialog returned or that the OS reported as dropped on the main window, and every other path gives one error text ("cannot be used"). The list is cleared at lock. Applies to `csv_preview`, `csv_import`, `ssh_key_import`, `tls_load_custom` and `backup_restore`. Tests: `aud11_*`; `aud11_the_lock_clears_the_picked_paths` unlocks again and shows that a picked and a dropped path are refused. DEC-T27-C-2, DEC-T27-C-10.

### AUD-12 — Low — `core:default` gives both windows more Tauri permissions than they use

- **Component:** desktop capabilities
- **Location:** `apps/desktop/src-tauri/capabilities/main.json:9`, `capabilities/approval.json:9`
- **Description:** The `core:default` set (checked against the Tauri 2 permission reference) includes the tray
  (`get-by-id`, `set-menu`, `set-tooltip`, `set-title`), `image:allow-from-path` and `event:allow-emit` /
  `allow-emit-to`.
- **Exploit:** After script injection, a script can change the real tray to show "Locked", replace the Lock and
  "Lock and revoke all" menu items, read image files from disk, or send false `VaultStateChanged` or
  `PendingCountChanged` events to the other window.
- **Fix:** Replace `core:default` with the exact permissions in use, for example `core:event:allow-listen`,
  `core:event:allow-unlisten` and the window permissions that the UI calls.
- **Owner:** Tauri Builder
- **T27 fix (T27-C):** `core:default` is removed. The main window has `core:event:allow-listen`, `allow-unlisten` and `core:app:allow-version`; the approval window has the two event permissions. Test: `capabilities_list_exact_core_permissions`. DEC-T27-C-3.

### AUD-13 — Low — After a LAN bind, new agent keys have no mTLS binding

- **Component:** desktop network settings
- **Location:** `apps/desktop/src-tauri/src/ops/system.rs:126-147` (the check runs only when the bind changes);
  `apps/desktop/src-tauri/src/dto/agents.rs:61` (`require_mtls: false` for every new key)
- **Description:** `network_set_bind` refuses a LAN bind while an active key has no mTLS binding. But after the bind,
  `agent_create`, `agent_key_create` and `agent_key_rotate` still make keys without a binding. The TLS layer still
  requires a client certificate signed by the vault CA on a LAN bind (`apps/desktop/src-tauri/src/server.rs:63`).
- **Exploit:** A LAN host that has the client certificate of agent A can use a leaked token of agent B, whose key
  has no binding. E-10 and ADR-0023 point 2 want a binding per key.
- **Fix:** While the bind is not loopback, refuse key creation until a client certificate is issued, or have the
  token check refuse a key without `require_mtls` when the peer address is not loopback.
- **Owner:** Tauri Builder (Crypto Smith if the check goes into `auth.rs`)
- **T27 fix (T27-C):** While the bind is not loopback, `agent_create`, `agent_key_create` and (for an unbound key) `agent_key_rotate` are refused. The person makes the key on loopback, issues its certificate, then binds to the LAN. Test: `aud13_no_new_key_without_a_binding_on_a_lan_bind`. The second layer in `auth.rs` (refuse an unbound key from a non-loopback peer) is for core and is described in DEC-T27-C-4.

### AUD-14 — Low — The clipboard is not cleared on quit, lock or panic; the panic hook leaves held values; there is no `panic = "abort"`

- **Component:** desktop shell; workspace profile
- **Location:** `apps/desktop/src-tauri/src/state.rs:444-460` (the 30 s timer is the only `clipboard_clear` call);
  `apps/desktop/src-tauri/src/lib.rs:148-155` (panic hook); `Cargo.toml` (no `[profile]` section)
- **Description:**
  - A secret copied less than 30 s before a quit or panic lock stays in the clipboard, because the timer task ends
    with the process.
  - The panic hook wipes the core keys but not the SSH drafts, the one-time recovery key or token, or the clipboard.
  - The threat model (I-8) says `panic = "abort"`, but the release profile uses unwind, so the process continues
    after a panic in a task.
- **Exploit:** A person copies a password and presses "Lock and revoke all" at once. The password stays for any
  clipboard manager and for the next paste.
- **Fix:** In `vault_lock`, `vault_panic`, quit and the panic hook, clear the clipboard if its digest still matches
  the last copy. Call `clear_held` with `try_lock` in the hook. Set `panic = "abort"` for release, or correct I-8.
- **Owner:** Tauri Builder
- **T27 fix (T27-C):** Lock, panic, quit and the panic hook clear the clipboard when it still holds the last text we copied. The hook also clears drafts, one-time values and picked files, with `try_lock` only. The release profile has `panic = "abort"`. Tests: `aud14_*`. DEC-T27-C-5.

### AUD-15 — Low — The approval window never gets content protection

- **Component:** desktop windows
- **Location:** `apps/desktop/src-tauri/src/windows.rs:24-36` (no `content_protected`);
  `apps/desktop/src-tauri/src/shell.rs:59-66` (only windows that exist when the setting changes)
- **Description:** The approval window is made later, on demand, and the setting is not applied to it.
- **Exploit:** With protection on (macOS, Windows), a screen recorder still captures agent names, item titles and
  reasons in the approval window.
- **Fix:** Add `.content_protected(prefs.content_protection)` to the approval window builder.
- **Owner:** Tauri Builder
- **T27 fix (T27-C):** The approval window is built with `.content_protected(prefs.content_protection)`. Test: `approval_window_is_built_with_content_protection` (it reads the builder chain: exactly one `.content_protected(protected)`, and `protected` is the saved setting, not a constant). DEC-T27-C-6, DEC-T27-C-10.

### AUD-16 — Low — The OS lock hooks are partial on Linux and missing on macOS and Windows

- **Component:** desktop OS hooks
- **Location:** `apps/desktop/src-tauri/src/os_hooks.rs:128-135` (only the logind `Lock` signal and
  `PrepareForSleep`, with no delay inhibitor); DEC-T15-8
- **Description:**
  - Linux: many desktops lock the screen without the logind `Lock` signal and only set `LockedHint` (plausible; it
    depends on the desktop). With no delay inhibitor, suspend or hibernate can start before the keys are gone, so
    keys can reach the hibernation image (I-8).
  - macOS and Windows: no hook. Only the idle lock (30 min) and the hard lock (12 h) apply.
  - The threat model lists "lock on OS sleep (keys erased before suspend)" as a control without this limit.
- **Exploit:** A person locks the screen and walks away. The vault stays unlocked behind the lock screen for up to
  30 minutes, and a laptop hibernation in that time can write keys to disk.
- **Fix:** Also watch `PropertiesChanged` of `LockedHint`. Take a logind `delay` inhibitor and release it after the
  lock. Record the macOS and Windows gap as an accepted risk in the threat model, with an owner, or build the hooks
  in `cerberus-crypto` under the ADR-0012 unsafe rules.
- **Owner:** Tauri Builder
- **T27 fix (T27-C):** Linux: a `LockedHint` watcher, and a logind `delay` inhibitor that is released after the lock (at most 3.5 s). macOS and Windows: no safe event source exists (checked `tao`), so the gap is an accepted risk in ADR-0026 (amendment) and the threat model, with the idle and hard locks as the control. Tests: `a_locked_hint_locks_and_an_unlocked_hint_does_not`, `the_inhibitor_wait_*`. DEC-T27-C-9.

### AUD-17 — Low — With a CA file and a pin, the client trusts every certificate in the file

- **Component:** `cerberus-client` TLS
- **Location:** `crates/cerberus-client/src/tls.rs:207-216`, `:243-256`
- **Description:** `Trust::CaFileAndPin` checks that one certificate in the file has the pinned SPKI. Then it adds
  every certificate in the file as a root.
- **Exploit:** The person points `CERBERUS_CA_FILE` at a system bundle that also holds the Cerberus CA, and uses a
  public host name. A server with a certificate from any public CA in the bundle is accepted, and the token is sent.
- **Fix:** Use only the certificate that matches the pin as the root, or refuse a file with more than one
  certificate when a pin is set.
- **Owner:** Rust Builder
- **T27 fix (T27-B):** With a pin, only the certificates of the CA file that have the pin are roots. Test: `aud17_a_pin_trusts_only_the_pinned_certificate_of_a_bundle`. DEC-T27-B-2.

### AUD-18 — Low — Output masking in `cerberus run` leaks the tail of a secret that starts with a shorter secret

- **Component:** `cerberus-client` run masking
- **Location:** `crates/cerberus-client/src/run.rs:415-439` (a full match of a short needle wins over a partial
  match of a longer one); `:254-265` (`DATABASE_URL` from parts is masked only as a whole)
- **Description:** With the secrets `admin` (user name) and `admin2024!secret` (password), the chunks `pw=admin` and
  `2024!secret` print `pw=[REDACTED]2024!secret`. The reviewer reproduced this with a copy of the logic. The user
  name and password parts of a built `DATABASE_URL` are not masked one by one.
- **Exploit:** A tool prints its connection settings. The tail of the password reaches the agent transcript (I-5).
- **Fix:** Hold back output while a longer needle can still match, and try the longest needle first. Add each part
  of a built URL as its own needle.
- **Owner:** Rust Builder
- **T27 fix (T27-B):** The masker holds back while a longer secret can still match, tries the longest first and masks the tail at the end of the stream; every secret field of the item is a needle (parts of a built `DATABASE_URL`). Tests: `aud18_*`. DEC-T27-B-4.

### AUD-19 — Low — The child of `cerberus run` can still get the agent token

- **Component:** `cerberus-client`
- **Location:** `crates/cerberus-client/src/run.rs:618-622`; `crates/cerberus-client/src/main.rs` (no process
  hardening)
- **Description:** `CERBERUS_TOKEN` is removed from the environment of the child. But the child runs as the same
  user and can read `/proc/$PPID/environ` of the `cerberus` process (the reviewer confirmed this with Yama
  `ptrace_scope=1`). The token file stays readable too. I-18 claims more than the code gives.
- **Exploit:** A malicious build script in the child reads the parent environment and sends the token away.
- **Fix:** Call `harden_process()` (not dumpable) in `cerberus` before the spawn, which makes `/proc/<pid>/environ`
  unreadable for the child. Document that a token file stays readable (AR-3).
- **Owner:** Rust Builder
- **T27 fix (T27-B):** `cerberus run` is not dumpable (Linux), so the child cannot read `/proc/<ppid>/environ`; the token env vars were already removed and no token descriptor is inherited. The readable token file stays documented (AR-3, I-18). Test: `aud19_the_child_cannot_read_the_token_from_the_parent_environment`. DEC-T27-B-5.

### AUD-20 — Low — `cerberusd` keeps plain copies of the unlock phrase

- **Component:** `cerberusd` unlock socket
- **Location:** `crates/cerberusd/src/unlock.rs:155-158` (`BufReader` buffer not wiped), `:159` and `:173-179`
  (`Request.phrase` is a plain `String`; on the "not sealed" path it is dropped without a wipe)
- **Description:** DEC-T13-1 says "Zeroizing on both sides". The read buffer and the serde target are plain heap
  memory. The client side `serde_json::to_vec` can also leave old copies when it grows.
- **Exploit:** Only memory access (AR-8) can read it. Not dumpable and `LimitCORE=0` reduce the risk.
- **Fix:** Read into a `Zeroizing<Vec<u8>>` with a fixed limit. Deserialize into a type with a `Zeroizing<String>`
  phrase. Pre-size the client buffer.
- **Owner:** Rust Builder
- **T27 fix (T27-B):** Fixed-size `Zeroizing` read buffer, `Zeroizing<String>` phrase in the request, and a pre-sized `Zeroizing` buffer on the client side. One `serde_json` scratch copy for escaped phrases is accepted. Tests: `aud20_*` in `crates/cerberusd/src/unlock.rs`. DEC-T27-B-6.

### AUD-21 — Low — The SSH socket signs any `SSHSIG` blob, with any namespace

- **Component:** `cerberus-core` SSH signing
- **Location:** `crates/cerberus-core/src/agent_api/ssh.rs:294-296` (prefix test only)
- **Description:** The user-auth parse is strict. But data that starts with `SSHSIG` is signed for any namespace
  (`git`, `file`, any custom text). A lease approved as "one SSH login" (DEC-T22-3) can sign a git tag or a file
  signature instead. The socket is not a general signing oracle, because the SSHSIG framing binds the namespace.
- **Exploit:** An agent asks for approval with the reason "log in to build-01". It uses the single signature to sign
  a release tag as the owner key.
- **Fix:** Parse the SSHSIG fields. Allow only the namespaces that the item allows (a new item setting), and write
  the namespace in the `ssh.sign` event.
- **Owner:** Crypto Smith
- **T27 fix (T27-A2):** New item setting `sshsig_namespaces` (comma list). An `SSHSIG` blob is parsed strictly and signed only for a listed namespace (else `forbidden`, before the ticket budget is used); without the setting a key signs SSH logins only. `ssh.sign` has `details.namespace`. Tests: `sshsig_signs_only_the_namespaces_that_the_item_allows`, `a_bad_sshsig_namespace_setting_is_refused`. DEC-T27-A2-6.

### AUD-22 — Low — An approval that lands during a repeated `request_access` opens a second pending request (T24)

- **Component:** `cerberus-core` approvals
- **Location:** `crates/cerberus-core/src/approvals/queue.rs:345` (read guard), `:427-436` (lease check outside
  `request_gate`), `:207` (gate taken only in `open_request`); DEC-T24-5
- **Description:** I confirm the race. The lease check and the pending check do not share `request_gate`. If the
  person approves between them, a second pending request opens. Nothing is shown and nothing is granted without a
  person. But the person sees a second prompt and can approve twice, which makes two leases.
- **Fix:** Take `request_gate` before the lease check in `request_access` and in the `NeedApproval` path of
  `authorize_secret_in`, as DEC-T24-5 says.
- **Owner:** Crypto Smith
- **T27 fix (T27-A2):** `request_access` and `authorize_secret_in` take `request_gate` before the lease check (order: request gate, then lease gate); `open_request` takes the caller's gate guard as a parameter. Test: `an_approval_during_a_repeated_request_opens_no_second_request`. DEC-T27-A2-4.

### AUD-23 — Low — Agent-created text reaches other agents and people without a mark, and resolve ignores `created_by`

- **Component:** `cerberus-core` resolve; `cerberus-mcp`
- **Location:** `crates/cerberus-core/src/resolve.rs` (score has no `created_by` term);
  `crates/cerberus-mcp/src/tools/find.rs`, `get.rs` (metadata goes into the tool text as it is)
- **Description:** AR-15 accepts that an agent item can mislead. Two effects go further than AR-15 says:
  - The title, description and tags of an agent item go into the LLM context of another agent (MCP catalog,
    candidates), so they are a prompt-injection channel between agents.
  - In resolve, an agent item can outscore an operator item with the same app, environment and role by adding hint
    words.
  See also AUD-5.
- **Fix:** In MCP text output, mark agent-written fields as untrusted. On an equal score, prefer operator items, and
  treat a cross-creator tie as `ambiguous`. Update AR-15 to name these effects.
- **Owner:** Crypto Smith (resolve); Rust Builder (MCP)
- **T27 fix (T27-B, MCP part):** Agent-created items get `untrusted_fields` in tool results and in the catalog resource, and the text starts with an `UNTRUSTED:` line. Test: `aud23_agent_written_item_text_is_marked_untrusted`. DEC-T27-B-7. The resolve part is T27-A2.
- **T27 fix (T27-A2, resolve part):** On an equal score an operator item sorts first. An agent item is the confident winner only when its score without hint points beats every operator candidate by the gap; else `ambiguous`. AR-15 names the two effects. Tests: `an_agent_item_does_not_win_over_an_operator_item_by_hint_words`, `on_an_equal_score_the_operator_item_comes_first`. DEC-T27-A2-5.

### AUD-24 — Low — Reason and title cleaning removes only `Cc` characters

- **Component:** `cerberus-core` approvals; UI
- **Location:** `crates/cerberus-core/src/approvals.rs:105-111` (`char::is_control` is `Cc` only);
  `apps/desktop/ui/src/ui/Untrusted.tsx:7-15`
- **Description:** Bidi controls (U+202A to U+202E, U+2066 to U+2069) and zero-width characters are kept. In the
  approval card, the reason is a block, so the reordering stays inside it. But agent names and item titles that
  agents write are inline text, and their display order can be changed (for example to make `prod` look like
  `dorp` or the opposite).
- **Fix:** Remove the `Cf` characters (bidi and zero-width) from the reason, from agent names and from agent-written
  titles. In the UI, put agent text in `<bdi>` or use `unicode-bidi: isolate`.
- **Owner:** Crypto Smith (core cleaning); UI Builder (display)
- **T27 fix (T27-C, UI part):** `UntrustedText`, `InlineUntrusted` and `showInvisible` write invisible and bidi characters as visible `‹U+XXXX›` codes and isolate the text in `<bdi>`; the approval card uses them for agent name, item title and workspace. Test: `ui/Untrusted.test.tsx`. DEC-T27-C-7. The core cleaning is T27-A2.
- **T27 fix (T27-A2, core part):** `cerberus_types::text` (`is_format_char`, `strip_format`, `strip_hidden`). Reasons lose `Cc` and `Cf`; agent-written item text (title, description, role, category, tags, target, custom) and agent names lose `Cf`. Test: `hidden_format_characters_are_removed_from_untrusted_text`. DEC-T27-A2-9.

### AUD-25 — Low — CSV import puts the raw URL, with user name, password and query, into the item `target`

- **Component:** `cerberus-core` CSV import
- **Location:** `crates/cerberus-core/src/csvio/rows.rs:240-242`
- **Description:** `target` is metadata that agents see in the catalog. Password manager exports often hold URLs such
  as `https://user:pass@host/` or URLs with tokens in the query. Only the title is cleaned. Some notes are also
  dropped without being counted in `notes_dropped` (`rows.rs:199-219`).
- **Exploit:** An agent with only `catalog:read` reads a password from the `target` field.
- **Fix:** Remove the user information, the query and the fragment from `target`. Count every dropped note.
- **Owner:** Crypto Smith
- **T27 fix (T27-A2):** `target` keeps scheme, host, port and path only (no user information, query or fragment). Every dropped note is counted. Tests: `the_target_drops_user_info_query_and_fragment`, `every_dropped_note_is_counted`. DEC-T27-A2-10.
- **T27-D fix (T27-D1, after the re-check):** `url_parts` handles passwords that are not percent-encoded: when an `@` comes after the first `/`, `?` or `#`, an authority that is not `host[:port]` is user information and the host is taken after the last `@`; a plain host keeps only scheme and host; any other case gives no target. `https://user:pa/ss@host/x` gives `https://host/x`, `https://user:p?ss@host/` gives `https://host/`. The title made from the URL (`host_of`) uses the same split (it had the same leak). Test: `the_target_never_keeps_an_unencoded_password`. DEC-T27-D1-2.
- **T27-E fix (after the T27-D re-check):** Conservative rule for the ambiguous case (an `@` after the first `/`, `?` or `#`): path, query and fragment are never kept. A `host[:port]` authority is kept as the host only when it is a dotted host name without a port (`https://site.example/login?email=a@b` → `https://site.example`); a dot-less name (`https://tokPart1/part2@github.com/x`) or a `host:port` gives no target and no title from the URL. User information (`user:pa`) gives the host after the `@` only when the text has exactly one `@` (`https://user:pa/ss@host/x` → `https://host`); with more (`https://user:pa/ss@host/x?token=abc@def/ghi`) there is no target. Test: `the_target_never_keeps_an_unencoded_password` (both re-check inputs; they gave `https://FAKEtokPart1` and `https://def/ghi` before). DEC-T27-E-5.

### AUD-26 — Info — DEC-FIX5-4: the operator role is not in the slot wrap AAD

- **Location:** `crates/cerberus-crypto/src/slots.rs:44-51` (`slot_aad`: purpose, vault ID, slot ID, version 0);
  `crates/cerberus-core/src/vault/custody.rs:360-376` (viewer when the header MAC fails)
- **Judgement:** The current control is correct. An attacker with no key who edits `key_slots.role` breaks the
  header MAC, and the session becomes `viewer`. `save_slots` refuses to sign an edited file again. A binding of the
  role in the wrap AAD **adds no security**. Any operator who has the file and the own phrase can unwrap the VMK
  offline. That operator can then derive `header_key`, edit the role and sign the header again, or read every item
  directly. No AAD can stop a key holder. Roles are a policy against people who have no file access, not a
  cryptographic boundary (AR-9). No change to the slot format is needed.
- **Recommended action:** Close the "follow-up, not done" text in DEC-FIX5-4. State in the docs (T28) that operators
  who share the OS account with the vault file are not limited by their role.
- **Owner:** Crypto Smith (docs)
- **T27 fix (T27-A1):** Accepted, as the judgement says; no format change. DEC-FIX5-4 is closed, and AR-9 in the threat model now says that an operator who shares the OS account with the file is not limited by the role. T28 repeats it in the guide. DEC-T27-A1-8.

### AUD-27 — Info — INT10 "Keep payload" rewrites the history snapshot of the current version

- **Location:** `crates/cerberus-core/src/items/service.rs:668-698`, `:737` (`Tx::update_version_meta`);
  DEC-INT10-6
- **Judgement:** No effect on secrecy, row MACs or the chain:
  - The snapshot is sealed with AEAD under (item, version), so a file attacker cannot move it.
  - Items have no row MAC.
  - `item.update` is written with `version` and `payload: "kept"`.
  - The lease end on a move between environments or workspaces, the `max_uses`, the expiry and the `use_count`
    carry-over are the same as for a replace.
  The only loss is history detail: the history no longer shows the old title or environment of the current version,
  and the audit event does not list the changed fields. An operator could move an item from `prod` to `staging` and
  back, and the history would not show it (the audit shows two updates, and the approval leases end).
- **Recommended action:** Add the names of the changed fields (not their values) and the old and new environment
  and workspace IDs to `item.update` details.
- **Owner:** Crypto Smith
- **T27 fix (T27-A1):** Fixed as recommended. `item.update` has `changed` (field names only), `old_environment`, `new_environment`, `old_workspace_id` and `new_workspace_id`, also for `Keep`. Test: `aud27_item_update_names_the_changed_fields`. DEC-T27-A1-9.

### AUD-28 — Info — Dependency advisories and the ignore claims

- **Results:**
  - `cargo audit` with no flags fails with 3 vulnerabilities: RUSTSEC-2026-0387, RUSTSEC-2026-0459, RUSTSEC-2023-0071.
  - `just audit` (with its four ignores) passes, with 7 "unmaintained" warnings allowed.
  - `cargo deny check` passes: advisories, bans, licenses and sources are all ok.
- **RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2026-0387 (`crypto-bigint`):**
  `cargo tree -e normal,build -i rsa --workspace` and the same for `crypto-bigint`, also with `--target all`, print
  nothing. The claim "not compiled" is **true**. These crates are only in the lock file.
- **RUSTSEC-2024-0429 (`glib` 0.18.5, unsound):** `glib` **is compiled** on Linux through gtk, tray-icon and tauri.
  No Cerberus code calls `glib` or `VariantStrIter`. The claim "not reachable from our code" is **plausible**: Tauri
  and GTK code paths were not audited (AR-16).
- **RUSTSEC-2026-0459 (`libsqlite3-sys` 0.37.0):** compiled and reachable. The mitigation is partial (AUD-10).
- **Recommended action:** Keep the ignores, correct the text for the sqlite ignore, and check again on each sqlx
  release.
- **Owner:** Rust Builder
- **T27 fix (T27-B):** `.cargo/audit.toml` holds the same ignores with reasons, and `just audit` is plain `cargo audit`. All claims were checked again. The sqlite ignore text says "partial mitigation". DEC-T27-B-8.

### AUD-29 — Info — systemd unit: more hardening is possible

- **Location:** `packaging/systemd/cerberusd.service`
- **Present and correct:** `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `MemoryDenyWriteExecute`, `RestrictAddressFamilies` (with `AF_UNIX`), `LimitCORE=0`, `UMask=0077`, and an empty
  `CapabilityBoundingSet`.
- **Recommended additions:** `SystemCallFilter=@system-service` with `~@privileged @resources`,
  `ProtectProc=invisible`, `ProcSubset=pid`, `RemoveIPC=yes`, `PrivateUsers=yes`, and, for a loopback-only
  deployment, `IPAddressDeny=any` with `IPAddressAllow=localhost`.
- **Owner:** Rust Builder
- **T27 fix (T27-B):** Syscall filter, `ProtectProc=invisible`, `ProcSubset=pid`, `RemoveIPC`, `PrivateUsers` and the loopback IP allow list were added to `packaging/systemd/cerberusd.service`. DEC-T27-B-9.

### AUD-30 — Info — Small items with no direct exploit

- `crates/cerberus-api/src/tls.rs:369-380`: `write_private` uses `mode(0o600)` only when it makes the file. A
  temporary file that already exists keeps its old mode. Use `create_new` or `fchmod`.
- `crates/cerberus-crypto/src/token.rs` (`hint`): the last 4 characters (24 bits) of the token secret are stored in
  plain text. This is acceptable for 256 bits.
- `crates/cerberus-ssh-agent/src/dirs.rs:55-63`: the stale-socket clean-up uses `kill(pid, 0)`. In another PID
  namespace that shares `XDG_RUNTIME_DIR`, it can remove the sockets of a live bridge.
- `crates/cerberus-client/src/commands.rs:140-156`: `get --show-secret` does not release its lease.
- `crates/cerberusd/src/daemon.rs:89-116`: the modes of the data directory and the vault file are not checked on a
  manual run (systemd sets them).
- `apps/desktop/src-tauri/src/ops/generate.rs:63`: `dedup()` without a sort leaves repeated character classes, which
  makes the generated passwords less uniform.
- `crates/cerberus-store/src/store.rs:181-183`: an old `.pre-migrate-vN` file blocks the open (dormant while only
  migration 0001 exists). Audit prune is never called (ADR-0025 says daily).

**Owner:** Rust Builder, except the generator item (Tauri Builder).
- **T27 fix (T27-B):** Done for `write_private` (`aud30_a_stale_loose_temp_file_does_not_set_the_key_mode`), the ssh-agent stale-socket clean-up (lock file), `get --show-secret` lease release, and the `cerberusd` mode check. The `.pre-migrate` and audit prune items are in the store and core (T27-A1). DEC-T27-B-10.
- **T27 fix (T27-C, generator item):** `password` removes a repeated class by a seen-list, so the mix is uniform (digit share 0.278 for lower and digits, was 0.165). Test: `a_repeated_class_does_not_change_the_mix`. DEC-T27-C-8.

### AUD-31 — Info — The pin moves to the custom chain

- **Location:** DEC-FIX9-1
- **Description:** With a custom certificate, the pin becomes the top certificate of the custom chain. That can be a
  public intermediate CA. The host name check still applies, so only someone who can get a public certificate for
  that name can attack. Tell the person this in the UI text for custom certificates.
- **Owner:** UI Builder
- **T27 fix (T27-C):** The custom certificate dialog and the in-use notice say that the pin is now the top certificate of the chain and that a public intermediate CA lets anyone with a certificate for the same host name pass. Test in `settings.test.tsx`. DEC-T27-C-8.

### AUD-32 — Info — DEC-FIX8-5 (`ssh_prepare` decrypts on the write guard)

- **Judgement:** It is not acceptable as it is, because an agent can choose the decrypt cost. AUD-3 covers it.
- **T27 fix (T27-A2):** Closed with AUD-3: the decrypt no longer runs on the guard (DEC-T27-A2-3 replaces the last sentence of DEC-FIX8-5).

## 4. Checked and sound

**Crypto (`cerberus-crypto`):**

- The envelope uses XChaCha20-Poly1305 with a random 24-byte nonce per seal. The AAD is length-prefixed and holds the
  context, purpose, vault ID, record ID and version. Padding is to 64 bytes. Open checks the version, the length, the
  pad bytes and the tag (`envelope.rs`).
- The key tree is HKDF-SHA256 with the vault ID as salt and a distinct label per key. Known-answer vectors exist
  (`keytree.rs`).
- Argon2id parameters are range-checked in every build. The read-path cap on memory and passes protects against a
  header edit that would use too much memory. The fast test cost cannot compile into release (`kdf.rs:15-18`).
- The phrase policy (12 or more characters after NFKC, zxcvbn score 3 or more) is enforced inside
  `create_passphrase_slot` (`slots.rs`).
- Slot rules: one owner passphrase slot or more, one recovery slot or less, the recovery slot is owner, IDs unique.
  The slot AAD binds the vault and the slot ID.
- The recovery key is 256 bits, has a 3-byte checksum and is written straight into locked memory (`recovery.rs`).
- Tokens: strict parse, SHA-256 with a label over the agent ID and the secret (`token.rs`).
- `memlock`: per-page reference counts, zeroize on drop, not dumpable and `RLIMIT_CORE=0` on Linux,
  `PT_DENY_ATTACH` on macOS. `unsafe` exists only in `memlock/mod.rs` (a grep found no other `unsafe` block, and
  `unsafe_code = "forbid"` is set for the workspace).

**Core (`cerberus-core`):**

- Token check: 10 constant-work compares, a dummy hash for unknown agents, then the checks for revoked, expired,
  agent status, IP allowlist and mTLS binding (compared in constant time). The IP limit runs before the check, and
  the agent limit after a good token. No cache, so a revoke takes effect at once (`auth.rs:230-358`).
- Unlock: the header MAC is checked after the VMK opens. A mismatch gives the viewer role and the
  `vault.header_mismatch` event. The KDF does not run during back-off (`vault/custody.rs:298-450`).
- Policy: the reason is checked for presence only (8 or more characters). A deny grant wins. `prod` without
  `allow_prod_auto` is `ask_always`. The grant expiry is the earlier of the plain and the sealed value. A grant that
  does not parse becomes deny-all (`policy.rs`, `policy/body.rs`).
- The check order of the Agent API is: state, then scope, then policy. The secret read and its strict audit happen on
  one write guard. TOTP seeds are never returned (`agent_api.rs:476-570`).
- Leases are bound to the agent and the item. A lease serves a mode only when it fits it (`ask_always` needs a
  one-use approval lease). Approval leases end when an item moves (`leases.rs`).
- Row MACs cover the table, the vault and the row ID. Every decision reads its row and checks the MAC (helper
  review, spot-checked at `approvals/queue.rs:51` and `policy/engine.rs:605`).

**Audit chain:** the genesis hash is bound to the vault. Verify finds edits, reorders and gaps. Prune checks the chain
first. The drain is in the same transaction as the append. The export file is new with mode 0600 (except AUD-1).

**Store:** `secure_delete=ON`, `trusted_schema=OFF`, WAL. A read-only probe runs before any write. Backups and
pre-migrate copies are mode 0600 and must not exist before. A restore keeps the old file (`store.rs:115-120`,
`backup.rs`).

**API (`cerberus-api`):**

- TLS 1.3 only (no `tls12` feature, `with_protocol_versions(&[TLS13])`), and no plain HTTP listener.
- With mTLS, the client certificate needs the vault CA and EKU `clientAuth`. A LAN bind needs mTLS (`config.rs:94-96`).
- The Host allow list is checked. `Origin` and a cross-site `Sec-Fetch-Site` are refused.
- Errors use fixed messages. The JSON body parser gives no serde text. Body limits are checked before the read.
- No header, body or query is logged. The server makes every request ID (`layers.rs`, `routes.rs:95-140`,
  `error.rs`).

**MCP:** the tools call the same `AgentApi` functions. Bad arguments get a fixed `invalid_request`. The log filter
pins `rmcp=warn` in `cerberusd` and in the desktop, and there is no `RUST_LOG` override. The shim refuses to start
without a CA or a pin.

**Client:**

- TLS 1.3 only. In pin-only mode, the pinned certificate is the only root, and webpki checks the chain, the dates
  and the SAN. `verify_tls13_signature` is called.
- The token never comes from argv. The token file must be mode 0600. `get` and `totp` hide values by default.
- SSH keys cannot go into an environment. The temporary storage-state file is new with mode 0600. Signals are
  forwarded.

**cerberusd:**

- The config file must be mode 0600.
- The unlock socket is 0600, checks the peer UID (`SO_PEERCRED`) and has an 8 KiB request limit.
- A LAN bind needs mTLS. The log level is fixed.

**ssh-agent:**

- The directories are 0700, have the right owner and are not symlinks. The sockets are 0600, and the peer UID is
  checked.
- Frames have limits. Only `REQUEST_IDENTITIES` and `SIGN_REQUEST` are served.
- The user-auth parse is strict. The key opens per signature in `spawn_blocking`.

**Desktop (`src-tauri`):**

- Every one of the 67 `ops` functions checks the window label first. The approval list matches `approval.json`.
- The role always comes from the session, never from the UI.
- The CSP is strict (`script-src 'self'`, no `unsafe-inline` or `unsafe-eval` in release), with `freezePrototype`.
  There is no `withGlobalTauri`, no remote URL, no asset protocol, no `fs:` permission, and no `devtools` feature
  in release.
- New files use `O_EXCL` with mode 0600.
- Held values and drafts are bound to the session. `clipboard_copy_secret` needs the operator role, is audited and is
  for the main window only.

**UI:** no `dangerouslySetInnerHTML` and no `innerHTML`. No `href` is built from agent text. `UntrustedText` shows
plain text. Secrets live only in component state, and the token reply does not go through the mutation cache.
localStorage holds view preferences only. The dev mock is behind `import.meta.env.DEV` and is not in `dist/`.

**Ignore claims:** `rsa` and `crypto-bigint` are not compiled (AUD-28).

## 5. Proofs run (outside the repository)

| Finding | What was run | Result |
|---|---|---|
| AUD-3 | Scratch crate with `ssh-key` 0.6.7 (`ed25519`, `encryption`): patch the bcrypt rounds of an encrypted key, parse, decrypt | Parse accepts any round count, including `u32::MAX`. The public key is unchanged. Decrypt time is linear (16 rounds 0.10 s, 256 rounds 1.6 s, 1024 rounds 6.6 s). |
| AUD-4 | Scratch crate with `hyper-util` 0.1.21, the same auto builder, `http1().timer().header_read_timeout(1 s)` | A silent connection is still open after 5 s. A connection with a partial request line is closed by the timeout. |
| AUD-18 | Copy of the `run.rs` mask logic, two secrets where one starts with the other, split chunks (helper review) | The tail of the longer secret is printed. |
| AUD-28 | `cargo audit`, `just audit` flags, `cargo deny check`, `cargo tree -e normal,build -i <crate>` (also `--target all`) | As described in AUD-28. |

No test file was added to the repository. No secret value is in this report. All values in the proofs were fake.

## 6. T27 re-check (fresh auditor)

- Date: 2026-11-17. Read-only re-check of every "T27 fix" note against the code. Tests run (debug):
  `cargo test -p cerberus-core -- aud1 a_cut_tail a_deleted_head a_lock_does_not_wait_for_the_key_decrypt
  an_encrypted_key_with_too_many`, 7 of 7 passed. `cargo test --release -p cerberus-core` does not compile: the
  `insecure-test-kdf` dev feature is a `compile_error!` in release (`cerberus-crypto/src/kdf.rs:19`). So the doubt
  that the AUD-3 lock test (">100 ms for 16 rounds") fails under `--release` cannot happen. The test only runs in
  debug, where bcrypt is slow.
- Verdicts: **closed** = the issue as reported is fixed; **closed-accepted** = the rest is a written, justified
  acceptance; **partially closed** = the reported attack still works in a close variant; **open** = not changed.

| AUD | Orig. | Verdict | Residual | Reason (file:line) |
|---|---|---|---|---|
| 1 | Medium | closed | Low (NEW-2) | `chain_position` checks the head HMAC and the newest row's `seq` and hash before each append (`audit/writer.rs:247-314`). A cut with an edited head, a deleted head, a wiped log (`expecting_log`, `vault/custody.rs:385`) and a tail cut under a good head all chain a mark, which `verify.rs:238` reports for good. Replaying an *older genuine* signed head row after a cut is still not found, but that is single-row rollback, accepted in AR-1. The permanent mark instead of a refusal fits the audit's "new, marked segment" option. False `log_missing` after a failed `vault.create` write is accepted (Info). |
| 2 | Medium | closed | — | Sealed `kind` must equal `items.kind` (`index/meta.rs:258-262`). Every read compares the row with the index (`items/service.rs:1160`), and `open_current` checks the payload kind (`:1141`). The legacy upgrade trusts only the AEAD-authenticated payload, whose JSON is tagged by `kind` (`vault/checks.rs:47-57`, `items/payload.rs:290`). A replayed kindless `meta_ct` goes through the same check, so I found no bypass. |
| 3 | Medium | closed | Info | The round limit is checked at import, validation, prepare and sign (`items/ssh.rs:127-131`, `agent_api/ssh.rs:396`). The decrypt runs after `drop(guard)` on `spawn_blocking`, and the session is checked again (`agent_api/ssh.rs:594-614`). Test gap: no test drives a stored over-limit key through `ssh_prepare` or `ssh_sign` (only `validate_payload` and import are tested). Rest: each sign of an encrypted key still runs up to 1024 rounds (about 6 s CPU) on the blocking pool. That costs CPU only and does not stall the lock. |
| 4 | Medium | **partially closed** | **Medium** | The watcher counts only bytes that move (`cerberus-api/src/idle.rs:139-157`). One byte per <60 s keeps a connection, and the 24-byte h2 preface can be sent one byte at a time (about 24 min). After the preface, an h2 PING every 50 s keeps the connection for ever, with no request, so no rate limit applies. h2 is offered in ALPN (`tls.rs:963`), and no h2 keep-alive or timer is set (`server.rs:457-461`). The silent-connection case is fixed. A client with no token can still hold the slots. See NEW-1. |
| 5 | Medium | **partially closed** | **Medium** | The list (`cerberus-types/src/env.rs:12-82`) blocks the names the audit gave. Well-known code-run and redirect names pass both core and client checks: `OPENSSL_CONF`/`OPENSSL_MODULES`/`OPENSSL_ENGINES` (loads a provider `.so` into any OpenSSL child, the same as `LD_PRELOAD`), `*_OPTS` (`MAVEN_OPTS`, `JAVA_OPTS`, `GRADLE_OPTS` with `-javaagent:`; the suffix rule covers only `_OPTIONS`), `GOFLAGS=-toolexec=`, `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`/`CARGO_BUILD_RUSTC_WRAPPER`/`CARGO_TARGET_*_RUNNER`/`CARGO_HOME`, `CC`/`CXX`/`LD`, `KUBECONFIG` (exec plugin), `AWS_CONFIG_FILE`/`AWS_SHARED_CREDENTIALS_FILE` (`credential_process`), `GOOGLE_APPLICATION_CREDENTIALS` plus `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`, `CLOUDSDK_PYTHON`, `DOCKER_HOST`/`DOCKER_CONFIG`, `DOTNET_STARTUP_HOOKS`/`CORECLR_PROFILER_PATH`, `LUA_INIT`, `PHPRC`/`PHP_INI_SCAN_DIR`, `GRADLE_USER_HOME`, `JAVA_HOME`, `TF_CLI_CONFIG_FILE`, `ANSIBLE_CONFIG`, `PIP_INDEX_URL`/`PIP_CONFIG_FILE`, `YARN_*`, `VIMINIT`/`EXINIT`, `SUDO_ASKPASS`, `SSLKEYLOGFILE` (TLS keys of the child to a file), and on Windows `COMSPEC`/`PATHEXT`/`PSModulePath`. The AUD-5 exploit works unchanged with `MAVEN_OPTS=-javaagent:/tmp/a.jar` or `OPENSSL_CONF=/tmp/a.cnf`. A deny list cannot be complete; agent-written items need an allow rule (for example only names that `--var` maps, or a person's confirmation). |
| 6 | Low | closed | — | `checked_item` compares `current_version` with the index version before the open and before the count (`items/service.rs:1160`). |
| 7 | Low | closed | Low (NEW-3) | The MAC is verified before the re-sign (`cerberus-store/src/tx.rs:665-668`). A row that does not parse still fails the whole call (NEW-3). |
| 8 | Low | closed | — | `delete_sealed_expired` after the unlock and after each sweep. The guard is dropped before the checkpoint (`vault/checks.rs:150-199`). |
| 9 | Low | closed | — | Malformed rows are skipped and counted. Only the locked-time types are accepted (`audit/writer.rs:94-102`). A failed drain raises the alert (`custody.rs:404-410`). |
| 10 | Low | partially closed | Low | Single copy, staging, mutex and rollback are fine (`ops/restore.rs:138-205`). Still open: `swap_files` (`cerberus-store/src/backup.rs:184-197`) returns `?` after the old vault (or its `-wal`) was moved, so the moved path is lost and `roll_back` is not reached. The desktop then reopens an empty path, and the old vault stays in `.pre-restore-*` (found by hand). Rare: a rename in the same folder. |
| 11 | Low | closed | — | Rust-side picker, and one reader with one error text (`ops/files.rs:72`). The JS `dialog:allow-open` path is never added to the picked list. |
| 12 | Low | closed | — | `capabilities/*.json` hold only the event, listen and version permissions plus the dialog permissions. |
| 13 | Low | closed | — | Key create, and rotate of an unbound key, are refused off loopback (DEC-T27-C-4). The `auth.rs` second layer is optional. |
| 14 | Low | closed | Info (NEW-4) | Clipboard clear and `try_lock` wipe (`state.rs:238-251`). `[profile.release] panic = "abort"` (`Cargo.toml:140`). |
| 15 | Low | closed | — | `.content_protected(protected)` (`windows.rs:41`). The test is a source check, which is the only check possible. |
| 16 | Low | closed-accepted | Low | Linux `LockedHint` and the delay inhibitor are added. The macOS and Windows gap is accepted in ADR-0026 and the threat model. |
| 17 | Low | closed | — | Only certificates that match the pin are roots (`cerberus-client/src/tls.rs:207-218`). |
| 18 | Low | closed | — | Hold-back plus longest-first (`run.rs:480-503`). Every secret field is a needle. |
| 19 | Low | partially closed | Low | Not dumpable on Linux only (`run.rs:668-671`). On macOS (sysctl `KERN_PROCARGS2`) and Windows (same-user `PROCESS_VM_READ`), the child can still read the parent's first environment, which holds `CERBERUS_TOKEN` when the token was given that way. |
| 20 | Low | closed-accepted | — | `Zeroizing` buffers and phrase (`cerberusd/src/unlock.rs:40`). The `serde_json` copy for escaped phrases is accepted. |
| 21 | Low | closed | — | Strict SSHSIG parse, and the namespace is checked before the budget is used (`agent_api/ssh.rs:347-358`, `:785-794`). |
| 22 | Low | closed | — | Gate order is request then lease, with no inverse path (`policy/engine.rs:453-454`). Every caller of `authorize_secret_in` already holds the exclusive vault **write** guard, so the extra gate adds no new serialization. The "global gate on every read" concern is unfounded. |
| 23 | Low | closed | — | MCP `untrusted_fields` and `UNTRUSTED:` text. Operator-first resolve uses the sealed `created_by` (DEC-T27-A2-5). |
| 24 | Low | closed | — | `strip_format` and `strip_hidden` (`cerberus-types/src/text.rs:35-56`). The UI uses `<bdi>` plus visible codes. |
| 25 | Low | partially closed | Low | `target_of` (`csvio/rows.rs:88-102`) cuts the authority at the first `/` before it looks for `@`, and cuts `?`/`#` first. `https://user:pa/ss@host/x` is returned **unchanged** (the whole user name and password, not part of it). `https://user:p?ss@host/` gives `https://user:p`. This is correct for RFC-valid URLs, but exports hold unencoded passwords. Fix: drop everything up to the last `@` that comes before the path, query or fragment, or refuse such a URL. |
| 26 | Info | closed-accepted | — | Judgement accepted (AR-9). |
| 27 | Info | closed | — | `changed` and the old and new env/workspace fields are in `item.update`. |
| 28 | Info | closed | — | `.cargo/audit.toml` ignores have reasons, and `just audit` is plain `cargo audit`. |
| 29 | Info | closed | — | Unit hardening is added. `SystemCallErrorNumber=EPERM` (`cerberusd.service:52`), so `~@resources` (`setrlimit`) gives EPERM, not SIGSYS. `LimitCORE=0` covers it. |
| 30 | Info | partially closed | Info | `write_private`, the ssh-agent lock file, the lease release and the `cerberusd` mode check are done. Still open: `.pre-migrate-vN` still blocks the open (`cerberus-store/src/store.rs:186-189`, dormant), and audit prune is still never called. After any AUD-1 mark, prune can never run anyway (`writer.rs:143-148`). |
| 31 | Info | closed | — | UI text is added. |
| 32 | Info | closed | — | Covered by AUD-3. |

### New findings

- **NEW-1 — Low — `max_connections_per_ip` makes the AUD-4 lockout cheaper on loopback.**
  `crates/cerberus-api/src/server.rs:342` with `config.rs:52` (64). Every local agent connects from `127.0.0.1`. A
  local user with no token opens 64 TLS connections from `127.0.0.1` and keeps them alive (AUD-4 rest: h2 PING or one
  byte every <60 s). After that, every new agent connection from `127.0.0.1` is closed at once. The project's own test
  `aud4_one_ip_cannot_hold_every_connection` shows the third same-IP connection refused. Before T27 the attacker
  needed 256 connections. The cap can also be bypassed by binding other `127.0.0.0/8` source addresses (Linux), so it
  does not protect the 256 global slots either. Confidence: confirmed by code and test reading; not run.
  - **T27-D fix (T27-D2):** The per-IP cap is removed. Unauthenticated connections have a budget of their own (64 of 256), authenticated connections are never evicted, and a new connection evicts the oldest unauthenticated one of the busiest source instead of being refused or waiting. All of `127.0.0.0/8` and `::1` (and v4-mapped forms) is one source, an IPv6 address counts by its `/64`. So 64 held loopback connections no longer lock agents out: the agent's connection takes the oldest slot. Left: a non-stop connect flood can still win the race against an agent's handshake (a CPU-costly local flood). Tests: `aud4_an_agent_gets_in_while_unauthenticated_clients_hold_every_slot`, `new1_another_loopback_address_gets_no_separate_budget`. DEC-T27-D2-2.
- **NEW-2 — Low — The first break mark hides every later break from `verify_chain`.** `audit/verify.rs:238` (a mark is
  reported as `HeadMismatch`, and the walk stops at the first problem). With T27, marks are permanent (DEC-T27-A1-1), and
  one can come from the accepted false `log_missing`. Scenario: after any mark at seq N, a file attacker deletes or
  edits middle rows after N. The operator's "Verify chain" and the check after unlock report the same `Broken { seq: N }`
  as before, and the alert is the same, so nothing new is shown. Tail cuts are still found by the writer check. Fix:
  make the walk go on past a mark and report the first break that is not a mark (or every break).
  Confidence: confirmed by code trace.
  - **T27-D fix (T27-D1):** The walk goes on past a break mark (and past the `seq` gap that a cut-tail mark follows) and reports the first later problem that is not a mark; with only marks the report is the same as before. Tests: `new2_a_break_mark_does_not_hide_a_later_break`, `new2_an_edit_after_a_head_mark_is_reported`. DEC-T27-D1-4.
- **NEW-3 — Low — One unparseable `leases` or `access_requests` row makes the panic revoke fail at every try.**
  `cerberus-store/src/tx.rs:664` (`LeaseRow::from_sql(..)?` before the MAC check). A file attacker inserts a lease row
  with a bad UUID or an unknown `permission` text (foreign keys are not enforced by the attacker's SQLite tool). Then
  `before_erase` fails (`vault/mod.rs:554-567`), the revoke is deferred, and `finish_deferred_panic` fails the same way
  at each unlock (`custody.rs:519-527`). The genuine leases of a stolen token stay live after "Lock and revoke all".
  This is the AUD-9 class, which T27 fixed for `audit_pending` but not here. Fix: skip and report rows that do not
  parse, as for `bad_mac`. Confidence: plausible (traced, not run).
  - **T27-D fix (T27-D1):** Revoke-all and cancel-pending skip a row that cannot be read, count it (`malformed`) and revoke or cancel the rest. The caller writes `integrity.row_mac_mismatch` with the count and raises `IntegrityAlert` for the table. The operator "revoke all" no longer fails on such a row either. Tests: `an_unreadable_row_does_not_stop_revoke_all_or_cancel_pending` (store), `new3_an_unreadable_lease_row_does_not_block_the_panic_revoke` (core). DEC-T27-D1-3.
  - **T27-E fix (after the T27-D re-check):** The rest (a genuine lease or pending request whose `items` or `agents` row was deleted with foreign keys off) is closed: revoke-all and cancel-pending now write with an `UPDATE` of only the revoke/cancel columns and the MAC, never `agent_id`/`item_id`, so SQLite runs no foreign-key check and the row is revoked and signed like the others. Test: `a_lease_whose_parent_row_is_gone_is_still_revoked` (store; `revoke_all_leases` failed with `Conflict` before). DEC-T27-E-4.
- **NEW-4 — Info — `panic = "abort"` in release also covers `cerberusd` and the API server.** `Cargo.toml:140`. A panic
  that any client can trigger in a connection or route task now ends the daemon, where tokio used to contain it. I
  found no such panic: the scan of the T27-changed files found no non-test `unwrap`, `expect` or `panic!`. Record it as
  a trade-off of AUD-14.

**Still open at Medium or higher:** AUD-4 (partially closed, Medium) and AUD-5 (partially closed, Medium).

**Verification assessment:** The AUD-1, AUD-2 and AUD-3 tests exercise the changed paths, and they passed when I ran
them. The AUD-4 tests cover only a fully silent connection and an idle keep-alive. No test trickles bytes or sends h2
PINGs, so they do not show that slot exhaustion is prevented. The AUD-5 tests check only the names on the list, so
they cannot show the list is complete. The AUD-25 test uses only valid URLs. The AUD-3 lock test depends on timing,
but it runs only in debug (release cannot compile it).

## 7. T27-D re-check (fresh auditor)

- Date: 2026-11-17. Read-only re-check of every "T27-D fix" note (AUD-4, AUD-5, AUD-25, NEW-1, NEW-2, NEW-3) against
  the code and DEC-T27-D1-1..4, DEC-T27-D2-1..2. Tests run (debug, one cargo command at a time), all passed:
  `cargo test -p cerberus-api -- aud4 new1 every_loopback an_ipv6 a_full_budget an_authenticated_connection an_evicted
  a_freed` (6 unit + 8 real-TLS), `cargo test -p cerberus-core -p cerberus-store -p cerberus-types -p cerberus-client --
  new2 new3 an_unreadable_row agent_items_may_set the_recheck_code_load the_target_never_keeps every_dropped_note aud5`
  (13), and `cargo test -p cerberus-api --test api -- repeated_bad_tokens_lock_the_ip_out` (1, for NEW-5). Scratch
  proofs outside the repository: `url_parts`/`target_of`/`host_of` copied into a stand-alone program (AUD-25), and a
  Python `sqlite3` run of the `put_lease` upsert against a lease whose parent row is gone (NEW-3). All values fake.
- Verdicts as in section 6.

| ID | Verdict | Residual | Reason (file:line) |
|---|---|---|---|
| AUD-4 | closed | Low (NEW-6) | Deadlines count requests only: first head due `header_timeout` after the handshake, `auth_timeout` (30 s) from accept for every unauthenticated connection even while a request runs, idle counts authenticated requests only (`cerberus-api/src/idle.rs:203-240`). The handshake itself has its own 10 s (`server.rs:389`). Bytes, a slow preface, PING/SETTINGS/WINDOW_UPDATE, an unfinished HEADERS+CONTINUATION, and up to 200 open streams on one connection all end at the 10 s or 30 s mark. Only `Ok(ctx)` of `auth().check` marks the connection (`layers.rs:155-169`); the agent rate limit is inside `check`, so a refused call never marks it. A connection evicted first cannot become authenticated (`idle.rs:96-107`, CAS). SSE stays open (`hold_until_sent`, test passes). Not fixed by this round, but a cheaper way to the same outcome exists: see NEW-5. |
| NEW-1 | closed-accepted | Low | Eviction is CAS-guarded, so an authenticated connection is never evicted (`idle.rs:111-125`, `:334-352`); loopback, `::1` and v4-mapped forms are one source, IPv6 by `/64` (`idle.rs:250-262`). The accepted race is cheaper than DEC-T27-D2-2 says: eviction happens at accept, before the TLS handshake (`server.rs:340-348`), so the flood is plain TCP connects with no TLS cost. About 64 connects in the agent's few-millisecond handshake-plus-first-request window are enough. Still a busy local flood, so Low. Two Info points are in NEW-7. |
| AUD-5 | closed | Low | Agent creates need the allow rule (`cerberus-types/src/env.rs:181-195`), checked in core before anything else (`cerberus-core/src/agent_api.rs:828`, `items/validate.rs:114-129`). The client applies the same function to every item whose `created_by` is not `operator:` (`cerberus-client/src/run.rs:233-243`, `:698`). Agents have no update, import or rename path. `update` takes an `OperatorContext` and keeps `old.created_by`, and `delete` checks ownership. `create_session` goes through the same `create`, and `created_by` comes from the sealed meta as `agent:<uuid>`, so it cannot be forged. Non-ASCII names fail the shape check, and case is folded with ASCII rules. I found no `*_TOKEN/_KEY/_SECRET/_PASS*/_USER/_CLIENT_ID` name that loads code: `*_FILE`, `*_COMMAND`, `*_CONFIG` and `*_URL` do not match the suffixes, and `GIT_CONFIG_KEY_n` is caught by the `GIT_` prefix. Rest (AR-15 "mislead", not code-run): the allowed exact names `DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `SENTRY_DSN` and credential swaps (`AWS_*`, `GITHUB_TOKEN`) can send the child's traffic or data to an attacker host or account. A `database` item already sets `DATABASE_URL`, so this is not new. |
| AUD-25 | partially closed | Low | The colon case is fixed (`csvio/rows.rs:109-128`). Two variants still leak (proved with a copy of the code). (1) A user info with no `:` that has a `/` (a token used as the user name): `https://FAKEtokPart1/FAKEpart2@github.com/x` gives target `https://FAKEtokPart1` and title `FAKEtokPart1`. The `plain_host(authority)` branch (`:127`) takes the token's first segment as host. (2) An `@` in the query after an unencoded password: `https://user:pa/ss@host/x?token=abc@def/ghi` gives target `https://def/ghi`. `rsplit('@')` over the whole text (`:120`) takes part of the query value. Fix: in the ambiguous case, take the host only from after the last `@` that comes before the first `?`/`#` *after* it, and refuse (no target) when the RFC authority is a dot-less plain host. |
| NEW-2 | closed | Info | The walk goes past marks (`audit/verify.rs:185-199`). A gap counts as a cut only when the row after it is a mark whose `prev_hash` is the hash of the row before the gap and whose HMAC is good (`check_row`, `:249-272`). A file attacker has no audit key, so cannot forge one. Deleting rows before a genuine cut changes the reported `seq`, and re-inserting old rows breaks the mark's `prev_hash`. Rest (Info): a *second* tail cut, made after an earlier mark, gets its own genuine mark. `verify_chain` then still returns the *first* mark (`:223`), so "Verify chain" and the post-unlock alert look unchanged. The second cut is shown only by the writer's alert when it chains the mark (`audit/writer.rs:357-358`) and by the mark event in the log. |
| NEW-3 | partially closed | Low | Rows that do not parse are now skipped and counted (`cerberus-store/src/tx.rs:668-673`, `:740-744`), and the alert is raised (`vault/checks.rs:154-177`). The same failure is still reachable from a row that *does* parse: `put_lease(..)?` / `put_access_request(..)?` (`tx.rs:682`, `:752`) is an UPSERT that sets `agent_id`/`item_id`, and `foreign_keys` is on (`store.rs:118`). A file attacker deletes the `items` (or `agents`) row that a live, genuine lease points to, using a SQLite tool where foreign keys are off by default (no cascade). The re-sign of that lease then fails with `FOREIGN KEY constraint failed` (checked with SQLite 3.51), and the whole `revoke_all_leases` fails. The lock still happens (`vault/mod.rs:491-497`), the revoke is deferred, and it fails the same way at each unlock (`custody.rs:519-527`), so the other leases of a stolen token stay live. Same result and the same attacker as NEW-3. Fix: run each row's write in a savepoint and count a failure like `malformed`, or check that the parent exists and skip and report. Confidence: plausible (SQLite behaviour confirmed, core path traced, not run end-to-end). |

### New findings (T27-D re-check)

- **NEW-5 — Medium — With no token, a local user can lock every loopback agent out with 10 requests per 5 minutes.**
  `crates/cerberus-core/src/auth.rs:345-355` (the per-IP lockout is checked before the token, so a good token is
  refused too), `:370-372` (every failure is counted per IP), `auth/limits.rs:130-138` (`ip_key` keeps
  `127.0.0.1` as one key), defaults `limits.rs:40-46` (10 failures in 300 s, then 300 s lockout). Every local agent
  connects from `127.0.0.1` (or `::1`), the same key as any other local OS user (ATK-3). Scenario: the attacker sends
  10 requests with `Authorization: Bearer x` to `https://127.0.0.1:7373/v1/status`, and 10 more to `[::1]`, every
  300 s. Each legitimate agent then gets `429 too_many_failures` on every call, for as long as the attacker keeps
  going. The project's own test `repeated_bad_tokens_lock_the_ip_out` (`crates/cerberus-api/tests/api.rs:502-521`)
  shows this: after the bad tokens, `fx.token` from the same IP gets 429 (I ran it, it passed). The outcome is the
  same as AUD-4 (agents cannot read credentials, and approvals cannot reach them), and the attack is far cheaper:
  about 20 requests per 5 minutes, with no slot to hold. It is the same class that DEC-T27-D2-2 gives as the reason
  to remove the per-IP connection cap ("on loopback ... a per-source cap is a lockout tool"), but that reasoning was
  not applied to the per-IP auth lockout or to the pre-auth per-IP bucket (30/s, burst 60, `auth.rs:346-350`). A
  local user can also drain that bucket, which is a CPU-cheap variant. Fix: never refuse a token that verifies
  because of the IP lockout (with a 256-bit secret, the lockout protects nothing against a correct token). That
  means verifying first and applying the lockout only to failing calls, or keying the lockout and the pre-auth
  bucket by the claimed agent ID on loopback. Add an API test: a bad-token burst from loopback, then a good token
  still gets 200. Confidence: confirmed (code and a passing test that shows the lockout of a good token).
  - **T27-E fix:** The token is verified first; a good token is limited per agent only and is never refused by a source limit. The per-IP lockout, the per-IP bucket and a new global lockout (100 failures from all sources in 300 s) apply only to checks that failed: further failing checks get `429 too_many_failures` (or `rate_limited`), with bounded memory (past 4096 sources, new ones share one entry), and are still audited in `auth.failed` once per IP per minute with the count. Brute force stays impractical because of the 256-bit secret. Tests: `repeated_bad_tokens_lock_the_ip_out` (now asserts `200` for the good token after the lockout), `new5_a_bad_token_flood_from_loopback_does_not_lock_out_an_agent` (api), `new5_a_bad_token_flood_never_locks_out_a_good_token`, `new5_failures_from_many_sources_hit_the_global_limit`, `new5_the_failure_table_stays_bounded` (core). DEC-T27-E-1.
- **NEW-6 — Low — Any token holder can pin all 256 connections for good, and revoking its key does not free them.**
  `crates/cerberus-api/src/idle.rs:211-214` (an authenticated connection with a request in flight is never idle),
  `:155-162` (`hold_until_sent` holds the guard until hyper drops the body). In hyper 1.12
  (`proto/h2/mod.rs` `PipeToSendStream`), the body chunk is buffered and the pipe waits in `poll_capacity`. So an
  h2 client that sets `SETTINGS_INITIAL_WINDOW_SIZE = 0` keeps any non-empty response "running", even a `403
  insufficient_scope`. Scenario: a prompt-injected agent with any valid token (any scope) opens 256 h2 connections and
  makes one call on each (about 7 s within its 40-burst, 20/s limit), then never opens its window. All slots are now
  authenticated and in flight, nothing is evictable, and new agent connections wait in the backlog
  (`server.rs:347-353`). Revoking the key does not help: no deadline applies to an authenticated, in-flight
  connection, and nothing closes connections on revoke. Only a restart of the app or daemon does, which contradicts
  the acceptance in DEC-T27-D2-2 ("the person can revoke its key"). Fix: give an in-flight response a write
  deadline (no progress on the body for N s closes the stream or connection), cap authenticated connections per
  agent, and close an agent's connections when its key is revoked or the agent is disabled. Confidence: plausible
  (traced in the code and in hyper's source, not run).
  - **T27-E fix:** (1) Per-agent cap: one agent (all its keys) may have at most `max_connections_per_agent` (32) authenticated connections; a good token on a further one gets `429 rate_limited` and that connection stays unauthenticated (deadlines and eviction apply). (2) `send_timeout` (30 s): a response that hyper has not pulled more of for 30 s (client does not read, or h2 window 0) closes the connection; an SSE stream waiting for its next event does not count. (3) The connection watcher checks every second that the connection's key is still live and closes it when the key is revoked or expired or the agent is not active. Tests (real TLS): `new6_a_response_the_client_never_takes_closes_the_connection`, `new6_one_agent_cannot_hold_every_connection`, `new6_revoking_a_key_closes_its_connections`. DEC-T27-E-2.
- **NEW-7 — Info — Small points in the new admission and deadline code.** (a) `wait.clamp(5, step)`
  (`idle.rs:238`) panics when any of `header_timeout`/`auth_timeout`/`idle_timeout` is under 5 ms (`step < 5`). With
  `panic = "abort"` that ends the daemon. Today the limits are set only in code (defaults are seconds), so this is
  not reachable from a setting. Use `wait.max(5).min(step.max(5))`, or validate the limits. (b) On the wait path
  (`server.rs:347-353`) the new connection's `Activity` and its `auth_timeout` start at accept, but it is served only
  when a permit frees. After a wait of 30 s or more (every slot authenticated, see NEW-6), `watch` closes it as
  `NotAuthenticated` right after its handshake, before its first request. While it waits, the other listener's
  accept loop can also evict it, and that frees no permit. (c) If the chosen victim authenticates between `retain`
  and `evict` (`idle.rs:309-316`), no other connection is evicted that round, so a full server waits for the next
  close. None of these let an unauthenticated client hold a slot beyond the deadlines.
  - **T27-E fix:** (a) the sleep bounds are floored at 5 ms, so no limit can make `clamp` panic (`tiny_limits_do_not_panic`); (b) a connection that waited for a slot gets its `auth_timeout` from when it got the slot (`the_auth_time_starts_when_the_slot_is_free`); (c) when the chosen victim authenticated after the prune, the next one is evicted (`a_victim_that_authenticated_does_not_stop_the_eviction`). Not changed: a waiting connection can still be evicted by the other listener (it ends at once when served). DEC-T27-E-3.

**Still open at Medium or higher (whole report):** NEW-5 (Medium). AUD-4 and AUD-5 are closed by this round. AUD-1,
AUD-2 and AUD-3 stay closed (section 6).

**Verification assessment:** The D2 tests use real TLS and exercise the changed paths. They cover a byte trickle, an
h2 PING-only client, the auth deadline while a request runs (and a token connection that outlives it), an SSE stream
that outlives the idle time, the server-full eviction path, and the shared `127.x` source; the 14 tests passed when I
ran them. Gaps: no integration test fills the `max_unauthenticated` budget while the server is not full (only the unit
test does). No test holds an authenticated connection with a zero h2 window (NEW-6). No test checks a good token after
a bad-token burst, and the one that exists asserts the lockout (NEW-5). The D1 tests exercise their paths: core refuses
the names (`agent_items_may_set_only_credential_env_names`), the client applies the rule by `created_by`, NEW-2 covers
a cut tail with an edit or delete after it and a changed head with an edit after it, and NEW-3 covers a bad-UUID lease
row on the panic path. They do not cover the AUD-25 variants above (a token as the user name with a `/`, or an `@` in
the query), a second tail cut after a mark (NEW-2 rest), or a lease that parses but has lost its parent row (NEW-3 rest).

## 8. T27-E re-check (fresh auditor)

- Date: 2026-11-17. Read-only re-check of the "T27-E fix" notes (NEW-5, NEW-6, NEW-7, NEW-3 rest, AUD-25 rest)
  against the code and DEC-T27-E-1..5, plus the `backup_and_restore_round_trip` flake. Tests run (debug, one cargo
  command at a time), all passed: `cargo test -p cerberus-api -- new5 new6 repeated_bad_tokens tiny_limits
  the_auth_time a_victim one_agent_binds a_response_waits` (5 unit, 2 api, 3 real-TLS) and `cargo test -p
  cerberus-core -p cerberus-store -- new5 key_active_follows a_lease_whose_parent the_target_never_keeps lockout_after
  per_ip_rate ipv6_addresses` (9). Flake: the `ops` test binary was run 30 times in a row and 192 times as 8 rounds
  of 24 parallel copies; it never failed, so the cause below is from reading the code, not from a reproduction.
- Verdicts as in section 6.

| ID | Verdict | Residual | Reason (file:line) |
|---|---|---|---|
| NEW-5 | closed | Low (NEW-8) | The token is verified before any limit (`cerberus-core/src/auth.rs:364-380`). A good token only takes from the per-agent bucket. The source bucket, the per-IP lockout and the global lockout are only reached from `failed()` (`:384-403`), and `layers.rs:156` is the only caller of `check`. So no per-IP limit before auth can refuse a valid token. The compare is constant-time: 10 slots, `subtle` `ct_eq`, a dummy hash for unknown agents (`auth.rs:413-426`). The only branches that depend on the data come after a SHA-256 preimage match. Unknown agent and wrong secret take the same failure path, and the agent ID is public anyway (`cvt_<id>.<secret>`). The secret is 32 bytes from the OS RNG (`cerberus-crypto/src/token.rs:30-34`, `:90-104`), so guessing is impractical and needs no lockout. The global lockout (100 failures in 300 s) cannot lock out a valid agent. A local user can hold it on for good: `ip_key` does not fold `127.0.0.0/8` (`auth/limits.rs:203-211`), so 10 loopback source addresses reach 100. The only effect is that a legitimately failing check (an expired key, a mistyped token) gets `429 too_many_failures` with `Retry-After` up to 300 s instead of `401`, which misleads diagnostics (Info). The overflow entry only merges failing sources; `::1` masks to `::`, the same value as the overflow key (Info). The audit side is NEW-8. |
| NEW-6 | closed | Low | (1) The cap is checked and set under one lock (`cerberus-api/src/idle.rs:529-546`). A slot is freed by `close()` at the end of every connection task (`server.rs:369`, also after eviction or a cut) or when the `Weak` cannot be upgraded. I found no way for a slot to leak and lock an agent out of its own connections. (2) `Held` marks a response as waiting only between the hand-over or a frame and the next pull (`idle.rs:278-290`). An SSE stream that waits for its next event has no waiting entry, so `send_timeout` does not break SSE. The h2 window-0 test closes at about 600 ms, against 30 s idle, so it exercises the new rule. (3) `key_active` takes only the `AuthTable` std `RwLock` for reading. It takes no vault guard and holds no lock across an await (`auth.rs:328-334`). The 1 s wake is at most 256 timers per second (`idle.rs:380`). I found no overflow or panic: `send - waited` and `idle - since` only run after the `>=` check. Rest, accepted by DEC-T27-D2-2 and DEC-T27-E-2: six tokens can still fill the 192 authenticated slots, and while all slots are authenticated the accept loop waits inline (`server.rs:350`). A refusal by the cap is not audited (Info). |
| NEW-7 | closed | Info | `step` is floored at 5 ms, so `clamp(5, step)` cannot panic (`idle.rs:330`, `:380`). `admitted()` is called after the wait for a permit (`server.rs:353`). `evict_any` removes one entry per try, so it always ends (`idle.rs:478-485`). The accepted rest (b) is unchanged. |
| NEW-3 | closed | — | Revoke-all and cancel-pending verify the MAC of the parsed row before they re-sign it, skip a bad MAC (`cerberus-store/src/tx.rs:677-680`, `:760-763`), and write only the revoke or cancel columns plus the new MAC, `WHERE id = <stored id text>` (`:684-697`, `:767-780`). The MAC covers the whole `LeaseRow` and `AccessRequestRow` (`rows.rs:416-433`). The stored columns that are not written are the ones whose parsed values the old MAC verified. So the new MAC signs the same genuine row with only the code-set revoke fields changed. A forged row is never signed, and a file attacker gains nothing. A copy of a genuine row with a non-canonical `id` text also verifies and gets revoked, which is the safe state. The test deletes the parents with foreign keys off and checks both the MAC and the parent columns afterwards. |
| AUD-25 | closed-accepted | Low (NEW-9) | In the ambiguous case (an `@` after the first `/`, `?` or `#`) the path is never kept (`csvio/rows.rs:125-133`). Both section-7 inputs now give no target and no title (test passes). The rule for the user-information part allows exactly one `@`, and a `host:port` authority gives `None`. I found no input that keeps any part of a password that contains `:`. Accepted rest (DEC-T27-E-5): a dotted user name or token with no `:` (`https://abc.def/ghi@host/`) shows `abc.def`. The note says such a value is "a user name, not a secret", but the section-7 variant (1) was a token used as the user name. Info. The case with no ambiguity still keeps the path, see NEW-9. |
| AUD-10 | partially closed | Low (NEW-10) | Not part of T27-E. The rest from section 6 is unchanged: `swap_files` still returns with `?` after the old vault was moved (`cerberus-store/src/backup.rs:188-196`). The flake analysis below gives this a concrete trigger. |

### New findings (T27-E re-check)

- **NEW-8 — Low — A local user with no token can write one `auth.failed` row per loopback address per minute (about
  4,096 a minute), and during a lockout the real failure reason is not recorded.** `cerberus-core/src/vault/authlog.rs:29-38`
  keys the audit throttle by the raw source IP (`layers.rs:190` passes `conn.peer.ip()`). On Linux any local user can
  connect from any `127.x.y.z` (the NEW-1 test does this). Scenario: the attacker opens TLS connections from 4,096
  different loopback addresses each minute and sends one bad token on each. Each address gets its own event.
  `MAX_TRACKED` only sends address 4,097 and later to the shared bucket, so the cap is 4,097 events a minute, about
  5.9 million chain rows a day. Each row is a `synchronous=FULL` commit (68 fsyncs a second against the vault's own
  writes). Rows are never pruned (AUD-30), and the post-unlock chain walk reads all of them. The vault file grows by
  roughly a few GB a day until the disk is full. While unlocked this is not capped (the 10,000 cap of D-4 covers only
  `audit_pending`), and the 256-bit secret does not help here. A second effect: a refused check gets the reason
  `locked_out` once the source or the global lockout is on (`auth.rs:385-388`), and only the first failure in each
  minute writes a row. An attacker who keeps the global lockout on (10 loopback addresses, NEW-5 row) can therefore
  test a stolen revoked or expired token, and the log never shows `key_revoked` or `key_expired`. Fix: key the
  audit throttle with the same source mapping as `idle::source_of` (all of loopback as one source, IPv6 by `/64`),
  add a global per-minute event cap with a count, and log the underlying reason next to `locked_out`. Confidence:
  confirmed by code trace; not run.
  - **T27-F fix:** The throttle keys by source and class (`cerberus-core/src/vault/authlog.rs`). The source uses the
    `idle::source_of` mapping (all of loopback, `::1` and IPv4-mapped forms as one source, IPv6 by `/64`). The class
    keeps a token that matched a real key (revoked, expired, inactive agent, IP or mTLS rule) apart from guesses. Per
    class at most 10 events a minute are written from all sources together. The rest is counted and carried by the
    next event of the class as `suppressed_other`, so the chain grows by at most 20 `auth.failed` rows a minute.
    `AuthTable::check_refusal` returns the credential failure under a limit, and the API audits it. The event's
    `reason` is that failure (`key_revoked` during a lockout), `result` is what the caller got, and `limit` names
    the limit. Rest: while locked, `audit_pending` has no details, so the reason under a lockout is not kept there.
    Tests: `new8_loopback_is_one_source_and_ipv6_counts_by_its_64`,
    `new8_a_flood_from_many_sources_is_capped_and_counted`, `new8_a_matched_key_is_not_hidden_by_a_guess_flood`,
    `new8_a_lockout_keeps_the_reason_under_it`, `new8_a_revoked_token_during_a_lockout_flood_is_recorded`,
    `new8_failures_from_many_sources_write_a_bounded_number_of_rows`. DEC-T27-F-2.
- **NEW-9 — Low — CSV import keeps the URL path in `target`, and webhook and bot URLs carry their secret in the
  path.** `crates/cerberus-core/src/csvio/rows.rs:120-124` (case with no ambiguity: `path` kept), `:88-93`
  (DEC-T27-A2-10 keeps scheme, host, port and path). Scenario: a password-manager export has an item whose URL is
  `https://hooks.slack.com/services/T000/B000/FAKESECRET`, `https://discord.com/api/webhooks/1/FAKETOKEN` or
  `https://api.telegram.org/botFAKE:TOKEN/getMe`. The import sets that whole URL as `target`, and an agent with
  only `catalog:read` reads the webhook or bot secret, which is the AUD-25 exploit with the secret in a different
  part of the URL. Fix: keep scheme and host (and port) only in `target`; the full URL stays in the sealed login
  payload. Confidence: confirmed by code trace.
  - **T27-F fix:** `csvio::rows::target_of` keeps scheme, host and port only. The path goes, like the query and the
    fragment. The full URL stays in the sealed login payload. `resolve` still matches by the host (`resolve/score.rs`).
    Only words from an imported path no longer count as hints. Test: `new9_the_target_never_keeps_the_url_path`
    (Slack, Discord and Telegram URLs, a port with a path, a bare host with a path). DEC-T27-F-3.
- **NEW-10 — Low — Restore moves the vault files while the old store's SQLite connections can still be open, and a
  failed move leaves the person with an empty vault (the likely cause of the `backup_and_restore_round_trip`
  flake).** Product bug, not only in the test. `apps/desktop/src-tauri/src/ops/restore.rs:169-183` drops the last
  `VaultService` handles and calls `restore_backup` without `Store::close().await` (`cerberus-store/src/store.rs:639`
  exists but no restore path calls it). The doc of `restore_backup` says "The vault must be closed first"
  (`backup.rs:122`). In sqlx-sqlite 0.9 each connection is closed by `sqlite3_close` on its own worker thread after
  its channel drops; nothing waits for that. The leaf-renewal task holds a `VaultService` clone and is aborted but not
  awaited (`apps/desktop/src-tauri/src/server.rs:86-88`), so the last handle can drop later still. The API
  connection tasks are cut but not awaited (`cerberus-api/src/server.rs:184`). The last connection to close a WAL
  database checkpoints it and then unlinks `vault.cerberus-wal` and `vault.cerberus-shm` by name. SQLite skips this
  only when it sees that the main file was already moved. Failure: the close starts just before `swap_files`, and its
  unlink lands between `from.exists()` and `std::fs::rename(&from, ..)?` for `-wal` or `-shm` (`backup.rs:190-191`).
  The rename fails with `ENOENT` after the main file was already moved. `backup_restore` takes the "the swap itself
  failed: the old file is still the vault file" branch (`restore.rs:187`) and reopens the vault path with
  `create: true` (`state.rs:210`). That creates a new empty vault, and the real one is left in `.pre-restore-*` with
  no message. The person sees `internal` / `store error`, which is the flake's error. In a rarer order, the close
  passes the "moved" check before the swap but unlinks after the restored file was installed and opened. It then
  deletes the restored vault's new `-wal` or `-shm`, and the post-restore `revoke_all_leases` or `record_restore`
  commit (ADR-0031 step 3.5) can be lost or the file damaged. `roll_back` (`restore.rs:212-213`, `undo_swap`) has
  the same pattern with the restored store. Fix: close the store before the swap. Await every task that holds the
  service (await the aborted renewal handle and the connection tasks), then call `Store::close().await` on the last
  handle, or expose `VaultService::close()`, which awaits `pool.close()`. Make `swap_files` undo its earlier renames
  when a later one fails, and treat a missing `-wal` or `-shm` as already moved (the AUD-10 rest). Confidence:
  plausible. The mechanism was traced in the code, in sqlx-sqlite 0.9 (`connection/worker.rs`, `handle.rs:139-148`)
  and in SQLite's documented close behaviour, but it did not reproduce in 222 runs. The failing call site (which
  `expect` panicked) was not in the report I had, so other sources of `store error` cannot be ruled out.
  - **T27-F fix:** Before any file moves, the desktop restore stops the server and the tasks, and awaits the aborted
    renewal handle. It then takes the service out of the state and awaits `VaultService::close_store` (new:
    `Store::close` on the shared pool, which waits until every connection is closed). The probe service and the
    restored service in `roll_back` are closed the same way. `swap_files` no longer stops half way. A `-wal` or
    `-shm` that is gone at its rename counts as moved. If any rename fails, the files moved so far go back, and the
    old vault is the vault file again. Only when a file cannot be moved back is the error
    `StoreError::RestoreStranded { moved }`. The `.pre-restore-*` name is never reused. After a failed swap the
    desktop tries once more to put a stranded file back, then opens with `create: false` (`reopen_service`). The
    same applies after a good swap and after `roll_back`. So a failed restore never makes a new empty vault. If the
    old file cannot be opened, no service runs, and the log names the `.pre-restore-*` path. Tests (store):
    `a_swap_that_fails_after_the_move_puts_the_old_vault_back`, `missing_side_files_do_not_stop_the_swap`,
    `a_second_restore_in_the_same_second_keeps_the_first_old_file`. Tests (desktop):
    `new10_the_old_store_is_closed_before_the_swap`,
    `new10_a_stranded_old_vault_is_put_back_not_replaced_by_an_empty_one`,
    `new10_a_failed_swap_never_makes_a_new_vault`. Rest: a connection that sqlx drops with `close_hard` (failed return
    ping) closes its handle a moment later, so the pool close does not wait for it. cerberusd and the CLI have no
    restore. DEC-T27-F-1.
  - **T27-G fix:** If the vault file is missing and one or more `<vault>.pre-restore-*` files exist next to it, the
    desktop start (`DesktopState::open`) makes no vault. `vault_status` reports state `no_vault` with
    `stranded_restore` (the paths, newest first), every command that needs the service fails with the code
    `stranded_restore` (so `vault_create` and `backup_restore` are refused), and the unlock screen shows where the old
    vault is and one button. The new command `vault_recover_stranded` moves the newest file with its `-wal` and `-shm`
    back to the vault path, never over an existing file, opens it with `create: false`, and writes `backup.recover` to
    the pending audit list (it joins the chain at the next unlock). A failed restore that cannot reopen the vault sets
    the same state at once. cerberusd never creates a vault and has no restore. Tests:
    `t27g_start_with_only_a_pre_restore_file_makes_no_vault`, `t27g_recover_puts_the_stranded_vault_back`,
    `t27g_recover_refuses_when_a_vault_file_exists`, `stranded_vaults_lists_main_files_newest_first`, and the UI test
    for the stranded screen. DEC-T27-G-1.

**Still open at Medium or higher (whole report):** none. NEW-5 is closed by T27-E. AUD-4 and AUD-5 stay closed
(section 7), and AUD-1, AUD-2 and AUD-3 stay closed (section 6). The Low rests still open are AUD-10, AUD-19,
AUD-25/NEW-9, NEW-1, NEW-6, NEW-8 and NEW-10.

**Verification assessment:** The T27-E tests exercise the changed paths. The API test
`new5_a_bad_token_flood_from_loopback_does_not_lock_out_an_agent` interleaves a good token with a bad-token flood
from `127.0.0.1` on a frozen clock and checks the throttled audit row. `new6_a_response_the_client_never_takes_...`
can only pass through the send-stall rule (idle 30 s, closed at about 600 ms), and `new6_revoking_a_key_...` can
only pass through the owner check (idle 30 s, closed within 3 s). The NEW-3 store test deletes both kinds of
parent with foreign keys off and checks the MAC afterwards. Gaps: no test covers an SSE stream that lives past
`send_timeout` while waiting for events (the reasoning above says it survives, but no test shows it). No test
covers failures from many loopback addresses (NEW-8). No test covers a URL with a secret in the path (NEW-9). No
test makes the old store close race the swap (NEW-10): `a_failed_restore_puts_the_old_vault_back` injects the
failure after the swap, not inside it.

## 9. T27-F/G re-check (fresh auditor)

- Date: 2026-11-17. Read-only re-check of the "T27-F fix" and "T27-G fix" notes (NEW-8, NEW-9, NEW-10, AUD-10) against
  the code and DEC-T27-F-1..3, DEC-T27-G-1. **No test was run in this round**: another task is the only cargo user on
  the machine, so every verdict below comes from reading the code (store, core, API, desktop backend, UI guard), not from
  a test run. Verdicts as in section 6.

| ID | Verdict | Residual | Reason (file:line) |
|---|---|---|---|
| AUD-10 | closed | — (see NEW-10 rest) | `swap_files` no longer returns half way: a side file that is gone counts as moved, any failed rename moves back what was moved, in reverse order, and only a failed move back gives `RestoreStranded { moved }` (`cerberus-store/src/backup.rs:197-233`). `free_name` checks all three names with `symlink_metadata` and adds `-N` (`:237-255`), so a second restore in the same second does not overwrite the first old file. An orphan `-wal`/`-shm` with no main file is moved aside too (`:201-209`). The single copy, the staging folder and the gate are unchanged (`apps/desktop/src-tauri/src/ops/restore.rs:64-123`, `:150-154`). |
| NEW-10 | closed | Low (NEW-11, NEW-12, NEW-14) | The old store is closed and waited for before any file moves: `close_service` stops the server and tasks, `stop_server` awaits the aborted renewal handle (`server.rs:82-94`), then `take_core` and `close_store` → `pool.close().await` (`restore.rs:264-272`, `cerberus-core/src/vault/mod.rs:249-251`, `cerberus-store/src/store.rs:642-644`). The probe service is closed before its folder goes (`restore.rs:104-107`). After a failed swap only `had_vault == false` may use `create: true` (`restore.rs:306-310`). After a good swap and in `roll_back` the vault opens with `create: false` (`:196`, `:328-332`), and a failure that leaves no vault file sets the stranded state at once (`:311-315`, `:333-336`). `move_files` checks every target first and never replaces a file (`:347-371`). I found no path in a running app where a failed restore makes an empty vault over or next to a real **regular** vault file. Two start-time gaps are left: a stranded **symlink** is not seen, and an error while the folder is listed counts as "nothing stranded" (NEW-11). A successful restore's leftover counts as stranded too (NEW-12). Accepted rest: `close_hard`. |
| NEW-9 | closed | Info | `target_of` returns `scheme://host[:port]` only and never the path (`cerberus-core/src/csvio/rows.rs:91-97`). The path in `url_parts` (`:115-136`) is no longer used for `target`. Resolve still works: `app_score` compares the app with the whole target, `host_of(target)` and the word runs (`resolve/score.rs:73-78`, `:103-112`). The host is still in the target, so matching by host is unchanged, and only words from the path are lost as hints. Accepted rest (DEC-T27-E-5): a dotted user name before a `/` (`https://first.last/pw@host/` gives `https://first.last`). |
| NEW-8 | closed | Low (NEW-13) | The throttle key is (`audit_source`, class): loopback, `::1` and IPv4-mapped forms are one source, and IPv6 counts by its `/64` (`vault/authlog.rs:31-41`). Each class can write at most 10 events per 60 s window from all sources together (`:95-107`), so the chain grows by at most 20 `auth.failed` rows a minute. I checked this: a source with an open window returns before the budget, and a refused budget does not insert the source. Memory is bounded at 4096 + 2 entries. When the table is full, expired entries are dropped and their counts move to their class (`:71-88`). Every counter uses saturating arithmetic, and `budgets[usize::from(bool)]` cannot go out of bounds. The real reason survives a limit: `check_with` returns `Refusal { failure, cause }` (`auth.rs:414-432`), the API audits the refusal (`cerberus-api/src/layers.rs:185-193`), and the event has `reason` = cause, `result` = outward code, and `limit` only when the two differ (`authlog.rs:155-166`). A guess cannot fill the matched-key class, because `matched_a_key` (`auth.rs:110-119`) is true only after the hash matched a real key. The std mutex is released before the await. The rest is in NEW-13. |

### New findings (T27-F/G re-check)

- **NEW-11 — Low — The stranded check at start misses a stranded symlink and fails open on a folder read error, so
  the app makes a new empty vault next to the real one.** `cerberus-store/src/backup.rs:285` (`!entry.file_type()?.is_file()`
  skips symlinks, because `DirEntry::file_type` does not follow them), `apps/desktop/src-tauri/src/state.rs:231-234` (an
  error from `stranded_vaults` becomes an empty list), then `state.rs:217-220` → `open_service` (`create: true`) →
  `Store::open` makes the file (`cerberus-store/src/store.rs:151-158`). Scenario (symlink): the person keeps
  `vault.cerberus` as a symlink to a file in a synced folder. `had_vault` is true (`restore.rs:186`, `exists()` follows
  the link), and `swap_files` renames **the link** to `vault.cerberus.pre-restore-<t>`. The restore then strands it (a
  failed move back, and a failed `put_back`). `note_stranded` does not list the link. The session ends in
  `unavailable`, not in `stranded_restore`, and `vault_recover_stranded` answers `not_found` (`restore.rs:232-235`).
  At the next start the vault path is missing and nothing is "stranded", so a new empty vault is made. The real data
  is still behind the moved link, but the app shows a new vault, which is the NEW-10 outcome that T27-G meant to end.
  Scenario (fail-open): a `read_dir` or `file_type` error at start (a transient I/O error, or an entry removed while
  the folder is listed on a filesystem with no `d_type`) gives the same result. Fix: count a symlink main file as
  stranded (or refuse to restore over a symlinked vault), and in `note_stranded` treat a listing error as stranded
  (no service, and the error shown), not as "none". Confidence: confirmed by code trace. Not run.
  - **T27-H fix (DEC-T27-H-2):** A restore over a linked vault path is refused, not followed:
    `cerberus_store::linked_vault_file` (any of `vault`, `-wal`, `-shm` that is a symbolic link) is checked by
    `backup_restore` before the backup is read, the vault locked or a file moved (`unavailable`, with a text that says
    to put the real file in place), and again by `restore_backup` (`Io(InvalidInput)`). `stranded_vaults` also lists a
    `.pre-restore-*` main file that is a link (folders are still skipped). `note_stranded` fails closed: an error while
    the vault path is checked or the folder is listed sets `stranded_check_failed`, no vault is made or opened, and
    `core()` answers `unavailable` ("restart Cerberus"). Tests: store `t27h_a_linked_vault_path_is_not_restored`,
    `t27h_a_linked_old_vault_file_is_listed_as_stranded`; desktop `t27h_a_restore_over_a_linked_vault_path_is_refused`,
    `t27h_a_folder_read_error_at_start_makes_no_vault`. Each failed with its fix taken out (the linked restore went
    through and returned the moved link; the folder error made a new vault file).
- **NEW-12 — Low — The `.pre-restore-*` file left by a *successful* restore is treated as a stranded vault. The only
  action offered puts the replaced vault back, with its agent keys still live, and a new vault cannot be made.**
  `state.rs:226-246` and `backup.rs:267-296` list every `<vault>.pre-restore-*` main file. They cannot tell a failed
  restore from a successful one, which keeps the old file by design (`backup-and-restore.md:43-44` tells the person to
  delete it by hand). Scenario: the owner restored a backup because agent tokens of the current vault leaked. The old
  vault was only locked (`restore.rs:170-171`): its agent keys and leases were never revoked (`finish_restore` revokes
  them only in the restored file, `:421-432`), and it stays as `.pre-restore-<t>`. Later the vault file is missing:
  the person deletes it to start over, a sync tool removes it, or the data folder is copied without it. At start the
  app makes no vault, says "Your vault was found, but it is not in place", hides create and restore
  (`ui/src/shell/guard.ts`, `resolveRoute`), and refuses `vault_create` and `backup_restore` with `stranded_restore`
  (`state.rs:343-359`). Its only button is `vault_recover_stranded`, which reinstates the superseded vault
  (`restore.rs:232-242`). When the person unlocks it, the leaked tokens work again. The guide never says that
  `.pre-restore-*` files must be removed before a new vault can be made. Fix: after a successful restore, rename the old
  file to a name the stranded check does not match (for example `.replaced-<t>`), or write a marker that the restore
  completed. Show the age of the file on the stranded screen, and offer "start a new vault" behind a confirmation.
  Confidence: confirmed by code trace.
  - **T27-H fix (DEC-T27-H-1):** A restore that went through renames its old file to `<vault>.replaced-<stamp>`
    (with `-wal` and `-shm`, never over a file; `cerberus_store::retire_replaced`), so `.pre-restore-*` means only a
    restore that did not finish and a successful restore's leftover no longer starts the stranded state. Any vault that
    `vault_recover_stranded` puts back loses its agent keys and leases at its first unlock: the `backup.recover` row in
    `audit_pending` is the marker, and `unlock_impl` revokes every live agent key and lease and cancels every pending
    request in one transaction before the drain and before the vault serves a call (`revoke_after_recovery`; a failure
    fails the unlock), then writes `backup.recover_revoke`. The marker ignores the pending cap and a failed write undoes
    the recovery. This also covers a failed rename, a crash mid-restore and files of older versions. Not done: the age
    of the file and a "start a new vault" choice on the stranded screen. Tests: store
    `t27h_a_replaced_vault_is_not_listed_as_stranded`; desktop `t27h_a_successful_restore_leaves_no_stranded_file`,
    `t27h_a_recovered_vault_loses_its_agent_keys_at_unlock`. Both desktop tests failed with their fix taken out.
- **NEW-13 — Low — `auth.failed` still loses facts that the owner needs to scope an attack.** (a) No event names the
  agent or key that matched: `Refusal` carries only `AuthFailure` values (`auth.rs:127-132`), and the event has reason,
  IP, surface and counts only (`vault/authlog.rs:155-166`). With a stolen revoked token, the owner learns that *a*
  revoked key was used, not *which* agent's. The agent ID is public in the token (`cvt_<id>.`), so logging it is safe.
  (b) Two different matched-key failures from loopback (one source) in the same minute give one row: the second is only
  `suppressed_before = 1`, with no reason. (c) While the vault is sealed, the `Due` counts are taken and then dropped:
  `audit_pending` has no details (`authlog.rs:168-175`), so a sealed-time flood shows as at most 20 rows a minute with
  no sign of its size, and a matched-key row under a lockout looks like a guess (`result = too_many_failures`, no
  reason). DEC-T27-F-2 records only the lost reason, not the lost counts. (d) A good token over the per-agent rate limit
  is `Refusal { RateLimited, RateLimited }`, and `matched_a_key(RateLimited)` is false, so the refusal goes in the
  *guess* class, with no agent. A single bad token a minute from loopback then folds the rate-limit events of a hammering
  (possibly prompt-injected) agent into `suppressed_before`. Fix: carry the token's agent ID (and the key ID when a key
  matched) in `Refusal` and in the event, count a good-token rate limit in the matched class, and write the counts in
  the pending row's `route` or a new column. Confidence: confirmed by code trace.
- **NEW-14 — Info — Smaller NEW-10/T27-G leftovers.** (a) `open_service_with` drops the `Store` without
  `close().await` when `VaultService::open` fails after `Store::open` succeeded (`state.rs:279-289`). `Store::open` does
  the same when a migration or the pre-migrate backup fails (`store.rs:181-197`). Then `vault_recover_stranded` moves
  the files back right away (`restore.rs:243-249`), and so does `undo_swap` in `roll_back` (`:323-324`). That is the
  NEW-10 race on a store that is still closing. The worst result I found is a `move_files` that fails half way and
  undoes itself: the vault file stays at the vault path, no service runs, and the state is `unavailable` until restart.
  No data is lost. Plausible. (b) `restore_gate` does not cover `vault_unlock`. An unlock of the old vault between the
  restore's `lock` (`restore.rs:170-171`) and `take_core` (`:267`) lets the pump call `after_unlock`
  (`pump.rs:64-66`, `server.rs:146-155`), which starts a server on the old service after `stop_server` ran. The restored
  service then never gets a server (`server.rs:29-31`, `services.server.is_some()`), because the stale server owns the
  port and its closed store fails every call until restart. Plausible, narrow window. (c) When only an orphan
  `-wal`/`-shm` was moved aside, `swap_files` returns `Some(target)` (`backup.rs:217`). A later `roll_back` then
  opens with `create: false` (`restore.rs:328`), fails, and leaves the session `unavailable` (the next start is fine).
  (d) `backup.recover` has no `target`, though the catalog gives it kind `vault`. Like `vault.unlock_failed`, it
  does not break the chain. A file attacker can forge such a pending row (AR-6, accepted). (e) `vault_recover_stranded`
  is safe as exposed: it takes no path input (`commands.rs:49`), is only in the main window's capability
  (`capabilities/main.json:82`, not in `approval.json`) and in `check` (`names.rs:77`, not in `APPROVAL_COMMANDS`), runs
  under the restore gate, and moves only the newest regular `<vault>.pre-restore-*` file to the fixed vault path. The
  UI guard is cosmetic: the backend refuses `vault_create` and `backup_restore` in the stranded state anyway.
  - **T27-H fix (DEC-T27-H-3), (a) and (b) only:** (a) `open_service_with` closes the store, and waits, when
    `VaultService::open` fails after `Store::open` succeeded; `Store::open` closes its pool when the pre-migrate backup,
    a migration or the version check fails. (b) `vault_unlock` and `vault_unlock_recovery` wait for the restore gate, so
    no unlock runs between the restore's `lock` and `take_core`, or during a recovery. (c) and (d) are unchanged. Tests:
    desktop `t27h_a_store_whose_service_does_not_open_is_closed`, `t27h_an_unlock_waits_for_the_restore_gate`. Both
    failed with their fix taken out. The `Store::open` part has no test of its own.

Panic scan: the changed non-test code (`backup.rs`, `restore.rs`, `state.rs`, `server.rs`, `authlog.rs`, `rows.rs`,
`integration.rs`, `auth.rs`, `layers.rs`) has no `unwrap`, `expect`, `panic!` or unchecked indexing. No std mutex
guard is held across an await. The `restore_gate` (tokio) is held across the whole restore and recovery, as intended.

### Doc drift (guides against the code)

1. `docs/guides/security-model.md:132`: NEW-8 is "Open, Low ... one per loopback address per minute ... the true
   reason is not logged". That was fixed in T27-F: at most 20 rows a minute, all of loopback is one source, and
   `reason` is kept under a lockout while unlocked.
2. `docs/guides/operator-guide.md:167`: "Local flood of failed logins (NEW-8) ... can write many `auth.failed` audit
   rows". This is stale for the same reason (now at most 20 a minute).
3. `docs/guides/backup-and-restore.md:30-31`: "You can start a restore from the unlock screen ... You do not need to
   unlock first." That is true only when no vault exists. With a vault, `backup_restore` needs an unlocked owner
   session (`restore.rs:156-161`, `admin/audit_ops.rs:345-351`), and the unlock screen offers restore only in
   `no_vault` (`ui/src/screens/unlock/route.tsx:83-90`).
4. `docs/guides/backup-and-restore.md:36`: "A broken chain shows a warning. The owner can still continue." The person
   sees nothing and makes no choice. `report_chain` only writes a `tracing::warn!` and the restore goes on
   (`restore.rs:410-414`). The dialog shows only the fixed `rs.warn` text (`ui/src/screens/settings/messages.ts:230`).
5. `docs/guides/backup-and-restore.md:44`: "The app offers a secure delete for it." No such feature exists. No IPC
   command deletes a `.pre-restore-*` file (`names.rs:5-79`), and no UI string offers it.
6. `docs/guides/backup-and-restore.md:80-83`: "The next start of the app then finds ..." The stranded state is set at
   once, in the same session, when the reopen fails (`restore.rs:311-315`, `:333-336`, DEC-T27-G-1), not only at the
   next start. The guide also never says that a `.pre-restore-*` file left by a *successful* restore triggers this
   screen when the vault file is missing, or that it must be removed before a new vault can be made (NEW-12).
7. `docs/guides/user-guide.md:168-170`: "It never keeps the user name" is wrong for a dotted user name before a `/`
   (accepted rest of DEC-T27-E-5, `rows.rs:126-128`). "The login itself keeps the full URL" is wrong for a URL that
   fails `http_url` (another scheme, whitespace, over 2048 characters): the payload URL is then empty
   (`rows.rs:270-279`), while `target` may still be set (`:337-339`). The text also says "for a login row", but
   `target_of` runs for every row with a URL.
8. `docs/guides/troubleshooting.md:37` and `docs/guides/agent-integration.md:119`: `too_many_failures` is described as
   "Too many failed token checks from this address". It is also the answer of the **global** lockout (100 failures from
   all sources, `auth/limits.rs:43-46`), so a failing check from a fresh address can get it too.
   `troubleshooting.md:36` (`rate_limited` on a good token) leaves out the per-agent connection cap of 32 (NEW-6), which
   also answers `429 rate_limited` (`cerberus-api/src/layers.rs:164-174`).

The env rules in `agent-integration.md:225-235` match `cerberus-types/src/env.rs` and `cerberus-client/src/run.rs:233-237`.

**Still open at Medium or higher (whole report):** none. AUD-1 to AUD-5 and NEW-5 stay closed (sections 6 to 8).
New in this round, all Low or Info: NEW-11, NEW-12, NEW-13 (Low) and NEW-14 (Info).

**Verification assessment:** I ran nothing in this round (cargo was reserved for another task), so this rests on
reading the code. The store tests named in DEC-T27-F-1 exercise `swap_files` directly: a failed final rename, a missing
side file, and two swaps in one second. The desktop tests go through `backup_restore`, with a swap hook that stands in
for the store. `new10_the_old_store_is_closed_before_the_swap` checks `is_closed()` and that no `-wal` exists right
before the swap, which is the right proof for the close order. No test covers a symlinked vault, a successful
restore's leftover at start, a `VaultService::open` failure during recovery, or a guess-class flood that hides a
good-token rate limit.
