# ADR-0034: Remote backend mode — opt-in admin API on `cerberusd` for the desktop app

- Status: Accepted (design, 2026-11-21). Built in phase 2, see `docs/remote-mode-plan.md`.
  Amends ADR-0001, ADR-0002 (points 2, 3, 4), ADR-0003 (points 1, 2), ADR-0023 (context, listener) and ADR-0024
  (crate table and edges).
- Date: 2026-11-21
- Plan reference: D1, D2, D3 (owner request: "I as a user connect from the desktop app to a deployed remote backend
  and work with it")
- Related: ADR-0001, ADR-0002, ADR-0003, ADR-0004, ADR-0009, ADR-0016, ADR-0018, ADR-0021, ADR-0023, ADR-0024,
  ADR-0026, ADR-0030, ADR-0032, `docs/security/threat-model.md` (TB-10), `docs/decisions.md` (DEC-RM-1 to DEC-RM-14)

## Context

Today a vault lives in one of two places:
- the desktop app, which holds the vault in its own process and serves agents on loopback (ADR-0001);
- `cerberusd`, which serves agents on a server and has **no admin interface** (ADR-0002 point 2, ADR-0003).

So a person who runs agents on a server must prepare the vault on the desktop, copy a backup to the server, and copy it
again after every change. Approvals (`ask_once`, `ask_always`) cannot work on the server: they give
`403 approval_unavailable` (ADR-0002 point 4). Items that agents create on the server are lost at the next copy.

The owner now wants the desktop app to be a **client of a deployed `cerberusd`**: unlock it, browse and edit items,
manage grants, see agents and leases, read the audit log, and approve requests live, all over the network.

This reverses a deliberate rule: "admin actions are not on the network" (D3). The rule existed because admin actions are
the most dangerous ones, and a stolen agent token or a local process must not reach them. This ADR keeps that goal and
moves the boundary: admin actions may cross the network only to a daemon whose owner turned the admin API on, only from
a device that the owner enrolled, and only after the person types an operator passphrase.

## Decision

### 1. Two modes of the desktop app

1. **Local mode** (default, and the mode after every fresh install): exactly as today. The desktop opens its own vault
   file and serves agents (ADR-0001). Nothing in this ADR changes local mode.
2. **Remote mode**: the desktop opens **no local vault** and starts **no local HTTPS server**. Every vault command that
   the remote allowlist (point 5) names goes to one `cerberusd` over pinned HTTPS. Commands that are not on the list
   are refused locally with the IPC error code `remote_unsupported` and the UI shows them as not available.
3. The mode is a desktop preference (`desktop-prefs.json`, field `remote.active`). Changing it restarts the app, so the
   two backends never run side by side. The switch to remote mode is refused while a local vault is unlocked.
4. One remote profile is active at a time. A profile is one enrolment bundle (point 3): server URL, CA pin, client
   certificate and key. Several profiles may be stored.

### 2. The admin API on `cerberusd` (on by default since DEC-SRV-3; was off)

1. A new config table in `cerberusd.toml` (mode 0600, ADR-0002 point 5):
   ```toml
   [admin]
   enabled = true                # CERBERUSD_ADMIN_ENABLED (default true since DEC-SRV-3; it was false)
   session_idle_seconds = 900    # 60..3600   CERBERUSD_ADMIN_SESSION_IDLE_SECONDS
   session_max_seconds = 43200   # 900..86400 CERBERUSD_ADMIN_SESSION_MAX_SECONDS
   ```
   With `enabled = false` (an explicit choice since DEC-SRV-3; it was the default) **no `/admin` route is mounted**:
   every `/admin/...` path gives `404 route_not_found`, the same answer as any unknown path. The daemon behaves exactly
   as before. The default became `true` so that a fresh default install can wait for its first client (point 9); with
   no desktop enrolled every admin route is refused by the device check (point 4), so nothing new is reachable. It is a
   behaviour change for an existing config that has no `enabled` key (admin routes, client-certificate request,
   registry read, `admin.api_start` audit and approvals on); `enabled = false` keeps the old behaviour.
2. With `enabled = true` the routes live on the **same TLS 1.3 listener** as the Agent API (ADR-0023), under
   `/admin/v1`. The `Host`, `Origin` and `Sec-Fetch-Site` rules of ADR-0023 apply unchanged. The listener asks every
   client for a certificate signed by the vault CA. When `require_mtls` is false (loopback bind), a client without a
   certificate is still accepted at the TLS layer so agents keep working; the admin routes refuse it (point 4).
3. When `enabled = true`, `cerberusd` builds its core with `approvals_available = true`, so `ask_once` and `ask_always`
   grants create access requests that an enrolled desktop can decide (ADR-0018). If no desktop decides, the request
   expires after its timeout (default 120 s) and the agent gets the normal `expired` result. With `enabled = false`
   the ADR-0002 point 4 behaviour (`403 approval_unavailable`) stays.
4. Every start with the admin API on logs a `warn` line ("admin API enabled, N enrolled clients") and writes the audit
   event `admin.api_start` (through `audit_pending`, so it joins the chain at the next unlock). `cerberusd status`
   prints whether the admin API is on and how many clients are enrolled.
5. A non-loopback bind still needs `require_mtls = true` for **every** connection (ADR-0023 listener point 2): agents
   on such a daemon need client certificates too. The recommended deployment keeps `cerberusd` on loopback and reaches
   it through an SSH tunnel or a VPN; the admin API works the same through the tunnel (the desktop URL then names the
   tunnel end, and `host_names` must hold that name).

### 3. Enrolment of a desktop (local to the server)

1. `cerberusd admin enroll --label <text> --url <https://host:port> [--operator <label>] --out <file>` runs on the
   server, from a terminal, as the daemon user. It talks to the running daemon over the existing unlock socket
   (`<data_dir>/cerberusd.sock`, mode 0600, same-UID check, DEC-T13-1). It asks for an **owner** passphrase with echo
   off. The vault must be unlocked (the CA key is sealed while locked, ADR-0023).
2. The daemon checks the owner phrase (point 6.3, counts toward the unlock back-off), then signs a client certificate:
   ECDSA P-256, EKU `clientAuth`, `CN = cerberus-admin <enrolment id>`, 90 days. It adds the enrolment to the admin
   registry and writes the audit event `admin.client_enroll` (enrolment ID, label, bound operator; no key).
3. The enrolment is **bound to one operator** (`--operator`, default the owner who typed the phrase). A session opened
   with this certificate must use the phrase of that operator.
4. The CLI writes a **bundle** file (mode 0600, created new, never over an existing file), JSON:
   `format = "cerberus-admin-bundle"`, `version = 1`, enrolment `id`, `label`, `url`, `operator_id`, `ca_pin`
   (`sha256/...`, ADR-0023), `ca_cert_pem`, `client_cert_pem`, `client_key_pem` (PKCS#8), `not_after`.
   The bundle holds a private key but no passphrase and no vault key. The person moves it to the desktop over a
   trusted channel (for example `scp`) and deletes it after import.
5. The registry is `<data_dir>/admin-clients.json`, mode 0600 (the daemon refuses to start with the admin API on if
   the mode is wider). One entry per enrolment: `id`, `label`, `operator_id`, `cert_sha256`, `created_at`,
   `not_after`, `revoked_at`. It is plain because it must be readable while the vault is sealed (a remote unlock needs
   it). It holds no secret. Tampering needs write access as the daemon user (accepted risk AR-19).
6. `cerberusd admin list` shows the enrolments. `cerberusd admin revoke <id>` sets `revoked_at` (through the socket
   when the daemon runs, so it takes effect at once; directly in the file when it does not), drops every session of
   that enrolment, closes its connections within about 1 s, and writes `admin.client_revoke`. Revoke needs no phrase:
   it only removes power.

### 4. Two factors on every admin call

1. **Device**: the TLS client certificate must verify against the vault CA **and** its SHA-256 must be an enrolment in
   the registry that is not revoked and not expired. A CA-signed **agent** certificate (ADR-0016, DEC-T09-5) is not in
   the registry and is refused. The check runs on every request, not only at the handshake. Failure:
   `403 admin_cert_required`, before any other work.
2. **Person**: an admin **session**, opened with the operator passphrase of the bound operator (point 6).
3. Agent bearer tokens (`cvt_...`) are never accepted on `/admin` routes, and admin session tokens are never accepted
   on `/v1` or `/mcp`.

### 5. Routes and the command allowlist

| Route | Needs | Does |
|---|---|---|
| `GET /admin/v1/hello` | device | Server version, `admin_protocol = 1`, vault state, the list of remote commands. The desktop refuses a different `admin_protocol`. |
| `POST /admin/v1/session` | device | Opens a session: `{ "operator_id", "phrase" }`. Returns the token, the `SessionView` and the idle and absolute limits. |
| `DELETE /admin/v1/session` | device + session | Closes the session. The vault stays as it is. |
| `POST /admin/v1/rpc/{command}` | device (+ session, except the two pre-session commands) | Runs one allowlisted IPC command. Body = the IPC arguments as a JSON object with the Rust (snake_case) argument names. Answer = the IPC result DTO, the same JSON the webview gets today. |
| `GET /admin/v1/events` | device + session | Server-sent events: the same typed UI events as the desktop pump emits (`VaultStateChanged`, `AccessRequestCreated`, `AccessRequestResolved`, `AgentActivity`, `LeaseChanged`, `AutolockTick`, `MassReadAlert`, `HeaderMismatch`, `IntegrityAlert`, `PendingCountChanged`). |

The MVP allowlist (25 commands; one constant shared by server and desktop):

| Gate | Commands |
|---|---|
| Pre-session (device only) | `vault_status`, `vault_list_operators` |
| Opens a session (route `POST /admin/v1/session`, never through `rpc`) | `vault_unlock` |
| Session | `vault_lock`, `vault_panic`, `ui_activity` (session keep-alive), `workspace_list`, `workspace_put`, `item_list`, `item_get`, `item_create`, `item_update`, `item_delete`, `item_reveal`, `item_totp_preview`, `agent_list`, `grant_list`, `grant_put`, `grant_delete`, `request_list_pending`, `request_approve`, `request_deny`, `lease_list`, `lease_revoke`, `audit_query` |

Rules:
1. The wire contract **is** the IPC contract: same command names, same argument names, same DTOs
   (`bindings.ts`). The DTOs and the error type move from the desktop crate into a new transport-free crate
   `cerberus-admin`, which both the desktop and `cerberus-api` use. One handler per command runs the core call and the
   conversion; the desktop's local `ops` and the server's `rpc` call the same handler. Role checks stay in core
   (`authorize`, DEC-WIRE6-13), so a remote call has exactly the power of the same local call.
2. Any other command name gives `404 remote_unsupported`. Unknown JSON fields give `400 invalid_request`.
3. Body limit 16 KiB, except `item_create` and `item_update`: 1 MiB (browser storage state, as ADR-0023).
4. Error body: `{ "request_id": "...", "error": <IpcError> }` with an HTTP status from the code. This is on purpose not
   the agent error shape of ADR-0021: the desktop hands the `IpcError` to the UI unchanged, so the UI error handling is
   the same in both modes. Errors from the shared outer layers (`origin_refused`, `route_not_found`) keep the ADR-0021
   shape; the desktop maps them by status. `cerberus_types::ErrorCode` and the Agent OpenAPI document do not change.
5. The admin routes are **not** in `docs/api/openapi-draft.yaml` (that file is the agent contract). A route-list test
   fixes the five admin routes, and a test checks that the generated agent OpenAPI has no `/admin` path.
6. Item payloads that point at a backend-held draft (`PayloadSource::Draft`, made by the local `ssh_key_generate` or
   `ssh_key_import`) are refused in remote mode (`remote_unsupported`): the draft lives on the desktop, not the server.

### 6. Admin sessions

1. Token format `cas_<session id>.<secret>`: UUIDv7 session ID, 32 random bytes in base64url. The prefix lets secret
   scanners find a leaked token (as `cvt_`, ADR-0016). The server keeps only SHA-256 of the secret, in memory. No
   session survives a daemon restart.
2. A session is bound to: the enrolment (certificate SHA-256) that opened it, the operator, and the unlock epoch of the
   vault. A request is refused (`401 admin_session_required`) when the token is unknown, comes over a connection with
   a different client certificate, is past its idle limit (default 900 s) or its absolute limit (default 12 h, never
   beyond the vault hard lock), or when the vault was locked or unlocked again since the session opened.
3. Opening a session (`POST /admin/v1/session`):
   - vault **sealed**: `unlock_with_phrase(operator, phrase)` (ADR-0026) unlocks the vault for that operator, as
     `cerberusd unlock` would. The vault then serves agents too.
   - vault **unlocked** by the same operator: the new core call `verify_operator_phrase` runs the KDF on that
     operator's slot and compares the opened VMK with the live one in constant time. The vault state does not change.
   - vault unlocked by **another** operator: `409 conflict` ("unlocked by another operator"). Core has one session
     (`Session::authorize` compares the operator ID, `vault/state.rs:58`); switching operators is not in the MVP.
   - Every failure counts in the vault-wide unlock back-off of ADR-0026 (header counter, `vault.unlock_failed`). On
     top, an in-memory limit per enrolment: after 5 failures in 15 min that enrolment gets `429 too_many_failures`
     for 15 min **before** the KDF runs, so a stolen bundle cannot drive the shared back-off far.
   - The recovery key is never accepted over the network (`vault_unlock_recovery` is local only).
4. At most 4 live sessions per daemon and 2 per enrolment; the oldest of the enrolment is closed first.
5. `ui_activity` resets the idle limit (the desktop sends it at most once per 30 s while the person works). Admin calls
   count as operator activity for the daemon idle lock (ADR-0026), which is off by default on `cerberusd`.
   As built (DEC-RM-26): only `ui_activity` and the actions of a person count, never a read, because the desktop
   also reads in the background; the desktop applies the idle and absolute limits on its own clock too.
6. Closing a session, its expiry, a lost connection or the desktop quitting **does not lock the server vault**: agents
   keep working. Only `vault_lock`, `vault_panic` or the daemon's own lock rules lock it. The UI has two different
   actions: "Disconnect" and "Lock the server vault".
7. Audit: `admin.session_open` (enrolment ID, operator, whether it unlocked the vault), `admin.session_close`
   (reason: `closed`, `idle`, `max`, `lock`, `revoked`). Every admin action is audited by core with actor
   `operator:<id>` as today (R-2).
8. The SSE stream needs a live session, ends when the session ends, sends a comment line every 15 s, and holds IDs and
   metadata only (threat I-19 applies unchanged). At most 2 streams per session.

### 7. The desktop in remote mode

1. **The proxy lives in Rust.** The webview CSP keeps `connect-src ipc: http://ipc.localhost` (ADR-0023): the webview
   never talks to the network. The `ipc!` command macro (`commands.rs`) checks the window label as today, then, in
   remote mode, serializes the typed arguments into a zeroizing buffer and sends them with the pinned HTTPS client of
   `cerberus-client` (`PinnedHttps`, TLS 1.3, CA pin, client certificate). The answer is decoded into the same Rust
   return type, so `bindings.ts` and every screen stay as they are.
2. The session token lives only in Rust memory (zeroized on drop, wiped by the panic hook). It never reaches the
   webview, the log or a file.
3. `vault_status` in remote mode reports `unlocked` only while **this desktop** holds a live session, else `sealed`,
   so the UI guard and routes work unchanged. A new field `remote` (null in local mode) carries the profile label,
   URL, the server's real vault state, whether the server is reachable and the server version.
4. `vault_unlock` maps to `POST /admin/v1/session`. When the session ends (expiry, server lock, revoke), the desktop
   drops the token and emits `VaultStateChanged { sealed }`; the UI shows the unlock screen and drops cached data as on
   a local lock (I-16).
5. OS sleep and screen lock **close the remote session** (they no longer lock anything locally). Quit sends
   `DELETE /admin/v1/session` (bounded wait 2 s).
6. A remote event pump reads `/admin/v1/events`, emits the same Tauri events, keeps the pending count, opens the
   approval window and updates the tray, as the local pump does. The approval window and its 7 commands work
   unchanged (all are on the allowlist).
7. **Local-only, disabled in remote mode** (`remote_unsupported`, and the UI hides or greys them with the text "Not
   available for a remote server"): `vault_create`, `vault_unlock_recovery`, `vault_recover_stranded`, `phrase_change`,
   `recovery_rotate`, operator management, `workspace_delete`, `item_versions`, `item_restore_version`,
   `clipboard_copy_secret`, `clipboard_copy_once`, `password_generate`, `ssh_key_generate`, `ssh_key_import`, agent
   create, update, status, keys, client certificates and snippets, `policy_simulate`, `lease_revoke_all`,
   `audit_verify`, `audit_export`, `settings_get`, `settings_set`, network and TLS settings, backup and restore, CSV
   import and export, `file_pick_open` (except for the bundle import), and the rest of the IPC list. Several of them
   can be added later by putting them on the allowlist; the first candidates are named in the plan.
8. Purely local UI preferences that touch no vault (UI scale and zoom keys, language, theme) keep working in remote
   mode; they never leave the webview.
9. UI: the unlock screen gets "Connect to a remote server" (import a bundle, check URL and pin, connect) and, in remote
   mode, "Use the local vault" (back to local mode). Settings gets a **Remote** section: the profiles, URL, CA pin and
   fingerprint, client certificate expiry, "Import bundle", "Test connection", "Disconnect", "Forget". The top bar
   shows "Remote: <label>" in remote mode. The safe default is local mode.
10. Bundle import goes through the native file dialog only (`file_pick_open`, AUD-11). The desktop shows URL, pin and
    CA fingerprint for the person to compare with the server (`cerberusd status`), then stores the certificate and
    CA PEM and the key (mode 0600) under `<app_data_dir>/remote/<enrolment id>/`; the profile metadata (no key) goes to
    `desktop-prefs.json`.

### 8. Bootstrap order on a new server

(Point 9 is the other way: the first client creates the vault, and steps 1 and 2 are not needed.)

1. Copy a desktop backup to `<data_dir>/vault.cerberus` (mode 0600), as today (`docs/guides/cerberusd.md`).
2. `cerberusd serve` with `[admin] enabled = true`; `cerberusd unlock` once at the terminal (makes the TLS leaf,
   ADR-0031 point 2); `cerberusd admin enroll ...` writes the bundle.
3. On the desktop: import the bundle, connect, unlock with the bound operator's phrase. After a later daemon restart the
   vault starts sealed and the desktop can unlock it remotely, because the leaf now exists.

### 9. First-time setup of a server with no vault (amendment 2026-11-22, DEC-SRV-3)

Point 8 assumed the vault exists before the first desktop connects. The server is the custodian of the vault, so a
new server needs no vault prepared elsewhere and no passphrase typed on it: the first client creates it.

1. With no `vault.cerberus` and the admin API on (the default), `cerberusd serve` starts, sends READY and runs a **setup
   listener** on the configured addresses. Its certificate is self-signed, not a CA, made in memory at each start and
   never stored in a vault. With an explicit `enabled = false` there is no listener (the client could not get a bundle); the daemon
   logs why and waits.
2. It makes a random 32-byte token and a one-time **setup code** `cerberus-setup:1:<base64url(json {url, token, pin})>`
   with the pin `sha256/<base64>` of the SPKI of the setup certificate. The code goes to `<data_dir>/setup-code` (mode
   `0600`, replaced at each start, deleted when the setup works or the daemon stops) and to `cerberusd setup-code`.
   The log has the file path and the pin, never the token.
3. Routes: `GET /v1/health` answers `{"status":"ok","vault":"no_vault","setup":"pending"|"locked_out","version"}`.
   `POST /v1/setup` takes `{setup_token, owner_label, passphrase, device_label?, url?}`. Every other route answers
   `503 unavailable`. Errors have the ADR-0021 shape. The token is compared in constant time; after 5 wrong tokens from
   one address that address waits 2 s, 4 s ... up to 5 min (`429 too_many_failures`, `retry_after_seconds`; health says
   `locked_out` to it meanwhile); other addresses (IPv6 by /64) are not affected. The listener serves one request per
   connection, with at most 4 connections per address and 16 in all, 40 s for a connection that starts no setup and 10 s
   for the body (threat model E-17). One setup runs at a time (`409 conflict`) and one
   that worked closes the listener for good. It runs in a task of its own that holds the phase lock, so a connection
   that ends cannot stop it half way; the vault is built under a temporary name and renamed to `vault.cerberus` after the
   enrolment (point 5). The passphrase policy is checked on the server, and the key-derivation cost
   is **measured by the server** (ADR-0013); the client cannot choose it. The `url` of the bundle (default: the URL of
   the code) must be a valid bundle URL (`check_url`) whose host is a TLS name of the server, checked before anything is made.
4. The client trusts only the key of the setup certificate (`cerberus_client::setup`: a leaf pin, TLS 1.3, no system
   roots). So the passphrase goes only to the server that holds the code.
5. On success the server makes the vault (core `create_vault`, same core settings as `serve`), enrols the client like
   `cerberusd admin enroll` (certificate, `admin-clients.json`, audit `admin.client_enroll`; `vault.create` is audited by
   the core), deletes the code file and answers once, over the pinned channel, with `{recovery_key, ca_pin, owner_id,
   bundle}`. The bundle is the file of point 3.4, so the desktop imports and activates it as any bundle. Any failure
   before the answer is ready removes every file of the attempt (the recovery key is never lost with a vault that
   exists).
6. Then the setup listener stops and the daemon goes on as for any vault, with no restart: HTTPS with the vault CA and
   leaf, renewal, the unlock socket and MCP. The vault stays unlocked, as `create_vault` leaves it; it starts sealed
   after the next restart, and point 6 (admin sessions, unlock through the desktop) applies.

Alternative rejected: keep a server-side `cerberusd init` that types the passphrase (DEC-SRV-2). It makes the server
the place where the secret is typed, which is the opposite of a custodian that serves vaults to clients.

## Consequences

- The person can run the vault on a server and work with it live from the desktop, approvals included. Items that agents
  create on the server are no longer lost by a re-copy.
- D3 is no longer true everywhere. It stays true for the desktop's own vault (local mode has no admin route) and for every
  daemon whose owner leaves the admin API off. Where it is on, the network carries admin power behind two factors.
- The operator passphrase now crosses the network (inside TLS 1.3 with a pinned CA and a client certificate). A
  compromise of the server or of the TLS channel would expose it. Threat model TB-10 lists the new threats and controls.
- One contract for both modes: the DTOs move into `cerberus-admin` and every allowlisted command has one handler. A
  change to a DTO changes the IPC and the admin wire at once. Desktop and daemon must run the same `admin_protocol`
  version; the desktop refuses a mismatch with a clear message.
- In remote mode the desktop serves no local agents. Local agents must point at the remote server or the person switches
  back to local mode.
- New crate and edges (ADR-0024 amended): `cerberus-admin` → core, store, crypto, types; `cerberus-api` → admin;
  `cerberusd` → admin; `cerberus-desktop` → admin, client. `just deps-check` gets the same table.
- The daemon gains state that is plain on disk (`admin-clients.json`) and state that is only in memory (sessions).
- Only one operator session per vault at a time (core limit). Two people with different operators cannot work on the
  same server vault at the same time.
- Doc drift found on the way: ADR-0002 point 3 and ADR-0031 point 3 name a `cerberusd restore` command that
  was never built (the daemon guide says so). Remote mode does not add it; restore stays a local file copy (DEC-RM-13).

## Alternatives considered

- **Keep D3; sync by backup copies.** The status quo. Rejected: no live work, no approvals, agent-created items are lost.
- **Admin over the unlock Unix socket, reached by SSH socket forwarding.** No new TLS path and SSH does the
  authentication. Rejected as the only transport: every desktop user needs an SSH account on the server, Windows
  desktops need an SSH client and agent forwarding setup, and the app would have to drive SSH. An SSH *port* tunnel to a
  loopback-bound daemon is supported and recommended (point 2.5).
- **A separate admin listener on its own port.** Rejected for the MVP: a second TLS config, a second port to firewall,
  and no gain, because the per-route device check already separates the surfaces. It can come later as `admin.bind`.
- **A resource-style admin REST API with its own OpenAPI document.** Rejected for the MVP: it duplicates about 60 DTO
  shapes and their conversions, and the two would drift. The RPC reuses the IPC contract that is already typed and
  tested. It is versioned (`/admin/v1`, `admin_protocol`), but it is not a public API for scripts.
- **Admin bearer token only (no client certificate).** Rejected, as in ADR-0003: one leaked string would be full
  admin power on the network.
- **Client certificate only (no passphrase per session).** Rejected: a stolen bundle would be full admin power, and the
  core needs an operator identity that a phrase proves (ADR-0009).
- **A remote approval channel only.** Rejected: it fixes approvals but not the copy-the-backup workflow the owner wants
  to end.
- **The webview talks HTTPS to the server.** Rejected: it needs `connect-src https:` in the CSP, puts the session token
  and the client key in JavaScript, and breaks ADR-0023's webview rules.
- **Run the desktop UI on the server (VNC, X forwarding).** Rejected: heavy, and it puts a desktop session on a server.
