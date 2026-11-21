# Remote backend mode — phase 2 implementation plan

- Design: [ADR-0034](adr/0034-remote-backend-mode.md), `docs/decisions.md` DEC-RM-1 to DEC-RM-14 (build notes from
  DEC-RM-15 on), threat model TB-10
  (`docs/security/threat-model.md`).
- Written 2026-11-21 against `main` at `f748eb6`. Line numbers are from that tree; re-check them after rebasing on
  the `rustdesk` item kind change (step 0).
- Abbreviations: **desk** = `apps/desktop/src-tauri`, **ui** = `apps/desktop/ui/src`, **api** = `crates/cerberus-api`,
  **d** = `crates/cerberusd`, **core** = `crates/cerberus-core`, **adm** = `crates/cerberus-admin` (new).

## Ground rules

1. **Green after every step.** Each step is one commit. Its "Done when" line lists the exact checks. Local mode
   behaviour does not change until step 8, and in step 8 only when a remote profile is active.
2. **RAM is limited.** Build and test per crate (`cargo build -p <crate>`, `cargo test -p <crate>`), never
   `cargo test --workspace` while another build runs. Use `-j 2` when a second agent compiles.
3. GUI checks run headless (Xvfb) and never activate a window on the person's desktop.
4. No new crates.io dependency is needed: `subtle`, `serde`, `serde_json`, `specta`, `rustls`, `hyper`, `zeroize`,
   `uuid`, `ipnet` are already in the workspace. `specta` moves to `[workspace.dependencies]` with its current pin
   (`=2.0.0-rc.28`) so the desktop and `cerberus-admin` share one version.

## Step overview

| Step | What | Crates | Depends on | New / changed LOC (prod + tests) |
|---|---|---|---|---|
| 0 | Rebase on the `rustdesk` change | — | — | 0 |
| 1 | New crate `cerberus-admin`: move DTOs and `IpcError` (pure move) | adm, desk | 0 | 60 new, ~2,560 moved |
| 2 | Shared handlers, remote allowlist, RPC args, wire events | adm, desk | 1 | 750 + 250 |
| 3 | Core `verify_operator_phrase`, admin audit events | crypto, core, ui (catalog) | 1 | 160 + 180 |
| 4 | Admin client certificate, registry, bundle format | api (tls), adm | 1 | 330 + 200 |
| 5 | Admin HTTP module in `cerberus-api` | api | 2, 3, 4 | 750 + 600 |
| 6 | `cerberusd`: config, enrolment CLI, socket ops, approvals on | d | 5 | 420 + 300 |
| 7 | `cerberus-client`: per-request bearer, generic SSE reader | client | 1 | 120 + 100 |
| 8 | Desktop remote backend (Rust), new IPC commands | desk | 2, 5, 7 | 900 + 450 |
| 9 | UI: connect flow, Remote settings, disabled states | ui | 8 | 800 + 400 |
| 10 | Acceptance A13, desktop-against-daemon test, docs | acceptance, desk, docs | 6, 8, 9 | 350 tests + ~300 docs |

Total about **4,200 lines of production code and 2,500 lines of tests**, plus the ~2,560-line move of step 1 and about
300 lines of guides. Steps 3, 4 and 7 can run in parallel after step 1; step 6 and step 8 can run in parallel after 5
(and 7 for step 8).

---

## Step 0 — Rebase on the `rustdesk` change

Another agent is adding a `rustdesk` item kind and one Tauri command. Wait for it to land, then rebase. It touches the
same files as steps 1, 2 and 8:
- `cerberus-types` `ItemKind`, `desk/src/dto/mod.rs:107-112` (`mirror_enum! ItemKind`), the payload in
  `desk/src/dto/items.rs`, core items;
- `desk/src/names.rs:5` (`ALL_COMMANDS: [&str; 69]` becomes 70), `desk/src/commands.rs`, `desk/src/lib.rs:54-124`
  (`collect_commands!`), `desk/capabilities/main.json`, `ui/src/bindings.ts`, `docs/interfaces.md` section 9.

Decide once it lands whether the new command is remote. Default: not on the allowlist (local-only) unless it is a pure
vault call on the unlocked session; then add it in step 2 with one line. The new item kind needs no remote work: it
flows through the shared DTOs.

The UI unlock files (`ui/screens/unlock/*`) and `ui/shell/Rail.tsx` are also being edited right now (uncommitted
changes in the tree). Step 9 starts after those land.

Done when: `git log` shows the rustdesk commit on the base of the remote-mode branch.

As built: the change landed in `95c58d4` and `e48a930` with **two** commands, `rustdesk_status` and
`rustdesk_connect` (`ALL_COMMANDS: [&str; 71]`), and a new DTO file `dto/rustdesk.rs`. Both commands are local-only
(DEC-RM-15): they find and start the RustDesk client on this machine and use the local clipboard.

---

## Step 1 — New crate `cerberus-admin` (pure move, no behaviour change)

Goal: the IPC DTOs and the error type live in a crate that `cerberus-api` and `cerberusd` can use without Tauri.

Files:
- New `crates/cerberus-admin/Cargo.toml`: deps `cerberus-core`, `cerberus-store`, `cerberus-crypto`, `cerberus-types`,
  `serde`, `serde_json`, `specta` (workspace, features `derive`, `serde_json`), `jiff` (`serde`), `ipnet`,
  `thiserror`, `tracing`, `zeroize`. `[lints] workspace = true`.
- New `crates/cerberus-admin/src/lib.rs`: crate docs, `#![forbid(unsafe_code)]`, `pub mod dto; pub mod error;`
  (ADR-0024 rule 6).
- `git mv desk/src/dto/{mod,agents,audit,csv,items,network,policy,rustdesk,vault}.rs crates/cerberus-admin/src/dto/` and
  `git mv desk/src/error.rs crates/cerberus-admin/src/error.rs`. Inside the moved files `crate::error` and `super::`
  paths stay valid. `IpcError` keeps its name (`error.rs:29`), so specta writes the same TypeScript.
- `desk/src/dto.rs` (new, replaces the folder): `pub use cerberus_admin::dto::*;`.
  `desk/src/error.rs` (new): `pub use cerberus_admin::error::*;`. Every `crate::dto::...` and `crate::error::...` path
  in desk (`ops/csv.rs:98` uses `crate::dto::opt_id`) and the 23 `cerberus_desktop::dto` / `::error` uses in
  `desk/tests/` keep working.
- Root `Cargo.toml`: member `crates/cerberus-admin`; `[workspace.dependencies]` `cerberus-admin = { path = ..., version
  = "0.3.0" }` (DEC-059: internal crates carry a version) and `specta = { version = "=2.0.0-rc.28", features = [...] }`.
- `desk/Cargo.toml`: add `cerberus-admin.workspace = true`; `specta` from the workspace.
- `justfile:72-84` (`deps-check` table): add `"cerberus-admin": ["cerberus-core", "cerberus-store", "cerberus-crypto",
  "cerberus-types"]`; add `"cerberus-admin"` to `cerberus-desktop`.
- `docs/interfaces.md` section 0 (dependency direction): add the crate.

Done when: `cargo build -p cerberus-desktop`; `cargo test -p cerberus-admin` (the moved `error.rs` tests);
`cargo test -p cerberus-desktop --test contract` (`bindings_file_is_up_to_date`, `contract.rs:53`: `bindings.ts` is
byte-identical); `just deps-check`.

---

## Step 2 — Shared handlers, allowlist, RPC args, wire events

Goal: one handler per remote command, called by the desktop `ops` now and by the server in step 5.

New in `cerberus-admin`:
- `src/handlers/{mod,vault,items,policy,agents,audit}.rs`. Signatures take the core and the context, never a Tauri
  state:
  ```rust
  pub async fn item_list(core: &VaultService, ctx: &OperatorContext, filter: ItemFilterView)
      -> IpcResult<Vec<ItemSummaryView>>;
  pub async fn item_create(core: &VaultService, ctx: &OperatorContext, input: ItemInputView, payload: Payload)
      -> IpcResult<ItemDetailView>;
  pub async fn item_update(core: &VaultService, ctx: &OperatorContext, item: String, input: ItemInputView,
      change: PayloadChange) -> IpcResult<ItemDetailView>;
  pub async fn vault_status(core: &VaultService) -> VaultStatusView;          // no session
  pub async fn vault_list_operators(core: &VaultService) -> IpcResult<Vec<OperatorPublic>>; // no session
  ```
  The bodies are the bodies of today's desktop ops after `state.operator()`: `desk/src/ops/items.rs:21-81`
  (workspace_list, workspace_put, item_list, item_get), `:99-171` (item_create, item_update, item_delete,
  item_reveal), `:200-210` (item_totp_preview); `ops/policy.rs:12-116` (grant_list, grant_put, grant_delete,
  request_list_pending, request_approve, request_deny, lease_list, lease_revoke); `ops/agents.rs:17` (agent_list);
  `ops/system.rs:22` (audit_query); `ops/vault.rs:116` (vault_lock) and vault_panic. The payload draft resolution
  (`ops/items.rs:84` `resolve_payload`) stays in the desktop: the handler gets a resolved `Payload` / `PayloadChange`.
- `src/remote.rs`:
  ```rust
  pub const ADMIN_PROTOCOL: u32 = 1;
  pub enum Gate { PreSession, OpensSession, Session }
  pub const REMOTE_COMMANDS: [(&str, Gate); 25] = [ ("vault_status", Gate::PreSession), ... ];
  pub fn gate(command: &str) -> Option<Gate>;
  ```
  The list is the one in ADR-0034 point 5 (plus the rustdesk command if step 0 decided so).
- `src/rpc.rs`: one `Args` struct per allowlisted command (`#[derive(Serialize, Deserialize)]
  #[serde(deny_unknown_fields)]`), field names = the Rust argument names in `desk/src/commands.rs:37-108`. A macro makes
  them and an `ARG_NAMES: &[(&str, &[&str])]` table. `pub fn to_body<T: Serialize>(args: &T) -> IpcResult<Zeroizing<Vec<u8>>>`
  writes into a zeroizing buffer (no `serde_json::Value`, so no unzeroized copy of a phrase or a secret).
  `pub async fn dispatch(core: &VaultService, ctx: Option<&OperatorContext>, command: &str, body: &[u8])
  -> IpcResult<Zeroizing<Vec<u8>>>`: unknown command → `remote_unsupported`; `Session` gate with `ctx = None` →
  `admin_session_required`; a `PayloadSource::Draft` → `remote_unsupported` (ADR-0034 point 5.6); otherwise parse the
  args, call the handler, serialize the result into a zeroizing buffer.
- `src/events.rs`: `pub enum WireEvent` (serde `tag = "event"`, the same fields as `desk/src/events.rs:10-87`) and
  `pub fn from_core(event: CoreEvent) -> WireEvent` — the mapping now in `desk/src/pump.rs:114-171`.
- serde derives needed by the wire (they do not change the specta output): add `Serialize` to `AuditQueryView`
  (`dto/audit.rs:31`), `ItemInputView` (`dto/items.rs:403`), `ItemFilterView` (`:456`), `WorkspaceInputView`
  (`:694`), `GrantInputView` (`dto/policy.rs:194`) and any nested input type that lacks it; add `Deserialize` to
  `RevealedSecretView` (`dto/items.rs:612`) and `TotpView` (`:660`).

Changed in desk:
- `ops/items.rs`, `ops/policy.rs`, `ops/agents.rs:17`, `ops/system.rs:22`, `ops/vault.rs:116`: keep `check(window,
  ...)` and `state.operator()`, then call the handler. `pump.rs:114` `on_event` maps through `WireEvent`.

Tests:
- adm unit: every `REMOTE_COMMANDS` entry has an `Args` type and an `ARG_NAMES` row; args JSON round-trips; unknown
  field → `invalid_request` (DEC-RM-16; a bad ID or time inside valid JSON stays `validation_failed`); unknown command
  → `remote_unsupported`; `Session` without ctx →
  `admin_session_required`; draft payload refused; `from_core` covers every `CoreEvent` variant.
- desk `tests/contract.rs` new `remote_commands_are_ipc_commands`: every remote name is in `ALL_COMMANDS`, and its
  `ARG_NAMES` equal the argument names in `bindings.ts` (the generated `TAURI_INVOKE("<name>", { ... })` call).

Done when: `cargo test -p cerberus-admin`; `cargo test -p cerberus-desktop` (all of `tests/ops.rs` unchanged, proving
the local behaviour is the same); `bindings_file_is_up_to_date` still passes.

---

## Step 3 — Core and crypto: verify a phrase, admin audit events

Files:
- `crates/cerberus-crypto/src/secret.rs:146` (`impl Vmk`): `pub fn ct_eq(&self, other: &Self) -> bool` with
  `subtle::ConstantTimeEq` (already a dependency of the crate).
- `core/src/vault/custody.rs`, next to `unlock_impl` (`:305`), an inherent method (not on `KeyCustody`, to keep the
  trait as in `docs/interfaces.md` section 4):
  ```rust
  pub async fn verify_operator_phrase(&self, operator: OperatorId, phrase: SecretString)
      -> Result<OperatorContext, CoreError>
  ```
  Takes `inner.gate`; `Locked` unless unlocked; `Conflict` when `operator` is not the session operator
  (`vault/state.rs:58`); `backoff::check`; runs the slot KDF with `blocking_raw` as `:327-334`; on
  `Integrity`/`SlotRule` the same failure path as `:349-361` (`record_unlock_failure`, `vault.unlock_failed`,
  `BadCredentials`); on success `ct_eq` with the live VMK (a mismatch is a failure plus an `IntegrityAlert`),
  `reset_unlock_failures`, and a context with the session role (keeps the header-MAC rule of DEC-FIX5-4).
- `core/src/audit/catalog.rs:51` (`catalog!`): `AdminApiStart "admin.api_start"`, `AdminSessionOpen
  "admin.session_open"`, `AdminSessionClose "admin.session_close"`, `AdminClientEnroll "admin.client_enroll"`,
  `AdminClientRevoke "admin.client_revoke"`. `core/src/audit/writer.rs:377` `LOCKED_TYPES`: add `admin.api_start`,
  `admin.client_revoke`, `admin.session_close` (these can happen while sealed).
- `core/src/vault/integration.rs` (pattern of `record_stranded_recovery`, `:99`): `pub async fn
  record_admin_event(&self, ctx: Option<&OperatorContext>, event: AdminAudit)` with `AdminAudit` holding enrolment ID,
  label, bound operator, reason, `unlocked: bool` — no secret, no certificate. Chain when unlocked, `audit_pending`
  when sealed.
- `docs/reference/audit-events.md` (the catalog test keeps it in step) and `ui/screens/audit/catalog.ts` (phrase list;
  `catalog.test.ts` keeps it in step).

Tests (`core/src/vault/tests/`, new `admin_verify.rs`): right phrase → context equal to the session, state unchanged;
wrong phrase → `BadCredentials`, `failed_unlocks` + 1, one `vault.unlock_failed`; sealed → `Locked`; another operator
→ `Conflict`; during the back-off → `UnlockBackoff` without running the KDF; the recovery slot ID → `BadCredentials`;
the five events write and verify in the chain.

Done when: `cargo test -p cerberus-crypto`, `cargo test -p cerberus-core`, `pnpm --dir apps/desktop/ui test
screens/audit`.

As built (DEC-RM-17): no crypto change — `Vmk::same_key` already is the constant-time compare. The check order is
`Locked` → back-off → unknown operator or recovery slot (a failed try, no KDF) → `Conflict` → KDF, so the recovery slot
is `BadCredentials` as the tests ask. A failure while unlocked writes `vault.unlock_failed` to the chain (with
`details.operator`). `AdminAudit { kind: AdminEventKind, enrolment, label, operator, reason: SessionCloseReason,
unlocked }`; `record_admin_event` returns `Result` and refuses `session_open` and `client_enroll` while sealed
(`Locked`), because the pending drain would drop them as unknown rows.

---

## Step 4 — Admin client certificate, registry, bundle

Files:
- `api/src/tls.rs`, after `issue_client` (`:284`): `pub fn issue_admin_client(&self, enrolment: &str, now: Timestamp)
  -> Result<IssuedCert, ServerError>`: ECDSA P-256, `CN = cerberus-admin <enrolment>`, EKU `clientAuth`,
  `ADMIN_CLIENT_DAYS = 90`.
- New `adm/src/clients.rs`: `ADMIN_CLIENTS_FILE = "admin-clients.json"`; `AdminClient { id: Uuid, label,
  operator_id, cert_sha256 (hex), created_at, not_after, revoked_at }`; `AdminClients::{load(path) (missing file =
  empty; mode other than 0600 = error), save(path) (tmp file 0600 + rename), find_live(&[u8; 32], now), add,
  revoke(id, now) -> bool, list}`.
- New `adm/src/bundle.rs`: `AdminBundle { format, version, id, label, url, operator_id, ca_pin, ca_cert_pem,
  client_cert_pem, client_key_pem: Zeroizing<String>, not_after }` with a redacted `Debug`; `write_new(path)`
  (`create_new`, mode 0600, from a zeroizing buffer); `read(path)` (64 KiB cap; checks `format`, `version == 1`,
  `https` URL, `sha256/` pin, that the CA PEM matches the pin, that the client certificate chains to the CA).

Tests: certificate verifies with `server_config` (`tls.rs:934`) client verifier, has the CN and EKU, lives 90 days;
registry round-trip, mode refusal, revoke, an expired entry is not live; bundle round-trip, no overwrite, wrong
version, pin mismatch.

Done when: `cargo test -p cerberus-api --lib tls`, `cargo test -p cerberus-admin`.

As built (DEC-RM-18): the enrolment ID is `clients::EnrolmentId` (`cerberus_types::uuid_id!`, UUIDv7); the registry
file is `{ "version": 1, "clients": [...] }` and refuses links, sizes over 1 MiB, bad hashes and duplicates;
`AdminClients` also has `get` and `live_count`. The bundle key is a `WireSecret` (zeroizing, redacted, with serde) and
`AdminBundle::read(path, now)` takes the time for the chain check; `check` also wants the CN `cerberus-admin <id>`, the
same `not_after` as the certificate, one certificate per PEM, and a key that matches the certificate.
`ca_sha256_hex()` gives the fingerprint to compare with `cerberusd status`. `server_config`'s client check moved into
`tls::client_verifier`, which the new test uses.

---

## Step 5 — Admin HTTP module in `cerberus-api`

Goal: `/admin/v1` exists when, and only when, the host passes an `AdminConfig`. No host does yet, so nothing changes at
run time in this step.

Files:
- New `api/src/admin/mod.rs`: `pub struct AdminState { clients: RwLock<AdminClients>, sessions: SessionTable,
  failures: per-enrolment limiter (5 / 15 min → 15 min), limits }`, `AdminState::new(clients, AdminLimits)`; methods
  `session_live(id)`, `revoke(id)` (drops its sessions), `reload_clients()`. `pub struct AdminConfig { pub state:
  Arc<AdminState> }`. The host makes the `Arc` so `cerberusd`'s socket task can share it (step 6).
- `api/src/admin/session.rs`: `SessionTable` — `open(enrolment, cert_sha256, ctx, epoch, now) -> (SessionId,
  WireSecret)` (token `cas_<uuidv7>.<base64url 32 bytes>`, store SHA-256), `check(token, cert_sha256, now,
  live_epoch) -> Result<Session, Refusal>`, `touch`, `close`, `drop_enrolment`, `sweep(now)`; caps 4 / 2 per
  enrolment (oldest out); idle and absolute limits.
- `api/src/admin/layers.rs`: `require_device` (reads `ConnInfo.client_cert_sha256`, `layers.rs:29-34`; `find_live`; else
  `403 admin_cert_required`) and `require_session` (bearer `cas_`; bound to the device; `401 admin_session_required`;
  binds the connection as an admin owner so the idle watcher keeps it, see `idle.rs` below; `touch`).
- `api/src/admin/routes.rs`: `GET /admin/v1/hello`, `POST /admin/v1/session` (body read into a zeroizing buffer with an
  8 KiB cap, as `d/src/unlock.rs:54` does; limiter; enrolment's operator must match → else `403 forbidden`; sealed →
  `unlock_with_phrase`, unlocked → `verify_operator_phrase`; audit `admin.session_open`), `DELETE /admin/v1/session`,
  `POST /admin/v1/rpc/{command}` (gate from `remote::gate`; body cap 1 MiB for `item_create`/`item_update`, else
  16 KiB; `rpc::dispatch`), `GET /admin/v1/events` (SSE: `core.subscribe()` → `events::from_core` → `event:` +
  `data:`; comment every 15 s; ends at session end, lock or revoke; at most 2 per session). Error body
  `{ request_id, error: IpcError }` with the status table below.
- `api/src/admin/errors.rs`: status by code — `vault_locked` 423, `not_found`/`remote_unsupported` 404,
  `forbidden`/`role_not_allowed`/`admin_cert_required` 403, `bad_credentials`/`admin_session_required` 401,
  `too_many_failures`/`rate_limited` 429 with `Retry-After`, `validation_failed`/`invalid_request` 400, `conflict` 409,
  else 500.
- `api/src/config.rs:84` `ApiConfig`: `pub admin: Option<AdminConfig>` (`loopback()` at `:102` sets `None`);
  `validate` (`:120`): admin needs `client_ca_der` (new `ServerError::AdminNeedsClientCa`). `Inner` (`:132`) and
  `AppState::new` (`:164`) keep the admin state; accessor `admin()`.
- `api/src/lib.rs:40` `app()`: `.merge(admin::router(state))` when `state.admin().is_some()`, before the `guard` and
  `envelope` layers, so `Host`/`Origin` rules and the response headers apply to `/admin` too.
- `api/src/idle.rs`: the connection owner becomes `enum ConnOwner { Agent(AgentId, AgentKeyId), Admin(SessionId) }`
  (`:81` field, `:122` `owner()`, `:322` the `owner_live` parameter of `watch`), plus `Owners::bind_admin` next to
  `bind` (`:529`, not counted in the per-agent cap). `api/src/server.rs:416-419`: the `owner_live` closure asks
  `key_active` for agents and `admin.session_live` for admin owners, so a revoked enrolment's connections close within
  about 1 s.
- `api/Cargo.toml`: `cerberus-admin.workspace = true`; `justfile` deps table: `cerberus-api` gets `cerberus-admin`.

Tests (new `api/tests/admin.rs`, ManualClock fixture like `api/tests/api.rs`, an admin and an agent certificate from
the vault CA):
1. No `AdminConfig` → every `/admin/...` path `404 route_not_found` (invariant 8).
2. No client certificate → `403 admin_cert_required`; agent certificate (CA-signed, not enrolled) → 403; revoked or
   expired enrolment → 403.
3. `hello` and `rpc/vault_status`, `rpc/vault_list_operators` with the device only → 200; `rpc/item_list` → 401.
4. Session open: wrong phrase → 401 `bad_credentials` and `failed_unlocks` + 1; six wrong in a row → `429` before the
   KDF; sealed vault → unlocks; unlocked by the same operator → state unchanged; another operator → 409; enrolment of
   another operator → 403.
5. A `cvt_` token on `/admin` → 401; a `cas_` token on `/v1/status` → 401.
6. Token over a second connection with a different enrolled certificate → 401.
7. Idle expiry and absolute expiry (ManualClock); a lock, and a new unlock, void every session; `DELETE` closes it and
   the vault stays unlocked (invariant 10).
8. `rpc/item_versions` (not allowlisted) → `404 remote_unsupported`; unknown JSON field → 400; body over the cap →
   413.
9. `rpc/request_approve` gives the agent a lease; `events` streams `AccessRequestCreated` then
   `AccessRequestResolved`; the stream ends at lock.
10. `Origin` header on `/admin` → `403 origin_refused`; wrong `Host` → 403.
11. Route list: exactly the five admin routes. `tests/openapi.rs` new `agent_openapi_has_no_admin_path`.
12. Log canary: the phrase and the `cas_` token never appear in the captured log (`api/tests/logging.rs` pattern).

Done when: `cargo test -p cerberus-api` (all old tests unchanged plus `admin.rs`); `just deps-check`.

As built (DEC-RM-19): core gained `VaultService::lock_epoch()` for the epoch binding; the shared answer types are in
`cerberus-admin` `wire.rs` (`HelloView`, `SessionOpenedView`, `AdminErrorBody`, the paths); `AdminState::new(clients,
limits).with_registry_file(path)` with `enroll`, `revoke(core, id)`, `reload_clients(core)`, `session_live(core, id)`,
`sweep(core)`, and a sweeper task in `start`. The failure limit lives in `admin/mod.rs`. `DELETE` answers 204. The
table adds 413 and 415. The log canary (group 12) is its own binary, `tests/admin_logging.rs`. Group 11's
`agent_openapi_has_no_admin_path` is in `tests/openapi.rs`.

---

## Step 6 — `cerberusd`: config, enrolment, approvals

Files:
- `d/src/config.rs`: `Config` (`:26`) gets `admin: AdminSettings { enabled, session_idle_seconds,
  session_max_seconds }`; `FileConfig` (`:99`) gets `admin: Option<FileAdmin>` (`deny_unknown_fields`); `resolve`
  (`:172`) reads `CERBERUSD_ADMIN_ENABLED`, `CERBERUSD_ADMIN_SESSION_IDLE_SECONDS`,
  `CERBERUSD_ADMIN_SESSION_MAX_SECONDS`; `validate` (`:234`): ranges 60–3600 and 900–86400, idle ≤ max.
- `d/src/daemon.rs`:
  - `serve` (`:105`): when `config.admin.enabled`, load `AdminClients` from `<data_dir>/admin-clients.json` (mode
    check, `DaemonError::Mode`), make the `Arc<AdminState>` before the socket task (`:142-143`) and pass it to
    `unlock::accept_loop`; `warn` log with the enrolment count; `core.record_admin_event(None, ApiStart)`.
  - `CoreConfig` (`:132-137`): `approvals_available: config.admin.enabled` (DEC-RM-7).
  - `start_http` (`:238-256`): with the admin API on, `api.client_ca_der = Some(core.tls_ca_cert().await?)` even when
    `require_mtls` is false, `api.require_client_cert = config.require_mtls`, `api.admin = Some(AdminConfig { state })`.
- `d/src/unlock.rs`: `Request` (`:36`) gets `#[serde(default)] op: Op` with `Unlock` (default, so today's clients keep
  working), `AdminEnroll { owner, operator, label, url }`, `AdminList`, `AdminRevoke { id }`; `phrase` becomes
  optional (required for `Unlock` and `AdminEnroll`). `handle` (`:210`) dispatches. `admin_enroll`: vault unlocked
  (else `vault_locked`), owner by `select_operator` (`:259`) and `verify_operator_phrase`, target operator by label,
  `tls_ca_material` → `LocalCa::from_parts` → `issue_admin_client`, add to the registry and save, audit
  `admin.client_enroll`, reply with the bundle fields. `Reply` (`:114`) gets `bundle: Option<...>` and `clients:
  Option<Vec<...>>`; the client read limit (`:336`) grows to 64 KiB for these replies.
- New `d/src/admin.rs`: client side — `enroll_with(socket, args, read_phrase) -> AdminBundle` and `write_new` of the
  bundle; `list_with`; `revoke_with` (through the socket; when the socket is not reachable, edit the file directly and
  say so).
- `d/src/main.rs` (`:29-41`): `Command::Admin { #[command(subcommand)] command: AdminCommand }` with `Enroll { label,
  url, owner, operator, out }`, `List`, `Revoke { id }`; `run` (`:65`) branches.
- `d/src/status.rs` (`:74`): print "admin API: on/off, N enrolled" from the config and the registry file (no network
  change).
- `d/Cargo.toml`: `cerberus-admin.workspace = true`; `justfile` deps table: `cerberusd` gets `cerberus-admin`.
- `docs/guides/cerberusd.md`: section "Remote admin from the desktop" (enable, unlock once, enroll, move the bundle,
  revoke, SSH tunnel recipe, `host_names`).

Tests: `config.rs` unit (default off, env wins, ranges, unknown `[admin]` key named in the error);
`d/tests/daemon.rs`: admin off → `/admin/v1/hello` 404; enroll over the socket while sealed → `vault_locked`; with a
wrong owner phrase → `bad_credentials`; good → registry entry and a bundle that `bundle::read` accepts; the new
certificate opens `hello`; `admin revoke` online drops the session, offline edits the file; an `ask_once` grant makes a
pending request (not `403 approval_unavailable`) when the admin API is on, and still 403 when it is off; old
`{"operator","phrase"}` unlock lines still work.

Done when: `cargo test -p cerberusd`; `just deps-check`; `systemd-analyze verify` unchanged (no unit change).

As built (DEC-RM-20): the socket `Request` is a flat struct with `op` and optional fields (and now
`deny_unknown_fields`); `accept_loop` takes a `SocketContext`. `admin::{enroll_with, list_with, revoke_with}` with
`EnrollRequest` and `Source::{Daemon, File}`; list also falls back to the file. An offline revoke is not audited (no open
vault). `Reply.bundle` is boxed. `status` also prints the CA pin and fingerprint. `https::request_as` sends a client
certificate. `packaging/systemd/cerberusd.toml.example` documents `[admin]`.

---

## Step 7 — `cerberus-client`: per-request bearer, generic SSE

Files:
- `crates/cerberus-client/src/transport.rs`: `PinnedHttps::with_client_cert(base_url, trust, cert_and_key:
  (PathBuf, PathBuf), timeout)` — `build` (`:195`) with `token: None`; `send_bearer(&self, request, bearer:
  Option<&WireSecret>)` sets a sensitive `Authorization` per request (shares the body of `send`, `:267`). `Request`
  still refuses a caller-set `Authorization`.
- `crates/cerberus-client/src/sse.rs`: a public `EventStream::next() -> Option<Result<(String, Vec<u8>), ClientError>>`
  (event name and data, comment lines skipped) taken out of `RequestEvents` (`:13-30`); `RequestEvents` uses it.
- `docs/interfaces.md` section 7.

Tests (`crates/cerberus-client/tests/pinning.rs` pattern): the client certificate is presented and verified by a test
server; a different bearer per request; the header is sensitive; SSE parser handles comments, multi-line data and
`event:` names.

Done when: `cargo test -p cerberus-client`; `just client-deps-check` (the client still has no vault or server crate).

As built (DEC-RM-21): `send_bearer(request, None)` sends no `Authorization`. Also `zeroizing_body` and
`Response::bytes_zeroizing` for phrase and reveal traffic. `EventStream` is re-exported at the crate root. The test
server of `tests/common/script.rs` gained `start_mtls`, `auths` and `client_certs`.

---

## Step 8 — Desktop remote backend (Rust)

Goal: with an active remote profile, the desktop opens no vault and forwards the allowlisted commands. Without one,
nothing changes.

Files:
- `desk/Cargo.toml`: `cerberus-client.workspace = true`; `justfile` deps table: desktop gets `cerberus-client`.
- `desk/src/prefs.rs:43` `Prefs`: `remote: RemotePrefs { active: Option<String>, profiles: Vec<RemoteProfile { id,
  label, url, ca_pin, operator_id, not_after }> }` with `#[serde(default)]` (old files load).
- New `desk/src/remote/mod.rs`: `RemoteBackend { profile, http: PinnedHttps, session: Mutex<Option<RemoteSession {
  token: WireSecret, view: SessionView, idle_seconds }>>, status: watch::Sender<RemoteStatusView>, last_keepalive }`;
  `hello()`; `call<R: DeserializeOwned>(command, body) -> IpcResult<R>` (local gate check first: off the list →
  `remote_unsupported` with no network call; decodes `{ request_id, error }` into `IpcError`; other error bodies by
  status; `401 admin_session_required` drops the session and emits `VaultStateChanged { sealed }`); `open_session`;
  `close_session`; `keepalive` (at most every 30 s); `wipe()` (drops the token).
- New `desk/src/remote/profile.rs`: `import(state, path)` (`state.is_picked(path)`, `state.rs:676`; `bundle::read`;
  files to `<data_dir>/remote/<id>/` with `cert.pem`, `ca.pem`, `key.pem` mode 0600 in a 0700 folder; profile into
  prefs); `trust(profile)` (pin + CA file).
- New `desk/src/remote/pump.rs`: SSE loop with reconnect (1 s doubling to 30 s), `WireEvent` → the Tauri events of
  `desk/src/events.rs`, pending count through `call("request_list_pending")`, `tray::update` (`tray.rs:129`),
  `windows::show_approval` / `close_approval` (`windows.rs:18`, `:49`); the side effects shared with the local pump are
  moved into `pub(crate)` helpers in `pump.rs` (`recount` at `:90`, `on_state` at `:57`).
- `desk/src/state.rs`:
  - `Inner` (`:88`): `remote: Option<Arc<RemoteBackend>>`.
  - `DesktopState::open` (`:194`): when `prefs.remote.active` names a profile, build the backend and return **before**
    `note_stranded` (`:234`) and `open_service` (`:237`): no store, no service, no server. A broken profile (files
    missing) logs an error and opens in local mode with `remote.active` cleared.
  - `remote()` accessor; `core()` (`:402`): in remote mode `remote_unsupported` ("not available for a remote server").
  - `shutdown` (`:386`): `close_session` with a 2 s bound. `emergency_wipe` (`:368`): `wipe()`. `attach_os_events`
    (`:480`): in remote mode an OS sleep or screen lock closes the remote session (DEC-RM-8). `ui_activity` (`:515`):
    remote keepalive.
- `desk/src/commands.rs:22-35`: the `ipc!` macro gets a second arm, `ipc!(@remote name(args) -> T)`, used for the
  allowlisted commands only. It runs `guard::check` as today; in remote mode it builds a borrowed `#[derive(Serialize)]
  struct Args<'a> { arg: &'a Ty, ... }`, `rpc::to_body`, and returns `remote.call::<T>(name, body)`; else it calls
  `ops::name` as today. The plain arm (local-only commands) returns `remote_unsupported` in remote mode without
  serializing anything, so their argument types need no `Serialize`. A contract test checks that the `@remote` set
  equals `REMOTE_COMMANDS`.
- `desk/src/ops/vault.rs`: `vault_status` (`:24`) in remote mode builds the view from `rpc/vault_status` and this
  desktop's session (DEC-RM-10), and fills the new field; `vault_unlock` (`:83`) → `open_session`; `vault_lock` →
  forwarded, then the session is dropped.
- `cerberus-admin` `dto/vault.rs`: `VaultStatusView` (after `stranded_restore`, `:236`) gets `remote:
  Option<RemoteStatusView { profile_id, label, url, server_state, reachable, has_session, server_version }>`; `None`
  in local mode.
- New IPC commands, in `desk/src/ops/remote.rs`, `commands.rs`, `names.rs` (`ALL_COMMANDS` + 5), `lib.rs`
  (`collect_commands!`), `capabilities/main.json` (main window only, not `APPROVAL_COMMANDS`):
  - `remote_status() -> RemoteOverview { mode, active, profiles, remote_commands }` (the UI reads the allowlist from
    here instead of copying it);
  - `remote_import_bundle(path) -> RemoteProfileView` (URL, pin, CA fingerprint, expiry, operator; nothing secret);
  - `remote_activate(profile: Option<String>)` — takes `tauri::AppHandle`; refused while a local vault is unlocked;
    `None` = back to local mode; saves prefs; closes a session; `app.restart()`;
  - `remote_disconnect()` — closes this desktop's session, the server vault stays as it is;
  - `remote_forget(profile)` — removes its folder and prefs entry; refused for the active profile.
- `desk/src/lib.rs` `setup` (`:159-188`): `remote::pump::spawn` instead of `pump::spawn` (`:187`) in remote mode.
- `docs/interfaces.md` section 9: the new commands, a "remote" column for every command, the `remote` status field.

Tests:
- `desk/tests/remote.rs` with the `FakeShell` of `tests/ops.rs:21` and an in-process `cerberus-api` server with an
  `AdminConfig` and a ManualClock core (as `tests/acceptance/tests/harness/mod.rs` builds its server): import a
  bundle; open the state in remote mode (no vault file is made in the data folder); `vault_status` = `sealed` with
  `remote.reachable`; `vault_unlock` → `unlocked`; `item_create` / `item_list` / `item_reveal` round-trip;
  `item_versions` → `remote_unsupported` and the server saw no request; server-side lock → the desktop reports
  `sealed` and emitted `VaultStateChanged`; `remote_disconnect` leaves the server unlocked; `shutdown` closes the
  session; the token never shows in the log capture.
- `tests/contract.rs`: `bindings_hold_every_command_and_event` (`:89`) and `capability_files_match_the_label_guard`
  (`:133`) cover the new commands; `remote_arm_matches_the_allowlist`.
- `tests/ops.rs` unchanged: local mode is the same.

Done when: `cargo test -p cerberus-desktop`; `bindings.ts` regenerated (debug run or `export_bindings`) and
committed; `just deps-check`.

As built (DEC-RM-23): the macro has three arms, `@remote` (generic forward), `@both` (`ops` handles both modes:
`vault_status`, `vault_unlock`, `vault_lock`, `vault_panic`, `file_pick_open`, the `remote_*` commands) and the plain
local-only arm; `remote::CUSTOM_REMOTE_COMMANDS` names the allowlisted commands that are not `@remote`.
`RemoteStatusView` also has `operator_id`, `not_after` and `problem`; `RemoteProfileView` has `ca_sha256` and `active`.
`remote_activate` runs the quit work, then `AppHandle::request_restart` (safe with the single-instance plugin, checked in
its source). The pump is `remote::pump::drive` (no Tauri) plus a Tauri half; the OS hook got a callback form
(`os_hooks::OsWatcher`). In remote mode the tray's Lock is Disconnect. `tests/remote.rs` runs a real `cerberusd` in
process (dev-dependency) rather than a hand-built API server. The test found a server race: `rpc/vault_lock` and
`vault_panic` answers were cut by the idle watcher; those calls no longer bind the connection to the session.

---

## Step 9 — UI

Files (rebase first: `ui/screens/unlock/*` and `ui/shell/Rail.tsx` have other uncommitted work right now):
- `ui/ipc/queries.ts`: `useRemoteOverview()`; `ui/state/` new `backendMode.ts` (`useBackendMode()`, from
  `vault_status.remote`) and `useRemoteUnsupported(command)` (true in remote mode when the command is not in
  `remote_commands`).
- Unlock: `ui/screens/unlock/route.tsx:87` `UnlockScreen` shows `RemoteUnlock` in remote mode (server label and URL,
  "Cannot reach the server" with Retry and "Use the local vault"); `UnlockForm.tsx` hides "Use recovery key" in remote
  mode; `NoVault` and `UnlockForm` get "Connect to a remote server" → new `ConnectRemoteDialog.tsx`
  (`file_pick_open` with the `cerberus-admin` extension → `remote_import_bundle` → shows URL, pin, fingerprint,
  operator, expiry, with "Compare these with `cerberusd status` on the server" → "Connect" = `remote_activate(id)`).
- Settings: `ui/screens/settings/route.tsx:16` `SECTIONS` adds `"remote"`; new `RemoteSection.tsx` (profiles, import,
  test connection, disconnect, "Lock the server vault", use local vault, forget). In remote mode the Security,
  Network and Backup sections show one `LocalOnlyNotice` ("Not available for a remote server") instead of their
  controls; Appearance (UI scale) stays.
- Shell: `ui/shell/TopBar.tsx` badge "Remote: <label>" and a Disconnect action; `PanicDialog.tsx` and `LockedState.tsx`
  say "the server vault" in remote mode. `ui/shell/guard.ts` (`resolveRoute`, `:19`) needs no change (DEC-RM-10).
- Disabled actions in remote mode (through `useRemoteUnsupported`): editor SSH generate and import, password
  generator, copy buttons, versions tab; agent create, edit, status, keys, client certificate, snippets; policy
  simulate; leases "revoke all"; audit verify and export; CSV import and export.
- `ui/i18n/en.ts` error texts: `remote_unsupported`, `remote_unreachable`, `remote_pin_mismatch`,
  `remote_protocol_mismatch`, `admin_session_required`, `admin_cert_required`; screen messages in each
  `messages.ts`. `ui/ipc/mock/` gets remote responses for dev and tests.

Tests (vitest, jsdom): connect flow; unreachable server; remote unlock without the recovery link; Remote settings
import and forget; disabled actions show the notice; panic text; guard tests unchanged.

Done when: `pnpm --dir apps/desktop/ui test`, `pnpm --dir apps/desktop/ui lint` (or the `ui-check` recipe), and a
headless smoke run on Xvfb (connect to a local `cerberusd` with the admin API on).

As built (DEC-RM-24): shared pieces in `ui/remote/` (connect dialog, profile facts, local-only notice). The connect link
sits under the compact unlock card (last in the tab order), not in it. The Settings section is `server` ("Remote
server"), because `remote` is already the RustDesk section. In remote mode Lock is Disconnect everywhere (collar,
Ctrl+L, palette, tray). Local-only areas show one notice; single local-only buttons are not shown. The Xvfb smoke run
of the real app was not made (no GUI launch in this build); screenshots are headless Playwright against the mock.

---

## Step 10 — Acceptance A13, desktop against the real daemon, docs

Files:
- `tests/acceptance/Cargo.toml` dev-deps: `cerberusd`, `cerberus-admin` (dev edges are free, DEC-T10-10).
- `tests/acceptance/tests/harness/remote.rs` and `acceptance.rs` new
  `a13_remote_admin_through_cerberusd`: write a `cerberusd.toml` (admin on, free port, the harness vault in a 0700
  folder), run `cerberusd::daemon::serve` in-process, `unlock::unlock_with` with the phrase, `admin::enroll_with` to get
  a bundle, then with `reqwest` (client identity from the bundle) and with `PinnedHttps`:
  1. a second daemon with the admin API off → `/admin/v1/hello` 404;
  2. no certificate → 403; agent certificate → 403;
  3. `rpc/item_list` without a session → 401; wrong phrase → 401; right phrase → session;
  4. `item_create`, `item_list`, `item_reveal`; the audit rows have actor `operator:<id>` and one
     `admin.session_open`;
  5. an agent with an `ask_once` grant on a `prod` item → pending request; `events` shows it; `rpc/request_approve` →
     the agent's reveal works (approvals over the admin channel);
  6. `DELETE` the session → the agent's `/v1/status` still works (the vault stays unlocked);
  7. `admin revoke` → the next admin call 403;
  8. `rpc/vault_lock` from a new session → agents get 423.
- `desk/tests/remote_daemon.rs` `r1_desktop_state_in_remote_mode_against_cerberusd`: the same daemon start, then a
  `DesktopState` in remote mode runs `vault_status`, `vault_unlock`, `item_list`, `request_approve`, `vault_lock`.
- Docs: `docs/interfaces.md` (sections 5 and 9, done in steps 5 and 8), `docs/guides/user-guide.md` ("Remote mode"),
  `docs/guides/security-model.md` (the new boundary in plain words), `docs/acceptance-report.md` (A13),
  `docs/security/threat-model.md` (status line: built, with the test names).

Done when: `cargo test -p cerberus-acceptance --test acceptance a13`, `cargo test -p cerberus-desktop --test
remote_daemon`, and then one full `just check` and `just test` when no other build runs.

---

## Test plan summary

| Level | Where | Covers |
|---|---|---|
| Unit | adm (`remote.rs`, `rpc.rs`, `clients.rs`, `bundle.rs`, `events.rs`) | allowlist, args, dispatch gates, registry, bundle, event mapping |
| Unit | core `vault/tests/admin_verify.rs`, crypto `Vmk::ct_eq` | phrase check while unlocked, back-off, audit events |
| Unit | d `config.rs` | `[admin]` keys, env, ranges |
| Integration | `api/tests/admin.rs` (12 groups above), `api/tests/openapi.rs` | the two gates, sessions, RPC, SSE, route list, log canary (invariants 8–10) |
| Integration | `d/tests/daemon.rs` | enrolment over the socket, revoke, approvals on/off, old unlock lines |
| Integration | `crates/cerberus-client/tests/pinning.rs` | client certificate, per-request bearer, SSE parser |
| Integration | `desk/tests/remote.rs`, `desk/tests/contract.rs`, unchanged `desk/tests/ops.rs` | proxy, status mapping, local-only refusal without network, local mode unchanged |
| Acceptance | `tests/acceptance` A13, `desk/tests/remote_daemon.rs` | real `cerberusd` with the admin API on and a desktop-side client end to end |
| UI | vitest in `ui/` | connect flow, disabled states, settings section |
| Manual | Xvfb smoke | the desktop connects to a local `cerberusd` through the bundle and approves a request |

## Follow-ups (not in the MVP, DEC-RM-14)

1. Copy to clipboard in remote mode: `clipboard_copy_secret` as `item_reveal` over RPC plus the local clipboard timer
   (`state.rs:690`), with the secret never in the webview.
2. More commands on the allowlist: `item_versions`, `item_restore_version`, `agent_create` / keys / status (tokens are
   one-time values: the desktop's `set_one_time` holds them), `lease_revoke_all`, `audit_verify`, vault settings.
3. Switch the session operator on an unlocked server vault.
4. A sealed mirror of `admin-clients.json`, checked at unlock (AR-19). The client key in the OS keychain (AR-20).
5. `admin.bind` (a separate admin listener), an encrypted bundle.

## Open points to confirm during phase 2

- `tauri::AppHandle::restart` with the single-instance plugin: check on Linux that the new process starts cleanly
  (else replace the restart with an in-process switch that reuses the restore close path, `ops/restore.rs:301`).
- `specta` in `cerberus-admin` is also compiled into `cerberusd`. It is a derive crate with no runtime cost; if build
  time matters, put the derives behind a `specta` feature that only the desktop enables.
- The response size limit of the desktop client for `item_reveal` of a browser session: 2 MiB.
