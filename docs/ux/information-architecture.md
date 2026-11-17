# Cerberus information architecture (T14)

## 1. Windows and routes

| Window label | Size | Routes | Notes |
|---|---|---|---|
| `main` | min 960 × 640, default 1280 × 820 | all screens below | Router guard reads `vault_status` first |
| `approval` | 400 × 560, always on top, not resizable | `/approval` only | Only `request_list_pending`, `request_approve`, `request_deny`, `vault_status`, `vault_lock`, `vault_panic`, `ui_activity` (ADR-0018, E-12) |

Router guard on `main`:

| `vault_status.state` | Allowed routes | Default |
|---|---|---|
| `no_vault` | `/create`, `/unlock` (restore only) | `/create` |
| `sealed` | `/unlock` | `/unlock` |
| `locking` | none (shows the locked state) | — |
| `unlocked` | all app routes | `/dashboard` |

## 2. Navigation

```
Rail (232 px)                          Top bar
├─ Cerberus (gate mark) → Dashboard    ├─ [crumb ›] Page title
├─ Dashboard            G D            ├─ page actions (New item, New agent, Export …)
├─ Vault                G V            └─ Search or run a command   Ctrl K
│    └─ Item editor (from Vault, N)
├─ Agents               G A
├─ Policies             G P
├─ Approvals (count)    G R
├─ Leases               G L
├─ Audit                G U
├─ ─────
├─ Settings             G S
└─ Collar: unlocked by · auto-lock ring · Lock · Lock and revoke all
```

Below 760 px the rail becomes a top strip with horizontal scroll; the collar keeps the Lock and panic buttons.

## 3. Screen to IPC map

Every screen loads only through these commands (`docs/interfaces.md` section 9). Events are `tauri-specta` events
with IDs and metadata only.

| # | Screen | Loads | Actions | Listens to |
|---|---|---|---|---|
| 1 | Create vault | `vault_status` | `passphrase_strength`, `passphrase_generate`, `kdf_benchmark`, `vault_create`, `backup_restore` (from empty unlock) | — |
| 2 | Unlock | `vault_status`, `vault_list_operators` | `vault_unlock`, `vault_unlock_recovery`, `backup_restore` | `vault-state-changed`, `header-mismatch` |
| 3 | Dashboard | `vault_status`, `request_list_pending`, `lease_list`, `item_list` (expiring), `audit_verify`, `network_status`, `settings_get` | `vault_lock`, `vault_panic`, `agent_set_status` (from mass-read alert) | `agent-activity`, `access-request-created`, `access-request-resolved`, `lease-changed`, `autolock-tick`, `mass-read-alert`, `integrity-alert` |
| 4 | Vault browser | `workspace_list`, `item_list { filter }`, `item_get`, `item_versions` | `item_reveal`, `clipboard_copy_secret`, `item_totp_preview`, `item_delete`, `item_restore_version`, `workspace_put`, `workspace_delete`, `csv_import` | `lease-changed` (exposed-to) |
| 5 | Item editor | `item_get`, `workspace_list`, `settings_get` | `item_create`, `item_update`, `password_generate`, `ssh_key_generate`, `ssh_key_import`, `item_totp_preview` | — |
| 6 | Agents | `agent_list`, `agent_snippets`, `grant_list { agent_id }` | `agent_create`, `agent_update`, `agent_set_status`, `agent_key_create`, `agent_key_rotate`, `agent_key_revoke`, `agent_issue_client_cert` | `agent-activity` (last seen) |
| 7 | Policies | `agent_list`, `grant_list`, `workspace_list`, `policy_simulate` | `grant_put`, `grant_delete` | — |
| 8 | Approval (window) | `request_list_pending`, `vault_status` | `request_approve { id, option }`, `request_deny { id }` | `access-request-created`, `access-request-resolved`, `vault-state-changed` |
| 9 | Leases and sessions | `lease_list`, `item_list { kind: session_token / browser_session }` | `lease_revoke`, `lease_revoke_all`, `vault_panic`, `item_delete` | `lease-changed` |
| 10 | Audit | `audit_query`, `audit_verify` | `audit_export` | `integrity-alert` |
| 11 | Settings | `settings_get`, `network_status`, `vault_list_operators` | `settings_set`, `phrase_change`, `recovery_rotate`, `operator_add`, `operator_remove`, `operator_set_role`, `kdf_benchmark`, `network_set_bind`, `tls_export_ca`, `tls_load_custom`, `backup_create`, `backup_restore`, `csv_export` | — |
| all | Shell | `vault_status` | `vault_lock`, `vault_panic`, `ui_activity` | `vault-state-changed`, `autolock-tick` |

Gaps found for T15 (logged as DEC-036): the recovery key and a new agent token need a clipboard copy with the
30 s clear, but `clipboard_copy_secret` takes an `item_id`. The dashboard "expires soon" list uses `item_list` and
`lease_list`; no extra command is needed.

## 4. States per screen

| # | Ready | Empty | Loading | Error | Locked |
|---|---|---|---|---|---|
| 1 | Wizard, step by step | Blank step 1 | Creating: list of steps | Cannot write the vault file | A vault already exists |
| 2 | Operator list + phrase | No vault on this device (create, restore) | Deriving the key (rings turn) | Wrong phrase, try count | Back-off countdown, input disabled |
| 3 | Gate band, queue, health, feed, expiring | The gate is ready: 3 numbered first steps | Skeleton + turning rings | Cannot read the vault status | Shared locked state |
| 4 | Facets, list or grid, drawer | No items: New item, Import CSV | Skeleton in 3 columns | Cannot load items (index) | Shared locked state |
| 5 | Form for the chosen kind + match preview | Blank form | Skeleton | Field errors + banner | Shared locked state |
| 6 | List + detail, keys, snippets | No agents yet | Skeleton | Cannot load agents | Shared locked state |
| 7 | Builder, grants, simulator | Agent can see nothing (safe default) | Skeleton | Grant not saved (owner only) | Shared locked state |
| 8 | Request card | Nothing waits for you | Skeleton card | This request ended | The vault locked: requests cancelled |
| 9 | Stop band, leases, session items | No agent holds access now | Skeleton | Cannot load leases (panic still works) | Shared locked state |
| 10 | Chain badge, filters, timeline | No events match these filters | Checking the chain | Cannot read the audit log | Shared locked state |
| 11 | All sections | Defaults: no backup yet, only one owner | Skeleton | Setting not saved (owner only) | Shared locked state |

Extra prototype variants: viewer role (3, 4, 6, 7), mass-read and integrity alerts (3), grid view (4), kind and prod
(5), token reveal and create form (6), prod with "never" (7), burst and decided (8), chain broken (10), operator (11),
weak phrase (1), recovery / idle / panic / failed tries (2).

## 5. Keyboard map

| Keys | Scope | Action |
|---|---|---|
| `Ctrl/Cmd K` | everywhere in `main` | Command palette |
| `Ctrl/Cmd L` | `main`, unlocked | Lock now (`vault_lock`) |
| `G` then `D V A P R L U S` | not in a text field | Go to Dashboard, Vault, Agents, Policies, Approvals, Leases, Audit, Settings |
| `/` | screens with search | Focus the search field |
| `N` | app screens | New item |
| `?` | everywhere | Shortcut list |
| `Esc` | dialog, drawer, palette | Close (never confirms) |
| `↑ ↓` | lists, palette | Move selection; `Enter` opens |
| `← →` | tabs, segmented controls, mode picker | Move and select |
| Hold `Space` / `Enter` 500 ms | eye button on a secret | Reveal; press again to hide |
| Hold `A`, `F`, `S` 600 ms | approval window | Approve once, 15 minutes, session |
| `D` | approval window | Deny (no hold: deny is the safe side) |
| Hold 1 s | panic confirm button | Lock and revoke all |

No single-key shortcut fires while focus is in an input. No shortcut approves without a hold. There is no
shortcut for "Lock and revoke all" outside the palette, so it cannot happen by a stray key.

## 6. Command palette actions

Groups and items (filter matches English and the current language):

| Group | Action | Result |
|---|---|---|
| Go to | Dashboard, Vault, Item editor, Agents, Policies, Approvals, Leases, Audit, Settings | Route change |
| Create | New item, New agent, New grant | Opens the form |
| Vault | Lock vault (`Ctrl L`) | `vault_lock` |
| Vault | Lock and revoke all | Opens the panic confirm (hold 1 s) |
| Vault | Verify audit chain | `audit_verify`, opens Audit |
| Vault | Export CA certificate | `tls_export_ca` via native save dialog |
| Vault | Create backup | `backup_create` via native save dialog |
| View | Switch theme, Switch language, Keyboard shortcuts | Local UI state |

T16 adds item and agent search results below the actions (from `item_list { q }` and `agent_list`), metadata only.

## 7. Content hierarchy rules

- Page title (h1) in the top bar; panel titles are h2; no deeper than h3.
- Lists show: kind icon, title, one-line context (kind in workspace, target in mono), then badges in this order:
  agent-made, TTL ring, role chip, environment badge (rightmost, so `prod` lines up down the list).
- Times: relative for the past ("1 min ago"), countdown for the future ("4:10", "4 h 16 m"), absolute in audit.
