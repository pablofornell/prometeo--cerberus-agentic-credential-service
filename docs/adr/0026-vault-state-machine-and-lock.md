# ADR-0026: Vault state machine, unlock limits and lock triggers

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.2, T05
- Related: ADR-0008, ADR-0009, ADR-0012, ADR-0013, ADR-0018, ADR-0019, ADR-0022

## Context

Key custody is the core risk. States and transitions must be few and exact.

## Decision

### States
```
NoVault ──create──► Unlocked
Sealed ──unlock ok──► Unlocked ──lock trigger──► Locking ──keys erased──► Sealed
   ▲  └─unlock fail─► Sealed (counter + back-off)
```
- `NoVault`: no file. Only `vault_create` and `backup_restore` IPC work.
- `Sealed`: file open, no keys. Agent API gives 401/423. Sweeper runs.
- `Unlocked`: keys and index in memory. Holds `operator_id`, `role`, `unlocked_at`, `last_activity_at`.
- `Locking`: short. New calls get 423. In-flight calls finish or are cut after 2 s. Then keys are erased.

The state is in one `tokio::sync::RwLock<VaultState>` inside `VaultService`. Keys live in `LockedBox`es (ADR-0012)
inside the `Unlocked` variant. Leaving `Unlocked` drops the variant, and drop zeroizes.

### Unlock limits
- After 5 failures in a row: wait `min(2^(n-5) s, 900 s)` before the next try. The counter is in the header
  (ADR-0013), so a restart does not reset it. The unlock screen shows the countdown.
- A recovery-key typing error (bad checksum) does not count.

### Lock triggers
| Trigger | Default | Setting |
|---|---|---|
| Manual lock (button, tray, Ctrl/Cmd+L) | on | — |
| Idle: no activity for `idle_lock_seconds` | 1800 s | 60..86400, or off |
| Hard limit: `max_unlocked_seconds` after unlock | 43200 s (12 h) | 900..604800, or off |
| OS sleep or screen lock | on | `lock_on_os_lock` |
| App quit, SIGTERM | on | — |
| Panic (Rust panic) | on | — |
| Panic button | on | — |

- Activity = operator input in the UI, and (if `agent_activity_keeps_unlocked`, default true) a successful agent
  API call. The hard limit stops agents from keeping the vault open forever.
- OS hooks are a trait (`OsLockEvents`) implemented in `cerberus-desktop`: Linux logind `PrepareForSleep` and
  session `Lock` signals over D-Bus, macOS workspace sleep and screen-lock notifications, Windows
  `WTS_SESSION_LOCK` and power-suspend messages.
- Panic: release profile uses `panic = "abort"`. A panic hook calls `KeyCustody::emergency_wipe()` (sync, no await),
  then the process aborts. Core dumps are off (ADR-0012).

### What lock does
Erase VMK, derived keys, the index and decrypted settings. Cancel pending approvals. Send a final SSE event
(`cancelled`) and close streams. Close SSH signing sockets. Write `vault.lock` with the trigger as `details.reason`.
Leases are kept (ADR-0019) except for the panic button.

## Consequences

- An agent server on the desktop app stays usable for at most 12 h without a person, by default.
- On Linux without logind, the OS hook is off and the UI shows this in health.

## Alternatives considered

- **Idle counts only operator input.** Rejected. Agents would get 423 30 minutes after the person stops typing, which
  defeats the main use case.

## Amendment (2026-11-17, security review fix, DEC-FIX5-1, DEC-FIX5-4)

- The erase runs in a task on the runtime the service was opened on. A caller that gives up (timeout, `select!`) does
  not stop it. An OS hook may call from any thread: it reads `lock_on_os_lock` once, marks `Locking` and starts the
  full lock (cancel requests, `vault.lock`, `StateChanged`) on that runtime. `emergency_wipe()` is for the panic hook
  only. The idle loop finishes a lock that is still at `Locking` (backstop).
- A panic button press during a pending lock joins it: that lock revokes all leases. If the lease revoke fails, the
  next unlock revokes all leases before the vault serves calls.
- A lock request during create leaves the new vault `Sealed`; the recovery key is still shown.
- When the header MAC fails at unlock, the session has viewer rights only, and every key slot change is refused, so
  a new header MAC never hides an edited file.

## Amendment (2026-11-17, T27-C, AUD-16, DEC-T27-C-9)

- Linux: the logind watcher also follows the `LockedHint` of the session, and the sleep watcher holds a logind
  `delay` inhibitor until the vault is locked (at most 3.5 s), so the keys are gone before the machine suspends.
- macOS and Windows: there is no hook. The Tauri runtime (`tao`) has no sleep or screen-lock event on desktop, no safe
  crate is used for it, and a native hook needs unsafe code that ADR-0012 allows only in `cerberus-crypto`. **Accepted
  risk** (owner: Tauri Builder): on these systems the vault stays unlocked until the idle lock (30 min) or the hard lock
  (12 h), also while the screen is locked, and keys can reach a hibernation image in that time. The status view shows
  the hook as off. A later task may add the hooks in `cerberus-crypto` under the ADR-0012 rules.
