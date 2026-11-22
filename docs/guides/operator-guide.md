# Operator guide

This guide is for the owner of a vault, and for anyone who runs the server side. It covers roles, lock settings,
network rules, limits, platform gaps and the open items you should know about. Read the
[security model](security-model.md) first if you want the full picture.

For the desktop screens, read the [user guide](user-guide.md). For a server with no screen, read the
[headless daemon guide](cerberusd.md). For backups, read [backup and restore](backup-and-restore.md).

## Read this first: roles do not limit an OS account

**AR-9.** The operator role does not limit an operator who shares the OS account with the vault file.

Roles are checked by the app. They are not a crypto boundary. Every key slot wraps the same Vault Master Key (VMK).
An operator who can read the vault file, and who knows their own phrase, can unwrap the VMK offline. That operator
can then sign the header again, or read every item. The role does not stop this.

What this means for you:

- Roles limit people who have no access to the vault file. They do not limit a person with that access.
- Give the vault file, its folder and its backups only to people who may read every item.
- A viewer with memory access to an unlocked vault can also read everything (threat model E-3).
- If two people must not see each other's items, keep them in different vaults under different OS accounts.

Sources: [ADR-0009](../adr/0009-operators-key-slots-roles.md), [threat model AR-9](../security/threat-model.md#7-accepted-risks),
audit AUD-26 in the [audit report](../security/audit-report.md#aud-26--info--dec-fix5-4-the-operator-role-is-not-in-the-slot-wrap-aad).

## Roles

Each operator has one passphrase key slot. Every slot opens the same VMK. The recovery key has no operator, and it
opens with owner rights.

| Action | Owner | Operator | Viewer |
|---|---|---|---|
| Unlock, lock, panic (lock and revoke all) | yes | yes | yes |
| Browse metadata, view the audit log, verify the chain | yes | yes | yes |
| Reveal or copy a secret in the app | yes | yes | no |
| Create, edit, delete items and workspaces | yes | yes | no |
| Create, rotate, revoke agents and keys | yes | yes | no |
| Create and edit grants (not `allow_prod_auto`) | yes | yes | no |
| Approve or deny access requests | yes | yes | no |
| Revoke leases | yes | yes | yes |
| Set `allow_prod_auto` on a grant | yes | no | no |
| Add or remove operators, change roles | yes | no | no |
| Network bind, TLS, key derivation, session time-to-live settings | yes | no | no |
| Rotate the recovery key, restore a backup | yes | no | no |
| Make a backup | yes | yes | no |
| Export CSV (plain text secrets) | yes | no | no |
| Import CSV | yes | yes | no |
| Change your own phrase | yes | yes | yes |

Rules that always apply:

- At least one owner slot must exist. The app refuses to remove or demote the last owner.
- A recovery key use writes `vault.unlock_recovery` to the audit log. The app then asks the person to set a new phrase.
- Operator labels are plain text in the key slot table. Anyone with the file can read them.

## Lock settings

| Setting | Default | Range or values | Who can change it |
|---|---|---|---|
| Idle lock | 30 minutes | off, or 60 to 86400 s | Owner or operator |
| Hard limit after unlock | 12 hours on the desktop, off on `cerberusd` | off, or 900 to 604800 s | Owner or operator |
| Lock on OS sleep and screen lock | on | on or off | Owner or operator |
| Agent calls count as activity | on | on or off | Owner or operator |

With "agent calls count as activity" on, a busy agent keeps the vault unlocked. The idle lock does not fire then. The
hard limit still does, when it is on.

The vault also locks at once on a manual lock, a panic, and when a restore starts.

## Items and policy settings

| Setting | Default | Range | Who |
|---|---|---|---|
| Session token time to live (default) | 3600 s | 60 s up to the maximum | Owner |
| Session token time to live (maximum) | 86400 s | 300 to 604800 s | Owner |
| Versions kept per item | 10 | 1 to 100 | Owner |
| Approval wait | 120 s | 30 to 600 s | Owner |
| Deny cooldown (same agent and item) | 600 s | 0 to 86400 s | Owner |
| Auto lease length | 900 s | 60 to 86400 s | Owner |
| Pending requests per agent | 5 | 1 to 50 | Owner |
| Access requests per agent per window | 10 per 600 s | count 1 to 1000, window 60 to 86400 s | Owner |
| Secret reads per agent per minute | 60 | 1 to 10000 | Owner |
| Distinct items read per agent per hour | 30 | 1 to 10000 | Owner |

A session approval lasts until the vault locks, capped at 8 hours (or the item's own session maximum, if shorter).

## Limits that are fixed in the build

These limits are set in the code. There is no setting for them in the app or in the daemon config. A change needs a
new build.

**Request and token limits** ([`AuthLimits`](../../crates/cerberus-core/src/auth/limits.rs), ADR-0030):

| Limit | Value | Result |
|---|---|---|
| Failed token checks per source address | 30 per second, burst 60 | `429 rate_limited` |
| Requests per agent (good tokens) | 20 per second, burst 40 | `429 rate_limited` |
| Failed checks from one address | 10 in 300 s starts a 300 s lockout of that address | `429 too_many_failures` |
| Failed checks from all addresses together | 100 in 300 s starts a 300 s lockout for every failing check | `429 too_many_failures` |

A good token is never refused by the failed-check limits, even from a locked address. A flood of bad tokens cannot
lock out an agent that sends a good token. See [DEC-T27-E-1](../decisions.md).

**Connection limits and deadlines** ([`ApiLimits`](../../crates/cerberus-api/src/config.rs), DEC-T27-D2-1, D2-2, E-2):

| Limit | Value | Meaning |
|---|---|---|
| Most open connections | 256 | All addresses together |
| Most connections without an authenticated request | 64 | Silent or slow clients use this budget first |
| Most authenticated connections for one agent | 32 | A request beyond this gets `429 rate_limited` |
| TLS handshake | 10 s | |
| First request head after the handshake | 10 s | Bytes and HTTP/2 pings do not count |
| Life of a connection with no authenticated request | 30 s from accept | Applies even while a request runs |
| Idle time of an authenticated connection | 60 s | Without an authenticated request |
| Request body read | 30 s | |
| Response send stall | 30 s | The client does not read the response |
| Shutdown grace | 10 s | Then open connections are cut |
| Body size, most routes | 16 KiB | `POST /v1/credentials` and `POST /v1/sessions`: 1 MiB |

When every connection slot is taken by authenticated connections, a new connection waits in the queue. A key that
is revoked or expired closes its open connections within about one second.

**SSH bridge** ([`cerberus-ssh-agent`](../../crates/cerberus-ssh-agent/src/lib.rs)): 32 sockets in total, 8 per agent,
8 connections per socket. A connection that sends no message for 300 s is closed. The lease time of a socket is 60 to
86400 s. One socket may make at most 60 signatures a minute.

**Unlock back-off.** The first five failed unlocks in a row have no wait. After that the wait is `2^(n-5)` seconds,
up to 900 seconds.

## Network

- The default bind is `127.0.0.1` and `::1`, on port 7373. The app lets you change the bind and the port. The port
  must be 1024 to 65535.
- The HTTPS server uses TLS 1.3 only ([ADR-0023](../adr/0023-network-boundary-tls.md)).
- The local CA is ECDSA P-256 and lives 10 years. The leaf certificate lives 90 days and is renewed while the server runs.
- Clients trust the CA by file or by pin. A client never trusts a public CA.
- **A LAN bind needs client certificates.** You cannot bind a non-loopback address unless every active agent key
  requires a client certificate (mTLS). The app refuses the change if one key does not.
- **Custom certificate.** The owner can load a certificate chain (up to 8 certificates, leaf first) and its key. The
  server then serves it, and the app never renews it. Clients must trust that chain. A pin of the local CA no longer
  matches. Revert to the local CA in the same settings screen.
- The `Host` header must match a name in the certificate. Any other name gets `403 origin_refused`.

The systemd unit for the daemon allows only loopback traffic by default. See the [daemon guide](cerberusd.md).

## Platform gaps

| Area | Linux | macOS and Windows |
|---|---|---|
| Lock on OS sleep | Yes. The vault locks before the machine sleeps, and on screen lock ([ADR-0026](../adr/0026-vault-state-machine-and-lock.md), amendment DEC-T27-C-9) | No hook. The vault stays unlocked until the idle lock or the hard limit, and keys can reach a hibernation image. This is an accepted risk (AUD-16) |
| `cerberus run` child and the parent's environment (AUD-19) | The child cannot read the parent's environment (not dumpable) | The child can read the parent's first environment. If you give the token as `CERBERUS_TOKEN`, the child can read it. Give the token as a file (`CERBERUS_TOKEN_FILE`) instead. The token file stays readable by the same user (AR-3). This is a partial fix. |
| SSH bridge | Yes | The bridge is Unix only. On other systems it reports that the feature is not supported |

## Items that are still open

These are open in the audit report (see [security model](security-model.md#9-status-of-the-audit) for the full list):

- **CSV import and the URL path (AUD-25, NEW-9).** The import keeps only scheme, host and port in the item target.
  The path stays only in the sealed login. A path that you type into a target by hand is visible to agents that can
  read the catalog.
- **A failed restore can strand the old vault (AUD-10, NEW-10, NEW-11, NEW-12).** The app moves the old vault back and
  never makes an empty one. If it cannot, it starts in a state that names the `.pre-restore-*` file and offers to put
  it back. A vault put back loses all agent keys and leases at its next unlock. A restore that went through keeps the
  old file as `.replaced-*`, which is never offered back; delete it yourself. A restore over a symbolic link is
  refused. See [backup and restore](backup-and-restore.md#if-a-restore-fails).
- **Audit log grows (AUD-30).** The audit log is not pruned in this version.
- **Local flood of failed logins (NEW-8).** A local user with no token can write `auth.failed` audit rows, at most 20 a minute. This grows the vault file slowly.

## Other things to know

- **The audit log never contains secret values.** It records who did what, and when. It is a hash chain. Run the chain
  check on the audit screen. It reports the position of a broken row.
- **Agent-written text is untrusted.** The MCP tools mark agent-written titles, descriptions and tags as untrusted.
  Approve requests only after you check the agent and the item.
- **Agent-written items are limited.** An item an agent wrote can set only credential-shaped environment names in
  `cerberus run`. An item a person wrote keeps any name, except the code-loading hooks, which are skipped unless a
  person maps them with `--var`. See the [agent integration guide](agent-integration.md#cerberus-run).
- **No backdoor.** Lost phrase and lost recovery key mean the data cannot be restored. This is by design (AR-13).
- **Daemon.** `cerberusd` has no admin surface by default. Make the vault on the server with `cerberusd init`, or
  create items, agents and grants in the desktop app and copy the vault to the server. The [daemon guide](cerberusd.md)
  explains how.
