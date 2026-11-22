# Security model

This page summarises how Cerberus protects credentials. It also lists what it does not protect. It does not replace
the two source documents:

- [Threat model](../security/threat-model.md): assets, attackers, trust boundaries, the STRIDE table, the security
  invariants, and the accepted risks (AR-1 to AR-17).
- [Security audit report](../security/audit-report.md): the findings (AUD-1 to AUD-32 and NEW-x), each with its fix and
  its re-check.

The design decisions are in the [ADRs](../adr/README.md) and the [decision log](../decisions.md).

## 1. What Cerberus protects

| Threat | Main control |
|---|---|
| A copy of the vault file is stolen | Item content and item metadata are encrypted with keys that come from the master phrase. Some fields stay plain: IDs, kinds, expiry times, timestamps, counts, operator labels and a few agent fields. No names, titles, descriptions or secrets (AR-2) |
| A guessed phrase | Argon2id with a high memory cost. The app checks phrase strength. Failed unlocks get a growing wait |
| An agent asks for too much | Grants, scopes, read and request limits, approval for `prod`, and an audit event for each call |
| A prompt-injected agent | Grants limit what it can read. Agent-written text is marked untrusted. Agent items cannot set loader variables |
| A local user sends bad tokens | Failed checks are limited per address. A good token is never refused by these limits |
| A network attacker | TLS 1.3 only. Clients trust the local CA by file or pin. A LAN bind needs client certificates |
| A tampered audit log | Each row has an HMAC and points to the row before it. The chain check reports the broken position |
| A locked vault | Keys leave memory. The API answers HTTP 423 and returns no data |

## 2. Keys

- The **master phrase** goes through **Argon2id**. The memory cost is 256 MiB with 4 GiB of RAM or more, otherwise
  64 MiB. Time cost 3 and parallelism 4 are the starting values. The app tunes the cost to about 0.7 s and stores it in
  the vault header.
- A random **Vault Master Key (VMK)** of 256 bits is wrapped once per key slot. Each slot is one operator's phrase, or
  the recovery key.
- HKDF-SHA256 derives the keys for items, metadata, the audit log and the local CA from the VMK.
- Each item has its own random key. The item key is wrapped with the item key encryption key. The cipher is
  XChaCha20-Poly1305. The additional data holds the vault ID, the item ID and the version. This stops a row from being
  swapped with another row ([ADR-0013](../adr/0013-vault-file-header-and-kdf.md), [ADR-0014](../adr/0014-key-hierarchy-and-envelope.md)).
- The **recovery key** is 256 random bits. It is shown one time.
- Changing the phrase wraps the VMK again. It does not encrypt the items again.
- Key memory uses `mlock`, `zeroize` and redacted `Debug` output. At start the desktop app and the daemon make the
  process not dumpable and set the core dump limit to zero, on Linux. The policy is that only the memory lock module
  may use `unsafe` code ([ADR-0012](../adr/0012-unsafe-code-policy.md)).

## 3. Agent tokens

- A token has the form `cvt_<agent ID>.<secret>`. The secret has 256 random bits. The server stores only a SHA-256 hash.
- The check compares the hash in constant time with a fixed number of slots. An unknown agent costs the same as a known one.
- A key has scopes, an optional IP allowlist, an optional client certificate, and an expiry. An agent has at most five
  live keys ([ADR-0016](../adr/0016-agent-token-format-and-auth.md)).
- A revoked or expired key stops working at once for new calls. Open connections with it are closed within about one
  second.
- Limits: a good token is limited per agent (20 a second, burst 40). Failed checks are limited per address, and a
  lockout follows ten failures in five minutes. A global lockout follows 100 failures from all sources. The limits
  for failed checks never refuse a good token ([DEC-T27-E-1](../decisions.md), [ADR-0030](../adr/0030-rate-limits-and-lockouts.md)).
- A connection belongs to one agent after its first authenticated request. One agent may hold at most 32 of them.

## 4. Roles, and the limit of roles (AR-9)

Roles are checked by the app. They are not a boundary for the cryptography. Every slot opens the same VMK. So an
operator who shares the OS account with the vault file, and who knows their own phrase, can read everything, even if
their role is viewer. Keep the vault file only with people who may read every item. The operator guide explains this in
full ([operator guide, AR-9](operator-guide.md#read-this-first-roles-do-not-limit-an-os-account)).

## 5. Transport

- The HTTPS server uses TLS 1.3 only, with ALPN for HTTP/2 and HTTP/1.1 ([ADR-0023](../adr/0023-network-boundary-tls.md)).
- The local CA is ECDSA P-256 and lives 10 years. The server leaf lives 90 days.
- The server listens on loopback by default. A LAN bind needs mandatory client certificates on every active key.
- Clients pin the CA or trust the CA file. The MCP shim and the CLI refuse to start without one of these. They never
  use a public CA.
- Each connection has deadlines for the handshake, the request head, the authenticated requests, the idle time, and
  the send of a response. A silent connection cannot hold a slot for ever (AUD-4, fixed by DEC-T27-B-1, D2-1 and E-2).

### Remote mode (ADR-0034)

The desktop can work with a vault on a server that runs `cerberusd` with the admin API on. This moves a boundary:
admin actions then cross the network. They stay behind two factors on every call:

- **The device.** A client certificate that `cerberusd admin enroll` made for this desktop. The server checks on every
  request that its hash is enrolled, not revoked and not expired. A CA-signed agent certificate does not pass.
- **The person.** A session opened with the passphrase of the operator the enrolment is bound to. The session token
  stays in the desktop's Rust memory, never in the page, the log or a file. It ends after 15 idle minutes, after 12
  hours, at every lock of the server vault, and at a revoke.

The desktop trusts only the CA pin from the bundle and speaks TLS 1.3 only. The person compares the pin and fingerprint
with `cerberusd status` before the first connect. The passphrase crosses the network only inside that channel, once per
session. The recovery key never does. A disconnect, a lost connection or the desktop quitting does not lock the server
vault; only a lock does. Every admin action runs the same core function as the local command and is audited as the
operator. The admin API is on by default on `cerberusd` (DEC-SRV-3) but exposes nothing until a desktop is enrolled; `[admin] enabled = false` removes it, and then no `/admin` route exists. See the threat model, boundary TB-10. A server with no vault also runs a temporary setup listener for the first client (threat model, E-17): it is reachable on the network, takes no client certificate, and is protected only by the one-time setup code, the pin of its certificate and the limits there; it closes when the vault exists.

What remote mode does not protect against: a stolen bundle together with the known phrase is that operator's full
power until the enrolment is revoked (AR-18, AR-20); a compromised server process sees the phrase, as it sees the
keys (AR-8).

## 6. Prompt injection and agent abuse

- **Grants.** Each grant names the items, the permissions and the mode. Deny wins over allow. The most specific grant
  decides.
- **Approval.** `prod` items use `ask_always` by default. An approval has a time limit. A denied request has a cooldown
  for the same agent and item.
- **Read limits.** 60 secret reads a minute, and 30 distinct items an hour, per agent by default. The dashboard shows an
  alert when the item limit is reached. Access requests are limited to 10 in 10 minutes, with at most 5 pending.
- **Untrusted text.** Titles, descriptions, tags, role labels, categories and targets of items that an agent wrote are
  marked as untrusted in MCP results. The text of the result begins with `UNTRUSTED:` ([DEC-T27-B-7](../decisions.md)).
- **Resolve.** On an equal score an operator item beats an agent item. An agent item cannot win over an operator item
  by hint words alone ([DEC-T27-A2-5](../decisions.md)).
- **Secrets in results.** A secret result begins with a handling line. The agent must not print it.
- **Panic.** Lock and revoke all ends every lease and cancels every pending request, and locks the vault.

## 7. Audit

- Calls that read, write, approve, sign or revoke write an event. Failed token checks write a throttled event too.
  An event never contains a secret value. Revealing a secret and each SSH signature (`ssh.sign`) are events.
- The events form a hash chain. The chain check finds an edited row, a deleted row, and a cut tail. It reports the
  position ([ADR-0025](../adr/0025-audit-hash-chain.md), [AUD-1](../security/audit-report.md#aud-1--medium--an-edited-audit-head-is-signed-again-at-the-next-append-so-a-cut-in-the-log-is-not-detected)).
- While the vault is locked, events wait in a table without a MAC. A file attacker can add or remove those rows
  (AR-6). They are checked when the vault unlocks.

## 8. Accepted risks

The threat model lists these. The most important ones for a user:

| ID | Risk | What to do |
|---|---|---|
| AR-1 | Rolling the file back to an older genuine copy | Keep the file safe. There is no trusted counter in version 1 |
| AR-3 | A `cerberus run` child writes or sends the secret | Run only commands you trust. Masking covers stdout and stderr only |
| AR-4 | An agent prints a secret it got legitimately | Prefer `cerberus run` and the SSH socket. They keep secrets out of the agent's output |
| AR-5 | A prompt-injected agent reads within its grants | Narrow the grants. Read the alerts |
| AR-7 | A stolen token works until it expires or is revoked | Short expiry, a revoke on suspicion, IP allowlist, mTLS |
| AR-8 | Malware or root reads memory while the vault is unlocked, or a hibernation image holds keys | Lock when you leave. Use short idle and hard limits. No user program can stop this |
| AR-9 | Operators with file access are not limited by roles | See section 4 |
| AR-13 | A lost phrase and a lost recovery key make the data unrecoverable | Keep the recovery key apart from the phrase, and keep backups |
| AR-14 | A clipboard manager keeps copies | Turn off clipboard history in the OS |
| AR-15 | Agent-written items can mislead other agents within the same grants | Give `write` only where needed. Read agent-written items with care |
| AR-20 | Remote mode: the desktop keeps its enrolled client key as a `0600` file, not in an OS keychain | Delete the bundle after the import. When a desktop is lost, run `cerberusd admin revoke` on the server. The key alone still needs an operator phrase |

## 9. Status of the audit

From the audit report (T26, re-checked by fresh auditors in T27):

- No critical or high findings. The report says no finding is open at medium or higher. The Medium findings AUD-1
  to AUD-5 are closed. Some fixes were only partly closed at first. Later rounds fixed the rest, and each round was
  re-checked.
- Fixes have regression tests. The re-checks ran the tests in debug builds.

Open or partly closed items (the verdicts are from the audit report, sections 6 to 8):

| ID | Status | Effect |
|---|---|---|
| AUD-10 and NEW-10 to NEW-12 | Partly closed, Low | The old store is closed before a restore moves files, and a failed restore moves them back. If the old vault still stays as a `.pre-restore-*` file, the app starts without a vault, names the file and offers to put it back; it never makes a new empty vault. A restore that went through renames the old file to `.replaced-*`, which never starts this state (NEW-12). A vault put back loses its agent keys and leases at its next unlock (`backup.recover_revoke`). A restore over a symbolic link is refused, and a folder that cannot be read at start gives no vault and an error (NEW-11). Still open: the stranded screen shows no file age and has no "start a new vault" choice See [backup and restore](backup-and-restore.md#if-a-restore-fails) |
| AUD-19 | Partly closed, Low | On macOS and Windows, a `cerberus run` child can read the parent's first environment. Give the token as a file |
| AUD-25 and NEW-9 | Accepted in part, Low | The CSV import target keeps only scheme, host and port. The path, query and fragment stay in the sealed login only. A path that a person types into a target by hand is visible to agents that read the catalog |
| AUD-16 | Accepted, Low | No OS lock hook on macOS and Windows (ADR-0026 amendment) |
| AUD-30 | Partly closed, Info | The audit log is never pruned. A leftover `.pre-migrate` file no longer blocks the open: the next copy gets a free name (DEC-RD-5) |
| NEW-8 | Partly closed, Low | A local user without a token can write `auth.failed` audit rows, at most 20 a minute (all of loopback counts as one source). This can still grow the vault file slowly. The true reason is kept in the row during a lockout while the vault is unlocked |
| NEW-1 | Accepted, Low | A local user who floods new connections can push out an agent's connection before it authenticates. It costs the attacker CPU. A token holder can still use up the authenticated slots, but the per-agent cap of 32 limits that |
| AUD-26 | Accepted, Info | The role is not bound in the slot wrap. This is AR-9 |

Note: the audit report's section 8 summary also lists NEW-1 and NEW-6 among the open Low items. Its verdict table marks
NEW-6 as closed, and NEW-1 as closed with an accepted residual. This page follows the verdict table.

## 10. What this model does not claim

- It does not protect against malware or root on an unlocked machine (AR-8).
- It does not limit an operator who has the vault file and the OS account (AR-9).
- It does not stop an agent from misusing a secret it was given (AR-3, AR-4, AR-5).
- It does not give a second factor for unlock. The recovery key opens the vault without a phrase.
- This is not a formal certification. The audit and its re-checks read the code and ran tests. Get an independent review
  before you rely on Cerberus for high-value secrets.
