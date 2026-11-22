# Troubleshooting

Find the symptom below. Each row gives the likely cause and the fix. Messages are quoted as the program prints them.

Most agent errors come back as JSON with `code`, `message`, `request_id` and `retryable`. Keep the `request_id` when
you report a problem. The `cerberus` CLI prints the code and the request ID, and exits with a code from the table at
the end of this page.

## Connection and trust

| Symptom | Likely cause | Fix |
|---|---|---|
| `cannot connect: ...` | The app or the daemon is not running, or it listens on another port or address | Start the app or `cerberusd`. Check `CERBERUS_URL`. The default is `https://127.0.0.1:7373` |
| `no trust anchor: set CERBERUS_CA_PIN or CERBERUS_CA_FILE` | No CA file and no pin | Export the CA from Settings and set `CERBERUS_CA_FILE` (or use `CERBERUS_CA_PIN`) |
| `the service URL must use https (plain HTTP is refused)` | `http://` in `CERBERUS_URL` | Use `https://` |
| `certificate pin mismatch` | The server certificate chain is not the one you pinned. This happens after a new vault, a restore of another vault, a new CA, or a custom certificate | Export the CA again from the app, and update `CERBERUS_CA_FILE` or the pin. If the owner loaded a custom certificate, pin its chain instead of the local CA |
| `TLS handshake failed: ...` | The client does not speak TLS 1.3, or it does not trust the CA | Cerberus accepts TLS 1.3 only. Update the client, and check the CA file |
| `403 origin_refused` | The host in the URL is not a name of the certificate | Use `127.0.0.1`, or a name listed in the certificate. For the daemon, add the name to `host_names` |
| Daemon cannot be reached from a LAN address | The systemd unit allows only loopback (`IPAddressDeny=any`, `IPAddressAllow=localhost`), or the bind is loopback | Edit the unit as the [daemon guide](cerberusd.md#1-install) says. A LAN bind also needs `require_mtls` |
| Settings refuse a LAN address (`a LAN address needs a client certificate on every active key`) | Some active key has no client certificate requirement | Require a client certificate on every active key, or keep the bind on loopback |

## Token and access

| Symptom | Likely cause | Fix |
|---|---|---|
| `bad configuration: the token file must not be readable by group or others (chmod 600)` | The token file mode is too open | `chmod 600 <token file>` |
| `bad configuration: the token file cannot be read` | Wrong path, or no permission | Check `CERBERUS_TOKEN_FILE`. The token must be readable by your user |
| `401 unauthenticated` | Wrong token, a revoked or expired key, a suspended or revoked agent, an IP that is not in the key's allowlist, or a missing client certificate | Check the token text. Check the agent and key state in the agents screen. A token is shown only once, so you may need a new key |
| `423 vault_locked` | The vault is locked. Nothing is returned | Unlock the vault in the app. For the daemon, run `cerberusd unlock` |
| `404 no_match` | No item matches `app`, `environment`, `role` or `kind`. Or the agent has no grant for the item | Check the names with `cerberus find`. Check the grant in the policies screen. An agent sees only what its grants allow |
| `403 forbidden` on a call that should work | No grant for that permission, or the scope is missing | Check the grant (`find`, `read`, `write`, `use_ssh`) and the key scopes |
| `403 insufficient_scope` | The key does not have the scope the route needs | Make a key with the scope, or ask the owner for it |
| `403 approval_unavailable` | The daemon cannot ask a person (the admin API is off: `[admin] enabled = false`) | Use an `auto` grant on the server, or approve in the desktop app |
| `403 approval_denied` | A person denied the request. The same agent cannot ask for the same item again for 10 minutes by default | Ask the person. Do not retry in a loop |
| `"outcome": "pending"` in an answer | Nobody decided within the wait (120 s by default) | Call again later. Keep the request ID. Ask the owner to look at the approval window |
| `429 rate_limited` on a good token | The agent is over its limit (20 calls a second, burst 40), or it already has 32 open connections | Read `Retry-After`. Slow down |
| `429 too_many_failures` | Too many failed token checks in five minutes, from this address or from all sources together (100) | Wait five minutes. Check for a script that sends a stale or wrong token. A good token is not refused by this limit. If a good token gets this error, report it with the request ID |
| `429 grant_rate_limited` | The grant's read limit for the hour is used up | Wait, or ask the owner to raise the limit |
| `422 validation_failed` | A field is wrong | The `details` field names it. Check the schema in [the MCP tool reference](../api/mcp-tools.md) or [the OpenAPI draft](../api/openapi-draft.yaml) |
| `413 payload_too_large` | The body is over the limit: 16 KiB for most routes, 1 MiB for create | Send less |
| `415 unsupported_media_type` | The request is not JSON | Send `Content-Type: application/json` |

## The CLI

| Symptom | Likely cause | Fix |
|---|---|---|
| `several items match; narrow the search or pass the item id` (exit 73) | More than one item fits | Add `--env`, `--role` or `--kind`, or pass `--id` |
| `access was not approved (status: ...)` (exit 72) | A person denied, or the approval was not available | See the rows for `approval_denied` and `approval_unavailable` |
| `cerberus: skipped N variable(s) that an item must not set in a child process: ...` | The item sets a name that is not allowed for an agent item, or a code-loading hook name | If the item is an agent item, a person must store the value under a credential name. A person can map the name with `--var NAME=field`. See [`cerberus run`](agent-integration.md#cerberus-run) |
| `cerberus run` output shows a secret | The secret was split by a boundary the masker cannot see, or `--no-mask` is set. Masking covers stdout and stderr of the command only | Remove `--no-mask`. Do not print secrets in the command. Files that the command writes are not masked |
| Child cannot find a variable | The item kind sets other names. Or `--var` is given, so only those names are set | Check the name list in [the agent guide](agent-integration.md#cerberus-run), or use `--var NAME=field` |
| Exit code 74 | Any other error | Read the message and the request ID |

## SSH agent socket

| Symptom | Likely cause | Fix |
|---|---|---|
| `ssh` says it cannot connect to the agent | `SSH_AUTH_SOCK` is not set to the `socket_path`, or the socket has closed | Call `ssh-prepare` again. The socket ends with its lease, at lock, or when the bridge stops |
| The key is not used for a git signature | The item has no `sshsig_namespaces` setting that includes the namespace (for example `git`). With no setting the key signs SSH logins only | The owner adds the namespace to the item's custom setting |
| `ssh-prepare` refuses | The grant has no `use_ssh`, the item is not an SSH key, or the agent is at its socket limit (8 per agent, 32 in total) | Check the grant. Close unused sockets by letting their leases end |
| SSH is not supported | Windows. The bridge is Unix only | Use the desktop app's key, or another method |

## Daemon (`cerberusd`)

| Symptom | Likely cause | Fix |
|---|---|---|
| `config file ... has mode 644; it must be 0600` | Config file is readable by others | `chmod 0600 /etc/cerberus/cerberusd.toml` and the owner `cerberus` |
| `... has mode ...; it must not be open to group or others` | The data folder or the vault file is open to others | Set mode `0700` on the folder and `0600` on the file |
| `no vault yet: waiting for the first client to create it` in the log | The data folder has no vault. This is normal on a first start | Read the code with `cerberusd setup-code` and give it to the first client (see the [daemon guide](cerberusd.md#2-put-the-vault-on-the-server)), or copy a desktop backup as `vault.cerberus` and restart (see [backup and restore](backup-and-restore.md#restore-to-the-headless-daemon)) |
| `no vault yet, and [admin] enabled = false` in the log | The data folder has no vault, and the config turns the admin API off, so no client can create it | Remove `enabled = false` from `[admin]` in `cerberusd.toml` (the default is true) and restart, or copy a desktop backup |
| `setup-code`: `no setup is pending` / `... is stale` | No daemon waits for a first client: it is stopped, it has a vault, or the config has `[admin] enabled = false` | Start the daemon with an empty data folder and the admin API on (the default). A new start makes a new code |
| `setup-code`: `... exists: this server has a vault already` | The data folder has `vault.cerberus`, so no setup is pending | Nothing to set up. To start again, remove the vault files yourself (`vault.cerberus`, `-wal`, `-shm`, `tls/`), after you check that you do not need them, and restart |
| The client gets `unauthenticated` from setup | The setup token is wrong, or the code is from an earlier start | Read the code again with `cerberusd setup-code` |
| The client gets `too_many_failures` from setup, health says `"setup": "locked_out"` | This address sent more than 5 wrong tokens and has to wait (2 s, 4 s ... up to 5 min) | Wait `retry_after_seconds` and use the current code (`cerberusd setup-code`). No restart is needed |
| The client gets `conflict` from setup | A setup is running, one already worked, or a vault file appeared in the data folder | Wait and try again. If a vault file is there, restart the daemon to serve it |
| The client gets `validation_failed` with the field `url` from setup | The host of the URL is not a TLS name of the server | Add the name to `host_names` in `cerberusd.toml` and restart, or use `localhost` through an SSH tunnel |
| The client gets a certificate pin mismatch from setup | The code is from another start or another server, or the vault was made already (the port now serves the vault certificate) | Read the current code with `cerberusd setup-code` |
| `vault.cerberus.setup-...` files in the data folder after a crash | A kill or a power loss while the first client made the vault. They are not the vault | Nothing: the next start removes them and waits for the first client again |
| `config file ...: unknown key ...` | A key in the TOML file is not known | Remove the key, or fix the spelling. See the [config reference](cerberusd.md#config-reference) |
| `no cerberusd is running for this data directory` | `unlock` ran while the daemon is stopped, or with another data directory | Start the service. Use the same `--config` |
| `cannot read the passphrase: ... Run this command from a local terminal.` | No terminal, for example in a remote script | Run `unlock` in a local terminal |
| `no cerberusd answered at ...` from `status` | `require_mtls` is set. `status` sends no client certificate (a known gap), or the daemon is not running | Check `systemctl status cerberusd` and the logs. Use a client with a certificate to check the health |
| `cannot read the CA certificate at ...: ... Has cerberusd started with this data directory?` | `status` uses another data directory, or the daemon never started | Start the daemon once, then run `status` with the same config |
| `cerberusd is already running for this data directory` | A second copy is running | Stop the first one |

## Unlock and locking

| Symptom | Likely cause | Fix |
|---|---|---|
| The phrase is refused, with a countdown | Too many failed unlocks. After five failures in a row, each failure doubles the wait, up to 15 minutes | Wait for the countdown. Check the caps lock key. Use the recovery key if you have lost the phrase |
| The vault locks more often than you expect | Idle lock (default 30 min), or the hard limit (12 h after unlock on the desktop, off by default on `cerberusd`) | Change them in Settings, as the owner or operator |
| The vault does not lock when the machine sleeps or the screen locks (macOS, Windows) | No OS lock hook on those systems | This is an accepted gap. Lock the vault yourself, or set a short idle lock |
| A busy agent keeps the vault open | "Agent calls count as activity" is on | Turn it off in Settings if you want the idle lock to run during agent work |

## Audit and integrity

| Symptom | Likely cause | Fix |
|---|---|---|
| The chain check shows a broken position | A row was changed, removed, or the file was damaged | Do not edit the file. Keep a copy of the folder. Compare with your latest backup, and ask the owner. Note the reported position |
| Events are missing after a restore | The backup is older than the events, so they are not in it | This is expected for a restore. A backup holds only the audit rows that it had at the time |

## Restore and backups

| Symptom | Likely cause | Fix |
|---|---|---|
| The restore fails | The app moves the old vault back, so the old vault is the vault again | Try the restore again from a good backup. See [If a restore fails](backup-and-restore.md#if-a-restore-fails). Do not delete any file |
| The app says "Your vault was found, but it is not in place" | A failed restore left the vault as `vault.cerberus.pre-restore-*` and there is no vault file. The app made no new vault | Press **Put the vault back**, then unlock. At that unlock the app revokes all agent keys and leases of the vault and cancels pending requests, so agents need new tokens. Only `.pre-restore-*` files start this state; `.replaced-*` files from restores that went through do not. If it refuses, see [If a restore fails](backup-and-restore.md#if-a-restore-fails). Do not delete any file |
| The app shows "Cannot read the vault status" at start (`unavailable`) | The vault file is missing and the app could not read the data folder, so it made no vault | Fix the permissions of the data folder, then restart the app. See [If a restore fails](backup-and-restore.md#if-a-restore-fails) |
| The restore is refused with `unavailable`, and the text says the vault file is a symbolic link | `vault.cerberus`, `-wal` or `-shm` is a symbolic link. The app does not follow it | Put the real file at the vault path, then restore again. Nothing was moved |
| The backup is refused | The file is not a Cerberus backup, or it is from a newer version | Check the file name and source. Use a backup made by this version |
| The phrase is not accepted for the restore | The phrase must match a key slot in the backup. The current phrase is not enough | Use the phrase or recovery key from the time of the backup |

## Build and development

| Symptom | Likely cause | Fix |
|---|---|---|
| `node-check: Node 22 or newer is needed` | The shell has an old Node | Run `nvm use` (see `.nvmrc`) |
| `just check` fails on `cargo deny` or `cargo audit` | A new advisory, or the tools are not installed | Install `cargo-deny` and `cargo-audit`. Read the advisory, and see `.cargo/audit.toml` and `deny.toml` for the ignores and their reasons |
| Tests are flaky under load | Parallel builds or tests use a small machine heavily | Run one cargo command at a time |

## Exit codes of the `cerberus` CLI

| Code | Meaning |
|---|---|
| 70 | Unauthenticated, or insufficient scope |
| 71 | Vault locked |
| 72 | Forbidden, approval denied, approval unavailable, or condition failed |
| 73 | No match, not found, or several matches |
| 74 | Any other error |

`cerberus run` returns the exit code of the command it runs. If the command was stopped by a signal, the code is
`128` plus the signal number.
