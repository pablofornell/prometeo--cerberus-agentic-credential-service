# Running the Cerberus daemon (cerberusd)

`cerberusd` serves the Agent API (REST and MCP) for a vault on a server with no screen. The server is the custodian of
the vault: nobody types a passphrase on it. On a first start with an empty data folder the daemon waits, and the first
client (the desktop app in remote mode) creates the vault over the network with a one-time setup code (section 2).
Or you prepare items, agents and grants in the desktop app and copy the vault to the server. If you turn on the admin
API, the desktop app can work with the server vault live, approvals included (section 6, ADR-0034).

## What it can and cannot do

- It serves the Agent API over HTTPS (TLS 1.3 only) and the MCP endpoint at `/mcp`.
- The admin API is **on by default** (DEC-SRV-3): it serves `/admin/v1` for desktops that you enrolled on the server
  (section 6). Every admin route needs the client certificate of an enrolled desktop, so with none enrolled nothing
  is reachable. Set `[admin] enabled = false` for a server with no admin surface at all (ADR-0002).
  *Behaviour change for an existing `cerberusd.toml` without the `enabled` key:* after the upgrade it has the admin
  API on, asks for client certificates on the listener (agents without one still connect on a loopback bind), reads
  `admin-clients.json`, writes the `admin.api_start` audit event at each start, and turns approvals on. Add
  `enabled = false` under `[admin]` to keep the old behaviour.
- With the admin API off it cannot ask a person for approval: a grant in mode `ask_once` or `ask_always` gives
  `403 approval_unavailable`, so use `auto` grants with tight selectors. With the admin API on (the default), such a
  grant makes an access request that a connected desktop decides; if no desktop is enrolled and connected, nobody
  decides and the request expires after its timeout (default 120 s) instead of failing at once.
- Items that agents create on the server exist only on the server. A new backup from the desktop replaces them.

## 1. Install

1. Build the binary: `cargo build --release -p cerberusd`. Copy `target/release/cerberusd` to `/usr/local/bin/`.
2. Create the service user and folders (run as root):
   ```
   useradd --system --home /var/lib/cerberus --shell /usr/sbin/nologin cerberus
   install -d -m 0700 -o cerberus -g cerberus /var/lib/cerberus
   install -d -m 0700 -o cerberus -g cerberus /etc/cerberus
   install -m 0600 -o cerberus -g cerberus packaging/systemd/cerberusd.toml.example /etc/cerberus/cerberusd.toml
   install -m 0644 packaging/systemd/cerberusd.service /etc/systemd/system/cerberusd.service
   systemctl daemon-reload
   ```
   The unit allows only loopback traffic (`IPAddressDeny=any`, `IPAddressAllow=localhost`). For a LAN bind, remove
   those two lines from the unit (and set `require_mtls`).
3. Check the config file (it must be mode `0600`):
   `sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml status` (the daemon must run first).

## 2. Put the vault on the server

There are two ways. Use one of them.

### Option A: the first client creates the vault (first-time setup)

Start the daemon with an empty data folder. The admin API is on by default, so no config is needed for this (a config
with `[admin] enabled = false` turns the setup off, see below). The daemon does
not stop for the missing vault: it tells systemd it is ready and **waits for its first client** (DEC-SRV-3). Nothing
on the server needs a passphrase, a terminal or an installer step.

1. **Set the config** before the first start, if the client reaches the server by a name: put in `host_names` every name
   that the client will use, except `localhost` (the TLS certificate of the new vault and the Host check carry the
   `host_names`; the client's URL must be one of those names, or the setup is refused before it makes anything).
2. **Start the service:** `sudo systemctl start cerberusd`. The data folder `/var/lib/cerberus` is made by systemd
   (`StateDirectory=`) and is empty. The log says `no vault yet: waiting for the first client to create it` and
   names the code file and the pin.
3. **Read the setup code**, as the daemon user (or root):
   ```
   sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml setup-code
   ```
   It prints one line, `cerberus-setup:1:...`, which holds the URL of the server, a random 32-byte one-time token and
   the pin of the temporary TLS certificate. The same line is in `<data_dir>/setup-code` (mode `0600`). Treat it as a
   secret until the vault exists: it lets whoever has it create the vault. The log has the file path and the pin, never
   the token. `cerberusd status` says "no vault yet" while the daemon waits.
4. **Give the code to the client** over a channel you trust, for example by pasting it in the desktop app (remote mode,
   create a vault on the server; the app uses `cerberus_client::setup`). The client connects to the URL in the code
   and trusts only the pinned key of the temporary certificate, so the passphrase goes only to the server that holds
   the code. If the desktop reaches the server through an SSH tunnel (`ssh -N -L 7373:localhost:7373 user@server`),
   the client changes the URL to `https://localhost:7373`.
5. **The client chooses the owner label and the passphrase** (12 characters or more, strength score 3 or more; the
   server checks it). The server measures the key-derivation cost of its own machine (about 0.7 s per unlock, a few
   seconds of measuring), makes the vault, enrols the client as an admin client (like `cerberusd admin enroll`) and
   answers **one time** with the recovery key and the admin bundle. The client shows the recovery key to the person and
   stores the bundle as a remote profile. The person stores the recovery key offline: it opens the vault without the
   passphrase and the server cannot show it again.
6. **The daemon goes on with the new vault, with no restart.** The temporary listener closes, the code file is
   deleted, and the same port now serves the vault with its own CA (`tls/ca-cert.pem`, the pin in the bundle). The
   vault stays **unlocked**, as it is after any create; it starts sealed after the next restart (section 3).

What protects the setup:

- The temporary certificate is self-signed, is not a CA, is made in memory at each start and is never stored. Only
  `GET /v1/health` (reports `"vault": "no_vault"`, `"setup": "pending"`) and `POST /v1/setup` answer; every other route
  answers `503 unavailable` ("no vault yet").
- The token is compared in constant time. After 5 wrong tokens from one address, that address has to wait before its next
  try: 2 s, then 4 s, 8 s ... up to 5 minutes (`429 too_many_failures` with `retry_after_seconds`; health says `"setup":
  "locked_out"` to that address while it waits). Other addresses are not affected and nothing needs a restart, so a flood
  cannot lock the owner out. Each address has at most 4 connections open, and a request body must arrive within 10 s. A
  restart always makes a new code and a new temporary certificate: an old code is useless.
- One setup runs at a time (a second call gets `409 conflict`), and a setup that worked closes the listener for good.
- The setup runs in a task of its own, so a client that disconnects, or a timeout, cannot stop it half way. The vault is
  built under a temporary name (`vault.cerberus.setup-<id>`) and gets `vault.cerberus` only after the client is enrolled
  and the answer is ready. If anything fails (the registry cannot be saved, for example), or the client is gone before it
  takes the answer, the server removes every file of the attempt and revokes the enrolment, and the same code can be
  used again. Temporary files that a killed daemon left (and the TLS files that the setup wrote) are removed at the next
  start. If the daemon is told to stop while a setup runs, the setup finishes and its answer leaves first. The vault is
  opened again sealed under its real name, and unlocked only after the answer has left (one more key derivation).
  The file system of the data folder must support hard links (or Linux `renameat2`), which every normal Linux file system
  does; otherwise the setup answers `internal` and creates nothing.
  **Two cases are not covered**, and in both the vault exists but the client has no recovery key: (1) the daemon is killed
  (SIGKILL, power loss) in the few milliseconds between the vault getting its name `vault.cerberus` and the answer being
  handed to the connection; (2) the connection breaks after the answer was handed to it. The vault is new and empty, so
  you have two real options. **Keep it without a recovery key:** the passphrase still opens it, but if the passphrase is
  lost the data cannot be restored. For case 2 enrol the desktop with `cerberusd admin enroll` and connect with the
  bundle. A remote session cannot rotate the recovery key (ADR-0034 section 7: `recovery_rotate` is local only), so a key
  cannot be added afterwards. **Or start again:** stop the daemon, remove `vault.cerberus`, `vault.cerberus-wal`,
  `vault.cerberus-shm` and the `tls/` folder from the data folder (and `admin-clients.json` if you want an empty
  registry), start it, and set up again with the new code.
- The setup works only with the admin API on (the default), because the client must come out of it with an admin bundle
  (there is no other way to manage the vault from a desktop). With an explicit `[admin] enabled = false` the daemon
  starts, logs why, and serves nothing; there is no setup code. Remove that line (or set `true`) and restart. A non-loopback `bind` also opens the
  temporary listener on that address (it cannot ask for client certificates, because the CA does not exist yet): the
  token and the pin are what protect it.
- A vault file that appears while the daemon waits (a backup you copied in) is never replaced: the setup answers
  `409 conflict`. Restart the daemon to serve that vault.
- A kill with SIGKILL, or a power loss, while the vault is built leaves only `vault.cerberus.setup-*` files (and their
  `-wal` and `-shm`) and TLS files, never a `vault.cerberus`, unless it falls in the short window described above. The
  next start removes them and waits for the first client again. A leaf in `tls/` that is not from the CA of the vault is
  never served: the daemon renews it at the first unlock.
- Each connection to the temporary listener serves one request and closes (no keep-alive); one that does not start a
  setup lives at most 40 s. IPv6 peers are limited by their /64, and the table of wrong tokens keeps the 1024 most recent
  addresses.

### Option B: copy a vault from the desktop app

Make a backup in the desktop app, copy the backup file to the server, and store it as the vault file. It must be mode
`0600` and owned by `cerberus`:

```
install -m 0600 -o cerberus -g cerberus cerberus-<id>-<date>.cerberus-backup /var/lib/cerberus/vault.cerberus
```

A backup has no TLS leaf key. The daemon makes a new leaf at the first unlock. Agents that trust the CA keep working.

Restoring over an existing vault file replaces every item, agent and token on the server with the backup's content.

## 3. Start and unlock

This section is for a server that has a vault (option B, or after a first-time setup and a restart).

```
sudo systemctl start cerberusd
```

The daemon starts sealed. Unlock it from a local terminal of the server, as the `cerberus` user:

```
sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml unlock
```

The command asks for the passphrase. Nothing is echoed. Use `--operator <label>` when the vault has more than one
owner. Until the first unlock, the HTTPS port is closed if the backup had no TLS leaf.

Check the daemon:

```
sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml status
```

It prints the daemon version, the address and `vault locked` or `vault unlocked`, then the CA pin and SHA-256
fingerprint, and whether the admin API is on with the number of enrolled clients.

## 4. Trust the CA

**Custom certificate.** The daemon config has no setting for your own certificate: you load it in the desktop app
(Settings, network, `tls_load_custom`). If the vault holds one (for example after a restore of a desktop backup), the daemon
serves it after each unlock and never renews over it. Then clients must trust the custom chain, and a pin of the local CA
no longer matches; `ca-cert.pem` below is still the local CA. See DEC-FIX9-1 and DEC-FIX9-6.

The daemon writes the CA certificate to `/var/lib/cerberus/tls/ca-cert.pem` at each start. It is public. Give agents
this file, for example with `NODE_EXTRA_CA_CERTS=/path/to/ca-cert.pem`, or pin the SPKI hash that the start log shows.

## 5. Stop

`sudo systemctl stop cerberusd` locks the vault first. Then it stops the listener. Open requests get 10 s to finish.
The vault locks again on every stop. Unlock it after each restart.

## 6. Remote admin from the desktop

With the admin API on, the desktop app in remote mode can unlock the server vault, browse and edit items, manage grants,
see agents and leases, read the audit log and approve requests (ADR-0034). It uses the same HTTPS listener as agents,
under `/admin/v1`. Every admin call needs two things: the client certificate of a desktop that you enrolled here, and
a session that the desktop opens with an operator passphrase. A stolen bundle alone opens no session.

A first-time setup (section 2, option A) has already enrolled the first desktop and left the vault unlocked, so steps
2 and 3 below are for more desktops, or for a vault you copied in (option B).

1. **Turn it on.** It is on by default. If the config says `enabled = false`, change it in `cerberusd.toml`:
   ```toml
   [admin]
   enabled = true
   ```
   and restart the daemon. The start log has a `warn` line `admin API enabled, N enrolled clients`, and the audit log gets
   `admin.api_start`. The daemon now asks every client for a certificate; agents without one still connect on a
   loopback bind.
2. **Unlock once at the terminal** (`cerberusd unlock`, section 3). Enrolment needs the unlocked vault (the CA key is
   sealed until then), and the first unlock also makes the TLS leaf.
3. **Enrol the desktop**, as the daemon user:
   ```
   sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml admin enroll \
       --label "work laptop" --url https://localhost:7373 --out /var/lib/cerberus/work-laptop.cerberus-admin
   ```
   It asks for an owner passphrase (no echo; use `--owner <label>` when there are several owners). `--url` is the
   address the desktop uses to reach the daemon. `--operator <label>` binds the enrolment to another operator: then
   only that operator's passphrase opens a session with it (default: the owner who typed the phrase). The command
   writes a bundle file (mode `0600`, never over an existing file) and prints the enrolment ID, the CA pin and the CA
   SHA-256 fingerprint. The certificate in it is valid for 90 days.
4. **Move the bundle** to the desktop over a trusted channel, for example
   `scp server:/var/lib/cerberus/work-laptop.cerberus-admin .`. It holds a private key (but no passphrase). On the
   desktop, import it ("Connect to a remote server"), compare the pin and fingerprint it shows with
   `cerberusd status`, then **delete the bundle file** on both machines.
5. **Connect.** The desktop unlocks with the bound operator's passphrase. If the vault is sealed (after a restart), this
   unlocks it for agents too. If it is unlocked by the same operator, the vault does not change. If another operator
   unlocked it, the desktop gets `conflict`.
6. **Disconnect is not lock.** When the desktop disconnects, quits, sleeps, or its session ends (15 minutes idle or
   12 hours, see `session_idle_seconds` and `session_max_seconds`), the server vault stays unlocked for its agents.
   Only "Lock the server vault" on the desktop, a lock at the server, or the daemon's own rules lock it. Every lock
   ends every admin session.
7. **List and revoke.**
   ```
   sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml admin list
   sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml admin revoke <enrolment id>
   ```
   Revoke needs no passphrase. With the daemon running, the desktop is refused at once and its sessions and
   connections close within about a second (audited as `admin.client_revoke`). With no daemon running, the command
   edits `admin-clients.json` and the revoke takes effect at the next start (no audit event then, because the vault
   is not open). Revoke a lost or retired desktop, and before a certificate expires enrol it again.

**Reach the daemon through an SSH tunnel (recommended).** Keep `bind` on loopback and forward a local port:

```
ssh -N -L 7373:localhost:7373 user@server
```

Enrol with `--url https://localhost:7373`: the desktop connects to its own end of the tunnel, and `localhost` is a
standard leaf name. If the desktop uses another name for the tunnel end or the server (for example
`cerberus.example.lan` through a VPN), add it to `host_names`, restart, unlock once (the leaf is renewed with the new
name), and enrol with that name in `--url`. A non-loopback bind needs `require_mtls = true`, so agents then need client
certificates too.

**Files.** `<data_dir>/admin-clients.json` (mode `0600`; the daemon refuses to start with the admin API on if it is
wider) lists the enrolments: ID, label, bound operator, certificate SHA-256 and times. It holds no secret. Sessions are
only in memory: a restart ends them all.

**Limits.** At most 4 admin sessions, 2 per enrolment (the oldest ends first). After 5 wrong passphrases in 15
minutes, an enrolment is refused for 15 minutes before any passphrase check; every wrong passphrase also counts in the
vault's unlock back-off. The recovery key is never accepted over the network.

## 7. Back up

Do not copy `/var/lib/cerberus` while the daemon runs: the vault is in WAL mode, so a file-by-file copy can be torn.
Run `cerberusd backup --out /var/lib/cerberus/backups --keep 14` instead. It makes a consistent copy while the daemon
serves, needs no passphrase, and keeps the file encrypted. The packaging has a systemd timer for it
(`cerberusd-backup.timer`, `cerberusd-backup.service`). Install and enable it:

```
install -m 0644 packaging/systemd/cerberusd-backup.service packaging/systemd/cerberusd-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cerberusd-backup.timer
```

Deploy pipelines must call `cerberusd backup`, or copy only the finished files in `backups/`, and never the
`vault.cerberus*` files. Details: [Back up the headless daemon](backup-and-restore.md#back-up-the-headless-daemon).

## Config reference

File: `/etc/cerberus/cerberusd.toml`. Environment variables win over the file.

| Key | Env | Default | Meaning |
|---|---|---|---|
| `data_dir` | `CERBERUSD_DATA_DIR` | `$XDG_DATA_HOME/cerberusd` | Absolute path. Holds `vault.cerberus`, `tls/`, the socket and, while the daemon waits for its first client, `setup-code` |
| `bind` | `CERBERUSD_BIND` | `127.0.0.1`, `::1` | IP addresses to listen on |
| `port` | `CERBERUSD_PORT` | `7373` | TCP port, 1 to 65535 |
| `host_names` | `CERBERUSD_HOST_NAMES` | none | Extra names for the TLS certificate and the allowed `Host` header |
| `require_mtls` | `CERBERUSD_REQUIRE_MTLS` | `false` | Client certificates on every connection. Must be `true` for a non-loopback bind |
| `idle_lock_seconds` | `CERBERUSD_IDLE_LOCK_SECONDS` | `0` (off) | Lock after idle seconds: `0` or `60` to `86400` |
| `max_unlocked_seconds` | `CERBERUSD_MAX_UNLOCKED_SECONDS` | `0` (off) | Hard limit: lock this many seconds after an unlock: `0` or `900` to `604800` |
| `[admin] enabled` | `CERBERUSD_ADMIN_ENABLED` | `true` | The admin API for enrolled desktops, and approvals (section 6). Also needed for the first-time setup (section 2) |
| `[admin] session_idle_seconds` | `CERBERUSD_ADMIN_SESSION_IDLE_SECONDS` | `900` | Admin session idle limit: `60` to `3600`, at most the max |
| `[admin] session_max_seconds` | `CERBERUSD_ADMIN_SESSION_MAX_SECONDS` | `43200` | Admin session absolute limit: `900` to `86400` |

Unknown keys stop the start, and the error names the key. The file must be mode `0600`, or the daemon refuses to start.

The daemon has no hard limit by default: the vault stays unlocked until a manual lock, an idle lock (if you set one), or a restart.
The desktop app has a default of 12 hours. To lock the server vault a fixed time after each unlock, set
`max_unlocked_seconds`. This value is only the default for a vault that has no setting saved. An owner or operator can
change the hard limit at run time in the vault settings (the saved setting then wins over the file). A hard limit
makes agents lose access when it ends, until a person unlocks the vault again.

A vault has a saved `max_unlocked_seconds` only when somebody set it to a value that was not the default at that time.
Changing another lock setting (for example the idle lock) does not save it. A vault that you made on the desktop and then
restored on the server can still carry it from an older build: the desktop default is `43200` (12 hours), and that
saved value wins over the file. To remove it, an owner or operator sets the hard limit to off in the vault settings
(`settings_set` with `max_unlocked_seconds` = `null`). The vault then has an explicit "off" and ignores the file value.

## Security notes

- The passphrase is never in argv or in an environment variable. It goes from the terminal to the unlock socket, or from the first client to the setup listener over the pinned TLS channel.
- The unlock socket is mode `0600` and accepts only the uid of the daemon.
- The daemon does not write the passphrase, tokens, the setup token or the recovery key to the log.
- Core dumps are off (`LimitCORE=0`, and the process itself is not dumpable).
- With `require_mtls`, the daemon needs client certificates. Agent certificates are made on the desktop app; the
  daemon checks them but cannot make them. Admin client certificates are made by `cerberusd admin enroll`. An agent
  certificate never passes the admin routes: only enrolled certificate hashes do.
- The admin API is on unless `[admin] enabled = false`. Then the operator passphrase crosses the network once per
  session, inside TLS 1.3 to a pinned CA, from an enrolled device only.

## Known gaps (version 1)

- `status` cannot reach the daemon when `require_mtls` is set (it sends no client certificate).
- The check "every active agent key has mTLS" is not done on a non-loopback bind. Make sure that keys have `require_mtls`
  on the desktop app before you open a LAN bind.
- Only the passphrase unlocks the daemon, at the terminal or from an enrolled desktop. The recovery key does not.
- There is no `cerberusd restore` command. Copy the backup file as described in step 2.
- `host_names` must include every name that agents use in the `Host` header.
