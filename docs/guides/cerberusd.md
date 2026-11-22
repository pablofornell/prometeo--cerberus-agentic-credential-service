# Running the Cerberus daemon (cerberusd)

`cerberusd` serves the Agent API (REST and MCP) for a vault on a server with no screen. You create the vault on the
server with `cerberusd init`, or you prepare items, agents and grants in the desktop app and copy the vault to the
server. If you turn on the admin API, the desktop app can work with the server vault live, approvals included
(section 6, ADR-0034).

## What it can and cannot do

- It serves the Agent API over HTTPS (TLS 1.3 only) and the MCP endpoint at `/mcp`.
- By default it has no admin surface: no admin route (ADR-0002). With `[admin] enabled = true` it serves `/admin/v1`
  for desktops that you enrolled on the server (section 6).
- Without the admin API it cannot ask a person for approval: a grant in mode `ask_once` or `ask_always` gives
  `403 approval_unavailable`, so use `auto` grants with tight selectors. With the admin API on, such a grant makes an
  access request that a connected desktop decides; if no one decides, it expires after its timeout (default 120 s).
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
   those two lines from the unit (and set `require_client_cert`).
3. Check the config file (it must be mode `0600`):
   `sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml status` (the daemon must run first).

## 2. Put the vault on the server

There are two ways. Use one of them.

### Option A: create the vault on the server

A headless deploy needs no desktop app for this. Run `init` as the `cerberus` user, in an interactive shell on the
server, before you start the service. This is the example for the packaged systemd install:

```
sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml init --owner alice
```

- It asks for the owner passphrase twice. Nothing is echoed. The passphrase must have 12 characters or more and a
  strength score of 3 or more. It is never read from an argument or the environment.
- `--owner` is the label of the first owner (default `owner`). The TLS certificate carries the `host_names` of the
  config, so set them in `cerberusd.toml` before you run `init`: the certificate and the Host check of the daemon then
  agree. There is no `--host-name` option.
- Run `init` as the user that owns the data folder (`sudo -u cerberus`). It refuses a data folder of another user before it
  asks anything.
- The recovery key opens the vault without the passphrase and is shown one time. In a terminal `init` prints it, and
  you write it down or put it in a password manager. Store it offline. When stdout is not a terminal (a script, or output
  sent to a file or a log) `init` refuses before it makes anything, so the key never lands in a journal. In that case use
  `--recovery-out FILE`: it writes the key to a new file (mode `0600`) and prints only the path. The file must be
  **outside** the data folder (never under `/var/lib/cerberus`: the key must not sit next to the vault), must not exist,
  and its folder must exist and be writable by the user that runs `init` (checked before the passphrase is asked).
  Make a private folder first. `/run` is memory, so the key does not reach the disk:

  ```
  sudo install -d -m 0700 -o cerberus -g cerberus /run/cerberus-init
  sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml init --owner alice \
      --recovery-out /run/cerberus-init/recovery-key.txt
  ```

  Then move the key to offline storage (a password manager or paper), and delete the folder:
  `sudo rm -r /run/cerberus-init`.
- It prints the **CA pin**. A desktop that connects to this server needs it (section 6).
- It refuses when `vault.cerberus`, `vault.cerberus-wal` or `vault.cerberus-shm` exists, and changes nothing. It never
  removes a file it did not make. If the vault cannot be made, it removes the files it made, and you can run it again.
- The passphrase check and the key-derivation cost test (a few seconds) run before any file is made. While the files are
  made, SIGINT, SIGTERM, SIGHUP and SIGQUIT are held and the command finishes first, so the recovery key is not lost. A kill
  with SIGKILL, or a power loss, in that short moment can leave a partial vault that makes the next `init` refuse. Remove
  `vault.cerberus`, `vault.cerberus-wal`, `vault.cerberus-shm` and the `tls/` folder from the data folder (only these
  names) and run `init` again.
- The vault is left sealed. The key derivation cost is measured on this server (about 0.7 s per unlock), as on the
  desktop.

Then go to section 3: start the service and run `cerberusd unlock`. You can create items, agents and grants with a
desktop in remote mode (section 6), or make the vault on the desktop (Option B) if you prefer to prepare it there.

### Option B: copy a vault from the desktop app

Make a backup in the desktop app, copy the backup file to the server, and store it as the vault file. It must be mode
`0600` and owned by `cerberus`:

```
install -m 0600 -o cerberus -g cerberus cerberus-<id>-<date>.cerberus-backup /var/lib/cerberus/vault.cerberus
```

A backup has no TLS leaf key. The daemon makes a new leaf at the first unlock. Agents that trust the CA keep working.

Restoring over an existing vault file replaces every item, agent and token on the server with the backup's content.

## 3. Start and unlock

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

1. **Turn it on.** In `cerberusd.toml`:
   ```toml
   [admin]
   enabled = true
   ```
   Restart the daemon. The start log has a `warn` line `admin API enabled, N enrolled clients`, and the audit log gets
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
| `data_dir` | `CERBERUSD_DATA_DIR` | `$XDG_DATA_HOME/cerberusd` | Absolute path. Holds `vault.cerberus`, `tls/` and the socket |
| `bind` | `CERBERUSD_BIND` | `127.0.0.1`, `::1` | IP addresses to listen on |
| `port` | `CERBERUSD_PORT` | `7373` | TCP port, 1 to 65535 |
| `host_names` | `CERBERUSD_HOST_NAMES` | none | Extra names for the TLS certificate and the allowed `Host` header |
| `require_mtls` | `CERBERUSD_REQUIRE_MTLS` | `false` | Client certificates on every connection. Must be `true` for a non-loopback bind |
| `idle_lock_seconds` | `CERBERUSD_IDLE_LOCK_SECONDS` | `0` (off) | Lock after idle seconds: `0` or `60` to `86400` |
| `max_unlocked_seconds` | `CERBERUSD_MAX_UNLOCKED_SECONDS` | `0` (off) | Hard limit: lock this many seconds after an unlock: `0` or `900` to `604800` |
| `[admin] enabled` | `CERBERUSD_ADMIN_ENABLED` | `false` | The admin API for enrolled desktops, and approvals (section 6) |
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

- The passphrase is never in argv or in an environment variable. It goes from the terminal to the unlock socket.
- The unlock socket is mode `0600` and accepts only the uid of the daemon.
- The daemon does not write the passphrase, tokens or secrets to the log.
- Core dumps are off (`LimitCORE=0`, and the process itself is not dumpable).
- With `require_mtls`, the daemon needs client certificates. Agent certificates are made on the desktop app; the
  daemon checks them but cannot make them. Admin client certificates are made by `cerberusd admin enroll`. An agent
  certificate never passes the admin routes: only enrolled certificate hashes do.
- The admin API is off unless `[admin] enabled = true`. Then the operator passphrase crosses the network once per
  session, inside TLS 1.3 to a pinned CA, from an enrolled device only.

## Known gaps (version 1)

- `status` cannot reach the daemon when `require_mtls` is set (it sends no client certificate).
- The check "every active agent key has mTLS" is not done on a non-loopback bind. Make sure that keys have `require_mtls`
  on the desktop app before you open a LAN bind.
- Only the passphrase unlocks the daemon, at the terminal or from an enrolled desktop. The recovery key does not.
- There is no `cerberusd restore` command. Copy the backup file as described in step 2.
- `host_names` must include every name that agents use in the `Host` header.
