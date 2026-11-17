# Running the Cerberus daemon (cerberusd)

`cerberusd` serves the Agent API (REST and MCP) for a vault on a server with no screen. It does not manage the
vault. You prepare items, agents and grants in the desktop app, then copy the vault to the server.

## What it can and cannot do

- It serves the Agent API over HTTPS (TLS 1.3 only) and the MCP endpoint at `/mcp`.
- It has no admin surface: no admin socket and no admin route (ADR-0002).
- It cannot ask a person for approval. A grant in mode `ask_once` or `ask_always` gives `403 approval_unavailable`.
  Use `auto` grants with tight selectors on a server.
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

The vault is made on the desktop app. Make a backup there, copy the backup file to the server, and store it as the
vault file. It must be mode `0600` and owned by `cerberus`:

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

It prints the daemon version, the address and `vault locked` or `vault unlocked`.

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

Unknown keys stop the start, and the error names the key. The file must be mode `0600`, or the daemon refuses to start.

The vault has a hard limit: it locks 12 hours after an unlock. The daemon cannot change it. Change it on the desktop
app, then make a new backup.

## Security notes

- The passphrase is never in argv or in an environment variable. It goes from the terminal to the unlock socket.
- The unlock socket is mode `0600` and accepts only the uid of the daemon.
- The daemon does not write the passphrase, tokens or secrets to the log.
- Core dumps are off (`LimitCORE=0`, and the process itself is not dumpable).
- With `require_mtls`, the daemon needs client certificates. Those are made on the desktop app. The daemon checks them
  but cannot make them.

## Known gaps (version 1)

- `status` cannot reach the daemon when `require_mtls` is set (it sends no client certificate).
- The check "every active agent key has mTLS" is not done on a non-loopback bind. Make sure that keys have `require_mtls`
  on the desktop app before you open a LAN bind.
- Only the passphrase unlocks the daemon. The recovery key does not.
- There is no `cerberusd restore` command. Copy the backup file as described in step 2.
- `host_names` must include every name that agents use in the `Host` header.
