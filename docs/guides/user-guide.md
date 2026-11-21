# User guide: the Cerberus desktop app

This guide is for the person who runs the vault. It covers the desktop app. For the agent side, read the
[agent integration guide](agent-integration.md). For roles and server settings, read the
[operator guide](operator-guide.md).

Cerberus holds your credentials. Agents ask for them. You decide what each agent may read. You approve or deny the
requests that need you.

## 1. Create the vault

1. Enter a name for the vault.
2. Enter a master phrase. The strength meter shows how strong it is. A Diceware generator can make one for you.
3. Save the recovery key. The app shows it one time. Print it, copy it, or write it down, then confirm it.
4. Wait while the app tunes the key derivation. The memory cost depends on your RAM: 256 MiB with 4 GiB or more,
   otherwise 64 MiB.

Keep the phrase and the recovery key safe and apart. If you lose both, nobody can open the vault again.

## 2. Unlock and lock

- **Unlock.** Pick your operator label, then type the phrase. The phrase is never shown.
- **Recovery key.** Use it when you lose the phrase. It opens the vault with owner rights. The app then asks you to
  set a new phrase. Each use is written to the audit log.
- **Failed tries.** The first five failures in a row have no wait. After that the wait doubles for each failure, up
  to 15 minutes. The screen shows a countdown.
- **Lock.** Press `Ctrl/Cmd + L`, or use the Lock button in the sidebar.
- **Automatic lock.** The default idle lock is 30 minutes. The hard limit is 12 hours after each unlock. Both can be
  changed in Settings. Agent calls count as activity by default, so the idle lock does not fire while agents work.
- **Lock on sleep or screen lock.** On by default. On Linux the vault locks when the machine sleeps or the session
  locks. On macOS and Windows this does not happen yet (see the [operator guide](operator-guide.md#platform-gaps)).
- **Lock and revoke all.** This is the panic button. Hold it for 1 second. It locks the vault, ends every active
  lease, and cancels every pending request. It is also in the command palette. It has no single-key shortcut, so a
  stray key cannot trigger it.

When the vault is locked, every agent gets HTTP 423 and no data.

## 3. Vault browser and items

The vault screen lists workspaces in the sidebar. A workspace is an application or a project, for example
`shop-frontend`. Use the filters for kind, environment and role label. Items with environment `prod` have a badge.
Session items show a ring that counts down their time to live.

Each item has a kind:

| Kind | Holds |
|---|---|
| Web login | User name, password, URL, optional TOTP seed |
| API key | One key value |
| SSH key | A private key, with host, port and user. The key never goes to an agent. Agents use the SSH socket |
| Session token | A token with a time to live |
| Browser session | A Playwright storage state (cookies and local storage of a site) |
| Database | A connection URL, or its parts |
| Cloud | Access key, secret and region for a cloud provider |
| Certificate | Certificate, key and chain in PEM |
| Env bundle | Named values for environment variables |
| Note | Free text |
| RustDesk | A remote machine: its RustDesk ID, optional self-hosted servers and key, and an optional permanent password |

Give each item a role label such as `admin`, `normal user` or `read-only`, and an environment (`dev`, `staging`,
`prod` or `other`). Agents search by these fields.

Items have these settings:

- **Time to live** (`ttl_seconds`). The item is removed when it expires.
- **Maximum reads** (`max_uses`). The item is removed after this many reads.
- **Versions.** Each save keeps the old version. The default is 10 versions per item. You can restore an old one.

**Reveal and copy.** Hold the eye button for half a second to show a secret. It hides again after 15 seconds. Copy
clears the clipboard after 30 seconds. The app does not keep the value after you hide it or lock the vault. Your
clipboard manager may still keep a copy. Cerberus cannot clear that.

**SSH keys.** In the item editor, import an OpenSSH private key or generate an Ed25519 key. An encrypted key is kept
as it is, with its passphrase. Its bcrypt cost must be at most 1024 rounds.

**TOTP.** The app shows a live preview of the code for a TOTP seed. Agents ask for the current code. They never see
the seed.

**Password generator.** The editor can make a password for you.

### RustDesk connections

A RustDesk item stores how to reach a machine with [RustDesk](https://rustdesk.com), for example your laptop.

1. On the machine, open RustDesk and note its **ID** (9 or more digits) and, if you set one, its **permanent
   password**.
2. In Cerberus, choose **New item** and the kind **RustDesk**. Type the ID (spaces are removed). If you run your own
   RustDesk server, also type the **ID server**, the **relay server** and the **server key** (its public key, not a
   secret). Leave them empty for the public RustDesk servers. The password is optional.
3. Save. The ID, the servers and the key are item metadata: the details show them, and a search for the ID finds the
   item. Only the password is secret.

In the item details, the **Connection** card has:

- **Connect.** Opens the RustDesk client of this computer on the ID, and copies the password to the clipboard. Paste
  it in RustDesk when it asks. The clipboard is cleared after 30 seconds. The password is never put on a command line.
  A viewer can connect, but the password is not copied. With an ID server, Connect asks RustDesk for
  `<ID>@<ID server>` (and the key), so it reaches the machine through your server even when the client is set to
  the public servers. If the key has a `+`, close RustDesk before Connect: RustDesk hands the request to an open
  window as a link and can misread the `+`.
- **Link.** `rustdesk://<ID>` for the public servers. With an ID server it is
  `rustdesk://connect/<ID>@<ID server>?key=<server key>` (the key is encoded). Copy it and open it on another computer
  with RustDesk installed. RustDesk gets the relay from the ID server, so the relay is not in the link. An ID server
  given as an IPv6 address cannot go into the link or Connect: the card then asks you to set it in the RustDesk
  client (Settings, Network).
- **To share** and **Copy all.** The ID, the servers, the key and the link as text, to send to someone who adds the
  connection to their own RustDesk client. The link and the text never hold the password. Send the password another
  way.
- The **Password** row works like every other secret: hold to reveal, copy with a 30 second clear.

Cerberus looks for the RustDesk client in this order: `rustdesk` on the search path, the standard install folder
(`/usr/bin`, `/usr/local/bin`, `/usr/share/rustdesk` on Linux; `/Applications/RustDesk.app` on macOS;
`Program Files\RustDesk` on Windows), then the Flatpak app `com.rustdesk.RustDesk`. If it is somewhere else, for
example an AppImage, choose its program in **Settings, Remote desktop**. The file name must start with `rustdesk`
(any case). When a program is chosen there, Cerberus starts only that one. If RustDesk is not found, the card says so
and **Connect** is off; install RustDesk from rustdesk.com or Flathub.

Agents get a RustDesk item like any other item: with a grant that allows `read`, the read answer holds the ID, the
servers, the key and the password (fields `rustdesk_id`, `id_server`, `relay_server`, `server_key`, `password`).
`cerberus run` sets `CERBERUS_RUSTDESK_ID`, `CERBERUS_RUSTDESK_PASSWORD`, `CERBERUS_RUSTDESK_ID_SERVER`,
`CERBERUS_RUSTDESK_RELAY_SERVER` and `CERBERUS_RUSTDESK_KEY`. A CSV export writes the password in the `password`
column and the connection in `extra`; a CSV import does not make RustDesk items.

## 4. Agents

An agent is a client, such as a coding assistant or a test runner. In the agents screen:

- **Create an agent.** Give it a name.
- **Create a key.** A key is a token for the agent. The token is shown one time. Copy it into the agent's
  configuration at once. An agent may have up to five live keys.
- **Rotate a key.** Make a new key. You choose how many seconds the old key keeps working (the overlap). After that
  the old key stops.
- **Revoke a key.** The next call with that key gets HTTP 401. Open connections with that key are closed within
  about a second.
- **Suspend or revoke an agent.** A suspended agent gets 401. A revoked agent cannot be used again.
- **Snippets.** The screen shows integration snippets: an MCP JSON block, a curl command, and environment variables.

A key can also be limited to some IP addresses, or to a client certificate. These limits are set on the key.

## 5. Policies (grants)

A grant gives one agent some permissions on some items. Build it in the policies screen, in plain words:
"agent X can read items in workspace Y, environment staging, category Web login, and I approve: never, once or
always."

A grant has:

- **Selector.** Workspace, environment, category, tags, kinds, role labels, or item IDs.
- **Permissions.** `find` (see the metadata), `read` (get the secret), `create_session`, `write` (store new items), and
  `use_ssh` (use an SSH key through the socket).
- **Mode.** `auto` (give it at once), `ask_once` (ask you, then keep a short lease), `ask_always` (ask every time), or
  `deny`.
- **Conditions.** A time window, a limit on reads per hour, an expiry, and whether a reason is required.

Items in `prod` use `ask_always` unless you change that. Only the owner can set `allow_prod_auto`, which lets a grant
give `prod` items with no approval.

The simulator answers "What can agent X see?" Use it before you save a broad grant.

**Limits on reads and requests.** By default an agent may read 60 secrets a minute, and 30 different items an hour.
Access requests are limited to 10 per 10 minutes, with at most 5 pending. The owner can change these in Settings. When
an agent reads 30 different items in one hour, the dashboard shows an alert.

## 6. Approvals

When an agent asks for an item that needs approval, an approval window opens. It stays on top of other windows. It
shows the agent, the item, the reason the agent gave, and whether the item is `prod`.

- **Approve once.** One use of the item.
- **Approve for 15 minutes.** A lease for 15 minutes.
- **Approve for the session.** A lease until the vault locks. It is capped at 8 hours. An item can have a shorter
  session limit.
- **Deny.** The agent is refused. The same agent cannot ask for the same item again for 10 minutes by default.

Hold `A`, `F` or `S` for 600 ms to approve. Press `D` to deny. The agent's wait ends after 120 seconds by default. The
agent then gets `pending` and can ask again.

The reason is text written by the agent. Read it as untrusted. Check the item and the agent before you approve.

## 7. Leases and sessions

The leases screen lists the active leases: each one is an approval or a grant that gives access for a time. You can
revoke one lease, or all of them. A revoked lease stops working at once.

## 8. Audit

The audit screen shows a timeline of events. Filter by event, agent, item, outcome, or a text search of up to
200 characters. The chain check badge shows whether the log is intact. The audit log never contains a secret value.
Export writes the events to a file.

## 9. Settings

| Group | What you can set | Who |
|---|---|---|
| Security | Idle lock, hard limit, lock on sleep, whether agent calls keep the vault open | Owner or operator |
| Security | Change your own phrase | Any role |
| Security | Rotate the recovery key | Owner |
| Items | Session time to live (default 3600 s, maximum 86400 s), number of versions kept | Owner |
| Policy | Approval wait, deny cooldown, auto lease length, request and read limits | Owner |
| Network | Bind addresses, port, client certificate rules, CA export, custom certificate | Owner |
| Remote desktop | The RustDesk client program that **Connect** starts (empty: found automatically). A setting of this computer | Owner or operator |
| Operators | Add or remove operators, change roles | Owner |
| Backup and restore | Make a backup, restore one | Owner (restore), owner or operator (backup) |
| Import and export | CSV import (preview first), CSV export | Import: owner or operator. Export: owner |

Your role decides what you can do. The [operator guide](operator-guide.md#roles) has the full table.

### CSV import and export

Import reads an export from Bitwarden, 1Password, KeePassXC, Chrome, Firefox or a generic file. The app can detect
the format. It shows a preview first. The import is all-or-nothing: if one row fails, nothing is saved.

The item's target keeps only the scheme, host and port of the URL. It drops the password, the path, the query and
the fragment, so a webhook or bot token in the path does not reach the target. A dotted user name before a `/` can
still be kept. When the URL is too unclear to split safely, the target is empty. This applies to every row with a URL.
The login keeps the full URL, because it is a secret. The exception is a URL that is not a plain `http` or `https`
address (another scheme, spaces, or over 2048 characters): then the login URL is empty. You can still type a path
into the target by hand. See the
[security model](security-model.md#9-status-of-the-audit).

Export writes every secret in plain text. The file has mode `0600`. Store it carefully, and delete it when you have
finished. The app warns you about this before it writes.

## Keyboard

| Keys | Action |
|---|---|
| `Ctrl/Cmd + K` | Command palette |
| `Ctrl/Cmd + L` | Lock now |
| `G`, then `D`, `V`, `A`, `P`, `R`, `L`, `U`, `S` | Go to Dashboard, Vault, Agents, Policies, Approvals, Leases, Audit, Settings |
| `N` | New item |
| `/` | Search on screens that have search |
| `?` | Shortcut list |
| `Esc` | Close a dialog or drawer. It never confirms |

No single key works while you type in a text field. No key approves a request without a hold.
