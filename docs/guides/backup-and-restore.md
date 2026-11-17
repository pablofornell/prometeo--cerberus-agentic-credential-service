# Backup and restore

A backup is one file that holds the whole vault. You need it when a disk fails, or when you move the vault to a server.
Read this guide with the [operator guide](operator-guide.md) and the design in [ADR-0031](../adr/0031-backup-and-restore.md).

## What a backup holds

- The vault header, the key slots, every encrypted row, the audit chain, and the audit rows that wait for the next unlock.
- It is a copy made by SQLite (`VACUUM INTO`). It is consistent at the moment of the copy.
- It does **not** hold the TLS leaf key. The app or the daemon makes a new leaf at the next unlock. The CA is in the
  backup, so agents that trust or pin the CA keep working.
- It holds the same secrets as the vault. Treat it with the same care. Anyone with a backup and their own phrase can
  read every item, the same as with the vault file (AR-9).
- It holds grants, agents and tokens as they were when the backup was made. Restoring an old backup brings back old
  tokens and old grants. That is a rollback, and the restore is written to the audit log.

## Make a backup (desktop app)

1. Unlock the vault, then open Settings, Backup and restore. You need an unlocked vault to reach Settings. Any role
   except viewer can make a backup.
2. Choose Create backup. The default file name is `cerberus-<vault short id>-<UTC date>.cerberus-backup`.
3. The file has mode `0600`. Keep it in a place that only you can read.
4. Copy it to a second place. Store one copy off the machine.

Make a new backup after each change of the phrase, the recovery key or the operators. Make one before any restore, an
upgrade, or any other change you cannot undo.

## Restore (desktop app)

Only the owner can restore. The app refuses a restore when `vault.cerberus`, `vault.cerberus-wal` or `vault.cerberus-shm` is a symbolic link. It answers `unavailable` and changes nothing. Put the real file at the vault path first, then restore. When no vault exists, you can start a restore from the unlock screen without unlocking.
When a vault exists, unlock it as the owner first, then start the restore from the settings. The restore is one operation, in this order:

1. The app checks that the file is a Cerberus backup of a supported version.
2. You type a phrase or the recovery key. It must be valid for a key slot **in the backup**. The phrase of the current
   vault is not enough.
3. The app checks the header MAC and the audit chain. A broken chain is only written to the log. You see no warning and make no choice, and the restore goes on.
4. The current vault file moves to `vault.cerberus.pre-restore-<UTC time>`. It is not deleted.
5. The backup is put in place. The app ends every lease, cancels every pending request, and writes `backup.restore`.
6. When the restore went through, the old file (with its `-wal` and `-shm` files) is renamed from `.pre-restore-<UTC time>`
   to `vault.cerberus.replaced-<UTC time>`. The app never offers it back.

An unlock waits until a running restore ends.

The app first copies the backup to a private staging folder, and removes that folder when the restore ends. The copy
is made so that the checks read a stable file.

After a restore, the vault has the items, operators, agents and grants of the backup. Check them, then delete the
`.replaced-*` file yourself when you are sure. The app has no delete command. The file still holds the old items and the
old agent keys, so do not leave it where others can read it.

## Restore to the headless daemon

The daemon has no restore command. It supports `serve`, `unlock` and `status` only. Do the copy by hand, as in the
[daemon guide](cerberusd.md#2-put-the-vault-on-the-server):

```
sudo systemctl stop cerberusd
sudo mv /var/lib/cerberus/vault.cerberus /var/lib/cerberus/vault.cerberus.old
sudo install -m 0600 -o cerberus -g cerberus cerberus-<id>-<date>.cerberus-backup /var/lib/cerberus/vault.cerberus
sudo systemctl start cerberusd
sudo -u cerberus cerberusd --config /etc/cerberus/cerberusd.toml unlock
```

Before you start, check the following:

- The daemon must be stopped. It locks the vault when it stops.
- After a clean stop, no `vault.cerberus-wal` or `vault.cerberus-shm` file should sit next to the vault. If one does,
  stop and check the folder. Do not copy over it.
- Keep `vault.cerberus.old` until the restored vault works. Do not delete it at once.
- Restoring over an existing vault replaces every item, agent and token on the server.
- A daemon restore with `install` does not ask for the phrase. The unlock step does. If the phrase is not valid for
  a slot in the backup, the unlock fails.

## Check a backup

A backup that you have never opened is only a guess. Once in a while, restore it on a spare machine or into a spare
data folder, unlock it, and check a few items. Do this on a copy, never on the only vault.

## If a restore fails

The app closes the old vault before it moves any file, and moves the files back when a step fails. After a failed
restore your old vault is the vault again, and you can try the restore again. The app never makes a new, empty vault
in place of the real one.

Only a `.pre-restore-*` file means that a restore did not finish. A restore that went through leaves `.replaced-*`,
which never starts the state below.

Rarely, the old vault cannot be moved back and stays as `vault.cerberus.pre-restore-<UTC time>` (with its `-wal` and
`-shm` files) in the data folder. A crash in the middle of a restore, a failed rename at the end, and files of older
versions leave the same thing. The app then has no vault file and one or more
`.pre-restore-*` files. It sets this state at once, in the same session, and again at each start. It does not make a new vault. It shows **Your vault was found, but it is not in place**, with
the path of the file. Press **Put the vault back**:

- The newest `.pre-restore-*` file, with its `-wal` and `-shm` files, moves back to `vault.cerberus`. It never
  replaces a file that is there: if a vault file already exists, nothing moves and the app says so.
- If the file does not open, it goes back to its old name and the app shows the error.
- The vault is sealed afterwards. Unlock it as usual. The audit log gets a `backup.recover` event.
- At that first unlock, before it serves any agent, the app revokes every agent key and every lease of the vault and
  cancels every pending request. The log gets `backup.recover_revoke` with the counts. Agents need new tokens. The app
  cannot tell which kind of file it put back, and a revoked key costs only a new token.
- Older `.pre-restore-*` files, from earlier restores, are left alone.

While the vault is in this state the app refuses to create a vault or to start a restore, so nothing can hide the old
file. The log names the path too. If the app cannot read the data folder at start (and the vault file is missing), it
makes no vault and shows **Cannot read the vault status** (`unavailable`). Fix the folder permissions and restart the
app. The headless daemon has no restore and never makes a vault, so
it cannot strand one: without a vault file it stops with `no vault file at <path>`.

If the button does not help, do this by hand:

1. Close the app. Stop the daemon if it runs.
2. Do not delete any file in the data folder. In the desktop app the folder is the Tauri app data folder for
   the identifier `dev.cerberus.vault` (on Linux, normally `~/.local/share/dev.cerberus.vault/`).
3. Copy the whole folder to a safe place first.
4. Look for `vault.cerberus.pre-restore-*`. If the vault file is missing and the `.pre-restore-*` file holds your
   data, rename it (and its `-wal` and `-shm` files, if any) to `vault.cerberus`, `vault.cerberus-wal` and
   `vault.cerberus-shm`. If a vault file exists too, keep both and do not rename or delete anything until you have a
   backup of the folder.
5. Start the app again, and try the restore again from a backup that you know is good.

If you are not sure which file holds your data, stop and ask the owner of the vault before you change anything.
