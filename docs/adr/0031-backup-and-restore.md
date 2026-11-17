# ADR-0031: Backup and restore

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.5, 7 screen 11
- Related: ADR-0002, ADR-0013, ADR-0023, ADR-0025

## Context

A backup must be safe to store anywhere and must open with a phrase or the recovery key.

## Decision

1. **Backup** (IPC `backup_create`, any role except viewer, locked or unlocked): `VACUUM INTO '<path>'`. The copy holds
   header, key slots, all encrypted rows, the audit chain and `audit_pending`. The default name is
   `cerberus-<vault short id>-<UTC date>.cerberus-backup`. The file mode is `0600`.
2. The backup does **not** hold the TLS leaf key file (ADR-0023). After restore, the app makes a new leaf at unlock.
   Agents that pin the CA keep working, because the CA is in the backup.
3. **Restore** (IPC `backup_restore`, owner, or `NoVault` state; `cerberusd restore <file>` from a TTY):
   1. Check `application_id`, `magic`, `format_version` and `user_version`.
   2. The person types a phrase or the recovery key that is valid for a slot **in the backup**.
   3. Check `header_mac` and verify the audit chain. A broken chain shows a warning; the owner can still continue.
   4. Move the current file to `vault.cerberus.pre-restore-<UTC time>` (not deleted). *Amended by DEC-T27-H-1: when the restore went through, the file is renamed to `vault.cerberus.replaced-<UTC time>`, and only `.pre-restore-*` means an unfinished restore.*
   5. Put the backup in place. Revoke all leases, cancel all pending requests, write `backup.restore`.
4. **Agent tokens** survive a restore only if the agents exist in the backup.

## Consequences

- Restoring an old backup brings back old grants and old tokens. This is a rollback by the owner. It is audited in the
  restored chain.
- The old file stays on disk until the owner deletes it by hand. The app has no delete command (the earlier "secure delete" claim was wrong). *Amended by DEC-T27-H-1: it is kept as `.replaced-*` after a successful restore.*

## Alternatives considered

- **Export as JSON with re-encryption.** Rejected. A second crypto format to maintain. CSV export (T23) exists for
  migration, and it warns that the file holds plain secrets.
