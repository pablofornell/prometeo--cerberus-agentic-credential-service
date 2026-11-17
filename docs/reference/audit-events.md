# Audit events

Every event type Cerberus writes to the audit log (ADR-0025). The code table is
`crates/cerberus-core/src/audit/catalog.rs` (`EventType`); a test checks that every row is listed here.

Each event body is sealed in the vault file. It holds `type`, `actor` (`agent`, `operator` or `system`),
`target` (`kind` and `id`), `result` (`ok` or an error code), `request_id` and `details`. It never holds a secret value.

Events written while the vault is locked wait in `audit_pending` and join the chain at the next unlock with
`details.recorded_while_locked = true`. Text in details is cut to 500 characters.

| Type | Target kind | When it is written |
|---|---|---|
| `vault.create` | `vault` | A new vault was created. |
| `vault.unlock` | `vault` | The vault was unlocked with an operator passphrase. |
| `vault.unlock_failed` | `vault` | An unlock attempt failed (wrong passphrase or recovery key). |
| `vault.unlock_recovery` | `vault` | The vault was unlocked with the recovery key. |
| `vault.lock` | `vault` | The vault was locked. details.reason says why. |
| `vault.panic` | `vault` | Panic: keys dropped and all leases revoked at once. |
| `vault.header_mismatch` | `vault` | The header MAC check failed at unlock. |
| `operator.add` | `operator` | An operator (key slot) was added. |
| `operator.remove` | `operator` | An operator was removed. |
| `operator.role_change` | `operator` | An operator role was changed. |
| `operator.phrase_change` | `operator` | An operator passphrase was changed. |
| `recovery.rotate` | `vault` | The recovery key was replaced. |
| `workspace.create` | `workspace` | A workspace was created. |
| `workspace.update` | `workspace` | A workspace was changed. |
| `workspace.delete` | `workspace` | A workspace was deleted. |
| `item.create` | `item` | An item was created. |
| `item.update` | `item` | An item was changed (new version). |
| `item.delete` | `item` | An item was deleted. |
| `item.reveal` | `item` | A secret value was read (reveal or resolve with value). |
| `item.totp` | `item` | A one-time code was generated. |
| `item.expire` | `item` | An item passed its expiry and was deleted by the sweeper. |
| `items.import` | `workspace` | Items were imported from a CSV file in one step. details hold counts only (`source`, `imported`, `skipped_problems`, `skipped_duplicates`, `renamed`), never titles or values. |
| `items.export` | `vault` | Items were exported to a CSV file with their secrets in plain text. details hold `count` (and `workspace_id` for a scoped export) only. Written before the bytes leave the vault. |
| `item.version_restore` | `item` | An old item version was restored as the newest. |
| `agent.create` | `agent` | An agent was created. |
| `agent.update` | `agent` | An agent was changed. |
| `agent.suspend` | `agent` | An agent was suspended. |
| `agent.resume` | `agent` | An agent was resumed. |
| `agent.revoke` | `agent` | An agent was revoked. |
| `agent_key.create` | `agent_key` | An agent API key was created. |
| `agent_key.rotate` | `agent_key` | An agent API key was rotated. |
| `agent_key.revoke` | `agent_key` | An agent API key was revoked. |
| `grant.create` | `grant` | A grant was created. |
| `grant.update` | `grant` | A grant was changed. |
| `grant.delete` | `grant` | A grant was deleted. |
| `request.create` | `request` | An agent asked for access that needs approval. |
| `request.approve` | `request` | An operator approved an access request. |
| `request.deny` | `request` | An operator denied an access request. |
| `request.expire` | `request` | An access request timed out. |
| `request.cancel` | `request` | An access request was cancelled. |
| `lease.create` | `lease` | A lease was issued. |
| `lease.use` | `lease` | A lease was used to read a secret. |
| `lease.release` | `lease` | A lease was released by its agent. |
| `lease.revoke` | `lease` | A lease was revoked by an operator or by a lock. |
| `lease.expire` | `lease` | A lease reached its end time. |
| `auth.failed` | none | A call failed authentication. |
| `auth.lockout` | none | An agent or address was locked out after repeated failures. |
| `api.locked_call` | none | A call arrived while the vault was locked. |
| `api.resolve` | none | An agent resolved a name to an item. |
| `api.catalog` | none | An agent listed its catalog. |
| `settings.change` | `settings` | A setting was changed. |
| `network.bind_change` | `settings` | The listen addresses were changed. |
| `tls.renew` | `settings` | The TLS leaf certificate was renewed. |
| `tls.custom_load` | `settings` | A custom TLS certificate was loaded. |
| `tls.custom_revert` | `settings` | The custom TLS certificate was removed and the local CA is in use again. |
| `backup.create` | `vault` | A backup was written. |
| `backup.restore` | `vault` | A backup was restored. |
| `backup.recover` | `vault` | A vault file left by a failed restore was put back in place. Written while locked, so details.recorded_while_locked is true. |
| `backup.recover_revoke` | `vault` | At the first unlock after a vault file left by a restore was put back, every agent key and lease of it was revoked and every pending request cancelled. details hold the counts. |
| `audit.export` | `vault` | The audit log was exported. |
| `audit.prune` | `vault` | Old audit rows were deleted by retention. |
| `audit.verify` | `vault` | The audit chain was verified. |
| `audit.pending_overflow` | `vault` | Events were lost while locked because the pending list was full. details.dropped holds the count. |
| `integrity.row_mac_mismatch` | none | A row failed its MAC check at unlock and was disabled. target.kind is the table, target.id the row. |
| `ssh.prepare` | `item` | An SSH key was prepared for the agent bridge. A second event with an error result and `decision: key_open` means the passphrase did not open the key (DEC-T27-A2-3). |
| `ssh.sign` | `item` | The ssh-agent bridge signed one request with an SSH key of the vault. For an `SSHSIG` blob, `details.namespace` names its namespace; only namespaces in the item setting `sshsig_namespaces` are signed (DEC-T27-A2-6). |

## Names used in the plan

The plan uses informal names. The catalog follows ADR-0025:

| Plan name | Event type |
|---|---|
| `unlock`, `lock`, `unlock.fail`, `panic` | `vault.unlock`, `vault.lock`, `vault.unlock_failed`, `vault.panic` |
| `item.read` | `item.reveal` (a secret read), `api.resolve` (a name lookup) |
| `request.timeout` | `request.expire` |
| `key.*` | `agent_key.*` (agent keys), `recovery.rotate`, `operator.phrase_change` |
