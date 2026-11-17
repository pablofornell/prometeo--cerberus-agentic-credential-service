# ADR-0009: Operators have their own key slots and roles

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D9
- Related: ADR-0003, ADR-0013, ADR-0014, ADR-0026

## Context

More than one person can manage the vault. Each person needs an own master phrase. Some people must only look.

## Decision

1. An **operator** is a person. Each operator has exactly one passphrase key slot. Each slot wraps the same VMK.
2. Roles:

   | Action | owner | operator | viewer |
   |---|---|---|---|
   | Unlock, lock, panic | yes | yes | yes |
   | Browse metadata, view audit, verify chain | yes | yes | yes |
   | Reveal or copy a secret in the UI | yes | yes | no |
   | Create, edit, delete items and workspaces | yes | yes | no |
   | Create, rotate, revoke agents and keys | yes | yes | no |
   | Create and edit grants (not `allow_prod_auto`) | yes | yes | no |
   | Approve or deny access requests | yes | yes | no |
   | Revoke leases | yes | yes | yes |
   | Set `allow_prod_auto` on a grant | yes | no | no |
   | Add or remove operators, change roles | yes | no | no |
   | Network bind, TLS, KDF, session TTL settings | yes | no | no |
   | Rotate recovery key, backup restore | yes | no | no |
   | Change own phrase | yes | yes | yes |

3. At least one owner slot must exist. The service refuses to remove or demote the last owner.
4. The **recovery key** slot has no operator. It unlocks with role owner. Its use writes a `vault.unlock_recovery`
   audit event, and the UI then asks the person to set a new phrase.
5. Unlock is by operator: the unlock screen lists operator labels, the person picks one and types the phrase.
   So operator labels are plain text in `key_slots.label` (an accepted leak, I-3 in the threat model).
6. The current operator ID and role are part of the unlocked session state. Every IPC command checks the role.

## Consequences

- Roles are an application rule, not a crypto boundary. Every slot opens the same VMK. A viewer who extracts
  the VMK from memory can read everything. This is accepted and documented (threat model E-3).
- One unlock serves all agents. The vault does not track which operator is "at the screen" after unlock,
  except for the audit actor of IPC actions.

## Alternatives considered

- **Per-role key trees (viewer gets only `meta_key`).** Rejected for version 1. It needs two DEK wrap paths and
  more key custody code. Possible later as a new ADR.
- **Try all slots with one phrase.** Rejected. Each Argon2id try costs about 0.7 s. Many slots make unlock slow.
