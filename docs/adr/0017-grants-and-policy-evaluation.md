# ADR-0017: Grants and policy evaluation

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 3 (grant fields), T07 ("deny wins, then most specific")
- Related: ADR-0006, ADR-0016, ADR-0018, ADR-0019, ADR-0020

## Context

The plan lists grant fields and says "deny wins, then most specific". The exact match rules, weights and the
`prod` rule need a definition, so T07 is deterministic and testable.

## Decision

### Grant
```
Grant {
  id, agent_id,
  selector:    { workspace_ids[], environments[], categories[], tags[], kinds[], role_labels[], item_ids[] },
  permissions: set of find | read | create_session | write | use_ssh,
  mode:        auto | ask_once | ask_always | deny,
  conditions:  { time_window?, max_reads_per_hour?, expires_at?, reason_required: bool },
  allow_prod_auto: bool   (owner only),
  created_at, updated_at
}
```
The whole body is encrypted (`grants.body_ct`). Only `id`, `agent_id`, `expires_at` and timestamps are plain.

### Match rules
1. A selector field that is empty matches all items.
2. A non-empty field matches when the item value is in the list ("any of"). For `tags`, the item matches when it has
   at least one of the listed tags. Text compare uses the normalized form (ADR-0006).
3. A grant matches an item when **all** non-empty fields match.
4. Permission implication: `read` implies `find`. `use_ssh` implies `find`. Nothing else is implied.
5. For `write` and `create_session`, the "item" is the proposed metadata of the new item.

### Evaluation of (agent, item, permission)
1. Take grants of the agent that match the item, are not expired, and whose permission set contains the permission
   (after implication). A `deny` grant with an empty permission set denies all permissions.
2. If a matching grant has mode `deny`: result **Deny**. Deny always wins.
3. If no grant is left: result **NoGrant**. For `find`, the item is invisible (`404 not_found`). For other permissions on
   a visible item: `403 forbidden`.
4. Else pick the most specific grant. Specificity = sum of weights of the non-empty selector fields:
   `item_ids` 64, `workspace_ids` 16, `environments` 8, `role_labels` 4, `kinds` 2, `categories` 2, `tags` 1.
   Tie: the stricter mode (`ask_always` > `ask_once` > `auto`). Next tie: older `created_at`, then smaller `id`.
5. Check the conditions of the chosen grant:
   - `time_window` (`days`, `start`, `end`, IANA `tz`; evaluated with `jiff`): outside gives `403 condition_failed`.
   - `max_reads_per_hour`: counted per (grant, agent) over a sliding hour in memory: over the limit gives
     `429 grant_rate_limited`.
   - `reason_required` and the call has no `purpose`/`reason` of at least 8 characters: `400 reason_required`.
6. **prod rule**: if the item environment is `prod`, the permission is `read` or `use_ssh`, and the grant does not
   have `allow_prod_auto`, then the effective mode is `ask_always`.
7. Result: **Allow(mode, grant_id)**. `auto` allows now. `ask_once` and `ask_always` go to the lease and approval logic
   (ADR-0018, ADR-0019).
8. Mode is only used for `read` and `use_ssh`. For `find`, `write` and `create_session`, any non-deny mode means allow.

### Rules
- Policy uses only agent identity, grant data and item metadata. It **never** reads the reason or purpose text,
  except to check that it is present (`reason_required`).
- The simulator (`policy_simulate` IPC) runs the same function for every item and permission of one agent and shows
  the result and the chosen grant.

## Consequences

- The result is deterministic. T07 table tests cover each step.
- An owner can make a narrow `auto` grant for one `prod` item with `allow_prod_auto`. This needs owner role and is audited.

## Alternatives considered

- **First-match rule order (like a firewall).** Rejected. Order is hard to show in the visual grant builder.
- **Allow wins.** Rejected. A deny must be a safe override.
