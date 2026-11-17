# ADR-0020: Resolve scoring

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 5.1 (resolve rules), A2, A4, T06 (40+ table cases)
- Related: ADR-0006, ADR-0017, ADR-0018, ADR-0021

## Context

Agents ask by intent ("app shop-frontend, env staging, role admin"), not by ID. The result must be predictable.
A wrong match can give an agent the wrong role, so the engine must prefer "ask the agent to choose" over a guess.

## Decision

### Input
`app` (required, 1..128 chars), `environment?`, `role?`, `kind?`, `hint?` (max 256 chars), `purpose` (required,
1..500 chars), `mode` (`best` default, or `candidates`). All text is normalized (ADR-0006).

### Steps
1. **Visible set**: items where policy gives `find` (ADR-0017), not expired.
2. **App match** (required). An item matches `app` when:
   - its workspace slug, a workspace alias or the normalized workspace name equals `app`: app score **100**; or
   - its `target` (URL host, SSH host, machine name or app name) equals `app`, or contains `app` as a whole word:
     app score **60**.
   Items with no app match are removed.
3. **Hard filters**:
   - `environment` given: keep exact matches only. Synonyms: `production`→`prod`, `stage`/`stg`→`staging`,
     `development`/`local`→`dev`.
   - `kind` given: keep exact matches only.
4. **Role** (when `role` is given):
   - exact normalized role label, or same synonym class: **+50**. Classes: admin = {admin, administrator,
     superuser, root}; user = {user, normal user, standard, regular, default}; read-only = {read-only, readonly,
     ro, viewer, read}. Custom labels (for example "SAI user") match only by exact text or word overlap.
   - at least one common word with the role label: **+20**.
   - no match: the item is removed. A wrong role is never returned.
5. **Hint** words: each word found in the title **+10** (max 30), in description, tags or target **+5** (max 20).
6. **Sort**: score descending, then `updated_at` descending, then `id` ascending.

### Outcome
- `mode = candidates`: return up to 20 candidates (`200`, `outcome: "candidates"`).
- `mode = best`: the top item is **confident** when it is the only item, or when its score is at least 25 points
  above the second item.
  - Confident: run the `read` policy on it. Result: `200` with the secret (`outcome: "secret"`), or `202` with an access
    request (`outcome: "pending"`), or `403`.
  - Not confident: `200` with `outcome: "ambiguous"` and up to 20 candidates. No secret.
- No item left: `404 no_match`, with `details.hints` built only from items the agent can see:
  - `app_known: false` when no visible item matched `app`;
  - else `environments`, `roles` and `kinds` that exist for that app among visible items.
- A candidate contains: `id`, `kind`, `title`, `description`, `role_label`, `environment`, `workspace` (slug),
  `target`, `score`, `expires_at`. Never a secret value.

### Rules
- `purpose` is stored in the audit event (`api.resolve`). It is not used for scoring or policy.
- An environment is never guessed. If `environment` is missing and both `staging` and `prod` items match with close
  scores, the result is `ambiguous`.

## Consequences

- A2 passes when exactly one `staging` + `admin` item exists in `shop-frontend`.
- A4 passes when the SSH item has target `build-01` (app score 60 via target).
- T06 writes at least 40 table cases from these rules.

## Alternatives considered

- **Fuzzy edit distance on all fields.** Rejected. It makes surprising matches, and surprises here leak secrets.
