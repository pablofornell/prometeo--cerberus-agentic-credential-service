# ADR-0005: Item content and item metadata are encrypted

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D5
- Related: ADR-0006, ADR-0013, ADR-0014, ADR-0027, `docs/schema.sql`

## Context

A stolen DB file must show nothing useful. Titles such as "prod root password for bank-x" are sensitive.
The expiry sweeper must still delete expired rows while the vault is locked.

## Decision

1. In table `items`, only these columns are plain text: `id`, `kind`, `expires_at`, `created_at`, `updated_at`,
   `current_version`. Delete is a hard delete (ADR-0027). All other item data is in encrypted blobs:
   - `meta_ct`: title, description, workspace ID, role label, category, tags, environment, target,
     created_by, max_uses, use_count, custom fields. Sealed with `meta_key` (ADR-0014).
   - `item_versions.payload_ct`: the typed secret payload of one version. Sealed with that version's DEK.
   - `item_versions.wrapped_dek`: the DEK of that version, sealed with `item_kek`.
   - `item_versions.meta_ct`: a snapshot of the metadata of that version (for version history).
2. The same rule applies to other tables with human text: workspace names, agent names, grant selectors,
   access request reasons and audit event bodies are encrypted with `meta_key`. The plain columns of each table
   are listed in `docs/schema.sql`.
3. `kind` is plain. It lets the sweeper and the schema checks work while locked. It shows only the type
   (for example `api_key`), not the content.
4. `workspace_id` is **not** plain on items. Policy runs on the in-memory index (ADR-0006).
5. The sweeper (ADR-0027) deletes rows where `expires_at <= now` while locked, with `secure_delete=ON`.
6. Acceptance test A7 opens the DB file as bytes and searches for each fake test title, description,
   username and secret. The test fails if one is found.

## Consequences

- A DB thief learns: the number of items, their kinds, expiry times, timestamps, agent IDs, lease rows
  (agent ID to item ID links) and the operator labels (ADR-0009). This is an accepted leak (threat model I-3).
- Search cannot run in SQL. It runs on the in-memory index.
- Each metadata change re-seals the whole `meta_ct` blob with a new nonce.

## Alternatives considered

- **SQLCipher (full-file encryption).** Rejected. The sweeper cannot run while locked, the key would be in a C library
  outside our zeroize control, and per-row AAD binding is lost.
- **Plain metadata, encrypted payload only.** Rejected. Titles and descriptions leak too much.
