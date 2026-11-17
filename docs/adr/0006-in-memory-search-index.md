# ADR-0006: Search runs on an in-memory index built at unlock

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D6
- Related: ADR-0005, ADR-0017, ADR-0020, ADR-0026

## Context

Metadata is encrypted (ADR-0005). SQL cannot filter or score it. Resolve, catalog and policy need fast access to it.

## Decision

1. At unlock, `cerberus-core` reads all rows of `items`, `workspaces`, `agents` and `grants`. It opens each `meta_ct`
   and builds an `Index` in memory:
   - `items: HashMap<ItemId, ItemMeta>`
   - `by_workspace`, `by_environment`, `by_kind`: `HashMap<_, BTreeSet<ItemId>>`
   - `tokens: HashMap<String, BTreeSet<ItemId>>` (normalized words of title, description, role label, tags, target)
   - `workspaces_by_slug: HashMap<String, WorkspaceId>` (slug and aliases)
   - `grants_by_agent: HashMap<AgentId, Vec<Grant>>`
2. The index never holds a secret payload or a DEK. It holds metadata only.
3. Each write through `VaultService` updates the DB first, then the index, inside one write lock
   (`tokio::sync::RwLock`). Reads take the read lock.
4. Lock drops the index. `ItemMeta` strings use `Zeroizing<String>`, so drop erases them.
5. Text normalization: Unicode NFKC, lower case, trim, collapse white space. Words split on characters that are not
   letters or digits.
6. Size target: 10,000 items build in less than 1 s on a laptop (benchmark in T06).

## Consequences

- Unlock time grows with the number of items. 10,000 items is the design target.
- Memory holds all metadata while unlocked. Memory attacks are covered in the threat model (accepted risk E-2).
- No search is possible while locked. The API returns 423 anyway (ADR-0008).

## Alternatives considered

- **Blind index (HMAC of words) in SQL.** Rejected. It leaks word frequency and equality, and fuzzy match is hard.
- **Decrypt on each query.** Rejected. Too slow for resolve with scoring.
