-- no-transaction
-- Cerberus vault schema, migration 0002 (DEC-RD-2): the item kind 'rustdesk' (DEC-RD-1).
--
-- SQLite cannot change a CHECK constraint in place, so the items table is rebuilt with the steps of
-- https://www.sqlite.org/lang_altertable.html#otheralter: make the new table, copy every row (rowid
-- included), drop the old table, rename the new one, make the index again. Nothing else changes.
--
-- Foreign keys must be off while the old table is dropped: with them on, DROP TABLE runs an
-- implicit DELETE that would cascade to item_versions, access_requests and leases. PRAGMA
-- foreign_keys has no effect inside a transaction, so this file runs outside the transaction of
-- the migrator (the first line) and opens its own. A failure before COMMIT rolls everything back,
-- user_version included, and the closed connection takes the open transaction with it. The
-- pre-migrate copy of the file is written before any migration runs (ADR-0013). A run on a vault
-- that already has this schema does the same rebuild again, so a crash between COMMIT and the
-- bookkeeping row of the migrator is harmless.
PRAGMA foreign_keys = OFF;
BEGIN IMMEDIATE;

CREATE TABLE items_new (
    id               TEXT    PRIMARY KEY,
    kind             TEXT    NOT NULL CHECK (kind IN ('web_login', 'api_key', 'ssh_key', 'session_token',
                                                      'browser_session', 'database', 'cloud', 'certificate',
                                                      'env_bundle', 'note', 'rustdesk')),
    expires_at       INTEGER,                                  -- NULL = no expiry. Sweeper uses it while locked.
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    current_version  INTEGER NOT NULL CHECK (current_version >= 1),
    meta_ct          BLOB    NOT NULL,
    CHECK (kind NOT IN ('session_token', 'browser_session') OR expires_at IS NOT NULL)
) STRICT;

INSERT INTO items_new (rowid, id, kind, expires_at, created_at, updated_at, current_version, meta_ct)
    SELECT rowid, id, kind, expires_at, created_at, updated_at, current_version, meta_ct FROM items;

DROP TABLE items;
ALTER TABLE items_new RENAME TO items;
CREATE INDEX items_expires_at ON items (expires_at) WHERE expires_at IS NOT NULL;

-- Every row that points at an item must still find it. The CHECK fails the migration otherwise.
CREATE TEMP TABLE migration_0002_fk_check (violations INTEGER NOT NULL CHECK (violations = 0)) STRICT;
INSERT INTO migration_0002_fk_check SELECT count(*) FROM pragma_foreign_key_check;
DROP TABLE migration_0002_fk_check;

PRAGMA user_version = 2;
COMMIT;
PRAGMA foreign_keys = ON;
