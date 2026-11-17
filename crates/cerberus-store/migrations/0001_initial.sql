-- Cerberus vault schema, migration 0001 (T04). Derived from docs/schema.sql.
--
-- Rules (ADR-0005, ADR-0013, ADR-0014, ADR-0033):
--   * Columns named *_ct are encrypted envelopes (ADR-0014). All other columns are plain: IDs, kinds,
--     states, counters, hashes, timestamps and KDF numbers. Never a title, name, reason or secret.
--   * Columns named row_mac are HMAC-SHA256 over the security-relevant plain columns of the row (ADR-0033).
--   * Times are INTEGER Unix milliseconds, UTC. IDs are lower-case hyphenated UUID TEXT.
--
-- Pragmas set at every open live in Rust (`Store::open`). `auto_vacuum = INCREMENTAL` is set there too,
-- before the first table exists. The two pragmas below are stored in the file header.
PRAGMA application_id = 1128419926; -- 0x43425256, "CBRV"
PRAGMA user_version = 1;

------------------------------------------------------------------------------------------------------------------
-- Vault header (exactly one row). Plain: needed before unlock.
------------------------------------------------------------------------------------------------------------------
CREATE TABLE vault_header (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    magic                  TEXT    NOT NULL CHECK (magic = 'CERBERUS-VAULT'),
    format_version         INTEGER NOT NULL CHECK (format_version = 1),
    vault_id               BLOB    NOT NULL CHECK (length(vault_id) = 16),   -- UUIDv4 bytes; AAD + HKDF salt
    created_at             INTEGER NOT NULL,
    failed_unlocks         INTEGER NOT NULL DEFAULT 0,                       -- not in header_mac (changes while locked)
    last_failed_unlock_at  INTEGER,
    header_mac             BLOB    NOT NULL CHECK (length(header_mac) = 32)  -- HMAC-SHA256(header_key, canonical header)
) STRICT;

------------------------------------------------------------------------------------------------------------------
-- Key slots. One per operator (kind 'passphrase') plus at most one 'recovery' slot.
-- The operator ID is the key slot ID of a passphrase slot (ADR-0009).
-- Plain: KDF parameters, label and role are needed before unlock.
-- `label` is the operator display label shown on the unlock screen (accepted leak, threat model I-3).
------------------------------------------------------------------------------------------------------------------
CREATE TABLE key_slots (
    id              TEXT    PRIMARY KEY,
    kind            TEXT    NOT NULL CHECK (kind IN ('passphrase', 'recovery')),
    label           TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
    role            TEXT    NOT NULL CHECK (role IN ('owner', 'operator', 'viewer')),
    kdf_alg         TEXT    NOT NULL CHECK (kdf_alg IN ('argon2id', 'hkdf-sha256')),
    argon2_version  INTEGER CHECK (argon2_version IS NULL OR argon2_version = 19),
    m_cost_kib      INTEGER CHECK (m_cost_kib IS NULL OR m_cost_kib BETWEEN 19456 AND 4194304),
    t_cost          INTEGER CHECK (t_cost IS NULL OR t_cost BETWEEN 1 AND 20),
    p_cost          INTEGER CHECK (p_cost IS NULL OR p_cost BETWEEN 1 AND 16),
    salt            BLOB    NOT NULL CHECK (length(salt) = 32),
    -- Envelope of the 32-byte VMK, sealed with the slot KEK. Purpose 'slot.vmk', record id = slot id.
    wrapped_vmk     BLOB    NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    last_unlock_at  INTEGER,
    CHECK ((kind = 'passphrase' AND kdf_alg = 'argon2id'
            AND argon2_version IS NOT NULL AND m_cost_kib IS NOT NULL AND t_cost IS NOT NULL AND p_cost IS NOT NULL)
        OR (kind = 'recovery' AND kdf_alg = 'hkdf-sha256' AND role = 'owner'))
) STRICT;
CREATE UNIQUE INDEX key_slots_one_recovery ON key_slots (kind) WHERE kind = 'recovery';

------------------------------------------------------------------------------------------------------------------
-- Settings. One row per setting key. The key name is plain (for example 'idle_lock_seconds');
-- the value is encrypted (purpose 'settings.value', record id = key name).
-- Exception: settings needed while locked are in the daemon/desktop config file, not here
-- (bind address, port).
------------------------------------------------------------------------------------------------------------------
CREATE TABLE settings (
    key         TEXT    PRIMARY KEY,
    updated_at  INTEGER NOT NULL,
    value_ct    BLOB    NOT NULL
) STRICT;

------------------------------------------------------------------------------------------------------------------
-- Local CA (one row). The CA certificate is public (plain DER). The CA private key is sealed with ca_key
-- (purpose 'ca.key'). The TLS leaf key is NOT in the DB (ADR-0023).
------------------------------------------------------------------------------------------------------------------
CREATE TABLE tls_ca (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    ca_cert_der  BLOB    NOT NULL,
    ca_key_ct    BLOB    NOT NULL,
    created_at   INTEGER NOT NULL,
    not_after    INTEGER NOT NULL
) STRICT;

------------------------------------------------------------------------------------------------------------------
-- Workspaces (tenants / applications).
-- Encrypted meta_ct (purpose 'workspace.meta'): slug, name, description, aliases[].
------------------------------------------------------------------------------------------------------------------
CREATE TABLE workspaces (
    id          TEXT    PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    meta_ct     BLOB    NOT NULL
) STRICT;

------------------------------------------------------------------------------------------------------------------
-- Items. Plain columns ONLY: id, kind, expiry, timestamps, current version number.
-- Encrypted meta_ct (purpose 'item.meta', version = current_version):
--   workspace_id, title, description, role_label, category, tags[], environment, target,
--   created_by, max_uses, use_count, custom{}, and a copy of expires_at.
-- Effective expiry = the earlier of the plain expires_at and the encrypted copy (ADR-0033).
-- The workspace link is inside meta_ct on purpose (ADR-0005), so there is no foreign key to workspaces.
------------------------------------------------------------------------------------------------------------------
CREATE TABLE items (
    id               TEXT    PRIMARY KEY,
    kind             TEXT    NOT NULL CHECK (kind IN ('web_login', 'api_key', 'ssh_key', 'session_token',
                                                      'browser_session', 'database', 'cloud', 'certificate',
                                                      'env_bundle', 'note')),
    expires_at       INTEGER,                                  -- NULL = no expiry. Sweeper uses it while locked.
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    current_version  INTEGER NOT NULL CHECK (current_version >= 1),
    meta_ct          BLOB    NOT NULL,
    CHECK (kind NOT IN ('session_token', 'browser_session') OR expires_at IS NOT NULL)
) STRICT;
CREATE INDEX items_expires_at ON items (expires_at) WHERE expires_at IS NOT NULL;

------------------------------------------------------------------------------------------------------------------
-- Item versions. One row per version; the current one is items.current_version.
--   wrapped_dek : the 32-byte DEK of this version, sealed with item_kek (purpose 'item.dek').
--   payload_ct  : typed secret payload, sealed with this DEK (purpose 'item.payload').
--   meta_ct     : metadata snapshot of this version, sealed with meta_key (purpose 'item.meta_snapshot').
-- AAD version = `version`, so a ciphertext copied into another version fails to open.
------------------------------------------------------------------------------------------------------------------
CREATE TABLE item_versions (
    item_id      TEXT    NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    version      INTEGER NOT NULL CHECK (version >= 1),
    created_at   INTEGER NOT NULL,
    wrapped_dek  BLOB    NOT NULL,
    payload_ct   BLOB    NOT NULL,
    meta_ct      BLOB    NOT NULL,
    PRIMARY KEY (item_id, version)
) STRICT, WITHOUT ROWID;

------------------------------------------------------------------------------------------------------------------
-- Agents. `status` is plain because token checks run while locked (ADR-0016).
-- Encrypted meta_ct (purpose 'agent.meta'): name, description, created_by operator, notes.
------------------------------------------------------------------------------------------------------------------
CREATE TABLE agents (
    id          TEXT    PRIMARY KEY,
    status      TEXT    NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    meta_ct     BLOB    NOT NULL,
    row_mac     BLOB    NOT NULL CHECK (length(row_mac) = 32)      -- over id, status, created_at
) STRICT;

------------------------------------------------------------------------------------------------------------------
-- Agent keys (tokens). All plain: they must work while locked.
-- secret_hash = SHA-256("cerberus/v1/agent-token" || agent_id bytes || secret bytes). The token is never stored.
-- scopes       : space-separated list from ADR-0016 (for example 'status:read catalog:read secrets:read requests').
-- ip_allowlist : space-separated CIDR list; empty string = any address.
------------------------------------------------------------------------------------------------------------------
CREATE TABLE agent_keys (
    id                  TEXT    PRIMARY KEY,
    agent_id            TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    secret_hash         BLOB    NOT NULL UNIQUE CHECK (length(secret_hash) = 32),
    hint                TEXT    NOT NULL CHECK (length(hint) = 4),
    scopes              TEXT    NOT NULL,
    ip_allowlist        TEXT    NOT NULL DEFAULT '',
    require_mtls        INTEGER NOT NULL DEFAULT 0 CHECK (require_mtls IN (0, 1)),
    client_cert_sha256  BLOB    CHECK (client_cert_sha256 IS NULL OR length(client_cert_sha256) = 32),
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER,                                -- NULL = no expiry (owner only)
    revoked_at          INTEGER,
    last_used_at        INTEGER,                                -- not in row_mac (changes on every call)
    row_mac             BLOB    NOT NULL CHECK (length(row_mac) = 32),
    CHECK (require_mtls = 0 OR client_cert_sha256 IS NOT NULL)
) STRICT;
CREATE INDEX agent_keys_agent ON agent_keys (agent_id) WHERE revoked_at IS NULL;

------------------------------------------------------------------------------------------------------------------
-- Grants. Plain: id, agent, expiry, timestamps.
-- Encrypted body_ct (purpose 'grant.body'): selector{}, permissions[], mode, conditions{}, allow_prod_auto,
-- created_by operator, and a copy of expires_at (effective = the earlier value, ADR-0033). Selectors hold workspace IDs, tags and role labels, which are metadata (ADR-0005).
------------------------------------------------------------------------------------------------------------------
CREATE TABLE grants (
    id          TEXT    PRIMARY KEY,
    agent_id    TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    body_ct     BLOB    NOT NULL
) STRICT;
CREATE INDEX grants_agent ON grants (agent_id);

------------------------------------------------------------------------------------------------------------------
-- Access requests (approval queue, ADR-0018). Plain: IDs, state, numbers, times.
-- Encrypted reason_ct (purpose 'request.reason'): the untrusted reason text from the agent (max 500 chars).
------------------------------------------------------------------------------------------------------------------
CREATE TABLE access_requests (
    id                     TEXT    PRIMARY KEY,
    agent_id               TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    item_id                TEXT    NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    permission             TEXT    NOT NULL CHECK (permission IN ('read', 'use_ssh')),
    status                 TEXT    NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled')),
    requested_ttl_seconds  INTEGER CHECK (requested_ttl_seconds IS NULL OR requested_ttl_seconds BETWEEN 60 AND 86400),
    created_at             INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    decided_at             INTEGER,
    decided_by             TEXT,                                                   -- operator ID; no FK, the row MAC covers it
    approval_option        TEXT    CHECK (approval_option IS NULL OR approval_option IN ('once', 'minutes_15', 'session')),
    lease_id               TEXT,                                                   -- set when approved
    request_id             TEXT    NOT NULL,                                       -- HTTP/MCP request ID that created it
    reason_ct              BLOB,
    row_mac                BLOB    NOT NULL CHECK (length(row_mac) = 32)           -- all columns except reason_ct
) STRICT;
CREATE INDEX access_requests_pending ON access_requests (agent_id, item_id, permission) WHERE status = 'pending';
CREATE INDEX access_requests_denied ON access_requests (agent_id, item_id, decided_at) WHERE status = 'denied';

------------------------------------------------------------------------------------------------------------------
-- Leases (ADR-0019). All plain: IDs, counters and times only.
-- Accepted leak: links agent ID -> item ID (threat model I-3).
------------------------------------------------------------------------------------------------------------------
CREATE TABLE leases (
    id           TEXT    PRIMARY KEY,
    agent_id     TEXT    NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    item_id      TEXT    NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    permission   TEXT    NOT NULL CHECK (permission IN ('read', 'use_ssh')),
    source       TEXT    NOT NULL CHECK (source IN ('auto', 'approval')),
    request_id   TEXT,                                                           -- access request, when source = approval; no FK, the row MAC covers it
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    max_uses     INTEGER CHECK (max_uses IS NULL OR max_uses >= 1),
    uses         INTEGER NOT NULL DEFAULT 0,
    released_at  INTEGER,
    revoked_at   INTEGER,
    revoked_by   TEXT,                                                           -- 'operator:<id>' or 'panic'
    row_mac      BLOB    NOT NULL CHECK (length(row_mac) = 32)                   -- all other columns
) STRICT;
CREATE INDEX leases_active ON leases (agent_id, item_id, permission, expires_at)
    WHERE released_at IS NULL AND revoked_at IS NULL;
CREATE INDEX leases_expires ON leases (expires_at);

------------------------------------------------------------------------------------------------------------------
-- Audit log (ADR-0025). Append-only. Plain: seq, time, chain hashes. Encrypted body_ct (purpose 'audit.body',
-- record id = seq as u64 big-endian): type, actor, target, result, request_id, details (never a secret value).
-- Triggers stop UPDATE and DELETE except by the prune path, which first sets the guard row in audit_prune_guard.
------------------------------------------------------------------------------------------------------------------
CREATE TABLE audit_events (
    seq          INTEGER PRIMARY KEY,                      -- 1, 2, 3, ... no gaps (AUTOINCREMENT not needed: never reused)
    occurred_at  INTEGER NOT NULL,
    prev_hash    BLOB    NOT NULL CHECK (length(prev_hash) = 32),
    hmac         BLOB    NOT NULL CHECK (length(hmac) = 32),
    body_ct      BLOB    NOT NULL
) STRICT;

CREATE TABLE audit_head (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq          INTEGER NOT NULL,
    last_entry_hash   BLOB    NOT NULL CHECK (length(last_entry_hash) = 32),
    anchor_seq        INTEGER NOT NULL,                     -- first kept row after prune
    anchor_prev_hash  BLOB    NOT NULL CHECK (length(anchor_prev_hash) = 32),
    head_hmac         BLOB    NOT NULL CHECK (length(head_hmac) = 32)   -- HMAC(audit_key, the four values above)
) STRICT;

CREATE TABLE audit_prune_guard (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    active  INTEGER NOT NULL CHECK (active IN (0, 1))
) STRICT;
INSERT INTO audit_prune_guard (id, active) VALUES (1, 0);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
WHEN (SELECT active FROM audit_prune_guard WHERE id = 1) = 0
BEGIN
    SELECT RAISE(ABORT, 'audit_events delete only through prune');
END;

-- Events that happen while locked (no audit_key). Folded into the chain at the next unlock, then deleted.
-- Plain on purpose: only IDs, codes and route templates. Never titles, reasons or secrets.
CREATE TABLE audit_pending (
    id           INTEGER PRIMARY KEY,
    occurred_at  INTEGER NOT NULL,
    event_type   TEXT    NOT NULL,                          -- for example 'api.locked_call', 'auth.failed', 'item.expire'
    agent_id     TEXT,
    target_id    TEXT,                                      -- item ID for 'item.expire'
    result_code  TEXT    NOT NULL,                          -- 'ok' or an error code (ADR-0021)
    route        TEXT,                                      -- route template, for example '/v1/credentials/{id}/reveal'
    request_id   TEXT
) STRICT;

CREATE TABLE audit_pending_overflow (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    count  INTEGER NOT NULL DEFAULT 0
) STRICT;
INSERT INTO audit_pending_overflow (id, count) VALUES (1, 0);
