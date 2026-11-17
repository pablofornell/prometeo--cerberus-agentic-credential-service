# ADR-0013: Vault file, header and KDF parameter format

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.1, 4.5 (gap: file and header format)
- Related: ADR-0005, ADR-0009, ADR-0014, ADR-0026, ADR-0031, `docs/schema.sql`

## Context

The plan says "the cost is stored in the header" but does not define the header. The file must be self-describing,
so a backup opens on another machine.

## Decision

### File
1. The vault is one SQLite file: `<app_data_dir>/vault.cerberus`. `app_data_dir` comes from Tauri
   (identifier `app.cerberus.desktop`) or from `cerberusd.toml` (`data_dir`).
2. Pragmas at each open: `application_id = 0x43425256` ("CBRV"), `journal_mode = WAL`, `synchronous = FULL`,
   `secure_delete = ON`, `foreign_keys = ON`, `auto_vacuum = INCREMENTAL` (set at create), `trusted_schema = OFF`.
3. `PRAGMA user_version` holds the schema version (starts at 1). A file with a higher version than the app knows is
   refused with `vault_too_new`. A lower version is migrated after unlock. The app writes a backup copy
   `vault.cerberus.pre-migrate-v<N>` first.
4. File mode `0600` on Unix. The data directory is `0700`.

### Header (table `vault_header`, one row)
| Field | Type | Meaning |
|---|---|---|
| `magic` | TEXT | Always `CERBERUS-VAULT` |
| `format_version` | INTEGER | Crypto format version. Version 1 = this ADR and ADR-0014 |
| `vault_id` | BLOB(16) | Random UUIDv4 bytes. Used in AAD and as HKDF salt |
| `created_at` | INTEGER | Unix ms |
| `failed_unlocks` | INTEGER | Count of failed unlocks since the last success |
| `last_failed_unlock_at` | INTEGER NULL | Unix ms |
| `header_mac` | BLOB(32) | HMAC-SHA256 with `header_key` over the canonical header (below) |

`header_mac` input: length-prefixed (u16 big-endian length + bytes) concatenation of `magic`, `format_version` (u32 BE),
`vault_id`, `created_at` (i64 BE), then for each key slot ordered by `id`: `id`, `kind`, `role`, `kdf_alg`, the KDF
numbers, `salt`, `wrapped_vmk`. The counters are not in the MAC (they change while locked).
After unlock the service checks the MAC. A mismatch puts the UI in a red "header changed" state and writes an audit event.
The vault still opens, because a valid slot proved the phrase.

### Key slot KDF parameters (table `key_slots`)
| Field | Value |
|---|---|
| `kdf_alg` | `argon2id` (phrase slots) or `hkdf-sha256` (recovery slot) |
| `argon2_version` | `19` (0x13) |
| `m_cost_kib`, `t_cost`, `p_cost` | Argon2id costs |
| `salt` | 32 random bytes |
| `wrap_nonce` + `wrapped_vmk` | One envelope (ADR-0014). Plaintext = 32-byte VMK |

Accepted ranges when the app reads a slot: `m_cost_kib` 19456..=4194304, `t_cost` 1..=20, `p_cost` 1..=16.
Values outside the range are refused (`vault_corrupt`). This stops a changed header from causing a denial of service.

### Cost tuning at create and at phrase change
1. Start: `m = 262144` KiB (256 MiB) if total RAM >= 4 GiB, else `65536` KiB. `p = 4`, `t = 3`.
2. Measure one derivation. Change `t` in 1..=10 so the time is near 0.7 s.
3. If `t = 1` still takes more than 1.5 s, halve `m` until the time is below 1.5 s, minimum 65536 KiB.
4. The UI shows the final cost and time (screen 1, "KDF test").

### Phrase rules
- Input is normalized to Unicode NFKC. It is not trimmed.
- Minimum length 12 characters and `zxcvbn` score >= 3. The Diceware generator makes 7 words from the EFF large list
  (about 90 bits).

### Recovery key
- 32 random bytes. KEK = HKDF-SHA256(ikm = recovery key, salt = slot salt, info = `cerberus/v1/recovery-kek`).
  No Argon2: the key has 256 bits of entropy.
- Text form: `CRK1-` + 14 groups of 4 characters, RFC 4648 Base32 alphabet, no padding. The encoded bytes are the
  32-byte key followed by the first 3 bytes of SHA-256(key) as a checksum (35 bytes = 56 characters).
- Parse: upper case, remove spaces and `-`, map `0`→`O`, `1`→`I`, `8`→`B`, check the checksum before the KDF.
  A bad checksum gives "typing error" and does not count as a failed unlock.

## Consequences

- A backup file holds all it needs to open: header, slots and data.
- The failed-unlock counter is plain and not in the MAC. An attacker with the file can reset it. It protects only
  against guessing in the UI. File theft is covered by Argon2id cost (threat model I-1).

## Amendment (2026-11-17, security review)

The range above is the only check at read time and `m = 4 GiB`, `t = 20` still allow a denial of service by an edited
file. Deriving a key now also refuses `m_cost` above half of the total RAM (when known) and `t_cost` above 10, the tuning
maximum, with `InvalidKdfParams`. `KdfParams::new` keeps the machine independent range. See DEC-073.

## Alternatives considered

- **Separate header file next to the DB.** Rejected. Two files can get out of sync in a backup.
- **scrypt or PBKDF2.** Rejected. Argon2id is the current recommendation for password hashing.
