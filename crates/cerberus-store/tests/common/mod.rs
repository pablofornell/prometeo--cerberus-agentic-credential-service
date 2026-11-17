//! Shared fixture: a fresh vault in a temp directory, with real keys from `cerberus-crypto`.
//! All secret-looking values are fake markers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
#![allow(dead_code, reason = "each test file uses a part of the fixture")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cerberus_crypto::{KdfParams, KeySlotSet, KeyTree, SecretString, Vmk};
use cerberus_store::{
    AccessRequestRow, AgentKeyRow, AgentRow, AgentStatus, Blobs, HeaderRow, ItemRow,
    ItemVersionRow, KeySlotRow, LeaseRow, LeaseSource, OpenOptions, RowMacs, SlotKind, Store,
    TlsCaRow, header_mac,
};
use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, AgentKeyId, ItemId, ItemKind, KeySlotId,
    LeaseId, ManualClock, Permission, RequestId, Scope, VaultId, t0,
};
use jiff::Timestamp;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub path: PathBuf,
    pub clock: ManualClock,
    pub store: Store,
    pub vault_id: VaultId,
    pub keys: KeyTree,
    pub owner: KeySlotId,
}

/// `t0` plus `secs` seconds.
pub fn at(secs: i64) -> Timestamp {
    Timestamp::from_second(t0().as_second() + secs).unwrap()
}

/// The lowest KDF cost the schema accepts (DEC-050).
pub fn test_params() -> KdfParams {
    KdfParams::new(19_456, 1, 1).unwrap()
}

pub fn slot_rows(set: &KeySlotSet, now: Timestamp) -> Vec<KeySlotRow> {
    set.slots()
        .iter()
        .map(|slot| KeySlotRow {
            id: slot.id,
            kind: if slot.is_recovery() {
                SlotKind::Recovery
            } else {
                SlotKind::Passphrase
            },
            label: "fake-label".to_owned(),
            role: slot.role,
            material: slot.material.clone(),
            created_at: now,
            updated_at: now,
            last_unlock_at: None,
        })
        .collect()
}

impl Fixture {
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join("vault.cerberus");
        let clock = ManualClock::new(t0());
        let store = Store::open(
            OpenOptions {
                path: path.clone(),
                create: true,
            },
            Arc::new(clock.clone()),
        )
        .await
        .unwrap();
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate().unwrap();
        let owner = KeySlotId::generate();
        let phrase = SecretString::new("fake-Phrase-Tq7-vle-9xw-Znb-4Rp".to_owned());
        let set = KeySlotSet::create(vault_id, &vmk, owner, &phrase, test_params()).unwrap();
        let keys = KeyTree::derive(&vmk, &vault_id).unwrap();
        let slots = slot_rows(&set, t0());
        let mut header = HeaderRow {
            format_version: 1,
            vault_id,
            created_at: t0(),
            failed_unlocks: 0,
            last_failed_unlock_at: None,
            header_mac: [0; 32],
        };
        header.header_mac = header_mac(&keys.header_key, &header, &slots);
        let ca = TlsCaRow {
            ca_cert_der: b"fake public certificate".to_vec(),
            ca_key_ct: Blobs::new(&vault_id, &keys)
                .seal_ca_key(b"FAKE-CA-PRIVATE-KEY-MARKER")
                .unwrap(),
            created_at: t0(),
            not_after: at(86_400 * 3650),
        };
        store.initialize(&header, &slots, &ca).await.unwrap();
        Self {
            dir,
            path,
            clock,
            store,
            vault_id,
            keys,
            owner,
        }
    }

    /// The time of the fixture clock.
    pub fn clock_now(&self) -> Timestamp {
        use cerberus_types::Clock;
        self.clock.now()
    }

    pub fn blobs(&self) -> Blobs<'_> {
        Blobs::new(&self.vault_id, &self.keys)
    }

    pub fn macs(&self) -> RowMacs<'_> {
        RowMacs::new(&self.keys.row_mac_key, &self.vault_id)
    }

    /// Opens the same file again with a new store (the old one must be closed or dropped).
    pub async fn reopen(path: &Path, clock: &ManualClock) -> Store {
        Store::open(
            OpenOptions {
                path: path.to_path_buf(),
                create: false,
            },
            Arc::new(clock.clone()),
        )
        .await
        .unwrap()
    }

    /// An item with sealed metadata and payload. `tag` goes into every secret-looking field.
    pub fn item(
        &self,
        kind: ItemKind,
        expires_at: Option<Timestamp>,
        tag: &str,
    ) -> (ItemRow, ItemVersionRow) {
        let id = ItemId::generate();
        let meta = serde_json::json!({
            "workspace_id": "fake-workspace",
            "title": format!("TITLE-{tag}"),
            "description": format!("DESCRIPTION-{tag}"),
            "role_label": format!("ROLE-{tag}"),
            "tags": [format!("TAG-{tag}")],
            "target": format!("https://TARGET-{tag}.example.invalid"),
        })
        .to_string();
        let payload = serde_json::json!({ "password": format!("SECRET-{tag}") }).to_string();
        let blobs = self.blobs();
        let sealed = blobs.seal_payload(&id, 1, payload.as_bytes()).unwrap();
        let item = ItemRow {
            id,
            kind,
            expires_at,
            created_at: t0(),
            updated_at: t0(),
            current_version: 1,
            meta_ct: blobs.seal_item_meta(&id, 1, meta.as_bytes()).unwrap(),
        };
        let version = ItemVersionRow {
            item_id: id,
            version: 1,
            created_at: t0(),
            wrapped_dek: sealed.wrapped_dek,
            payload_ct: sealed.payload_ct,
            meta_ct: blobs.seal_item_snapshot(&id, 1, meta.as_bytes()).unwrap(),
        };
        (item, version)
    }

    pub fn agent(&self, tag: &str) -> AgentRow {
        let id = AgentId::generate();
        let mut row = AgentRow {
            id,
            status: AgentStatus::Active,
            created_at: t0(),
            updated_at: t0(),
            meta_ct: self
                .blobs()
                .seal_agent_meta(&id, format!("AGENT-NAME-{tag}").as_bytes())
                .unwrap(),
            row_mac: [0; 32],
        };
        self.macs().sign_agent(&mut row).unwrap();
        row
    }

    pub fn agent_key(&self, agent: &AgentRow, hash_byte: u8) -> AgentKeyRow {
        let mut row = AgentKeyRow {
            id: AgentKeyId::generate(),
            agent_id: agent.id,
            secret_hash: [hash_byte; 32],
            hint: "abcd".to_owned(),
            scopes: vec![Scope::StatusRead, Scope::SecretsRead],
            ip_allowlist: vec!["10.0.0.0/8".parse().unwrap()],
            require_mtls: false,
            client_cert_sha256: None,
            created_at: t0(),
            expires_at: Some(at(3600)),
            revoked_at: None,
            last_used_at: None,
            row_mac: [0; 32],
        };
        self.macs().sign_agent_key(&mut row).unwrap();
        row
    }

    pub fn lease(&self, agent: &AgentRow, item: &ItemRow, expires: Timestamp) -> LeaseRow {
        let mut row = LeaseRow {
            id: LeaseId::generate(),
            agent_id: agent.id,
            item_id: item.id,
            permission: Permission::Read,
            source: LeaseSource::Auto,
            request_id: None,
            created_at: t0(),
            expires_at: expires,
            max_uses: Some(3),
            uses: 0,
            released_at: None,
            revoked_at: None,
            revoked_by: None,
            row_mac: [0; 32],
        };
        self.macs().sign_lease(&mut row).unwrap();
        row
    }

    pub fn request(
        &self,
        agent: &AgentRow,
        item: &ItemRow,
        status: AccessRequestStatus,
        expires: Timestamp,
        tag: &str,
    ) -> AccessRequestRow {
        let id = AccessRequestId::generate();
        let mut row = AccessRequestRow {
            id,
            agent_id: agent.id,
            item_id: item.id,
            permission: Permission::Read,
            status,
            requested_ttl_seconds: Some(900),
            created_at: t0(),
            expires_at: expires,
            decided_at: None,
            decided_by: None,
            approval_option: None,
            lease_id: None,
            request_id: RequestId::generate(),
            reason_ct: Some(
                self.blobs()
                    .seal_request_reason(&id, format!("REASON-{tag}").as_bytes())
                    .unwrap(),
            ),
            row_mac: [0; 32],
        };
        self.macs().sign_access_request(&mut row).unwrap();
        row
    }
}

/// A raw connection to the vault file, for tests that look at or change rows behind the store.
pub async fn raw(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
        .unwrap()
}

/// True when `needle` appears in the main file or in its `-wal` or `-shm` file.
pub fn file_contains(path: &Path, needle: &str) -> bool {
    ["", "-wal", "-shm"].iter().any(|suffix| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        std::fs::read(PathBuf::from(name))
            .map(|bytes| {
                bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
            .unwrap_or(false)
    })
}
