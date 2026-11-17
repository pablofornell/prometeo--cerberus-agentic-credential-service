//! Test fixture: a vault file in a temp dir, a manual clock and a fake CA.

use std::path::PathBuf;
use std::sync::Arc;

use cerberus_crypto::{KdfParams, SecretBytes, SecretString};
use cerberus_store::{
    AccessRequestRow, AgentRow, AgentStatus, ItemRow, ItemVersionRow, LeaseRow, LeaseSource,
    OpenOptions, Store,
};
use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, Environment, ItemId, ItemKind, LeaseId,
    ManualClock, OperatorRole, Permission, RequestId, VaultId, WorkspaceId, t0,
};
use jiff::{SignedDuration, Timestamp};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use zeroize::Zeroizing;

use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::{CreatedBy, ItemMeta, encode_item_meta};
use crate::vault::{
    CaIssuer, CoreConfig, CreatedVault, IssuedCa, KeyCustody, NewVault, VaultService,
};

pub const OWNER_PHRASE: &str = "orbit velvet canyon mosaic 7";
pub const SECOND_PHRASE: &str = "lantern quartz meadow ripple 3";
pub const NEW_PHRASE: &str = "harbor tundra nickel saffron 9";
pub const WRONG_PHRASE: &str = "pebble frozen lizard comet 4";

pub fn phrase(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

/// The fast floor cost that the schema accepts (DEC-050).
pub fn kdf() -> KdfParams {
    KdfParams::new(19_456, 1, 1).unwrap()
}

#[derive(Debug)]
pub struct FakeCa;

impl CaIssuer for FakeCa {
    fn issue_ca(&self, _vault_id: &VaultId, now: Timestamp) -> Result<IssuedCa, CoreError> {
        Ok(IssuedCa {
            cert_der: b"fake-ca-cert".to_vec(),
            key_der: SecretBytes::new(b"fake-ca-key".to_vec()),
            not_after: now + SignedDuration::from_hours(24 * 3650),
            pin: "sha256/fake-pin".to_owned(),
        })
    }
}

pub struct Fixture {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub clock: ManualClock,
    pub service: VaultService,
}

pub fn config() -> CoreConfig {
    CoreConfig::desktop(PathBuf::from("."), Arc::new(FakeCa))
}

impl Fixture {
    pub async fn empty() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let clock = ManualClock::new(t0());
        let service = open_service(&path, &clock).await;
        Self {
            _dir: dir,
            path,
            clock,
            service,
        }
    }

    /// A new vault, unlocked by its owner.
    pub async fn created() -> (Self, CreatedVault, OperatorContext) {
        let fixture = Self::empty().await;
        let created = fixture
            .service
            .create_vault(NewVault {
                owner_label: "Owner".to_owned(),
                phrase: phrase(OWNER_PHRASE),
                kdf: kdf(),
                host_names: vec!["build-box".to_owned()],
            })
            .await
            .unwrap();
        let ctx = OperatorContext {
            operator_id: created.owner_id,
            role: OperatorRole::Owner,
            request_id: RequestId::generate(),
        };
        (fixture, created, ctx)
    }

    /// A second service on the same file, as after a restart.
    pub async fn reopen(&self) -> VaultService {
        open_service(&self.path, &self.clock).await
    }

    pub fn clock_now(&self) -> Timestamp {
        cerberus_types::Clock::now(&self.clock)
    }

    pub fn advance(&self, seconds: i64) {
        self.clock.advance(SignedDuration::from_secs(seconds));
    }

    /// Writes an item (sealed metadata and payload) behind the index, as a later task will.
    pub async fn add_item(&self, title: &str) -> ItemId {
        let guard = self.service.unlocked().await.unwrap();
        let blobs = guard.blobs();
        let id = ItemId::generate();
        let meta = ItemMeta {
            id,
            kind: ItemKind::ApiKey,
            workspace_id: WorkspaceId::generate(),
            title: Zeroizing::new(title.to_owned()),
            description: Zeroizing::new("fake test item".to_owned()),
            role_label: None,
            category: Zeroizing::new("API key".to_owned()),
            tags: vec![Zeroizing::new("fake".to_owned())],
            environment: Environment::Dev,
            target: None,
            created_by: CreatedBy::Operator(guard.session.operator_id),
            max_uses: None,
            use_count: 0,
            expires_at: None,
            updated_at: t0(),
            has_totp: false,
            custom: std::collections::BTreeMap::new(),
        };
        let json = encode_item_meta(&meta).unwrap();
        let sealed = blobs
            .seal_payload(&id, 1, b"{\"key\":\"fake-key\"}")
            .unwrap();
        let item = ItemRow {
            id,
            kind: meta.kind,
            expires_at: None,
            created_at: t0(),
            updated_at: t0(),
            current_version: 1,
            meta_ct: blobs.seal_item_meta(&id, 1, &json).unwrap(),
        };
        let version = ItemVersionRow {
            item_id: id,
            version: 1,
            created_at: t0(),
            wrapped_dek: sealed.wrapped_dek,
            payload_ct: sealed.payload_ct,
            meta_ct: blobs.seal_item_snapshot(&id, 1, &json).unwrap(),
        };
        let mut tx = self.service.store().begin().await.unwrap();
        tx.insert_item(&item, &version).await.unwrap();
        tx.commit().await.unwrap();
        id
    }

    /// An agent with one active lease and one pending request on `item`.
    pub async fn add_lease_and_request(&self, item: ItemId) -> (LeaseId, AccessRequestId) {
        let guard = self.service.unlocked().await.unwrap();
        let macs = guard.row_macs();
        let blobs = guard.blobs();
        let agent_id = AgentId::generate();
        let mut agent = AgentRow {
            id: agent_id,
            status: AgentStatus::Active,
            created_at: t0(),
            updated_at: t0(),
            meta_ct: blobs.seal_agent_meta(&agent_id, b"{}").unwrap(),
            row_mac: [0; 32],
        };
        macs.sign_agent(&mut agent).unwrap();
        let mut lease = LeaseRow {
            id: LeaseId::generate(),
            agent_id,
            item_id: item,
            permission: Permission::Read,
            source: LeaseSource::Auto,
            request_id: None,
            created_at: t0(),
            expires_at: t0() + SignedDuration::from_hours(1),
            max_uses: None,
            uses: 0,
            released_at: None,
            revoked_at: None,
            revoked_by: None,
            row_mac: [0; 32],
        };
        macs.sign_lease(&mut lease).unwrap();
        let mut request = AccessRequestRow {
            id: AccessRequestId::generate(),
            agent_id,
            item_id: item,
            permission: Permission::Read,
            status: AccessRequestStatus::Pending,
            requested_ttl_seconds: Some(900),
            created_at: t0(),
            expires_at: t0() + SignedDuration::from_mins(2),
            decided_at: None,
            decided_by: None,
            approval_option: None,
            lease_id: None,
            request_id: RequestId::generate(),
            reason_ct: None,
            row_mac: [0; 32],
        };
        macs.sign_access_request(&mut request).unwrap();
        let mut tx = self.service.store().begin().await.unwrap();
        tx.put_agent(&agent).await.unwrap();
        tx.put_lease(&lease).await.unwrap();
        tx.put_access_request(&request).await.unwrap();
        tx.commit().await.unwrap();
        (lease.id, request.id)
    }

    /// A raw connection to the file, to change rows behind the store.
    pub async fn raw(&self) -> SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::new().filename(&self.path))
            .await
            .unwrap()
    }
}

pub async fn open_service(path: &std::path::Path, clock: &ManualClock) -> VaultService {
    let store = Store::open(
        OpenOptions {
            path: path.to_path_buf(),
            create: true,
        },
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    VaultService::open(store, Arc::new(clock.clone()), config())
        .await
        .unwrap()
}

/// A context for `operator` that the Tauri layer would build after an unlock.
pub fn ctx_for(operator: cerberus_types::OperatorId, role: OperatorRole) -> OperatorContext {
    OperatorContext {
        operator_id: operator,
        role,
        request_id: RequestId::generate(),
    }
}
