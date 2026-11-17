//! Test kit for policy, lease and approval tests: a vault in a temp dir, a manual clock, agents,
//! items and grants. All values are fake test values.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use cerberus_crypto::{KdfParams, SecretBytes, SecretString};
use cerberus_store::{AgentRow, AgentStatus, ItemRow, ItemVersionRow, OpenOptions, Store};
use cerberus_types::{
    AgentId, AgentKeyId, Environment, GrantMode, ItemId, ItemKind, ManualClock, OperatorRole,
    Permission, RequestId, VaultId, WorkspaceId, t0,
};
use jiff::{SignedDuration, Timestamp};
use zeroize::Zeroizing;

use super::{Conditions, Grant, GrantInput, PolicyEngine, Selector};
use crate::context::{AgentContext, OperatorContext, Surface};
use crate::error::CoreError;
use crate::index::{CreatedBy, ItemMeta, encode_item_meta};
use crate::vault::{CaIssuer, CoreConfig, IssuedCa, KeyCustody, NewVault, VaultService};

pub const OWNER_PHRASE: &str = "orbit velvet canyon mosaic 7";

#[derive(Debug)]
struct FakeCa;

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

/// What a test item looks like.
#[derive(Clone, Debug)]
pub struct ItemSpec {
    pub workspace_id: WorkspaceId,
    pub kind: ItemKind,
    pub environment: Environment,
    pub category: &'static str,
    pub tags: Vec<&'static str>,
    pub role_label: Option<&'static str>,
    pub expires_at: Option<Timestamp>,
}

impl ItemSpec {
    pub fn new(workspace_id: WorkspaceId, environment: Environment) -> Self {
        Self {
            workspace_id,
            kind: ItemKind::WebLogin,
            environment,
            category: "Web login",
            tags: vec!["shop"],
            role_label: Some("admin"),
            expires_at: None,
        }
    }

    pub fn meta(&self, id: ItemId) -> ItemMeta {
        ItemMeta {
            id,
            kind: self.kind,
            workspace_id: self.workspace_id,
            title: Zeroizing::new(format!("Fake item {id}")),
            description: Zeroizing::new("fake test item".to_owned()),
            role_label: self.role_label.map(|r| Zeroizing::new(r.to_owned())),
            category: Zeroizing::new(self.category.to_owned()),
            tags: self
                .tags
                .iter()
                .map(|t| Zeroizing::new((*t).to_owned()))
                .collect(),
            environment: self.environment,
            target: None,
            created_by: CreatedBy::Operator(cerberus_types::KeySlotId::generate()),
            max_uses: None,
            use_count: 0,
            expires_at: self.expires_at,
            updated_at: t0(),
            has_totp: false,
            custom: std::collections::BTreeMap::new(),
        }
    }
}

pub struct Kit {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub clock: ManualClock,
    pub service: VaultService,
    pub engine: PolicyEngine,
    pub owner: OperatorContext,
    pub workspace: WorkspaceId,
}

pub fn agent_ctx(agent: AgentId) -> AgentContext {
    AgentContext {
        agent_id: agent,
        key_id: AgentKeyId::generate(),
        scopes: BTreeSet::new(),
        request_id: RequestId::generate(),
        source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        surface: Surface::Rest,
    }
}

/// A grant input with the given parts and no conditions.
pub fn input(
    agent: AgentId,
    selector: Selector,
    perms: &[Permission],
    mode: GrantMode,
) -> GrantInput {
    GrantInput {
        id: None,
        agent_id: agent,
        selector,
        permissions: perms.iter().copied().collect(),
        mode,
        conditions: Conditions::default(),
        allow_prod_auto: false,
    }
}

impl Kit {
    pub async fn new() -> Self {
        Self::with_approvals(true).await
    }

    pub async fn with_approvals(approvals: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
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
        let mut config = CoreConfig::desktop(PathBuf::from("."), Arc::new(FakeCa));
        config.approvals_available = approvals;
        let service = VaultService::open(store, Arc::new(clock.clone()), config)
            .await
            .unwrap();
        let created = service
            .create_vault(NewVault {
                owner_label: "Owner".to_owned(),
                phrase: SecretString::new(OWNER_PHRASE.to_owned()),
                kdf: KdfParams::new(19_456, 1, 1).unwrap(),
                host_names: vec!["build-box".to_owned()],
            })
            .await
            .unwrap();
        let owner = OperatorContext {
            operator_id: created.owner_id,
            role: OperatorRole::Owner,
            request_id: RequestId::generate(),
        };
        let engine = PolicyEngine::new(service.clone());
        Self {
            _dir: dir,
            path,
            clock,
            service,
            engine,
            owner,
            workspace: WorkspaceId::generate(),
        }
    }

    pub fn now(&self) -> Timestamp {
        cerberus_types::Clock::now(&self.clock)
    }

    pub fn advance(&self, seconds: i64) {
        self.clock.advance(SignedDuration::from_secs(seconds));
    }

    /// An active agent row (signed).
    pub async fn agent(&self) -> AgentContext {
        let guard = self.service.unlocked().await.unwrap();
        let id = AgentId::generate();
        let mut row = AgentRow {
            id,
            status: AgentStatus::Active,
            created_at: t0(),
            updated_at: t0(),
            meta_ct: guard
                .blobs()
                .seal_agent_meta(&id, br#"{"name":"fake-agent","description":""}"#)
                .unwrap(),
            row_mac: [0; 32],
        };
        guard.row_macs().sign_agent(&mut row).unwrap();
        let mut tx = self.service.store().begin().await.unwrap();
        tx.put_agent(&row).await.unwrap();
        tx.commit().await.unwrap();
        agent_ctx(id)
    }

    /// An item in the DB and in the index.
    pub async fn item(&self, spec: &ItemSpec) -> ItemId {
        let id = ItemId::generate();
        let meta = spec.meta(id);
        {
            let guard = self.service.unlocked().await.unwrap();
            let blobs = guard.blobs();
            let json = encode_item_meta(&meta).unwrap();
            let sealed = blobs
                .seal_payload(&id, 1, b"{\"key\":\"fake-key\"}")
                .unwrap();
            let row = ItemRow {
                id,
                kind: meta.kind,
                expires_at: meta.expires_at,
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
            tx.insert_item(&row, &version).await.unwrap();
            tx.commit().await.unwrap();
        }
        self.service
            .unlocked_mut()
            .await
            .unwrap()
            .index
            .upsert_item(meta);
        id
    }

    pub async fn dev_item(&self) -> ItemId {
        self.item(&ItemSpec::new(self.workspace, Environment::Dev))
            .await
    }

    pub async fn grant(&self, input: GrantInput) -> Grant {
        self.engine.put_grant(&self.owner, input).await.unwrap()
    }

    /// A grant of `perms` in `mode` on everything.
    pub async fn grant_all(&self, agent: AgentId, perms: &[Permission], mode: GrantMode) -> Grant {
        self.grant(input(agent, Selector::default(), perms, mode))
            .await
    }

    /// A raw connection to the file, to change rows behind the store.
    pub async fn raw(&self) -> sqlx::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&self.path))
            .await
            .unwrap()
    }

    /// A read of `item` with no reason and no lease choice.
    pub fn ask(item: ItemId) -> super::SecretAsk<'static> {
        super::SecretAsk {
            item_id: item,
            permission: Permission::Read,
            reason: None,
            lease_id: None,
            requested_ttl_seconds: None,
        }
    }

    pub async fn lock(&self) {
        self.service
            .lock(cerberus_types::LockReason::Manual)
            .await
            .unwrap();
    }

    pub async fn unlock(&self) {
        let ctx = self
            .service
            .unlock_with_phrase(
                self.owner.operator_id,
                SecretString::new(OWNER_PHRASE.to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(ctx.operator_id, self.owner.operator_id);
    }

    /// Event types in the audit chain, in order.
    pub async fn audit_types(&self) -> Vec<String> {
        let guard = self.service.unlocked().await.unwrap();
        let rows = self.service.store().audit_range(1, 100_000).await.unwrap();
        rows.iter()
            .map(|row| {
                let plain = guard
                    .blobs()
                    .open_audit_body(row.seq, &row.body_ct)
                    .unwrap();
                let value: serde_json::Value =
                    serde_json::from_slice(plain.expose_secret()).unwrap();
                value["type"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    /// The decrypted audit bodies as text (to check that no secret is in them).
    pub async fn audit_text(&self) -> String {
        let guard = self.service.unlocked().await.unwrap();
        let rows = self.service.store().audit_range(1, 100_000).await.unwrap();
        rows.iter()
            .map(|row| {
                let plain = guard
                    .blobs()
                    .open_audit_body(row.seq, &row.body_ct)
                    .unwrap();
                String::from_utf8(plain.expose_secret().to_vec()).unwrap()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
