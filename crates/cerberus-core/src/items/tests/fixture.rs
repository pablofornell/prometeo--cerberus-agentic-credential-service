//! A real vault in a temp dir with a manual clock, plus builders for inputs. Fake values only.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use cerberus_crypto::{KdfParams, SecretBytes, SecretString};
use cerberus_store::{OpenOptions, Store, WorkspaceRow};
use cerberus_types::{
    Environment, ItemId, ManualClock, OperatorRole, RequestId, VaultId, WorkspaceId, t0,
};
use jiff::{SignedDuration, Timestamp};
use zeroize::Zeroizing;

use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::{WorkspaceMeta, encode_workspace_meta};
use crate::items::{ItemInput, Payload, TotpSeed};
use crate::vault::{CaIssuer, CoreConfig, IssuedCa, KeyCustody, NewVault, VaultService};

pub const OWNER_PHRASE: &str = "orbit velvet canyon mosaic 7";
pub const VIEWER_PHRASE: &str = "lantern quartz meadow ripple 3";

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

pub fn phrase(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

pub struct Fx {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub clock: ManualClock,
    pub service: VaultService,
    pub ctx: OperatorContext,
    pub ws: WorkspaceId,
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
    VaultService::open(
        store,
        Arc::new(clock.clone()),
        CoreConfig::desktop(PathBuf::from("."), Arc::new(FakeCa)),
    )
    .await
    .unwrap()
}

impl Fx {
    /// A new vault, unlocked by its owner, with the workspace `shop-frontend`.
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let clock = ManualClock::new(t0());
        let service = open_service(&path, &clock).await;
        let created = service
            .create_vault(NewVault {
                owner_label: "Owner".to_owned(),
                phrase: phrase(OWNER_PHRASE),
                kdf: KdfParams::new(19_456, 1, 1).unwrap(),
                host_names: vec!["build-box".to_owned()],
            })
            .await
            .unwrap();
        let ctx = OperatorContext {
            operator_id: created.owner_id,
            role: OperatorRole::Owner,
            request_id: RequestId::generate(),
        };
        let mut fx = Self {
            _dir: dir,
            path,
            clock,
            service,
            ctx,
            ws: WorkspaceId::generate(),
        };
        fx.ws = fx
            .add_workspace("shop-frontend", "Shop Frontend", &["shop"])
            .await;
        fx
    }

    pub fn advance(&self, seconds: i64) {
        self.clock.advance(SignedDuration::from_secs(seconds));
    }

    pub fn now(&self) -> Timestamp {
        cerberus_types::Clock::now(&self.clock)
    }

    /// Writes a workspace row and indexes it (the admin workspace API comes later).
    pub async fn add_workspace(&self, slug: &str, name: &str, aliases: &[&str]) -> WorkspaceId {
        let mut guard = self.service.unlocked_mut().await.unwrap();
        let meta = WorkspaceMeta {
            id: WorkspaceId::generate(),
            slug: Zeroizing::new(slug.to_owned()),
            name: Zeroizing::new(name.to_owned()),
            description: Zeroizing::new(String::new()),
            aliases: aliases
                .iter()
                .map(|a| Zeroizing::new((*a).to_owned()))
                .collect(),
            updated_at: self.now(),
        };
        let json = encode_workspace_meta(&meta).unwrap();
        let row = WorkspaceRow {
            id: meta.id,
            created_at: meta.updated_at,
            updated_at: meta.updated_at,
            meta_ct: guard.blobs().seal_workspace_meta(&meta.id, &json).unwrap(),
        };
        let mut tx = self.service.store().begin().await.unwrap();
        tx.put_workspace(&row).await.unwrap();
        tx.commit().await.unwrap();
        let id = meta.id;
        guard.index.upsert_workspace(meta);
        id
    }

    pub async fn create(&self, input: ItemInput) -> ItemId {
        self.service
            .create_item_as_operator(&self.ctx, input)
            .await
            .unwrap()
            .summary
            .id
    }
}

pub fn secret(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

pub fn login_payload(user: &str, password: &str) -> Payload {
    Payload::WebLogin {
        username: secret(user),
        password: secret(password),
        url: Some("https://shop.example.test/login".to_owned()),
        totp: None,
    }
}

pub fn totp_login_payload(seed_base32: &str) -> Payload {
    Payload::WebLogin {
        username: secret("tester"),
        password: secret("fake-password-1"),
        url: None,
        totp: Some(TotpSeed::standard(secret(seed_base32))),
    }
}

pub fn input(ws: WorkspaceId, title: &str, payload: Payload) -> ItemInput {
    ItemInput {
        workspace_id: ws,
        title: title.to_owned(),
        description: "fake test item".to_owned(),
        role_label: Some("admin".to_owned()),
        category: "Web login".to_owned(),
        tags: vec!["fake".to_owned()],
        environment: Environment::Staging,
        target: Some("https://shop.example.test".to_owned()),
        custom: BTreeMap::new(),
        expires_at: None,
        max_uses: None,
        payload,
    }
}

pub fn session_payload(token: &str) -> Payload {
    Payload::SessionToken {
        token: secret(token),
        token_type: Some("Bearer".to_owned()),
        header_name: None,
    }
}
