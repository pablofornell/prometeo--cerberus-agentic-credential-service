#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use cerberus_crypto::{KeyTree, Vmk};
use cerberus_store::OpenOptions;
use cerberus_types::ids::RequestId;
use cerberus_types::{ManualClock, VaultId, t0};

use super::*;
use crate::Surface;
use crate::auth::{AuthFailure, AuthLimits, TokenCheckInput};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    clock: ManualClock,
    vault_id: VaultId,
    keys: KeyTree,
    auth: AuthTable,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = ManualClock::new(t0());
        let store = Store::open(
            OpenOptions {
                path: dir.path().join("data").join("vault.cerberus"),
                create: true,
            },
            Arc::new(clock.clone()),
        )
        .await
        .unwrap();
        let vault_id = VaultId::generate();
        let keys = KeyTree::derive(&Vmk::generate().unwrap(), &vault_id).unwrap();
        Self {
            _dir: dir,
            store,
            clock,
            vault_id,
            keys,
            auth: AuthTable::new(AuthLimits::default()),
        }
    }

    /// The service as the vault builds it for a session with `role`.
    fn as_role(&self, role: OperatorRole) -> AgentService<'_> {
        AgentService::new(
            &self.store,
            &self.auth,
            Blobs::new(&self.vault_id, &self.keys),
            RowMacs::new(&self.keys.row_mac_key, &self.vault_id),
            &self.clock,
            role,
        )
    }

    fn check(&self, token: &SecretString) -> Result<crate::AgentContext, AuthFailure> {
        self.auth.check(
            &TokenCheckInput {
                raw_token: token.expose_secret(),
                source_ip: LOCAL,
                client_cert_sha256: None,
                request_id: RequestId::generate(),
                surface: Surface::Rest,
            },
            self.clock.now(),
        )
    }

    fn advance(&self, secs: i64) {
        self.clock.advance(SignedDuration::from_secs(secs));
    }
}

/// The session role the vault passes in. The caller's context is checked by the vault, not here.
const fn ctx(role: OperatorRole) -> OperatorRole {
    role
}

fn input(name: &str) -> AgentInput {
    AgentInput {
        name: name.to_owned(),
        description: "fake description".to_owned(),
    }
}

fn key_input() -> AgentKeyInput {
    AgentKeyInput {
        scopes: Vec::new(),
        lifetime_days: Some(90),
        ip_allowlist: Vec::new(),
        require_mtls: false,
    }
}

#[tokio::test]
async fn create_agent_shows_token_once_and_stores_only_the_hash() {
    let fx = Fixture::new().await;
    let owner = ctx(OperatorRole::Owner);
    let (agent, new_key) = fx
        .as_role(owner)
        .create_agent(input("  QA agent "), key_input())
        .await
        .unwrap();
    assert_eq!(agent.name, "QA agent");
    assert_eq!(agent.status, AgentStatus::Active);
    assert_eq!(agent.keys.len(), 1);
    assert_eq!(new_key.key.scopes, DEFAULT_SCOPES.to_vec().tap_sorted());
    assert_eq!(
        new_key.key.expires_at,
        Some(
            t0().checked_add(SignedDuration::from_secs(90 * 86_400))
                .unwrap()
        )
    );
    let token = new_key.token.expose_secret();
    assert!(token.starts_with(&format!("cvt_{}.", agent.id)));
    assert!(token.ends_with(&new_key.key.hint));

    // The token works, and the DB holds neither the token nor the secret part.
    assert_eq!(fx.check(&new_key.token).unwrap().agent_id, agent.id);
    let (_, rows) = fx.store.load_auth_rows().await.unwrap();
    let secret_part = token.split_once('.').unwrap().1;
    assert!(!rows.iter().any(|r| r.hint == secret_part));
    assert_eq!(rows[0].secret_hash.len(), 32);
    let listed = fx.as_role(owner).list_agents().await.unwrap();
    assert_eq!(listed, vec![agent]);
}

trait TapSorted {
    fn tap_sorted(self) -> Self;
}

impl TapSorted for Vec<Scope> {
    fn tap_sorted(mut self) -> Self {
        self.sort();
        self
    }
}

#[tokio::test]
async fn roles_are_checked() {
    let fx = Fixture::new().await;
    let viewer = ctx(OperatorRole::Viewer);
    let operator = ctx(OperatorRole::Operator);
    assert!(matches!(
        fx.as_role(viewer)
            .create_agent(input("a"), key_input())
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    // No expiry needs the owner.
    let mut forever = key_input();
    forever.lifetime_days = None;
    assert!(matches!(
        fx.as_role(operator)
            .create_agent(input("a"), forever.clone())
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    let owner = ctx(OperatorRole::Owner);
    let (agent, key) = fx
        .as_role(owner)
        .create_agent(input("a"), forever)
        .await
        .unwrap();
    assert_eq!(key.key.expires_at, None);
    assert!(fx.as_role(viewer).list_agents().await.is_ok());
    assert!(matches!(
        fx.as_role(viewer)
            .set_agent_status(agent.id, AgentStatus::Suspended)
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    assert!(matches!(
        fx.as_role(viewer).revoke_agent_key(key.key.id).await,
        Err(CoreError::RoleNotAllowed)
    ));
}

#[tokio::test]
async fn input_is_validated() {
    let fx = Fixture::new().await;
    let owner = ctx(OperatorRole::Owner);
    for bad in ["", "   ", &"x".repeat(81), "tab\there"] {
        assert!(
            matches!(
                fx.as_role(owner)
                    .create_agent(input(bad), key_input())
                    .await,
                Err(CoreError::Validation(_))
            ),
            "{bad:?}"
        );
    }
    for days in [0, 366] {
        let mut key = key_input();
        key.lifetime_days = Some(days);
        assert!(matches!(
            fx.as_role(owner).create_agent(input("ok"), key).await,
            Err(CoreError::Validation(_))
        ));
    }
    let mut key = key_input();
    key.ip_allowlist = vec!["10.0.0.0/8".parse().unwrap(); 33];
    assert!(matches!(
        fx.as_role(owner).create_agent(input("ok"), key).await,
        Err(CoreError::Validation(_))
    ));
    assert!(fx.as_role(owner).list_agents().await.unwrap().is_empty());
}

#[tokio::test]
async fn rename_keeps_keys_and_working_tokens() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, key) = fx
        .as_role(op)
        .create_agent(input("old"), key_input())
        .await
        .unwrap();
    let renamed = fx
        .as_role(op)
        .update_agent(agent.id, input("new"))
        .await
        .unwrap();
    assert_eq!(renamed.name, "new");
    assert_eq!(renamed.keys.len(), 1);
    assert!(fx.check(&key.token).is_ok());
}

#[tokio::test]
async fn suspend_and_resume_take_effect_at_once() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, key) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let view = fx
        .as_role(op)
        .set_agent_status(agent.id, AgentStatus::Suspended)
        .await
        .unwrap();
    assert_eq!(view.status, AgentStatus::Suspended);
    assert_eq!(
        fx.check(&key.token).unwrap_err(),
        AuthFailure::AgentInactive
    );
    fx.as_role(op)
        .set_agent_status(agent.id, AgentStatus::Active)
        .await
        .unwrap();
    assert!(fx.check(&key.token).is_ok());
}

#[tokio::test]
async fn delete_revokes_all_keys_and_is_final() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, first) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let second = fx
        .as_role(op)
        .create_agent_key(agent.id, key_input())
        .await
        .unwrap();
    fx.as_role(op)
        .set_agent_status(agent.id, AgentStatus::Revoked)
        .await
        .unwrap();
    assert!(fx.check(&first.token).is_err());
    assert!(fx.check(&second.token).is_err());
    let listed = fx.as_role(op).list_agents().await.unwrap();
    assert_eq!(listed[0].status, AgentStatus::Revoked);
    assert!(listed[0].keys.iter().all(|k| k.revoked_at.is_some()));
    assert!(matches!(
        fx.as_role(op)
            .set_agent_status(agent.id, AgentStatus::Active)
            .await,
        Err(CoreError::Conflict)
    ));
    assert!(matches!(
        fx.as_role(op).create_agent_key(agent.id, key_input()).await,
        Err(CoreError::Conflict)
    ));
    assert!(matches!(
        fx.as_role(op).update_agent(agent.id, input("b")).await,
        Err(CoreError::Conflict)
    ));
}

#[tokio::test]
async fn revoke_key_is_effective_before_the_call_returns() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, first) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let second = fx
        .as_role(op)
        .create_agent_key(agent.id, key_input())
        .await
        .unwrap();
    assert!(fx.check(&first.token).is_ok());
    fx.as_role(op).revoke_agent_key(first.key.id).await.unwrap();
    assert_eq!(fx.check(&first.token).unwrap_err(), AuthFailure::KeyRevoked);
    assert!(fx.check(&second.token).is_ok());
    // Revoking twice is harmless and keeps the first time.
    let revoked_at = fx.as_role(op).list_agents().await.unwrap()[0]
        .keys
        .iter()
        .find(|k| k.id == first.key.id)
        .unwrap()
        .revoked_at;
    fx.advance(10);
    fx.as_role(op).revoke_agent_key(first.key.id).await.unwrap();
    let again = fx.as_role(op).list_agents().await.unwrap()[0]
        .keys
        .iter()
        .find(|k| k.id == first.key.id)
        .unwrap()
        .revoked_at;
    assert_eq!(revoked_at, again);
    assert!(matches!(
        fx.as_role(op)
            .revoke_agent_key(cerberus_types::ids::AgentKeyId::generate())
            .await,
        Err(CoreError::NotFound)
    ));
}

#[tokio::test]
async fn at_most_five_live_keys() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, first) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    for _ in 0..4 {
        fx.as_role(op)
            .create_agent_key(agent.id, key_input())
            .await
            .unwrap();
    }
    assert!(matches!(
        fx.as_role(op).create_agent_key(agent.id, key_input()).await,
        Err(CoreError::Conflict)
    ));
    assert!(matches!(
        fx.as_role(op)
            .rotate_agent_key(first.key.id, Duration::from_secs(60))
            .await,
        Err(CoreError::Conflict)
    ));
    fx.as_role(op).revoke_agent_key(first.key.id).await.unwrap();
    assert!(
        fx.as_role(op)
            .create_agent_key(agent.id, key_input())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn rotation_overlap_old_key_works_until_the_overlap_ends() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (_, old) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let new = fx
        .as_role(op)
        .rotate_agent_key(old.key.id, Duration::from_secs(3600))
        .await
        .unwrap();
    assert_ne!(new.key.id, old.key.id);
    assert_eq!(new.key.scopes, old.key.scopes);
    // The new key lives as long as the old one was meant to live.
    assert_eq!(
        new.key.expires_at,
        Some(
            t0().checked_add(SignedDuration::from_secs(90 * 86_400))
                .unwrap()
        )
    );
    assert!(fx.check(&old.token).is_ok());
    assert!(fx.check(&new.token).is_ok());
    fx.advance(3599);
    assert!(fx.check(&old.token).is_ok());
    fx.advance(1);
    assert_eq!(fx.check(&old.token).unwrap_err(), AuthFailure::KeyExpired);
    assert!(fx.check(&new.token).is_ok());
    // An old key that is no longer live cannot be rotated.
    assert!(matches!(
        fx.as_role(op)
            .rotate_agent_key(old.key.id, Duration::ZERO)
            .await,
        Err(CoreError::Conflict)
    ));
}

#[tokio::test]
async fn rotation_with_zero_overlap_ends_the_old_key_now() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (_, old) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let new = fx
        .as_role(op)
        .rotate_agent_key(old.key.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(fx.check(&old.token).unwrap_err(), AuthFailure::KeyExpired);
    assert!(fx.check(&new.token).is_ok());
    assert!(matches!(
        fx.as_role(op)
            .rotate_agent_key(new.key.id, Duration::from_secs(8 * 86_400))
            .await,
        Err(CoreError::Validation(_))
    ));
}

#[tokio::test]
async fn rotation_never_extends_a_short_old_expiry() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let mut short = key_input();
    short.lifetime_days = Some(1);
    let (_, old) = fx
        .as_role(op)
        .create_agent(input("a"), short)
        .await
        .unwrap();
    fx.as_role(op)
        .rotate_agent_key(old.key.id, MAX_OVERLAP)
        .await
        .unwrap();
    fx.advance(86_400);
    assert_eq!(fx.check(&old.token).unwrap_err(), AuthFailure::KeyExpired);
}

#[tokio::test]
async fn rotating_a_key_without_expiry_needs_the_owner() {
    let fx = Fixture::new().await;
    let owner = ctx(OperatorRole::Owner);
    let mut forever = key_input();
    forever.lifetime_days = None;
    let (_, old) = fx
        .as_role(owner)
        .create_agent(input("a"), forever)
        .await
        .unwrap();
    assert!(matches!(
        fx.as_role(ctx(OperatorRole::Operator))
            .rotate_agent_key(old.key.id, Duration::ZERO)
            .await,
        Err(CoreError::RoleNotAllowed)
    ));
    let new = fx
        .as_role(owner)
        .rotate_agent_key(old.key.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(new.key.expires_at, None);
}

#[tokio::test]
async fn key_settings_scopes_allowlist_and_mtls() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, _) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let new = fx
        .as_role(op)
        .create_agent_key(
            agent.id,
            AgentKeyInput {
                scopes: vec![Scope::SshUse, Scope::StatusRead, Scope::SshUse],
                lifetime_days: Some(7),
                ip_allowlist: vec!["10.0.0.0/8".parse().unwrap()],
                require_mtls: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(new.key.scopes, vec![Scope::StatusRead, Scope::SshUse]);
    assert_eq!(fx.check(&new.token).unwrap_err(), AuthFailure::IpNotAllowed);

    let inside = |cert| TokenCheckInput {
        raw_token: new.token.expose_secret(),
        source_ip: "10.1.1.1".parse().unwrap(),
        client_cert_sha256: cert,
        request_id: RequestId::generate(),
        surface: Surface::Mcp,
    };
    let now = fx.clock.now();
    assert!(fx.auth.check(&inside(None), now).is_ok());
    let view = fx
        .as_role(op)
        .bind_client_cert(new.key.id, [5; 32])
        .await
        .unwrap();
    assert!(view.require_mtls);
    let ctx_ok = fx.auth.check(&inside(Some([5; 32])), now).unwrap();
    assert_eq!(ctx_ok.surface, Surface::Mcp);
    assert!(ctx_ok.scopes.contains(&Scope::SshUse));
    assert_eq!(
        fx.auth.check(&inside(None), now).unwrap_err(),
        AuthFailure::MtlsMismatch
    );
    assert_eq!(
        fx.auth.check(&inside(Some([6; 32])), now).unwrap_err(),
        AuthFailure::MtlsMismatch
    );
    // A new key cannot ask for mTLS before it has a certificate.
    let mut early = key_input();
    early.require_mtls = true;
    assert!(matches!(
        fx.as_role(op).create_agent_key(agent.id, early).await,
        Err(CoreError::Validation(_))
    ));
    // Rotation keeps the binding.
    let rotated = fx
        .as_role(op)
        .rotate_agent_key(new.key.id, Duration::ZERO)
        .await
        .unwrap();
    assert!(rotated.key.require_mtls);
}

#[tokio::test]
async fn table_rebuilt_from_the_store_matches_and_catches_tampering() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    let (agent, good) = fx
        .as_role(op)
        .create_agent(input("a"), key_input())
        .await
        .unwrap();
    let second = fx
        .as_role(op)
        .create_agent_key(agent.id, key_input())
        .await
        .unwrap();
    let macs = RowMacs::new(&fx.keys.row_mac_key, &fx.vault_id);

    // Unlock: rebuild a fresh table from the DB with MAC checks.
    let fresh = AuthTable::new(AuthLimits::default());
    let (agents, keys) = fx.store.load_auth_rows().await.unwrap();
    assert!(
        fresh
            .rebuild(&agents, &keys, Some(&macs), fx.clock.now())
            .unwrap()
            .is_empty()
    );
    let probe = |token: &SecretString| {
        fresh.check(
            &TokenCheckInput {
                raw_token: token.expose_secret(),
                source_ip: LOCAL,
                client_cert_sha256: None,
                request_id: RequestId::generate(),
                surface: Surface::Rest,
            },
            fx.clock.now(),
        )
    };
    assert!(probe(&good.token).is_ok());
    assert!(probe(&second.token).is_ok());

    // File tampering: a key row gets more scopes without a new MAC.
    let mut forged = keys.iter().find(|k| k.id == second.key.id).unwrap().clone();
    forged.scopes.push(Scope::SecretsWrite);
    let mut tx = fx.store.begin().await.unwrap();
    tx.put_agent_key(&forged).await.unwrap();
    tx.commit().await.unwrap();
    let (agents, keys) = fx.store.load_auth_rows().await.unwrap();
    let issues = fresh
        .rebuild(&agents, &keys, Some(&macs), fx.clock.now())
        .unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].row_id, second.key.id.to_string());
    assert_eq!(probe(&second.token).unwrap_err(), AuthFailure::KeyRevoked);
    assert!(probe(&good.token).is_ok());

    // The list shows it revoked, and a change of that row is refused instead of re-signing it.
    let listed = fx.as_role(op).list_agents().await.unwrap();
    let shown = listed[0]
        .keys
        .iter()
        .find(|k| k.id == second.key.id)
        .unwrap();
    assert!(shown.revoked_at.is_some());
    assert!(matches!(
        fx.as_role(op).revoke_agent_key(second.key.id).await,
        Err(CoreError::Corrupt)
    ));
}

#[tokio::test]
async fn agent_names_are_not_in_the_db_file() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    fx.as_role(op)
        .create_agent(input("DISTINCTIVE-AGENT-NAME-MARKER"), key_input())
        .await
        .unwrap();
    let (agents, _) = fx.store.load_auth_rows().await.unwrap();
    let marker = b"DISTINCTIVE-AGENT-NAME-MARKER";
    assert!(!agents[0].meta_ct.windows(marker.len()).any(|w| w == marker));
}

/// Finding 2: a revoke racing a rotate of the same key must stay revoked (no stale row wins).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_racing_rotate_stays_revoked() {
    let fx = Fixture::new().await;
    let owner = ctx(OperatorRole::Owner);
    for _ in 0..40 {
        let (_view, first) = fx
            .as_role(owner)
            .create_agent(input("racer"), key_input())
            .await
            .unwrap();
        let key = first.key.id;
        let svc = fx.as_role(owner);
        let (rot, rev) = tokio::join!(
            svc.rotate_agent_key(key, Duration::from_secs(7 * 86_400)),
            svc.revoke_agent_key(key),
        );
        rev.unwrap();
        assert!(
            fx.check(&first.token).is_err(),
            "revoked key works now (rotate {rot:?})"
        );
        let (agents, keys) = fx.store.load_auth_rows().await.unwrap();
        let row = keys.iter().find(|k| k.id == key).unwrap();
        assert!(row.revoked_at.is_some(), "revoke undone in the DB");
        let macs = RowMacs::new(&fx.keys.row_mac_key, &fx.vault_id);
        let issues = fx
            .auth
            .rebuild(&agents, &keys, Some(&macs), fx.clock.now())
            .unwrap();
        assert!(issues.is_empty());
        assert!(fx.check(&first.token).is_err(), "revoke undone at rebuild");
    }
}

/// Finding 3: a rename racing a suspend must not write the old status back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_racing_suspend_keeps_the_suspend() {
    let fx = Fixture::new().await;
    let op = ctx(OperatorRole::Operator);
    for _ in 0..40 {
        let (view, first) = fx
            .as_role(op)
            .create_agent(input("victim"), key_input())
            .await
            .unwrap();
        let svc = fx.as_role(op);
        let (s, r) = tokio::join!(
            svc.set_agent_status(view.id, AgentStatus::Suspended),
            svc.update_agent(view.id, input("victim (renamed)")),
        );
        s.unwrap();
        r.unwrap();
        assert!(fx.check(&first.token).is_err(), "suspend effective now");
        let (agents, keys) = fx.store.load_auth_rows().await.unwrap();
        let row = agents.iter().find(|a| a.id == view.id).unwrap();
        assert_eq!(
            row.status,
            AgentStatus::Suspended,
            "suspend undone in the DB"
        );
        let macs = RowMacs::new(&fx.keys.row_mac_key, &fx.vault_id);
        fx.auth
            .rebuild(&agents, &keys, Some(&macs), fx.clock.now())
            .unwrap();
        assert!(fx.check(&first.token).is_err(), "suspend undone at rebuild");
    }
}
