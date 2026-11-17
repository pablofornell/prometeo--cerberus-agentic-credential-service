//! End-to-end tests of the Agent API at the core level: the acceptance scenarios A2, A3, A4,
//! A5, A6, A10 and A11 (`docs/PLAN.md` section 11), plus the wiring: lock ends a wait with a
//! terminal event, exposure, `lease.expire` after a restart, integrity events, and no secret in
//! the audit export. Real vault in a temp dir, manual clock, tokens from the token table.
//! Every secret here is a fake test value with the marker `zq-fake`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cerberus_crypto::{KdfParams, SecretBytes, SecretString};
use cerberus_store::{OpenOptions, SettingRow, Store};
use cerberus_types::{
    AccessRequestStatus, AgentId, ApprovalOption, Environment, ErrorCode, GrantMode,
    HANDLING_SECRET, ItemId, ItemKind, LockReason, ManualClock, OperatorRole, Permission,
    RequestId, Scope, VaultId, t0,
};
use jiff::{SignedDuration, Timestamp};

use super::{
    AgentItemInput, AgentSessionInput, CatalogQuery, ResolveResult, RevealInput, RevealOutcome,
    TotpInput, TotpOutcome,
};
use crate::admin::{AuditQuery, WorkspaceInput};
use crate::agents::{AgentInput, AgentKeyInput};
use crate::approvals::CreateAccess;
use crate::auth::TokenCheckInput;
use crate::context::{AgentContext, OperatorContext, Surface};
use crate::error::CoreError;
use crate::items::{ItemInput, ItemSettings, Payload, TotpSeed, generate_ed25519};
use crate::policy::{Conditions, GrantInput, Selector};
use crate::resolve::{ResolveMode, ResolveRequest};
use crate::vault::{CaIssuer, CoreConfig, CoreEvent, IssuedCa, KeyCustody, NewVault, VaultService};

pub(crate) const OWNER_PHRASE: &str = "orbit velvet canyon mosaic 7";
/// Every fake secret value contains this text, so one scan finds a leak.
pub(crate) const MARK: &str = "zq-fake";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

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

fn secret(text: &str) -> SecretString {
    SecretString::new(text.to_owned())
}

pub(crate) fn all_scopes() -> Vec<Scope> {
    vec![
        Scope::StatusRead,
        Scope::CatalogRead,
        Scope::SecretsRead,
        Scope::SecretsWrite,
        Scope::SessionsWrite,
        Scope::Requests,
    ]
}

pub(crate) async fn open_service(
    path: &std::path::Path,
    clock: &ManualClock,
    approvals: bool,
) -> VaultService {
    let store = Store::open(
        OpenOptions {
            path: path.to_path_buf(),
            create: true,
        },
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    let mut config = CoreConfig::desktop(PathBuf::from("."), Arc::new(FakeCa));
    config.approvals_available = approvals;
    VaultService::open(store, Arc::new(clock.clone()), config)
        .await
        .unwrap()
}

pub(crate) struct Fx {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
    pub(crate) clock: ManualClock,
    pub(crate) service: VaultService,
    pub(crate) owner: OperatorContext,
}

impl Fx {
    pub(crate) async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.cerberus");
        let clock = ManualClock::new(t0());
        let service = open_service(&path, &clock, true).await;
        let created = service
            .create_vault(NewVault {
                owner_label: "Owner".to_owned(),
                phrase: secret(OWNER_PHRASE),
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
        Self {
            dir,
            path,
            clock,
            service,
            owner,
        }
    }

    pub(crate) fn now(&self) -> Timestamp {
        cerberus_types::Clock::now(&self.clock)
    }

    pub(crate) fn advance(&self, seconds: i64) {
        self.clock.advance(SignedDuration::from_secs(seconds));
    }

    pub(crate) async fn workspace(&self, slug: &str) -> cerberus_types::WorkspaceId {
        self.service
            .put_workspace(
                &self.owner,
                None,
                WorkspaceInput {
                    slug: slug.to_owned(),
                    name: slug.to_owned(),
                    description: String::new(),
                    aliases: Vec::new(),
                },
            )
            .await
            .unwrap()
            .id
    }

    pub(crate) async fn item(&self, input: ItemInput) -> ItemId {
        self.service
            .create_item_as_operator(&self.owner, input)
            .await
            .unwrap()
            .summary
            .id
    }

    /// A new agent with one key of `scopes`, and the context of a good token check.
    pub(crate) async fn agent(&self, scopes: &[Scope]) -> AgentContext {
        let (_, key) = self
            .service
            .create_agent(
                &self.owner,
                AgentInput {
                    name: "qa-agent".to_owned(),
                    description: String::new(),
                },
                AgentKeyInput {
                    scopes: scopes.to_vec(),
                    lifetime_days: Some(90),
                    ip_allowlist: Vec::new(),
                    require_mtls: false,
                },
            )
            .await
            .unwrap();
        self.check(&key.token).unwrap()
    }

    pub(crate) fn check(
        &self,
        token: &SecretString,
    ) -> Result<AgentContext, crate::auth::AuthFailure> {
        self.service.auth().check(
            &TokenCheckInput {
                raw_token: token.expose_secret(),
                source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                client_cert_sha256: None,
                request_id: RequestId::generate(),
                surface: Surface::Rest,
            },
            self.now(),
        )
    }

    pub(crate) async fn grant(&self, agent: AgentId, perms: &[Permission], mode: GrantMode) {
        self.service
            .put_grant(
                &self.owner,
                GrantInput {
                    id: None,
                    agent_id: agent,
                    selector: Selector::default(),
                    permissions: perms.iter().copied().collect(),
                    mode,
                    conditions: Conditions::default(),
                    allow_prod_auto: false,
                },
            )
            .await
            .unwrap();
    }

    pub(crate) async fn audit_types(&self) -> Vec<String> {
        let mut rows = self
            .service
            .audit_query(
                &self.owner,
                AuditQuery {
                    limit: 1000,
                    ..AuditQuery::default()
                },
            )
            .await
            .unwrap();
        rows.reverse();
        rows.into_iter().map(|e| e.event.event_type).collect()
    }

    pub(crate) async fn lock(&self) {
        self.service.lock(LockReason::Manual).await.unwrap();
    }

    pub(crate) async fn unlock(&self) {
        self.service
            .unlock_with_phrase(self.owner.operator_id, secret(OWNER_PHRASE))
            .await
            .unwrap();
    }
}

pub(crate) fn login(
    ws: cerberus_types::WorkspaceId,
    title: &str,
    env: Environment,
    user: &str,
    password: &str,
) -> ItemInput {
    ItemInput {
        workspace_id: ws,
        title: title.to_owned(),
        description: "fake test item".to_owned(),
        role_label: Some("admin".to_owned()),
        category: "Web login".to_owned(),
        tags: vec!["qa".to_owned()],
        environment: env,
        target: Some("https://shop.example.test".to_owned()),
        custom: BTreeMap::new(),
        expires_at: None,
        max_uses: None,
        payload: Payload::WebLogin {
            username: secret(user),
            password: secret(password),
            url: None,
            totp: None,
        },
    }
}

fn a2_request() -> ResolveRequest {
    ResolveRequest {
        environment: Some("staging".to_owned()),
        role: Some("admin".to_owned()),
        ..ResolveRequest::new("shop-frontend", "run the QA login test")
    }
}

fn reveal_input() -> RevealInput {
    RevealInput {
        purpose: "run the QA login test".to_owned(),
        ..RevealInput::default()
    }
}

fn session_input(token: &str, ttl: Option<u32>) -> AgentSessionInput {
    AgentSessionInput {
        workspace: "shop-frontend".to_owned(),
        title: "QA session".to_owned(),
        description: None,
        environment: Environment::Staging,
        role_label: None,
        target: None,
        ttl_seconds: ttl,
        payload: Payload::SessionToken {
            token: secret(token),
            token_type: Some("Bearer".to_owned()),
            header_name: None,
        },
    }
}

fn secret_of(result: ResolveResult) -> Box<super::SecretResult> {
    match result {
        ResolveResult::Secret(secret) => secret,
        other => panic!("expected a secret, got {other:?}"),
    }
}

fn revealed(outcome: RevealOutcome) -> Box<super::SecretResult> {
    match outcome {
        RevealOutcome::Secret(secret) => secret,
        RevealOutcome::Pending(p) => panic!("expected a secret, got pending {p:?}"),
    }
}

/// A2: resolve app/environment/role gives user and password in one response, with audit events.
#[tokio::test]
async fn a2_resolve_gives_user_and_password_and_audits() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let id = fx
        .item(login(
            ws,
            "Staging admin",
            Environment::Staging,
            "qa-admin",
            "zq-fake-a2-pw",
        ))
        .await;
    fx.item(login(
        ws,
        "Prod admin",
        Environment::Prod,
        "prod-admin",
        "zq-fake-a2-prod",
    ))
    .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();

    let got = secret_of(api.resolve(&agent, a2_request()).await.unwrap());
    assert_eq!(got.handling, HANDLING_SECRET);
    assert_eq!(got.handling, "secret \u{2014} do not print or log");
    assert_eq!(got.item.id, id);
    assert_eq!(got.request_id, agent.request_id);
    let Payload::WebLogin {
        username, password, ..
    } = &got.secret
    else {
        panic!("web login expected");
    };
    assert_eq!(username.expose_secret(), "qa-admin");
    assert_eq!(password.expose_secret(), "zq-fake-a2-pw");
    assert!(!format!("{got:?}").contains(MARK), "Debug shows no secret");
    let types = fx.audit_types().await;
    for wanted in ["lease.create", "lease.use", "item.reveal", "api.resolve"] {
        assert!(types.contains(&wanted.to_owned()), "{wanted} in {types:?}");
    }

    // Candidates mode needs only `catalog:read` and returns metadata.
    let catalog_only = fx.agent(&[Scope::CatalogRead]).await;
    fx.grant(catalog_only.agent_id, &[Permission::Find], GrantMode::Auto)
        .await;
    let list = api
        .resolve(
            &catalog_only,
            ResolveRequest {
                mode: ResolveMode::Candidates,
                ..a2_request()
            },
        )
        .await
        .unwrap();
    assert!(matches!(&list, ResolveResult::Candidates(c) if c.len() == 1 && c[0].item.id == id));
    assert!(matches!(
        api.resolve(&catalog_only, a2_request()).await,
        Err(CoreError::InsufficientScope(Scope::SecretsRead))
    ));
    // The exposure of the item now names the first agent.
    let detail = fx.service.get_item(&fx.owner, id).await.unwrap();
    assert_eq!(
        detail
            .exposed_to
            .iter()
            .map(|(a, _)| *a)
            .collect::<Vec<_>>(),
        vec![agent.agent_id]
    );
}

/// A3: a session with ttl 3600 exists, and after 3600 s it is gone.
#[tokio::test]
async fn a3_session_with_ttl_is_gone_after_the_ttl() {
    let fx = Fx::new().await;
    fx.workspace("shop-frontend").await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(
        agent.agent_id,
        &[Permission::CreateSession, Permission::Read],
        GrantMode::Auto,
    )
    .await;
    let api = fx.service.agent_api();
    let created = api
        .create_session(&agent, session_input("zq-fake-a3-token", Some(3600)))
        .await
        .unwrap();
    let id = created.item.id;
    assert_eq!(created.item.kind, ItemKind::SessionToken);
    assert_eq!(
        created.item.expires_at,
        Some(fx.now() + SignedDuration::from_secs(3600))
    );
    assert!(created.item.created_by.starts_with("agent:"));
    fx.advance(3599);
    let page = api.catalog(&agent, CatalogQuery::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    revealed(api.reveal(&agent, id, reveal_input()).await.unwrap());
    fx.advance(1);
    assert!(
        api.catalog(&agent, CatalogQuery::default())
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert!(matches!(
        api.reveal(&agent, id, reveal_input()).await,
        Err(CoreError::NotFound)
    ));

    // Default TTL is 3600 s; a TTL above `session_ttl_max_seconds` is refused.
    let default = api
        .create_session(
            &agent,
            AgentSessionInput {
                title: "Default TTL".to_owned(),
                ..session_input("zq-fake-a3-b", None)
            },
        )
        .await
        .unwrap();
    assert_eq!(
        default.item.expires_at,
        Some(fx.now() + SignedDuration::from_secs(3600))
    );
    let max = ItemSettings::default().session_ttl_max_seconds;
    assert!(matches!(
        api.create_session(
            &agent,
            AgentSessionInput {
                title: "Too long".to_owned(),
                ..session_input("zq-fake-a3-c", Some(max + 1))
            }
        )
        .await,
        Err(CoreError::Validation(_))
    ));
    // A non-session payload is refused on this route.
    let mut wrong = session_input("x", None);
    wrong.payload = Payload::Note {
        text: secret("zq-fake-note"),
    };
    assert!(matches!(
        api.create_session(&agent, wrong).await,
        Err(CoreError::Validation(_))
    ));
}

/// A4: the SSH key of machine `build-01` is resolvable.
#[tokio::test]
async fn a4_ssh_key_of_a_machine_is_resolvable() {
    let fx = Fx::new().await;
    let ws = fx.workspace("infra").await;
    let mut custom = BTreeMap::new();
    custom.insert("machine".to_owned(), "build-01".to_owned());
    custom.insert("user".to_owned(), "ci".to_owned());
    let id = fx
        .item(ItemInput {
            workspace_id: ws,
            title: "Build machine key".to_owned(),
            description: "fake test key".to_owned(),
            role_label: None,
            category: "SSH key".to_owned(),
            tags: Vec::new(),
            environment: Environment::Dev,
            target: Some("build-01".to_owned()),
            custom,
            expires_at: None,
            max_uses: None,
            payload: generate_ed25519("fake-build-01").unwrap(),
        })
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let got = secret_of(
        fx.service
            .agent_api()
            .resolve(
                &agent,
                ResolveRequest {
                    kind: Some(ItemKind::SshKey),
                    ..ResolveRequest::new("build-01", "deploy the build")
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(got.item.id, id);
    assert!(matches!(&got.secret, Payload::SshKey { private_key, .. }
        if private_key.expose_secret().contains("OPENSSH PRIVATE KEY")));
    let ssh = got.ssh.as_ref().unwrap();
    assert_eq!(ssh.machine.as_deref(), Some("build-01"));
    assert_eq!(ssh.user.as_deref(), Some("ci"));
}

/// A5: while sealed, every Agent API call gives `Locked` and no data; the calls are audited.
#[tokio::test]
async fn a5_sealed_vault_refuses_every_call() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let id = fx
        .item(login(
            ws,
            "Staging admin",
            Environment::Staging,
            "u",
            "zq-fake-a5",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(
        agent.agent_id,
        &[Permission::Read, Permission::Write],
        GrantMode::Auto,
    )
    .await;
    fx.lock().await;
    let api = fx.service.agent_api();
    let request = cerberus_types::AccessRequestId::generate();
    let lease = cerberus_types::LeaseId::generate();
    let locked = |r: &Result<(), CoreError>| matches!(r, Err(CoreError::Locked));
    let results: Vec<Result<(), CoreError>> = vec![
        api.status(&agent).await.map(|_| ()),
        api.resolve(&agent, a2_request()).await.map(|_| ()),
        api.catalog(&agent, CatalogQuery::default())
            .await
            .map(|_| ()),
        api.reveal(&agent, id, reveal_input()).await.map(|_| ()),
        api.totp(
            &agent,
            id,
            TotpInput {
                purpose: "login".to_owned(),
                lease_id: None,
            },
        )
        .await
        .map(|_| ()),
        api.create_item(
            &agent,
            AgentItemInput {
                workspace: "shop-frontend".to_owned(),
                title: "x".to_owned(),
                description: None,
                environment: Environment::Dev,
                role_label: None,
                category: None,
                tags: Vec::new(),
                target: None,
                custom: BTreeMap::new(),
                ttl_seconds: None,
                max_uses: None,
                payload: Payload::Note {
                    text: secret("zq-fake-a5-note"),
                },
            },
        )
        .await
        .map(|_| ()),
        api.create_session(&agent, session_input("zq-fake-a5-s", None))
            .await
            .map(|_| ()),
        api.delete_item(&agent, id).await,
        api.request_access(
            &agent,
            CreateAccess {
                item_id: id,
                permission: Permission::Read,
                reason: "need it for the test".to_owned(),
                ttl_seconds: None,
            },
        )
        .await
        .map(|_| ()),
        api.get_access_request(&agent, request).await.map(|_| ()),
        api.wait_access_request(&agent, request, Duration::from_secs(1))
            .await
            .map(|_| ()),
        api.release_lease(&agent, lease).await.map(|_| ()),
    ];
    assert_eq!(results.len(), 12);
    for (n, result) in results.iter().enumerate() {
        assert!(locked(result), "call {n}: {result:?}");
        assert_eq!(
            result.as_ref().err().map(CoreError::code),
            Some(ErrorCode::VaultLocked)
        );
    }
    fx.unlock().await;
    let locked_calls = fx
        .audit_types()
        .await
        .iter()
        .filter(|t| *t == "api.locked_call")
        .count();
    assert_eq!(
        locked_calls, 12,
        "each refused call is in the chain after unlock"
    );
}

/// A6: a prod item needs approval. Deny gives `approval_denied` (403); approve gives a lease and
/// the secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a6_prod_needs_approval_deny_and_approve() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let denied_item = fx
        .item(login(
            ws,
            "Prod admin",
            Environment::Prod,
            "u",
            "zq-fake-a6-a",
        ))
        .await;
    let approved_item = fx
        .item(login(
            ws,
            "Prod billing",
            Environment::Prod,
            "u",
            "zq-fake-a6-b",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    // Even an `auto` grant gives `ask_always` on prod without `allow_prod_auto` (ADR-0017).
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();

    let RevealOutcome::Pending(pending) = api
        .reveal(&agent, denied_item, reveal_input())
        .await
        .unwrap()
    else {
        panic!("prod must need approval");
    };
    assert_eq!(pending.access_request.status, AccessRequestStatus::Pending);
    fx.service
        .deny_request(&fx.owner, pending.access_request.id)
        .await
        .unwrap();
    let after = api
        .get_access_request(&agent, pending.access_request.id)
        .await
        .unwrap();
    assert_eq!(after.status, AccessRequestStatus::Denied);
    let again = api.reveal(&agent, denied_item, reveal_input()).await;
    assert!(
        matches!(again, Err(CoreError::ApprovalDenied(Some(_)))),
        "{again:?}"
    );
    let code = again.err().map(|e| e.code());
    assert_eq!(code, Some(ErrorCode::ApprovalDenied));
    assert_eq!(code.map(ErrorCode::http_status), Some(403));

    let RevealOutcome::Pending(pending) = api
        .reveal(&agent, approved_item, reveal_input())
        .await
        .unwrap()
    else {
        panic!("prod must need approval");
    };
    let id = pending.access_request.id;
    let waiter = {
        let api = api.clone();
        let ctx = agent.clone();
        tokio::spawn(async move {
            api.wait_access_request(&ctx, id, Duration::from_secs(30))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let lease = fx
        .service
        .approve_request(&fx.owner, id, ApprovalOption::Once)
        .await
        .unwrap();
    let decided = waiter.await.unwrap().unwrap();
    assert_eq!(decided.status, AccessRequestStatus::Approved);
    assert_eq!(decided.lease.as_ref().map(|l| l.id), Some(lease.id));
    let got = revealed(
        api.reveal(&agent, approved_item, reveal_input())
            .await
            .unwrap(),
    );
    assert_eq!(got.lease.id, lease.id);
    assert!(matches!(&got.secret, Payload::WebLogin { password, .. }
        if password.expose_secret() == "zq-fake-a6-b"));
    // "Approve once": the next read needs a new approval.
    assert!(matches!(
        api.reveal(&agent, approved_item, reveal_input())
            .await
            .unwrap(),
        RevealOutcome::Pending(_)
    ));
}

/// A10: after a key is revoked, the next token check fails at once.
#[tokio::test]
async fn a10_revoked_key_fails_the_next_check() {
    let fx = Fx::new().await;
    let (_, key) = fx
        .service
        .create_agent(
            &fx.owner,
            AgentInput {
                name: "short-lived".to_owned(),
                description: String::new(),
            },
            AgentKeyInput {
                scopes: all_scopes(),
                lifetime_days: Some(30),
                ip_allowlist: Vec::new(),
                require_mtls: false,
            },
        )
        .await
        .unwrap();
    let ctx = fx.check(&key.token).unwrap();
    let status = fx.service.agent_api().status(&ctx).await.unwrap();
    assert_eq!(status.agent.name, "short-lived");
    assert_eq!(status.agent.key_id, key.key.id);
    assert!(status.agent.key_expires_at.is_some());
    fx.service
        .revoke_agent_key(&fx.owner, key.key.id)
        .await
        .unwrap();
    let failure = fx.check(&key.token).unwrap_err();
    assert_eq!(failure, crate::auth::AuthFailure::KeyRevoked);
}

/// A11: an agent without the `write` permission cannot store a secret (403); without the scope
/// it gets `insufficient_scope`.
#[tokio::test]
async fn a11_store_without_write_is_forbidden() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let human_item = fx
        .item(login(
            ws,
            "Human made",
            Environment::Dev,
            "u",
            "zq-fake-a11-h",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();
    let note = |title: &str| AgentItemInput {
        workspace: "shop-frontend".to_owned(),
        title: title.to_owned(),
        description: None,
        environment: Environment::Dev,
        role_label: None,
        category: None,
        tags: Vec::new(),
        target: None,
        custom: BTreeMap::new(),
        ttl_seconds: None,
        max_uses: None,
        payload: Payload::Note {
            text: secret("zq-fake-a11-note"),
        },
    };
    let refused = api.create_item(&agent, note("Agent note")).await;
    assert!(matches!(refused, Err(CoreError::Forbidden)), "{refused:?}");
    assert_eq!(refused.err().map(|e| e.code().http_status()), Some(403));
    let rows = fx
        .service
        .audit_query(
            &fx.owner,
            AuditQuery {
                event_type: Some("item.create".to_owned()),
                agent_id: Some(agent.agent_id),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event.result, "forbidden");

    let no_scope = fx.agent(&[Scope::SecretsRead]).await;
    fx.grant(no_scope.agent_id, &[Permission::Write], GrantMode::Auto)
        .await;
    assert!(matches!(
        api.create_item(&no_scope, note("No scope")).await,
        Err(CoreError::InsufficientScope(Scope::SecretsWrite))
    ));

    // With `write` the agent can create, then delete its own item but not others'.
    fx.grant(agent.agent_id, &[Permission::Write], GrantMode::Auto)
        .await;
    let created = api.create_item(&agent, note("Agent note")).await.unwrap();
    assert_eq!(created.item.category, "Note");
    assert!(matches!(
        api.delete_item(&agent, human_item).await,
        Err(CoreError::Forbidden)
    ));
    let stranger = fx.agent(&all_scopes()).await;
    assert!(
        matches!(
            api.delete_item(&stranger, human_item).await,
            Err(CoreError::NotFound)
        ),
        "an item the agent cannot see is not found"
    );
    api.delete_item(&agent, created.item.id).await.unwrap();
    assert!(matches!(
        api.delete_item(&agent, created.item.id).await,
        Err(CoreError::NotFound)
    ));
}

/// TOTP through the Agent API: a code with the handling marker; the seed never leaves.
#[tokio::test]
async fn totp_gives_a_code_and_never_the_seed() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let mut input = login(ws, "With TOTP", Environment::Dev, "u", "zq-fake-totp-pw");
    input.payload = Payload::WebLogin {
        username: secret("u"),
        password: secret("zq-fake-totp-pw"),
        url: None,
        totp: Some(TotpSeed::standard(secret(TOTP_SEED))),
    };
    let id = fx.item(input).await;
    let plain = fx
        .item(login(ws, "No TOTP", Environment::Dev, "u", "zq-fake-plain"))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();
    let TotpOutcome::Code(code) = api
        .totp(
            &agent,
            id,
            TotpInput {
                purpose: "log in".to_owned(),
                lease_id: None,
            },
        )
        .await
        .unwrap()
    else {
        panic!("code expected");
    };
    assert_eq!(code.handling, HANDLING_SECRET);
    assert_eq!(code.code.expose_secret().len(), 6);
    assert!((1..=30).contains(&code.expires_in_seconds));
    assert!(matches!(
        api.totp(
            &agent,
            plain,
            TotpInput {
                purpose: "log in".to_owned(),
                lease_id: None,
            }
        )
        .await,
        Err(CoreError::NotFound)
    ));
    let got = revealed(api.reveal(&agent, id, reveal_input()).await.unwrap());
    assert!(
        matches!(got.secret, Payload::WebLogin { totp: None, .. }),
        "seed is stripped"
    );
    assert!(fx.audit_types().await.contains(&"item.totp".to_owned()));
}

/// A lock cancels a request that an agent waits on and sends a terminal event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_ends_a_wait_with_a_terminal_event() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let id = fx
        .item(login(
            ws,
            "Prod admin",
            Environment::Prod,
            "u",
            "zq-fake-lock",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::AskOnce)
        .await;
    let api = fx.service.agent_api();
    let view = api
        .request_access(
            &agent,
            CreateAccess {
                item_id: id,
                permission: Permission::Read,
                reason: "need it for the release".to_owned(),
                ttl_seconds: None,
            },
        )
        .await
        .unwrap();
    let mut events = fx.service.subscribe();
    let waiter = {
        let api = api.clone();
        let ctx = agent.clone();
        let id = view.id;
        tokio::spawn(async move {
            api.wait_access_request(&ctx, id, Duration::from_secs(60))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(Duration::from_secs(5), fx.lock())
        .await
        .expect("a waiting agent must not block the lock");
    let ended = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(ended.status, AccessRequestStatus::Cancelled);
    let mut saw = false;
    while let Ok(event) = events.try_recv() {
        if let CoreEvent::AccessRequestResolved { id, status } = event
            && id == view.id
        {
            assert_eq!(status, AccessRequestStatus::Cancelled);
            saw = true;
        }
    }
    assert!(
        saw,
        "AccessRequestResolved was sent for the cancelled request"
    );
}

/// `lease.expire` is written for a lease that ended while the process was down, once.
#[tokio::test]
async fn lease_expire_is_written_after_a_restart() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let id = fx
        .item(login(ws, "Dev admin", Environment::Dev, "u", "zq-fake-exp"))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    revealed(
        fx.service
            .agent_api()
            .reveal(&agent, id, reveal_input())
            .await
            .unwrap(),
    );
    fx.lock().await;
    // The process stops; the auto lease (900 s) ends while it is down.
    fx.advance(2000);
    let count = |types: &[String]| types.iter().filter(|t| *t == "lease.expire").count();
    for round in 0..2 {
        let again = open_service(&fx.path, &fx.clock, true).await;
        again
            .unlock_with_phrase(fx.owner.operator_id, secret(OWNER_PHRASE))
            .await
            .unwrap();
        let report = again.policy().expire_due(fx.now()).await.unwrap();
        assert_eq!(report.leases_expired, 0, "the unlock already wrote it");
        let owner = OperatorContext {
            request_id: RequestId::generate(),
            ..fx.owner.clone()
        };
        let rows = again
            .audit_query(
                &owner,
                AuditQuery {
                    event_type: Some("lease.expire".to_owned()),
                    limit: 100,
                    ..AuditQuery::default()
                },
            )
            .await
            .unwrap();
        let types: Vec<String> = rows.into_iter().map(|r| r.event.event_type).collect();
        assert_eq!(count(&types), 1, "round {round}: exactly one lease.expire");
        again.lock(LockReason::Manual).await.unwrap();
    }
}

/// `spawn_background` also starts the approval and lease expiry loop.
#[tokio::test]
async fn background_includes_the_expiry_loop() {
    let fx = Fx::new().await;
    let handles = fx.service.spawn_background();
    assert_eq!(handles.len(), 4);
    for handle in handles {
        handle.abort();
    }
}

/// A sealed item or policy setting that does not open writes `integrity.row_mac_mismatch`.
#[tokio::test]
async fn bad_setting_rows_write_integrity_events() {
    let fx = Fx::new().await;
    fx.workspace("shop-frontend").await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(
        agent.agent_id,
        &[Permission::CreateSession, Permission::Read],
        GrantMode::Auto,
    )
    .await;
    let mut tx = fx.service.store().begin().await.unwrap();
    for key in [
        crate::items::setting_keys::SESSION_TTL_MAX_SECONDS,
        crate::policy::POLICY_SETTINGS_KEY,
    ] {
        tx.put_setting(&SettingRow {
            key: key.to_owned(),
            updated_at: fx.now(),
            value_ct: b"not a sealed value".to_vec(),
        })
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    // Unlock again so the policy settings cache is reloaded.
    fx.lock().await;
    fx.unlock().await;
    let api = fx.service.agent_api();
    let created = api
        .create_session(&agent, session_input("zq-fake-int", None))
        .await
        .unwrap();
    revealed(
        api.reveal(&agent, created.item.id, reveal_input())
            .await
            .unwrap(),
    );
    let rows = fx
        .service
        .audit_query(
            &fx.owner,
            AuditQuery {
                event_type: Some("integrity.row_mac_mismatch".to_owned()),
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    let ids: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r.event.target.as_ref().map(|t| t.id.clone()))
        .collect();
    assert!(ids.contains("session_ttl_max_seconds"), "{ids:?}");
    assert!(ids.contains("policy_settings"), "{ids:?}");
}

/// After the acceptance flows, the audit export holds no fake secret value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_export_holds_no_secret_value() {
    let fx = Fx::new().await;
    let ws = fx.workspace("shop-frontend").await;
    let staging = fx
        .item(login(
            ws,
            "Staging admin",
            Environment::Staging,
            "zq-fake-user",
            "zq-fake-pw",
        ))
        .await;
    let prod = fx
        .item(login(
            ws,
            "Prod admin",
            Environment::Prod,
            "zq-fake-user2",
            "zq-fake-pw2",
        ))
        .await;
    let agent = fx.agent(&all_scopes()).await;
    fx.grant(
        agent.agent_id,
        &[
            Permission::Read,
            Permission::Write,
            Permission::CreateSession,
        ],
        GrantMode::Auto,
    )
    .await;
    let api = fx.service.agent_api();
    secret_of(api.resolve(&agent, a2_request()).await.unwrap());
    revealed(api.reveal(&agent, staging, reveal_input()).await.unwrap());
    let RevealOutcome::Pending(p) = api.reveal(&agent, prod, reveal_input()).await.unwrap() else {
        panic!("prod needs approval");
    };
    fx.service
        .approve_request(&fx.owner, p.access_request.id, ApprovalOption::Minutes15)
        .await
        .unwrap();
    revealed(api.reveal(&agent, prod, reveal_input()).await.unwrap());
    api.create_session(&agent, session_input("zq-fake-session", None))
        .await
        .unwrap();
    fx.service.reveal_item(&fx.owner, staging).await.unwrap();
    let dest = fx.dir.path().join("audit.jsonl");
    let lines = fx.service.audit_export(&fx.owner, &dest).await.unwrap();
    let text = std::fs::read_to_string(&dest).unwrap();
    assert_eq!(u64::try_from(text.lines().count()).unwrap(), lines);
    assert!(text.contains("item.reveal"));
    assert!(!text.contains(MARK), "no secret value in the audit export");
    // The database file holds no plain secret either.
    let raw = std::fs::read(&fx.path).unwrap();
    assert!(
        !raw.windows(MARK.len()).any(|w| w == MARK.as_bytes()),
        "no plain secret in the vault file"
    );
}
