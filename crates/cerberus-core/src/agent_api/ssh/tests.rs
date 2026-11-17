//! Tests of the SSH signing path (T22): prepare, sign, the checks at each sign, the ticket end,
//! and no private key material in any result or audit export. Keys are made at run time.

use std::collections::BTreeMap;

use cerberus_types::{
    ApprovalOption, Environment, GrantMode, ItemId, Permission, Scope, WorkspaceId,
};
use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature, SshSig};

use super::{SignData, SshGrant, SshPrepareInput, SshPrepareOutcome, sign_data_kind};
use crate::agent_api::tests::{Fx, MARK, all_scopes};
use crate::context::AgentContext;
use crate::error::CoreError;
use crate::items::{ItemInput, Payload, generate_ed25519, import_private_key};
use crate::vault::KeyCustody;

fn ssh_scopes() -> Vec<Scope> {
    let mut scopes = all_scopes();
    scopes.push(Scope::SshUse);
    scopes
}

fn ssh_item(ws: WorkspaceId, payload: Payload, env: Environment) -> ItemInput {
    let mut custom = BTreeMap::new();
    custom.insert("machine".to_owned(), "build-01".to_owned());
    custom.insert("host".to_owned(), "127.0.0.1".to_owned());
    custom.insert("port".to_owned(), "2222".to_owned());
    custom.insert("user".to_owned(), "ci".to_owned());
    ItemInput {
        workspace_id: ws,
        title: "Build machine key".to_owned(),
        description: "fake test key".to_owned(),
        role_label: None,
        category: "SSH key".to_owned(),
        tags: Vec::new(),
        environment: env,
        target: Some("build-01".to_owned()),
        custom,
        expires_at: None,
        max_uses: None,
        payload,
    }
}

fn input() -> SshPrepareInput {
    SshPrepareInput {
        purpose: "deploy the build".to_owned(),
        ..SshPrepareInput::default()
    }
}

fn ready(outcome: SshPrepareOutcome) -> Box<SshGrant> {
    match outcome {
        SshPrepareOutcome::Ready(grant) => grant,
        SshPrepareOutcome::Pending(p) => panic!("expected ready, got pending {p:?}"),
    }
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
}

/// The data an SSH client asks the agent to sign for a public key login.
pub(crate) fn userauth(blob: &[u8], user: &str, method: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, &[7; 32]);
    out.push(50);
    put_string(&mut out, user.as_bytes());
    put_string(&mut out, b"ssh-connection");
    put_string(&mut out, method.as_bytes());
    out.push(1);
    put_string(&mut out, b"ssh-ed25519");
    put_string(&mut out, blob);
    if method != "publickey" {
        put_string(&mut out, b"fake-host-key");
    }
    out
}

/// Text forms of the private key that must never leave core: each Base64 line of the OpenSSH
/// text, and the hex of the ed25519 seed.
fn key_markers(payload: &Payload) -> Vec<String> {
    let Payload::SshKey { private_key, .. } = payload else {
        panic!("ssh payload expected");
    };
    let text = private_key.expose_secret();
    let mut out: Vec<String> = text
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
        .map(str::to_owned)
        .collect();
    let key = PrivateKey::from_openssh(text).unwrap();
    let seed = key.key_data().ed25519().unwrap().private.to_bytes();
    out.push(seed.iter().map(|b| format!("{b:02x}")).collect());
    out
}

struct SshFx {
    fx: Fx,
    item: ItemId,
    agent: AgentContext,
    markers: Vec<String>,
}

impl SshFx {
    async fn new(mode: GrantMode) -> Self {
        Self::with_namespaces(mode, None).await
    }

    /// As [`Self::new`]; `namespaces` goes into the item setting `sshsig_namespaces`.
    async fn with_namespaces(mode: GrantMode, namespaces: Option<&str>) -> Self {
        let fx = Fx::new().await;
        let ws = fx.workspace("infra").await;
        let payload = generate_ed25519("zq-fake-build-01").unwrap();
        let markers = key_markers(&payload);
        let mut input = ssh_item(ws, payload, Environment::Dev);
        if let Some(list) = namespaces {
            input
                .custom
                .insert("sshsig_namespaces".to_owned(), list.to_owned());
        }
        let item = fx.item(input).await;
        let agent = fx.agent(&ssh_scopes()).await;
        fx.grant(agent.agent_id, &[Permission::UseSsh], mode).await;
        Self {
            fx,
            item,
            agent,
            markers,
        }
    }

    async fn prepare(&self) -> Box<SshGrant> {
        ready(
            self.fx
                .service
                .agent_api()
                .ssh_prepare(&self.agent, self.item, input())
                .await
                .unwrap(),
        )
    }

    async fn sign(&self, grant: &SshGrant) -> Result<Vec<u8>, CoreError> {
        let data = userauth(grant.ticket.key_blob(), "ci", "publickey");
        self.fx
            .service
            .agent_api()
            .ssh_sign(&grant.ticket, &data, 0)
            .await
    }
}

#[tokio::test]
async fn prepare_gives_public_facts_and_a_ticket_and_signs_verifiable_sshsig() {
    let s = SshFx::with_namespaces(GrantMode::Auto, Some("git")).await;
    let grant = s.prepare().await;
    assert!(grant.fingerprint.starts_with("SHA256:"));
    assert!(grant.public_key.starts_with("ssh-ed25519 "));
    assert_eq!(grant.ssh.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(grant.ssh.port, Some(2222));
    assert_eq!(grant.ssh.user.as_deref(), Some("ci"));
    assert_eq!(grant.ticket.signs_left(), None);
    assert_eq!(grant.expires_at, grant.lease.expires_at);
    let public = PublicKey::from_openssh(&grant.public_key).unwrap();
    assert_eq!(
        grant.ticket.key_blob(),
        public.to_bytes().unwrap().as_slice()
    );

    // An SSHSIG blob signs and verifies with the public key.
    let msg = b"fake commit to sign";
    let data = SshSig::signed_data("git", HashAlg::Sha512, msg).unwrap();
    let api = s.fx.service.agent_api();
    let blob = api.ssh_sign(&grant.ticket, &data, 0).await.unwrap();
    let signature = Signature::try_from(blob.as_slice()).unwrap();
    let sshsig = SshSig::new(public.key_data().clone(), "git", HashAlg::Sha512, signature).unwrap();
    public.verify("git", msg, &sshsig).unwrap();

    // A user authentication request (plain and host-bound) signs too.
    let sig = s.sign(&grant).await.unwrap();
    assert_eq!(&sig[4..15], b"ssh-ed25519");
    let bound = userauth(
        grant.ticket.key_blob(),
        "ci",
        "publickey-hostbound-v00@openssh.com",
    );
    api.ssh_sign(&grant.ticket, &bound, 0).await.unwrap();
    assert!(api.ssh_ticket_open(&grant.ticket).await);

    let types = s.fx.audit_types().await;
    assert!(types.contains(&"ssh.prepare".to_owned()), "{types:?}");
    assert_eq!(types.iter().filter(|t| *t == "ssh.sign").count(), 3);
}

#[tokio::test]
async fn data_that_is_not_a_login_or_sshsig_is_refused() {
    let s = SshFx::new(GrantMode::Auto).await;
    let grant = s.prepare().await;
    let api = s.fx.service.agent_api();
    let other_key = PrivateKey::from_openssh(match &generate_ed25519("x").unwrap() {
        Payload::SshKey { private_key, .. } => private_key.expose_secret().to_owned(),
        _ => unreachable!(),
    })
    .unwrap();
    let other_blob = other_key.public_key().to_bytes().unwrap();
    let cases: Vec<Vec<u8>> = vec![
        b"random bytes to sign".to_vec(),
        Vec::new(),
        userauth(&other_blob, "ci", "publickey"),
        userauth(grant.ticket.key_blob(), "ci", "password"),
        {
            let mut long = userauth(grant.ticket.key_blob(), "ci", "publickey");
            long.push(0);
            long
        },
        vec![0; super::MAX_SIGN_DATA_BYTES + 1],
    ];
    for data in cases {
        assert!(
            matches!(
                api.ssh_sign(&grant.ticket, &data, 0).await,
                Err(CoreError::Validation(_))
            ),
            "refused: {} bytes",
            data.len()
        );
    }
    assert_eq!(
        sign_data_kind(&userauth(b"k", "c\u{7}i", "publickey"), b"k"),
        Some(SignData::UserAuth {
            user: "ci".to_owned()
        })
    );
}

#[tokio::test]
async fn prepare_needs_scope_kind_and_policy() {
    let s = SshFx::new(GrantMode::Auto).await;
    let api = s.fx.service.agent_api();
    // No `ssh:use` scope.
    let plain = s.fx.agent(&all_scopes()).await;
    s.fx.grant(plain.agent_id, &[Permission::UseSsh], GrantMode::Auto)
        .await;
    assert!(matches!(
        api.ssh_prepare(&plain, s.item, input()).await,
        Err(CoreError::InsufficientScope(Scope::SshUse))
    ));
    // No grant: the item is hidden.
    let stranger = s.fx.agent(&ssh_scopes()).await;
    assert!(matches!(
        api.ssh_prepare(&stranger, s.item, input()).await,
        Err(CoreError::NotFound)
    ));
    // `read` alone does not give `use_ssh`.
    let reader = s.fx.agent(&ssh_scopes()).await;
    s.fx.grant(reader.agent_id, &[Permission::Read], GrantMode::Auto)
        .await;
    assert!(matches!(
        api.ssh_prepare(&reader, s.item, input()).await,
        Err(CoreError::Forbidden)
    ));
    // Bad purpose and TTL.
    let empty = SshPrepareInput::default();
    assert!(matches!(
        api.ssh_prepare(&s.agent, s.item, empty).await,
        Err(CoreError::Validation(_))
    ));
    let short = SshPrepareInput {
        ttl_seconds: Some(59),
        ..input()
    };
    assert!(matches!(
        api.ssh_prepare(&s.agent, s.item, short).await,
        Err(CoreError::Validation(_))
    ));
    // A visible item of another kind.
    let ws = s.fx.workspace("web").await;
    let login =
        s.fx.item(crate::agent_api::tests::login(
            ws,
            "Web",
            Environment::Dev,
            "u",
            "zq-fake-pw",
        ))
        .await;
    assert!(matches!(
        api.ssh_prepare(&s.agent, login, input()).await,
        Err(CoreError::Validation(_))
    ));
}

#[tokio::test]
async fn a_shorter_ttl_shortens_the_ticket() {
    let s = SshFx::new(GrantMode::Auto).await;
    let api = s.fx.service.agent_api();
    let grant = ready(
        api.ssh_prepare(
            &s.agent,
            s.item,
            SshPrepareInput {
                ttl_seconds: Some(60),
                ..input()
            },
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        grant.expires_at,
        s.fx.now() + jiff::SignedDuration::from_secs(60)
    );
    assert!(grant.expires_at < grant.lease.expires_at);
    s.fx.advance(61);
    assert!(!api.ssh_ticket_open(&grant.ticket).await);
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Forbidden)));
}

#[tokio::test]
async fn release_revoke_and_lock_end_the_ticket() {
    let s = SshFx::new(GrantMode::Auto).await;
    let api = s.fx.service.agent_api();

    let grant = s.prepare().await;
    api.release_lease(&s.agent, grant.lease.id).await.unwrap();
    assert!(!api.ssh_ticket_open(&grant.ticket).await);
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Forbidden)));

    let grant = s.prepare().await;
    assert!(s.sign(&grant).await.is_ok());
    s.fx.service
        .revoke_lease(&s.fx.owner, grant.lease.id)
        .await
        .unwrap();
    assert!(!api.ssh_ticket_open(&grant.ticket).await);
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Forbidden)));

    // A lock ends the ticket, also after the next unlock (new session).
    s.fx.advance(1000);
    let grant = s.prepare().await;
    s.fx.lock().await;
    assert!(!api.ssh_ticket_open(&grant.ticket).await);
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Locked)));
    s.fx.unlock().await;
    assert!(!api.ssh_ticket_open(&grant.ticket).await);
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Forbidden)));
}

#[tokio::test]
async fn a_revoked_agent_key_or_a_deny_grant_stops_signing() {
    let s = SshFx::new(GrantMode::Auto).await;
    let grant = s.prepare().await;
    assert!(s.sign(&grant).await.is_ok());
    s.fx.grant(s.agent.agent_id, &[Permission::UseSsh], GrantMode::Deny)
        .await;
    // A deny of `use_ssh` also hides the item (DEC-T07-2 a).
    assert!(matches!(s.sign(&grant).await, Err(CoreError::NotFound)));

    let s = SshFx::new(GrantMode::Auto).await;
    let grant = s.prepare().await;
    s.fx.service
        .revoke_agent_key(&s.fx.owner, s.agent.key_id)
        .await
        .unwrap();
    assert!(
        !s.fx
            .service
            .agent_api()
            .ssh_ticket_open(&grant.ticket)
            .await
    );
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Forbidden)));
}

#[tokio::test]
async fn an_ask_always_lease_gives_one_signature() {
    let s = SshFx::new(GrantMode::AskAlways).await;
    let api = s.fx.service.agent_api();
    let pending = match api.ssh_prepare(&s.agent, s.item, input()).await.unwrap() {
        SshPrepareOutcome::Pending(p) => p,
        SshPrepareOutcome::Ready(_) => panic!("approval expected"),
    };
    s.fx.service
        .approve_request(&s.fx.owner, pending.access_request.id, ApprovalOption::Once)
        .await
        .unwrap();
    let grant = s.prepare().await;
    assert_eq!(grant.ticket.signs_left(), Some(1));
    assert!(api.ssh_ticket_open(&grant.ticket).await);
    assert!(s.sign(&grant).await.is_ok());
    assert_eq!(grant.ticket.signs_left(), Some(0));
    assert!(!api.ssh_ticket_open(&grant.ticket).await);
    assert!(matches!(s.sign(&grant).await, Err(CoreError::Forbidden)));
    // The next prepare needs a new approval.
    assert!(matches!(
        api.ssh_prepare(&s.agent, s.item, input()).await.unwrap(),
        SshPrepareOutcome::Pending(_)
    ));
}

#[tokio::test]
async fn signing_is_rate_limited_per_ticket() {
    let s = SshFx::new(GrantMode::Auto).await;
    let grant = s.prepare().await;
    for _ in 0..super::SIGNS_PER_MINUTE {
        s.sign(&grant).await.unwrap();
    }
    assert!(matches!(
        s.sign(&grant).await,
        Err(CoreError::RateLimited { .. })
    ));
    s.fx.advance(61);
    assert!(s.sign(&grant).await.is_ok());
}

#[tokio::test]
async fn an_encrypted_key_signs_with_its_passphrase() {
    let fx = Fx::new().await;
    let ws = fx.workspace("infra").await;
    let plain = generate_ed25519("zq-fake-enc").unwrap();
    let Payload::SshKey { private_key, .. } = &plain else {
        panic!("ssh payload");
    };
    let key = PrivateKey::from_openssh(private_key.expose_secret()).unwrap();
    let locked = key
        .encrypt(&mut ssh_key::rand_core::OsRng, "zq-fake-passphrase")
        .unwrap();
    let text = locked.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let payload = import_private_key(
        &text,
        Some(cerberus_crypto::SecretString::new(
            "zq-fake-passphrase".to_owned(),
        )),
    )
    .unwrap();
    let item = fx.item(ssh_item(ws, payload, Environment::Dev)).await;
    let agent = fx.agent(&ssh_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::UseSsh], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();
    let grant = ready(api.ssh_prepare(&agent, item, input()).await.unwrap());
    let data = userauth(grant.ticket.key_blob(), "ci", "publickey");
    assert!(api.ssh_sign(&grant.ticket, &data, 0).await.is_ok());
    assert_eq!(
        grant.ticket.key_blob(),
        key.public_key().to_bytes().unwrap().as_slice()
    );
}

#[tokio::test]
async fn no_private_key_material_in_results_or_the_audit_export() {
    let s = SshFx::new(GrantMode::Auto).await;
    let grant = s.prepare().await;
    s.sign(&grant).await.unwrap();
    let shown = format!("{grant:?}");
    for marker in &s.markers {
        assert!(
            !shown.contains(marker.as_str()),
            "no key text in the result"
        );
    }
    let dest = s.fx.dir.path().join("audit.jsonl");
    s.fx.service.audit_export(&s.fx.owner, &dest).await.unwrap();
    let text = std::fs::read_to_string(&dest).unwrap();
    assert!(text.contains("ssh.sign"));
    assert!(!text.contains(MARK));
    for marker in &s.markers {
        assert!(!text.contains(marker.as_str()), "no key text in the export");
    }
}

/// DEC-FIX8-5: opening an encrypted key (bcrypt-pbkdf) does not hold the vault guard, so another
/// call is not stalled while a signature is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signing_with_an_encrypted_key_does_not_stall_other_calls() {
    let fx = Fx::new().await;
    let ws = fx.workspace("infra").await;
    let plain = generate_ed25519("zq-fake-enc").unwrap();
    let Payload::SshKey { private_key, .. } = &plain else {
        panic!("ssh payload");
    };
    let key = PrivateKey::from_openssh(private_key.expose_secret()).unwrap();
    let text = key
        .encrypt(&mut ssh_key::rand_core::OsRng, "zq-fake-passphrase")
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
    let payload = import_private_key(
        &text,
        Some(cerberus_crypto::SecretString::new(
            "zq-fake-passphrase".to_owned(),
        )),
    )
    .unwrap();
    let item = fx.item(ssh_item(ws, payload, Environment::Dev)).await;
    let agent = fx.agent(&ssh_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::UseSsh], GrantMode::Auto)
        .await;
    let api = fx.service.agent_api();
    let grant = ready(api.ssh_prepare(&agent, item, input()).await.unwrap());
    let data = userauth(grant.ticket.key_blob(), "ci", "publickey");
    // One signature alone shows how long the key opening takes.
    let start = cerberus_types::Stopwatch::start();
    api.ssh_sign(&grant.ticket, &data, 0).await.unwrap();
    let alone = start.elapsed();
    assert!(
        alone > std::time::Duration::from_millis(100),
        "the test needs a slow key opening: {alone:?}"
    );
    let signer = {
        let api = fx.service.agent_api();
        let ticket = grant.ticket.clone();
        let data = data.clone();
        tokio::spawn(async move { api.ssh_sign(&ticket, &data, 0).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(
        alone.as_millis() as u64 / 5,
    ))
    .await;
    let start = cerberus_types::Stopwatch::start();
    let status = fx.service.status().await;
    let waited = start.elapsed();
    assert!(status.session.is_some());
    assert!(
        waited < alone / 3,
        "another call waited {waited:?} while a signature took {alone:?}"
    );
    signer.await.unwrap().unwrap();
}

/// DEC-FIX8-7: a second prepare on the same lease does not reset the per-minute sign limit.
#[tokio::test]
async fn a_replacement_ticket_keeps_the_rate_window() {
    let s = SshFx::new(GrantMode::Auto).await;
    let first = s.prepare().await;
    for _ in 0..super::SIGNS_PER_MINUTE {
        s.sign(&first).await.unwrap();
    }
    let second = ready(
        s.fx.service
            .agent_api()
            .ssh_prepare(
                &s.agent,
                s.item,
                SshPrepareInput {
                    lease_id: Some(first.ticket.lease_id()),
                    ..input()
                },
            )
            .await
            .unwrap(),
    );
    assert_eq!(second.ticket.lease_id(), first.ticket.lease_id());
    // The bridge socket does this when it takes the newer ticket.
    second.ticket.carry_rate_window(&first.ticket);
    assert!(matches!(
        s.sign(&second).await,
        Err(CoreError::RateLimited { .. })
    ));
    s.fx.advance(61);
    assert!(s.sign(&second).await.is_ok());
}

/// An item with an encrypted key (default 16 bcrypt rounds), an agent and an auto grant.
async fn encrypted_fx() -> (Fx, ItemId, AgentContext) {
    let fx = Fx::new().await;
    let ws = fx.workspace("infra").await;
    let text = crate::items::encrypted_key_with_rounds("zq-fake-passphrase", 16);
    let payload = import_private_key(
        &text,
        Some(cerberus_crypto::SecretString::new(
            "zq-fake-passphrase".to_owned(),
        )),
    )
    .unwrap();
    let item = fx.item(ssh_item(ws, payload, Environment::Dev)).await;
    let agent = fx.agent(&ssh_scopes()).await;
    fx.grant(agent.agent_id, &[Permission::UseSsh], GrantMode::Auto)
        .await;
    (fx, item, agent)
}

/// AUD-3: `ssh_prepare` opens an encrypted key (bcrypt-pbkdf) without the vault guard, so a
/// lock or the panic button never waits for the decrypt. The prepare that was running gives no
/// ticket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_does_not_wait_for_the_key_decrypt_of_a_prepare() {
    for panic_button in [false, true] {
        let (fx, item, agent) = encrypted_fx().await;
        let api = fx.service.agent_api();
        // One prepare alone shows how long the key opening takes.
        let start = cerberus_types::Stopwatch::start();
        ready(api.ssh_prepare(&agent, item, input()).await.unwrap());
        let alone = start.elapsed();
        assert!(
            alone > std::time::Duration::from_millis(100),
            "the test needs a slow key opening: {alone:?}"
        );
        let preparing = {
            let api = fx.service.agent_api();
            let agent = agent.clone();
            tokio::spawn(async move { api.ssh_prepare(&agent, item, input()).await })
        };
        tokio::time::sleep(alone / 5).await;
        let start = cerberus_types::Stopwatch::start();
        if panic_button {
            fx.service.panic_lock(&fx.owner).await.unwrap();
        } else {
            fx.lock().await;
        }
        let waited = start.elapsed();
        // Under load the lock itself can be slow; then the decrypt must still be running, so
        // the lock did not wait for it.
        assert!(
            waited < alone / 3 || !preparing.is_finished(),
            "the lock waited {waited:?} for a decrypt of {alone:?} (panic: {panic_button})"
        );
        assert!(
            preparing.await.unwrap().is_err(),
            "a prepare cut by a lock gives no ticket"
        );
    }
}

/// AUD-21: an `SSHSIG` blob is signed only for a namespace that the item allows (setting
/// `sshsig_namespaces`), so a lease for "one SSH login" cannot sign a git tag. The namespace is
/// in the `ssh.sign` event.
#[tokio::test]
async fn sshsig_signs_only_the_namespaces_that_the_item_allows() {
    let msg = b"fake release tag";
    let sig = |ns: &str| SshSig::signed_data(ns, HashAlg::Sha512, msg).unwrap();

    let none = SshFx::new(GrantMode::Auto).await;
    let grant = none.prepare().await;
    let api = none.fx.service.agent_api();
    assert!(matches!(
        api.ssh_sign(&grant.ticket, &sig("git"), 0).await,
        Err(CoreError::Forbidden)
    ));
    // A login still signs without the setting.
    none.sign(&grant).await.unwrap();

    let s = SshFx::with_namespaces(GrantMode::Auto, Some("git, file")).await;
    let grant = s.prepare().await;
    let api = s.fx.service.agent_api();
    api.ssh_sign(&grant.ticket, &sig("git"), 0).await.unwrap();
    api.ssh_sign(&grant.ticket, &sig("file"), 0).await.unwrap();
    assert!(matches!(
        api.ssh_sign(&grant.ticket, &sig("gitx"), 0).await,
        Err(CoreError::Forbidden)
    ));
    // An SSHSIG blob that does not parse is not signed.
    let mut bad = sig("git");
    bad.push(0);
    assert!(matches!(
        api.ssh_sign(&grant.ticket, &bad, 0).await,
        Err(CoreError::Validation(_))
    ));
    assert!(matches!(
        api.ssh_sign(&grant.ticket, b"SSHSIG", 0).await,
        Err(CoreError::Validation(_))
    ));
    let rows =
        s.fx.service
            .audit_query(
                &s.fx.owner,
                crate::admin::AuditQuery {
                    event_type: Some("ssh.sign".to_owned()),
                    limit: 100,
                    ..crate::admin::AuditQuery::default()
                },
            )
            .await
            .unwrap();
    let namespaces: Vec<String> = rows
        .iter()
        .filter_map(|r| r.event.details.get("namespace"))
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    assert!(namespaces.contains(&"git".to_owned()), "{namespaces:?}");
    assert!(namespaces.contains(&"gitx".to_owned()), "{namespaces:?}");
}

/// AUD-21: the setting is a comma list of namespace names.
#[tokio::test]
async fn a_bad_sshsig_namespace_setting_is_refused() {
    let fx = Fx::new().await;
    let ws = fx.workspace("infra").await;
    let mut input = ssh_item(ws, generate_ed25519("zq-fake").unwrap(), Environment::Dev);
    input
        .custom
        .insert("sshsig_namespaces".to_owned(), "git,,has space".to_owned());
    let error = fx
        .service
        .create_item_as_operator(&fx.owner, input)
        .await
        .unwrap_err();
    let CoreError::Validation(problems) = error else {
        panic!("validation expected");
    };
    assert_eq!(problems[0].field, "custom.sshsig_namespaces");
}
