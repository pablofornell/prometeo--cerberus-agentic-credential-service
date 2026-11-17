//! Conversions between the wire DTOs ([`cerberus_types::wire`]) and the vault types of
//! `cerberus-core` (ADR-0021, ADR-0027, ADR-0028).
//!
//! They are functions, not `From` impls: both sides are foreign to this crate. The one place that
//! knows both the wire form and the vault form is here.

use std::collections::BTreeMap;

use cerberus_core::CoreError;
use cerberus_core::agent_api::{
    AgentItemInput, AgentSessionInput, AgentStatusView, CatalogPage as CoreCatalogPage,
    CreatedItem as CoreCreatedItem, PendingResult, RevealInput, SecretResult, TotpInput,
    TotpResult,
};
use cerberus_core::approvals::{AccessRequestView as CoreAccessRequest, CreateAccess};
use cerberus_core::items::{
    ItemSummary as CoreItemSummary, Payload, SshMeta, TotpAlgorithm, TotpSeed,
};
use cerberus_core::leases::{LeaseView as CoreLease, ReleaseOutcome};
use cerberus_core::resolve::{
    Candidate as CoreCandidate, ResolveMode as CoreResolveMode, ResolveRequest as CoreResolve,
};
use cerberus_crypto::SecretString;
use cerberus_types::wire::{
    AccessPermission, AccessRequestView, ApiKeySecret, BrowserSessionSecret, Candidate,
    CatalogPage, CertificateSecret, CloudSecret, CreateAccessRequest, CreateItemRequest,
    CreateSessionRequest, CreatedItem, DatabaseSecret, EnvBundleSecret, ItemSummary, LeaseView,
    NoteSecret, PendingResponse, ReleaseResponse, ResolveMode, ResolveRequest, RevealRequest,
    Scope, SecretPayload, SecretResponse, SessionPayload, SessionTokenSecret, SshKeySecret,
    StatusAgent, StatusResponse, TotpAlgorithmWire, TotpRequest, TotpResponse, TotpSeedInput,
    WebLoginSecret, WireSecret,
};
use cerberus_types::{ItemId, LeaseId, Permission, RequestId};

use crate::error::ApiError;

fn wire_secret(secret: &SecretString) -> WireSecret {
    WireSecret::new(secret.expose_secret().to_owned())
}

fn wire_secret_opt(secret: Option<&SecretString>) -> Option<WireSecret> {
    secret.map(wire_secret)
}

fn core_secret(secret: WireSecret) -> SecretString {
    SecretString::new(secret.into_string())
}

fn access_permission(
    value: Permission,
    request_id: RequestId,
) -> Result<AccessPermission, ApiError> {
    match value {
        Permission::Read => Ok(AccessPermission::Read),
        Permission::UseSsh => Ok(AccessPermission::UseSsh),
        _ => Err(ApiError::new(
            cerberus_types::ErrorCode::Internal,
            request_id,
        )),
    }
}

/// The wire form of the status view of `GET /status`.
#[must_use]
pub fn status_response(view: AgentStatusView) -> StatusResponse {
    StatusResponse {
        vault: view.vault.into(),
        agent: StatusAgent {
            id: *view.agent.id.as_uuid(),
            name: view.agent.name,
            key_id: *view.agent.key_id.as_uuid(),
            scopes: view.agent.scopes.into_iter().map(Scope::from).collect(),
            key_expires_at: view.agent.key_expires_at,
        },
        server_time: view.server_time,
    }
}

/// The wire form of an item summary.
#[must_use]
pub fn item_summary(item: CoreItemSummary) -> ItemSummary {
    ItemSummary {
        id: *item.id.as_uuid(),
        kind: item.kind.into(),
        title: item.title,
        description: item.description,
        role_label: item.role_label,
        category: item.category,
        tags: item.tags,
        environment: item.environment.into(),
        workspace: item.workspace,
        target: item.target,
        created_by: item.created_by,
        expires_at: item.expires_at,
        updated_at: item.updated_at,
        has_totp: item.has_totp,
    }
}

/// The wire form of a catalog page.
#[must_use]
pub fn catalog_page(page: CoreCatalogPage) -> CatalogPage {
    CatalogPage {
        items: page.items.into_iter().map(item_summary).collect(),
        next_cursor: page.next_cursor,
    }
}

/// The wire form of a created item.
#[must_use]
pub fn created_item(created: CoreCreatedItem) -> CreatedItem {
    CreatedItem {
        item: item_summary(created.item),
    }
}

/// The core input of a resolve call.
#[must_use]
pub fn resolve_input(req: ResolveRequest) -> CoreResolve {
    CoreResolve {
        app: req.app,
        environment: req.environment,
        role: req.role,
        kind: req.kind.map(Into::into),
        hint: req.hint,
        purpose: req.purpose,
        mode: match req.mode {
            None | Some(ResolveMode::Best) => CoreResolveMode::Best,
            Some(ResolveMode::Candidates) => CoreResolveMode::Candidates,
        },
    }
}

/// The wire form of a resolve candidate.
#[must_use]
pub fn candidate(candidate: CoreCandidate) -> Candidate {
    Candidate {
        item: item_summary(candidate.item),
        score: candidate.score,
    }
}

fn lease_view(lease: CoreLease, request_id: RequestId) -> Result<LeaseView, ApiError> {
    Ok(LeaseView {
        id: *lease.id.as_uuid(),
        item_id: *lease.item_id.as_uuid(),
        permission: access_permission(lease.permission, request_id)?,
        expires_at: lease.expires_at,
        uses_left: lease.uses_left,
    })
}

/// The wire form of an access request.
///
/// # Errors
/// `internal` when the permission is not `read` or `use_ssh`.
pub fn access_request_view(
    view: CoreAccessRequest,
    request_id: RequestId,
) -> Result<AccessRequestView, ApiError> {
    Ok(AccessRequestView {
        id: *view.id.as_uuid(),
        item_id: *view.item_id.as_uuid(),
        permission: access_permission(view.permission, request_id)?,
        status: view.status.into(),
        requested_ttl_seconds: view.requested_ttl_seconds,
        created_at: view.created_at,
        expires_at: view.expires_at,
        decided_at: view.decided_at,
        lease: view
            .lease
            .map(|lease| lease_view(lease, request_id))
            .transpose()?,
    })
}

/// The wire form of a pending result.
///
/// # Errors
/// As [`access_request_view`].
pub fn pending_response(pending: PendingResult) -> Result<PendingResponse, ApiError> {
    let request_id = pending.request_id;
    Ok(PendingResponse {
        request_id: *request_id.as_uuid(),
        access_request: access_request_view(pending.access_request, request_id)?,
    })
}

/// The wire form of a lease release.
#[must_use]
pub fn release_response(outcome: ReleaseOutcome) -> ReleaseResponse {
    ReleaseResponse {
        lease_id: *outcome.lease_id.as_uuid(),
        released_at: outcome.released_at,
    }
}

/// The core input of a reveal call.
#[must_use]
pub fn reveal_input(req: RevealRequest) -> RevealInput {
    RevealInput {
        purpose: req.purpose,
        lease_id: req.lease_id.map(LeaseId::from_uuid),
        ttl_seconds: req.ttl_seconds,
    }
}

/// The core input of a TOTP call.
#[must_use]
pub fn totp_input(req: TotpRequest) -> TotpInput {
    TotpInput {
        purpose: req.purpose,
        lease_id: req.lease_id.map(LeaseId::from_uuid),
    }
}

/// The wire form of a secret result.
///
/// # Errors
/// `internal` when the lease permission is not `read` or `use_ssh`.
pub fn secret_response(result: SecretResult) -> Result<SecretResponse, ApiError> {
    let request_id = result.request_id;
    let ssh = result.ssh;
    let mut secret = secret_payload(&result.secret);
    if let (SecretPayload::SshKey(key), Some(meta)) = (&mut secret, ssh) {
        key.host = meta.host;
        key.port = meta.port;
        key.user = meta.user;
    }
    Ok(SecretResponse {
        handling: result.handling.into(),
        request_id: *request_id.as_uuid(),
        item: item_summary(result.item),
        secret,
        lease: lease_view(result.lease, request_id)?,
    })
}

/// The wire form of a TOTP result.
///
/// # Errors
/// `internal` when the lease permission is not `read` or `use_ssh`.
pub fn totp_response(result: TotpResult) -> Result<TotpResponse, ApiError> {
    Ok(TotpResponse {
        handling: result.handling.into(),
        request_id: *result.request_id.as_uuid(),
        item_id: *result.item_id.as_uuid(),
        code: wire_secret(&result.code),
        period: result.period,
        expires_in_seconds: result.expires_in_seconds,
        lease: lease_view(result.lease, result.request_id)?,
    })
}

/// The wire form of a core payload. The TOTP seed is left out (ADR-0027).
#[must_use]
pub fn secret_payload(payload: &Payload) -> SecretPayload {
    match payload {
        Payload::WebLogin {
            username,
            password,
            url,
            ..
        } => SecretPayload::WebLogin(WebLoginSecret {
            username: wire_secret(username),
            password: wire_secret(password),
            url: url.clone(),
        }),
        Payload::ApiKey {
            key,
            key_id,
            header_name,
            base_url,
        } => SecretPayload::ApiKey(ApiKeySecret {
            key: wire_secret(key),
            key_id: key_id.clone(),
            header_name: header_name.clone(),
            base_url: base_url.clone(),
        }),
        Payload::SshKey {
            private_key,
            passphrase,
            public_key,
            fingerprint,
        } => SecretPayload::SshKey(SshKeySecret {
            private_key: wire_secret(private_key),
            passphrase: wire_secret_opt(passphrase.as_ref()),
            public_key: public_key.clone(),
            fingerprint: fingerprint.clone(),
            host: None,
            port: None,
            user: None,
        }),
        Payload::SessionToken {
            token,
            token_type,
            header_name,
        } => SecretPayload::SessionToken(SessionTokenSecret {
            token: wire_secret(token),
            token_type: token_type.clone(),
            header_name: header_name.clone(),
        }),
        Payload::BrowserSession {
            storage_state,
            origin,
        } => SecretPayload::BrowserSession(BrowserSessionSecret {
            storage_state: wire_secret(storage_state),
            origin: origin.clone(),
        }),
        Payload::Database {
            url,
            engine,
            host,
            port,
            database,
            username,
            password,
            params,
        } => SecretPayload::Database(DatabaseSecret {
            url: wire_secret_opt(url.as_ref()),
            engine: engine.clone(),
            host: host.clone(),
            port: *port,
            database: database.clone(),
            username: wire_secret_opt(username.as_ref()),
            password: wire_secret_opt(password.as_ref()),
            params: Some(params.clone()),
        }),
        Payload::Cloud {
            provider,
            access_key_id,
            secret_access_key,
            session_token,
            region,
            extra,
        } => SecretPayload::Cloud(CloudSecret {
            provider: provider.clone(),
            access_key_id: wire_secret_opt(access_key_id.as_ref()),
            secret_access_key: wire_secret_opt(secret_access_key.as_ref()),
            session_token: wire_secret_opt(session_token.as_ref()),
            region: region.clone(),
            extra: Some(
                extra
                    .iter()
                    .map(|(name, value)| (name.clone(), wire_secret(value)))
                    .collect(),
            ),
        }),
        Payload::Certificate {
            cert_pem,
            key_pem,
            chain_pem,
        } => SecretPayload::Certificate(CertificateSecret {
            cert_pem: cert_pem.clone(),
            key_pem: wire_secret_opt(key_pem.as_ref()),
            chain_pem: chain_pem.clone(),
        }),
        Payload::EnvBundle { vars } => SecretPayload::EnvBundle(EnvBundleSecret {
            vars: vars
                .iter()
                .map(|(name, value)| (name.clone(), wire_secret(value)))
                .collect(),
        }),
        Payload::Note { text } => SecretPayload::Note(NoteSecret {
            text: wire_secret(text),
        }),
    }
}

/// The core payload. `totp` is allowed only for a web login.
///
/// # Errors
/// A field problem for `totp` on another kind.
pub fn core_payload(payload: SecretPayload, totp: Option<TotpSeed>) -> Result<Payload, CoreError> {
    let payload = match payload {
        SecretPayload::WebLogin(login) => Payload::WebLogin {
            username: core_secret(login.username),
            password: core_secret(login.password),
            url: login.url,
            totp,
        },
        other => {
            if totp.is_some() {
                return Err(CoreError::Validation(vec![cerberus_types::FieldProblem {
                    field: "totp".to_owned(),
                    problem: "is allowed only for a web_login".to_owned(),
                }]));
            }
            core_payload_without_totp(other)
        }
    };
    Ok(payload)
}

fn core_payload_without_totp(payload: SecretPayload) -> Payload {
    match payload {
        SecretPayload::WebLogin(login) => Payload::WebLogin {
            username: core_secret(login.username),
            password: core_secret(login.password),
            url: login.url,
            totp: None,
        },
        SecretPayload::ApiKey(key) => Payload::ApiKey {
            key: core_secret(key.key),
            key_id: key.key_id,
            header_name: key.header_name,
            base_url: key.base_url,
        },
        SecretPayload::SshKey(key) => Payload::SshKey {
            private_key: core_secret(key.private_key),
            passphrase: key.passphrase.map(core_secret),
            public_key: key.public_key,
            fingerprint: key.fingerprint,
        },
        SecretPayload::SessionToken(token) => session_token(token),
        SecretPayload::BrowserSession(session) => browser_session(session),
        SecretPayload::Database(db) => Payload::Database {
            url: db.url.map(core_secret),
            engine: db.engine,
            host: db.host,
            port: db.port,
            database: db.database,
            username: db.username.map(core_secret),
            password: db.password.map(core_secret),
            params: db.params.unwrap_or_default(),
        },
        SecretPayload::Cloud(cloud) => Payload::Cloud {
            provider: cloud.provider,
            access_key_id: cloud.access_key_id.map(core_secret),
            secret_access_key: cloud.secret_access_key.map(core_secret),
            session_token: cloud.session_token.map(core_secret),
            region: cloud.region,
            extra: cloud
                .extra
                .unwrap_or_default()
                .into_iter()
                .map(|(name, value)| (name, core_secret(value)))
                .collect(),
        },
        SecretPayload::Certificate(cert) => Payload::Certificate {
            cert_pem: cert.cert_pem,
            key_pem: cert.key_pem.map(core_secret),
            chain_pem: cert.chain_pem,
        },
        SecretPayload::EnvBundle(bundle) => Payload::EnvBundle {
            vars: bundle
                .vars
                .into_iter()
                .map(|(name, value)| (name, core_secret(value)))
                .collect(),
        },
        SecretPayload::Note(note) => Payload::Note {
            text: core_secret(note.text),
        },
    }
}

fn session_token(token: SessionTokenSecret) -> Payload {
    Payload::SessionToken {
        token: core_secret(token.token),
        token_type: token.token_type,
        header_name: token.header_name,
    }
}

fn browser_session(session: BrowserSessionSecret) -> Payload {
    Payload::BrowserSession {
        storage_state: core_secret(session.storage_state),
        origin: session.origin,
    }
}

fn core_session_payload(payload: SessionPayload) -> Payload {
    match payload {
        SessionPayload::SessionToken(token) => session_token(token),
        SessionPayload::BrowserSession(session) => browser_session(session),
    }
}

/// The core TOTP seed, with the defaults of ADR-0027.
#[must_use]
pub fn totp_seed(input: TotpSeedInput) -> TotpSeed {
    TotpSeed {
        secret: core_secret(input.secret),
        algorithm: match input.algorithm {
            None | Some(TotpAlgorithmWire::Sha1) => TotpAlgorithm::Sha1,
            Some(TotpAlgorithmWire::Sha256) => TotpAlgorithm::Sha256,
            Some(TotpAlgorithmWire::Sha512) => TotpAlgorithm::Sha512,
        },
        digits: input.digits.unwrap_or(6),
        period: input.period.unwrap_or(30),
    }
}

/// The core input of `POST /credentials`.
///
/// # Errors
/// A field problem when `totp` is sent for a kind other than `web_login`.
pub fn create_item_input(req: CreateItemRequest) -> Result<AgentItemInput, CoreError> {
    let custom = match &req.payload {
        SecretPayload::SshKey(key) => SshMeta {
            machine: None,
            host: key.host.clone(),
            port: key.port,
            user: key.user.clone(),
        }
        .into_custom(),
        _ => BTreeMap::new(),
    };
    let payload = core_payload(req.payload, req.totp.map(totp_seed))?;
    Ok(AgentItemInput {
        workspace: req.workspace,
        title: req.title,
        description: req.description,
        environment: req.environment.into(),
        role_label: req.role_label,
        category: req.category,
        tags: req.tags.unwrap_or_default(),
        target: req.target,
        custom,
        ttl_seconds: req.ttl_seconds,
        max_uses: req.max_uses,
        payload,
    })
}

/// The core input of `POST /sessions`.
#[must_use]
pub fn create_session_input(req: CreateSessionRequest) -> AgentSessionInput {
    AgentSessionInput {
        workspace: req.workspace,
        title: req.title,
        description: req.description,
        environment: req.environment.into(),
        role_label: req.role_label,
        target: req.target,
        ttl_seconds: req.ttl_seconds,
        payload: core_session_payload(req.payload),
    }
}

/// The core input of `POST /requests`.
#[must_use]
pub fn create_access_input(req: CreateAccessRequest) -> CreateAccess {
    CreateAccess {
        item_id: ItemId::from_uuid(req.item_id),
        permission: req.permission.map_or(Permission::Read, Permission::from),
        reason: req.reason,
        ttl_seconds: req.ttl_seconds,
    }
}

/// The core input of `POST /credentials/{id}/ssh-prepare` (MCP `ssh_prepare`).
#[must_use]
pub fn ssh_prepare_input(
    req: cerberus_types::wire::SshPrepareRequest,
) -> cerberus_core::agent_api::ssh::SshPrepareInput {
    cerberus_core::agent_api::ssh::SshPrepareInput {
        purpose: req.purpose,
        lease_id: req.lease_id.map(LeaseId::from_uuid),
        ttl_seconds: req.ttl_seconds,
    }
}

/// The wire form of a ready signing socket. REST and MCP send the same fields.
///
/// # Errors
/// `internal` when the socket path is not UTF-8 or the lease permission is not `use_ssh`.
pub fn ssh_prepare_response(
    ready: cerberus_ssh_agent::SshReady,
) -> Result<cerberus_types::wire::SshPrepareResponse, ApiError> {
    let request_id = ready.request_id;
    let socket_path = ready
        .socket_path
        .to_str()
        .ok_or_else(|| ApiError::new(cerberus_types::ErrorCode::Internal, request_id))?
        .to_owned();
    Ok(cerberus_types::wire::SshPrepareResponse {
        request_id: *request_id.as_uuid(),
        socket_path,
        public_key: ready.public_key,
        fingerprint: ready.fingerprint,
        host: ready.ssh.host,
        port: ready.ssh.port,
        user: ready.ssh.user,
        expires_at: ready.expires_at,
        lease: lease_view(ready.lease, request_id)?,
    })
}
