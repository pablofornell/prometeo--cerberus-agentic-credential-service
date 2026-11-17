//! The typed SDK against a real vault and a real API server, and the event stream against a
//! scripted one.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use cerberus_client::{
    CatalogQuery, Client, ClientConfig, RetryPolicy, RevealResult, Trust, WireSecret,
};
use cerberus_types::wire::{
    AccessRequestStatus, ApiKeySecret, CreateItemRequest, CreateSessionRequest, Environment,
    ResolveMode, ResolveRequest, ResolveResponse, RevealRequest, SecretPayload, SessionPayload,
    SessionTokenSecret,
};
use cerberus_types::{AccessRequestId, ErrorCode, HANDLING_SECRET, ItemId, LeaseId};
use common::real::{PASSWORD, Real, USERNAME};
use common::script::{Pki, Reply, Script, Versions};

const PURPOSE: &str = "sdk integration test";

fn resolve(mode: ResolveMode) -> ResolveRequest {
    ResolveRequest {
        app: "shop".to_owned(),
        environment: Some("staging".to_owned()),
        role: Some("admin".to_owned()),
        kind: None,
        hint: None,
        purpose: PURPOSE.to_owned(),
        mode: Some(mode),
    }
}

fn payload(key: &str) -> SecretPayload {
    SecretPayload::ApiKey(ApiKeySecret {
        key: WireSecret::new(key.to_owned()),
        key_id: None,
        header_name: None,
        base_url: None,
    })
}

#[tokio::test]
async fn every_route_works_through_the_typed_client() {
    let real = Real::start().await;
    let client = real.client();

    assert_eq!(client.health().await.unwrap().vault, "unlocked");
    let status = client.status().await.unwrap();
    assert_eq!(status.agent.name, "qa-agent");

    // resolve: candidates, then best (secret)
    let ResolveResponse::Candidates(found) = client
        .resolve(&resolve(ResolveMode::Candidates))
        .await
        .unwrap()
    else {
        panic!("expected candidates");
    };
    assert_eq!(found.candidates.len(), 1);
    let ResolveResponse::Secret(secret) =
        client.resolve(&resolve(ResolveMode::Best)).await.unwrap()
    else {
        panic!("expected a secret");
    };
    assert_eq!(secret.handling, HANDLING_SECRET);
    let SecretPayload::WebLogin(login) = &secret.secret else {
        panic!("expected a web login");
    };
    assert_eq!(login.username.expose(), USERNAME);
    assert_eq!(login.password.expose(), PASSWORD);
    assert!(
        !format!("{secret:?}").contains(PASSWORD),
        "Debug must redact"
    );

    // catalog
    let page = client
        .catalog(&CatalogQuery {
            workspace: Some("shop".to_owned()),
            limit: Some(10),
            ..CatalogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);

    // reveal and release
    let item = ItemId(page.items[0].id);
    let reveal = RevealRequest {
        purpose: PURPOSE.to_owned(),
        lease_id: None,
        ttl_seconds: Some(60),
    };
    let RevealResult::Secret(revealed) = client.reveal(item, &reveal).await.unwrap() else {
        panic!("expected a secret");
    };
    let released = client
        .release_lease(LeaseId(revealed.lease.id))
        .await
        .unwrap();
    assert_eq!(released.lease_id, revealed.lease.id);
    let again = client
        .release_lease(LeaseId(revealed.lease.id))
        .await
        .unwrap_err();
    assert_eq!(again.code(), Some(ErrorCode::Conflict));

    // create and delete
    let created = client
        .create_item(&CreateItemRequest {
            workspace: "shop".to_owned(),
            title: "Shop API key".to_owned(),
            description: None,
            environment: Environment::Staging,
            role_label: None,
            category: None,
            tags: None,
            target: None,
            ttl_seconds: Some(600),
            max_uses: None,
            payload: payload("canary-key-0001"),
            totp: None,
        })
        .await
        .unwrap();
    client.delete_item(ItemId(created.item.id)).await.unwrap();
    let gone = client
        .delete_item(ItemId(created.item.id))
        .await
        .unwrap_err();
    assert_eq!(gone.code(), Some(ErrorCode::NotFound));

    // sessions
    let session = client
        .create_session(&CreateSessionRequest {
            workspace: "shop".to_owned(),
            title: "Shop session".to_owned(),
            description: None,
            environment: Environment::Staging,
            role_label: None,
            target: None,
            ttl_seconds: Some(600),
            payload: SessionPayload::SessionToken(SessionTokenSecret {
                token: WireSecret::new("canary-session-0001".to_owned()),
                token_type: None,
                header_name: None,
            }),
        })
        .await
        .unwrap();
    assert_eq!(session.item.title, "Shop session");

    // A prod item needs a person: reveal gives a pending request, the stream reports the
    // approval, and the second reveal with the lease gives the secret.
    let pending = match client
        .reveal(ItemId(real.prod_item.0), &reveal)
        .await
        .unwrap()
    {
        RevealResult::Pending(pending) => pending,
        RevealResult::Secret(_) => panic!("a prod item must need approval"),
    };
    let request_id = AccessRequestId(pending.access_request.id);
    assert_eq!(pending.access_request.status, AccessRequestStatus::Pending);
    assert_eq!(
        client.get_request(request_id).await.unwrap().id,
        request_id.0
    );
    let waiter = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .wait_request(request_id, Duration::from_secs(10))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    real.approve(request_id).await;
    let approved = waiter.await.unwrap().unwrap();
    assert_eq!(approved.status, AccessRequestStatus::Approved);
    let lease = approved.lease.unwrap();
    let with_lease = RevealRequest {
        lease_id: Some(lease.id),
        ..reveal
    };
    let RevealResult::Secret(prod_secret) =
        client.reveal(real.prod_item, &with_lease).await.unwrap()
    else {
        panic!("expected a secret after approval");
    };
    assert_eq!(prod_secret.lease.id, lease.id);
    let again = client
        .request_access(&cerberus_types::wire::CreateAccessRequest {
            item_id: real.prod_item.0,
            permission: None,
            reason: PURPOSE.to_owned(),
            ttl_seconds: None,
        })
        .await
        .unwrap();
    // "Once" was used up by the reveal, so a new request waits for a person.
    assert_eq!(again.status, AccessRequestStatus::Pending);

    real.stop().await;
}

#[tokio::test]
async fn a_locked_vault_gives_a_typed_error_with_a_request_id() {
    let real = Real::start().await;
    let client = real.client().with_retry(RetryPolicy::none());
    real.lock().await;
    assert_eq!(client.health().await.unwrap().vault, "locked");
    let error = client.status().await.unwrap_err();
    let api = error.api().unwrap();
    assert_eq!(api.code, ErrorCode::VaultLocked);
    assert_eq!(api.status, 423);
    assert!(api.retryable);
    assert_eq!(error.exit_code(), 71);
    real.unlock().await;
    assert!(client.status().await.is_ok());
    real.stop().await;
}

#[tokio::test]
async fn a_bad_token_is_unauthenticated() {
    let real = Real::start().await;
    let mut config = real.config();
    config.token = WireSecret::new("cvt_00000000-0000-0000-0000-000000000000.wrong".to_owned());
    let client = Client::new(&config).unwrap();
    let error = client.status().await.unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::Unauthenticated));
    assert_eq!(error.exit_code(), 70);
    assert!(!error.to_string().contains("wrong"));
    real.stop().await;
}

const VIEW_PENDING: &str = r#"{"id":"0190f000-0000-7000-8000-000000000001","item_id":"0190f000-0000-7000-8000-000000000002","permission":"read","status":"pending","requested_ttl_seconds":900,"created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:02:00Z","decided_at":null,"lease":null}"#;
const VIEW_APPROVED: &str = r#"{"id":"0190f000-0000-7000-8000-000000000001","item_id":"0190f000-0000-7000-8000-000000000002","permission":"read","status":"approved","requested_ttl_seconds":900,"created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:02:00Z","decided_at":"2026-01-01T00:00:30Z","lease":{"id":"0190f000-0000-7000-8000-000000000009","item_id":"0190f000-0000-7000-8000-000000000002","permission":"read","expires_at":"2026-01-01T00:15:00Z","uses_left":null}}"#;

async fn scripted(replies: Vec<Reply>) -> (Script, Client) {
    let pki = Pki::new();
    let server = Script::start(&pki, true, Versions::Tls13, replies).await;
    let config = ClientConfig {
        base_url: url::Url::parse(&server.url()).unwrap(),
        token: WireSecret::new("cvt_00000000-0000-0000-0000-000000000000.fake".to_owned()),
        trust: Trust::Pin(pki.export.pin.clone()),
        client_cert: None,
        timeout: Duration::from_secs(5),
    };
    (
        server,
        Client::new(&config)
            .unwrap()
            .with_retry(RetryPolicy::none()),
    )
}

#[tokio::test]
async fn the_event_stream_ends_with_the_final_status() {
    let body = format!(
        ": keep-alive\n\nevent: status\nid: 1\ndata: {VIEW_PENDING}\n\nevent: status\nid: 2\ndata: {VIEW_APPROVED}\n\n"
    );
    let (_server, client) = scripted(vec![Reply::Events(body)]).await;
    let id = AccessRequestId::generate();
    let mut events = client.watch_request(id).await.unwrap();
    let first = events.next().await.unwrap().unwrap();
    assert_eq!(first.status, AccessRequestStatus::Pending);
    let second = events.next().await.unwrap().unwrap();
    assert_eq!(second.status, AccessRequestStatus::Approved);
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn wait_request_returns_the_approved_view() {
    let body = format!(
        "event: status\nid: 1\ndata: {VIEW_PENDING}\n\nevent: status\nid: 2\ndata: {VIEW_APPROVED}\n\n"
    );
    let (_server, client) = scripted(vec![Reply::Events(body)]).await;
    let view = client
        .wait_request(AccessRequestId::generate(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(view.status, AccessRequestStatus::Approved);
    assert!(view.lease.is_some());
}

#[tokio::test]
async fn wait_request_polls_when_the_stream_is_not_available() {
    // The stream answers 404 JSON, which is a real error: wait_request must not hide it.
    let error_body = r#"{"error":{"code":"not_found","message":"x","request_id":"0190f000-0000-7000-8000-000000000003","retryable":false}}"#;
    let (_server, client) = scripted(vec![
        Reply::Json(404, error_body.into()),
        Reply::Json(200, VIEW_APPROVED.into()),
    ])
    .await;
    let view = client
        .wait_request(AccessRequestId::generate(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(view.status, AccessRequestStatus::Approved);
}

#[tokio::test]
async fn an_error_event_ends_the_stream_with_a_typed_error() {
    let data = r#"{"error":{"code":"vault_locked","message":"x","request_id":"0190f000-0000-7000-8000-000000000003","retryable":true}}"#;
    let body = format!("event: error\ndata: {data}\n\n");
    let (_server, client) = scripted(vec![Reply::Events(body)]).await;
    let mut events = client
        .watch_request(AccessRequestId::generate())
        .await
        .unwrap();
    let error = events.next().await.unwrap().unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::VaultLocked));
    assert!(events.next().await.is_none());
}
