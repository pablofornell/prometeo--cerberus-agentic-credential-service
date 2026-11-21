//! R1 (plan step 10): a desktop state in remote mode against a real `cerberusd` with the admin API, through the same
//! `ops` functions and forwarded commands the Tauri commands use: status, unlock, items, an approval, lock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use cerberus_desktop::dto::{AccessRequestView, ItemSummaryView, LeaseView, Secret, VaultState};
use cerberus_desktop::ops;
use common::{Daemon, MAIN, PHRASE, remote_desktop};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_desktop_state_in_remote_mode_against_cerberusd() {
    let daemon = Daemon::start(true).await;
    let bundle = daemon.enroll("laptop").await;
    let file = daemon.bundle_file(&bundle, "laptop.cerberus-admin");
    let (state, dir, _shell) = remote_desktop(&file).await;
    let remote = state.remote().expect("remote mode").clone();
    let operator = bundle.operator_id.to_string();
    assert!(
        !dir.path().join("vault.cerberus").exists(),
        "no local vault"
    );

    // vault_status: sealed for this desktop, the server's own state alongside.
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed);
    let link = status.remote.expect("remote");
    assert!(link.reachable);
    assert_eq!(link.server_state, Some(VaultState::Unlocked));

    // vault_unlock opens the session.
    let session = ops::vault_unlock(
        &state,
        MAIN,
        operator.clone(),
        Secret::new(PHRASE.to_owned()),
    )
    .await
    .expect("unlock");
    assert_eq!(session.operator_id, operator);
    assert_eq!(
        ops::vault_status(&state, MAIN).await.expect("status").state,
        VaultState::Unlocked
    );

    // item_list through the server.
    let items: Vec<ItemSummaryView> = remote
        .forward("item_list", &json!({ "filter": {} }))
        .await
        .expect("items");
    assert!(items.iter().any(|i| i.id == daemon.seed.item.to_string()));

    // request_approve: an agent's ask_once read waits; the desktop approves it; the agent reads.
    let path = format!("/v1/credentials/{}/reveal", daemon.seed.item);
    let purpose = r#"{"purpose":"remote daemon test read"}"#;
    let pending = daemon.agent("POST", &path, Some(purpose)).await;
    assert_eq!(
        pending.status,
        202,
        "{}",
        String::from_utf8_lossy(&pending.body)
    );
    let waiting: Vec<AccessRequestView> = remote
        .forward("request_list_pending", &json!({}))
        .await
        .expect("pending");
    assert_eq!(waiting.len(), 1);
    let lease: LeaseView = remote
        .forward(
            "request_approve",
            &json!({ "request": waiting[0].id, "option": "once" }),
        )
        .await
        .expect("approve");
    assert!(!lease.id.is_empty());
    assert_eq!(daemon.agent("POST", &path, Some(purpose)).await.status, 200);

    // vault_lock locks the server vault; the desktop is sealed and agents get 423.
    ops::vault_lock(&state, MAIN).await.expect("lock");
    let status = ops::vault_status(&state, MAIN).await.expect("status");
    assert_eq!(status.state, VaultState::Sealed);
    assert_eq!(
        status.remote.expect("remote").server_state,
        Some(VaultState::Sealed)
    );
    assert_eq!(daemon.agent("GET", "/v1/status", None).await.status, 423);

    state.shutdown().await;
    daemon.stop().await;
}
