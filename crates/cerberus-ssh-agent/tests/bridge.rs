//! The bridge over a real Unix socket: the ssh-agent protocol with a raw client, refused message
//! types, file modes, the socket end (release, revoke, lock, drop), limits, and no private key
//! material in results or the audit export.
#![cfg(unix)]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::os::unix::fs::PermissionsExt;

use cerberus_core::items::generate_ed25519;
use cerberus_ssh_agent::{BridgeError, MAX_SOCKETS_PER_AGENT, PrepareOutcome};
use cerberus_types::GrantMode;
use common::{AgentClient, Fx, gone, input, ssh_item, userauth};
use signature::Verifier;
use ssh_key::{PublicKey, Signature};

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test]
async fn a_raw_client_lists_the_key_and_gets_a_valid_signature() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    assert!(ready.fingerprint.starts_with("SHA256:"));
    assert_eq!(ready.ssh.host.as_deref(), Some("127.0.0.1"));
    assert_eq!(ready.ssh.port, Some(2222));
    assert_eq!(ready.ssh.user.as_deref(), Some("ci"));
    let public = PublicKey::from_openssh(&ready.public_key).unwrap();
    let blob = public.to_bytes().unwrap();

    let mut client = AgentClient::connect(&ready.socket_path).await;
    let ids = client.identities().await;
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].0, blob);
    assert_eq!(ids[0].1, format!("cerberus:{}", fx.item));

    let data = userauth(&blob, "ci");
    let sig = client.sign(&blob, &data).await.expect("a signature");
    let signature = Signature::try_from(sig.as_slice()).unwrap();
    public.key_data().verify(&data, &signature).unwrap();
    // A changed message does not verify with that signature.
    let mut other = data.clone();
    other[40] ^= 1;
    assert!(public.key_data().verify(&other, &signature).is_err());

    // A key that is not the ticket key, and data that is no login, get a failure.
    assert!(client.sign(b"other-key", &data).await.is_none());
    assert!(client.sign(&blob, b"arbitrary bytes").await.is_none());
    // The connection still works.
    assert_eq!(client.identities().await.len(), 1);
    let audit = fx.audit_export_text().await;
    assert!(audit.contains("\"ssh.sign\""));
    assert!(audit.contains("\"ssh.prepare\""));
}

#[tokio::test]
async fn every_other_message_type_is_refused() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    let mut client = AgentClient::connect(&ready.socket_path).await;
    // ADD_IDENTITY, REMOVE_IDENTITY, REMOVE_ALL, ADD_SMARTCARD, REMOVE_SMARTCARD, LOCK, UNLOCK,
    // ADD_ID_CONSTRAINED, ADD_SMARTCARD_CONSTRAINED, EXTENSION, SSH1 types, unknown.
    for kind in [17_u8, 18, 19, 20, 21, 22, 23, 25, 26, 27, 1, 9, 99, 255] {
        let mut body = vec![kind];
        common::put_string(&mut body, b"session-bind@openssh.com");
        assert_eq!(client.call(&body).await, vec![5], "type {kind}");
    }
    // A lock request with a passphrase does not lock anything: the key is still listed.
    assert_eq!(client.identities().await.len(), 1);
    // A frame above the limit closes the connection.
    assert!(client.send_raw(&[0x00, 0x04, 0x00, 0x01]).await);
    assert!(client.read().await.is_none());
    // A zero-length frame too.
    let mut client = AgentClient::connect(&ready.socket_path).await;
    assert!(client.send_raw(&[0, 0, 0, 0]).await);
    assert!(client.read().await.is_none());
}

#[tokio::test]
async fn socket_is_0600_in_a_0700_directory() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    let path = &ready.socket_path;
    let meta = std::fs::symlink_metadata(path).unwrap();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
    assert_eq!(mode(path), 0o600);
    let dir = path.parent().unwrap();
    assert_eq!(mode(dir), 0o700);
    assert_eq!(mode(dir.parent().unwrap()), 0o700);
    assert!(path.starts_with(common::runtime_dir(fx.dir.path())));
}

#[tokio::test]
async fn release_closes_the_socket_and_removes_the_file() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    assert_eq!(fx.bridge.socket_count(), 1);
    fx.core
        .agent_api()
        .release_lease(&fx.agent, ready.lease.id)
        .await
        .unwrap();
    assert!(gone(&ready.socket_path).await, "socket file removed");
    assert_eq!(fx.bridge.socket_count(), 0);
    assert!(fx.bridge.socket_path(ready.lease.id).is_none());
}

#[tokio::test]
async fn revoke_closes_the_socket_and_an_open_connection_stops_signing() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    let blob = PublicKey::from_openssh(&ready.public_key)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut client = AgentClient::connect(&ready.socket_path).await;
    assert_eq!(client.identities().await.len(), 1);
    fx.core
        .revoke_lease(&fx.owner, ready.lease.id)
        .await
        .unwrap();
    assert!(gone(&ready.socket_path).await, "socket file removed");
    // The connection opened before is closed too (or at least refuses to sign).
    let mut body = vec![13];
    common::put_string(&mut body, &blob);
    common::put_string(&mut body, &userauth(&blob, "ci"));
    body.extend_from_slice(&0_u32.to_be_bytes());
    let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    if client.send_raw(&frame).await {
        let answer = client.read().await;
        assert!(answer.is_none() || answer == Some(vec![5]), "{answer:?}");
    }
}

#[tokio::test]
async fn lock_closes_every_socket() {
    let fx = Fx::new().await;
    let first = fx.prepare().await;
    let payload = generate_ed25519("fake-second").unwrap();
    let second_item = fx
        .core
        .create_item_as_operator(
            &fx.owner,
            ssh_item(fx.workspace, "Second key", payload, 22, "ci"),
        )
        .await
        .unwrap()
        .summary
        .id;
    let second = fx.prepare_item(second_item).await;
    assert_ne!(first.socket_path, second.socket_path);
    assert_eq!(fx.bridge.socket_count(), 2);
    fx.lock().await;
    assert!(gone(&first.socket_path).await);
    assert!(gone(&second.socket_path).await);
    assert_eq!(fx.bridge.socket_count(), 0);
    // While locked, prepare is refused.
    assert!(matches!(
        fx.bridge.prepare(&fx.agent, fx.item, input()).await,
        Err(BridgeError::Core(cerberus_core::CoreError::Locked))
    ));
    // After unlock the agent prepares again and gets a working socket (same auto lease).
    fx.unlock().await;
    let again = fx.prepare().await;
    let mut client = AgentClient::connect(&again.socket_path).await;
    assert_eq!(client.identities().await.len(), 1);
}

#[tokio::test]
async fn one_socket_per_lease_and_a_bounded_number() {
    let fx = Fx::new().await;
    let one = fx.prepare().await;
    let two = fx.prepare().await;
    assert_eq!(one.lease.id, two.lease.id, "auto mode reuses the lease");
    assert_eq!(one.socket_path, two.socket_path);
    assert_eq!(fx.bridge.socket_count(), 1);
    for n in 1..MAX_SOCKETS_PER_AGENT {
        let payload = generate_ed25519("fake-more").unwrap();
        let item = fx
            .core
            .create_item_as_operator(
                &fx.owner,
                ssh_item(fx.workspace, &format!("Key {n}"), payload, 22, "ci"),
            )
            .await
            .unwrap()
            .summary
            .id;
        fx.prepare_item(item).await;
    }
    assert_eq!(fx.bridge.socket_count(), MAX_SOCKETS_PER_AGENT);
    let payload = generate_ed25519("fake-over").unwrap();
    let item = fx
        .core
        .create_item_as_operator(&fx.owner, ssh_item(fx.workspace, "Over", payload, 22, "ci"))
        .await
        .unwrap()
        .summary
        .id;
    assert!(matches!(
        fx.bridge.prepare(&fx.agent, item, input()).await,
        Err(BridgeError::Full)
    ));
}

#[tokio::test]
async fn dropping_the_bridge_removes_sockets_and_directory() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    let dir = ready.socket_path.parent().unwrap().to_path_buf();
    let Fx {
        bridge, dir: _tmp, ..
    } = fx;
    drop(bridge);
    assert!(!ready.socket_path.exists());
    assert!(!dir.exists());
}

#[tokio::test]
async fn an_approval_lease_gives_one_signature_then_closes() {
    let fx = Fx::with(2222, "ci", GrantMode::AskAlways).await;
    let pending = match fx
        .bridge
        .prepare(&fx.agent, fx.item, input())
        .await
        .unwrap()
    {
        PrepareOutcome::Pending(p) => p,
        PrepareOutcome::Ready(_) => panic!("approval expected"),
    };
    fx.core
        .approve_request(
            &fx.owner,
            pending.access_request.id,
            cerberus_types::ApprovalOption::Once,
        )
        .await
        .unwrap();
    let ready = fx.prepare().await;
    let blob = PublicKey::from_openssh(&ready.public_key)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut client = AgentClient::connect(&ready.socket_path).await;
    assert!(client.sign(&blob, &userauth(&blob, "ci")).await.is_some());
    assert!(gone(&ready.socket_path).await, "budget used: socket closed");
}

#[tokio::test]
async fn no_private_key_material_in_results_or_audit() {
    let fx = Fx::new().await;
    let ready = fx.prepare().await;
    let blob = PublicKey::from_openssh(&ready.public_key)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut client = AgentClient::connect(&ready.socket_path).await;
    client.sign(&blob, &userauth(&blob, "ci")).await.unwrap();
    let shown = format!("{ready:?}");
    let audit = fx.audit_export_text().await;
    for marker in &fx.markers {
        assert!(
            !shown.contains(marker.as_str()),
            "no key text in the result"
        );
        assert!(
            !audit.contains(marker.as_str()),
            "no key text in the audit export"
        );
    }
}
