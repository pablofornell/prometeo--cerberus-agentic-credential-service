//! Tests of the RPC layer: the argument types, the gates, and the dispatch against a real vault
//! file with the cheapest KDF the schema allows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use cerberus_core::{
    CaIssuer, CoreConfig, CoreError, IssuedCa, KeyCustody, NewVault, OperatorContext,
};
use cerberus_crypto::{KdfParams, SecretBytes, SecretString};
use cerberus_store::{OpenOptions, Store};
use cerberus_types::{AgentId, ItemId, ManualClock, OperatorRole, RequestId, VaultId, t0};
use jiff::{SignedDuration, Timestamp};
use serde_json::{Value, json};

use super::*;
use crate::dto::{ConditionsView, RevealedSecretView, SelectorView};
use crate::remote::REMOTE_COMMANDS;

const PHRASE: &str = "orbit velvet canyon mosaic 7";

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

struct Fixture {
    _dir: tempfile::TempDir,
    core: VaultService,
    ctx: OperatorContext,
}

/// A new vault, unlocked by its owner.
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let clock = ManualClock::new(t0());
    let store = Store::open(
        OpenOptions {
            path: dir.path().join("vault.cerberus"),
            create: true,
        },
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    let core = VaultService::open(
        store,
        Arc::new(clock),
        CoreConfig::desktop(PathBuf::from("."), Arc::new(FakeCa)),
    )
    .await
    .unwrap();
    let created = core
        .create_vault(NewVault {
            owner_label: "Owner".to_owned(),
            phrase: SecretString::new(PHRASE.to_owned()),
            kdf: KdfParams::new(19_456, 1, 1).unwrap(),
            host_names: Vec::new(),
        })
        .await
        .unwrap();
    let ctx = OperatorContext {
        operator_id: created.owner_id,
        role: OperatorRole::Owner,
        request_id: RequestId::generate(),
    };
    Fixture {
        _dir: dir,
        core,
        ctx,
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn note_input(workspace: &str, text: &str) -> Value {
    json!({
        "workspace_id": workspace, "title": "Shop note", "description": "", "role_label": null,
        "category": "Note", "tags": [], "environment": "dev", "target": null, "custom": {},
        "expires_at": null, "max_uses": null, "payload": { "kind": "note", "text": text },
    })
}

/// Valid arguments of every remote command, with every field written out.
fn sample(command: &str) -> Value {
    let item = ItemId::generate().to_string();
    let agent = AgentId::generate().to_string();
    match command {
        "vault_unlock" => json!({ "operator_id": agent, "phrase": "a phrase" }),
        "workspace_put" => json!({
            "workspace": null,
            "input": { "slug": "shop", "name": "Shop", "description": "", "aliases": [] },
        }),
        "item_list" => json!({
            "filter": { "workspace_id": null, "environment": null, "kind": null, "tag": null, "q": null },
        }),
        "item_get" | "item_delete" | "item_reveal" | "item_totp_preview" => json!({ "item": item }),
        "item_create" => json!({ "input": note_input(&item, "text") }),
        "item_update" => json!({ "item": item, "input": note_input(&item, "text") }),
        "grant_list" => json!({ "agent_id": agent }),
        "grant_put" => json!({
            "input": {
                "id": null, "agent_id": agent,
                "selector": serde_json::to_value(SelectorView::default()).unwrap(),
                "permissions": ["read"], "mode": "auto",
                "conditions": serde_json::to_value(ConditionsView::default()).unwrap(),
                "allow_prod_auto": false,
            },
        }),
        "grant_delete" => json!({ "grant": item }),
        "request_approve" => json!({ "request": item, "option": "once" }),
        "request_deny" => json!({ "request": item }),
        "lease_revoke" => json!({ "lease": item }),
        "audit_query" => json!({
            "query": {
                "from": null, "to": null, "event_type": null, "agent_id": null, "item_id": null,
                "outcome": null, "before_seq": null, "limit": 50, "text": null,
            },
        }),
        _ => json!({}),
    }
}

fn code<T>(result: IpcResult<T>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => error.code,
    }
}

async fn call(f: &Fixture, command: &str, body: &Value) -> IpcResult<Value> {
    let out = dispatch(&f.core, Some(&f.ctx), command, &bytes(body)).await?;
    Ok(serde_json::from_slice(&out).unwrap())
}

#[test]
fn every_remote_command_has_args_and_an_arg_names_row() {
    let commands: Vec<&str> = REMOTE_COMMANDS.iter().map(|(name, _)| *name).collect();
    let rows: Vec<&str> = ARG_NAMES.iter().map(|(name, _)| *name).collect();
    assert_eq!(commands, rows);
    for command in commands {
        let body = sample(command);
        let names: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = arg_names(command).unwrap().to_vec();
        expected.sort_unstable();
        assert_eq!(names, expected, "{command}");
        let again = reencode(command, &bytes(&body))
            .unwrap_or_else(|| panic!("{command} has no Args type"))
            .unwrap_or_else(|e| panic!("{command}: {e}"));
        assert_eq!(
            serde_json::from_slice::<Value>(&again).unwrap(),
            body,
            "{command}"
        );
    }
    assert!(reencode("item_versions", b"{}").is_none());
    assert_eq!(arg_names("item_update"), Some(&["item", "input"][..]));
}

#[test]
fn unknown_fields_and_bad_shapes_are_invalid_request() {
    let mut body = sample("item_get");
    body["extra"] = json!(1);
    assert_eq!(
        code(reencode("item_get", &bytes(&body)).unwrap()),
        "invalid_request"
    );
    assert_eq!(
        code(reencode("vault_status", br#"{"x":1}"#).unwrap()),
        "invalid_request"
    );
    assert_eq!(
        code(reencode("vault_status", b"").unwrap()),
        "invalid_request"
    );
    assert_eq!(
        code(reencode("item_get", b"[]").unwrap()),
        "invalid_request"
    );
    assert_eq!(
        code(reencode("item_get", br#"{"item":7}"#).unwrap()),
        "invalid_request"
    );
    assert_eq!(
        code(reencode("item_get", b"{}").unwrap()),
        "invalid_request"
    );
}

#[test]
fn a_bad_body_error_never_quotes_the_input() {
    let error =
        from_body::<VaultUnlockArgs>(br#"{"operator_id":"x","phrase":12345678}"#).unwrap_err();
    assert!(!error.message.contains("12345678"));
    assert!(error.fields.is_empty());
}

#[test]
fn to_body_matches_serde_json_and_grows_its_buffer() {
    let big = json!({ "text": "x".repeat(100_000), "list": (0..1000).collect::<Vec<u32>>() });
    let ours = to_body(&big).unwrap();
    assert_eq!(&*ours, serde_json::to_vec(&big).unwrap().as_slice());
    assert_eq!(&*to_body(&()).unwrap(), b"null");
}

#[tokio::test]
async fn commands_off_the_allowlist_and_vault_unlock_are_remote_unsupported() {
    let f = fixture().await;
    for command in [
        "item_versions",
        "vault_create",
        "settings_set",
        "rustdesk_connect",
        "nope",
    ] {
        let result = dispatch(&f.core, Some(&f.ctx), command, b"{}").await;
        assert_eq!(code(result), "remote_unsupported", "{command}");
    }
    let unlock = bytes(&sample("vault_unlock"));
    let result = dispatch(&f.core, Some(&f.ctx), "vault_unlock", &unlock).await;
    assert_eq!(code(result), "remote_unsupported");
}

#[tokio::test]
async fn session_commands_need_a_session_before_their_body_is_read() {
    let f = fixture().await;
    for (command, gate) in REMOTE_COMMANDS {
        if gate != Gate::Session {
            continue;
        }
        let result = dispatch(&f.core, None, command, b"not json").await;
        assert_eq!(code(result), "admin_session_required", "{command}");
    }
    assert_eq!(f.core.state(), cerberus_types::VaultStateKind::Unlocked);
}

#[tokio::test]
async fn pre_session_commands_work_without_a_session() {
    let f = fixture().await;
    let status = dispatch(&f.core, None, "vault_status", b"{}")
        .await
        .unwrap();
    let status: Value = serde_json::from_slice(&status).unwrap();
    assert_eq!(status["state"], "unlocked");
    let operators = dispatch(&f.core, None, "vault_list_operators", b"{}")
        .await
        .unwrap();
    let operators: Value = serde_json::from_slice(&operators).unwrap();
    assert_eq!(operators.as_array().unwrap().len(), 1);
    assert_eq!(operators[0]["label"], "Owner");
}

#[tokio::test]
async fn every_command_reaches_its_handler() {
    let f = fixture().await;
    for (command, gate) in REMOTE_COMMANDS {
        if gate == Gate::OpensSession || matches!(command, "vault_lock" | "vault_panic") {
            continue;
        }
        // The IDs of the samples name nothing, so most answers are `not_found` (or, for
        // `request_approve`, the storage error the core gives for an unknown request). A command
        // without a dispatch arm would answer `remote_unsupported`.
        let result = call(&f, command, &sample(command)).await;
        let code = code(result);
        assert!(
            !matches!(code.as_str(), "invalid_request" | "remote_unsupported"),
            "{command}: {code}"
        );
    }
    assert_eq!(code(call(&f, "vault_panic", &json!({})).await), "ok");
    assert_eq!(code(call(&f, "vault_lock", &json!({})).await), "ok");
    assert_eq!(f.core.state(), cerberus_types::VaultStateKind::Sealed);
    let after = call(&f, "item_list", &sample("item_list")).await;
    assert_eq!(code(after), "vault_locked");
}

#[tokio::test]
async fn items_round_trip_through_dispatch() {
    let f = fixture().await;
    let workspace = call(&f, "workspace_put", &sample("workspace_put"))
        .await
        .unwrap();
    let ws = workspace["id"].as_str().unwrap().to_owned();
    let created = call(
        &f,
        "item_create",
        &json!({ "input": note_input(&ws, "remote text") }),
    )
    .await
    .unwrap();
    let item = created["summary"]["id"].as_str().unwrap().to_owned();
    let list = call(&f, "item_list", &sample("item_list")).await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);

    let revealed = dispatch(
        &f.core,
        Some(&f.ctx),
        "item_reveal",
        &bytes(&json!({ "item": item })),
    )
    .await
    .unwrap();
    let revealed: RevealedSecretView = from_body(&revealed).unwrap();
    let PayloadView::Note { text } = revealed.payload else {
        panic!("not a note");
    };
    assert_eq!(text.expose(), "remote text");

    let mut keep = note_input(&ws, "unused");
    keep["payload"] = json!({ "kind": "keep" });
    keep["title"] = json!("Renamed");
    let updated = call(&f, "item_update", &json!({ "item": item, "input": keep }))
        .await
        .unwrap();
    assert_eq!(updated["summary"]["title"], "Renamed");
    let mut keep_new = note_input(&ws, "unused");
    keep_new["payload"] = json!({ "kind": "keep" });
    let refused = call(&f, "item_create", &json!({ "input": keep_new })).await;
    assert_eq!(code(refused), "validation_failed");

    let bad = call(&f, "item_get", &json!({ "item": "not-an-id" })).await;
    assert_eq!(code(bad), "validation_failed");
    assert_eq!(
        code(call(&f, "item_delete", &json!({ "item": item })).await),
        "ok"
    );
    let gone = call(&f, "item_get", &json!({ "item": item })).await;
    assert_eq!(code(gone), "not_found");
}

#[tokio::test]
async fn a_desktop_draft_is_refused() {
    let f = fixture().await;
    let workspace = call(&f, "workspace_put", &sample("workspace_put"))
        .await
        .unwrap();
    let ws = workspace["id"].as_str().unwrap().to_owned();
    let mut input = note_input(&ws, "unused");
    input["payload"] = json!({ "kind": "ssh_key_draft", "draft_id": "draft-1" });
    let created = call(&f, "item_create", &json!({ "input": input.clone() })).await;
    assert_eq!(code(created), "remote_unsupported");
    let item = ItemId::generate().to_string();
    let updated = call(&f, "item_update", &json!({ "item": item, "input": input })).await;
    assert_eq!(code(updated), "remote_unsupported");
    let list = call(&f, "item_list", &sample("item_list")).await.unwrap();
    assert!(list.as_array().unwrap().is_empty());
}
