//! `ssh_prepare`: `POST /v1/credentials/{id}/ssh-prepare` (T22).
//!
//! The same function as the REST route ([`cerberus_api::routes::prepare_ssh`]) on the same shared
//! ssh-agent bridge, so both give the same socket and the same fields; this tool adds
//! `outcome: "ready"` (or `"pending"`). It waits for a person like `get_totp`. The answer holds no
//! secret value: the private key stays in the vault.

use cerberus_api::ApiError;
use cerberus_api::routes::{SshPrepared, prepare_ssh};
use cerberus_core::CoreError;
use cerberus_core::agent_api::PendingResult;
use cerberus_types::wire::SshPrepareRequest;
use cerberus_types::{AccessRequestStatus, ItemId};
use rmcp::model::JsonObject;
use serde::Deserialize;
use uuid::Uuid;

use super::{pending_output, to_value, wait_of};
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    item_id: Uuid,
    ttl_seconds: Option<u32>,
    lease_id: Option<Uuid>,
    purpose: String,
    wait_seconds: Option<u32>,
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let wait = wait_of(call, input.wait_seconds)?;
    let item = ItemId::from_uuid(input.item_id);
    let first = prepare(call, item, &input, input.lease_id).await?;
    let outcome = match first {
        SshPrepared::Pending(pending) if !wait.is_zero() => {
            let request = pending.access_request.clone();
            let decided = call
                .wait_for(request.id, request, wait)
                .await
                .map_err(|error| call.fail(error))?;
            match decided.status {
                AccessRequestStatus::Approved => {
                    let lease = decided.lease.as_ref().map(|lease| *lease.id.as_uuid());
                    prepare(call, item, &input, lease).await?
                }
                AccessRequestStatus::Denied => {
                    return Err(call.fail(CoreError::ApprovalDenied(Some(decided.id))));
                }
                _ => SshPrepared::Pending(PendingResult {
                    request_id: pending.request_id,
                    access_request: decided,
                }),
            }
        }
        other => other,
    };
    match outcome {
        SshPrepared::Ready(ready) => {
            Ok(Output::plain(to_value(call, &ready)?).with_outcome("ready"))
        }
        SshPrepared::Pending(pending) => pending_output(call, pending),
    }
}

async fn prepare(
    call: &Call,
    item: ItemId,
    input: &Input,
    lease: Option<Uuid>,
) -> Result<SshPrepared, ApiError> {
    let body = SshPrepareRequest {
        purpose: input.purpose.clone(),
        ttl_seconds: input.ttl_seconds,
        lease_id: lease,
    };
    prepare_ssh(&call.core, &call.ctx, item, body).await
}
