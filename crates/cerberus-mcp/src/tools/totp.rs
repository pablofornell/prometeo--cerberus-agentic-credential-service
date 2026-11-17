//! `get_totp`: `POST /v1/credentials/{id}/totp`.

use cerberus_api::ApiError;
use cerberus_core::CoreError;
use cerberus_core::agent_api::{PendingResult, TotpInput, TotpOutcome};
use cerberus_types::{AccessRequestStatus, ItemId, LeaseId};
use rmcp::model::JsonObject;
use serde::Deserialize;
use uuid::Uuid;

use super::{code_output, pending_output, wait_of};
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    item_id: Uuid,
    lease_id: Option<Uuid>,
    purpose: String,
    wait_seconds: Option<u32>,
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let wait = wait_of(call, input.wait_seconds)?;
    let item = ItemId::from_uuid(input.item_id);
    let first = code(call, item, input.lease_id, &input.purpose).await?;
    let outcome = match first {
        TotpOutcome::Pending(pending) if !wait.is_zero() => {
            let request = pending.access_request.clone();
            let decided = call
                .wait_for(request.id, request, wait)
                .await
                .map_err(|error| call.fail(error))?;
            match decided.status {
                AccessRequestStatus::Approved => {
                    let lease = decided.lease.as_ref().map(|lease| *lease.id.as_uuid());
                    code(call, item, lease, &input.purpose).await?
                }
                AccessRequestStatus::Denied => {
                    return Err(call.fail(CoreError::ApprovalDenied(Some(decided.id))));
                }
                _ => TotpOutcome::Pending(PendingResult {
                    request_id: pending.request_id,
                    access_request: decided,
                }),
            }
        }
        other => other,
    };
    match outcome {
        TotpOutcome::Code(result) => code_output(call, *result),
        TotpOutcome::Pending(pending) => pending_output(call, pending),
    }
}

async fn code(
    call: &Call,
    item: ItemId,
    lease: Option<Uuid>,
    purpose: &str,
) -> Result<TotpOutcome, ApiError> {
    let request = TotpInput {
        purpose: purpose.to_owned(),
        lease_id: lease.map(LeaseId::from_uuid),
    };
    call.api
        .totp(&call.ctx, item, request)
        .await
        .map_err(|error| call.fail(error))
}
