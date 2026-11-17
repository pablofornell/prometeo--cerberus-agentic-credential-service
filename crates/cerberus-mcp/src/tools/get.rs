//! `get_credential`: `POST /v1/credentials/resolve` (`mode: best`) or `POST /v1/credentials/{id}/reveal`.

use cerberus_api::{ApiError, convert};
use cerberus_core::CoreError;
use cerberus_core::agent_api::{PendingResult, ResolveResult, RevealInput, RevealOutcome};
use cerberus_types::wire::{
    CandidatesBody, ItemKind, ResolveMode, ResolveRequest, ResolveResponse,
};
use cerberus_types::{AccessRequestStatus, ErrorCode, ItemId, LeaseId};
use rmcp::model::JsonObject;
use serde::Deserialize;
use uuid::Uuid;

use super::{pending_output, secret_output, to_value, wait_of};
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    id: Option<Uuid>,
    app: Option<String>,
    environment: Option<String>,
    role: Option<String>,
    kind: Option<ItemKind>,
    hint: Option<String>,
    lease_id: Option<Uuid>,
    ttl_seconds: Option<u32>,
    purpose: String,
    wait_seconds: Option<u32>,
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let wait = wait_of(call, input.wait_seconds)?;
    let first = match (input.id, input.app.clone()) {
        (Some(id), None) => reveal(call, ItemId::from_uuid(id), input.lease_id, &input).await?,
        (None, Some(app)) if input.lease_id.is_none() => {
            let request = convert::resolve_input(ResolveRequest {
                app,
                environment: input.environment.clone(),
                role: input.role.clone(),
                kind: input.kind,
                hint: input.hint.clone(),
                purpose: input.purpose.clone(),
                mode: Some(ResolveMode::Best),
            });
            call.api
                .resolve(&call.ctx, request)
                .await
                .map_err(|error| call.fail(error))?
        }
        _ => return Err(call.refuse(ErrorCode::InvalidRequest)),
    };
    let result = match first {
        ResolveResult::Pending(pending) if !wait.is_zero() => {
            after_wait(call, pending, wait, &input).await?
        }
        other => other,
    };
    output(call, result)
}

async fn reveal(
    call: &Call,
    id: ItemId,
    lease: Option<Uuid>,
    input: &Input,
) -> Result<ResolveResult, ApiError> {
    let request = RevealInput {
        purpose: input.purpose.clone(),
        lease_id: lease.map(LeaseId::from_uuid),
        ttl_seconds: input.ttl_seconds,
    };
    match call
        .api
        .reveal(&call.ctx, id, request)
        .await
        .map_err(|error| call.fail(error))?
    {
        RevealOutcome::Secret(secret) => Ok(ResolveResult::Secret(secret)),
        RevealOutcome::Pending(pending) => Ok(ResolveResult::Pending(pending)),
    }
}

/// Waits for the person. When they approve, reads the secret with the new lease.
async fn after_wait(
    call: &Call,
    pending: PendingResult,
    wait: std::time::Duration,
    input: &Input,
) -> Result<ResolveResult, ApiError> {
    let request = pending.access_request.clone();
    let decided = call
        .wait_for(request.id, request, wait)
        .await
        .map_err(|error| call.fail(error))?;
    match decided.status {
        AccessRequestStatus::Approved => {
            let lease = decided.lease.as_ref().map(|lease| *lease.id.as_uuid());
            reveal(call, decided.item_id, lease, input).await
        }
        AccessRequestStatus::Denied => Err(call.fail(CoreError::ApprovalDenied(Some(decided.id)))),
        _ => Ok(ResolveResult::Pending(PendingResult {
            request_id: pending.request_id,
            access_request: decided,
        })),
    }
}

fn output(call: &Call, result: ResolveResult) -> Result<Output, ApiError> {
    match result {
        ResolveResult::Secret(secret) => secret_output(call, *secret),
        ResolveResult::Pending(pending) => pending_output(call, pending),
        // `find_credentials` is the tool for a list; here a list only means "no clear winner".
        ResolveResult::Ambiguous(list) | ResolveResult::Candidates(list) => {
            let body = CandidatesBody {
                candidates: list.into_iter().map(convert::candidate).collect(),
            };
            Ok(Output::plain(to_value(
                call,
                &ResolveResponse::Ambiguous(body),
            )?))
        }
    }
}
