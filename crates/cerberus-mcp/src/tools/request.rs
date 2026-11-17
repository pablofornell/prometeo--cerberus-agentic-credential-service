//! `request_access`: `POST /v1/requests`, then a bounded wait for the person.

use cerberus_api::{ApiError, convert};
use cerberus_types::AccessRequestStatus;
use cerberus_types::wire::{AccessPermission, CreateAccessRequest};
use rmcp::model::JsonObject;
use serde::Deserialize;
use uuid::Uuid;

use super::{to_value, wait_of};
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    item_id: Uuid,
    permission: Option<AccessPermission>,
    reason: String,
    ttl_seconds: Option<u32>,
    wait_seconds: Option<u32>,
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let wait = wait_of(call, input.wait_seconds)?;
    let request = convert::create_access_input(CreateAccessRequest {
        item_id: input.item_id,
        permission: input.permission,
        reason: input.reason,
        ttl_seconds: input.ttl_seconds,
    });
    let mut view = call
        .api
        .request_access(&call.ctx, request)
        .await
        .map_err(|error| call.fail(error))?;
    if view.status == AccessRequestStatus::Pending && !wait.is_zero() {
        view = call
            .wait_for(view.id, view, wait)
            .await
            .map_err(|error| call.fail(error))?;
    }
    let wire = convert::access_request_view(view, call.request_id)?;
    Ok(Output::plain(to_value(call, &wire)?))
}
