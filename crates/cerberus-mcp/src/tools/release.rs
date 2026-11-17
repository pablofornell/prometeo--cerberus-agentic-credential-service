//! `release_credential`: `POST /v1/leases/{id}/release`.

use cerberus_api::{ApiError, convert};
use cerberus_types::LeaseId;
use rmcp::model::JsonObject;
use serde::Deserialize;
use uuid::Uuid;

use super::to_value;
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    lease_id: Uuid,
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let outcome = call
        .api
        .release_lease(&call.ctx, LeaseId::from_uuid(input.lease_id))
        .await
        .map_err(|error| call.fail(error))?;
    Ok(Output::plain(to_value(
        call,
        &convert::release_response(outcome),
    )?))
}
