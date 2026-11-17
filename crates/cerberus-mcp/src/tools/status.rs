//! `vault_status`: `GET /v1/status`.

use cerberus_api::{ApiError, convert};
use cerberus_core::CoreError;
use rmcp::model::JsonObject;
use serde::Deserialize;
use serde_json::json;

use super::to_value;
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let Input {} = call.parse(arguments)?;
    match call.api.status(&call.ctx).await {
        Ok(view) => Ok(Output::plain(to_value(
            call,
            &convert::status_response(view),
        )?)),
        // The tool that tells the agent about the lock does not fail on it (ADR-0008).
        Err(CoreError::Locked) => Ok(Output::plain(json!({ "vault": "locked" }))),
        Err(error) => Err(call.fail(error)),
    }
}
