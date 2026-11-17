//! `find_credentials`: `POST /v1/credentials/resolve` with `mode: candidates`.

use cerberus_api::{ApiError, convert};
use cerberus_core::agent_api::ResolveResult;
use cerberus_types::ErrorCode;
use cerberus_types::wire::{
    CandidatesBody, ItemKind, ResolveMode, ResolveRequest, ResolveResponse,
};
use rmcp::model::JsonObject;
use serde::Deserialize;

use super::to_value;
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    app: String,
    environment: Option<String>,
    role: Option<String>,
    kind: Option<ItemKind>,
    hint: Option<String>,
    purpose: String,
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let request = convert::resolve_input(ResolveRequest {
        app: input.app,
        environment: input.environment,
        role: input.role,
        kind: input.kind,
        hint: input.hint,
        purpose: input.purpose,
        mode: Some(ResolveMode::Candidates),
    });
    match call
        .api
        .resolve(&call.ctx, request)
        .await
        .map_err(|error| call.fail(error))?
    {
        ResolveResult::Candidates(list) => {
            let body = CandidatesBody {
                candidates: list.into_iter().map(convert::candidate).collect(),
            };
            Ok(Output::plain(to_value(
                call,
                &ResolveResponse::Candidates(body),
            )?))
        }
        ResolveResult::Secret(_) | ResolveResult::Pending(_) | ResolveResult::Ambiguous(_) => {
            Err(call.refuse(ErrorCode::Internal))
        }
    }
}
