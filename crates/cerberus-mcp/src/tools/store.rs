//! `store_secret`: `POST /v1/credentials`, or `POST /v1/sessions` for the session kinds.

use cerberus_api::{ApiError, convert};
use cerberus_types::ErrorCode;
use cerberus_types::wire::{
    CreateItemRequest, CreateSessionRequest, Environment, ItemKind, SecretPayload, SessionPayload,
};
use rmcp::model::JsonObject;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::to_value;
use crate::call::{Call, Output};

/// Fuzz entry point: true when `arguments` parse as this tool's input.
pub(super) fn arguments_parse(arguments: JsonObject) -> bool {
    serde_json::from_value::<Input>(serde_json::Value::Object(arguments)).is_ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    kind: ItemKind,
    workspace: String,
    title: String,
    description: Option<String>,
    environment: Environment,
    role_label: Option<String>,
    tags: Option<Vec<String>>,
    target: Option<String>,
    ttl_seconds: Option<u32>,
    value: Value,
}

/// The payload object of the kind: a string stands for the one text field of `api_key`
/// (`key`), `session_token` (`token`) and `note` (`text`); an object holds the fields of the kind.
fn payload_json(kind: ItemKind, value: Value) -> Option<Value> {
    let mut fields = match value {
        Value::String(text) => {
            let name = match kind {
                ItemKind::ApiKey => "key",
                ItemKind::SessionToken => "token",
                ItemKind::Note => "text",
                _ => return None,
            };
            Map::from_iter([(name.to_owned(), Value::String(text))])
        }
        Value::Object(fields) => fields,
        _ => return None,
    };
    fields.insert("kind".to_owned(), serde_json::to_value(kind).ok()?);
    Some(Value::Object(fields))
}

pub async fn run(call: &Call, arguments: JsonObject) -> Result<Output, ApiError> {
    let input: Input = call.parse(arguments)?;
    let invalid = || call.refuse(ErrorCode::InvalidRequest);
    let payload = payload_json(input.kind, input.value).ok_or_else(invalid)?;
    let created = if matches!(
        input.kind,
        ItemKind::SessionToken | ItemKind::BrowserSession
    ) {
        let payload: SessionPayload = serde_json::from_value(payload).map_err(|_| invalid())?;
        let request = CreateSessionRequest {
            workspace: input.workspace,
            title: input.title,
            description: input.description,
            environment: input.environment,
            role_label: input.role_label,
            target: input.target,
            ttl_seconds: input.ttl_seconds,
            payload,
        };
        call.api
            .create_session(&call.ctx, convert::create_session_input(request))
            .await
    } else {
        let payload: SecretPayload = serde_json::from_value(payload).map_err(|_| invalid())?;
        let request = CreateItemRequest {
            workspace: input.workspace,
            title: input.title,
            description: input.description,
            environment: input.environment,
            role_label: input.role_label,
            category: None,
            tags: input.tags,
            target: input.target,
            ttl_seconds: input.ttl_seconds,
            max_uses: None,
            payload,
            totp: None,
        };
        let item = convert::create_item_input(request).map_err(|error| call.fail(error))?;
        call.api.create_item(&call.ctx, item).await
    }
    .map_err(|error| call.fail(error))?;
    Ok(Output::plain(to_value(
        call,
        &convert::created_item(created),
    )?))
}
