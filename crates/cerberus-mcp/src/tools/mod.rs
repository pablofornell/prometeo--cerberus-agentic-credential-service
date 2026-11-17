//! One file per tool. Each tool calls the same `AgentApi` function as its REST route.

use std::time::Duration;

use cerberus_api::{ApiError, convert};
use cerberus_core::agent_api::{PendingResult, SecretResult, TotpResult};
use cerberus_types::ErrorCode;
use rmcp::model::JsonObject;
use serde::Serialize;
use serde_json::Value;

use crate::call::{Call, Output};

mod find;
mod get;
mod release;
mod request;
mod ssh;
mod status;
mod store;
mod totp;

/// Seconds a waiting tool waits when the caller gives no `wait_seconds` (ADR-0018).
const DEFAULT_WAIT_SECONDS: u32 = 60;
/// The most `wait_seconds` a caller may ask for (ADR-0018).
const MAX_WAIT_SECONDS: u32 = 120;

/// Fuzz entry point (see `fuzz/`): parses `arguments` as the input of tool `name`. `None` when
/// there is no such tool, else whether the arguments are valid.
#[doc(hidden)]
#[must_use]
pub fn arguments_parse(name: &str, arguments: JsonObject) -> Option<bool> {
    Some(match name {
        "vault_status" => status::arguments_parse(arguments),
        "find_credentials" => find::arguments_parse(arguments),
        "get_credential" => get::arguments_parse(arguments),
        "request_access" => request::arguments_parse(arguments),
        "get_totp" => totp::arguments_parse(arguments),
        "store_secret" => store::arguments_parse(arguments),
        "release_credential" => release::arguments_parse(arguments),
        "ssh_prepare" => ssh::arguments_parse(arguments),
        _ => return None,
    })
}

/// Runs the tool `name`. `None` when there is no such tool.
pub async fn run(
    name: &str,
    call: &Call,
    arguments: JsonObject,
) -> Option<Result<Output, ApiError>> {
    Some(match name {
        "vault_status" => status::run(call, arguments).await,
        "find_credentials" => find::run(call, arguments).await,
        "get_credential" => get::run(call, arguments).await,
        "request_access" => request::run(call, arguments).await,
        "get_totp" => totp::run(call, arguments).await,
        "store_secret" => store::run(call, arguments).await,
        "release_credential" => release::run(call, arguments).await,
        "ssh_prepare" => ssh::run(call, arguments).await,
        _ => return None,
    })
}

/// The wait of a call: `wait_seconds` (default 60, at most 120).
fn wait_of(call: &Call, seconds: Option<u32>) -> Result<Duration, ApiError> {
    let seconds = seconds.unwrap_or(DEFAULT_WAIT_SECONDS);
    if seconds > MAX_WAIT_SECONDS {
        return Err(call.refuse(ErrorCode::InvalidRequest));
    }
    Ok(Duration::from_secs(u64::from(seconds)))
}

fn to_value<T: Serialize>(call: &Call, value: &T) -> Result<Value, ApiError> {
    serde_json::to_value(value).map_err(|_| call.refuse(ErrorCode::Internal))
}

/// `outcome: secret`.
fn secret_output(call: &Call, result: SecretResult) -> Result<Output, ApiError> {
    let wire = convert::secret_response(result)?;
    Ok(Output::secret(to_value(call, &wire)?).with_outcome("secret"))
}

/// `outcome: code`.
fn code_output(call: &Call, result: TotpResult) -> Result<Output, ApiError> {
    let wire = convert::totp_response(result)?;
    Ok(Output::secret(to_value(call, &wire)?).with_outcome("code"))
}

/// `outcome: pending`.
fn pending_output(call: &Call, result: PendingResult) -> Result<Output, ApiError> {
    let wire = convert::pending_response(result)?;
    Ok(Output::plain(to_value(call, &wire)?).with_outcome("pending"))
}
