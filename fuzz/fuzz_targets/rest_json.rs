//! JSON bodies of the REST routes (cerberus-types wire DTOs), and the conversions into core input.
#![no_main]

use cerberus_api::convert;
use cerberus_types::wire::{
    CreateAccessRequest, CreateItemRequest, CreateSessionRequest, ResolveRequest, RevealRequest,
    SecretPayload, SshPrepareRequest, TotpRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&kind, body)) = data.split_first() else {
        return;
    };
    match kind % 8 {
        0 => {
            if let Ok(req) = serde_json::from_slice::<ResolveRequest>(body) {
                let _ = convert::resolve_input(req).validate();
            }
        }
        1 => {
            if let Ok(req) = serde_json::from_slice::<RevealRequest>(body) {
                let _ = convert::reveal_input(req);
            }
        }
        2 => {
            if let Ok(req) = serde_json::from_slice::<TotpRequest>(body) {
                let _ = convert::totp_input(req);
            }
        }
        3 => {
            if let Ok(req) = serde_json::from_slice::<CreateItemRequest>(body) {
                let _ = convert::create_item_input(req);
            }
        }
        4 => {
            if let Ok(req) = serde_json::from_slice::<CreateSessionRequest>(body) {
                let _ = convert::create_session_input(req);
            }
        }
        5 => {
            if let Ok(req) = serde_json::from_slice::<CreateAccessRequest>(body) {
                let _ = convert::create_access_input(req);
            }
        }
        6 => {
            if let Ok(req) = serde_json::from_slice::<SshPrepareRequest>(body) {
                let _ = convert::ssh_prepare_input(req);
            }
        }
        _ => {
            if let Ok(payload) = serde_json::from_slice::<SecretPayload>(body) {
                let _ = convert::core_payload(payload, None);
            }
        }
    }
});
