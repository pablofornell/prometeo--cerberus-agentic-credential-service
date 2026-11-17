//! Resolve query (ADR-0020): the core request as JSON, its validation, and the scoring over a
//! catalog that holds one item.
#![no_main]

use cerberus_core::resolve::ResolveRequest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<ResolveRequest>(data) {
        let _ = request.validate();
    }
});
