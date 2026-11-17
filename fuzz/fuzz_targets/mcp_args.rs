//! MCP tool arguments: the first byte picks the tool, the rest is a JSON object.
#![no_main]

use cerberus_mcp::TOOL_NAMES;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    let name = TOOL_NAMES[usize::from(pick) % TOOL_NAMES.len()];
    if let Ok(arguments) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body) {
        assert!(cerberus_mcp::arguments_parse(name, arguments).is_some());
    }
});
