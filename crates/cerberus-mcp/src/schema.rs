//! The tool list: names, descriptions, annotations and the JSON schemas of
//! `docs/api/mcp-tools.md` (embedded as `schemas.json`; a test compares them with the document).

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};

use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde_json::Value;

const SCHEMAS: &str = include_str!("schemas.json");

/// Tool names. Order matches `docs/api/mcp-tools.md`.
pub const TOOL_NAMES: [&str; 8] = [
    "vault_status",
    "find_credentials",
    "get_credential",
    "request_access",
    "get_totp",
    "store_secret",
    "release_credential",
    "ssh_prepare",
];

/// What the model reads about each tool. Tools that return a secret say not to print it.
const DESCRIPTIONS: [(&str, &str); 8] = [
    (
        "vault_status",
        "Check if the Cerberus vault is unlocked and who you are. Call this first if other tools return vault_locked.",
    ),
    (
        "find_credentials",
        "Find credentials by app, environment and role. Returns candidates with metadata only, never secret values. Use get_credential with an id to get the secret.",
    ),
    (
        "get_credential",
        "Get a secret. Give either an item id, or app/environment/role to pick the best match. The result is a secret: never print it, log it or repeat it in your answer, and use it only for the task. If a person must approve, this waits up to wait_seconds and may return pending.",
    ),
    (
        "request_access",
        "Ask a person for access to an item before you need it. Give a short, true reason. The person sees the reason as untrusted text. Waits up to wait_seconds.",
    ),
    (
        "get_totp",
        "Get the current one-time code (TOTP) of a login item. The seed stays in the vault. The code is a secret: never print it or log it.",
    ),
    (
        "store_secret",
        "Save a secret in the vault, for example a session token you just got. Session kinds need ttl_seconds or use the default of 3600 seconds. Do not repeat the secret in your answer.",
    ),
    (
        "release_credential",
        "Give back a lease when you are done with a secret. Forget the secret value after this call.",
    ),
    (
        "ssh_prepare",
        "Get an ssh-agent socket for an SSH key item. Set SSH_AUTH_SOCK to socket_path. The private key never leaves the vault.",
    ),
];

/// The tools, built once. The embedded schemas are checked by a test, so an `Err` here is a build error.
static TOOLS: LazyLock<Result<Vec<Tool>, String>> = LazyLock::new(build);

/// The tool list of `tools/list`.
///
/// # Errors
/// A text that says what is wrong with the embedded schemas.
pub fn tools() -> Result<Vec<Tool>, String> {
    TOOLS.clone()
}

/// The definition of one tool.
#[must_use]
pub fn tool(name: &str) -> Option<Tool> {
    TOOLS
        .as_ref()
        .ok()?
        .iter()
        .find(|tool| tool.name == name)
        .cloned()
}

fn object(value: &Value) -> Result<JsonObject, String> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| "schema is not an object".to_owned())
}

/// Collects the names of the `$defs` that `value` uses, and the ones those use.
fn used_defs(value: &Value, defs: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            if let Some(name) = text.strip_prefix("#/$defs/")
                && out.insert(name.to_owned())
                && let Some(def) = defs.get(name)
            {
                used_defs(def, defs, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| used_defs(item, defs, out)),
        Value::Object(map) => map.values().for_each(|item| used_defs(item, defs, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The schema of a tool with the `$defs` it uses. An output schema gets `"type": "object"` at the
/// root when it has none (MCP wants an object schema; every branch is an object).
fn with_defs(schema: &Value, defs: &Value, root_object: bool) -> Result<JsonObject, String> {
    let mut out = object(schema)?;
    if root_object && !out.contains_key("type") {
        out.insert("type".to_owned(), Value::String("object".to_owned()));
    }
    let mut used = BTreeSet::new();
    used_defs(schema, defs, &mut used);
    if !used.is_empty() {
        let mut selected = serde_json::Map::new();
        for name in used {
            let def = defs
                .get(&name)
                .ok_or_else(|| format!("missing $defs/{name}"))?;
            selected.insert(name, def.clone());
        }
        out.insert("$defs".to_owned(), Value::Object(selected));
    }
    Ok(out)
}

fn annotations(name: &str) -> ToolAnnotations {
    let base = ToolAnnotations::new().open_world(false);
    match name {
        "vault_status" | "find_credentials" | "get_totp" => base.read_only(true),
        "release_credential" => base.destructive(true),
        _ => base,
    }
}

fn build() -> Result<Vec<Tool>, String> {
    let all: Value = serde_json::from_str(SCHEMAS).map_err(|error| error.to_string())?;
    let defs = all.get("defs").ok_or("no defs")?;
    let mut tools = Vec::new();
    for name in TOOL_NAMES {
        let entry = all
            .get("tools")
            .and_then(|tools| tools.get(name))
            .ok_or_else(|| format!("no schema for {name}"))?;
        let input = with_defs(entry.get("input").ok_or("no input")?, defs, false)?;
        let output = with_defs(entry.get("output").ok_or("no output")?, defs, true)?;
        let description = DESCRIPTIONS
            .iter()
            .find(|(tool, _)| *tool == name)
            .map(|(_, text)| *text)
            .ok_or_else(|| format!("no description for {name}"))?;
        tools.push(
            Tool::new(name, description, Arc::new(input))
                .with_raw_output_schema(Arc::new(output))
                .annotate(annotations(name)),
        );
    }
    Ok(tools)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document the schemas must match.
    fn doc() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api/mcp-tools.md");
        std::fs::read_to_string(path).expect("docs/api/mcp-tools.md")
    }

    fn json_block(text: &str) -> Value {
        let start = text.find("```json\n").expect("a json block") + "```json\n".len();
        let end = start + text[start..].find("```").expect("end of block");
        serde_json::from_str(&text[start..end]).expect("valid JSON in the document")
    }

    fn section<'a>(doc: &'a str, name: &str) -> &'a str {
        let start = doc
            .find(&format!("\n### `{name}`"))
            .unwrap_or_else(|| panic!("no section for {name}"));
        let rest = &doc[start + 1..];
        let end = rest[4..].find("\n## ").map_or(rest.len(), |i| i + 4);
        let end = rest[4..end].find("\n### ").map_or(end, |i| i + 4);
        &rest[..end]
    }

    fn doc_defs(doc: &str) -> Value {
        let start = doc.find("## Shared definitions").expect("definitions");
        json_block(&doc[start..])["$defs"].clone()
    }

    fn doc_schema(text: &str, label: &str) -> Option<Value> {
        let marker = format!("{label}:\n```json\n");
        let start = text.find(&marker)? + label.len() + 2;
        Some(json_block(&text[start..]))
    }

    fn doc_description(text: &str) -> String {
        let start = text.find("Description").expect("description");
        let open = start + text[start..].find('"').expect("open quote") + 1;
        let close = open + text[open..].find('"').expect("close quote");
        text[open..close]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A schema without its `$defs`, and the names in them.
    fn split(schema: &JsonObject) -> (Value, BTreeSet<String>, JsonObject) {
        let mut plain = schema.clone();
        let defs = plain
            .remove("$defs")
            .and_then(|defs| defs.as_object().cloned())
            .unwrap_or_default();
        (Value::Object(plain), defs.keys().cloned().collect(), defs)
    }

    #[test]
    fn the_embedded_schemas_parse_and_name_every_tool() {
        let tools = tools().expect("schemas");
        let names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
        assert_eq!(names, TOOL_NAMES);
    }

    #[test]
    fn tool_schemas_match_docs_api_mcp_tools_md() {
        let doc = doc();
        let defs = doc_defs(&doc);
        for tool in tools().expect("schemas") {
            let name = tool.name.to_string();
            let text = section(&doc, &name);
            let expected_input = doc_schema(text, "Input").expect("input schema in the doc");
            let expected_output = doc_schema(text, "Output").unwrap_or_else(|| {
                // `Output: `#/$defs/Name``: a reference in prose.
                let start = text.find("Output: `#/$defs/").expect("output") + "Output: `".len();
                let end = start + text[start..].find('`').expect("end");
                serde_json::json!({ "$ref": &text[start..end] })
            });
            for (label, schema, expected, root_object) in [
                ("input", &tool.input_schema, expected_input, false),
                (
                    "output",
                    tool.output_schema.as_ref().expect("output schema"),
                    expected_output,
                    true,
                ),
            ] {
                let (plain, names, own_defs) = split(schema);
                let mut expected = expected;
                if root_object && let Some(map) = expected.as_object_mut() {
                    map.entry("type")
                        .or_insert_with(|| Value::String("object".to_owned()));
                }
                assert_eq!(plain, expected, "{name} {label} differs from the doc");
                let mut used = BTreeSet::new();
                used_defs(&expected, &defs, &mut used);
                assert_eq!(names, used, "{name} {label} has the wrong $defs");
                for (def_name, def) in own_defs {
                    assert_eq!(Some(&def), defs.get(&def_name), "{name} $defs/{def_name}");
                }
            }
            assert_eq!(
                tool.description
                    .as_deref()
                    .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" ")),
                Some(doc_description(text)),
                "{name} description differs from the doc"
            );
        }
    }

    #[test]
    fn annotations_match_adr_0029() {
        for tool in tools().expect("schemas") {
            let hints = tool.annotations.expect("annotations");
            assert_eq!(hints.open_world_hint, Some(false));
            let name = tool.name.to_string();
            assert_eq!(
                hints.read_only_hint == Some(true),
                ["vault_status", "find_credentials", "get_totp"].contains(&name.as_str()),
                "{name}"
            );
            assert_eq!(
                hints.destructive_hint == Some(true),
                name == "release_credential",
                "{name}"
            );
        }
    }
}
