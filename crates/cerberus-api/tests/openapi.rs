//! The OpenAPI document generated from the code must match `docs/api/openapi-draft.yaml`:
//! the same paths, methods, operation IDs, status codes, schema names, properties and enums.
//! Differences that are on purpose are listed in `docs/decisions.md` (DEC-T10-8) and the draft
//! carries them, so this test needs no allow-list.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

fn draft() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi-draft.yaml");
    let text = std::fs::read_to_string(path).expect("draft");
    serde_yaml_ng::from_str(&text).expect("yaml")
}

fn generated() -> Value {
    serde_json::to_value(cerberus_api::openapi()).expect("json")
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

fn names(value: &Value, key: &str) -> BTreeSet<String> {
    value[key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

const METHODS: [&str; 4] = ["get", "post", "delete", "put"];

fn ref_name(schema: &Value) -> Option<String> {
    schema["$ref"]
        .as_str()
        .and_then(|r| r.rsplit('/').next())
        .map(str::to_owned)
}

#[test]
fn paths_methods_operations_and_status_codes_match() {
    let (want, got) = (draft(), generated());
    assert_eq!(keys(&want["paths"]), keys(&got["paths"]), "path list");
    let mut problems = Vec::new();
    for (path, item) in want["paths"].as_object().expect("paths") {
        let other = &got["paths"][path];
        let methods = |v: &Value| -> BTreeSet<String> {
            keys(v)
                .into_iter()
                .filter(|k| METHODS.contains(&k.as_str()))
                .collect()
        };
        if methods(item) != methods(other) {
            problems.push(format!(
                "{path}: methods {:?} vs {:?}",
                methods(item),
                methods(other)
            ));
            continue;
        }
        for method in methods(item) {
            let (a, b) = (&item[&method], &other[&method]);
            let at = format!("{method} {path}");
            if a["operationId"] != b["operationId"] {
                problems.push(format!(
                    "{at}: operationId {} vs {}",
                    a["operationId"], b["operationId"]
                ));
            }
            if a["tags"] != b["tags"] {
                problems.push(format!("{at}: tags {} vs {}", a["tags"], b["tags"]));
            }
            if keys(&a["responses"]) != keys(&b["responses"]) {
                problems.push(format!(
                    "{at}: status codes {:?} vs {:?}",
                    keys(&a["responses"]),
                    keys(&b["responses"])
                ));
            }
            let body =
                |v: &Value| ref_name(&v["requestBody"]["content"]["application/json"]["schema"]);
            if body(a) != body(b) {
                problems.push(format!("{at}: request body {:?} vs {:?}", body(a), body(b)));
            }
            let open = |v: &Value| {
                v["security"] == serde_json::json!([]) || v["security"] == serde_json::json!([{}])
            };
            if open(a) != open(b) {
                problems.push(format!("{at}: open route flag differs"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn server_and_security_scheme_match() {
    let (want, got) = (draft(), generated());
    assert_eq!(want["servers"][0]["url"], got["servers"][0]["url"]);
    assert_eq!(
        want["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        got["components"]["securitySchemes"]["bearerAuth"]["scheme"]
    );
    assert_eq!(want["security"], got["security"]);
}

#[test]
fn schema_names_properties_required_and_enums_match() {
    let (want, got) = (draft(), generated());
    let (a, b) = (
        &want["components"]["schemas"],
        &got["components"]["schemas"],
    );
    let mut problems = Vec::new();
    let only_draft: Vec<_> = keys(a).difference(&keys(b)).cloned().collect();
    let only_code: Vec<_> = keys(b).difference(&keys(a)).cloned().collect();
    if !only_draft.is_empty() || !only_code.is_empty() {
        problems.push(format!(
            "schema names: only in draft {only_draft:?}; only in code {only_code:?}"
        ));
    }
    for name in keys(a).intersection(&keys(b)) {
        let (x, y) = (&a[name], &b[name]);
        if keys(&x["properties"]) != keys(&y["properties"]) {
            problems.push(format!(
                "{name}: properties {:?} vs {:?}",
                keys(&x["properties"]),
                keys(&y["properties"])
            ));
        }
        if names(x, "required") != names(y, "required") {
            problems.push(format!(
                "{name}: required {:?} vs {:?}",
                names(x, "required"),
                names(y, "required")
            ));
        }
        if x["enum"].is_array() && names(x, "enum") != names(y, "enum") {
            problems.push(format!(
                "{name}: enum {:?} vs {:?}",
                names(x, "enum"),
                names(y, "enum")
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// ADR-0034 point 5.5, DEC-RM-12: the admin routes are not part of the agent contract.
#[test]
fn agent_openapi_has_no_admin_path() {
    let got = generated();
    let paths = keys(&got["paths"]);
    assert!(!paths.is_empty());
    assert!(
        paths.iter().all(|path| !path.contains("admin")),
        "{paths:?}"
    );
    assert!(
        keys(&draft()["paths"])
            .iter()
            .all(|path| !path.contains("admin")),
        "the draft has no admin path either"
    );
}
