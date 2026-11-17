//! Conversions between Rust values and SQLite column values. A bad stored value is `Corrupt`.

use std::str::FromStr;

use jiff::Timestamp;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::StoreError;

/// Unix milliseconds of a timestamp (ADR-0022).
pub(crate) fn to_ms(at: Timestamp) -> i64 {
    at.as_millisecond()
}

pub(crate) fn from_ms(ms: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_millisecond(ms).map_err(|_| StoreError::Corrupt)
}

pub(crate) fn opt_to_ms(at: Option<Timestamp>) -> Option<i64> {
    at.map(to_ms)
}

pub(crate) fn opt_from_ms(ms: Option<i64>) -> Result<Option<Timestamp>, StoreError> {
    ms.map(from_ms).transpose()
}

/// Parses an ID from its stored text.
pub(crate) fn parse_id<T: FromStr>(text: &str) -> Result<T, StoreError> {
    text.parse().map_err(|_| StoreError::Corrupt)
}

pub(crate) fn opt_parse_id<T: FromStr>(text: Option<&str>) -> Result<Option<T>, StoreError> {
    text.map(parse_id).transpose()
}

/// The text of a unit enum, as its serde name (the wire value, which is also the CHECK value).
pub(crate) fn enum_text<T: Serialize>(value: &T) -> Result<String, StoreError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => Ok(text),
        _ => Err(StoreError::Corrupt),
    }
}

pub(crate) fn parse_enum<T: DeserializeOwned>(text: &str) -> Result<T, StoreError> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| StoreError::Corrupt)
}

pub(crate) fn opt_parse_enum<T: DeserializeOwned>(
    text: Option<&str>,
) -> Result<Option<T>, StoreError> {
    text.map(parse_enum).transpose()
}

pub(crate) fn bytes32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Corrupt)
}

pub(crate) fn opt_bytes32(bytes: Option<&[u8]>) -> Result<Option<[u8; 32]>, StoreError> {
    bytes.map(bytes32).transpose()
}

pub(crate) fn to_u32(value: i64) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError::Corrupt)
}

pub(crate) fn opt_to_u32(value: Option<i64>) -> Result<Option<u32>, StoreError> {
    value.map(to_u32).transpose()
}

pub(crate) fn to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt)
}

/// A `u64` as an SQLite INTEGER. Sequence numbers never reach `i64::MAX`.
pub(crate) fn from_u64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Corrupt)
}

/// Scopes as the stored space-separated list (ADR-0016).
pub(crate) fn scopes_text(scopes: &[cerberus_types::Scope]) -> Result<String, StoreError> {
    let names: Result<Vec<String>, StoreError> = scopes.iter().map(enum_text).collect();
    Ok(names?.join(" "))
}

pub(crate) fn parse_scopes(text: &str) -> Result<Vec<cerberus_types::Scope>, StoreError> {
    text.split_whitespace().map(parse_enum).collect()
}

/// IP allowlist as the stored space-separated CIDR list. Empty = any address.
pub(crate) fn nets_text(nets: &[ipnet::IpNet]) -> String {
    nets.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn parse_nets(text: &str) -> Result<Vec<ipnet::IpNet>, StoreError> {
    text.split_whitespace().map(parse_id).collect()
}
