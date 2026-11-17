//! IPC `settings_get` and `settings_set`: one key-value view over the three settings groups.
//!
//! | Group | Keys | Write role |
//! |---|---|---|
//! | Lock triggers (ADR-0026) | `idle_lock_seconds`, `max_unlocked_seconds`, `lock_on_os_lock`, `agent_activity_keeps_unlocked` | operator |
//! | Items (ADR-0007) | `session_ttl_default_seconds`, `session_ttl_max_seconds`, `item_versions_keep` | owner |
//! | Policy (ADR-0018, ADR-0030) | the fields of [`PolicySettings`] | owner |
//!
//! Each group keeps its own setter, role check and audit event; `settings_set` reads the group,
//! changes one key and calls that setter.

use std::collections::BTreeMap;

use cerberus_types::FieldProblem;
use serde_json::Value;

use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::items::{ItemSettings, setting_keys as item_keys};
use crate::policy::PolicySettings;
use crate::vault::{LockSettings, VaultService, setting_keys as lock_keys};

/// Every setting by key, as JSON values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingsView {
    /// Key to value.
    pub values: BTreeMap<String, Value>,
}

fn bad(key: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: key.to_owned(),
        problem: text.to_owned(),
    }])
}

fn number(key: &str, value: &Value) -> Result<u32, CoreError> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| bad(key, "must be a whole number"))
}

fn number_or_off(key: &str, value: &Value) -> Result<Option<u32>, CoreError> {
    if value.is_null() {
        Ok(None)
    } else {
        number(key, value).map(Some)
    }
}

fn flag(key: &str, value: &Value) -> Result<bool, CoreError> {
    value
        .as_bool()
        .ok_or_else(|| bad(key, "must be true or false"))
}

impl VaultService {
    /// IPC `settings_get`. Any role.
    ///
    /// # Errors
    /// `Locked`, the role check, or a storage error.
    pub async fn settings_get(&self, ctx: &OperatorContext) -> Result<SettingsView, CoreError> {
        let lock = self.lock_settings(ctx).await?;
        let items = self.item_settings(ctx).await?;
        let policy = self.policy_settings(ctx).await?;
        let mut values = BTreeMap::new();
        values.insert(
            lock_keys::IDLE_LOCK_SECONDS.to_owned(),
            lock.idle_lock_seconds.into(),
        );
        values.insert(
            lock_keys::MAX_UNLOCKED_SECONDS.to_owned(),
            lock.max_unlocked_seconds.into(),
        );
        values.insert(
            lock_keys::LOCK_ON_OS_LOCK.to_owned(),
            lock.lock_on_os_lock.into(),
        );
        values.insert(
            lock_keys::AGENT_ACTIVITY_KEEPS_UNLOCKED.to_owned(),
            lock.agent_activity_keeps_unlocked.into(),
        );
        values.insert(
            item_keys::SESSION_TTL_DEFAULT_SECONDS.to_owned(),
            items.session_ttl_default_seconds.into(),
        );
        values.insert(
            item_keys::SESSION_TTL_MAX_SECONDS.to_owned(),
            items.session_ttl_max_seconds.into(),
        );
        values.insert(
            item_keys::ITEM_VERSIONS_KEEP.to_owned(),
            items.versions_keep.into(),
        );
        if let Value::Object(map) = serde_json::to_value(policy).map_err(|_| CoreError::Corrupt)? {
            values.extend(map);
        }
        Ok(SettingsView { values })
    }

    /// IPC `settings_set`: changes one key (see the module table for the roles) and returns
    /// all settings.
    ///
    /// # Errors
    /// `Validation` (unknown key, wrong type or out of range), `Locked`, the role check, or a
    /// storage error.
    pub async fn settings_set(
        &self,
        ctx: &OperatorContext,
        key: &str,
        value: Value,
    ) -> Result<SettingsView, CoreError> {
        match key {
            lock_keys::IDLE_LOCK_SECONDS
            | lock_keys::MAX_UNLOCKED_SECONDS
            | lock_keys::LOCK_ON_OS_LOCK
            | lock_keys::AGENT_ACTIVITY_KEEPS_UNLOCKED => {
                let mut lock: LockSettings = self.lock_settings(ctx).await?;
                match key {
                    lock_keys::IDLE_LOCK_SECONDS => {
                        lock.idle_lock_seconds = number_or_off(key, &value)?;
                    }
                    lock_keys::MAX_UNLOCKED_SECONDS => {
                        lock.max_unlocked_seconds = number_or_off(key, &value)?;
                    }
                    lock_keys::LOCK_ON_OS_LOCK => lock.lock_on_os_lock = flag(key, &value)?,
                    _ => lock.agent_activity_keeps_unlocked = flag(key, &value)?,
                }
                self.set_lock_settings(ctx, lock).await?;
            }
            item_keys::SESSION_TTL_DEFAULT_SECONDS
            | item_keys::SESSION_TTL_MAX_SECONDS
            | item_keys::ITEM_VERSIONS_KEEP => {
                let mut items: ItemSettings = self.item_settings(ctx).await?;
                let n = number(key, &value)?;
                match key {
                    item_keys::SESSION_TTL_DEFAULT_SECONDS => items.session_ttl_default_seconds = n,
                    item_keys::SESSION_TTL_MAX_SECONDS => items.session_ttl_max_seconds = n,
                    _ => items.versions_keep = n,
                }
                self.set_item_settings(ctx, items).await?;
            }
            _ => {
                let policy = self.policy_settings(ctx).await?;
                let mut json = serde_json::to_value(policy).map_err(|_| CoreError::Corrupt)?;
                let Some(slot) = json.get_mut(key) else {
                    return Err(bad(key, "is not a setting"));
                };
                *slot = value;
                let policy: PolicySettings =
                    serde_json::from_value(json).map_err(|_| bad(key, "must be a whole number"))?;
                self.set_policy_settings(ctx, policy).await?;
            }
        }
        self.settings_get(ctx).await
    }
}
