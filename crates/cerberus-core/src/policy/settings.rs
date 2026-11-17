//! Policy, approval and lease settings (ADR-0018, ADR-0019, ADR-0030). One sealed settings row,
//! [`POLICY_SETTINGS_KEY`], with a JSON value. A missing row gives the defaults. Owner only.

use cerberus_types::FieldProblem;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Key of the sealed settings row.
pub const POLICY_SETTINGS_KEY: &str = "policy_settings";

/// The settings. Defaults are the ADR values. The longest "approve for the session" lease is not
/// here: it is `min(8 h, session_ttl_max_seconds)` of the item settings (ADR-0018, DEC-WIRE6-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    /// Time a request waits for a person (ADR-0018: default 120, range 30..=600).
    pub approval_timeout_seconds: u32,
    /// Refusal time after a deny for the same agent and item (ADR-0018: default 600, 0..=86400).
    pub deny_cooldown_seconds: u32,
    /// TTL of an auto lease (ADR-0019: default 900, 60..=86400).
    pub lease_ttl_auto_seconds: u32,
    /// Most pending requests per agent (ADR-0018: 5, 1..=50).
    pub max_pending_per_agent: u32,
    /// Access requests per agent in one window (ADR-0030: 10, 1..=1000).
    pub requests_per_window: u32,
    /// Length of that window (ADR-0030: 600 s, 60..=86400).
    pub requests_window_seconds: u32,
    /// Secret reads per agent per minute (ADR-0030: 60, 1..=10000).
    pub secret_reads_per_minute: u32,
    /// Distinct items read per agent per hour (ADR-0030: 30, 1..=10000).
    pub distinct_items_per_hour: u32,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            approval_timeout_seconds: 120,
            deny_cooldown_seconds: 600,
            lease_ttl_auto_seconds: 900,
            max_pending_per_agent: 5,
            requests_per_window: 10,
            requests_window_seconds: 600,
            secret_reads_per_minute: 60,
            distinct_items_per_hour: 30,
        }
    }
}

impl PolicySettings {
    /// Checks every range.
    ///
    /// # Errors
    /// [`CoreError::Validation`] with one problem per bad field.
    pub fn validate(&self) -> Result<(), CoreError> {
        let checks: [(&str, u32, u32, u32); 8] = [
            (
                "approval_timeout_seconds",
                self.approval_timeout_seconds,
                30,
                600,
            ),
            (
                "deny_cooldown_seconds",
                self.deny_cooldown_seconds,
                0,
                86_400,
            ),
            (
                "lease_ttl_auto_seconds",
                self.lease_ttl_auto_seconds,
                60,
                86_400,
            ),
            ("max_pending_per_agent", self.max_pending_per_agent, 1, 50),
            ("requests_per_window", self.requests_per_window, 1, 1000),
            (
                "requests_window_seconds",
                self.requests_window_seconds,
                60,
                86_400,
            ),
            (
                "secret_reads_per_minute",
                self.secret_reads_per_minute,
                1,
                10_000,
            ),
            (
                "distinct_items_per_hour",
                self.distinct_items_per_hour,
                1,
                10_000,
            ),
        ];
        let problems: Vec<FieldProblem> = checks
            .iter()
            .filter(|(_, value, min, max)| value < min || value > max)
            .map(|(field, _, min, max)| FieldProblem {
                field: (*field).to_owned(),
                problem: format!("must be {min} to {max}"),
            })
            .collect();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(CoreError::Validation(problems))
        }
    }
}

impl super::PolicyEngine {
    /// The policy settings of this vault. Any role.
    ///
    /// # Errors
    /// `Locked` or the role check.
    pub async fn policy_settings(
        &self,
        ctx: &crate::context::OperatorContext,
    ) -> Result<PolicySettings, CoreError> {
        let guard = self
            .service
            .authorize(ctx, cerberus_types::OperatorRole::Viewer)
            .await?;
        Ok(self.settings_in(&guard).await)
    }

    /// Saves the policy settings (sealed row). Owner only (ADR-0030: limits are owner settings).
    ///
    /// # Errors
    /// `Validation`, `Locked`, the role check, or a storage error.
    pub async fn set_policy_settings(
        &self,
        ctx: &crate::context::OperatorContext,
        value: PolicySettings,
    ) -> Result<(), CoreError> {
        let guard = self
            .service
            .authorize(ctx, cerberus_types::OperatorRole::Owner)
            .await?;
        value.validate()?;
        let plain = super::engine::settings_json(&value)?;
        let row = cerberus_store::SettingRow {
            key: POLICY_SETTINGS_KEY.to_owned(),
            updated_at: self.now(),
            value_ct: guard
                .blobs()
                .seal_setting(POLICY_SETTINGS_KEY, plain.expose_secret())?,
        };
        let mut tx = self.service.store().begin().await?;
        tx.put_setting(&row).await?;
        tx.commit().await?;
        self.cache_settings(&guard, value);
        let event = crate::audit::AuditEvent::new(
            crate::audit::EventType::SettingsChange,
            crate::audit::Actor::operator(ctx.operator_id.to_string()),
        )
        .request_id(ctx.request_id)
        .target("settings", POLICY_SETTINGS_KEY)
        .detail(
            "value",
            serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        );
        self.service.audit(&guard, event).await;
        Ok(())
    }
}
