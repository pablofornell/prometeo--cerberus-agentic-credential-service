//! Item settings (ADR-0007, ADR-0027) and the expiry rules that use them.

use std::ops::RangeInclusive;

use cerberus_types::{FieldProblem, ItemKind};
use jiff::{SignedDuration, Timestamp};

use crate::error::CoreError;

/// Setting keys in the `settings` table. The value is a JSON number.
pub mod setting_keys {
    /// TTL of a session item when the caller gives none, in seconds.
    pub const SESSION_TTL_DEFAULT_SECONDS: &str = "session_ttl_default_seconds";
    /// Largest TTL of a session item, in seconds.
    pub const SESSION_TTL_MAX_SECONDS: &str = "session_ttl_max_seconds";
    /// How many versions of an item are kept.
    pub const ITEM_VERSIONS_KEEP: &str = "item_versions_keep";
}

/// Allowed default TTL: 60 s up to the maximum.
const DEFAULT_TTL_MIN: u32 = 60;
/// Allowed maximum TTL (ADR-0007): 5 minutes to 7 days.
const MAX_TTL_RANGE: RangeInclusive<u32> = 300..=604_800;
/// Allowed number of versions (ADR-0027).
const KEEP_RANGE: RangeInclusive<u32> = 1..=100;
/// Allowed `ttl_seconds` for kinds without a forced expiry (ADR-0007 point 3).
const OTHER_TTL_RANGE: RangeInclusive<u64> = 60..=31_536_000;

/// The settings that change how items live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemSettings {
    /// TTL of a session item without a given TTL (default 3600 s).
    pub session_ttl_default_seconds: u32,
    /// Largest TTL of a session item (default 86400 s).
    pub session_ttl_max_seconds: u32,
    /// Versions kept per item (default 10).
    pub versions_keep: u32,
}

impl Default for ItemSettings {
    fn default() -> Self {
        Self {
            session_ttl_default_seconds: 3_600,
            session_ttl_max_seconds: 86_400,
            versions_keep: 10,
        }
    }
}

fn problem(field: &str, text: &str) -> FieldProblem {
    FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }
}

/// Session kinds always expire and keep one version (ADR-0007, ADR-0027).
const fn is_session(kind: ItemKind) -> bool {
    matches!(kind, ItemKind::SessionToken | ItemKind::BrowserSession)
}

impl ItemSettings {
    /// Checks the ranges.
    ///
    /// # Errors
    /// [`CoreError::Validation`] with one problem per bad field.
    pub fn validate(&self) -> Result<(), CoreError> {
        let mut problems = Vec::new();
        if !MAX_TTL_RANGE.contains(&self.session_ttl_max_seconds) {
            problems.push(problem(
                setting_keys::SESSION_TTL_MAX_SECONDS,
                "must be 300..604800",
            ));
        }
        if !(DEFAULT_TTL_MIN..=self.session_ttl_max_seconds)
            .contains(&self.session_ttl_default_seconds)
        {
            problems.push(problem(
                setting_keys::SESSION_TTL_DEFAULT_SECONDS,
                "must be 60 up to the maximum",
            ));
        }
        if !KEEP_RANGE.contains(&self.versions_keep) {
            problems.push(problem(setting_keys::ITEM_VERSIONS_KEEP, "must be 1..100"));
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(CoreError::Validation(problems))
        }
    }

    /// How many versions to keep for `kind`. Session kinds keep one.
    #[must_use]
    pub const fn keep_for(&self, kind: ItemKind) -> u32 {
        if is_session(kind) {
            1
        } else {
            self.versions_keep
        }
    }

    /// The expiry of an item from a requested end time (an operator form).
    ///
    /// Session kinds always get one: the default TTL when `requested` is `None`. A request must be
    /// in the future, and for a session kind not later than the maximum TTL. Nothing is clamped in
    /// silence (ADR-0007 point 2).
    ///
    /// # Errors
    /// A list of field problems (field `expires_at`).
    pub fn expiry(
        &self,
        kind: ItemKind,
        requested: Option<Timestamp>,
        now: Timestamp,
    ) -> Result<Option<Timestamp>, Vec<FieldProblem>> {
        let fail = |text: &str| vec![problem("expires_at", text)];
        match requested {
            None if is_session(kind) => Ok(Some(
                now + SignedDuration::from_secs(i64::from(self.session_ttl_default_seconds)),
            )),
            None => Ok(None),
            Some(at) if at <= now => Err(fail("must be in the future")),
            Some(at)
                if is_session(kind)
                    && at
                        > now
                            + SignedDuration::from_secs(i64::from(
                                self.session_ttl_max_seconds,
                            )) =>
            {
                Err(fail("is later than the maximum session TTL"))
            }
            Some(at) => Ok(Some(at)),
        }
    }

    /// The expiry of an item from `ttl_seconds` (an agent call): `now + ttl`.
    ///
    /// Session kinds use the default when `ttl_seconds` is `None` and refuse a value above the
    /// maximum. Other kinds accept 60..=31,536,000 or no TTL (ADR-0007).
    ///
    /// # Errors
    /// A list of field problems (field `ttl_seconds`).
    pub fn expiry_from_ttl(
        &self,
        kind: ItemKind,
        ttl_seconds: Option<u64>,
        now: Timestamp,
    ) -> Result<Option<Timestamp>, Vec<FieldProblem>> {
        let fail = |text: &str| vec![problem("ttl_seconds", text)];
        let ttl = match ttl_seconds {
            None if is_session(kind) => u64::from(self.session_ttl_default_seconds),
            None => return Ok(None),
            Some(ttl) => ttl,
        };
        if is_session(kind) {
            if !(u64::from(DEFAULT_TTL_MIN)..=u64::from(self.session_ttl_max_seconds))
                .contains(&ttl)
            {
                return Err(fail("must be 60 up to the maximum session TTL"));
            }
        } else if !OTHER_TTL_RANGE.contains(&ttl) {
            return Err(fail("must be 60..31536000"));
        }
        let secs = i64::try_from(ttl).map_err(|_| fail("is too large"))?;
        Ok(Some(now + SignedDuration::from_secs(secs)))
    }
}
