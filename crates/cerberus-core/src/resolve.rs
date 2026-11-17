//! The resolve engine (ADR-0020): from "app, environment, role" to the best item.
//!
//! [`resolve`] is a pure function over the index. It scores, filters and sorts; it never opens a
//! payload. Its output ([`ResolveOutcome`]) holds item IDs and scores only, and the candidate
//! type ([`Candidate`]) is built from [`ItemSummary`], which has no field for a secret.
//!
//! Policy comes in through [`ResolvePolicy`]: `can_find` is rule 1 (remove what the agent cannot
//! see) and `read_access` decides reveal or approval for the winner (rule 3).

mod score;
mod service;

#[cfg(test)]
mod tests;

use cerberus_types::{FieldProblem, ItemId, ItemKind, NoMatchHints};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::index::{Index, ItemMeta};
use crate::items::ItemSummary;

pub use score::resolve;
pub use service::{ReadAccess, Resolution};

/// Most candidates in one answer (ADR-0020).
pub const MAX_CANDIDATES: usize = 20;
/// A winner needs this many points more than the second item (ADR-0020).
pub const CONFIDENCE_GAP: u32 = 25;

/// `best` returns one item when it is clear; `candidates` always returns the list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveMode {
    /// One confident item, else the list.
    #[default]
    Best,
    /// The list.
    Candidates,
}

/// A resolve call (ADR-0020 "Input").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    /// Application: workspace slug, alias or name, or a target name. 1..128 characters.
    pub app: String,
    /// Environment. `production`, `stage`, `stg`, `development` and `local` are accepted.
    #[serde(default)]
    pub environment: Option<String>,
    /// Role label or a synonym of it.
    #[serde(default)]
    pub role: Option<String>,
    /// Item kind.
    #[serde(default)]
    pub kind: Option<ItemKind>,
    /// Free words, at most 256 characters.
    #[serde(default)]
    pub hint: Option<String>,
    /// Why the agent asks, 1..500 characters. Goes to the audit event, never to scoring.
    pub purpose: String,
    /// `best` (default) or `candidates`.
    #[serde(default)]
    pub mode: ResolveMode,
}

impl ResolveRequest {
    /// A `best` request for an app, with a purpose.
    #[must_use]
    pub fn new(app: impl Into<String>, purpose: impl Into<String>) -> Self {
        Self {
            app: app.into(),
            environment: None,
            role: None,
            kind: None,
            hint: None,
            purpose: purpose.into(),
            mode: ResolveMode::Best,
        }
    }

    /// Checks the length limits of ADR-0020.
    ///
    /// # Errors
    /// [`CoreError::Validation`] with one problem per bad field.
    pub fn validate(&self) -> Result<(), CoreError> {
        let mut problems = Vec::new();
        let mut check = |field: &str, text: &str, min: usize, max: usize| {
            let len = text.trim().chars().count();
            if len < min || len > max {
                problems.push(FieldProblem {
                    field: field.to_owned(),
                    problem: format!("must be {min}..{max} characters"),
                });
            }
        };
        check("app", &self.app, 1, 128);
        check("purpose", &self.purpose, 1, 500);
        for (field, value) in [
            ("environment", &self.environment),
            ("role", &self.role),
            ("hint", &self.hint),
        ] {
            if let Some(text) = value {
                check(field, text, 0, if field == "hint" { 256 } else { 64 });
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(CoreError::Validation(problems))
        }
    }
}

/// An item and its score.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scored {
    /// The item.
    pub item_id: ItemId,
    /// Total score.
    pub score: u32,
}

/// The result of scoring, before policy decides about reveal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// `best` mode and one clear winner.
    Confident(Scored),
    /// `candidates` mode: the list, best first (at most 20).
    Candidates(Vec<Scored>),
    /// `best` mode but no clear winner: the list, best first (at most 20).
    Ambiguous(Vec<Scored>),
    /// Nothing is left. The hints come from items the agent can see only.
    NoMatch(NoMatchHints),
}

/// One candidate for the agent: metadata and score. No secret (ADR-0020).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// The item metadata.
    pub item: ItemSummary,
    /// The score.
    pub score: u32,
}

/// What resolve needs from policy (ADR-0017). T07 implements it for one agent.
pub trait ResolvePolicy: Sync {
    /// Rule 1: true when the agent has `find` on the item.
    fn can_find(&self, item: &ItemMeta) -> bool;

    /// Rule 3: the `read` decision for the winner.
    ///
    /// # Errors
    /// The refusal as a [`CoreError`]: `Forbidden`, `ReasonRequired`, `ConditionFailed`,
    /// `GrantRateLimited` or `ApprovalUnavailable`.
    fn read_access(&self, item: &ItemMeta) -> Result<ReadAccess, CoreError>;
}

/// A [`Candidate`] list from scored items. Items that left the index are skipped.
pub(crate) fn candidates(index: &Index, scored: &[Scored]) -> Vec<Candidate> {
    scored
        .iter()
        .filter_map(|s| {
            index.item(&s.item_id).map(|meta| Candidate {
                item: ItemSummary::of(meta, index),
                score: s.score,
            })
        })
        .collect()
}
