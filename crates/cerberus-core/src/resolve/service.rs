//! Resolve on the vault service: score, then ask policy about the winner.

use super::{Candidate, ResolveOutcome, ResolvePolicy, ResolveRequest, candidates, resolve};
use crate::error::CoreError;
use crate::items::ItemSummary;
use crate::vault::VaultService;

/// How the winner may be read (the answer of the `read` policy check).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadAccess {
    /// A grant or a lease allows the read now. Call [`VaultService::read_payload`].
    Granted,
    /// A person must approve first (`ask_once` or `ask_always`). Start an access request.
    NeedsApproval,
}

/// The answer of [`VaultService::resolve`]. It never holds a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// One confident item and the `read` decision for it.
    Best {
        /// The item.
        item: Box<ItemSummary>,
        /// Its score.
        score: u32,
        /// Reveal now, or ask a person.
        access: ReadAccess,
    },
    /// `candidates` mode.
    Candidates(Vec<Candidate>),
    /// `best` mode without a clear winner.
    Ambiguous(Vec<Candidate>),
}

impl VaultService {
    /// Resolves a request to an item (ADR-0020). The `purpose` is for the caller's audit event.
    ///
    /// # Errors
    /// [`CoreError::Validation`] for a bad request, [`CoreError::NoMatch`] with hints,
    /// the refusal of `policy.read_access`, or [`CoreError::Locked`].
    pub async fn resolve(
        &self,
        request: &ResolveRequest,
        policy: &dyn ResolvePolicy,
    ) -> Result<Resolution, CoreError> {
        request.validate()?;
        let guard = self.unlocked().await?;
        let index = &guard.index;
        let now = self.clock().now();
        match resolve(index, request, now, &|meta| policy.can_find(meta)) {
            ResolveOutcome::NoMatch(hints) => Err(CoreError::NoMatch(hints)),
            ResolveOutcome::Candidates(list) => {
                Ok(Resolution::Candidates(candidates(index, &list)))
            }
            ResolveOutcome::Ambiguous(list) => Ok(Resolution::Ambiguous(candidates(index, &list))),
            ResolveOutcome::Confident(best) => {
                let meta = index.item(&best.item_id).ok_or(CoreError::NotFound)?;
                let access = policy.read_access(meta)?;
                Ok(Resolution::Best {
                    item: Box::new(ItemSummary::of(meta, index)),
                    score: best.score,
                    access,
                })
            }
        }
    }
}
