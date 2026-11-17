//! The vault state and the unlocked session (ADR-0026).
//!
//! Keys exist only inside [`Unlocked`]. Leaving the `Unlocked` variant drops it: `Vmk` and every
//! `Key32` of the key tree zeroize their locked memory on drop, and the index text is `Zeroizing`.

use std::sync::Arc;

use cerberus_crypto::{KeyTree, Vmk};
use cerberus_store::{Blobs, RowMacs};
use cerberus_types::{OperatorId, OperatorRole, VaultId};
use jiff::Timestamp;

use crate::audit::AuditWriter;
use crate::context::OperatorContext;
use crate::error::CoreError;
use crate::index::Index;

/// `VaultState` as stored in the service. `Locking` is not a variant: it is the time between
/// the lock request (the state kind flag says `Locking`) and the write lock that drops the keys.
pub(crate) enum VaultState {
    /// No vault file content yet.
    NoVault,
    /// File open, no keys.
    Sealed,
    /// Keys and index in memory.
    Unlocked(Box<Unlocked>),
}

/// Who unlocked the vault, and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    /// The operator (key slot). For a recovery unlock it is the recovery slot ID.
    pub operator_id: OperatorId,
    /// The current role of that operator.
    pub role: OperatorRole,
    /// Unlock time (the hard limit counts from here).
    pub unlocked_at: Timestamp,
    /// True when the recovery key opened the vault.
    pub via_recovery: bool,
}

/// Rank of a role: owner > operator > viewer (ADR-0009).
const fn rank(role: OperatorRole) -> u8 {
    match role {
        OperatorRole::Owner => 3,
        OperatorRole::Operator => 2,
        OperatorRole::Viewer => 1,
    }
}

impl Session {
    /// Checks that `ctx` belongs to this session and that the session role is at least `min`.
    /// The role comes from the session, not from `ctx`, so a stale context cannot keep an old role.
    ///
    /// # Errors
    /// [`CoreError::Forbidden`] for a context of another session, [`CoreError::RoleNotAllowed`]
    /// for a lower role.
    pub fn authorize(&self, ctx: &OperatorContext, min: OperatorRole) -> Result<(), CoreError> {
        if ctx.operator_id != self.operator_id {
            return Err(CoreError::Forbidden);
        }
        if rank(self.role) < rank(min) {
            return Err(CoreError::RoleNotAllowed);
        }
        Ok(())
    }
}

/// Everything that exists only while the vault is unlocked.
pub(crate) struct Unlocked {
    /// The session.
    pub(crate) session: Session,
    /// The vault ID (AAD and HKDF salt).
    pub(crate) vault_id: VaultId,
    /// The VMK, for new slots. Shared only with a slot task that the service awaits.
    pub(crate) vmk: Arc<Vmk>,
    /// The derived keys. Shared only with parts that live inside this struct.
    pub(crate) keys: Arc<KeyTree>,
    /// The metadata index.
    pub(crate) index: Index,
    /// False when the header MAC check failed at unlock.
    pub(crate) header_ok: bool,
    /// The audit chain writer. It holds a share of `keys` and goes with this struct.
    pub(crate) audit: AuditWriter,
}

impl Unlocked {
    /// Seals and opens blobs with this vault's keys.
    pub(crate) fn blobs(&self) -> Blobs<'_> {
        Blobs::new(&self.vault_id, &self.keys)
    }

    /// Makes and checks row MACs with this vault's `row_mac_key`.
    pub(crate) fn row_macs(&self) -> RowMacs<'_> {
        RowMacs::new(&self.keys.row_mac_key, &self.vault_id)
    }
}
