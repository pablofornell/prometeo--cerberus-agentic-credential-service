//! Events for the UI and SSE, OS lock hooks, and the service configuration.

use std::sync::{Arc, Weak};
use std::time::Duration;

use cerberus_types::{
    AccessRequestId, AccessRequestStatus, AgentId, ItemId, LeaseId, VaultStateKind,
};

use super::ca::CaIssuer;
use super::{Inner, VaultService};

/// Events sent to the UI and to SSE streams. They hold IDs and metadata only, never a secret.
#[derive(Clone, Debug)]
pub enum CoreEvent {
    /// The vault state changed.
    StateChanged(VaultStateKind),
    /// An agent asked for access.
    AccessRequestCreated(AccessRequestId),
    /// A person decided a request, or it expired or was cancelled.
    AccessRequestResolved {
        /// The request.
        id: AccessRequestId,
        /// Its new state.
        status: AccessRequestStatus,
    },
    /// An agent call that the dashboard shows.
    AgentActivity {
        /// The agent.
        agent_id: AgentId,
        /// Audit event type, for example `secret.reveal`.
        event_type: &'static str,
        /// The item, if the call was about one.
        item_id: Option<ItemId>,
        /// When.
        at: jiff::Timestamp,
    },
    /// A lease was made, used up, released or revoked.
    LeaseChanged(LeaseId),
    /// Seconds left before the next automatic lock (idle or hard limit).
    AutoLockTick {
        /// Seconds until the lock.
        seconds_left: u64,
    },
    /// An agent read many different items in one hour (ADR-0030).
    MassReadAlert {
        /// The agent.
        agent_id: AgentId,
        /// Distinct items read.
        distinct_items: u32,
    },
    /// The header MAC check failed at unlock (ADR-0013).
    HeaderMismatch,
    /// A row MAC or a sealed blob failed a check (ADR-0033). Table name and row ID only.
    IntegrityAlert {
        /// Table name.
        table: &'static str,
        /// Row ID.
        row_id: String,
    },
}

/// An OS event that locks the vault when `lock_on_os_lock` is on (ADR-0026).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsEvent {
    /// The machine goes to sleep.
    Sleep,
    /// The screen or the session was locked.
    ScreenLocked,
}

/// Handle that an OS hook calls when an [`OsEvent`] happens. It does not keep the service alive.
#[derive(Clone, Debug)]
pub struct OsEventSink {
    inner: Weak<Inner>,
}

impl OsEventSink {
    pub(super) fn new(inner: &Arc<Inner>) -> Self {
        Self {
            inner: Arc::downgrade(inner),
        }
    }

    /// Reports an OS event to the vault service. Does nothing when the service is gone.
    pub fn send(&self, event: OsEvent) {
        if let Some(inner) = self.inner.upgrade() {
            VaultService { inner }.on_os_event(event);
        }
    }
}

/// An OS sleep and screen-lock watcher (logind, macOS workspace notifications, WTS on Windows).
/// `cerberus-desktop` implements it (ADR-0026).
pub trait OsLockEvents: Send + Sync {
    /// Starts to watch and calls `sink.send` for each event. Returns false when the OS gives no
    /// such events (for example Linux without logind); the health view then shows the hook as off.
    fn start(&self, sink: OsEventSink) -> bool;
}

/// Configuration of the core service.
#[derive(Clone, Debug)]
pub struct CoreConfig {
    /// False on `cerberusd`: no person can approve there (ADR-0002).
    pub approvals_available: bool,
    /// Idle lock time when the vault has no `idle_lock_seconds` setting. `None` = off.
    pub idle_lock_default: Option<Duration>,
    /// The application data directory.
    pub data_dir: std::path::PathBuf,
    /// Makes the local CA when a vault is created (ADR-0023). The API layer implements it.
    pub ca_issuer: Arc<dyn CaIssuer>,
}

impl CoreConfig {
    /// Desktop defaults: approvals on, idle lock after 30 minutes (ADR-0026).
    #[must_use]
    pub fn desktop(data_dir: std::path::PathBuf, ca_issuer: Arc<dyn CaIssuer>) -> Self {
        Self {
            approvals_available: true,
            idle_lock_default: Some(Duration::from_secs(super::autolock::DEFAULT_IDLE_SECONDS)),
            data_dir,
            ca_issuer,
        }
    }
}
