//! One handler per command of the remote allowlist ([`crate::remote::REMOTE_COMMANDS`]).
//!
//! A handler takes the vault service and the operator context, makes the one core call, and
//! converts the result into the IPC type. It never checks a role: the core does that
//! (`authorize`, DEC-WIRE6-13), so a remote call has exactly the power of the same local call. The
//! desktop `ops` call these after the window check and `DesktopState::operator`; the admin API
//! of `cerberusd` calls them through [`crate::rpc::dispatch`] after its device and session checks.

mod agents;
mod audit;
mod items;
mod policy;
mod vault;

pub use agents::*;
pub use audit::*;
pub use items::*;
pub use policy::*;
pub use vault::*;
