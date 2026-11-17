//! The event catalog: every audit event type Cerberus writes (ADR-0025).
//!
//! The table below is the single source. `docs/reference/audit-events.md` lists the same rows and a
//! test keeps the two in step.

use std::fmt;
use std::str::FromStr;

macro_rules! catalog {
    ($( $variant:ident, $name:literal, $target:expr, $about:literal; )+) => {
        /// One audit event type. The stable text name is what the body and the export hold.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum EventType {
            $(
                #[doc = $about]
                $variant,
            )+
        }

        impl EventType {
            /// Every event type, in catalog order.
            pub const ALL: &'static [EventType] = &[$(EventType::$variant),+];

            /// The stable text name, for example `item.reveal`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(EventType::$variant => $name,)+
                }
            }

            /// The kind of object the event is about, when it has one.
            #[must_use]
            pub const fn target_kind(self) -> Option<&'static str> {
                match self {
                    $(EventType::$variant => $target,)+
                }
            }

            /// One line saying when the event is written.
            #[must_use]
            pub const fn description(self) -> &'static str {
                match self {
                    $(EventType::$variant => $about,)+
                }
            }
        }
    };
}

catalog! {
    VaultCreate, "vault.create", Some("vault"), "A new vault was created.";
    VaultUnlock, "vault.unlock", Some("vault"), "The vault was unlocked with an operator passphrase.";
    VaultUnlockFailed, "vault.unlock_failed", Some("vault"), "An unlock attempt failed (wrong passphrase or recovery key).";
    VaultUnlockRecovery, "vault.unlock_recovery", Some("vault"), "The vault was unlocked with the recovery key.";
    VaultLock, "vault.lock", Some("vault"), "The vault was locked. details.reason says why.";
    VaultPanic, "vault.panic", Some("vault"), "Panic: keys dropped and all leases revoked at once.";
    VaultHeaderMismatch, "vault.header_mismatch", Some("vault"), "The header MAC check failed at unlock.";
    OperatorAdd, "operator.add", Some("operator"), "An operator (key slot) was added.";
    OperatorRemove, "operator.remove", Some("operator"), "An operator was removed.";
    OperatorRoleChange, "operator.role_change", Some("operator"), "An operator role was changed.";
    OperatorPhraseChange, "operator.phrase_change", Some("operator"), "An operator passphrase was changed.";
    RecoveryRotate, "recovery.rotate", Some("vault"), "The recovery key was replaced.";
    WorkspaceCreate, "workspace.create", Some("workspace"), "A workspace was created.";
    WorkspaceUpdate, "workspace.update", Some("workspace"), "A workspace was changed.";
    WorkspaceDelete, "workspace.delete", Some("workspace"), "A workspace was deleted.";
    ItemCreate, "item.create", Some("item"), "An item was created.";
    ItemUpdate, "item.update", Some("item"), "An item was changed (new version).";
    ItemDelete, "item.delete", Some("item"), "An item was deleted.";
    ItemReveal, "item.reveal", Some("item"), "A secret value was read (reveal or resolve with value).";
    ItemTotp, "item.totp", Some("item"), "A one-time code was generated.";
    ItemExpire, "item.expire", Some("item"), "An item passed its expiry and was deleted by the sweeper.";
    ItemsImport, "items.import", Some("workspace"), "Items were imported from a CSV file in one step. details hold counts only.";
    ItemsExport, "items.export", Some("vault"), "Items were exported to a CSV file with their secrets in plain text. details hold counts only.";
    ItemVersionRestore, "item.version_restore", Some("item"), "An old item version was restored as the newest.";
    AgentCreate, "agent.create", Some("agent"), "An agent was created.";
    AgentUpdate, "agent.update", Some("agent"), "An agent was changed.";
    AgentSuspend, "agent.suspend", Some("agent"), "An agent was suspended.";
    AgentResume, "agent.resume", Some("agent"), "An agent was resumed.";
    AgentRevoke, "agent.revoke", Some("agent"), "An agent was revoked.";
    AgentKeyCreate, "agent_key.create", Some("agent_key"), "An agent API key was created.";
    AgentKeyRotate, "agent_key.rotate", Some("agent_key"), "An agent API key was rotated.";
    AgentKeyRevoke, "agent_key.revoke", Some("agent_key"), "An agent API key was revoked.";
    GrantCreate, "grant.create", Some("grant"), "A grant was created.";
    GrantUpdate, "grant.update", Some("grant"), "A grant was changed.";
    GrantDelete, "grant.delete", Some("grant"), "A grant was deleted.";
    RequestCreate, "request.create", Some("request"), "An agent asked for access that needs approval.";
    RequestApprove, "request.approve", Some("request"), "An operator approved an access request.";
    RequestDeny, "request.deny", Some("request"), "An operator denied an access request.";
    RequestExpire, "request.expire", Some("request"), "An access request timed out.";
    RequestCancel, "request.cancel", Some("request"), "An access request was cancelled.";
    LeaseCreate, "lease.create", Some("lease"), "A lease was issued.";
    LeaseUse, "lease.use", Some("lease"), "A lease was used to read a secret.";
    LeaseRelease, "lease.release", Some("lease"), "A lease was released by its agent.";
    LeaseRevoke, "lease.revoke", Some("lease"), "A lease was revoked by an operator or by a lock.";
    LeaseExpire, "lease.expire", Some("lease"), "A lease reached its end time.";
    AuthFailed, "auth.failed", None, "A call failed authentication.";
    AuthLockout, "auth.lockout", None, "An agent or address was locked out after repeated failures.";
    ApiLockedCall, "api.locked_call", None, "A call arrived while the vault was locked.";
    ApiResolve, "api.resolve", None, "An agent resolved a name to an item.";
    ApiCatalog, "api.catalog", None, "An agent listed its catalog.";
    SettingsChange, "settings.change", Some("settings"), "A setting was changed.";
    NetworkBindChange, "network.bind_change", Some("settings"), "The listen addresses were changed.";
    TlsRenew, "tls.renew", Some("settings"), "The TLS leaf certificate was renewed.";
    TlsCustomLoad, "tls.custom_load", Some("settings"), "A custom TLS certificate was loaded.";
    TlsCustomRevert, "tls.custom_revert", Some("settings"), "The custom TLS certificate was removed and the local CA is in use again.";
    BackupCreate, "backup.create", Some("vault"), "A backup was written.";
    BackupRestore, "backup.restore", Some("vault"), "A backup was restored.";
    BackupRecover, "backup.recover", Some("vault"), "A vault file left by a failed restore was put back in place. Written while locked, so details.recorded_while_locked is true.";
    BackupRecoverRevoke, "backup.recover_revoke", Some("vault"), "At the first unlock after a vault file left by a restore was put back, every agent key and lease of it was revoked and every pending request cancelled. details hold the counts.";
    AuditExport, "audit.export", Some("vault"), "The audit log was exported.";
    AuditPrune, "audit.prune", Some("vault"), "Old audit rows were deleted by retention.";
    AuditVerify, "audit.verify", Some("vault"), "The audit chain was verified.";
    AuditPendingOverflow, "audit.pending_overflow", Some("vault"), "Events were lost while locked because the pending list was full. details.dropped holds the count.";
    IntegrityRowMacMismatch, "integrity.row_mac_mismatch", None, "A row failed its MAC check at unlock and was disabled. target.kind is the table, target.id the row.";
    SshPrepare, "ssh.prepare", Some("item"), "An SSH key was prepared for the agent bridge.";
    SshSign, "ssh.sign", Some("item"), "The ssh-agent bridge signed one request with an SSH key of the vault.";
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The text is not a catalog event name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownEventType;

impl FromStr for EventType {
    type Err = UnknownEventType;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == text)
            .ok_or(UnknownEventType)
    }
}
