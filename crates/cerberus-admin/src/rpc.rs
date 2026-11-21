//! The RPC layer of the admin API (ADR-0034 point 5, DEC-RM-6): `POST /admin/v1/rpc/{command}`
//! carries the IPC arguments of one allowlisted command as a JSON object with the Rust argument
//! names, and answers with the IPC result DTO, the same JSON the webview gets.
//!
//! - One `Args` struct per command of [`crate::remote::REMOTE_COMMANDS`]. Unknown fields are refused, so a typo
//!   is an error and not a silently dropped argument.
//! - [`to_body`] writes JSON into a zeroizing buffer and [`from_body`] reads it, so a phrase or
//!   a revealed secret leaves no plain copy behind in a grown buffer or a `serde_json::Value`.
//! - [`dispatch`] checks the gate of the command, parses the arguments, calls the handler and
//!   writes the answer. The device and session checks happen before, in the server.

use std::io;

use cerberus_core::items::PayloadChange;
use cerberus_core::{OperatorContext, VaultService};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::dto::{
    ApprovalOption, AuditQueryView, GrantInputView, ItemFilterView, ItemInputView, PayloadSource,
    PayloadView, Secret, WorkspaceInputView,
};
use crate::error::{IpcError, IpcResult};
use crate::handlers;
use crate::remote::{Gate, gate};

/// Makes one `Args` struct per command and the [`ARG_NAMES`] table.
macro_rules! rpc_args {
    ($($command:ident => $args:ident { $($field:ident : $ty:ty),* $(,)? }),+ $(,)?) => {
        $(
            #[doc = concat!("Arguments of `", stringify!($command), "`.")]
            #[derive(Debug, Serialize, Deserialize)]
            #[serde(deny_unknown_fields)]
            pub struct $args {
                $(
                    #[doc = concat!("Argument `", stringify!($field), "`.")]
                    pub $field: $ty,
                )*
            }
        )+

        /// The argument names of every remote command, in the order of the IPC command.
        pub const ARG_NAMES: &[(&str, &[&str])] = &[
            $((stringify!($command), &[$(stringify!($field)),*])),+
        ];

        /// Test only: parses `body` as the arguments of `command` and writes them again.
        /// `None`: no such command.
        #[cfg(test)]
        fn reencode(command: &str, body: &[u8]) -> Option<IpcResult<Zeroizing<Vec<u8>>>> {
            match command {
                $(stringify!($command) => Some(from_body::<$args>(body).and_then(|args| to_body(&args))),)+
                _ => None,
            }
        }
    };
}

rpc_args! {
    vault_status => VaultStatusArgs {},
    vault_list_operators => VaultListOperatorsArgs {},
    vault_unlock => VaultUnlockArgs { operator_id: String, phrase: Secret },
    vault_lock => VaultLockArgs {},
    vault_panic => VaultPanicArgs {},
    ui_activity => UiActivityArgs {},
    workspace_list => WorkspaceListArgs {},
    workspace_put => WorkspacePutArgs { workspace: Option<String>, input: WorkspaceInputView },
    item_list => ItemListArgs { filter: ItemFilterView },
    item_get => ItemGetArgs { item: String },
    item_create => ItemCreateArgs { input: ItemInputView },
    item_update => ItemUpdateArgs { item: String, input: ItemInputView },
    item_delete => ItemDeleteArgs { item: String },
    item_reveal => ItemRevealArgs { item: String },
    item_totp_preview => ItemTotpPreviewArgs { item: String },
    agent_list => AgentListArgs {},
    grant_list => GrantListArgs { agent_id: Option<String> },
    grant_put => GrantPutArgs { input: GrantInputView },
    grant_delete => GrantDeleteArgs { grant: String },
    request_list_pending => RequestListPendingArgs {},
    request_approve => RequestApproveArgs { request: String, option: ApprovalOption },
    request_deny => RequestDenyArgs { request: String },
    lease_list => LeaseListArgs {},
    lease_revoke => LeaseRevokeArgs { lease: String },
    audit_query => AuditQueryArgs { query: AuditQueryView },
}

/// The argument names of `command`. `None`: not a remote command.
#[must_use]
pub fn arg_names(command: &str) -> Option<&'static [&'static str]> {
    ARG_NAMES
        .iter()
        .find(|(name, _)| *name == command)
        .map(|(_, names)| *names)
}

/// A `Vec` that grows into a new zeroizing buffer, so no old buffer is freed with data in it.
struct ZeroizingWriter(Zeroizing<Vec<u8>>);

impl io::Write for ZeroizingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let needed = self
            .0
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if needed > self.0.capacity() {
            let capacity = needed.max(self.0.capacity().saturating_mul(2)).max(256);
            let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
            grown.extend_from_slice(&self.0);
            // The old buffer is zeroized when it drops here.
            self.0 = grown;
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Writes `value` as JSON into a zeroizing buffer.
///
/// # Errors
/// `internal` when the value cannot be written as JSON.
pub fn to_body<T: Serialize + ?Sized>(value: &T) -> IpcResult<Zeroizing<Vec<u8>>> {
    let mut out = ZeroizingWriter(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut out, value).map_err(|error| IpcError::internal(&error))?;
    Ok(out.0)
}

/// Reads JSON arguments or a JSON answer.
///
/// # Errors
/// `invalid_request` for a bad shape or an unknown field. The serde text is not kept: it can
/// quote the value of a secret field.
pub fn from_body<T: DeserializeOwned>(body: &[u8]) -> IpcResult<T> {
    serde_json::from_slice(body).map_err(|_| IpcError::invalid_request())
}

/// The payload change of a remote input. A draft is refused: it lives on the desktop that made
/// it, not on the server (ADR-0034 point 5.6).
fn remote_change(view: PayloadView) -> IpcResult<PayloadChange> {
    match view.into_source() {
        PayloadSource::Payload(payload) => Ok(PayloadChange::Replace(payload)),
        PayloadSource::Keep => Ok(PayloadChange::Keep),
        PayloadSource::Draft(_) => Err(IpcError::remote_unsupported(
            "an SSH key made or imported on the desktop is not available for a remote server",
        )),
    }
}

/// Runs one remote command. `ctx` is the context of the live admin session, if there is one.
///
/// # Errors
/// - `remote_unsupported`: the command is not on the allowlist, or it is `vault_unlock` (which
///   goes to the session route), or the input names a desktop draft;
/// - `admin_session_required`: the command needs a session and `ctx` is `None`;
/// - `invalid_request`: the body is not the arguments of the command;
/// - the error of the handler.
pub async fn dispatch(
    core: &VaultService,
    ctx: Option<&OperatorContext>,
    command: &str,
    body: &[u8],
) -> IpcResult<Zeroizing<Vec<u8>>> {
    match gate(command) {
        None => Err(IpcError::remote_unsupported(
            "this command is not available for a remote server",
        )),
        Some(Gate::OpensSession) => Err(IpcError::remote_unsupported(
            "vault_unlock opens an admin session; it is not an rpc command",
        )),
        Some(Gate::PreSession) => pre_session(core, command, body).await,
        Some(Gate::Session) => {
            let ctx = ctx.ok_or_else(IpcError::admin_session_required)?;
            session(core, ctx, command, body).await
        }
    }
}

async fn pre_session(
    core: &VaultService,
    command: &str,
    body: &[u8],
) -> IpcResult<Zeroizing<Vec<u8>>> {
    match command {
        "vault_status" => {
            let VaultStatusArgs {} = from_body(body)?;
            to_body(&handlers::vault_status(core).await)
        }
        "vault_list_operators" => {
            let VaultListOperatorsArgs {} = from_body(body)?;
            to_body(&handlers::vault_list_operators(core).await?)
        }
        _ => Err(IpcError::remote_unsupported(
            "this command has no remote handler",
        )),
    }
}

async fn session(
    core: &VaultService,
    ctx: &OperatorContext,
    command: &str,
    body: &[u8],
) -> IpcResult<Zeroizing<Vec<u8>>> {
    match command {
        "vault_lock" => {
            let VaultLockArgs {} = from_body(body)?;
            to_body(&handlers::vault_lock(core).await?)
        }
        "vault_panic" => {
            let VaultPanicArgs {} = from_body(body)?;
            to_body(&handlers::vault_panic(core, ctx).await?)
        }
        "ui_activity" => {
            let UiActivityArgs {} = from_body(body)?;
            handlers::ui_activity(core);
            to_body(&())
        }
        "workspace_list" => {
            let WorkspaceListArgs {} = from_body(body)?;
            to_body(&handlers::workspace_list(core, ctx).await?)
        }
        "workspace_put" => {
            let WorkspacePutArgs { workspace, input } = from_body(body)?;
            to_body(&handlers::workspace_put(core, ctx, workspace, input).await?)
        }
        "item_list" => {
            let ItemListArgs { filter } = from_body(body)?;
            to_body(&handlers::item_list(core, ctx, filter).await?)
        }
        "item_get" => {
            let ItemGetArgs { item } = from_body(body)?;
            to_body(&handlers::item_get(core, ctx, item).await?)
        }
        "item_create" => {
            let ItemCreateArgs { mut input } = from_body(body)?;
            let change = remote_change(handlers::take_payload(&mut input))?;
            let payload = handlers::payload_for_create(change)?;
            to_body(&handlers::item_create(core, ctx, input, payload).await?)
        }
        "item_update" => {
            let ItemUpdateArgs { item, mut input } = from_body(body)?;
            let change = remote_change(handlers::take_payload(&mut input))?;
            to_body(&handlers::item_update(core, ctx, item, input, change).await?)
        }
        "item_delete" => {
            let ItemDeleteArgs { item } = from_body(body)?;
            to_body(&handlers::item_delete(core, ctx, item).await?)
        }
        "item_reveal" => {
            let ItemRevealArgs { item } = from_body(body)?;
            to_body(&handlers::item_reveal(core, ctx, item).await?)
        }
        "item_totp_preview" => {
            let ItemTotpPreviewArgs { item } = from_body(body)?;
            to_body(&handlers::item_totp_preview(core, ctx, item).await?)
        }
        "agent_list" => {
            let AgentListArgs {} = from_body(body)?;
            to_body(&handlers::agent_list(core, ctx).await?)
        }
        "grant_list" => {
            let GrantListArgs { agent_id } = from_body(body)?;
            to_body(&handlers::grant_list(core, ctx, agent_id).await?)
        }
        "grant_put" => {
            let GrantPutArgs { input } = from_body(body)?;
            to_body(&handlers::grant_put(core, ctx, input).await?)
        }
        "grant_delete" => {
            let GrantDeleteArgs { grant } = from_body(body)?;
            to_body(&handlers::grant_delete(core, ctx, grant).await?)
        }
        "request_list_pending" => {
            let RequestListPendingArgs {} = from_body(body)?;
            to_body(&handlers::request_list_pending(core, ctx).await?)
        }
        "request_approve" => {
            let RequestApproveArgs { request, option } = from_body(body)?;
            to_body(&handlers::request_approve(core, ctx, request, option).await?)
        }
        "request_deny" => {
            let RequestDenyArgs { request } = from_body(body)?;
            to_body(&handlers::request_deny(core, ctx, request).await?)
        }
        "lease_list" => {
            let LeaseListArgs {} = from_body(body)?;
            to_body(&handlers::lease_list(core, ctx).await?)
        }
        "lease_revoke" => {
            let LeaseRevokeArgs { lease } = from_body(body)?;
            to_body(&handlers::lease_revoke(core, ctx, lease).await?)
        }
        "audit_query" => {
            let AuditQueryArgs { query } = from_body(body)?;
            to_body(&handlers::audit_query(core, ctx, query).await?)
        }
        _ => Err(IpcError::remote_unsupported(
            "this command has no remote handler",
        )),
    }
}

#[cfg(test)]
mod tests;
