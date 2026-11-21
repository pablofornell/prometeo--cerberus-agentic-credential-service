//! The `#[tauri::command]` wrappers. Each one passes the label of the calling window and the state
//! to the function of the same name in `ops`, which does the work. No wrapper takes a role or an
//! operator from the UI.
//!
//! In remote mode (ADR-0034 point 7.1) the wrappers of the remote allowlist (`ipc!(@remote ...)`)
//! check the window label, write their typed arguments into a zeroizing JSON body and send them
//! to the server; the answer is decoded into the same return type, so `bindings.ts` and the UI
//! do not change. `ipc!(@both ...)` commands handle remote mode in their `ops` function. Every
//! other command is local only: in remote mode it answers `remote_unsupported` without a network
//! call (DEC-RM-11).

use serde_json::Value;

use crate::dto::{
    AccessRequestView, AgentCreated, AgentInputView, AgentKeyCreated, AgentKeyInputView,
    AgentStatus, AgentView, ApprovalOption, AuditEntryView, AuditQueryView, ChainReportView,
    CreatedVaultView, CsvImportRequest, GrantInputView, GrantView, ImportPreviewView, ImportReport,
    IssuedClientCert, ItemDetailView, ItemFilterView, ItemInputView, ItemSummaryView,
    ItemVersionView, KdfParamsView, KdfTuningView, LeaseDetailView, LeaseView, NetworkView,
    OneTimeKind, OperatorPublic, OperatorRole, RemoteOverview, RemoteProfileView,
    RestoreUnlockInput, RevealedSecretView, RustdeskConnectView, RustdeskStatusView, Secret,
    SessionView, SettingsView, SimulationRow, Snippets, SshKeyDraft, StrengthView, TotpView,
    VaultStatusView, WorkspaceInputView, WorkspaceView,
};
use crate::error::IpcResult;
use crate::guard::check;
use crate::ops::{self, CharClass, SshKeySource};
use crate::remote;
use crate::state::DesktopState;

/// Makes a command that calls `ops::<name>(&state, window_label, args...)`.
///
/// - `ipc!(@remote name(..) -> T)`: on the remote allowlist. In remote mode it is sent to the
///   server; locally it calls `ops`.
/// - `ipc!(@both name(..) -> T)`: always calls `ops`, which handles both modes.
/// - `ipc!(name(..) -> T)`: local only. In remote mode it checks the window label and answers
///   `remote_unsupported`; its arguments are never serialized.
macro_rules! ipc {
    (@remote $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty) => {
        impl Dispatch {
            #[doc = concat!("The work of `", stringify!($name), "` (remote allowlist): in remote mode the label check, then the arguments to the server; locally `ops::", stringify!($name), "`.")]
            pub async fn $name(state: &DesktopState, window: &str $(, $arg: $ty)*) -> IpcResult<$ret> {
                if let Some(remote) = state.remote() {
                    check(window, stringify!($name))?;
                    /// The arguments as the server reads them: the IPC argument names.
                    #[derive(serde::Serialize)]
                    struct Args<'a> {
                        $($arg: &'a $ty,)*
                        #[serde(skip)]
                        _borrow: std::marker::PhantomData<&'a ()>,
                    }
                    let args = Args { $($arg: &$arg,)* _borrow: std::marker::PhantomData };
                    return remote.forward::<$ret, _>(stringify!($name), &args).await;
                }
                ops::$name(state, window $(, $arg)*).await
            }
        }

        ipc!(@command $name ( $($arg : $ty),* ) -> $ret, "(remote allowlist)");
    };
    (@both $name:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty) => {
        impl Dispatch {
            #[doc = concat!("The work of `", stringify!($name), "`: `ops::", stringify!($name), "`, which handles both modes.")]
            pub async fn $name(state: &DesktopState, window: &str $(, $arg: $ty)*) -> IpcResult<$ret> {
                ops::$name(state, window $(, $arg)*).await
            }
        }

        ipc!(@command $name ( $($arg : $ty),* ) -> $ret, "(both modes)");
    };
    (@command $name:ident ( $($arg:ident : $ty:ty),* ) -> $ret:ty, $kind:literal) => {
        #[doc = concat!("IPC command `", stringify!($name), "` ", $kind, ". See `Dispatch::", stringify!($name), "`.")]
        #[tauri::command]
        #[specta::specta]
        pub async fn $name(
            window: tauri::Window,
            state: tauri::State<'_, DesktopState>,
            $($arg: $ty),*
        ) -> IpcResult<$ret> {
            Dispatch::$name(&state, window.label() $(, $arg)*).await
        }
    };
    ($name:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty) => {
        impl Dispatch {
            #[doc = concat!("The work of `", stringify!($name), "` (local only): in remote mode the label check, then `remote_unsupported`; locally `ops::", stringify!($name), "`.")]
            pub async fn $name(state: &DesktopState, window: &str $(, $arg: $ty)*) -> IpcResult<$ret> {
                if state.remote().is_some() {
                    check(window, stringify!($name))?;
                    return Err(remote::unsupported());
                }
                ops::$name(state, window $(, $arg)*).await
            }
        }

        ipc!(@command $name ( $($arg : $ty),* ) -> $ret, "(local only)");
    };
}

/// The work behind each `ipc!` command, without Tauri: the state and the label of the calling
/// window, then the arguments. The `#[tauri::command]` of the same name only passes them on, so
/// tests run exactly the code of each command arm (the remote forward, the label check order, the
/// local-only refusal).
#[derive(Debug)]
pub struct Dispatch;

ipc!(@both vault_status() -> VaultStatusView);
ipc!(@remote vault_list_operators() -> Vec<OperatorPublic>);
ipc!(
    vault_create(
        owner_label: String,
        phrase: Secret,
        kdf: KdfParamsView,
        host_names: Vec<String>,
    ) -> CreatedVaultView
);
ipc!(@both vault_unlock(operator_id: String, phrase: Secret) -> SessionView);
ipc!(vault_unlock_recovery(recovery_key: Secret) -> SessionView);
ipc!(vault_recover_stranded() -> ());
ipc!(@both vault_lock() -> ());
ipc!(@both vault_panic() -> ());
ipc!(phrase_change(current_phrase: Secret, new_phrase: Secret, kdf: Option<KdfParamsView>) -> ());
ipc!(recovery_rotate() -> Secret);
ipc!(operator_add(label: String, role: OperatorRole, phrase: Secret) -> OperatorPublic);
ipc!(operator_remove(operator: String) -> ());
ipc!(operator_set_role(operator: String, role: OperatorRole) -> ());
ipc!(@remote workspace_list() -> Vec<WorkspaceView>);
ipc!(@remote workspace_put(workspace: Option<String>, input: WorkspaceInputView) -> WorkspaceView);
ipc!(workspace_delete(workspace: String) -> ());
ipc!(@remote item_list(filter: ItemFilterView) -> Vec<ItemSummaryView>);
ipc!(@remote item_get(item: String) -> ItemDetailView);
ipc!(@remote item_create(input: ItemInputView) -> ItemDetailView);
ipc!(@remote item_update(item: String, input: ItemInputView) -> ItemDetailView);
ipc!(@remote item_delete(item: String) -> ());
ipc!(@remote item_reveal(item: String) -> RevealedSecretView);
ipc!(item_versions(item: String) -> Vec<ItemVersionView>);
ipc!(item_restore_version(item: String, version: u32) -> ItemDetailView);
ipc!(@remote item_totp_preview(item: String) -> TotpView);
ipc!(clipboard_copy_secret(item: String, field: String) -> ());
ipc!(clipboard_copy_once(kind: OneTimeKind) -> ());
ipc!(password_generate(length: u32, classes: Vec<CharClass>) -> Secret);
ipc!(ssh_key_generate(comment: String) -> SshKeyDraft);
ipc!(ssh_key_import(source: SshKeySource, passphrase: Option<Secret>) -> SshKeyDraft);
ipc!(@remote agent_list() -> Vec<AgentView>);
ipc!(agent_create(input: AgentInputView, key: AgentKeyInputView) -> AgentCreated);
ipc!(agent_update(agent: String, input: AgentInputView) -> AgentView);
ipc!(agent_set_status(agent: String, status: AgentStatus) -> AgentView);
ipc!(agent_key_create(agent_id: String, key: AgentKeyInputView) -> AgentKeyCreated);
ipc!(agent_key_rotate(key_id: String, overlap_seconds: u32) -> AgentKeyCreated);
ipc!(agent_key_revoke(key_id: String) -> ());
ipc!(agent_issue_client_cert(key_id: String, dest_dir: String) -> IssuedClientCert);
ipc!(agent_snippets(agent_id: String) -> Snippets);
ipc!(@remote grant_list(agent_id: Option<String>) -> Vec<GrantView>);
ipc!(@remote grant_put(input: GrantInputView) -> GrantView);
ipc!(@remote grant_delete(grant: String) -> ());
ipc!(policy_simulate(agent_id: String) -> Vec<SimulationRow>);
ipc!(@remote request_list_pending() -> Vec<AccessRequestView>);
ipc!(@remote request_approve(request: String, option: ApprovalOption) -> LeaseView);
ipc!(@remote request_deny(request: String) -> ());
ipc!(@remote lease_list() -> Vec<LeaseDetailView>);
ipc!(@remote lease_revoke(lease: String) -> ());
ipc!(lease_revoke_all() -> u64);
ipc!(@remote audit_query(query: AuditQueryView) -> Vec<AuditEntryView>);
ipc!(audit_verify() -> ChainReportView);
ipc!(audit_export(dest: String) -> u64);
ipc!(settings_get() -> SettingsView);
ipc!(settings_set(key: String, value: Value) -> SettingsView);
ipc!(network_status() -> NetworkView);
ipc!(network_set_bind(addrs: Vec<String>, port: u16) -> NetworkView);
ipc!(tls_export_ca(dest: String) -> ());
ipc!(tls_load_custom(chain_path: String, key_path: String) -> NetworkView);
ipc!(tls_use_local_ca() -> NetworkView);
ipc!(backup_create(dest: String) -> ());
ipc!(backup_restore(src: String, unlock: RestoreUnlockInput) -> ());
ipc!(csv_preview(request: CsvImportRequest) -> ImportPreviewView);
ipc!(csv_import(request: CsvImportRequest) -> ImportReport);
ipc!(csv_export(dest: String, workspace_id: Option<String>) -> u64);
ipc!(@both file_pick_open(title: Option<String>, extensions: Vec<String>) -> Option<String>);
ipc!(rustdesk_status() -> RustdeskStatusView);
ipc!(rustdesk_connect(item: String, copy_password: bool) -> RustdeskConnectView);
ipc!(@both remote_status() -> RemoteOverview);
ipc!(@both remote_import_bundle(path: String) -> RemoteProfileView);
ipc!(@both remote_discard_import() -> ());
ipc!(@both remote_disconnect() -> ());
ipc!(@both remote_forget(profile: String) -> ());

/// `remote_activate`: chooses the backend (`None`: local mode) and restarts the app to use it.
/// `lock_local` locks an unlocked local vault once every check passed ("Lock and connect"). The
/// quit work (lock, session close) runs before the restart. See `ops::remote_activate`.
#[tauri::command]
#[specta::specta]
pub async fn remote_activate(
    app: tauri::AppHandle,
    window: tauri::Window,
    state: tauri::State<'_, DesktopState>,
    profile: Option<String>,
    lock_local: bool,
) -> IpcResult<()> {
    if ops::remote_activate(&state, window.label(), profile, lock_local).await? {
        if tokio::time::timeout(crate::QUIT_WAIT, state.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("the shutdown before the restart took too long");
        }
        // The single-instance lock is released before the new process starts (DEC-RM-22).
        app.request_restart();
    }
    Ok(())
}

/// `kdf_benchmark`.
#[tauri::command]
#[specta::specta]
pub async fn kdf_benchmark(
    window: tauri::Window,
    state: tauri::State<'_, DesktopState>,
) -> IpcResult<KdfTuningView> {
    local_only(&state, window.label(), "kdf_benchmark")?;
    ops::kdf_benchmark(window.label()).await
}

/// `passphrase_strength`.
#[tauri::command]
#[specta::specta]
pub fn passphrase_strength(
    window: tauri::Window,
    state: tauri::State<'_, DesktopState>,
    phrase: Secret,
    user_inputs: Vec<String>,
) -> IpcResult<StrengthView> {
    local_only(&state, window.label(), "passphrase_strength")?;
    ops::passphrase_strength(window.label(), phrase, &user_inputs)
}

/// `passphrase_generate`.
#[tauri::command]
#[specta::specta]
pub fn passphrase_generate(
    window: tauri::Window,
    state: tauri::State<'_, DesktopState>,
    words: u32,
) -> IpcResult<Secret> {
    local_only(&state, window.label(), "passphrase_generate")?;
    ops::passphrase_generate(window.label(), words)
}

/// `ui_activity`.
#[tauri::command]
#[specta::specta]
pub fn ui_activity(window: tauri::Window, state: tauri::State<'_, DesktopState>) -> IpcResult<()> {
    ops::ui_activity(&state, window.label())
}

/// In remote mode: the window label check, then `remote_unsupported`. Locally: nothing.
fn local_only(state: &DesktopState, window: &str, command: &str) -> IpcResult<()> {
    if state.remote().is_some() {
        check(window, command)?;
        return Err(remote::unsupported());
    }
    Ok(())
}
