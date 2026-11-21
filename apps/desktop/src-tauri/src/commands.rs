//! The `#[tauri::command]` wrappers. Each one passes the label of the calling window and the state
//! to the function of the same name in `ops`, which does the work. No wrapper takes a role or an
//! operator from the UI.

use serde_json::Value;

use crate::dto::{
    AccessRequestView, AgentCreated, AgentInputView, AgentKeyCreated, AgentKeyInputView,
    AgentStatus, AgentView, ApprovalOption, AuditEntryView, AuditQueryView, ChainReportView,
    CreatedVaultView, CsvImportRequest, GrantInputView, GrantView, ImportPreviewView, ImportReport,
    IssuedClientCert, ItemDetailView, ItemFilterView, ItemInputView, ItemSummaryView,
    ItemVersionView, KdfParamsView, KdfTuningView, LeaseDetailView, LeaseView, NetworkView,
    OneTimeKind, OperatorPublic, OperatorRole, RestoreUnlockInput, RevealedSecretView,
    RustdeskConnectView, RustdeskStatusView, Secret, SessionView, SettingsView, SimulationRow,
    Snippets, SshKeyDraft, StrengthView, TotpView, VaultStatusView, WorkspaceInputView,
    WorkspaceView,
};
use crate::error::IpcResult;
use crate::ops::{self, CharClass, SshKeySource};
use crate::state::DesktopState;

/// Makes a command that calls `ops::<name>(&state, window_label, args...)`.
macro_rules! ipc {
    ($name:ident ( $($arg:ident : $ty:ty),* $(,)? ) -> $ret:ty) => {
        #[doc = concat!("IPC command `", stringify!($name), "`. See `ops::", stringify!($name), "`.")]
        #[tauri::command]
        #[specta::specta]
        pub async fn $name(
            window: tauri::Window,
            state: tauri::State<'_, DesktopState>,
            $($arg: $ty),*
        ) -> IpcResult<$ret> {
            ops::$name(&state, window.label() $(, $arg)*).await
        }
    };
}

ipc!(vault_status() -> VaultStatusView);
ipc!(vault_list_operators() -> Vec<OperatorPublic>);
ipc!(
    vault_create(
        owner_label: String,
        phrase: Secret,
        kdf: KdfParamsView,
        host_names: Vec<String>,
    ) -> CreatedVaultView
);
ipc!(vault_unlock(operator_id: String, phrase: Secret) -> SessionView);
ipc!(vault_unlock_recovery(recovery_key: Secret) -> SessionView);
ipc!(vault_recover_stranded() -> ());
ipc!(vault_lock() -> ());
ipc!(vault_panic() -> ());
ipc!(phrase_change(current_phrase: Secret, new_phrase: Secret, kdf: Option<KdfParamsView>) -> ());
ipc!(recovery_rotate() -> Secret);
ipc!(operator_add(label: String, role: OperatorRole, phrase: Secret) -> OperatorPublic);
ipc!(operator_remove(operator: String) -> ());
ipc!(operator_set_role(operator: String, role: OperatorRole) -> ());
ipc!(workspace_list() -> Vec<WorkspaceView>);
ipc!(workspace_put(workspace: Option<String>, input: WorkspaceInputView) -> WorkspaceView);
ipc!(workspace_delete(workspace: String) -> ());
ipc!(item_list(filter: ItemFilterView) -> Vec<ItemSummaryView>);
ipc!(item_get(item: String) -> ItemDetailView);
ipc!(item_create(input: ItemInputView) -> ItemDetailView);
ipc!(item_update(item: String, input: ItemInputView) -> ItemDetailView);
ipc!(item_delete(item: String) -> ());
ipc!(item_reveal(item: String) -> RevealedSecretView);
ipc!(item_versions(item: String) -> Vec<ItemVersionView>);
ipc!(item_restore_version(item: String, version: u32) -> ItemDetailView);
ipc!(item_totp_preview(item: String) -> TotpView);
ipc!(clipboard_copy_secret(item: String, field: String) -> ());
ipc!(clipboard_copy_once(kind: OneTimeKind) -> ());
ipc!(password_generate(length: u32, classes: Vec<CharClass>) -> Secret);
ipc!(ssh_key_generate(comment: String) -> SshKeyDraft);
ipc!(ssh_key_import(source: SshKeySource, passphrase: Option<Secret>) -> SshKeyDraft);
ipc!(agent_list() -> Vec<AgentView>);
ipc!(agent_create(input: AgentInputView, key: AgentKeyInputView) -> AgentCreated);
ipc!(agent_update(agent: String, input: AgentInputView) -> AgentView);
ipc!(agent_set_status(agent: String, status: AgentStatus) -> AgentView);
ipc!(agent_key_create(agent_id: String, key: AgentKeyInputView) -> AgentKeyCreated);
ipc!(agent_key_rotate(key_id: String, overlap_seconds: u32) -> AgentKeyCreated);
ipc!(agent_key_revoke(key_id: String) -> ());
ipc!(agent_issue_client_cert(key_id: String, dest_dir: String) -> IssuedClientCert);
ipc!(agent_snippets(agent_id: String) -> Snippets);
ipc!(grant_list(agent_id: Option<String>) -> Vec<GrantView>);
ipc!(grant_put(input: GrantInputView) -> GrantView);
ipc!(grant_delete(grant: String) -> ());
ipc!(policy_simulate(agent_id: String) -> Vec<SimulationRow>);
ipc!(request_list_pending() -> Vec<AccessRequestView>);
ipc!(request_approve(request: String, option: ApprovalOption) -> LeaseView);
ipc!(request_deny(request: String) -> ());
ipc!(lease_list() -> Vec<LeaseDetailView>);
ipc!(lease_revoke(lease: String) -> ());
ipc!(lease_revoke_all() -> u64);
ipc!(audit_query(query: AuditQueryView) -> Vec<AuditEntryView>);
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
ipc!(file_pick_open(title: Option<String>, extensions: Vec<String>) -> Option<String>);
ipc!(rustdesk_status() -> RustdeskStatusView);
ipc!(rustdesk_connect(item: String, copy_password: bool) -> RustdeskConnectView);

/// `kdf_benchmark`.
#[tauri::command]
#[specta::specta]
pub async fn kdf_benchmark(window: tauri::Window) -> IpcResult<KdfTuningView> {
    ops::kdf_benchmark(window.label()).await
}

/// `passphrase_strength`.
#[tauri::command]
#[specta::specta]
pub fn passphrase_strength(
    window: tauri::Window,
    phrase: Secret,
    user_inputs: Vec<String>,
) -> IpcResult<StrengthView> {
    ops::passphrase_strength(window.label(), phrase, &user_inputs)
}

/// `passphrase_generate`.
#[tauri::command]
#[specta::specta]
pub fn passphrase_generate(window: tauri::Window, words: u32) -> IpcResult<Secret> {
    ops::passphrase_generate(window.label(), words)
}

/// `ui_activity`.
#[tauri::command]
#[specta::specta]
pub fn ui_activity(window: tauri::Window, state: tauri::State<'_, DesktopState>) -> IpcResult<()> {
    ops::ui_activity(&state, window.label())
}
