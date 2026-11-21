//! The remote allowlist (ADR-0034 point 5): the IPC commands that a desktop in remote mode may
//! send to the admin API of `cerberusd`, and what each one needs. The server and the desktop use
//! this one list, so they cannot disagree.

/// Version of the admin wire. `GET /admin/v1/hello` reports it; the desktop refuses a server
/// with another version.
pub const ADMIN_PROTOCOL: u32 = 1;

/// What a remote command needs besides an enrolled client certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// The device only: it works before a session is open, also while the vault is sealed.
    PreSession,
    /// Opens a session. It goes to `POST /admin/v1/session`, never through `rpc`.
    OpensSession,
    /// A live admin session.
    Session,
}

/// Number of commands on the remote allowlist.
pub const REMOTE_COMMAND_COUNT: usize = 25;

/// The remote allowlist. Every other IPC command is local only (`remote_unsupported`).
pub const REMOTE_COMMANDS: [(&str, Gate); REMOTE_COMMAND_COUNT] = [
    ("vault_status", Gate::PreSession),
    ("vault_list_operators", Gate::PreSession),
    ("vault_unlock", Gate::OpensSession),
    ("vault_lock", Gate::Session),
    ("vault_panic", Gate::Session),
    ("ui_activity", Gate::Session),
    ("workspace_list", Gate::Session),
    ("workspace_put", Gate::Session),
    ("item_list", Gate::Session),
    ("item_get", Gate::Session),
    ("item_create", Gate::Session),
    ("item_update", Gate::Session),
    ("item_delete", Gate::Session),
    ("item_reveal", Gate::Session),
    ("item_totp_preview", Gate::Session),
    ("agent_list", Gate::Session),
    ("grant_list", Gate::Session),
    ("grant_put", Gate::Session),
    ("grant_delete", Gate::Session),
    ("request_list_pending", Gate::Session),
    ("request_approve", Gate::Session),
    ("request_deny", Gate::Session),
    ("lease_list", Gate::Session),
    ("lease_revoke", Gate::Session),
    ("audit_query", Gate::Session),
];

/// The session commands that count as activity of the person: they reset the idle limit of the admin session and
/// the operator activity of the vault (ADR-0034 point 6.5). The keep-alive `ui_activity`, and the actions that change
/// something or show a secret, which only a person starts. The reads (lists, `item_get`, `audit_query`,
/// `request_list_pending`) do not count: the desktop also makes them in the background, after live events, so they
/// must not keep an unattended desktop's session or the server's idle lock alive (DEC-RM-26). This is the local
/// rule too, where only `ui_activity` and actions of the person count.
pub const ACTIVITY_COMMANDS: [&str; 13] = [
    "ui_activity",
    "vault_lock",
    "vault_panic",
    "workspace_put",
    "item_create",
    "item_update",
    "item_delete",
    "item_reveal",
    "item_totp_preview",
    "grant_put",
    "grant_delete",
    "request_approve",
    "request_deny",
];

/// True when a session call of `command` counts as activity of the person. See [`ACTIVITY_COMMANDS`].
#[must_use]
pub fn counts_as_activity(command: &str) -> bool {
    ACTIVITY_COMMANDS.contains(&command)
}

/// The gate of a command. `None`: the command is not on the remote allowlist.
#[must_use]
pub fn gate(command: &str) -> Option<Gate> {
    REMOTE_COMMANDS
        .iter()
        .find(|(name, _)| *name == command)
        .map(|(_, gate)| *gate)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn the_allowlist_has_unique_names_and_the_gates_of_adr_0034() {
        let names: BTreeSet<_> = REMOTE_COMMANDS.iter().map(|(name, _)| *name).collect();
        assert_eq!(names.len(), REMOTE_COMMAND_COUNT);
        let count = |g: Gate| REMOTE_COMMANDS.iter().filter(|(_, x)| *x == g).count();
        assert_eq!(count(Gate::PreSession), 2);
        assert_eq!(count(Gate::OpensSession), 1);
        assert_eq!(count(Gate::Session), 22);
        assert_eq!(gate("vault_unlock"), Some(Gate::OpensSession));
        assert_eq!(gate("vault_status"), Some(Gate::PreSession));
        assert_eq!(gate("item_reveal"), Some(Gate::Session));
    }

    #[test]
    fn activity_is_the_keep_alive_and_the_actions_of_a_person_never_a_read() {
        for command in ACTIVITY_COMMANDS {
            assert_eq!(gate(command), Some(Gate::Session), "{command}");
        }
        for read in [
            "workspace_list",
            "item_list",
            "item_get",
            "agent_list",
            "grant_list",
            "request_list_pending",
            "lease_list",
            "audit_query",
            "vault_status",
            "vault_list_operators",
        ] {
            assert!(!counts_as_activity(read), "{read}");
        }
        assert!(counts_as_activity("ui_activity"));
        assert!(counts_as_activity("request_approve"));
    }

    #[test]
    fn local_only_commands_are_not_on_the_list() {
        for command in [
            "vault_create",
            "vault_unlock_recovery",
            "item_versions",
            "clipboard_copy_secret",
            "ssh_key_generate",
            "lease_revoke_all",
            "settings_set",
            "backup_restore",
            "rustdesk_status",
            "rustdesk_connect",
            "file_pick_open",
            "",
        ] {
            assert_eq!(gate(command), None, "{command}");
        }
    }
}
