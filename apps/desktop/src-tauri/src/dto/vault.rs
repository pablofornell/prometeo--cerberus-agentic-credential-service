//! Types of the vault, operator, session and passphrase commands.

use cerberus_core::{CreatedVault, OperatorInfo, Session, VaultStatus};
use cerberus_crypto::{KdfParams, KdfTuning, SecretString, Strength};
use cerberus_types::LockReason;
use cerberus_types::wire::WireSecret;
use serde::{Deserialize, Serialize};
use specta::Type;

use super::{OperatorRole, VaultState, opt_ts, ts};
use crate::error::{IpcError, IpcResult};

/// A secret text that comes from the UI (a phrase, a recovery key). It is zeroized on drop, its
/// `Debug` prints `[REDACTED]`, and the bindings type it as `string`.
#[derive(Deserialize, Serialize, Type)]
#[serde(transparent)]
pub struct Secret(#[specta(type = String)] WireSecret);

impl Secret {
    /// Wraps a text.
    #[must_use]
    pub fn new(text: String) -> Self {
        Self(WireSecret::new(text))
    }

    /// The text as a core secret. The `String` inside moves, so no second copy is left behind.
    #[must_use]
    pub fn into_core(self) -> SecretString {
        SecretString::new(self.0.into_string())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Argon2id cost chosen by the person or by `kdf_benchmark`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct KdfParamsView {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Passes.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl From<KdfParams> for KdfParamsView {
    fn from(value: KdfParams) -> Self {
        Self {
            m_cost_kib: value.m_cost_kib(),
            t_cost: value.t_cost(),
            p_cost: value.p_cost(),
        }
    }
}

impl KdfParamsView {
    /// The checked core value.
    ///
    /// # Errors
    /// `validation_failed` when a value is outside the ADR-0013 range.
    pub fn into_core(self) -> IpcResult<KdfParams> {
        KdfParams::new(self.m_cost_kib, self.t_cost, self.p_cost)
            .map_err(|_| IpcError::invalid("kdf", "is outside the allowed range"))
    }
}

/// Result of `kdf_benchmark`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct KdfTuningView {
    /// The chosen cost.
    pub params: KdfParamsView,
    /// Measured time of one derivation, in milliseconds.
    pub measured_ms: u32,
}

impl From<KdfTuning> for KdfTuningView {
    fn from(value: KdfTuning) -> Self {
        Self {
            params: value.params.into(),
            measured_ms: u32::try_from(value.measured.as_millis()).unwrap_or(u32::MAX),
        }
    }
}

/// Result of `passphrase_strength`. It holds feedback text only, never the phrase.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Type)]
pub struct StrengthView {
    /// 0 (weak) to 4 (strong).
    pub score: u8,
    /// log10 of the estimated guesses.
    pub guesses_log10: f64,
    /// Main warning.
    pub warning: Option<String>,
    /// Suggestions.
    pub suggestions: Vec<String>,
    /// True when the phrase passes the vault rule (12 characters and a score of 3).
    pub acceptable: bool,
}

impl StrengthView {
    /// The view of a zxcvbn result.
    #[must_use]
    pub fn of(strength: Strength, acceptable: bool) -> Self {
        Self {
            score: strength.score,
            guesses_log10: strength.guesses_log10,
            warning: strength.warning,
            suggestions: strength.suggestions,
            acceptable,
        }
    }
}

/// One operator on the unlock screen. It is plain data: the list works while the vault is sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct OperatorPublic {
    /// Operator ID.
    pub id: String,
    /// Label.
    pub label: String,
    /// Role.
    pub role: OperatorRole,
    /// Last successful unlock.
    pub last_unlock_at: Option<String>,
}

impl From<OperatorInfo> for OperatorPublic {
    fn from(value: OperatorInfo) -> Self {
        Self {
            id: value.id.to_string(),
            label: value.label,
            role: value.role.into(),
            last_unlock_at: opt_ts(value.last_unlock_at),
        }
    }
}

/// Who is unlocked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct SessionView {
    /// Operator ID (the recovery slot ID for a recovery unlock).
    pub operator_id: String,
    /// The role of the session.
    pub role: OperatorRole,
    /// Unlock time.
    pub unlocked_at: String,
    /// True when the recovery key opened the vault.
    pub via_recovery: bool,
}

impl From<Session> for SessionView {
    fn from(value: Session) -> Self {
        Self {
            operator_id: value.operator_id.to_string(),
            role: value.role.into(),
            unlocked_at: ts(value.unlocked_at),
            via_recovery: value.via_recovery,
        }
    }
}

/// Why the vault was locked (DEC-INT10-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum LockReasonView {
    /// The person locked it.
    Manual,
    /// The idle timeout.
    Idle,
    /// The hard limit of unlocked time.
    MaxUnlocked,
    /// OS sleep or screen lock.
    Os,
    /// The app quit.
    Quit,
    /// The panic button, or a crash of the process.
    Panic,
    /// A backup restore.
    Restore,
}

impl From<LockReason> for LockReasonView {
    fn from(value: LockReason) -> Self {
        match value {
            LockReason::Manual => Self::Manual,
            LockReason::Idle => Self::Idle,
            LockReason::MaxUnlocked => Self::MaxUnlocked,
            LockReason::OsLock => Self::Os,
            LockReason::Quit => Self::Quit,
            LockReason::Panic | LockReason::PanicButton => Self::Panic,
            LockReason::Restore => Self::Restore,
        }
    }
}

/// Result of `vault_status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct VaultStatusView {
    /// The state.
    pub state: VaultState,
    /// Operator ID of the session, while unlocked.
    pub operator: Option<String>,
    /// Role of the session, while unlocked.
    pub role: Option<OperatorRole>,
    /// Seconds until the idle lock.
    pub idle_seconds_left: Option<u32>,
    /// Time of the hard lock.
    pub hard_lock_at: Option<String>,
    /// True when every key page is locked in RAM.
    pub memlock_ok: bool,
    /// True when the OS sleep and screen-lock hook works.
    pub os_hook_ok: bool,
    /// False when the header check failed at unlock.
    pub header_ok: bool,
    /// Unlock cost of the session operator's passphrase (no measured time is stored). `null`
    /// while sealed and for a recovery session. DEC-INT10-8.
    pub kdf: Option<KdfParamsView>,
    /// Why the latest lock of this run happened. `null` when the vault was not locked yet in this
    /// run. It stays after the next unlock. DEC-INT10-9.
    pub last_lock_reason: Option<LockReasonView>,
    /// Failed unlocks in a row. Kept in the vault header, so a restart and a second window see
    /// the same number. DEC-INT10-10.
    pub failed_unlocks: u32,
    /// Tries left before the wait starts (5 minus `failed_unlocks`, never below 0).
    pub free_unlock_tries_left: u32,
    /// Seconds until the next unlock try is allowed. `null` when no wait runs.
    pub retry_after_seconds: Option<u32>,
    /// Old vault files of a failed restore (`<vault>.pre-restore-*`), newest first, found while
    /// the vault file itself is missing. Empty in every normal run. While it is not empty the
    /// state is `no_vault`, no vault is made, and the person can put the newest one back
    /// (`vault_recover_stranded`). T27-G.
    pub stranded_restore: Vec<String>,
}

impl VaultStatusView {
    /// The status while the vault is stranded: no vault service runs.
    #[must_use]
    pub fn stranded(paths: &[std::path::PathBuf]) -> Self {
        Self {
            state: VaultState::NoVault,
            operator: None,
            role: None,
            idle_seconds_left: None,
            hard_lock_at: None,
            memlock_ok: !cerberus_crypto::memlock::lock_failed(),
            os_hook_ok: false,
            header_ok: true,
            kdf: None,
            last_lock_reason: None,
            failed_unlocks: 0,
            free_unlock_tries_left: 0,
            retry_after_seconds: None,
            stranded_restore: paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        }
    }
}

impl From<VaultStatus> for VaultStatusView {
    fn from(value: VaultStatus) -> Self {
        Self {
            state: value.state.into(),
            operator: value.session.map(|s| s.operator_id.to_string()),
            role: value.session.map(|s| s.role.into()),
            idle_seconds_left: value
                .idle_seconds_left
                .map(|s| u32::try_from(s).unwrap_or(u32::MAX)),
            hard_lock_at: opt_ts(value.hard_lock_at),
            memlock_ok: value.memlock_ok,
            os_hook_ok: value.os_hook_ok,
            header_ok: value.header_ok,
            kdf: value.kdf.map(Into::into),
            last_lock_reason: value.last_lock_reason.map(Into::into),
            failed_unlocks: value.failed_unlocks,
            free_unlock_tries_left: value.free_unlock_tries_left,
            retry_after_seconds: Some(value.retry_after_seconds).filter(|s| *s > 0),
            stranded_restore: Vec::new(),
        }
    }
}

/// Result of `vault_create`. The recovery key is shown one time.
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct CreatedVaultView {
    /// ID of the owner operator.
    pub owner_id: String,
    /// The recovery key text.
    pub recovery_key: Secret,
    /// `sha256/...` pin of the local CA.
    pub ca_pin: String,
}

impl CreatedVaultView {
    /// The view of a new vault. The recovery key text moves into the view.
    #[must_use]
    pub fn of(created: CreatedVault, recovery_text: String) -> Self {
        Self {
            owner_id: created.owner_id.to_string(),
            recovery_key: Secret::new(recovery_text),
            ca_pin: created.ca_pin,
        }
    }
}

/// A one-time value the backend keeps for the clipboard (DEC-036).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum OneTimeKind {
    /// The recovery key of `vault_create` or `recovery_rotate`.
    RecoveryKey,
    /// The token of `agent_create`, `agent_key_create` or `agent_key_rotate`.
    AgentToken,
}
