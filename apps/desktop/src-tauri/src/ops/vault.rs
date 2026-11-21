//! Commands of the vault, the operators and the passphrase tools.

use std::time::Duration;

use cerberus_admin::handlers;
use cerberus_core::{KeyCustody, NewVault};
use cerberus_crypto::{
    DICEWARE_MAX_WORDS, RecoveryKey, meets_phrase_policy, normalize_phrase, phrase_strength,
    total_ram_bytes, tune_kdf,
};
use cerberus_types::OperatorRole as CoreRole;

use crate::dto::{
    CreatedVaultView, KdfParamsView, KdfTuningView, OneTimeKind, OperatorPublic, OperatorRole,
    Secret, SessionView, StrengthView, VaultStatusView, id,
};
use crate::error::{IpcError, IpcResult};
use crate::guard::check;
use crate::state::DesktopState;

/// Target time of one key derivation at unlock (ADR-0013, DEC-049).
const KDF_TARGET: Duration = Duration::from_millis(700);

/// `vault_status`.
pub async fn vault_status(state: &DesktopState, window: &str) -> IpcResult<VaultStatusView> {
    check(window, "vault_status")?;
    let stranded = state.stranded_restore();
    if !stranded.is_empty() {
        return Ok(VaultStatusView::stranded(&stranded));
    }
    Ok(handlers::vault_status(&state.core()?).await)
}

/// `vault_list_operators`. Works while sealed.
pub async fn vault_list_operators(
    state: &DesktopState,
    window: &str,
) -> IpcResult<Vec<OperatorPublic>> {
    check(window, "vault_list_operators")?;
    handlers::vault_list_operators(&state.core()?).await
}

/// `vault_create`. Only in state `NoVault`. Starts the HTTPS server, because the local CA and the
/// first leaf certificate exist now.
pub async fn vault_create(
    state: &DesktopState,
    window: &str,
    owner_label: String,
    phrase: Secret,
    kdf: KdfParamsView,
    host_names: Vec<String>,
) -> IpcResult<CreatedVaultView> {
    check(window, "vault_create")?;
    let core = state.core()?;
    let created = core
        .create_vault(NewVault {
            owner_label,
            phrase: phrase.into_core(),
            kdf: kdf.into_core()?,
            host_names,
        })
        .await?;
    let recovery_text = created.recovery_key.expose_secret().to_owned();
    state
        .set_one_time(OneTimeKind::RecoveryKey, &recovery_text)
        .await;
    state.start_server_if_ready(&core).await;
    Ok(CreatedVaultView::of(created, recovery_text))
}

async fn session_view(state: &DesktopState) -> IpcResult<SessionView> {
    let (core, _) = state.operator().await?;
    core.status()
        .await
        .session
        .map(Into::into)
        .ok_or_else(|| cerberus_core::CoreError::Locked.into())
}

/// `vault_unlock`. It waits while a restore or a stranded-vault recovery runs (they hold the
/// restore gate): an unlock of the old vault between the restore's lock and the swap would start
/// a server on a service that is being closed (NEW-14), and a recovered vault must have its
/// revoke marker written before it can be unlocked (NEW-12). Then it unlocks the vault that is in
/// place.
pub async fn vault_unlock(
    state: &DesktopState,
    window: &str,
    operator_id: String,
    phrase: Secret,
) -> IpcResult<SessionView> {
    check(window, "vault_unlock")?;
    let operator = id("operator_id", &operator_id)?;
    let _gate = state.inner.restore_gate.lock().await;
    state
        .core()?
        .unlock_with_phrase(operator, phrase.into_core())
        .await?;
    session_view(state).await
}

/// `vault_unlock_recovery`. Waits for the restore gate, as [`vault_unlock`].
pub async fn vault_unlock_recovery(
    state: &DesktopState,
    window: &str,
    recovery_key: Secret,
) -> IpcResult<SessionView> {
    check(window, "vault_unlock_recovery")?;
    let text = recovery_key.into_core();
    let key = RecoveryKey::parse(text.expose_secret())
        .map_err(|_| IpcError::invalid("recovery_key", "is not a valid recovery key"))?;
    let _gate = state.inner.restore_gate.lock().await;
    state.core()?.unlock_with_recovery(key).await?;
    session_view(state).await
}

/// `vault_lock`. Locking a vault that is already locked is not an error.
pub async fn vault_lock(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "vault_lock")?;
    handlers::vault_lock(&state.core()?).await?;
    state.clear_held();
    Ok(())
}

/// `vault_panic`: revokes all leases, cancels all requests, locks.
pub async fn vault_panic(state: &DesktopState, window: &str) -> IpcResult<()> {
    check(window, "vault_panic")?;
    let (core, ctx) = state.operator().await?;
    handlers::vault_panic(&core, &ctx).await?;
    state.clear_held();
    Ok(())
}

/// `kdf_benchmark`: measures this machine (a few hundred milliseconds of work).
pub async fn kdf_benchmark(window: &str) -> IpcResult<KdfTuningView> {
    check(window, "kdf_benchmark")?;
    let ram = total_ram_bytes().unwrap_or(u64::MAX);
    let tuning = tokio::task::spawn_blocking(move || tune_kdf(KDF_TARGET, ram))
        .await
        .map_err(|e| IpcError::internal(&e))??;
    Ok(tuning.into())
}

/// `passphrase_strength`.
pub fn passphrase_strength(
    window: &str,
    phrase: Secret,
    user_inputs: &[String],
) -> IpcResult<StrengthView> {
    check(window, "passphrase_strength")?;
    let phrase = normalize_phrase(phrase.into_core().expose_secret());
    let inputs: Vec<&str> = user_inputs.iter().map(String::as_str).collect();
    let strength = phrase_strength(&phrase, &inputs);
    let acceptable = meets_phrase_policy(&phrase, &inputs);
    Ok(StrengthView::of(strength, acceptable))
}

/// `passphrase_generate`: a Diceware phrase. The text goes to the UI one time.
pub fn passphrase_generate(window: &str, words: u32) -> IpcResult<Secret> {
    check(window, "passphrase_generate")?;
    let words = usize::try_from(words).unwrap_or(usize::MAX);
    if words == 0 || words > DICEWARE_MAX_WORDS {
        return Err(IpcError::invalid("words", "must be 1 to 64"));
    }
    let phrase = cerberus_crypto::diceware(words)?;
    Ok(Secret::new(phrase.expose_secret().to_owned()))
}

/// `phrase_change`: the operator's own phrase. Any role.
pub async fn phrase_change(
    state: &DesktopState,
    window: &str,
    current_phrase: Secret,
    new_phrase: Secret,
    kdf: Option<KdfParamsView>,
) -> IpcResult<()> {
    check(window, "phrase_change")?;
    let (core, ctx) = state.operator().await?;
    let kdf = kdf.map(KdfParamsView::into_core).transpose()?;
    core.change_phrase_with_kdf(
        &ctx,
        current_phrase.into_core(),
        new_phrase.into_core(),
        kdf,
    )
    .await?;
    Ok(())
}

/// `recovery_rotate`: owner. The new key text is shown one time.
pub async fn recovery_rotate(state: &DesktopState, window: &str) -> IpcResult<Secret> {
    check(window, "recovery_rotate")?;
    let (core, ctx) = state.operator().await?;
    let key = core.rotate_recovery_key(&ctx).await?;
    state
        .set_one_time(OneTimeKind::RecoveryKey, key.expose_secret())
        .await;
    Ok(Secret::new(key.expose_secret().to_owned()))
}

/// `operator_add`: owner.
pub async fn operator_add(
    state: &DesktopState,
    window: &str,
    label: String,
    role: OperatorRole,
    phrase: Secret,
) -> IpcResult<OperatorPublic> {
    check(window, "operator_add")?;
    let (core, ctx) = state.operator().await?;
    let new_id = core
        .add_operator(&ctx, label, CoreRole::from(role), phrase.into_core())
        .await?;
    core.list_operators()
        .await?
        .into_iter()
        .find(|operator| operator.id == new_id)
        .map(Into::into)
        .ok_or_else(|| cerberus_core::CoreError::NotFound.into())
}

/// `operator_remove`: owner.
pub async fn operator_remove(
    state: &DesktopState,
    window: &str,
    operator: String,
) -> IpcResult<()> {
    check(window, "operator_remove")?;
    let (core, ctx) = state.operator().await?;
    core.remove_operator(&ctx, id("id", &operator)?).await?;
    Ok(())
}

/// `operator_set_role`: owner.
pub async fn operator_set_role(
    state: &DesktopState,
    window: &str,
    operator: String,
    role: OperatorRole,
) -> IpcResult<()> {
    check(window, "operator_set_role")?;
    let (core, ctx) = state.operator().await?;
    core.set_operator_role(&ctx, id("id", &operator)?, role.into())
        .await?;
    Ok(())
}
