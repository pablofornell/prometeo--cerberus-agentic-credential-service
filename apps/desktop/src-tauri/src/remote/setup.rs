//! First-time setup of a server (ADR-0034, DEC-SRV-3), the desktop side: the types that the two
//! commands share with the UI, the setup code with its optional address, and the mapping of the
//! client errors to IPC errors.
//!
//! The operator reads a setup code on the server (`cerberusd setup-code`) and pastes it here. The
//! code holds the pin of the throwaway certificate that the server shows until its vault exists,
//! so the passphrase goes only to the server that holds the code. The text of an error never holds
//! the code, the token, the passphrase or the recovery key.

use cerberus_admin::bundle::{AdminBundle, check_url};
use cerberus_admin::dto::{RemoteProfileView, Secret};
use cerberus_admin::error::{FieldProblemView, IpcError, IpcResult};
use cerberus_client::ClientError;
use cerberus_client::setup::{SetupCode, SetupHealth};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use specta::Type;

/// What a server without a vault says about its setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    /// The server waits for its first client.
    Pending,
    /// The server took too many wrong tokens from this address and asks it to wait. The wait is temporary, the code stays
    /// valid and no restart is needed; the answer of a refused setup has the seconds (`retry_after_seconds`).
    LockedOut,
}

/// Result of `remote_setup_check`: what the server of a setup code says before anything is sent
/// to it that is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct RemoteSetupCheckView {
    /// The address the setup connects to: the one in the code, or the one the person chose.
    pub url: String,
    /// The setup state of the server.
    pub state: SetupState,
    /// The server version.
    pub version: String,
}

/// Result of `remote_setup`: the recovery key, which the server shows only once, and the profile
/// of the new server. The key always comes back once the server made the vault, even when this
/// desktop could not keep the profile: then `profile` is `None`, `store_error` says why, and
/// `remote_setup_save` tries again from the bundle that the backend holds.
#[derive(Debug, Serialize, Deserialize, Type)]
pub struct RemoteSetupView {
    /// The profile of the new server. It is stored, and not the active one: `remote_activate`
    /// connects to it.
    pub profile: Option<RemoteProfileView>,
    /// Why the profile is not stored.
    pub store_error: Option<IpcError>,
    /// The recovery key of the new vault.
    pub recovery_key: Secret,
}

/// Reads the setup code the person pasted and applies the address they chose, if any. A bad code
/// is `validation_failed` on the field `code`; the text of the code is never quoted.
///
/// # Errors
/// `validation_failed` for a code that is not a setup code or an address that is not
/// `https://host[:port]`.
pub fn parse_code(code: Secret, url: Option<&str>) -> IpcResult<SetupCode> {
    let text = code.into_core();
    let mut parsed = SetupCode::parse(text.expose_secret())
        .map_err(|_| IpcError::invalid("code", "is not a Cerberus setup code"))?;
    if let Some(url) = chosen_url(url)? {
        parsed.url = url;
    }
    Ok(parsed)
}

/// The address the person typed: `None` when empty.
///
/// # Errors
/// `validation_failed` on the field `url` when it is not `https://host[:port]`.
pub fn chosen_url(url: Option<&str>) -> IpcResult<Option<String>> {
    let Some(text) = url.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    check_url(text).map_err(|_| IpcError::invalid("url", "must look like https://host:port"))?;
    Ok(Some(text.to_owned()))
}

/// The view of the health answer of a server.
///
/// # Errors
/// `conflict` when the server has a vault, `remote_protocol_mismatch` when it says something this
/// desktop does not know.
pub fn check_view(url: &str, health: SetupHealth) -> IpcResult<RemoteSetupCheckView> {
    if health.vault != "no_vault" {
        return Err(IpcError::new("conflict", "this server already has a vault"));
    }
    let state = match health.setup.as_deref() {
        Some("pending") => SetupState::Pending,
        Some("locked_out") => SetupState::LockedOut,
        _ => {
            return Err(IpcError::new(
                "remote_protocol_mismatch",
                "the server does not speak the setup protocol of this desktop",
            ));
        }
    };
    Ok(RemoteSetupCheckView {
        url: url.to_owned(),
        state,
        version: health.version,
    })
}

/// How far before its end the certificate of a setup bundle is checked: inside its validity,
/// whatever the clock of this computer says.
const CHECK_BEFORE_END_SECS: i64 = 3600;

/// The admin bundle of a setup, read from its JSON and checked as the import of a file is, with
/// one difference. The bundle just came over the channel that the setup code pins, and the server
/// back-dates the start of its certificate by a few minutes only, so a clock of this computer that
/// is behind would fail an honest bundle. The chain and the key are checked at a time inside the
/// validity; the end of the validity is checked against the clock of this computer.
///
/// # Errors
/// `invalid_bundle` when the bundle cannot be read, does not pass the checks, or has expired.
pub fn bundle_from_json(json: &[u8], now: Timestamp) -> IpcResult<AdminBundle> {
    let invalid = |text: &str| IpcError::new("invalid_bundle", text);
    let bundle: AdminBundle = serde_json::from_slice(json)
        .map_err(|_| invalid("the server sent a bundle that cannot be read"))?;
    let inside = Timestamp::from_second(
        bundle
            .not_after
            .as_second()
            .saturating_sub(CHECK_BEFORE_END_SECS),
    )
    .map_err(|_| invalid("the bundle has a date that cannot be used"))?;
    bundle
        .check(inside)
        .map_err(|error| invalid(&error.to_string()))?;
    if now >= bundle.not_after {
        return Err(invalid("the client certificate of the bundle has expired"));
    }
    Ok(bundle)
}

/// The IPC error of a failed call to a server that waits for its setup. `unconfirmed` is true for
/// the call that creates the vault: after a timeout, a broken connection or an answer that cannot
/// be read, the vault may exist.
///
/// The codes the UI reads: the codes of the server (`unauthenticated`, `too_many_failures`,
/// `conflict`, `validation_failed`, `unavailable`, `internal`), `setup_wrong_server` (the pin of
/// the code does not match), `remote_unreachable`, `setup_unconfirmed` and
/// `remote_protocol_mismatch`.
#[must_use]
pub fn setup_error(error: &ClientError, unconfirmed: bool) -> IpcError {
    match error {
        ClientError::Api(api) => {
            let mut out = IpcError::new(api.code.as_str(), &api.message);
            out.retry_after_seconds = api.retry_after_seconds();
            out.fields = api
                .details
                .iter()
                .filter_map(|details| details.fields.as_ref())
                .flatten()
                .map(|problem| FieldProblemView {
                    field: problem.field.clone(),
                    problem: problem.problem.clone(),
                })
                .collect();
            out
        }
        ClientError::PinMismatch => IpcError::new(
            "setup_wrong_server",
            "this is not the server of the setup code, or its setup code changed",
        ),
        ClientError::Timeout | ClientError::Transport(_) | ClientError::Decode(_)
            if unconfirmed =>
        {
            tracing::warn!(%error, "the server setup did not finish");
            IpcError::new(
                "setup_unconfirmed",
                "the answer of the server did not arrive; the vault may exist",
            )
        }
        ClientError::Connect(_)
        | ClientError::Tls(_)
        | ClientError::Timeout
        | ClientError::Transport(_) => {
            tracing::warn!(%error, "the server of the setup code cannot be reached");
            IpcError::new("remote_unreachable", "cannot reach the server")
        }
        ClientError::Config(_) => IpcError::invalid("url", "is not a usable server address"),
        ClientError::Decode(_) => IpcError::new(
            "remote_protocol_mismatch",
            "the server does not speak the setup protocol of this desktop",
        ),
        other => IpcError::internal(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(vault: &str, setup: Option<&str>) -> SetupHealth {
        SetupHealth {
            status: "ok".to_owned(),
            vault: vault.to_owned(),
            setup: setup.map(ToOwned::to_owned),
            version: "0.4.0".to_owned(),
        }
    }

    #[test]
    fn a_waiting_server_has_a_state_and_any_other_is_refused() {
        let url = "https://vault.example.test:7373";
        assert_eq!(
            check_view(url, health("no_vault", Some("pending")))
                .expect("pending")
                .state,
            SetupState::Pending
        );
        assert_eq!(
            check_view(url, health("no_vault", Some("locked_out")))
                .expect("locked")
                .state,
            SetupState::LockedOut
        );
        assert_eq!(
            check_view(url, health("sealed", None))
                .expect_err("has a vault")
                .code,
            "conflict"
        );
        assert_eq!(
            check_view(url, health("no_vault", None))
                .expect_err("unknown")
                .code,
            "remote_protocol_mismatch"
        );
    }

    #[test]
    fn an_address_is_a_plain_https_origin_or_nothing() {
        assert_eq!(chosen_url(None).expect("none"), None);
        assert_eq!(chosen_url(Some("  ")).expect("blank"), None);
        assert_eq!(
            chosen_url(Some(" https://localhost:7373 ")).expect("ok"),
            Some("https://localhost:7373".to_owned())
        );
        for bad in ["http://x", "localhost:7373", "https://u:p@x", "https://x/a"] {
            assert_eq!(
                chosen_url(Some(bad)).expect_err(bad).code,
                "validation_failed",
                "{bad}"
            );
        }
    }

    #[test]
    fn a_text_that_is_not_a_code_is_refused_without_quoting_it() {
        let error =
            parse_code(Secret::new("canary-not-a-code".to_owned()), None).expect_err("not a code");
        assert_eq!(error.code, "validation_failed");
        assert_eq!(error.fields.len(), 1);
        assert_eq!(error.fields[0].field, "code");
        assert!(!format!("{error:?}").contains("canary-not-a-code"));
    }

    #[test]
    fn a_wait_after_too_many_wrong_codes_keeps_its_seconds_and_the_fields_of_a_refusal_come_through()
     {
        use cerberus_client::ApiError;
        use cerberus_types::wire::{ErrorDetails, FieldProblem};
        use cerberus_types::{ErrorCode, RequestId};
        let api = |code, details| {
            ClientError::Api(Box::new(ApiError {
                status: 429,
                code,
                message: "wait before the next try".to_owned(),
                request_id: RequestId::generate(),
                retryable: true,
                details: Some(details),
            }))
        };
        let wait = setup_error(
            &api(
                ErrorCode::TooManyFailures,
                ErrorDetails {
                    retry_after_seconds: Some(8),
                    ..ErrorDetails::default()
                },
            ),
            true,
        );
        assert_eq!(wait.code, "too_many_failures");
        assert_eq!(wait.retry_after_seconds, Some(8));
        let fields = setup_error(
            &api(
                ErrorCode::ValidationFailed,
                ErrorDetails {
                    fields: Some(vec![FieldProblem {
                        field: "passphrase".to_owned(),
                        problem: "is too weak".to_owned(),
                    }]),
                    ..ErrorDetails::default()
                },
            ),
            true,
        );
        assert_eq!(fields.fields.len(), 1);
        assert_eq!(fields.fields[0].field, "passphrase");
        assert_eq!(fields.retry_after_seconds, None);
    }

    #[test]
    fn transport_failures_are_unconfirmed_only_for_the_call_that_makes_the_vault() {
        assert_eq!(
            setup_error(&ClientError::Timeout, true).code,
            "setup_unconfirmed"
        );
        assert_eq!(
            setup_error(&ClientError::Transport("x".to_owned()), false).code,
            "remote_unreachable"
        );
        assert_eq!(
            setup_error(&ClientError::Decode("x".to_owned()), true).code,
            "setup_unconfirmed"
        );
        assert_eq!(
            setup_error(&ClientError::Decode("x".to_owned()), false).code,
            "remote_protocol_mismatch"
        );
        assert_eq!(
            setup_error(&ClientError::Connect("x".to_owned()), true).code,
            "remote_unreachable"
        );
        assert_eq!(
            setup_error(&ClientError::PinMismatch, true).code,
            "setup_wrong_server"
        );
    }
}
