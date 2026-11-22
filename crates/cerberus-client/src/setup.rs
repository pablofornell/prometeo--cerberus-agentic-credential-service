//! First-time setup of a `cerberusd` that has no vault yet (ADR-0034, DEC-SRV-3).
//!
//! A server with no vault waits for its first client. The operator reads a **setup code** on the server
//! (`cerberusd setup-code`) and gives it to the client: `cerberus-setup:1:<base64url(json {url, token, pin})>`. The
//! `pin` is `sha256/<base64>` of the key of the throwaway certificate that the server shows until the vault exists,
//! so [`setup`] sends the passphrase only to the server that holds the code. The server makes the vault, enrols this
//! client as an admin client and answers one time with the recovery key and an admin bundle: the same bundle that
//! `cerberusd admin enroll` writes, so the desktop imports it like any other.
//!
//! ```no_run
//! # async fn demo() -> Result<(), cerberus_client::ClientError> {
//! use cerberus_client::setup::{SetupCode, SetupRequest, setup};
//! use cerberus_client::WireSecret;
//!
//! let code = SetupCode::parse("cerberus-setup:1:...")?;
//! let outcome = setup(
//!     &code,
//!     &SetupRequest::new("owner", WireSecret::new("a long passphrase".to_owned())),
//! )
//! .await?;
//! // Show `outcome.recovery_key` one time, then keep the bundle: `outcome.bundle.write_new(path)`.
//! # Ok(()) }
//! ```
//!
//! Nothing here keeps a secret longer than its owner: [`WireSecret`] and zeroizing buffers wipe on drop. Debug
//! output never shows the token, the passphrase, the recovery key or the bundle key.

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

use cerberus_types::wire::{ErrorResponse, WireSecret};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::parse_base_url;
use crate::error::{ApiError, ClientError};
use crate::tls::parse_pin;
use crate::transport::{PinnedHttps, Request, zeroizing_body};

/// What a setup code starts with: the format name and its version.
pub const SETUP_CODE_PREFIX: &str = "cerberus-setup:1:";
/// Time limit of one call. The server measures the key-derivation cost of its machine before it makes the vault.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest answer that is read.
const MAX_ANSWER_BYTES: usize = 64 * 1024;
/// Room for the JSON of a request without growing: a character takes at most six bytes when escaped.
const REQUEST_ROOM: usize = 512;

/// A parsed setup code. `Debug` does not show the token.
#[derive(Debug)]
pub struct SetupCode {
    /// The URL of the server, `https://host:port`. The client connects to it, and the bundle holds it unless the
    /// request names another. The app may change it (an SSH tunnel end, for example) before it calls [`setup`]; the
    /// host must be a TLS name of the server.
    pub url: String,
    /// The one-time token.
    pub token: WireSecret,
    /// `sha256/<base64>` of the key of the setup certificate.
    pub pin: String,
}

/// The JSON inside a setup code.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeBody {
    url: String,
    token: WireSecret,
    pin: String,
}

impl SetupCode {
    /// Reads a setup code as the operator pastes it. Spaces and line breaks around it are ignored.
    ///
    /// # Errors
    /// [`ClientError::Config`] when it is not a setup code of this version, or its URL or pin is not valid.
    pub fn parse(text: &str) -> Result<Self, ClientError> {
        let bad = || ClientError::Config("this is not a Cerberus setup code".to_owned());
        let body = text
            .trim()
            .strip_prefix(SETUP_CODE_PREFIX)
            .ok_or_else(bad)?;
        let json = Zeroizing::new(BASE64URL_NOPAD.decode(body.as_bytes()).map_err(|_| bad())?);
        let parsed: CodeBody = serde_json::from_slice(&json).map_err(|_| bad())?;
        parse_base_url(&parsed.url)?;
        parse_pin(&parsed.pin)?;
        if parsed.token.expose().is_empty() {
            return Err(bad());
        }
        Ok(Self {
            url: parsed.url,
            token: parsed.token,
            pin: parsed.pin,
        })
    }
}

/// What the client asks for. `Debug` does not show the passphrase.
#[derive(Debug)]
pub struct SetupRequest {
    /// Label of the first owner, 1 to 64 characters.
    pub owner_label: String,
    /// The owner passphrase. The server checks the passphrase policy (12 characters or more, a strength score of 3
    /// or more); a refusal is a [`ClientError::Api`] with the code `validation_failed` and the field `passphrase`.
    pub passphrase: WireSecret,
    /// Label of this client in the admin registry of the server, 1 to 64 characters. Default on the server: `desktop`.
    pub device_label: Option<String>,
    /// The URL that the bundle holds, `https://host:port`. Default: the URL of the setup code.
    pub url: Option<String>,
}

impl SetupRequest {
    /// A request with the two required values.
    #[must_use]
    pub fn new(owner_label: impl Into<String>, passphrase: WireSecret) -> Self {
        Self {
            owner_label: owner_label.into(),
            passphrase,
            device_label: None,
            url: None,
        }
    }
}

/// The answer to [`health`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SetupHealth {
    /// Always `ok`.
    pub status: String,
    /// `no_vault` while the server waits for its first client.
    pub vault: String,
    /// `pending`, or `locked_out` while the address of this client has to wait after too many wrong tokens (temporary:
    /// see `retry_after_seconds` of the `too_many_failures` error; no restart is needed).
    #[serde(default)]
    pub setup: Option<String>,
    /// The server version.
    pub version: String,
}

/// The admin bundle of the new enrolment. It has the same fields and the same JSON as the file that
/// `cerberusd admin enroll` writes (`cerberus_admin::bundle::AdminBundle`), so the desktop reads it with that type. It
/// holds the client private key: `Debug` shows `[REDACTED]` for it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupBundle {
    /// Always `cerberus-admin-bundle`.
    pub format: String,
    /// The bundle version.
    pub version: u32,
    /// Enrolment ID.
    pub id: String,
    /// The device label.
    pub label: String,
    /// The URL of the server.
    pub url: String,
    /// The operator the enrolment is bound to: the new owner.
    pub operator_id: String,
    /// `sha256/<base64>` of the CA public key of the new vault.
    pub ca_pin: String,
    /// The vault CA certificate, PEM.
    pub ca_cert_pem: String,
    /// The client certificate, PEM.
    pub client_cert_pem: String,
    /// The client private key, PKCS#8 PEM.
    pub client_key_pem: WireSecret,
    /// End of validity of the client certificate, RFC 3339.
    pub not_after: String,
}

impl SetupBundle {
    /// The bundle as the JSON text of a bundle file, in a zeroizing buffer.
    ///
    /// # Errors
    /// [`ClientError::Decode`] when it cannot be written (it cannot, in practice).
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let mut out = Zeroizing::new(Vec::with_capacity(16 * 1024));
        serde_json::to_writer(&mut *out, self)
            .map_err(|error| ClientError::Decode(error.to_string()))?;
        Ok(out)
    }

    /// Writes the bundle to a new file with mode `0600` on Unix, the same file `cerberusd admin enroll` writes. The
    /// file must not exist.
    ///
    /// # Errors
    /// [`ClientError::Io`] when the file exists or cannot be written.
    pub fn write_new(&self, path: &Path) -> Result<(), ClientError> {
        let body = self.to_json()?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&body)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }
}

/// What a successful setup gives. It is the only time the server shows the recovery key. `Debug` shows no secret.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupOutcome {
    /// The recovery key, `CRK1-...`. Show it to the person one time and ask them to store it offline: without it and
    /// the passphrase the data cannot be restored, and the server cannot show it again.
    pub recovery_key: WireSecret,
    /// `sha256/<base64>` of the CA public key of the new vault.
    pub ca_pin: String,
    /// The ID of the first owner (the operator of the bundle).
    pub owner_id: String,
    /// The admin bundle of this client.
    pub bundle: SetupBundle,
}

/// The request as it goes on the wire.
#[derive(Serialize)]
struct WireRequest<'a> {
    setup_token: &'a str,
    owner_label: &'a str,
    passphrase: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_label: Option<&'a str>,
    url: &'a str,
}

/// Asks the server in `code` for its state: `GET /v1/health` over the pinned setup channel.
///
/// # Errors
/// [`ClientError::Connect`], [`ClientError::PinMismatch`] (not the server of the code), [`ClientError::Tls`],
/// [`ClientError::Api`] or [`ClientError::Decode`].
pub async fn health(code: &SetupCode) -> Result<SetupHealth, ClientError> {
    let http = PinnedHttps::for_setup(&code.url, &code.pin, CALL_TIMEOUT)?;
    let response = http.send(Request::get("/v1/health")).await?;
    let status = response.status();
    let body = response.bytes_zeroizing(MAX_ANSWER_BYTES).await?;
    if status != 200 {
        return Err(api_error(status, &body));
    }
    serde_json::from_slice(&body).map_err(|error| ClientError::Decode(error.to_string()))
}

/// Creates the vault on the server of `code` (`POST /v1/setup`) and enrols this client.
///
/// The server checks the passphrase policy, measures its own key-derivation cost and takes a few seconds. A refusal
/// leaves the server as it was, so the call can be repeated with a changed request (after `too_many_failures`, once the
/// wait of `retry_after_seconds` is over).
///
/// # Errors
/// [`ClientError::Connect`], [`ClientError::PinMismatch`] (not the server of the code), [`ClientError::Tls`],
/// [`ClientError::Timeout`] or [`ClientError::Transport`] (the vault may have been made: ask the operator to check
/// with `cerberusd status`), and [`ClientError::Api`] with these codes: `unauthenticated` (wrong token),
/// `too_many_failures` (this address must wait `retry_after_seconds`, which grows with each wrong token), `conflict` (a setup runs, a setup already
/// worked, or a vault file exists), `validation_failed` (the fields are in the error details), `unavailable`,
/// `internal`.
pub async fn setup(code: &SetupCode, request: &SetupRequest) -> Result<SetupOutcome, ClientError> {
    let http = PinnedHttps::for_setup(&code.url, &code.pin, CALL_TIMEOUT)?;
    let room = REQUEST_ROOM
        + 6 * (code.token.expose().len()
            + request.owner_label.len()
            + request.passphrase.expose().len()
            + request.device_label.as_deref().map_or(0, str::len)
            + request.url.as_deref().unwrap_or(&code.url).len());
    let mut line = Zeroizing::new(Vec::with_capacity(room));
    serde_json::to_writer(
        &mut *line,
        &WireRequest {
            setup_token: code.token.expose(),
            owner_label: &request.owner_label,
            passphrase: request.passphrase.expose(),
            device_label: request.device_label.as_deref(),
            url: request.url.as_deref().unwrap_or(&code.url),
        },
    )
    .map_err(|error| ClientError::Decode(error.to_string()))?;
    let response = http
        .send(Request::post_json("/v1/setup", zeroizing_body(line)))
        .await?;
    let status = response.status();
    let body = response.bytes_zeroizing(MAX_ANSWER_BYTES).await?;
    if status != 200 {
        return Err(api_error(status, &body));
    }
    serde_json::from_slice(&body).map_err(|error| ClientError::Decode(error.to_string()))
}

/// The error of an answer that is not a success.
fn api_error(status: u16, body: &[u8]) -> ClientError {
    match serde_json::from_slice::<ErrorResponse>(body) {
        Ok(parsed) => ClientError::Api(Box::new(ApiError::from_response(status, parsed))),
        Err(_) => ClientError::Decode(format!(
            "the server answered HTTP {status} with no error object"
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn code_text(json: &str) -> String {
        format!(
            "{SETUP_CODE_PREFIX}{}",
            BASE64URL_NOPAD.encode(json.as_bytes())
        )
    }

    const PIN: &str = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn a_code_parses_and_hides_the_token_in_debug() {
        let text = code_text(&format!(
            r#"{{"url":"https://localhost:7373","token":"secret-token","pin":"{PIN}"}}"#
        ));
        let code = SetupCode::parse(&format!("  {text}\n")).unwrap();
        assert_eq!(code.url, "https://localhost:7373");
        assert_eq!(code.token.expose(), "secret-token");
        assert_eq!(code.pin, PIN);
        assert!(!format!("{code:?}").contains("secret-token"));
    }

    #[test]
    fn a_text_that_is_not_a_code_is_refused() {
        for text in [
            "",
            "cerberus-setup:2:e30",
            "cerberus-setup:1:!!!",
            &code_text("{}"),
            &code_text(
                r#"{"url":"http://x","token":"t","pin":"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#,
            ),
            &code_text(&format!(
                r#"{{"url":"https://x","token":"","pin":"{PIN}"}}"#
            )),
            &code_text(r#"{"url":"https://x","token":"t","pin":"nope"}"#),
            &code_text(&format!(
                r#"{{"url":"https://x","token":"t","pin":"{PIN}","extra":1}}"#
            )),
        ] {
            assert!(SetupCode::parse(text).is_err(), "{text}");
        }
    }
}
