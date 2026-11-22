//! TLS 1.3 client setup with CA pinning (ADR-0023).
//!
//! The only trust anchor is the Cerberus CA. Two ways to name it:
//! - a PEM file (`Trust::CaFile`): the chain is verified against that CA with webpki, and when a
//!   pin is also given, the CA key in the file must match it;
//! - a pin (`Trust::Pin`): the server must send the CA certificate after the leaf. The certificate
//!   whose public key (SPKI) hashes to the pin becomes the only trust anchor for that handshake.
//!
//! A third mode, [`leaf_pin_config`], is for the first-time setup of a `cerberusd` that has no vault yet: the server
//! has only a throwaway self-signed certificate, so the pin is the SPKI hash of that certificate itself (DEC-SRV-3).
//!
//! No system roots are loaded. TLS 1.2 is not offered.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use data_encoding::BASE64;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error, OtherError, RootCertStore,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::config::Trust;
use crate::error::ClientError;

const PIN_PREFIX: &str = "sha256/";

/// The server chain does not hold a certificate with the pinned key.
#[derive(Debug)]
struct PinMismatch;

impl fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no certificate in the chain matches the pinned CA key")
    }
}

impl std::error::Error for PinMismatch {}

/// True when a handshake error came from the pin check.
pub(crate) fn is_pin_mismatch(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidCertificate(CertificateError::Other(OtherError(inner)))
            if inner.downcast_ref::<PinMismatch>().is_some()
    )
}

/// Parses `sha256/<base64>` into 32 bytes.
pub(crate) fn parse_pin(text: &str) -> Result<[u8; 32], ClientError> {
    let bad = || ClientError::Config("the CA pin must look like sha256/<base64>".to_owned());
    let body = text.trim().strip_prefix(PIN_PREFIX).ok_or_else(bad)?;
    let bytes = BASE64.decode(body.as_bytes()).map_err(|_| bad())?;
    bytes.try_into().map_err(|_| bad())
}

/// DER length bytes of a SEQUENCE body.
fn der_header(len: usize) -> Vec<u8> {
    let mut out = vec![0x30];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap_or(0));
        out.extend(bytes);
    }
    out
}

/// SHA-256 of the SubjectPublicKeyInfo of a certificate, or `None` when it does not parse.
pub(crate) fn spki_sha256(cert: &CertificateDer<'_>) -> Option<[u8; 32]> {
    let mut store = RootCertStore::empty();
    store.add(cert.clone()).ok()?;
    let anchor = store.roots.first()?;
    let inner: &[u8] = anchor.subject_public_key_info.as_ref();
    let mut hasher = Sha256::new();
    hasher.update(der_header(inner.len()));
    hasher.update(inner);
    Some(hasher.finalize().into())
}

/// Reads the certificates of a PEM file.
fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ClientError> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|_| ClientError::Config("the CA file cannot be read".to_owned()))?
        .collect();
    let certs =
        certs.map_err(|_| ClientError::Config("the CA file is not valid PEM".to_owned()))?;
    if certs.is_empty() {
        return Err(ClientError::Config(
            "the CA file holds no certificate".to_owned(),
        ));
    }
    Ok(certs)
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
enum Mode {
    /// Chain verified against fixed roots (the CA file).
    Roots(Arc<WebPkiServerVerifier>),
    /// The CA must be in the presented chain and match the pin.
    Pinned([u8; 32]),
    /// The server certificate itself must have the pinned key (a self-signed setup certificate). The handshake
    /// signature still proves that the server holds the key.
    PinnedLeaf([u8; 32]),
}

#[derive(Debug)]
struct PinVerifier {
    mode: Mode,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    fn algorithms(&self) -> &WebPkiSupportedAlgorithms {
        &self.provider.signature_verification_algorithms
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match &self.mode {
            Mode::Roots(verifier) => verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
            Mode::PinnedLeaf(pin) => {
                if spki_sha256(end_entity).is_some_and(|hash| hash == *pin) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(Error::InvalidCertificate(CertificateError::Other(
                        OtherError(Arc::new(PinMismatch)),
                    )))
                }
            }
            Mode::Pinned(pin) => {
                let ca = intermediates
                    .iter()
                    .find(|cert| spki_sha256(cert).is_some_and(|hash| hash == *pin))
                    .ok_or_else(|| {
                        Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
                            PinMismatch,
                        ))))
                    })?;
                let mut roots = RootCertStore::empty();
                roots.add(ca.clone())?;
                let verifier = WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    self.provider.clone(),
                )
                .build()
                .map_err(|e| Error::General(e.to_string()))?;
                verifier.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms().supported_schemes()
    }
}

/// Builds the rustls client config: TLS 1.3 only, ALPN `http/1.1`, the pin verifier, and an
/// optional client certificate for mTLS.
pub(crate) fn client_config(
    trust: &Trust,
    client_cert: Option<&(std::path::PathBuf, std::path::PathBuf)>,
) -> Result<ClientConfig, ClientError> {
    let provider = ring_provider();
    let mode = match trust {
        Trust::Pin(pin) => Mode::Pinned(parse_pin(pin)?),
        Trust::CaFile(path) => Mode::Roots(roots_verifier(&read_certs(path)?, &provider)?),
        Trust::CaFileAndPin { ca, pin } => {
            let pin = parse_pin(pin)?;
            // Only the pinned certificate is a root. The other certificates of the file (a system
            // bundle, for example) must not become trusted by the pin (AUD-17).
            let pinned: Vec<CertificateDer<'static>> = read_certs(ca)?
                .into_iter()
                .filter(|cert| spki_sha256(cert).is_some_and(|hash| hash == pin))
                .collect();
            if pinned.is_empty() {
                return Err(ClientError::PinMismatch);
            }
            Mode::Roots(roots_verifier(&pinned, &provider)?)
        }
    };
    finish_config(mode, &provider, client_cert)
}

/// The rustls client config for the first-time setup: the server certificate must have the key of `pin`
/// (`sha256/<base64>`), and no client certificate is sent.
pub(crate) fn leaf_pin_config(pin: &str) -> Result<ClientConfig, ClientError> {
    finish_config(Mode::PinnedLeaf(parse_pin(pin)?), &ring_provider(), None)
}

fn finish_config(
    mode: Mode,
    provider: &Arc<CryptoProvider>,
    client_cert: Option<&(std::path::PathBuf, std::path::PathBuf)>,
) -> Result<ClientConfig, ClientError> {
    let verifier = Arc::new(PinVerifier {
        mode,
        provider: provider.clone(),
    });
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ClientError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match client_cert {
        None => builder.with_no_client_auth(),
        Some((cert_path, key_path)) => {
            let chain = read_certs(cert_path)?;
            let key = PrivateKeyDer::from_pem_file(key_path)
                .map_err(|_| ClientError::Config("the client key cannot be read".to_owned()))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| ClientError::Config(e.to_string()))?
        }
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn roots_verifier(
    certs: &[CertificateDer<'static>],
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<WebPkiServerVerifier>, ClientError> {
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert.clone())
            .map_err(|_| ClientError::Config("the CA file holds a bad certificate".to_owned()))?;
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| ClientError::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_parser_wants_prefix_and_32_bytes() {
        let good = format!("sha256/{}", BASE64.encode(&[7u8; 32]));
        assert_eq!(parse_pin(&good).unwrap(), [7u8; 32]);
        assert!(parse_pin("sha256/AAAA").is_err());
        assert!(parse_pin(&BASE64.encode(&[7u8; 32])).is_err());
    }

    #[test]
    fn der_header_has_short_and_long_forms() {
        assert_eq!(der_header(5), vec![0x30, 5]);
        assert_eq!(der_header(0x91), vec![0x30, 0x81, 0x91]);
        assert_eq!(der_header(0x1234), vec![0x30, 0x82, 0x12, 0x34]);
    }
}
