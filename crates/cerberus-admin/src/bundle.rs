//! The enrolment bundle (ADR-0034 point 3.4, DEC-RM-4): the file that `cerberusd admin enroll`
//! writes and the desktop imports.
//!
//! JSON with the server URL, the CA pin and certificate, and the client certificate and its
//! PKCS#8 key. It holds a private key but no passphrase and no vault key: on its own it opens no
//! session. It is written as a new file with mode `0600` and never over another file.
//! [`AdminBundle::read`] checks everything the desktop relies on before it stores anything.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cerberus_types::OperatorId;
use cerberus_types::wire::WireSecret;
use data_encoding::BASE64;
use jiff::Timestamp;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use crate::clients::{EnrolmentId, check_label, sha256_hex};

/// The `format` value of a bundle.
pub const BUNDLE_FORMAT: &str = "cerberus-admin-bundle";
/// The bundle version this build reads and writes.
pub const BUNDLE_VERSION: u32 = 1;
/// The largest bundle file that is read.
pub const MAX_BUNDLE_BYTES: u64 = 64 * 1024;

/// Why a bundle cannot be written or read.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// A file error.
    #[error("admin bundle: {0}")]
    Io(std::io::Error),
    /// The target file exists; a bundle is never written over another file.
    #[error("the bundle file exists already; choose a new file name")]
    Exists,
    /// The path is not a regular file.
    #[error("the bundle is not a regular file")]
    NotAFile,
    /// The file is larger than [`MAX_BUNDLE_BYTES`].
    #[error("the bundle file is too large")]
    TooLarge,
    /// The file is not a bundle, or its parts do not agree.
    #[error("the file is not a valid Cerberus admin bundle: {0}")]
    Format(&'static str),
    /// Another bundle version.
    #[error("the bundle has version {0}; this Cerberus reads version 1")]
    Version(u32),
    /// The URL is not an `https` URL with a host and nothing else.
    #[error("the bundle URL must be https://host:port with no user, query or fragment")]
    Url,
    /// The CA pin is missing, malformed or does not match the CA certificate.
    #[error("the CA pin of the bundle does not match its CA certificate")]
    Pin,
    /// The client certificate is not signed by the CA, has no clientAuth, or is not valid now.
    #[error("the client certificate of the bundle is not valid for its CA now")]
    Chain,
    /// The key is not a PKCS#8 key of the client certificate.
    #[error("the private key of the bundle does not belong to its client certificate")]
    Key,
    /// The label is empty, too long or has control characters.
    #[error("the bundle label must be 1 to 64 characters without control characters")]
    Label,
}

impl From<std::io::Error> for BundleError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Self::Exists
        } else {
            Self::Io(error)
        }
    }
}

/// One enrolment bundle. `Debug` does not print the key.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminBundle {
    /// Always [`BUNDLE_FORMAT`].
    pub format: String,
    /// Always [`BUNDLE_VERSION`].
    pub version: u32,
    /// Enrolment ID.
    pub id: EnrolmentId,
    /// Enrolment label.
    pub label: String,
    /// Base URL of the daemon, as the desktop reaches it (`https://host:port`).
    pub url: String,
    /// The operator the enrolment is bound to.
    pub operator_id: OperatorId,
    /// `sha256/<base64>` of the CA SubjectPublicKeyInfo (ADR-0023 point 6).
    pub ca_pin: String,
    /// The vault CA certificate, PEM.
    pub ca_cert_pem: String,
    /// The client certificate, PEM.
    pub client_cert_pem: String,
    /// The client private key, PKCS#8 PEM. Zeroized on drop, redacted in `Debug`.
    pub client_key_pem: WireSecret,
    /// End of validity of the client certificate.
    pub not_after: Timestamp,
}

impl AdminBundle {
    /// Writes the bundle to a new file with mode `0600`.
    ///
    /// # Errors
    /// [`BundleError::Exists`] when `path` exists, or a file error.
    pub fn write_new(&self, path: &Path) -> Result<(), BundleError> {
        let body = crate::rpc::zeroizing_json(self).map_err(std::io::Error::other)?;
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

    /// Reads a bundle file (at most [`MAX_BUNDLE_BYTES`]) and checks it with [`Self::check`].
    ///
    /// # Errors
    /// [`BundleError::NotAFile`], [`BundleError::TooLarge`], [`BundleError::Format`] (the error
    /// never quotes the file: it holds a key), a file error, or an error of [`Self::check`].
    pub fn read(path: &Path, now: Timestamp) -> Result<Self, BundleError> {
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            return Err(BundleError::NotAFile);
        }
        if meta.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge);
        }
        let capacity = usize::try_from(MAX_BUNDLE_BYTES + 1).unwrap_or(usize::MAX);
        let mut body = Zeroizing::new(Vec::with_capacity(capacity));
        std::fs::File::open(path)?
            .take(MAX_BUNDLE_BYTES + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge);
        }
        let bundle: Self =
            serde_json::from_slice(&body).map_err(|_| BundleError::Format("not bundle JSON"))?;
        bundle.check(now)?;
        Ok(bundle)
    }

    /// Checks the bundle: format and version, label, an `https` URL, the CA pin against the CA
    /// certificate, the client certificate (for this enrolment, signed by the CA, clientAuth,
    /// valid at `now`, the same end time), and that the key belongs to it.
    ///
    /// # Errors
    /// The first [`BundleError`] found.
    pub fn check(&self, now: Timestamp) -> Result<(), BundleError> {
        if self.format != BUNDLE_FORMAT {
            return Err(BundleError::Format("not a Cerberus admin bundle"));
        }
        if self.version != BUNDLE_VERSION {
            return Err(BundleError::Version(self.version));
        }
        check_label(&self.label).map_err(|_| BundleError::Label)?;
        check_url(&self.url)?;
        let ca_der = self.ca_cert_der()?;
        if !self.ca_pin.starts_with("sha256/") || spki_pin(&ca_der)? != self.ca_pin {
            return Err(BundleError::Pin);
        }
        let client_der = one_cert(&self.client_cert_pem)?;
        let (_, client) = X509Certificate::from_der(&client_der)
            .map_err(|_| BundleError::Format("the client certificate does not parse"))?;
        let cn = client
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok());
        if cn != Some(format!("cerberus-admin {}", self.id).as_str()) {
            return Err(BundleError::Format(
                "the client certificate is not for this enrolment",
            ));
        }
        if client.validity().not_after.timestamp() != self.not_after.as_second() {
            return Err(BundleError::Format(
                "not_after does not match the client certificate",
            ));
        }
        let provider = Arc::new(ring_provider::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_der))
            .map_err(|_| BundleError::Format("the CA certificate is not a usable CA"))?;
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|_| BundleError::Format("the CA certificate is not a usable CA"))?;
        let at = UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(now.as_second()).unwrap_or(0),
        ));
        let client_der = CertificateDer::from(client_der);
        verifier
            .verify_client_cert(&client_der, &[], at)
            .map_err(|_| BundleError::Chain)?;
        let key = PrivatePkcs8KeyDer::from_pem_slice(self.client_key_pem.expose().as_bytes())
            .map_err(|_| BundleError::Key)?;
        let signing = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(key))
            .map_err(|_| BundleError::Key)?;
        CertifiedKey::new(vec![client_der], signing)
            .keys_match()
            .map_err(|_| BundleError::Key)?;
        Ok(())
    }

    /// The CA certificate, DER.
    ///
    /// # Errors
    /// [`BundleError::Format`] when `ca_cert_pem` is not one certificate.
    pub fn ca_cert_der(&self) -> Result<Vec<u8>, BundleError> {
        one_cert(&self.ca_cert_pem)
    }

    /// Lower-case hex SHA-256 of the CA certificate: the fingerprint `cerberusd status` prints,
    /// for the person to compare before the import.
    ///
    /// # Errors
    /// As [`Self::ca_cert_der`].
    pub fn ca_sha256_hex(&self) -> Result<String, BundleError> {
        Ok(sha256_hex(&self.ca_cert_der()?))
    }
}

/// Checks the URL of a bundle: `https://host[:port]/` with no user, query or fragment. `cerberusd` checks it before a
/// first-time setup makes a vault, so a bad URL cannot fail after the vault exists.
///
/// # Errors
/// [`BundleError::Url`].
pub fn check_url(text: &str) -> Result<(), BundleError> {
    let url = url::Url::parse(text).map_err(|_| BundleError::Url)?;
    let plain = url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/";
    if plain { Ok(()) } else { Err(BundleError::Url) }
}

/// The one certificate of a PEM text.
fn one_cert(pem: &str) -> Result<Vec<u8>, BundleError> {
    let mut certs = CertificateDer::pem_slice_iter(pem.as_bytes());
    let first = certs
        .next()
        .and_then(Result::ok)
        .ok_or(BundleError::Format("a certificate PEM is missing"))?;
    if certs.next().is_some() {
        return Err(BundleError::Format("a certificate PEM holds more than one"));
    }
    Ok(first.as_ref().to_vec())
}

/// `sha256/<base64>` of the SubjectPublicKeyInfo, as `cerberus_api::tls::spki_pin`.
fn spki_pin(cert_der: &[u8]) -> Result<String, BundleError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_| BundleError::Format("the CA certificate does not parse"))?;
    let digest = Sha256::digest(cert.tbs_certificate.subject_pki.raw);
    Ok(format!("sha256/{}", BASE64.encode(&digest)))
}

#[cfg(test)]
mod tests;
