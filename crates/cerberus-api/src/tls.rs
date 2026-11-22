//! The local CA, the leaf and client certificates, and the rustls server config (ADR-0023).
//!
//! The CA is ECDSA P-256 and lives 10 years. The leaf lives 90 days. The leaf key is a file with
//! mode `0600` outside the vault, so TLS works while the vault is locked.

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use cerberus_core::{CaIssuer, CoreError, IssuedCa, OperatorContext, VaultService};
use cerberus_crypto::{CryptoError, SecretBytes};
use cerberus_types::{AgentId, OperatorRole, VaultId};
use data_encoding::BASE64;
use jiff::{SignedDuration, Timestamp};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls::crypto::ring as ring_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::server::ServerError;

/// Lifetime of the CA.
const CA_DAYS: i64 = 3650;
/// Lifetime of a leaf.
const LEAF_DAYS: i64 = 90;
/// Lifetime of an agent client certificate.
const CLIENT_DAYS: i64 = 365;
/// Lifetime of an admin client certificate of an enrolled desktop (ADR-0034 point 3.2).
pub const ADMIN_CLIENT_DAYS: i64 = 90;
/// A leaf with less time left than this is renewed (ADR-0023 point 5).
const RENEW_BEFORE_DAYS: i64 = 30;
/// Certificates start this long before `now`, so a small clock difference does not break them.
const BACKDATE: SignedDuration = SignedDuration::from_mins(5);

/// Where the leaf certificate and key are stored.
#[derive(Clone, Debug)]
pub struct TlsPaths {
    /// Leaf certificate, DER.
    pub leaf_cert_der: PathBuf,
    /// Leaf private key, PKCS#8 DER, mode `0600`.
    pub leaf_key_der: PathBuf,
    /// CA certificate, DER. Served after the leaf, so a client that trusts only the CA can verify
    /// the chain. It is public (also in the DB), so it is not a secret.
    pub ca_cert_der: PathBuf,
}

impl TlsPaths {
    /// The standard place: `<app_data_dir>/tls/leaf-cert.der` and `leaf-key.der` (ADR-0023).
    #[must_use]
    pub fn in_data_dir(data_dir: &Path) -> Self {
        let dir = data_dir.join("tls");
        Self {
            leaf_cert_der: dir.join("leaf-cert.der"),
            leaf_key_der: dir.join("leaf-key.der"),
            ca_cert_der: dir.join("ca-cert.der"),
        }
    }
}

/// A certificate with its private key.
#[derive(Debug)]
pub struct IssuedCert {
    /// The certificate, DER.
    pub cert_der: Vec<u8>,
    /// The private key, PKCS#8 DER.
    pub key_der: SecretBytes,
    /// End of validity.
    pub not_after: Timestamp,
}

impl IssuedCert {
    /// SHA-256 of the certificate. For a client certificate this is the value the agent key binds to
    /// (core `bind_client_cert`).
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.cert_der).into()
    }

    /// The certificate as PEM.
    #[must_use]
    pub fn cert_pem(&self) -> String {
        pem("CERTIFICATE", &self.cert_der)
    }

    /// The private key as PEM. Treat the result as a secret.
    #[must_use]
    pub fn key_pem(&self) -> String {
        pem("PRIVATE KEY", self.key_der.expose_secret())
    }
}

/// What the owner gives to agents: the CA certificate and its two fingerprints (ADR-0023 points 6, 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaExport {
    /// CA certificate, PEM. Use it as `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE`.
    pub pem: String,
    /// `sha256/<base64>` of the CA SubjectPublicKeyInfo. It survives leaf renewal.
    pub pin: String,
    /// Lower-case hex SHA-256 of the CA certificate.
    pub cert_sha256_hex: String,
}

impl CaExport {
    /// Builds the export from the CA certificate (DER). It needs no key, so it works while locked.
    ///
    /// # Errors
    /// [`ServerError::Cert`] when the DER is not a certificate.
    pub fn from_der(cert_der: &[u8]) -> Result<Self, ServerError> {
        Ok(Self {
            pem: pem("CERTIFICATE", cert_der),
            pin: spki_pin(cert_der)?,
            cert_sha256_hex: hex(&Sha256::digest(cert_der)),
        })
    }
}

/// The local CA with its key. Drop it when you are done: the key zeroizes on drop.
pub struct LocalCa {
    cert_der: Vec<u8>,
    key_der: SecretBytes,
    issuer: Issuer<'static, KeyPair>,
    not_after: Timestamp,
}

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCa")
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

fn cert_error(error: impl std::fmt::Display) -> ServerError {
    ServerError::Cert(error.to_string())
}

fn offset_time(at: Timestamp) -> Result<time::OffsetDateTime, ServerError> {
    time::OffsetDateTime::from_unix_timestamp(at.as_second()).map_err(cert_error)
}

fn after_days(now: Timestamp, days: i64) -> Result<Timestamp, ServerError> {
    now.checked_add(SignedDuration::from_hours(24 * days))
        .map_err(cert_error)
}

fn validity(
    params: &mut CertificateParams,
    now: Timestamp,
    days: i64,
) -> Result<Timestamp, ServerError> {
    let not_after = after_days(now, days)?;
    params.not_before = offset_time(now.checked_sub(BACKDATE).map_err(cert_error)?)?;
    params.not_after = offset_time(not_after)?;
    Ok(not_after)
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

impl LocalCa {
    /// Makes a new CA (ECDSA P-256, self-signed, path length 0, ADR-0023).
    ///
    /// # Errors
    /// [`ServerError::Cert`] when a key or certificate cannot be made.
    pub fn create(vault_id: &VaultId, now: Timestamp) -> Result<Self, ServerError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let mut params = CertificateParams::default();
        let short: String = vault_id
            .0
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect();
        params.distinguished_name = dn(&format!("Cerberus Local CA {short}"));
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let not_after = validity(&mut params, now, CA_DAYS)?;
        let cert = params.self_signed(&key).map_err(cert_error)?;
        let cert_der = cert.der().to_vec();
        let key_der = SecretBytes::new(key.serialize_der());
        Self::build(cert_der, key_der, key, not_after)
    }

    /// Opens a CA from its certificate and key (for example after unlock).
    ///
    /// # Errors
    /// [`ServerError::Cert`] when the parts are not a certificate and a matching key.
    pub fn from_parts(cert_der: &[u8], key_der: &SecretBytes) -> Result<Self, ServerError> {
        let key = KeyPair::try_from(key_der.expose_secret()).map_err(cert_error)?;
        let (_, parsed) = X509Certificate::from_der(cert_der).map_err(cert_error)?;
        let not_after =
            Timestamp::from_second(parsed.validity().not_after.timestamp()).map_err(cert_error)?;
        Self::build(
            cert_der.to_vec(),
            SecretBytes::new(key_der.expose_secret().to_vec()),
            key,
            not_after,
        )
    }

    fn build(
        cert_der: Vec<u8>,
        key_der: SecretBytes,
        key: KeyPair,
        not_after: Timestamp,
    ) -> Result<Self, ServerError> {
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(cert_der.clone()), key)
            .map_err(cert_error)?;
        Ok(Self {
            cert_der,
            key_der,
            issuer,
            not_after,
        })
    }

    /// The CA certificate, DER.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The export for agents: PEM, pin and fingerprint.
    ///
    /// # Errors
    /// [`ServerError::Cert`] when the certificate does not parse.
    pub fn export(&self) -> Result<CaExport, ServerError> {
        CaExport::from_der(&self.cert_der)
    }

    /// The parts the vault stores (core `IssuedCa`).
    ///
    /// # Errors
    /// [`ServerError::Cert`] when the certificate does not parse.
    pub fn to_issued(&self) -> Result<IssuedCa, ServerError> {
        Ok(IssuedCa {
            cert_der: self.cert_der.clone(),
            key_der: SecretBytes::new(self.key_der.expose_secret().to_vec()),
            not_after: self.not_after,
            pin: spki_pin(&self.cert_der)?,
        })
    }

    /// Signs a leaf for `names` (DNS names and IP addresses). ECDSA P-256, 90 days, EKU serverAuth.
    ///
    /// # Errors
    /// [`ServerError::Cert`] when a name is not valid or signing fails.
    pub fn issue_leaf(&self, names: &[String], now: Timestamp) -> Result<IssuedCert, ServerError> {
        let first = names
            .first()
            .ok_or_else(|| cert_error("no names for the leaf"))?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(first);
        params.subject_alt_names = names
            .iter()
            .map(|name| san(name))
            .collect::<Result<Vec<_>, _>>()?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let not_after = validity(&mut params, now, LEAF_DAYS)?;
        let cert = params.signed_by(&key, &self.issuer).map_err(cert_error)?;
        Ok(IssuedCert {
            cert_der: cert.der().to_vec(),
            key_der: SecretBytes::new(key.serialize_der()),
            not_after,
        })
    }

    /// Signs a client certificate for an agent (EKU clientAuth, 365 days). Bind its
    /// [`IssuedCert::sha256`] to the agent key with core `bind_client_cert` (ADR-0016).
    ///
    /// # Errors
    /// [`ServerError::Cert`] when signing fails.
    pub fn issue_client(&self, agent: AgentId, now: Timestamp) -> Result<IssuedCert, ServerError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(&format!("cerberus-agent {agent}"));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let not_after = validity(&mut params, now, CLIENT_DAYS)?;
        let cert = params.signed_by(&key, &self.issuer).map_err(cert_error)?;
        Ok(IssuedCert {
            cert_der: cert.der().to_vec(),
            key_der: SecretBytes::new(key.serialize_der()),
            not_after,
        })
    }

    /// Signs the client certificate of an enrolled desktop for the admin API (ADR-0034 point
    /// 3.2): ECDSA P-256, `CN = cerberus-admin <enrolment>`, EKU clientAuth, 90 days. Being
    /// signed by the CA is not enough to pass the admin routes: its [`IssuedCert::sha256`] must
    /// also be in the admin registry (DEC-RM-3).
    ///
    /// # Errors
    /// [`ServerError::Cert`] when signing fails.
    pub fn issue_admin_client(
        &self,
        enrolment: &str,
        now: Timestamp,
    ) -> Result<IssuedCert, ServerError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(&format!("cerberus-admin {enrolment}"));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let not_after = validity(&mut params, now, ADMIN_CLIENT_DAYS)?;
        let cert = params.signed_by(&key, &self.issuer).map_err(cert_error)?;
        Ok(IssuedCert {
            cert_der: cert.der().to_vec(),
            key_der: SecretBytes::new(key.serialize_der()),
            not_after,
        })
    }
}

fn san(name: &str) -> Result<SanType, ServerError> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    let dns = rcgen::string::Ia5String::try_from(name.to_owned()).map_err(cert_error)?;
    Ok(SanType::DnsName(dns))
}

/// The names of the leaf: `localhost`, `127.0.0.1`, `::1`, the host name, then `extra` (ADR-0023).
#[must_use]
pub fn leaf_names(extra: &[String]) -> Vec<String> {
    let mut names: Vec<String> = ["localhost", "127.0.0.1", "::1"]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    if let Ok(host) = gethostname::gethostname().into_string() {
        names.push(host);
    }
    names.extend(extra.iter().cloned());
    let mut seen = std::collections::BTreeSet::new();
    names.retain(|name| !name.is_empty() && seen.insert(name.to_ascii_lowercase()));
    names
}

/// `sha256/<base64>` of the SubjectPublicKeyInfo of a certificate (ADR-0023 point 6).
///
/// # Errors
/// [`ServerError::Cert`] when the DER is not a certificate.
pub fn spki_pin(cert_der: &[u8]) -> Result<String, ServerError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(cert_error)?;
    let digest = Sha256::digest(cert.tbs_certificate.subject_pki.raw);
    Ok(format!("sha256/{}", BASE64.encode(&digest)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = BASE64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Writes the leaf: key with mode `0600`, certificate next to it. Each file is written to a
/// temporary name and renamed, so a reader never sees half a file.
///
/// # Errors
/// [`ServerError::Io`] on a file error.
pub fn write_leaf(paths: &TlsPaths, leaf: &IssuedCert) -> Result<(), ServerError> {
    write_private(&paths.leaf_key_der, leaf.key_der.expose_secret())?;
    write_private(&paths.leaf_cert_der, &leaf.cert_der)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ServerError> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let tmp = path.with_extension("tmp");
    // A stale temporary file keeps its old mode, so remove it and make a new one (AUD-30).
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Writes the CA certificate that the server sends after the leaf (DEC-FIX8-1).
///
/// # Errors
/// [`ServerError::Io`] on a file error.
pub fn write_ca_cert(paths: &TlsPaths, ca_der: &[u8]) -> Result<(), ServerError> {
    write_private(&paths.ca_cert_der, ca_der)
}

/// Reads the leaf files.
///
/// # Errors
/// [`ServerError::Io`] when a file is missing, [`ServerError::Cert`] when the key is not valid.
pub fn read_leaf(paths: &TlsPaths) -> Result<Arc<CertifiedKey>, ServerError> {
    let cert = std::fs::read(&paths.leaf_cert_der)?;
    let key = zeroize::Zeroizing::new(std::fs::read(&paths.leaf_key_der)?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));
    let signer = ring_provider::sign::any_supported_type(&key).map_err(cert_error)?;
    let mut chain = vec![CertificateDer::from(cert)];
    // A missing CA file (a vault from before FIX8) gives a leaf-only chain until the next renewal.
    match std::fs::read(&paths.ca_cert_der) {
        Ok(ca) => chain.push(CertificateDer::from(ca)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(Arc::new(CertifiedKey::new(chain, signer)))
}

/// True when the leaf has less than 30 days left, or its names differ from `names` (ADR-0023 point 5).
///
/// # Errors
/// [`ServerError::Io`] or [`ServerError::Cert`] when the leaf cannot be read.
pub fn leaf_needs_renewal(
    paths: &TlsPaths,
    names: &[String],
    now: Timestamp,
) -> Result<bool, ServerError> {
    let der = std::fs::read(&paths.leaf_cert_der)?;
    let (_, cert) = X509Certificate::from_der(&der).map_err(cert_error)?;
    let end = Timestamp::from_second(cert.validity().not_after.timestamp()).map_err(cert_error)?;
    if end < after_days(now, RENEW_BEFORE_DAYS)? {
        return Ok(true);
    }
    let mut have: Vec<String> = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => have.push(dns.to_ascii_lowercase()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_from_bytes(bytes) {
                        have.push(ip.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let mut want: Vec<String> = names
        .iter()
        .map(|name| match name.parse::<IpAddr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => name.to_ascii_lowercase(),
        })
        .collect();
    have.sort();
    want.sort();
    Ok(have != want)
}

/// True when the leaf file was issued by the CA certificate `ca_der`: the issuer name of the leaf is the subject name of
/// the CA (the name has the short ID of the vault, so the CA of another vault never matches). A leaf that cannot be read
/// is not issued by it. `cerberusd` uses it so that a leaf of a dead CA (left by a setup that was killed, or copied with an
/// old data folder) is never served for a vault with another CA.
#[must_use]
pub fn leaf_issued_by(paths: &TlsPaths, ca_der: &[u8]) -> bool {
    let Ok(leaf_der) = std::fs::read(&paths.leaf_cert_der) else {
        return false;
    };
    let (Ok((_, leaf)), Ok((_, ca))) = (
        X509Certificate::from_der(&leaf_der),
        X509Certificate::from_der(ca_der),
    ) else {
        return false;
    };
    leaf.issuer().as_raw() == ca.subject().as_raw()
}

fn ip_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from)
}

/// Signs a new leaf and writes it when `leaf_needs_renewal` says so. Returns true when it wrote one.
///
/// # Errors
/// As [`leaf_needs_renewal`], [`LocalCa::issue_leaf`] and [`write_leaf`]. A missing leaf is made.
pub fn renew_leaf_if_needed(
    ca: &LocalCa,
    paths: &TlsPaths,
    names: &[String],
    now: Timestamp,
) -> Result<bool, ServerError> {
    let needed = match leaf_needs_renewal(paths, names, now) {
        Ok(needed) => needed || !leaf_issued_by(paths, ca.cert_der()),
        Err(ServerError::Io(_) | ServerError::Cert(_)) => true,
        Err(other) => return Err(other),
    };
    if needed {
        write_leaf(paths, &ca.issue_leaf(names, now)?)?;
    }
    // The chain must keep the CA after every renewal, and a vault from before FIX8 has no file.
    let ca_stale = std::fs::read(&paths.ca_cert_der).map_or(true, |have| have != ca.cert_der());
    if ca_stale {
        write_ca_cert(paths, ca.cert_der())?;
    }
    Ok(needed || ca_stale)
}

/// Why a custom certificate was not loaded.
#[derive(Debug, thiserror::Error)]
pub enum CustomCertError {
    /// The session or the vault state does not allow it (owner only, unlocked).
    #[error(transparent)]
    Core(#[from] CoreError),
    /// The certificate or the key is not acceptable. The text names the rule, never the content.
    #[error("{0}")]
    Invalid(String),
}

fn invalid(reason: &str) -> CustomCertError {
    CustomCertError::Invalid(reason.to_owned())
}

/// The longest custom chain.
const MAX_CUSTOM_CHAIN: usize = 8;
/// Signature algorithms that are not safe for TLS (MD5 and SHA-1 with RSA, ECDSA with SHA-1).
const WEAK_SIGNATURE_OIDS: [&str; 3] = [
    "1.2.840.113549.1.1.4",
    "1.2.840.113549.1.1.5",
    "1.2.840.10045.4.1",
];

/// An owner certificate that passed the checks, ready to serve and to store.
pub struct CustomCert {
    chain_der: Vec<Vec<u8>>,
    key_stored: SecretBytes,
    certified: Arc<CertifiedKey>,
    not_after: Timestamp,
}

impl std::fmt::Debug for CustomCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomCert")
            .field("chain_len", &self.chain_der.len())
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl CustomCert {
    /// End of validity of the leaf.
    #[must_use]
    pub const fn not_after(&self) -> Timestamp {
        self.not_after
    }

    /// The chain the server sends, DER, leaf first.
    #[must_use]
    pub fn chain_der(&self) -> &[Vec<u8>] {
        &self.chain_der
    }

    /// The certified key for rustls.
    #[must_use]
    pub fn certified(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }
}

/// Key type tags in the stored key: the first byte says how the DER is wrapped.
const KEY_PKCS8: u8 = 0;
const KEY_SEC1: u8 = 1;
const KEY_PKCS1: u8 = 2;

fn key_to_stored(key: &PrivateKeyDer<'_>) -> Result<SecretBytes, CustomCertError> {
    let (tag, der) = match key {
        PrivateKeyDer::Pkcs8(k) => (KEY_PKCS8, k.secret_pkcs8_der()),
        PrivateKeyDer::Sec1(k) => (KEY_SEC1, k.secret_sec1_der()),
        PrivateKeyDer::Pkcs1(k) => (KEY_PKCS1, k.secret_pkcs1_der()),
        _ => return Err(invalid("the private key format is not supported")),
    };
    let mut out = Vec::with_capacity(der.len() + 1);
    out.push(tag);
    out.extend_from_slice(der);
    Ok(SecretBytes::new(out))
}

fn key_from_stored(stored: &[u8]) -> Result<PrivateKeyDer<'static>, CustomCertError> {
    let (tag, der) = stored
        .split_first()
        .ok_or_else(|| invalid("the stored private key is empty"))?;
    let der = der.to_vec();
    match *tag {
        KEY_PKCS8 => Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))),
        KEY_SEC1 => Ok(PrivateKeyDer::Sec1(der.into())),
        KEY_PKCS1 => Ok(PrivateKeyDer::Pkcs1(der.into())),
        _ => Err(invalid("the stored private key format is not known")),
    }
}

/// The DNS names and IP addresses in the SAN of a certificate.
fn san_names(cert: &X509Certificate<'_>) -> (Vec<String>, Vec<IpAddr>) {
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(text) => dns.push(text.to_ascii_lowercase()),
                GeneralName::IPAddress(bytes) => ips.extend(ip_from_bytes(bytes)),
                _ => {}
            }
        }
    }
    (dns, ips)
}

/// True when a DNS SAN entry (maybe `*.example.com`, one label) covers `host`.
fn dns_matches(entry: &str, host: &str) -> bool {
    match entry.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(label, tail)| !label.is_empty() && tail == rest),
        None => entry == host,
    }
}

fn san_covers(dns: &[String], ips: &[IpAddr], name: &str) -> bool {
    match name.parse::<IpAddr>() {
        Ok(ip) => ips.contains(&ip),
        Err(_) => {
            let host = name.to_ascii_lowercase();
            dns.iter().any(|entry| dns_matches(entry, &host))
        }
    }
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, CustomCertError> {
    match X509Certificate::from_der(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(invalid("a certificate in the chain is not valid X.509")),
    }
}

/// The checks of ADR-0023 point 8 on the chain and the names. `configured` are the owner host
/// names: the certificate must cover all of them, or, when there are none, at least one of the
/// standard names (`localhost`, `127.0.0.1`, `::1`, the host name).
fn check_chain(
    chain: &[Vec<u8>],
    configured: &[String],
    now: Timestamp,
) -> Result<(), CustomCertError> {
    if chain.is_empty() {
        return Err(invalid("the certificate file holds no certificate"));
    }
    if chain.len() > MAX_CUSTOM_CHAIN {
        return Err(invalid("the certificate chain is too long"));
    }
    let skew = BACKDATE.as_secs();
    let mut parsed = Vec::with_capacity(chain.len());
    for der in chain {
        let cert = parse_cert(der)?;
        let start = cert.validity().not_before.timestamp();
        let end = cert.validity().not_after.timestamp();
        if end <= now.as_second() {
            return Err(invalid("a certificate in the chain has expired"));
        }
        if start > now.as_second() + skew {
            return Err(invalid("a certificate in the chain is not valid yet"));
        }
        parsed.push(cert);
    }
    let leaf = &parsed[0];
    if leaf.is_ca() {
        return Err(invalid(
            "the first certificate is a CA, not a server certificate",
        ));
    }
    if let Ok(Some(eku)) = leaf.extended_key_usage()
        && !eku.value.server_auth
        && !eku.value.any
    {
        return Err(invalid("the certificate is not allowed for a TLS server"));
    }
    if WEAK_SIGNATURE_OIDS.contains(&leaf.signature_algorithm.algorithm.to_id_string().as_str()) {
        return Err(invalid(
            "the certificate uses a weak signature (MD5 or SHA-1)",
        ));
    }
    for pair in parsed.windows(2) {
        if pair[0].issuer() != pair[1].subject() {
            return Err(invalid(
                "the certificates are not in order: each must be followed by its issuer",
            ));
        }
    }
    let (dns, ips) = san_names(leaf);
    if dns.is_empty() && ips.is_empty() {
        return Err(invalid(
            "the certificate has no subject alternative name (SAN)",
        ));
    }
    if configured.is_empty() {
        if !leaf_names(&[]).iter().any(|n| san_covers(&dns, &ips, n)) {
            return Err(invalid(
                "the certificate covers none of the standard names; add your host name in the network settings first",
            ));
        }
    } else if let Some(missing) = configured.iter().find(|n| !san_covers(&dns, &ips, n)) {
        return Err(CustomCertError::Invalid(format!(
            "the certificate has no SAN for the host name {missing}"
        )));
    }
    Ok(())
}

fn build_custom(
    chain: Vec<Vec<u8>>,
    key: &PrivateKeyDer<'_>,
) -> Result<CustomCert, CustomCertError> {
    let signer = ring_provider::sign::any_supported_type(key).map_err(|_| {
        invalid("the private key type or size is not supported (RSA needs 2048 bits or more)")
    })?;
    let certified = CertifiedKey::new(
        chain
            .iter()
            .map(|d| CertificateDer::from(d.clone()))
            .collect(),
        signer,
    );
    if certified.keys_match().is_err() {
        return Err(invalid("the private key does not match the certificate"));
    }
    let not_after = {
        let leaf = parse_cert(&chain[0])?;
        Timestamp::from_second(leaf.validity().not_after.timestamp())
            .map_err(|_| invalid("the certificate end date is not valid"))?
    };
    Ok(CustomCert {
        key_stored: key_to_stored(key)?,
        chain_der: chain,
        certified: Arc::new(certified),
        not_after,
    })
}

/// Parses and checks an owner certificate chain and private key (PEM). The chain starts with the
/// server certificate. See `check_chain` for the name rule.
///
/// # Errors
/// [`CustomCertError::Invalid`] when the PEM does not parse, the key is encrypted or not
/// supported, the key does not match, a certificate is expired, or the SAN misses a name.
pub fn parse_custom_pem(
    chain_pem: &[u8],
    key_pem: &[u8],
    configured_names: &[String],
    now: Timestamp,
) -> Result<CustomCert, CustomCertError> {
    use rustls::pki_types::pem::PemObject;
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .map(|item| item.map(|der| der.to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("the certificate file is not valid PEM"))?;
    check_chain(&chain, configured_names, now)?;
    if String::from_utf8_lossy(key_pem).contains("ENCRYPTED PRIVATE KEY") {
        return Err(invalid(
            "the private key is encrypted; remove its passphrase first",
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| invalid("the key file holds no usable private key"))?;
    build_custom(chain, &key)
}

/// Rebuilds the certificate from what the vault stored. The checks of the load already passed, so
/// a date that has gone by since then does not stop the server (the UI shows the end date).
///
/// # Errors
/// [`CustomCertError::Invalid`] when the stored parts are not a certificate and a matching key.
pub fn custom_from_stored(
    chain_der: Vec<Vec<u8>>,
    stored_key: &SecretBytes,
) -> Result<CustomCert, CustomCertError> {
    if chain_der.is_empty() {
        return Err(invalid("the stored chain is empty"));
    }
    let key = key_from_stored(stored_key.expose_secret())?;
    build_custom(chain_der, &key)
}

/// Checks and stores an owner certificate in the vault (sealed), and writes `tls.custom_load`.
/// Owner only, from the session. It does not touch a running server: call
/// [`crate::RunningServer::apply_tls`] next. The owner host names (vault and `extra_names`) must
/// all be in the SAN.
///
/// # Errors
/// [`CustomCertError::Core`] (locked, not an owner) or [`CustomCertError::Invalid`].
pub async fn store_custom_cert(
    core: &VaultService,
    ctx: &OperatorContext,
    chain_pem: &[u8],
    key_pem: &[u8],
    extra_names: &[String],
) -> Result<CustomCert, CustomCertError> {
    core.authorize_role(ctx, OperatorRole::Owner).await?;
    let mut names = core.tls_ca_material().await?.host_names;
    names.extend(extra_names.iter().cloned());
    let cert = parse_custom_pem(chain_pem, key_pem, &names, core.clock().now())?;
    core.tls_custom_store(ctx, &cert.chain_der, &cert.key_stored)
        .await?;
    Ok(cert)
}

/// What the clients pin now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveTls {
    /// True when the owner custom certificate is in use.
    pub custom: bool,
    /// Export of the certificate at the top of the served chain: the local CA, or the last
    /// certificate of the custom chain. Its pin and fingerprint are what clients pin.
    pub anchor: CaExport,
    /// End of validity of the custom leaf; `None` for the local CA (its leaf is a file).
    pub leaf_not_after: Option<Timestamp>,
}

/// The active chain: the custom one when stored, else the local CA. Needs an unlocked vault only
/// for a custom certificate (it is sealed).
///
/// # Errors
/// [`ServerError::Cert`] when the vault does not give the certificates.
pub async fn active_tls(core: &VaultService) -> Result<ActiveTls, ServerError> {
    let custom = match core.tls_custom_material().await {
        Ok(found) => found,
        Err(CoreError::Locked) => None,
        Err(error) => return Err(cert_error(error)),
    };
    if let Some(material) = custom {
        let top = material
            .chain_der
            .last()
            .ok_or_else(|| cert_error("empty custom chain"))?;
        let leaf_not_after = custom_from_stored(material.chain_der.clone(), &material.key_der)
            .ok()
            .map(|cert| cert.not_after());
        return Ok(ActiveTls {
            custom: true,
            anchor: CaExport::from_der(top)?,
            leaf_not_after,
        });
    }
    let ca = core.tls_ca_cert().await.map_err(cert_error)?;
    Ok(ActiveTls {
        custom: false,
        anchor: CaExport::from_der(&ca)?,
        leaf_not_after: None,
    })
}

/// The certificate the server uses now: the local leaf (files) or the owner custom certificate.
#[derive(Debug)]
struct Active {
    key: Arc<CertifiedKey>,
    custom: bool,
}

/// Gives rustls the current certificate. `reload`, `use_custom` and `use_local` swap it with no
/// restart, so renewal and a change of certificate do not drop clients.
#[derive(Debug)]
pub struct LeafResolver {
    paths: TlsPaths,
    current: RwLock<Active>,
}

impl LeafResolver {
    /// Loads the leaf files.
    ///
    /// # Errors
    /// As [`read_leaf`].
    pub fn load(paths: TlsPaths) -> Result<Arc<Self>, ServerError> {
        let current = RwLock::new(Active {
            key: read_leaf(&paths)?,
            custom: false,
        });
        Ok(Arc::new(Self { paths, current }))
    }

    /// Reads the leaf files again. New handshakes use the new leaf. While a custom certificate is
    /// in use this does nothing: a renewal never replaces it (ADR-0023 point 8).
    ///
    /// # Errors
    /// As [`read_leaf`]. The old certificate stays in use on error.
    pub fn reload(&self) -> Result<(), ServerError> {
        if self.is_custom() {
            return Ok(());
        }
        let fresh = read_leaf(&self.paths)?;
        *self.write() = Active {
            key: fresh,
            custom: false,
        };
        Ok(())
    }

    /// Serves the owner custom certificate from now on.
    pub fn use_custom(&self, key: Arc<CertifiedKey>) {
        *self.write() = Active { key, custom: true };
    }

    /// Goes back to the local leaf files, also when a custom certificate is in use.
    ///
    /// # Errors
    /// As [`read_leaf`]. The custom certificate stays in use on error.
    pub fn use_local(&self) -> Result<(), ServerError> {
        let fresh = read_leaf(&self.paths)?;
        *self.write() = Active {
            key: fresh,
            custom: false,
        };
        Ok(())
    }

    /// True when the owner custom certificate is in use.
    #[must_use]
    pub fn is_custom(&self) -> bool {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .custom
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Active> {
        self.current.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ResolvesServerCert for LeafResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .key,
        ))
    }
}

/// The rustls server config: TLS 1.3 only, ALPN `h2` and `http/1.1`. With `client_ca` set, a client
/// certificate signed by that CA is verified; it is required when `require_client_cert` is true.
///
/// # Errors
/// [`ServerError::Tls`] when rustls refuses the settings.
pub fn server_config(
    resolver: Arc<LeafResolver>,
    client_ca: Option<&[u8]>,
    require_client_cert: bool,
) -> Result<Arc<ServerConfig>, ServerError> {
    let provider = Arc::new(ring_provider::default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    let builder = match client_ca {
        None => builder.with_no_client_auth(),
        Some(ca_der) => builder.with_client_cert_verifier(client_verifier(
            ca_der,
            require_client_cert,
            provider,
        )?),
    };
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Lifetime of the throwaway certificate of the first-start setup listener. Clients pin its key, so the date
/// is only a bound on a forgotten process.
const BOOTSTRAP_DAYS: i64 = 365;

/// The TLS side of the first-start setup listener of `cerberusd` (ADR-0034, DEC-SRV-3): a self-signed leaf with no
/// CA flag, made in memory at each start. It is never stored in a vault and it is not the vault CA.
pub struct BootstrapTls {
    /// The rustls server config: TLS 1.3 only, ALPN `http/1.1`, no client certificate.
    pub config: Arc<ServerConfig>,
    /// `sha256/<base64>` of the SubjectPublicKeyInfo of the certificate. The setup code carries it, and the client
    /// pins it.
    pub pin: String,
}

impl std::fmt::Debug for BootstrapTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapTls")
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

/// Makes the certificate and the server config of the setup listener, for `names` (DNS names and IP addresses).
/// ECDSA P-256, EKU serverAuth, not a CA.
///
/// # Errors
/// [`ServerError::Cert`] when a name is not valid or signing fails, [`ServerError::Tls`] when rustls refuses the
/// settings.
pub fn bootstrap_tls(names: &[String], now: Timestamp) -> Result<BootstrapTls, ServerError> {
    let first = names
        .first()
        .ok_or_else(|| cert_error("no names for the setup certificate"))?;
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = dn(first);
    params.subject_alt_names = names
        .iter()
        .map(|name| san(name))
        .collect::<Result<Vec<_>, _>>()?;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut params, now, BOOTSTRAP_DAYS)?;
    let cert = params.self_signed(&key).map_err(cert_error)?;
    let pin = spki_pin(cert.der())?;
    let provider = Arc::new(ring_provider::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ServerError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(BootstrapTls {
        config: Arc::new(config),
        pin,
    })
}

/// The client certificate check of [`server_config`]: signed by the CA in `ca_der`, EKU
/// clientAuth, in its validity time.
fn client_verifier(
    ca_der: &[u8],
    require_client_cert: bool,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, ServerError> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    let mut verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    if !require_client_cert {
        verifier = verifier.allow_unauthenticated();
    }
    verifier
        .build()
        .map_err(|e| ServerError::Tls(e.to_string()))
}

/// Makes the CA when a vault is created, and the first leaf next to it (ADR-0023, DEC-T05-1).
#[derive(Clone, Debug)]
pub struct LocalCaIssuer {
    tls: TlsPaths,
    extra_names: Vec<String>,
}

impl LocalCaIssuer {
    /// An issuer that writes the first leaf to `tls`, with `extra_names` as owner-added names.
    #[must_use]
    pub const fn new(tls: TlsPaths, extra_names: Vec<String>) -> Self {
        Self { tls, extra_names }
    }
}

fn issue_error(error: &ServerError) -> CoreError {
    tracing::error!(%error, "local CA issue failed");
    CoreError::Crypto(CryptoError::Encoding)
}

impl CaIssuer for LocalCaIssuer {
    fn issue_ca(&self, vault_id: &VaultId, now: Timestamp) -> Result<IssuedCa, CoreError> {
        let ca = LocalCa::create(vault_id, now).map_err(|e| issue_error(&e))?;
        let leaf = ca
            .issue_leaf(&leaf_names(&self.extra_names), now)
            .map_err(|e| issue_error(&e))?;
        write_leaf(&self.tls, &leaf).map_err(|e| issue_error(&e))?;
        write_ca_cert(&self.tls, ca.cert_der()).map_err(|e| issue_error(&e))?;
        ca.to_issued().map_err(|e| issue_error(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_types::{Clock, SystemClock};

    fn names() -> Vec<String> {
        leaf_names(&["agents.internal".to_owned()])
    }

    #[test]
    fn leaf_names_hold_the_adr_names_once() {
        let list = leaf_names(&["LOCALHOST".to_owned(), "extra.test".to_owned()]);
        for wanted in ["localhost", "127.0.0.1", "::1", "extra.test"] {
            assert_eq!(
                list.iter()
                    .filter(|n| n.eq_ignore_ascii_case(wanted))
                    .count(),
                1,
                "{wanted}"
            );
        }
    }

    #[test]
    fn ca_is_p256_constrained_and_signs_a_leaf_with_the_names() {
        let now = SystemClock.now();
        let ca = LocalCa::create(&VaultId::generate(), now).expect("ca");
        let (_, cert) = X509Certificate::from_der(ca.cert_der()).expect("parse");
        assert!(cert.is_ca());
        assert_eq!(
            cert.basic_constraints()
                .ok()
                .flatten()
                .and_then(|b| b.value.path_len_constraint),
            Some(0)
        );
        assert!(cert.subject().to_string().contains("Cerberus Local CA"));
        let leaf = ca.issue_leaf(&names(), now).expect("leaf");
        let (_, parsed) = X509Certificate::from_der(&leaf.cert_der).expect("leaf parse");
        assert!(!parsed.is_ca());
        assert_eq!(parsed.issuer(), cert.subject());
        let san = parsed
            .subject_alternative_name()
            .expect("san")
            .expect("ext");
        assert_eq!(san.value.general_names.len(), names().len());
        // The leaf lives 90 days.
        let days = (leaf.not_after.as_second() - now.as_second()) / 86_400;
        assert_eq!(days, 90);
    }

    #[test]
    fn a_ca_opened_from_its_parts_signs_leaves_the_same_ca_verifies() {
        let now = SystemClock.now();
        let ca = LocalCa::create(&VaultId::generate(), now).expect("ca");
        let issued = ca.to_issued().expect("issued");
        assert_eq!(issued.pin, spki_pin(ca.cert_der()).expect("pin"));
        let again = LocalCa::from_parts(&issued.cert_der, &issued.key_der).expect("from parts");
        assert_eq!(again.cert_der(), ca.cert_der());
        assert!(again.issue_leaf(&names(), now).is_ok());
        assert!(again.issue_client(AgentId::generate(), now).is_ok());
    }

    #[test]
    fn renewal_when_missing_changed_or_old_and_not_otherwise() {
        let dir = tempfile::tempdir().expect("dir");
        let paths = TlsPaths::in_data_dir(dir.path());
        let now = SystemClock.now();
        let ca = LocalCa::create(&VaultId::generate(), now).expect("ca");
        assert!(
            leaf_needs_renewal(&paths, &names(), now).is_err(),
            "no files yet"
        );
        assert!(
            renew_leaf_if_needed(&ca, &paths, &names(), now).expect("renew"),
            "missing leaf is made"
        );
        assert!(!leaf_needs_renewal(&paths, &names(), now).expect("check"));
        assert!(!renew_leaf_if_needed(&ca, &paths, &names(), now).expect("renew"));
        let mut other = names();
        other.push("new-name.test".to_owned());
        assert!(
            leaf_needs_renewal(&paths, &other, now).expect("check"),
            "names changed"
        );
        let later = now
            .checked_add(SignedDuration::from_hours(24 * 61))
            .expect("time");
        assert!(
            leaf_needs_renewal(&paths, &names(), later).expect("check"),
            "less than 30 days left"
        );
        let soon = now
            .checked_add(SignedDuration::from_hours(24 * 50))
            .expect("time");
        assert!(
            !leaf_needs_renewal(&paths, &names(), soon).expect("check"),
            "40 days left"
        );
        read_leaf(&paths).expect("the files load");
    }

    #[test]
    fn a_client_cert_has_client_auth_and_a_stable_fingerprint() {
        let now = SystemClock.now();
        let ca = LocalCa::create(&VaultId::generate(), now).expect("ca");
        let agent = AgentId::generate();
        let cert = ca.issue_client(agent, now).expect("cert");
        assert_eq!(cert.sha256(), cert.sha256());
        assert!(cert.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.key_pem().starts_with("-----BEGIN PRIVATE KEY-----"));
        let (_, parsed) = X509Certificate::from_der(&cert.cert_der).expect("parse");
        assert!(parsed.subject().to_string().contains(&agent.to_string()));
        let eku = parsed.extended_key_usage().expect("eku").expect("ext");
        assert!(eku.value.client_auth && !eku.value.server_auth);
    }

    fn unix_time(at: Timestamp) -> rustls::pki_types::UnixTime {
        rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            u64::try_from(at.as_second()).expect("after 1970"),
        ))
    }

    #[test]
    fn an_admin_client_cert_has_its_cn_client_auth_90_days_and_passes_the_client_check() {
        let now = SystemClock.now();
        let ca = LocalCa::create(&VaultId::generate(), now).expect("ca");
        let enrolment = "0190e0a0-0000-7000-8000-000000000001";
        let cert = ca.issue_admin_client(enrolment, now).expect("cert");
        let (_, parsed) = X509Certificate::from_der(&cert.cert_der).expect("parse");
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .expect("cn");
        assert_eq!(cn, format!("cerberus-admin {enrolment}"));
        let eku = parsed.extended_key_usage().expect("eku").expect("ext");
        assert!(eku.value.client_auth && !eku.value.server_auth);
        assert!(!parsed.is_ca());
        let days = (cert.not_after.as_second() - now.as_second()) / 86_400;
        assert_eq!(days, ADMIN_CLIENT_DAYS);
        assert!(cert.key_pem().starts_with("-----BEGIN PRIVATE KEY-----"));

        let provider = Arc::new(ring_provider::default_provider());
        let verifier =
            client_verifier(ca.cert_der(), false, Arc::clone(&provider)).expect("verifier");
        let der = CertificateDer::from(cert.cert_der.clone());
        assert!(
            verifier
                .verify_client_cert(&der, &[], unix_time(now))
                .is_ok()
        );
        let late = now + SignedDuration::from_hours(24 * (ADMIN_CLIENT_DAYS + 1));
        assert!(
            verifier
                .verify_client_cert(&der, &[], unix_time(late))
                .is_err()
        );
        let other = LocalCa::create(&VaultId::generate(), now).expect("other ca");
        let foreign = client_verifier(other.cert_der(), true, provider).expect("verifier");
        assert!(
            foreign
                .verify_client_cert(&der, &[], unix_time(now))
                .is_err()
        );
    }
}
