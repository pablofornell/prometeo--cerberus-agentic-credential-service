//! SSH keys: generate an ed25519 key, import an OpenSSH private key, compute the fingerprint.
//!
//! Machine name, host, port and user are item metadata in `custom` (ADR-0027), so search and
//! resolve can use them. The fingerprint is also in the payload.

use std::collections::BTreeMap;

use cerberus_crypto::SecretString;
use cerberus_types::FieldProblem;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, Kdf, LineEnding, PrivateKey, PublicKey};

use super::payload::Payload;
use crate::error::CoreError;

const KEY_MACHINE: &str = "machine";
const KEY_HOST: &str = "host";
const KEY_PORT: &str = "port";
const KEY_USER: &str = "user";
/// Item setting (in `custom`): the `SSHSIG` namespaces the key may sign, as a comma list, for
/// example `git` or `git,file` (AUD-21). Without it the key signs SSH logins only.
pub const KEY_SSHSIG_NAMESPACES: &str = "sshsig_namespaces";
/// Longest `SSHSIG` namespace name.
const MAX_NAMESPACE_CHARS: usize = 64;

/// Largest bcrypt-pbkdf round count of an encrypted key (AUD-3, DEC-T27-A2-2). The count is in
/// the key file in clear text and the decrypt time grows with it, so whoever writes the item
/// chooses the cost. OpenSSH uses 16 by default; 1024 is a generous upper bound.
pub const MAX_SSH_KDF_ROUNDS: u32 = 1024;

/// The SSH facts that live in the item metadata (`custom`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshMeta {
    /// Machine name, for example `build-01`.
    pub machine: Option<String>,
    /// Host name or address.
    pub host: Option<String>,
    /// Port.
    pub port: Option<u16>,
    /// User name on the machine.
    pub user: Option<String>,
}

impl SshMeta {
    /// The `custom` entries for these facts.
    #[must_use]
    pub fn into_custom(self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let texts = [
            (KEY_MACHINE, self.machine),
            (KEY_HOST, self.host),
            (KEY_USER, self.user),
            (KEY_PORT, self.port.map(|p| p.to_string())),
        ];
        for (key, value) in texts {
            if let Some(value) = value {
                out.insert(key.to_owned(), value);
            }
        }
        out
    }

    /// Reads the facts back from `custom`. A port that is not a number is left out.
    #[must_use]
    pub fn from_custom<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Self {
        Self {
            machine: get(KEY_MACHINE).map(str::to_owned),
            host: get(KEY_HOST).map(str::to_owned),
            port: get(KEY_PORT).and_then(|p| p.parse().ok()),
            user: get(KEY_USER).map(str::to_owned),
        }
    }
}

/// The `SSHSIG` namespace names of the setting text: comma separated, trimmed. `None` when a
/// name is empty or has a character other than ASCII letters, digits and `.`, `-`, `_`, `@`.
fn namespace_list(text: &str) -> Option<Vec<&str>> {
    text.split(',')
        .map(str::trim)
        .map(|name| {
            let ok = (1..=MAX_NAMESPACE_CHARS).contains(&name.len())
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'));
            ok.then_some(name)
        })
        .collect()
}

/// True when the setting `sshsig_namespaces` (its text, if any) allows `namespace`. No setting,
/// or a setting that does not parse, allows nothing.
#[must_use]
pub(crate) fn allows_sshsig(setting: Option<&str>, namespace: &str) -> bool {
    setting
        .and_then(namespace_list)
        .is_some_and(|names| names.contains(&namespace))
}

/// Problems of the SSH entries in `custom`.
pub(crate) fn check_custom(custom: &BTreeMap<String, String>, problems: &mut Vec<FieldProblem>) {
    if custom
        .get(KEY_SSHSIG_NAMESPACES)
        .is_some_and(|text| namespace_list(text).is_none())
    {
        problems.push(FieldProblem {
            field: format!("custom.{KEY_SSHSIG_NAMESPACES}"),
            problem: "must be a comma list of names (letters, digits, . - _ @)".to_owned(),
        });
    }
    if custom
        .get(KEY_PORT)
        .is_some_and(|p| p.parse::<u16>().map_or(true, |n| n == 0))
    {
        problems.push(FieldProblem {
            field: "custom.port".to_owned(),
            problem: "must be a port number 1..65535".to_owned(),
        });
    }
}

/// The problem text for a key whose bcrypt round count is above [`MAX_SSH_KDF_ROUNDS`].
pub(crate) const KDF_ROUNDS_PROBLEM: &str =
    "the encrypted key uses more than 1024 bcrypt rounds; encrypt it again with fewer rounds";

/// True when the KDF cost of `key` is in the limit: no KDF, or bcrypt with at most
/// [`MAX_SSH_KDF_ROUNDS`] rounds. Reading the count is cheap; nothing is decrypted.
pub(crate) fn kdf_cost_ok(key: &PrivateKey) -> bool {
    match key.kdf() {
        Kdf::Bcrypt { rounds, .. } => *rounds <= MAX_SSH_KDF_ROUNDS,
        _ => true,
    }
}

fn problem(field: &str, text: &str) -> CoreError {
    CoreError::Validation(vec![FieldProblem {
        field: field.to_owned(),
        problem: text.to_owned(),
    }])
}

/// The `SHA256:...` fingerprint of an OpenSSH public key line.
///
/// # Errors
/// [`CoreError::Validation`] when the text is not an OpenSSH public key.
pub fn ssh_fingerprint(public_key: &str) -> Result<String, CoreError> {
    let key = PublicKey::from_openssh(public_key)
        .map_err(|_| problem("public_key", "is not an OpenSSH public key"))?;
    Ok(key.fingerprint(HashAlg::Sha256).to_string())
}

fn payload_of(key: &PrivateKey, passphrase: Option<SecretString>) -> Result<Payload, CoreError> {
    let text = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| CoreError::Corrupt)?;
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|_| CoreError::Corrupt)?;
    Ok(Payload::SshKey {
        private_key: SecretString::new(text.to_string()),
        passphrase,
        public_key,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// Makes a new ed25519 key pair without a passphrase. `comment` goes into the key text.
///
/// # Errors
/// [`CoreError::Corrupt`] when the system random generator fails.
pub fn generate_ed25519(comment: &str) -> Result<Payload, CoreError> {
    let mut key =
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| CoreError::Corrupt)?;
    key.set_comment(comment);
    payload_of(&key, None)
}

/// Imports an OpenSSH private key. The public key and the fingerprint are computed from it.
/// An encrypted key is kept as it is, together with its `passphrase`.
///
/// # Errors
/// [`CoreError::Validation`] (field `private_key`) when the text is not an OpenSSH private key,
/// or when it is encrypted with more than [`MAX_SSH_KDF_ROUNDS`] bcrypt rounds.
pub fn import_private_key(
    text: &str,
    passphrase: Option<SecretString>,
) -> Result<Payload, CoreError> {
    let key = PrivateKey::from_openssh(text.trim())
        .map_err(|_| problem("private_key", "is not an OpenSSH private key"))?;
    if !kdf_cost_ok(&key) {
        return Err(problem("private_key", KDF_ROUNDS_PROBLEM));
    }
    payload_of(&key, passphrase)
}

/// Checks an SSH payload: the key parses, its KDF cost is in the limit (AUD-3), and the stored
/// public key and fingerprint belong to it.
pub(crate) fn check_payload(
    private_key: &SecretString,
    public_key: &str,
    fingerprint: &str,
    problems: &mut Vec<FieldProblem>,
) {
    let bad = |field: &str, text: &str| FieldProblem {
        field: format!("payload.{field}"),
        problem: text.to_owned(),
    };
    let Ok(private) = PrivateKey::from_openssh(private_key.expose_secret()) else {
        problems.push(bad("private_key", "is not an OpenSSH private key"));
        return;
    };
    if !kdf_cost_ok(&private) {
        problems.push(bad("private_key", KDF_ROUNDS_PROBLEM));
    }
    match PublicKey::from_openssh(public_key) {
        Ok(public) if public.key_data() == private.public_key().key_data() => {}
        _ => problems.push(bad("public_key", "does not belong to the private key")),
    }
    if private.fingerprint(HashAlg::Sha256).to_string() != fingerprint {
        problems.push(bad("fingerprint", "does not match the key"));
    }
}

/// Test helper: an encrypted OpenSSH ed25519 key (passphrase `passphrase`) whose bcrypt round
/// count field says `rounds`. The key is encrypted with the default 16 rounds and the field is
/// then patched, so a large count costs nothing here (AUD-3).
#[cfg(test)]
pub(crate) fn encrypted_key_with_rounds(passphrase: &str, rounds: u32) -> String {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("fake key");
    let mut bytes = key
        .encrypt(&mut OsRng, passphrase)
        .expect("encrypt")
        .to_bytes()
        .expect("encode")
        .to_vec();
    // "openssh-key-v1\0", string cipher, string kdf name, string kdf options (string salt,
    // uint32 rounds).
    let len_at = |bytes: &[u8], at: usize| -> usize {
        let mut four = [0_u8; 4];
        four.copy_from_slice(&bytes[at..at + 4]);
        usize::try_from(u32::from_be_bytes(four)).expect("length")
    };
    let mut at = b"openssh-key-v1\0".len();
    at += 4 + len_at(&bytes, at);
    at += 4 + len_at(&bytes, at);
    at += 4;
    at += 4 + len_at(&bytes, at);
    bytes[at..at + 4].copy_from_slice(&rounds.to_be_bytes());
    PrivateKey::from_bytes(&bytes)
        .expect("patched key parses")
        .to_openssh(LineEnding::LF)
        .expect("text")
        .to_string()
}
