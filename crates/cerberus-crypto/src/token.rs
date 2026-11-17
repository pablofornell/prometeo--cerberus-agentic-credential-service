//! Agent bearer tokens: `cvt_<agent_id>.<secret>` (ADR-0016).

use std::fmt;

use cerberus_types::AgentId;
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::random;
use crate::secret::SecretString;

/// Token prefix. Secret scanners look for it.
pub const TOKEN_PREFIX: &str = "cvt_";
/// Domain label of the token hash.
pub const TOKEN_HASH_LABEL: &[u8] = b"cerberus/v1/agent-token";
/// Length of the Base64url secret part (32 bytes, no padding).
pub const TOKEN_SECRET_CHARS: usize = 43;
const AGENT_ID_CHARS: usize = 36;

/// The 32 random bytes of a token, zeroized on drop.
pub struct TokenSecret(Zeroizing<[u8; 32]>);

impl TokenSecret {
    /// A new secret from the OS random generator.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the OS random generator fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        random::fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    fn encoded(&self) -> Zeroizing<[u8; TOKEN_SECRET_CHARS]> {
        let mut text = Zeroizing::new([0u8; TOKEN_SECRET_CHARS]);
        BASE64URL_NOPAD.encode_mut(&self.0[..], &mut text[..]);
        text
    }

    /// The full token text, shown to the person one time.
    #[must_use]
    pub fn to_token_string(&self, agent: &AgentId) -> SecretString {
        let mut out =
            String::with_capacity(TOKEN_PREFIX.len() + AGENT_ID_CHARS + 1 + TOKEN_SECRET_CHARS);
        out.push_str(TOKEN_PREFIX);
        out.push_str(&agent.to_string());
        out.push('.');
        out.extend(self.encoded().iter().map(|b| char::from(*b)));
        SecretString::new(out)
    }

    /// The last 4 characters of the secret, for display (`agent_keys.hint`).
    #[must_use]
    pub fn hint(&self) -> String {
        let text = self.encoded();
        text[TOKEN_SECRET_CHARS - 4..]
            .iter()
            .map(|b| char::from(*b))
            .collect()
    }
}

impl fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl ZeroizeOnDrop for TokenSecret {}

/// A parsed token. The agent ID is not secret; the secret part is.
#[derive(Debug)]
pub struct ParsedToken {
    /// Agent from the token text.
    pub agent_id: AgentId,
    /// Secret part.
    pub secret: TokenSecret,
}

/// Parses `cvt_<agent_id>.<secret>`. Strict: canonical lower-case agent ID, exactly 43
/// Base64url characters with canonical trailing bits.
///
/// # Errors
/// [`CryptoError::Encoding`] for any other form. The caller answers `401 unauthenticated`.
pub fn parse_token(raw: &str) -> Result<ParsedToken, CryptoError> {
    let rest = raw
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(CryptoError::Encoding)?;
    let (agent, secret) = rest.split_once('.').ok_or(CryptoError::Encoding)?;
    if agent.len() != AGENT_ID_CHARS || secret.len() != TOKEN_SECRET_CHARS {
        return Err(CryptoError::Encoding);
    }
    let agent_id: AgentId = agent.parse().map_err(|_| CryptoError::Encoding)?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    let len = BASE64URL_NOPAD
        .decode_len(secret.len())
        .map_err(|_| CryptoError::Encoding)?;
    if len != bytes.len() {
        return Err(CryptoError::Encoding);
    }
    BASE64URL_NOPAD
        .decode_mut(secret.as_bytes(), &mut bytes[..])
        .map_err(|_| CryptoError::Encoding)?;
    Ok(ParsedToken {
        agent_id,
        secret: TokenSecret(bytes),
    })
}

/// `SHA-256("cerberus/v1/agent-token" || agent_id (16 bytes) || secret (32 bytes))` (ADR-0016).
///
/// A fast hash is right here: the secret has 256 random bits. Compare hashes with
/// [`crate::ct_eq`] against every key of the agent, without an early exit.
#[must_use]
pub fn token_hash(agent: &AgentId, secret: &TokenSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_HASH_LABEL);
    hasher.update(agent.as_bytes());
    hasher.update(&secret.0[..]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn token_roundtrip() {
        let agent = AgentId::generate();
        let secret = TokenSecret::generate().unwrap();
        let text = secret.to_token_string(&agent);
        let text = text.expose_secret();
        assert!(text.starts_with("cvt_"));
        assert_eq!(text.len(), 4 + 36 + 1 + 43);
        assert!(text.ends_with(&secret.hint()));
        let parsed = parse_token(text).unwrap();
        assert_eq!(parsed.agent_id, agent);
        assert_eq!(
            token_hash(&agent, &parsed.secret),
            token_hash(&agent, &secret)
        );
    }

    #[test]
    fn known_hash() {
        // Fake values. Checked with Python: sha256(label + agent bytes + secret bytes).
        let agent: AgentId = "01890000-0000-7000-8000-000000000000".parse().unwrap();
        let secret = TokenSecret(Zeroizing::new([0x42; 32]));
        assert_eq!(hex(&token_hash(&agent, &secret)), KNOWN_HASH);
        let text = secret.to_token_string(&agent);
        assert_eq!(
            text.expose_secret(),
            "cvt_01890000-0000-7000-8000-000000000000.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
        );
        assert_eq!(secret.hint(), "CQkI");
    }

    const KNOWN_HASH: &str = "9115cae28117d62fc90f8e7c32dc136209ab75c016d8ef7a58967db0a91aabea";

    #[test]
    fn parse_refuses_bad_forms() {
        let agent = AgentId::generate();
        let good = TokenSecret::generate()
            .unwrap()
            .to_token_string(&agent)
            .expose_secret()
            .to_owned();
        let upper_agent = format!("cvt_{}{}", agent.to_string().to_uppercase(), &good[40..]);
        let bad_tail = format!("{}{}", &good[..good.len() - 1], "!");
        let cases = [
            String::new(),
            good.replacen("cvt_", "cvx_", 1),
            good.replacen('.', ":", 1),
            format!("{good}A"),
            good[..good.len() - 1].to_owned(),
            upper_agent,
            bad_tail,
            format!(" {good}"),
            "cvt_01890000-0000-7000-8000-000000000000.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
                .to_owned(),
            // Last character 'J' sets one of the 2 unused bits: not the canonical encoding.
            "cvt_01890000-0000-7000-8000-000000000000.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ"
                .to_owned(),
        ];
        for case in cases {
            assert!(parse_token(&case).is_err(), "accepted {case:?}");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let parsed = parse_token(
            "cvt_01890000-0000-7000-8000-000000000000.QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
        )
        .unwrap();
        let shown = format!("{parsed:?}");
        assert!(shown.contains("[REDACTED]"));
        assert!(!shown.contains("QkJC"));
    }
}
