//! Secret types never print their value (ADR-0032), and they zeroize on drop where we can see it.
//!
//! What is tested about zeroize, honestly:
//! - `LockedBox` drop calls `zeroize` before it frees the memory (`memlock` test with a probe type).
//! - Every secret type implements `ZeroizeOnDrop` (compile-time check below), which holds because
//!   each wraps `Zeroizing`, `secrecy::SecretBox` or `LockedBox`.
//! - Reading memory after drop is undefined behavior in Rust, so no test reads freed memory.
//!   The wipe of freed buffers itself relies on the `zeroize` and `secrecy` crates.

use std::fmt::Display;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use cerberus_types::{AgentId, VaultId};
use zeroize::ZeroizeOnDrop;

use crate::memlock::LockedBox;
use crate::{
    Key32, KeyTree, ParsedToken, RecoveryKey, SecretBytes, SecretString, TokenSecret, Vmk,
    parse_token,
};

const FAKE_TEXT: &str = "canary-pw-5f2c9e71";
const FAKE_BYTES: [u8; 32] = *b"canary-key-bytes-0123456789abcde";
/// Fake recovery key (bytes 00..1f). Fixed, so no random group can match other log text by chance.
const FAKE_RECOVERY: &str =
    "CRK1-AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPW-GDON";

/// The recovery text as needles: each group and the body without dashes.
fn recovery_needles() -> Vec<String> {
    let mut needles: Vec<String> = FAKE_RECOVERY
        .split('-')
        .skip(1)
        .map(str::to_owned)
        .collect();
    needles.push(needles.concat());
    needles
}

/// Every printed form of `value` that the language allows for a type without `Display`.
fn printed<T: std::fmt::Debug>(value: &T) -> Vec<String> {
    vec![
        format!("{value:?}"),
        format!("{value:#?}"),
        format!("{:?}", Some(value)),
        format!("{:?}", [value]),
    ]
}

fn assert_hidden(outputs: &[String], needles: &[&str]) {
    for out in outputs {
        assert!(out.contains("[REDACTED]"), "no redaction marker in {out:?}");
        for needle in needles {
            assert!(!out.contains(needle), "secret leaked in {out:?}");
        }
    }
}

/// Text forms a key could take in a log: raw text, decimal bytes, hex.
fn byte_needles(bytes: &[u8]) -> Vec<String> {
    vec![
        String::from_utf8_lossy(bytes).into_owned(),
        format!("{:?}", bytes),
        bytes.iter().map(|b| format!("{b:02x}")).collect(),
        bytes[..8]
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    ]
}

#[test]
fn debug_never_shows_the_value() {
    let text = SecretString::new(FAKE_TEXT.to_owned());
    assert_hidden(&printed(&text), &[FAKE_TEXT]);

    let bytes = SecretBytes::new(FAKE_BYTES.to_vec());
    let needles = byte_needles(&FAKE_BYTES);
    let needles: Vec<&str> = needles.iter().map(String::as_str).collect();
    assert_hidden(&printed(&bytes), &needles);

    let key = Key32::from_bytes(FAKE_BYTES);
    assert_hidden(&printed(&key), &needles);
    let vmk = Vmk(Key32::from_bytes(FAKE_BYTES));
    assert_hidden(&printed(&vmk), &needles);
    let boxed = LockedBox::new(FAKE_BYTES);
    assert_hidden(&printed(&boxed), &needles);

    let recovery = RecoveryKey::parse(FAKE_RECOVERY).unwrap();
    let shown = recovery.to_display();
    assert_eq!(shown.expose_secret(), FAKE_RECOVERY);
    let groups = recovery_needles();
    let groups: Vec<&str> = groups.iter().map(String::as_str).collect();
    assert_hidden(&printed(&recovery), &groups);
    assert_hidden(&printed(&shown), &groups);
}

#[test]
fn containers_of_secrets_stay_redacted() {
    let tree = KeyTree::derive(&Vmk(Key32::from_bytes(FAKE_BYTES)), &VaultId([1; 16])).unwrap();
    let hex: Vec<String> = [
        &tree.item_kek,
        &tree.meta_key,
        &tree.audit_key,
        &tree.ca_key,
        &tree.header_key,
        &tree.row_mac_key,
    ]
    .iter()
    .map(|k| {
        k.expose_secret()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    })
    .collect();
    let shown = format!("{tree:?}");
    assert!(shown.contains("item_kek: [REDACTED]"));
    for h in &hex {
        assert!(!shown.contains(h.as_str()));
    }

    let agent = AgentId::generate();
    let secret = TokenSecret::generate().unwrap();
    let token = secret.to_token_string(&agent);
    let secret_part = token.expose_secret().split('.').nth(1).unwrap().to_owned();
    let parsed: ParsedToken = parse_token(token.expose_secret()).unwrap();
    assert_hidden(&printed(&parsed), &[secret_part.as_str()]);
    assert_hidden(&printed(&secret), &[secret_part.as_str()]);
    assert_hidden(
        &printed(&token),
        &[secret_part.as_str(), token.expose_secret()],
    );
    // The agent ID is not secret and may show.
    assert!(format!("{parsed:?}").contains(&agent.to_string()));
}

/// `IMPLS` is true only for types with `Display` (an inherent const wins over the trait const).
struct DisplayProbe<T: ?Sized>(PhantomData<T>);
trait NoDisplay {
    const IMPLS: bool = false;
}
impl<T: ?Sized> NoDisplay for DisplayProbe<T> {}
impl<T: ?Sized + Display> DisplayProbe<T> {
    const IMPLS: bool = true;
}

// Checked at compile time: a `Display` impl on a secret type stops the test build.
// Serialize: this crate has no serde dependency, so no type here can implement it.
const _: () = {
    assert!(
        DisplayProbe::<String>::IMPLS,
        "control: the probe must see Display on String"
    );
    assert!(!DisplayProbe::<SecretString>::IMPLS);
    assert!(!DisplayProbe::<SecretBytes>::IMPLS);
    assert!(!DisplayProbe::<Key32>::IMPLS);
    assert!(!DisplayProbe::<Vmk>::IMPLS);
    assert!(!DisplayProbe::<RecoveryKey>::IMPLS);
    assert!(!DisplayProbe::<TokenSecret>::IMPLS);
    assert!(!DisplayProbe::<ParsedToken>::IMPLS);
    assert!(!DisplayProbe::<KeyTree>::IMPLS);
    assert!(!DisplayProbe::<LockedBox<[u8; 32]>>::IMPLS);
};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn secret_types_zeroize_on_drop() {
    assert_zeroize_on_drop::<SecretString>();
    assert_zeroize_on_drop::<SecretBytes>();
    assert_zeroize_on_drop::<Key32>();
    assert_zeroize_on_drop::<Vmk>();
    assert_zeroize_on_drop::<RecoveryKey>();
    assert_zeroize_on_drop::<TokenSecret>();
    assert_zeroize_on_drop::<LockedBox<[u8; 32]>>();
}

/// A `tracing` writer that keeps everything in memory.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn tracing_output_never_shows_secrets() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();

    let text = SecretString::new(FAKE_TEXT.to_owned());
    let key = Key32::from_bytes(FAKE_BYTES);
    let bytes = SecretBytes::new(FAKE_BYTES.to_vec());
    let recovery = RecoveryKey::parse(FAKE_RECOVERY).unwrap();
    let recovery_text = recovery.to_display();
    let tree = KeyTree::derive(&Vmk(Key32::from_bytes(FAKE_BYTES)), &VaultId([1; 16])).unwrap();

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(phrase = ?text, key = ?key, "event with secret fields");
        tracing::warn!(?bytes, ?recovery, ?recovery_text, "short form");
        tracing::error!("message arguments {:?} {:?}", text, tree);
        let span = tracing::info_span!("span", secret = ?key);
        let _guard = span.enter();
        tracing::debug!(inner = ?bytes, "inside a span");
    });

    let out = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        out.contains("event with secret fields"),
        "capture is empty: {out:?}"
    );
    assert!(out.contains("[REDACTED]"));
    let mut needles = byte_needles(&FAKE_BYTES);
    needles.push(FAKE_TEXT.to_owned());
    needles.extend(recovery_needles());
    needles.push(
        tree.meta_key
            .expose_secret()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    for needle in &needles {
        assert!(
            !out.contains(needle.as_str()),
            "secret leaked into the log: {needle:?}"
        );
    }
}

#[test]
fn errors_hold_no_data() {
    // `CryptoError` has no fields, so its text cannot hold a secret.
    let all = [
        crate::CryptoError::Integrity,
        crate::CryptoError::InvalidKdfParams,
        crate::CryptoError::Kdf,
        crate::CryptoError::Rng,
        crate::CryptoError::Encoding,
        crate::CryptoError::ChecksumMismatch,
        crate::CryptoError::EnvelopeVersion,
        crate::CryptoError::WeakPhrase,
        crate::CryptoError::SlotRule,
    ];
    for err in all {
        let text = err.to_string();
        assert!(!text.is_empty() && text.len() < 40);
    }
}
