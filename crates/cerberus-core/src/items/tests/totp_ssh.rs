//! TOTP against RFC 6238 vectors, and SSH key fingerprints.

use ssh_key::{HashAlg, PrivateKey, PublicKey};
use totp_rs::Secret;

use super::fixture::secret;
use crate::error::CoreError;
use crate::items::{
    Payload, TotpAlgorithm, TotpSeed, generate_ed25519, import_private_key, ssh_fingerprint,
    totp_now, validate_payload,
};

fn base32(raw: &[u8]) -> String {
    Secret::new(raw.to_vec().into_boxed_slice()).to_base32()
}

fn seed(raw: &[u8], algorithm: TotpAlgorithm) -> TotpSeed {
    TotpSeed {
        secret: secret(&base32(raw)),
        algorithm,
        digits: 8,
        period: 30,
    }
}

fn at(seconds: i64) -> jiff::Timestamp {
    jiff::Timestamp::from_second(seconds).unwrap()
}

/// RFC 6238 appendix B. The seeds are the ASCII strings of the RFC, 8 digits, 30 s.
#[test]
fn rfc_6238_vectors() {
    let sha1 = seed(b"12345678901234567890", TotpAlgorithm::Sha1);
    let sha256 = seed(b"12345678901234567890123456789012", TotpAlgorithm::Sha256);
    let sha512 = seed(
        b"1234567890123456789012345678901234567890123456789012345678901234",
        TotpAlgorithm::Sha512,
    );
    let table: [(i64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];
    for (time, want1, want256, want512) in table {
        for (seed, want) in [(&sha1, want1), (&sha256, want256), (&sha512, want512)] {
            let code = totp_now(seed, at(time)).unwrap();
            assert_eq!(
                code.code.expose_secret(),
                want,
                "t={time} {:?}",
                seed.algorithm
            );
        }
    }
}

#[test]
fn seconds_left_and_period() {
    let s = seed(b"12345678901234567890", TotpAlgorithm::Sha1);
    let first = totp_now(&s, at(59)).unwrap();
    assert_eq!((first.period, first.expires_in_seconds), (30, 1));
    let second = totp_now(&s, at(60)).unwrap();
    assert_eq!(second.expires_in_seconds, 30);
    assert_ne!(first.code.expose_secret(), second.code.expose_secret());
}

#[test]
fn pasted_seed_forms_are_accepted() {
    let plain = TotpSeed::standard(secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    let pasted = TotpSeed::standard(secret("gezd gnbv-gy3t qojq GEZDGNBVGY3TQOJQ=="));
    let (a, b) = (
        totp_now(&plain, at(1000)).unwrap(),
        totp_now(&pasted, at(1000)).unwrap(),
    );
    assert_eq!(a.code.expose_secret(), b.code.expose_secret());
    assert_eq!(a.code.expose_secret().len(), 6);
}

#[test]
fn a_bad_seed_is_corrupt_data_at_read_time() {
    let bad = TotpSeed::standard(secret("!!!"));
    assert!(matches!(totp_now(&bad, at(1)), Err(CoreError::Corrupt)));
    assert!(matches!(
        totp_now(
            &TotpSeed::standard(secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
            at(-5)
        ),
        Err(CoreError::Corrupt)
    ));
}

#[test]
fn generated_key_fingerprint_matches_ssh_key() {
    let payload = generate_ed25519("build@fake").unwrap();
    let Payload::SshKey {
        private_key,
        public_key,
        fingerprint,
        passphrase,
    } = &payload
    else {
        unreachable!("generate_ed25519 makes an ssh key")
    };
    assert!(passphrase.is_none());
    assert!(fingerprint.starts_with("SHA256:"));
    let parsed = PrivateKey::from_openssh(private_key.expose_secret()).unwrap();
    assert_eq!(
        parsed.fingerprint(HashAlg::Sha256).to_string(),
        *fingerprint
    );
    let public = PublicKey::from_openssh(public_key).unwrap();
    assert_eq!(
        public.fingerprint(HashAlg::Sha256).to_string(),
        *fingerprint
    );
    assert_eq!(ssh_fingerprint(public_key).unwrap(), *fingerprint);
    assert!(public_key.starts_with("ssh-ed25519 "));
    assert!(validate_payload(&payload).is_empty());
}

#[test]
fn import_gives_the_same_fingerprint_and_rejects_garbage() {
    let made = generate_ed25519("fake").unwrap();
    let Payload::SshKey {
        private_key,
        fingerprint,
        ..
    } = &made
    else {
        unreachable!("ssh key")
    };
    let imported = import_private_key(private_key.expose_secret(), None).unwrap();
    let Payload::SshKey {
        fingerprint: again, ..
    } = imported
    else {
        unreachable!("ssh key")
    };
    assert_eq!(&again, fingerprint);
    let other = generate_ed25519("other").unwrap();
    let Payload::SshKey {
        fingerprint: other_fp,
        ..
    } = other
    else {
        unreachable!("ssh key")
    };
    assert_ne!(&other_fp, fingerprint, "two keys, two fingerprints");
    assert!(matches!(
        import_private_key("-----BEGIN NOPE-----", None),
        Err(CoreError::Validation(_))
    ));
    assert!(matches!(
        ssh_fingerprint("ssh-ed25519"),
        Err(CoreError::Validation(_))
    ));
}

#[test]
fn a_public_key_or_fingerprint_that_does_not_match_is_refused() {
    let Payload::SshKey {
        private_key,
        public_key,
        ..
    } = generate_ed25519("a").unwrap()
    else {
        unreachable!("ssh key")
    };
    let Payload::SshKey {
        public_key: other_public,
        fingerprint: other_fp,
        ..
    } = generate_ed25519("b").unwrap()
    else {
        unreachable!("ssh key")
    };
    let wrong_public = Payload::SshKey {
        private_key: private_key.clone(),
        passphrase: None,
        public_key: other_public,
        fingerprint: other_fp.clone(),
    };
    let fields: Vec<String> = validate_payload(&wrong_public)
        .into_iter()
        .map(|p| p.field)
        .collect();
    assert!(
        fields.contains(&"payload.public_key".to_owned()),
        "{fields:?}"
    );
    let wrong_fp = Payload::SshKey {
        private_key,
        passphrase: None,
        public_key,
        fingerprint: other_fp,
    };
    let fields: Vec<String> = validate_payload(&wrong_fp)
        .into_iter()
        .map(|p| p.field)
        .collect();
    assert_eq!(fields, ["payload.fingerprint"]);
}

/// AUD-3: the bcrypt round count of an encrypted key is chosen by whoever writes the item. A
/// count above the limit is refused at import and at validation, so no later decrypt can run
/// for days.
#[test]
fn an_encrypted_key_with_too_many_kdf_rounds_is_refused() {
    use crate::items::MAX_SSH_KDF_ROUNDS;
    use crate::items::ssh::encrypted_key_with_rounds;

    let phrase = || Some(secret("zq-fake-passphrase"));
    let at_limit = encrypted_key_with_rounds("zq-fake-passphrase", MAX_SSH_KDF_ROUNDS);
    let payload = import_private_key(&at_limit, phrase()).unwrap();
    assert!(validate_payload(&payload).is_empty());

    let over = encrypted_key_with_rounds("zq-fake-passphrase", MAX_SSH_KDF_ROUNDS + 1);
    let Err(CoreError::Validation(problems)) = import_private_key(&over, phrase()) else {
        panic!("import must refuse the round count");
    };
    assert_eq!(problems[0].field, "private_key");

    let huge = encrypted_key_with_rounds("zq-fake-passphrase", u32::MAX);
    let parsed = PrivateKey::from_openssh(&huge).unwrap();
    let stored = Payload::SshKey {
        private_key: secret(&huge),
        passphrase: phrase(),
        public_key: parsed.public_key().to_openssh().unwrap(),
        fingerprint: parsed.fingerprint(HashAlg::Sha256).to_string(),
    };
    let fields: Vec<String> = validate_payload(&stored)
        .into_iter()
        .map(|p| p.field)
        .collect();
    assert_eq!(fields, ["payload.private_key"]);
}
