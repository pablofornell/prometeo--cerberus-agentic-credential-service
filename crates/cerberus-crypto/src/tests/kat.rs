//! Known-answer tests.
//!
//! - Argon2id: RFC 9106 section 5.3 (checks the library and the Argon2id v0x13 choice), plus
//!   vectors for our exact path (NFKC + Argon2id, 32-byte output) computed with `argon2-cffi`
//!   (the reference C implementation).
//! - XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 appendix A.3.1.
//! - HKDF-SHA256: RFC 5869 appendix A.1 and A.3, through the library and through our helper.
//! - HMAC-SHA256: RFC 4231 test cases 1, 2, 3, 4 and 6, through the library and (for the keys that
//!   fit) through our `hmac_sha256`. SHA-256: FIPS 180-4 examples "abc" and the empty message.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::kdf::hkdf_sha256;
use crate::{
    KdfParams, Key32, RecoveryKey, SecretString, derive_passphrase_kek, derive_recovery_kek,
    hmac_sha256, sha256,
};

fn unhex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn argon2id_rfc9106_section_5_3() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .build()
        .unwrap();
    let ctx =
        Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    ctx.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
        .unwrap();
    assert_eq!(
        out.to_vec(),
        unhex(
            "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59"
        )
    );
}

#[test]
fn passphrase_kek_matches_reference_argon2() {
    // The phrase has a ligature and a combining accent, so the vector also covers NFKC.
    let phrase = SecretString::new("fake kat phrase \u{FB01} cafe\u{0301}".to_owned());
    let salt = [0x11; 32];
    let fast =
        derive_passphrase_kek(&phrase, &salt, &KdfParams::insecure_fast_for_tests()).unwrap();
    assert_eq!(
        fast.expose_secret().to_vec(),
        unhex("ae7f4beb07fb443824266b05ee6f54e8a3cebc5a18596b60983993528474337d")
    );
    let floor =
        derive_passphrase_kek(&phrase, &salt, &KdfParams::new(19_456, 1, 2).unwrap()).unwrap();
    assert_eq!(
        floor.expose_secret().to_vec(),
        unhex("dd94d48be17ef7c17be8077b01ae768ff4ca5277bfea9c6e6f62f93d598a2f97")
    );
}

#[test]
fn xchacha20poly1305_draft_a_3_1() {
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let key_bytes: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce_bytes: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
    let expected_ct = unhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13b52e",
    );
    let expected_tag = unhex("c0875924c1c7987947deafd8780acf49");

    let key: &Key = (&key_bytes).into();
    let nonce: &XNonce = (&nonce_bytes).into();
    let cipher = XChaCha20Poly1305::new(key);
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(nonce, &aad, (&mut buf[..]).into())
        .unwrap();
    assert_eq!(buf, expected_ct);
    assert_eq!(tag.to_vec(), expected_tag);

    let tag = <&Tag>::try_from(expected_tag.as_slice()).unwrap();
    cipher
        .decrypt_inout_detached(nonce, &aad, (&mut buf[..]).into(), tag)
        .unwrap();
    assert_eq!(buf, plaintext);
}

#[test]
fn hkdf_rfc5869_a1_and_a3() {
    // A.1: basic case.
    let ikm = [0x0b; 22];
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let okm_a1 = unhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
    let mut okm = [0u8; 42];
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(&info, &mut okm)
        .unwrap();
    assert_eq!(okm.to_vec(), okm_a1);
    // Our helper makes 32 bytes: the first 32 bytes of the same OKM.
    let ours = hkdf_sha256(&salt, &ikm, &info).unwrap();
    assert_eq!(ours.expose_secret().as_slice(), &okm_a1[..32]);

    // A.3: empty salt and info.
    let okm_a3 = unhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&[], &mut okm)
        .unwrap();
    assert_eq!(okm.to_vec(), okm_a3);
    let ours = hkdf_sha256(&[], &ikm, &[]).unwrap();
    assert_eq!(ours.expose_secret().as_slice(), &okm_a3[..32]);
}

#[test]
fn recovery_kek_vector() {
    // Computed with Python `hmac` (RFC 5869), key 00..1f, salt 0x33 * 32.
    let text = "CRK1-AAAQ-EAYE-AUDA-OCAJ-BIFQ-YDIO-B4IB-CEQT-CQKR-MFYY-DENB-WHA5-DYPW-GDON";
    let recovery = RecoveryKey::parse(text).unwrap();
    let kek = derive_recovery_kek(&recovery, &[0x33; 32]).unwrap();
    assert_eq!(
        kek.expose_secret().to_vec(),
        unhex("5988247fc6bbc913f0ec94414dae9f89bc775e110e47339edc2ed65ae6926410")
    );
}

/// RFC 4231 section 4: (key, data, HMAC-SHA-256).
fn rfc4231_cases() -> Vec<(Vec<u8>, Vec<u8>, &'static str)> {
    vec![
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            b"Jefe".to_vec(),
            b"what do ya want for nothing?".to_vec(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        (
            (1..=25).collect(),
            vec![0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        (
            vec![0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
    ]
}

#[test]
fn hmac_sha256_rfc4231() {
    use hmac::{Hmac, KeyInit, Mac};
    for (key, data, expected) in rfc4231_cases() {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        mac.update(&data);
        assert_eq!(mac.finalize().into_bytes().to_vec(), unhex(expected));
        // Our wrapper takes a 32-byte key. HMAC pads a short key with zero bytes, so the same
        // key with zeros up to 32 bytes gives the same tag.
        if key.len() <= 32 {
            let mut padded = [0u8; 32];
            padded[..key.len()].copy_from_slice(&key);
            let ours = hmac_sha256(&Key32::from_bytes(padded), &[&data[..4], &data[4..]]);
            assert_eq!(ours.to_vec(), unhex(expected));
        }
    }
}

#[test]
fn sha256_fips_180_4_examples() {
    assert_eq!(
        sha256(&[b"a", b"bc"]).to_vec(),
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(
        sha256(&[]).to_vec(),
        unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}
