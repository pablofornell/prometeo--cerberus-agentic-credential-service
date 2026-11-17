//! Passphrase and recovery-key KDFs, and Argon2id cost tuning (ADR-0013).

use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use cerberus_types::Stopwatch;
use hkdf::HkdfExtract;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::random;
use crate::recovery::RecoveryKey;
use crate::secret::{Key32, SecretString};

// The fast test parameters must never reach a release build (see `KdfParams::insecure_fast_for_tests`).
#[cfg(all(feature = "insecure-test-kdf", not(debug_assertions)))]
compile_error!(
    "feature `insecure-test-kdf` is for debug test builds only; never enable it in release"
);

/// HKDF `info` label for the recovery KEK (ADR-0013).
pub const RECOVERY_KEK_INFO: &[u8] = b"cerberus/v1/recovery-kek";

/// Argon2 version stored in `key_slots.argon2_version` (0x13 = 19).
pub const ARGON2_VERSION: u32 = 0x13;

/// Argon2id cost parameters of one key slot.
///
/// The fields are private, so every value went through [`KdfParams::new`] and its range check.
/// Values read from a vault file must use [`KdfParams::new`]: a changed header cannot lower the
/// cost below the floor or raise it to a denial of service (threat model T-2, D-3). Deriving a
/// key adds a cap that depends on the machine: memory up to half of RAM and `t` up to 10.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// Lowest accepted memory cost in KiB (19 MiB, OWASP minimum).
    pub const MIN_M_COST_KIB: u32 = 19_456;
    /// Highest accepted memory cost in KiB (4 GiB).
    pub const MAX_M_COST_KIB: u32 = 4_194_304;
    /// Lowest accepted time cost.
    pub const MIN_T_COST: u32 = 1;
    /// Highest accepted time cost.
    pub const MAX_T_COST: u32 = 20;
    /// Lowest accepted parallelism.
    pub const MIN_P_COST: u32 = 1;
    /// Highest accepted parallelism.
    pub const MAX_P_COST: u32 = 16;

    /// Start values of the tuning when RAM is 4 GiB or more: 256 MiB, t = 3, p = 4.
    pub const DEFAULT_LARGE: Self = Self {
        m_cost_kib: 262_144,
        t_cost: 3,
        p_cost: 4,
    };
    /// Start values of the tuning when RAM is less than 4 GiB: 64 MiB, t = 3, p = 4.
    pub const DEFAULT_SMALL: Self = Self {
        m_cost_kib: 65_536,
        t_cost: 3,
        p_cost: 4,
    };

    /// Checked constructor. Use it for every value that comes from outside, such as a vault file.
    ///
    /// It always applies the production range, also in test builds. So the fast test values
    /// cannot come in from a file.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKdfParams`] when a value is out of the ADR-0013 range.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        let params = Self {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        if params.in_production_range() {
            Ok(params)
        } else {
            Err(CryptoError::InvalidKdfParams)
        }
    }

    /// Memory cost in KiB.
    #[must_use]
    pub const fn m_cost_kib(&self) -> u32 {
        self.m_cost_kib
    }

    /// Time cost (passes).
    #[must_use]
    pub const fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Parallelism (lanes).
    #[must_use]
    pub const fn p_cost(&self) -> u32 {
        self.p_cost
    }

    /// Checks the ADR-0013 ranges: m 19456..=4194304 KiB, t 1..=20, p 1..=16.
    ///
    /// Test builds (see `KdfParams::insecure_fast_for_tests`) also accept the one fast test value.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKdfParams`] when a value is out of range.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.in_production_range() || self.is_test_fast() {
            Ok(())
        } else {
            Err(CryptoError::InvalidKdfParams)
        }
    }

    fn in_production_range(&self) -> bool {
        (Self::MIN_M_COST_KIB..=Self::MAX_M_COST_KIB).contains(&self.m_cost_kib)
            && (Self::MIN_T_COST..=Self::MAX_T_COST).contains(&self.t_cost)
            && (Self::MIN_P_COST..=Self::MAX_P_COST).contains(&self.p_cost)
    }

    /// Very weak parameters (64 KiB, t = 1, p = 1) so tests run fast.
    ///
    /// Three guards keep them out of production:
    /// 1. The function exists only in this crate's unit tests and with feature
    ///    `insecure-test-kdf`. Other crates enable the feature only in `[dev-dependencies]`, so a
    ///    normal or release build of a binary cannot name it.
    /// 2. A release build (no `debug_assertions`) with the feature fails to compile.
    /// 3. [`KdfParams::new`], the only way to build values read from a file, refuses them in
    ///    every build. A changed header cannot bring them in.
    ///
    /// The values are below the `CHECK` ranges of `key_slots` in `docs/schema.sql`, so slots made
    /// with them cannot be stored. Storage tests use the floor, `KdfParams::new(19_456, 1, 1)`.
    #[cfg(any(test, feature = "insecure-test-kdf"))]
    #[must_use]
    pub const fn insecure_fast_for_tests() -> Self {
        Self {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[cfg(any(test, feature = "insecure-test-kdf"))]
    fn is_test_fast(&self) -> bool {
        *self == Self::insecure_fast_for_tests()
    }

    #[cfg(not(any(test, feature = "insecure-test-kdf")))]
    #[allow(clippy::unused_self, reason = "same signature as the test build")]
    fn is_test_fast(&self) -> bool {
        false
    }

    /// Read-path cap: costs a vault file may ask for on this machine, below the ADR-0013 range.
    ///
    /// Memory may be at most half of `total_ram` (when known) and time at most the tuning
    /// maximum. The range of [`KdfParams::new`] stays machine independent. This cap needs the
    /// RAM size, so it runs when a key is derived, which is also the only moment memory is used.
    /// An edited header then cannot force an out-of-memory or very slow unlock (threat model D-3).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKdfParams`] when a cost is above the cap.
    fn check_read_cap(&self, total_ram: Option<u64>) -> Result<(), CryptoError> {
        let too_much_memory =
            total_ram.is_some_and(|ram| u64::from(self.m_cost_kib).saturating_mul(1024) > ram / 2);
        if too_much_memory || self.t_cost > TUNE_MAX_T {
            Err(CryptoError::InvalidKdfParams)
        } else {
            Ok(())
        }
    }

    fn argon2(&self) -> Result<Argon2<'static>, CryptoError> {
        self.validate()?;
        self.check_read_cap(total_ram_bytes())?;
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|_| CryptoError::InvalidKdfParams)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Result of [`tune_kdf`]: the chosen cost and the time of one derivation with it.
#[derive(Clone, Copy, Debug)]
pub struct KdfTuning {
    /// Chosen parameters.
    pub params: KdfParams,
    /// Measured time of one derivation with `params`.
    pub measured: Duration,
}

/// Total RAM of this machine in bytes, when a safe OS call can tell it.
///
/// Linux and Android only. Other systems give `None`; see [`tune_kdf`] for the effect.
#[must_use]
pub fn total_ram_bytes() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let info = rustix::system::sysinfo();
        #[allow(
            clippy::useless_conversion,
            reason = "c_ulong is u32 on 32-bit targets"
        )]
        u64::from(info.totalram).checked_mul(u64::from(info.mem_unit))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        None
    }
}

/// RAM limit for the large start cost (ADR-0013: 4 GiB).
const LARGE_RAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Time limit for one derivation at t = 1 before memory is halved (ADR-0013: 1.5 s).
const SLOW_LIMIT: Duration = Duration::from_millis(1500);
/// Highest time cost the tuning picks (ADR-0013: t in 1..=10).
const TUNE_MAX_T: u32 = 10;
/// Lowest memory cost the tuning picks (ADR-0013: 64 MiB).
const TUNE_MIN_M_KIB: u32 = 65_536;

/// Measures this machine and picks Argon2id costs near `target` (ADR-0013 "Cost tuning").
///
/// 1. Start with 256 MiB if `total_ram_bytes >= 4 GiB`, else 64 MiB; p = 4, t = 3.
/// 2. Measure, then pick t in 1..=10 so one derivation takes about `target`.
/// 3. If t = 1 still takes more than 1.5 s, halve m (not below 64 MiB) until it is faster.
///
/// Pass `u64::MAX` when the RAM size is not known ([`total_ram_bytes`] gave `None`).
///
/// # Errors
/// [`CryptoError::Kdf`] when Argon2id fails (for example out of memory).
pub fn tune_kdf(target: Duration, total_ram_bytes: u64) -> Result<KdfTuning, CryptoError> {
    let mut salt = [0u8; 32];
    random::fill(&mut salt)?;
    let probe = SecretString::new(String::from("cerberus-kdf-cost-probe"));
    tune_with(target, total_ram_bytes, |params| {
        let watch = Stopwatch::start();
        derive_passphrase_kek(&probe, &salt, params)?;
        Ok(watch.elapsed())
    })
}

/// The tuning steps with an injected measurement, so tests can use a cost model.
fn tune_with(
    target: Duration,
    total_ram_bytes: u64,
    mut measure: impl FnMut(&KdfParams) -> Result<Duration, CryptoError>,
) -> Result<KdfTuning, CryptoError> {
    let start = if total_ram_bytes >= LARGE_RAM_BYTES {
        KdfParams::DEFAULT_LARGE
    } else {
        KdfParams::DEFAULT_SMALL
    };
    let first = measure(&start)?;
    // Argon2id time grows about linearly with t, so one pass costs first / t.
    let per_pass = first.as_secs_f64() / f64::from(start.t_cost);
    let wanted = if per_pass > 0.0 {
        (target.as_secs_f64() / per_pass).round()
    } else {
        f64::from(TUNE_MAX_T)
    };
    let t_cost = pick_t(wanted);
    let mut params = KdfParams::new(start.m_cost_kib, t_cost, start.p_cost)?;
    let mut measured = if t_cost == start.t_cost {
        first
    } else {
        measure(&params)?
    };
    while params.t_cost == 1 && measured > SLOW_LIMIT && params.m_cost_kib > TUNE_MIN_M_KIB {
        let m_cost = (params.m_cost_kib / 2).max(TUNE_MIN_M_KIB);
        params = KdfParams::new(m_cost, 1, params.p_cost)?;
        measured = measure(&params)?;
    }
    Ok(KdfTuning { params, measured })
}

/// Rounds and clamps the wanted pass count to 1..=10.
fn pick_t(wanted: f64) -> u32 {
    let mut t = 1;
    while t < TUNE_MAX_T && f64::from(t) < wanted {
        t += 1;
    }
    t
}

/// Normalizes a phrase to Unicode NFKC. It does not trim (ADR-0013).
#[must_use]
pub fn normalize_phrase(input: &str) -> SecretString {
    // NFKC can make the text longer. Count first, so the buffer never grows: a grown buffer
    // would leave a copy of the phrase behind in freed memory.
    let len: usize = input.nfkc().map(char::len_utf8).sum();
    let mut out = String::with_capacity(len);
    out.extend(input.nfkc());
    SecretString::new(out)
}

/// Phrase -> NFKC -> Argon2id(salt, params) -> 32-byte KEK in locked memory.
///
/// The phrase is normalized here as well, so a caller cannot forget it (NFKC is idempotent).
///
/// # Errors
/// [`CryptoError::InvalidKdfParams`] for out-of-range params, [`CryptoError::Kdf`] when Argon2 fails.
pub fn derive_passphrase_kek(
    phrase: &SecretString,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<Key32, CryptoError> {
    let argon2 = params.argon2()?;
    let normalized = normalize_phrase(phrase.expose_secret());
    Key32::try_fill(|out| {
        argon2
            .hash_password_into(normalized.expose_secret().as_bytes(), salt, out)
            .map_err(|_| CryptoError::Kdf)
    })
}

/// Recovery key -> HKDF-SHA256(salt = slot salt, info = `cerberus/v1/recovery-kek`) -> KEK.
///
/// No Argon2 here: the recovery key has 256 bits of entropy (ADR-0013).
///
/// # Errors
/// [`CryptoError::Kdf`] when HKDF fails (it does not for a 32-byte output).
pub fn derive_recovery_kek(recovery: &RecoveryKey, salt: &[u8; 32]) -> Result<Key32, CryptoError> {
    hkdf_sha256(salt, recovery.key().expose_secret(), RECOVERY_KEK_INFO)
}

/// HKDF-SHA256 extract and expand to a 32-byte key in locked memory. The PRK is zeroized.
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Key32, CryptoError> {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    extract.input_ikm(ikm);
    let (mut prk, hkdf) = extract.finalize();
    prk.as_mut_slice().zeroize();
    Key32::try_fill(|out| hkdf.expand(info, out).map_err(|_| CryptoError::Kdf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_of_adr_0013() {
        assert!(KdfParams::new(19_456, 1, 1).is_ok());
        assert!(KdfParams::new(4_194_304, 20, 16).is_ok());
        for (m, t, p) in [
            (19_455, 3, 4),
            (4_194_305, 3, 4),
            (65_536, 0, 4),
            (65_536, 21, 4),
            (65_536, 3, 0),
            (65_536, 3, 17),
            (0, 0, 0),
            (u32::MAX, u32::MAX, u32::MAX),
        ] {
            assert_eq!(
                KdfParams::new(m, t, p),
                Err(CryptoError::InvalidKdfParams),
                "{m} {t} {p}"
            );
        }
        assert!(KdfParams::DEFAULT_LARGE.validate().is_ok());
        assert!(KdfParams::DEFAULT_SMALL.validate().is_ok());
    }

    #[test]
    fn read_cap_limits_memory_to_half_of_ram() {
        let gib = 1u64 << 30;
        // 8 GiB of RAM: 4 GiB (4_194_304 KiB) is exactly half, one KiB more is not.
        let at_half = KdfParams::new(4_194_304, 3, 4).unwrap();
        assert!(at_half.check_read_cap(Some(8 * gib)).is_ok());
        assert_eq!(
            at_half.check_read_cap(Some(8 * gib - 2048)),
            Err(CryptoError::InvalidKdfParams)
        );
        // 2 GiB of RAM: 256 MiB is fine, 1 GiB + 1 KiB is not.
        assert!(
            KdfParams::DEFAULT_LARGE
                .check_read_cap(Some(2 * gib))
                .is_ok()
        );
        let big = KdfParams::new(1_048_577, 3, 4).unwrap();
        assert_eq!(
            big.check_read_cap(Some(2 * gib)),
            Err(CryptoError::InvalidKdfParams)
        );
        // Unknown RAM: only the time cap applies.
        assert!(at_half.check_read_cap(None).is_ok());
    }

    #[test]
    fn read_cap_limits_time_to_the_tuning_maximum() {
        let ten = KdfParams::new(65_536, TUNE_MAX_T, 4).unwrap();
        assert!(ten.check_read_cap(None).is_ok());
        let eleven = KdfParams::new(65_536, TUNE_MAX_T + 1, 4).unwrap();
        // Inside the ADR-0013 range, so `new` accepts it, but it is above the cap.
        assert_eq!(
            eleven.check_read_cap(None),
            Err(CryptoError::InvalidKdfParams)
        );
        // The cap runs before Argon2, so this returns at once and does not hash.
        let phrase = SecretString::new("fake phrase".to_owned());
        assert_eq!(
            derive_passphrase_kek(&phrase, &[0; 32], &eleven).err(),
            Some(CryptoError::InvalidKdfParams)
        );
    }

    #[test]
    fn tuning_results_pass_the_read_cap() {
        let tuned = tune_with(Duration::from_millis(700), 2 << 30, model(0.9)).unwrap();
        assert!(tuned.params.check_read_cap(Some(2 << 30)).is_ok());
    }

    #[test]
    fn weaker_than_floor_cannot_derive() {
        // Anything below the floor except the exact test value is refused before Argon2 runs.
        let weak = KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let phrase = SecretString::new("fake phrase".to_owned());
        assert_eq!(
            derive_passphrase_kek(&phrase, &[0; 32], &weak).err(),
            Some(CryptoError::InvalidKdfParams)
        );
    }

    #[test]
    fn nfkc_without_trim() {
        // U+FB01 (ligature "fi") becomes "fi"; U+00C5 composed stays; spaces stay.
        let n = normalize_phrase(" \u{FB01}sh A\u{030A} ");
        assert_eq!(n.expose_secret(), " fish \u{00C5} ");
    }

    #[test]
    fn nfkc_that_grows_the_text() {
        // U+FDFA is one character that NFKC turns into 18 characters.
        let n = normalize_phrase("\u{FDFA}");
        assert_eq!(n.expose_secret().chars().count(), 18);
        assert_eq!(n.expose_secret(), "\u{FDFA}".nfkc().collect::<String>());
    }

    #[test]
    fn normalized_forms_give_the_same_kek() {
        let params = KdfParams::insecure_fast_for_tests();
        let salt = [5u8; 32];
        let composed = SecretString::new("caf\u{00E9} test".to_owned());
        let decomposed = SecretString::new("cafe\u{0301} test".to_owned());
        let a = derive_passphrase_kek(&composed, &salt, &params).unwrap();
        let b = derive_passphrase_kek(&decomposed, &salt, &params).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
        let other = derive_passphrase_kek(&composed, &[6u8; 32], &params).unwrap();
        assert_ne!(a.expose_secret(), other.expose_secret());
    }

    /// Cost model: time = m (MiB) * t * `ms_per_mib_pass` ms.
    fn model(ms_per_mib_pass: f64) -> impl FnMut(&KdfParams) -> Result<Duration, CryptoError> {
        move |p| {
            let mib = f64::from(p.m_cost_kib()) / 1024.0;
            Ok(Duration::from_secs_f64(
                mib * f64::from(p.t_cost()) * ms_per_mib_pass / 1000.0,
            ))
        }
    }

    #[test]
    fn tuning_picks_large_memory_on_big_machines() {
        // 256 MiB pass = 256 * 0.9 ms = 230 ms -> t = 3 gives 0.69 s.
        let tuned = tune_with(Duration::from_millis(700), 16 << 30, model(0.9)).unwrap();
        assert_eq!(tuned.params, KdfParams::new(262_144, 3, 4).unwrap());
        assert!(tuned.measured.as_millis().abs_diff(700) < 50);
    }

    #[test]
    fn tuning_picks_small_memory_below_4_gib() {
        let tuned = tune_with(Duration::from_millis(700), 2 << 30, model(0.9)).unwrap();
        assert_eq!(tuned.params.m_cost_kib(), 65_536);
        // 64 MiB pass = 57.6 ms -> t = 12 wanted, clamped to 10.
        assert_eq!(tuned.params.t_cost(), 10);
    }

    #[test]
    fn tuning_raises_t_on_fast_machines_and_lowers_it_on_slow_ones() {
        let fast = tune_with(Duration::from_millis(700), 16 << 30, model(0.4)).unwrap();
        assert_eq!(fast.params.t_cost(), 7);
        let slow = tune_with(Duration::from_millis(700), 16 << 30, model(2.0)).unwrap();
        assert_eq!(slow.params.t_cost(), 1);
        assert_eq!(slow.params.m_cost_kib(), 262_144);
    }

    #[test]
    fn tuning_halves_memory_on_very_slow_machines() {
        // 256 MiB at t = 1 takes 2.56 s (> 1.5 s): halve to 128 MiB = 1.28 s.
        let tuned = tune_with(Duration::from_millis(700), 16 << 30, model(10.0)).unwrap();
        assert_eq!(tuned.params, KdfParams::new(131_072, 1, 4).unwrap());
        // Extremely slow: stops at the 64 MiB minimum.
        let floor = tune_with(Duration::from_millis(700), 16 << 30, model(100.0)).unwrap();
        assert_eq!(floor.params, KdfParams::new(65_536, 1, 4).unwrap());
    }

    #[test]
    fn tuning_passes_errors_on() {
        let result = tune_with(Duration::from_millis(700), 16 << 30, |_| {
            Err(CryptoError::Kdf)
        });
        assert_eq!(result.err(), Some(CryptoError::Kdf));
    }

    #[test]
    fn pick_t_rounds_up_and_clamps() {
        assert_eq!(pick_t(0.0), 1);
        assert_eq!(pick_t(1.0), 1);
        assert_eq!(pick_t(2.3), 3);
        assert_eq!(pick_t(10.0), 10);
        assert_eq!(pick_t(50.0), 10);
        assert_eq!(pick_t(f64::NAN), 1);
    }

    #[test]
    fn total_ram_is_known_on_linux() {
        if cfg!(target_os = "linux") {
            assert!(total_ram_bytes().is_some_and(|r| r > 256 << 20));
        }
    }
}
