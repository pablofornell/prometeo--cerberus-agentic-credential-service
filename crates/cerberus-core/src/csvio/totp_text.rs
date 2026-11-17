//! TOTP seeds as password managers export them: an `otpauth://` URI or a bare Base32 seed.

use cerberus_crypto::SecretString;

use crate::items::{TotpAlgorithm, TotpSeed};

fn query_value<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

/// A seed from `text`. `None` when the text has no seed at all. A bad algorithm, digit count or
/// period falls back to the usual value, and the item validator then judges the seed.
pub(crate) fn parse_seed(text: &str) -> Option<TotpSeed> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let Some(rest) = text.strip_prefix("otpauth://") else {
        return Some(TotpSeed::standard(SecretString::new(text.to_owned())));
    };
    let query = rest.split_once('?').map_or("", |(_, q)| q);
    let secret = query_value(query, "secret")?;
    let algorithm = match query_value(query, "algorithm").map(str::to_ascii_uppercase) {
        Some(a) if a == "SHA256" => TotpAlgorithm::Sha256,
        Some(a) if a == "SHA512" => TotpAlgorithm::Sha512,
        _ => TotpAlgorithm::Sha1,
    };
    let digits = query_value(query, "digits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let period = query_value(query, "period")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    Some(TotpSeed {
        secret: SecretString::new(secret.to_owned()),
        algorithm,
        digits,
        period,
    })
}

/// The `otpauth://` text of a seed, for the export.
pub(crate) fn seed_uri(seed: &TotpSeed) -> String {
    let algorithm = match seed.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };
    format!(
        "otpauth://totp/Cerberus?secret={}&algorithm={algorithm}&digits={}&period={}",
        seed.secret.expose_secret(),
        seed.digits,
        seed.period
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_text_has_no_seed() {
        assert!(parse_seed("  \t").is_none());
    }

    #[test]
    fn a_bare_text_is_a_standard_seed() {
        let seed = parse_seed(" JBSWY3DP ").unwrap();
        assert_eq!(seed.secret.expose_secret(), "JBSWY3DP");
        assert_eq!(
            (seed.algorithm, seed.digits, seed.period),
            (TotpAlgorithm::Sha1, 6, 30)
        );
    }

    #[test]
    fn a_uri_gives_algorithm_digits_and_period() {
        let seed =
            parse_seed("otpauth://totp/x?Secret=ABC&algorithm=sha512&digits=8&period=60").unwrap();
        assert_eq!(seed.secret.expose_secret(), "ABC");
        assert_eq!(
            (seed.algorithm, seed.digits, seed.period),
            (TotpAlgorithm::Sha512, 8, 60)
        );
        let seed = parse_seed("otpauth://totp/x?secret=ABC&algorithm=SHA256").unwrap();
        assert_eq!(seed.algorithm, TotpAlgorithm::Sha256);
    }

    #[test]
    fn a_uri_with_bad_values_falls_back_to_the_usual_ones() {
        let seed =
            parse_seed("otpauth://totp/x?secret=ABC&algorithm=MD5&digits=x&period=-1").unwrap();
        assert_eq!(
            (seed.algorithm, seed.digits, seed.period),
            (TotpAlgorithm::Sha1, 6, 30)
        );
    }

    #[test]
    fn a_uri_without_a_secret_has_no_seed() {
        assert!(parse_seed("otpauth://totp/x?digits=6").is_none());
        assert!(parse_seed("otpauth://totp/x").is_none());
    }

    #[test]
    fn the_exported_uri_reads_back() {
        let seed = TotpSeed {
            secret: SecretString::new("ABCDEFGH".to_owned()),
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period: 45,
        };
        let back = parse_seed(&seed_uri(&seed)).unwrap();
        assert_eq!(back.secret.expose_secret(), "ABCDEFGH");
        assert_eq!(
            (back.algorithm, back.digits, back.period),
            (TotpAlgorithm::Sha512, 8, 45)
        );
    }
}
