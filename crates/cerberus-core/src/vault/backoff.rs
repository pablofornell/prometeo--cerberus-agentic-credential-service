//! Unlock back-off (ADR-0026, ADR-0030). The counter is in the header, so a restart keeps it.

use cerberus_store::HeaderRow;
use jiff::Timestamp;

use crate::error::CoreError;

/// Failures in a row that need no wait.
pub const FREE_UNLOCK_FAILURES: u32 = 5;
/// The longest wait, in seconds.
pub const MAX_UNLOCK_WAIT_SECONDS: u64 = 900;

/// Wait in seconds after `failures` failed unlocks in a row: `min(2^(n-5), 900)` from the 5th on.
#[must_use]
pub fn unlock_wait_seconds(failures: u32) -> u64 {
    if failures < FREE_UNLOCK_FAILURES {
        return 0;
    }
    let exponent = (failures - FREE_UNLOCK_FAILURES).min(10);
    (1u64 << exponent).min(MAX_UNLOCK_WAIT_SECONDS)
}

/// Seconds until the next unlock try is allowed, or 0.
#[must_use]
pub fn seconds_until_retry(header: &HeaderRow, now: Timestamp) -> u32 {
    let wait_ms = unlock_wait_seconds(header.failed_unlocks).saturating_mul(1000);
    let Some(last) = header.last_failed_unlock_at else {
        return 0;
    };
    let until = last
        .as_millisecond()
        .saturating_add(i64::try_from(wait_ms).unwrap_or(i64::MAX));
    let left_ms = until.saturating_sub(now.as_millisecond());
    if left_ms <= 0 {
        return 0;
    }
    // Round up, so the UI never shows 0 while the try is still refused.
    let seconds = left_ms.saturating_add(999) / 1000;
    u32::try_from(seconds).unwrap_or(u32::MAX)
}

/// Refuses an unlock try during the back-off.
///
/// # Errors
/// [`CoreError::UnlockBackoff`] with the seconds left.
pub(crate) fn check(header: &HeaderRow, now: Timestamp) -> Result<(), CoreError> {
    match seconds_until_retry(header, now) {
        0 => Ok(()),
        retry_after_seconds => Err(CoreError::UnlockBackoff {
            retry_after_seconds,
        }),
    }
}

#[cfg(test)]
mod tests {
    use cerberus_types::{VaultId, t0};
    use jiff::SignedDuration;

    use super::*;

    #[test]
    fn wait_grows_and_stops_at_900() {
        let waits: Vec<u64> = (0..=16).map(unlock_wait_seconds).collect();
        assert_eq!(
            waits,
            [
                0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 900, 900
            ]
        );
        assert_eq!(unlock_wait_seconds(u32::MAX), 900);
    }

    #[test]
    fn retry_counts_from_the_last_failure() {
        let mut header = HeaderRow {
            format_version: 1,
            vault_id: VaultId([1; 16]),
            created_at: t0(),
            failed_unlocks: 7,
            last_failed_unlock_at: Some(t0()),
            header_mac: [0; 32],
        };
        assert_eq!(seconds_until_retry(&header, t0()), 4);
        let later = t0() + SignedDuration::from_millis(3_500);
        assert_eq!(seconds_until_retry(&header, later), 1);
        assert_eq!(
            seconds_until_retry(&header, t0() + SignedDuration::from_secs(4)),
            0
        );
        header.failed_unlocks = 4;
        assert_eq!(seconds_until_retry(&header, t0()), 0);
        assert!(check(&header, t0()).is_ok());
        header.failed_unlocks = 5;
        assert!(matches!(
            check(&header, t0()),
            Err(CoreError::UnlockBackoff {
                retry_after_seconds: 1
            })
        ));
    }
}
