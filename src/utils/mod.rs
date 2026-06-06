// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Miscellaneous utilities shared across the worker.

pub mod origin;
pub mod perf;
pub mod retry;
pub mod ssrf_protection;
pub mod timeout;
pub mod validation;

use std::time::Duration;
use zeroize::Zeroizing;

use crate::error::ApiError;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

/// Generates a cryptographically secure random byte vector of the requested length.
///
/// SECURITY: Returns `Zeroizing<Vec<u8>>` to ensure secret random bytes are
/// scrubbed from memory on drop (ASVS V6.4.2).
///
/// CIV-107: Returns `Result` instead of panicking on RNG failure.
pub fn generate_secure_random(len: usize) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!("Secure random generation failed: {}", e))
    })?;
    Ok(Zeroizing::new(bytes))
}

/// Upper bound for a challenge's TTL in seconds.
pub const MAX_CHALLENGE_TTL: u64 = 300;
/// Lower bound for a challenge's TTL in seconds.
///
/// Cloudflare Workers KV's `.expiration_ttl()` rejects any value below 60s.
/// The expert `/v1/challenge` flow stores a `code:<short>` mapping with this
/// ttl, so a value below 60 makes the KV write fail and the response surfaces
/// as a generic 500 with no useful detail. Match the hosted flow's MIN of 60.
pub const MIN_CHALLENGE_TTL: u64 = 60;
/// Nonce deduplication TTL (5 minutes, aligned with challenge lifetime).
pub const NONCE_DEDUP_TTL: Duration = Duration::from_secs(300);

/// Seconds since the Unix epoch.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn current_timestamp() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (worker::js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Current day expressed as days since the Unix epoch.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
pub fn current_epoch_days() -> u32 {
    (current_timestamp() / 86_400) as u32
}

/// Calculate the exact number of days for a given age in years, accounting for leap years.
///
/// This function uses JavaScript's Date API when running in WebAssembly (Cloudflare Workers)
/// to calculate the precise number of days between today and exactly N years ago. This ensures
/// day-level accuracy for age verification, accounting for the actual leap years that occurred
/// in that specific time period.
///
/// # Arguments
/// * `years` - Age requirement in years (e.g., 13, 16, 18, 21)
///
/// # Returns
/// The exact number of days representing that age as of today
///
/// # Examples
/// ```
/// use provii_verifier::utils::calculate_exact_days_for_years;
///
/// let days = calculate_exact_days_for_years(18);
/// assert!(days > 6500 && days < 6600);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::arithmetic_side_effects
)]
pub fn calculate_exact_days_for_years(years: u32) -> u32 {
    #[cfg(target_arch = "wasm32")]
    {
        use worker::js_sys::Date;

        // Get current date and time
        let now = Date::new_0();
        let now_time_ms = now.get_time();

        // Create a date exactly N years ago
        let years_ago = Date::new_0();
        let current_year = now.get_full_year();
        let target_year = current_year.saturating_sub(years);
        years_ago.set_full_year(target_year);
        let years_ago_time_ms = years_ago.get_time();

        // Calculate exact difference in milliseconds and convert to days
        let diff_ms = now_time_ms - years_ago_time_ms;

        (diff_ms / 86_400_000.0).floor() as u32
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // For testing environments without JavaScript Date API,
        // use approximation: 365.25 days/year (accounts for leap years on average)
        (years as f64 * 365.25).round() as u32
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /* ========================================================================== */
    /*                    current_timestamp() TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_current_timestamp_nonzero() {
        let ts = current_timestamp();
        assert!(ts > 0);
    }

    #[test]
    fn test_current_timestamp_reasonable_range() {
        let ts = current_timestamp();
        // Should be after Jan 1, 2020 (1577836800) and before Jan 1, 2040 (2208988800)
        assert!(ts > 1_577_836_800);
        assert!(ts < 2_208_988_800);
    }

    #[test]
    fn test_current_timestamp_monotonic() {
        let ts1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let ts2 = current_timestamp();
        // Time should move forward
        assert!(ts2 >= ts1);
    }

    #[test]
    fn test_current_timestamp_seconds_precision() {
        let ts = current_timestamp();
        // Should be reasonable Unix timestamp (10 digits for years 2001-2286)
        assert!(ts > 1_000_000_000);
        assert!(ts < 10_000_000_000);
    }

    /* ========================================================================== */
    /*                    current_epoch_days() TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_current_epoch_days_nonzero() {
        let days = current_epoch_days();
        assert!(days > 0);
    }

    #[test]
    fn test_current_epoch_days_reasonable_range() {
        let days = current_epoch_days();
        // Should be after Jan 1, 2020 (18262 days) and before Jan 1, 2040 (25567 days)
        assert!(days > 18_262);
        assert!(days < 25_567);
    }

    #[test]
    fn test_current_epoch_days_derived_from_timestamp() {
        let ts = current_timestamp();
        let days = current_epoch_days();
        let expected_days = (ts / 86_400) as u32;
        // Should match within 1 day (accounting for timing)
        assert!((days as i64 - expected_days as i64).abs() <= 1);
    }

    #[test]
    fn test_current_epoch_days_consistent() {
        let days1 = current_epoch_days();
        let days2 = current_epoch_days();
        // Should be same day (within milliseconds)
        assert!((days1 as i64 - days2 as i64).abs() <= 1);
    }

    /* ========================================================================== */
    /*                    calculate_exact_days_for_years() TESTS                */
    /* ========================================================================== */

    #[test]
    fn test_calculate_exact_days_for_years_18() {
        let days = calculate_exact_days_for_years(18);
        // Should be approximately 18 * 365.25 = 6574.5 days
        // Allow for ±10 days tolerance (accounting for leap year variations)
        assert!(
            (6_564..=6_584).contains(&days),
            "18 years should be ~6574 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_21() {
        let days = calculate_exact_days_for_years(21);
        // Should be approximately 21 * 365.25 = 7670.25 days
        assert!(
            (7_660..=7_680).contains(&days),
            "21 years should be ~7670 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_16() {
        let days = calculate_exact_days_for_years(16);
        // Should be approximately 16 * 365.25 = 5844 days
        assert!(
            (5_834..=5_854).contains(&days),
            "16 years should be ~5844 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_13() {
        let days = calculate_exact_days_for_years(13);
        // Should be approximately 13 * 365.25 = 4748.25 days
        assert!(
            (4_738..=4_758).contains(&days),
            "13 years should be ~4748 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_65() {
        let days = calculate_exact_days_for_years(65);
        // Should be approximately 65 * 365.25 = 23741.25 days
        assert!(
            (23_731..=23_751).contains(&days),
            "65 years should be ~23741 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_deterministic() {
        // Should return same value when called multiple times on same day
        let days1 = calculate_exact_days_for_years(18);
        let days2 = calculate_exact_days_for_years(18);
        assert_eq!(days1, days2, "Should return same value when called twice");
    }

    #[test]
    fn test_calculate_exact_days_for_years_monotonic() {
        // More years should mean more days
        let days_13 = calculate_exact_days_for_years(13);
        let days_18 = calculate_exact_days_for_years(18);
        let days_21 = calculate_exact_days_for_years(21);

        assert!(
            days_13 < days_18,
            "13 years ({}) should be less than 18 years ({})",
            days_13,
            days_18
        );
        assert!(
            days_18 < days_21,
            "18 years ({}) should be less than 21 years ({})",
            days_18,
            days_21
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_reasonable_range() {
        // Test various ages produce reasonable results
        for years in [1, 5, 10, 18, 21, 25, 50, 100] {
            let days = calculate_exact_days_for_years(years);
            let expected_min = (years as f64 * 365.0) as u32;
            let expected_max = (years as f64 * 366.0) as u32;
            assert!(
                days >= expected_min && days <= expected_max,
                "{}  years produced {} days, expected between {} and {}",
                years,
                days,
                expected_min,
                expected_max
            );
        }
    }

    #[test]
    fn test_calculate_exact_days_nonzero() {
        // Even 1 year should be more than 0 days
        let days = calculate_exact_days_for_years(1);
        assert!(
            (365..=366).contains(&days),
            "1 year should be 365 or 366 days, got {}",
            days
        );
    }

    /* ========================================================================== */
    /*                    generate_secure_random() TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_generate_secure_random_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(32)?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_zero_length() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(0)?;
        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_one_byte() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(1)?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_large() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(1024)?;
        assert_eq!(result.len(), 1024);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_not_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        // With 32 bytes of entropy, the probability of all zeros is 2^-256
        let result = generate_secure_random(32)?;
        let is_all_zeros = result.iter().all(|&b| b == 0);
        assert!(!is_all_zeros, "32 random bytes should not all be zero");
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_different_each_call() -> Result<(), Box<dyn std::error::Error>> {
        let r1 = generate_secure_random(32)?;
        let r2 = generate_secure_random(32)?;
        // With 32 bytes of entropy, collision probability is negligible
        assert_ne!(*r1, *r2, "Two independent 32-byte randoms should differ");
        Ok(())
    }

    /* ========================================================================== */
    /*                    CONSTANTS TESTS                                         */
    /* ========================================================================== */

    #[test]
    fn test_max_challenge_ttl() {
        assert_eq!(MAX_CHALLENGE_TTL, 300);
    }

    #[test]
    fn test_min_challenge_ttl() {
        assert_eq!(MIN_CHALLENGE_TTL, 60);
    }

    // Compile-time assertion: MIN < MAX for challenge TTL.
    const _: () = assert!(MIN_CHALLENGE_TTL < MAX_CHALLENGE_TTL);

    #[test]
    fn test_nonce_dedup_ttl() {
        assert_eq!(NONCE_DEDUP_TTL, Duration::from_secs(300));
    }

    /* ========================================================================== */
    /*                    calculate_exact_days_for_years() EDGE TESTS            */
    /* ========================================================================== */

    #[test]
    fn test_calculate_exact_days_for_years_zero() {
        let days = calculate_exact_days_for_years(0);
        assert_eq!(days, 0, "0 years should be 0 days");
    }

    #[test]
    fn test_calculate_exact_days_for_years_large() {
        let days = calculate_exact_days_for_years(200);
        // 200 * 365.25 = 73050
        let expected_min = 200 * 365;
        let expected_max = 200 * 366;
        assert!(
            days >= expected_min && days <= expected_max,
            "200 years should be between {} and {} days, got {}",
            expected_min,
            expected_max,
            days
        );
    }

    /* ========================================================================== */
    /*                    INTEGRATION TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_timestamp_to_days_conversion() {
        // Test that timestamp to days conversion is consistent
        let ts = current_timestamp();
        let days_from_ts = (ts / 86_400) as u32;
        let days_direct = current_epoch_days();

        // Should match within 1 day
        assert!((days_from_ts as i64 - days_direct as i64).abs() <= 1);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    /* ========================================================================== */
    /*                    generate_secure_random() ADDITIONAL TESTS             */
    /* ========================================================================== */

    #[test]
    fn test_generate_secure_random_returns_zeroizing_type() -> Result<(), Box<dyn std::error::Error>>
    {
        let result = generate_secure_random(16)?;
        // Verify the Zeroizing wrapper is accessible via Deref
        let slice: &[u8] = &result;
        assert_eq!(slice.len(), 16);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_64_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(64)?;
        assert_eq!(result.len(), 64);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_256_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(256)?;
        assert_eq!(result.len(), 256);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_entropy_distribution() -> Result<(), Box<dyn std::error::Error>>
    {
        // With 256 bytes, at least two distinct byte values should appear
        let result = generate_secure_random(256)?;
        let first = result.first().copied().unwrap_or(0);
        let has_different = result.iter().any(|&b| b != first);
        assert!(
            has_different,
            "256 random bytes should have more than one distinct value"
        );
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_multiple_calls_independent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let r1 = generate_secure_random(16)?;
        let r2 = generate_secure_random(16)?;
        let r3 = generate_secure_random(16)?;
        // At least two of the three should differ
        let all_same = *r1 == *r2 && *r2 == *r3;
        assert!(
            !all_same,
            "Three independent 16-byte random values should not all be identical"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    calculate_exact_days_for_years() ADDITIONAL            */
    /* ========================================================================== */

    #[test]
    fn test_calculate_exact_days_for_years_2() {
        let days = calculate_exact_days_for_years(2);
        assert!(
            (730..=732).contains(&days),
            "2 years should be ~731 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_4() {
        let days = calculate_exact_days_for_years(4);
        // 4 * 365.25 = 1461
        assert!(
            (1_458..=1_464).contains(&days),
            "4 years should be ~1461 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_5() {
        let days = calculate_exact_days_for_years(5);
        // 5 * 365.25 = 1826.25
        assert!(
            (1_823..=1_830).contains(&days),
            "5 years should be ~1826 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_25() {
        let days = calculate_exact_days_for_years(25);
        // 25 * 365.25 = 9131.25
        assert!(
            (9_121..=9_141).contains(&days),
            "25 years should be ~9131 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_for_years_50() {
        let days = calculate_exact_days_for_years(50);
        // 50 * 365.25 = 18262.5
        assert!(
            (18_250..=18_275).contains(&days),
            "50 years should be ~18263 days, got {}",
            days
        );
    }

    #[test]
    fn test_calculate_exact_days_difference_between_ages() {
        let days_18 = calculate_exact_days_for_years(18);
        let days_21 = calculate_exact_days_for_years(21);
        // The difference should be approximately 3 * 365.25 = 1095.75 days
        let diff = days_21 - days_18;
        assert!(
            (1_090..=1_100).contains(&diff),
            "Difference between 21 and 18 years should be ~1096 days, got {}",
            diff
        );
    }

    /* ========================================================================== */
    /*                    CONSTANTS ADDITIONAL TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_nonce_dedup_ttl_matches_max_challenge() {
        // NONCE_DEDUP_TTL should be aligned with MAX_CHALLENGE_TTL (both 300s)
        assert_eq!(NONCE_DEDUP_TTL.as_secs(), MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_min_challenge_ttl_at_least_60() {
        // KV expiration_ttl minimum is 60s
        assert!(MIN_CHALLENGE_TTL >= 60);
    }

    #[test]
    fn test_max_challenge_ttl_no_greater_than_600() {
        // Reasonable upper bound for a challenge lifetime
        assert!(MAX_CHALLENGE_TTL <= 600);
    }

    /* ========================================================================== */
    /*                    current_timestamp() ADDITIONAL TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_current_timestamp_not_future() {
        let ts = current_timestamp();
        // Should not be more than a few seconds in the future from "now"
        // (accounting for test execution time)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert!(
            ts <= now + 2,
            "Timestamp {} should not be far in the future of {}",
            ts,
            now
        );
    }

    #[test]
    fn test_current_epoch_days_u32_range() {
        let days = current_epoch_days();
        // Verify it fits comfortably in u32 (max ~11.7 million years)
        assert!(days < u32::MAX);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: current_timestamp increases over time
        #[test]
        fn prop_timestamp_monotonic(_seed in any::<u8>()) {
            let ts1 = current_timestamp();
            std::thread::sleep(std::time::Duration::from_millis(1));
            let ts2 = current_timestamp();
            prop_assert!(ts2 >= ts1);
        }

        /// Property: current_epoch_days equals timestamp / 86400
        #[test]
        fn prop_epoch_days_matches_timestamp(_seed in any::<u8>()) {
            let ts = current_timestamp();
            let days = current_epoch_days();
            let expected_days = (ts / 86_400) as u32;
            // Allow 1 day tolerance for timing
            prop_assert!((days as i64 - expected_days as i64).abs() <= 1);
        }

        /// Property: calculate_exact_days_for_years is deterministic
        #[test]
        fn prop_exact_days_deterministic(years in 1u32..150) {
            let days1 = calculate_exact_days_for_years(years);
            let days2 = calculate_exact_days_for_years(years);
            prop_assert_eq!(days1, days2);
        }

        /// Property: More years means more days (monotonic)
        #[test]
        fn prop_exact_days_monotonic(years1 in 1u32..100, years2 in 1u32..100) {
            prop_assume!(years1 < years2);
            let days1 = calculate_exact_days_for_years(years1);
            let days2 = calculate_exact_days_for_years(years2);
            prop_assert!(days1 < days2,
                "Expected {} years ({} days) < {} years ({} days)",
                years1, days1, years2, days2);
        }

        /// Property: Days are within reasonable bounds for years
        #[test]
        fn prop_exact_days_reasonable(years in 1u32..150) {
            let days = calculate_exact_days_for_years(years);
            let min_expected = years * 365;
            let max_expected = years * 366;
            prop_assert!(days >= min_expected && days <= max_expected,
                "{} years produced {} days, expected between {} and {}",
                years, days, min_expected, max_expected);
        }

        /// Property: Nonzero years produces nonzero days
        #[test]
        fn prop_exact_days_nonzero(years in 1u32..150) {
            let days = calculate_exact_days_for_years(years);
            prop_assert!(days > 0);
        }

        /// Property: generate_secure_random produces correct length
        #[test]
        fn prop_secure_random_correct_length(len in 0usize..512) {
            let result = generate_secure_random(len);
            match result {
                Ok(bytes) => prop_assert_eq!(bytes.len(), len),
                Err(_) => prop_assert!(false, "generate_secure_random should not fail"),
            }
        }
    }
}
