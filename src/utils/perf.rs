// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Performance monitoring utilities for Cloudflare Workers.
#![forbid(unsafe_code)]

/// Returns current time in milliseconds since epoch.
/// Uses `js_sys::Date::now()` on WASM targets and `std::time` on native targets.
pub(crate) fn now_millis() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as f64
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
mod tests {
    use super::*;

    #[test]
    fn test_now_millis_positive() {
        let ms = now_millis();
        assert!(ms > 0.0);
    }

    #[test]
    fn test_now_millis_reasonable_range() {
        let ms = now_millis();
        // After 2020-01-01 in ms: ~1577836800000
        assert!(ms > 1_577_836_800_000.0);
        // Before 2040-01-01 in ms: ~2208988800000
        assert!(ms < 2_208_988_800_000.0);
    }

    #[test]
    fn test_now_millis_monotonic() {
        let ms1 = now_millis();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let ms2 = now_millis();
        assert!(ms2 >= ms1);
    }

    #[test]
    fn test_now_millis_precision_milliseconds() {
        // The value should be in the billions (milliseconds since epoch)
        let ms = now_millis();
        assert!(
            ms > 1_000_000_000_000.0,
            "Expected millisecond precision, got {}",
            ms
        );
    }
}
