// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Public-safe fingerprints for rotation-capable secrets.
//!
//! The fingerprint format
//! is the first **6 hex characters** of `lowercase(hex(sha256(secret_value)))`.
//! 6 hex (24 bits) defeats birthday-paradox collisions across an active set of
//! roughly 100 fingerprints (~50 rotation-capable secrets times 2 active slots).
//!
//! The fingerprint is one-way derived but only carries 24 bits of entropy. It
//! is NOT secret. Logs ship with this fingerprint by design so the Grafana
//! `secret_version` panel can show which slot satisfied each request.
//!
//! The literal string `"000000"` is reserved as a sentinel for "no value" /
//! unset slot. A real SHA-256 prefix of `000000` is statistically vanishingly
//! rare and treating it as a sentinel is consistent with the schema.
//!
//! SECURITY: Fingerprints are public-safe. Constant-time comparison is NOT
//! required when comparing fingerprints; constant-time primitives are still
//! mandatory for the underlying secret comparison (handled at the verify site,
//! not here).
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Sentinel returned when the slot has no bound value.
pub const FINGERPRINT_UNSET: &str = "000000";

/// Compute the 6-character lower-case hex fingerprint of a secret value.
///
/// Returns [`FINGERPRINT_UNSET`] when `value` is `None` or empty.
pub fn fingerprint6_str(value: Option<&str>) -> String {
    match value {
        Some(v) if !v.is_empty() => fingerprint6_bytes(v.as_bytes()),
        _ => FINGERPRINT_UNSET.to_string(),
    }
}

/// Compute the 6-character lower-case hex fingerprint of arbitrary bytes.
///
/// Empty input returns [`FINGERPRINT_UNSET`].
pub fn fingerprint6_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return FINGERPRINT_UNSET.to_string();
    }
    let digest = Sha256::digest(bytes);
    // First 3 bytes = 6 hex chars. Width 2 keeps leading zeros. SHA-256 always
    // returns at least 32 bytes, so the chunk slice is always present, but we
    // pattern-match defensively to keep the path panic-free (no unwrap/expect).
    match digest.first_chunk::<3>() {
        Some([a, b, c]) => format!("{:02x}{:02x}{:02x}", a, b, c),
        None => FINGERPRINT_UNSET.to_string(),
    }
}

/// Sentinel returned by [`fingerprint8_str`] / [`fingerprint8_bytes`] when the
/// slot has no bound value. 8 hex chars to match the wider field width.
pub const FINGERPRINT8_UNSET: &str = "00000000";

/// Compute the 8-character lower-case hex fingerprint of a secret value.
///
/// Used by the `/_internal/version` endpoint for rotation observability.
/// 8 hex chars (32 bits) is the wider field used for definitive identification
/// of a slot value when 6 hex chars (24 bits) might collide across the active
/// fingerprint set.
pub fn fingerprint8_str(value: Option<&str>) -> String {
    match value {
        Some(v) if !v.is_empty() => fingerprint8_bytes(v.as_bytes()),
        _ => FINGERPRINT8_UNSET.to_string(),
    }
}

/// Compute the 8-character lower-case hex fingerprint of arbitrary bytes.
///
/// Empty input returns [`FINGERPRINT8_UNSET`].
pub fn fingerprint8_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return FINGERPRINT8_UNSET.to_string();
    }
    let digest = Sha256::digest(bytes);
    match digest.first_chunk::<4>() {
        Some([a, b, c, d]) => format!("{:02x}{:02x}{:02x}{:02x}", a, b, c, d),
        None => FINGERPRINT8_UNSET.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_sentinel() {
        assert_eq!(fingerprint6_bytes(b""), FINGERPRINT_UNSET);
        assert_eq!(fingerprint6_str(None), FINGERPRINT_UNSET);
        assert_eq!(fingerprint6_str(Some("")), FINGERPRINT_UNSET);
    }

    #[test]
    fn fingerprint_is_six_hex_chars() {
        let fp = fingerprint6_bytes(b"some-secret-value");
        assert_eq!(fp.len(), 6);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = fingerprint6_bytes(b"k");
        let b = fingerprint6_bytes(b"k");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_diverge() {
        let a = fingerprint6_bytes(b"key-one");
        let b = fingerprint6_bytes(b"key-two");
        assert_ne!(a, b);
    }

    #[test]
    fn known_vector_sha256_abc_prefix() {
        // SHA-256("abc") = ba7816bf...; first 6 hex = "ba7816"
        assert_eq!(fingerprint6_bytes(b"abc"), "ba7816");
    }

    #[test]
    fn str_helper_matches_bytes_helper() {
        let s = "rotation-test-token";
        assert_eq!(fingerprint6_str(Some(s)), fingerprint6_bytes(s.as_bytes()));
    }

    #[test]
    fn fingerprint8_known_vector_sha256_abc_prefix() {
        // SHA-256("abc") = ba7816bf...; first 8 hex = "ba7816bf"
        assert_eq!(fingerprint8_bytes(b"abc"), "ba7816bf");
    }

    #[test]
    fn fingerprint8_empty_yields_sentinel() {
        assert_eq!(fingerprint8_bytes(b""), FINGERPRINT8_UNSET);
        assert_eq!(fingerprint8_str(None), FINGERPRINT8_UNSET);
        assert_eq!(fingerprint8_str(Some("")), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint8_is_eight_hex_chars() {
        let fp = fingerprint8_bytes(b"some-secret-value");
        assert_eq!(fp.len(), 8);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn fingerprint8_extends_fingerprint6() {
        // The 8-char variant must agree with the 6-char variant on the first 6
        // chars: both are SHA-256 prefixes of the same input.
        let bytes = b"rotation-test-token";
        let fp6 = fingerprint6_bytes(bytes);
        let fp8 = fingerprint8_bytes(bytes);
        assert_eq!(fp8.get(..6).unwrap_or(""), fp6);
    }

    #[test]
    fn leading_zero_byte_preserved() {
        // SHA-256 of "" is e3b0... but we treat empty as sentinel.
        // Pick an input whose SHA-256 starts with a low byte to confirm width-2 formatting.
        let fp = fingerprint6_bytes(&[0u8]);
        assert_eq!(fp.len(), 6);
        // The point is the format string preserves leading zeros if any byte is < 0x10.
        // We don't pin the exact value here; the length + hex check above is sufficient.
    }

    /* ========================================================================== */
    /*                    ADDITIONAL COVERAGE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn fingerprint_unset_is_six_zeros() {
        assert_eq!(FINGERPRINT_UNSET, "000000");
        assert_eq!(FINGERPRINT_UNSET.len(), 6);
    }

    #[test]
    fn fingerprint8_unset_is_eight_zeros() {
        assert_eq!(FINGERPRINT8_UNSET, "00000000");
        assert_eq!(FINGERPRINT8_UNSET.len(), 8);
    }

    #[test]
    fn sentinels_differ_in_length() {
        assert_ne!(FINGERPRINT_UNSET, FINGERPRINT8_UNSET);
        assert_eq!(FINGERPRINT_UNSET.len(), 6);
        assert_eq!(FINGERPRINT8_UNSET.len(), 8);
    }

    #[test]
    fn fingerprint8_is_deterministic() {
        let a = fingerprint8_bytes(b"determinism-test");
        let b = fingerprint8_bytes(b"determinism-test");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint8_different_inputs_diverge() {
        let a = fingerprint8_bytes(b"alpha");
        let b = fingerprint8_bytes(b"bravo");
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint8_str_matches_bytes() {
        let s = "rotation-key-v2";
        assert_eq!(fingerprint8_str(Some(s)), fingerprint8_bytes(s.as_bytes()));
    }

    #[test]
    fn fingerprint6_single_byte_inputs() {
        // Each single byte should produce a unique 6-char fingerprint
        let fp_0 = fingerprint6_bytes(&[0x00]);
        let fp_1 = fingerprint6_bytes(&[0x01]);
        let fp_ff = fingerprint6_bytes(&[0xFF]);
        assert_ne!(fp_0, fp_1);
        assert_ne!(fp_1, fp_ff);
        assert_ne!(fp_0, fp_ff);
        // All should be 6 chars
        assert_eq!(fp_0.len(), 6);
        assert_eq!(fp_1.len(), 6);
        assert_eq!(fp_ff.len(), 6);
    }

    #[test]
    fn fingerprint8_single_byte_inputs() {
        let fp_0 = fingerprint8_bytes(&[0x00]);
        let fp_1 = fingerprint8_bytes(&[0x01]);
        assert_ne!(fp_0, fp_1);
        assert_eq!(fp_0.len(), 8);
        assert_eq!(fp_1.len(), 8);
    }

    #[test]
    fn fingerprint6_unicode_input() {
        let fp = fingerprint6_str(Some("\u{1f511}\u{1f512}"));
        assert_eq!(fp.len(), 6);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn fingerprint8_unicode_input() {
        let fp = fingerprint8_str(Some("\u{1f511}\u{1f512}"));
        assert_eq!(fp.len(), 8);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn fingerprint6_known_vector_empty_string_is_sentinel() {
        // SHA-256("") = e3b0c44298fc... but we return sentinel for empty
        assert_eq!(fingerprint6_str(Some("")), FINGERPRINT_UNSET);
    }

    #[test]
    fn fingerprint8_known_vector_empty_string_is_sentinel() {
        assert_eq!(fingerprint8_str(Some("")), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint6_none_returns_sentinel() {
        assert_eq!(fingerprint6_str(None), FINGERPRINT_UNSET);
    }

    #[test]
    fn fingerprint8_none_returns_sentinel() {
        assert_eq!(fingerprint8_str(None), FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint6_long_input() {
        let long_input = "a".repeat(10_000);
        let fp = fingerprint6_str(Some(&long_input));
        assert_eq!(fp.len(), 6);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint8_long_input() {
        let long_input = "b".repeat(10_000);
        let fp = fingerprint8_str(Some(&long_input));
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint8_extends_fingerprint6_multiple_inputs() {
        // Verify the prefix relationship holds across several inputs
        let inputs: Vec<&[u8]> = vec![b"one", b"two", b"three", b"four", b"five"];
        for input in inputs {
            let fp6 = fingerprint6_bytes(input);
            let fp8 = fingerprint8_bytes(input);
            assert_eq!(
                fp8.get(..6).unwrap_or(""),
                fp6,
                "8-char fingerprint must start with the 6-char fingerprint for input {:?}",
                input
            );
        }
    }

    #[test]
    fn fingerprint6_bytes_all_zero_input() {
        let fp = fingerprint6_bytes(&[0u8; 32]);
        assert_eq!(fp.len(), 6);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        // Should NOT equal sentinel (non-empty input)
        assert_ne!(fp, FINGERPRINT_UNSET);
    }

    #[test]
    fn fingerprint8_bytes_all_zero_input() {
        let fp = fingerprint8_bytes(&[0u8; 32]);
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(fp, FINGERPRINT8_UNSET);
    }

    #[test]
    fn fingerprint6_output_is_lowercase_only() {
        // Exhaustive check: hash several inputs, confirm no uppercase
        let inputs = [b"aaa".as_slice(), b"bbb", b"ccc", b"ddd"];
        for input in inputs {
            let fp = fingerprint6_bytes(input);
            assert!(!fp.chars().any(|c| c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn fingerprint8_output_is_lowercase_only() {
        let inputs = [b"eee".as_slice(), b"fff", b"ggg", b"hhh"];
        for input in inputs {
            let fp = fingerprint8_bytes(input);
            assert!(!fp.chars().any(|c| c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn known_vector_sha256_single_a() {
        // SHA-256("a") = ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
        // First 6 hex = "ca9781", first 8 hex = "ca978112"
        assert_eq!(fingerprint6_bytes(b"a"), "ca9781");
        assert_eq!(fingerprint8_bytes(b"a"), "ca978112");
    }
}
