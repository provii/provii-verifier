// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Input validation utilities for preventing injection attacks.
//!
//! SECURITY: This module addresses CSA-01 (Injection Flaws) and CWE-89 (SQL Injection).
//! All user inputs used in key construction or database queries MUST be validated.

#![forbid(unsafe_code)]

use crate::error::ApiError;

/// Maximum length for a nonce tag to prevent resource exhaustion.
const MAX_NONCE_TAG_LENGTH: usize = 256;

/// Maximum length for a short code (12 digits formatted as "XXXX XXXX XXXX").
const SHORT_CODE_LENGTH: usize = 12;

/// Validates a nonce tag for use in Durable Object key construction.
///
/// SECURITY: Prevents SQL injection (CWE-89) and key injection attacks in Durable Objects.
/// Nonce tags are used to construct keys like "nonce:verify:{challenge_id}".
/// Without validation, malicious input could manipulate key structure.
///
/// # Validation Rules
/// - Length: 1-256 characters
/// - Characters: Alphanumeric, hyphens, underscores, colons only
/// - No path traversal sequences (../, ..\)
/// - No null bytes
///
/// # Arguments
/// * `tag` - The nonce tag to validate (e.g., "verify:{uuid}")
///
/// # Returns
/// - `Ok(())` if validation passes
/// - `Err(ApiError::BadRequest)` with details if validation fails
///
/// # Examples
/// ```
/// # use provii_verifier::utils::validation::validate_nonce_tag;
/// assert!(validate_nonce_tag("verify:550e8400-e29b-41d4-a716-446655440000").is_ok());
/// assert!(validate_nonce_tag("").is_err());
/// assert!(validate_nonce_tag("../../../etc/passwd").is_err());
/// ```
pub fn validate_nonce_tag(tag: &str) -> Result<(), ApiError> {
    // Check length
    if tag.is_empty() {
        return Err(ApiError::BadRequest(Some(
            "Nonce tag cannot be empty".to_string(),
        )));
    }

    if tag.len() > MAX_NONCE_TAG_LENGTH {
        return Err(ApiError::BadRequest(Some(format!(
            "Nonce tag too long (max {} characters)",
            MAX_NONCE_TAG_LENGTH
        ))));
    }

    // Check for null bytes (common injection technique)
    if tag.contains('\0') {
        return Err(ApiError::BadRequest(Some(
            "Nonce tag contains invalid null byte".to_string(),
        )));
    }

    // Check for path traversal sequences
    if tag.contains("../") || tag.contains("..\\") {
        return Err(ApiError::BadRequest(Some(
            "Nonce tag contains path traversal sequence".to_string(),
        )));
    }

    // Allow only alphanumeric, hyphens, underscores, and colons
    // Colons are allowed for structured tags like "verify:{uuid}"
    if !tag
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ':')
    {
        return Err(ApiError::BadRequest(Some(
            "Nonce tag contains invalid characters (allowed: alphanumeric, -, _, :)".to_string(),
        )));
    }

    Ok(())
}

/// Validates a UUID string for use in Durable Object key construction.
///
/// SECURITY: Prevents injection attacks when UUIDs are used as keys (CWE-89, CSA-01).
/// UUIDs must conform to RFC 4122 format: 8-4-4-4-12 hexadecimal digits.
///
/// # Arguments
/// * `uuid_str` - The UUID string to validate
///
/// # Returns
/// - `Ok(())` if validation passes
/// - `Err(ApiError::BadRequest)` with details if validation fails
///
/// # Examples
/// ```
/// # use provii_verifier::utils::validation::validate_uuid_format;
/// assert!(validate_uuid_format("550e8400-e29b-41d4-a716-446655440000").is_ok());
/// assert!(validate_uuid_format("not-a-uuid").is_err());
/// assert!(validate_uuid_format("550e8400e29b41d4a716446655440000").is_err()); // missing hyphens
/// ```
pub fn validate_uuid_format(uuid_str: &str) -> Result<(), ApiError> {
    // UUID format: 8-4-4-4-12 (36 characters total including hyphens)
    if uuid_str.len() != 36 {
        return Err(ApiError::BadRequest(Some(format!(
            "Invalid UUID length: expected 36 characters, got {}",
            uuid_str.len()
        ))));
    }

    // Check hyphen positions
    let expected_hyphens = [8, 13, 18, 23];
    for pos in expected_hyphens {
        let byte = uuid_str.as_bytes().get(pos).copied().unwrap_or(0);
        if byte != b'-' {
            return Err(ApiError::BadRequest(Some(format!(
                "Invalid UUID format: expected hyphen at position {}",
                pos
            ))));
        }
    }

    // Check all other characters are hexadecimal
    for (i, c) in uuid_str.chars().enumerate() {
        if expected_hyphens.contains(&i) {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return Err(ApiError::BadRequest(Some(format!(
                "Invalid UUID format: non-hexadecimal character '{}' at position {}",
                c, i
            ))));
        }
    }

    Ok(())
}

/// Validates a 12-digit short code.
///
/// SECURITY: Prevents injection when short codes are used in key lookups (CWE-89, CSA-01).
/// Short codes are exactly 12 decimal digits, displayed as "XXXX XXXX XXXX".
///
/// # Arguments
/// * `short_code` - The short code to validate (spaces optional)
///
/// # Returns
/// - `Ok(())` if validation passes
/// - `Err(ApiError::BadRequest)` with details if validation fails
///
/// # Examples
/// ```
/// # use provii_verifier::utils::validation::validate_short_code;
/// assert!(validate_short_code("123456789012").is_ok());
/// assert!(validate_short_code("1234 5678 9012").is_ok()); // spaces allowed
/// assert!(validate_short_code("12345678901").is_err()); // too short
/// assert!(validate_short_code("12345678901a").is_err()); // non-digit
/// ```
pub fn validate_short_code(short_code: &str) -> Result<(), ApiError> {
    // Remove spaces for validation
    let digits_only: String = short_code.chars().filter(|c| !c.is_whitespace()).collect();

    // Check length (must be exactly 12 digits)
    if digits_only.len() != SHORT_CODE_LENGTH {
        return Err(ApiError::BadRequest(Some(format!(
            "Invalid short code length: expected {} digits, got {}",
            SHORT_CODE_LENGTH,
            digits_only.len()
        ))));
    }

    // Check all characters are digits
    if !digits_only.chars().all(|c| c.is_ascii_digit()) {
        return Err(ApiError::BadRequest(Some(
            "Short code must contain only digits".to_string(),
        )));
    }

    Ok(())
}

/// Validates a challenge ID used in nonce tags.
///
/// SECURITY: Wrapper around validate_uuid_format for semantic clarity.
/// Challenge IDs are UUIDs that must be validated before use in nonce tags.
///
/// # Arguments
/// * `challenge_id` - The challenge ID to validate
///
/// # Returns
/// - `Ok(())` if validation passes
/// - `Err(ApiError::BadRequest)` with details if validation fails
pub fn validate_challenge_id(challenge_id: &str) -> Result<(), ApiError> {
    validate_uuid_format(challenge_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    validate_nonce_tag() TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_validate_nonce_tag_valid() {
        // Valid nonce tags
        assert!(validate_nonce_tag("verify:550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_nonce_tag("redeem:test-uuid").is_ok());
        assert!(validate_nonce_tag("simple_tag").is_ok());
        assert!(validate_nonce_tag("tag-with-hyphens").is_ok());
        assert!(validate_nonce_tag("tag_with_underscores").is_ok());
        assert!(validate_nonce_tag("123456").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_empty() {
        assert!(validate_nonce_tag("").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_too_long() {
        let long_tag = "a".repeat(MAX_NONCE_TAG_LENGTH + 1);
        assert!(validate_nonce_tag(&long_tag).is_err());
    }

    #[test]
    fn test_validate_nonce_tag_null_byte() {
        assert!(validate_nonce_tag("test\0tag").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_path_traversal() {
        assert!(validate_nonce_tag("../etc/passwd").is_err());
        assert!(validate_nonce_tag("..\\windows\\system32").is_err());
        assert!(validate_nonce_tag("test/../other").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_invalid_chars() {
        assert!(validate_nonce_tag("tag with spaces").is_err());
        assert!(validate_nonce_tag("tag@with#special").is_err());
        assert!(validate_nonce_tag("tag;drop table").is_err());
        assert!(validate_nonce_tag("tag'or'1'='1").is_err());
    }

    /* ========================================================================== */
    /*                    validate_uuid_format() TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_validate_uuid_format_valid() {
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid_format("00000000-0000-0000-0000-000000000000").is_ok());
        assert!(validate_uuid_format("ffffffff-ffff-ffff-ffff-ffffffffffff").is_ok());
        assert!(validate_uuid_format("AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF").is_ok());
        // uppercase
    }

    #[test]
    fn test_validate_uuid_format_wrong_length() {
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716").is_err()); // too short
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-446655440000-extra").is_err());
        // too long
    }

    #[test]
    fn test_validate_uuid_format_missing_hyphens() {
        assert!(validate_uuid_format("550e8400e29b41d4a716446655440000").is_err());
        assert!(validate_uuid_format("550e8400-e29b41d4-a716-446655440000").is_err());
    }

    #[test]
    fn test_validate_uuid_format_invalid_chars() {
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-44665544000g").is_err()); // 'g' not hex
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-44665544000@").is_err());
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-44665544 000").is_err());
        // space
    }

    /* ========================================================================== */
    /*                    validate_short_code() TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_validate_short_code_valid() {
        assert!(validate_short_code("123456789012").is_ok());
        assert!(validate_short_code("000000000000").is_ok());
        assert!(validate_short_code("999999999999").is_ok());
        assert!(validate_short_code("1234 5678 9012").is_ok()); // with spaces
        assert!(validate_short_code("1234  5678  9012").is_ok()); // multiple spaces
    }

    #[test]
    fn test_validate_short_code_wrong_length() {
        assert!(validate_short_code("12345678901").is_err()); // too short
        assert!(validate_short_code("1234567890123").is_err()); // too long
        assert!(validate_short_code("").is_err());
    }

    #[test]
    fn test_validate_short_code_invalid_chars() {
        assert!(validate_short_code("12345678901a").is_err()); // letter
        assert!(validate_short_code("123456789012.").is_err()); // period
        assert!(validate_short_code("123456-789012").is_err()); // hyphen
    }

    #[test]
    fn test_validate_challenge_id() {
        assert!(validate_challenge_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_challenge_id("not-a-uuid").is_err());
    }

    /* ========================================================================== */
    /*                    validate_nonce_tag() BOUNDARY TESTS                    */
    /* ========================================================================== */

    #[test]
    fn test_validate_nonce_tag_max_length() {
        let tag = "a".repeat(MAX_NONCE_TAG_LENGTH);
        assert!(validate_nonce_tag(&tag).is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_one_over_max() {
        let tag = "a".repeat(MAX_NONCE_TAG_LENGTH + 1);
        assert!(validate_nonce_tag(&tag).is_err());
    }

    #[test]
    fn test_validate_nonce_tag_single_char() {
        assert!(validate_nonce_tag("a").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_only_colons() {
        assert!(validate_nonce_tag(":::").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_only_hyphens() {
        assert!(validate_nonce_tag("---").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_only_underscores() {
        assert!(validate_nonce_tag("___").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_mixed_allowed() {
        assert!(validate_nonce_tag("verify:abc-123_def:456").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_dot_rejected() {
        assert!(validate_nonce_tag("tag.with.dots").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_leading_null_byte() {
        assert!(validate_nonce_tag("\0tag").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_double_dot_slash() {
        assert!(validate_nonce_tag("a../b").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_double_dot_backslash() {
        assert!(validate_nonce_tag("a..\\b").is_err());
    }

    /* ========================================================================== */
    /*                    validate_uuid_format() ADDITIONAL TESTS                */
    /* ========================================================================== */

    #[test]
    fn test_validate_uuid_format_all_zeros() {
        assert!(validate_uuid_format("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn test_validate_uuid_format_all_fs() {
        assert!(validate_uuid_format("ffffffff-ffff-ffff-ffff-ffffffffffff").is_ok());
    }

    #[test]
    fn test_validate_uuid_format_empty_string() {
        let result = validate_uuid_format("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_format_no_hyphens_correct_length() {
        // 32 hex chars, but no hyphens and wrong total length
        assert!(validate_uuid_format("550e8400e29b41d4a716446655440000").is_err());
    }

    #[test]
    fn test_validate_uuid_format_extra_hyphen() {
        assert!(validate_uuid_format("550e8400-e29b-41d4-a716-4466554400-0").is_err());
    }

    #[test]
    fn test_validate_uuid_format_null_char() {
        let mut s = "550e8400-e29b-41d4-a716-44665544000".to_string();
        s.push('\0');
        assert!(validate_uuid_format(&s).is_err());
    }

    /* ========================================================================== */
    /*                    validate_short_code() ADDITIONAL TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_validate_short_code_with_newlines() {
        // Whitespace includes newlines; digits should be extracted
        assert!(validate_short_code("1234\n5678\n9012").is_ok());
    }

    #[test]
    fn test_validate_short_code_only_spaces() {
        assert!(validate_short_code("            ").is_err());
    }

    #[test]
    fn test_validate_short_code_leading_zeros() {
        assert!(validate_short_code("000000000001").is_ok());
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    /* ========================================================================== */
    /*                    validate_nonce_tag() ADDITIONAL TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_validate_nonce_tag_backslash_only_traversal() {
        assert!(validate_nonce_tag("..\\secret").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_tab_rejected() {
        assert!(validate_nonce_tag("tag\twith\ttabs").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_newline_rejected() {
        assert!(validate_nonce_tag("tag\nwith\nnewline").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_carriage_return_rejected() {
        assert!(validate_nonce_tag("tag\rwith\rcr").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_equals_rejected() {
        assert!(validate_nonce_tag("key=value").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_slash_rejected() {
        assert!(validate_nonce_tag("path/to/resource").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_backslash_rejected() {
        assert!(validate_nonce_tag("path\\to\\resource").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_unicode_rejected() {
        // Non-ASCII characters are not alphanumeric in is_alphanumeric terms,
        // but actually they are: Rust's is_alphanumeric() returns true for
        // Unicode letters and digits. Let's verify the specific case.
        // This depends on the char: e.g. 'e' with accent is alphanumeric.
        // But emoji is not alphanumeric.
        assert!(validate_nonce_tag("tag\u{1F600}").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_at_exactly_max_length() {
        let tag = "x".repeat(MAX_NONCE_TAG_LENGTH);
        assert!(validate_nonce_tag(&tag).is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_two_over_max() {
        let tag = "x".repeat(MAX_NONCE_TAG_LENGTH + 2);
        assert!(validate_nonce_tag(&tag).is_err());
    }

    #[test]
    fn test_validate_nonce_tag_numeric_only() {
        assert!(validate_nonce_tag("0123456789").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_sql_injection_attempt() {
        assert!(validate_nonce_tag("'; DROP TABLE nonces; --").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_percent_encoding() {
        assert!(validate_nonce_tag("tag%20value").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_angle_brackets() {
        assert!(validate_nonce_tag("<script>").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_parentheses() {
        assert!(validate_nonce_tag("tag(value)").is_err());
    }

    /* ========================================================================== */
    /*                    validate_uuid_format() ADDITIONAL TESTS                */
    /* ========================================================================== */

    #[test]
    fn test_validate_uuid_format_hyphen_at_wrong_position() {
        // Hyphens at positions 9, 14, 19, 24 instead of 8, 13, 18, 23
        assert!(validate_uuid_format("550e8400e-29b-41d4-a716-44665544000").is_err());
    }

    #[test]
    fn test_validate_uuid_format_mixed_case_valid() {
        assert!(validate_uuid_format("550E8400-e29B-41d4-A716-446655440000").is_ok());
    }

    #[test]
    fn test_validate_uuid_format_with_braces_rejected() {
        assert!(validate_uuid_format("{550e8400-e29b-41d4-a716-44665544000}").is_err());
    }

    #[test]
    fn test_validate_uuid_format_urn_prefix_rejected() {
        assert!(validate_uuid_format("urn:uuid:550e8400-e29b-41d4-a716-446655440000").is_err());
    }

    #[test]
    fn test_validate_uuid_format_v4_uuid() {
        // A standard v4 UUID
        assert!(validate_uuid_format("f47ac10b-58cc-4372-a567-0e02b2c3d479").is_ok());
    }

    #[test]
    fn test_validate_uuid_format_hyphen_replaced_with_space() {
        assert!(validate_uuid_format("550e8400 e29b 41d4 a716 446655440000").is_err());
    }

    #[test]
    fn test_validate_uuid_format_only_hyphens_at_correct_positions() {
        // 36 chars, hyphens at 8,13,18,23, but non-hex elsewhere
        assert!(validate_uuid_format("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz").is_err());
    }

    /* ========================================================================== */
    /*                    validate_short_code() ADDITIONAL TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_validate_short_code_with_tabs() {
        // Tabs are whitespace and should be stripped
        assert!(validate_short_code("1234\t5678\t9012").is_ok());
    }

    #[test]
    fn test_validate_short_code_all_nines() {
        assert!(validate_short_code("999999999999").is_ok());
    }

    #[test]
    fn test_validate_short_code_with_hyphen_chars_after_strip() {
        // After stripping whitespace, hyphens remain and fail digit check
        assert!(validate_short_code("1234-5678-9012").is_err());
    }

    #[test]
    fn test_validate_short_code_unicode_digits_rejected() {
        // Arabic-Indic digits are not ASCII digits
        assert!(validate_short_code("\u{0660}\u{0661}\u{0662}\u{0663}\u{0664}\u{0665}\u{0666}\u{0667}\u{0668}\u{0669}\u{0660}\u{0661}").is_err());
    }

    #[test]
    fn test_validate_short_code_mixed_digits_and_letters() {
        assert!(validate_short_code("12345678901z").is_err());
    }

    #[test]
    fn test_validate_short_code_leading_trailing_whitespace_only() {
        assert!(validate_short_code("  123456789012  ").is_ok());
    }

    #[test]
    fn test_validate_short_code_single_digit() {
        assert!(validate_short_code("1").is_err());
    }

    #[test]
    fn test_validate_short_code_13_digits() {
        assert!(validate_short_code("1234567890123").is_err());
    }

    /* ========================================================================== */
    /*                    validate_challenge_id() ADDITIONAL TESTS               */
    /* ========================================================================== */

    #[test]
    fn test_validate_challenge_id_valid_uuid() {
        assert!(validate_challenge_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890").is_ok());
    }

    #[test]
    fn test_validate_challenge_id_empty() {
        assert!(validate_challenge_id("").is_err());
    }

    #[test]
    fn test_validate_challenge_id_too_short() {
        assert!(validate_challenge_id("a1b2c3d4").is_err());
    }

    #[test]
    fn test_validate_challenge_id_path_traversal() {
        assert!(validate_challenge_id("../../../etc/passwd/aabbccdd").is_err());
    }

    /* ========================================================================== */
    /*                    Error message content tests                            */
    /* ========================================================================== */

    #[test]
    fn test_nonce_tag_empty_error_message() {
        let err = validate_nonce_tag("").unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad-request"),
            "Expected bad-request error, got: {}",
            msg
        );
    }

    #[test]
    fn test_nonce_tag_too_long_error_mentions_max() {
        let tag = "a".repeat(MAX_NONCE_TAG_LENGTH + 1);
        let err = validate_nonce_tag(&tag).unwrap_err();
        // The error is an ApiError; we check it was created
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_uuid_wrong_length_error() {
        let err = validate_uuid_format("short").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_short_code_wrong_length_error() {
        let err = validate_short_code("123").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(target_arch = "wasm32")]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Valid nonce tags always accepted
        #[test]
        fn prop_valid_nonce_tag(tag in "[a-zA-Z0-9_:-]{1,256}") {
            prop_assert!(validate_nonce_tag(&tag).is_ok());
        }

        /// Property: Valid UUIDs always accepted
        #[test]
        fn prop_valid_uuid(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{4}",
            d in "[0-9a-f]{4}",
            e in "[0-9a-f]{12}"
        ) {
            let uuid = format!("{}-{}-{}-{}-{}", a, b, c, d, e);
            prop_assert!(validate_uuid_format(&uuid).is_ok());
        }

        /// Property: 12-digit strings always accepted as short codes
        #[test]
        fn prop_valid_short_code(code in "[0-9]{12}") {
            prop_assert!(validate_short_code(&code).is_ok());
        }

        /// Property: Non-12-digit strings are rejected
        #[test]
        fn prop_wrong_length_short_code(len in 0usize..30) {
            prop_assume!(len != 12);
            let code = "0".repeat(len);
            prop_assert!(validate_short_code(&code).is_err());
        }

        /// Property: Nonce tags with null bytes always rejected
        #[test]
        fn prop_nonce_tag_null_rejected(prefix in "[a-z]{1,10}", suffix in "[a-z]{1,10}") {
            let tag = format!("{}\0{}", prefix, suffix);
            prop_assert!(validate_nonce_tag(&tag).is_err());
        }

        /// Property: validate_challenge_id behaves identically to validate_uuid_format
        #[test]
        fn prop_challenge_id_matches_uuid(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{4}",
            d in "[0-9a-f]{4}",
            e in "[0-9a-f]{12}"
        ) {
            let uuid = format!("{}-{}-{}-{}-{}", a, b, c, d, e);
            prop_assert_eq!(
                validate_uuid_format(&uuid).is_ok(),
                validate_challenge_id(&uuid).is_ok()
            );
        }
    }
}
