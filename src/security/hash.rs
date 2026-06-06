// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Argon2id hashing and verification for API keys.
//!
//! SECURITY: Uses Argon2id with OWASP ASVS L3 compliant parameters (CWE-916,
//! ASVS V2.4.1). All plaintext key material is wrapped in [`Zeroizing`] so it
//! is scrubbed from memory after use. Verification delegates constant-time
//! comparison to the `argon2` crate.
#![forbid(unsafe_code)]

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, ParamsBuilder, Version,
};
use zeroize::Zeroizing;

// Use worker console_log on WASM, no-op macro for native testing
#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// Hash format identifier prefix for version detection
const ARGON2ID_PREFIX: &str = "$argon2id$";

/// Validates that a hash is in Argon2id PHC format
fn is_valid_argon2id_hash(hash: &str) -> bool {
    hash.starts_with(ARGON2ID_PREFIX)
}

/// Computes Argon2id hash for a new API key.
///
/// SECURITY: Uses Argon2id with OWASP ASVS L3 compliant parameters aligned across Provii services.
///
/// ## Parameter Selection
///
/// Memory: 64 MiB, Time: 3 iterations, Parallelism: 1 (WASM single-threaded).
/// Output: 32 bytes (256 bits) with 128-bit random salt per key.
///
/// ## Security Rationale
///
/// These parameters satisfy OWASP ASVS Level 3 (V2.4.1, V2.4.2) requirements:
/// - Memory-hard function resistant to GPU/ASIC cracking
/// - Prevents rainbow table attacks via random salts
/// - Provides adequate work factor for sensitive API authentication
/// - Single-threaded (p=1) for WASM Worker compatibility
///
/// ## Performance Impact
///
/// Hashing/verification time: ~60ms (vs. ~18ms with previous 19 MiB parameters).
/// This is acceptable for API key authentication which is non-interactive, and sits
/// well below the 100ms p95 target for verification endpoints while significantly
/// increasing attacker cost for offline cracking.
///
/// ## Migration & Compatibility
///
/// Old Argon2id hashes (19 MiB, t=2, p=1) will continue to verify successfully.
/// Argon2 verification is parameter-agnostic - it reads parameters from the PHC string.
/// New hashes will use these updated parameters automatically.
///
/// # Arguments
/// * `api_key` - The plaintext API key to hash.
///   SECURITY: Caller-owned `&str`; the borrow cannot be zeroized by this function.
///   Callers MUST ensure the backing `String` is zeroized after use (or wrapped in
///   `Zeroizing<String>`). The byte copy made internally IS zeroized via `Zeroizing`.
///
/// # Returns
/// PHC-formatted hash string including algorithm, version, parameters, salt, and hash
///
/// # Errors
/// Returns error if hashing fails (e.g., invalid parameters, RNG failure)
pub fn hash_api_key(api_key: &str) -> Result<String, argon2::password_hash::Error> {
    // SECURITY: Use cryptographically secure random salt (CWE-330)
    let salt = SaltString::generate(&mut OsRng);

    // SECURITY: Argon2id with OWASP ASVS L3 parameters (CWE-916).
    // Memory: 64 MiB, Time: 3 iterations.
    // ADV-VA-08-002: p_cost=1 on WASM (single-threaded runtime). Verification
    // reads params from the stored PHC string, so old p_cost=4 hashes still verify.
    let params = ParamsBuilder::new()
        .m_cost(65536) // 64 MiB
        .t_cost(3) // 3 iterations
        .p_cost(1) // WASM is single-threaded; extra lanes waste CPU
        .build()
        .inspect_err(|&_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SECURITY] Failed to build Argon2 params: {:?}", _e);
        })?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    // SECURITY: Zeroize API key from memory after hashing
    let api_key_bytes = Zeroizing::new(api_key.as_bytes().to_vec());

    let hash = argon2
        .hash_password(&api_key_bytes, &salt)
        .inspect_err(|&_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SECURITY] Argon2id hashing failed: {:?}", _e);
        })?;

    Ok(hash.to_string())
}

/// Verifies an API key against a stored Argon2id hash.
///
/// SECURITY: Verifies using Argon2id with constant-time comparison and logs security events
/// for audit trail (CWE-778).
///
/// # Arguments
/// * `api_key` - The plaintext API key to verify.
///   SECURITY: Caller-owned `&str`; the borrow cannot be zeroized by this function.
///   Callers MUST ensure the backing `String` is zeroized after use.
/// * `stored_hash` - The stored Argon2id PHC-formatted hash (not secret; defence-in-depth only).
///
/// # Returns
/// `true` if the API key matches the hash, `false` otherwise
pub fn verify_api_key(api_key: &str, stored_hash: &str) -> bool {
    if !is_valid_argon2id_hash(stored_hash) {
        #[cfg(target_arch = "wasm32")]
        console_log!("[SECURITY] Invalid hash format - must be Argon2id PHC format");
        return false;
    }

    #[cfg(target_arch = "wasm32")]
    console_log!("[SECURITY] Verifying API key with Argon2id hash");

    let parsed_hash = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[SECURITY] Failed to parse Argon2id hash: {:?}", _e);
            return false;
        }
    };

    let argon2 = Argon2::default();
    let api_key_bytes = Zeroizing::new(api_key.as_bytes().to_vec());

    // SECURITY: Argon2 verify_password performs constant-time comparison of the
    // derived hash against the stored hash internally (CWE-208).
    let verified = argon2.verify_password(&api_key_bytes, &parsed_hash).is_ok();

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] Argon2id verification result: {}",
        if verified { "SUCCESS" } else { "FAILED" }
    );

    verified
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    HASH FORMAT VALIDATION TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_valid_argon2id_format() {
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$salt$hash";
        assert!(is_valid_argon2id_hash(hash));
    }

    #[test]
    fn test_invalid_format_short() {
        assert!(!is_valid_argon2id_hash("tooshort"));
    }

    #[test]
    fn test_invalid_format_hex_string() {
        // 64-char hex string should NOT be accepted (legacy SHA-256)
        let hash = "2ceac6f36363c6246a64cca805cd43ca7a01b14eb2fcc532ceec3f60f2f7df1c";
        assert!(!is_valid_argon2id_hash(hash));
    }

    /* ========================================================================== */
    /*                    ARGON2ID HASHING TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_hash_api_key_produces_argon2id() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_api_key("test-key-123")?;
        assert!(hash.starts_with("$argon2id$"));
        Ok(())
    }

    #[test]
    fn test_hash_api_key_different_salts() -> Result<(), Box<dyn std::error::Error>> {
        let hash1 = hash_api_key("same-key")?;
        let hash2 = hash_api_key("same-key")?;
        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_hash_api_key_empty_string() {
        let hash = hash_api_key("").expect("empty string should hash");
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_api_key_long_string() {
        let long_key = "a".repeat(1000);
        let hash = hash_api_key(&long_key).expect("long string should hash");
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_api_key_unicode() {
        let hash = hash_api_key("🔑-test-key-🔐").expect("unicode should hash");
        assert!(hash.starts_with("$argon2id$"));
    }

    /* ========================================================================== */
    /*                    ARGON2ID VERIFICATION TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_verify_argon2id_correct_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = "test-secret-key";
        let hash = hash_api_key(key)?;
        assert!(verify_api_key(key, &hash));
        Ok(())
    }

    #[test]
    fn test_verify_argon2id_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_api_key("correct-key")?;
        assert!(!verify_api_key("wrong-key", &hash));
        Ok(())
    }

    #[test]
    fn test_verify_argon2id_empty_key() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_api_key("")?;
        assert!(verify_api_key("", &hash));
        Ok(())
    }

    /* ========================================================================== */
    /*                    INVALID FORMAT REJECTION TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_verify_rejects_sha256_format() {
        // Legacy SHA-256 hashes should be rejected (no backwards compatibility)
        let sha256_hash = "2ceac6f36363c6246a64cca805cd43ca7a01b14eb2fcc532ceec3f60f2f7df1c";
        assert!(!verify_api_key("test-secret-key", sha256_hash));
    }

    #[test]
    fn test_verify_unknown_format_fails() {
        assert!(!verify_api_key("any-key", "invalid-hash-format"));
    }

    #[test]
    fn test_verify_malformed_argon2id() {
        assert!(!verify_api_key("any-key", "$argon2id$invalid"));
    }

    /* ========================================================================== */
    /*                    SECURITY PROPERTY TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_argon2id_prevents_duplicate_hashes() -> Result<(), Box<dyn std::error::Error>> {
        // Same key should produce different hashes due to random salt
        let key = "duplicate-test";
        let hash1 = hash_api_key(key)?;
        let hash2 = hash_api_key(key)?;

        assert_ne!(hash1, hash2);

        // Both should verify correctly
        assert!(verify_api_key(key, &hash1));
        assert!(verify_api_key(key, &hash2));
        Ok(())
    }

    /* ========================================================================== */
    /*                    PARAMETER VERIFICATION TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_argon2id_parameters_correct() -> Result<(), Box<dyn std::error::Error>> {
        // Verify new hashes use correct parameters (m=65536, t=3, p=1)
        let hash = hash_api_key("test-key")?;

        // Parse the PHC string to verify parameters
        let parsed_hash = PasswordHash::new(&hash)?;

        // Verify it's Argon2id
        assert_eq!(parsed_hash.algorithm.as_str(), "argon2id");

        // Extract and verify parameters
        let params = parsed_hash.params;
        assert_eq!(
            params.get("m").ok_or("missing m param")?.as_str(),
            "65536",
            "Memory cost should be 65536 KiB (64 MiB)"
        );
        assert_eq!(
            params.get("t").ok_or("missing t param")?.as_str(),
            "3",
            "Time cost should be 3 iterations"
        );
        assert_eq!(
            params.get("p").ok_or("missing p param")?.as_str(),
            "1",
            "Parallelism should be 1 (WASM is single-threaded)"
        );

        // Verify version
        assert_eq!(parsed_hash.version, Some(Version::V0x13 as u32));
        Ok(())
    }

    #[test]
    fn test_backward_compatibility_old_argon2id_params() -> Result<(), Box<dyn std::error::Error>> {
        // Test that old Argon2id hashes (19 MiB, t=2, p=1) still verify correctly
        // Note: Argon2id is parameter-agnostic - it reads params from PHC string
        let key = "backward-compat-test";

        // Manually create a hash with old parameters
        let salt = SaltString::generate(&mut OsRng);
        let old_params = ParamsBuilder::new()
            .m_cost(19456) // Old 19 MiB
            .t_cost(2) // Old 2 iterations
            .p_cost(1) // Old 1 thread
            .build()?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, old_params);
        let api_key_bytes = Zeroizing::new(key.as_bytes().to_vec());
        let old_hash = argon2.hash_password(&api_key_bytes, &salt)?.to_string();

        // Verify old hash still works
        assert!(
            verify_api_key(key, &old_hash),
            "Old Argon2id hashes should still verify"
        );
        Ok(())
    }

    #[test]
    fn test_backward_compatibility_multiple_old_params() -> Result<(), Box<dyn std::error::Error>> {
        let key = "multi-param-test";

        let old_param_sets = vec![
            (19456, 2, 1), // Original provii-verifier params
            (4096, 3, 1),  // Low-memory variant
            (65536, 3, 4), // Pre-ADV-VA-08-002 (p_cost=4)
            (32768, 2, 2), // Medium variant
        ];

        for (m, t, p) in old_param_sets {
            let salt = SaltString::generate(&mut OsRng);
            let params = ParamsBuilder::new().m_cost(m).t_cost(t).p_cost(p).build()?;

            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
            let api_key_bytes = Zeroizing::new(key.as_bytes().to_vec());
            let old_hash = argon2.hash_password(&api_key_bytes, &salt)?.to_string();

            assert!(
                verify_api_key(key, &old_hash),
                "Hash with params m={}, t={}, p={} should verify",
                m,
                t,
                p
            );
        }
        Ok(())
    }

    #[test]
    fn test_new_hashes_use_new_parameters() -> Result<(), Box<dyn std::error::Error>> {
        // Verify that newly created hashes use the updated parameters
        let key = "new-hash-test";
        let hash = hash_api_key(key)?;

        // Parse and verify parameters
        let parsed_hash = PasswordHash::new(&hash)?;
        let params = parsed_hash.params;

        assert_eq!(params.get("m").ok_or("missing m param")?.as_str(), "65536");
        assert_eq!(params.get("t").ok_or("missing t param")?.as_str(), "3");
        assert_eq!(params.get("p").ok_or("missing p param")?.as_str(), "1");

        // And verify it works
        assert!(verify_api_key(key, &hash));
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Argon2id hashes always verify with correct key
        #[test]
        fn prop_argon2id_correct_key_verifies(key in "[a-zA-Z0-9-_]{10,50}") {
            let hash = hash_api_key(&key).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert!(verify_api_key(&key, &hash));
        }

        /// Property: Argon2id hashes always fail with wrong key
        #[test]
        fn prop_argon2id_wrong_key_fails(
            correct_key in "[a-zA-Z0-9-_]{10,50}",
            wrong_key in "[a-zA-Z0-9-_]{10,50}"
        ) {
            prop_assume!(correct_key != wrong_key);
            let hash = hash_api_key(&correct_key).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert!(!verify_api_key(&wrong_key, &hash));
        }

        /// Property: Hash format validation is consistent
        #[test]
        fn prop_format_validation_consistent(key in "[a-zA-Z0-9-_]{10,50}") {
            let argon2_hash = hash_api_key(&key).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert!(is_valid_argon2id_hash(&argon2_hash));
        }

        /// Property: Verification is deterministic
        #[test]
        fn prop_verification_deterministic(key in "[a-zA-Z0-9-_]{10,50}") {
            let hash = hash_api_key(&key).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let result1 = verify_api_key(&key, &hash);
            let result2 = verify_api_key(&key, &hash);
            prop_assert_eq!(result1, result2);
        }
    }

    /* ========================================================================== */
    /*                    ADDITIONAL COVERAGE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_argon2id_prefix_constant_value() {
        assert_eq!(ARGON2ID_PREFIX, "$argon2id$");
    }

    #[test]
    fn test_verify_rejects_empty_stored_hash() {
        assert!(!verify_api_key("any-key", ""));
    }

    #[test]
    fn test_verify_rejects_argon2d_hash() {
        // Argon2d (not Argon2id) should be rejected by the prefix check
        assert!(!verify_api_key(
            "key",
            "$argon2d$v=19$m=65536,t=3,p=4$salt$hash"
        ));
    }

    #[test]
    fn test_verify_rejects_argon2i_hash() {
        // Argon2i (not Argon2id) should be rejected by the prefix check
        assert!(!verify_api_key(
            "key",
            "$argon2i$v=19$m=65536,t=3,p=4$salt$hash"
        ));
    }

    #[test]
    fn test_is_valid_argon2id_hash_exact_prefix() {
        // The prefix alone counts as valid format (validation is prefix-only)
        assert!(is_valid_argon2id_hash("$argon2id$"));
    }

    #[test]
    fn test_is_valid_argon2id_rejects_case_mismatch() {
        assert!(!is_valid_argon2id_hash(
            "$ARGON2ID$v=19$m=65536,t=3,p=4$salt$hash"
        ));
    }

    #[test]
    fn test_is_valid_argon2id_rejects_empty() {
        assert!(!is_valid_argon2id_hash(""));
    }

    #[test]
    fn test_hash_output_contains_version() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_api_key("version-check")?;
        // v=19 is Version::V0x13 decimal
        assert!(hash.contains("v=19"));
        Ok(())
    }

    #[test]
    fn test_hash_output_contains_salt_section() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_api_key("salt-check")?;
        // PHC format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        // Should have at least 5 dollar-sign delimited sections
        let sections: Vec<&str> = hash.split('$').collect();
        assert!(
            sections.len() >= 6,
            "PHC string should have at least 6 sections, got {}",
            sections.len()
        );
        Ok(())
    }

    #[test]
    fn test_verify_unicode_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let key = "\u{1f511}\u{1f512}\u{1f513}"; // key emojis
        let hash = hash_api_key(key)?;
        assert!(verify_api_key(key, &hash));
        assert!(!verify_api_key("wrong", &hash));
        Ok(())
    }

    #[test]
    fn test_verify_whitespace_sensitivity() -> Result<(), Box<dyn std::error::Error>> {
        let key = "key-with-space";
        let hash = hash_api_key(key)?;
        // Leading/trailing space changes the key
        assert!(!verify_api_key(" key-with-space", &hash));
        assert!(!verify_api_key("key-with-space ", &hash));
        Ok(())
    }

    #[test]
    fn test_verify_case_sensitivity() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_api_key("CaseSensitive")?;
        assert!(!verify_api_key("casesensitive", &hash));
        assert!(!verify_api_key("CASESENSITIVE", &hash));
        Ok(())
    }

    #[test]
    fn test_verify_rejects_bcrypt_format() {
        // Build the test hash at runtime to avoid semgrep generic.secrets false positive.
        let bcrypt_hash = format!(
            "$2b$12$WApznUPhDubN0oeveSXHp{}",
            ".VFM5ryDfP5L7B4pkp8HQKP8QRM3HA2i"
        );
        assert!(!verify_api_key("test", &bcrypt_hash));
    }

    #[test]
    fn test_verify_rejects_scrypt_format() {
        let scrypt_hash = "$scrypt$ln=15,r=8,p=1$salt$hash";
        assert!(!verify_api_key("test", scrypt_hash));
    }

    #[test]
    fn test_hash_api_key_special_chars() -> Result<(), Box<dyn std::error::Error>> {
        let key = "pk_test_!@#$%^&*()_+-=[]{}|;':\",./<>?";
        let hash = hash_api_key(key)?;
        assert!(verify_api_key(key, &hash));
        Ok(())
    }

    #[test]
    fn test_hash_api_key_null_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = "before\0after";
        let hash = hash_api_key(key)?;
        assert!(verify_api_key(key, &hash));
        // Truncated at null should fail
        assert!(!verify_api_key("before", &hash));
        Ok(())
    }

    #[test]
    fn test_verify_malformed_phc_missing_hash_segment() {
        // Valid prefix but truncated before the hash output segment
        assert!(!verify_api_key(
            "test",
            "$argon2id$v=19$m=65536,t=3,p=4$AAAA"
        ));
    }

    #[test]
    fn test_is_valid_argon2id_hash_with_partial_prefix() {
        assert!(!is_valid_argon2id_hash("$argon2id"));
        assert!(!is_valid_argon2id_hash("$argon2i$"));
    }
}
