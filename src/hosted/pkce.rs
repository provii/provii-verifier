// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! PKCE (Proof Key for Code Exchange) verification utilities.
//!
//! This module provides secure verification of PKCE challenges using constant-time
//! comparison to prevent timing attacks. PKCE is required for secure OAuth 2.0
//! flows in public clients.
//!
//! # Security Considerations
//!
//! - All comparisons use constant-time algorithms to prevent timing attacks (OWASP ASVS 11.2.4)
//! - Uses `subtle::ConstantTimeEq` for cryptographic comparisons
//! - SHA-256 is used for hashing code_verifier values (via provii-crypto-protocol)
//! - Base64url encoding follows RFC 4648 Section 5 (no padding)
//!
//! Code verifiers must be 43-128 characters ([A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~").
//!
//! Challenge generation delegates to the audited `provii-crypto-protocol` library,
//! ensuring consistency across Provii components.

// Re-export from the pure-logic crate so existing call sites compile unchanged.
pub use provii_verifier_logic::pkce::generate_challenge;
pub use provii_verifier_logic::pkce::validate_verifier;
pub use provii_verifier_logic::pkce::verify_challenge;
pub use provii_verifier_logic::pkce::ChallengeMethod;
pub use provii_verifier_logic::pkce::PkceError;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    #[test]
    fn test_validate_verifier_valid() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(validate_verifier(verifier).is_ok());
    }

    #[test]
    fn test_validate_verifier_too_short() {
        let verifier = "short";
        let result = validate_verifier(verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierLength { length: 5 })
        ));
    }

    #[test]
    fn test_validate_verifier_too_long() {
        let verifier = "a".repeat(129);
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierLength { length: 129 })
        ));
    }

    #[test]
    fn test_validate_verifier_invalid_chars() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk!@#$";
        let result = validate_verifier(verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_validate_verifier_all_valid_chars() {
        // Test all allowed characters
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert!(validate_verifier(verifier).is_ok());
    }

    #[test]
    fn test_generate_challenge_s256() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let result = generate_challenge(verifier);
        assert!(result.is_ok());

        let challenge = result?;
        // SHA-256 hash should be 32 bytes, which becomes 43 chars in base64url (no padding)
        assert_eq!(challenge.len(), 43);

        // Verify it's valid base64url
        assert!(URL_SAFE_NO_PAD.decode(&challenge).is_ok());
        Ok(())
    }

    #[test]
    fn test_generate_challenge_invalid_verifier() {
        let verifier = "short";
        let result = generate_challenge(verifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_challenge_s256_success() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_challenge(verifier)?;

        let result = verify_challenge(verifier, &challenge, ChallengeMethod::S256);
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_verify_challenge_s256_failure() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "WRONG_CHALLENGE_VALUE_1234567890abcdefgh";

        let result = verify_challenge(verifier, wrong_challenge, ChallengeMethod::S256);
        assert!(matches!(result, Err(PkceError::VerificationFailed)));
    }

    // NOTE: ChallengeMethod::Plain is #[cfg(test)]-only inside the verifier-logic
    // crate (production is S256-only), so it is not reachable from this dependent
    // crate's tests. Plain-method behaviour is covered by verifier-logic's own
    // tests; these wrapper tests cover the production S256 path only.

    #[test]
    fn test_verify_challenge_empty_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let result = verify_challenge(verifier, "", ChallengeMethod::S256);
        assert!(matches!(
            result,
            Err(PkceError::InvalidChallengeFormat { .. })
        ));
    }

    #[test]
    fn test_constant_time_comparison_equal() {
        use subtle::ConstantTimeEq;
        let a = b"hello";
        let b = b"hello";
        assert!(bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_constant_time_comparison_different() {
        use subtle::ConstantTimeEq;
        let a = b"hello";
        let b = b"world";
        assert!(!bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_constant_time_comparison_different_length() {
        use subtle::ConstantTimeEq;
        let a = b"hello";
        let b = b"hello world";
        assert!(!bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_constant_time_comparison_empty() {
        use subtle::ConstantTimeEq;
        let a = b"";
        let b = b"";
        assert!(bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_pkce_error_display() {
        let err = PkceError::VerificationFailed;
        assert!(format!("{}", err).contains("verification failed"));

        let err = PkceError::InvalidVerifierLength { length: 10 };
        assert!(format!("{}", err).contains("10"));
        assert!(format!("{}", err).contains("43-128"));
    }

    #[test]
    fn test_deterministic_challenge_generation() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge1 = generate_challenge(verifier)?;
        let challenge2 = generate_challenge(verifier)?;
        assert_eq!(challenge1, challenge2);
        Ok(())
    }

    // --- New coverage tests below ---

    #[test]
    fn test_validate_verifier_exact_min_length() {
        // Exactly 43 characters
        let verifier = "a".repeat(43);
        assert!(validate_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_verifier_exact_max_length() {
        // Exactly 128 characters
        let verifier = "a".repeat(128);
        assert!(validate_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_verifier_one_below_min() {
        let verifier = "a".repeat(42);
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierLength { length: 42 })
        ));
    }

    #[test]
    fn test_validate_verifier_one_above_max() {
        let verifier = "a".repeat(129);
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierLength { length: 129 })
        ));
    }

    #[test]
    fn test_validate_verifier_empty() {
        let result = validate_verifier("");
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierLength { length: 0 })
        ));
    }

    #[test]
    fn test_validate_verifier_invalid_char_space() {
        // 43 chars but contains a space
        let verifier = format!("{}a b", "a".repeat(40));
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_validate_verifier_invalid_char_plus() {
        // '+' is valid in standard base64 but NOT in PKCE verifier charset
        let mut verifier = "a".repeat(42);
        verifier.push('+');
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_validate_verifier_invalid_char_slash() {
        let mut verifier = "a".repeat(42);
        verifier.push('/');
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_validate_verifier_invalid_char_equals() {
        // '=' is base64 padding, not allowed in PKCE verifier
        let mut verifier = "a".repeat(42);
        verifier.push('=');
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_validate_verifier_each_special_char() {
        // Each of the four allowed special characters individually
        for ch in ['-', '.', '_', '~'] {
            let verifier = format!("{}{}", "a".repeat(42), ch);
            assert!(
                validate_verifier(&verifier).is_ok(),
                "Character '{}' should be allowed",
                ch
            );
        }
    }

    #[test]
    fn test_validate_verifier_unicode() {
        // Unicode characters are not in the PKCE charset
        let mut verifier = "a".repeat(42);
        verifier.push('\u{00e9}'); // e-acute
        let result = validate_verifier(&verifier);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_generate_challenge_different_verifiers_produce_different_challenges(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let v1 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let v2 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let c1 = generate_challenge(v1)?;
        let c2 = generate_challenge(v2)?;
        assert_ne!(c1, c2);
        Ok(())
    }

    #[test]
    fn test_generate_challenge_output_is_valid_base64url() -> Result<(), Box<dyn std::error::Error>>
    {
        let verifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let challenge = generate_challenge(verifier)?;

        // Must be valid base64url with no padding
        assert!(!challenge.contains('='), "base64url must have no padding");
        assert!(!challenge.contains('+'), "base64url must not contain '+'");
        assert!(!challenge.contains('/'), "base64url must not contain '/'");

        // Must decode to exactly 32 bytes (SHA-256 output)
        let decoded = URL_SAFE_NO_PAD.decode(&challenge)?;
        assert_eq!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_verify_challenge_s256_wrong_verifier() -> Result<(), Box<dyn std::error::Error>> {
        let correct_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_verifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let challenge = generate_challenge(correct_verifier)?;

        let result = verify_challenge(wrong_verifier, &challenge, ChallengeMethod::S256);
        assert!(matches!(result, Err(PkceError::VerificationFailed)));
        Ok(())
    }

    #[test]
    fn test_verify_challenge_invalid_verifier_format() {
        let result = verify_challenge("short", "some-challenge", ChallengeMethod::S256);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierLength { .. })
        ));
    }

    #[test]
    fn test_verify_challenge_invalid_verifier_chars() {
        let bad_verifier = format!("{}!!!", "a".repeat(43));
        let result = verify_challenge(&bad_verifier, "some-challenge", ChallengeMethod::S256);
        assert!(matches!(
            result,
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_pkce_error_display_all_variants() {
        let cases = [
            (
                PkceError::InvalidVerifierFormat {
                    reason: "bad char".to_string(),
                },
                "Invalid code_verifier format: bad char",
            ),
            (
                PkceError::InvalidChallengeFormat {
                    reason: "empty".to_string(),
                },
                "Invalid code_challenge format: empty",
            ),
            (PkceError::VerificationFailed, "PKCE verification failed"),
            (
                PkceError::InvalidVerifierLength { length: 5 },
                "Invalid code_verifier length: 5 (must be 43-128)",
            ),
            (
                PkceError::Base64DecodingFailed {
                    details: "invalid byte".to_string(),
                },
                "Base64 decoding failed: invalid byte",
            ),
        ];
        for (err, expected_substr) in &cases {
            let display = format!("{}", err);
            assert!(
                display.contains(expected_substr),
                "Expected '{}' to contain '{}'",
                display,
                expected_substr
            );
        }
    }

    #[test]
    fn test_pkce_error_is_std_error() {
        // Verify PkceError implements std::error::Error
        let err: Box<dyn std::error::Error> = Box::new(PkceError::VerificationFailed);
        let _ = format!("{}", err);
    }

    #[test]
    fn test_pkce_error_debug() {
        let err = PkceError::InvalidVerifierLength { length: 42 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("42"));
        assert!(debug.contains("InvalidVerifierLength"));
    }

    #[test]
    fn test_pkce_error_clone() {
        let err = PkceError::VerificationFailed;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_pkce_error_eq() {
        assert_eq!(PkceError::VerificationFailed, PkceError::VerificationFailed);
        assert_ne!(
            PkceError::VerificationFailed,
            PkceError::InvalidVerifierLength { length: 5 }
        );
        assert_eq!(
            PkceError::InvalidVerifierLength { length: 10 },
            PkceError::InvalidVerifierLength { length: 10 }
        );
        assert_ne!(
            PkceError::InvalidVerifierLength { length: 10 },
            PkceError::InvalidVerifierLength { length: 11 }
        );
    }

    #[test]
    fn test_challenge_method_debug() {
        let method = ChallengeMethod::S256;
        let debug = format!("{:?}", method);
        assert_eq!(debug, "S256");
    }

    #[test]
    fn test_challenge_method_equality() {
        assert_eq!(ChallengeMethod::S256, ChallengeMethod::S256);
    }

    #[test]
    fn test_verify_s256_end_to_end_rfc_vector() -> Result<(), Box<dyn std::error::Error>> {
        // RFC 7636 Appendix B test vector
        // code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        // SHA256 -> base64url = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let generated = generate_challenge(verifier)?;
        assert_eq!(generated, expected_challenge);

        assert!(verify_challenge(verifier, expected_challenge, ChallengeMethod::S256).is_ok());
        Ok(())
    }
}
