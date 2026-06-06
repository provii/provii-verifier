// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! PKCE (Proof Key for Code Exchange) verification utilities (pure logic).
//!
//! SECURITY: All comparisons use `subtle::ConstantTimeEq` for constant-time
//! comparison to prevent timing side-channels (OWASP ASVS 11.2.4).
//! SHA-256 challenge generation delegates to `provii-crypto-protocol`.
#![forbid(unsafe_code)]

use provii_crypto_protocol::code_challenge_s256;
use std::error::Error;
use std::fmt;
use subtle::ConstantTimeEq;

/// Errors that can occur during PKCE verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkceError {
    /// Code verifier format is invalid
    InvalidVerifierFormat { reason: String },
    /// Code challenge format is invalid
    InvalidChallengeFormat { reason: String },
    /// Code verifier does not match code challenge
    VerificationFailed,
    /// Code verifier length is out of range (43-128 characters)
    InvalidVerifierLength { length: usize },
    /// Base64 decoding failed
    Base64DecodingFailed { details: String },
}

impl fmt::Display for PkceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkceError::InvalidVerifierFormat { reason } => {
                write!(f, "Invalid code_verifier format: {}", reason)
            }
            PkceError::InvalidChallengeFormat { reason } => {
                write!(f, "Invalid code_challenge format: {}", reason)
            }
            PkceError::VerificationFailed => {
                write!(
                    f,
                    "PKCE verification failed: code_verifier does not match code_challenge"
                )
            }
            PkceError::InvalidVerifierLength { length } => {
                write!(
                    f,
                    "Invalid code_verifier length: {} (must be 43-128)",
                    length
                )
            }
            PkceError::Base64DecodingFailed { details } => {
                write!(f, "Base64 decoding failed: {}", details)
            }
        }
    }
}

impl Error for PkceError {}

/// PKCE code challenge method.
///
/// Only S256 is available in production builds. `Plain` is test-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeMethod {
    /// SHA-256 hashing (the only method allowed in production)
    S256,
    /// Plain text (insecure, test-only)
    #[cfg(test)]
    Plain,
}

/// Validate that a code_verifier meets PKCE requirements per RFC 7636.
///
/// Length must be 43-128 characters. Character set: `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`.
pub fn validate_verifier(verifier: &str) -> Result<(), PkceError> {
    let len = verifier.len();
    if len < 43 {
        return Err(PkceError::InvalidVerifierLength { length: len });
    }
    if len > 128 {
        return Err(PkceError::InvalidVerifierLength { length: len });
    }
    for c in verifier.chars() {
        if !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~') {
            return Err(PkceError::InvalidVerifierFormat {
                reason: format!("Invalid character: '{}'", c),
            });
        }
    }
    Ok(())
}

/// Generate a code_challenge from a code_verifier using SHA-256.
pub fn generate_challenge(verifier: &str) -> Result<String, PkceError> {
    validate_verifier(verifier)?;
    Ok(code_challenge_s256(verifier))
}

/// Verify a code_verifier against a code_challenge using constant-time comparison.
///
/// SECURITY: Uses `subtle::ConstantTimeEq` to prevent timing side-channels.
pub fn verify_challenge(
    verifier: &str,
    challenge: &str,
    method: ChallengeMethod,
) -> Result<(), PkceError> {
    validate_verifier(verifier)?;

    if challenge.is_empty() {
        return Err(PkceError::InvalidChallengeFormat {
            reason: "Challenge cannot be empty".to_string(),
        });
    }

    let computed_challenge = match method {
        ChallengeMethod::S256 => generate_challenge(verifier)?,
        #[cfg(test)]
        ChallengeMethod::Plain => verifier.to_string(),
    };

    // SECURITY: Constant-time comparison via subtle::ConstantTimeEq.
    let is_equal = computed_challenge.as_bytes().ct_eq(challenge.as_bytes());

    if bool::from(is_equal) {
        Ok(())
    } else {
        Err(PkceError::VerificationFailed)
    }
}

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
        assert!(matches!(
            validate_verifier("short"),
            Err(PkceError::InvalidVerifierLength { length: 5 })
        ));
    }

    #[test]
    fn test_validate_verifier_too_long() {
        let v = "a".repeat(129);
        assert!(matches!(
            validate_verifier(&v),
            Err(PkceError::InvalidVerifierLength { length: 129 })
        ));
    }

    #[test]
    fn test_validate_verifier_invalid_chars() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk!@#$";
        assert!(matches!(
            validate_verifier(v),
            Err(PkceError::InvalidVerifierFormat { .. })
        ));
    }

    #[test]
    fn test_validate_verifier_all_valid_chars() {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert!(validate_verifier(v).is_ok());
    }

    #[test]
    fn test_generate_challenge_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_challenge(verifier).expect("valid verifier");
        assert_eq!(challenge.len(), 43);
        assert!(URL_SAFE_NO_PAD.decode(&challenge).is_ok());
    }

    #[test]
    fn test_verify_challenge_s256_success() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_challenge(verifier).expect("valid");
        assert!(verify_challenge(verifier, &challenge, ChallengeMethod::S256).is_ok());
    }

    #[test]
    fn test_verify_challenge_s256_failure() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let result = verify_challenge(
            verifier,
            "WRONG_CHALLENGE_VALUE_1234567890abcdefgh",
            ChallengeMethod::S256,
        );
        assert!(matches!(result, Err(PkceError::VerificationFailed)));
    }

    #[test]
    fn test_verify_challenge_plain_success() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(verify_challenge(verifier, verifier, ChallengeMethod::Plain).is_ok());
    }

    #[test]
    fn test_verify_challenge_plain_failure() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(matches!(
            verify_challenge(verifier, wrong, ChallengeMethod::Plain),
            Err(PkceError::VerificationFailed)
        ));
    }

    #[test]
    fn test_verify_challenge_empty_challenge() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(matches!(
            verify_challenge(verifier, "", ChallengeMethod::S256),
            Err(PkceError::InvalidChallengeFormat { .. })
        ));
    }

    #[test]
    fn test_verify_s256_rfc_vector() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let generated = generate_challenge(verifier).expect("valid");
        assert_eq!(generated, expected);
        assert!(verify_challenge(verifier, expected, ChallengeMethod::S256).is_ok());
    }

    #[test]
    fn test_validate_verifier_exact_min_length() {
        assert!(validate_verifier(&"a".repeat(43)).is_ok());
    }

    #[test]
    fn test_validate_verifier_exact_max_length() {
        assert!(validate_verifier(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn test_validate_verifier_one_below_min() {
        assert!(matches!(
            validate_verifier(&"a".repeat(42)),
            Err(PkceError::InvalidVerifierLength { length: 42 })
        ));
    }

    #[test]
    fn test_validate_verifier_empty() {
        assert!(matches!(
            validate_verifier(""),
            Err(PkceError::InvalidVerifierLength { length: 0 })
        ));
    }

    #[test]
    fn test_deterministic_challenge_generation() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c1 = generate_challenge(verifier).expect("valid");
        let c2 = generate_challenge(verifier).expect("valid");
        assert_eq!(c1, c2);
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
    fn test_constant_time_comparison_equal() {
        let a = b"hello";
        let b = b"hello";
        assert!(bool::from(a.ct_eq(b)));
    }

    #[test]
    fn test_constant_time_comparison_different() {
        let a = b"hello";
        let b = b"world";
        assert!(!bool::from(a.ct_eq(b)));
    }
}
