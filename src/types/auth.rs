// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Authentication envelopes shared by trusted verifier clients.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Shared HMAC-based authorizer used by relying parties when calling the API.
///
/// SECURITY: `hmac` and `nonce` are secret authentication material. The `Debug`
/// impl redacts them to prevent accidental logging (ASVS V11.7.2).
/// `Zeroize` + `ZeroizeOnDrop` ensure they are cleared from memory on drop.
#[derive(Clone, Serialize, Deserialize, JsonSchema, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Authorizer {
    /// Identifier of the client credential used to authenticate the request.
    #[serde(rename = "keyId")]
    #[zeroize(skip)]
    pub key_id: String,
    /// Unix timestamp (seconds) included in the canonical signing payload.
    #[zeroize(skip)]
    pub timestamp: u64,
    /// Hex-encoded HMAC (SHA-256) over the canonical message.
    pub hmac: String,
    /// SECURITY: Cryptographic nonce for replay protection (64 hex chars / 256 bits).
    /// Required for nonce-based replay attack prevention (ASVS V6.1.3).
    pub nonce: String,
}

impl fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorizer")
            .field("key_id", &self.key_id)
            .field("timestamp", &self.timestamp)
            .field("hmac", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl Authorizer {
    /// Perform lightweight structural validation of the authorizer fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.key_id.trim().is_empty() {
            return Err("keyId must not be empty".into());
        }

        if self.key_id.len() > 128 {
            return Err("keyId too long".into());
        }

        if !self.key_id.chars().all(|c| c.is_ascii_graphic()) {
            return Err("keyId contains invalid characters".into());
        }

        if self.hmac.len() != 64 || !self.hmac.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("hmac must be a 64-character hex string".into());
        }

        // SECURITY: Validate nonce format - mandatory for replay protection (CWE-287, ASVS V6.1.3)
        // Nonce must be exactly 64 hex characters (256 bits of entropy)
        if self.nonce.len() != 64 {
            return Err("nonce must be exactly 64 hex characters (256 bits)".into());
        }

        if !self.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("nonce must be a hex string".into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_authorizer() -> Authorizer {
        Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64), // 64 hex chars (256 bits)
        }
    }

    /* ========================================================================== */
    /*                    CONSTRUCTOR AND FIELD TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_authorizer_creation() {
        let auth = create_valid_authorizer();
        assert_eq!(auth.key_id, "client-123");
        assert_eq!(auth.timestamp, 1234567890);
        assert_eq!(auth.hmac.len(), 64);
    }

    #[test]
    fn test_authorizer_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let auth = create_valid_authorizer();
        let json = serde_json::to_string(&auth)?;
        assert!(json.contains("client-123"));
        assert!(json.contains("1234567890"));
        assert!(json.contains("keyId")); // Check camelCase
        Ok(())
    }

    #[test]
    fn test_authorizer_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"keyId":"client-456","timestamp":9876543210,"hmac":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","nonce":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#;
        let auth: Authorizer = serde_json::from_str(json)?;
        assert_eq!(auth.key_id, "client-456");
        assert_eq!(auth.timestamp, 9876543210);
        assert_eq!(auth.hmac, "b".repeat(64));
        assert_eq!(auth.nonce, "c".repeat(64));
        Ok(())
    }

    #[test]
    fn test_authorizer_deny_unknown_fields() {
        let json = r#"{"keyId":"test","timestamp":123,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"550e8400-e29b-41d4-a716-446655440000","extra":"field"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err()); // Should fail due to deny_unknown_fields
    }

    /* ========================================================================== */
    /*                    validate() TESTS - VALID CASES                         */
    /* ========================================================================== */

    #[test]
    fn test_validate_valid_authorizer() {
        let auth = create_valid_authorizer();
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_min_length() {
        let auth = Authorizer {
            key_id: "a".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_max_length() {
        let auth = Authorizer {
            key_id: "a".repeat(128),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_ascii_graphic() {
        let auth = Authorizer {
            key_id: "client-123_test.v1".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_hmac_lowercase() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "abcdef1234567890".repeat(4),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_hmac_uppercase() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "ABCDEF1234567890".repeat(4),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_hmac_mixed_case() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "AbCdEf1234567890".repeat(4),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    /* ========================================================================== */
    /*                    validate() TESTS - INVALID CASES                       */
    /* ========================================================================== */

    #[test]
    fn test_validate_empty_key_id() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result.err().ok_or("expected error")?.contains("empty"));
        Ok(())
    }

    #[test]
    fn test_validate_whitespace_only_key_id() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "   ".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result.err().ok_or("expected error")?.contains("empty"));
        Ok(())
    }

    #[test]
    fn test_validate_key_id_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "a".repeat(129),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result.err().ok_or("expected error")?.contains("too long"));
        Ok(())
    }

    #[test]
    fn test_validate_key_id_non_ascii() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client-🔒".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("invalid characters"));
        Ok(())
    }

    #[test]
    fn test_validate_key_id_control_chars() {
        let auth = Authorizer {
            key_id: "client\n123".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_hmac_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(63),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("64-character"));
        Ok(())
    }

    #[test]
    fn test_validate_hmac_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(65),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("64-character"));
        Ok(())
    }

    #[test]
    fn test_validate_hmac_invalid_chars() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: format!("{}g", "a".repeat(63)), // 'g' not hex
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result.err().ok_or("expected error")?.contains("hex"));
        Ok(())
    }

    #[test]
    fn test_validate_hmac_with_padding() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: format!("{}=", "a".repeat(63)),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    Debug REDACTION TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_authorizer_debug_redacts_hmac() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        assert!(debug.contains("[REDACTED]"));
        // The actual HMAC value should NOT appear
        assert!(!debug.contains(&"a".repeat(64)));
    }

    #[test]
    fn test_authorizer_debug_redacts_nonce() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        // The actual nonce value should NOT appear
        assert!(!debug.contains(&"b".repeat(64)));
    }

    #[test]
    fn test_authorizer_debug_shows_key_id() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        assert!(debug.contains("client-123"));
    }

    #[test]
    fn test_authorizer_debug_shows_timestamp() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        assert!(debug.contains("1234567890"));
    }

    /* ========================================================================== */
    /*                    validate() NONCE TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_validate_nonce_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(63), // 63 chars, not 64
        };
        let result = auth.validate();
        assert!(result.is_err());
        let err_msg = result.err().ok_or("expected error")?;
        assert!(err_msg.contains("64 hex characters"));
        Ok(())
    }

    #[test]
    fn test_validate_nonce_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(65), // 65 chars, not 64
        };
        let result = auth.validate();
        assert!(result.is_err());
        let err_msg = result.err().ok_or("expected error")?;
        assert!(err_msg.contains("64 hex characters"));
        Ok(())
    }

    #[test]
    fn test_validate_nonce_non_hex() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: format!("{}g", "a".repeat(63)), // 'g' is not hex
        };
        let result = auth.validate();
        assert!(result.is_err());
        let err_msg = result.err().ok_or("expected error")?;
        assert!(err_msg.contains("hex"));
        Ok(())
    }

    #[test]
    fn test_validate_nonce_empty() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: String::new(),
        };
        let result = auth.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_nonce_valid_mixed_case() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "AbCdEf1234567890".repeat(4),
        };
        assert!(auth.validate().is_ok());
    }

    /* ========================================================================== */
    /*                    validate() key_id edge cases                           */
    /* ========================================================================== */

    #[test]
    fn test_validate_key_id_with_space() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client 123".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        let err_msg = result.err().ok_or("expected error")?;
        assert!(err_msg.contains("invalid characters"));
        Ok(())
    }

    #[test]
    fn test_validate_key_id_with_tab() {
        let auth = Authorizer {
            key_id: "client\t123".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_key_id_all_special_ascii_graphic() {
        // ASCII graphic chars like !@#$%^&*() should be allowed
        let auth = Authorizer {
            key_id: "!@#$%^&*()".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_exactly_128() {
        let auth = Authorizer {
            key_id: "x".repeat(128),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_129_too_long() {
        let auth = Authorizer {
            key_id: "x".repeat(129),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    /* ========================================================================== */
    /*                    Authorizer Clone TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_authorizer_clone() {
        let auth = create_valid_authorizer();
        let cloned = auth.clone();
        assert_eq!(cloned.key_id, auth.key_id);
        assert_eq!(cloned.timestamp, auth.timestamp);
        assert_eq!(cloned.hmac, auth.hmac);
        assert_eq!(cloned.nonce, auth.nonce);
    }

    /* ========================================================================== */
    /*                    Authorizer serde edge cases                            */
    /* ========================================================================== */

    #[test]
    fn test_authorizer_deserialize_missing_nonce() {
        let json = r#"{"keyId":"test","timestamp":123,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorizer_deserialize_missing_hmac() {
        let json = r#"{"keyId":"test","timestamp":123,"nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorizer_deserialize_missing_key_id() {
        let json = r#"{"timestamp":123,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorizer_deserialize_missing_timestamp() {
        let json = r#"{"keyId":"test","hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorizer_timestamp_zero() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 0,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        // Validation does not check timestamp bounds
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_authorizer_timestamp_max() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: u64::MAX,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Valid key_id lengths (1-128 ASCII graphic) are accepted
        #[test]
        fn prop_valid_key_id_length(len in 1usize..=128) {
            let auth = Authorizer {
                key_id: "a".repeat(len),
                timestamp: 1234567890,
                hmac: "a".repeat(64),
                nonce: "b".repeat(64),
            };
            prop_assert!(auth.validate().is_ok());
        }

        /// Property: key_id length 0 or > 128 is rejected
        #[test]
        fn prop_invalid_key_id_length(len in 129usize..200) {
            let auth = Authorizer {
                key_id: "a".repeat(len),
                timestamp: 123,
                hmac: "a".repeat(64),
                nonce: "b".repeat(64),
            };
            prop_assert!(auth.validate().is_err());
        }

        /// Property: HMAC must be exactly 64 hex characters
        #[test]
        fn prop_hmac_length_strict(len in 0usize..128) {
            prop_assume!(len != 64);
            let auth = Authorizer {
                key_id: "client".to_string(),
                timestamp: 123,
                hmac: "a".repeat(len),
                nonce: "b".repeat(64),
            };
            prop_assert!(auth.validate().is_err());
        }

        /// Property: Any 64-char hex string is valid HMAC
        #[test]
        fn prop_hex_hmac_valid(hex_char in "[0-9a-fA-F]") {
            let auth = Authorizer {
                key_id: "client".to_string(),
                timestamp: 123,
                hmac: hex_char.repeat(64),
                nonce: "b".repeat(64),
            };
            prop_assert!(auth.validate().is_ok());
        }

        /// Property: serialisation roundtrip preserves data
        #[test]
        fn prop_serialization_roundtrip(
            key_id in "[a-zA-Z0-9]{1,128}",
            timestamp in any::<u64>(),
            hmac in "[0-9a-f]{64}",
            nonce in "[0-9a-f]{64}"
        ) {
            let auth = Authorizer {
                key_id: key_id.clone(),
                timestamp,
                hmac: hmac.clone(),
                nonce: nonce.clone(),
            };

            let json = serde_json::to_string(&auth).map_err(|e| proptest::test_runner::TestCaseError::Fail(e.to_string().into()))?;
            let decoded: Authorizer = serde_json::from_str(&json).map_err(|e| proptest::test_runner::TestCaseError::Fail(e.to_string().into()))?;

            prop_assert_eq!(&decoded.key_id, &key_id);
            prop_assert_eq!(decoded.timestamp, timestamp);
            prop_assert_eq!(&decoded.hmac, &hmac);
            prop_assert_eq!(&decoded.nonce, &nonce);
        }

        /// Property: Valid authorizers always pass validation
        #[test]
        fn prop_valid_always_validates(
            key_id in "[a-zA-Z0-9]{1,128}",
            timestamp in any::<u64>()
        ) {
            let auth = Authorizer {
                key_id,
                timestamp,
                hmac: "a".repeat(64),
                nonce: "b".repeat(64),
            };
            prop_assert!(auth.validate().is_ok());
        }

        /// Property: Validation is deterministic
        #[test]
        fn prop_validation_deterministic(
            key_id in "[a-zA-Z0-9]{1,128}",
            timestamp in any::<u64>()
        ) {
            let auth = Authorizer {
                key_id,
                timestamp,
                hmac: "a".repeat(64),
                nonce: "b".repeat(64),
            };

            let result1 = auth.validate();
            let result2 = auth.validate();

            prop_assert_eq!(result1.is_ok(), result2.is_ok());
        }

        /// Property: Nonce must be exactly 64 hex characters
        #[test]
        fn prop_nonce_length_strict(len in 0usize..128) {
            prop_assume!(len != 64);
            let auth = Authorizer {
                key_id: "client".to_string(),
                timestamp: 123,
                hmac: "a".repeat(64),
                nonce: "b".repeat(len),
            };
            prop_assert!(auth.validate().is_err());
        }

        /// Property: Clone preserves validation result
        #[test]
        fn prop_clone_preserves_validation(
            key_id in "[a-zA-Z0-9]{1,128}",
            timestamp in any::<u64>()
        ) {
            let auth = Authorizer {
                key_id,
                timestamp,
                hmac: "a".repeat(64),
                nonce: "b".repeat(64),
            };
            let cloned = auth.clone();
            prop_assert_eq!(auth.validate().is_ok(), cloned.validate().is_ok());
        }

        /// Property: Debug output never contains the actual HMAC
        #[test]
        fn prop_debug_never_leaks_hmac(hmac in "[0-9a-f]{64}") {
            let auth = Authorizer {
                key_id: "client".to_string(),
                timestamp: 123,
                hmac: hmac.clone(),
                nonce: "b".repeat(64),
            };
            let debug = format!("{:?}", auth);
            // 64 identical chars could match "[REDACTED]" substring coincidentally,
            // so only assert when the hmac is not all-identical characters
            if hmac.chars().collect::<std::collections::HashSet<_>>().len() > 1 {
                prop_assert!(!debug.contains(&hmac));
            }
        }

        /// Property: Debug output never contains the actual nonce
        #[test]
        fn prop_debug_never_leaks_nonce(nonce in "[0-9a-f]{64}") {
            let auth = Authorizer {
                key_id: "client".to_string(),
                timestamp: 123,
                hmac: "a".repeat(64),
                nonce: nonce.clone(),
            };
            let debug = format!("{:?}", auth);
            if nonce.chars().collect::<std::collections::HashSet<_>>().len() > 1 {
                prop_assert!(!debug.contains(&nonce));
            }
        }
    }

    /* ========================================================================== */
    /*                    validate() – VALIDATION ORDER TESTS                    */
    /* ========================================================================== */

    #[test]
    fn test_validate_empty_key_id_before_checking_hmac() -> Result<(), Box<dyn std::error::Error>> {
        // Both key_id and hmac are invalid; key_id should be checked first
        let auth = Authorizer {
            key_id: "".to_string(),
            timestamp: 123,
            hmac: "too_short".to_string(),
            nonce: "b".repeat(64),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("empty"));
        Ok(())
    }

    #[test]
    fn test_validate_key_id_too_long_before_checking_hmac() -> Result<(), Box<dyn std::error::Error>>
    {
        let auth = Authorizer {
            key_id: "a".repeat(200),
            timestamp: 123,
            hmac: "short".to_string(),
            nonce: "b".repeat(64),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("too long"));
        Ok(())
    }

    #[test]
    fn test_validate_key_id_invalid_chars_before_checking_hmac(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "has space".to_string(),
            timestamp: 123,
            hmac: "short".to_string(),
            nonce: "b".repeat(64),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("invalid characters"));
        Ok(())
    }

    #[test]
    fn test_validate_hmac_error_before_nonce() -> Result<(), Box<dyn std::error::Error>> {
        // key_id valid, hmac invalid, nonce invalid; hmac error should come first
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "short".to_string(),
            nonce: "short".to_string(),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("hmac"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    validate() – HMAC EDGE CASES                          */
    /* ========================================================================== */

    #[test]
    fn test_validate_hmac_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: String::new(),
            nonce: "b".repeat(64),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("64-character"));
        Ok(())
    }

    #[test]
    fn test_validate_hmac_all_zeros() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "0".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_hmac_all_f() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "f".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_hmac_with_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: format!("{} ", "a".repeat(63)), // space is not hex
            nonce: "b".repeat(64),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("hex"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    validate() – NONCE ADDITIONAL EDGE CASES              */
    /* ========================================================================== */

    #[test]
    fn test_validate_nonce_all_zeros() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "0".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_nonce_all_uppercase_hex() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "ABCDEF1234567890".repeat(4),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_nonce_with_spaces_inside() -> Result<(), Box<dyn std::error::Error>> {
        // 64 chars but contains spaces (not hex)
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: format!("{} {}", "a".repeat(31), "b".repeat(32)),
        };
        let err = auth.validate().err().ok_or("expected error")?;
        assert!(err.contains("hex"));
        Ok(())
    }

    #[test]
    fn test_validate_nonce_with_newline() {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: format!("{}\n{}", "a".repeat(32), "b".repeat(31)),
        };
        assert!(auth.validate().is_err());
    }

    /* ========================================================================== */
    /*                    validate() – key_id CHARACTER EDGE CASES              */
    /* ========================================================================== */

    #[test]
    fn test_validate_key_id_del_character() {
        // DEL (0x7F) is ASCII but not graphic
        let auth = Authorizer {
            key_id: format!("client{}123", '\x7F'),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_validate_key_id_null_byte() {
        let auth = Authorizer {
            key_id: format!("client{}123", '\x00'),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_validate_key_id_single_char() {
        let auth = Authorizer {
            key_id: "x".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_tilde_valid() {
        // Tilde is ASCII graphic
        let auth = Authorizer {
            key_id: "~client~".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_validate_key_id_backslash_valid() {
        let auth = Authorizer {
            key_id: r"client\123".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    /* ========================================================================== */
    /*                    Debug FORMAT TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_debug_contains_struct_name() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        assert!(debug.contains("Authorizer"));
    }

    #[test]
    fn test_debug_contains_field_names() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        assert!(debug.contains("key_id"));
        assert!(debug.contains("timestamp"));
        assert!(debug.contains("hmac"));
        assert!(debug.contains("nonce"));
    }

    #[test]
    fn test_debug_redaction_count() {
        let auth = create_valid_authorizer();
        let debug = format!("{:?}", auth);
        let redacted_count = debug.matches("[REDACTED]").count();
        // Both hmac and nonce should be redacted
        assert_eq!(redacted_count, 2);
    }

    /* ========================================================================== */
    /*                    SERDE EDGE CASES                                       */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_timestamp_as_string_fails() {
        let json = r#"{"keyId":"test","timestamp":"not_a_number","hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_null_key_id_fails() {
        let json = r#"{"keyId":null,"timestamp":123,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_null_timestamp_fails() {
        let json = r#"{"keyId":"test","timestamp":null,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_null_hmac_fails() {
        let json = r#"{"keyId":"test","timestamp":123,"hmac":null,"nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_null_nonce_fails() {
        let json = r#"{"keyId":"test","timestamp":123,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":null}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_negative_timestamp_fails() {
        let json = r#"{"keyId":"test","timestamp":-1,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty_json_object_fails() {
        let json = r#"{}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_contains_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let auth = create_valid_authorizer();
        let json = serde_json::to_string(&auth)?;
        assert!(json.contains("keyId"));
        assert!(json.contains("timestamp"));
        assert!(json.contains("hmac"));
        assert!(json.contains("nonce"));
        Ok(())
    }

    #[test]
    fn test_serialize_key_id_camel_case() -> Result<(), Box<dyn std::error::Error>> {
        let auth = create_valid_authorizer();
        let json = serde_json::to_string(&auth)?;
        // Must be "keyId" not "key_id"
        assert!(json.contains("\"keyId\""));
        assert!(!json.contains("\"key_id\""));
        Ok(())
    }

    #[test]
    fn test_deserialize_snake_case_key_id_fails() {
        // "key_id" instead of "keyId" must fail
        let json = r#"{"key_id":"test","timestamp":123,"hmac":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;
        let result: Result<Authorizer, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    CLONE + VALIDATE INTERACTION                           */
    /* ========================================================================== */

    #[test]
    fn test_clone_of_valid_validates() {
        let auth = create_valid_authorizer();
        let cloned = auth.clone();
        assert!(cloned.validate().is_ok());
    }

    #[test]
    fn test_clone_of_invalid_still_invalid() {
        let auth = Authorizer {
            key_id: "".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let cloned = auth.clone();
        assert!(cloned.validate().is_err());
    }

    #[test]
    fn test_clone_fields_independent() {
        let auth = create_valid_authorizer();
        let mut cloned = auth.clone();
        cloned.key_id = "different".to_string();
        // Original should be unaffected
        assert_eq!(auth.key_id, "client-123");
        assert_eq!(cloned.key_id, "different");
    }
}
