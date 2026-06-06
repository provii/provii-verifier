// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Input validation and sanitisation for the verifier API.
//!
//! Enforces size limits, character set restrictions, Unicode normalisation (NFC),
//! and pattern validation on all untrusted input before it reaches business logic.
//! Every public validator returns [`ApiResult`] so callers propagate rejections
//! without panicking.
#![forbid(unsafe_code)]

use crate::error::{ApiError, ApiResult};
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

// Use worker console_log on WASM, no-op macro for native testing
#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// Maximum sizes for various fields to prevent DoS.
pub struct FieldSizeLimit {
    /// Maximum encoded size for credential identifiers (32 bytes base64url encoded).
    pub cred_id: usize,
    /// Maximum encoded size for date-of-birth commitments (32 bytes base64url encoded).
    pub dob_commitment: usize,
    /// Maximum allowed size for the bulletproof range proof.
    pub bulletproof: usize,
    /// Maximum allowed size for credential signatures.
    pub cred_sig: usize,
    /// Maximum allowed size for wallet signatures.
    pub wallet_sig: usize,
    /// Maximum encoded size for user public keys (32 bytes base64url encoded).
    pub user_pub_key: usize,
    /// Maximum encoded size for nonces (32 bytes base64url encoded).
    pub nonce: usize,
    /// Maximum length for PKCE code challenges (RFC 7636).
    pub code_challenge: usize,
    /// Maximum length for PKCE code verifiers (RFC 7636).
    pub code_verifier: usize,
    /// Maximum length for origin strings.
    pub origin: usize,
    /// Maximum length for session identifiers (UUID string length).
    pub sid: usize,
    /// Default cap for general-purpose strings.
    pub general_string: usize,
}

impl Default for FieldSizeLimit {
    fn default() -> Self {
        Self {
            cred_id: 64,
            dob_commitment: 64,
            bulletproof: 10_240,
            cred_sig: 1_024,
            wallet_sig: 1_024,
            user_pub_key: 64,
            nonce: 64,
            code_challenge: 128,
            code_verifier: 128,
            origin: 255,
            sid: 36,
            general_string: 1_024,
        }
    }
}

/// Validation rules governing how raw input is sanitised.
pub struct ValidationRules {
    /// Per-field byte-length caps (DoS prevention).
    pub size_limits: FieldSizeLimit,
    /// When `false` (the default), any embedded `\0` causes immediate rejection.
    pub allow_null_bytes: bool,
    /// When `true` (the default), leading and trailing whitespace is trimmed
    /// before length checking.
    pub strip_whitespace: bool,
    /// When `true` (the default), strings are NFC-normalised after trimming.
    pub normalize_unicode: bool,
}

impl Default for ValidationRules {
    fn default() -> Self {
        Self {
            size_limits: FieldSizeLimit::default(),
            allow_null_bytes: false,
            strip_whitespace: true,
            normalize_unicode: true,
        }
    }
}

/// Input validator combining size limits, pattern matching, and sanitisation.
pub struct InputValidator {
    rules: ValidationRules,
    patterns: HashMap<String, Regex>,
}

impl Default for InputValidator {
    fn default() -> Self {
        // All patterns are compile-time constant literals, so regex compilation
        // cannot fail in practice. If it does, we fall back to an empty map and
        // validation methods will reject all inputs (fail-closed).
        Self::try_new().unwrap_or_else(|_| Self {
            rules: ValidationRules::default(),
            patterns: HashMap::new(),
        })
    }
}

impl InputValidator {
    /// Fallible constructor that compiles all validation regex patterns.
    fn try_new() -> Result<Self, regex::Error> {
        let mut patterns = HashMap::new();

        patterns.insert(
            "uuid".to_string(),
            Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")?,
        );
        patterns.insert("base64url".to_string(), Regex::new(r"^[A-Za-z0-9_-]+$")?);
        patterns.insert(
            "pkce".to_string(),
            Regex::new(r"^[A-Za-z0-9\-._~]{43,128}$")?,
        );
        patterns.insert(
            "origin".to_string(),
            Regex::new(r"^https?://[a-zA-Z0-9\-.]+(:[0-9]+)?$")?,
        );
        patterns.insert(
            "safe_string".to_string(),
            Regex::new(r"^[A-Za-z0-9\-._~ ]+$")?,
        );

        Ok(Self {
            rules: ValidationRules::default(),
            patterns,
        })
    }

    /// Create a validator with custom rules.
    pub fn with_rules(rules: ValidationRules) -> Self {
        Self {
            rules,
            ..Default::default()
        }
    }

    /// Validate and sanitise a string input.
    pub fn validate_string(
        &self,
        value: &str,
        field_name: &str,
        max_size: usize,
    ) -> ApiResult<String> {
        // Reject embedded null bytes unless explicitly allowed.
        if !self.rules.allow_null_bytes && value.contains('\0') {
            return Err(ApiError::BadRequest(Some(format!(
                "{} contains null bytes",
                field_name
            ))));
        }

        // Trim leading and trailing whitespace when configured.
        // This must be done BEFORE length checking to allow inputs like "  UUID  ".
        let value = if self.rules.strip_whitespace {
            value.trim()
        } else {
            value
        };

        // Enforce the maximum length constraint AFTER trimming.
        if value.len() > max_size {
            return Err(ApiError::BadRequest(Some(format!(
                "{} exceeds maximum size of {} bytes",
                field_name, max_size
            ))));
        }

        // Normalize Unicode to NFC when configured.
        let value = if self.rules.normalize_unicode {
            unicode_normalization::UnicodeNormalization::nfc(value).collect::<String>()
        } else {
            value.to_string()
        };

        Ok(value)
    }

    /// Validate base64url encoded data with size limits.
    pub fn validate_base64url(
        &self,
        value: &str,
        field_name: &str,
        max_decoded_size: usize,
    ) -> ApiResult<Vec<u8>> {
        // Reject padding or non-url-safe characters.
        if value.contains('=') || value.contains('+') || value.contains('/') {
            return Err(ApiError::BadRequest(Some(format!(
                "{} must be base64url without padding",
                field_name
            ))));
        }

        // Ensure the value conforms to the base64url character set.
        let base64url_pat = self
            .patterns
            .get("base64url")
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("missing base64url pattern")))?;
        if !base64url_pat.is_match(value) {
            return Err(ApiError::BadRequest(Some(format!(
                "{} contains invalid base64url characters",
                field_name
            ))));
        }

        // Decode the value and enforce the decoded size limit.
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ApiError::BadRequest(Some(format!("Invalid {} format", field_name))))?;

        if decoded.len() > max_decoded_size {
            return Err(ApiError::BadRequest(Some(format!(
                "{} decoded size {} exceeds maximum {}",
                field_name,
                decoded.len(),
                max_decoded_size
            ))));
        }

        Ok(decoded)
    }

    /// Validate a fixed-size base64url field.
    pub fn validate_base64url_fixed(
        &self,
        value: &str,
        field_name: &str,
        expected_size: usize,
    ) -> ApiResult<Vec<u8>> {
        let decoded = self.validate_base64url(value, field_name, expected_size)?;

        if decoded.len() != expected_size {
            return Err(ApiError::BadRequest(Some(format!(
                "{} must be exactly {} bytes",
                field_name, expected_size
            ))));
        }

        Ok(decoded)
    }

    /// Validate a UUID field.
    pub fn validate_uuid(&self, value: &str, field_name: &str) -> ApiResult<uuid::Uuid> {
        let sanitized = self.validate_string(value, field_name, self.rules.size_limits.sid)?;

        let uuid_pat = self
            .patterns
            .get("uuid")
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("missing uuid pattern")))?;
        if !uuid_pat.is_match(&sanitized.to_lowercase()) {
            return Err(ApiError::BadRequest(Some(format!(
                "{} is not a valid UUID",
                field_name
            ))));
        }

        uuid::Uuid::parse_str(&sanitized)
            .map_err(|_| ApiError::BadRequest(Some(format!("Invalid {}", field_name))))
    }

    /// Validate an origin string.
    pub fn validate_origin(&self, origin: &str) -> ApiResult<String> {
        let sanitized = self.validate_string(origin, "origin", self.rules.size_limits.origin)?;

        // Apply additional scheme-based safety checks FIRST.
        // This is important from a security perspective.
        if sanitized.contains("javascript:")
            || sanitized.contains("data:")
            || sanitized.contains("vbscript:")
        {
            // AL-043: Structured audit log for malicious origin detection.
            // AuditLogger is unavailable here (sync context); callers with
            // AuditLogger access should also call log_malicious_origin_detected().
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "{{\"audit\":true,\"event\":\"malicious_origin_detected\",\"severity\":\"critical\",\"origin\":\"{}\",\"reason\":\"scheme_injection\"}}",
                self.sanitize_for_logging(&sanitized, 200)
            );
            return Err(ApiError::BadRequest(Some("Malicious origin".to_string())));
        }

        // Check against the origin pattern.
        let origin_pat = self
            .patterns
            .get("origin")
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("missing origin pattern")))?;
        if !origin_pat.is_match(&sanitized) {
            return Err(ApiError::BadRequest(Some(
                "Invalid origin format".to_string(),
            )));
        }

        Ok(sanitized)
    }

    /// Validate a PKCE `code_verifier`.
    pub fn validate_code_verifier(&self, value: &str) -> ApiResult<String> {
        if value.len() < 43 || value.len() > 128 {
            return Err(ApiError::BadRequest(Some(
                "code_verifier must be 43-128 characters".to_string(),
            )));
        }

        let pkce_pat = self
            .patterns
            .get("pkce")
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("missing pkce pattern")))?;
        if !pkce_pat.is_match(value) {
            return Err(ApiError::BadRequest(Some(
                "code_verifier contains invalid characters".to_string(),
            )));
        }

        Ok(value.to_string())
    }

    /// Validate a PKCE `code_challenge`.
    pub fn validate_code_challenge(&self, value: &str) -> ApiResult<Vec<u8>> {
        // `code_challenge` is the SHA-256 hash of the verifier, so expect 32 bytes.
        self.validate_base64url_fixed(value, "code_challenge", 32)
    }

    /// Sanitise a string for safe logging (remove sensitive data).
    ///
    /// CIV-070: Truncation is performed at a valid UTF-8 char boundary to avoid
    /// panicking on multi-byte sequences.
    pub fn sanitize_for_logging(&self, value: &str, max_len: usize) -> String {
        let truncated = if value.len() > max_len {
            match value.get(..max_len) {
                Some(s) => s,
                None => {
                    // max_len falls inside a multi-byte character.
                    // Walk backwards to the nearest char boundary.
                    let mut end = max_len;
                    while end > 0 && !value.is_char_boundary(end) {
                        end = end.saturating_sub(1);
                    }
                    value.get(..end).unwrap_or("")
                }
            }
        } else {
            value
        };

        // Remove potential sensitive patterns.
        // First replace newlines and carriage returns with spaces,
        // then remove any remaining control characters.

        truncated
            .replace(['\n', '\r'], " ")
            .replace(|c: char| c.is_control(), "")
    }

    /// Validate the raw request size for an endpoint.
    pub fn validate_request_size(&self, size: usize, endpoint: &str) -> ApiResult<()> {
        let max_size = match endpoint {
            "/v1/challenge" | "/v1/challenge/raw" => 64 * 1024,
            "/v1/verify" => 128 * 1024,
            "/v1/challenge/*/redeem" => 8 * 1024,
            _ => 32 * 1024,
        };

        if size > max_size {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[Validation] Request size {} exceeds limit {} for endpoint {}",
                size,
                max_size,
                endpoint
            );
            return Err(ApiError::PayloadTooLarge(Some(format!(
                "Request size {} exceeds maximum {} bytes",
                size, max_size
            ))));
        }

        Ok(())
    }
}

/// Global validator instance.
pub static VALIDATOR: Lazy<InputValidator> = Lazy::new(InputValidator::default);

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::string_slice
)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    FIELD SIZE LIMIT TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_field_size_limit_defaults() {
        let limits = FieldSizeLimit::default();
        assert_eq!(limits.cred_id, 64);
        assert_eq!(limits.dob_commitment, 64);
        assert_eq!(limits.bulletproof, 10_240);
        assert_eq!(limits.cred_sig, 1_024);
        assert_eq!(limits.wallet_sig, 1_024);
        assert_eq!(limits.user_pub_key, 64);
        assert_eq!(limits.nonce, 64);
        assert_eq!(limits.code_challenge, 128);
        assert_eq!(limits.code_verifier, 128);
        assert_eq!(limits.origin, 255);
        assert_eq!(limits.sid, 36);
        assert_eq!(limits.general_string, 1_024);
    }

    /* ========================================================================== */
    /*                    VALIDATION RULES TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_validation_rules_defaults() {
        let rules = ValidationRules::default();
        assert!(!rules.allow_null_bytes);
        assert!(rules.strip_whitespace);
        assert!(rules.normalize_unicode);
    }

    /* ========================================================================== */
    /*                    STRING VALIDATION TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_validate_string_success() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_string("hello", "test_field", 100)?;
        assert_eq!(result, "hello");
        Ok(())
    }

    #[test]
    fn test_validate_string_strips_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_string("  hello world  ", "test_field", 100)?;
        assert_eq!(result, "hello world");
        Ok(())
    }

    #[test]
    fn test_validate_string_rejects_null_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_string("hello\0world", "test_field", 100);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("null bytes")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_string_rejects_oversized() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let long_string = "a".repeat(200);
        let result = validator.validate_string(&long_string, "test_field", 100);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("exceeds maximum size")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_string_empty() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_string("", "test_field", 100)?;
        assert_eq!(result, "");
        Ok(())
    }

    /* ========================================================================== */
    /*                    BASE64URL VALIDATION TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_validate_base64url_success() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // Valid base64url: "hello" -> "aGVsbG8"
        let result = validator.validate_base64url("aGVsbG8", "test_field", 10)?;
        assert_eq!(result, b"hello");
        Ok(())
    }

    #[test]
    fn test_validate_base64url_rejects_padding() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("aGVsbG8=", "test_field", 10);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("without padding")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_base64url_rejects_plus() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("aGVs+G8", "test_field", 10);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("without padding")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_base64url_rejects_slash() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("aGVs/G8", "test_field", 10);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("without padding")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_base64url_rejects_invalid_chars() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("aGVs!G8", "test_field", 10);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("invalid base64url characters")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_base64url_rejects_oversized_decoded() -> Result<(), Box<dyn std::error::Error>>
    {
        let validator = InputValidator::default();
        // "hello world" is 11 bytes
        let result = validator.validate_base64url("aGVsbG8gd29ybGQ", "test_field", 5);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("decoded size")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_base64url_urlsafe_chars() {
        let validator = InputValidator::default();
        // Test URL-safe characters (- and _)
        let result = validator.validate_base64url("aGVs-G_8", "test_field", 10);
        assert!(result.is_ok());
    }

    /* ========================================================================== */
    /*                    FIXED SIZE BASE64URL TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_validate_base64url_fixed_success() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // 32 bytes of zeros in base64url (43 chars, no padding)
        let zeros_32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = validator.validate_base64url_fixed(zeros_32, "test_field", 32)?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_validate_base64url_fixed_rejects_wrong_size() -> Result<(), Box<dyn std::error::Error>>
    {
        let validator = InputValidator::default();
        // "hello" is 5 bytes, not 32
        let result = validator.validate_base64url_fixed("aGVsbG8", "test_field", 32);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("must be exactly")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    UUID VALIDATION TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_validate_uuid_success() {
        let validator = InputValidator::default();
        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let result = validator.validate_uuid(valid_uuid, "test_uuid");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_uuid_uppercase() {
        let validator = InputValidator::default();
        let valid_uuid = "550E8400-E29B-41D4-A716-446655440000";
        let result = validator.validate_uuid(valid_uuid, "test_uuid");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_uuid_rejects_invalid_format() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("not-a-uuid", "test_uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_rejects_malformed() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("550e8400-e29b-41d4-a716", "test_uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_strips_whitespace() {
        let validator = InputValidator::default();
        let uuid_with_space = "  550e8400-e29b-41d4-a716-446655440000  ";
        let result = validator.validate_uuid(uuid_with_space, "test_uuid");
        assert!(result.is_ok());
    }

    /* ========================================================================== */
    /*                    ORIGIN VALIDATION TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_validate_origin_https() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://example.com")?;
        assert_eq!(result, "https://example.com");
        Ok(())
    }

    #[test]
    fn test_validate_origin_http() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("http://localhost");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_origin_with_port() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://example.com:8080");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_origin_with_subdomain() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://api.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_origin_rejects_javascript() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("javascript:alert(1)");
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("Malicious origin")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_origin_rejects_data() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("data:text/html,<script>alert(1)</script>");
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("Malicious origin")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_origin_rejects_vbscript() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("vbscript:msgbox(1)");
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("Malicious origin")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_origin_rejects_invalid_format() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("not-a-valid-origin");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_rejects_oversized() {
        let validator = InputValidator::default();
        let long_origin = format!("https://{}.com", "a".repeat(300));
        let result = validator.validate_origin(&long_origin);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    PKCE CODE VERIFIER TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_validate_code_verifier_success() {
        let validator = InputValidator::default();
        let verifier = "a".repeat(64);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_code_verifier_min_length() {
        let validator = InputValidator::default();
        let verifier = "a".repeat(43);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_code_verifier_max_length() {
        let validator = InputValidator::default();
        let verifier = "a".repeat(128);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_code_verifier_rejects_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let verifier = "a".repeat(42);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("43-128 characters")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_code_verifier_rejects_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let verifier = "a".repeat(129);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("43-128 characters")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_code_verifier_allowed_special_chars() {
        let validator = InputValidator::default();
        let verifier = format!("{}-._~", "a".repeat(39));
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_code_verifier_rejects_invalid_chars() -> Result<(), Box<dyn std::error::Error>>
    {
        let validator = InputValidator::default();
        let verifier = format!("{}!", "a".repeat(42));
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_err());
        assert!(
            matches!(result.err().ok_or("expected error")?, ApiError::BadRequest(Some(msg)) if msg.contains("invalid characters")),
            "Expected BadRequest error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_code_verifier_rfc7636_example() {
        let validator = InputValidator::default();
        // Example from RFC 7636
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let result = validator.validate_code_verifier(verifier);
        assert!(result.is_ok());
    }

    /* ========================================================================== */
    /*                    PKCE CODE CHALLENGE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_validate_code_challenge_success() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // 32 bytes of zeros in base64url (43 chars, no padding)
        let challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = validator.validate_code_challenge(challenge)?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_validate_code_challenge_rfc7636_example() {
        let validator = InputValidator::default();
        // Example from RFC 7636
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let result = validator.validate_code_challenge(challenge);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_code_challenge_rejects_wrong_size() {
        let validator = InputValidator::default();
        // "hello" is 5 bytes, not 32
        let result = validator.validate_code_challenge("aGVsbG8");
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    LOGGING SANITIZATION TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_sanitize_for_logging_truncates() {
        let validator = InputValidator::default();
        let long_string = "a".repeat(100);
        let result = validator.sanitize_for_logging(&long_string, 10);
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_sanitize_for_logging_removes_newlines() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("hello\nworld", 100);
        assert!(!result.contains('\n'));
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_sanitize_for_logging_removes_carriage_returns() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("hello\rworld", 100);
        assert!(!result.contains('\r'));
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_sanitize_for_logging_removes_control_chars() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("hello\x00world\x01test", 100);
        assert_eq!(result, "helloworldtest");
    }

    #[test]
    fn test_sanitize_for_logging_no_truncation() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("hello", 100);
        assert_eq!(result, "hello");
    }

    /* ========================================================================== */
    /*                    REQUEST SIZE VALIDATION TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_validate_request_size_challenge_endpoint() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(60 * 1024, "/v1/challenge");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_request_size_challenge_raw_endpoint() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(60 * 1024, "/v1/challenge/raw");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_request_size_verify_endpoint() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(120 * 1024, "/v1/verify");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_request_size_redeem_endpoint() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(7 * 1024, "/v1/challenge/*/redeem");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_request_size_default_endpoint() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(30 * 1024, "/v1/other");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_request_size_rejects_oversized_challenge(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(65 * 1024, "/v1/challenge");
        assert!(result.is_err());
        assert!(
            matches!(
                result.err().ok_or("expected error")?,
                ApiError::PayloadTooLarge(_)
            ),
            "Expected PayloadTooLarge error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_request_size_rejects_oversized_verify(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(129 * 1024, "/v1/verify");
        assert!(result.is_err());
        assert!(
            matches!(
                result.err().ok_or("expected error")?,
                ApiError::PayloadTooLarge(_)
            ),
            "Expected PayloadTooLarge error"
        );
        Ok(())
    }

    #[test]
    fn test_validate_request_size_rejects_oversized_redeem(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(9 * 1024, "/v1/challenge/*/redeem");
        assert!(result.is_err());
        assert!(
            matches!(
                result.err().ok_or("expected error")?,
                ApiError::PayloadTooLarge(_)
            ),
            "Expected PayloadTooLarge error"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    CUSTOM RULES TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_custom_rules_allow_null_bytes() {
        let rules = ValidationRules {
            allow_null_bytes: true,
            ..ValidationRules::default()
        };
        let validator = InputValidator::with_rules(rules);
        let result = validator.validate_string("hello\0world", "test_field", 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_custom_rules_no_strip_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        let rules = ValidationRules {
            strip_whitespace: false,
            ..ValidationRules::default()
        };
        let validator = InputValidator::with_rules(rules);
        let result = validator.validate_string("  hello  ", "test_field", 100)?;
        assert_eq!(result, "  hello  ");
        Ok(())
    }

    /* ========================================================================== */
    /*                    REGEX PATTERN TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_patterns_exist() {
        let validator = InputValidator::default();
        assert!(validator.patterns.contains_key("uuid"));
        assert!(validator.patterns.contains_key("base64url"));
        assert!(validator.patterns.contains_key("pkce"));
        assert!(validator.patterns.contains_key("origin"));
        assert!(validator.patterns.contains_key("safe_string"));
    }

    #[test]
    fn test_uuid_pattern_matches() {
        let validator = InputValidator::default();
        let pattern = &validator.patterns["uuid"];
        assert!(pattern.is_match("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!pattern.is_match("not-a-uuid"));
        assert!(!pattern.is_match("550e8400-e29b-41d4-a716"));
    }

    #[test]
    fn test_base64url_pattern_matches() {
        let validator = InputValidator::default();
        let pattern = &validator.patterns["base64url"];
        assert!(pattern.is_match("aGVsbG8"));
        assert!(pattern.is_match("aGVs-G_8"));
        assert!(!pattern.is_match("aGVs+G/8"));
        assert!(!pattern.is_match("aGVsbG8="));
    }

    #[test]
    fn test_pkce_pattern_matches() {
        let validator = InputValidator::default();
        let pattern = &validator.patterns["pkce"];
        assert!(pattern.is_match(&"a".repeat(43)));
        assert!(pattern.is_match(&"a".repeat(128)));
        assert!(!pattern.is_match(&"a".repeat(42)));
        assert!(!pattern.is_match(&"a".repeat(129)));
        assert!(pattern.is_match(&format!("{}-._~", "a".repeat(39))));
        assert!(!pattern.is_match(&format!("{}!", "a".repeat(42))));
    }

    #[test]
    fn test_origin_pattern_matches() {
        let validator = InputValidator::default();
        let pattern = &validator.patterns["origin"];
        assert!(pattern.is_match("https://example.com"));
        assert!(pattern.is_match("http://localhost"));
        assert!(pattern.is_match("https://example.com:8080"));
        assert!(!pattern.is_match("ftp://example.com"));
        assert!(!pattern.is_match("javascript:alert(1)"));
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Strings within size limit are accepted
        #[test]
        fn prop_validate_string_within_limit(
            s in "[a-zA-Z0-9]{1,50}",
            max_size in 51usize..200
        ) {
            let validator = InputValidator::default();
            prop_assert!(validator.validate_string(&s, "test", max_size).is_ok());
        }

        /// Property: Strings exceeding size limit are rejected
        #[test]
        fn prop_validate_string_exceeds_limit(
            len in 101usize..200,
            max_size in 1usize..100
        ) {
            let validator = InputValidator::default();
            let s = "a".repeat(len);
            prop_assert!(validator.validate_string(&s, "test", max_size).is_err());
        }

        /// Property: Null bytes are always rejected (default rules)
        #[test]
        fn prop_validate_string_rejects_null(
            prefix in "[a-zA-Z]{1,20}",
            suffix in "[a-zA-Z]{1,20}"
        ) {
            let validator = InputValidator::default();
            let s = format!("{}\0{}", prefix, suffix);
            prop_assert!(validator.validate_string(&s, "test", 100).is_err());
        }

        /// Property: Whitespace is stripped when enabled
        #[test]
        fn prop_validate_string_strips_whitespace(
            s in "[a-zA-Z0-9]{1,20}",
            leading_spaces in 0usize..10,
            trailing_spaces in 0usize..10
        ) {
            let validator = InputValidator::default();
            let padded = format!("{}{}{}", " ".repeat(leading_spaces), s, " ".repeat(trailing_spaces));
            let validated = validator.validate_string(&padded, "test", 100)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{}", e)))?;
            prop_assert_eq!(validated.trim(), s.trim());
        }

        /// Property: Valid base64url characters are accepted
        #[test]
        fn prop_validate_base64url_valid_chars(
            s in "[A-Za-z0-9_-]{4,20}"
        ) {
            let validator = InputValidator::default();
            // May fail decoding, but shouldn't fail character validation
            let _ = validator.validate_base64url(&s, "test", 1000);
        }

        /// Property: Base64url rejects padding
        #[test]
        fn prop_validate_base64url_rejects_padding(
            s in "[A-Za-z0-9_-]{4,20}"
        ) {
            let validator = InputValidator::default();
            let with_padding = format!("{}=", s);
            prop_assert!(validator.validate_base64url(&with_padding, "test", 1000).is_err());
        }

        /// Property: Base64url rejects standard base64 characters
        #[test]
        fn prop_validate_base64url_rejects_plus_slash(
            prefix in "[A-Za-z0-9]{2,10}",
            invalid_char in prop::sample::select(vec!['+', '/'])
        ) {
            let validator = InputValidator::default();
            let s = format!("{}{}", prefix, invalid_char);
            prop_assert!(validator.validate_base64url(&s, "test", 1000).is_err());
        }

        /// Property: UUID pattern matches valid UUIDs
        #[test]
        fn prop_validate_uuid_valid_format(
            part1 in "[0-9a-f]{8}",
            part2 in "[0-9a-f]{4}",
            part3 in "[0-9a-f]{4}",
            part4 in "[0-9a-f]{4}",
            part5 in "[0-9a-f]{12}"
        ) {
            let validator = InputValidator::default();
            let uuid_str = format!("{}-{}-{}-{}-{}", part1, part2, part3, part4, part5);
            let result = validator.validate_uuid(&uuid_str, "test_uuid");
            prop_assert!(result.is_ok());
        }

        /// Property: UUID validation rejects wrong formats
        #[test]
        fn prop_validate_uuid_rejects_invalid(
            s in "[a-z]{5,20}"
        ) {
            let validator = InputValidator::default();
            prop_assume!(!s.contains('-'));
            let result = validator.validate_uuid(&s, "test_uuid");
            prop_assert!(result.is_err());
        }

        /// Property: HTTPS origins are accepted
        #[test]
        fn prop_validate_origin_https(
            domain in "[a-z]{3,20}",
            tld in prop::sample::select(vec!["com", "org", "net"])
        ) {
            let validator = InputValidator::default();
            let origin = format!("https://{}.{}", domain, tld);
            prop_assert!(validator.validate_origin(&origin).is_ok());
        }

        /// Property: HTTP origins are accepted
        #[test]
        fn prop_validate_origin_http(
            domain in "[a-z]{3,20}",
            tld in prop::sample::select(vec!["com", "org", "net"])
        ) {
            let validator = InputValidator::default();
            let origin = format!("http://{}.{}", domain, tld);
            prop_assert!(validator.validate_origin(&origin).is_ok());
        }

        /// Property: Origins with ports are accepted
        #[test]
        fn prop_validate_origin_with_port(
            domain in "[a-z]{3,15}",
            port in 1u16..=65535
        ) {
            let validator = InputValidator::default();
            let origin = format!("https://{}.com:{}", domain, port);
            prop_assert!(validator.validate_origin(&origin).is_ok());
        }

        /// Property: Malicious schemes are rejected
        #[test]
        fn prop_validate_origin_rejects_malicious(
            scheme in prop::sample::select(vec!["javascript:", "data:", "vbscript:"])
        ) {
            let validator = InputValidator::default();
            let origin = format!("{}alert(1)", scheme);
            prop_assert!(validator.validate_origin(&origin).is_err());
        }

        /// Property: PKCE verifiers within 43-128 chars are accepted
        #[test]
        fn prop_validate_code_verifier_valid_length(
            len in 43usize..=128
        ) {
            let validator = InputValidator::default();
            let verifier = "a".repeat(len);
            prop_assert!(validator.validate_code_verifier(&verifier).is_ok());
        }

        /// Property: PKCE verifiers shorter than 43 are rejected
        #[test]
        fn prop_validate_code_verifier_too_short(
            len in 1usize..43
        ) {
            let validator = InputValidator::default();
            let verifier = "a".repeat(len);
            prop_assert!(validator.validate_code_verifier(&verifier).is_err());
        }

        /// Property: PKCE verifiers longer than 128 are rejected
        #[test]
        fn prop_validate_code_verifier_too_long(
            len in 129usize..200
        ) {
            let validator = InputValidator::default();
            let verifier = "a".repeat(len);
            prop_assert!(validator.validate_code_verifier(&verifier).is_err());
        }

        /// Property: PKCE verifiers with allowed characters are accepted
        #[test]
        fn prop_validate_code_verifier_allowed_chars(
            base in "[a-zA-Z0-9]{40}",
            special in prop::sample::select(vec!["-", ".", "_", "~"])
        ) {
            let validator = InputValidator::default();
            let verifier = format!("{}{}", base, special.repeat(3));
            prop_assert!(validator.validate_code_verifier(&verifier).is_ok());
        }

        /// Property: PKCE verifiers with invalid characters are rejected
        #[test]
        fn prop_validate_code_verifier_invalid_chars(
            base in "[a-zA-Z0-9]{40}",
            invalid in prop::sample::select(vec!["!", "@", "#", "$", "%", "&", "*", "+", "="])
        ) {
            let validator = InputValidator::default();
            let verifier = format!("{}{}", base, invalid.repeat(3));
            prop_assert!(validator.validate_code_verifier(&verifier).is_err());
        }

        /// Property: Logging sanitization removes control characters
        #[test]
        fn prop_sanitize_removes_control_chars(
            s in "[a-zA-Z0-9 ]{10,50}"
        ) {
            let validator = InputValidator::default();
            let with_control = format!("{}\\x00\\x01", s);
            let sanitized = validator.sanitize_for_logging(&with_control, 100);
            prop_assert!(!sanitized.chars().any(|c| c.is_control()));
        }

        /// Property: Logging sanitization respects max length
        #[test]
        fn prop_sanitize_respects_max_length(
            len in 50usize..200,
            max_len in 10usize..49
        ) {
            let validator = InputValidator::default();
            let s = "a".repeat(len);
            let sanitized = validator.sanitize_for_logging(&s, max_len);
            prop_assert!(sanitized.len() <= max_len);
        }

        /// Property: Logging sanitization removes newlines
        #[test]
        fn prop_sanitize_removes_newlines(
            prefix in "[a-zA-Z]{5,20}",
            suffix in "[a-zA-Z]{5,20}"
        ) {
            let validator = InputValidator::default();
            let s = format!("{}\n{}", prefix, suffix);
            let sanitized = validator.sanitize_for_logging(&s, 100);
            prop_assert!(!sanitized.contains('\n'));
        }

        /// Property: Request size validation accepts sizes within limits
        #[test]
        fn prop_validate_request_size_within_limit(
            size in 1usize..60000
        ) {
            let validator = InputValidator::default();
            prop_assert!(validator.validate_request_size(size, "/v1/challenge").is_ok());
        }

        /// Property: Request size validation rejects oversized requests
        #[test]
        fn prop_validate_request_size_exceeds_limit(
            size in 65537usize..100000
        ) {
            let validator = InputValidator::default();
            // 64KB = 65536 bytes, so 65537+ should fail
            prop_assert!(validator.validate_request_size(size, "/v1/challenge").is_err());
        }

        /// Property: Different endpoints have different limits
        #[test]
        fn prop_validate_request_size_endpoint_specific(
            size in 65537usize..70000
        ) {
            let validator = InputValidator::default();
            // Should fail for /v1/challenge (64KB = 65536 limit)
            prop_assert!(validator.validate_request_size(size, "/v1/challenge").is_err());
            // Should succeed for /v1/verify (128KB = 131072 limit)
            prop_assert!(validator.validate_request_size(size, "/v1/verify").is_ok());
        }

        /// Property: Empty strings pass validation if size limit allows
        #[test]
        fn prop_validate_empty_string(max_size in 1usize..100) {
            let validator = InputValidator::default();
            prop_assert!(validator.validate_string("", "test", max_size).is_ok());
        }

        /// Property: UUID case insensitivity
        #[test]
        fn prop_validate_uuid_case_insensitive(
            part1 in "[0-9A-F]{8}",
            part2 in "[0-9a-f]{4}",
            part3 in "[0-9A-F]{4}",
            part4 in "[0-9a-f]{4}",
            part5 in "[0-9A-F]{12}"
        ) {
            let validator = InputValidator::default();
            let uuid_str = format!("{}-{}-{}-{}-{}", part1, part2, part3, part4, part5);
            // Should accept mixed case
            prop_assert!(validator.validate_uuid(&uuid_str, "test_uuid").is_ok());
        }

        /// Property: Origin subdomains are accepted
        #[test]
        fn prop_validate_origin_subdomains(
            subdomain in "[a-z]{3,10}",
            domain in "[a-z]{3,10}",
            tld in prop::sample::select(vec!["com", "org", "net"])
        ) {
            let validator = InputValidator::default();
            let origin = format!("https://{}.{}.{}", subdomain, domain, tld);
            prop_assert!(validator.validate_origin(&origin).is_ok());
        }

        /// Property: Base64url decoded size enforcement
        #[test]
        fn prop_validate_base64url_decoded_size(
            // Generate valid base64url by using byte sequences
            len in 10usize..50
        ) {
            let validator = InputValidator::default();
            let bytes = vec![b'A'; len];
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

            // Should fail if max_decoded_size < len
            if len > 40 {
                prop_assert!(validator.validate_base64url(&encoded, "test", 40).is_err());
            }
            // Should succeed if max_decoded_size >= len
            prop_assert!(validator.validate_base64url(&encoded, "test", len + 10).is_ok());
        }

        /// Property: Code challenge must be exactly 32 bytes decoded
        #[test]
        fn prop_validate_code_challenge_size(
            len in 20usize..50
        ) {
            let validator = InputValidator::default();
            let bytes = vec![b'A'; len];
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

            if len == 32 {
                prop_assert!(validator.validate_code_challenge(&encoded).is_ok());
            } else {
                prop_assert!(validator.validate_code_challenge(&encoded).is_err());
            }
        }

        /// Property: Origin must start with http:// or https://
        #[test]
        fn prop_validate_origin_scheme_required(
            domain in "[a-z]{5,15}"
        ) {
            let validator = InputValidator::default();
            // Without scheme should fail
            let no_scheme = format!("{}.com", domain);
            prop_assert!(validator.validate_origin(&no_scheme).is_err());
            // With https scheme should pass
            let with_https = format!("https://{}.com", domain);
            prop_assert!(validator.validate_origin(&with_https).is_ok());
        }

        /// Property: Logging sanitization is idempotent
        #[test]
        fn prop_sanitize_idempotent(
            s in "[a-zA-Z0-9 ]{10,50}"
        ) {
            let validator = InputValidator::default();
            let once = validator.sanitize_for_logging(&s, 100);
            let twice = validator.sanitize_for_logging(&once, 100);
            prop_assert_eq!(once, twice);
        }

        /// Property: Fixed-size base64url validation
        #[test]
        fn prop_validate_base64url_fixed_exact_size(
            expected_size in 16usize..64,
            actual_size in 16usize..64
        ) {
            let validator = InputValidator::default();
            let bytes = vec![b'A'; actual_size];
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

            let result = validator.validate_base64url_fixed(&encoded, "test", expected_size);
            if actual_size == expected_size {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        }

        /// Property: Whitespace-only strings become empty after trimming
        #[test]
        fn prop_validate_string_whitespace_only(
            spaces in 1usize..50
        ) {
            let validator = InputValidator::default();
            let s = " ".repeat(spaces);
            let validated = validator.validate_string(&s, "test", 100)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{}", e)))?;
            prop_assert_eq!(validated, "");
        }
    }

    #[test]
    fn test_global_validator_instance() -> Result<(), Box<dyn std::error::Error>> {
        // Test that the global VALIDATOR instance works correctly
        let result = VALIDATOR.validate_string("test", "field", 100)?;
        assert_eq!(result, "test");
        Ok(())
    }

    #[test]
    fn test_unicode_normalization_nfd_to_nfc() -> Result<(), Box<dyn std::error::Error>> {
        // Test Unicode normalisation converts NFD to NFC
        let validator = InputValidator::default();

        // "é" can be represented as:
        // NFC: U+00E9 (single character)
        // NFD: U+0065 U+0301 (e + combining acute accent)
        let nfd = "e\u{0301}"; // NFD form
        let normalized = validator.validate_string(nfd, "test", 100)?;
        // After NFC normalisation, should be a single character
        assert_eq!(normalized, "\u{00E9}"); // NFC form
        Ok(())
    }

    #[test]
    fn test_unicode_normalization_with_combining_characters(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test Unicode normalisation with multiple combining characters
        let validator = InputValidator::default();

        // "ñ" in NFD is "n" + combining tilde
        let nfd = "n\u{0303}"; // NFD form of ñ
        let result = validator.validate_string(nfd, "test", 100);
        assert!(result.is_ok());

        let normalized = result?;
        assert_eq!(normalized, "\u{00F1}"); // NFC form of ñ
        Ok(())
    }

    #[test]
    fn test_combined_validation_rules_all_enabled() -> Result<(), Box<dyn std::error::Error>> {
        // Test with all validation rules enabled
        let rules = ValidationRules {
            size_limits: FieldSizeLimit::default(),
            allow_null_bytes: false,
            strip_whitespace: true,
            normalize_unicode: true,
        };
        let validator = InputValidator::with_rules(rules);

        // Test with whitespace, Unicode, no null bytes
        let input = "  e\u{0301}  "; // Whitespace + NFD Unicode
        let result = validator.validate_string(input, "test", 100);
        assert!(result.is_ok());

        let validated = result?;
        // Should be trimmed and normalised
        assert_eq!(validated, "\u{00E9}"); // Trimmed and NFC normalised
        Ok(())
    }

    #[test]
    fn test_combined_validation_rules_all_disabled() -> Result<(), Box<dyn std::error::Error>> {
        // Test with all validation rules disabled
        let rules = ValidationRules {
            size_limits: FieldSizeLimit::default(),
            allow_null_bytes: true,
            strip_whitespace: false,
            normalize_unicode: false,
        };
        let validator = InputValidator::with_rules(rules);

        // Test with whitespace, Unicode, null bytes
        let input = "  hello\0world  ";
        let result = validator.validate_string(input, "test", 100);
        assert!(result.is_ok());

        let validated = result?;
        // Should preserve everything (no trimming, no normalisation, allows null)
        assert_eq!(validated, "  hello\0world  ");
        Ok(())
    }

    #[test]
    fn test_multiple_validation_failures_in_sequence() -> Result<(), Box<dyn std::error::Error>> {
        // Test that validation correctly reports the first failure in a sequence
        let validator = InputValidator::default();

        // First validate a bad UUID
        let bad_uuid_result = validator.validate_uuid("not-a-uuid", "uuid");
        assert!(bad_uuid_result.is_err());

        // Then validate a bad origin
        let bad_origin_result = validator.validate_origin("javascript:alert(1)");
        assert!(bad_origin_result.is_err());

        // Then validate a bad base64url
        let bad_b64_result = validator.validate_base64url("invalid!@#", "b64", 100);
        assert!(bad_b64_result.is_err());

        // Verify all failed with appropriate errors
        assert!(matches!(
            bad_uuid_result.err().ok_or("expected error")?,
            ApiError::BadRequest(_)
        ));
        assert!(matches!(
            bad_origin_result.err().ok_or("expected error")?,
            ApiError::BadRequest(_)
        ));
        assert!(matches!(
            bad_b64_result.err().ok_or("expected error")?,
            ApiError::BadRequest(_)
        ));
        Ok(())
    }

    #[test]
    fn test_all_field_size_limits_integration() {
        // Test that all field size limits work correctly together
        let validator = InputValidator::default();
        let limits = &validator.rules.size_limits;

        // Test each field size limit
        let result1 =
            validator.validate_string(&"a".repeat(limits.origin), "origin", limits.origin);
        assert!(result1.is_ok());

        let result2 =
            validator.validate_string(&"a".repeat(limits.origin + 1), "origin", limits.origin);
        assert!(result2.is_err());

        let result3 = validator.validate_string(&"a".repeat(limits.sid), "sid", limits.sid);
        assert!(result3.is_ok());

        let result4 = validator.validate_string(
            &"a".repeat(limits.general_string),
            "general",
            limits.general_string,
        );
        assert!(result4.is_ok());
    }

    #[test]
    fn regex_constants_compile() {
        // Force the global VALIDATOR (Lazy<InputValidator>) to initialise,
        // which compiles all 5 static regexes. If any pattern is invalid the
        // expect("BUG: ...") will panic here rather than in production.
        let v = &*VALIDATOR;
        assert!(v.patterns.contains_key("uuid"));
        assert!(v.patterns.contains_key("base64url"));
        assert!(v.patterns.contains_key("pkce"));
        assert!(v.patterns.contains_key("origin"));
        assert!(v.patterns.contains_key("safe_string"));
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_string edge cases                   */
    /* ========================================================================== */

    #[test]
    fn test_validate_string_exact_max_size() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let exact = "a".repeat(100);
        let result = validator.validate_string(&exact, "field", 100)?;
        assert_eq!(result.len(), 100);
        Ok(())
    }

    #[test]
    fn test_validate_string_one_over_max_size() {
        let validator = InputValidator::default();
        let over = "a".repeat(101);
        let result = validator.validate_string(&over, "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_string_whitespace_trimmed_then_under_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Input is 104 bytes with whitespace, but after trim it is 100, which is exactly at limit.
        let validator = InputValidator::default();
        let input = format!("  {}  ", "a".repeat(100));
        let result = validator.validate_string(&input, "field", 100)?;
        assert_eq!(result.len(), 100);
        Ok(())
    }

    #[test]
    fn test_validate_string_whitespace_trimmed_still_over_limit() {
        // Even after trimming, the string is still over limit.
        let validator = InputValidator::default();
        let input = format!("  {}  ", "a".repeat(101));
        let result = validator.validate_string(&input, "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_string_no_strip_whitespace_over_limit() {
        // Without stripping, the whitespace counts towards the limit.
        let rules = ValidationRules {
            strip_whitespace: false,
            ..ValidationRules::default()
        };
        let validator = InputValidator::with_rules(rules);
        let input = format!("  {}  ", "a".repeat(97)); // 101 bytes total
        let result = validator.validate_string(&input, "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_string_no_unicode_normalization() -> Result<(), Box<dyn std::error::Error>> {
        let rules = ValidationRules {
            normalize_unicode: false,
            ..ValidationRules::default()
        };
        let validator = InputValidator::with_rules(rules);
        let nfd = "e\u{0301}"; // NFD: two code points
        let result = validator.validate_string(nfd, "field", 100)?;
        // Without normalisation the NFD form should be preserved (2 code points).
        assert_eq!(result, "e\u{0301}");
        Ok(())
    }

    #[test]
    fn test_validate_string_null_byte_at_start() {
        let validator = InputValidator::default();
        let result = validator.validate_string("\0hello", "field", 100);
        assert!(result.is_err());
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("null bytes")
        ));
    }

    #[test]
    fn test_validate_string_null_byte_at_end() {
        let validator = InputValidator::default();
        let result = validator.validate_string("hello\0", "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_string_only_null_bytes() {
        let validator = InputValidator::default();
        let result = validator.validate_string("\0\0\0", "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_string_max_size_zero() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // Empty string with max_size 0 should succeed.
        let result = validator.validate_string("", "field", 0)?;
        assert_eq!(result, "");
        Ok(())
    }

    #[test]
    fn test_validate_string_max_size_zero_non_empty() {
        let validator = InputValidator::default();
        let result = validator.validate_string("a", "field", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_string_multibyte_unicode_within_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // 4-byte UTF-8 emoji
        let result = validator.validate_string("\u{1F600}", "field", 10)?;
        assert!(!result.is_empty());
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_base64url edge cases                */
    /* ========================================================================== */

    #[test]
    fn test_validate_base64url_empty_string() {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("", "field", 100);
        // Empty string does not match ^[A-Za-z0-9_-]+$ (requires at least one char).
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base64url_single_char() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // Single valid base64url char: 'A' decodes to partial byte.
        // base64url "AA" decodes to [0x00].
        let result = validator.validate_base64url("AA", "field", 100)?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn test_validate_base64url_decoded_size_exact_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let validator = InputValidator::default();
        // 5 bytes encodes to "aGVsbG8" (7 chars).
        let result = validator.validate_base64url("aGVsbG8", "field", 5)?;
        assert_eq!(result.len(), 5);
        Ok(())
    }

    #[test]
    fn test_validate_base64url_decoded_size_one_over_limit() {
        let validator = InputValidator::default();
        // "aGVsbG8" decodes to 5 bytes, limit is 4.
        let result = validator.validate_base64url("aGVsbG8", "field", 4);
        assert!(result.is_err());
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("decoded size")
        ));
    }

    #[test]
    fn test_validate_base64url_spaces_not_allowed() {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("aGVs bG8", "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base64url_with_hash_char() {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("aGVs#G8", "field", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base64url_all_url_safe_chars() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // Test with underscore and hyphen (the url-safe replacements for + and /).
        let result = validator.validate_base64url("_-_-", "field", 100)?;
        assert!(!result.is_empty());
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_base64url_fixed edge cases           */
    /* ========================================================================== */

    #[test]
    fn test_validate_base64url_fixed_decoded_smaller_than_expected() {
        let validator = InputValidator::default();
        // "aGVsbG8" decodes to 5 bytes, expected 10.
        let result = validator.validate_base64url_fixed("aGVsbG8", "field", 10);
        assert!(result.is_err());
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("must be exactly")
        ));
    }

    #[test]
    fn test_validate_base64url_fixed_decoded_larger_than_expected() {
        let validator = InputValidator::default();
        // 32 bytes (43 chars base64url) but expected 16.
        let zeros_32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = validator.validate_base64url_fixed(zeros_32, "field", 16);
        // validate_base64url will reject because decoded.len() (32) > max_decoded_size (16).
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_base64url_fixed_exact_16_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let bytes = vec![0u8; 16];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let result = validator.validate_base64url_fixed(&encoded, "field", 16)?;
        assert_eq!(result.len(), 16);
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_uuid edge cases                      */
    /* ========================================================================== */

    #[test]
    fn test_validate_uuid_empty_string() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("", "uuid");
        // Empty string will not match UUID pattern.
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_with_null_bytes() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("550e8400-e29b-41d4-a716-\x00446655440000", "uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_too_long() {
        let validator = InputValidator::default();
        // sid limit is 36 chars, this is 37+.
        let long = "550e8400-e29b-41d4-a716-4466554400001";
        let result = validator.validate_uuid(long, "uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_mixed_case() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let uuid_str = "550e8400-E29B-41d4-A716-446655440000";
        let result = validator.validate_uuid(uuid_str, "uuid")?;
        assert_eq!(result.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn test_validate_uuid_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("00000000-0000-0000-0000-000000000000", "uuid")?;
        assert_eq!(result, uuid::Uuid::nil());
        Ok(())
    }

    #[test]
    fn test_validate_uuid_all_fs() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("ffffffff-ffff-ffff-ffff-ffffffffffff", "uuid")?;
        assert_eq!(result, uuid::Uuid::max());
        Ok(())
    }

    #[test]
    fn test_validate_uuid_wrong_dash_positions() {
        let validator = InputValidator::default();
        // Valid hex but dashes in wrong places.
        let result = validator.validate_uuid("550e84-00e29b-41d4-a716-446655440000", "uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_no_dashes() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("550e8400e29b41d4a716446655440000", "uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_with_braces() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("{550e8400-e29b-41d4-a716-446655440000}", "uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_uuid_with_non_hex_chars() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("550g8400-e29b-41d4-a716-446655440000", "uuid");
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_origin edge cases                    */
    /* ========================================================================== */

    #[test]
    fn test_validate_origin_empty_string() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_with_path() {
        let validator = InputValidator::default();
        // Origin pattern should NOT match paths.
        let result = validator.validate_origin("https://example.com/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_with_trailing_slash() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://example.com/");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_with_query_string() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://example.com?foo=bar");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_with_fragment() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://example.com#section");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_ftp_rejected() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_bare_domain() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_with_whitespace_trimmed() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("  https://example.com  ")?;
        assert_eq!(result, "https://example.com");
        Ok(())
    }

    #[test]
    fn test_validate_origin_with_null_bytes() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://example\0.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_javascript_mixed_in_url() {
        let validator = InputValidator::default();
        // "javascript:" embedded in a longer string.
        let result = validator.validate_origin("https://javascript:alert@evil.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_data_mixed_in_url() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://data:text@evil.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_vbscript_mixed_in_url() {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://vbscript:run@evil.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_origin_http_with_port() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("http://localhost:3000")?;
        assert_eq!(result, "http://localhost:3000");
        Ok(())
    }

    #[test]
    fn test_validate_origin_hyphenated_domain() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://my-site.example.com")?;
        assert_eq!(result, "https://my-site.example.com");
        Ok(())
    }

    #[test]
    fn test_validate_origin_numeric_domain() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://192.168.1.1")?;
        assert_eq!(result, "https://192.168.1.1");
        Ok(())
    }

    #[test]
    fn test_validate_origin_numeric_domain_with_port() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let result = validator.validate_origin("https://192.168.1.1:8443")?;
        assert_eq!(result, "https://192.168.1.1:8443");
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_code_verifier edge cases             */
    /* ========================================================================== */

    #[test]
    fn test_validate_code_verifier_empty() {
        let validator = InputValidator::default();
        let result = validator.validate_code_verifier("");
        assert!(result.is_err());
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("43-128 characters")
        ));
    }

    #[test]
    fn test_validate_code_verifier_one_char() {
        let validator = InputValidator::default();
        let result = validator.validate_code_verifier("a");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_verifier_exactly_42() {
        let validator = InputValidator::default();
        let verifier = "a".repeat(42);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_verifier_exactly_129() {
        let validator = InputValidator::default();
        let verifier = "a".repeat(129);
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_verifier_with_spaces() {
        let validator = InputValidator::default();
        // Spaces are not allowed in PKCE verifier ([A-Za-z0-9\-._~]).
        let verifier = format!("{} {}", "a".repeat(21), "b".repeat(21));
        let result = validator.validate_code_verifier(&verifier);
        assert!(result.is_err());
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("invalid characters")
        ));
    }

    #[test]
    fn test_validate_code_verifier_all_special_chars() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // Verifier built entirely from the allowed special chars (plus alphanumeric to meet length).
        let verifier = format!("{}-.~_-.~_-.~_-.~_-.~_-.~_-.~_-.~_-.~_-.~_-", "aA0");
        let result = validator.validate_code_verifier(&verifier)?;
        assert_eq!(result, verifier);
        Ok(())
    }

    #[test]
    fn test_validate_code_verifier_numeric_only() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        let verifier = "0123456789".repeat(5); // 50 chars, all digits
        let result = validator.validate_code_verifier(&verifier)?;
        assert_eq!(result.len(), 50);
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_code_challenge edge cases            */
    /* ========================================================================== */

    #[test]
    fn test_validate_code_challenge_empty() {
        let validator = InputValidator::default();
        let result = validator.validate_code_challenge("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_challenge_too_small() {
        let validator = InputValidator::default();
        let bytes = vec![0u8; 16];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let result = validator.validate_code_challenge(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_challenge_too_large() {
        let validator = InputValidator::default();
        let bytes = vec![0u8; 64];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let result = validator.validate_code_challenge(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_code_challenge_exactly_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        // SHA-256 of "test" in base64url (32 bytes).
        let bytes = vec![0xAB; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
        let result = validator.validate_code_challenge(&encoded)?;
        assert_eq!(result.len(), 32);
        assert_eq!(result, bytes);
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: sanitize_for_logging edge cases               */
    /* ========================================================================== */

    #[test]
    fn test_sanitize_for_logging_empty_string() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("", 100);
        assert_eq!(result, "");
    }

    #[test]
    fn test_sanitize_for_logging_max_len_zero() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("hello", 0);
        assert_eq!(result, "");
    }

    #[test]
    fn test_sanitize_for_logging_multibyte_truncation_boundary() {
        let validator = InputValidator::default();
        // 3-byte UTF-8: e.g. "\u{4e16}" is 3 bytes (U+4E16, CJK character).
        // If we truncate at byte 1 or 2, we must walk back to byte 0.
        let input = "\u{4e16}abc"; // 3 + 3 = 6 bytes
        let result = validator.sanitize_for_logging(input, 2);
        // max_len=2 falls inside the 3-byte char, should walk back to 0.
        assert_eq!(result, "");
    }

    #[test]
    fn test_sanitize_for_logging_multibyte_truncation_after_char() {
        let validator = InputValidator::default();
        // Truncate at exactly 3, which is a valid char boundary for our 3-byte char.
        let input = "\u{4e16}abc";
        let result = validator.sanitize_for_logging(input, 3);
        assert_eq!(result, "\u{4e16}");
    }

    #[test]
    fn test_sanitize_for_logging_four_byte_char_truncation() {
        let validator = InputValidator::default();
        // Emoji: U+1F600 is 4 bytes in UTF-8.
        let input = "\u{1F600}hello";
        // Truncating at byte 1, 2, or 3 lands inside the emoji.
        let result = validator.sanitize_for_logging(input, 1);
        assert_eq!(result, "");
        let result = validator.sanitize_for_logging(input, 2);
        assert_eq!(result, "");
        let result = validator.sanitize_for_logging(input, 3);
        assert_eq!(result, "");
        // At byte 4, we get the full emoji.
        let result = validator.sanitize_for_logging(input, 4);
        assert_eq!(result, "\u{1F600}");
    }

    #[test]
    fn test_sanitize_for_logging_combined_newline_and_control() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("a\nb\rc\x01d\x00e", 100);
        // \n -> " ", \r -> " ", \x01 -> removed, \x00 -> removed
        assert_eq!(result, "a b cde");
    }

    #[test]
    fn test_sanitize_for_logging_only_control_chars() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("\x00\x01\x02\x03", 100);
        assert_eq!(result, "");
    }

    #[test]
    fn test_sanitize_for_logging_only_newlines() {
        let validator = InputValidator::default();
        let result = validator.sanitize_for_logging("\n\r\n\r", 100);
        assert_eq!(result, "    ");
    }

    #[test]
    fn test_sanitize_for_logging_exact_max_len() {
        let validator = InputValidator::default();
        let input = "a".repeat(50);
        let result = validator.sanitize_for_logging(&input, 50);
        assert_eq!(result.len(), 50);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_for_logging_tab_characters() {
        let validator = InputValidator::default();
        // Tab (\t) is a control character.
        let result = validator.sanitize_for_logging("hello\tworld", 100);
        assert_eq!(result, "helloworld");
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: validate_request_size boundary tests          */
    /* ========================================================================== */

    #[test]
    fn test_validate_request_size_zero() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        validator.validate_request_size(0, "/v1/challenge")?;
        Ok(())
    }

    #[test]
    fn test_validate_request_size_challenge_exact_limit() -> Result<(), Box<dyn std::error::Error>>
    {
        let validator = InputValidator::default();
        // Exactly 64 * 1024 = 65536.
        validator.validate_request_size(64 * 1024, "/v1/challenge")?;
        Ok(())
    }

    #[test]
    fn test_validate_request_size_challenge_one_over() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(64 * 1024 + 1, "/v1/challenge");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_request_size_verify_exact_limit() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        validator.validate_request_size(128 * 1024, "/v1/verify")?;
        Ok(())
    }

    #[test]
    fn test_validate_request_size_verify_one_over() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(128 * 1024 + 1, "/v1/verify");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_request_size_redeem_exact_limit() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        validator.validate_request_size(8 * 1024, "/v1/challenge/*/redeem")?;
        Ok(())
    }

    #[test]
    fn test_validate_request_size_redeem_one_over() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(8 * 1024 + 1, "/v1/challenge/*/redeem");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_request_size_default_exact_limit() -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        validator.validate_request_size(32 * 1024, "/v1/unknown")?;
        Ok(())
    }

    #[test]
    fn test_validate_request_size_default_one_over() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(32 * 1024 + 1, "/v1/unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_request_size_challenge_raw_exact_limit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let validator = InputValidator::default();
        validator.validate_request_size(64 * 1024, "/v1/challenge/raw")?;
        Ok(())
    }

    #[test]
    fn test_validate_request_size_challenge_raw_one_over() {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(64 * 1024 + 1, "/v1/challenge/raw");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_request_size_error_message_content() -> Result<(), Box<dyn std::error::Error>>
    {
        let validator = InputValidator::default();
        let result = validator.validate_request_size(100_000, "/v1/challenge");
        assert!(matches!(
            &result,
            Err(ApiError::PayloadTooLarge(Some(msg))) if msg.contains("100000") && msg.contains("65536")
        ));
        Ok(())
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: with_rules constructor                        */
    /* ========================================================================== */

    #[test]
    fn test_with_rules_custom_size_limits() -> Result<(), Box<dyn std::error::Error>> {
        let rules = ValidationRules {
            size_limits: FieldSizeLimit {
                origin: 50,
                ..FieldSizeLimit::default()
            },
            ..ValidationRules::default()
        };
        let validator = InputValidator::with_rules(rules);
        // Origin under 50 chars should work.
        let result = validator.validate_origin("https://example.com")?;
        assert_eq!(result, "https://example.com");
        Ok(())
    }

    #[test]
    fn test_with_rules_custom_size_limits_rejects() {
        let rules = ValidationRules {
            size_limits: FieldSizeLimit {
                origin: 10,
                ..FieldSizeLimit::default()
            },
            ..ValidationRules::default()
        };
        let validator = InputValidator::with_rules(rules);
        // "https://example.com" is 19 chars, over the 10-char limit.
        let result = validator.validate_origin("https://example.com");
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: safe_string pattern                           */
    /* ========================================================================== */

    #[test]
    fn test_safe_string_pattern_allows_expected() {
        let validator = InputValidator::default();
        let pattern = &validator.patterns["safe_string"];
        assert!(pattern.is_match("Hello World"));
        assert!(pattern.is_match("test-value"));
        assert!(pattern.is_match("test.value"));
        assert!(pattern.is_match("test_value"));
        assert!(pattern.is_match("test~value"));
        assert!(pattern.is_match("abc123"));
    }

    #[test]
    fn test_safe_string_pattern_rejects_special() {
        let validator = InputValidator::default();
        let pattern = &validator.patterns["safe_string"];
        assert!(!pattern.is_match("test!value"));
        assert!(!pattern.is_match("test@value"));
        assert!(!pattern.is_match("test#value"));
        assert!(!pattern.is_match("test$value"));
        assert!(!pattern.is_match("test<value>"));
        assert!(!pattern.is_match(""));
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: InputValidator::default fallback path         */
    /* ========================================================================== */

    #[test]
    fn test_input_validator_default_has_all_patterns() {
        let validator = InputValidator::default();
        assert_eq!(validator.patterns.len(), 5);
        assert!(validator.patterns.contains_key("uuid"));
        assert!(validator.patterns.contains_key("base64url"));
        assert!(validator.patterns.contains_key("pkce"));
        assert!(validator.patterns.contains_key("origin"));
        assert!(validator.patterns.contains_key("safe_string"));
    }

    #[test]
    fn test_input_validator_try_new_succeeds() {
        let result = InputValidator::try_new();
        assert!(result.is_ok());
        let validator = result.expect("try_new should succeed");
        assert_eq!(validator.patterns.len(), 5);
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: error message content verification            */
    /* ========================================================================== */

    #[test]
    fn test_validate_string_error_includes_field_name() {
        let validator = InputValidator::default();
        let result = validator.validate_string("a".repeat(200).as_str(), "my_special_field", 100);
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("my_special_field")
        ));
    }

    #[test]
    fn test_validate_base64url_error_includes_field_name() {
        let validator = InputValidator::default();
        let result = validator.validate_base64url("invalid!!!", "credential_id", 100);
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("credential_id")
        ));
    }

    #[test]
    fn test_validate_uuid_error_includes_field_name() {
        let validator = InputValidator::default();
        let result = validator.validate_uuid("bad", "session_id");
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("session_id")
        ));
    }

    #[test]
    fn test_validate_base64url_fixed_error_includes_field_and_size() {
        let validator = InputValidator::default();
        let result = validator.validate_base64url_fixed("aGVsbG8", "nonce", 32);
        assert!(matches!(
            &result,
            Err(ApiError::BadRequest(Some(msg))) if msg.contains("nonce") && msg.contains("32")
        ));
    }

    /* ========================================================================== */
    /*          ADDITIONAL COVERAGE: GLOBAL VALIDATOR usage patterns               */
    /* ========================================================================== */

    #[test]
    fn test_global_validator_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let uuid = VALIDATOR.validate_uuid("550e8400-e29b-41d4-a716-446655440000", "sid")?;
        assert_eq!(uuid.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn test_global_validator_origin() -> Result<(), Box<dyn std::error::Error>> {
        let origin = VALIDATOR.validate_origin("https://provii.app")?;
        assert_eq!(origin, "https://provii.app");
        Ok(())
    }

    #[test]
    fn test_global_validator_base64url() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = VALIDATOR.validate_base64url("aGVsbG8", "test", 100)?;
        assert_eq!(decoded, b"hello");
        Ok(())
    }

    #[test]
    fn test_global_validator_code_verifier() -> Result<(), Box<dyn std::error::Error>> {
        let verifier = "a".repeat(64);
        let result = VALIDATOR.validate_code_verifier(&verifier)?;
        assert_eq!(result.len(), 64);
        Ok(())
    }

    #[test]
    fn test_global_validator_request_size() -> Result<(), Box<dyn std::error::Error>> {
        VALIDATOR.validate_request_size(1024, "/v1/challenge")?;
        Ok(())
    }

    #[test]
    fn test_global_validator_sanitize_for_logging() {
        let result = VALIDATOR.sanitize_for_logging("test\nvalue", 100);
        assert_eq!(result, "test value");
    }
}
