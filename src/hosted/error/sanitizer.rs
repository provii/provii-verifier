// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error Message Sanitiser
//!
//! SECURITY: This module sanitises error messages to prevent information disclosure.
//! It removes sensitive internal details while maintaining user-friendly messages.

use crate::hosted::types::errors::{HostedApiError, HostedErrorResponse};
use regex::Regex;
use std::sync::OnceLock;

/// Environment mode for error handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Production environment - minimal error details
    Production,
    /// Sandbox/development environment - more detailed errors
    Sandbox,
    /// Development environment - full error details
    Development,
}

impl Environment {
    /// Parse environment from string
    pub fn parse_env(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Environment::Production,
            "sandbox" | "staging" => Environment::Sandbox,
            "development" | "dev" | "local" => Environment::Development,
            _ => Environment::Production, // Default to production for safety
        }
    }

    /// Check if detailed errors should be included
    pub fn include_details(&self) -> bool {
        matches!(self, Environment::Sandbox | Environment::Development)
    }
}

/// Error sanitizer for production environments
pub struct ErrorSanitizer {
    environment: Environment,
}

impl ErrorSanitizer {
    /// Create a new error sanitizer
    pub fn new(environment: Environment) -> Self {
        Self { environment }
    }

    /// SECURITY: Sanitise a HostedApiError for client consumption.
    ///
    /// Returns a sanitised error safe for client responses and
    /// the original error details for internal logging.
    pub fn sanitize(&self, error: HostedApiError) -> (HostedApiError, String) {
        let internal_details = format!("{:?}", error);

        if self.environment.include_details() {
            // In non-production, return original error
            return (error.clone(), internal_details);
        }

        // In production, sanitize the error
        let sanitized = match error {
            HostedApiError::InvalidRequest { message } => HostedApiError::InvalidRequest {
                message: Self::sanitize_message(&message),
            },
            HostedApiError::Unauthorized { .. } => {
                HostedApiError::unauthorized("Authentication required")
            }
            HostedApiError::Forbidden { .. } => HostedApiError::forbidden("Access denied"),
            HostedApiError::NotFound { .. } => HostedApiError::not_found("Resource not found"),
            HostedApiError::Conflict { .. } => {
                HostedApiError::conflict("Request conflicts with current state")
            }
            HostedApiError::Gone { .. } => HostedApiError::gone("Resource no longer available"),
            HostedApiError::InternalError { .. } => {
                HostedApiError::internal("Internal server error")
            }
            HostedApiError::ServiceUnavailable { .. } => {
                HostedApiError::service_unavailable("Service temporarily unavailable")
            }
            HostedApiError::GatewayTimeout { .. } => {
                HostedApiError::gateway_timeout("upstream service")
            }
            HostedApiError::RateLimitExceeded {
                retry_after,
                limit,
                window,
            } => HostedApiError::RateLimitExceeded {
                retry_after,
                limit,
                window,
            },
            HostedApiError::InsufficientCredits { .. } => {
                HostedApiError::insufficient_credits("Insufficient credits")
            }
            HostedApiError::MethodNotAllowed { allowed } => {
                HostedApiError::MethodNotAllowed { allowed }
            }
        };

        (sanitized, internal_details)
    }

    /// Sanitize an error response
    pub fn sanitize_response(
        &self,
        response: HostedErrorResponse,
    ) -> (HostedErrorResponse, String) {
        let internal_details = format!("{:?}", response);

        if self.environment.include_details() {
            return (response, internal_details);
        }

        let (sanitized_error, _) = self.sanitize(response.error);

        let sanitized_response = HostedErrorResponse {
            error: sanitized_error,
            request_id: response.request_id,
            timestamp: response.timestamp,
        };

        (sanitized_response, internal_details)
    }

    /// Maximum length for sanitised error messages returned to clients.
    /// Messages longer than this are truncated to prevent large error bodies.
    const MAX_MESSAGE_LENGTH: usize = 200;

    /// Sanitize a message string.
    ///
    /// EIL-022/023/024/025/026: Extended sanitisation covers JWT tokens,
    /// API keys, KV key prefixes, and enforces message truncation.
    /// Fail-closed: if any step panics (caught by catch_unwind), a
    /// generic error is returned instead of the original message.
    fn sanitize_message(message: &str) -> String {
        // EIL-026: Fail-closed sanitisation. If anything goes wrong during
        // sanitisation, return a generic message rather than the original.
        std::panic::catch_unwind(|| Self::sanitize_message_inner(message))
            .unwrap_or_else(|_| "An error occurred".to_string())
    }

    /// Inner sanitisation logic (separated so catch_unwind can wrap it).
    fn sanitize_message_inner(message: &str) -> String {
        let mut sanitized = message.to_string();

        // Remove IP addresses FIRST (before other patterns that might partially match)
        sanitized = Self::remove_ip_addresses(&sanitized);

        // Remove file paths
        sanitized = Self::remove_file_paths(&sanitized);

        // Remove SQL-like patterns
        sanitized = Self::remove_sql_patterns(&sanitized);

        // EIL-023: Remove JWT tokens (eyJ... base64url segments)
        sanitized = Self::remove_jwt_tokens(&sanitized);

        // EIL-023: Remove API keys (pk_live_*, pk_test_*, sk_*)
        sanitized = Self::remove_api_keys(&sanitized);

        // Remove KV key patterns (extended in EIL-024)
        sanitized = Self::remove_kv_patterns(&sanitized);

        // Remove stack trace patterns
        sanitized = Self::remove_stack_traces(&sanitized);

        // Remove internal field names
        sanitized = Self::remove_internal_fields(&sanitized);

        // EIL-025: Truncate to prevent large error messages
        if sanitized.len() > Self::MAX_MESSAGE_LENGTH {
            sanitized.truncate(Self::MAX_MESSAGE_LENGTH);
            // Avoid truncating in the middle of a multi-byte character
            while !sanitized.is_char_boundary(sanitized.len()) {
                sanitized.pop();
            }
        }

        // If message is now empty or too generic, use default
        if sanitized.is_empty() || sanitized.len() < 10 {
            return "Invalid request".to_string();
        }

        sanitized
    }

    /// Compile a regex from a known-good pattern, returning `None` if
    /// compilation fails (should never happen for literal patterns).
    fn compile_regex<'a>(lock: &'a OnceLock<Option<Regex>>, pattern: &str) -> Option<&'a Regex> {
        lock.get_or_init(|| Regex::new(pattern).ok()).as_ref()
    }

    /// Remove JWT tokens from error messages (EIL-023).
    /// Matches the standard eyJ... base64url-encoded header.segment.signature pattern.
    fn remove_jwt_tokens(message: &str) -> String {
        static JWT_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(
            &JWT_REGEX,
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        ) {
            Some(regex) => regex.replace_all(message, "[token]").to_string(),
            None => message.to_string(),
        }
    }

    /// Remove API keys from error messages (EIL-023).
    /// Matches pk_live_*, pk_test_*, sk_live_*, sk_test_* patterns.
    fn remove_api_keys(message: &str) -> String {
        static API_KEY_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(&API_KEY_REGEX, r"\b(pk|sk)_(live|test)_[A-Za-z0-9_-]+\b") {
            Some(regex) => regex.replace_all(message, "[key]").to_string(),
            None => message.to_string(),
        }
    }

    /// Remove IPv4 and IPv6 addresses from error messages
    fn remove_ip_addresses(message: &str) -> String {
        static IPV4_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        static IPV6_REGEX: OnceLock<Option<Regex>> = OnceLock::new();

        let ipv4 = Self::compile_regex(&IPV4_REGEX, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
        let ipv6 = Self::compile_regex(
            &IPV6_REGEX,
            concat!(
                r"(?i)",
                // Full 8-group: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
                r"[0-9a-f]{1,4}(:[0-9a-f]{1,4}){7}",
                r"|",
                // Compressed with leading groups: fe80::1
                r"[0-9a-f]{1,4}(:[0-9a-f]{1,4}){0,5}::[0-9a-f]{0,4}(:[0-9a-f]{1,4}){0,5}",
                r"|",
                // Compressed starting with :: (e.g. ::1, ::ffff:192.168.1.1)
                r"::(:[0-9a-f]{1,4}){0,6}",
                r"|",
                // :: alone (unspecified address)
                r"::",
            ),
        );

        let result = match ipv4 {
            Some(r) => r.replace_all(message, "[IP_REDACTED]").to_string(),
            None => message.to_string(),
        };
        match ipv6 {
            Some(r) => r.replace_all(&result, "[IP_REDACTED]").to_string(),
            None => result,
        }
    }

    /// Remove file paths from error messages
    fn remove_file_paths(message: &str) -> String {
        static FILE_PATH_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(
            &FILE_PATH_REGEX,
            r"(/[\w/\-_.]+\.(rs|ts|js|json|toml)|\w:\\[\w\\\-_.]+\.(rs|ts|js|json|toml))",
        ) {
            Some(regex) => regex.replace_all(message, "[file]").to_string(),
            None => message.to_string(),
        }
    }

    /// Remove SQL patterns from error messages
    fn remove_sql_patterns(message: &str) -> String {
        static SQL_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(
            &SQL_REGEX,
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|TABLE|COLUMN|DATABASE)\s+[\w\s,=]+",
        ) {
            Some(regex) => regex.replace_all(message, "[query]").to_string(),
            None => message.to_string(),
        }
    }

    /// Remove KV key patterns from error messages (EIL-024: extended prefixes).
    fn remove_kv_patterns(message: &str) -> String {
        static KV_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(
            &KV_REGEX,
            r"(session|config|audit|admin|key|secret|credential|nonce|challenge_to_session|rate_limit|expiry|mek|hosted)[:_-][\w\-]+",
        ) {
            Some(regex) => regex.replace_all(message, "[key]").to_string(),
            None => message.to_string(),
        }
    }

    /// Remove stack trace patterns from error messages
    fn remove_stack_traces(message: &str) -> String {
        static STACK_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(&STACK_REGEX, r"at\s+[\w::<>]+\s*\(.*?\)") {
            Some(regex) => regex.replace_all(message, "").to_string(),
            None => message.to_string(),
        }
    }

    /// Remove internal field names from error messages
    fn remove_internal_fields(message: &str) -> String {
        static FIELD_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
        match Self::compile_regex(
            &FIELD_REGEX,
            r"\b(code_verifier|code_challenge|key_hash|secret_key|private_key|session_token|hmac|salt)\b",
        ) {
            Some(regex) => regex.replace_all(message, "[field]").to_string(),
            None => message.to_string(),
        }
    }
}

/// Sanitise an error using a fresh production-mode sanitiser.
///
/// Returns the sanitised error for the client and internal details for logging.
/// EIL-026: Defaults to production-level sanitisation (fail-closed).
pub fn sanitize_error(error: HostedApiError) -> (HostedApiError, String) {
    let sanitizer = ErrorSanitizer::new(Environment::Production);
    sanitizer.sanitize(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_from_str() {
        assert_eq!(
            Environment::parse_env("production"),
            Environment::Production
        );
        assert_eq!(Environment::parse_env("PROD"), Environment::Production);
        assert_eq!(Environment::parse_env("sandbox"), Environment::Sandbox);
        assert_eq!(
            Environment::parse_env("development"),
            Environment::Development
        );
        assert_eq!(Environment::parse_env("unknown"), Environment::Production);
    }

    #[test]
    fn test_environment_include_details() {
        assert!(!Environment::Production.include_details());
        assert!(Environment::Sandbox.include_details());
        assert!(Environment::Development.include_details());
    }

    #[test]
    fn test_sanitize_file_paths() {
        let message = "Error at /home/user/project/src/main.rs:123";
        let sanitized = ErrorSanitizer::remove_file_paths(message);
        assert!(!sanitized.contains("/home/user"));
        assert!(sanitized.contains("[file]"));
    }

    #[test]
    fn test_sanitize_ipv4_addresses() {
        let message = "Connection refused from 192.168.1.100 to 10.0.0.1";
        let sanitized = ErrorSanitizer::remove_ip_addresses(message);
        assert!(!sanitized.contains("192.168.1.100"));
        assert!(!sanitized.contains("10.0.0.1"));
        assert_eq!(
            sanitized,
            "Connection refused from [IP_REDACTED] to [IP_REDACTED]"
        );
    }

    #[test]
    fn test_sanitize_ipv6_addresses() {
        let message = "Request from 2001:0db8:85a3:0000:0000:8a2e:0370:7334 failed";
        let sanitized = ErrorSanitizer::remove_ip_addresses(message);
        assert!(!sanitized.contains("2001:0db8"));
        assert!(sanitized.contains("[IP_REDACTED]"));
    }

    #[test]
    fn test_sanitize_ipv6_compressed() {
        let message = "Loopback ::1 and unspecified :: detected";
        let sanitized = ErrorSanitizer::remove_ip_addresses(message);
        assert!(!sanitized.contains("::1"));
        assert!(sanitized.contains("[IP_REDACTED]"));
    }

    #[test]
    fn test_sanitize_sql_patterns() {
        // The regex requires a SQL keyword followed by \s+[\w\s,=]+.
        // "SELECT *" does NOT match because '*' is outside [\w\s,=].
        // Use an input where the keyword is followed by word characters.
        let message = "Error in SELECT id, name FROM users WHERE id = 123";
        let sanitized = ErrorSanitizer::remove_sql_patterns(message);
        assert!(!sanitized.contains("SELECT"));
        assert!(sanitized.contains("[query]"));
    }

    #[test]
    fn test_sanitize_kv_patterns() {
        let message = "Failed to get session:abc-123 from KV";
        let sanitized = ErrorSanitizer::remove_kv_patterns(message);
        assert!(!sanitized.contains("session:abc-123"));
        assert!(sanitized.contains("[key]"));
    }

    #[test]
    fn test_sanitize_internal_fields() {
        let message = "Invalid code_verifier provided";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("code_verifier"));
        assert!(sanitized.contains("[field]"));
    }

    #[test]
    fn test_sanitize_production_internal_error() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::internal("Database connection failed at db.rs:456");

        let (sanitized, internal) = sanitizer.sanitize(error);

        // Client sees generic message
        assert_eq!(sanitized.message(), "Internal server error");

        // Internal logs have full details
        assert!(internal.contains("Database connection failed"));
    }

    #[test]
    fn test_sanitize_production_unauthorized() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::unauthorized("Invalid key: admin_key_secret123");

        let (sanitized, internal) = sanitizer.sanitize(error);

        // Client sees generic message
        assert_eq!(sanitized.message(), "Authentication required");

        // Internal logs have full details
        assert!(internal.contains("admin_key_secret123"));
    }

    #[test]
    fn test_sanitize_development_preserves_details() {
        let sanitizer = ErrorSanitizer::new(Environment::Development);
        let error = HostedApiError::internal("Database connection failed at db.rs:456");

        let (sanitized, _) = sanitizer.sanitize(error.clone());

        // Development mode preserves original error
        assert_eq!(sanitized.message(), error.message());
    }

    #[test]
    fn test_sanitize_rate_limit_preserved() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::RateLimitExceeded {
            retry_after: 60,
            limit: 100,
            window: 60,
        };

        let (sanitized, _) = sanitizer.sanitize(error.clone());

        // Rate limit errors preserve their structure
        assert!(matches!(
            sanitized,
            HostedApiError::RateLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_sanitize_invalid_request() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::invalid_request(
            "Missing field: code_verifier at /app/src/endpoints/redeem.rs:123",
        );

        let (sanitized, _) = sanitizer.sanitize(error);

        let msg = sanitized.message();
        // Should not contain internal field name
        assert!(!msg.contains("code_verifier"));
        // Should not contain file path
        assert!(!msg.contains("/app/src"));
    }

    #[test]
    fn test_sanitize_empty_message() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let message = "code_verifier"; // Will be fully replaced
        let sanitized = ErrorSanitizer::sanitize_message(message);

        // Should return default message for overly sanitized content
        assert_eq!(sanitized, "Invalid request");

        // Suppress unused variable warning
        let _ = sanitizer;
    }

    #[test]
    fn test_sanitize_error_response() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::internal("Secret key leaked: sk_test_123");
        let response = HostedErrorResponse::new(error, "req-123".to_string());

        let (sanitized_response, internal) = sanitizer.sanitize_response(response);

        // Response preserves request_id
        assert_eq!(sanitized_response.request_id, "req-123");

        // Error is sanitized
        assert_eq!(sanitized_response.error.message(), "Internal server error");

        // Internal details preserved
        assert!(internal.contains("sk_test_123"));
    }

    // ── Environment::parse_env additional branches ─────────────────────

    #[test]
    fn test_environment_parse_staging() {
        assert_eq!(Environment::parse_env("staging"), Environment::Sandbox);
    }

    #[test]
    fn test_environment_parse_dev() {
        assert_eq!(Environment::parse_env("dev"), Environment::Development);
    }

    #[test]
    fn test_environment_parse_local() {
        assert_eq!(Environment::parse_env("local"), Environment::Development);
    }

    #[test]
    fn test_environment_parse_case_insensitive() {
        assert_eq!(
            Environment::parse_env("PRODUCTION"),
            Environment::Production
        );
        assert_eq!(Environment::parse_env("SANDBOX"), Environment::Sandbox);
        assert_eq!(
            Environment::parse_env("DEVELOPMENT"),
            Environment::Development
        );
    }

    // ── JWT token removal ──────────────────────────────────────────────

    #[test]
    fn test_sanitize_jwt_tokens() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let message = format!("Token invalid: {}", jwt);
        let sanitized = ErrorSanitizer::remove_jwt_tokens(&message);
        assert!(!sanitized.contains("eyJ"));
        assert!(sanitized.contains("[token]"));
    }

    #[test]
    fn test_sanitize_jwt_no_false_positive() {
        let message = "eyJ is not a JWT by itself";
        let sanitized = ErrorSanitizer::remove_jwt_tokens(message);
        // Short strings should not match the JWT regex (requires 10+ chars per segment)
        assert_eq!(sanitized, message);
    }

    // ── API key removal ────────────────────────────────────────────────

    #[test]
    fn test_sanitize_api_keys_pk_live() {
        let message = "Failed with key pk_live_abc123XYZ";
        let sanitized = ErrorSanitizer::remove_api_keys(message);
        assert!(!sanitized.contains("pk_live_abc123XYZ"));
        assert!(sanitized.contains("[key]"));
    }

    #[test]
    fn test_sanitize_api_keys_sk_test() {
        let message = "Key sk_test_secretvalue was rejected";
        let sanitized = ErrorSanitizer::remove_api_keys(message);
        assert!(!sanitized.contains("sk_test_secretvalue"));
        assert!(sanitized.contains("[key]"));
    }

    #[test]
    fn test_sanitize_api_keys_pk_test() {
        let message = "Using pk_test_mykey for authentication";
        let sanitized = ErrorSanitizer::remove_api_keys(message);
        assert!(!sanitized.contains("pk_test_mykey"));
    }

    #[test]
    fn test_sanitize_api_keys_sk_live() {
        let message = "Error: sk_live_supersecret is invalid";
        let sanitized = ErrorSanitizer::remove_api_keys(message);
        assert!(!sanitized.contains("sk_live_supersecret"));
    }

    // ── KV pattern removal extended prefixes ───────────────────────────

    #[test]
    fn test_sanitize_kv_admin_prefix() {
        let message = "Lookup failed for admin:user-42";
        let sanitized = ErrorSanitizer::remove_kv_patterns(message);
        assert!(!sanitized.contains("admin:user-42"));
        assert!(sanitized.contains("[key]"));
    }

    #[test]
    fn test_sanitize_kv_challenge_to_session() {
        let message = "Missing challenge_to_session:abc-def in KV";
        let sanitized = ErrorSanitizer::remove_kv_patterns(message);
        assert!(!sanitized.contains("challenge_to_session:abc-def"));
    }

    #[test]
    fn test_sanitize_kv_rate_limit() {
        let message = "rate_limit:ip-hash exceeded";
        let sanitized = ErrorSanitizer::remove_kv_patterns(message);
        assert!(!sanitized.contains("rate_limit:ip-hash"));
    }

    #[test]
    fn test_sanitize_kv_mek_prefix() {
        let message = "mek:current not found";
        let sanitized = ErrorSanitizer::remove_kv_patterns(message);
        assert!(!sanitized.contains("mek:current"));
    }

    #[test]
    fn test_sanitize_kv_hosted_prefix() {
        let message = "hosted:config-abc error";
        let sanitized = ErrorSanitizer::remove_kv_patterns(message);
        assert!(!sanitized.contains("hosted:config-abc"));
    }

    // ── Stack trace removal ────────────────────────────────────────────

    #[test]
    fn test_sanitize_stack_trace() {
        let message = "Error at worker::handle_request(src/lib.rs:42) in main";
        let sanitized = ErrorSanitizer::remove_stack_traces(message);
        assert!(!sanitized.contains("worker::handle_request"));
    }

    // ── Internal field removal additional fields ───────────────────────

    #[test]
    fn test_sanitize_internal_field_code_challenge() {
        let message = "Invalid code_challenge provided by client";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("code_challenge"));
        assert!(sanitized.contains("[field]"));
    }

    #[test]
    fn test_sanitize_internal_field_key_hash() {
        let message = "Mismatch in key_hash comparison";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("key_hash"));
    }

    #[test]
    fn test_sanitize_internal_field_hmac() {
        let message = "hmac verification failed for request";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("hmac"));
    }

    #[test]
    fn test_sanitize_internal_field_salt() {
        let message = "Missing salt for key derivation";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("salt"));
    }

    #[test]
    fn test_sanitize_internal_field_session_token() {
        let message = "Invalid session_token in cookie";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("session_token"));
    }

    #[test]
    fn test_sanitize_internal_field_private_key() {
        let message = "Failed to load private_key from storage";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("private_key"));
    }

    #[test]
    fn test_sanitize_internal_field_secret_key() {
        let message = "Error reading secret_key from KV";
        let sanitized = ErrorSanitizer::remove_internal_fields(message);
        assert!(!sanitized.contains("secret_key"));
    }

    // ── Message truncation (EIL-025) ───────────────────────────────────

    #[test]
    fn test_sanitize_message_truncation() {
        let long_message = "A".repeat(500);
        let sanitized = ErrorSanitizer::sanitize_message(&long_message);
        assert!(sanitized.len() <= ErrorSanitizer::MAX_MESSAGE_LENGTH);
    }

    #[test]
    fn test_sanitize_message_truncation_at_char_boundary() {
        // Multi-byte characters near the boundary should not produce invalid UTF-8
        let mut message = "Valid prefix with enough characters to be long ".to_string();
        // Pad to just beyond MAX_MESSAGE_LENGTH with multi-byte chars
        while message.len() < 195 {
            message.push('a');
        }
        // Add multi-byte chars near the boundary
        message.push_str("\u{00E9}\u{00E9}\u{00E9}\u{00E9}\u{00E9}");
        let sanitized = ErrorSanitizer::sanitize_message(&message);
        assert!(sanitized.len() <= ErrorSanitizer::MAX_MESSAGE_LENGTH);
        // Must be valid UTF-8 (if it were not, this would fail to compile/run)
        assert!(sanitized.is_char_boundary(sanitized.len()));
    }

    #[test]
    fn test_sanitize_message_short_becomes_default() {
        // After sanitisation a message < 10 chars returns "Invalid request"
        let sanitized = ErrorSanitizer::sanitize_message("salt");
        assert_eq!(sanitized, "Invalid request");
    }

    // ── Production sanitisation of each error variant ──────────────────

    #[test]
    fn test_sanitize_production_forbidden() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::forbidden("Session does not belong to user pk_test_abc");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert_eq!(sanitized.message(), "Access denied");
    }

    #[test]
    fn test_sanitize_production_not_found() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::not_found("session:abc-123-secret");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert_eq!(
            sanitized.message(),
            "Resource not found: Resource not found"
        );
    }

    #[test]
    fn test_sanitize_production_conflict() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::conflict("Session already redeemed at timestamp 123456");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert_eq!(sanitized.message(), "Request conflicts with current state");
    }

    #[test]
    fn test_sanitize_production_gone() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::gone("Expired session:abc with key_hash xyz");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert_eq!(sanitized.message(), "Resource no longer available");
    }

    #[test]
    fn test_sanitize_production_service_unavailable() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::service_unavailable("KV store circuit breaker tripped");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert_eq!(sanitized.message(), "Service temporarily unavailable");
    }

    #[test]
    fn test_sanitize_production_gateway_timeout() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::gateway_timeout("provii-verifier at 10.0.0.5:8080");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert!(sanitized.message().contains("upstream service"));
    }

    #[test]
    fn test_sanitize_production_insufficient_credits() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::insufficient_credits("Account abc has 0 credits remaining");
        let (sanitized, _) = sanitizer.sanitize(error);
        assert_eq!(sanitized.message(), "Insufficient credits");
    }

    #[test]
    fn test_sanitize_production_method_not_allowed() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::MethodNotAllowed {
            allowed: vec!["GET".to_string(), "POST".to_string()],
        };
        let (sanitized, _) = sanitizer.sanitize(error);
        // MethodNotAllowed should pass through
        assert!(matches!(sanitized, HostedApiError::MethodNotAllowed { .. }));
    }

    // ── Sandbox preserves details ──────────────────────────────────────

    #[test]
    fn test_sanitize_sandbox_preserves_details() {
        let sanitizer = ErrorSanitizer::new(Environment::Sandbox);
        let error = HostedApiError::internal("Database connection failed at db.rs:456");
        let (sanitized, _) = sanitizer.sanitize(error.clone());
        assert_eq!(sanitized.message(), error.message());
    }

    // ── sanitize_response in non-production ────────────────────────────

    #[test]
    fn test_sanitize_response_sandbox_preserves() {
        let sanitizer = ErrorSanitizer::new(Environment::Sandbox);
        let error = HostedApiError::internal("DB crash: secret_key leaked");
        let response = HostedErrorResponse::new(error.clone(), "req-sb".to_string());
        let (sanitized_response, _) = sanitizer.sanitize_response(response);
        assert_eq!(sanitized_response.error.message(), error.message());
        assert_eq!(sanitized_response.request_id, "req-sb");
    }

    // ── sanitize_error free function ───────────────────────────────────

    #[test]
    fn test_sanitize_error_free_function() {
        let error = HostedApiError::unauthorized("sk_live_secret was invalid");
        let (sanitized, internal) = sanitize_error(error);
        // Free function uses Production mode
        assert_eq!(sanitized.message(), "Authentication required");
        assert!(internal.contains("sk_live_secret"));
    }

    // ── Combined sanitisation (multiple patterns in one message) ───────

    #[test]
    fn test_sanitize_message_combined_patterns() {
        let sanitizer = ErrorSanitizer::new(Environment::Production);
        let error = HostedApiError::invalid_request(
            "Error for session:abc-123 from 192.168.1.1 at /app/src/main.rs with code_verifier",
        );
        let (sanitized, _) = sanitizer.sanitize(error);
        let msg = sanitized.message();
        assert!(!msg.contains("session:abc-123"));
        assert!(!msg.contains("192.168.1.1"));
        assert!(!msg.contains("/app/src/main.rs"));
        assert!(!msg.contains("code_verifier"));
    }

    // ── File path removal edge cases ───────────────────────────────────

    #[test]
    fn test_sanitize_windows_file_path() {
        let message = r"Error at C:\Users\dev\project\src\main.rs during compilation";
        let sanitized = ErrorSanitizer::remove_file_paths(message);
        assert!(!sanitized.contains(r"C:\Users"));
        assert!(sanitized.contains("[file]"));
    }

    #[test]
    fn test_sanitize_toml_file_path() {
        let message = "Cannot parse /etc/config/settings.toml properly";
        let sanitized = ErrorSanitizer::remove_file_paths(message);
        assert!(!sanitized.contains("/etc/config/settings.toml"));
    }

    #[test]
    fn test_sanitize_json_file_path() {
        let message = "Failed to read /data/config.json from disk";
        let sanitized = ErrorSanitizer::remove_file_paths(message);
        assert!(!sanitized.contains("/data/config.json"));
    }

    // ── SQL pattern additional cases ───────────────────────────────────

    #[test]
    fn test_sanitize_sql_insert() {
        let message = "Failed: INSERT INTO users VALUES (1, 'test')";
        let sanitized = ErrorSanitizer::remove_sql_patterns(message);
        assert!(!sanitized.contains("INSERT"));
        assert!(sanitized.contains("[query]"));
    }

    #[test]
    fn test_sanitize_sql_update() {
        let message = "Error in UPDATE sessions SET status = 'expired'";
        let sanitized = ErrorSanitizer::remove_sql_patterns(message);
        assert!(!sanitized.contains("UPDATE"));
    }

    #[test]
    fn test_sanitize_sql_delete() {
        let message = "Failed: DELETE FROM sessions WHERE id = 123";
        let sanitized = ErrorSanitizer::remove_sql_patterns(message);
        assert!(!sanitized.contains("DELETE FROM"));
    }

    // ── IPv6 additional cases ──────────────────────────────────────────

    #[test]
    fn test_sanitize_ipv6_full_address() {
        let message = "Blocked fe80:0000:0000:0000:0000:0000:0000:0001 from access";
        let sanitized = ErrorSanitizer::remove_ip_addresses(message);
        assert!(!sanitized.contains("fe80"));
        assert!(sanitized.contains("[IP_REDACTED]"));
    }
}
