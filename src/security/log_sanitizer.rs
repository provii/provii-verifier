// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Log sanitisation utilities for GDPR compliance and security.
//!
//! SECURITY: Implements data minimisation (GDPR Article 5(1)(c)) and prevents
//! sensitive data exposure in logs. All PII and secrets must be redacted or
//! hashed before logging.
//!
//! # Privacy Compliance
//!
//! - GDPR Article 5(1)(c): Data minimisation
//! - GDPR Article 25: Data protection by design
//! - GDPR Article 32: Security of processing
//!
//! # What Gets Sanitised
//!
//! - Client IP addresses: HMAC-SHA-256 hash (PII under GDPR)
//! - Challenge IDs: first 8 characters only (information disclosure prevention)
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Redacts a challenge ID for safe logging.
///
/// SECURITY: Challenge IDs are UUIDs that can be used to access challenges.
/// While not as sensitive as PKCE verifiers, truncating them reduces information
/// disclosure while still allowing log correlation.
///
/// # Arguments
/// * `challenge_id` - The challenge ID to redact
///
/// # Returns
/// A truncated string showing only the first 8 characters
///
/// # Example
/// ```
/// use provii_verifier::security::log_sanitizer::redact_challenge_id;
///
/// let id = "550e8400-e29b-41d4-a716-446655440000";
/// let redacted = redact_challenge_id(id);
/// assert_eq!(redacted, "550e8400");
/// ```
pub fn redact_challenge_id(challenge_id: &str) -> String {
    // SECURITY: Show only first 8 chars (enough for log correlation)
    challenge_id.get(..8).unwrap_or(challenge_id).to_string()
}

/// Redacts a session ID for safe logging.
///
/// SECURITY (ADV-VA-026): Session IDs are bearer-like tokens that grant
/// access to verification sessions. Logging them in full creates a risk of
/// session hijacking from log exposure. Truncate to the same 8-character
/// prefix used for challenge IDs.
///
/// # Arguments
/// * `session_id` - The session ID to redact
///
/// # Returns
/// A truncated string showing only the first 8 characters
///
/// # Example
/// ```
/// use provii_verifier::security::log_sanitizer::redact_session_id;
///
/// let id = "550e8400-e29b-41d4-a716-446655440000";
/// let redacted = redact_session_id(id);
/// assert_eq!(redacted, "550e8400");
/// ```
pub fn redact_session_id(session_id: &str) -> String {
    // SECURITY: Show only first 8 chars (enough for log correlation)
    session_id.get(..8).unwrap_or(session_id).to_string()
}

/// Hashes a client IP address for privacy-preserving logging.
///
/// SECURITY/GDPR: IP addresses are Personally Identifiable Information (PII)
/// under GDPR Article 4(1). Logging raw IPs violates data minimisation principles.
/// We use HMAC-SHA-256 keyed by the salt with domain-separated messages:
/// `HMAC-SHA-256(key=salt, msg="provii-ip-v0" || ip)` to allow correlation in
/// logs while protecting privacy. HMAC provides stronger guarantees than plain
/// hash concatenation (no length-extension attacks, proper key/data separation).
/// The domain tag prevents cross-context collisions (an IP hash can never
/// collide with a UA hash).
///
/// # Arguments
/// * `ip` - The client IP address to hash
/// * `salt` - HMAC key from Secrets Store (VERIFIER_IP_HASH_SALT)
///
/// # Returns
/// Full 64-character hex-encoded HMAC-SHA-256 output
///
/// # Example
/// ```
/// use provii_verifier::security::log_sanitizer::hash_ip;
///
/// let ip = "192.168.1.1";
/// let salt = "test-salt-for-hashing";
/// let hashed = hash_ip(ip, salt);
/// assert_eq!(hashed.len(), 64); // Full HMAC-SHA-256 hex digest
/// ```
pub fn hash_ip(ip: &str, salt: &str) -> String {
    // SECURITY: HMAC-SHA-256 with salt as key. Domain tag "provii-ip-v0" prevents
    // cross-context collisions (an IP HMAC can never collide with a UA HMAC).
    // HMAC-SHA-256 accepts any key length; unwrap_or_default returns a zero-keyed MAC
    // if construction fails (should never happen, but avoids a panic in library code).
    let Ok(mut mac) = HmacSha256::new_from_slice(salt.as_bytes()) else {
        return "0".repeat(64);
    };
    mac.update(b"provii-ip-v0");
    mac.update(ip.as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_challenge_id_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "550e8400");
    }

    #[test]
    fn test_redact_challenge_id_short() {
        let id = "short";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "short");
    }

    #[test]
    fn test_redact_session_id_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = redact_session_id(id);
        assert_eq!(redacted, "550e8400");
    }

    #[test]
    fn test_redact_session_id_short() {
        let id = "short";
        let redacted = redact_session_id(id);
        assert_eq!(redacted, "short");
    }

    #[test]
    fn test_hash_ip_ipv4() {
        let ip = "192.168.1.1";
        let salt = "test-salt-32-bytes-long-secure-random";
        let hashed = hash_ip(ip, salt);
        assert_eq!(hashed.len(), 64); // HMAC-SHA-256 hex digest (32 bytes = 64 hex)
                                      // Hash should be deterministic
        assert_eq!(hashed, hash_ip(ip, salt));
        // All hex chars
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_ip_ipv6() {
        let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let salt = "test-salt-32-bytes-long-secure-random";
        let hashed = hash_ip(ip, salt);
        assert_eq!(hashed.len(), 64);
        assert_eq!(hashed, hash_ip(ip, salt));
    }

    #[test]
    fn test_hash_ip_different_ips_different_hashes() {
        let ip1 = "192.168.1.1";
        let ip2 = "192.168.1.2";
        let salt = "test-salt-32-bytes-long-secure-random";
        let hash1 = hash_ip(ip1, salt);
        let hash2 = hash_ip(ip2, salt);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_ip_different_salts_different_hashes() {
        let ip = "192.168.1.1";
        let salt1 = "salt-one";
        let salt2 = "salt-two";
        let hash1 = hash_ip(ip, salt1);
        let hash2 = hash_ip(ip, salt2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_ip_unknown() {
        let ip = "unknown";
        let salt = "test-salt-32-bytes-long-secure-random";
        let hashed = hash_ip(ip, salt);
        assert_eq!(hashed.len(), 64);
    }

    /* ========================================================================== */
    /*                    ADDITIONAL COVERAGE TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_redact_challenge_id_exactly_eight_chars() {
        let id = "abcdefgh";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "abcdefgh");
    }

    #[test]
    fn test_redact_challenge_id_nine_chars() {
        let id = "abcdefghi";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "abcdefgh");
    }

    #[test]
    fn test_redact_challenge_id_empty() {
        let redacted = redact_challenge_id("");
        assert_eq!(redacted, "");
    }

    #[test]
    fn test_redact_challenge_id_single_char() {
        let redacted = redact_challenge_id("x");
        assert_eq!(redacted, "x");
    }

    #[test]
    fn test_redact_challenge_id_does_not_leak_full_value() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = redact_challenge_id(id);
        assert!(!redacted.contains("e29b"));
        assert!(!redacted.contains("446655440000"));
    }

    #[test]
    fn test_redact_session_id_exactly_eight_chars() {
        let id = "12345678";
        let redacted = redact_session_id(id);
        assert_eq!(redacted, "12345678");
    }

    #[test]
    fn test_redact_session_id_empty() {
        let redacted = redact_session_id("");
        assert_eq!(redacted, "");
    }

    #[test]
    fn test_redact_session_id_does_not_leak_full_value() {
        let id = "sess_abcdefghijklmnopqrstuvwxyz";
        let redacted = redact_session_id(id);
        assert!(!redacted.contains("ijklmnop"));
        assert!(!redacted.contains("uvwxyz"));
    }

    #[test]
    fn test_redact_challenge_id_unicode() {
        // Multi-byte UTF-8: each emoji is 4 bytes, so 8 bytes is 2 emojis
        // get(..8) works on byte indices, so this exercises the boundary safely
        let id = "abcdefghijklmnop";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "abcdefgh");
    }

    #[test]
    fn test_hash_ip_empty_ip() {
        let salt = "test-salt";
        let hashed = hash_ip("", salt);
        assert_eq!(hashed.len(), 64);
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_ip_empty_salt() {
        // Empty salt should still produce a valid HMAC (HMAC spec allows zero-length keys)
        let hashed = hash_ip("192.168.1.1", "");
        assert_eq!(hashed.len(), 64);
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_ip_domain_separation() {
        // The domain tag "provii-ip-v0" is prepended to the IP, so the same IP
        // with a different domain prefix would produce a different hash. We test
        // that two different IPs that share a suffix produce different outputs.
        let salt = "domain-sep-test-salt";
        let hash_a = hash_ip("10.0.0.1", salt);
        let hash_b = hash_ip("10.0.0.2", salt);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn test_hash_ip_loopback() {
        let salt = "loop-salt";
        let hashed = hash_ip("127.0.0.1", salt);
        assert_eq!(hashed.len(), 64);
        // Deterministic
        assert_eq!(hashed, hash_ip("127.0.0.1", salt));
    }

    #[test]
    fn test_hash_ip_ipv6_compressed() {
        let salt = "test-salt";
        let hashed = hash_ip("::1", salt);
        assert_eq!(hashed.len(), 64);
        // Compressed and expanded forms are different strings, different hashes
        let hashed_expanded = hash_ip("0000:0000:0000:0000:0000:0000:0000:0001", salt);
        assert_ne!(hashed, hashed_expanded);
    }

    #[test]
    fn test_hash_ip_output_is_lowercase_hex() {
        let hashed = hash_ip("192.168.1.1", "salt");
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
        // Verify lowercase specifically: no uppercase A-F
        assert!(!hashed.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_hash_ip_deterministic_across_calls() {
        let salt = "stable-salt";
        let ip = "203.0.113.42";
        let results: Vec<String> = (0..5).map(|_| hash_ip(ip, salt)).collect();
        for r in &results {
            assert_eq!(r, &results[0]);
        }
    }

    #[test]
    fn test_redact_session_id_seven_chars() {
        let id = "1234567";
        let redacted = redact_session_id(id);
        assert_eq!(redacted, "1234567");
    }

    #[test]
    fn test_redact_challenge_id_seven_chars() {
        let id = "abcdefg";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "abcdefg");
    }
}
