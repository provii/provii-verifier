// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Session binding utilities: keyed hashing and WebSocket ticket generation.
//!
//! Provides HMAC-SHA-256 based hashing with domain separation and single-use
//! WebSocket ticket generation/validation for the hosted verification flow.

use crate::error::ApiError;
use crate::hosted::types::session::SessionBindingMode;

// Re-export the pure-logic types for existing call sites.
pub use provii_verifier_logic::session_binding::BindingOutcome;

/// Bridge from the logic crate's `SessionBindingMode` to the hosted types crate's version.
fn to_logic_mode(
    mode: SessionBindingMode,
) -> provii_verifier_logic::session_binding::SessionBindingMode {
    match mode {
        SessionBindingMode::Strict => {
            provii_verifier_logic::session_binding::SessionBindingMode::Strict
        }
        SessionBindingMode::Relaxed => {
            provii_verifier_logic::session_binding::SessionBindingMode::Relaxed
        }
        SessionBindingMode::None => {
            provii_verifier_logic::session_binding::SessionBindingMode::None
        }
    }
}

/// Convert a logic crate error into an `ApiError`.
impl From<provii_verifier_logic::error::LogicError> for ApiError {
    fn from(e: provii_verifier_logic::error::LogicError) -> Self {
        match e {
            provii_verifier_logic::error::LogicError::SessionBindingMismatch => {
                ApiError::Forbidden(Some("Session binding mismatch".into()))
            }
            provii_verifier_logic::error::LogicError::HmacKeyRejected => {
                ApiError::Internal(anyhow::anyhow!("HMAC key rejected"))
            }
            other => ApiError::Internal(anyhow::anyhow!("{}", other)),
        }
    }
}

/// Verify that the current request's IP and User-Agent match the session's
/// stored binding hashes. Thin wrapper that delegates to the logic crate
/// and converts errors to `ApiError`.
pub fn verify_session_binding(
    current_ip: &str,
    current_ua: Option<&str>,
    stored_ip_hash: Option<&str>,
    stored_ua_hash: Option<&str>,
    salt: &str,
    mode: SessionBindingMode,
) -> Result<BindingOutcome, ApiError> {
    provii_verifier_logic::session_binding::verify_session_binding(
        current_ip,
        current_ua,
        stored_ip_hash,
        stored_ua_hash,
        salt,
        to_logic_mode(mode),
    )
    .map_err(ApiError::from)
}

/// Hash a string with HMAC-SHA-256 using a keyed MAC and a domain separation tag.
/// Thin wrapper that delegates to the logic crate and converts errors.
pub fn hash_with_salt(input: &str, salt: &str, domain: &str) -> Result<String, ApiError> {
    provii_verifier_logic::session_binding::hash_with_salt(input, salt, domain)
        .map_err(ApiError::from)
}

/// Generate a single-use WebSocket ticket for a session.
/// Thin wrapper that delegates to the logic crate and converts errors.
pub fn generate_ws_ticket(
    session_id: &str,
    expires_at: u64,
    secret: &str,
) -> Result<String, ApiError> {
    provii_verifier_logic::session_binding::generate_ws_ticket(session_id, expires_at, secret)
        .map_err(ApiError::from)
}

/// Validate a WebSocket ticket using constant-time comparison.
/// Thin wrapper that delegates to the logic crate and converts errors.
pub fn validate_ws_ticket(
    ticket: &str,
    session_id: &str,
    expires_at: u64,
    secret: &str,
) -> Result<bool, ApiError> {
    provii_verifier_logic::session_binding::validate_ws_ticket(
        ticket, session_id, expires_at, secret,
    )
    .map_err(ApiError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_with_salt() -> Result<(), Box<dyn std::error::Error>> {
        let input = "192.168.1.1";
        let salt = "test-salt";
        let domain = "provii-ip-v0";

        let hash1 = hash_with_salt(input, salt, domain)?;
        let hash2 = hash_with_salt(input, salt, domain)?;

        // Should be deterministic
        assert_eq!(hash1, hash2);

        // Should be 64 hex characters (HMAC-SHA-256)
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_hash_with_different_salts() -> Result<(), Box<dyn std::error::Error>> {
        let input = "192.168.1.1";
        let salt1 = "salt1";
        let salt2 = "salt2";
        let domain = "provii-ip-v0";

        let hash1 = hash_with_salt(input, salt1, domain)?;
        let hash2 = hash_with_salt(input, salt2, domain)?;

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_hash_with_different_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let salt = "test-salt";
        let domain = "provii-ip-v0";

        let hash1 = hash_with_salt("192.168.1.1", salt, domain)?;
        let hash2 = hash_with_salt("192.168.1.2", salt, domain)?;

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
        Ok(())
    }

    #[test]
    fn test_hash_with_different_domains() -> Result<(), Box<dyn std::error::Error>> {
        let input = "192.168.1.1";
        let salt = "test-salt";

        let hash_ip = hash_with_salt(input, salt, "provii-ip-v0")?;
        let hash_ua = hash_with_salt(input, salt, "provii-ua-v0")?;

        // Different domains should produce different hashes (domain separation)
        assert_ne!(hash_ip, hash_ua);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let expires_at = 1711234567u64;
        let secret = "test-secret-key";

        let ticket1 = generate_ws_ticket(session_id, expires_at, secret)?;
        let ticket2 = generate_ws_ticket(session_id, expires_at, secret)?;

        assert_eq!(ticket1, ticket2);

        // Base64url: alphanumeric, dash, underscore, no padding
        assert!(ticket1
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // HMAC-SHA-256 = 32 bytes = 43 base64url chars (no padding)
        assert_eq!(ticket1.len(), 43);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_different_sessions() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key";
        let expires_at = 1711234567u64;

        let ticket1 = generate_ws_ticket("session-a", expires_at, secret)?;
        let ticket2 = generate_ws_ticket("session-b", expires_at, secret)?;

        assert_ne!(ticket1, ticket2);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_different_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = "session-a";
        let expires_at = 1711234567u64;

        let ticket1 = generate_ws_ticket(session_id, expires_at, "secret-1")?;
        let ticket2 = generate_ws_ticket(session_id, expires_at, "secret-2")?;

        assert_ne!(ticket1, ticket2);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_different_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = "session-a";
        let secret = "test-secret-key";

        let ticket1 = generate_ws_ticket(session_id, 1000, secret)?;
        let ticket2 = generate_ws_ticket(session_id, 2000, secret)?;

        assert_ne!(ticket1, ticket2);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_valid() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = "550e8400-e29b-41d4-a716-446655440000";
        let expires_at = 1711234567u64;
        let secret = "test-secret-key";

        let ticket = generate_ws_ticket(session_id, expires_at, secret)?;
        assert!(validate_ws_ticket(&ticket, session_id, expires_at, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_wrong_session() -> Result<(), Box<dyn std::error::Error>> {
        let secret = "test-secret-key";
        let expires_at = 1711234567u64;

        let ticket = generate_ws_ticket("session-a", expires_at, secret)?;
        assert!(!validate_ws_ticket(
            &ticket,
            "session-b",
            expires_at,
            secret
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_wrong_secret() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = "session-a";
        let expires_at = 1711234567u64;

        let ticket = generate_ws_ticket(session_id, expires_at, "secret-1")?;
        assert!(!validate_ws_ticket(
            &ticket, session_id, expires_at, "secret-2"
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_wrong_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let session_id = "session-a";
        let secret = "test-secret-key";

        let ticket = generate_ws_ticket(session_id, 1000, secret)?;
        assert!(!validate_ws_ticket(&ticket, session_id, 2000, secret)?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_garbage_input() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!validate_ws_ticket(
            "not-a-valid-ticket",
            "session-a",
            1000,
            "secret"
        )?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_empty_ticket() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!validate_ws_ticket("", "session-a", 1000, "secret")?);
        Ok(())
    }

    // --- New coverage tests below ---

    #[test]
    fn test_hash_with_salt_empty_input() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_with_salt("", "salt", "domain")?;
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_hash_with_salt_empty_salt() -> Result<(), Box<dyn std::error::Error>> {
        // HMAC-SHA-256 accepts zero-length keys
        let hash = hash_with_salt("input", "", "domain")?;
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_hash_with_salt_empty_domain() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_with_salt("input", "salt", "")?;
        assert_eq!(hash.len(), 64);

        // Should differ from hash with a non-empty domain
        let hash_with_domain = hash_with_salt("input", "salt", "some-domain")?;
        assert_ne!(hash, hash_with_domain);
        Ok(())
    }

    #[test]
    fn test_hash_with_salt_long_salt() -> Result<(), Box<dyn std::error::Error>> {
        // HMAC internally hashes keys longer than block size (64 bytes for SHA-256)
        let long_salt = "x".repeat(256);
        let hash = hash_with_salt("input", &long_salt, "domain")?;
        assert_eq!(hash.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hash_with_salt_different_domains_differ() -> Result<(), Box<dyn std::error::Error>> {
        // Same input and salt but different domains must yield different hashes,
        // as long as the domain+input concatenation differs.
        let h1 = hash_with_salt("input", "salt", "domain_a")?;
        let h2 = hash_with_salt("input", "salt", "domain_b")?;
        assert_ne!(h1, h2);
        Ok(())
    }

    #[test]
    fn test_hash_with_salt_unicode_input() -> Result<(), Box<dyn std::error::Error>> {
        let hash = hash_with_salt("\u{1F600}", "salt", "domain")?;
        assert_eq!(hash.len(), 64);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_empty_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let ticket = generate_ws_ticket("", 1000, "secret")?;
        assert_eq!(ticket.len(), 43);
        assert!(ticket
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_zero_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let ticket = generate_ws_ticket("sess", 0, "secret")?;
        assert_eq!(ticket.len(), 43);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_max_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let ticket = generate_ws_ticket("sess", u64::MAX, "secret")?;
        assert_eq!(ticket.len(), 43);
        Ok(())
    }

    #[test]
    fn test_generate_ws_ticket_empty_secret() -> Result<(), Box<dyn std::error::Error>> {
        // HMAC accepts empty keys
        let ticket = generate_ws_ticket("sess", 1000, "")?;
        assert_eq!(ticket.len(), 43);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_roundtrip_various_inputs() -> Result<(), Box<dyn std::error::Error>>
    {
        let long_session = "a".repeat(1000);
        let cases = [
            ("session-with-dashes", 1000u64, "key1"),
            ("", 0, ""),
            (long_session.as_str(), u64::MAX, "long-secret-key-here"),
        ];
        for &(session_id, expires_at, secret) in &cases {
            let ticket = generate_ws_ticket(session_id, expires_at, secret)?;
            assert!(
                validate_ws_ticket(&ticket, session_id, expires_at, secret)?,
                "Roundtrip failed for session_id={}, expires_at={}",
                session_id,
                expires_at
            );
        }
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_tampered_single_char() -> Result<(), Box<dyn std::error::Error>> {
        let ticket = generate_ws_ticket("sess", 1000, "secret")?;

        // Flip first character
        let tampered = ticket.clone();
        let first = tampered.as_bytes()[0];
        let replacement = if first == b'A' { b'B' } else { b'A' };
        let mut bytes = tampered.into_bytes();
        bytes[0] = replacement;
        let tampered = String::from_utf8(bytes)?;

        assert!(!validate_ws_ticket(&tampered, "sess", 1000, "secret")?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_truncated() -> Result<(), Box<dyn std::error::Error>> {
        let ticket = generate_ws_ticket("sess", 1000, "secret")?;
        let truncated = &ticket[..ticket.len() - 1];
        assert!(!validate_ws_ticket(truncated, "sess", 1000, "secret")?);
        Ok(())
    }

    #[test]
    fn test_validate_ws_ticket_extended() -> Result<(), Box<dyn std::error::Error>> {
        let ticket = generate_ws_ticket("sess", 1000, "secret")?;
        let extended = format!("{}A", ticket);
        assert!(!validate_ws_ticket(&extended, "sess", 1000, "secret")?);
        Ok(())
    }

    // NOTE: base64url encoding lives in the verifier-logic crate as the private
    // helper session_binding::base64_url_encode_bytes, which is unit-tested there.
    // This module is a thin wrapper over generate_ws_ticket/validate_ws_ticket, so
    // the encoding contract is covered upstream and the ws-ticket tests above
    // exercise it end to end.

    #[test]
    fn test_hash_determinism_across_calls() -> Result<(), Box<dyn std::error::Error>> {
        // Run 5 times to confirm determinism
        let mut results = Vec::new();
        for _ in 0..5 {
            results.push(hash_with_salt("192.168.1.1", "salt", "provii-ip-v0")?);
        }
        for r in &results {
            assert_eq!(r, &results[0]);
        }
        Ok(())
    }
}
