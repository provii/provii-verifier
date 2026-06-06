// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Session binding: keyed hashing and WebSocket ticket generation (pure logic).
//!
//! SECURITY: All comparisons of computed vs stored hashes use
//! `subtle::ConstantTimeEq` to prevent timing side-channels.
//! HMAC-SHA-256 with domain separation tags (`provii-ip-v0`, `provii-ua-v0`,
//! `provii-ws-ticket-v1`) prevents cross-context hash collisions.
#![forbid(unsafe_code)]

use crate::error::LogicError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Session binding mode for IP/User-Agent validation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SessionBindingMode {
    /// Reject any IP or User-Agent mismatch.
    Strict,
    /// Log warning but allow (for mobile IP changes).
    #[default]
    Relaxed,
    /// No enforcement.
    None,
}

/// Outcome of a session binding verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingOutcome {
    /// All binding checks passed (or no stored hashes to compare).
    Ok,
    /// IP mismatch in Relaxed mode (logged, not rejected).
    IpMismatchRelaxed,
    /// UA mismatch in Relaxed mode (logged, not rejected).
    UaMismatchRelaxed,
}

/// Verify that the current request's IP and User-Agent match the session's
/// stored binding hashes.
///
/// SECURITY: Recomputes HMAC-SHA-256 hashes and compares via
/// `subtle::ConstantTimeEq`.
pub fn verify_session_binding(
    current_ip: &str,
    current_ua: Option<&str>,
    stored_ip_hash: Option<&str>,
    stored_ua_hash: Option<&str>,
    salt: &str,
    mode: SessionBindingMode,
) -> Result<BindingOutcome, LogicError> {
    if mode == SessionBindingMode::None {
        return Ok(BindingOutcome::Ok);
    }

    // Verify IP binding.
    if let Some(expected_ip_hash) = stored_ip_hash {
        let computed_ip_hash = hash_with_salt(current_ip, salt, "provii-ip-v0")?;
        // SECURITY: Constant-time comparison via subtle::ConstantTimeEq.
        let ip_match: bool = computed_ip_hash
            .as_bytes()
            .ct_eq(expected_ip_hash.as_bytes())
            .into();
        if !ip_match {
            match mode {
                SessionBindingMode::Strict => {
                    return Err(LogicError::SessionBindingMismatch);
                }
                SessionBindingMode::Relaxed => {
                    return Ok(BindingOutcome::IpMismatchRelaxed);
                }
                SessionBindingMode::None => { /* handled above */ }
            }
        }
    }

    // Verify UA binding.
    if let (Some(expected_ua_hash), Some(ua)) = (stored_ua_hash, current_ua) {
        let computed_ua_hash = hash_with_salt(ua, salt, "provii-ua-v0")?;
        // SECURITY: Constant-time comparison via subtle::ConstantTimeEq.
        let ua_match: bool = computed_ua_hash
            .as_bytes()
            .ct_eq(expected_ua_hash.as_bytes())
            .into();
        if !ua_match {
            match mode {
                SessionBindingMode::Strict => {
                    return Err(LogicError::SessionBindingMismatch);
                }
                SessionBindingMode::Relaxed => {
                    return Ok(BindingOutcome::UaMismatchRelaxed);
                }
                SessionBindingMode::None => { /* handled above */ }
            }
        }
    }

    Ok(BindingOutcome::Ok)
}

/// Hash a string with HMAC-SHA-256 using a keyed MAC and a domain separation tag.
///
/// Uses `HMAC-SHA-256(key=salt, message=domain || input)`.
/// The domain tag prevents cross-context hash collisions.
///
/// Returns hex-encoded HMAC-SHA-256 tag (64 characters).
pub fn hash_with_salt(input: &str, salt: &str, domain: &str) -> Result<String, LogicError> {
    let mut mac =
        HmacSha256::new_from_slice(salt.as_bytes()).map_err(|_| LogicError::HmacKeyRejected)?;
    mac.update(domain.as_bytes());
    mac.update(input.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Generate a single-use WebSocket ticket for a session.
///
/// Domain tag `"provii-ws-ticket-v1"` prevents cross-context collisions.
/// 4-byte LE length prefix before session_id eliminates concatenation ambiguity.
pub fn generate_ws_ticket(
    session_id: &str,
    expires_at: u64,
    secret: &str,
) -> Result<String, LogicError> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| LogicError::HmacKeyRejected)?;
    mac.update(b"provii-ws-ticket-v1");
    let len_u32 = u32::try_from(session_id.len()).map_err(|_| LogicError::MalformedInput)?;
    mac.update(&len_u32.to_le_bytes());
    mac.update(session_id.as_bytes());
    mac.update(expires_at.to_string().as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(base64_url_encode_bytes(&result))
}

/// Validate a WebSocket ticket using constant-time comparison.
///
/// SECURITY: Uses `subtle::ConstantTimeEq` to prevent timing side-channels.
pub fn validate_ws_ticket(
    ticket: &str,
    session_id: &str,
    expires_at: u64,
    secret: &str,
) -> Result<bool, LogicError> {
    let expected = generate_ws_ticket(session_id, expires_at, secret)?;
    Ok(expected.as_bytes().ct_eq(ticket.as_bytes()).into())
}

/// Base64url-encode a byte slice without padding.
fn base64_url_encode_bytes(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_with_salt() {
        let hash1 = hash_with_salt("192.168.1.1", "test-salt", "provii-ip-v0").expect("ok");
        let hash2 = hash_with_salt("192.168.1.1", "test-salt", "provii-ip-v0").expect("ok");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_with_different_salts() {
        let h1 = hash_with_salt("192.168.1.1", "salt1", "provii-ip-v0").expect("ok");
        let h2 = hash_with_salt("192.168.1.1", "salt2", "provii-ip-v0").expect("ok");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_with_different_domains() {
        let h1 = hash_with_salt("192.168.1.1", "salt", "provii-ip-v0").expect("ok");
        let h2 = hash_with_salt("192.168.1.1", "salt", "provii-ua-v0").expect("ok");
        assert_ne!(h1, h2);
    }

    // AAD/domain-sep regression: the provii-verifier domain tags must produce
    // stable, distinct hashes. If these change, session binding breaks.
    #[test]
    fn domain_tags_are_distinct_regression() {
        let ip = hash_with_salt("x", "s", "provii-ip-v0").expect("ok");
        let ua = hash_with_salt("x", "s", "provii-ua-v0").expect("ok");
        let ws = hash_with_salt("x", "s", "provii-ws-ticket-v1").expect("ok");
        assert_ne!(ip, ua);
        assert_ne!(ip, ws);
        assert_ne!(ua, ws);
    }

    #[test]
    fn test_generate_ws_ticket_deterministic() {
        let t1 = generate_ws_ticket("sess-a", 1711234567, "secret").expect("ok");
        let t2 = generate_ws_ticket("sess-a", 1711234567, "secret").expect("ok");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn test_generate_ws_ticket_different_sessions() {
        let t1 = generate_ws_ticket("session-a", 1000, "secret").expect("ok");
        let t2 = generate_ws_ticket("session-b", 1000, "secret").expect("ok");
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_validate_ws_ticket_valid() {
        let ticket = generate_ws_ticket("sess-a", 1000, "secret").expect("ok");
        assert!(validate_ws_ticket(&ticket, "sess-a", 1000, "secret").expect("ok"));
    }

    #[test]
    fn test_validate_ws_ticket_wrong_session() {
        let ticket = generate_ws_ticket("session-a", 1000, "secret").expect("ok");
        assert!(!validate_ws_ticket(&ticket, "session-b", 1000, "secret").expect("ok"));
    }

    #[test]
    fn test_validate_ws_ticket_wrong_secret() {
        let ticket = generate_ws_ticket("session-a", 1000, "secret-1").expect("ok");
        assert!(!validate_ws_ticket(&ticket, "session-a", 1000, "secret-2").expect("ok"));
    }

    #[test]
    fn test_validate_ws_ticket_wrong_expiry() {
        let ticket = generate_ws_ticket("sess-a", 1000, "secret").expect("ok");
        assert!(!validate_ws_ticket(&ticket, "sess-a", 2000, "secret").expect("ok"));
    }

    #[test]
    fn test_validate_ws_ticket_garbage() {
        assert!(!validate_ws_ticket("not-a-valid-ticket", "sess-a", 1000, "secret").expect("ok"));
    }

    #[test]
    fn test_validate_ws_ticket_empty() {
        assert!(!validate_ws_ticket("", "sess-a", 1000, "secret").expect("ok"));
    }

    #[test]
    fn test_verify_session_binding_none_mode() {
        let result = verify_session_binding(
            "1.2.3.4",
            Some("ua"),
            Some("wrong-hash"),
            Some("wrong-hash"),
            "salt",
            SessionBindingMode::None,
        );
        assert_eq!(result.expect("ok"), BindingOutcome::Ok);
    }

    #[test]
    fn test_verify_session_binding_strict_ip_mismatch() {
        let ip_hash = hash_with_salt("1.2.3.4", "salt", "provii-ip-v0").expect("ok");
        let result = verify_session_binding(
            "5.6.7.8",
            None,
            Some(&ip_hash),
            None,
            "salt",
            SessionBindingMode::Strict,
        );
        assert_eq!(result.unwrap_err(), LogicError::SessionBindingMismatch);
    }

    #[test]
    fn test_verify_session_binding_relaxed_ip_mismatch() {
        let ip_hash = hash_with_salt("1.2.3.4", "salt", "provii-ip-v0").expect("ok");
        let result = verify_session_binding(
            "5.6.7.8",
            None,
            Some(&ip_hash),
            None,
            "salt",
            SessionBindingMode::Relaxed,
        );
        assert_eq!(result.expect("ok"), BindingOutcome::IpMismatchRelaxed);
    }

    #[test]
    fn test_verify_session_binding_strict_ua_mismatch() {
        let ua_hash = hash_with_salt("Firefox", "salt", "provii-ua-v0").expect("ok");
        let result = verify_session_binding(
            "1.2.3.4",
            Some("Chrome"),
            None,
            Some(&ua_hash),
            "salt",
            SessionBindingMode::Strict,
        );
        assert_eq!(result.unwrap_err(), LogicError::SessionBindingMismatch);
    }

    #[test]
    fn test_verify_session_binding_relaxed_ua_mismatch() {
        let ua_hash = hash_with_salt("Firefox", "salt", "provii-ua-v0").expect("ok");
        let result = verify_session_binding(
            "1.2.3.4",
            Some("Chrome"),
            None,
            Some(&ua_hash),
            "salt",
            SessionBindingMode::Relaxed,
        );
        assert_eq!(result.expect("ok"), BindingOutcome::UaMismatchRelaxed);
    }

    #[test]
    fn test_verify_session_binding_match() {
        let ip_hash = hash_with_salt("1.2.3.4", "salt", "provii-ip-v0").expect("ok");
        let ua_hash = hash_with_salt("Firefox", "salt", "provii-ua-v0").expect("ok");
        let result = verify_session_binding(
            "1.2.3.4",
            Some("Firefox"),
            Some(&ip_hash),
            Some(&ua_hash),
            "salt",
            SessionBindingMode::Strict,
        );
        assert_eq!(result.expect("ok"), BindingOutcome::Ok);
    }

    #[test]
    fn test_verify_session_binding_no_stored_hashes() {
        let result = verify_session_binding(
            "1.2.3.4",
            Some("Firefox"),
            None,
            None,
            "salt",
            SessionBindingMode::Strict,
        );
        assert_eq!(result.expect("ok"), BindingOutcome::Ok);
    }

    #[test]
    fn test_hash_with_salt_empty_input() {
        let hash = hash_with_salt("", "salt", "domain").expect("ok");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_hash_with_salt_empty_salt() {
        let hash = hash_with_salt("input", "", "domain").expect("ok");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_base64_url_encode_bytes_no_padding() {
        let data = [0u8; 32];
        let encoded = base64_url_encode_bytes(&data);
        assert_eq!(encoded.len(), 43);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }
}
