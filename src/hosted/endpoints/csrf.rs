// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! CSRF token endpoint.
//!
//! `GET /v1/csrf-token` generates a new CSRF token for the current session.
//!
//! SECURITY: Tokens are HMAC-signed and bound to the session ID (hashed, never
//! stored in plaintext). The signing key is wrapped in `Zeroizing` so it is
//! cleared from memory on drop. Rate limiting is applied upstream to prevent
//! token-generation DoS.
//!
//! No service binding is involved; this handler is ported as-is from
//! provii-verifier.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use worker::{Error as WorkerError, Response};
use zeroize::Zeroizing;

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

/// CSRF header name used by the hosted verification flow.
pub const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for CSRF token generation.
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Token validity duration in seconds.
    pub token_expiration_seconds: u64,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            token_expiration_seconds: 3600,
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Response for `GET /v1/csrf-token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrfTokenResponse {
    /// CSRF token to include in subsequent mutating requests.
    pub csrf_token: String,

    /// When the token expires (Unix timestamp seconds).
    pub expires_at: u64,

    /// Token validity duration in seconds.
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

/// Generate a CSRF token bound to `session_id`.
///
/// SECURITY: The session ID is hashed inside the token (never stored as
/// plaintext). The signing key is HMAC-derived from the provided key material.
///
/// Pass `"anonymous"` as `session_id` for pre-session endpoints (challenge
/// creation).
///
/// Token format: `base64url(timestamp:session_hash).base64url(hmac_sig)`
fn generate_csrf_token(
    session_id: &str,
    signing_key: &[u8],
    config: &CsrfConfig,
) -> Result<(String, u64), ApiError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let now = crate::utils::current_timestamp();
    let expires_at = now.saturating_add(config.token_expiration_seconds);

    // Hash the session ID so it never appears as plaintext in the token.
    let mut session_mac = HmacSha256::new_from_slice(signing_key)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("Invalid CSRF signing key length")))?;
    session_mac.update(session_id.as_bytes());
    let session_hash = session_mac.finalize().into_bytes();
    let session_hash_b64 = URL_SAFE_NO_PAD.encode(session_hash.get(..16).unwrap_or(&session_hash)); // Truncate to 16 bytes

    // Build payload: "timestamp:session_hash_prefix"
    let payload = format!("{}:{}", now, session_hash_b64);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    // Sign the payload.
    let mut sig_mac = HmacSha256::new_from_slice(signing_key)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("Invalid CSRF signing key length")))?;
    sig_mac.update(payload_b64.as_bytes());
    let sig = sig_mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    let token = format!("{}.{}", payload_b64, sig_b64);
    Ok((token, expires_at))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Reason a CSRF token was rejected.
///
/// Exposed as a short machine-readable tag for audit logging; never surfaces
/// in the response body (clients always receive a generic 403).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfValidationError {
    /// `X-CSRF-Token` header absent or empty.
    Missing,
    /// Token structure is malformed (missing separator, bad base64, bad UTF-8,
    /// unparseable timestamp).
    InvalidFormat,
    /// HMAC signature does not match the recomputed expected signature.
    InvalidSignature,
    /// Token is older than `max_age_seconds`.
    Expired,
    /// Session hash embedded in the token does not match the expected session.
    SessionMismatch,
}

impl CsrfValidationError {
    /// Return a machine-readable failure reason for audit logging.
    pub fn failure_reason(&self) -> &'static str {
        match self {
            CsrfValidationError::Missing => "missing_token",
            CsrfValidationError::InvalidFormat => "invalid_format",
            CsrfValidationError::InvalidSignature => "invalid_signature",
            CsrfValidationError::Expired => "token_expired",
            CsrfValidationError::SessionMismatch => "session_mismatch",
        }
    }
}

/// Compute the 16-byte session-hash prefix that is embedded in a CSRF token.
///
/// Mirrors the logic in [`generate_csrf_token`] so validation and generation
/// produce identical values. The hash truncates to 16 bytes to keep the token
/// short while retaining 128 bits of collision resistance.
fn session_hash_prefix(session_id: &str, signing_key: &[u8]) -> Result<String, ApiError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let mut session_mac = HmacSha256::new_from_slice(signing_key)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("Invalid CSRF signing key length")))?;
    session_mac.update(session_id.as_bytes());
    let session_hash = session_mac.finalize().into_bytes();
    Ok(URL_SAFE_NO_PAD.encode(session_hash.get(..16).unwrap_or(&session_hash)))
}

/// SEC-028: Validate a CSRF token produced by `generate_csrf_token`.
///
/// Validation order matches the order an attacker can cheaply probe:
/// 1. Format is well-formed (base64url payload + '.' + base64url signature).
/// 2. Signature matches the recomputed HMAC (constant-time via
///    `subtle::ConstantTimeEq`). Signature is checked before session binding
///    so that unauthenticated callers cannot probe valid session IDs through
///    timing or response differences.
/// 3. Timestamp is within `max_age_seconds` of `now`.
/// 4. Session hash matches the expected session (constant-time).
///
/// On any failure, returns the structured `CsrfValidationError` variant; the
/// caller is responsible for mapping this to a 403 response and audit log.
///
/// # Arguments
///
/// * `token` - Raw token string from `X-CSRF-Token` header.
/// * `expected_session_id` - Session UUID the token is expected to bind to, or
///   `"anonymous"` for pre-session tokens (logout, simulate-proof).
/// * `signing_key` - HMAC key, the cached current `SESSION_TOKEN_SECRET`.
/// * `max_age_seconds` - Maximum acceptable token age (see [`CsrfConfig::token_expiration_seconds`]).
///
/// # Rotation behaviour (single-slot read path, #31)
///
/// The CSRF read path is single-slot per the rotation class
/// cross-class invariants and the structured observability
/// `secret_version_used` shape. Only the current
/// `SESSION_TOKEN_SECRET` is consulted; `SESSION_TOKEN_SECRET_PREVIOUS`
/// remains loaded into `AppState` for the unrelated session-cookie
/// verify path (which IS dual-slot under its own rolling-window
/// class) but is NOT consulted by this verifier. Rationale:
///
/// - CSRF tokens are short-lived (`token_expiration_seconds`,
///   default 1 hour). Operator runbook waits at least one CSRF TTL
///   between writing the new `SESSION_TOKEN_SECRET` and dropping
///   `_PREVIOUS`, which already covers any in-flight token without
///   needing dual-slot accept on this path.
/// - Single-slot keeps the `secret_version_used` panel cardinality
///   consistent with §10 (one fingerprint per request), so the
///   rotation drill harness reads cleanly.
/// - The drill harness continues to rotate the value (write
///   current, drop previous). The runtime read path here
///   intentionally only consults the current slot.
///
/// A token signed under what was the `_PREVIOUS` slot returns
/// `CsrfValidationError::InvalidSignature` and the user retries.
/// The loud-failure shape is the §4.5 documented behaviour for the
/// CSRF HMAC sub-class.
pub fn validate_csrf_token(
    token: &str,
    expected_session_id: &str,
    signing_key: &[u8],
    max_age_seconds: u64,
) -> Result<(), CsrfValidationError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    if token.is_empty() {
        return Err(CsrfValidationError::Missing);
    }

    // Split payload.signature (generator uses '.' as the sole separator).
    let (payload_b64, sig_b64) = match token.split_once('.') {
        Some(parts) => parts,
        None => return Err(CsrfValidationError::InvalidFormat),
    };

    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err(CsrfValidationError::InvalidFormat);
    }

    // Recompute the expected signature over the opaque payload bytes.
    // This must happen BEFORE decoding the payload so that signature-forgery
    // attempts do not short-circuit on payload parse errors.
    let mut sig_mac = match HmacSha256::new_from_slice(signing_key) {
        Ok(m) => m,
        Err(_) => return Err(CsrfValidationError::InvalidFormat),
    };
    sig_mac.update(payload_b64.as_bytes());
    let expected_sig = sig_mac.finalize().into_bytes();
    let expected_sig_b64 = URL_SAFE_NO_PAD.encode(expected_sig);

    // Constant-time signature comparison (ASVS 11.2.4).
    let sig_match = sig_b64.as_bytes().ct_eq(expected_sig_b64.as_bytes());
    if !bool::from(sig_match) {
        return Err(CsrfValidationError::InvalidSignature);
    }

    // Decode and parse payload AFTER signature is verified. Any malformed
    // payload at this point indicates internal corruption, not a forgery.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .map_err(|_| CsrfValidationError::InvalidFormat)?;
    let payload_str =
        std::str::from_utf8(&payload_bytes).map_err(|_| CsrfValidationError::InvalidFormat)?;

    let (ts_str, session_hash_from_token) = payload_str
        .split_once(':')
        .ok_or(CsrfValidationError::InvalidFormat)?;

    let issued_at: u64 = ts_str
        .parse()
        .map_err(|_| CsrfValidationError::InvalidFormat)?;

    // Expiry check.
    let now = crate::utils::current_timestamp();
    if now.saturating_sub(issued_at) > max_age_seconds {
        return Err(CsrfValidationError::Expired);
    }

    // Session binding (constant-time).
    let expected_session_hash = session_hash_prefix(expected_session_id, signing_key)
        .map_err(|_| CsrfValidationError::InvalidFormat)?;
    let session_match = session_hash_from_token
        .as_bytes()
        .ct_eq(expected_session_hash.as_bytes());
    if !bool::from(session_match) {
        return Err(CsrfValidationError::SessionMismatch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Generate a CSRF token bound to `session_id`.
///
/// SECURITY: The session ID is hashed inside the token (never stored as
/// plaintext). The signing key is HMAC-derived from the provided key material.
///
/// Pass `"anonymous"` as `session_id` for pre-session endpoints (challenge
/// creation). Returns 500 if the signing key is malformed.
///
/// TODO(testing): ADV-VA-06-012 -- CSRF token generation and validation
/// paths lack integration tests covering the full request lifecycle.
pub async fn handle_csrf_token_generation(
    session_id: String,
    signing_key: Zeroizing<String>,
    config: CsrfConfig,
) -> Result<Response, WorkerError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Both failures here are server-side configuration / runtime issues, never
    // user-driven. Map to 503 so the round-trip dispatcher reports it correctly
    // instead of falling through to opaque 500.
    let key_bytes = URL_SAFE_NO_PAD
        .decode(signing_key.as_bytes())
        .map_err(|_| {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[hosted/csrf] Invalid CSRF signing key encoding");
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?;

    let (token, expires_at) =
        generate_csrf_token(&session_id, &key_bytes, &config).map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[hosted/csrf] CSRF token generation failed: {}", _e);
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?;

    let response = CsrfTokenResponse {
        csrf_token: token,
        expires_at,
        expires_in: config.token_expiration_seconds,
    };

    Response::from_json(&response)
}

/// Generate a CSRF token for pre-session use (challenge creation).
///
/// Delegates to [`handle_csrf_token_generation`] with a fixed `"anonymous"`
/// session identifier.
pub async fn handle_anonymous_csrf_token(
    signing_key: Zeroizing<String>,
    config: CsrfConfig,
) -> Result<Response, WorkerError> {
    handle_csrf_token_generation("anonymous".to_string(), signing_key, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csrf_token_basic() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![42u8; 32];
        let config = CsrfConfig::default();

        let result = generate_csrf_token("session-123", &key, &config);
        assert!(result.is_ok());
        let (token, expires_at) = result?;
        assert!(!token.is_empty());
        assert!(token.contains('.'));
        // Session ID should be hashed, not plaintext.
        assert!(!token.contains("session-123"));
        assert!(expires_at > 0);
        Ok(())
    }

    #[test]
    fn test_generate_csrf_token_anonymous() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![42u8; 32];
        let config = CsrfConfig::default();

        let result = generate_csrf_token("anonymous", &key, &config);
        assert!(result.is_ok());
        let (token, _) = result?;
        assert!(!token.contains("anonymous"));
        Ok(())
    }

    #[test]
    fn test_csrf_token_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = CsrfTokenResponse {
            csrf_token: "test-token".to_string(),
            expires_at: 1234567890,
            expires_in: 3600,
        };

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("csrf_token"));
        assert!(json.contains("test-token"));
        assert!(json.contains("1234567890"));
        assert!(json.contains("3600"));
        Ok(())
    }

    #[test]
    fn test_csrf_config_default() {
        let config = CsrfConfig::default();
        assert_eq!(config.token_expiration_seconds, 3600);
    }

    // ── SEC-028 validator tests ─────────────────────────────────────────────

    #[test]
    fn test_validate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![42u8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session-xyz", &key, &config)?;

        validate_csrf_token(&token, "session-xyz", &key, config.token_expiration_seconds)
            .map_err(|e| format!("unexpected {:?}", e))?;
        Ok(())
    }

    #[test]
    fn test_validate_anonymous_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![42u8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("anonymous", &key, &config)?;

        validate_csrf_token(&token, "anonymous", &key, config.token_expiration_seconds)
            .map_err(|e| format!("unexpected {:?}", e))?;
        Ok(())
    }

    #[test]
    fn test_validate_rejects_wrong_session() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![7u8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session-a", &key, &config)?;

        let result =
            validate_csrf_token(&token, "session-b", &key, config.token_expiration_seconds);
        assert_eq!(result, Err(CsrfValidationError::SessionMismatch));
        Ok(())
    }

    #[test]
    fn test_validate_rejects_missing() {
        let key = vec![0u8; 32];
        assert_eq!(
            validate_csrf_token("", "anonymous", &key, 3600),
            Err(CsrfValidationError::Missing)
        );
    }

    #[test]
    fn test_validate_rejects_malformed() {
        let key = vec![0u8; 32];
        // No '.' separator.
        assert_eq!(
            validate_csrf_token("no-dot-here", "anonymous", &key, 3600),
            Err(CsrfValidationError::InvalidFormat)
        );
        // Empty payload or signature part.
        assert_eq!(
            validate_csrf_token(".sig", "anonymous", &key, 3600),
            Err(CsrfValidationError::InvalidFormat)
        );
        assert_eq!(
            validate_csrf_token("payload.", "anonymous", &key, 3600),
            Err(CsrfValidationError::InvalidFormat)
        );
    }

    #[test]
    fn test_validate_rejects_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![1u8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session-1", &key, &config)?;

        let (payload, _sig) = token.split_once('.').ok_or("no dot")?;
        let tampered = format!("{}.AAAA", payload);
        let result = validate_csrf_token(
            &tampered,
            "session-1",
            &key,
            config.token_expiration_seconds,
        );
        assert_eq!(result, Err(CsrfValidationError::InvalidSignature));
        Ok(())
    }

    #[test]
    fn test_validate_rejects_expired() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let key = vec![9u8; 32];

        // Hand-craft a well-signed token with a timestamp two hours in the
        // past so the expiry check fires regardless of clock skew.
        let stale_ts = crate::utils::current_timestamp().saturating_sub(7200);
        let session_hash = session_hash_prefix("session-old", &key)?;
        let payload = format!("{}:{}", stale_ts, session_hash);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let mut mac = HmacSha256::new_from_slice(&key)?;
        mac.update(payload_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let stale_token = format!("{}.{}", payload_b64, sig_b64);

        let result = validate_csrf_token(&stale_token, "session-old", &key, 3600);
        assert_eq!(result, Err(CsrfValidationError::Expired));
        Ok(())
    }

    #[test]
    fn test_validate_rejects_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
        let key_a = vec![0xAAu8; 32];
        let key_b = vec![0xBBu8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session-x", &key_a, &config)?;

        let result =
            validate_csrf_token(&token, "session-x", &key_b, config.token_expiration_seconds);
        assert_eq!(result, Err(CsrfValidationError::InvalidSignature));
        Ok(())
    }

    // ── #31: single-slot read path (rotation class §10) ───────────────────
    //
    // Regression tests pin the §10 single-slot invariant for the CSRF
    // verifier so a future refactor cannot silently reintroduce a dual
    // slot read path against the structured observability
    // `secret_version_used` shape. The session-cookie verify path is
    // separately dual-slot under its own rolling-window class; this
    // surface deliberately is not.

    /// CSRF read path is single-slot: a token signed under what would
    /// historically have been the `_PREVIOUS` slot must NOT verify
    /// against the current key. Pins the rotation read-path shape.
    #[test]
    fn test_single_slot_rejects_token_signed_under_previous_slot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current = vec![0xAAu8; 32];
        let previous = vec![0xBBu8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session-roll", &previous, &config)?;

        let result = validate_csrf_token(
            &token,
            "session-roll",
            &current,
            config.token_expiration_seconds,
        );
        assert_eq!(result, Err(CsrfValidationError::InvalidSignature));
        Ok(())
    }

    /// Single-slot success path: a token signed under the current
    /// key verifies against the current key. Sanity-checks the
    /// dual-slot fallback removal did not break the happy path.
    #[test]
    fn test_single_slot_accepts_token_signed_under_current_slot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current = vec![0x11u8; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session-current", &current, &config)?;

        validate_csrf_token(
            &token,
            "session-current",
            &current,
            config.token_expiration_seconds,
        )
        .map_err(|e| format!("current slot must accept its own token, got {:?}", e))?;
        Ok(())
    }

    // ── CsrfValidationError::failure_reason ─────────────────────────────

    #[test]
    fn test_csrf_validation_error_failure_reasons() {
        assert_eq!(
            CsrfValidationError::Missing.failure_reason(),
            "missing_token"
        );
        assert_eq!(
            CsrfValidationError::InvalidFormat.failure_reason(),
            "invalid_format"
        );
        assert_eq!(
            CsrfValidationError::InvalidSignature.failure_reason(),
            "invalid_signature"
        );
        assert_eq!(
            CsrfValidationError::Expired.failure_reason(),
            "token_expired"
        );
        assert_eq!(
            CsrfValidationError::SessionMismatch.failure_reason(),
            "session_mismatch"
        );
    }

    // ── CSRF_HEADER_NAME constant ───────────────────────────────────────

    #[test]
    fn test_csrf_header_name() {
        assert_eq!(CSRF_HEADER_NAME, "X-CSRF-Token");
    }

    // ── generate_csrf_token determinism and uniqueness ──────────────────

    #[test]
    fn test_generate_csrf_token_contains_dot_separator() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0xCC; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("s", &key, &config)?;
        assert!(
            token.contains('.'),
            "token must contain payload.signature separator"
        );
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 2, "exactly two parts separated by '.'");
        assert!(!parts[0].is_empty());
        assert!(!parts[1].is_empty());
        Ok(())
    }

    #[test]
    fn test_generate_csrf_token_different_sessions_produce_different_tokens(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0xDD; 32];
        let config = CsrfConfig::default();
        let (token_a, _) = generate_csrf_token("session-a", &key, &config)?;
        let (token_b, _) = generate_csrf_token("session-b", &key, &config)?;
        // Different session IDs should produce different tokens
        // (the session hash inside the payload differs).
        assert_ne!(token_a, token_b);
        Ok(())
    }

    #[test]
    fn test_generate_csrf_token_expiration_uses_config() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0xEE; 32];
        let config = CsrfConfig {
            token_expiration_seconds: 7200,
        };
        let now = crate::utils::current_timestamp();
        let (_, expires_at) = generate_csrf_token("test", &key, &config)?;
        // expires_at should be now + 7200, with a small tolerance
        assert!(
            expires_at >= now + 7200 - 2,
            "expires_at should be ~now+7200"
        );
        assert!(
            expires_at <= now + 7200 + 2,
            "expires_at should be ~now+7200"
        );
        Ok(())
    }

    // ── session_hash_prefix consistency ──────────────────────────────────

    #[test]
    fn test_session_hash_prefix_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x55; 32];
        let h1 = session_hash_prefix("session-x", &key)?;
        let h2 = session_hash_prefix("session-x", &key)?;
        assert_eq!(h1, h2, "same input must produce same hash");
        Ok(())
    }

    #[test]
    fn test_session_hash_prefix_different_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x66; 32];
        let h1 = session_hash_prefix("session-a", &key)?;
        let h2 = session_hash_prefix("session-b", &key)?;
        assert_ne!(h1, h2, "different sessions must produce different hashes");
        Ok(())
    }

    #[test]
    fn test_session_hash_prefix_different_keys() -> Result<(), Box<dyn std::error::Error>> {
        let key_a = vec![0x77; 32];
        let key_b = vec![0x88; 32];
        let h1 = session_hash_prefix("session", &key_a)?;
        let h2 = session_hash_prefix("session", &key_b)?;
        assert_ne!(h1, h2, "different keys must produce different hashes");
        Ok(())
    }

    // ── CsrfTokenResponse deserialisation ────────────────────────────────

    #[test]
    fn test_csrf_token_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = CsrfTokenResponse {
            csrf_token: "abc.def".to_string(),
            expires_at: 9999,
            expires_in: 3600,
        };
        let json = serde_json::to_string(&original)?;
        let deserialized: CsrfTokenResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.csrf_token, "abc.def");
        assert_eq!(deserialized.expires_at, 9999);
        assert_eq!(deserialized.expires_in, 3600);
        Ok(())
    }

    #[test]
    fn test_csrf_token_response_rejects_unknown_fields() {
        let json = r#"{"csrf_token":"t","expires_at":1,"expires_in":2,"extra":"bad"}"#;
        let result = serde_json::from_str::<CsrfTokenResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── Validation with zero-length max_age ─────────────────────────────

    #[test]
    fn test_validate_zero_max_age_accepts_same_second_token(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0x99; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("session", &key, &config)?;

        // max_age_seconds = 0 with a token issued in the same second:
        // age is 0, and the expiry check is `age > max_age` (strict gt),
        // so 0 > 0 is false and the token is still valid.
        let result = validate_csrf_token(&token, "session", &key, 0);
        assert_eq!(result, Ok(()));
        Ok(())
    }

    // ── CsrfConfig ──────────────────────────────────────────────────────

    #[test]
    fn test_csrf_config_custom_expiration() {
        let config = CsrfConfig {
            token_expiration_seconds: 1800,
        };
        assert_eq!(config.token_expiration_seconds, 1800);
    }

    // ── CsrfConfig derive coverage ─────────────────────────────────────

    #[test]
    fn test_csrf_config_clone() {
        let original = CsrfConfig {
            token_expiration_seconds: 900,
        };
        let cloned = original.clone();
        assert_eq!(cloned.token_expiration_seconds, 900);
    }

    #[test]
    fn test_csrf_config_debug() {
        let config = CsrfConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("CsrfConfig"));
        assert!(debug_str.contains("3600"));
    }

    // ── CsrfTokenResponse missing fields ────────────────────────────────

    #[test]
    fn test_csrf_token_response_rejects_missing_csrf_token() {
        let json = r#"{"expires_at":1,"expires_in":2}"#;
        let result = serde_json::from_str::<CsrfTokenResponse>(json);
        assert!(result.is_err(), "missing csrf_token should fail");
    }

    #[test]
    fn test_csrf_token_response_rejects_missing_expires_at() {
        let json = r#"{"csrf_token":"t","expires_in":2}"#;
        let result = serde_json::from_str::<CsrfTokenResponse>(json);
        assert!(result.is_err(), "missing expires_at should fail");
    }

    #[test]
    fn test_csrf_token_response_rejects_missing_expires_in() {
        let json = r#"{"csrf_token":"t","expires_at":1}"#;
        let result = serde_json::from_str::<CsrfTokenResponse>(json);
        assert!(result.is_err(), "missing expires_in should fail");
    }

    // ── CsrfValidationError derive coverage ─────────────────────────────

    #[test]
    fn test_csrf_validation_error_clone() {
        let original = CsrfValidationError::SessionMismatch;
        let cloned = original;
        assert_eq!(cloned, CsrfValidationError::SessionMismatch);
    }

    #[test]
    fn test_csrf_validation_error_debug() {
        let err = CsrfValidationError::InvalidSignature;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidSignature"));
    }

    // ── generate_csrf_token with empty session ──────────────────────────

    #[test]
    fn test_generate_csrf_token_empty_session() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0xAA; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("", &key, &config)?;
        assert!(!token.is_empty());
        // Roundtrip validation should work with empty session.
        validate_csrf_token(&token, "", &key, config.token_expiration_seconds)
            .map_err(|e| format!("unexpected {:?}", e))?;
        Ok(())
    }

    // ── validate_csrf_token with max u64 max_age ────────────────────────

    #[test]
    fn test_validate_with_max_age_u64_max() -> Result<(), Box<dyn std::error::Error>> {
        let key = vec![0xBB; 32];
        let config = CsrfConfig::default();
        let (token, _) = generate_csrf_token("s", &key, &config)?;
        // u64::MAX max_age should never expire.
        validate_csrf_token(&token, "s", &key, u64::MAX)
            .map_err(|e| format!("unexpected {:?}", e))?;
        Ok(())
    }

    // ── session_hash_prefix truncation ──────────────────────────────────

    #[test]
    fn test_session_hash_prefix_output_is_base64url() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let key = vec![0xCC; 32];
        let hash = session_hash_prefix("test", &key)?;
        // Must be valid base64url (no padding).
        let decoded = URL_SAFE_NO_PAD.decode(hash.as_bytes())?;
        // Truncated to 16 bytes.
        assert_eq!(decoded.len(), 16);
        Ok(())
    }
}
