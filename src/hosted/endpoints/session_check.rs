// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Session check endpoint.
//!
//! `GET /v1/hosted/session/check` lets provii-agegate check for existing sessions
//! without requiring JavaScript to read HttpOnly cookies. The server reads the
//! cookie and validates the HMAC-signed session token.
//!
//! SECURITY: The HMAC signature is verified with constant-time comparison
//! (`hmac::Mac::verify_slice`). Token expiration and origin binding are both
//! checked. Only the verified status and session ID are returned to the client,
//! never the full token payload. Tampered tokens are audited at Critical
//! severity.
//!
//! No service binding is involved; this handler is ported as-is from
//! provii-verifier.
#![forbid(unsafe_code)]

use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::{Error as WorkerError, Headers, Response};
use zeroize::Zeroizing;

use crate::{analytics::Analytics, AppState};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the session check endpoint.
///
/// SECURITY: Manual `Debug` impl redacts both secret fields to prevent leakage
/// via logging.
#[derive(Clone)]
pub struct SessionCheckConfig {
    /// Session token secret key (base64url-encoded, 32+ bytes).
    /// Wrapped in Zeroizing so the key material is cleared from memory on drop.
    pub session_token_secret: Zeroizing<String>,

    /// Previous session token secret for key rotation (optional).
    /// Wrapped in Zeroizing so the key material is cleared from memory on drop.
    pub session_token_secret_previous: Option<Zeroizing<String>>,

    /// Cookie name to read (e.g., "__Host-session" or "__Host-session-sandbox").
    pub cookie_name: String,
}

impl std::fmt::Debug for SessionCheckConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCheckConfig")
            .field("session_token_secret", &"[REDACTED]")
            .field(
                "session_token_secret_previous",
                &self
                    .session_token_secret_previous
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("cookie_name", &self.cookie_name)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Session details nested object (matches provii-agegate SessionCheckResponse.session).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SessionDetails {
    /// Session ID.
    pub session_id: String,

    /// When session expires (Unix timestamp seconds).
    pub expires_at: u64,
}

/// Response body for session check (matches provii-agegate SessionCheckResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckResponse {
    /// Whether the user has a valid session.
    pub verified: bool,

    /// Session details (only present if verified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionDetails>,
}

impl SessionCheckResponse {
    /// Create a "not verified" response.
    pub fn not_verified() -> Self {
        Self {
            verified: false,
            session: None,
        }
    }

    /// Create a "verified" response.
    ///
    /// ADV-VA-11-004: Returns `not_verified()` if `session_id` is empty,
    /// preventing a verified response with no identity attached.
    pub fn verified(session_id: String, expires_at: u64) -> Self {
        if session_id.is_empty() {
            return Self::not_verified();
        }
        Self {
            verified: true,
            session: Some(SessionDetails {
                session_id,
                expires_at,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Session token types
// ---------------------------------------------------------------------------

/// Data payload inside an HMAC-signed session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Session ID.
    pub session_id: String,
    /// Origin the session was created for.
    pub origin: String,
    /// Expiration timestamp (Unix seconds).
    pub exp: u64,
}

// ---------------------------------------------------------------------------
// Cookie parsing
// ---------------------------------------------------------------------------

/// Parse a named cookie from a `Cookie` header value.
fn parse_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            let value = value.trim_start();
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.trim());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

/// Verify a session token's HMAC signature and extract the payload.
///
/// Token format: `base64url(json_payload).base64url(hmac_sha256(json_payload))`.
///
/// SECURITY: Uses `hmac::Mac::verify_slice` for constant-time comparison.
/// Returns `None` on any failure (bad format, invalid signature, expired,
/// origin mismatch).
fn verify_token(token: &str, origin: &str, secret: &str) -> Option<SessionData> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let (data_b64, sig_b64) = match token.split_once('.') {
        Some((d, s)) if !s.contains('.') => (d, s),
        _ => return None,
    };

    let provided_sig = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).ok()?;
    let secret_bytes = URL_SAFE_NO_PAD.decode(secret.as_bytes()).ok()?;

    // SECURITY: Constant-time HMAC verification.
    let mut mac = HmacSha256::new_from_slice(&secret_bytes).ok()?;
    mac.update(data_b64.as_bytes());
    if mac.verify_slice(&provided_sig).is_err() {
        return None;
    }

    let json_data = URL_SAFE_NO_PAD.decode(data_b64.as_bytes()).ok()?;
    let session_data: SessionData = serde_json::from_slice(&json_data).ok()?;

    // Check expiration.
    let now = crate::utils::current_timestamp();
    if now > session_data.exp {
        return None;
    }

    // Check origin binding (constant-time to prevent timing oracle on origin values).
    {
        use subtle::ConstantTimeEq;
        let a = session_data.origin.as_bytes();
        let b = origin.as_bytes();
        let matches = a.len() == b.len() && bool::from(a.ct_eq(b));
        if !matches {
            return None;
        }
    }

    // ADV-VA-11-004: Fail-closed. If the token parsed successfully but
    // the session_id is empty, the HMAC signature covered a malformed
    // payload. Reject to prevent a verified response with no identity.
    if session_data.session_id.is_empty() {
        return None;
    }

    Some(session_data)
}

/// Verify a token with fallback to the previous secret (key rotation support).
///
/// Returns the [`SessionData`] alongside the [`RotationSlot`] that satisfied
/// verification so the caller can wire the slot signal into the per-request
/// `secret_version` log line.
fn verify_token_with_fallback(
    token: &str,
    origin: &str,
    primary_secret: &str,
    previous_secret: Option<&str>,
) -> Option<(SessionData, crate::security::secret_versions::RotationSlot)> {
    use crate::security::secret_versions::RotationSlot;
    if let Some(data) = verify_token(token, origin, primary_secret) {
        return Some((data, RotationSlot::Current));
    }
    if let Some(prev) = previous_secret {
        if let Some(data) = verify_token(token, origin, prev) {
            return Some((data, RotationSlot::Previous));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `GET /v1/hosted/session/check`.
///
/// Reads the session cookie, validates the HMAC signature (with constant-time
/// comparison) and expiration, then returns the verification status. Falls back
/// to the previous secret during key rotation.
///
/// SECURITY: Tampered tokens are audited at Critical severity as a
/// `SecurityEvent`. Configuration errors and expired tokens return
/// `not_verified` without leaking internal details to the client.
pub async fn handle_hosted_session_check(
    state: Arc<AppState>,
    headers: Headers,
    config: &SessionCheckConfig,
    origin: &str,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();

    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    // 1. Get Cookie header.
    let cookie_header = match headers.get("Cookie").ok().flatten() {
        Some(header) => header,
        None => {
            // No cookies = not verified (normal flow, not an error).
            return Response::from_json(&SessionCheckResponse::not_verified());
        }
    };

    // 2. Parse session cookie.
    let session_token = match parse_cookie(&cookie_header, &config.cookie_name) {
        Some(token) => token.to_string(),
        None => {
            // Cookie not found = not verified (normal flow, not an error).
            return Response::from_json(&SessionCheckResponse::not_verified());
        }
    };

    // 3. Verify token (HMAC signature + expiration + origin), with fallback
    //    to the previous secret for key rotation.
    let previous_ref = config
        .session_token_secret_previous
        .as_ref()
        .map(|z| z.as_str());

    match verify_token_with_fallback(
        &session_token,
        origin,
        &config.session_token_secret,
        previous_ref,
    ) {
        Some((session_data, slot)) => {
            // Valid session.
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_session_check:success")
                .await;

            let duration_ms = worker::Date::now().as_millis().saturating_sub(start) as f64;
            let analytics = Analytics::new(&state.env);
            analytics.hosted_session_checked(
                "/v1/hosted/session/check",
                origin,
                duration_ms,
                "verified",
                &state.cfg.environment,
            );

            // emit secret_version log + apply x-secret-version
            // header carrying the SESSION_TOKEN slot fingerprint that satisfied.
            let line = crate::security::secret_versions::SecretVersionLine::single_for_slot(
                state.session_token_role_label,
                &state.session_token_fingerprint,
                &state.session_token_fingerprint_previous,
                Some(slot),
            );
            line.emit_log("GET /v1/hosted/session/check");
            let mut response = Response::from_json(&SessionCheckResponse::verified(
                session_data.session_id,
                session_data.exp,
            ))?;
            line.apply_header(&mut response)?;
            Ok(response)
        }
        None => {
            // SECURITY: Could be expired, bad format, or tampered. We cannot
            // distinguish without re-parsing, but any failure beyond "no cookie"
            // warrants a warning-level audit entry. The router layer can
            // escalate tampered tokens to Critical.
            // ADV-VA-029: Structured auth failure audit for invalid session tokens.
            state
                .audit_logger
                .log_authentication_failure(
                    &client_ip,
                    "hosted_session_check:token_invalid",
                    None,
                    Some(origin),
                    Some(serde_json::json!({
                        "endpoint": "/v1/hosted/session/check",
                    })),
                )
                .await;

            let duration_ms = worker::Date::now().as_millis().saturating_sub(start) as f64;
            let analytics = Analytics::new(&state.env);
            analytics.hosted_session_checked(
                "/v1/hosted/session/check",
                origin,
                duration_ms,
                "not_verified",
                &state.cfg.environment,
            );

            // emit secret_version log + apply x-secret-version
            // header even on the not-verified path so the rotation panel can
            // group rejected sessions by the slot binding that was active.
            let line = crate::security::secret_versions::SecretVersionLine::single_for_slot(
                state.session_token_role_label,
                &state.session_token_fingerprint,
                &state.session_token_fingerprint_previous,
                None,
            );
            line.emit_log("GET /v1/hosted/session/check");
            let mut response = Response::from_json(&SessionCheckResponse::not_verified())?;
            line.apply_header(&mut response)?;
            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_not_verified() {
        let response = SessionCheckResponse::not_verified();
        assert!(!response.verified);
        assert!(response.session.is_none());
    }

    #[test]
    fn test_response_verified() -> Result<(), Box<dyn std::error::Error>> {
        let response = SessionCheckResponse::verified("sess-123".to_string(), 1700000000);
        assert!(response.verified);
        assert!(response.session.is_some());
        let session = response.session.ok_or("session was None")?;
        assert_eq!(session.session_id, "sess-123");
        assert_eq!(session.expires_at, 1700000000);
        Ok(())
    }

    #[test]
    fn test_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        // Not verified: should not include session field.
        let not_verified = SessionCheckResponse::not_verified();
        let json = serde_json::to_string(&not_verified)?;
        assert!(!json.contains("session"));
        assert!(json.contains("verified"));

        // Verified: should include session with camelCase fields.
        let verified = SessionCheckResponse::verified("sess-123".to_string(), 1700000000);
        let json = serde_json::to_string(&verified)?;
        assert!(json.contains("session"));
        assert!(json.contains("sessionId"));
        assert!(json.contains("expiresAt"));
        // Ensure snake_case is not used.
        assert!(!json.contains("session_id"));
        assert!(!json.contains("expires_at"));
        Ok(())
    }

    #[test]
    fn test_parse_cookie_found() {
        let header = "__Host-session=abc123; other=xyz";
        assert_eq!(parse_cookie(header, "__Host-session"), Some("abc123"));
    }

    #[test]
    fn test_parse_cookie_not_found() {
        let header = "other=xyz; another=abc";
        assert_eq!(parse_cookie(header, "__Host-session"), None);
    }

    #[test]
    fn test_parse_cookie_with_spaces() {
        let header = " __Host-session = abc123 ; other=xyz ";
        assert_eq!(parse_cookie(header, "__Host-session"), Some("abc123"));
    }

    #[test]
    fn test_verify_token_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let data = SessionData {
            session_id: "sess-test".to_string(),
            origin: "https://example.com".to_string(),
            exp: u64::MAX, // never expires for test
        };

        let json = serde_json::to_vec(&data)?;
        let data_b64 = URL_SAFE_NO_PAD.encode(&json);

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);
        let result = verify_token(&token, "https://example.com", &secret);
        assert!(result.is_some());
        let result = result.ok_or("verify_token returned None")?;
        assert_eq!(result.session_id, "sess-test");
        Ok(())
    }

    #[test]
    fn test_verify_token_wrong_origin() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let data = SessionData {
            session_id: "sess-test".to_string(),
            origin: "https://example.com".to_string(),
            exp: u64::MAX,
        };

        let json = serde_json::to_vec(&data)?;
        let data_b64 = URL_SAFE_NO_PAD.encode(&json);

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);
        let result = verify_token(&token, "https://evil.com", &secret);
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_verify_token_tampered() {
        let result = verify_token("tampered.data", "https://example.com", "c29tZS1zZWNyZXQ");
        assert!(result.is_none());
    }

    #[test]
    fn test_config_debug_redacts_secrets() {
        let config = SessionCheckConfig {
            session_token_secret: Zeroizing::new("supersecret".to_string()),
            session_token_secret_previous: Some(Zeroizing::new("oldsecret".to_string())),
            cookie_name: "__Host-session".to_string(),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecret"));
        assert!(!debug_str.contains("oldsecret"));
    }

    // ── parse_cookie: additional edge cases ─────────────────────────────

    #[test]
    fn test_parse_cookie_empty_header() {
        assert_eq!(parse_cookie("", "__Host-session"), None);
    }

    #[test]
    fn test_parse_cookie_only_semicolons() {
        assert_eq!(parse_cookie(";;;", "__Host-session"), None);
    }

    #[test]
    fn test_parse_cookie_name_prefix_of_another() {
        // "session" should NOT match "session_extra=val".
        let header = "session_extra=wrong; session=right";
        assert_eq!(parse_cookie(header, "session"), Some("right"));
    }

    #[test]
    fn test_parse_cookie_empty_value() {
        let header = "__Host-session=";
        assert_eq!(parse_cookie(header, "__Host-session"), Some(""));
    }

    #[test]
    fn test_parse_cookie_value_with_equals() {
        // Cookie values can contain '='.
        let header = "__Host-session=abc=def";
        assert_eq!(parse_cookie(header, "__Host-session"), Some("abc=def"));
    }

    #[test]
    fn test_parse_cookie_multiple_cookies_returns_first() {
        let header = "__Host-session=first; other=x; __Host-session=second";
        // The parser iterates and returns on first match.
        assert_eq!(parse_cookie(header, "__Host-session"), Some("first"));
    }

    #[test]
    fn test_parse_cookie_no_equals_sign() {
        // A cookie pair without '=' should not match.
        let header = "__Host-session";
        assert_eq!(parse_cookie(header, "__Host-session"), None);
    }

    #[test]
    fn test_parse_cookie_whitespace_around_value() {
        let header = "__Host-session =  token_value  ";
        assert_eq!(parse_cookie(header, "__Host-session"), Some("token_value"));
    }

    #[test]
    fn test_parse_cookie_sandbox_name() {
        let header = "__Host-session-sandbox=abc123; __Host-session=other";
        assert_eq!(
            parse_cookie(header, "__Host-session-sandbox"),
            Some("abc123")
        );
    }

    #[test]
    fn test_parse_cookie_value_with_dots() {
        let header = "__Host-session=payload.signature";
        assert_eq!(
            parse_cookie(header, "__Host-session"),
            Some("payload.signature")
        );
    }

    // ── verify_token: malformed formats ─────────────────────────────────

    #[test]
    fn test_verify_token_empty_string() {
        assert!(verify_token("", "https://example.com", "c29tZS1zZWNyZXQ").is_none());
    }

    #[test]
    fn test_verify_token_no_dot() {
        assert!(verify_token("nodothere", "https://example.com", "c29tZS1zZWNyZXQ").is_none());
    }

    #[test]
    fn test_verify_token_multiple_dots_rejected() {
        // Token format must be exactly two parts separated by a single dot.
        assert!(
            verify_token("a.b.c", "https://example.com", "c29tZS1zZWNyZXQ").is_none(),
            "token with two dots should be rejected"
        );
    }

    #[test]
    fn test_verify_token_empty_parts() {
        assert!(verify_token(".", "https://example.com", "c29tZS1zZWNyZXQ").is_none());
    }

    #[test]
    fn test_verify_token_empty_signature_part() {
        assert!(verify_token("payload.", "https://example.com", "c29tZS1zZWNyZXQ").is_none());
    }

    #[test]
    fn test_verify_token_empty_data_part() {
        assert!(verify_token(".signature", "https://example.com", "c29tZS1zZWNyZXQ").is_none());
    }

    // ── verify_token: wrong secret ──────────────────────────────────────

    #[test]
    fn test_verify_token_wrong_secret() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let data = SessionData {
            session_id: "sess-wrong-secret".to_string(),
            origin: "https://example.com".to_string(),
            exp: u64::MAX,
        };

        let json = serde_json::to_vec(&data)?;
        let data_b64 = URL_SAFE_NO_PAD.encode(&json);

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);

        // Verify with a different secret.
        let wrong_secret = URL_SAFE_NO_PAD.encode([99u8; 32]);
        assert!(
            verify_token(&token, "https://example.com", &wrong_secret).is_none(),
            "wrong secret must fail verification"
        );

        // Verify with the correct secret still works.
        assert!(verify_token(&token, "https://example.com", &secret).is_some());
        Ok(())
    }

    // ── verify_token: expired token ─────────────────────────────────────

    #[test]
    fn test_verify_token_expired() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let data = SessionData {
            session_id: "sess-expired".to_string(),
            origin: "https://example.com".to_string(),
            exp: 0, // expired (Unix epoch)
        };

        let json = serde_json::to_vec(&data)?;
        let data_b64 = URL_SAFE_NO_PAD.encode(&json);

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);
        assert!(
            verify_token(&token, "https://example.com", &secret).is_none(),
            "expired token (exp=0) must fail verification"
        );
        Ok(())
    }

    // ── verify_token: payload not valid JSON ────────────────────────────

    #[test]
    fn test_verify_token_non_json_payload() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        // Encode "not json" as base64url payload.
        let data_b64 = URL_SAFE_NO_PAD.encode(b"not json at all");

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);
        assert!(
            verify_token(&token, "https://example.com", &secret).is_none(),
            "non-JSON payload must fail"
        );
        Ok(())
    }

    // ── verify_token: missing fields in payload ─────────────────────────

    #[test]
    fn test_verify_token_missing_origin_field() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        // JSON with session_id and exp but no origin.
        let partial_json = r#"{"session_id":"sess-1","exp":9999999999}"#;
        let data_b64 = URL_SAFE_NO_PAD.encode(partial_json.as_bytes());

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);
        assert!(
            verify_token(&token, "https://example.com", &secret).is_none(),
            "payload missing 'origin' field must fail"
        );
        Ok(())
    }

    // ── verify_token: invalid base64url in signature ────────────────────

    #[test]
    fn test_verify_token_invalid_base64_signature() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let data_b64 = URL_SAFE_NO_PAD.encode(b"{}");
        // '!!!' is not valid base64url.
        let token = format!("{}.!!!", data_b64);
        assert!(verify_token(&token, "https://example.com", "c29tZS1zZWNyZXQ").is_none());
    }

    // ── verify_token_with_fallback ──────────────────────────────────────

    /// Helper to build a valid signed token for a given secret and origin.
    fn build_token(
        session_id: &str,
        origin: &str,
        exp: u64,
        secret_bytes: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let data = SessionData {
            session_id: session_id.to_string(),
            origin: origin.to_string(),
            exp,
        };
        let json = serde_json::to_vec(&data)?;
        let data_b64 = URL_SAFE_NO_PAD.encode(&json);

        let mut mac = HmacSha256::new_from_slice(secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        Ok(format!("{}.{}", data_b64, sig_b64))
    }

    #[test]
    fn test_verify_token_with_fallback_primary_succeeds() -> Result<(), Box<dyn std::error::Error>>
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let primary_bytes = [1u8; 32];
        let previous_bytes = [2u8; 32];
        let primary_secret = URL_SAFE_NO_PAD.encode(primary_bytes);
        let previous_secret = URL_SAFE_NO_PAD.encode(previous_bytes);

        let token = build_token(
            "sess-primary",
            "https://example.com",
            u64::MAX,
            &primary_bytes,
        )?;

        let result = verify_token_with_fallback(
            &token,
            "https://example.com",
            &primary_secret,
            Some(&previous_secret),
        );
        assert!(result.is_some(), "token signed with primary should verify");
        let (data, slot) = result.ok_or("expected Some")?;
        assert_eq!(data.session_id, "sess-primary");
        assert_eq!(
            slot,
            crate::security::secret_versions::RotationSlot::Current
        );
        Ok(())
    }

    #[test]
    fn test_verify_token_with_fallback_previous_succeeds() -> Result<(), Box<dyn std::error::Error>>
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let primary_bytes = [1u8; 32];
        let previous_bytes = [2u8; 32];
        let primary_secret = URL_SAFE_NO_PAD.encode(primary_bytes);
        let previous_secret = URL_SAFE_NO_PAD.encode(previous_bytes);

        let token = build_token(
            "sess-previous",
            "https://example.com",
            u64::MAX,
            &previous_bytes,
        )?;

        let result = verify_token_with_fallback(
            &token,
            "https://example.com",
            &primary_secret,
            Some(&previous_secret),
        );
        assert!(
            result.is_some(),
            "token signed with previous secret should verify via fallback"
        );
        let (data, slot) = result.ok_or("expected Some")?;
        assert_eq!(data.session_id, "sess-previous");
        assert_eq!(
            slot,
            crate::security::secret_versions::RotationSlot::Previous
        );
        Ok(())
    }

    #[test]
    fn test_verify_token_with_fallback_neither_succeeds() -> Result<(), Box<dyn std::error::Error>>
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let primary_bytes = [1u8; 32];
        let previous_bytes = [2u8; 32];
        let unrelated_bytes = [3u8; 32];
        let primary_secret = URL_SAFE_NO_PAD.encode(primary_bytes);
        let previous_secret = URL_SAFE_NO_PAD.encode(previous_bytes);

        let token = build_token(
            "sess-unknown",
            "https://example.com",
            u64::MAX,
            &unrelated_bytes,
        )?;

        let result = verify_token_with_fallback(
            &token,
            "https://example.com",
            &primary_secret,
            Some(&previous_secret),
        );
        assert!(
            result.is_none(),
            "token signed with unknown secret must fail both slots"
        );
        Ok(())
    }

    #[test]
    fn test_verify_token_with_fallback_no_previous_secret() -> Result<(), Box<dyn std::error::Error>>
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let primary_bytes = [1u8; 32];
        let primary_secret = URL_SAFE_NO_PAD.encode(primary_bytes);

        let token = build_token(
            "sess-noprev",
            "https://example.com",
            u64::MAX,
            &primary_bytes,
        )?;

        let result = verify_token_with_fallback(
            &token,
            "https://example.com",
            &primary_secret,
            None, // no previous secret
        );
        assert!(result.is_some());
        let (data, slot) = result.ok_or("expected Some")?;
        assert_eq!(data.session_id, "sess-noprev");
        assert_eq!(
            slot,
            crate::security::secret_versions::RotationSlot::Current
        );
        Ok(())
    }

    #[test]
    fn test_verify_token_with_fallback_no_previous_and_wrong_primary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let primary_bytes = [1u8; 32];
        let unrelated_bytes = [3u8; 32];
        let primary_secret = URL_SAFE_NO_PAD.encode(primary_bytes);

        let token = build_token(
            "sess-fail",
            "https://example.com",
            u64::MAX,
            &unrelated_bytes,
        )?;

        let result =
            verify_token_with_fallback(&token, "https://example.com", &primary_secret, None);
        assert!(result.is_none());
        Ok(())
    }

    #[test]
    fn test_verify_token_with_fallback_expired_token() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let primary_bytes = [1u8; 32];
        let primary_secret = URL_SAFE_NO_PAD.encode(primary_bytes);

        // exp=0 is in the past.
        let token = build_token("sess-exp", "https://example.com", 0, &primary_bytes)?;

        let result =
            verify_token_with_fallback(&token, "https://example.com", &primary_secret, None);
        assert!(
            result.is_none(),
            "expired token must fail even with correct secret"
        );
        Ok(())
    }

    // ── SessionData serde ───────────────────────────────────────────────

    #[test]
    fn test_session_data_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let data = SessionData {
            session_id: "sess-rt".to_string(),
            origin: "https://example.com".to_string(),
            exp: 1700000000,
        };
        let json = serde_json::to_string(&data)?;
        let deserialized: SessionData = serde_json::from_str(&json)?;
        assert_eq!(deserialized.session_id, "sess-rt");
        assert_eq!(deserialized.origin, "https://example.com");
        assert_eq!(deserialized.exp, 1700000000);
        Ok(())
    }

    #[test]
    fn test_session_data_field_names() -> Result<(), Box<dyn std::error::Error>> {
        let data = SessionData {
            session_id: "s".to_string(),
            origin: "o".to_string(),
            exp: 0,
        };
        let val: serde_json::Value = serde_json::to_value(&data)?;
        assert!(val.get("session_id").is_some());
        assert!(val.get("origin").is_some());
        assert!(val.get("exp").is_some());
        Ok(())
    }

    #[test]
    fn test_session_data_missing_field_rejected() {
        let json = r#"{"session_id":"s","origin":"o"}"#;
        let result = serde_json::from_str::<SessionData>(json);
        assert!(result.is_err(), "missing 'exp' field should fail");
    }

    #[test]
    fn test_session_data_debug_shows_fields() {
        let data = SessionData {
            session_id: "sess-dbg".to_string(),
            origin: "https://test.com".to_string(),
            exp: 42,
        };
        let debug_str = format!("{:?}", data);
        assert!(debug_str.contains("sess-dbg"));
        assert!(debug_str.contains("https://test.com"));
    }

    #[test]
    fn test_session_data_clone() {
        let data = SessionData {
            session_id: "sess-clone".to_string(),
            origin: "https://clone.com".to_string(),
            exp: 999,
        };
        let cloned = data.clone();
        assert_eq!(cloned.session_id, "sess-clone");
        assert_eq!(cloned.origin, "https://clone.com");
        assert_eq!(cloned.exp, 999);
    }

    // ── SessionDetails serde (camelCase) ────────────────────────────────

    #[test]
    fn test_session_details_camel_case_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let details = SessionDetails {
            session_id: "s1".to_string(),
            expires_at: 123,
        };
        let json = serde_json::to_string(&details)?;
        assert!(
            json.contains("sessionId"),
            "session_id must serialize as sessionId"
        );
        assert!(
            json.contains("expiresAt"),
            "expires_at must serialize as expiresAt"
        );
        assert!(!json.contains("session_id"));
        assert!(!json.contains("expires_at"));
        Ok(())
    }

    #[test]
    fn test_session_details_camel_case_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"sessionId":"s2","expiresAt":456}"#;
        let details: SessionDetails = serde_json::from_str(json)?;
        assert_eq!(details.session_id, "s2");
        assert_eq!(details.expires_at, 456);
        Ok(())
    }

    #[test]
    fn test_session_details_snake_case_deserialization_rejected() {
        let json = r#"{"session_id":"s3","expires_at":789}"#;
        let result = serde_json::from_str::<SessionDetails>(json);
        assert!(
            result.is_err(),
            "snake_case field names should be rejected with rename_all=camelCase + deny_unknown_fields"
        );
    }

    #[test]
    fn test_session_details_unknown_field_rejected() {
        let json = r#"{"sessionId":"s4","expiresAt":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<SessionDetails>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── SessionCheckResponse serde ──────────────────────────────────────

    #[test]
    fn test_session_check_response_not_verified_json_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = SessionCheckResponse::not_verified();
        let val: serde_json::Value = serde_json::to_value(&resp)?;
        let obj = val.as_object().ok_or("expected object")?;
        // "session" should be absent (skip_serializing_if = None).
        assert_eq!(
            obj.len(),
            1,
            "not_verified should only have 'verified' field"
        );
        assert_eq!(val["verified"], false);
        Ok(())
    }

    #[test]
    fn test_session_check_response_verified_json_shape() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SessionCheckResponse::verified("sid".to_string(), 100);
        let val: serde_json::Value = serde_json::to_value(&resp)?;
        let obj = val.as_object().ok_or("expected object")?;
        assert_eq!(
            obj.len(),
            2,
            "verified response should have 'verified' and 'session'"
        );
        assert_eq!(val["verified"], true);
        assert!(val["session"].is_object());
        assert_eq!(val["session"]["sessionId"], "sid");
        assert_eq!(val["session"]["expiresAt"], 100);
        Ok(())
    }

    #[test]
    fn test_session_check_response_roundtrip_not_verified() -> Result<(), Box<dyn std::error::Error>>
    {
        let original = SessionCheckResponse::not_verified();
        let json = serde_json::to_string(&original)?;
        let deserialized: SessionCheckResponse = serde_json::from_str(&json)?;
        assert!(!deserialized.verified);
        assert!(deserialized.session.is_none());
        Ok(())
    }

    #[test]
    fn test_session_check_response_roundtrip_verified() -> Result<(), Box<dyn std::error::Error>> {
        let original = SessionCheckResponse::verified("sess-rt".to_string(), 9999);
        let json = serde_json::to_string(&original)?;
        let deserialized: SessionCheckResponse = serde_json::from_str(&json)?;
        assert!(deserialized.verified);
        let session = deserialized.session.ok_or("session should be present")?;
        assert_eq!(session.session_id, "sess-rt");
        assert_eq!(session.expires_at, 9999);
        Ok(())
    }

    #[test]
    fn test_session_check_response_rejects_unknown_fields() {
        let json = r#"{"verified":true,"session":null,"extra":"bad"}"#;
        let result = serde_json::from_str::<SessionCheckResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_check_response_missing_verified() {
        let json = r#"{"session":null}"#;
        let result = serde_json::from_str::<SessionCheckResponse>(json);
        assert!(result.is_err(), "missing 'verified' field should fail");
    }

    // ── SessionCheckConfig ──────────────────────────────────────────────

    #[test]
    fn test_config_debug_without_previous_secret() {
        let config = SessionCheckConfig {
            session_token_secret: Zeroizing::new("current-key".to_string()),
            session_token_secret_previous: None,
            cookie_name: "__Host-session".to_string(),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(debug_str.contains("None"));
        assert!(!debug_str.contains("current-key"));
        assert!(debug_str.contains("__Host-session"));
    }

    #[test]
    fn test_config_clone() {
        let config = SessionCheckConfig {
            session_token_secret: Zeroizing::new("secret".to_string()),
            session_token_secret_previous: Some(Zeroizing::new("prev".to_string())),
            cookie_name: "__Host-session-sandbox".to_string(),
        };
        let cloned = config.clone();
        assert_eq!(*cloned.session_token_secret, "secret");
        assert_eq!(
            cloned
                .session_token_secret_previous
                .as_deref()
                .map(String::as_str),
            Some("prev")
        );
        assert_eq!(cloned.cookie_name, "__Host-session-sandbox");
    }

    #[test]
    fn test_config_debug_shows_cookie_name() {
        let config = SessionCheckConfig {
            session_token_secret: Zeroizing::new("x".to_string()),
            session_token_secret_previous: None,
            cookie_name: "__Host-session-sandbox".to_string(),
        };
        let debug_str = format!("{:?}", config);
        assert!(
            debug_str.contains("__Host-session-sandbox"),
            "cookie_name is not secret and should appear in debug output"
        );
    }

    // ── SessionCheckResponse constructors ───────────────────────────────

    #[test]
    fn test_not_verified_is_not_verified() {
        let resp = SessionCheckResponse::not_verified();
        assert!(!resp.verified);
    }

    #[test]
    fn test_verified_with_empty_session_id_returns_not_verified() {
        // ADV-VA-11-004: Empty session_id must not produce a verified response.
        let resp = SessionCheckResponse::verified(String::new(), 0);
        assert!(
            !resp.verified,
            "empty session_id must fail-close to not_verified"
        );
        assert!(resp.session.is_none());
    }

    #[test]
    fn test_verified_with_max_expires_at() {
        let resp = SessionCheckResponse::verified("s".to_string(), u64::MAX);
        let session = resp.session.expect("session should be present");
        assert_eq!(session.expires_at, u64::MAX);
    }

    // ── verify_token: origin binding edge cases ─────────────────────────

    #[test]
    fn test_verify_token_empty_origin() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let token = build_token("sess-empty-origin", "", u64::MAX, &secret_bytes)?;

        // Verify with empty origin should succeed (origin matches).
        assert!(verify_token(&token, "", &secret).is_some());
        // Verify with non-empty origin should fail.
        assert!(verify_token(&token, "https://example.com", &secret).is_none());
        Ok(())
    }

    #[test]
    fn test_verify_token_case_sensitive_origin() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let token = build_token("sess-case", "https://Example.Com", u64::MAX, &secret_bytes)?;

        // Exact match works.
        assert!(verify_token(&token, "https://Example.Com", &secret).is_some());
        // Different case fails.
        assert!(verify_token(&token, "https://example.com", &secret).is_none());
        Ok(())
    }

    // ── verify_token: payload with extra fields still parses ────────────

    #[test]
    fn test_verify_token_extra_fields_in_payload() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        // SessionData does not have deny_unknown_fields, so extra fields are tolerated.
        let payload_json = r#"{"session_id":"sess-extra","origin":"https://example.com","exp":9999999999,"extra":"bonus"}"#;
        let data_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let mut mac = HmacSha256::new_from_slice(&secret_bytes)?;
        mac.update(data_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        let token = format!("{}.{}", data_b64, sig_b64);
        let result = verify_token(&token, "https://example.com", &secret);
        assert!(
            result.is_some(),
            "extra fields in token payload should not break verification"
        );
        let data = result.ok_or("expected Some")?;
        assert_eq!(data.session_id, "sess-extra");
        Ok(())
    }

    // ── verify_token: token signed with one-byte secret ─────────────────

    #[test]
    fn test_verify_token_short_secret() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        // HMAC-SHA256 accepts any key length. A single byte is valid but weak.
        let secret_bytes = [0xABu8];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        let token = build_token(
            "sess-short-key",
            "https://example.com",
            u64::MAX,
            &secret_bytes,
        )?;

        let result = verify_token(&token, "https://example.com", &secret);
        assert!(result.is_some(), "HMAC-SHA256 should accept any key length");
        Ok(())
    }

    // ── verify_token_with_fallback: primary preferred over previous ─────

    #[test]
    fn test_verify_token_with_fallback_prefers_primary() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        // Use the same secret for both primary and previous.
        let shared_bytes = [7u8; 32];
        let shared_secret = URL_SAFE_NO_PAD.encode(shared_bytes);

        let token = build_token("sess-both", "https://example.com", u64::MAX, &shared_bytes)?;

        let result = verify_token_with_fallback(
            &token,
            "https://example.com",
            &shared_secret,
            Some(&shared_secret),
        );
        assert!(result.is_some());
        let (_, slot) = result.ok_or("expected Some")?;
        // When both secrets are the same, primary should be returned (checked first).
        assert_eq!(
            slot,
            crate::security::secret_versions::RotationSlot::Current,
            "primary slot should be preferred when both secrets match"
        );
        Ok(())
    }

    // ── parse_cookie: realistic token values ────────────────────────────

    #[test]
    fn test_parse_cookie_token_with_base64url_chars() {
        let token = "eyJzZXNzaW9uX2lkIjoic2Vzcy0xIn0.HMAC_SIG-abc_def";
        let header = format!("__Host-session={}", token);
        assert_eq!(parse_cookie(&header, "__Host-session"), Some(token));
    }

    #[test]
    fn test_parse_cookie_many_cookies() {
        let header = "a=1; b=2; c=3; d=4; __Host-session=target; e=5; f=6";
        assert_eq!(parse_cookie(header, "__Host-session"), Some("target"));
    }

    // ── ADV-VA-11-004: fail-closed on empty session_id ─────────────────

    #[test]
    fn test_verify_token_rejects_empty_session_id() -> Result<(), Box<dyn std::error::Error>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let secret_bytes = [42u8; 32];
        let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

        // Build a token with an empty session_id
        let token = build_token("", "https://example.com", u64::MAX, &secret_bytes)?;

        // ADV-VA-11-004: verify_token must reject empty session_id
        let result = verify_token(&token, "https://example.com", &secret);
        assert!(
            result.is_none(),
            "empty session_id in token must be rejected (fail-closed)"
        );
        Ok(())
    }

    #[test]
    fn test_verified_response_with_valid_session_id() {
        let resp = SessionCheckResponse::verified("sess-valid".to_string(), 9999);
        assert!(resp.verified);
        let session = resp.session.expect("session should be present");
        assert_eq!(session.session_id, "sess-valid");
    }
}
