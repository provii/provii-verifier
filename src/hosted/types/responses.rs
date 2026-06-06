// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Response types for hosted backend API endpoints.

use crate::hosted::types::session::SessionState;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

fn default_proof_direction() -> String {
    "over_age".to_string()
}

/// Response from POST /v1/hosted/challenge
///
/// Returns session details and QR code data for the frontend SDK.
/// Includes PKCE-compatible fields for browser SDK integration.
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// `submit_secret` and `csrf_token` are zeroised on drop. Debug output redacts
/// both fields plus the CSRF token to prevent accidental logging of secrets.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    /// Unique session identifier
    pub session_id: String,

    /// Issuer challenge ID (from provii-issuer)
    pub challenge_id: String,

    /// QR code URL for scanning
    pub qr_code_url: String,

    /// Human-readable challenge code (e.g., "1234-5678-9012")
    pub challenge_code: String,

    /// 12-digit short code for accessibility (raw, without dashes)
    pub short_code: String,

    /// Human-readable formatted short code for accessibility (e.g. "1234 5678 9012")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_code_formatted: Option<String>,

    /// When the session expires (Unix timestamp seconds)
    pub expires_at: u64,

    /// Current session status
    pub status: String,

    // -------------------------------------------------------------------------
    // PKCE-compatible fields for browser SDK (provii-agegate) integration
    // These fields are passed through from provii-verifier to enable the SDK's
    // state machine to work correctly with the hosted backend flow.
    // -------------------------------------------------------------------------
    /// Base64url-encoded relying-party challenge (43 chars)
    /// Used by the mobile wallet to generate the ZK proof
    pub rp_challenge: String,

    /// Base64url-encoded submit secret (43 chars)
    /// Anti-spam token for proof submission (server-generated, per-challenge)
    pub submit_secret: String,

    /// Cutoff days for age verification (e.g., 6570 for 18 years)
    pub cutoff_days: i32,

    /// Verifying key ID for the ZK circuit
    pub verifying_key_id: u32,

    /// URL to check challenge status
    pub status_url: String,

    /// URL to submit verification proof
    pub verify_url: String,

    /// Proof direction: "over_age" or "under_age"
    /// Passed through from provii-verifier to inform the wallet which circuit to use
    #[serde(default = "default_proof_direction")]
    pub proof_direction: String,

    /// Server-configured outage failure mode for this origin
    /// ("block" | "allow" | "defer"), or absent when force-explicit. The SDK
    /// caches this so it survives an outage. Omitted from JSON when None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_mode: Option<String>,

    /// When true, the integrator's data-on-unavailable choice is ignored
    /// (governance lock).
    #[serde(default)]
    pub failure_mode_locked: bool,

    /// CSRF token for subsequent requests (optional, only if CSRF protection is enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,

    /// WebSocket URL for push notifications (replaces polling)
    /// Format: wss://{origin}/v1/hosted/ws/{session_id}
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_url: Option<String>,
}

impl std::fmt::Debug for ChallengeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeResponse")
            .field("session_id", &self.session_id)
            .field("challenge_id", &self.challenge_id)
            .field("qr_code_url", &self.qr_code_url)
            .field("challenge_code", &self.challenge_code)
            .field("short_code", &self.short_code)
            .field("expires_at", &self.expires_at)
            .field("status", &self.status)
            .field("rp_challenge", &self.rp_challenge)
            .field("submit_secret", &"[REDACTED]")
            .field("cutoff_days", &self.cutoff_days)
            .field("verifying_key_id", &self.verifying_key_id)
            .field("status_url", &self.status_url)
            .field("verify_url", &self.verify_url)
            .field("proof_direction", &self.proof_direction)
            .field(
                "csrf_token",
                &self.csrf_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("ws_url", &self.ws_url)
            .finish()
    }
}

impl Drop for ChallengeResponse {
    fn drop(&mut self) {
        self.submit_secret.zeroize();
        if let Some(ref mut token) = self.csrf_token {
            token.zeroize();
        }
    }
}

/// Response from GET /v1/hosted/status/{session_id}
///
/// Provides current verification progress. Supports long-polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// Session identifier
    pub session_id: String,

    /// Current session status (renamed from state for API consistency)
    #[serde(rename = "status")]
    pub state: SessionState,

    /// When the session was created (Unix timestamp seconds)
    pub created_at: u64,

    /// When the session expires (Unix timestamp seconds)
    pub expires_at: u64,

    /// Whether proof has been verified
    pub proof_verified: bool,

    /// Whether verification is complete
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,

    /// Error message if verification failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// When to poll next (Unix timestamp seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_after: Option<u64>,

    /// Remaining status checks before rate limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_checks: Option<u32>,
}

impl StatusResponse {
    /// Create a pending status response.
    pub fn pending(session_id: String, poll_after: u64, remaining_checks: u32) -> Self {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        Self {
            session_id,
            state: SessionState::Pending,
            created_at: now,
            expires_at: now.saturating_add(3600),
            proof_verified: false,
            complete: Some(false),
            error: None,
            poll_after: Some(poll_after),
            remaining_checks: Some(remaining_checks),
        }
    }

    /// Create a proof-ok status response.
    pub fn proof_ok(session_id: String, remaining_checks: u32) -> Self {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        Self {
            session_id,
            state: SessionState::ProofOk,
            created_at: now,
            expires_at: now.saturating_add(3600),
            proof_verified: true,
            complete: Some(true),
            error: None,
            poll_after: None,
            remaining_checks: Some(remaining_checks),
        }
    }

    /// Create a verified status response.
    pub fn verified(session_id: String, remaining_checks: u32) -> Self {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        Self {
            session_id,
            state: SessionState::Verified,
            created_at: now,
            expires_at: now.saturating_add(3600),
            proof_verified: true,
            complete: Some(true),
            error: None,
            poll_after: None,
            remaining_checks: Some(remaining_checks),
        }
    }

    /// Create an error status response.
    pub fn error(session_id: String, error: String, remaining_checks: u32) -> Self {
        let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        Self {
            session_id,
            state: SessionState::Expired,
            created_at: now,
            expires_at: now,
            proof_verified: false,
            complete: Some(true),
            error: Some(error),
            poll_after: None,
            remaining_checks: Some(remaining_checks),
        }
    }
}

/// Response from POST /v1/hosted/redeem/{session_id}
///
/// Returns an HMAC-signed session token and sets a secure session cookie.
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// `token` is zeroised on drop. Debug output redacts it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemResponse {
    /// SECURITY: Session token (HMAC-signed). Zeroised on drop.
    pub token: String,

    /// When the token expires (Unix timestamp seconds)
    pub expires_at: u64,

    /// Origin that owns this session
    pub origin: String,

    /// Token type (always "Bearer")
    pub token_type: String,
}

impl std::fmt::Debug for RedeemResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedeemResponse")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("origin", &self.origin)
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl Drop for RedeemResponse {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl RedeemResponse {
    /// Create a new redeem response.
    pub fn new(token: String, expires_at: u64, origin: String) -> Self {
        Self {
            token,
            expires_at,
            origin,
            token_type: "Bearer".to_string(),
        }
    }
}

/// Response from GET /v1/hosted/session/check
///
/// Checks if a session cookie is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCheckResponse {
    /// Whether the session is valid
    pub valid: bool,

    /// When the session expires (Unix timestamp seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Origin that owns this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl SessionCheckResponse {
    /// Create a valid session check response.
    pub fn valid(expires_at: u64, origin: String) -> Self {
        Self {
            valid: true,
            expires_at: Some(expires_at),
            origin: Some(origin),
        }
    }

    /// Create an invalid session check response.
    pub fn invalid() -> Self {
        Self {
            valid: false,
            expires_at: None,
            origin: None,
        }
    }
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    /// Service status
    pub status: String,

    /// Service version
    pub version: String,

    /// Current timestamp
    pub timestamp: u64,

    /// Detailed component health (for deep checks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<ComponentHealth>,
}

/// Component health details for deep health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentHealth {
    /// KV store health
    pub kv: HealthStatus,

    /// Durable Objects health
    pub durable_objects: HealthStatus,

    /// provii-verifier connectivity
    pub provii_verifier: HealthStatus,
}

/// Health status for individual components.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,

    /// Component is degraded but functional
    Degraded,

    /// Component is unhealthy
    Unhealthy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_response() -> Result<(), Box<dyn std::error::Error>> {
        let resp = ChallengeResponse {
            session_id: "sess-123".to_string(),
            challenge_id: "chal-456".to_string(),
            qr_code_url: "https://verify.provii.app/challenge/chal-456".to_string(),
            challenge_code: "1234-5678-9012".to_string(),
            short_code: "123456789012".to_string(),
            expires_at: 1234567890,
            status: "pending".to_string(),
            rp_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            submit_secret: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            cutoff_days: 6570,
            verifying_key_id: 914153247,
            status_url: "https://verify.provii.app/v1/challenge/chal-456".to_string(),
            verify_url: "https://verify.provii.app/v1/challenge/chal-456/submit".to_string(),
            proof_direction: "over_age".to_string(),
            csrf_token: None,
            ws_url: None,
            short_code_formatted: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("sess-123"));
        assert!(json.contains("chal-456"));
        assert!(json.contains("1234-5678-9012"));
        assert!(json.contains("rp_challenge"));
        assert!(json.contains("submit_secret"));
        assert!(json.contains("proof_direction"));
        Ok(())
    }

    #[test]
    fn test_status_response_pending() {
        let resp = StatusResponse::pending("sess-123".to_string(), 1234567890, 50);
        assert_eq!(resp.state, SessionState::Pending);
        assert_eq!(resp.complete, Some(false));
        assert!(resp.poll_after.is_some());
        assert_eq!(resp.remaining_checks, Some(50));
    }

    #[test]
    fn test_status_response_proof_ok() {
        let resp = StatusResponse::proof_ok("sess-456".to_string(), 45);
        assert_eq!(resp.state, SessionState::ProofOk);
        assert_eq!(resp.complete, Some(true));
        assert!(resp.poll_after.is_none());
        assert_eq!(resp.remaining_checks, Some(45));
    }

    #[test]
    fn test_status_response_verified() {
        let resp = StatusResponse::verified("sess-789".to_string(), 40);
        assert_eq!(resp.state, SessionState::Verified);
        assert_eq!(resp.complete, Some(true));
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_status_response_error() -> Result<(), Box<dyn std::error::Error>> {
        let resp = StatusResponse::error("sess-999".to_string(), "Test error".to_string(), 35);
        assert_eq!(resp.state, SessionState::Expired);
        assert_eq!(resp.complete, Some(true));
        assert_eq!(resp.error.as_ref().ok_or("missing error")?, "Test error");
        Ok(())
    }

    #[test]
    fn test_redeem_response() {
        let resp = RedeemResponse::new(
            "jwt-token".to_string(),
            1234567890,
            "https://example.com".to_string(),
        );
        assert_eq!(resp.token, "jwt-token");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.origin, "https://example.com");
    }

    #[test]
    fn test_session_check_valid() {
        let resp = SessionCheckResponse::valid(1234567890, "https://example.com".to_string());
        assert!(resp.valid);
        assert!(resp.expires_at.is_some());
        assert!(resp.origin.is_some());
    }

    #[test]
    fn test_session_check_invalid() {
        let resp = SessionCheckResponse::invalid();
        assert!(!resp.valid);
        assert!(resp.expires_at.is_none());
        assert!(resp.origin.is_none());
    }

    #[test]
    fn test_health_response() -> Result<(), Box<dyn std::error::Error>> {
        let resp = HealthResponse {
            status: "healthy".to_string(),
            version: "0.1.0".to_string(),
            timestamp: 1234567890,
            components: None,
        };
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("healthy"));
        assert!(json.contains("0.1.0"));
        Ok(())
    }

    #[test]
    fn test_component_health() -> Result<(), Box<dyn std::error::Error>> {
        let health = ComponentHealth {
            kv: HealthStatus::Healthy,
            durable_objects: HealthStatus::Healthy,
            provii_verifier: HealthStatus::Degraded,
        };
        let json = serde_json::to_string(&health)?;
        assert!(json.contains("healthy"));
        assert!(json.contains("degraded"));
        Ok(())
    }

    #[test]
    fn test_response_serialization_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = ChallengeResponse {
            session_id: "sess-test".to_string(),
            challenge_id: "chal-test".to_string(),
            qr_code_url: "https://verify.provii.app/challenge/chal-test".to_string(),
            challenge_code: "1234-5678-9012".to_string(),
            short_code: "123456789012".to_string(),
            expires_at: 999,
            status: "pending".to_string(),
            rp_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            submit_secret: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            cutoff_days: 6570,
            verifying_key_id: 914153247,
            status_url: "https://verify.provii.app/v1/challenge/chal-test".to_string(),
            verify_url: "https://verify.provii.app/v1/challenge/chal-test/submit".to_string(),
            proof_direction: "over_age".to_string(),
            csrf_token: None,
            ws_url: None,
            short_code_formatted: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&original)?;
        let decoded: ChallengeResponse = serde_json::from_str(&json)?;
        assert_eq!(decoded.session_id, original.session_id);
        assert_eq!(decoded.challenge_code, original.challenge_code);
        assert_eq!(decoded.status, original.status);
        assert_eq!(decoded.rp_challenge, original.rp_challenge);
        assert_eq!(decoded.submit_secret, original.submit_secret);
        assert_eq!(decoded.proof_direction, original.proof_direction);
        Ok(())
    }

    // ── ChallengeResponse Debug redaction ──────────────────────────────

    #[test]
    fn test_challenge_response_debug_redacts_submit_secret() {
        let resp = ChallengeResponse {
            session_id: "sess-dbg".to_string(),
            challenge_id: "chal-dbg".to_string(),
            qr_code_url: "https://example.com/qr".to_string(),
            challenge_code: "1234-5678-9012".to_string(),
            short_code: "123456789012".to_string(),
            expires_at: 100,
            status: "pending".to_string(),
            rp_challenge: "rp_chal".to_string(),
            submit_secret: "super-secret-value".to_string(),
            cutoff_days: 6570,
            verifying_key_id: 1,
            status_url: "https://example.com/status".to_string(),
            verify_url: "https://example.com/verify".to_string(),
            proof_direction: "over_age".to_string(),
            csrf_token: Some("csrf-secret-value".to_string()),
            ws_url: None,
            short_code_formatted: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let debug = format!("{:?}", resp);
        assert!(
            !debug.contains("super-secret-value"),
            "submit_secret must be redacted"
        );
        assert!(
            !debug.contains("csrf-secret-value"),
            "csrf_token must be redacted"
        );
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("sess-dbg"));
    }

    #[test]
    fn test_challenge_response_debug_csrf_none() {
        let resp = ChallengeResponse {
            session_id: "s".to_string(),
            challenge_id: "c".to_string(),
            qr_code_url: "u".to_string(),
            challenge_code: "cc".to_string(),
            short_code: "sc".to_string(),
            expires_at: 0,
            status: "pending".to_string(),
            rp_challenge: "rp".to_string(),
            submit_secret: "secret".to_string(),
            cutoff_days: 0,
            verifying_key_id: 0,
            status_url: "su".to_string(),
            verify_url: "vu".to_string(),
            proof_direction: "over_age".to_string(),
            csrf_token: None,
            ws_url: None,
            short_code_formatted: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let debug = format!("{:?}", resp);
        // csrf_token should show None, not [REDACTED]
        assert!(debug.contains("csrf_token: None"));
    }

    // ── ChallengeResponse optional field serialisation ─────────────────

    #[test]
    fn test_challenge_response_skip_none_fields() -> Result<(), Box<dyn std::error::Error>> {
        let resp = ChallengeResponse {
            session_id: "s".to_string(),
            challenge_id: "c".to_string(),
            qr_code_url: "u".to_string(),
            challenge_code: "cc".to_string(),
            short_code: "sc".to_string(),
            expires_at: 0,
            status: "pending".to_string(),
            rp_challenge: "rp".to_string(),
            submit_secret: "ss".to_string(),
            cutoff_days: 0,
            verifying_key_id: 0,
            status_url: "su".to_string(),
            verify_url: "vu".to_string(),
            proof_direction: "over_age".to_string(),
            csrf_token: None,
            ws_url: None,
            short_code_formatted: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&resp)?;
        assert!(
            !json.contains("csrf_token"),
            "None csrf_token must be omitted"
        );
        assert!(!json.contains("ws_url"), "None ws_url must be omitted");
        assert!(
            !json.contains("short_code_formatted"),
            "None short_code_formatted must be omitted"
        );
        Ok(())
    }

    #[test]
    fn test_challenge_response_includes_optional_fields_when_present(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = ChallengeResponse {
            session_id: "s".to_string(),
            challenge_id: "c".to_string(),
            qr_code_url: "u".to_string(),
            challenge_code: "cc".to_string(),
            short_code: "sc".to_string(),
            expires_at: 0,
            status: "pending".to_string(),
            rp_challenge: "rp".to_string(),
            submit_secret: "ss".to_string(),
            cutoff_days: 0,
            verifying_key_id: 0,
            status_url: "su".to_string(),
            verify_url: "vu".to_string(),
            proof_direction: "over_age".to_string(),
            csrf_token: Some("token123".to_string()),
            ws_url: Some("wss://example.com/ws/s".to_string()),
            short_code_formatted: Some("1234 5678 9012".to_string()),
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("csrf_token"));
        assert!(json.contains("ws_url"));
        assert!(json.contains("short_code_formatted"));
        Ok(())
    }

    // ── ChallengeResponse deny_unknown_fields ──────────────────────────

    #[test]
    fn test_challenge_response_rejects_unknown_fields() {
        let json = r#"{"session_id":"s","challenge_id":"c","qr_code_url":"u","challenge_code":"cc","short_code":"sc","expires_at":0,"status":"p","rp_challenge":"rp","submit_secret":"ss","cutoff_days":0,"verifying_key_id":0,"status_url":"su","verify_url":"vu","proof_direction":"over_age","extra":"bad"}"#;
        let result = serde_json::from_str::<ChallengeResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── ChallengeResponse proof_direction default ──────────────────────

    #[test]
    fn test_challenge_response_proof_direction_default() -> Result<(), Box<dyn std::error::Error>> {
        // When proof_direction is absent from JSON, serde default should supply "over_age"
        let json = r#"{"session_id":"s","challenge_id":"c","qr_code_url":"u","challenge_code":"cc","short_code":"sc","expires_at":0,"status":"p","rp_challenge":"rp","submit_secret":"ss","cutoff_days":0,"verifying_key_id":0,"status_url":"su","verify_url":"vu"}"#;
        let decoded: ChallengeResponse = serde_json::from_str(json)?;
        assert_eq!(decoded.proof_direction, "over_age");
        Ok(())
    }

    // ── StatusResponse field values ────────────────────────────────────

    #[test]
    fn test_status_response_pending_session_id() {
        let resp = StatusResponse::pending("my-session".to_string(), 999, 10);
        assert_eq!(resp.session_id, "my-session");
        assert!(!resp.proof_verified);
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_status_response_proof_ok_fields() {
        let resp = StatusResponse::proof_ok("sess-po".to_string(), 20);
        assert!(resp.proof_verified);
        assert_eq!(resp.complete, Some(true));
        assert!(resp.poll_after.is_none());
        assert_eq!(resp.session_id, "sess-po");
    }

    #[test]
    fn test_status_response_verified_fields() {
        let resp = StatusResponse::verified("sess-v".to_string(), 5);
        assert!(resp.proof_verified);
        assert_eq!(resp.remaining_checks, Some(5));
        assert!(resp.poll_after.is_none());
    }

    #[test]
    fn test_status_response_error_fields() -> Result<(), Box<dyn std::error::Error>> {
        let resp = StatusResponse::error("sess-err".to_string(), "Proof invalid".to_string(), 0);
        assert_eq!(resp.state, SessionState::Expired);
        assert!(!resp.proof_verified);
        assert_eq!(resp.complete, Some(true));
        let err_msg = resp.error.as_ref().ok_or("missing error")?;
        assert_eq!(err_msg, "Proof invalid");
        assert_eq!(resp.remaining_checks, Some(0));
        // expires_at should equal created_at for error responses
        assert_eq!(resp.expires_at, resp.created_at);
        Ok(())
    }

    // ── StatusResponse serialisation ───────────────────────────────────

    #[test]
    fn test_status_response_serialization_renames_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let resp = StatusResponse::pending("sess-serde".to_string(), 100, 50);
        let json = serde_json::to_string(&resp)?;
        // The field is named "state" in the struct but serialises as "status"
        assert!(
            json.contains("\"status\""),
            "state field should be renamed to status"
        );
        assert!(
            !json.contains("\"state\""),
            "raw 'state' field name should not appear"
        );
        Ok(())
    }

    #[test]
    fn test_status_response_skip_none_fields() -> Result<(), Box<dyn std::error::Error>> {
        let resp = StatusResponse::verified("s".to_string(), 10);
        let json = serde_json::to_string(&resp)?;
        assert!(!json.contains("error"), "None error must be omitted");
        assert!(
            !json.contains("poll_after"),
            "None poll_after must be omitted"
        );
        Ok(())
    }

    #[test]
    fn test_status_response_deny_unknown_fields() {
        let json = r#"{"session_id":"s","status":"pending","created_at":0,"expires_at":0,"proof_verified":false,"extra":"bad"}"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── RedeemResponse ─────────────────────────────────────────────────

    #[test]
    fn test_redeem_response_debug_redacts_token() {
        let resp = RedeemResponse::new(
            "actual-jwt-token-value".to_string(),
            9999,
            "https://example.com".to_string(),
        );
        let debug = format!("{:?}", resp);
        assert!(
            !debug.contains("actual-jwt-token-value"),
            "token must be redacted"
        );
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("Bearer"));
    }

    #[test]
    fn test_redeem_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse::new(
            "token-abc".to_string(),
            12345,
            "https://example.com".to_string(),
        );
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("token-abc"));
        assert!(json.contains("Bearer"));
        assert!(json.contains("12345"));
        assert!(json.contains("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_redeem_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse::new(
            "my-token".to_string(),
            54321,
            "https://test.com".to_string(),
        );
        let json = serde_json::to_string(&resp)?;
        let decoded: RedeemResponse = serde_json::from_str(&json)?;
        assert_eq!(decoded.token, "my-token");
        assert_eq!(decoded.expires_at, 54321);
        assert_eq!(decoded.origin, "https://test.com");
        assert_eq!(decoded.token_type, "Bearer");
        Ok(())
    }

    #[test]
    fn test_redeem_response_deny_unknown_fields() {
        let json =
            r#"{"token":"t","expires_at":0,"origin":"o","token_type":"Bearer","extra":"bad"}"#;
        let result = serde_json::from_str::<RedeemResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── SessionCheckResponse ───────────────────────────────────────────

    #[test]
    fn test_session_check_valid_fields() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SessionCheckResponse::valid(9999, "https://test.com".to_string());
        assert!(resp.valid);
        let exp = resp.expires_at.ok_or("missing expires_at")?;
        assert_eq!(exp, 9999);
        let org = resp.origin.as_ref().ok_or("missing origin")?;
        assert_eq!(org, "https://test.com");
        Ok(())
    }

    #[test]
    fn test_session_check_invalid_fields() {
        let resp = SessionCheckResponse::invalid();
        assert!(!resp.valid);
        assert!(resp.expires_at.is_none());
        assert!(resp.origin.is_none());
    }

    #[test]
    fn test_session_check_serialization_skip_none() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SessionCheckResponse::invalid();
        let json = serde_json::to_string(&resp)?;
        assert!(
            !json.contains("expires_at"),
            "None expires_at must be omitted"
        );
        assert!(!json.contains("origin"), "None origin must be omitted");
        Ok(())
    }

    #[test]
    fn test_session_check_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SessionCheckResponse::valid(42, "https://app.example".to_string());
        let json = serde_json::to_string(&resp)?;
        let decoded: SessionCheckResponse = serde_json::from_str(&json)?;
        assert!(decoded.valid);
        assert_eq!(decoded.expires_at, Some(42));
        assert_eq!(decoded.origin.as_deref(), Some("https://app.example"));
        Ok(())
    }

    #[test]
    fn test_session_check_deny_unknown_fields() {
        let json = r#"{"valid":true,"extra":"bad"}"#;
        let result = serde_json::from_str::<SessionCheckResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── HealthResponse ─────────────────────────────────────────────────

    #[test]
    fn test_health_response_with_components() -> Result<(), Box<dyn std::error::Error>> {
        let resp = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            timestamp: 111,
            components: Some(ComponentHealth {
                kv: HealthStatus::Healthy,
                durable_objects: HealthStatus::Degraded,
                provii_verifier: HealthStatus::Unhealthy,
            }),
        };
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("components"));
        assert!(json.contains("unhealthy"));
        assert!(json.contains("degraded"));
        Ok(())
    }

    #[test]
    fn test_health_response_skip_none_components() -> Result<(), Box<dyn std::error::Error>> {
        let resp = HealthResponse {
            status: "ok".to_string(),
            version: "0.1.0".to_string(),
            timestamp: 0,
            components: None,
        };
        let json = serde_json::to_string(&resp)?;
        assert!(
            !json.contains("components"),
            "None components must be omitted"
        );
        Ok(())
    }

    #[test]
    fn test_health_response_deny_unknown_fields() {
        let json = r#"{"status":"ok","version":"1","timestamp":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<HealthResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── HealthStatus serde ─────────────────────────────────────────────

    #[test]
    fn test_health_status_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = vec![
            (HealthStatus::Healthy, "\"healthy\""),
            (HealthStatus::Degraded, "\"degraded\""),
            (HealthStatus::Unhealthy, "\"unhealthy\""),
        ];
        for (status, expected) in cases {
            let json = serde_json::to_string(&status)?;
            assert_eq!(json, expected);
            let decoded: HealthStatus = serde_json::from_str(&json)?;
            assert_eq!(format!("{:?}", decoded), format!("{:?}", status));
        }
        Ok(())
    }

    // ── ComponentHealth deny_unknown_fields ─────────────────────────────

    #[test]
    fn test_component_health_deny_unknown_fields() {
        let json = r#"{"kv":"healthy","durable_objects":"healthy","provii_verifier":"healthy","extra":"bad"}"#;
        let result = serde_json::from_str::<ComponentHealth>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    #[test]
    fn test_health_status_rejects_unknown_variant() {
        let result = serde_json::from_str::<HealthStatus>(r#""unknown""#);
        assert!(result.is_err());
        let result2 = serde_json::from_str::<HealthStatus>(r#""HEALTHY""#);
        assert!(result2.is_err());
    }

    #[test]
    fn test_health_response_full_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = HealthResponse {
            status: "ok".to_string(),
            version: "2.0.0".to_string(),
            timestamp: 1_700_000_000,
            components: Some(ComponentHealth {
                kv: HealthStatus::Healthy,
                durable_objects: HealthStatus::Degraded,
                provii_verifier: HealthStatus::Healthy,
            }),
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: HealthResponse = serde_json::from_str(&json)?;
        assert_eq!(decoded.version, "2.0.0");
        assert_eq!(decoded.timestamp, 1_700_000_000);
        let comp = decoded.components.unwrap();
        assert!(matches!(comp.durable_objects, HealthStatus::Degraded));
        Ok(())
    }

    #[test]
    fn test_session_check_response_invalid_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = SessionCheckResponse::invalid();
        let json = serde_json::to_string(&resp)?;
        let decoded: SessionCheckResponse = serde_json::from_str(&json)?;
        assert!(!decoded.valid);
        assert!(decoded.expires_at.is_none());
        assert!(decoded.origin.is_none());
        Ok(())
    }

    #[test]
    fn test_challenge_response_clone_independence() {
        let original = ChallengeResponse {
            session_id: "sess-1".to_string(),
            challenge_id: "test-id".to_string(),
            qr_code_url: "https://example.com/qr".to_string(),
            challenge_code: "1234-5678-9012".to_string(),
            short_code: "123456789012".to_string(),
            short_code_formatted: Some("1234 5678 9012".to_string()),
            expires_at: 100,
            status: "pending".to_string(),
            rp_challenge: "test_rp_challenge_base64url_aaaa".to_string(),
            submit_secret: "test_submit_secret_base64url_aa".to_string(),
            cutoff_days: 6570,
            verifying_key_id: 1,
            status_url: "https://example.com/status".to_string(),
            verify_url: "https://example.com/verify".to_string(),
            proof_direction: default_proof_direction(),
            csrf_token: None,
            ws_url: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let mut cloned = original.clone();
        cloned.challenge_id = "changed".to_string();
        assert_eq!(original.challenge_id, "test-id");
    }
}
