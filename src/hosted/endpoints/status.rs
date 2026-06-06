// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Status polling handler for hosted verification sessions.
//!
//! `GET /v1/hosted/status/:session_id` lets the browser SDK (provii-agegate) poll
//! for proof completion. In the original provii-verifier this handler called
//! provii-verifier via a service binding to check challenge state. Now that the
//! handler lives inside provii-verifier, it reads the challenge store directly,
//! eliminating the inter-service hop.
//!
//! SECURITY: BOLA prevention (X-Public-Key must match session creator), origin
//! matching, session binding (IP + UA HMAC), per-IP and per-session rate limiting
//! are all enforced before returning any challenge state.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{Error as WorkerError, Headers, Response};

#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_challenge_id;

use crate::{
    analytics::Analytics,
    cache::ChallengeState,
    error::ApiError,
    hosted::session_binding::{verify_session_binding, BindingOutcome},
    hosted::storage::kv::get_session_kv,
    utils::current_timestamp,
    AppState,
};

/// Rate limit window for status checks (60 seconds).
pub const STATUS_CHECK_RATE_LIMIT_WINDOW: u32 = 60;

/// Default maximum number of status checks per session per window.
const DEFAULT_MAX_STATUS_CHECKS: u32 = 120;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Session state as reported to the browser SDK.
///
/// This is the hosted-flow view of session lifecycle, not the internal
/// `ChallengeState`. The mapping is:
///   Pending                       -> Pending
///   ProofOkWaitingForRedeem       -> ProofOk
///   Verified                      -> Verified
///   Failed / Expired              -> Expired
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HostedSessionState {
    /// Waiting for the wallet to submit a proof.
    Pending,
    /// Proof verified, awaiting PKCE redemption.
    #[serde(rename = "proof_ok_waiting_for_redeem")]
    ProofOk,
    /// Fully redeemed.
    Verified,
    /// Session expired or failed.
    Expired,
}

impl HostedSessionState {
    fn from_challenge_state(state: &ChallengeState) -> Self {
        match state {
            ChallengeState::Pending => Self::Pending,
            ChallengeState::ProofOkWaitingForRedeem => Self::ProofOk,
            ChallengeState::Verified => Self::Verified,
            ChallengeState::Failed | ChallengeState::Expired => Self::Expired,
        }
    }
}

/// Response from `GET /v1/hosted/status/:session_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    /// Session/challenge identifier.
    pub session_id: String,

    /// Current lifecycle state.
    #[serde(rename = "status")]
    pub state: HostedSessionState,

    /// When the challenge was created (Unix timestamp seconds).
    pub created_at: u64,

    /// When the challenge expires (Unix timestamp seconds).
    pub expires_at: u64,

    /// Whether proof has been verified.
    pub proof_verified: bool,

    /// Whether the flow is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complete: Option<bool>,

    /// Error description if the session failed or expired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Unix timestamp (seconds) after which the next poll should occur.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_after: Option<u64>,

    /// Remaining status checks before rate limit is hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_checks: Option<u32>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Poll the status of a hosted verification session.
///
/// Reads directly from the challenge store instead of calling provii-verifier
/// via a service binding. This is the most performance-critical hosted
/// endpoint because provii-agegate polls it repeatedly until the proof lands.
///
/// # Security checks
///
/// 1. Per-IP rate limit (via KV quota)
/// 2. Session ID format validation (UUID)
/// 3. Origin presence and match
/// 4. BOLA: `X-Public-Key` header must be present (ownership is enforced
///    by the caller via session store; the challenge store itself does not
///    carry a public key, so we gate on header presence)
/// 5. Session binding (IP + UA HMAC hash) verification (ADV-VA-04-002)
/// 6. Challenge expiry detection
pub async fn handle_hosted_status(
    state: Arc<AppState>,
    headers: Headers,
    session_id: &str,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();

    let origin = headers.get("Origin").ok().flatten().unwrap_or_default();

    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    // ── Validate session_id format ──────────────────────────────────────────
    if Uuid::parse_str(session_id).is_err() {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_status:invalid_session_id")
            .await;
        return ApiError::BadRequest(Some("Invalid session_id format".into())).to_response();
    }

    // ── Require Origin ─────────────────────────────────────────────────────
    if origin.is_empty() {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_status:missing_origin")
            .await;
        return ApiError::BadRequest(Some("Missing Origin header".into())).to_response();
    }

    // ── BOLA: extract X-Public-Key for ownership check after session load ──
    let provided_public_key = headers
        .get("X-Public-Key")
        .ok()
        .flatten()
        .unwrap_or_default();
    if provided_public_key.is_empty() {
        // ADV-VA-029: Structured auth failure audit (matches expert endpoint pattern).
        state
            .audit_logger
            .log_authentication_failure(
                &client_ip,
                "hosted_status:bola_missing_public_key",
                None,
                Some(&origin),
                Some(serde_json::json!({
                    "endpoint": "/v1/hosted/status",
                    "session_id": session_id,
                })),
            )
            .await;
        return ApiError::Forbidden(Some("Access denied".into())).to_response();
    }

    // ── Load session from KV to get the verifier challenge_id ──────────────
    // The URL contains the session_id, but the challenge store is indexed by
    // challenge_id. Load the hosted session first to resolve the mapping.
    let mut session = match get_session_kv(&state.env, session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Session not found in KV: {}",
                redact_challenge_id(session_id)
            );
            return ApiError::NotFound.to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Failed to read session {}: {}",
                redact_challenge_id(session_id),
                e
            );
            return ApiError::Internal(anyhow::anyhow!(e)).to_response();
        }
    };

    // ── BOLA: constant-time comparison of X-Public-Key against session owner ─
    {
        use subtle::ConstantTimeEq;
        let provided_bytes = provided_public_key.as_bytes();
        let expected_bytes = session.public_key.as_bytes();
        let len_ok = provided_bytes.len() == expected_bytes.len();
        // Pad to equal length for ct_eq; length mismatch already fails.
        let ct_ok = if len_ok {
            bool::from(provided_bytes.ct_eq(expected_bytes))
        } else {
            false
        };
        if !ct_ok {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] SECURITY: BOLA - X-Public-Key mismatch for session {}",
                redact_challenge_id(session_id)
            );
            // ADV-VA-029: Structured auth failure audit.
            state
                .audit_logger
                .log_authentication_failure(
                    &client_ip,
                    "hosted_status:bola_public_key_mismatch",
                    None,
                    Some(&origin),
                    Some(serde_json::json!({
                        "endpoint": "/v1/hosted/status",
                        "session_id": session_id,
                    })),
                )
                .await;
            return ApiError::Forbidden(Some("Access denied".into())).to_response();
        }
    }

    // ── Origin must match the session creator (constant-time) ──────────────
    let origin_match = {
        use subtle::ConstantTimeEq;
        let a = origin.as_bytes();
        let b = session.origin.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    };
    if !origin_match {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/status] SECURITY: Origin mismatch for session {}",
            redact_challenge_id(session_id)
        );
        // ADV-VA-029: Structured auth failure audit.
        state
            .audit_logger
            .log_authentication_failure(
                &client_ip,
                "hosted_status:origin_mismatch",
                None,
                Some(&origin),
                Some(serde_json::json!({
                    "endpoint": "/v1/hosted/status",
                    "session_id": session_id,
                    "expected_origin": session.origin,
                })),
            )
            .await;
        return ApiError::Forbidden(Some("Origin does not match session origin".into()))
            .to_response();
    }

    // ── ADV-VA-04-002: Session binding verification (IP + UA hash) ──────────
    // Verify that the current request's IP and User-Agent match the session's
    // stored binding hashes. The verify_session_binding function uses
    // constant-time comparison internally (subtle::ConstantTimeEq).
    {
        let current_ua = headers.get("User-Agent").ok().flatten();
        let binding_result = verify_session_binding(
            &client_ip,
            current_ua.as_deref(),
            session.client_ip_hash.as_deref(),
            session.user_agent.as_deref(),
            &state.ip_hash_salt,
            session.binding_mode,
        );
        match binding_result {
            Ok(BindingOutcome::Ok) => {}
            Ok(BindingOutcome::IpMismatchRelaxed) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/status] Session binding: IP mismatch (relaxed) for session {}",
                    redact_challenge_id(session_id)
                );
            }
            Ok(BindingOutcome::UaMismatchRelaxed) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/status] Session binding: UA mismatch (relaxed) for session {}",
                    redact_challenge_id(session_id)
                );
            }
            Err(e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/status] SECURITY: Session binding rejected for session {}",
                    redact_challenge_id(session_id)
                );
                state
                    .audit_logger
                    .log_authentication_failure(
                        &client_ip,
                        "hosted_status:session_binding_mismatch",
                        None,
                        Some(&origin),
                        Some(serde_json::json!({
                            "endpoint": "/v1/hosted/status",
                            "session_id": session_id,
                            "binding_mode": format!("{:?}", session.binding_mode),
                        })),
                    )
                    .await;
                return e.to_response();
            }
        }
    }

    // ── Per-session status check rate limit ──────────────────────────────────
    {
        session.increment_status_checks();
        if session.status_check_count > DEFAULT_MAX_STATUS_CHECKS {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Rate limit exceeded for session {}",
                redact_challenge_id(session_id)
            );
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_status:session_rate_limit_exceeded")
                .await;
            return ApiError::TooManyRequests(Some("Status check rate limit exceeded".into()))
                .to_response();
        }
        // Fire-and-forget: persist updated count. Non-fatal if write fails.
        // Pass prior state to avoid redundant KV GET + decrypt.
        if let Err(_e) = crate::hosted::storage::kv::update_session_kv_checked(
            &state.env,
            &session,
            Some(session.state),
        )
        .await
        {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Failed to persist status_check_count for {}: {}",
                redact_challenge_id(session_id),
                _e
            );
        }
    }

    // ── Read challenge from store using the verifier challenge_id ───────────
    let challenge_id = match Uuid::parse_str(&session.verifier_challenge_id) {
        Ok(id) => id,
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Invalid challenge_id in session: {}",
                redact_challenge_id(session_id)
            );
            return ApiError::Internal(anyhow::anyhow!("corrupt session data")).to_response();
        }
    };

    let entry = match state.challenge_store.get(&challenge_id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Challenge not found for session: {}",
                redact_challenge_id(session_id)
            );
            return ApiError::NotFound.to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/status] Failed to read challenge {}: {:?}",
                redact_challenge_id(&session.verifier_challenge_id),
                e
            );
            return ApiError::Internal(e.into()).to_response();
        }
    };

    // ── Check expiry ────────────────────────────────────────────────────────
    let now = current_timestamp();
    let is_expired = now > entry.expires_at && entry.state != ChallengeState::Verified;

    let effective_state = if is_expired {
        HostedSessionState::Expired
    } else {
        HostedSessionState::from_challenge_state(&entry.state)
    };

    let proof_verified = matches!(
        entry.state,
        ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
    );

    let poll_after = match effective_state {
        HostedSessionState::Pending => Some(now.saturating_add(2)), // 2-second poll interval
        _ => None,
    };

    let complete = match effective_state {
        HostedSessionState::Pending => Some(false),
        _ => Some(true),
    };

    let error = match effective_state {
        HostedSessionState::Expired => Some("Session expired".to_string()),
        _ => None,
    };

    let remaining_checks = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(session.status_check_count);

    let response = StatusResponse {
        session_id: session_id.to_string(),
        state: effective_state,
        created_at: entry.created_at,
        expires_at: entry.expires_at,
        proof_verified,
        complete,
        error,
        poll_after,
        remaining_checks: Some(remaining_checks),
    };

    let duration_ms = worker::Date::now().as_millis().saturating_sub(start) as f64;
    #[cfg(target_arch = "wasm32")]
    console_log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-verifier","route":"/v1/hosted/status","status":200,"duration_ms":{:.1}}}"#,
        duration_ms
    );

    // Fire-and-forget analytics event for status polling.
    let analytics = Analytics::new(&state.env);
    analytics.hosted_status_checked(
        "/v1/hosted/status",
        session_id,
        &origin,
        duration_ms,
        &state.cfg.environment,
    );

    Response::from_json(&response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosted_session_state_mapping() {
        assert_eq!(
            HostedSessionState::from_challenge_state(&ChallengeState::Pending),
            HostedSessionState::Pending
        );
        assert_eq!(
            HostedSessionState::from_challenge_state(&ChallengeState::ProofOkWaitingForRedeem),
            HostedSessionState::ProofOk
        );
        assert_eq!(
            HostedSessionState::from_challenge_state(&ChallengeState::Verified),
            HostedSessionState::Verified
        );
        assert_eq!(
            HostedSessionState::from_challenge_state(&ChallengeState::Failed),
            HostedSessionState::Expired
        );
        assert_eq!(
            HostedSessionState::from_challenge_state(&ChallengeState::Expired),
            HostedSessionState::Expired
        );
    }

    #[test]
    fn test_status_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "test-123".to_string(),
            state: HostedSessionState::Pending,
            created_at: 1000000,
            expires_at: 1000300,
            proof_verified: false,
            complete: Some(false),
            error: None,
            poll_after: Some(1000002),
            remaining_checks: Some(120),
        };

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"pending\""));
        assert!(json.contains("\"proof_verified\":false"));
        assert!(!json.contains("error"));
        Ok(())
    }

    #[test]
    fn test_status_response_expired_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "test-456".to_string(),
            state: HostedSessionState::Expired,
            created_at: 1000000,
            expires_at: 1000300,
            proof_verified: false,
            complete: Some(true),
            error: Some("Session expired".to_string()),
            poll_after: None,
            remaining_checks: Some(0),
        };

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"expired\""));
        assert!(json.contains("Session expired"));
        assert!(!json.contains("poll_after"));
        Ok(())
    }

    #[test]
    fn test_status_response_proof_ok_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "test-789".to_string(),
            state: HostedSessionState::ProofOk,
            created_at: 1000000,
            expires_at: 1000300,
            proof_verified: true,
            complete: Some(true),
            error: None,
            poll_after: None,
            remaining_checks: Some(100),
        };

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"proof_ok_waiting_for_redeem\""));
        assert!(json.contains("\"proof_verified\":true"));
        Ok(())
    }

    // ── HostedSessionState serde roundtrip ──────────────────────────────

    #[test]
    fn test_hosted_session_state_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let states = vec![
            (HostedSessionState::Pending, "\"pending\""),
            (
                HostedSessionState::ProofOk,
                "\"proof_ok_waiting_for_redeem\"",
            ),
            (HostedSessionState::Verified, "\"verified\""),
            (HostedSessionState::Expired, "\"expired\""),
        ];
        for (state, expected_json) in states {
            let json = serde_json::to_string(&state)?;
            assert_eq!(json, expected_json, "serialize {:?}", state);
            let deserialized: HostedSessionState = serde_json::from_str(&json)?;
            assert_eq!(deserialized, state, "deserialize {:?}", state);
        }
        Ok(())
    }

    // ── StatusResponse skip_serializing_if behaviour ─────────────────────

    #[test]
    fn test_status_response_omits_none_fields() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "test".to_string(),
            state: HostedSessionState::Verified,
            created_at: 1000,
            expires_at: 2000,
            proof_verified: true,
            complete: None,
            error: None,
            poll_after: None,
            remaining_checks: None,
        };
        let json = serde_json::to_string(&response)?;
        assert!(
            !json.contains("complete"),
            "None complete should be omitted"
        );
        assert!(!json.contains("error"), "None error should be omitted");
        assert!(
            !json.contains("poll_after"),
            "None poll_after should be omitted"
        );
        assert!(
            !json.contains("remaining_checks"),
            "None remaining_checks should be omitted"
        );
        Ok(())
    }

    // ── StatusResponse deserialisation roundtrip ─────────────────────────

    #[test]
    fn test_status_response_deserialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = StatusResponse {
            session_id: "abc-def".to_string(),
            state: HostedSessionState::Pending,
            created_at: 500,
            expires_at: 800,
            proof_verified: false,
            complete: Some(false),
            error: None,
            poll_after: Some(502),
            remaining_checks: Some(119),
        };
        let json = serde_json::to_string(&original)?;
        let deserialized: StatusResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.session_id, "abc-def");
        assert_eq!(deserialized.state, HostedSessionState::Pending);
        assert_eq!(deserialized.created_at, 500);
        assert_eq!(deserialized.expires_at, 800);
        assert!(!deserialized.proof_verified);
        assert_eq!(deserialized.complete, Some(false));
        assert_eq!(deserialized.poll_after, Some(502));
        assert_eq!(deserialized.remaining_checks, Some(119));
        Ok(())
    }

    #[test]
    fn test_status_response_rejects_unknown_fields() {
        let json = r#"{"session_id":"a","status":"pending","created_at":1,"expires_at":2,"proof_verified":false,"extra":"bad"}"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── Verified state serialisation ────────────────────────────────────

    #[test]
    fn test_status_response_verified_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "verified-session".to_string(),
            state: HostedSessionState::Verified,
            created_at: 1000000,
            expires_at: 1000300,
            proof_verified: true,
            complete: Some(true),
            error: None,
            poll_after: None,
            remaining_checks: Some(50),
        };
        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"verified\""));
        assert!(!json.contains("poll_after"));
        assert!(!json.contains("error"));
        Ok(())
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_status_check_rate_limit_window() {
        assert_eq!(STATUS_CHECK_RATE_LIMIT_WINDOW, 60);
    }

    #[test]
    fn test_default_max_status_checks() {
        assert_eq!(DEFAULT_MAX_STATUS_CHECKS, 120);
    }

    // ── Handler inline logic: effective_state computation ───────────────
    //
    // The handler computes effective_state, proof_verified, poll_after,
    // complete, error, and remaining_checks from ChallengeState + timestamps.
    // These helpers replicate the inline logic exactly so we can prove
    // correctness for every state/expiry combination without needing the
    // Worker runtime.

    /// Replicate the handler's is_expired check.
    fn compute_is_expired(now: u64, expires_at: u64, state: &ChallengeState) -> bool {
        now > expires_at && *state != ChallengeState::Verified
    }

    /// Replicate the handler's effective_state derivation.
    fn compute_effective_state(
        now: u64,
        expires_at: u64,
        state: &ChallengeState,
    ) -> HostedSessionState {
        if compute_is_expired(now, expires_at, state) {
            HostedSessionState::Expired
        } else {
            HostedSessionState::from_challenge_state(state)
        }
    }

    /// Replicate the handler's proof_verified check.
    fn compute_proof_verified(state: &ChallengeState) -> bool {
        matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        )
    }

    /// Replicate the handler's poll_after derivation.
    fn compute_poll_after(effective_state: HostedSessionState, now: u64) -> Option<u64> {
        match effective_state {
            HostedSessionState::Pending => Some(now.saturating_add(2)),
            _ => None,
        }
    }

    /// Replicate the handler's complete derivation.
    fn compute_complete(effective_state: HostedSessionState) -> Option<bool> {
        match effective_state {
            HostedSessionState::Pending => Some(false),
            _ => Some(true),
        }
    }

    /// Replicate the handler's error derivation.
    fn compute_error(effective_state: HostedSessionState) -> Option<String> {
        match effective_state {
            HostedSessionState::Expired => Some("Session expired".to_string()),
            _ => None,
        }
    }

    // ── Effective state: Pending + not expired ─────────────────────────

    #[test]
    fn test_effective_state_pending_not_expired() {
        let state = ChallengeState::Pending;
        let now = 1000;
        let expires_at = 1300;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Pending);
        assert!(!compute_is_expired(now, expires_at, &state));
    }

    // ── Effective state: Pending + expired ─────────────────────────────

    #[test]
    fn test_effective_state_pending_expired() {
        let state = ChallengeState::Pending;
        let now = 1400;
        let expires_at = 1300;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
        assert!(compute_is_expired(now, expires_at, &state));
    }

    // ── Effective state: Pending at exact expiry boundary ──────────────

    #[test]
    fn test_effective_state_pending_at_exact_expiry() {
        // now == expires_at should NOT be expired (handler uses strict >)
        let state = ChallengeState::Pending;
        let now = 1300;
        let expires_at = 1300;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Pending);
        assert!(!compute_is_expired(now, expires_at, &state));
    }

    // ── Effective state: Pending one second past expiry ────────────────

    #[test]
    fn test_effective_state_pending_one_second_past_expiry() {
        let state = ChallengeState::Pending;
        let now = 1301;
        let expires_at = 1300;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
    }

    // ── Effective state: Verified never becomes Expired ────────────────

    #[test]
    fn test_verified_never_expires() {
        let state = ChallengeState::Verified;
        let now = u64::MAX;
        let expires_at = 0;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Verified);
        assert!(!compute_is_expired(now, expires_at, &state));
    }

    // ── Effective state: ProofOkWaitingForRedeem + expired ─────────────

    #[test]
    fn test_effective_state_proof_ok_expired() {
        let state = ChallengeState::ProofOkWaitingForRedeem;
        let now = 2000;
        let expires_at = 1000;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
    }

    // ── Effective state: ProofOkWaitingForRedeem + not expired ─────────

    #[test]
    fn test_effective_state_proof_ok_not_expired() {
        let state = ChallengeState::ProofOkWaitingForRedeem;
        let now = 500;
        let expires_at = 1000;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::ProofOk);
    }

    // ── Effective state: Failed + expired (already terminal) ──────────

    #[test]
    fn test_effective_state_failed_expired() {
        let state = ChallengeState::Failed;
        let now = 2000;
        let expires_at = 1000;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
    }

    // ── Effective state: Failed + not expired ─────────────────────────

    #[test]
    fn test_effective_state_failed_not_expired() {
        // Failed maps to Expired even when not past expiry
        let state = ChallengeState::Failed;
        let now = 500;
        let expires_at = 1000;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
    }

    // ── Effective state: Expired + already past expiry ─────────────────

    #[test]
    fn test_effective_state_expired_past_expiry() {
        let state = ChallengeState::Expired;
        let now = 2000;
        let expires_at = 1000;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
    }

    // ── Effective state: Expired + not past expiry ────────────────────

    #[test]
    fn test_effective_state_expired_not_past_expiry() {
        // ChallengeState::Expired maps to HostedSessionState::Expired
        // regardless of time
        let state = ChallengeState::Expired;
        let now = 500;
        let expires_at = 1000;
        let effective = compute_effective_state(now, expires_at, &state);
        assert_eq!(effective, HostedSessionState::Expired);
    }

    // ── proof_verified: all ChallengeState variants ───────────────────

    #[test]
    fn test_proof_verified_pending() {
        assert!(!compute_proof_verified(&ChallengeState::Pending));
    }

    #[test]
    fn test_proof_verified_proof_ok() {
        assert!(compute_proof_verified(
            &ChallengeState::ProofOkWaitingForRedeem
        ));
    }

    #[test]
    fn test_proof_verified_verified() {
        assert!(compute_proof_verified(&ChallengeState::Verified));
    }

    #[test]
    fn test_proof_verified_failed() {
        assert!(!compute_proof_verified(&ChallengeState::Failed));
    }

    #[test]
    fn test_proof_verified_expired() {
        assert!(!compute_proof_verified(&ChallengeState::Expired));
    }

    // ── poll_after: only Pending gets a value ─────────────────────────

    #[test]
    fn test_poll_after_pending() {
        let now = 5000;
        assert_eq!(
            compute_poll_after(HostedSessionState::Pending, now),
            Some(5002)
        );
    }

    #[test]
    fn test_poll_after_proof_ok() {
        assert_eq!(compute_poll_after(HostedSessionState::ProofOk, 5000), None);
    }

    #[test]
    fn test_poll_after_verified() {
        assert_eq!(compute_poll_after(HostedSessionState::Verified, 5000), None);
    }

    #[test]
    fn test_poll_after_expired() {
        assert_eq!(compute_poll_after(HostedSessionState::Expired, 5000), None);
    }

    // ── poll_after: saturating_add at u64::MAX ────────────────────────

    #[test]
    fn test_poll_after_saturating_at_u64_max() {
        let now = u64::MAX;
        assert_eq!(
            compute_poll_after(HostedSessionState::Pending, now),
            Some(u64::MAX)
        );
    }

    // ── complete: Pending -> false, everything else -> true ────────────

    #[test]
    fn test_complete_pending() {
        assert_eq!(compute_complete(HostedSessionState::Pending), Some(false));
    }

    #[test]
    fn test_complete_proof_ok() {
        assert_eq!(compute_complete(HostedSessionState::ProofOk), Some(true));
    }

    #[test]
    fn test_complete_verified() {
        assert_eq!(compute_complete(HostedSessionState::Verified), Some(true));
    }

    #[test]
    fn test_complete_expired() {
        assert_eq!(compute_complete(HostedSessionState::Expired), Some(true));
    }

    // ── error: only Expired produces an error string ──────────────────

    #[test]
    fn test_error_pending() {
        assert_eq!(compute_error(HostedSessionState::Pending), None);
    }

    #[test]
    fn test_error_proof_ok() {
        assert_eq!(compute_error(HostedSessionState::ProofOk), None);
    }

    #[test]
    fn test_error_verified() {
        assert_eq!(compute_error(HostedSessionState::Verified), None);
    }

    #[test]
    fn test_error_expired() {
        assert_eq!(
            compute_error(HostedSessionState::Expired),
            Some("Session expired".to_string())
        );
    }

    // ── remaining_checks: saturating subtraction ──────────────────────

    #[test]
    fn test_remaining_checks_zero_used() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(0);
        assert_eq!(remaining, 120);
    }

    #[test]
    fn test_remaining_checks_some_used() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(50);
        assert_eq!(remaining, 70);
    }

    #[test]
    fn test_remaining_checks_all_used() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(120);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_remaining_checks_over_limit_saturates_to_zero() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(200);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_remaining_checks_at_u32_max() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(u32::MAX);
        assert_eq!(remaining, 0);
    }

    // ── Full response construction: Pending ────────────────────────────

    #[test]
    fn test_full_response_construction_pending() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_state = ChallengeState::Pending;
        let now = 1000u64;
        let expires_at = 1300u64;
        let created_at = 900u64;
        let session_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let status_check_count = 5u32;

        let effective_state = compute_effective_state(now, expires_at, &challenge_state);
        let proof_verified = compute_proof_verified(&challenge_state);
        let poll_after = compute_poll_after(effective_state, now);
        let complete = compute_complete(effective_state);
        let error = compute_error(effective_state);
        let remaining_checks = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(status_check_count);

        let response = StatusResponse {
            session_id: session_id.to_string(),
            state: effective_state,
            created_at,
            expires_at,
            proof_verified,
            complete,
            error,
            poll_after,
            remaining_checks: Some(remaining_checks),
        };

        assert_eq!(response.state, HostedSessionState::Pending);
        assert!(!response.proof_verified);
        assert_eq!(response.poll_after, Some(1002));
        assert_eq!(response.complete, Some(false));
        assert!(response.error.is_none());
        assert_eq!(response.remaining_checks, Some(115));

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"pending\""));
        assert!(json.contains("\"poll_after\":1002"));
        assert!(!json.contains("\"error\""));
        Ok(())
    }

    // ── Full response construction: Verified ──────────────────────────

    #[test]
    fn test_full_response_construction_verified() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_state = ChallengeState::Verified;
        let now = 2000u64;
        let expires_at = 1300u64; // past expiry, but Verified never expires
        let created_at = 900u64;
        let session_id = "11111111-2222-3333-4444-555555555555";
        let status_check_count = 100u32;

        let effective_state = compute_effective_state(now, expires_at, &challenge_state);
        let proof_verified = compute_proof_verified(&challenge_state);
        let poll_after = compute_poll_after(effective_state, now);
        let complete = compute_complete(effective_state);
        let error = compute_error(effective_state);
        let remaining_checks = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(status_check_count);

        let response = StatusResponse {
            session_id: session_id.to_string(),
            state: effective_state,
            created_at,
            expires_at,
            proof_verified,
            complete,
            error,
            poll_after,
            remaining_checks: Some(remaining_checks),
        };

        assert_eq!(response.state, HostedSessionState::Verified);
        assert!(response.proof_verified);
        assert!(response.poll_after.is_none());
        assert_eq!(response.complete, Some(true));
        assert!(response.error.is_none());
        assert_eq!(response.remaining_checks, Some(20));

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"verified\""));
        assert!(!json.contains("\"poll_after\""));
        Ok(())
    }

    // ── Full response construction: Expired (from Pending past expiry) ─

    #[test]
    fn test_full_response_construction_expired_from_pending(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let challenge_state = ChallengeState::Pending;
        let now = 2000u64;
        let expires_at = 1300u64;
        let created_at = 900u64;
        let session_id = "deadbeef-dead-beef-dead-beefdeadbeef";
        let status_check_count = 120u32;

        let effective_state = compute_effective_state(now, expires_at, &challenge_state);
        let proof_verified = compute_proof_verified(&challenge_state);
        let poll_after = compute_poll_after(effective_state, now);
        let complete = compute_complete(effective_state);
        let error = compute_error(effective_state);
        let remaining_checks = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(status_check_count);

        let response = StatusResponse {
            session_id: session_id.to_string(),
            state: effective_state,
            created_at,
            expires_at,
            proof_verified,
            complete,
            error,
            poll_after,
            remaining_checks: Some(remaining_checks),
        };

        assert_eq!(response.state, HostedSessionState::Expired);
        assert!(!response.proof_verified);
        assert!(response.poll_after.is_none());
        assert_eq!(response.complete, Some(true));
        assert_eq!(response.error.as_deref(), Some("Session expired"));
        assert_eq!(response.remaining_checks, Some(0));

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\":\"expired\""));
        assert!(json.contains("\"error\":\"Session expired\""));
        Ok(())
    }

    // ── Full response construction: ProofOk ───────────────────────────

    #[test]
    fn test_full_response_construction_proof_ok() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_state = ChallengeState::ProofOkWaitingForRedeem;
        let now = 1000u64;
        let expires_at = 1300u64;
        let created_at = 900u64;
        let session_id = "cafebabe-cafe-babe-cafe-babecafebabe";

        let effective_state = compute_effective_state(now, expires_at, &challenge_state);
        let proof_verified = compute_proof_verified(&challenge_state);
        let poll_after = compute_poll_after(effective_state, now);
        let complete = compute_complete(effective_state);
        let error = compute_error(effective_state);
        let remaining_checks = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(10);

        let response = StatusResponse {
            session_id: session_id.to_string(),
            state: effective_state,
            created_at,
            expires_at,
            proof_verified,
            complete,
            error,
            poll_after,
            remaining_checks: Some(remaining_checks),
        };

        assert_eq!(response.state, HostedSessionState::ProofOk);
        assert!(response.proof_verified);
        assert!(response.poll_after.is_none());
        assert_eq!(response.complete, Some(true));
        assert!(response.error.is_none());
        assert_eq!(response.remaining_checks, Some(110));
        Ok(())
    }

    // ── Full response construction: Failed (not past expiry) ──────────

    #[test]
    fn test_full_response_construction_failed() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_state = ChallengeState::Failed;
        let now = 1000u64;
        let expires_at = 1300u64;
        let created_at = 900u64;
        let session_id = "fa17fa17-fa17-fa17-fa17-fa17fa17fa17";

        let effective_state = compute_effective_state(now, expires_at, &challenge_state);
        let proof_verified = compute_proof_verified(&challenge_state);
        let poll_after = compute_poll_after(effective_state, now);
        let complete = compute_complete(effective_state);
        let error = compute_error(effective_state);

        let response = StatusResponse {
            session_id: session_id.to_string(),
            state: effective_state,
            created_at,
            expires_at,
            proof_verified,
            complete,
            error,
            poll_after,
            remaining_checks: Some(120),
        };

        // Failed maps to Expired even when not past expiry
        assert_eq!(response.state, HostedSessionState::Expired);
        assert!(!response.proof_verified);
        assert!(response.poll_after.is_none());
        assert_eq!(response.complete, Some(true));
        assert_eq!(response.error.as_deref(), Some("Session expired"));
        Ok(())
    }

    // ── Serde: deserialize valid minimal StatusResponse ────────────────

    #[test]
    fn test_status_response_deserialize_minimal_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "session_id": "abc",
            "status": "verified",
            "created_at": 100,
            "expires_at": 200,
            "proof_verified": true
        }"#;
        let resp: StatusResponse = serde_json::from_str(json)?;
        assert_eq!(resp.session_id, "abc");
        assert_eq!(resp.state, HostedSessionState::Verified);
        assert_eq!(resp.created_at, 100);
        assert_eq!(resp.expires_at, 200);
        assert!(resp.proof_verified);
        assert!(resp.complete.is_none());
        assert!(resp.error.is_none());
        assert!(resp.poll_after.is_none());
        assert!(resp.remaining_checks.is_none());
        Ok(())
    }

    // ── Serde: deserialize StatusResponse with all fields present ──────

    #[test]
    fn test_status_response_deserialize_all_fields_present(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "session_id": "full-test",
            "status": "pending",
            "created_at": 100,
            "expires_at": 400,
            "proof_verified": false,
            "complete": false,
            "error": "some error",
            "poll_after": 102,
            "remaining_checks": 99
        }"#;
        let resp: StatusResponse = serde_json::from_str(json)?;
        assert_eq!(resp.session_id, "full-test");
        assert_eq!(resp.state, HostedSessionState::Pending);
        assert_eq!(resp.created_at, 100);
        assert_eq!(resp.expires_at, 400);
        assert!(!resp.proof_verified);
        assert_eq!(resp.complete, Some(false));
        assert_eq!(resp.error.as_deref(), Some("some error"));
        assert_eq!(resp.poll_after, Some(102));
        assert_eq!(resp.remaining_checks, Some(99));
        Ok(())
    }

    // ── Serde: deserialize with explicit null for optional fields ──────

    #[test]
    fn test_status_response_deserialize_explicit_nulls() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "session_id": "null-test",
            "status": "expired",
            "created_at": 50,
            "expires_at": 100,
            "proof_verified": false,
            "complete": null,
            "error": null,
            "poll_after": null,
            "remaining_checks": null
        }"#;
        let resp: StatusResponse = serde_json::from_str(json)?;
        assert_eq!(resp.state, HostedSessionState::Expired);
        assert!(resp.complete.is_none());
        assert!(resp.error.is_none());
        assert!(resp.poll_after.is_none());
        assert!(resp.remaining_checks.is_none());
        Ok(())
    }

    // ── Serde: unknown HostedSessionState variant rejected ────────────

    #[test]
    fn test_hosted_session_state_deserialize_unknown_variant() {
        let result = serde_json::from_str::<HostedSessionState>("\"unknown_state\"");
        assert!(
            result.is_err(),
            "deserialising an unrecognised variant must fail"
        );
    }

    #[test]
    fn test_hosted_session_state_deserialize_empty_string() {
        let result = serde_json::from_str::<HostedSessionState>("\"\"");
        assert!(result.is_err(), "empty string must not deserialise");
    }

    #[test]
    fn test_hosted_session_state_deserialize_numeric() {
        let result = serde_json::from_str::<HostedSessionState>("42");
        assert!(result.is_err(), "numeric value must not deserialise");
    }

    #[test]
    fn test_hosted_session_state_deserialize_null() {
        let result = serde_json::from_str::<HostedSessionState>("null");
        assert!(result.is_err(), "null must not deserialise");
    }

    // ── Serde: StatusResponse missing required fields ─────────────────

    #[test]
    fn test_status_response_missing_session_id() {
        let json = r#"{
            "status": "pending",
            "created_at": 1,
            "expires_at": 2,
            "proof_verified": false
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "missing session_id should fail");
    }

    #[test]
    fn test_status_response_missing_status() {
        let json = r#"{
            "session_id": "x",
            "created_at": 1,
            "expires_at": 2,
            "proof_verified": false
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "missing status should fail");
    }

    #[test]
    fn test_status_response_missing_created_at() {
        let json = r#"{
            "session_id": "x",
            "status": "pending",
            "expires_at": 2,
            "proof_verified": false
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "missing created_at should fail");
    }

    #[test]
    fn test_status_response_missing_expires_at() {
        let json = r#"{
            "session_id": "x",
            "status": "pending",
            "created_at": 1,
            "proof_verified": false
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "missing expires_at should fail");
    }

    #[test]
    fn test_status_response_missing_proof_verified() {
        let json = r#"{
            "session_id": "x",
            "status": "pending",
            "created_at": 1,
            "expires_at": 2
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "missing proof_verified should fail");
    }

    // ── Serde: StatusResponse wrong types for fields ──────────────────

    #[test]
    fn test_status_response_wrong_type_for_created_at() {
        let json = r#"{
            "session_id": "x",
            "status": "pending",
            "created_at": "not_a_number",
            "expires_at": 2,
            "proof_verified": false
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "string for created_at should fail");
    }

    #[test]
    fn test_status_response_wrong_type_for_proof_verified() {
        let json = r#"{
            "session_id": "x",
            "status": "pending",
            "created_at": 1,
            "expires_at": 2,
            "proof_verified": "yes"
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err(), "string for proof_verified should fail");
    }

    // ── HostedSessionState: Copy semantics ────────────────────────────

    #[test]
    fn test_hosted_session_state_copy_semantics() {
        let a = HostedSessionState::Pending;
        let b = a; // Copy
        let c = a; // still valid because Copy
        assert_eq!(b, c);
        assert_eq!(a, HostedSessionState::Pending);
    }

    // ── HostedSessionState: Debug output ──────────────────────────────

    #[test]
    fn test_hosted_session_state_debug_format() {
        let state = HostedSessionState::ProofOk;
        let debug = format!("{:?}", state);
        assert!(
            debug.contains("ProofOk"),
            "Debug output should contain variant name, got: {}",
            debug
        );
    }

    // ── StatusResponse: Debug output ──────────────────────────────────

    #[test]
    fn test_status_response_debug_format() {
        let response = StatusResponse {
            session_id: "dbg-test".to_string(),
            state: HostedSessionState::Pending,
            created_at: 0,
            expires_at: 0,
            proof_verified: false,
            complete: None,
            error: None,
            poll_after: None,
            remaining_checks: None,
        };
        let debug = format!("{:?}", response);
        assert!(debug.contains("dbg-test"));
        assert!(debug.contains("Pending"));
    }

    // ── Serde: verify rename_all = lowercase is applied ───────────────

    #[test]
    fn test_serde_rename_all_lowercase() -> Result<(), Box<dyn std::error::Error>> {
        // Ensure PascalCase variants are rejected
        let result = serde_json::from_str::<HostedSessionState>("\"Pending\"");
        assert!(result.is_err(), "PascalCase should be rejected");

        let result = serde_json::from_str::<HostedSessionState>("\"PENDING\"");
        assert!(result.is_err(), "UPPERCASE should be rejected");

        // Confirm the correct lowercase form
        let state: HostedSessionState = serde_json::from_str("\"pending\"")?;
        assert_eq!(state, HostedSessionState::Pending);
        Ok(())
    }

    // ── Serde: proof_ok_waiting_for_redeem rename is exact ────────────

    #[test]
    fn test_serde_proof_ok_exact_rename() -> Result<(), Box<dyn std::error::Error>> {
        // The custom rename overrides the rename_all for ProofOk
        let state: HostedSessionState = serde_json::from_str("\"proof_ok_waiting_for_redeem\"")?;
        assert_eq!(state, HostedSessionState::ProofOk);

        // "proofok" (from rename_all = lowercase) should be rejected
        let result = serde_json::from_str::<HostedSessionState>("\"proofok\"");
        assert!(result.is_err(), "proofok without rename should be rejected");

        // "proof_ok" (truncated) should be rejected
        let result = serde_json::from_str::<HostedSessionState>("\"proof_ok\"");
        assert!(result.is_err(), "truncated proof_ok should be rejected");
        Ok(())
    }

    // ── Edge case: zero timestamps ────────────────────────────────────

    #[test]
    fn test_effective_state_zero_timestamps() {
        let state = ChallengeState::Pending;
        let now = 0u64;
        let expires_at = 0u64;
        // now == expires_at, strict >, so not expired
        assert_eq!(
            compute_effective_state(now, expires_at, &state),
            HostedSessionState::Pending
        );
    }

    // ── Edge case: u64::MAX timestamps ────────────────────────────────

    #[test]
    fn test_effective_state_max_timestamps() {
        let state = ChallengeState::Pending;
        let now = u64::MAX;
        let expires_at = u64::MAX;
        // Equal, so not expired
        assert_eq!(
            compute_effective_state(now, expires_at, &state),
            HostedSessionState::Pending
        );
    }

    // ── Edge case: remaining_checks with one check used ───────────────

    #[test]
    fn test_remaining_checks_one_used() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(1);
        assert_eq!(remaining, 119);
    }

    // ── Edge case: remaining_checks at exactly the limit ──────────────

    #[test]
    fn test_remaining_checks_at_exactly_limit() {
        let remaining = DEFAULT_MAX_STATUS_CHECKS.saturating_sub(DEFAULT_MAX_STATUS_CHECKS);
        assert_eq!(remaining, 0);
    }

    // ── Serde: StatusResponse serialisation field ordering stability ──

    #[test]
    fn test_status_response_contains_required_json_keys() -> Result<(), Box<dyn std::error::Error>>
    {
        let response = StatusResponse {
            session_id: "key-check".to_string(),
            state: HostedSessionState::Pending,
            created_at: 10,
            expires_at: 20,
            proof_verified: false,
            complete: Some(false),
            error: None,
            poll_after: Some(12),
            remaining_checks: Some(100),
        };
        let val: serde_json::Value = serde_json::to_value(&response)?;
        let obj = val.as_object().expect("should be an object");
        assert!(obj.contains_key("session_id"));
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("created_at"));
        assert!(obj.contains_key("expires_at"));
        assert!(obj.contains_key("proof_verified"));
        assert!(obj.contains_key("complete"));
        assert!(obj.contains_key("poll_after"));
        assert!(obj.contains_key("remaining_checks"));
        // error is None and skip_serializing_if, so must be absent
        assert!(!obj.contains_key("error"));
        Ok(())
    }

    // ── Serde: field name is "status" not "state" ─────────────────────

    #[test]
    fn test_status_response_field_renamed_to_status() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "rename-check".to_string(),
            state: HostedSessionState::Expired,
            created_at: 1,
            expires_at: 2,
            proof_verified: false,
            complete: None,
            error: None,
            poll_after: None,
            remaining_checks: None,
        };
        let json = serde_json::to_string(&response)?;
        assert!(json.contains("\"status\""));
        assert!(!json.contains("\"state\""));
        Ok(())
    }

    // ── Serde: "state" field in JSON should fail (renamed to "status") ─

    #[test]
    fn test_status_response_rejects_state_field_name() {
        let json = r#"{
            "session_id": "x",
            "state": "pending",
            "created_at": 1,
            "expires_at": 2,
            "proof_verified": false
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        // "state" is not recognised because of rename + deny_unknown_fields
        assert!(result.is_err(), "\"state\" field name should be rejected");
    }

    // ── Clone semantics for HostedSessionState ────────────────────────

    #[test]
    fn test_hosted_session_state_clone() {
        let original = HostedSessionState::Verified;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    // ── Clone semantics for StatusResponse ────────────────────────────

    #[test]
    fn test_status_response_clone() {
        let original = StatusResponse {
            session_id: "clone-test".to_string(),
            state: HostedSessionState::ProofOk,
            created_at: 100,
            expires_at: 200,
            proof_verified: true,
            complete: Some(true),
            error: None,
            poll_after: None,
            remaining_checks: Some(80),
        };
        let cloned = original.clone();
        assert_eq!(cloned.session_id, "clone-test");
        assert_eq!(cloned.state, HostedSessionState::ProofOk);
        assert_eq!(cloned.created_at, 100);
        assert_eq!(cloned.expires_at, 200);
        assert!(cloned.proof_verified);
        assert_eq!(cloned.complete, Some(true));
        assert!(cloned.error.is_none());
        assert!(cloned.poll_after.is_none());
        assert_eq!(cloned.remaining_checks, Some(80));
    }

    // ── Serde: large values for timestamps ────────────────────────────

    #[test]
    fn test_status_response_large_timestamp_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let response = StatusResponse {
            session_id: "large-ts".to_string(),
            state: HostedSessionState::Pending,
            created_at: u64::MAX - 1,
            expires_at: u64::MAX,
            proof_verified: false,
            complete: Some(false),
            error: None,
            poll_after: Some(u64::MAX),
            remaining_checks: Some(u32::MAX),
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: StatusResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.created_at, u64::MAX - 1);
        assert_eq!(deserialized.expires_at, u64::MAX);
        assert_eq!(deserialized.poll_after, Some(u64::MAX));
        assert_eq!(deserialized.remaining_checks, Some(u32::MAX));
        Ok(())
    }

    // ── Serde: empty session_id string is allowed by serde ────────────

    #[test]
    fn test_status_response_empty_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "session_id": "",
            "status": "pending",
            "created_at": 0,
            "expires_at": 0,
            "proof_verified": false
        }"#;
        let resp: StatusResponse = serde_json::from_str(json)?;
        assert_eq!(resp.session_id, "");
        Ok(())
    }

    // ── Serde: multiple unknown fields rejected ───────────────────────

    #[test]
    fn test_status_response_rejects_multiple_unknown_fields() {
        let json = r#"{
            "session_id": "a",
            "status": "pending",
            "created_at": 1,
            "expires_at": 2,
            "proof_verified": false,
            "extra1": "bad",
            "extra2": 42
        }"#;
        let result = serde_json::from_str::<StatusResponse>(json);
        assert!(result.is_err());
    }
}
