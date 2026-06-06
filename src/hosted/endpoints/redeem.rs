// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! PKCE redemption handler for hosted verification sessions.
//!
//! `POST /v1/hosted/redeem/:session_id` completes the hosted verification flow.
//! The browser SDK sends the PKCE `code_verifier`; this handler SHA-256 hashes
//! it and compares the digest against the stored `code_challenge_bytes` in
//! constant time, then transitions the challenge to `Verified`.
//!
//! In the original provii-verifier this involved a dual-PKCE flow with two
//! separate service binding calls to provii-verifier. Now that the handler lives
//! inside provii-verifier, the challenge store is accessed directly and only one
//! PKCE check is needed (the SDK-side verifier against the challenge's
//! code_challenge).
//!
//! SECURITY: Constant-time PKCE comparison via `subtle::ConstantTimeEq`, origin
//! matching, session binding, per-IP and per-session rate limiting, and
//! idempotency deduplication are all enforced.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use worker::{Error as WorkerError, Headers, Response};
use zeroize::Zeroize;

use crate::{
    analytics::Analytics,
    cache::ChallengeState,
    clients::{ConsumeCreditsRequest, CreditError},
    error::ApiError,
    hosted::session_binding::{verify_session_binding, BindingOutcome},
    hosted::storage::kv::get_session_kv_tracked,
    security::log_sanitizer::redact_challenge_id,
    utils::{current_timestamp, NONCE_DEDUP_TTL},
    AppState,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};

/// Default maximum redemption attempts per challenge.
///
/// Used by the router layer (M-058) to enforce per-session redeem rate limits.
pub const DEFAULT_MAX_REDEEM_ATTEMPTS: u32 = 3;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/hosted/redeem/:session_id`.
///
/// SECURITY: `code_verifier` is zeroized on drop (ASVS 11.7.1 L3). The manual
/// `Debug` impl redacts the verifier to prevent secret leakage via logging.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedRedeemRequest {
    /// PKCE code verifier (43-128 chars, [A-Za-z0-9-._~]).
    pub code_verifier: String,
}

impl std::fmt::Debug for HostedRedeemRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedRedeemRequest")
            .field("code_verifier", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HostedRedeemRequest {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
    }
}

/// Response body for a successful hosted redemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedRedeemResponse {
    /// Session state, always `"verified"` on success.
    pub status: String,

    /// When verification completed (Unix timestamp seconds).
    pub verified_at: u64,

    /// When the session expires (Unix timestamp seconds).
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate PKCE code_verifier format and length per RFC 7636.
fn validate_code_verifier(verifier: &str) -> Result<(), ApiError> {
    if verifier.is_empty() {
        return Err(ApiError::BadRequest(Some(
            "Code verifier cannot be empty".into(),
        )));
    }

    // PKCE spec requires 43-128 characters.
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(ApiError::BadRequest(Some(
            "Code verifier must be 43-128 characters".into(),
        )));
    }

    // Base64url unreserved characters only (RFC 7636 appendix B).
    if !verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~')
    {
        return Err(ApiError::BadRequest(Some(
            "Code verifier must contain only unreserved characters [A-Za-z0-9-._~]".into(),
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Redeem a hosted verification session with a PKCE code verifier.
///
/// Validates the code verifier against the challenge's stored code_challenge
/// (SHA-256 + constant-time comparison), transitions the challenge to
/// `Verified`, and returns the verification timestamp.
///
/// This replaces the original provii-verifier flow which called provii-verifier
/// twice via service bindings (once for local PKCE, once for server-side PKCE).
/// Now there is a single PKCE check against the challenge store.
///
/// # Security checks
///
/// 1. Per-IP rate limit (enforced at router level)
/// 2. Session ID format validation (UUID)
/// 3. Origin presence and match
/// 4. Code verifier format validation (RFC 7636)
/// 5. Session binding (IP + UA HMAC hash) verification (ADV-VA-04-002)
/// 6. Nonce deduplication (prevents concurrent redemption)
/// 7. Challenge state validation (must be ProofOkWaitingForRedeem)
/// 8. PKCE SHA-256 constant-time comparison (`subtle::ConstantTimeEq`)
/// 9. Challenge state transition to Verified
///
/// TODO(testing): ADV-VA-06-012 / VA-RTE-011 -- session cookie validation,
/// CSRF, PKCE verification, and challenge state transitions lack integration
/// tests. Requires a test harness with Durable Object and KV bindings.
pub async fn handle_hosted_redeem(
    state: Arc<AppState>,
    headers: Headers,
    session_id: &str,
    mut body: HostedRedeemRequest,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(8);

    let origin = headers.get("Origin").ok().flatten().unwrap_or_default();

    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    // ── Require Origin ─────────────────────────────────────────────────────
    if origin.is_empty() {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_redeem:missing_origin")
            .await;
        return ApiError::BadRequest(Some("Missing Origin header".into())).to_response();
    }

    // ── Validate session_id format ──────────────────────────────────────────
    if Uuid::parse_str(session_id).is_err() {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_redeem:invalid_session_id")
            .await;
        return ApiError::BadRequest(Some("Invalid session_id format".into())).to_response();
    }

    // ── Validate code verifier format ──────────────────────────────────────
    if let Err(e) = validate_code_verifier(&body.code_verifier) {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_redeem:invalid_code_verifier")
            .await;
        return e.to_response();
    }

    // ── Load session from KV to resolve challenge_id ───────────────────────
    // The URL contains session_id, but the challenge store is indexed by
    // challenge_id. Load the hosted session to find the mapping.
    //
    // capture which HOSTED_MEK slot satisfied the session
    // decrypt path so the per-request `secret_version` log line can attribute
    // the satisfying slot.
    let mut hosted_mek_slot: Option<crate::security::secret_versions::RotationSlot> = None;
    let session =
        match get_session_kv_tracked(&state.env, session_id, Some(&mut hosted_mek_slot)).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/redeem] Session not found in KV: {}",
                    redact_challenge_id(session_id)
                );
                return ApiError::NotFound.to_response();
            }
            Err(e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/redeem] Failed to read session {}: {}",
                    redact_challenge_id(session_id),
                    e
                );
                return ApiError::Internal(anyhow::anyhow!(e)).to_response();
            }
        };

    // ── Origin must match the session creator ──────────────────────────────
    let origin_match = {
        use subtle::ConstantTimeEq;
        let a = origin.as_bytes();
        let b = session.origin.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    };
    if !origin_match {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/redeem] SECURITY: Origin mismatch for session {}",
            redact_challenge_id(session_id)
        );
        // ADV-VA-029: Structured auth failure audit.
        state
            .audit_logger
            .log_authentication_failure(
                &client_ip,
                "hosted_redeem:origin_mismatch",
                None,
                Some(&origin),
                Some(serde_json::json!({
                    "endpoint": "/v1/hosted/redeem",
                    "session_id": session_id,
                    "expected_origin": session.origin,
                })),
            )
            .await;
        return ApiError::Forbidden(Some("Origin does not match session".into())).to_response();
    }

    // ── BOLA: require X-Public-Key and compare to session owner ─────────────
    {
        let provided_public_key = headers
            .get("X-Public-Key")
            .ok()
            .flatten()
            .unwrap_or_default();
        if provided_public_key.is_empty() {
            // ADV-VA-029: Structured auth failure audit.
            state
                .audit_logger
                .log_authentication_failure(
                    &client_ip,
                    "hosted_redeem:bola_missing_public_key",
                    None,
                    Some(&origin),
                    Some(serde_json::json!({
                        "endpoint": "/v1/hosted/redeem",
                        "session_id": session_id,
                    })),
                )
                .await;
            return ApiError::Forbidden(Some("Access denied".into())).to_response();
        }
        let provided_bytes = provided_public_key.as_bytes();
        let expected_bytes = session.public_key.as_bytes();
        let len_ok = provided_bytes.len() == expected_bytes.len();
        let ct_ok = if len_ok {
            bool::from(ConstantTimeEq::ct_eq(provided_bytes, expected_bytes))
        } else {
            false
        };
        if !ct_ok {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] SECURITY: BOLA - X-Public-Key mismatch for session {}",
                redact_challenge_id(session_id)
            );
            // ADV-VA-029: Structured auth failure audit.
            state
                .audit_logger
                .log_authentication_failure(
                    &client_ip,
                    "hosted_redeem:bola_public_key_mismatch",
                    None,
                    Some(&origin),
                    Some(serde_json::json!({
                        "endpoint": "/v1/hosted/redeem",
                        "session_id": session_id,
                    })),
                )
                .await;
            return ApiError::Forbidden(Some("Access denied".into())).to_response();
        }
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
                    "[hosted/redeem] Session binding: IP mismatch (relaxed) for session {}",
                    redact_challenge_id(session_id)
                );
            }
            Ok(BindingOutcome::UaMismatchRelaxed) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/redeem] Session binding: UA mismatch (relaxed) for session {}",
                    redact_challenge_id(session_id)
                );
            }
            Err(e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/redeem] SECURITY: Session binding rejected for session {}",
                    redact_challenge_id(session_id)
                );
                state
                    .audit_logger
                    .log_authentication_failure(
                        &client_ip,
                        "hosted_redeem:session_binding_mismatch",
                        None,
                        Some(&origin),
                        Some(serde_json::json!({
                            "endpoint": "/v1/hosted/redeem",
                            "session_id": session_id,
                            "binding_mode": format!("{:?}", session.binding_mode),
                        })),
                    )
                    .await;
                return e.to_response();
            }
        }
    }

    // ── Per-session redemption rate limit ─────────────────────────────────────
    // INV-VA-041: This counter is stored in KV, which is eventually consistent
    // and not atomic. Two concurrent requests could both read the same count
    // and both pass the limit check. This is acceptable because the nonce
    // deduplication check below (DO-backed, single-writer serialised) is the
    // real protection against duplicate redemption. This KV counter serves
    // only as a coarse brute-force throttle; it does not need to be precise.
    {
        let mut session_mut = session.clone();
        session_mut.increment_redeem_attempts();
        if session_mut.redeem_attempt_count > DEFAULT_MAX_REDEEM_ATTEMPTS {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Redemption rate limit exceeded for session {}",
                redact_challenge_id(session_id)
            );
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_redeem:session_rate_limit_exceeded")
                .await;
            return ApiError::TooManyRequests(Some("Redemption rate limit exceeded".into()))
                .to_response();
        }
        // Persist updated count. Non-fatal if write fails (defence in depth:
        // nonce dedup catches successful duplicates, this catches brute-force).
        // Pass prior state to avoid redundant KV GET + decrypt.
        if let Err(_e) = crate::hosted::storage::kv::update_session_kv_checked(
            &state.env,
            &session_mut,
            Some(session_mut.state),
        )
        .await
        {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Failed to persist redeem_attempt_count for {}: {}",
                redact_challenge_id(session_id),
                _e
            );
        }
    }

    let challenge_id = match Uuid::parse_str(&session.verifier_challenge_id) {
        Ok(id) => id,
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Invalid challenge_id in session: {}",
                redact_challenge_id(session_id)
            );
            return ApiError::Internal(anyhow::anyhow!("corrupt session data")).to_response();
        }
    };

    // ── Nonce dedup: prevent concurrent redemption ─────────────────────────
    let nonce_tag = format!("hosted_redeem:{}", challenge_id);
    let phase_start = worker::Date::now().as_millis();
    let nonce_result = state
        .nonce_store
        .check_and_set(&nonce_tag, NONCE_DEDUP_TTL)
        .await;
    phase_timings.push((
        "nonce_dedup",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));
    match nonce_result {
        Ok(true) => { /* first observation, proceed */ }
        Ok(false) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Duplicate redemption detected for challenge {}",
                redact_challenge_id(session_id)
            );
            state
                .audit_logger
                .log_replay_attempt(
                    &challenge_id.to_string(),
                    &client_ip,
                    state.analytics.as_ref(),
                )
                .await;
            return ApiError::Conflict(Some("Duplicate redemption attempt".into())).to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/redeem] Nonce store error: {:?}", e);
            return ApiError::Internal(e.into()).to_response();
        }
    }

    // ── Load challenge ─────────────────────────────────────────────────────
    let phase_start = worker::Date::now().as_millis();
    let mut cached = match state.challenge_store.get(&challenge_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Challenge not found: {}",
                redact_challenge_id(session_id)
            );
            state
                .audit_logger
                .log_verification_attempt(
                    &challenge_id.to_string(),
                    &client_ip,
                    false,
                    Some("hosted_redeem_not_found".to_string()),
                )
                .await;
            return ApiError::NotFound.to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Failed to load challenge {}: {:?}",
                redact_challenge_id(session_id),
                e
            );
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "downstream_failure:challenge_store_read")
                .await;
            return ApiError::Internal(e.into()).to_response();
        }
    };
    phase_timings.push((
        "challenge_get",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    // SECURITY: Eagerly zeroize the submit_secret; it is not needed during redemption.
    cached.submit_secret.zeroize();

    // Origin was already checked against the session. Defence in depth: verify
    // the challenge store origin matches too (should always be the case since
    // both are set during challenge creation).
    if origin != cached.origin {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/redeem] SECURITY: Challenge origin diverged from session origin for {}",
            redact_challenge_id(session_id)
        );
        return ApiError::Internal(anyhow::anyhow!("origin consistency violation")).to_response();
    }

    // ── Check expiry ────────────────────────────────────────────────────────
    let now = current_timestamp();
    if now > cached.expires_at && cached.state != ChallengeState::Verified {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/redeem] Challenge expired: {}",
            redact_challenge_id(session_id)
        );
        state
            .audit_logger
            .log_verification_attempt(
                &challenge_id.to_string(),
                &client_ip,
                false,
                Some("hosted_redeem_expired".to_string()),
            )
            .await;
        return ApiError::Gone(Some("Session has expired".into())).to_response();
    }

    // ── KV eventual consistency retry ──────────────────────────────────────
    // If state is Pending, the verify endpoint may have written
    // ProofOkWaitingForRedeem from a different isolate. Re-read once.
    if cached.state == ChallengeState::Pending {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/redeem] Challenge {} in Pending state, retrying read",
            redact_challenge_id(session_id)
        );
        #[cfg(target_arch = "wasm32")]
        {
            let promise = js_sys::Promise::resolve(&wasm_bindgen::JsValue::NULL);
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
        }
        match state.challenge_store.get(&challenge_id).await {
            Ok(Some(refreshed)) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/redeem] Retry: challenge {} now {:?}",
                    redact_challenge_id(session_id),
                    refreshed.state
                );
                let mut r = refreshed;
                r.submit_secret.zeroize();
                cached = r;
            }
            Ok(None) => {
                // Challenge not found on retry; proceed with cached value.
            }
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[REDEEM][WARN] KV retry failed: {}", _e);
                // proceed with cached value
            }
        }
    }

    // ── Verify challenge is awaiting redemption ─────────────────────────────
    if cached.state != ChallengeState::ProofOkWaitingForRedeem {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/redeem] Challenge {} in wrong state: {:?}",
            redact_challenge_id(session_id),
            cached.state
        );
        state
            .audit_logger
            .log_verification_attempt(
                &challenge_id.to_string(),
                &client_ip,
                false,
                Some(format!("hosted_redeem_wrong_state:{:?}", cached.state)),
            )
            .await;

        return match cached.state {
            ChallengeState::Pending => {
                ApiError::Conflict(Some("Proof not submitted yet".into())).to_response()
            }
            ChallengeState::ProofOkWaitingForRedeem => {
                // Should not reach here (guarded above), but handle for exhaustiveness.
                ApiError::Conflict(Some("Challenge not ready for redemption".into())).to_response()
            }
            ChallengeState::Verified => {
                ApiError::Conflict(Some("Session has already been redeemed".into())).to_response()
            }
            ChallengeState::Failed => {
                ApiError::Conflict(Some("Challenge failed verification".into())).to_response()
            }
            ChallengeState::Expired => {
                ApiError::Gone(Some("Session has expired".into())).to_response()
            }
        };
    }

    // ── PKCE SHA-256 constant-time comparison ──────────────────────────────
    let phase_start = worker::Date::now().as_millis();
    let computed = Sha256::digest(body.code_verifier.as_bytes());
    phase_timings.push((
        "pkce_hash",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    // SECURITY: ct_eq is deliberately NOT timed to avoid leaking comparison duration.
    let pkce_ok = bool::from(ConstantTimeEq::ct_eq(
        computed.as_slice(),
        cached.code_challenge_bytes.as_slice(),
    ));
    if !pkce_ok {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/redeem] PKCE validation failed for challenge {}",
            redact_challenge_id(session_id)
        );
        state
            .audit_logger
            .log_verification_attempt(
                &challenge_id.to_string(),
                &client_ip,
                false,
                Some("hosted_redeem_pkce_failed".to_string()),
            )
            .await;
        return ApiError::BadRequest(Some("Invalid code_verifier".into())).to_response();
    }

    // Zeroize the code verifier now that verification is complete.
    body.code_verifier.zeroize();

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[hosted/redeem] PKCE validated for challenge {}",
        redact_challenge_id(session_id)
    );

    // ── F-CRP-008: Read SESSION_TOKEN_SECRET from cached AppState ─────────
    // SC-001: Secret is pre-loaded at startup (M-049). Fail with 503 BEFORE
    // any credit deduction if absent, avoiding the paid-but-no-session scenario.
    //
    // this read is sign-side only.
    // The handler does not verify any inbound session token; verification lives
    // in `hosted::endpoints::session_check::verify_token_with_fallback` and is
    // already dual-slot. New tokens are always signed with the current secret,
    // so no `_PREVIOUS` fallback is required here.
    let session_token_secret = match state.session_token_secret.as_ref() {
        Some(s) => (**s).clone(),
        None => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[CRITICAL] [hosted/redeem] SESSION_TOKEN_SECRET not cached at startup; \
                 returning 503 before billing"
            );
            state
                .audit_logger
                .log_suspicious_activity(
                    &client_ip,
                    "hosted_redeem:session_token_secret_unavailable",
                )
                .await;
            return ApiError::ServiceUnavailable(Some("Session signing unavailable".into()))
                .to_response();
        }
    };

    // ── Transition challenge to Verified ────────────────────────────────────
    // ── Credit enforcement: fail closed for metered origins ───────────────
    // Policy: no credits => no service. The challenge-creation gate can lag, so a
    // metered origin's balance can reach zero between challenge and redemption.
    // Deduct SYNCHRONOUSLY here, before granting the verdict, and refuse to verify
    // if the deduction cannot be completed. metering_enabled is stable per-origin
    // config (unlike the volatile has_credits), so re-reading ORIGIN_INDEX is
    // authoritative. Unmetered / test origins have no CreditBalance account (the
    // DO returns 402 for an unprovisioned customer), so only metered origins are
    // enforced; unmetered origins keep the best-effort background deduction below.
    let origin_is_metered: bool = {
        let mut metered = false;
        if let Ok(oi_kv) = state.env.kv("ORIGIN_INDEX") {
            let oi_kv_clone = oi_kv.clone();
            let origin_clone = origin.clone();
            if let Ok(Ok(Some(json_str))) = crate::utils::timeout::with_timeout(
                "origin_index KV read (hosted redeem)",
                crate::utils::timeout::KV_READ_TIMEOUT_MS,
                async move { oi_kv_clone.get(&origin_clone).text().await },
            )
            .await
            {
                #[derive(serde::Deserialize)]
                struct OIMetering {
                    #[serde(default)]
                    metering_enabled: Option<bool>,
                }
                if let Ok(entry) = serde_json::from_str::<OIMetering>(&json_str) {
                    metered = entry.metering_enabled == Some(true);
                }
            }
        }
        metered
    };

    if origin_is_metered {
        match state.credit_management_client.clone() {
            Some(credit_client) => {
                let environment = state
                    .env
                    .var("ENVIRONMENT")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| "production".to_string());
                let credit_request = ConsumeCreditsRequest {
                    customer_id: cached.tenant_id.clone().unwrap_or_else(|| origin.clone()),
                    verification_id: challenge_id.to_string(),
                    origin: origin.clone(),
                    issuer_kid: cached.issuer_kid.clone(),
                    environment,
                    partner_id: None,
                };
                match credit_client.consume_credits(credit_request).await {
                    Ok(_) | Err(CreditError::Conflict(_)) => {}
                    Err(CreditError::InsufficientCredits {
                        available: _available,
                        required: _required,
                    }) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"INFO","component":"billing","event":"redeem_denied_insufficient","challenge_id":"{}","available":{},"required":{}}}"#,
                            redact_challenge_id(&challenge_id.to_string()),
                            _available,
                            _required
                        );
                        let _ = state
                            .audit_logger
                            .log_suspicious_activity(
                                &client_ip,
                                "billing:redeem_denied_insufficient",
                            )
                            .await;
                        return ApiError::PaymentRequired(None).to_response();
                    }
                    Err(_e) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"CRITICAL","component":"billing","event":"redeem_denied_credit_unavailable","challenge_id":"{}","error":"{:?}"}}"#,
                            redact_challenge_id(&challenge_id.to_string()),
                            _e
                        );
                        let _ = state
                            .audit_logger
                            .log_suspicious_activity(
                                &client_ip,
                                "billing:redeem_denied_credit_unavailable",
                            )
                            .await;
                        return ApiError::ServiceUnavailable(Some(
                            "Billing temporarily unavailable".into(),
                        ))
                        .to_response();
                    }
                }
            }
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[CRITICAL] [hosted/redeem] Metered origin {} but credit client unavailable; denying",
                    origin
                );
                return ApiError::ServiceUnavailable(Some("Billing not configured".into()))
                    .to_response();
            }
        }
    }

    // Mark the challenge as verified. Metered origins were billed synchronously
    // above; unmetered origins are billed best-effort below.
    cached.state = ChallengeState::Verified;
    cached.verified_at = Some(now);
    let phase_start = worker::Date::now().as_millis();
    if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
        // KV-046: State write failed. Credits have not been deducted yet (they
        // are dispatched in the background below), so no billing inconsistency.
        // Log CRITICAL and return failure.
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[CRITICAL] [hosted/redeem] State write failed for challenge {}: {:?}",
            redact_challenge_id(session_id),
            _e
        );
        state
            .audit_logger
            .log_state_write_failed_after_billing(
                &challenge_id.to_string(),
                &client_ip,
                state.analytics.as_ref(),
            )
            .await;
        return ApiError::Internal(anyhow::anyhow!("State transition failed")).to_response();
    }
    phase_timings.push((
        "challenge_put",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    // ── Audit: log successful redemption ────────────────────────────────────
    let _redacted_id = redact_challenge_id(session_id);
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[BILLING] Hosted redemption complete: Challenge={}, RP={}, Status=REDEEMED",
        _redacted_id,
        cached.origin
    );

    state
        .audit_logger
        .log_verification_attempt(&challenge_id.to_string(), &client_ip, true, None)
        .await;

    // ── F-CRP-007: Billing analytics and audit events ─────────────────────
    let zero = [0u8; 32];
    let issuer_kid_opt = cached.issuer_kid.as_deref();
    let issuer_vk_ref = cached.issuer_vk_bytes.as_ref().unwrap_or(&zero);
    let analytics = Analytics::new(&state.env);

    if let Some(kid) = issuer_kid_opt {
        analytics.billing_verification_success(
            "/v1/hosted/redeem",
            &challenge_id.to_string(),
            &origin,
            Some(kid),
            Some(&URL_SAFE_NO_PAD.encode(issuer_vk_ref)),
            cached.cutoff_days,
            true,
            &state.cfg.environment,
        );
    } else {
        analytics.billing_verification_success(
            "/v1/hosted/redeem",
            &challenge_id.to_string(),
            &origin,
            None,
            None,
            cached.cutoff_days,
            false,
            &state.cfg.environment,
        );

        if let Err(_e) = state
            .audit_logger
            .log_verification_no_royalty(&challenge_id.to_string(), &origin, &zero, now)
            .await
        {
            #[cfg(target_arch = "wasm32")]
            console_log!("[AUDIT][ERROR] no-royalty event logging failed: {}", _e);
        }
    }

    // Audit log the billing event.
    if let Err(_e) = state
        .audit_logger
        .log_billing_event(
            &challenge_id.to_string(),
            &origin,
            issuer_kid_opt,
            issuer_vk_ref,
            cached.cutoff_days,
            now,
        )
        .await
    {
        #[cfg(target_arch = "wasm32")]
        console_log!("[AUDIT][ERROR] billing event logging failed: {}", _e);
    }

    // ── F-CRP-001-REV: Dispatch credit deduction off the critical path ────
    // Unmetered origins: best-effort background deduction (metered origins were
    // already billed synchronously above, so skip them here). For unmetered/test
    // origins the CreditBalance DO returns 402 for an unprovisioned customer, so
    // any failure here is expected and must not block the verdict.
    if origin_is_metered {
        // Already billed synchronously; nothing to do.
    } else if let Some(credit_client) = state.credit_management_client.clone() {
        let environment = state
            .env
            .var("ENVIRONMENT")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "production".to_string());

        let credit_request = ConsumeCreditsRequest {
            customer_id: cached.tenant_id.clone().unwrap_or_else(|| origin.clone()),
            verification_id: challenge_id.to_string(),
            origin: origin.clone(),
            issuer_kid: cached.issuer_kid.clone(),
            environment,
            partner_id: None, // Populated once challenge creation stores provisioned_by
        };

        let bg_audit = state.audit_logger.clone();
        let _bg_challenge_id = challenge_id.to_string();
        let bg_client_ip = client_ip.clone();

        if let Some(ctx) = crate::take_worker_context() {
            ctx.wait_until(async move {
                match credit_client.consume_credits(credit_request).await {
                    Ok(_response) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[hosted/redeem] Background credit deduction succeeded: \
                             balance={} units, royalty_units_credited={}",
                            _response.balance_after_units.unwrap_or(0),
                            _response.royalty_units_credited.unwrap_or(0)
                        );
                    }
                    Err(CreditError::Conflict(_msg)) => {
                        // Idempotent duplicate, already charged. Expected during retries.
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[hosted/redeem] Background credit conflict (duplicate): {}",
                            _msg
                        );
                    }
                    Err(CreditError::InsufficientCredits { available: _available, required: _required }) => {
                        // Should not happen if the early challenge-time check works,
                        // but log CRITICAL so ops can investigate stale credit data.
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"CRITICAL","component":"billing","event":"background_deduction_insufficient","challenge_id":"{}","available":{},"required":{}}}"#,
                            redact_challenge_id(&_bg_challenge_id),
                            _available,
                            _required
                        );
                        let _ = bg_audit
                            .log_suspicious_activity(
                                &bg_client_ip,
                                "billing:background_deduction_insufficient",
                            )
                            .await;
                    }
                    Err(_e) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"CRITICAL","component":"billing","event":"background_deduction_failed","challenge_id":"{}","error":"{:?}"}}"#,
                            redact_challenge_id(&_bg_challenge_id),
                            _e
                        );
                        let _ = bg_audit
                            .log_suspicious_activity(
                                &bg_client_ip,
                                "billing:background_deduction_failed",
                            )
                            .await;
                    }
                }
            });
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/redeem] Credit deduction dispatched via wait_until for {}",
                redact_challenge_id(&challenge_id.to_string())
            );
        } else {
            // No worker context available (should not happen in production).
            // Fall back to inline deduction to avoid silent billing loss.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[WARN] [hosted/redeem] Worker context unavailable, running credit deduction inline"
            );
            match credit_client.consume_credits(credit_request).await {
                Ok(_) => {}
                Err(CreditError::Conflict(_)) => {}
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        r#"{{"level":"CRITICAL","component":"billing","event":"inline_deduction_failed","challenge_id":"{}","error":"{:?}"}}"#,
                        redact_challenge_id(&challenge_id.to_string()),
                        _e
                    );
                    state
                        .audit_logger
                        .log_suspicious_activity(&client_ip, "billing:inline_deduction_failed")
                        .await;
                }
            }
        }
    } else {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[WARN] [hosted/redeem] Credit client not configured. \
             Verification proceeding without billing."
        );
    }

    // ── Create signed session token and Set-Cookie header ─────────────────
    // Token format: base64url(json_payload).base64url(hmac_sha256(payload))
    // This mirrors the format expected by session_check::verify_token().
    // SESSION_TOKEN_SECRET was pre-fetched before billing (F-CRP-008).
    let session_cookie = {
        let cookie_name = state
            .env
            .var("SESSION_COOKIE_NAME")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "__Host-session".to_string());

        let token_data = serde_json::json!({
            "session_id": session_id,
            "origin": origin,
            "exp": cached.expires_at,
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(token_data.to_string().as_bytes());
        let secret_bytes = URL_SAFE_NO_PAD
            .decode(session_token_secret.as_bytes())
            .unwrap_or_else(|_| session_token_secret.as_bytes().to_vec());

        let mut mac = <Hmac<Sha256>>::new_from_slice(&secret_bytes).map_err(|_| {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/redeem] HMAC key rejected");
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?;
        mac.update(payload_b64.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        let token = format!("{}.{}", payload_b64, sig);
        let max_age = cached.expires_at.saturating_sub(now);

        // Use CookieConfig for consistent cookie attributes across all endpoints.
        let cookie_cfg = crate::hosted::cookie::CookieConfig::new()
            .with_name(cookie_name)
            .with_max_age(max_age);
        crate::hosted::cookie::generate_session_cookie(&token, &cookie_cfg)
    };

    // ── Build response ──────────────────────────────────────────────────────
    let response = HostedRedeemResponse {
        status: "verified".to_string(),
        verified_at: now,
        expires_at: cached.expires_at,
    };

    let duration_ms = worker::Date::now().as_millis().saturating_sub(start) as f64;
    let _phases_json = phase_timings
        .iter()
        .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
        .collect::<Vec<_>>()
        .join(",");
    let _slow_phases: Vec<&str> = phase_timings
        .iter()
        .filter(|(_, ms)| *ms > 50.0)
        .map(|(name, _)| *name)
        .collect();
    #[cfg(target_arch = "wasm32")]
    console_log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-verifier","route":"/v1/hosted/redeem","status":200,"duration_ms":{:.1},"phases":{{{}}},"slow":{},"slow_phases":"{}"}}"#,
        duration_ms,
        _phases_json,
        duration_ms > 500.0,
        _slow_phases.join(",")
    );

    // Fire-and-forget analytics event for successful redemption.
    analytics.hosted_redeemed(
        "/v1/hosted/redeem",
        session_id,
        &origin,
        duration_ms,
        &state.cfg.environment,
    );

    let mut resp = Response::from_json(&response)?;
    resp.headers_mut().append("Set-Cookie", &session_cookie)?;

    // emit the per-request `secret_version` log line + apply
    // the `x-secret-version` header carrying the HOSTED_MEK slot that
    // satisfied the session decrypt at the top of the handler.
    {
        let line = crate::security::secret_versions::SecretVersionLine::single_for_slot(
            state.hosted_mek_role,
            &state.hosted_mek_fingerprint,
            &state.hosted_mek_fingerprint_previous,
            hosted_mek_slot,
        );
        line.emit_log("POST /v1/hosted/redeem");
        line.apply_header(&mut resp)?;
    }

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_code_verifier_valid() {
        let verifier = "a".repeat(43);
        assert!(validate_code_verifier(&verifier).is_ok());

        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs";
        assert!(validate_code_verifier(verifier).is_ok());

        let verifier = "abcdefghijklmnopqrstuvwxyz-._~ABCDEFGHIJKLMNOPQ";
        assert!(validate_code_verifier(verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_too_short() {
        let verifier = "a".repeat(42);
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_too_long() {
        let verifier = "a".repeat(129);
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_empty() {
        assert!(validate_code_verifier("").is_err());
    }

    #[test]
    fn test_validate_code_verifier_invalid_chars() {
        let verifier = format!("{}!", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_redeem_request_debug_redacts() {
        let req = HostedRedeemRequest {
            code_verifier: "secret-verifier".to_string(),
        };
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("secret-verifier"));
    }

    #[test]
    fn test_redeem_response_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 1234567890,
            expires_at: 1234568190,
        };

        let json = serde_json::to_string(&response)?;
        assert!(json.contains("verified"));
        assert!(json.contains("1234567890"));
        assert!(json.contains("1234568190"));
        Ok(())
    }

    // ── Additional code_verifier validation edge cases ──────────────────

    #[test]
    fn test_validate_code_verifier_exact_43() {
        let verifier = "a".repeat(43);
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_exact_128() {
        let verifier = "A".repeat(128);
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_all_unreserved_chars() {
        // Every allowed char class: uppercase, lowercase, digits, -, ., _, ~
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk0123456789-._~A";
        assert_eq!(verifier.len(), 52);
        assert!(validate_code_verifier(verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_rejects_space() {
        let verifier = format!("{} {}", "a".repeat(21), "b".repeat(21));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_plus() {
        // + is not in the unreserved character set
        let verifier = format!("{}+", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_equals() {
        // = is not in the unreserved character set
        let verifier = format!("{}=", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_slash() {
        let verifier = format!("{}/", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    // ── Redeem request deserialisation ───────────────────────────────────

    #[test]
    fn test_redeem_request_deserialize_valid() {
        let json = r#"{"code_verifier":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let req: HostedRedeemRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.code_verifier.len(), 43);
    }

    #[test]
    fn test_redeem_request_rejects_unknown_fields() {
        let json = r#"{"code_verifier":"aaa","extra_field":"evil"}"#;
        let result = serde_json::from_str::<HostedRedeemRequest>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    #[test]
    fn test_redeem_request_rejects_missing_verifier() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<HostedRedeemRequest>(json);
        assert!(result.is_err());
    }

    // ── Redeem response deserialisation roundtrip ────────────────────────

    #[test]
    fn test_redeem_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 1700000000,
            expires_at: 1700000300,
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: HostedRedeemResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.status, "verified");
        assert_eq!(deserialized.verified_at, 1700000000);
        assert_eq!(deserialized.expires_at, 1700000300);
        Ok(())
    }

    #[test]
    fn test_redeem_response_rejects_unknown_fields() {
        let json = r#"{"status":"verified","verified_at":1,"expires_at":2,"extra":"bad"}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn test_default_max_redeem_attempts() {
        assert_eq!(DEFAULT_MAX_REDEEM_ATTEMPTS, 3);
    }

    // ── code_verifier: unicode and control character rejection ──────────

    #[test]
    fn test_validate_code_verifier_rejects_unicode() {
        // Non-ASCII characters are rejected.
        let verifier = format!("{}\u{00E9}", "a".repeat(42)); // e-acute
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_null_byte() {
        let verifier = format!("{}\0", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_newline() {
        let verifier = format!("{}\n", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_tab() {
        let verifier = format!("{}\t", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_at_sign() {
        let verifier = format!("{}@", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_hash() {
        let verifier = format!("{}#", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    // ── code_verifier: full unreserved character set per RFC 7636 ───────

    #[test]
    fn test_validate_code_verifier_allows_tilde() {
        let verifier = format!("{}~", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_allows_dot() {
        let verifier = format!("{}.", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_allows_hyphen() {
        let verifier = format!("{}-", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_allows_underscore() {
        let verifier = format!("{}_", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_allows_digits() {
        let verifier = "0123456789012345678901234567890123456789012";
        assert_eq!(verifier.len(), 43);
        assert!(validate_code_verifier(verifier).is_ok());
    }

    // ── HostedRedeemRequest serde edge cases ────────────────────────────

    #[test]
    fn test_redeem_request_serialization_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let req = HostedRedeemRequest {
            code_verifier: "a".repeat(43),
        };
        let json = serde_json::to_string(&req)?;
        let deserialized: HostedRedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(deserialized.code_verifier, "a".repeat(43));
        Ok(())
    }

    #[test]
    fn test_redeem_request_json_field_name() -> Result<(), Box<dyn std::error::Error>> {
        let req = HostedRedeemRequest {
            code_verifier: "x".repeat(43),
        };
        let json = serde_json::to_string(&req)?;
        let val: serde_json::Value = serde_json::from_str(&json)?;
        assert!(
            val.get("code_verifier").is_some(),
            "field must be named 'code_verifier'"
        );
        Ok(())
    }

    // ── HostedRedeemResponse field names ────────────────────────────────

    #[test]
    fn test_redeem_response_json_field_names() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 100,
            expires_at: 200,
        };
        let json = serde_json::to_string(&response)?;
        let val: serde_json::Value = serde_json::from_str(&json)?;
        assert!(val.get("status").is_some());
        assert!(val.get("verified_at").is_some());
        assert!(val.get("expires_at").is_some());
        Ok(())
    }

    #[test]
    fn test_redeem_response_missing_status() {
        let json = r#"{"verified_at":1,"expires_at":2}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(result.is_err(), "missing 'status' should fail");
    }

    #[test]
    fn test_redeem_response_missing_verified_at() {
        let json = r#"{"status":"verified","expires_at":2}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(result.is_err(), "missing 'verified_at' should fail");
    }

    #[test]
    fn test_redeem_response_missing_expires_at() {
        let json = r#"{"status":"verified","verified_at":1}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(result.is_err(), "missing 'expires_at' should fail");
    }

    // ── HostedRedeemResponse clone and debug ────────────────────────────

    #[test]
    fn test_redeem_response_clone() {
        let original = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 42,
            expires_at: 99,
        };
        let cloned = original.clone();
        assert_eq!(cloned.status, "verified");
        assert_eq!(cloned.verified_at, 42);
        assert_eq!(cloned.expires_at, 99);
    }

    #[test]
    fn test_redeem_response_debug() {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 0,
            expires_at: 0,
        };
        let debug_str = format!("{:?}", response);
        assert!(debug_str.contains("HostedRedeemResponse"));
        assert!(debug_str.contains("verified"));
    }

    // ── HostedRedeemRequest clone redaction persistence ─────────────────

    #[test]
    fn test_redeem_request_clone_also_redacts_debug() {
        let req = HostedRedeemRequest {
            code_verifier: "super-secret-verifier-that-should-never-leak-out".to_string(),
        };
        let cloned = req.clone();
        let debug_str = format!("{:?}", cloned);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-secret"));
    }

    // ── PKCE SHA-256 computation and constant-time comparison ───────────

    /// Helper: produce a code_challenge (SHA-256 digest bytes) from a code_verifier,
    /// mirroring the logic used in handle_hosted_redeem.
    fn pkce_challenge_from_verifier(verifier: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(verifier.as_bytes()).to_vec()
    }

    #[test]
    fn test_pkce_sha256_digest_is_32_bytes() {
        let verifier = "a".repeat(43);
        let digest = pkce_challenge_from_verifier(&verifier);
        assert_eq!(digest.len(), 32, "SHA-256 digest must always be 32 bytes");
    }

    #[test]
    fn test_pkce_sha256_matching_verifier_passes_ct_eq() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs";
        let challenge = pkce_challenge_from_verifier(verifier);
        let computed = Sha256::digest(verifier.as_bytes());
        assert!(
            bool::from(ConstantTimeEq::ct_eq(
                computed.as_slice(),
                challenge.as_slice()
            )),
            "identical verifier must pass constant-time comparison"
        );
    }

    #[test]
    fn test_pkce_sha256_wrong_verifier_fails_ct_eq() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs";
        let challenge = pkce_challenge_from_verifier(verifier);
        let wrong_verifier = "ZBCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs";
        let computed = Sha256::digest(wrong_verifier.as_bytes());
        assert!(
            !bool::from(ConstantTimeEq::ct_eq(
                computed.as_slice(),
                challenge.as_slice()
            )),
            "different verifier must fail constant-time comparison"
        );
    }

    #[test]
    fn test_pkce_sha256_deterministic() {
        let verifier = "test-verifier-0123456789-abcdefghijklmnopqrstuvw";
        let d1 = pkce_challenge_from_verifier(verifier);
        let d2 = pkce_challenge_from_verifier(verifier);
        assert_eq!(d1, d2, "SHA-256 of the same input must be deterministic");
    }

    #[test]
    fn test_pkce_sha256_different_inputs_produce_different_digests() {
        let v1 = "a".repeat(43);
        let v2 = "b".repeat(43);
        let d1 = pkce_challenge_from_verifier(&v1);
        let d2 = pkce_challenge_from_verifier(&v2);
        assert_ne!(d1, d2, "different verifiers must produce different digests");
    }

    // ── validate_code_verifier error message content ────────────────────

    #[test]
    fn test_validate_code_verifier_empty_error_message() {
        let err = validate_code_verifier("").expect_err("empty should fail");
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad-request"),
            "empty verifier should produce bad-request error"
        );
    }

    #[test]
    fn test_validate_code_verifier_short_error_is_bad_request() {
        let err = validate_code_verifier("a").expect_err("too short should fail");
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad-request"),
            "short verifier should produce bad-request error"
        );
    }

    #[test]
    fn test_validate_code_verifier_long_error_is_bad_request() {
        let err = validate_code_verifier(&"z".repeat(129)).expect_err("too long should fail");
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad-request"),
            "long verifier should produce bad-request error"
        );
    }

    #[test]
    fn test_validate_code_verifier_invalid_char_error_is_bad_request() {
        let v = format!("{}!", "a".repeat(42));
        let err = validate_code_verifier(&v).expect_err("invalid char should fail");
        let msg = format!("{}", err);
        assert!(
            msg.contains("bad-request"),
            "invalid char verifier should produce bad-request error"
        );
    }

    // ── validate_code_verifier: boundary lengths ────────────────────────

    #[test]
    fn test_validate_code_verifier_length_42_rejected() {
        assert!(validate_code_verifier(&"a".repeat(42)).is_err());
    }

    #[test]
    fn test_validate_code_verifier_length_44_accepted() {
        assert!(validate_code_verifier(&"a".repeat(44)).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_length_127_accepted() {
        assert!(validate_code_verifier(&"a".repeat(127)).is_ok());
    }

    #[test]
    fn test_validate_code_verifier_length_1_rejected() {
        assert!(validate_code_verifier("a").is_err());
    }

    // ── validate_code_verifier: more invalid characters ─────────────────

    #[test]
    fn test_validate_code_verifier_rejects_backslash() {
        let verifier = format!("{}\\", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_percent() {
        let verifier = format!("{}%", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_ampersand() {
        let verifier = format!("{}&", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_colon() {
        let verifier = format!("{}:", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_semicolon() {
        let verifier = format!("{};", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_question_mark() {
        let verifier = format!("{}?", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_caret() {
        let verifier = format!("{}^", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_pipe() {
        let verifier = format!("{}|", "a".repeat(42));
        assert!(validate_code_verifier(&verifier).is_err());
    }

    #[test]
    fn test_validate_code_verifier_rejects_emoji() {
        // Multi-byte UTF-8 that should fail the ASCII check.
        let base = "a".repeat(42);
        // Emoji is multi-byte so len will push it over 43 chars but the check
        // should fail on the non-ASCII character regardless of length.
        let verifier = format!("{}\u{1F600}", base);
        assert!(validate_code_verifier(&verifier).is_err());
    }

    // ── validate_code_verifier: all-special-char verifier ───────────────

    #[test]
    fn test_validate_code_verifier_mixed_unreserved_at_boundaries() {
        // 43 chars using all four special unreserved chars mixed with alphanumerics.
        let verifier = "-._~aB0-._~aB0-._~aB0-._~aB0-._~aB0-._~aB0x";
        assert_eq!(verifier.len(), 43);
        assert!(validate_code_verifier(verifier).is_ok());
    }

    // ── HostedRedeemRequest: Drop trait zeroizes ────────────────────────

    #[test]
    fn test_redeem_request_zeroize_on_drop() {
        // We cannot directly observe zeroisation after drop, but we can verify
        // that the Zeroize trait is wired up by calling it manually on a clone.
        let mut req = HostedRedeemRequest {
            code_verifier: "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFG".to_string(),
        };
        req.code_verifier.zeroize();
        assert!(
            req.code_verifier.is_empty() || req.code_verifier.chars().all(|c| c == '\0'),
            "after zeroize, code_verifier should be cleared"
        );
    }

    // ── HostedRedeemResponse: JSON value types ──────────────────────────

    #[test]
    fn test_redeem_response_json_value_types() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 1700000000,
            expires_at: 1700000300,
        };
        let val: serde_json::Value = serde_json::to_value(&response)?;
        assert!(val["status"].is_string(), "status must be a string");
        assert!(val["verified_at"].is_u64(), "verified_at must be a u64");
        assert!(val["expires_at"].is_u64(), "expires_at must be a u64");
        Ok(())
    }

    #[test]
    fn test_redeem_response_zero_timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 0,
            expires_at: 0,
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: HostedRedeemResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.verified_at, 0);
        assert_eq!(deserialized.expires_at, 0);
        Ok(())
    }

    #[test]
    fn test_redeem_response_max_timestamps() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: u64::MAX,
            expires_at: u64::MAX,
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: HostedRedeemResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.verified_at, u64::MAX);
        assert_eq!(deserialized.expires_at, u64::MAX);
        Ok(())
    }

    #[test]
    fn test_redeem_response_status_can_be_arbitrary_string(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The struct does not enforce that status is "verified"; it just
        // serialises whatever string it holds.
        let response = HostedRedeemResponse {
            status: "pending".to_string(),
            verified_at: 1,
            expires_at: 2,
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: HostedRedeemResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.status, "pending");
        Ok(())
    }

    #[test]
    fn test_redeem_response_empty_status() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: String::new(),
            verified_at: 1,
            expires_at: 2,
        };
        let json = serde_json::to_string(&response)?;
        let deserialized: HostedRedeemResponse = serde_json::from_str(&json)?;
        assert_eq!(deserialized.status, "");
        Ok(())
    }

    // ── HostedRedeemRequest: null and empty code_verifier via JSON ──────

    #[test]
    fn test_redeem_request_null_code_verifier_rejected() {
        let json = r#"{"code_verifier":null}"#;
        let result = serde_json::from_str::<HostedRedeemRequest>(json);
        assert!(
            result.is_err(),
            "null code_verifier should fail deserialization"
        );
    }

    #[test]
    fn test_redeem_request_integer_code_verifier_rejected() {
        let json = r#"{"code_verifier":12345}"#;
        let result = serde_json::from_str::<HostedRedeemRequest>(json);
        assert!(
            result.is_err(),
            "integer code_verifier should fail deserialization"
        );
    }

    #[test]
    fn test_redeem_request_empty_string_code_verifier_deserializes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Empty string deserializes fine; validation is a separate step.
        let json = r#"{"code_verifier":""}"#;
        let req: HostedRedeemRequest = serde_json::from_str(json)?;
        assert_eq!(req.code_verifier, "");
        Ok(())
    }

    // ── HostedRedeemResponse: wrong field types rejected ────────────────

    #[test]
    fn test_redeem_response_string_verified_at_rejected() {
        let json = r#"{"status":"verified","verified_at":"not_a_number","expires_at":2}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(
            result.is_err(),
            "string verified_at should fail deserialization"
        );
    }

    #[test]
    fn test_redeem_response_string_expires_at_rejected() {
        let json = r#"{"status":"verified","verified_at":1,"expires_at":"not_a_number"}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(
            result.is_err(),
            "string expires_at should fail deserialization"
        );
    }

    #[test]
    fn test_redeem_response_negative_timestamp_rejected() {
        let json = r#"{"status":"verified","verified_at":-1,"expires_at":2}"#;
        let result = serde_json::from_str::<HostedRedeemResponse>(json);
        assert!(
            result.is_err(),
            "negative verified_at should fail for u64 field"
        );
    }

    // ── PKCE: known test vector ─────────────────────────────────────────

    #[test]
    fn test_pkce_sha256_known_vector() {
        // RFC 7636 Appendix B example: code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        // The challenge is base64url(SHA-256(ASCII(code_verifier)))
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let digest = pkce_challenge_from_verifier(verifier);
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest);
        assert_eq!(
            challenge_b64, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "SHA-256 of RFC 7636 Appendix B test vector must match"
        );
    }

    // ── PKCE: ct_eq with truncated challenge ────────────────────────────

    #[test]
    fn test_pkce_ct_eq_different_length_slices() {
        let verifier = "a".repeat(43);
        let digest = pkce_challenge_from_verifier(&verifier);
        let truncated = &digest[..16];
        // ConstantTimeEq on slices of different length should return false.
        // (In the real handler, code_challenge_bytes is always 32 bytes, but
        // we test the comparison primitive behaviour.)
        assert!(
            !bool::from(ConstantTimeEq::ct_eq(digest.as_slice(), truncated)),
            "ct_eq on different-length slices must return false"
        );
    }

    // ── DEFAULT_MAX_REDEEM_ATTEMPTS value ───────────────────────────────

    #[test]
    fn test_default_max_redeem_attempts_is_positive() {
        assert!(DEFAULT_MAX_REDEEM_ATTEMPTS > 0);
    }

    #[test]
    fn test_default_max_redeem_attempts_is_small() {
        // Should be a reasonable brute-force limit, not hundreds.
        assert!(DEFAULT_MAX_REDEEM_ATTEMPTS <= 10);
    }

    // ── HostedRedeemRequest: Debug never leaks verifier content ─────────

    #[test]
    fn test_redeem_request_debug_does_not_leak_any_verifier_chars() {
        let secret = "xY9_mN3~.aB-CDEFGHIJKLMNOPQRSTUVWXYZ0123456";
        let req = HostedRedeemRequest {
            code_verifier: secret.to_string(),
        };
        let debug_str = format!("{:?}", req);
        // None of the individual distinctive substrings should appear.
        assert!(!debug_str.contains("xY9_mN3"));
        assert!(!debug_str.contains("CDEFGHIJKLM"));
        assert!(!debug_str.contains(secret));
    }

    // ── HostedRedeemResponse: exact JSON shape ──────────────────────────

    #[test]
    fn test_redeem_response_has_exactly_three_fields() -> Result<(), Box<dyn std::error::Error>> {
        let response = HostedRedeemResponse {
            status: "verified".to_string(),
            verified_at: 1,
            expires_at: 2,
        };
        let val: serde_json::Value = serde_json::to_value(&response)?;
        let obj = val.as_object().ok_or("expected JSON object")?;
        assert_eq!(obj.len(), 3, "response must have exactly 3 fields");
        Ok(())
    }
}
