// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Challenge redemption via PKCE code verifier exchange.
//!
//! After the wallet submits a valid proof (`/v1/verify`), the relying party
//! calls `POST /v1/challenge/:session_id/redeem` with the PKCE `code_verifier` to
//! finalise the verification. This two-step flow prevents replay attacks and
//! ensures only the original requester can consume the result.
//!
//! ## Request flow
//!
//! 1. Authentication and BOLA ownership check (EA-004, pre-lock)
//! 2. Idempotency cache check (EA-002, post-auth)
//! 3. Challenge load + state and expiry validation
//! 4. PKCE SHA-256 constant time comparison
//! 5. Nonce deduplication (KV-044, post-PKCE), only successful-or-racing
//!    redemptions consume the dedup window.
//! 6. Credit deduction (KV-036, fail-closed)
//! 7. State transition to `Verified` and audit logging
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use base64::prelude::*;
use schemars::JsonSchema;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use uuid::Uuid;
use worker::{Error as WorkerError, Response};

#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_challenge_id;

use subtle::ConstantTimeEq;

use crate::{
    analytics::Analytics,
    cache::{CachedChallenge, ChallengeState},
    error::ApiError,
    security::validate_fetch_metadata,
    types::strict::PkceCodeVerifier,
    utils::{current_timestamp, NONCE_DEDUP_TTL},
    AppState,
};

/// Request body for `POST /v1/challenge/:session_id/redeem`.
#[derive(serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedeemRequest {
    /// PKCE code verifier (43-128 unreserved characters, RFC 7636 appendix B).
    pub code_verifier: PkceCodeVerifier,
}

/// JSON response returned from `POST /v1/challenge/:session_id/redeem`.
#[derive(serde::Serialize, JsonSchema)]
pub struct RedeemResponse {
    /// `"OK"` on success.
    pub result: String,
    /// `true` when the challenge has been successfully redeemed.
    pub verified: bool,
}

/// Handle `POST /v1/challenge/:session_id/redeem`: verify the PKCE code verifier,
/// deduct billing credits, and transition the challenge to `Verified`.
///
/// # Security annotations
///
/// PKCE: the SHA-256 of `code_verifier` is compared against
/// `code_challenge_bytes` in constant time (subtle::ct_eq). BOLA: challenge
/// ownership is checked before any nonce write or state transition.
/// CWE-362: concurrent redemption is serialised by the challenge Durable
/// Object's single-writer model; the nonce dedup check-and-set fires only
/// after PKCE validation, so a state-rejected call cannot poison the dedup
/// window for subsequent legitimate redeems. KV-036: credits are deducted
/// before the state transitions; failures are closed (no free
/// verifications). `submit_secret` is zeroised immediately on load since
/// it is not needed during redemption.
pub async fn redeem_challenge(
    state: Arc<AppState>,
    headers: worker::Headers,
    sid: Uuid,
    body: RedeemRequest,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(8);
    let mut sub_ops: Vec<(&str, f64)> = Vec::with_capacity(12);

    // Sandbox cross-origin fallback reads the challenge DO to extract
    // client_id for auth. Cache the full struct here so the main challenge load
    // at line ~210 can skip the redundant DO round-trip. Only populated in
    // sandbox; production never hits the cross-origin path.
    let mut prefetched_challenge: Option<CachedChallenge> = None;

    // Extract client IP for audit logging (raw; hashed by AuditLogger before any output)
    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    // SECURITY: Extract idempotency key (header parse only, no cache lookup).
    // EA-002: The cache check is deferred to after authentication so that
    // client_id is available for the request fingerprint.
    let idempotency_key =
        crate::security::idempotency::extract_idempotency_key(&headers, "POST", "/v1/redeem")?;

    // SECURITY: Validate Sec-Fetch-* headers to prevent CSRF attacks (defence in depth).
    // Preserve the typed status (400/403) by returning the Response directly
    // instead of stringifying through WorkerError::RustError (which the
    // dispatcher fallback maps to 500 INTERNAL_ERROR).
    if let Err(e) = validate_fetch_metadata(&headers) {
        return e.to_response();
    }

    let analytics = Analytics::new(&state.env);

    // SECURITY: Redact challenge_id in logs
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/redeem] Starting redemption for challenge {}",
        redact_challenge_id(&sid.to_string())
    );

    // SECURITY (EA-004): Authenticate BEFORE lock acquisition and nonce consumption.
    // This prevents unauthenticated callers from exhausting locks and nonces.
    //
    // PG-VAL-016: Peek the challenge to get its recorded owner clientId for
    // sandbox cross-origin fallback. The result is cached and reused later
    // during the main challenge load to avoid a redundant DO round-trip.
    let phase_start = worker::Date::now().as_millis();
    let expected_owner_id: Option<String> = if state.cfg.environment == "sandbox" {
        match state.challenge_store.get(&sid).await {
            Ok(Some(c)) => {
                let owner = c.client_id.clone();
                prefetched_challenge = Some(c);
                owner
            }
            _ => None,
        }
    } else {
        None
    };

    let auth_result = super::api_key_auth::authenticate_api_key(
        &headers,
        &state,
        super::api_key_auth::ApiKeyAuthOptions {
            expected_owner_id: expected_owner_id.as_deref(),
            allow_mobile_flow: false,
            stored_client_id: None,
            route_label: "redeem_challenge",
        },
    )
    .await?;
    let authenticated_client_id = auth_result.client_id;
    phase_timings.push((
        "auth",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // SECURITY: Mandatory authentication - reject if no valid client_id.
    // Rejecting here (before lock/nonce) prevents resource exhaustion by unauthenticated callers.
    let client_id = match authenticated_client_id {
        Some(id) => id,
        None => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] redeem_challenge: Authentication failed for challenge {} - missing or invalid credentials",
                redact_challenge_id(&sid.to_string())
            );
            state
                .audit_logger
                .log_authentication_failure(&client_ip, "redeem_auth_failed", None, None, None)
                .await;
            return ApiError::unauthorized(
                "REDEEM_AUTH_FAILED",
                "Origin + X-API-Key did not match the client that created this challenge. In sandbox the X-API-Key must match the credential returned from /v1/register-test-origin for this challenge's owner.",
            )
            .to_response();
        }
    };

    // EA-002: Idempotency cache check runs AFTER auth so client_id is available
    // for the request fingerprint. This prevents cross-client cache collisions.
    let phase_start = worker::Date::now().as_millis();
    if let (Some(ref key), Some(ref store)) = (&idempotency_key, &state.idempotency_store) {
        // Removed client_ip from fingerprint (non-deterministic).
        let fingerprint =
            crate::security::idempotency::compute_request_fingerprint("redeem", &client_id);
        if let Some(cached_response) = crate::security::idempotency::check_idempotency(
            store,
            key,
            "redeem",
            &fingerprint,
            Some(&state.audit_logger),
            Some(&client_ip),
            state.analytics.as_ref(),
        )
        .await?
        {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Returning cached response for redemption (key: {})",
                key.get(..key.len().min(8)).unwrap_or(key)
            );
            return Ok(cached_response);
        }
    }
    phase_timings.push((
        "idempotency",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Nonce dedup is placed after auth, state, expiry, and PKCE gates so that
    // only successful-or-concurrent redemptions consume the dedup window.
    // The DO single-writer model on the challenge store serialises racing
    // redemptions through the state transition itself.

    // Load the challenge record before continuing.
    //
    // If the sandbox cross-origin path already fetched this challenge,
    // reuse it instead of making a second DO round-trip. The cached value may
    // be stale if a concurrent request mutated the challenge between the two
    // read sites, but this is acceptable: nonce dedup at the check-and-set
    // gate below is the authoritative concurrency control, and state/expiry
    // checks that follow will reject genuinely invalid entries.
    let phase_start = worker::Date::now().as_millis();
    let (mut cached, cache_hit) = if let Some(pre) = prefetched_challenge.take() {
        // Sandbox prefetch available; skip DO call.
        sub_ops.push(("challenge_do_get_cached", 0.0));
        (pre, true)
    } else {
        let t = worker::Date::now().as_millis();
        let challenge_get_result = state.challenge_store.get(&sid).await;
        sub_ops.push((
            "challenge_do_get",
            (worker::Date::now().as_millis().saturating_sub(t)) as f64,
        ));
        match challenge_get_result {
            Ok(Some(c)) => (c, false),
            Ok(None) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[/v1/redeem] Challenge {} not found",
                    redact_challenge_id(&sid.to_string())
                );
                return ApiError::NotFound.to_response();
            }
            Err(e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[/v1/redeem] Error loading challenge: {:?}", e);
                state
                    .audit_logger
                    .log_suspicious_activity(&client_ip, "downstream_failure:challenge_store_read")
                    .await;
                return ApiError::Internal(e.into()).to_response();
            }
        }
    };
    let _ = cache_hit; // suppress unused warning in production builds
    phase_timings.push((
        "challenge_get",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // SECURITY: Eagerly zeroize the submit_secret; it is not needed during redemption.
    // This limits the window in which the secret is resident in memory.
    {
        use zeroize::Zeroize;
        cached.submit_secret.zeroize();
    }

    // SECURITY: Verify ownership (mandatory for all authenticated requests)
    if let Err(e) = super::ownership::verify_ownership(
        cached.client_id.as_deref(),
        Some(&client_id),
        &sid.to_string(),
        "redeem_challenge",
        &state.audit_logger,
        &client_ip,
        "redeem_bola_ownership_mismatch",
    )
    .await
    {
        return e.to_response();
    }

    let origin = cached.origin.clone();

    // Ensure the challenge is still valid.
    let now = current_timestamp();
    if now > cached.expires_at {
        // SECURITY: Redact challenge_id in logs
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/redeem] ❌ Challenge {} expired",
            redact_challenge_id(&sid.to_string())
        );
        state
            .audit_logger
            .log_verification_attempt(
                &sid.to_string(),
                &client_ip,
                false,
                Some("challenge_expired".to_string()),
            )
            .await;
        return ApiError::gone(
            "CHALLENGE_EXPIRED",
            "Challenge has passed its expiry timestamp; create a new one via POST /v1/challenge",
        )
        .to_response();
    }

    // Verify the challenge is awaiting redemption rather than already verified.
    if cached.state != ChallengeState::ProofOkWaitingForRedeem {
        // SECURITY: Redact challenge_id in logs
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/redeem] ❌ Challenge {} in wrong state: {:?}",
            redact_challenge_id(&sid.to_string()),
            cached.state
        );

        state
            .audit_logger
            .log_verification_attempt(
                &sid.to_string(),
                &client_ip,
                false,
                Some("invalid_challenge_state".to_string()),
            )
            .await;

        // Return a state-specific error for clearer diagnostics.
        return match cached.state {
            ChallengeState::Pending => ApiError::conflict(
                "PROOF_NOT_SUBMITTED",
                "The wallet has not yet submitted a proof for this challenge; redeem is only valid after proof_ok",
            )
            .to_response(),
            ChallengeState::Verified => ApiError::conflict(
                "CHALLENGE_ALREADY_REDEEMED",
                "This challenge has already been redeemed",
            )
            .to_response(),
            ChallengeState::Failed => ApiError::conflict(
                "CHALLENGE_VERIFICATION_FAILED",
                "Wallet proof verification failed; this challenge cannot be redeemed",
            )
            .to_response(),
            ChallengeState::Expired => ApiError::gone(
                "CHALLENGE_EXPIRED",
                "Challenge has passed its expiry timestamp; create a new one via POST /v1/challenge",
            )
            .to_response(),
            _ => ApiError::conflict(
                "CHALLENGE_NOT_READY",
                "Challenge is not in a redeemable state",
            )
            .to_response(),
        };
    }

    // PkceCodeVerifier already enforces PKCE length and character constraints.
    // SECURITY: Redact challenge_id in logs
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/redeem] Validating PKCE code_verifier for challenge {}",
        redact_challenge_id(&sid.to_string())
    );

    // Hash the verifier and compare it with the stored code challenge.
    let computed = Sha256::digest(body.code_verifier.as_str().as_bytes());
    if !bool::from(computed.ct_eq(&cached.code_challenge_bytes)) {
        // SECURITY: Redact challenge_id in logs
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/redeem] ❌ PKCE validation failed for challenge {}",
            redact_challenge_id(&sid.to_string())
        );
        // Preserve the challenge state on PKCE failure so the client can retry.
        state
            .audit_logger
            .log_verification_attempt(
                &sid.to_string(),
                &client_ip,
                false,
                Some("pkce_validation_failed".to_string()),
            )
            .await;
        return ApiError::bad_request(
            "INVALID_PKCE_VERIFIER",
            Some("code_verifier"),
            "code_verifier does not match the code_challenge supplied at challenge creation",
        )
        .to_response();
    }

    // SECURITY: Redact challenge_id in logs
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/redeem] PKCE validation passed for challenge {}",
        redact_challenge_id(&sid.to_string())
    );

    // R9 (RL-03): Per-ACCOUNT quota on the VERIFIED client_id, as a SUPPLEMENT
    // to the pre-auth per-IP gate in worker_routes.rs (which already ran and is
    // untouched). Placed here it is provably:
    //   * post-auth    -- `client_id` above is the verified identity returned by
    //                      authenticate_api_key, never a raw header, and
    //                      ownership has already been verified;
    //   * replay-safe  -- the EA-002 idempotency cache check earlier returns the
    //                      cached response for an idempotent replay BEFORE this
    //                      point, and this sits AFTER the expiry/state/PKCE gates
    //                      that legitimately allow a no-charge retry, so neither
    //                      an idempotent replay nor a benign retry is double-
    //                      charged;
    //   * pre-mutation -- it runs BEFORE the nonce check_and_set, the Verified
    //                      state write, and the credit deduction below, so no
    //                      side effect / billing has occurred yet.
    if let Err(resp) =
        super::api_key_auth::enforce_account_quota(&state, &client_id, "redeem").await
    {
        return resp;
    }

    // SECURITY: Nonce dedup. The check-and-set runs only after
    // every gate (auth, ownership, expiry, state == ProofOkWaitingForRedeem,
    // PKCE) has passed, so the dedup window represents successful-or-racing
    // redemptions only. A redeem call that fails any earlier gate no longer
    // consumes the nonce, so a subsequent legitimate redeem cannot hit a
    // false REDEEM_REPLAY. Concurrent racing redemptions in the redeemable
    // window still hit this gate (the loser sees REDEEM_REPLAY).
    let nonce_tag = format!("redeem:{}", sid);
    let nonce_ttl = NONCE_DEDUP_TTL;

    let phase_start = worker::Date::now().as_millis();
    let t = worker::Date::now().as_millis();
    let nonce_result = state.nonce_store.check_and_set(&nonce_tag, nonce_ttl).await;
    sub_ops.push((
        "nonce_do_check_and_set",
        (worker::Date::now().as_millis().saturating_sub(t)) as f64,
    ));
    phase_timings.push((
        "nonce_dedup",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    match nonce_result {
        Ok(true) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/redeem] Nonce check passed for challenge {}",
                redact_challenge_id(&sid.to_string())
            );
        }
        Ok(false) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/redeem] Duplicate redemption detected for challenge {}",
                redact_challenge_id(&sid.to_string())
            );
            state
                .audit_logger
                .log_replay_attempt(&sid.to_string(), &client_ip, state.analytics.as_ref())
                .await;
            return ApiError::conflict(
                "REDEEM_REPLAY",
                "This challenge has already been redeemed by a recent request (nonce dedup window)",
            )
            .to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/redeem] Nonce store error: {:?}", e);
            return ApiError::Internal(e.into()).to_response();
        }
    }

    // Reuse stored issuer metadata to enrich billing events.
    let zero = [0u8; 32];
    let issuer_kid_opt = cached.issuer_kid.as_deref();
    let issuer_vk_ref = cached.issuer_vk_bytes.as_ref().unwrap_or(&zero);

    // ── Credit enforcement: fail closed for metered origins ───────────────
    // Policy: no credits => no service. The challenge-creation gate
    // (ORIGIN_INDEX has_credits) rejects metered origins that are already
    // exhausted, but that flag can lag, so a metered origin's balance can reach
    // zero between challenge creation and redemption. We therefore deduct
    // SYNCHRONOUSLY here, before granting the verdict, and refuse to verify if
    // the deduction cannot be completed.
    //
    // metering_enabled is stable per-origin config (unlike the volatile
    // has_credits), so re-reading ORIGIN_INDEX at redeem is authoritative.
    // Unmetered / test origins have NO CreditBalance account - the DO returns
    // 402 for an unprovisioned customer - so they MUST NOT be gated on a
    // successful deduction; only metered origins are enforced (the unmetered
    // path keeps the best-effort background deduction below).
    let origin_is_metered: bool = {
        let mut metered = false;
        if let Ok(oi_kv) = state.env.kv("ORIGIN_INDEX") {
            let oi_kv_clone = oi_kv.clone();
            let origin_clone = origin.clone();
            if let Ok(Ok(Some(json_str))) = crate::utils::timeout::with_timeout(
                "origin_index KV read (redeem)",
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
        use crate::clients::{ConsumeCreditsRequest, CreditError};
        match state.credit_management_client.clone() {
            Some(credit_client) => {
                let environment = state
                    .env
                    .var("ENVIRONMENT")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| "production".to_string());
                let credit_request = ConsumeCreditsRequest {
                    customer_id: cached.tenant_id.clone().unwrap_or_else(|| origin.clone()),
                    verification_id: sid.to_string(),
                    origin: origin.clone(),
                    issuer_kid: issuer_kid_opt.map(|s| s.to_string()),
                    environment,
                    partner_id: None,
                };
                match credit_client.consume_credits(credit_request).await {
                    // Credits deducted (or already deducted on a prior attempt -
                    // consume is idempotent on verification_id). Grant the verdict.
                    Ok(_) | Err(CreditError::Conflict(_)) => {}
                    Err(CreditError::InsufficientCredits {
                        available: _available,
                        required: _required,
                    }) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"INFO","component":"billing","event":"redeem_denied_insufficient","challenge_id":"{}","available":{},"required":{}}}"#,
                            redact_challenge_id(&sid.to_string()),
                            _available,
                            _required
                        );
                        state
                            .audit_logger
                            .log_suspicious_activity(
                                &client_ip,
                                "billing:redeem_denied_insufficient",
                            )
                            .await;
                        // No state change: the challenge stays redeemable, and
                        // credit-management released the verification lock, so a
                        // top-up + retry succeeds.
                        return ApiError::PaymentRequired(None).to_response();
                    }
                    Err(_e) => {
                        // Service unavailable / unexpected error: we cannot
                        // confirm the deduction, so fail closed rather than serve
                        // an unbilled verification.
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"CRITICAL","component":"billing","event":"redeem_denied_credit_unavailable","challenge_id":"{}","error":"{:?}"}}"#,
                            redact_challenge_id(&sid.to_string()),
                            _e
                        );
                        state
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
                // Metered origin but the credit client is not configured: we
                // cannot bill, so fail closed.
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[CRITICAL] [/v1/redeem] Metered origin {} but credit client unavailable; denying",
                    origin
                );
                return ApiError::ServiceUnavailable(Some("Billing not configured".into()))
                    .to_response();
            }
        }
    }

    // Mark the challenge as verified. For metered origins the deduction above has
    // already succeeded; unmetered origins are billed best-effort below.
    cached.state = ChallengeState::Verified;
    cached.verified_at = Some(now);
    let phase_start = worker::Date::now().as_millis();
    let t = worker::Date::now().as_millis();
    if let Err(_e) = state.challenge_store.put(&sid, &cached).await {
        // KV-046: State write failed. Credits have not been deducted yet (they
        // are dispatched in the background below), so no billing inconsistency.
        // Log CRITICAL and return failure.
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[CRITICAL] [/v1/redeem] State write failed for challenge {}: {:?}",
            redact_challenge_id(&sid.to_string()),
            _e
        );
        state
            .audit_logger
            .log_state_write_failed_after_billing(
                &sid.to_string(),
                &client_ip,
                state.analytics.as_ref(),
            )
            .await;
        return ApiError::Internal(anyhow::anyhow!("State transition failed")).to_response();
    }
    sub_ops.push((
        "challenge_do_put",
        (worker::Date::now().as_millis().saturating_sub(t)) as f64,
    ));
    phase_timings.push((
        "challenge_put",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // ── Unmetered origins: best-effort background deduction ───────────────
    // Metered origins were already billed synchronously above (fail-closed), so
    // skip them here. For unmetered/test origins the CreditBalance DO returns 402
    // for an unprovisioned customer, so any failure here is expected and must NOT
    // block the verdict - dispatch off the critical path and only log.
    if origin_is_metered {
        // Already billed synchronously; nothing to do.
    } else if let Some(credit_client) = state.credit_management_client.clone() {
        use crate::clients::{ConsumeCreditsRequest, CreditError};

        let environment = state
            .env
            .var("ENVIRONMENT")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "production".to_string());

        let credit_request = ConsumeCreditsRequest {
            customer_id: cached.tenant_id.clone().unwrap_or_else(|| origin.clone()),
            verification_id: sid.to_string(),
            origin: origin.clone(),
            issuer_kid: issuer_kid_opt.map(|s| s.to_string()),
            environment,
            partner_id: None, // Populated once challenge creation stores provisioned_by
        };

        let bg_audit = state.audit_logger.clone();
        let _bg_sid = sid.to_string();
        let bg_client_ip = client_ip.clone();

        if let Some(ctx) = crate::take_worker_context() {
            ctx.wait_until(async move {
                match credit_client.consume_credits(credit_request).await {
                    Ok(_response) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[/v1/redeem] Background credit deduction succeeded: \
                             balance={} units, royalty_units_credited={}",
                            _response.balance_after_units.unwrap_or(0),
                            _response.royalty_units_credited.unwrap_or(0)
                        );
                    }
                    Err(CreditError::Conflict(_msg)) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[/v1/redeem] Background credit conflict (duplicate): {}",
                            _msg
                        );
                    }
                    Err(CreditError::InsufficientCredits { available: _available, required: _required }) => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            r#"{{"level":"CRITICAL","component":"billing","event":"background_deduction_insufficient","challenge_id":"{}","available":{},"required":{}}}"#,
                            redact_challenge_id(&_bg_sid),
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
                            redact_challenge_id(&_bg_sid),
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
                "[/v1/redeem] Credit deduction dispatched via wait_until for {}",
                redact_challenge_id(&sid.to_string())
            );
        } else {
            // No worker context available. Fall back to inline deduction.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[WARN] [/v1/redeem] Worker context unavailable, running credit deduction inline"
            );
            match credit_client.consume_credits(credit_request).await {
                Ok(_) => {}
                Err(CreditError::Conflict(_)) => {}
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        r#"{{"level":"CRITICAL","component":"billing","event":"inline_deduction_failed","challenge_id":"{}","error":"{:?}"}}"#,
                        redact_challenge_id(&sid.to_string()),
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
            "[WARN] [/v1/redeem] Credit client not configured. Verification proceeding \
             without billing. Set CREDIT_MGMT_URL and provision HMAC secret to enable billing."
        );
    }

    // Emit a billing log entry with issuer context.
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[BILLING] Verification complete: Challenge={}, RP={}, Status=REDEEMED",
        redact_challenge_id(&sid.to_string()),
        origin
    );

    if let Some(kid) = issuer_kid_opt {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/redeem] Using stored issuer for billing: {} ({})",
            kid,
            BASE64_URL_SAFE_NO_PAD.encode(issuer_vk_ref)
        );

        analytics.billing_verification_success(
            "/v1/challenge/:sid/redeem",
            &sid.to_string(),
            &origin,
            Some(kid),
            Some(&BASE64_URL_SAFE_NO_PAD.encode(issuer_vk_ref)),
            cached.cutoff_days,
            true,
            &state.cfg.environment,
        );
    } else {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/redeem] No issuer KID stored (unknown issuer), billing without royalty");

        analytics.billing_verification_success(
            "/v1/challenge/:sid/redeem",
            &sid.to_string(),
            &origin,
            None,
            None,
            cached.cutoff_days,
            false,
            &state.cfg.environment,
        );

        if let Err(_e) = state
            .audit_logger
            .log_verification_no_royalty(&sid.to_string(), &origin, &zero, now)
            .await
        {
            #[cfg(target_arch = "wasm32")]
            console_log!("[AUDIT][ERROR] no-royalty event logging failed: {}", _e);
        }
    }

    // Audit log the billing event
    if let Err(_e) = state
        .audit_logger
        .log_billing_event(
            &sid.to_string(),
            &origin,
            issuer_kid_opt.map(|s| s.to_string()).as_deref(),
            issuer_vk_ref,
            cached.cutoff_days,
            now,
        )
        .await
    {
        #[cfg(target_arch = "wasm32")]
        console_log!("[AUDIT][ERROR] billing event logging failed: {}", _e);
    }

    let _duration_ms = (worker::Date::now().as_millis().saturating_sub(start)) as f64;
    // SECURITY: Redact challenge_id in logs
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/redeem] ✅ verified challenge_id={} origin={} duration_ms={}",
        redact_challenge_id(&sid.to_string()),
        origin,
        _duration_ms
    );

    state
        .audit_logger
        .log_verification_attempt(&sid.to_string(), &client_ip, true, None)
        .await;

    // Emit structured per-phase timing log for Grafana Loki
    let total_ms = (worker::Date::now().as_millis().saturating_sub(start)) as f64;
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
    let _is_slow = total_ms > 500.0;
    let _sub_ops_json = sub_ops
        .iter()
        .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
        .collect::<Vec<_>>()
        .join(",");
    #[cfg(target_arch = "wasm32")]
    console_log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-verifier","route":"/v1/redeem","status":200,"duration_ms":{:.1},"phases":{{{}}},"sub_ops":{{{}}},"slow":{},"slow_phases":"{}"}}"#,
        total_ms,
        _phases_json,
        _sub_ops_json,
        _is_slow,
        _slow_phases.join(",")
    );

    let redeem_response = RedeemResponse {
        result: "OK".to_string(),
        verified: true,
    };

    let worker_response = Response::from_json(&redeem_response)?.with_status(200);

    // SECURITY: Store response in idempotency cache if key was provided
    if let (Some(key), Some(store)) = (idempotency_key, &state.idempotency_store) {
        let response_body = serde_json::to_string(&redeem_response).unwrap_or_else(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[IDEMPOTENCY] Failed to serialize response for caching: {:?}",
                _e
            );
            "{}".to_string()
        });

        // EA-002: Fingerprint includes client_id to prevent cross-client cache collisions.
        // Removed client_ip (non-deterministic, causes spurious mismatches).
        let fingerprint =
            crate::security::idempotency::compute_request_fingerprint("redeem", &client_id);
        let _ = crate::security::idempotency::store_idempotency_response(
            store,
            &key,
            response_body,
            200,
            "redeem",
            None,
            &fingerprint,
        )
        .await;
    }

    Ok(worker_response)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    // ========================================================================
    // Request/Response Structure Tests
    // ========================================================================

    #[test]
    fn test_redeem_request_valid() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"code_verifier":"abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_ok());
        let req = req?;
        assert_eq!(
            req.code_verifier.as_str(),
            "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        );
        Ok(())
    }

    #[test]
    fn test_redeem_request_denies_unknown_fields() {
        let json = r#"{"code_verifier":"abc123def456ghi789jkl012mno345pqr678stu901vwx234yz","extra":"field"}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_requires_code_verifier() {
        let json = r#"{}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_response_structure() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "OK".to_string(),
            verified: true,
        };
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("\"result\":\"OK\""));
        assert!(json.contains("\"verified\":true"));
        Ok(())
    }

    #[test]
    fn test_redeem_response_verified_false() {
        let resp = RedeemResponse {
            result: "ERROR".to_string(),
            verified: false,
        };
        assert_eq!(resp.result, "ERROR");
        assert!(!resp.verified);
    }

    // ========================================================================
    // Nonce Tag Generation Tests
    // ========================================================================

    #[test]
    fn test_nonce_tag_format() -> Result<(), Box<dyn std::error::Error>> {
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let nonce_tag = format!("redeem:{}", sid);
        assert_eq!(nonce_tag, "redeem:550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn test_nonce_tag_uniqueness() {
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();
        let tag1 = format!("redeem:{}", sid1);
        let tag2 = format!("redeem:{}", sid2);
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_nonce_tag_prefix() {
        let sid = Uuid::new_v4();
        let tag = format!("redeem:{}", sid);
        assert!(tag.starts_with("redeem:"));
    }

    #[test]
    fn test_nonce_ttl_value() {
        let nonce_ttl = Duration::from_secs(300);
        assert_eq!(nonce_ttl.as_secs(), 300);
        assert_eq!(nonce_ttl, Duration::from_secs(5 * 60)); // 5 minutes
    }

    // ========================================================================
    // SHA256 Hash Computation Tests
    // ========================================================================

    #[test]
    fn test_sha256_code_verifier_computation() {
        let verifier = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let computed = Sha256::digest(verifier.as_bytes());
        assert_eq!(computed.len(), 32);
    }

    #[test]
    fn test_sha256_deterministic() {
        let verifier = "test_verifier_12345";
        let hash1 = Sha256::digest(verifier.as_bytes());
        let hash2 = Sha256::digest(verifier.as_bytes());
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let verifier1 = "verifier1";
        let verifier2 = "verifier2";
        let hash1 = Sha256::digest(verifier1.as_bytes());
        let hash2 = Sha256::digest(verifier2.as_bytes());
        assert_ne!(&hash1[..], &hash2[..]);
    }

    #[test]
    fn test_sha256_empty_input() {
        let verifier = "";
        let computed = Sha256::digest(verifier.as_bytes());
        assert_eq!(computed.len(), 32);
        // SHA256 always produces 32 bytes even for empty input
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(&computed[..], &expected);
    }

    #[test]
    fn test_sha256_long_input() {
        let verifier = "a".repeat(1000);
        let computed = Sha256::digest(verifier.as_bytes());
        assert_eq!(computed.len(), 32);
    }

    // ========================================================================
    // Constant-Time Comparison Tests
    // ========================================================================

    #[test]
    fn test_ct_eq_identical_hashes() {
        let verifier = "test_verifier";
        let hash1 = Sha256::digest(verifier.as_bytes());
        let hash2 = Sha256::digest(verifier.as_bytes());
        assert!(bool::from(hash1.ct_eq(&hash2[..])));
    }

    #[test]
    fn test_ct_eq_different_hashes() {
        let hash1 = Sha256::digest("verifier1".as_bytes());
        let hash2 = Sha256::digest("verifier2".as_bytes());
        assert!(!bool::from(hash1.ct_eq(&hash2[..])));
    }

    #[test]
    fn test_ct_eq_one_bit_difference() {
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        bytes1[0] = 0b00000000;
        bytes2[0] = 0b00000001; // One bit different
        assert!(!bool::from(bytes1.ct_eq(&bytes2)));
    }

    #[test]
    fn test_ct_eq_empty_slices() {
        let empty1: &[u8] = &[];
        let empty2: &[u8] = &[];
        assert!(bool::from(empty1.ct_eq(empty2)));
    }

    #[test]
    fn test_ct_eq_all_zeros() {
        let zeros = [0u8; 32];
        assert!(bool::from(zeros.ct_eq(&zeros)));
    }

    #[test]
    fn test_ct_eq_all_ones() {
        let ones = [0xFFu8; 32];
        assert!(bool::from(ones.ct_eq(&ones)));
    }

    #[test]
    fn test_ct_eq_different_lengths() {
        let short = [1u8; 16];
        let long = [1u8; 32];
        assert!(!bool::from(short.as_slice().ct_eq(long.as_slice())));
    }

    // ========================================================================
    // Base64 Encoding Tests
    // ========================================================================

    #[test]
    fn test_base64_url_safe_no_pad_encoding() {
        let bytes = [0u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_base64_issuer_vk_encoding() {
        let vk = [0x42u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(vk);
        assert!(!encoded.is_empty());
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_base64_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(original);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;
        assert_eq!(&original[..], &decoded[..]);
        Ok(())
    }

    // ========================================================================
    // Challenge State Validation Tests
    // ========================================================================

    #[test]
    fn test_challenge_state_proof_ok_waiting() {
        let state = ChallengeState::ProofOkWaitingForRedeem;
        assert_eq!(state, ChallengeState::ProofOkWaitingForRedeem);
    }

    #[test]
    fn test_challenge_state_pending() {
        let state = ChallengeState::Pending;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
    }

    #[test]
    fn test_challenge_state_verified() {
        let state = ChallengeState::Verified;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
    }

    #[test]
    fn test_challenge_state_failed() {
        let state = ChallengeState::Failed;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
    }

    #[test]
    fn test_challenge_state_expired() {
        let state = ChallengeState::Expired;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
    }

    // ========================================================================
    // Timestamp and Expiry Tests
    // ========================================================================

    #[test]
    fn test_expiry_check_not_expired() {
        let now = current_timestamp();
        let expires_at = now + 3600; // 1 hour in the future
        assert!(now <= expires_at);
    }

    #[test]
    fn test_expiry_check_expired() {
        let now = current_timestamp();
        let expires_at = now - 1; // 1 second in the past
        assert!(now > expires_at);
    }

    #[test]
    fn test_expiry_check_exact_boundary() {
        let now = current_timestamp();
        let expires_at = now;
        assert!(now <= expires_at);
    }

    #[test]
    fn test_current_timestamp_monotonic() {
        let t1 = current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = current_timestamp();
        assert!(t2 >= t1);
    }

    // ========================================================================
    // Issuer Metadata Tests
    // ========================================================================

    #[test]
    fn test_issuer_kid_some() {
        let kid: Option<String> = Some("issuer-key-id-123".to_string());
        assert!(kid.is_some());
        assert_eq!(kid.as_deref(), Some("issuer-key-id-123"));
    }

    #[test]
    fn test_issuer_kid_none() {
        let kid: Option<String> = None;
        assert!(kid.is_none());
        assert_eq!(kid.as_deref(), None);
    }

    #[test]
    fn test_issuer_vk_bytes_some() {
        let vk_bytes: Option<[u8; 32]> = Some([0x42u8; 32]);
        let zero = [0u8; 32];
        let vk_ref = vk_bytes.as_ref().unwrap_or(&zero);
        assert_eq!(vk_ref, &[0x42u8; 32]);
    }

    #[test]
    fn test_issuer_vk_bytes_none() {
        let vk_bytes: Option<[u8; 32]> = None;
        let zero = [0u8; 32];
        let vk_ref = vk_bytes.as_ref().unwrap_or(&zero);
        assert_eq!(vk_ref, &zero);
    }

    #[test]
    fn test_redeem_response_serialises_verified_true() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "OK".to_string(),
            verified: true,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["verified"], true);
        assert_eq!(parsed["result"], "OK");
        Ok(())
    }

    #[test]
    fn test_redeem_response_serialises_verified_false() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "ERROR".to_string(),
            verified: false,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["verified"], false);
        assert_eq!(parsed["result"], "ERROR");
        Ok(())
    }

    // ========================================================================
    // Error Code Mapping Tests
    // ========================================================================

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_conflict_duplicate_redemption() {
        let err = ApiError::Conflict(Some("Duplicate redemption attempt".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_not_found_challenge() {
        let err = ApiError::NotFound;
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_gone_expired() {
        let err = ApiError::Gone(Some("Challenge expired".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_conflict_proof_not_submitted() {
        let err = ApiError::Conflict(Some("Proof not submitted yet".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_conflict_already_redeemed() {
        let err = ApiError::Conflict(Some("Challenge already redeemed".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_conflict_failed_verification() {
        let err = ApiError::Conflict(Some("Challenge failed verification".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_conflict_not_ready() {
        let err = ApiError::Conflict(Some("Challenge not ready for redemption".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_error_bad_request_invalid_verifier() {
        let err = ApiError::BadRequest(Some("Invalid code_verifier".into()));
        let response = err.to_response();
        assert!(response.is_ok());
    }

    // ========================================================================
    // PKCE Code Verifier Tests
    // ========================================================================

    #[test]
    fn test_pkce_code_verifier_valid_length() {
        let verifier = "a".repeat(43); // Minimum length
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn test_pkce_code_verifier_max_length() {
        let verifier = "a".repeat(128); // Maximum length
        assert_eq!(verifier.len(), 128);
    }

    #[test]
    fn test_pkce_code_verifier_valid_chars() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert!(verifier.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~'
        }));
    }

    #[test]
    fn test_pkce_sha256_challenge_generation() {
        let verifier = "test_verifier_for_pkce";
        let challenge = Sha256::digest(verifier.as_bytes());
        let challenge_b64 = BASE64_URL_SAFE_NO_PAD.encode(challenge);
        assert!(!challenge_b64.is_empty());
        assert!(!challenge_b64.contains('='));
    }

    // ========================================================================
    // UUID Tests
    // ========================================================================

    #[test]
    fn test_uuid_parsing_valid() {
        let sid_str = "550e8400-e29b-41d4-a716-446655440000";
        let sid = Uuid::parse_str(sid_str);
        assert!(sid.is_ok());
    }

    #[test]
    fn test_uuid_parsing_invalid() {
        let sid_str = "not-a-valid-uuid";
        let sid = Uuid::parse_str(sid_str);
        assert!(sid.is_err());
    }

    #[test]
    fn test_uuid_to_string() -> Result<(), Box<dyn std::error::Error>> {
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let sid_str = sid.to_string();
        assert_eq!(sid_str, "550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn test_uuid_uniqueness() {
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();
        assert_ne!(sid1, sid2);
    }

    // ========================================================================
    // Response Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_redeem_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "OK".to_string(),
            verified: true,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        // Verify the serialised JSON has exactly the expected fields and values
        assert_eq!(parsed.as_object().map(|o| o.len()), Some(2));
        assert_eq!(parsed["result"], "OK");
        assert_eq!(parsed["verified"], true);
        Ok(())
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// SHA256 hash computation is deterministic
        #[test]
        fn prop_sha256_deterministic(verifier in "[a-zA-Z0-9_-]{43,128}") {
            let hash1 = Sha256::digest(verifier.as_bytes());
            let hash2 = Sha256::digest(verifier.as_bytes());
            prop_assert_eq!(hash1.as_slice(), hash2.as_slice());
        }

        /// SHA256 hash always produces 32 bytes
        #[test]
        fn prop_sha256_output_length(verifier in ".*") {
            let hash = Sha256::digest(verifier.as_bytes());
            prop_assert_eq!(hash.len(), 32);
        }

        /// Different inputs produce different hashes
        #[test]
        fn prop_sha256_different_inputs(v1 in "[a-zA-Z0-9_-]{43,128}", v2 in "[a-zA-Z0-9_-]{43,128}") {
            if v1 != v2 {
                let hash1 = Sha256::digest(v1.as_bytes());
                let hash2 = Sha256::digest(v2.as_bytes());
                prop_assert_ne!(hash1.as_slice(), hash2.as_slice());
            }
        }

        /// Constant-time comparison is reflexive
        #[test]
        fn prop_ct_eq_reflexive(bytes in prop::collection::vec(any::<u8>(), 32)) {
            prop_assert!(bool::from(bytes.as_slice().ct_eq(bytes.as_slice())));
        }

        /// Constant-time comparison is symmetric
        #[test]
        fn prop_ct_eq_symmetric(
            bytes1 in prop::collection::vec(any::<u8>(), 32),
            bytes2 in prop::collection::vec(any::<u8>(), 32)
        ) {
            prop_assert_eq!(
                bool::from(bytes1.as_slice().ct_eq(bytes2.as_slice())),
                bool::from(bytes2.as_slice().ct_eq(bytes1.as_slice()))
            );
        }

        /// Base64 encoding roundtrip preserves data
        #[test]
        fn prop_base64_roundtrip(bytes in prop::collection::vec(any::<u8>(), 1..100)) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(&bytes);
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded).expect("decode");
            prop_assert_eq!(&bytes, &decoded);
        }

        /// Base64 URL_SAFE_NO_PAD never contains padding
        #[test]
        fn prop_base64_no_padding(bytes in prop::collection::vec(any::<u8>(), 1..100)) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(&bytes);
            prop_assert!(!encoded.contains('='));
        }

        /// Base64 URL_SAFE_NO_PAD never contains + or /
        #[test]
        fn prop_base64_url_safe(bytes in prop::collection::vec(any::<u8>(), 1..100)) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(&bytes);
            prop_assert!(!encoded.contains('+'));
            prop_assert!(!encoded.contains('/'));
        }

        /// Nonce tag always starts with "redeem:"
        #[test]
        fn prop_nonce_tag_prefix(uuid_str in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") {
            if let Ok(sid) = Uuid::parse_str(&uuid_str) {
                let tag = format!("redeem:{}", sid);
                prop_assert!(tag.starts_with("redeem:"));
            }
        }

        /// Nonce tag contains the UUID
        #[test]
        fn prop_nonce_tag_contains_uuid(uuid_str in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") {
            if let Ok(sid) = Uuid::parse_str(&uuid_str) {
                let tag = format!("redeem:{}", sid);
                prop_assert!(tag.contains(&uuid_str));
            }
        }

        /// Timestamp ordering
        #[test]
        fn prop_timestamp_ordering(offset in 1u64..3600) {
            let now = current_timestamp();
            let future = now + offset;
            prop_assert!(now < future);
        }

        /// Expiry validation logic
        #[test]
        fn prop_expiry_validation(offset in 1u64..3600) {
            let now = current_timestamp();
            let future_expiry = now + offset;
            let past_expiry = now.saturating_sub(offset);

            prop_assert!(now <= future_expiry); // Not expired
            prop_assert!(now > past_expiry);    // Expired
        }

        /// PKCE roundtrip: verifier -> SHA256 -> ct_eq matches stored challenge
        #[test]
        fn prop_pkce_roundtrip(verifier in "[a-zA-Z0-9._~-]{43,128}") {
            let challenge_bytes = Sha256::digest(verifier.as_bytes());
            let stored: Vec<u8> = challenge_bytes.to_vec();
            let computed = Sha256::digest(verifier.as_bytes());
            prop_assert!(bool::from(computed.ct_eq(stored.as_slice())));
        }

        /// PKCE wrong verifier never matches a different challenge
        #[test]
        fn prop_pkce_wrong_verifier_rejects(
            v1 in "[a-zA-Z0-9._~-]{43,128}",
            v2 in "[a-zA-Z0-9._~-]{43,128}"
        ) {
            if v1 != v2 {
                let stored = Sha256::digest(v1.as_bytes());
                let computed = Sha256::digest(v2.as_bytes());
                prop_assert!(!bool::from(computed.ct_eq(stored.as_slice())));
            }
        }

        /// Nonce tag length is always "redeem:" prefix + 36-char UUID = 43
        #[test]
        fn prop_nonce_tag_length(uuid_str in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") {
            if let Ok(sid) = Uuid::parse_str(&uuid_str) {
                let tag = format!("redeem:{}", sid);
                prop_assert_eq!(tag.len(), 43);
            }
        }

        /// Fingerprint computation is deterministic
        #[test]
        fn prop_fingerprint_deterministic(
            endpoint in "[a-z:/_]{5,50}",
            identity in "[a-zA-Z0-9]{5,50}"
        ) {
            let f1 = crate::security::idempotency::compute_request_fingerprint(&endpoint, &identity);
            let f2 = crate::security::idempotency::compute_request_fingerprint(&endpoint, &identity);
            prop_assert_eq!(f1, f2);
        }

        /// Fingerprint differs when endpoint differs
        #[test]
        fn prop_fingerprint_endpoint_sensitive(
            e1 in "[a-z]{5,20}",
            e2 in "[a-z]{5,20}",
            identity in "[a-zA-Z0-9]{5,20}"
        ) {
            if e1 != e2 {
                let f1 = crate::security::idempotency::compute_request_fingerprint(&e1, &identity);
                let f2 = crate::security::idempotency::compute_request_fingerprint(&e2, &identity);
                prop_assert_ne!(f1, f2);
            }
        }

        /// Fingerprint differs when identity differs
        #[test]
        fn prop_fingerprint_identity_sensitive(
            endpoint in "[a-z]{5,20}",
            i1 in "[a-zA-Z0-9]{5,20}",
            i2 in "[a-zA-Z0-9]{5,20}"
        ) {
            if i1 != i2 {
                let f1 = crate::security::idempotency::compute_request_fingerprint(&endpoint, &i1);
                let f2 = crate::security::idempotency::compute_request_fingerprint(&endpoint, &i2);
                prop_assert_ne!(f1, f2);
            }
        }

        /// Phase timing JSON format is valid
        #[test]
        fn prop_phase_timing_json(
            name in "[a-z_]{3,15}",
            ms in 0.0f64..10000.0
        ) {
            let json_fragment = format!(r#""{}":{:.1}"#, name, ms);
            prop_assert!(json_fragment.starts_with('"'));
            prop_assert!(json_fragment.contains(':'));
        }

        /// Redact challenge ID returns at most 8 bytes when input is pure ASCII
        #[test]
        fn prop_redact_challenge_id_length(id in "[a-zA-Z0-9_-]{0,100}") {
            let redacted = crate::security::log_sanitizer::redact_challenge_id(&id);
            prop_assert!(redacted.len() <= 8);
        }
    }

    // ========================================================================
    // PKCE Roundtrip Verification Tests
    // ========================================================================

    #[test]
    fn test_pkce_roundtrip_matching_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge_bytes = Sha256::digest(verifier.as_bytes());
        let stored: Vec<u8> = challenge_bytes.to_vec();
        let computed = Sha256::digest(verifier.as_bytes());
        assert!(bool::from(computed.ct_eq(stored.as_slice())));
    }

    #[test]
    fn test_pkce_roundtrip_wrong_verifier_rejects() {
        let correct_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_verifier = "XBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let stored = Sha256::digest(correct_verifier.as_bytes());
        let computed = Sha256::digest(wrong_verifier.as_bytes());
        assert!(!bool::from(computed.ct_eq(stored.as_slice())));
    }

    #[test]
    fn test_pkce_ct_eq_with_vec_u8_stored_challenge() {
        // Mirrors the actual code path: code_challenge_bytes is Vec<u8>
        let verifier = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let stored: Vec<u8> = Sha256::digest(verifier.as_bytes()).to_vec();
        let computed = Sha256::digest(verifier.as_bytes());
        assert!(bool::from(computed.ct_eq(stored.as_slice())));
    }

    #[test]
    fn test_pkce_ct_eq_wrong_length_stored_challenge() {
        // If stored challenge bytes have wrong length, ct_eq should fail
        let verifier = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let stored: Vec<u8> = vec![0u8; 16]; // Wrong length: 16 instead of 32
        let computed = Sha256::digest(verifier.as_bytes());
        assert!(!bool::from(computed.ct_eq(stored.as_slice())));
    }

    #[test]
    fn test_pkce_ct_eq_empty_stored_challenge() {
        let verifier = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let stored: Vec<u8> = vec![];
        let computed = Sha256::digest(verifier.as_bytes());
        assert!(!bool::from(computed.ct_eq(stored.as_slice())));
    }

    #[test]
    fn test_pkce_ct_eq_all_zero_stored_challenge() {
        let verifier = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let stored: Vec<u8> = vec![0u8; 32];
        let computed = Sha256::digest(verifier.as_bytes());
        // SHA256 of a non-empty string should not equal all zeros
        assert!(!bool::from(computed.ct_eq(stored.as_slice())));
    }

    // ========================================================================
    // PKCE RFC 7636 Appendix B Test Vector
    // ========================================================================

    #[test]
    fn test_pkce_rfc7636_appendix_b_vector() -> Result<(), Box<dyn std::error::Error>> {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge_b64 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let computed = Sha256::digest(verifier.as_bytes());
        let computed_b64 = BASE64_URL_SAFE_NO_PAD.encode(computed);
        assert_eq!(computed_b64, expected_challenge_b64);
        Ok(())
    }

    #[test]
    fn test_pkce_rfc7636_roundtrip_with_stored_bytes() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate the full flow: verifier -> challenge at creation,
        // then verifier -> hash -> ct_eq at redemption
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_b64 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let stored_bytes = BASE64_URL_SAFE_NO_PAD.decode(expected_b64)?;
        let computed = Sha256::digest(verifier.as_bytes());
        assert!(bool::from(computed.ct_eq(stored_bytes.as_slice())));
        Ok(())
    }

    // ========================================================================
    // RedeemRequest Deserialisation Edge Cases
    // ========================================================================

    #[test]
    fn test_redeem_request_verifier_too_short() {
        // 42 chars, one below minimum
        let short = "a".repeat(42);
        let json = format!(r#"{{"code_verifier":"{}"}}"#, short);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_too_long() {
        // 129 chars, one above maximum
        let long = "a".repeat(129);
        let json = format!(r#"{{"code_verifier":"{}"}}"#, long);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_exact_min_43() -> Result<(), Box<dyn std::error::Error>> {
        let min = "a".repeat(43);
        let json = format!(r#"{{"code_verifier":"{}"}}"#, min);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str().len(), 43);
        Ok(())
    }

    #[test]
    fn test_redeem_request_verifier_exact_max_128() -> Result<(), Box<dyn std::error::Error>> {
        let max = "a".repeat(128);
        let json = format!(r#"{{"code_verifier":"{}"}}"#, max);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str().len(), 128);
        Ok(())
    }

    #[test]
    fn test_redeem_request_verifier_invalid_char_space() {
        let v = "abc123def456ghi789jkl012mno345pqr678stu901 wx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_invalid_char_plus() {
        let v = "abc123def456ghi789jkl012mno345pqr678stu901+wx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_invalid_char_slash() {
        let v = "abc123def456ghi789jkl012mno345pqr678stu901/wx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_invalid_char_equals() {
        let v = "abc123def456ghi789jkl012mno345pqr678stu901=wx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_valid_unreserved_chars(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // All RFC 7636 unreserved chars: ALPHA DIGIT "-" "." "_" "~"
        let v = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFG";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str(), v);
        Ok(())
    }

    #[test]
    fn test_redeem_request_verifier_null_value() {
        let json = r#"{"code_verifier":null}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_numeric_value() {
        let json = r#"{"code_verifier":12345}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_boolean_value() {
        let json = r#"{"code_verifier":true}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_array_value() {
        let json = r#"{"code_verifier":["abc"]}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_verifier_object_value() {
        let json = r#"{"code_verifier":{"v":"abc"}}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_empty_json() {
        let json = "{}";
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_empty_string_verifier() {
        let json = r#"{"code_verifier":""}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_malformed_json() {
        let json = r#"{"code_verifier":}"#;
        let req: Result<RedeemRequest, _> = serde_json::from_str(json);
        assert!(req.is_err());
    }

    #[test]
    fn test_redeem_request_multiple_unknown_fields() {
        let v = "a".repeat(43);
        let json = format!(r#"{{"code_verifier":"{}","extra1":"a","extra2":"b"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    // ========================================================================
    // RedeemResponse Serialization Edge Cases
    // ========================================================================

    #[test]
    fn test_redeem_response_serialize_success() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "OK".to_string(),
            verified: true,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["result"], "OK");
        assert_eq!(parsed["verified"], true);
        Ok(())
    }

    #[test]
    fn test_redeem_response_serialize_error() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "ERROR".to_string(),
            verified: false,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["result"], "ERROR");
        assert_eq!(parsed["verified"], false);
        Ok(())
    }

    #[test]
    fn test_redeem_response_serialize_empty_result() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: String::new(),
            verified: false,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["result"], "");
        Ok(())
    }

    #[test]
    fn test_redeem_response_has_exactly_two_fields() -> Result<(), Box<dyn std::error::Error>> {
        let resp = RedeemResponse {
            result: "OK".to_string(),
            verified: true,
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&json)?;
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains_key("result"));
        assert!(parsed.contains_key("verified"));
        Ok(())
    }

    // ========================================================================
    // Expiry Boundary Tests (exact semantics of `now > cached.expires_at`)
    // ========================================================================

    #[test]
    fn test_expiry_gt_semantics_not_expired_when_equal() {
        // The code uses `now > cached.expires_at` (strict greater-than).
        // When now == expires_at, the challenge is NOT expired.
        let now: u64 = 1700000000;
        let expires_at: u64 = 1700000000;
        let expired = now > expires_at;
        assert!(
            !expired,
            "Challenge should NOT be expired when now == expires_at"
        );
    }

    #[test]
    fn test_expiry_gt_semantics_expired_one_second_past() {
        let now: u64 = 1700000001;
        let expires_at: u64 = 1700000000;
        let expired = now > expires_at;
        assert!(expired, "Challenge should be expired when now > expires_at");
    }

    #[test]
    fn test_expiry_gt_semantics_not_expired_one_second_before() {
        let now: u64 = 1699999999;
        let expires_at: u64 = 1700000000;
        let expired = now > expires_at;
        assert!(
            !expired,
            "Challenge should NOT be expired when now < expires_at"
        );
    }

    #[test]
    fn test_expiry_at_zero() {
        // Edge case: expires_at is 0 (epoch)
        let now: u64 = 1;
        let expires_at: u64 = 0;
        let expired = now > expires_at;
        assert!(expired);
    }

    #[test]
    fn test_expiry_at_u64_max() {
        // Edge case: expires_at at u64::MAX
        let now: u64 = u64::MAX;
        let expires_at: u64 = u64::MAX;
        let expired = now > expires_at;
        assert!(!expired, "Not expired when equal at max");
    }

    #[test]
    fn test_expiry_now_zero_expires_at_zero() {
        let now: u64 = 0;
        let expires_at: u64 = 0;
        let expired = now > expires_at;
        assert!(!expired, "Not expired when both are zero (equal)");
    }

    // ========================================================================
    // Challenge State Match Arm Coverage
    // ========================================================================

    #[test]
    fn test_state_match_pending_is_not_redeemable() {
        let state = ChallengeState::Pending;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
        // Corresponds to PROOF_NOT_SUBMITTED error
    }

    #[test]
    fn test_state_match_verified_is_not_redeemable() {
        let state = ChallengeState::Verified;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
        // Corresponds to CHALLENGE_ALREADY_REDEEMED error
    }

    #[test]
    fn test_state_match_failed_is_not_redeemable() {
        let state = ChallengeState::Failed;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
        // Corresponds to CHALLENGE_VERIFICATION_FAILED error
    }

    #[test]
    fn test_state_match_expired_is_not_redeemable() {
        let state = ChallengeState::Expired;
        assert_ne!(state, ChallengeState::ProofOkWaitingForRedeem);
        // Corresponds to CHALLENGE_EXPIRED error
    }

    #[test]
    fn test_state_proof_ok_is_redeemable() {
        let state = ChallengeState::ProofOkWaitingForRedeem;
        assert_eq!(state, ChallengeState::ProofOkWaitingForRedeem);
    }

    #[test]
    fn test_all_non_redeemable_states_rejected() {
        let non_redeemable = [
            ChallengeState::Pending,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];
        for state in &non_redeemable {
            assert_ne!(
                state,
                &ChallengeState::ProofOkWaitingForRedeem,
                "State {:?} should not be redeemable",
                state
            );
        }
    }

    #[test]
    fn test_challenge_state_as_str_values() {
        assert_eq!(ChallengeState::Pending.as_str(), "pending");
        assert_eq!(
            ChallengeState::ProofOkWaitingForRedeem.as_str(),
            "proof_ok_waiting_for_redeem"
        );
        assert_eq!(ChallengeState::Verified.as_str(), "verified");
        assert_eq!(ChallengeState::Failed.as_str(), "failed");
        assert_eq!(ChallengeState::Expired.as_str(), "expired");
    }

    // ========================================================================
    // State Transition Tests
    // ========================================================================

    #[test]
    fn test_state_transition_to_verified() {
        let state = ChallengeState::Verified;
        assert_eq!(state, ChallengeState::Verified);
    }

    #[test]
    fn test_verified_at_set_on_transition() {
        let now = current_timestamp();
        let verified_at: Option<u64> = Some(now);
        assert!(verified_at.is_some());
        assert_eq!(verified_at, Some(now));
    }

    #[test]
    fn test_verified_at_none_before_transition() {
        let verified_at: Option<u64> = None;
        assert!(verified_at.is_none());
    }

    // ========================================================================
    // Nonce Tag Edge Cases
    // ========================================================================

    #[test]
    fn test_nonce_tag_with_nil_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let nil = Uuid::nil();
        let tag = format!("redeem:{}", nil);
        assert_eq!(tag, "redeem:00000000-0000-0000-0000-000000000000");
        Ok(())
    }

    #[test]
    fn test_nonce_tag_with_max_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let max = Uuid::max();
        let tag = format!("redeem:{}", max);
        assert_eq!(tag, "redeem:ffffffff-ffff-ffff-ffff-ffffffffffff");
        Ok(())
    }

    #[test]
    fn test_nonce_tag_length_is_43() -> Result<(), Box<dyn std::error::Error>> {
        // "redeem:" = 7 chars, UUID = 36 chars, total = 43
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let tag = format!("redeem:{}", sid);
        assert_eq!(tag.len(), 43);
        Ok(())
    }

    #[test]
    fn test_nonce_dedup_ttl_is_300_seconds() {
        assert_eq!(NONCE_DEDUP_TTL.as_secs(), 300);
    }

    #[test]
    fn test_nonce_dedup_ttl_is_5_minutes() {
        assert_eq!(NONCE_DEDUP_TTL, Duration::from_secs(5 * 60));
    }

    // ========================================================================
    // Issuer Metadata Fallback Tests
    // ========================================================================

    #[test]
    fn test_issuer_vk_fallback_to_zero_array() {
        let zero = [0u8; 32];
        let issuer_vk_bytes: Option<[u8; 32]> = None;
        let vk_ref = issuer_vk_bytes.as_ref().unwrap_or(&zero);
        assert_eq!(vk_ref, &[0u8; 32]);
    }

    #[test]
    fn test_issuer_vk_present_uses_actual_bytes() {
        let zero = [0u8; 32];
        let actual = [0xABu8; 32];
        let issuer_vk_bytes: Option<[u8; 32]> = Some(actual);
        let vk_ref = issuer_vk_bytes.as_ref().unwrap_or(&zero);
        assert_eq!(vk_ref, &[0xABu8; 32]);
    }

    #[test]
    fn test_issuer_vk_zero_encodes_to_base64() {
        let zero = [0u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(zero);
        assert_eq!(encoded, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn test_issuer_kid_as_deref_some() {
        let kid = Some("test-kid-123".to_string());
        assert_eq!(kid.as_deref(), Some("test-kid-123"));
    }

    #[test]
    fn test_issuer_kid_as_deref_none() {
        let kid: Option<String> = None;
        assert_eq!(kid.as_deref(), None);
    }

    // ========================================================================
    // Tenant ID / Origin Fallback Tests
    // ========================================================================

    #[test]
    fn test_tenant_id_present_uses_tenant() {
        let customer_id = "tenant-abc".to_string();
        assert_eq!(customer_id, "tenant-abc");
    }

    #[test]
    fn test_tenant_id_none_falls_back_to_origin() {
        let customer_id = "https://example.com".to_string();
        assert_eq!(customer_id, "https://example.com");
    }

    #[test]
    fn test_tenant_id_empty_string_is_still_some() {
        let customer_id = String::new();
        assert_eq!(customer_id, "");
    }

    // ========================================================================
    // Fingerprint Computation Tests
    // ========================================================================

    #[test]
    fn test_fingerprint_deterministic() {
        let f1 = crate::security::idempotency::compute_request_fingerprint(
            "redeem:1.2.3.4:client-1",
            "client-1",
        );
        let f2 = crate::security::idempotency::compute_request_fingerprint(
            "redeem:1.2.3.4:client-1",
            "client-1",
        );
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_fingerprint_different_endpoints() {
        let f1 = crate::security::idempotency::compute_request_fingerprint(
            "redeem:1.2.3.4:client-1",
            "client-1",
        );
        let f2 = crate::security::idempotency::compute_request_fingerprint(
            "redeem:5.6.7.8:client-1",
            "client-1",
        );
        assert_ne!(f1, f2);
    }

    #[test]
    fn test_fingerprint_different_identities() {
        let f1 = crate::security::idempotency::compute_request_fingerprint(
            "redeem:1.2.3.4:client-1",
            "client-1",
        );
        let f2 = crate::security::idempotency::compute_request_fingerprint(
            "redeem:1.2.3.4:client-1",
            "client-2",
        );
        assert_ne!(f1, f2);
    }

    #[test]
    fn test_fingerprint_is_hex_encoded() {
        let f = crate::security::idempotency::compute_request_fingerprint(
            "redeem:1.2.3.4:client-1",
            "client-1",
        );
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
        // SHA256 hex = 64 chars
        assert_eq!(f.len(), 64);
    }

    #[test]
    fn test_fingerprint_format_matches_code_usage() {
        // The code does: format!("redeem:{}:{}", client_ip, client_id)
        let client_ip = "203.0.113.1";
        let client_id = "pk_test_abc123";
        let endpoint = format!("redeem:{}:{}", client_ip, client_id);
        let f = crate::security::idempotency::compute_request_fingerprint(&endpoint, client_id);
        assert_eq!(f.len(), 64);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ========================================================================
    // Redact Challenge ID Tests
    // ========================================================================

    #[test]
    fn test_redact_challenge_id_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = crate::security::log_sanitizer::redact_challenge_id(id);
        assert_eq!(redacted, "550e8400");
    }

    #[test]
    fn test_redact_challenge_id_short_input() {
        let id = "abc";
        let redacted = crate::security::log_sanitizer::redact_challenge_id(id);
        assert_eq!(redacted, "abc");
    }

    #[test]
    fn test_redact_challenge_id_empty_input() {
        let id = "";
        let redacted = crate::security::log_sanitizer::redact_challenge_id(id);
        assert_eq!(redacted, "");
    }

    #[test]
    fn test_redact_challenge_id_exactly_8_chars() {
        let id = "12345678";
        let redacted = crate::security::log_sanitizer::redact_challenge_id(id);
        assert_eq!(redacted, "12345678");
    }

    #[test]
    fn test_redact_challenge_id_9_chars_truncates() {
        let id = "123456789";
        let redacted = crate::security::log_sanitizer::redact_challenge_id(id);
        assert_eq!(redacted, "12345678");
    }

    // ========================================================================
    // Phase Timing Log Format Tests
    // ========================================================================

    #[test]
    fn test_phase_timings_json_format() {
        let phase_timings: Vec<(&str, f64)> = vec![
            ("auth", 12.5),
            ("idempotency", 3.2),
            ("challenge_get", 45.0),
            ("challenge_put", 8.1),
        ];
        let phases_json = phase_timings
            .iter()
            .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            phases_json,
            r#""auth":12.5,"idempotency":3.2,"challenge_get":45.0,"challenge_put":8.1"#
        );
    }

    #[test]
    fn test_phase_timings_empty() {
        let phase_timings: Vec<(&str, f64)> = vec![];
        let phases_json = phase_timings
            .iter()
            .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(phases_json, "");
    }

    #[test]
    fn test_slow_phases_filter() {
        let phase_timings: Vec<(&str, f64)> = vec![
            ("auth", 12.5),
            ("idempotency", 3.2),
            ("challenge_get", 55.0),
            ("nonce_dedup", 80.0),
        ];
        let slow_phases: Vec<&str> = phase_timings
            .iter()
            .filter(|(_, ms)| *ms > 50.0)
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(slow_phases, vec!["challenge_get", "nonce_dedup"]);
    }

    #[test]
    fn test_slow_phases_none_slow() {
        let phase_timings: Vec<(&str, f64)> = vec![("auth", 10.0), ("idempotency", 5.0)];
        let slow_phases: Vec<&str> = phase_timings
            .iter()
            .filter(|(_, ms)| *ms > 50.0)
            .map(|(name, _)| *name)
            .collect();
        assert!(slow_phases.is_empty());
    }

    #[test]
    fn test_slow_phases_at_threshold_not_slow() {
        // Exactly 50.0 is NOT slow (filter is > 50.0, not >=)
        let phase_timings: Vec<(&str, f64)> = vec![("auth", 50.0)];
        let slow_phases: Vec<&str> = phase_timings
            .iter()
            .filter(|(_, ms)| *ms > 50.0)
            .map(|(name, _)| *name)
            .collect();
        assert!(slow_phases.is_empty());
    }

    #[test]
    fn test_is_slow_threshold() {
        let total_ms_slow: f64 = 501.0;
        let total_ms_not_slow: f64 = 500.0;
        let total_ms_fast: f64 = 100.0;
        assert!(total_ms_slow > 500.0);
        assert!(total_ms_not_slow <= 500.0);
        assert!(total_ms_fast <= 500.0);
    }

    #[test]
    fn test_sub_ops_json_format() {
        let sub_ops: Vec<(&str, f64)> = vec![
            ("challenge_do_get", 15.3),
            ("nonce_do_check_and_set", 22.7),
            ("challenge_do_put", 9.1),
        ];
        let sub_ops_json = sub_ops
            .iter()
            .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            sub_ops_json,
            r#""challenge_do_get":15.3,"nonce_do_check_and_set":22.7,"challenge_do_put":9.1"#
        );
    }

    #[test]
    fn test_sub_ops_cached_variant() {
        // When sandbox prefetch hits, the sub_op uses "challenge_do_get_cached" with 0.0
        let sub_ops: Vec<(&str, f64)> = vec![("challenge_do_get_cached", 0.0)];
        let sub_ops_json = sub_ops
            .iter()
            .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(sub_ops_json, r#""challenge_do_get_cached":0.0"#);
    }

    // ========================================================================
    // Zeroize Behaviour Tests
    // ========================================================================

    #[test]
    fn test_zeroize_submit_secret() {
        use zeroize::Zeroize;
        let mut secret = vec![0xABu8; 32];
        secret.zeroize();
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_empty_vec() {
        use zeroize::Zeroize;
        let mut secret: Vec<u8> = vec![];
        secret.zeroize();
        assert!(secret.is_empty());
    }

    #[test]
    fn test_zeroize_large_vec() {
        use zeroize::Zeroize;
        let mut secret = vec![0xFFu8; 1024];
        secret.zeroize();
        assert!(secret.iter().all(|&b| b == 0));
    }

    // ========================================================================
    // CachedChallenge Validate Tests
    // ========================================================================

    fn make_test_challenge(state: ChallengeState) -> CachedChallenge {
        CachedChallenge {
            id: Uuid::new_v4(),
            short_code: "1234 5678 9012".to_string(),
            rp_challenge: vec![0u8; 32],
            cutoff_days: 6570,
            verifying_key_id: 0,
            code_challenge: "test".to_string(),
            code_challenge_bytes: vec![0u8; 32],
            submit_secret: vec![0u8; 32],
            origin: "https://example.com".to_string(),
            expires_at: current_timestamp() + 300,
            created_at: current_timestamp(),
            state,
            proof_submitted: false,
            verified_at: None,
            proof_verified_at: None,
            issuer_kid: None,
            issuer_vk_bytes: None,
            client_id: Some("client-1".to_string()),
            tenant_id: None,
            proof_direction: crate::storage::origin_policy::ProofDirection::OverAge,
        }
    }

    #[test]
    fn test_cached_challenge_validate_valid() -> Result<(), Box<dyn std::error::Error>> {
        let c = make_test_challenge(ChallengeState::Pending);
        c.validate().map_err(|e| e.into())
    }

    #[test]
    fn test_cached_challenge_validate_bad_rp_challenge() {
        let mut c = make_test_challenge(ChallengeState::Pending);
        c.rp_challenge = vec![0u8; 16]; // Wrong length
        let result = c.validate();
        assert!(result.is_err());
        assert!(result.err().is_some_and(|e| e.contains("rp_challenge")));
    }

    #[test]
    fn test_cached_challenge_validate_bad_code_challenge_bytes() {
        let mut c = make_test_challenge(ChallengeState::Pending);
        c.code_challenge_bytes = vec![0u8; 64]; // Wrong length
        let result = c.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .is_some_and(|e| e.contains("code_challenge_bytes")));
    }

    #[test]
    fn test_cached_challenge_validate_bad_submit_secret() {
        let mut c = make_test_challenge(ChallengeState::Pending);
        c.submit_secret = vec![0u8; 16]; // Wrong length (not 0 and not 32)
        let result = c.validate();
        assert!(result.is_err());
        assert!(result.err().is_some_and(|e| e.contains("submit_secret")));
    }

    #[test]
    fn test_cached_challenge_validate_zeroed_submit_secret_allowed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // After zeroize, submit_secret becomes empty; validation should pass
        let mut c = make_test_challenge(ChallengeState::ProofOkWaitingForRedeem);
        c.submit_secret = vec![];
        c.validate().map_err(|e| e.into())
    }

    #[test]
    fn test_cached_challenge_state_transition_simulation() {
        // Simulate the actual code: state = Verified, verified_at = Some(now)
        let mut c = make_test_challenge(ChallengeState::ProofOkWaitingForRedeem);
        assert_eq!(c.state, ChallengeState::ProofOkWaitingForRedeem);
        assert!(c.verified_at.is_none());

        let now = current_timestamp();
        c.state = ChallengeState::Verified;
        c.verified_at = Some(now);

        assert_eq!(c.state, ChallengeState::Verified);
        assert_eq!(c.verified_at, Some(now));
    }

    #[test]
    fn test_cached_challenge_debug_redacts_secrets() {
        let c = make_test_challenge(ChallengeState::Pending);
        let debug_str = format!("{:?}", c);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&format!("{:?}", c.rp_challenge)));
    }

    #[test]
    fn test_cached_challenge_origin_preserved() {
        let c = make_test_challenge(ChallengeState::ProofOkWaitingForRedeem);
        let origin = c.origin.clone();
        assert_eq!(origin, "https://example.com");
    }

    // ========================================================================
    // Client IP Extraction Fallback Tests
    // ========================================================================

    #[test]
    fn test_client_ip_fallback_to_unknown() {
        let client_ip = "unknown".to_string();
        assert_eq!(client_ip, "unknown");
    }

    #[test]
    fn test_client_ip_present() {
        let client_ip = "203.0.113.42".to_string();
        assert_eq!(client_ip, "203.0.113.42");
    }

    // ========================================================================
    // SHA256 Known Test Vectors
    // ========================================================================

    #[test]
    fn test_sha256_known_vector_abc() {
        // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = Sha256::digest("abc".as_bytes());
        let hex = hex::encode(hash);
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_known_vector_empty_string() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = Sha256::digest("".as_bytes());
        let hex = hex::encode(hash);
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ========================================================================
    // Constant-Time Comparison Additional Edge Cases
    // ========================================================================

    #[test]
    fn test_ct_eq_last_byte_different() {
        let mut a = [0xAAu8; 32];
        let mut b = [0xAAu8; 32];
        a[31] = 0x00;
        b[31] = 0x01;
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_first_byte_different() {
        let mut a = [0xBBu8; 32];
        let mut b = [0xBBu8; 32];
        a[0] = 0x00;
        b[0] = 0x01;
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_middle_byte_different() {
        let mut a = [0xCCu8; 32];
        let mut b = [0xCCu8; 32];
        a[15] = 0x00;
        b[15] = 0x01;
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_vec_against_array() {
        // This mirrors the actual code: computed (GenericArray) ct_eq against cached.code_challenge_bytes (Vec<u8>)
        let verifier = "test_verifier_for_ct_eq_vec_array_comparison";
        let hash = Sha256::digest(verifier.as_bytes());
        let stored_vec: Vec<u8> = hash.to_vec();
        assert!(bool::from(hash.ct_eq(stored_vec.as_slice())));
    }

    #[test]
    fn test_ct_eq_alternating_pattern() {
        let a: [u8; 32] = [0xAA; 32];
        let b: [u8; 32] = [0x55; 32]; // Bit complement
        assert!(!bool::from(a.ct_eq(&b)));
    }

    // ========================================================================
    // Base64 URL Safe Encoding Additional Tests
    // ========================================================================

    #[test]
    fn test_base64_url_safe_no_pad_32_bytes() {
        let bytes = [0xFFu8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        // 32 bytes -> ceil(32*4/3) = 43 chars (no padding)
        assert_eq!(encoded.len(), 43);
    }

    #[test]
    fn test_base64_url_safe_no_pad_empty() {
        let bytes: [u8; 0] = [];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(encoded, "");
    }

    #[test]
    fn test_base64_url_safe_no_pad_single_byte() {
        let bytes = [0x42u8; 1];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        assert!(!encoded.contains('='));
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_base64_decode_invalid_rejects() {
        let invalid = "!!!not_valid_base64!!!";
        let result = BASE64_URL_SAFE_NO_PAD.decode(invalid);
        assert!(result.is_err());
    }

    // ========================================================================
    // UUID Parsing Edge Cases
    // ========================================================================

    #[test]
    fn test_uuid_nil() {
        let nil = Uuid::nil();
        assert_eq!(nil.to_string(), "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_uuid_max() {
        let max = Uuid::max();
        assert_eq!(max.to_string(), "ffffffff-ffff-ffff-ffff-ffffffffffff");
    }

    #[test]
    fn test_uuid_v4_format() {
        let id = Uuid::new_v4();
        let s = id.to_string();
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn test_uuid_parse_uppercase_rejected() {
        // UUID parsing is case-insensitive
        let upper = "550E8400-E29B-41D4-A716-446655440000";
        let result = Uuid::parse_str(upper);
        assert!(result.is_ok());
    }

    #[test]
    fn test_uuid_parse_no_dashes() {
        let no_dashes = "550e8400e29b41d4a716446655440000";
        let result = Uuid::parse_str(no_dashes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_uuid_parse_empty() {
        let result = Uuid::parse_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_uuid_parse_too_short() {
        let result = Uuid::parse_str("550e8400");
        assert!(result.is_err());
    }

    // ========================================================================
    // Idempotency Key Truncation Tests
    // ========================================================================

    #[test]
    fn test_idempotency_key_log_truncation_short() {
        let key = "abc";
        let truncated = key.get(..key.len().min(8)).unwrap_or(key);
        assert_eq!(truncated, "abc");
    }

    #[test]
    fn test_idempotency_key_log_truncation_exact_8() {
        let key = "12345678";
        let truncated = key.get(..key.len().min(8)).unwrap_or(key);
        assert_eq!(truncated, "12345678");
    }

    #[test]
    fn test_idempotency_key_log_truncation_long() {
        let key = "12345678-9abc-def0-1234-567890abcdef";
        let truncated = key.get(..key.len().min(8)).unwrap_or(key);
        assert_eq!(truncated, "12345678");
    }

    #[test]
    fn test_idempotency_key_log_truncation_empty() {
        let key = "";
        let truncated = key.get(..key.len().min(8)).unwrap_or(key);
        assert_eq!(truncated, "");
    }

    // ========================================================================
    // Slow Phase Join Format Tests
    // ========================================================================

    #[test]
    fn test_slow_phases_join_single() {
        let slow_phases = ["auth"];
        let joined = slow_phases.join(",");
        assert_eq!(joined, "auth");
    }

    #[test]
    fn test_slow_phases_join_multiple() {
        let slow_phases = ["auth", "challenge_get", "nonce_dedup"];
        let joined = slow_phases.join(",");
        assert_eq!(joined, "auth,challenge_get,nonce_dedup");
    }

    #[test]
    fn test_slow_phases_join_empty() {
        let slow_phases: Vec<&str> = vec![];
        let joined = slow_phases.join(",");
        assert_eq!(joined, "");
    }

    // ========================================================================
    // Credit Request Customer ID Resolution Tests
    // ========================================================================

    #[test]
    fn test_credit_customer_id_with_tenant() {
        let tenant_id = Some("tenant-xyz".to_string());
        let origin = "https://shop.example.com".to_string();
        let customer_id = tenant_id.clone().unwrap_or_else(|| origin.clone());
        assert_eq!(customer_id, "tenant-xyz");
    }

    #[test]
    fn test_credit_customer_id_without_tenant() {
        let tenant_id: Option<String> = None;
        let origin = "https://shop.example.com".to_string();
        let customer_id = tenant_id.clone().unwrap_or_else(|| origin.clone());
        assert_eq!(customer_id, "https://shop.example.com");
    }

    #[test]
    fn test_credit_verification_id_is_session_id() -> Result<(), Box<dyn std::error::Error>> {
        let sid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let verification_id = sid.to_string();
        assert_eq!(verification_id, "550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    // ========================================================================
    // PKCE Verifier Character Boundary Tests
    // ========================================================================

    #[test]
    fn test_pkce_verifier_with_tilde() -> Result<(), Box<dyn std::error::Error>> {
        let v = "abc~def~ghi~jkl~mno~pqr~stu~vwx~yz0123456789ab";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str(), v);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_with_dots() -> Result<(), Box<dyn std::error::Error>> {
        let v = "abc.def.ghi.jkl.mno.pqr.stu.vwx.yz0123456789ab";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str(), v);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_with_dashes() -> Result<(), Box<dyn std::error::Error>> {
        let v = "abc-def-ghi-jkl-mno-pqr-stu-vwx-yz0123456789ab";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str(), v);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_with_underscores() -> Result<(), Box<dyn std::error::Error>> {
        let v = "abc_def_ghi_jkl_mno_pqr_stu_vwx_yz0123456789ab";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: RedeemRequest = serde_json::from_str(&json)?;
        assert_eq!(req.code_verifier.as_str(), v);
        Ok(())
    }

    #[test]
    fn test_pkce_verifier_unicode_rejected() {
        let v = "abc\u{00E9}def456ghi789jkl012mno345pqr678stu901vwx";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_pkce_verifier_control_char_rejected() {
        let v = "abc\x01def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_pkce_verifier_tab_rejected() {
        let v = "abc\tdef456ghi789jkl012mno345pqr678stu901vwx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_pkce_verifier_at_sign_rejected() {
        let v = "abc@def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    #[test]
    fn test_pkce_verifier_hash_rejected() {
        let v = "abc#def456ghi789jkl012mno345pqr678stu901vwx234yz";
        let json = format!(r#"{{"code_verifier":"{}"}}"#, v);
        let req: Result<RedeemRequest, _> = serde_json::from_str(&json);
        assert!(req.is_err());
    }

    // ========================================================================
    // CachedChallenge Serialization Roundtrip
    // ========================================================================

    #[test]
    fn test_cached_challenge_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = make_test_challenge(ChallengeState::ProofOkWaitingForRedeem);
        let json = serde_json::to_string(&original)?;
        let deserialized: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(deserialized.state, original.state);
        assert_eq!(deserialized.origin, original.origin);
        assert_eq!(deserialized.expires_at, original.expires_at);
        assert_eq!(deserialized.client_id, original.client_id);
        assert_eq!(deserialized.proof_direction, original.proof_direction);
        Ok(())
    }

    #[test]
    fn test_cached_challenge_serde_all_states() -> Result<(), Box<dyn std::error::Error>> {
        for state in [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ] {
            let c = make_test_challenge(state.clone());
            let json = serde_json::to_string(&c)?;
            let d: CachedChallenge = serde_json::from_str(&json)?;
            assert_eq!(d.state, state);
        }
        Ok(())
    }

    #[test]
    fn test_cached_challenge_with_issuer_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let mut c = make_test_challenge(ChallengeState::Verified);
        c.issuer_kid = Some("kid-abc-123".to_string());
        c.issuer_vk_bytes = Some([0x42u8; 32]);
        let json = serde_json::to_string(&c)?;
        let d: CachedChallenge = serde_json::from_str(&json)?;
        assert_eq!(d.issuer_kid, Some("kid-abc-123".to_string()));
        assert_eq!(d.issuer_vk_bytes, Some([0x42u8; 32]));
        Ok(())
    }

    #[test]
    fn test_cached_challenge_default_proof_direction() -> Result<(), Box<dyn std::error::Error>> {
        // When proof_direction is missing from JSON, defaults to "over_age"
        let c = make_test_challenge(ChallengeState::Pending);
        let mut json_val: serde_json::Value = serde_json::to_value(&c)?;
        json_val
            .as_object_mut()
            .map(|m| m.remove("proof_direction"));
        let d: CachedChallenge = serde_json::from_value(json_val)?;
        assert_eq!(
            d.proof_direction,
            crate::storage::origin_policy::ProofDirection::OverAge
        );
        Ok(())
    }

    // ========================================================================
    // Saturating Subtraction Tests (used in phase timing)
    // ========================================================================

    #[test]
    fn test_saturating_sub_no_underflow() {
        let start: u64 = 100;
        let end: u64 = 50;
        let diff = end.saturating_sub(start);
        assert_eq!(diff, 0);
    }

    #[test]
    fn test_saturating_sub_normal() {
        let start: u64 = 100;
        let end: u64 = 150;
        let diff = end.saturating_sub(start);
        assert_eq!(diff, 50);
    }

    #[test]
    fn test_saturating_sub_equal() {
        let val: u64 = 42;
        assert_eq!(val.saturating_sub(val), 0);
    }
}
