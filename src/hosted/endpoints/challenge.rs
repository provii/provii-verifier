// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Merged challenge creation handler for hosted age verification.
//!
//! POST /v1/hosted/challenge initiates a new verification session via
//! a single in-process execution path inside provii-verifier.
//!
//! ## Flow
//!
//! 1. Parse and validate `ChallengeRequest` body
//! 2. Authenticate via public key KV lookup + origin allowlist
//! 3. Per-customer hourly rate limit via KV counter
//! 4. Generate nonce, store in HostedNonceDO for replay protection
//! 5. Look up origin policy (directly, no service binding)
//! 6. Generate challenge crypto (UUID, short code, rp_challenge, submit_secret)
//! 7. Persist challenge in `ChallengeStore` and short code KV mapping
//! 8. Create `HostedSession`, store encrypted in session KV + DO
//! 9. Generate HMAC-signed WebSocket ticket
//! 10. Return `ChallengeResponse`
//!
//! ## Security properties
//!
//! SECURITY: Origin validation is enforced against the `allowed_origins` list
//! registered for the public key in KV. This prevents cross-origin abuse of
//! customer credentials.
//!
//! SECURITY: PKCE (RFC 7636, S256) binds the browser SDK to the session. The
//! `code_challenge` is stored at creation time and verified during redemption.
//! The `code_verifier` is generated server-side and encrypted before KV storage.
//!
//! SECURITY: Session binding hashes the client IP and User-Agent using the
//! `ip_hash_salt` from AppState to detect session hijacking on subsequent
//! requests (status polling, redemption).
//!
//! SECURITY: Nonce storage uses Durable Objects with atomic check-and-set to
//! eliminate the KV TOCTOU race that would otherwise allow replay attacks.
//! Nonces expire after 300 seconds.
//!
//! SECURITY: All secret material (submit_secret, code_verifier, MEK) is wrapped
//! in `Zeroizing` and intermediate byte arrays are explicitly zeroized after copy.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::join;
use provii_crypto_protocol::{generate_nonce, rp_challenge};
use serde_valid::Validate;
use uuid::Uuid;
use worker::{Env, Error as WorkerError, Headers, Response};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    analytics::Analytics,
    bindings::{KV_CONFIG, KV_RATE_LIMITS},
    cache::{CachedChallenge, ChallengeState},
    error::ApiError,
    hosted::{
        keys::{validate_key_format, KeyManager},
        rate_limiting::{check_quota, service_unavailable_with_retry_after},
        session_binding::{generate_ws_ticket, hash_with_salt},
        storage::kv::{store_challenge_mapping_kv, store_nonce_do, store_session_kv},
        types::{requests::ChallengeRequest, responses::ChallengeResponse, session::HostedSession},
    },
    routes::challenge::generate_short_code_from_uuid,
    security::log_sanitizer::redact_challenge_id,
    types::{B64Url32, CutoffDays, ShortCode, UuidV4, VkId},
    utils::{
        calculate_exact_days_for_years, current_timestamp, generate_secure_random,
        MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL, NONCE_DEDUP_TTL,
    },
    AppState,
};

// VA-HEP-003: Import the canonical MAX_ORIGIN_LENGTH from the shared types
// module to eliminate conflicting definitions across the codebase.
use crate::hosted::types::requests::MAX_ORIGIN_LENGTH;

/// Default hourly rate limit per public key (used when env var is missing).
const DEFAULT_QUOTA_PER_HOUR: u32 = 500;

/// Handle `POST /v1/hosted/challenge`.
///
/// Orchestrates the complete challenge creation flow: request validation,
/// public key auth, rate limiting, nonce tracking, origin policy lookup,
/// challenge crypto generation, session storage, and response mapping.
///
/// # Errors
///
/// Returns structured JSON error responses for all failure modes:
/// - 400 for validation failures
/// - 401 for unknown or disabled public keys
/// - 403 for origin not in the allowed list
/// - 409 for nonce reuse (replay detection)
/// - 429 for rate limit exceeded
/// - 500 for internal failures
///
/// TODO(testing): ADV-VA-06-012 / VA-RTE-011 -- auth, CSRF, and cookie
/// validation paths lack integration tests. Requires a test harness that
/// can construct a worker::Request with realistic headers and cookies.
pub async fn handle_hosted_challenge(
    state: Arc<AppState>,
    env: &Env,
    body_bytes: Vec<u8>,
    headers: &Headers,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(8);

    // ── Read SESSION_TTL from env (default 300s / 5 minutes) ────────────────
    let session_ttl: u64 = env
        .var("SESSION_TTL_SEC")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(300);

    // ── Extract client context ─────────────────────────────────────────────
    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());
    let user_agent = headers.get("User-Agent").ok().flatten();

    // ── Parse and validate request body (already size-limited by router) ──
    // PG-VAL-016 / R4 NEW-2/NEW-4: Use the structured envelope so devs get
    // {error, code, field, detail, request_id} on every body-shape failure.
    // Mirrors simulate-proof and the v1 expert /challenge dispatcher; the
    // hosted dispatcher was the last 400 path that omitted `field`.
    let body: ChallengeRequest = serde_json::from_slice(&body_bytes).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Failed to parse request body: {:?}", _e);
        WorkerError::from(ApiError::bad_request(
            "BODY_SCHEMA_INVALID",
            Some("body"),
            "Request body could not be parsed as JSON or has unknown fields",
        ))
    })?;

    if let Err(e) = body.validate() {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Request validation failed: {:?}", e);
        return ApiError::bad_request(
            "BODY_SCHEMA_INVALID",
            Some("body"),
            format!("Request validation failed: {}", e),
        )
        .to_response();
    }

    // Extract public key from body or X-Public-Key header.
    let public_key = if !body.public_key.is_empty() {
        body.public_key.clone()
    } else {
        match headers.get("X-Public-Key").ok().flatten() {
            Some(pk) if !pk.is_empty() => pk,
            _ => {
                state
                    .audit_logger
                    .log_suspicious_activity(&client_ip, "hosted_challenge:missing_public_key")
                    .await;
                return ApiError::bad_request(
                    "BODY_SCHEMA_INVALID",
                    Some("public_key"),
                    "public key is required (set the `public_key` body field or the `X-Public-Key` header)",
                )
                .to_response();
            }
        }
    };

    // Extract origin from body or Origin header.
    let origin = if !body.origin.is_empty() {
        body.origin.clone()
    } else {
        match headers.get("Origin").ok().flatten() {
            Some(o) if !o.is_empty() => o,
            _ => {
                state
                    .audit_logger
                    .log_suspicious_activity(&client_ip, "hosted_challenge:missing_origin")
                    .await;
                return ApiError::bad_request(
                    "BODY_SCHEMA_INVALID",
                    Some("origin"),
                    "origin is required (set the `origin` body field or the `Origin` header)",
                )
                .to_response();
            }
        }
    };

    if origin.len() > MAX_ORIGIN_LENGTH {
        return ApiError::bad_request(
            "BODY_SCHEMA_INVALID",
            Some("origin"),
            "origin exceeds the maximum allowed length (2048 bytes)",
        )
        .to_response();
    }

    let validation_ms = worker::Date::now().as_millis().saturating_sub(start) as f64;
    phase_timings.push(("validation", validation_ms));

    // ── Public key authentication ──────────────────────────────────────────
    let auth_start = worker::Date::now().as_millis();

    if let Err(_e) = validate_key_format(&public_key) {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Invalid key format: {:?}", _e);
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_challenge:invalid_key_format")
            .await;
        return ApiError::bad_request(
            "BODY_SCHEMA_INVALID",
            Some("public_key"),
            "public_key is not a valid public-key identifier",
        )
        .to_response();
    }

    let key_manager = KeyManager::new(env).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Failed to create KeyManager: {:?}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;

    let key_data = match key_manager.get_key(&public_key).await {
        Ok(kd) => kd,
        Err(_e) => {
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "hosted_challenge:unknown_public_key")
                .await;
            return ApiError::Unauthorized.to_response();
        }
    };

    if !key_data.enabled {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_challenge:disabled_public_key")
            .await;
        return ApiError::Unauthorized.to_response();
    }

    // SECURITY: Origin validation against allowed_origins whitelist.
    // Sandbox pk_test_* keys skip origin enforcement so developers can test from
    // any origin (localhost, dev domains, hosted playgrounds) without registering
    // each one. Production pk_live_* keys always enforce origin restrictions.
    let is_sandbox_test_key =
        state.cfg.environment == "sandbox" && public_key.starts_with("pk_test_");

    if is_sandbox_test_key {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/challenge] Sandbox pk_test_* origin check skipped: pk_prefix={}, origin={}",
            public_key.get(..8).unwrap_or(&public_key),
            origin
        );
    } else if let Err(_e) = key_manager.validate_origin(&key_data, &origin) {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_challenge:origin_not_allowed")
            .await;
        return ApiError::Forbidden(Some("Origin not allowed for this key".into())).to_response();
    }

    // ── Per-customer hourly rate limit ─────────────────────────────────────
    // R14 (RL-07): Read the per-customer quota from the DEFAULT_QUOTA_PER_HOUR
    // env var so the sandbox's relaxed value (2000) actually applies, instead of
    // the hardcoded const that ignored it. Production sets the same 500 it always
    // used, so prod behaviour is unchanged. Falls back to the const when the var
    // is missing or unparseable. Mirrors the SESSION_TTL_SEC read above and the
    // pre-auth gate's `env_var_u32(..., "DEFAULT_QUOTA_PER_HOUR", 500)`.
    let default_quota: u32 = env
        .var("DEFAULT_QUOTA_PER_HOUR")
        .ok()
        .and_then(|v| v.to_string().parse::<u32>().ok())
        .unwrap_or(DEFAULT_QUOTA_PER_HOUR);

    let rl_kv = match env.kv(KV_RATE_LIMITS) {
        Ok(kv) => kv,
        Err(_) => {
            // SECURITY: Fail closed. Missing binding means rate limiting cannot
            // function; deny the request with 503 + Retry-After.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "{{\"audit\":true,\"event\":\"hosted_kv_binding_missing\",\"severity\":\"critical\",\"endpoint\":\"hosted_challenge\",\"binding\":\"KV_RATE_LIMITS\"}}"
            );
            return service_unavailable_with_retry_after(5);
        }
    };

    let result = check_quota(&rl_kv, &rl_kv, &public_key, "challenge", default_quota).await;

    if result.kv_unavailable {
        // NOTE: The rate limiter internals already emit structured audit logs
        // for KV failures (hosted_kv_read_failure / hosted_circuit_breaker_tripped).
        // No additional KV failure log here to avoid double-logging.
        return service_unavailable_with_retry_after(5);
    }
    if !result.allowed {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[RateLimit] Exceeded for pk={} endpoint=hosted_challenge count={}/{}",
            public_key,
            result.current_count,
            result.limit,
        );
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_challenge:rate_limit_exceeded")
            .await;
        return ApiError::TooManyRequests(Some("Rate limit exceeded".into())).to_response();
    }

    phase_timings.push((
        "auth_rate_limit",
        worker::Date::now().as_millis().saturating_sub(auth_start) as f64,
    ));

    // ── Look up origin policy (direct, no service binding) ─────────────────
    let phase_start = worker::Date::now().as_millis();
    let policy = match state.origin_policy_store.get_policy(&origin).await {
        Ok(Some(p)) => p,
        Ok(None) if is_sandbox_test_key => {
            // Sandbox pk_test_* keys get a default origin policy when the
            // origin has no explicit policy in KV. This allows developers to
            // test from any origin without pre-registering it.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/challenge] Sandbox pk_test_*: using default policy for unregistered origin {}",
                origin
            );
            crate::storage::origin_policy::OriginPolicy {
                tenant_id: "sandbox_default".to_string(),
                min_age_years: 18,
                allowed_vk_ids: vec![crate::VK_ID],
                max_ttl_sec: 300,
                billing: crate::storage::origin_policy::BillingConfig {
                    plan: "sandbox".to_string(),
                    metering_enabled: false,
                },
                enabled: true,
                ..crate::storage::origin_policy::OriginPolicy::default()
            }
        }
        Ok(None) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/challenge] Origin {} not approved", origin);
            return ApiError::Forbidden(Some("Origin not approved".into())).to_response();
        }
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/challenge] Policy lookup failed: {:?}", e);
            return ApiError::Internal(e.into()).to_response();
        }
    };
    phase_timings.push((
        "policy_lookup",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[hosted/challenge] Origin {} policy: min_age_years={}, tenant={}",
        origin,
        policy.min_age_years,
        policy.tenant_id
    );

    // ── Derive proof direction and age threshold ───────────────────────────
    let direction = policy.effective_proof_direction();
    let age_years = policy.age_threshold().map_err(|_msg| {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/challenge] Origin {} policy error: {}",
            origin,
            _msg
        );
        // Misconfigured policy is an operator/data issue, not a user input
        // problem. Map to 503 so the round-trip dispatcher reports it as such.
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;

    let today_epoch_days = u32::try_from(current_timestamp() / 86_400).unwrap_or(u32::MAX);
    let age_days = calculate_exact_days_for_years(age_years);
    let cutoff_days_raw = i32::try_from(today_epoch_days)
        .unwrap_or(i32::MAX)
        .saturating_sub(i32::try_from(age_days).unwrap_or(i32::MAX));
    let cutoff_days = CutoffDays::new(cutoff_days_raw).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Invalid cutoff_days: {}", _e);
        // Derived from server-side timestamp + policy; failure here is internal,
        // never user-driven.
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;

    // ── VK selection ───────────────────────────────────────────────────────
    let verifying_key_id = {
        let first_vk = *policy.allowed_vk_ids.first().ok_or_else(|| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/challenge] No allowed VK IDs configured for origin {}",
                origin
            );
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?;
        VkId::new(first_vk).ok_or_else(|| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/challenge] Invalid VK ID configured for origin {}",
                origin
            );
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?
    };

    // ── Early credit check via ORIGIN_INDEX (zero additional latency) ─────
    // The ORIGIN_INDEX KV entry is needed later for billing entity resolution
    // (organisation_id). Read it once here and reuse the result. When metering
    // is enabled, reject early with 402 if credits are exhausted. This avoids
    // wasting proof-generation work on sessions that will fail at redemption.
    // Per-operation timeout for ORIGIN_INDEX KV read (hosted path).
    let origin_index_json: Option<String> = if let Ok(oi_kv) = env.kv("ORIGIN_INDEX") {
        let oi_kv_clone = oi_kv.clone();
        let origin_clone = origin.clone();
        match crate::utils::timeout::with_timeout(
            "hosted origin_index KV read",
            crate::utils::timeout::KV_READ_TIMEOUT_MS,
            async move { oi_kv_clone.get(&origin_clone).text().await },
        )
        .await
        {
            Ok(result) => result.unwrap_or_default(),
            Err(_) => None,
        }
    } else {
        None
    };

    if let Some(ref json_str) = origin_index_json {
        #[derive(serde::Deserialize)]
        struct OICreditCheck {
            #[serde(default)]
            metering_enabled: Option<bool>,
            #[serde(default)]
            has_credits: Option<bool>,
        }
        match serde_json::from_str::<OICreditCheck>(json_str) {
            Ok(entry) => {
                if entry.metering_enabled == Some(true) && entry.has_credits != Some(true) {
                    // Fail-closed: Some(false) means exhausted, None means not yet
                    // synced. Both reject to prevent unbilled verifications.
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[hosted/challenge] Early credit check failed for origin {}: \
                         metering enabled but has_credits={:?}",
                        origin,
                        entry.has_credits
                    );
                    state
                        .audit_logger
                        .log_suspicious_activity(
                            &client_ip,
                            "hosted_challenge:early_credit_check_failed",
                        )
                        .await;
                    return ApiError::PaymentRequired(None).to_response();
                }
            }
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/challenge] WARNING: Failed to deserialise ORIGIN_INDEX \
                     for origin {}: {}",
                    origin,
                    _e
                );
            }
        }
    }

    // ── Generate challenge crypto ──────────────────────────────────────────
    let phase_start = worker::Date::now().as_millis();

    let challenge_id = Uuid::new_v4();
    let _challenge_id_v4 = UuidV4(challenge_id);
    let short_code = generate_short_code_from_uuid(&challenge_id);

    let nonce = generate_nonce().map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Failed to generate nonce: {:?}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;
    let rp_challenge_bytes = rp_challenge(&origin, &nonce);

    // SECURITY: submit_secret wrapped in Zeroizing. Intermediate array
    // explicitly zeroized after copy into B64Url32.
    let submit_secret_bytes = generate_secure_random(32).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] secure_random failed: {:?}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;
    let mut submit_secret_arr = [0u8; 32];
    submit_secret_arr.copy_from_slice(&submit_secret_bytes);
    let submit_secret = B64Url32::new(submit_secret_arr);
    submit_secret_arr.zeroize();

    let mut rp_challenge_arr = [0u8; 32];
    rp_challenge_arr.copy_from_slice(&rp_challenge_bytes);
    let rp_challenge_b64 = B64Url32::new(rp_challenge_arr);
    rp_challenge_arr.zeroize();

    phase_timings.push((
        "crypto_gen",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    // ── Compute TTL and expiry ─────────────────────────────────────────────
    let ttl_secs = policy
        .max_ttl_sec
        .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
    let now = current_timestamp();
    let expires_at = now.saturating_add(ttl_secs);
    let session_id = Uuid::new_v4().to_string();

    // ── Nonce base64url for storage (DO + session) ─────────────────────────
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    // ── Store nonce in DO (replay protection) ──────────────────────────────
    // AL-008: Pass the worker-level audit logger so the DO's
    // `nonce_replay_detected` (CRITICAL) and any other embedded events reach
    // the audit queue. `request_id` is not currently threaded through this
    // handler; pass empty so the audit pipeline falls back to a generated id.
    let phase_start = worker::Date::now().as_millis();
    let nonce_ok = store_nonce_do(
        env,
        &nonce_b64,
        NONCE_DEDUP_TTL.as_secs(),
        Some(&state.audit_logger),
        &client_ip,
        &origin,
        "",
    )
    .await
    .map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Nonce DO store failed: {:?}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;
    if !nonce_ok {
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "hosted_challenge:nonce_replay")
            .await;
        return ApiError::Conflict(Some("Nonce already used (replay attack detected)".into()))
            .to_response();
    }
    phase_timings.push((
        "nonce_do",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    // ── Persist challenge + short code mapping in parallel ──────────────────
    let client_id = "provii-verifier".to_string();

    let cached = CachedChallenge {
        id: challenge_id,
        short_code: short_code.clone(),
        rp_challenge: rp_challenge_bytes.to_vec(),
        cutoff_days: cutoff_days.get(),
        verifying_key_id: verifying_key_id.get(),
        code_challenge: body.code_challenge.clone(),
        code_challenge_bytes: {
            let decoded = URL_SAFE_NO_PAD
                .decode(body.code_challenge.as_bytes())
                .map_err(|_| {
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[hosted/challenge] Invalid base64url code_challenge");
                    // User-supplied PKCE challenge: 400 BAD_REQUEST with the
                    // structured envelope so the dev sees `field: code_challenge`.
                    WorkerError::from(ApiError::bad_request(
                        "BODY_SCHEMA_INVALID",
                        Some("code_challenge"),
                        "code_challenge must decode to exactly 32 bytes from base64url (no padding)",
                    ))
                })?;
            if decoded.len() != 32 {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[hosted/challenge] code_challenge decoded to {} bytes, expected 32",
                    decoded.len()
                );
                return ApiError::bad_request(
                    "BODY_SCHEMA_INVALID",
                    Some("code_challenge"),
                    "code_challenge must decode to exactly 32 bytes from base64url (no padding)",
                )
                .to_response();
            }
            decoded
        },
        submit_secret: submit_secret_bytes.to_vec(),
        origin: origin.clone(),
        expires_at,
        created_at: now,
        state: ChallengeState::Pending,
        proof_submitted: false,
        verified_at: None,
        proof_verified_at: None,
        issuer_kid: None,
        issuer_vk_bytes: None,
        client_id: Some(client_id.clone()),
        tenant_id: {
            // Billing entity: reuse the ORIGIN_INDEX KV entry fetched during the
            // early credit check. Credits are provisioned under the organisation,
            // not the tenant. Falls back to tenant_id from the origin policy if
            // ORIGIN_INDEX is unavailable.
            let org_id = origin_index_json.as_ref().and_then(|json_str| {
                #[derive(serde::Deserialize)]
                struct OIEntry {
                    organization_id: Option<String>,
                }
                serde_json::from_str::<OIEntry>(json_str)
                    .ok()
                    .and_then(|e| e.organization_id)
            });
            org_id.or_else(|| {
                if policy.tenant_id.is_empty() {
                    None
                } else {
                    Some(policy.tenant_id.clone())
                }
            })
        },
        proof_direction: direction,
    };

    let kv = state.env.kv(KV_CONFIG).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Failed to get KV namespace: {:?}", _e);
        WorkerError::from(ApiError::ServiceUnavailable(None))
    })?;

    let code_key = format!("code:{}", short_code);
    let short_code_builder = kv
        .put(&code_key, challenge_id.to_string())
        .map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/challenge] Failed to create short code mapping builder: {:?}",
                _e
            );
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?
        .expiration_ttl(ttl_secs);

    let phase_start = worker::Date::now().as_millis();
    let (challenge_result, short_code_result) = join!(
        state.challenge_store.put(&challenge_id, &cached),
        short_code_builder.execute()
    );
    phase_timings.push((
        "kv_challenge_writes",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    if let Err(_e) = challenge_result {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Failed to store challenge: {:?}", _e);
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "downstream_failure:challenge_store_write")
            .await;
        return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
    }

    if let Err(_e) = short_code_result {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[hosted/challenge] Failed to store short code mapping: {:?}",
            _e
        );
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "downstream_failure:kv_write")
            .await;
        return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
    }

    // ── Generate PKCE code_verifier ────────────────────────────────────────
    // SECURITY: Wrapped in Zeroizing so the raw entropy is cleared on drop.
    let code_verifier = {
        let mut verifier_bytes = Zeroizing::new(vec![0u8; 32]);
        getrandom::getrandom(&mut verifier_bytes).map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[hosted/challenge] Failed to generate code_verifier: {:?}",
                _e
            );
            WorkerError::from(ApiError::ServiceUnavailable(None))
        })?;
        Zeroizing::new(URL_SAFE_NO_PAD.encode(&*verifier_bytes))
    };

    // ── Build and store session ────────────────────────────────────────────
    let mut session = HostedSession::new(
        session_id.clone(),
        public_key.clone(),
        origin.clone(),
        body.code_challenge.clone(),
        (*code_verifier).clone(),
        challenge_id.to_string(),
        nonce_b64,
        expires_at,
        body.environment.clone(),
    );

    session.proof_direction = direction.as_str().to_string();
    session.verifying_key_id = Some(verifying_key_id.get());

    // SECURITY: Bind session to client IP and User-Agent HMAC hashes.
    let client_ip_hash = Some(hash_with_salt(
        &client_ip,
        &state.ip_hash_salt,
        "provii-ip-v0",
    )?);
    let user_agent_hash = user_agent
        .as_ref()
        .map(|ua| hash_with_salt(ua, &state.ip_hash_salt, "provii-ua-v0"))
        .transpose()?;
    session.set_binding(client_ip_hash, user_agent_hash);

    // Store session (encrypted) and challenge-to-session mapping in parallel.
    let phase_start = worker::Date::now().as_millis();
    let challenge_id_str = challenge_id.to_string();
    let session_fut = store_session_kv(env, &session, session_ttl);
    let mapping_fut = store_challenge_mapping_kv(env, &challenge_id_str, &session_id, session_ttl);
    let (session_result, mapping_result) = join!(session_fut, mapping_fut);
    phase_timings.push((
        "session_store",
        worker::Date::now().as_millis().saturating_sub(phase_start) as f64,
    ));

    // Session write is fatal.
    if let Err(_e) = session_result {
        #[cfg(target_arch = "wasm32")]
        console_log!("[hosted/challenge] Failed to store session: {:?}", _e);
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "downstream_failure:session_kv_write")
            .await;
        return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
    }

    // Mapping write is non-fatal: WebSocket push won't work but polling will.
    if let Err(_e) = mapping_result {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            r#"{{"component":"session_mapping","event":"session_mapping_write_failed","challenge_id":"{}","error":"{}"}}"#,
            redact_challenge_id(&challenge_id.to_string()),
            _e,
        );
    }

    // ── Generate WebSocket ticket ──────────────────────────────────────────
    // SECURITY: WS ticket signed with SESSION_TOKEN_SECRET via HMAC-SHA-256.
    // SC-001: Read from cached AppState (loaded at startup, M-049).
    let ws_url = match state.session_token_secret.as_ref() {
        Some(secret) => {
            let ws_ticket = generate_ws_ticket(&session_id, expires_at, secret)?;
            let ws_base = format!(
                "wss://{}/v1/hosted/ws/{}",
                state
                    .cfg
                    .hosted_base_url
                    .trim_start_matches("https://")
                    .trim_start_matches("http://"),
                session_id
            );
            Some(format!("{}?ticket={}", ws_base, ws_ticket))
        }
        None => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/challenge] SESSION_TOKEN_SECRET not cached at startup");
            None
        }
    };

    // ── Audit logging (fire-and-forget via wait_until) ─────────────────────
    let _redacted_id = redact_challenge_id(&challenge_id.to_string());
    #[cfg(target_arch = "wasm32")]
    console_log!(
        r#"{{"type":"AUDIT_DISPATCHED","service":"provii-verifier","route":"/v1/hosted/challenge","event":"challenge_created","challenge_id":"{}","session_id":"{}"}}"#,
        _redacted_id,
        session_id,
    );

    {
        let audit_state = state.clone();
        let audit_cid = challenge_id.to_string();
        let audit_ip = client_ip.clone();
        let audit_origin = origin.clone();
        let audit_client_id = client_id.clone();
        if let Some(ctx) = crate::take_worker_context() {
            ctx.wait_until(async move {
                let _ = audit_state
                    .audit_logger
                    .log_challenge_created(
                        &audit_cid,
                        &audit_ip,
                        &audit_origin,
                        Some(&audit_client_id),
                    )
                    .await;
            });
        } else {
            #[cfg(target_arch = "wasm32")]
            console_log!("[hosted/challenge] Worker context unavailable, running audit inline");
            let _ = state
                .audit_logger
                .log_challenge_created(
                    &challenge_id.to_string(),
                    &client_ip,
                    &origin,
                    Some(&client_id),
                )
                .await;
        }
    }

    // ── Analytics ──────────────────────────────────────────────────────────
    let analytics = Analytics::new(&state.env);
    analytics.challenge_created(
        "/v1/hosted/challenge",
        &challenge_id.to_string(),
        &origin,
        cutoff_days.get(),
        &state.cfg.environment,
    );

    // ── Structured performance log ─────────────────────────────────────────
    let total_ms = worker::Date::now().as_millis().saturating_sub(start) as f64;
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
    #[cfg(target_arch = "wasm32")]
    console_log!(
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-verifier","route":"/v1/hosted/challenge","status":200,"duration_ms":{:.1},"phases":{{{}}},"slow":{},"slow_phases":"{}"}}"#,
        total_ms,
        _phases_json,
        _is_slow,
        _slow_phases.join(",")
    );

    // ── Assemble response ──────────────────────────────────────────────────
    let short_code_formatted = ShortCode::new(&short_code)
        .map(|sc| sc.display_formatted())
        .unwrap_or_else(|_| short_code.clone());

    let challenge_code = format_short_code(&short_code);

    let hosted_status_url = format!(
        "{}/v1/hosted/status/{}",
        state.cfg.hosted_base_url, session_id
    );

    let response = ChallengeResponse {
        session_id,
        challenge_id: challenge_id.to_string(),
        qr_code_url: format!("{}/challenge/{}", state.cfg.hosted_base_url, challenge_id),
        challenge_code,
        short_code,
        short_code_formatted: Some(short_code_formatted),
        expires_at,
        status: "pending".to_string(),
        rp_challenge: URL_SAFE_NO_PAD.encode(rp_challenge_b64.as_bytes()),
        submit_secret: URL_SAFE_NO_PAD.encode(submit_secret.as_bytes()),
        cutoff_days: cutoff_days.get(),
        verifying_key_id: verifying_key_id.get(),
        status_url: hosted_status_url,
        verify_url: format!(
            "{}/v1/challenge/{}/submit",
            state.cfg.hosted_base_url, challenge_id
        ),
        proof_direction: direction.as_str().to_string(),
        // Server-configured outage failure mode, passed through to the SDK
        // (which caches it so it survives an outage).
        failure_mode: policy.failure_mode.clone(),
        failure_mode_locked: policy.failure_mode_locked,
        csrf_token: None,
        ws_url,
    };

    Ok(Response::from_json(&response)?.with_status(200))
}

/// Format a 12-digit short code into `XXXX-XXXX-XXXX` for display.
///
/// Strips any existing whitespace or dashes, then inserts dashes at positions 4
/// and 8. Returns the cleaned digits unchanged if the input is not exactly 12
/// digits.
fn format_short_code(short_code: &str) -> String {
    let clean: String = short_code.chars().filter(|c| c.is_ascii_digit()).collect();

    if clean.len() == 12 {
        // SAFETY: len == 12 guarantees these ranges are in-bounds and all chars are ASCII digits
        let (a, rest) = clean.split_at(4);
        let (b, c) = rest.split_at(4);
        format!("{}-{}-{}", a, b, c)
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_short_code_12_digits() {
        assert_eq!(format_short_code("123456789012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_with_spaces() {
        assert_eq!(format_short_code("1234 5678 9012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_wrong_length() {
        assert_eq!(format_short_code("12345"), "12345");
    }

    #[test]
    fn test_format_short_code_empty() {
        assert_eq!(format_short_code(""), "");
    }

    #[test]
    fn test_format_short_code_with_existing_dashes() {
        // Dashes are stripped before reformatting
        assert_eq!(format_short_code("1234-5678-9012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_mixed_whitespace_dashes() {
        assert_eq!(format_short_code("12-34 56-78 90-12"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_non_digits_stripped() {
        // Non-digit characters are stripped entirely
        assert_eq!(format_short_code("12a345b6789c012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_11_digits() {
        // Under 12 digits: returned as cleaned digits, no dashes
        assert_eq!(format_short_code("12345678901"), "12345678901");
    }

    #[test]
    fn test_format_short_code_13_digits() {
        // Over 12 digits: returned as cleaned digits, no dashes
        assert_eq!(format_short_code("1234567890123"), "1234567890123");
    }

    #[test]
    fn test_format_short_code_all_zeros() {
        assert_eq!(format_short_code("000000000000"), "0000-0000-0000");
    }

    #[test]
    fn test_format_short_code_all_nines() {
        assert_eq!(format_short_code("999999999999"), "9999-9999-9999");
    }

    #[test]
    fn test_max_origin_length_constant() {
        assert_eq!(MAX_ORIGIN_LENGTH, 2048);
    }

    #[test]
    fn test_default_quota_per_hour_constant() {
        assert_eq!(DEFAULT_QUOTA_PER_HOUR, 500);
    }

    // ── format_short_code additional edge cases ───────────────────────────

    #[test]
    fn test_format_short_code_single_digit() {
        assert_eq!(format_short_code("7"), "7");
    }

    #[test]
    fn test_format_short_code_only_letters_no_digits() {
        // All non-digit characters stripped, result is empty
        assert_eq!(format_short_code("abcdefghijkl"), "");
    }

    #[test]
    fn test_format_short_code_unicode_ignored() {
        // Non-ASCII characters are not ASCII digits, so they get stripped
        assert_eq!(format_short_code("123456789012\u{00E9}"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_tabs_stripped() {
        // Tabs are not digits, stripped by the filter
        assert_eq!(format_short_code("1234\t5678\t9012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_newlines_stripped() {
        assert_eq!(format_short_code("1234\n5678\n9012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_carriage_return_stripped() {
        assert_eq!(format_short_code("1234\r5678\r9012"), "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_only_whitespace() {
        assert_eq!(format_short_code("   \t\n  "), "");
    }

    #[test]
    fn test_format_short_code_very_long_input() {
        // 100 digits: not 12, so returned as-is (cleaned)
        let input = "1".repeat(100);
        let result = format_short_code(&input);
        assert_eq!(result.len(), 100);
        assert!(result.chars().all(|c| c == '1'));
    }

    #[test]
    fn test_format_short_code_exactly_12_with_leading_zeros() {
        assert_eq!(format_short_code("000000000001"), "0000-0000-0001");
    }

    #[test]
    fn test_format_short_code_mixed_letters_yielding_12_digits() {
        // "a1b2c3d4e5f6g7h8i9j0k1l2" has digits: 1 2 3 4 5 6 7 8 9 0 1 2 = 12
        assert_eq!(
            format_short_code("a1b2c3d4e5f6g7h8i9j0k1l2"),
            "1234-5678-9012"
        );
    }

    #[test]
    fn test_format_short_code_special_chars_stripped() {
        assert_eq!(
            format_short_code("!1@2#3$4%5^6&7*8(9)0+1=2"),
            "1234-5678-9012"
        );
    }

    #[test]
    fn test_format_short_code_with_embedded_null() {
        // Null byte (\0) is not an ASCII digit, stripped by the filter.
        // After stripping, "123456789012" remains (12 digits).
        let input = String::from("1234") + "\0" + "5678" + "\0" + "9012";
        let result = format_short_code(&input);
        assert_eq!(result, "1234-5678-9012");
    }

    #[test]
    fn test_format_short_code_sequential_digits() {
        assert_eq!(format_short_code("111122223333"), "1111-2222-3333");
    }

    #[test]
    fn test_format_short_code_alternating_digit_letter() {
        // "1a2b3c4d5e6f7g8h9i0j" -> digits are 1234567890 = 10 digits, not 12
        assert_eq!(format_short_code("1a2b3c4d5e6f7g8h9i0j"), "1234567890");
    }

    // ── OICreditCheck deserialisation and decision logic ───────────────────
    //
    // The handler defines an inner struct `OICreditCheck` for early credit
    // checks. We replicate the struct here to test its deserialisation and
    // the decision matrix without needing the Worker runtime.

    #[derive(serde::Deserialize, Debug)]
    struct OICreditCheck {
        #[serde(default)]
        metering_enabled: Option<bool>,
        #[serde(default)]
        has_credits: Option<bool>,
    }

    /// Helper: returns true when the handler would reject (402).
    /// Mirrors the condition: metering_enabled == Some(true) && has_credits != Some(true)
    fn credit_check_would_reject(entry: &OICreditCheck) -> bool {
        entry.metering_enabled == Some(true) && entry.has_credits != Some(true)
    }

    #[test]
    fn test_credit_check_metering_true_credits_true_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"metering_enabled": true, "has_credits": true}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert!(!credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_metering_true_credits_false_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"metering_enabled": true, "has_credits": false}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert!(credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_metering_true_credits_null_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // has_credits absent => None, which is != Some(true), so reject (fail-closed)
        let json = r#"{"metering_enabled": true}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert_eq!(entry.has_credits, None);
        assert!(credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_metering_false_credits_false_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // metering not enabled: no rejection regardless of credit status
        let json = r#"{"metering_enabled": false, "has_credits": false}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert!(!credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_metering_null_credits_null_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Both absent => metering_enabled is None, not Some(true), so allows
        let json = r#"{}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert_eq!(entry.metering_enabled, None);
        assert_eq!(entry.has_credits, None);
        assert!(!credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_metering_null_credits_false_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"has_credits": false}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert_eq!(entry.metering_enabled, None);
        assert!(!credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_metering_false_credits_null_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"metering_enabled": false}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert!(!credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_extra_fields_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"metering_enabled": true, "has_credits": true, "extra_field": 42}"#;
        let entry: OICreditCheck = serde_json::from_str(json)?;
        assert!(!credit_check_would_reject(&entry));
        Ok(())
    }

    #[test]
    fn test_credit_check_invalid_json_fails() {
        let result = serde_json::from_str::<OICreditCheck>("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_credit_check_wrong_type_for_metering_fails() {
        // metering_enabled should be bool, string should fail
        let result = serde_json::from_str::<OICreditCheck>(r#"{"metering_enabled": "yes"}"#);
        assert!(result.is_err());
    }

    // ── OIEntry deserialisation (organization_id extraction) ───────────────

    #[derive(serde::Deserialize)]
    struct OIEntry {
        organization_id: Option<String>,
    }

    #[test]
    fn test_oi_entry_with_org_id() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"organization_id": "org_abc123"}"#;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert_eq!(entry.organization_id, Some("org_abc123".to_string()));
        Ok(())
    }

    #[test]
    fn test_oi_entry_without_org_id() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{}"#;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert_eq!(entry.organization_id, None);
        Ok(())
    }

    #[test]
    fn test_oi_entry_with_null_org_id() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"organization_id": null}"#;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert_eq!(entry.organization_id, None);
        Ok(())
    }

    #[test]
    fn test_oi_entry_with_empty_org_id() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"organization_id": ""}"#;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert_eq!(entry.organization_id, Some(String::new()));
        Ok(())
    }

    #[test]
    fn test_oi_entry_extra_fields_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"organization_id": "org_x", "metering_enabled": true, "has_credits": true}"#;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert_eq!(entry.organization_id, Some("org_x".to_string()));
        Ok(())
    }

    // ── Tenant ID fallback logic ──────────────────────────────────────────
    //
    // Mirrors the inline logic:
    //   org_id.or_else(|| if tenant_id.is_empty() { None } else { Some(tenant_id) })

    fn resolve_tenant_id(org_id: Option<String>, policy_tenant_id: &str) -> Option<String> {
        org_id.or_else(|| {
            if policy_tenant_id.is_empty() {
                None
            } else {
                Some(policy_tenant_id.to_string())
            }
        })
    }

    #[test]
    fn test_tenant_id_prefers_org_id() {
        let result = resolve_tenant_id(Some("org_123".to_string()), "tenant_456");
        assert_eq!(result, Some("org_123".to_string()));
    }

    #[test]
    fn test_tenant_id_falls_back_to_policy_tenant() {
        let result = resolve_tenant_id(None, "tenant_456");
        assert_eq!(result, Some("tenant_456".to_string()));
    }

    #[test]
    fn test_tenant_id_none_when_both_absent() {
        let result = resolve_tenant_id(None, "");
        assert_eq!(result, None);
    }

    #[test]
    fn test_tenant_id_org_id_wins_over_empty_tenant() {
        let result = resolve_tenant_id(Some("org_x".to_string()), "");
        assert_eq!(result, Some("org_x".to_string()));
    }

    #[test]
    fn test_tenant_id_empty_org_id_is_still_some() {
        // Some("") is truthy for Option, so org_id wins even when empty
        let result = resolve_tenant_id(Some(String::new()), "tenant_456");
        assert_eq!(result, Some(String::new()));
    }

    // ── TTL clamping logic ────────────────────────────────────────────────

    #[test]
    fn test_ttl_clamp_within_range() {
        let ttl: u64 = 120;
        let clamped = ttl.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, 120);
    }

    #[test]
    fn test_ttl_clamp_below_min() {
        let ttl: u64 = 10;
        let clamped = ttl.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_clamp_above_max() {
        let ttl: u64 = 1000;
        let clamped = ttl.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_clamp_at_min_boundary() {
        let clamped = MIN_CHALLENGE_TTL.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_clamp_at_max_boundary() {
        let clamped = MAX_CHALLENGE_TTL.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_clamp_zero() {
        let ttl: u64 = 0;
        let clamped = ttl.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_clamp_u64_max() {
        let clamped = u64::MAX.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(clamped, MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_min_max_challenge_ttl_relationship() {
        // Sanity: MIN < MAX
        assert!(MIN_CHALLENGE_TTL < MAX_CHALLENGE_TTL);
        // MIN must be >= 60 (Cloudflare KV constraint)
        assert!(MIN_CHALLENGE_TTL >= 60);
    }

    // ── Origin length validation ──────────────────────────────────────────

    #[test]
    fn test_origin_at_max_length_is_valid() {
        let origin = "x".repeat(MAX_ORIGIN_LENGTH);
        assert!(origin.len() <= MAX_ORIGIN_LENGTH);
    }

    #[test]
    fn test_origin_exceeding_max_length_is_rejected() {
        let origin = "x".repeat(MAX_ORIGIN_LENGTH + 1);
        assert!(origin.len() > MAX_ORIGIN_LENGTH);
    }

    #[test]
    fn test_origin_one_below_max_is_valid() {
        let origin = "x".repeat(MAX_ORIGIN_LENGTH - 1);
        assert!(origin.len() <= MAX_ORIGIN_LENGTH);
    }

    #[test]
    fn test_empty_origin_within_length() {
        let origin = "";
        assert!(origin.len() <= MAX_ORIGIN_LENGTH);
    }

    // ── Cutoff days arithmetic ────────────────────────────────────────────
    //
    // Mirrors the handler's computation:
    //   today_epoch_days = current_timestamp() / 86_400
    //   age_days = calculate_exact_days_for_years(age_years)
    //   cutoff_days_raw = today_epoch_days as i32 - age_days as i32

    #[test]
    fn test_cutoff_days_computation_18_years() {
        use crate::types::CutoffDays;
        use crate::utils::{calculate_exact_days_for_years, current_timestamp};

        let today_epoch_days = u32::try_from(current_timestamp() / 86_400).unwrap_or(u32::MAX);
        let age_days = calculate_exact_days_for_years(18);
        let cutoff_days_raw = i32::try_from(today_epoch_days)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(age_days).unwrap_or(i32::MAX));
        let cutoff = CutoffDays::new(cutoff_days_raw);
        assert!(cutoff.is_ok());
        // 18 years ago should be a positive epoch day
        assert!(cutoff_days_raw > 0);
    }

    #[test]
    fn test_cutoff_days_computation_13_years() {
        use crate::types::CutoffDays;
        use crate::utils::{calculate_exact_days_for_years, current_timestamp};

        let today_epoch_days = u32::try_from(current_timestamp() / 86_400).unwrap_or(u32::MAX);
        let age_days = calculate_exact_days_for_years(13);
        let cutoff_days_raw = i32::try_from(today_epoch_days)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(age_days).unwrap_or(i32::MAX));
        let cutoff = CutoffDays::new(cutoff_days_raw);
        assert!(cutoff.is_ok());
        // 13 years is less than 18, so cutoff should be greater (more recent)
        let cutoff_18 = {
            let age_18 = calculate_exact_days_for_years(18);
            i32::try_from(today_epoch_days)
                .unwrap_or(i32::MAX)
                .saturating_sub(i32::try_from(age_18).unwrap_or(i32::MAX))
        };
        assert!(cutoff_days_raw > cutoff_18);
    }

    #[test]
    fn test_cutoff_days_computation_21_years() {
        use crate::types::CutoffDays;
        use crate::utils::{calculate_exact_days_for_years, current_timestamp};

        let today_epoch_days = u32::try_from(current_timestamp() / 86_400).unwrap_or(u32::MAX);
        let age_days = calculate_exact_days_for_years(21);
        let cutoff_days_raw = i32::try_from(today_epoch_days)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(age_days).unwrap_or(i32::MAX));
        let cutoff = CutoffDays::new(cutoff_days_raw);
        assert!(cutoff.is_ok());
        assert!(cutoff_days_raw > 0);
    }

    #[test]
    fn test_cutoff_days_zero_years() {
        use crate::types::CutoffDays;
        use crate::utils::{calculate_exact_days_for_years, current_timestamp};

        let today_epoch_days = u32::try_from(current_timestamp() / 86_400).unwrap_or(u32::MAX);
        let age_days = calculate_exact_days_for_years(0);
        let cutoff_days_raw = i32::try_from(today_epoch_days)
            .unwrap_or(i32::MAX)
            .saturating_sub(i32::try_from(age_days).unwrap_or(i32::MAX));
        // 0 years => cutoff_days_raw should be approximately today_epoch_days
        assert_eq!(cutoff_days_raw, today_epoch_days as i32);
        let cutoff = CutoffDays::new(cutoff_days_raw);
        assert!(cutoff.is_ok());
    }

    // ── Expires computation ───────────────────────────────────────────────

    #[test]
    fn test_expires_at_saturating_add() {
        let now: u64 = 1_700_000_000;
        let ttl: u64 = 300;
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, 1_700_000_300);
    }

    #[test]
    fn test_expires_at_saturating_add_overflow() {
        let now = u64::MAX;
        let ttl: u64 = 300;
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, u64::MAX);
    }

    // ── Code challenge base64url decode length validation ─────────────────
    //
    // Mirrors the handler logic that decodes code_challenge and checks 32 bytes.

    #[test]
    fn test_code_challenge_valid_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        // 32 bytes of zeros, base64url encoded without padding = 43 chars
        let bytes = [0u8; 32];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_eq!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_code_challenge_wrong_length_31_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [0u8; 31];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_ne!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_code_challenge_wrong_length_33_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [0u8; 33];
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
        assert_ne!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_code_challenge_invalid_base64() {
        let result = URL_SAFE_NO_PAD.decode("!!!not-valid-base64!!!".as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_code_challenge_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = URL_SAFE_NO_PAD.decode("".as_bytes())?;
        assert_eq!(decoded.len(), 0);
        assert_ne!(decoded.len(), 32);
        Ok(())
    }

    // ── NONCE_DEDUP_TTL constant validation ───────────────────────────────

    #[test]
    fn test_nonce_dedup_ttl_is_300_seconds() {
        assert_eq!(NONCE_DEDUP_TTL.as_secs(), 300);
    }

    #[test]
    fn test_nonce_dedup_ttl_matches_max_challenge_ttl() {
        // Nonce dedup should align with max challenge lifetime
        assert_eq!(NONCE_DEDUP_TTL.as_secs(), MAX_CHALLENGE_TTL);
    }

    // ── ShortCode + display_formatted (used at response assembly) ─────────

    #[test]
    fn test_short_code_new_valid_12_digits() -> Result<(), String> {
        let sc = ShortCode::new("123456789012")?;
        assert_eq!(sc.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_short_code_display_formatted() -> Result<(), String> {
        let sc = ShortCode::new("123456789012")?;
        assert_eq!(sc.display_formatted(), "1234 5678 9012");
        Ok(())
    }

    #[test]
    fn test_short_code_new_rejects_11_digits() {
        let result = ShortCode::new("12345678901");
        assert!(result.is_err());
    }

    #[test]
    fn test_short_code_new_rejects_13_digits() {
        let result = ShortCode::new("1234567890123");
        assert!(result.is_err());
    }

    #[test]
    fn test_short_code_new_rejects_letters() {
        let result = ShortCode::new("12345678901a");
        assert!(result.is_err());
    }

    #[test]
    fn test_short_code_new_strips_whitespace() -> Result<(), String> {
        let sc = ShortCode::new("1234 5678 9012")?;
        assert_eq!(sc.as_str(), "123456789012");
        assert_eq!(sc.display_formatted(), "1234 5678 9012");
        Ok(())
    }

    #[test]
    fn test_short_code_fallback_on_error() {
        // Mirrors the handler: ShortCode::new(&short_code).map(|sc| sc.display_formatted()).unwrap_or_else(|_| short_code.clone())
        let code = "12345"; // invalid, not 12 digits
        let formatted = ShortCode::new(code)
            .map(|sc| sc.display_formatted())
            .unwrap_or_else(|_| code.to_string());
        assert_eq!(formatted, "12345");
    }

    #[test]
    fn test_short_code_all_zeros_formatted() -> Result<(), String> {
        let sc = ShortCode::new("000000000000")?;
        assert_eq!(sc.display_formatted(), "0000 0000 0000");
        Ok(())
    }

    // ── Credit check combined with OIEntry (full pipeline) ────────────────

    #[test]
    fn test_credit_and_org_from_same_json() -> Result<(), Box<dyn std::error::Error>> {
        // The handler parses the same JSON string twice: once for credit check,
        // once for org_id extraction. Verify both work on the same payload.
        let json =
            r#"{"metering_enabled": true, "has_credits": true, "organization_id": "org_billing"}"#;
        let credit: OICreditCheck = serde_json::from_str(json)?;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert!(!credit_check_would_reject(&credit));
        assert_eq!(entry.organization_id, Some("org_billing".to_string()));
        Ok(())
    }

    #[test]
    fn test_credit_rejected_but_org_still_parses() -> Result<(), Box<dyn std::error::Error>> {
        let json =
            r#"{"metering_enabled": true, "has_credits": false, "organization_id": "org_x"}"#;
        let credit: OICreditCheck = serde_json::from_str(json)?;
        let entry: OIEntry = serde_json::from_str(json)?;
        assert!(credit_check_would_reject(&credit));
        // Even though credits are exhausted, the org_id still parses
        assert_eq!(entry.organization_id, Some("org_x".to_string()));
        Ok(())
    }

    // ── Sandbox key detection logic ───────────────────────────────────────
    //
    // Mirrors: state.cfg.environment == "sandbox" && public_key.starts_with("pk_test_")

    fn is_sandbox_test_key(environment: &str, public_key: &str) -> bool {
        environment == "sandbox" && public_key.starts_with("pk_test_")
    }

    #[test]
    fn test_sandbox_test_key_detected() {
        assert!(is_sandbox_test_key("sandbox", "pk_test_abc123"));
    }

    #[test]
    fn test_production_test_key_not_sandbox() {
        assert!(!is_sandbox_test_key("production", "pk_test_abc123"));
    }

    #[test]
    fn test_sandbox_live_key_not_test() {
        assert!(!is_sandbox_test_key("sandbox", "pk_live_abc123"));
    }

    #[test]
    fn test_production_live_key_not_test() {
        assert!(!is_sandbox_test_key("production", "pk_live_abc123"));
    }

    #[test]
    fn test_empty_environment_not_sandbox() {
        assert!(!is_sandbox_test_key("", "pk_test_abc123"));
    }

    #[test]
    fn test_empty_key_not_test() {
        assert!(!is_sandbox_test_key("sandbox", ""));
    }

    // ── URL construction patterns (response assembly) ─────────────────────

    #[test]
    fn test_qr_code_url_format() {
        let base_url = "https://verify.example.com";
        let challenge_id = "550e8400-e29b-41d4-a716-446655440000";
        let url = format!("{}/challenge/{}", base_url, challenge_id);
        assert_eq!(
            url,
            "https://verify.example.com/challenge/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_status_url_format() {
        let base_url = "https://verify.example.com";
        let session_id = "session-uuid-here";
        let url = format!("{}/v1/hosted/status/{}", base_url, session_id);
        assert_eq!(
            url,
            "https://verify.example.com/v1/hosted/status/session-uuid-here"
        );
    }

    #[test]
    fn test_verify_url_format() {
        let base_url = "https://verify.example.com";
        let challenge_id = "challenge-uuid-here";
        let url = format!("{}/v1/challenge/{}/submit", base_url, challenge_id);
        assert_eq!(
            url,
            "https://verify.example.com/v1/challenge/challenge-uuid-here/submit"
        );
    }

    #[test]
    fn test_ws_url_format_https_stripped() {
        let hosted_base_url = "https://verify.example.com";
        let session_id = "sess-123";
        let ws_base = format!(
            "wss://{}/v1/hosted/ws/{}",
            hosted_base_url
                .trim_start_matches("https://")
                .trim_start_matches("http://"),
            session_id
        );
        assert_eq!(ws_base, "wss://verify.example.com/v1/hosted/ws/sess-123");
    }

    #[test]
    fn test_ws_url_format_http_stripped() {
        let hosted_base_url = "http://localhost:8787";
        let session_id = "sess-456";
        let ws_base = format!(
            "wss://{}/v1/hosted/ws/{}",
            hosted_base_url
                .trim_start_matches("https://")
                .trim_start_matches("http://"),
            session_id
        );
        assert_eq!(ws_base, "wss://localhost:8787/v1/hosted/ws/sess-456");
    }

    #[test]
    fn test_ws_url_with_ticket_appended() {
        let ws_base = "wss://verify.example.com/v1/hosted/ws/sess-123";
        let ticket = "some-ticket-value";
        let full = format!("{}?ticket={}", ws_base, ticket);
        assert_eq!(
            full,
            "wss://verify.example.com/v1/hosted/ws/sess-123?ticket=some-ticket-value"
        );
    }

    // ── Phase timing performance logging helpers ──────────────────────────

    #[test]
    fn test_phase_timings_json_format() {
        let phase_timings: Vec<(&str, f64)> = vec![("validation", 1.5), ("auth_rate_limit", 23.7)];
        let phases_json = phase_timings
            .iter()
            .map(|(name, ms)| format!(r#""{}":{:.1}"#, name, ms))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(phases_json, r#""validation":1.5,"auth_rate_limit":23.7"#);
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
    fn test_slow_phases_detection() {
        let phase_timings: Vec<(&str, f64)> = vec![
            ("validation", 10.0),
            ("auth_rate_limit", 75.0),
            ("policy_lookup", 3.2),
            ("nonce_do", 120.0),
        ];
        let slow_phases: Vec<&str> = phase_timings
            .iter()
            .filter(|(_, ms)| *ms > 50.0)
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(slow_phases, vec!["auth_rate_limit", "nonce_do"]);
    }

    #[test]
    fn test_slow_phases_none_slow() {
        let phase_timings: Vec<(&str, f64)> = vec![("validation", 10.0), ("crypto_gen", 5.0)];
        let slow_phases: Vec<&str> = phase_timings
            .iter()
            .filter(|(_, ms)| *ms > 50.0)
            .map(|(name, _)| *name)
            .collect();
        assert!(slow_phases.is_empty());
    }

    #[test]
    fn test_is_slow_threshold() {
        let total_ms: f64 = 501.0;
        let is_slow = total_ms > 500.0;
        assert!(is_slow);

        let total_ms: f64 = 500.0;
        let is_slow = total_ms > 500.0;
        assert!(!is_slow);

        let total_ms: f64 = 499.9;
        let is_slow = total_ms > 500.0;
        assert!(!is_slow);
    }

    // ── B64Url32 construction and encoding ────────────────────────────────

    #[test]
    fn test_b64url32_roundtrip() {
        let bytes = [42u8; 32];
        let wrapper = B64Url32::new(bytes);
        assert_eq!(wrapper.as_bytes(), &bytes);
    }

    #[test]
    fn test_b64url32_encode_deterministic() {
        let bytes = [1u8; 32];
        let encoded1 = URL_SAFE_NO_PAD.encode(B64Url32::new(bytes).as_bytes());
        let encoded2 = URL_SAFE_NO_PAD.encode(B64Url32::new(bytes).as_bytes());
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_b64url32_debug_redacted() {
        let wrapper = B64Url32::new([0u8; 32]);
        let debug_str = format!("{:?}", wrapper);
        assert_eq!(debug_str, "B64Url32(***redacted***)");
        assert!(!debug_str.contains("0"));
    }

    #[test]
    fn test_b64url32_display_redacted() {
        let wrapper = B64Url32::new([0u8; 32]);
        let display_str = format!("{}", wrapper);
        assert_eq!(display_str, "[REDACTED]");
    }

    // ── Code key format ───────────────────────────────────────────────────

    #[test]
    fn test_code_key_format() {
        let short_code = "123456789012";
        let code_key = format!("code:{}", short_code);
        assert_eq!(code_key, "code:123456789012");
    }

    // ── Redact challenge ID (used in logging) ─────────────────────────────

    #[test]
    fn test_redact_challenge_id_uuid() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "550e8400");
    }

    #[test]
    fn test_redact_challenge_id_short() {
        let id = "abc";
        let redacted = redact_challenge_id(id);
        assert_eq!(redacted, "abc");
    }

    #[test]
    fn test_redact_challenge_id_empty() {
        let redacted = redact_challenge_id("");
        assert_eq!(redacted, "");
    }

    #[test]
    fn test_redact_challenge_id_exactly_8_chars() {
        let redacted = redact_challenge_id("12345678");
        assert_eq!(redacted, "12345678");
    }

    #[test]
    fn test_redact_challenge_id_9_chars_truncated() {
        let redacted = redact_challenge_id("123456789");
        assert_eq!(redacted, "12345678");
    }
}
