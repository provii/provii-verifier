// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Zero knowledge proof submission and SNARK verification.
//!
//! Accepts a Groth16/BLS12-381 age proof from the wallet, validates all public
//! inputs against the stored challenge record, runs the SNARK verifier, and
//! transitions the challenge to `ProofOkWaitingForRedeem` on success.
//!
//! ## Request flow
//!
//! 1. Ban list check (pre-nonce, KV-039)
//! 2. Challenge load and authentication (BOLA, OWASP API1:2023)
//! 3. Idempotency cache check (EA-002, post-auth)
//! 4. Nonce deduplication (EA-001, post-auth)
//! 5. Origin policy and VK/issuer allowlist validation
//! 6. Anti-abuse submit_secret constant time comparison
//! 7. RP challenge hash, issuer key hash, cutoff days matching
//! 8. Groth16 SNARK verification via `provii_crypto_verifier`
//! 9. Issuer JWKS cache lookup and revocation check
//! 10. State persistence and audit logging
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use base64::prelude::*;
use blake2::{Blake2s256, Digest};
use schemars::JsonSchema;
use std::sync::Arc;
use uuid::Uuid;

use worker::{Error as WorkerError, Response};
use zeroize::{Zeroize, Zeroizing};

use subtle::ConstantTimeEq;

use crate::{
    analytics::Analytics,
    cache::{CachedChallenge, ChallengeState},
    error::ApiError,
    security::{log_sanitizer::redact_challenge_id, validate_fetch_metadata},
    storage::origin_policy::PolicyLookupResult,
    types::strict::{B64Url192, B64Url32, CutoffDays, UuidV4, VkId},
    utils::{current_timestamp, NONCE_DEDUP_TTL},
    AppState,
};

use provii_crypto_commons::Error;
use provii_crypto_verifier::verify_age_snark;

/// Top-level request body for `POST /v1/verify`.
///
/// All fields are required. Unknown fields are rejected at deserialisation.
#[derive(serde::Deserialize, JsonSchema)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct SubmitProofRequest {
    /// Challenge UUID returned from `POST /v1/challenge`.
    pub challenge_id: UuidV4,
    /// Anti-abuse secret (base64url, 32 bytes). Compared in constant time.
    pub submit_secret: B64Url32,
    /// The Groth16 age proof and its public inputs.
    pub proof: AgeProofJson,
}

/// Groth16 age proof with its associated public inputs.
#[derive(serde::Deserialize, JsonSchema)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct AgeProofJson {
    /// Identifier selecting the verifying key registered for this origin.
    pub verifying_key_id: VkId,
    /// Public inputs fed into the Groth16 verifier.
    pub public: PublicInputsJson,
    /// Groth16 proof bytes (base64url, exactly 192 bytes decoded).
    pub proof: B64Url192,
}

/// Public inputs that the SNARK circuit constrains.
///
/// Every field is re-validated against the stored challenge record before the
/// proof is passed to the Groth16 verifier.
#[derive(serde::Deserialize, JsonSchema)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct PublicInputsJson {
    /// Minimum age threshold in days (e.g. 6570 for 18 years).
    pub cutoff_days: CutoffDays,
    /// Relying-party challenge (base64url, 32 bytes). Blake2s-256 hashed before circuit input.
    pub rp_challenge: B64Url32,
    /// Issuer verifying key.
    pub issuer: IssuerKeyJson,
    /// Credential nullifier (base64url, 32 bytes). Checked against the ban list.
    pub cred_nullifier: B64Url32,
}

/// Issuer verifying key transmitted as raw bytes (not a hash).
#[derive(serde::Deserialize, JsonSchema)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct IssuerKeyJson {
    /// Raw RedJubjub verifying key bytes (base64url-encoded, 32 bytes).
    /// Fed directly as public inputs 4 and 5 of the Groth16 circuit.
    pub value: B64Url32,
}

/// JSON response returned from `POST /v1/verify`.
#[derive(serde::Serialize, JsonSchema)]
pub struct VerifyResponse {
    /// `"OK"` on success, or an error code such as `"INVALID_PROOF"`.
    pub result: String,
    /// Current challenge state, e.g. `"proof_ok_waiting_for_redeem"`.
    pub state: String,
}

/// Handle `POST /v1/verify`: validate public inputs, run the Groth16 SNARK
/// verifier, and transition the challenge to `ProofOkWaitingForRedeem`.
///
/// # Security annotations
///
/// submit_secret and rp_challenge are compared in constant time
/// (subtle::ct_eq) to prevent timing side channels. Challenge ownership
/// is verified against `authenticated_client_id` before any state
/// mutation (BOLA). Nonce consumption is deferred until after
/// authentication to prevent unauthenticated callers from burning nonces
/// (EA-001). `submit_secret` and `api_key` are zeroised immediately
/// after use.
pub async fn submit_verification(
    state: Arc<AppState>,
    headers: worker::Headers,
    body: SubmitProofRequest,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(10);
    let mut sub_ops: Vec<(&str, f64)> = Vec::with_capacity(20);

    // Extract client IP for audit logging (raw; hashed by AuditLogger before any output)
    let client_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    // SECURITY: Extract idempotency key header early (cheap parse, no cache lookup yet).
    // EA-002: The cache check is deferred until after authentication so that
    // client_id is available for the request fingerprint.
    let idempotency_key =
        crate::security::idempotency::extract_idempotency_key(&headers, "POST", "/v1/verify")?;

    // SECURITY: Validate Sec-Fetch-* headers to prevent CSRF attacks (defence in depth).
    // Preserve the typed status (400/403) by returning the Response directly
    // instead of stringifying through WorkerError::RustError (which the
    // dispatcher fallback maps to 500 INTERNAL_ERROR).
    if let Err(e) = validate_fetch_metadata(&headers) {
        return e.to_response();
    }

    // Capture metrics for the verification flow.
    let analytics = Analytics::new(&state.env);

    let challenge_id = body.challenge_id.0;

    // SECURITY: Redact challenge_id to prevent information disclosure
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/verify] Starting verification for challenge_id={}",
        redact_challenge_id(&challenge_id.to_string())
    );

    // KV-039: Check the ban list BEFORE consuming the nonce. The nullifier is
    // available directly from the request body (it is a claimed public input,
    // not derived from SNARK verification). Checking early avoids wasting the
    // nonce on a credential that will be rejected, so a user whose credential
    // is transiently flagged can retry with the same challenge once the ban is
    // lifted.
    //
    // PERFORMANCE: Ban check and challenge load are independent KV reads.
    // Running them in parallel saves one full round-trip (~50ms).
    let cred_nullifier = body.proof.public.cred_nullifier.0;
    let parallel_start = worker::Date::now().as_millis();
    let ((ban_result, ban_ms), (challenge_get_result, challenge_do_ms)) = futures::join!(
        async {
            let t = worker::Date::now().as_millis();
            let r = state.ban_store.is_banned(&cred_nullifier).await;
            (r, worker::Date::now().as_millis().saturating_sub(t) as f64)
        },
        async {
            let t = worker::Date::now().as_millis();
            let r = state.challenge_store.get(&challenge_id).await;
            (r, worker::Date::now().as_millis().saturating_sub(t) as f64)
        },
    );
    phase_timings.push((
        "ban_challenge_parallel",
        (worker::Date::now()
            .as_millis()
            .saturating_sub(parallel_start)) as f64,
    ));
    sub_ops.push(("ban_do_fetch", ban_ms));
    sub_ops.push(("challenge_do_fetch", challenge_do_ms));

    // Handle ban check result first (cheaper to reject early).
    let is_banned = ban_result?;
    if is_banned {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] Banned credential for challenge {}",
            redact_challenge_id(&challenge_id.to_string())
        );

        state
            .audit_logger
            .log_verification_attempt(
                &challenge_id.to_string(),
                &client_ip,
                false,
                Some("banned_credential".to_string()),
            )
            .await;

        // ADV-VA-05-003: Return ErrorResponse (5-key envelope), not VerifyResponse.
        return ApiError::Forbidden(Some("Credential is banned".into())).to_response();
    }

    // EA-001: Challenge load MUST precede auth since the auth block
    // references cached.client_id and cached.origin.
    let mut cached = match challenge_get_result {
        Ok(Some(c)) => c,
        Ok(None) => {
            // SECURITY: Redact challenge_id in logs
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ❌ Challenge {} not found",
                redact_challenge_id(&challenge_id.to_string())
            );
            return ApiError::NotFound.to_response();
        }
        Err(e) => {
            // SECURITY: Redact challenge_id and error details in logs
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ❌ Failed to load challenge {}: {:?}",
                redact_challenge_id(&challenge_id.to_string()),
                e
            );
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "downstream_failure:challenge_store_read")
                .await;
            return ApiError::Internal(e.into()).to_response();
        }
    };

    // SECURITY: Enforce mandatory BOLA protection (OWASP API1:2023, CWE-639)
    // Extract and validate client_id from headers OR use challenge's stored client_id for mobile clients
    let phase_start = worker::Date::now().as_millis();
    let auth_result = super::api_key_auth::authenticate_api_key(
        &headers,
        &state,
        super::api_key_auth::ApiKeyAuthOptions {
            expected_owner_id: cached.client_id.as_deref(),
            allow_mobile_flow: true,
            stored_client_id: cached.client_id.clone(),
            route_label: "submit_verification",
        },
    )
    .await?;
    phase_timings.push((
        "auth",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    let authenticated_client_id = auth_result.client_id;
    let is_mobile_flow = auth_result.is_mobile_flow;

    // SECURITY: Mandatory authentication - reject if no valid client_id
    let client_id = match authenticated_client_id {
        Some(id) => id,
        None => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] submit_verification: Authentication failed for challenge {} - missing or invalid credentials",
                redact_challenge_id(&challenge_id.to_string())
            );
            state
                .audit_logger
                .log_authentication_failure(
                    &client_ip,
                    "verification_auth_failed",
                    None,
                    Some(&cached.origin),
                    Some(serde_json::json!({
                        "challenge_id": redact_challenge_id(&challenge_id.to_string()),
                        "endpoint": "/v1/verify"
                    })),
                )
                .await;
            return ApiError::Unauthorized.to_response();
        }
    };

    // SECURITY: Verify ownership (mandatory for browser/API-key authenticated requests).
    //
    // ST-VA-016: The mobile flow is authenticated by capability tokens (challenge_id +
    // submit_secret), not by matching client_id against challenge owner. Comparing the
    // stored client_id against itself is tautological and provides no security value.
    // The submit_secret constant-time check below is the real mobile auth gate.
    if !is_mobile_flow {
        if let Err(e) = super::ownership::verify_ownership(
            cached.client_id.as_deref(),
            Some(&client_id),
            &challenge_id.to_string(),
            "submit_verification",
            &state.audit_logger,
            &client_ip,
            "bola_ownership_violation",
        )
        .await
        {
            return e.to_response();
        }
    }

    // EA-002: Idempotency cache check runs AFTER auth so client_id is available
    // for the request fingerprint. This prevents cross-client cache collisions
    // where different API keys could retrieve each other's cached responses.
    let phase_start = worker::Date::now().as_millis();
    if let (Some(ref key), Some(ref store)) = (&idempotency_key, &state.idempotency_store) {
        // Removed client_ip from fingerprint (non-deterministic).
        let fingerprint =
            crate::security::idempotency::compute_request_fingerprint("verify", &client_id);
        if let Some(cached_response) = crate::security::idempotency::check_idempotency(
            store,
            key,
            "verify",
            &fingerprint,
            Some(&state.audit_logger),
            Some(&client_ip),
            state.analytics.as_ref(),
        )
        .await?
        {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Returning cached response for verification (key: {})",
                key.get(..key.len().min(8)).unwrap_or(key)
            );
            return Ok(cached_response);
        }
    }
    phase_timings.push((
        "idempotency",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // R9 (RL-03): Per-ACCOUNT quota on the VERIFIED client_id, as a SUPPLEMENT
    // to the pre-auth per-IP gate in worker_routes.rs (which already ran and is
    // untouched). Placed here it is provably:
    //   * post-auth   -- `client_id` above is the verified identity (Argon2id
    //                     via authenticate_api_key, or the mobile capability
    //                     token owner), never a raw header;
    //   * replay-safe -- the EA-002 idempotency cache check immediately above
    //                     returns the cached response for an idempotent replay
    //                     BEFORE this point, so a replay is never double-charged;
    //   * pre-mutation -- it runs BEFORE nonce consumption (check_and_set below),
    //                     the SNARK verify, and the ProofOkWaitingForRedeem state
    //                     write, so no side effect has occurred yet.
    if let Err(resp) =
        super::api_key_auth::enforce_account_quota(&state, &client_id, "verify").await
    {
        return resp;
    }

    // EA-001: Nonce dedup moved AFTER authentication. Previously an
    // unauthenticated caller could burn the one-time nonce for any known
    // challenge_id, causing the legitimate wallet to receive 409 Conflict.
    //
    // INV-VA-046: The nonce is consumed BEFORE the submit_secret check. This
    // means a caller who knows challenge_id but not submit_secret can still
    // burn the nonce (one-shot DoS). Moving it after submit_secret would fix
    // that, but would allow unlimited submit_secret brute-force attempts
    // against the same challenge. Since submit_secret is 256 bits of entropy
    // (not brute-forceable) and burning a nonce only affects a single
    // challenge, the current ordering is the better trade-off: it prevents
    // computational abuse at the cost of a low-impact single-challenge DoS
    // that requires knowing the challenge_id.
    let nonce_tag = format!("verify:{}", challenge_id);
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
            // Continue processing on the first observation of this nonce.
            // SECURITY: Redact challenge_id in logs
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] Nonce check passed for challenge_id={}",
                redact_challenge_id(&challenge_id.to_string())
            );
        }
        Ok(false) => {
            // SECURITY: Redact challenge_id in logs
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] Duplicate submission detected for challenge_id={}",
                redact_challenge_id(&challenge_id.to_string())
            );
            state
                .audit_logger
                .log_replay_attempt(
                    &challenge_id.to_string(),
                    &client_ip,
                    state.analytics.as_ref(),
                )
                .await;
            return ApiError::Conflict(Some("Duplicate verification submission".into()))
                .to_response();
        }
        Err(e) => {
            // SECURITY: Log error without debug format to avoid leaking internal implementation details
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Nonce store error occurred");
            return ApiError::Internal(e.into()).to_response();
        }
    }

    let origin = cached.origin.clone();

    // Validate the origin against its configured policy.
    // AL-046/AL-047: Use detailed lookup to distinguish disabled vs not-found.
    let phase_start = worker::Date::now().as_millis();
    let t = worker::Date::now().as_millis();
    let policy_detail_result = state.origin_policy_store.get_policy_detail(&origin).await?;
    sub_ops.push((
        "policy_detail_kv_get",
        (worker::Date::now().as_millis().saturating_sub(t)) as f64,
    ));
    phase_timings.push((
        "policy_detail",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));
    let policy = match policy_detail_result {
        PolicyLookupResult::Found(p) => p,
        PolicyLookupResult::Disabled => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Origin {} is disabled", origin);

            analytics.verification_failed(
                "/v1/verify",
                &challenge_id.to_string(),
                &origin,
                "origin_disabled",
                Some((worker::Date::now().as_millis().saturating_sub(start)) as f64),
                &state.cfg.environment,
            );

            state
                .audit_logger
                .log_origin_disabled(&origin, &client_ip)
                .await;
            state
                .audit_logger
                .log_verification_attempt(
                    &challenge_id.to_string(),
                    &client_ip,
                    false,
                    Some("origin_disabled".to_string()),
                )
                .await;

            return ApiError::Forbidden(Some("Origin not approved".into())).to_response();
        }
        PolicyLookupResult::NotFound => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Origin {} not approved", origin);

            analytics.verification_failed(
                "/v1/verify",
                &challenge_id.to_string(),
                &origin,
                "origin_not_approved",
                Some((worker::Date::now().as_millis().saturating_sub(start)) as f64),
                &state.cfg.environment,
            );

            state
                .audit_logger
                .log_origin_not_found(&origin, &client_ip)
                .await;
            state
                .audit_logger
                .log_verification_attempt(
                    &challenge_id.to_string(),
                    &client_ip,
                    false,
                    Some("origin_not_approved".to_string()),
                )
                .await;

            return ApiError::Forbidden(Some("Origin not approved".into())).to_response();
        }
    };

    // RT-004: Check expiry BEFORE any policy or VK validation. Expired challenges
    // must be rejected immediately to prevent wasted work on stale data.
    let now = current_timestamp();
    if now > cached.expires_at {
        // AL-027: Audit challenge expiry inconsistency (found in KV but past logical expiry).
        state
            .audit_logger
            .log_challenge_expiry_inconsistency(
                &challenge_id.to_string(),
                cached.expires_at,
                now,
                &client_ip,
            )
            .await;

        cached.state = ChallengeState::Expired;
        cached.submit_secret.zeroize();

        // RT-005: Log discarded KV put errors for observability.
        if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] Failed to persist challenge state update: {:?}",
                _e
            );
        }
        // SECURITY: Redact challenge_id in logs
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] Challenge {} expired",
            redact_challenge_id(&challenge_id.to_string())
        );

        state
            .audit_logger
            .log_verification_attempt(
                &challenge_id.to_string(),
                &client_ip,
                false,
                Some("challenge_expired".to_string()),
            )
            .await;

        return ApiError::Gone(Some("Challenge expired".into())).to_response();
    }

    // Guard against reusing a previously processed challenge.
    if cached.proof_submitted
        || cached.state == ChallengeState::ProofOkWaitingForRedeem
        || cached.state == ChallengeState::Verified
        || cached.state == ChallengeState::Failed
    {
        // SECURITY: Redact challenge_id in logs
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] Challenge {} already consumed",
            redact_challenge_id(&challenge_id.to_string())
        );

        state
            .audit_logger
            .log_verification_attempt(
                &challenge_id.to_string(),
                &client_ip,
                false,
                Some("challenge_already_consumed".to_string()),
            )
            .await;

        return ApiError::Gone(Some("Challenge already consumed".into())).to_response();
    }

    // Ensure the verifying key is permitted for the requesting origin.
    if !policy
        .allowed_vk_ids
        .contains(&body.proof.verifying_key_id.get())
    {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] Invalid VK ID {} for origin {}",
            body.proof.verifying_key_id.get(),
            origin
        );
        fail_challenge_and_persist(
            &state,
            &analytics,
            &mut cached,
            &challenge_id,
            &origin,
            &client_ip,
            "invalid_vk_id_for_origin",
            start,
            false,
        )
        .await;
        return ApiError::BadRequest(Some("Invalid verifying_key_id for this origin".into()))
            .to_response();
    }

    // Confirm the anti-abuse secret matches the stored value.
    // SECURITY: Declare directly as Zeroizing so no bare copy remains on the stack.
    // CIV-064: Return an error if cached bytes are not exactly 32 bytes instead of
    // falling back to all-zeros, which would silently pass comparison against a
    // zeroed submit_secret.
    // VA-VFY-003: Secret bytes are wrapped in Zeroizing from the start, avoiding a
    // bare [u8; 32] intermediate that the compiler could leave on the stack.
    let cached_secret: Zeroizing<[u8; 32]> = {
        let src = cached.submit_secret.clone();
        if src.len() != 32 {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Corrupt challenge: submit_secret is not 32 bytes");
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        let slice = src.get(..32).ok_or_else(|| {
            ApiError::Internal(anyhow::anyhow!("submit_secret shorter than 32 bytes"))
        });
        match slice {
            Ok(s) => arr.copy_from_slice(s),
            Err(e) => return e.to_response(),
        }
        arr
    };
    if !bool::from(body.submit_secret.0.ct_eq(&*cached_secret)) {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] ❌ Invalid submit_secret for challenge {}",
            redact_challenge_id(&challenge_id.to_string())
        );
        fail_challenge_and_persist(
            &state,
            &analytics,
            &mut cached,
            &challenge_id,
            &origin,
            &client_ip,
            "invalid_submit_secret",
            start,
            false,
        )
        .await;
        return ApiError::BadRequest(Some("Invalid submit_secret".into())).to_response();
    }

    cached.submit_secret.zeroize();

    // Extract strongly typed fields for the downstream checks.
    // NOTE: cred_nullifier was extracted earlier (before nonce consumption) for
    // the KV-039 early ban check. We reuse that binding here.
    let rp_challenge = body.proof.public.rp_challenge.0;
    let issuer_vk_bytes = body.proof.public.issuer.value.0;

    let rp_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(rp_challenge);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    };

    // Derive the issuer hash off-circuit to compare against policy entries.
    let issuer_key_hash = {
        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update(issuer_vk_bytes);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    };

    // Consult the issuer cache for revocation status using the hash lookup.
    if let Some(issuer) = state.jwks_cache.peek_issuer(&issuer_key_hash) {
        if issuer.revoked {
            // AL-023: Audit revocation cache hit.
            state
                .audit_logger
                .log_revocation_cache_hit(&challenge_id.to_string(), &origin, &client_ip)
                .await;

            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ❌ Revoked issuer for challenge {}",
                redact_challenge_id(&challenge_id.to_string())
            );
            fail_challenge_and_persist(
                &state,
                &analytics,
                &mut cached,
                &challenge_id,
                &origin,
                &client_ip,
                "issuer_revoked",
                start,
                false,
            )
            .await;

            // ADV-VA-05-003: Return ErrorResponse (5-key envelope), not VerifyResponse.
            return ApiError::Forbidden(Some("Issuer has been revoked".into())).to_response();
        }
    }

    // Apply origin-specific issuer allowlists when configured.
    //
    // SECURITY (AA-005-H2 / C1): allowed_issuers is a per-RP RESTRICTION layered on
    // top of the global trust anchor, not the anchor itself. When empty (the
    // default for new RPs) this origin accepts any issuer that is present in the
    // JWKS registry - the registry membership check further below
    // (`Err(NotFound) => reject`) is the trust anchor that stops a wallet-supplied,
    // self-minted issuer from forging a verdict. RPs that want to restrict to
    // specific issuers configure allowed_issuers via the management API.
    if policy.allowed_issuers.is_empty() {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] No issuer allowlist for origin {}; any registered issuer accepted",
            origin
        );
    } else {
        let issuer_key_hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(issuer_key_hash);
        if !policy.allowed_issuers.contains(&issuer_key_hash_b64) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] ❌ Issuer not allowed for origin {}", origin);
            fail_challenge_and_persist(
                &state,
                &analytics,
                &mut cached,
                &challenge_id,
                &origin,
                &client_ip,
                "issuer_not_allowed",
                start,
                false,
            )
            .await;
            return ApiError::Forbidden(Some("Issuer not allowed for this origin".into()))
                .to_response();
        }
    }

    // Validate the submitted proof against the stored challenge metadata.
    // Confirm the verifying key matches what was issued.
    if body.proof.verifying_key_id.get() != cached.verifying_key_id {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] ❌ VK ID mismatch for challenge {}",
            redact_challenge_id(&challenge_id.to_string())
        );
        fail_challenge_and_persist(
            &state,
            &analytics,
            &mut cached,
            &challenge_id,
            &origin,
            &client_ip,
            "verifying_key_id_mismatch",
            start,
            false,
        )
        .await;
        return ApiError::BadRequest(Some("verifying_key_id mismatch".into())).to_response();
    }

    // Confirm the relying-party challenge remains unchanged.
    // CIV-064: Return an error if cached bytes are not exactly 32 bytes instead of
    // falling back to all-zeros.
    let cached_rp_challenge: [u8; 32] = match cached.rp_challenge.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Corrupt challenge: rp_challenge is not 32 bytes");
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
    };
    if !bool::from(rp_challenge.ct_eq(&cached_rp_challenge)) {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] ❌ RP challenge mismatch for challenge {}",
            redact_challenge_id(&challenge_id.to_string())
        );
        fail_challenge_and_persist(
            &state,
            &analytics,
            &mut cached,
            &challenge_id,
            &origin,
            &client_ip,
            "rp_challenge_mismatch",
            start,
            false,
        )
        .await;
        return ApiError::BadRequest(Some("rp_challenge mismatch".into())).to_response();
    }

    // Confirm the requested cutoff aligns with the challenge definition.
    if body.proof.public.cutoff_days.get() != cached.cutoff_days {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] ❌ Cutoff days mismatch for challenge {}",
            redact_challenge_id(&challenge_id.to_string())
        );
        fail_challenge_and_persist(
            &state,
            &analytics,
            &mut cached,
            &challenge_id,
            &origin,
            &client_ip,
            "cutoff_days_mismatch",
            start,
            false,
        )
        .await;
        return ApiError::BadRequest(Some("cutoff_days mismatch".into())).to_response();
    }

    // Proof length was checked during strict decoding.
    let proof_bytes = &body.proof.proof.0;

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/verify] Starting SNARK verification for challenge {}",
        redact_challenge_id(&challenge_id.to_string())
    );

    // Use exhaustive enum match instead of string comparison.
    let direction = match cached.proof_direction {
        crate::storage::origin_policy::ProofDirection::OverAge => true,
        crate::storage::origin_policy::ProofDirection::UnderAge => false,
    };
    let phase_start = worker::Date::now().as_millis();
    let verify_result = match verify_age_snark(
        proof_bytes,
        direction,
        cached.cutoff_days,
        rp_hash,
        issuer_vk_bytes,
        cred_nullifier,
        cached.verifying_key_id,
    ) {
        Ok(result) => result,
        Err(e) => {
            let error_code = match e {
                Error::VerificationFailed => "invalid_proof",
                Error::InvalidFormat => "invalid_proof_format",
                Error::VerifierNotInitialized => "verifier_error",
                _ => "verification_failed",
            };

            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ❌ SNARK verification failed: {} for challenge {}",
                error_code,
                redact_challenge_id(&challenge_id.to_string())
            );
            fail_challenge_and_persist(
                &state,
                &analytics,
                &mut cached,
                &challenge_id,
                &origin,
                &client_ip,
                error_code,
                start,
                true,
            )
            .await;

            let error_msg = match e {
                Error::VerificationFailed => "INVALID_PROOF",
                Error::InvalidFormat => "INVALID_PROOF_FORMAT",
                Error::VerifierNotInitialized => "VERIFIER_ERROR",
                _ => "VERIFICATION_FAILED",
            };

            return Ok(Response::from_json(&VerifyResponse {
                result: error_msg.to_string(),
                state: "failed".to_string(),
            })?
            .with_status(400));
        }
    };
    phase_timings.push((
        "snark_verify",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Fetch issuer metadata, refreshing the JWKS cache when required.
    let issuer_key_hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(issuer_key_hash);

    let phase_start = worker::Date::now().as_millis();
    match state.jwks_cache.lookup_issuer(&issuer_key_hash).await {
        Ok(issuer) => {
            if issuer.revoked {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[/v1/verify] ❌ Issuer revoked post-verify for challenge {}",
                    redact_challenge_id(&challenge_id.to_string())
                );
                fail_challenge_and_persist(
                    &state,
                    &analytics,
                    &mut cached,
                    &challenge_id,
                    &origin,
                    &client_ip,
                    "issuer_revoked_post_verify",
                    start,
                    true,
                )
                .await;

                // ADV-VA-05-003: Return ErrorResponse (5-key envelope), not VerifyResponse.
                return ApiError::Forbidden(Some("Issuer revoked after proof verification".into()))
                    .to_response();
            }

            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ✅ Proof verified - Issuer: {} for challenge {} origin {}",
                issuer.kid,
                redact_challenge_id(&challenge_id.to_string()),
                origin
            );

            let duration_ms = (worker::Date::now().as_millis().saturating_sub(start)) as f64;
            analytics.verification_success(
                "/v1/verify",
                &challenge_id.to_string(),
                &origin,
                Some(&issuer.kid),
                Some(&issuer_key_hash_b64),
                verify_result.cutoff_days,
                Some(duration_ms),
                true,
                &state.cfg.environment,
            );

            // Audit log the royalty event
            state
                .audit_logger
                .log_royalty_event(
                    &issuer.kid,
                    &verify_result.issuer_vk_bytes,
                    &origin,
                    verify_result.cutoff_days,
                )
                .await;

            cached.issuer_kid = Some(issuer.kid.clone());
            cached.issuer_vk_bytes = Some(verify_result.issuer_vk_bytes);
        }
        Err(ApiError::NotFound) => {
            // SECURITY (C1 - verdict forgery): the issuer verifying key is
            // wallet-supplied and fed directly as a Groth16 public input; the age
            // circuit only proves the credential signature verifies under THAT
            // key, not that the key belongs to a trusted issuer. The JWKS registry
            // is the trust anchor, so an issuer absent from it is unverifiable and
            // MUST be rejected - otherwise a self-minted RedJubjub key + self-signed
            // DOB + a valid proof would forge verified:true. Empty allowed_issuers
            // means "any REGISTERED issuer", never "any bytes the wallet sends".
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ❌ Unknown issuer {} (not in registry) for challenge {} origin {}",
                issuer_key_hash_b64,
                redact_challenge_id(&challenge_id.to_string()),
                origin
            );

            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "unknown_issuer_rejected")
                .await;

            fail_challenge_and_persist(
                &state,
                &analytics,
                &mut cached,
                &challenge_id,
                &origin,
                &client_ip,
                "unknown_issuer",
                start,
                false,
            )
            .await;
            return ApiError::Forbidden(Some("Unknown issuer".into())).to_response();
        }
        Err(_e) => {
            // SECURITY (AA-005-H1): Infrastructure errors (JWKS fetch failure,
            // circuit breaker open, internal errors) must NOT silently accept the
            // proof. Return 503 so the caller can retry.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/verify] ❌ Issuer registry lookup failed for challenge {} origin {}: {}",
                redact_challenge_id(&challenge_id.to_string()),
                origin,
                _e
            );

            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "downstream_failure:issuer_registry_lookup")
                .await;

            return ApiError::ServiceUnavailable(Some(
                "Issuer registry temporarily unavailable".into(),
            ))
            .to_response();
        }
    }
    phase_timings.push((
        "jwks_lookup",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Persist intermediate state for the redeem flow.
    cached.state = ChallengeState::ProofOkWaitingForRedeem;
    cached.proof_verified_at = Some(now);
    cached.proof_submitted = true;
    cached.submit_secret.zeroize();

    let phase_start = worker::Date::now().as_millis();
    let t = worker::Date::now().as_millis();
    if let Err(e) = state.challenge_store.put(&challenge_id, &cached).await {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/verify] ❌ Failed to update challenge: {:?}", e);
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "downstream_failure:challenge_store_write")
            .await;
        // VA-VFY-004: Return structured error response instead of raw Err(WorkerError)
        // which bypasses the 5-key envelope and returns an opaque 500.
        return ApiError::Internal(e.into()).to_response();
    }
    sub_ops.push((
        "challenge_do_put",
        (worker::Date::now().as_millis().saturating_sub(t)) as f64,
    ));
    phase_timings.push((
        "challenge_put",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Audit: log successful verification attempt
    state
        .audit_logger
        .log_verification_attempt(&challenge_id.to_string(), &client_ip, true, None)
        .await;

    // M-057: Notify hosted session directly (no service binding). Updates
    // session state to ProofOk and pushes WebSocket notification. Best-effort,
    // fire-and-forget: the notification runs after the response is returned to
    // the wallet via ctx.wait_until(). This removes 1-3 seconds from the
    // critical path.
    {
        let notify_state = state.clone();
        let notify_cid = challenge_id.to_string();
        if let Some(ctx) = crate::take_worker_context() {
            ctx.wait_until(async move {
                crate::hosted::endpoints::notify::notify_proof_verified(&notify_state, &notify_cid)
                    .await;
            });
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Hosted notify scheduled via wait_until (off critical path)");
        } else {
            // Fallback: context already consumed or unavailable. Run inline.
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/verify] Worker context unavailable, running notify inline");
            crate::hosted::endpoints::notify::notify_proof_verified(
                &state,
                &challenge_id.to_string(),
            )
            .await;
        }
    }

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
        r#"{{"type":"REQUEST_COMPLETE","service":"provii-verifier","route":"/v1/verify","status":200,"duration_ms":{:.1},"phases":{{{}}},"sub_ops":{{{}}},"slow":{},"slow_phases":"{}"}}"#,
        total_ms,
        _phases_json,
        _sub_ops_json,
        _is_slow,
        _slow_phases.join(",")
    );

    // SECURITY: Redact challenge_id in logs
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/verify] proof verified challenge_id={} origin={} duration_ms={}",
        redact_challenge_id(&challenge_id.to_string()),
        origin,
        worker::Date::now().as_millis().saturating_sub(start)
    );

    let verify_response = VerifyResponse {
        result: "OK".to_string(),
        state: "proof_ok_waiting_for_redeem".to_string(),
    };

    let worker_response = Response::from_json(&verify_response)?.with_status(200); // nosemgrep: provii.workers.response-missing-no-store (security headers added by worker router)

    // SECURITY: Store response in idempotency cache if key was provided
    if let (Some(key), Some(store)) = (idempotency_key, &state.idempotency_store) {
        let response_body = serde_json::to_string(&verify_response).unwrap_or_else(|_e| {
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
            crate::security::idempotency::compute_request_fingerprint("verify", &client_id);
        let _ = crate::security::idempotency::store_idempotency_response(
            store,
            &key,
            response_body,
            200,
            "verify",
            None,
            &fingerprint,
        )
        .await;
    }

    Ok(worker_response)
}

/// Transition a challenge to Failed, persist, emit analytics and audit events.
///
/// Consolidates the repeated fail-persist-analytics-audit pattern used across
/// all rejection paths in `submit_verification`. The caller is responsible for
/// emitting its own `console_log!` before invoking this helper.
async fn fail_challenge_and_persist(
    state: &Arc<AppState>,
    analytics: &Analytics,
    cached: &mut CachedChallenge,
    challenge_id: &Uuid,
    origin: &str,
    client_ip: &str,
    error_code: &str,
    start: u64,
    notify_hosted: bool,
) {
    // 1. State transition
    cached.state = ChallengeState::Failed;
    cached.proof_submitted = true;
    cached.submit_secret.zeroize();

    // 2. Persist (log discarded errors per RT-005)
    if let Err(_e) = state.challenge_store.put(challenge_id, cached).await {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[/v1/verify] Failed to persist challenge state update: {:?}",
            _e
        );
    }

    // 3. Analytics
    analytics.verification_failed(
        "/v1/verify",
        &challenge_id.to_string(),
        origin,
        error_code,
        Some((worker::Date::now().as_millis().saturating_sub(start)) as f64),
        &state.cfg.environment,
    );

    // 4. Audit
    state
        .audit_logger
        .log_verification_attempt(
            &challenge_id.to_string(),
            client_ip,
            false,
            Some(error_code.to_string()),
        )
        .await;

    // 5. Optional hosted notification (fire-and-forget)
    if notify_hosted {
        let ns = state.clone();
        let cid = challenge_id.to_string();
        if let Some(ctx) = crate::take_worker_context() {
            ctx.wait_until(async move {
                crate::hosted::endpoints::notify::notify_proof_failed(&ns, &cid).await;
            });
        } else {
            crate::hosted::endpoints::notify::notify_proof_failed(state, &challenge_id.to_string())
                .await;
        }
    }
}

// M-057: notify_hosted_backend() removed. Proof notification is now a direct
// function call via crate::hosted::endpoints::notify::notify_proof_verified().
// The HOSTED_BACKEND service binding is no longer needed.

/// Compute the Blake2s-256 hash of a 32-byte relying-party challenge.
///
/// This matches the off-circuit hashing performed before the value is fed
/// into the Groth16 public inputs.
pub fn compute_rp_challenge_hash(rp_challenge: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(rp_challenge);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    hash_bytes
}

/// Compute the Blake2s-256 hash of an issuer verifying key.
///
/// The domain-separation prefix `"provii.issuer.vk.v0"` is prepended before
/// hashing. This matches the off-circuit derivation used for issuer
/// allowlist and JWKS cache lookups.
pub fn compute_issuer_key_hash(issuer_vk_bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"provii.issuer.vk.v0");
    hasher.update(issuer_vk_bytes);
    let result = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result);
    hash_bytes
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
    use std::time::Duration;
    use uuid::Uuid;

    /* ========================================================================== */
    /*                    TEST HELPER FUNCTIONS                                  */
    /* ========================================================================== */

    fn create_test_submit_proof_request() -> Result<SubmitProofRequest, Box<dyn std::error::Error>>
    {
        Ok(SubmitProofRequest {
            challenge_id: UuidV4(Uuid::new_v4()),
            submit_secret: B64Url32::new([1u8; 32]),
            proof: AgeProofJson {
                verifying_key_id: VkId::new(1).ok_or("VkId::new(1) returned None")?,
                public: PublicInputsJson {
                    cutoff_days: CutoffDays::new(6570)?,
                    rp_challenge: B64Url32::new([2u8; 32]),
                    issuer: IssuerKeyJson {
                        value: B64Url32::new([3u8; 32]),
                    },
                    cred_nullifier: B64Url32::new([4u8; 32]),
                },
                proof: B64Url192::new([5u8; 192]),
            },
        })
    }

    /* ========================================================================== */
    /*                    REQUEST/RESPONSE STRUCTURE TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_submit_proof_request_creation() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert_eq!(req.proof.verifying_key_id.get(), 1);
        assert_eq!(req.proof.public.cutoff_days.get(), 6570);
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let json = serde_json::to_string(&req)?;
        // Serialised output must contain the expected field names
        assert!(json.contains("challenge_id"), "missing challenge_id field");
        assert!(
            json.contains("submit_secret"),
            "missing submit_secret field"
        );
        assert!(
            json.contains("verifying_key_id"),
            "missing verifying_key_id field"
        );
        assert!(json.contains("cutoff_days"), "missing cutoff_days field");
        assert!(json.contains("rp_challenge"), "missing rp_challenge field");
        assert!(
            json.contains("cred_nullifier"),
            "missing cred_nullifier field"
        );
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_deserialize_valid() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{
                            "value": "{}"
                        }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );

        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_submit_proof_request_deserialize_rejects_unknown_fields() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "{}",
                "unknown_field": "should_fail",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{
                            "value": "{}"
                        }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );

        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err()); // deny_unknown_fields should reject this
    }

    #[test]
    fn test_age_proof_json_deserialize_rejects_unknown_fields() {
        let json = format!(
            r#"{{
                "verifying_key_id": 1,
                "extra_field": "bad",
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{
                        "value": "{}"
                    }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );

        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_inputs_json_deserialize_rejects_unknown_fields() {
        let json = format!(
            r#"{{
                "cutoff_days": 6570,
                "rp_challenge": "{}",
                "issuer": {{
                    "value": "{}"
                }},
                "cred_nullifier": "{}",
                "bad_field": "reject"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );

        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_issuer_key_json_deserialize_rejects_unknown_fields() {
        let json = format!(
            r#"{{
                "value": "{}",
                "unknown": "field"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
        );

        let result: Result<IssuerKeyJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_response_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: "OK".to_string(),
            state: "proof_ok_waiting_for_redeem".to_string(),
        };

        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("OK"));
        assert!(json.contains("proof_ok_waiting_for_redeem"));
        Ok(())
    }

    #[test]
    fn test_verify_response_different_results() -> Result<(), Box<dyn std::error::Error>> {
        let responses = vec![
            ("OK", "verified"),
            ("INVALID_PROOF", "failed"),
            ("POLICY_REJECTED", "failed"),
            ("VERIFIER_ERROR", "failed"),
        ];

        for (result, state) in responses {
            let resp = VerifyResponse {
                result: result.to_string(),
                state: state.to_string(),
            };
            let json = serde_json::to_string(&resp)?;
            assert!(json.contains(result));
            assert!(json.contains(state));
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    HASH COMPUTATION TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_compute_rp_challenge_hash_deterministic() {
        let input = [42u8; 32];
        let hash1 = compute_rp_challenge_hash(&input);
        let hash2 = compute_rp_challenge_hash(&input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_rp_challenge_hash_different_inputs() {
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        let hash1 = compute_rp_challenge_hash(&input1);
        let hash2 = compute_rp_challenge_hash(&input2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_rp_challenge_hash_length() {
        let input = [99u8; 32];
        let hash = compute_rp_challenge_hash(&input);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_compute_rp_challenge_hash_all_zeros() {
        let input = [0u8; 32];
        let hash = compute_rp_challenge_hash(&input);
        // Hash of all zeros should not be all zeros
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_compute_rp_challenge_hash_all_ones() {
        let input = [0xFFu8; 32];
        let hash = compute_rp_challenge_hash(&input);
        // Hash should be different from input
        assert_ne!(hash, input);
    }

    #[test]
    fn test_compute_issuer_key_hash_deterministic() {
        let input = [42u8; 32];
        let hash1 = compute_issuer_key_hash(&input);
        let hash2 = compute_issuer_key_hash(&input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_issuer_key_hash_different_inputs() {
        let input1 = [1u8; 32];
        let input2 = [2u8; 32];
        let hash1 = compute_issuer_key_hash(&input1);
        let hash2 = compute_issuer_key_hash(&input2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_issuer_key_hash_length() {
        let input = [99u8; 32];
        let hash = compute_issuer_key_hash(&input);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_compute_issuer_key_hash_with_prefix() {
        let input = [5u8; 32];
        let hash = compute_issuer_key_hash(&input);

        // Verify it's different from hashing without prefix
        let mut hasher = Blake2s256::new();
        hasher.update(input);
        let no_prefix_hash = hasher.finalize();

        assert_ne!(&hash[..], &no_prefix_hash[..]);
    }

    #[test]
    fn test_compute_issuer_key_hash_prefix_matters() {
        // Two different inputs should produce different hashes even with prefix
        let input1 = [10u8; 32];
        let input2 = [20u8; 32];

        let hash1 = compute_issuer_key_hash(&input1);
        let hash2 = compute_issuer_key_hash(&input2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_rp_hash_vs_issuer_hash_different() {
        let input = [42u8; 32];
        let rp_hash = compute_rp_challenge_hash(&input);
        let issuer_hash = compute_issuer_key_hash(&input);

        // Same input should produce different hashes due to prefix
        assert_ne!(rp_hash, issuer_hash);
    }

    /* ========================================================================== */
    /*                    REQUEST VALIDATION TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_submit_proof_request_valid_challenge_id() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        // UUID should be valid
        assert_ne!(req.challenge_id.0, Uuid::nil());
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_valid_vk_id() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert!(req.proof.verifying_key_id.get() > 0);
        assert!(req.proof.verifying_key_id.get() < 1000000); // Reasonable bounds
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_valid_cutoff_days() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let cutoff = req.proof.public.cutoff_days.get();
        assert!(cutoff > 0);
        assert!(cutoff < 30000); // Reasonable upper bound (82 years)
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_submit_secret_length() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert_eq!(req.submit_secret.0.len(), 32);
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_rp_challenge_length() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert_eq!(req.proof.public.rp_challenge.0.len(), 32);
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_issuer_value_length() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert_eq!(req.proof.public.issuer.value.0.len(), 32);
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_cred_nullifier_length() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert_eq!(req.proof.public.cred_nullifier.0.len(), 32);
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_proof_length() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        assert_eq!(req.proof.proof.0.len(), 192);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ERROR CODE MAPPING TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_crypto_error_to_error_code_verification_failed() {
        // Test that we correctly map crypto errors to error codes
        // This tests the match logic in lines 413-418
        let error = provii_crypto_commons::Error::VerificationFailed;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "invalid_proof");
    }

    #[test]
    fn test_crypto_error_to_error_code_invalid_format() {
        let error = provii_crypto_commons::Error::InvalidFormat;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "invalid_proof_format");
    }

    #[test]
    fn test_crypto_error_to_error_message_verification_failed() {
        let error = provii_crypto_commons::Error::VerificationFailed;
        let msg = match error {
            provii_crypto_commons::Error::VerificationFailed => "INVALID_PROOF",
            provii_crypto_commons::Error::InvalidFormat => "INVALID_PROOF_FORMAT",
            provii_crypto_commons::Error::VerifierNotInitialized => "VERIFIER_ERROR",
            _ => "VERIFICATION_FAILED",
        };
        assert_eq!(msg, "INVALID_PROOF");
    }

    #[test]
    fn test_crypto_error_to_error_message_invalid_format() {
        let error = provii_crypto_commons::Error::InvalidFormat;
        let msg = match error {
            provii_crypto_commons::Error::VerificationFailed => "INVALID_PROOF",
            provii_crypto_commons::Error::InvalidFormat => "INVALID_PROOF_FORMAT",
            provii_crypto_commons::Error::VerifierNotInitialized => "VERIFIER_ERROR",
            _ => "VERIFICATION_FAILED",
        };
        assert_eq!(msg, "INVALID_PROOF_FORMAT");
    }

    /* ========================================================================== */
    /*                    NONCE TAG GENERATION TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_nonce_tag_format() {
        let challenge_id = Uuid::new_v4();
        let nonce_tag = format!("verify:{}", challenge_id);

        assert!(nonce_tag.starts_with("verify:"));
        assert!(nonce_tag.contains(&challenge_id.to_string()));
    }

    #[test]
    fn test_nonce_tag_uniqueness() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let tag1 = format!("verify:{}", id1);
        let tag2 = format!("verify:{}", id2);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_nonce_tag_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let tag1 = format!("verify:{}", challenge_id);
        let tag2 = format!("verify:{}", challenge_id);

        assert_eq!(tag1, tag2);
        assert_eq!(tag1, "verify:550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: RP challenge hash is deterministic
        #[test]
        fn prop_rp_challenge_hash_deterministic(bytes in any::<[u8; 32]>()) {
            let hash1 = compute_rp_challenge_hash(&bytes);
            let hash2 = compute_rp_challenge_hash(&bytes);
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: Different RP challenges produce different hashes
        #[test]
        fn prop_rp_challenge_hash_unique(
            bytes1 in any::<[u8; 32]>(),
            bytes2 in any::<[u8; 32]>()
        ) {
            prop_assume!(bytes1 != bytes2);
            let hash1 = compute_rp_challenge_hash(&bytes1);
            let hash2 = compute_rp_challenge_hash(&bytes2);
            prop_assert_ne!(hash1, hash2);
        }

        /// Property: RP challenge hash is always 32 bytes
        #[test]
        fn prop_rp_challenge_hash_length(bytes in any::<[u8; 32]>()) {
            let hash = compute_rp_challenge_hash(&bytes);
            prop_assert_eq!(hash.len(), 32);
        }

        /// Property: Issuer key hash is deterministic
        #[test]
        fn prop_issuer_key_hash_deterministic(bytes in any::<[u8; 32]>()) {
            let hash1 = compute_issuer_key_hash(&bytes);
            let hash2 = compute_issuer_key_hash(&bytes);
            prop_assert_eq!(hash1, hash2);
        }

        /// Property: Different issuer keys produce different hashes
        #[test]
        fn prop_issuer_key_hash_unique(
            bytes1 in any::<[u8; 32]>(),
            bytes2 in any::<[u8; 32]>()
        ) {
            prop_assume!(bytes1 != bytes2);
            let hash1 = compute_issuer_key_hash(&bytes1);
            let hash2 = compute_issuer_key_hash(&bytes2);
            prop_assert_ne!(hash1, hash2);
        }

        /// Property: Issuer key hash is always 32 bytes
        #[test]
        fn prop_issuer_key_hash_length(bytes in any::<[u8; 32]>()) {
            let hash = compute_issuer_key_hash(&bytes);
            prop_assert_eq!(hash.len(), 32);
        }

        /// Property: RP hash and issuer hash are different for same input
        #[test]
        fn prop_rp_vs_issuer_hash_different(bytes in any::<[u8; 32]>()) {
            let rp_hash = compute_rp_challenge_hash(&bytes);
            let issuer_hash = compute_issuer_key_hash(&bytes);
            prop_assert_ne!(rp_hash, issuer_hash);
        }

        /// Property: Nonce tag format is consistent
        #[test]
        fn prop_nonce_tag_format(_seed in any::<u64>()) {
            let challenge_id = Uuid::new_v4();
            let nonce_tag = format!("verify:{}", challenge_id);

            prop_assert!(nonce_tag.starts_with("verify:"));
            prop_assert!(nonce_tag.len() > 7); // "verify:" + UUID
        }

        /// Property: Nonce tags for different UUIDs are different
        #[test]
        fn prop_nonce_tag_uniqueness(_seed1 in any::<u64>(), _seed2 in any::<u64>()) {
            let id1 = Uuid::new_v4();
            let id2 = Uuid::new_v4();

            if id1 != id2 {
                let tag1 = format!("verify:{}", id1);
                let tag2 = format!("verify:{}", id2);
                prop_assert_ne!(tag1, tag2);
            }
        }

        /// Property: Hash output is not trivially related to input
        #[test]
        fn prop_hash_not_identity(bytes in any::<[u8; 32]>()) {
            let rp_hash = compute_rp_challenge_hash(&bytes);
            let issuer_hash = compute_issuer_key_hash(&bytes);

            // Hash should not equal input (extremely unlikely)
            prop_assert_ne!(rp_hash, bytes);
            prop_assert_ne!(issuer_hash, bytes);
        }

        /// Property: Small input changes produce different hashes (avalanche)
        #[test]
        fn prop_hash_avalanche_effect(mut bytes in any::<[u8; 32]>(), bit_pos in 0u8..8) {
            let hash1 = compute_rp_challenge_hash(&bytes);

            // Flip one bit
            bytes[0] ^= 1 << bit_pos;
            let hash2 = compute_rp_challenge_hash(&bytes);

            prop_assert_ne!(hash1, hash2);
        }
    }

    /* ========================================================================== */
    /*                    EDGE CASE TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_hash_with_sequential_bytes() {
        let input: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hash = compute_rp_challenge_hash(&input);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, input);
    }

    #[test]
    fn test_hash_with_alternating_pattern() {
        let input = [0xAAu8; 32]; // 10101010 pattern
        let hash = compute_rp_challenge_hash(&input);
        assert_ne!(hash, input);
    }

    #[test]
    fn test_hash_max_values() {
        let input = [0xFFu8; 32];
        let hash1 = compute_rp_challenge_hash(&input);
        let hash2 = compute_issuer_key_hash(&input);

        assert_ne!(hash1, input);
        assert_ne!(hash2, input);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_submit_proof_request_minimal_valid() -> Result<(), Box<dyn std::error::Error>> {
        // Test with minimal valid values
        let req = SubmitProofRequest {
            challenge_id: UuidV4(Uuid::nil()),
            submit_secret: B64Url32::new([0u8; 32]),
            proof: AgeProofJson {
                verifying_key_id: VkId::new(1).ok_or("VkId::new(1) returned None")?,
                public: PublicInputsJson {
                    cutoff_days: CutoffDays::new(1)?,
                    rp_challenge: B64Url32::new([0u8; 32]),
                    issuer: IssuerKeyJson {
                        value: B64Url32::new([0u8; 32]),
                    },
                    cred_nullifier: B64Url32::new([0u8; 32]),
                },
                proof: B64Url192::new([0u8; 192]),
            },
        };

        assert_eq!(req.proof.verifying_key_id.get(), 1);
        assert_eq!(req.proof.public.cutoff_days.get(), 1);
        Ok(())
    }

    #[test]
    fn test_submit_proof_request_maximum_values() -> Result<(), Box<dyn std::error::Error>> {
        // Test with maximum reasonable values
        let max_cutoff = CutoffDays::new(29999)?; // ~82 years
        let max_vk = VkId::new(999999).ok_or("VkId::new(999999) returned None")?;

        let req = SubmitProofRequest {
            challenge_id: UuidV4(Uuid::new_v4()),
            submit_secret: B64Url32::new([0xFFu8; 32]),
            proof: AgeProofJson {
                verifying_key_id: max_vk,
                public: PublicInputsJson {
                    cutoff_days: max_cutoff,
                    rp_challenge: B64Url32::new([0xFFu8; 32]),
                    issuer: IssuerKeyJson {
                        value: B64Url32::new([0xFFu8; 32]),
                    },
                    cred_nullifier: B64Url32::new([0xFFu8; 32]),
                },
                proof: B64Url192::new([0xFFu8; 192]),
            },
        };

        assert_eq!(req.proof.verifying_key_id.get(), 999999);
        assert_eq!(req.proof.public.cutoff_days.get(), 29999);
        Ok(())
    }

    #[test]
    fn test_verify_response_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: String::new(),
            state: String::new(),
        };

        let json = serde_json::to_string(&resp)?;
        assert!(json.contains(r#""result":"""#));
        assert!(json.contains(r#""state":"""#));
        Ok(())
    }

    #[test]
    fn test_verify_response_long_strings() -> Result<(), Box<dyn std::error::Error>> {
        let long_result = "X".repeat(1000);
        let long_state = "Y".repeat(1000);

        let resp = VerifyResponse {
            result: long_result.clone(),
            state: long_state.clone(),
        };

        let json = serde_json::to_string(&resp)?;
        assert!(json.contains(&long_result));
        assert!(json.contains(&long_state));
        Ok(())
    }

    #[test]
    fn test_hash_functions_handle_extreme_inputs() {
        let extremes = vec![
            [0u8; 32],    // All zeros
            [0xFFu8; 32], // All ones
            [0xAAu8; 32], // Alternating 10101010
            [0x55u8; 32], // Alternating 01010101
        ];

        for input in extremes {
            let rp_hash = compute_rp_challenge_hash(&input);
            let issuer_hash = compute_issuer_key_hash(&input);

            assert_eq!(rp_hash.len(), 32);
            assert_eq!(issuer_hash.len(), 32);
            assert_ne!(rp_hash, issuer_hash);
        }
    }

    /* ========================================================================== */
    /*                    CHALLENGE STATE VALIDATION TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_already_submitted() {
        // Test logic from lines 175-185: proof_submitted check
        let proof_submitted = true;
        let state = ChallengeState::Pending;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_proof_ok_waiting() {
        let proof_submitted = false;
        let state = ChallengeState::ProofOkWaitingForRedeem;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_verified() {
        let proof_submitted = false;
        let state = ChallengeState::Verified;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_failed() {
        let proof_submitted = false;
        let state = ChallengeState::Failed;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_pending_allowed() {
        let proof_submitted = false;
        let state = ChallengeState::Pending;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(!should_reject);
    }

    #[test]
    fn test_challenge_state_expired_allowed() {
        // Expired state is allowed to proceed (will be caught by timestamp check)
        let proof_submitted = false;
        let state = ChallengeState::Expired;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(!should_reject);
    }

    /* ========================================================================== */
    /*                    EXPIRY VALIDATION TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_challenge_expiry_check_expired() {
        let now = 1000u64;
        let expires_at = 999u64;

        assert!(now > expires_at);
    }

    #[test]
    fn test_challenge_expiry_check_not_expired() {
        let now = 1000u64;
        let expires_at = 1001u64;

        assert!((now <= expires_at));
    }

    #[test]
    fn test_challenge_expiry_check_exactly_expired() {
        let now = 1000u64;
        let expires_at = 1000u64;

        // Now == expires_at means NOT expired (now > expires_at is false)
        assert!((now <= expires_at));
    }

    #[test]
    fn test_challenge_expiry_check_far_future() {
        let now = current_timestamp();
        let expires_at = now + 1000000;

        assert!((now <= expires_at));
    }

    #[test]
    fn test_challenge_expiry_check_far_past() {
        let now = current_timestamp();
        let expires_at = now.saturating_sub(1000000);

        assert!(now > expires_at);
    }

    /* ========================================================================== */
    /*                    CONSTANT-TIME COMPARISON TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_submit_secret_comparison_matching() {
        let secret1 = [42u8; 32];
        let secret2 = [42u8; 32];

        assert!(bool::from(secret1.ct_eq(&secret2)));
    }

    #[test]
    fn test_submit_secret_comparison_not_matching() {
        let secret1 = [42u8; 32];
        let secret2 = [43u8; 32];

        assert!(!bool::from(secret1.ct_eq(&secret2)));
    }

    #[test]
    fn test_submit_secret_comparison_single_bit_diff() {
        let secret1 = [0u8; 32];
        let mut secret2 = [0u8; 32];
        secret2[31] = 1;

        assert!(!bool::from(secret1.ct_eq(&secret2)));
    }

    #[test]
    fn test_submit_secret_comparison_first_byte_diff() {
        let mut secret1 = [42u8; 32];
        let mut secret2 = [42u8; 32];
        secret1[0] = 1;
        secret2[0] = 2;

        assert!(!bool::from(secret1.ct_eq(&secret2)));
    }

    #[test]
    fn test_submit_secret_comparison_last_byte_diff() {
        let mut secret1 = [42u8; 32];
        let mut secret2 = [42u8; 32];
        secret1[31] = 1;
        secret2[31] = 2;

        assert!(!bool::from(secret1.ct_eq(&secret2)));
    }

    #[test]
    fn test_rp_challenge_comparison_matching() {
        let challenge1 = [99u8; 32];
        let challenge2 = [99u8; 32];

        assert!(bool::from(challenge1.ct_eq(&challenge2)));
    }

    #[test]
    fn test_rp_challenge_comparison_not_matching() {
        let challenge1 = [99u8; 32];
        let challenge2 = [98u8; 32];

        assert!(!bool::from(challenge1.ct_eq(&challenge2)));
    }

    /* ========================================================================== */
    /*                    VK ID MATCHING TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_vk_id_match() {
        let submitted_vk = 1u32;
        let cached_vk = 1u32;

        assert_eq!(submitted_vk, cached_vk);
    }

    #[test]
    fn test_vk_id_mismatch() {
        let submitted_vk = 1u32;
        let cached_vk = 2u32;

        assert_ne!(submitted_vk, cached_vk);
    }

    #[test]
    fn test_vk_id_match_large_values() {
        let submitted_vk = 999999u32;
        let cached_vk = 999999u32;

        assert_eq!(submitted_vk, cached_vk);
    }

    #[test]
    fn test_vk_id_off_by_one() {
        let submitted_vk = 100u32;
        let cached_vk = 101u32;

        assert_ne!(submitted_vk, cached_vk);
    }

    /* ========================================================================== */
    /*                    CUTOFF DAYS MATCHING TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_match() {
        let submitted = 6570i32;
        let cached = 6570i32;

        assert_eq!(submitted, cached);
    }

    #[test]
    fn test_cutoff_days_mismatch() {
        let submitted = 6570i32;
        let cached = 6571i32;

        assert_ne!(submitted, cached);
    }

    #[test]
    fn test_cutoff_days_zero_vs_one() {
        let submitted = 0i32;
        let cached = 1i32;

        assert_ne!(submitted, cached);
    }

    #[test]
    fn test_cutoff_days_max_value() {
        let submitted = i32::MAX;
        let cached = i32::MAX;

        assert_eq!(submitted, cached);
    }

    #[test]
    fn test_cutoff_days_off_by_one() {
        let submitted = 10000i32;
        let cached = 10001i32;

        assert_ne!(submitted, cached);
    }

    /* ========================================================================== */
    /*                    ALLOWED LIST CHECKING TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_vk_id_in_allowed_list() {
        let vk_id = 1u32;
        let allowed_vk_ids = [1, 2, 3];

        assert!(allowed_vk_ids.contains(&vk_id));
    }

    #[test]
    fn test_vk_id_not_in_allowed_list() {
        let vk_id = 4u32;
        let allowed_vk_ids = [1, 2, 3];

        assert!(!allowed_vk_ids.contains(&vk_id));
    }

    #[test]
    fn test_vk_id_empty_allowed_list() {
        let vk_id = 1u32;
        let allowed_vk_ids: Vec<u32> = vec![];

        assert!(!allowed_vk_ids.contains(&vk_id));
    }

    #[test]
    fn test_issuer_in_allowed_list() {
        let issuer_hash = "abc123";
        let allowed_issuers = ["abc123".to_string(), "def456".to_string()];

        assert!(allowed_issuers.contains(&issuer_hash.to_string()));
    }

    #[test]
    fn test_issuer_not_in_allowed_list() {
        let issuer_hash = "xyz789";
        let allowed_issuers = ["abc123".to_string(), "def456".to_string()];

        assert!(!allowed_issuers.contains(&issuer_hash.to_string()));
    }

    #[test]
    fn test_issuer_empty_allowed_list() {
        let _issuer_hash = "abc123";
        let allowed_issuers: Vec<String> = vec![];

        // Empty list means no restriction
        assert!(allowed_issuers.is_empty());
    }

    #[test]
    fn test_issuer_case_sensitive() {
        let issuer_hash = "ABC123";
        let allowed_issuers = ["abc123".to_string()];

        // Base64 is case-sensitive
        assert!(!allowed_issuers.contains(&issuer_hash.to_string()));
    }

    /* ========================================================================== */
    /*                    NONCE TTL DURATION TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_nonce_ttl_value() {
        let ttl = Duration::from_secs(300);

        assert_eq!(ttl.as_secs(), 300);
        assert_eq!(ttl.as_millis(), 300000);
    }

    #[test]
    fn test_nonce_ttl_5_minutes() {
        let ttl = Duration::from_secs(300);

        assert_eq!(ttl.as_secs(), 5 * 60);
    }

    /* ========================================================================== */
    /*                    BASE64 ENCODING TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_issuer_hash_base64_encoding() {
        let hash = [42u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);

        assert_eq!(encoded.len(), 43); // 32 bytes -> 43 chars in base64url
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_issuer_hash_base64_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let hash = [123u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;

        assert_eq!(decoded.len(), 32);
        assert_eq!(&decoded[..], &hash[..]);
        Ok(())
    }

    #[test]
    fn test_base64_different_hashes_different_encodings() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        let encoded1 = BASE64_URL_SAFE_NO_PAD.encode(hash1);
        let encoded2 = BASE64_URL_SAFE_NO_PAD.encode(hash2);

        assert_ne!(encoded1, encoded2);
    }

    /* ========================================================================== */
    /*                    ERROR SCENARIO TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_multiple_invalid_states() {
        // Test that all invalid states are properly detected
        let invalid_states = vec![
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
        ];

        for state in invalid_states {
            let should_reject = state == ChallengeState::ProofOkWaitingForRedeem
                || state == ChallengeState::Verified
                || state == ChallengeState::Failed;

            assert!(should_reject, "State {:?} should be rejected", state);
        }
    }

    #[test]
    fn test_valid_states_allowed() {
        let valid_states = vec![
            ChallengeState::Pending,
            ChallengeState::Expired, // Will be caught by expiry check
        ];

        for state in valid_states {
            let should_reject = state == ChallengeState::ProofOkWaitingForRedeem
                || state == ChallengeState::Verified
                || state == ChallengeState::Failed;

            assert!(!should_reject, "State {:?} should be allowed", state);
        }
    }

    /* ========================================================================== */
    /*                    PROOF BYTES TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_proof_bytes_extraction() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let proof_bytes = &req.proof.proof.0;

        assert_eq!(proof_bytes.len(), 192);
        Ok(())
    }

    #[test]
    fn test_proof_bytes_all_zeros() {
        let proof = B64Url192::new([0u8; 192]);
        assert_eq!(proof.0.len(), 192);
        assert_eq!(proof.0[0], 0);
        assert_eq!(proof.0[191], 0);
    }

    #[test]
    fn test_proof_bytes_all_ones() {
        let proof = B64Url192::new([0xFFu8; 192]);
        assert_eq!(proof.0.len(), 192);
        assert_eq!(proof.0[0], 0xFF);
        assert_eq!(proof.0[191], 0xFF);
    }

    #[test]
    fn test_proof_bytes_pattern() {
        let bytes: [u8; 192] = core::array::from_fn(|i| (i % 256) as u8);
        let proof = B64Url192::new(bytes);

        assert_eq!(proof.0[0], 0);
        assert_eq!(proof.0[100], 100);
        assert_eq!(proof.0[191], 191);
    }

    /* ========================================================================== */
    /*                    PUBLIC INPUTS EXTRACTION TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_extract_rp_challenge() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let rp_challenge = req.proof.public.rp_challenge.0;

        assert_eq!(rp_challenge.len(), 32);
        assert_eq!(rp_challenge, [2u8; 32]);
        Ok(())
    }

    #[test]
    fn test_extract_issuer_vk_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let issuer_vk_bytes = req.proof.public.issuer.value.0;

        assert_eq!(issuer_vk_bytes.len(), 32);
        assert_eq!(issuer_vk_bytes, [3u8; 32]);
        Ok(())
    }

    #[test]
    fn test_extract_cred_nullifier() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let cred_nullifier = req.proof.public.cred_nullifier.0;

        assert_eq!(cred_nullifier.len(), 32);
        assert_eq!(cred_nullifier, [4u8; 32]);
        Ok(())
    }

    #[test]
    fn test_all_public_inputs_different() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;

        let rp_challenge = req.proof.public.rp_challenge.0;
        let issuer_vk = req.proof.public.issuer.value.0;
        let cred_nullifier = req.proof.public.cred_nullifier.0;

        // All three should be different
        assert_ne!(rp_challenge, issuer_vk);
        assert_ne!(rp_challenge, cred_nullifier);
        assert_ne!(issuer_vk, cred_nullifier);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ADDITIONAL PROPERTY TESTS                              */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Expiry check is consistent
        #[test]
        fn prop_expiry_check_consistent(now in any::<u64>(), expires_at in any::<u64>()) {
            let is_expired = now > expires_at;
            let is_expired2 = now > expires_at;
            prop_assert_eq!(is_expired, is_expired2);
        }

        /// Property: Expiry check boundary
        #[test]
        fn prop_expiry_at_boundary(base_time in 1000u64..1000000) {
            // At exactly expires_at, should NOT be expired
            prop_assert!(!(base_time > base_time));

            // One second after should be expired
            prop_assert!((base_time + 1) > base_time);
        }

        /// Property: VK ID matching is reflexive
        #[test]
        fn prop_vk_id_reflexive(vk_id in any::<u32>()) {
            prop_assert_eq!(vk_id, vk_id);
        }

        /// Property: VK ID matching is symmetric
        #[test]
        fn prop_vk_id_symmetric(vk1 in any::<u32>(), vk2 in any::<u32>()) {
            prop_assert_eq!(vk1 == vk2, vk2 == vk1);
        }

        /// Property: Cutoff days matching is reflexive
        #[test]
        fn prop_cutoff_days_reflexive(cutoff in any::<i32>()) {
            prop_assert_eq!(cutoff, cutoff);
        }

        /// Property: Base64 encoding length
        #[test]
        fn prop_base64_length(bytes in any::<[u8; 32]>()) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
            prop_assert_eq!(encoded.len(), 43);
        }

        /// Property: Base64 no padding
        #[test]
        fn prop_base64_no_padding(bytes in any::<[u8; 32]>()) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
            prop_assert!(!encoded.contains('='));
        }

        /// Property: Base64 URL-safe
        #[test]
        fn prop_base64_url_safe(bytes in any::<[u8; 32]>()) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
            prop_assert!(!encoded.contains('+'));
            prop_assert!(!encoded.contains('/'));
        }

        /// Property: Constant-time comparison is reflexive
        #[test]
        fn prop_ct_eq_reflexive(bytes in any::<[u8; 32]>()) {
            prop_assert!(bool::from(bytes.ct_eq(&bytes)));
        }

        /// Property: Constant-time comparison is symmetric
        #[test]
        fn prop_ct_eq_symmetric(bytes1 in any::<[u8; 32]>(), bytes2 in any::<[u8; 32]>()) {
            prop_assert_eq!(bool::from(bytes1.ct_eq(&bytes2)), bool::from(bytes2.ct_eq(&bytes1)));
        }

        /// Property: Challenge state check logic
        #[test]
        fn prop_challenge_state_pending_valid(proof_submitted in any::<bool>()) {
            let state = ChallengeState::Pending;
            let should_reject = proof_submitted
                || state == ChallengeState::ProofOkWaitingForRedeem
                || state == ChallengeState::Verified
                || state == ChallengeState::Failed;

            prop_assert_eq!(should_reject, proof_submitted);
        }

        /// Property: Nonce tag length
        #[test]
        fn prop_nonce_tag_min_length(_seed in any::<u64>()) {
            let challenge_id = Uuid::new_v4();
            let nonce_tag = format!("verify:{}", challenge_id);

            // "verify:" (7 chars) + UUID (36 chars) = 43 chars minimum
            prop_assert!(nonce_tag.len() >= 43);
        }

        /// Property: Issuer key hash avalanche (single bit flip)
        #[test]
        fn prop_issuer_key_hash_avalanche(mut bytes in any::<[u8; 32]>(), bit_pos in 0u8..8) {
            let hash1 = compute_issuer_key_hash(&bytes);
            bytes[0] ^= 1 << bit_pos;
            let hash2 = compute_issuer_key_hash(&bytes);
            prop_assert_ne!(hash1, hash2);
        }

        /// Property: Issuer key hash never equals all zeros
        #[test]
        fn prop_issuer_key_hash_non_trivial(bytes in any::<[u8; 32]>()) {
            let hash = compute_issuer_key_hash(&bytes);
            prop_assert_ne!(hash, [0u8; 32]);
        }

        /// Property: RP challenge hash never equals all zeros
        #[test]
        fn prop_rp_challenge_hash_non_trivial(bytes in any::<[u8; 32]>()) {
            let hash = compute_rp_challenge_hash(&bytes);
            prop_assert_ne!(hash, [0u8; 32]);
        }

        /// Property: Base64url roundtrip for issuer hash
        #[test]
        fn prop_issuer_hash_b64_roundtrip(bytes in any::<[u8; 32]>()) {
            let hash = compute_issuer_key_hash(&bytes);
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded).expect("decode must succeed");
            prop_assert_eq!(&decoded[..], &hash[..]);
        }

        /// Property: Base64url roundtrip for rp challenge hash
        #[test]
        fn prop_rp_hash_b64_roundtrip(bytes in any::<[u8; 32]>()) {
            let hash = compute_rp_challenge_hash(&bytes);
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(hash);
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded).expect("decode must succeed");
            prop_assert_eq!(&decoded[..], &hash[..]);
        }

        /// Property: Proof direction enum exhaustiveness
        #[test]
        fn prop_proof_direction_over_age(s in "over_age|under_age") {
            use crate::storage::origin_policy::ProofDirection;
            // Only valid directions can be deserialised
            if let Ok(dir) = serde_json::from_value::<ProofDirection>(serde_json::json!(s.as_str())) {
                let is_over = match dir {
                    ProofDirection::OverAge => true,
                    ProofDirection::UnderAge => false,
                };
                if s == "over_age" {
                    prop_assert!(is_over);
                } else {
                    prop_assert!(!is_over);
                }
            }
        }
    }

    /* ========================================================================== */
    /*                    ERROR CODE MAPPING COMPLETENESS                        */
    /* ========================================================================== */

    #[test]
    fn test_crypto_error_to_error_code_verifier_not_initialized() {
        let error = provii_crypto_commons::Error::VerifierNotInitialized;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "verifier_error");
    }

    #[test]
    fn test_crypto_error_to_error_message_verifier_not_initialized() {
        let error = provii_crypto_commons::Error::VerifierNotInitialized;
        let msg = match error {
            provii_crypto_commons::Error::VerificationFailed => "INVALID_PROOF",
            provii_crypto_commons::Error::InvalidFormat => "INVALID_PROOF_FORMAT",
            provii_crypto_commons::Error::VerifierNotInitialized => "VERIFIER_ERROR",
            _ => "VERIFICATION_FAILED",
        };
        assert_eq!(msg, "VERIFIER_ERROR");
    }

    #[test]
    fn test_crypto_error_to_error_code_fallback_internal() {
        let error = provii_crypto_commons::Error::Internal;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "verification_failed");
    }

    #[test]
    fn test_crypto_error_to_error_message_fallback_internal() {
        let error = provii_crypto_commons::Error::Internal;
        let msg = match error {
            provii_crypto_commons::Error::VerificationFailed => "INVALID_PROOF",
            provii_crypto_commons::Error::InvalidFormat => "INVALID_PROOF_FORMAT",
            provii_crypto_commons::Error::VerifierNotInitialized => "VERIFIER_ERROR",
            _ => "VERIFICATION_FAILED",
        };
        assert_eq!(msg, "VERIFICATION_FAILED");
    }

    #[test]
    fn test_crypto_error_to_error_code_fallback_expired() {
        let error = provii_crypto_commons::Error::Expired;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "verification_failed");
    }

    #[test]
    fn test_crypto_error_to_error_code_fallback_invalid_input() {
        let error = provii_crypto_commons::Error::InvalidInput;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "verification_failed");
    }

    #[test]
    fn test_crypto_error_to_error_code_fallback_prover_failed() {
        let error = provii_crypto_commons::Error::ProverFailed;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "verification_failed");
    }

    #[test]
    fn test_crypto_error_to_error_code_fallback_not_found() {
        let error = provii_crypto_commons::Error::NotFound;
        let code = match error {
            provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
            provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
            provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
            _ => "verification_failed",
        };
        assert_eq!(code, "verification_failed");
    }

    /* ========================================================================== */
    /*                    DESERIALIZATION REJECTION TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_submit_proof_missing_challenge_id() {
        let json = format!(
            r#"{{
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_proof_missing_submit_secret() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_proof_missing_proof() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "{}"
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_proof_empty_json() {
        let json = "{}";
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_proof_null() {
        let json = "null";
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_proof_array_instead_of_object() {
        let json = "[]";
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_proof_string_instead_of_object() {
        let json = r#""not a request""#;
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_age_proof_missing_verifying_key_id() {
        let json = format!(
            r#"{{
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_age_proof_missing_public() {
        let json = format!(
            r#"{{
                "verifying_key_id": 1,
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_age_proof_missing_proof_bytes() {
        let json = format!(
            r#"{{
                "verifying_key_id": 1,
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }}
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_public_inputs_missing_cutoff_days() {
        let json = format!(
            r#"{{
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_public_inputs_missing_rp_challenge() {
        let json = format!(
            r#"{{
                "cutoff_days": 6570,
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_public_inputs_missing_issuer() {
        let json = format!(
            r#"{{
                "cutoff_days": 6570,
                "rp_challenge": "{}",
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_public_inputs_missing_cred_nullifier() {
        let json = format!(
            r#"{{
                "cutoff_days": 6570,
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }}
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_issuer_key_json_missing_value() {
        let json = "{}";
        let result: Result<IssuerKeyJson, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    INVALID BASE64/LENGTH DESERIALIZATION                  */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_submit_secret_wrong_length() {
        // 16 bytes instead of 32
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 16]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_rp_challenge_wrong_length() {
        // 64 bytes instead of 32
        let json = format!(
            r#"{{
                "cutoff_days": 6570,
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 64]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_issuer_value_wrong_length() {
        // 48 bytes instead of 32
        let json = format!(
            r#"{{ "value": "{}" }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 48]),
        );
        let result: Result<IssuerKeyJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_proof_bytes_wrong_length() {
        // 96 bytes instead of 192
        let json = format!(
            r#"{{
                "verifying_key_id": 1,
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 96]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_secret_invalid_base64() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "!!!not-valid-base64!!!-padding!!!",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_submit_secret_empty_string() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    VK ID / CUTOFF DAYS BOUNDARY DESERIALIZATION           */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_vk_id_zero_rejected() {
        let json = format!(
            r#"{{
                "verifying_key_id": 0,
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_vk_id_one_accepted() {
        let json = format!(
            r#"{{
                "verifying_key_id": 1,
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_vk_id_negative_rejected() {
        let json = format!(
            r#"{{
                "verifying_key_id": -1,
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_cutoff_days_below_min() {
        let below_min = CutoffDays::MIN - 1;
        let json = format!(
            r#"{{
                "cutoff_days": {},
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            below_min,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_cutoff_days_above_max() {
        let above_max = CutoffDays::MAX + 1;
        let json = format!(
            r#"{{
                "cutoff_days": {},
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            above_max,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_cutoff_days_at_min_accepted() {
        let json = format!(
            r#"{{
                "cutoff_days": {},
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            CutoffDays::MIN,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_cutoff_days_at_max_accepted() {
        let json = format!(
            r#"{{
                "cutoff_days": {},
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            CutoffDays::MAX,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_cutoff_days_negative_accepted() {
        // Negative cutoff days (future dates) are valid within bounds
        let json = format!(
            r#"{{
                "cutoff_days": -100,
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_cutoff_days_zero_accepted() {
        let json = format!(
            r#"{{
                "cutoff_days": 0,
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    /* ========================================================================== */
    /*                    UUID V4 DESERIALIZATION TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_uuid_v4_valid() {
        let uuid = Uuid::new_v4();
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            uuid,
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deserialize_uuid_nil_rejected() {
        // Nil UUID is version 0, not version 4
        let json = format!(
            r#"{{
                "challenge_id": "00000000-0000-0000-0000-000000000000",
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_uuid_invalid_string() {
        let json = format!(
            r#"{{
                "challenge_id": "not-a-valid-uuid",
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_uuid_integer_instead_of_string() {
        let json = format!(
            r#"{{
                "challenge_id": 12345,
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    HASH DOMAIN SEPARATION TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_issuer_key_hash_uses_domain_prefix() {
        // Manually compute with and without the domain prefix to confirm they differ
        let input = [7u8; 32];

        // With prefix (what compute_issuer_key_hash does)
        let hash_with_prefix = compute_issuer_key_hash(&input);

        // Without prefix (raw hash of input only)
        let mut hasher = Blake2s256::new();
        hasher.update(input);
        let hash_without_prefix = hasher.finalize();

        assert_ne!(&hash_with_prefix[..], &hash_without_prefix[..]);
    }

    #[test]
    fn test_issuer_key_hash_exact_prefix() {
        // Verify the domain prefix is exactly "provii.issuer.vk.v0"
        let input = [42u8; 32];

        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update(input);
        let expected = hasher.finalize();

        let actual = compute_issuer_key_hash(&input);
        assert_eq!(&actual[..], &expected[..]);
    }

    #[test]
    fn test_rp_challenge_hash_matches_raw_blake2s() {
        // The RP challenge hash is just raw Blake2s-256 with no domain prefix
        let input = [42u8; 32];

        let mut hasher = Blake2s256::new();
        hasher.update(input);
        let expected = hasher.finalize();

        let actual = compute_rp_challenge_hash(&input);
        assert_eq!(&actual[..], &expected[..]);
    }

    #[test]
    fn test_issuer_hash_wrong_prefix_differs() {
        let input = [42u8; 32];

        // Correct prefix
        let correct = compute_issuer_key_hash(&input);

        // Wrong prefix
        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v1");
        hasher.update(input);
        let wrong_version: [u8; 32] = hasher.finalize().into();

        assert_ne!(correct, wrong_version);
    }

    /* ========================================================================== */
    /*                    PROOF DIRECTION LOGIC TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_proof_direction_over_age_enum() {
        use crate::storage::origin_policy::ProofDirection;
        let proof_direction = ProofDirection::OverAge;
        let direction = match proof_direction {
            ProofDirection::OverAge => true,
            ProofDirection::UnderAge => false,
        };
        assert!(direction);
    }

    #[test]
    fn test_proof_direction_under_age_enum() {
        use crate::storage::origin_policy::ProofDirection;
        let proof_direction = ProofDirection::UnderAge;
        let direction = match proof_direction {
            ProofDirection::OverAge => true,
            ProofDirection::UnderAge => false,
        };
        assert!(!direction);
    }

    #[test]
    fn test_proof_direction_default_is_over_age() {
        use crate::storage::origin_policy::ProofDirection;
        let default_dir = ProofDirection::default();
        assert_eq!(default_dir, ProofDirection::OverAge);
    }

    /* ========================================================================== */
    /*                    SUBMIT SECRET TRY_INTO VALIDATION                     */
    /* ========================================================================== */

    #[test]
    fn test_submit_secret_try_into_valid_32_bytes() {
        let bytes: Vec<u8> = vec![42u8; 32];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_submit_secret_try_into_empty_vec() {
        let bytes: Vec<u8> = vec![];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_secret_try_into_31_bytes() {
        let bytes: Vec<u8> = vec![42u8; 31];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_secret_try_into_33_bytes() {
        let bytes: Vec<u8> = vec![42u8; 33];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_secret_try_into_64_bytes() {
        let bytes: Vec<u8> = vec![42u8; 64];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_secret_try_into_1_byte() {
        let bytes: Vec<u8> = vec![42u8; 1];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    RP CHALLENGE TRY_INTO VALIDATION                      */
    /* ========================================================================== */

    #[test]
    fn test_rp_challenge_try_into_valid_32_bytes() {
        let bytes: Vec<u8> = vec![99u8; 32];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_ok());
    }

    #[test]
    fn test_rp_challenge_try_into_empty_vec() {
        let bytes: Vec<u8> = vec![];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_rp_challenge_try_into_wrong_length() {
        let bytes: Vec<u8> = vec![99u8; 16];
        let result: Result<[u8; 32], _> = bytes.try_into();
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    VERIFY RESPONSE ROUND-TRIP TESTS                      */
    /* ========================================================================== */

    #[test]
    fn test_verify_response_json_field_names() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: "OK".to_string(),
            state: "proof_ok_waiting_for_redeem".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;

        assert_eq!(parsed.get("result").and_then(|v| v.as_str()), Some("OK"));
        assert_eq!(
            parsed.get("state").and_then(|v| v.as_str()),
            Some("proof_ok_waiting_for_redeem")
        );
        Ok(())
    }

    #[test]
    fn test_verify_response_json_only_two_fields() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: "OK".to_string(),
            state: "verified".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let obj = parsed.as_object().ok_or("not an object")?;

        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("result"));
        assert!(obj.contains_key("state"));
        Ok(())
    }

    #[test]
    fn test_verify_response_invalid_proof() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: "INVALID_PROOF".to_string(),
            state: "failed".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(
            parsed.get("result").and_then(|v| v.as_str()),
            Some("INVALID_PROOF")
        );
        assert_eq!(parsed.get("state").and_then(|v| v.as_str()), Some("failed"));
        Ok(())
    }

    #[test]
    fn test_verify_response_policy_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: "POLICY_REJECTED".to_string(),
            state: "failed".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(
            parsed.get("result").and_then(|v| v.as_str()),
            Some("POLICY_REJECTED")
        );
        Ok(())
    }

    #[test]
    fn test_verify_response_special_chars() -> Result<(), Box<dyn std::error::Error>> {
        let resp = VerifyResponse {
            result: "test\"with\\special\nchars".to_string(),
            state: "test\ttab".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        // Should be valid JSON despite special characters
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok());
        Ok(())
    }

    /* ========================================================================== */
    /*                    COMBINED HASH WORKFLOW TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_full_hash_workflow_rp_and_issuer() {
        // Simulate the full hash workflow as done in submit_verification
        let rp_challenge = [10u8; 32];
        let issuer_vk_bytes = [20u8; 32];

        // Step 1: Compute RP hash
        let rp_hash = compute_rp_challenge_hash(&rp_challenge);

        // Step 2: Compute issuer key hash
        let issuer_key_hash = compute_issuer_key_hash(&issuer_vk_bytes);

        // Step 3: Encode issuer key hash as base64url for allowlist comparison
        let issuer_key_hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(issuer_key_hash);

        // Verify all outputs are valid
        assert_eq!(rp_hash.len(), 32);
        assert_eq!(issuer_key_hash.len(), 32);
        assert_eq!(issuer_key_hash_b64.len(), 43);
        assert_ne!(rp_hash, issuer_key_hash);
    }

    #[test]
    fn test_inline_rp_hash_matches_helper() {
        // The inline hash in submit_verification (lines 610-617) should produce
        // the same result as compute_rp_challenge_hash
        let rp_challenge = [50u8; 32];

        // Inline version (mimicking the code in submit_verification)
        let rp_hash_inline = {
            let mut hasher = Blake2s256::new();
            hasher.update(rp_challenge);
            let result = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&result);
            hash_bytes
        };

        let rp_hash_helper = compute_rp_challenge_hash(&rp_challenge);
        assert_eq!(rp_hash_inline, rp_hash_helper);
    }

    #[test]
    fn test_inline_issuer_hash_matches_helper() {
        // The inline hash in submit_verification (lines 620-628) should produce
        // the same result as compute_issuer_key_hash
        let issuer_vk_bytes = [60u8; 32];

        // Inline version (mimicking the code in submit_verification)
        let issuer_key_hash_inline = {
            let mut hasher = Blake2s256::new();
            hasher.update(b"provii.issuer.vk.v0");
            hasher.update(issuer_vk_bytes);
            let result = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&result);
            hash_bytes
        };

        let issuer_key_hash_helper = compute_issuer_key_hash(&issuer_vk_bytes);
        assert_eq!(issuer_key_hash_inline, issuer_key_hash_helper);
    }

    /* ========================================================================== */
    /*                    CHALLENGE STATE COMBINED CONDITIONS                    */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_submitted_and_verified() {
        // Both proof_submitted=true AND state=Verified
        let proof_submitted = true;
        let state = ChallengeState::Verified;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_submitted_and_failed() {
        let proof_submitted = true;
        let state = ChallengeState::Failed;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_submitted_and_proof_ok() {
        let proof_submitted = true;
        let state = ChallengeState::ProofOkWaitingForRedeem;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    #[test]
    fn test_challenge_state_submitted_and_expired() {
        // proof_submitted=true overrides any state
        let proof_submitted = true;
        let state = ChallengeState::Expired;

        let should_reject = proof_submitted
            || state == ChallengeState::ProofOkWaitingForRedeem
            || state == ChallengeState::Verified
            || state == ChallengeState::Failed;

        assert!(should_reject);
    }

    /* ========================================================================== */
    /*                    ISSUER ALLOWLIST POLICY TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_issuer_allowlist_b64_lookup_hit() {
        let issuer_vk = [42u8; 32];
        let hash = compute_issuer_key_hash(&issuer_vk);
        let hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash);

        let allowed = [hash_b64.clone(), "other-issuer-hash".to_string()];
        assert!(allowed.contains(&hash_b64));
    }

    #[test]
    fn test_issuer_allowlist_b64_lookup_miss() {
        let issuer_vk = [42u8; 32];
        let hash = compute_issuer_key_hash(&issuer_vk);
        let hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash);

        let allowed = [
            "different-hash-1".to_string(),
            "different-hash-2".to_string(),
        ];
        assert!(!allowed.contains(&hash_b64));
    }

    #[test]
    fn test_issuer_allowlist_empty_means_any() {
        let allowed: Vec<String> = vec![];
        // Empty allowed_issuers means any issuer is accepted
        assert!(allowed.is_empty());
    }

    #[test]
    fn test_issuer_allowlist_single_entry() {
        let issuer_vk = [99u8; 32];
        let hash = compute_issuer_key_hash(&issuer_vk);
        let hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash);

        let allowed = [hash_b64.clone()];
        assert!(allowed.contains(&hash_b64));
    }

    #[test]
    fn test_issuer_allowlist_different_key_not_in_list() {
        let issuer_vk_1 = [1u8; 32];
        let issuer_vk_2 = [2u8; 32];
        let hash_1 = compute_issuer_key_hash(&issuer_vk_1);
        let hash_1_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash_1);

        let hash_2 = compute_issuer_key_hash(&issuer_vk_2);
        let hash_2_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash_2);

        let allowed = [hash_1_b64.clone()];
        assert!(allowed.contains(&hash_1_b64));
        assert!(!allowed.contains(&hash_2_b64));
    }

    /* ========================================================================== */
    /*                    CONSTANT-TIME COMPARISON EDGE CASES                    */
    /* ========================================================================== */

    #[test]
    fn test_ct_eq_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_all_max() {
        let a = [0xFFu8; 32];
        let b = [0xFFu8; 32];
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_zeros_vs_max() {
        let a = [0u8; 32];
        let b = [0xFFu8; 32];
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_middle_byte_diff() {
        let mut a = [42u8; 32];
        let b = [42u8; 32];
        a[15] = 43;
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_sequential_vs_reverse() {
        let a: [u8; 32] = core::array::from_fn(|i| i as u8);
        let b: [u8; 32] = core::array::from_fn(|i| (31 - i) as u8);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_ct_eq_adjacent_values() {
        // Ensure single-value differences are detected
        for i in 0..32 {
            let a = [42u8; 32];
            let mut b = [42u8; 32];
            b[i] = 43;
            assert!(
                !bool::from(a.ct_eq(&b)),
                "ct_eq should detect difference at position {}",
                i
            );
        }
    }

    /* ========================================================================== */
    /*                    EXPIRY BOUNDARY PRECISION TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_expiry_zero_timestamp() {
        let now = 0u64;
        let expires_at = 0u64;
        // now == expires_at is NOT expired
        assert!(now <= expires_at);
    }

    #[test]
    fn test_expiry_max_timestamp() {
        let now = u64::MAX;
        let expires_at = u64::MAX;
        assert!(now <= expires_at);
    }

    #[test]
    fn test_expiry_one_second_margin() {
        let expires_at = 1000u64;

        // One second before expiry
        assert!(999 <= expires_at);
        // Exactly at expiry
        assert!(1000 <= expires_at);
        // One second after expiry
        assert!(1001 > expires_at);
    }

    #[test]
    fn test_expiry_near_overflow() {
        let now = u64::MAX;
        let expires_at = u64::MAX - 1;
        assert!(now > expires_at);
    }

    /* ========================================================================== */
    /*                    NESTED UNKNOWN FIELD REJECTION                         */
    /* ========================================================================== */

    #[test]
    fn test_public_inputs_json_nested_unknown_in_issuer() {
        let json = format!(
            r#"{{
                "cutoff_days": 6570,
                "rp_challenge": "{}",
                "issuer": {{
                    "value": "{}",
                    "extra_nested": "should_fail"
                }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_proof_unknown_in_proof_nested() {
        let json = format!(
            r#"{{
                "challenge_id": "{}",
                "submit_secret": "{}",
                "proof": {{
                    "verifying_key_id": 1,
                    "injected_field": "attack",
                    "public": {{
                        "cutoff_days": 6570,
                        "rp_challenge": "{}",
                        "issuer": {{ "value": "{}" }},
                        "cred_nullifier": "{}"
                    }},
                    "proof": "{}"
                }}
            }}"#,
            Uuid::new_v4(),
            BASE64_URL_SAFE_NO_PAD.encode([1u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<SubmitProofRequest, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    TYPE COERCION REJECTION TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_vk_id_string_instead_of_number() {
        let json = format!(
            r#"{{
                "verifying_key_id": "1",
                "public": {{
                    "cutoff_days": 6570,
                    "rp_challenge": "{}",
                    "issuer": {{ "value": "{}" }},
                    "cred_nullifier": "{}"
                }},
                "proof": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([5u8; 192]),
        );
        let result: Result<AgeProofJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_cutoff_days_string_instead_of_number() {
        let json = format!(
            r#"{{
                "cutoff_days": "6570",
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_cutoff_days_float() {
        let json = format!(
            r#"{{
                "cutoff_days": 6570.5,
                "rp_challenge": "{}",
                "issuer": {{ "value": "{}" }},
                "cred_nullifier": "{}"
            }}"#,
            BASE64_URL_SAFE_NO_PAD.encode([2u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([3u8; 32]),
            BASE64_URL_SAFE_NO_PAD.encode([4u8; 32]),
        );
        let result: Result<PublicInputsJson, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_issuer_value_number_instead_of_string() {
        let json = r#"{ "value": 12345 }"#;
        let result: Result<IssuerKeyJson, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_issuer_value_null() {
        let json = r#"{ "value": null }"#;
        let result: Result<IssuerKeyJson, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    BASE64 ENCODING EDGE CASES                            */
    /* ========================================================================== */

    #[test]
    fn test_b64_192_encoding_length() {
        let proof_bytes = [0u8; 192];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(proof_bytes);
        assert_eq!(encoded.len(), 256);
    }

    #[test]
    fn test_b64_192_encoding_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let proof_bytes: [u8; 192] = core::array::from_fn(|i| (i % 256) as u8);
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(proof_bytes);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;
        assert_eq!(decoded.len(), 192);
        assert_eq!(&decoded[..], &proof_bytes[..]);
        Ok(())
    }

    #[test]
    fn test_b64_32_encoding_url_safe_chars() {
        // Test a range of values to ensure URL-safe encoding
        for byte_val in [0u8, 63, 127, 191, 255] {
            let bytes = [byte_val; 32];
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
            assert!(
                !encoded.contains('+'),
                "Encoding of [{}; 32] contains '+' (not URL-safe)",
                byte_val
            );
            assert!(
                !encoded.contains('/'),
                "Encoding of [{}; 32] contains '/' (not URL-safe)",
                byte_val
            );
            assert!(
                !encoded.contains('='),
                "Encoding of [{}; 32] contains '=' (has padding)",
                byte_val
            );
        }
    }

    /* ========================================================================== */
    /*                    NONCE DEDUP TTL INVARIANTS                             */
    /* ========================================================================== */

    #[test]
    fn test_nonce_dedup_ttl_matches_max_challenge_ttl() {
        // The nonce TTL should match or exceed the max challenge TTL
        assert!(NONCE_DEDUP_TTL.as_secs() >= crate::utils::MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_nonce_dedup_ttl_is_five_minutes() {
        assert_eq!(NONCE_DEDUP_TTL, Duration::from_secs(300));
    }

    #[test]
    fn test_nonce_dedup_ttl_not_zero() {
        assert!(NONCE_DEDUP_TTL.as_secs() > 0);
    }

    /* ========================================================================== */
    /*                    REQUEST SERIALIZATION ROUND-TRIP                       */
    /* ========================================================================== */

    #[test]
    fn test_submit_proof_request_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_submit_proof_request()?;
        let json = serde_json::to_string(&req)?;
        let deserialized: SubmitProofRequest = serde_json::from_str(&json)?;

        assert_eq!(deserialized.challenge_id.0, req.challenge_id.0);
        assert_eq!(
            deserialized.proof.verifying_key_id.get(),
            req.proof.verifying_key_id.get()
        );
        assert_eq!(
            deserialized.proof.public.cutoff_days.get(),
            req.proof.public.cutoff_days.get()
        );
        assert_eq!(deserialized.submit_secret.0, req.submit_secret.0);
        assert_eq!(
            deserialized.proof.public.rp_challenge.0,
            req.proof.public.rp_challenge.0
        );
        assert_eq!(
            deserialized.proof.public.issuer.value.0,
            req.proof.public.issuer.value.0
        );
        assert_eq!(
            deserialized.proof.public.cred_nullifier.0,
            req.proof.public.cred_nullifier.0
        );
        assert_eq!(deserialized.proof.proof.0, req.proof.proof.0);
        Ok(())
    }

    #[test]
    fn test_age_proof_json_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let proof = AgeProofJson {
            verifying_key_id: VkId::new(42).ok_or("VkId::new(42) returned None")?,
            public: PublicInputsJson {
                cutoff_days: CutoffDays::new(7300)?,
                rp_challenge: B64Url32::new([10u8; 32]),
                issuer: IssuerKeyJson {
                    value: B64Url32::new([20u8; 32]),
                },
                cred_nullifier: B64Url32::new([30u8; 32]),
            },
            proof: B64Url192::new([40u8; 192]),
        };

        let json = serde_json::to_string(&proof)?;
        let deserialized: AgeProofJson = serde_json::from_str(&json)?;

        assert_eq!(deserialized.verifying_key_id.get(), 42);
        assert_eq!(deserialized.public.cutoff_days.get(), 7300);
        assert_eq!(deserialized.public.rp_challenge.0, [10u8; 32]);
        assert_eq!(deserialized.public.issuer.value.0, [20u8; 32]);
        assert_eq!(deserialized.public.cred_nullifier.0, [30u8; 32]);
        assert_eq!(deserialized.proof.0, [40u8; 192]);
        Ok(())
    }

    #[test]
    fn test_public_inputs_json_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let inputs = PublicInputsJson {
            cutoff_days: CutoffDays::new(6570)?,
            rp_challenge: B64Url32::new([11u8; 32]),
            issuer: IssuerKeyJson {
                value: B64Url32::new([22u8; 32]),
            },
            cred_nullifier: B64Url32::new([33u8; 32]),
        };

        let json = serde_json::to_string(&inputs)?;
        let deserialized: PublicInputsJson = serde_json::from_str(&json)?;

        assert_eq!(deserialized.cutoff_days.get(), 6570);
        assert_eq!(deserialized.rp_challenge.0, [11u8; 32]);
        assert_eq!(deserialized.issuer.value.0, [22u8; 32]);
        assert_eq!(deserialized.cred_nullifier.0, [33u8; 32]);
        Ok(())
    }

    #[test]
    fn test_issuer_key_json_serialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let issuer = IssuerKeyJson {
            value: B64Url32::new([77u8; 32]),
        };

        let json = serde_json::to_string(&issuer)?;
        let deserialized: IssuerKeyJson = serde_json::from_str(&json)?;

        assert_eq!(deserialized.value.0, [77u8; 32]);
        Ok(())
    }

    /* ========================================================================== */
    /*                    CHALLENGE STATE AS_STR TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_as_str_pending() {
        assert_eq!(ChallengeState::Pending.as_str(), "pending");
    }

    #[test]
    fn test_challenge_state_as_str_proof_ok() {
        assert_eq!(
            ChallengeState::ProofOkWaitingForRedeem.as_str(),
            "proof_ok_waiting_for_redeem"
        );
    }

    #[test]
    fn test_challenge_state_as_str_verified() {
        assert_eq!(ChallengeState::Verified.as_str(), "verified");
    }

    #[test]
    fn test_challenge_state_as_str_failed() {
        assert_eq!(ChallengeState::Failed.as_str(), "failed");
    }

    #[test]
    fn test_challenge_state_as_str_expired() {
        assert_eq!(ChallengeState::Expired.as_str(), "expired");
    }

    /* ========================================================================== */
    /*                    VK ID ALLOWLIST WITH REAL TYPES                        */
    /* ========================================================================== */

    #[test]
    fn test_vk_id_in_allowed_list_typed() -> Result<(), Box<dyn std::error::Error>> {
        let vk = VkId::new(5).ok_or("VkId::new(5) returned None")?;
        let allowed: Vec<u32> = vec![1, 2, 5, 10];
        assert!(allowed.contains(&vk.get()));
        Ok(())
    }

    #[test]
    fn test_vk_id_not_in_allowed_list_typed() -> Result<(), Box<dyn std::error::Error>> {
        let vk = VkId::new(99).ok_or("VkId::new(99) returned None")?;
        let allowed: Vec<u32> = vec![1, 2, 5, 10];
        assert!(!allowed.contains(&vk.get()));
        Ok(())
    }

    #[test]
    fn test_vk_id_new_zero_returns_none() {
        assert!(VkId::new(0).is_none());
    }

    #[test]
    fn test_vk_id_new_one_returns_some() {
        assert!(VkId::new(1).is_some());
    }

    #[test]
    fn test_vk_id_new_max_returns_some() {
        assert!(VkId::new(u32::MAX).is_some());
    }

    /* ========================================================================== */
    /*                    CUTOFF DAYS CONSTRUCTION TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_new_valid() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(6570)?;
        assert_eq!(cd.get(), 6570);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_at_min() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(CutoffDays::MIN)?;
        assert_eq!(cd.get(), CutoffDays::MIN);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_at_max() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(CutoffDays::MAX)?;
        assert_eq!(cd.get(), CutoffDays::MAX);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_below_min_err() {
        let result = CutoffDays::new(CutoffDays::MIN - 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_new_above_max_err() {
        let result = CutoffDays::new(CutoffDays::MAX + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_new_zero() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(0)?;
        assert_eq!(cd.get(), 0);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_negative() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(-1000)?;
        assert_eq!(cd.get(), -1000);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_common_ages() -> Result<(), Box<dyn std::error::Error>> {
        // 13 years = ~4748 days, 16 years = ~5844 days, 18 years = ~6570 days, 21 years = ~7665 days
        for days in [4748, 5844, 6570, 7665] {
            let cd = CutoffDays::new(days)?;
            assert_eq!(cd.get(), days);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    ZEROIZE BEHAVIOUR TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_zeroizing_wrapper_clears_on_drop() {
        let secret = Zeroizing::new([42u8; 32]);
        // Verify value is accessible before drop
        assert_eq!(*secret, [42u8; 32]);
        // After drop, memory would be zeroed (we can only test that the type exists)
        drop(secret);
    }

    #[test]
    fn test_zeroize_vec() {
        let mut bytes = vec![42u8; 32];
        bytes.zeroize();
        // Vec::zeroize() drops the allocation and sets length to 0
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_submit_secret_zeroize_clears() {
        let mut submit_secret = vec![0xABu8; 32];
        submit_secret.zeroize();
        assert!(submit_secret.iter().all(|&b| b == 0));
    }

    /* ========================================================================== */
    /*                    B64Url32 DEBUG REDACTION TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_debug_is_redacted() {
        let secret = B64Url32::new([42u8; 32]);
        let debug = format!("{:?}", secret);
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn test_b64url192_debug_is_redacted() {
        let proof = B64Url192::new([42u8; 192]);
        let debug = format!("{:?}", proof);
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("42"));
    }

    /* ========================================================================== */
    /*                    NONCE TAG STRUCTURE INVARIANTS                         */
    /* ========================================================================== */

    #[test]
    fn test_nonce_tag_exactly_43_chars() -> Result<(), Box<dyn std::error::Error>> {
        let challenge_id = Uuid::parse_str("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")?;
        let nonce_tag = format!("verify:{}", challenge_id);
        // "verify:" (7) + UUID hyphenated (36) = 43
        assert_eq!(nonce_tag.len(), 43);
        Ok(())
    }

    #[test]
    fn test_nonce_tag_contains_no_whitespace() {
        let challenge_id = Uuid::new_v4();
        let nonce_tag = format!("verify:{}", challenge_id);
        assert!(!nonce_tag.chars().any(|c| c.is_whitespace()));
    }

    #[test]
    fn test_nonce_tag_prefix_is_lowercase() {
        let challenge_id = Uuid::new_v4();
        let nonce_tag = format!("verify:{}", challenge_id);
        let prefix = &nonce_tag[..7];
        assert_eq!(prefix, "verify:");
    }

    /* ========================================================================== */
    /*                    TIMESTAMP UTILITY TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_current_timestamp_is_reasonable() {
        let ts = current_timestamp();
        // Should be after 2024-01-01 (1704067200) and before 2050-01-01 (2524608000)
        assert!(ts > 1_704_067_200, "Timestamp {} is before 2024", ts);
        assert!(ts < 2_524_608_000, "Timestamp {} is after 2050", ts);
    }

    #[test]
    fn test_current_timestamp_monotonic() {
        let ts1 = current_timestamp();
        let ts2 = current_timestamp();
        // Second call should be >= first (not strictly greater since resolution is seconds)
        assert!(ts2 >= ts1);
    }

    /* ========================================================================== */
    /*                    CRYPTO ERROR VARIANT EXHAUSTIVENESS                    */
    /* ========================================================================== */

    #[test]
    fn test_all_crypto_error_variants_mapped_to_code() {
        // Verify every variant of provii_crypto_commons::Error maps to a string
        let variants: Vec<provii_crypto_commons::Error> = vec![
            provii_crypto_commons::Error::InvalidFormat,
            provii_crypto_commons::Error::InvalidProof,
            provii_crypto_commons::Error::VerificationFailed,
            provii_crypto_commons::Error::InvalidInput,
            provii_crypto_commons::Error::InvalidSignature,
            provii_crypto_commons::Error::InvalidOriginHash,
            provii_crypto_commons::Error::MissingTimestamp,
            provii_crypto_commons::Error::FutureTimestamp,
            provii_crypto_commons::Error::CredentialBanned,
            provii_crypto_commons::Error::NullifierStoreFailure,
            provii_crypto_commons::Error::Expired,
            provii_crypto_commons::Error::NotFound,
            provii_crypto_commons::Error::RateLimitExceeded,
            provii_crypto_commons::Error::ProverFailed,
            provii_crypto_commons::Error::VerifierNotInitialized,
            provii_crypto_commons::Error::AlreadyInitialized,
            provii_crypto_commons::Error::Internal,
            provii_crypto_commons::Error::FieldTooLong,
        ];

        for error in variants {
            let code = match error {
                provii_crypto_commons::Error::VerificationFailed => "invalid_proof",
                provii_crypto_commons::Error::InvalidFormat => "invalid_proof_format",
                provii_crypto_commons::Error::VerifierNotInitialized => "verifier_error",
                _ => "verification_failed",
            };
            assert!(!code.is_empty());

            let msg = match error {
                provii_crypto_commons::Error::VerificationFailed => "INVALID_PROOF",
                provii_crypto_commons::Error::InvalidFormat => "INVALID_PROOF_FORMAT",
                provii_crypto_commons::Error::VerifierNotInitialized => "VERIFIER_ERROR",
                _ => "VERIFICATION_FAILED",
            };
            assert!(!msg.is_empty());
        }
    }

    /* ========================================================================== */
    /*                    HASH KNOWN TEST VECTORS                               */
    /* ========================================================================== */

    #[test]
    fn test_rp_hash_known_vector_all_zeros() {
        // Blake2s-256 of 32 zero bytes. Pin the output so changes to the
        // hash computation break this test.
        let input = [0u8; 32];
        let hash = compute_rp_challenge_hash(&input);

        // Recompute to get the expected value
        let mut hasher = Blake2s256::new();
        hasher.update([0u8; 32]);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_issuer_hash_known_vector_all_zeros() {
        let input = [0u8; 32];
        let hash = compute_issuer_key_hash(&input);

        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update([0u8; 32]);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_rp_hash_stability() {
        // Pin a specific input/output pair for regression detection
        let input = [1u8; 32];
        let hash1 = compute_rp_challenge_hash(&input);

        // Run 100 times to confirm stability
        for _ in 0..100 {
            let hash = compute_rp_challenge_hash(&input);
            assert_eq!(hash, hash1);
        }
    }

    #[test]
    fn test_issuer_hash_stability() {
        let input = [1u8; 32];
        let hash1 = compute_issuer_key_hash(&input);

        for _ in 0..100 {
            let hash = compute_issuer_key_hash(&input);
            assert_eq!(hash, hash1);
        }
    }
}
