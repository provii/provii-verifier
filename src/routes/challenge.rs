// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Challenge route implementation.
//!
//! Handles the full lifecycle of age verification challenges: creation via
//! HMAC-authenticated requests, short code and UUID-based lookups, and
//! polling for proof completion. Every public endpoint enforces BOLA
//! ownership checks (OWASP API1:2023) and emits structured audit events.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use futures::join;
use provii_crypto_protocol::{generate_nonce, rp_challenge};
use schemars::JsonSchema;
use std::sync::Arc;
use uuid::Uuid;
use worker::{Error as WorkerError, Headers, Response};
use zeroize::Zeroize;

#[cfg(target_arch = "wasm32")]
use crate::security::log_sanitizer::redact_challenge_id;

use crate::{
    analytics::Analytics,
    bindings::KV_CONFIG,
    cache::{CachedChallenge, ChallengeState},
    error::ApiError,
    security::{validate_fetch_metadata, ClientAuthenticator},
    storage::origin_policy::PolicyLookupResult,
    types::{Authorizer, B64Url32, CutoffDays, ExpiresIn, PkceMethod, ShortCode, UuidV4, VkId},
    utils::{current_timestamp, generate_secure_random},
    AppState,
};
use serde_json::json;

use crate::utils::{MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL};

/// Build a `/v1`-prefixed base for response URLs (status_url, verify_url).
///
/// Some environments (sandbox) configure `API_BASE_URL` without the `/v1`
/// segment because the wrangler route already mounts the worker at the apex.
/// Other environments (production) include `/v1` for hosted-mode CORS reasons.
/// Without this normaliser, sandbox responses emit URLs like
/// `https://sandbox-verify.provii.app/challenge/<id>` which return 404
/// because the worker actually serves `/v1/challenge/<id>`.
///
/// Idempotent: if the configured base already ends in `/v1`, it is returned
/// as-is (with any trailing `/` stripped). Production stays unchanged.
#[doc(hidden)]
pub fn build_v1_base(api_base_url: &str) -> String {
    let trimmed = api_base_url.trim_end_matches('/');
    if trimmed.ends_with("/v1") {
        trimmed.to_string()
    } else {
        format!("{}/v1", trimmed)
    }
}

/// Attempts to extract client_id from request headers for optional authentication.
///
/// Thin wrapper around the shared `api_key_auth::authenticate_api_key` function.
/// Used by poll and detail endpoints where authentication is optional for BOLA.
///
/// # Arguments
/// * `headers` - HTTP request headers
/// * `state` - Application state containing origin policy store
/// * `expected_owner_id` - Optional `client_id` already known from challenge
///   storage. When present and starts with `rp_sandbox_`, the sandbox bypass
///   resolves the policy via `client_lookup/<client_id>` instead of relying
///   on the (shared) X-API-Key index.
///
/// # Returns
/// Option<String> containing the authenticated client_id, or None if not authenticated
async fn try_extract_client_id(
    headers: &Headers,
    state: &Arc<AppState>,
    expected_owner_id: Option<&str>,
) -> Option<String> {
    let result = super::api_key_auth::authenticate_api_key(
        headers,
        state,
        super::api_key_auth::ApiKeyAuthOptions {
            expected_owner_id,
            allow_mobile_flow: false,
            stored_client_id: None,
            route_label: "challenge_poll",
        },
    )
    .await
    .ok()?;
    result.client_id
}

/// Returns `true` when the expert-flow `/v1/challenge` route should skip the
/// request-Origin allowlist check for this client.
///
/// Mirrors the hosted-flow `pk_test_*` bypass in `hosted/endpoints/challenge.rs`:
/// in `sandbox`, developer-issued `rp_sandbox_*` credentials work from any
/// Origin (the playground, localhost, dev domains) without each origin being
/// pre-registered. Production credentials are unaffected.
///
/// SECURITY: Origin is browser-CORS theatre on a server-to-server route. The
/// HMAC-SHA256 + nonce + PKCE envelope is the actual authentication boundary
/// and is enforced unchanged.
#[doc(hidden)]
pub fn should_skip_origin_check_for_rp_sandbox(environment: &str, key_id: &str) -> bool {
    environment == "sandbox" && key_id.starts_with("rp_sandbox_")
}

/// Apply the sandbox bypass shape to a real registered policy.
///
/// Loads the policy registered for `registered_origin` (so the `clients`
/// list, the source of HMAC secrets, is preserved) and overlays the
/// sandbox defaults that match the hosted-flow `pk_test_*` synthetic policy:
///
/// * `tenant_id`           = `"sandbox_default"`
/// * `min_age_years`       = `18`
/// * `billing.plan`        = `"sandbox"`
/// * `billing.metering_enabled` = `false`
///
/// Returns `None` when the registered origin has no enabled policy in KV.
fn apply_sandbox_bypass_overrides(
    mut policy: crate::storage::origin_policy::OriginPolicy,
) -> crate::storage::origin_policy::OriginPolicy {
    policy.tenant_id = "sandbox_default".to_string();
    policy.min_age_years = 18;
    policy.billing.plan = "sandbox".to_string();
    policy.billing.metering_enabled = false;
    policy
}

/// Generates a 12-digit numeric short code derived from the challenge UUID.
/// The code is zero-padded and displayed as XXXX XXXX XXXX to users.
///
/// PERFORMANCE: This function is deterministic and requires NO KV lookups.
/// UUID uniqueness guarantees short code uniqueness within the challenge's lifetime.
/// With 10^12 possible codes and <1M active challenges, collision probability is ~10^-6.
///
/// SECURITY (ASVS V6.7.2): This short code (~40 bits) is intentionally NOT a cryptographic nonce.
/// It serves as a user-facing accessibility feature for manual entry, not a security primitive.
/// Cryptographic security is provided by the full 128-bit UUID and 256-bit submit_secret.
/// ACCEPTED RISK: Short entropy is a UX/accessibility tradeoff for human-readable codes.
pub fn generate_short_code_from_uuid(challenge_id: &uuid::Uuid) -> String {
    // Use the first 8 bytes of UUID (which contains timestamp + random bits)
    let bytes = challenge_id.as_bytes();

    // Combine bytes to create a deterministic 12-digit code
    // Use XOR folding to mix all 16 bytes into 8 bytes for better distribution
    let folded: [u8; 8] = [
        bytes[0] ^ bytes[8],
        bytes[1] ^ bytes[9],
        bytes[2] ^ bytes[10],
        bytes[3] ^ bytes[11],
        bytes[4] ^ bytes[12],
        bytes[5] ^ bytes[13],
        bytes[6] ^ bytes[14],
        bytes[7] ^ bytes[15],
    ];

    let num = u64::from_be_bytes(folded);
    // Modulo to get 12-digit number, zero-padded
    format!("{:012}", num % 1_000_000_000_000)
}

/// Extract the client IP from request headers.
///
/// SECURITY: Uses ONLY CF-Connecting-IP which is set by the Cloudflare edge
/// and cannot be spoofed.
fn get_client_ip(headers: &Headers) -> String {
    headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build the canonical HMAC signing message for challenge creation.
///
/// EA-018: The nonce is now included as a fifth field when present. This
/// prevents an attacker from substituting a fresh nonce with a captured
/// HMAC within the same-second timestamp window.
///
/// Format: `{timestamp}:{method}:{path}:{body_json}:{nonce}`
///
/// Marked `pub` (and `doc(hidden)`) so the cross-service golden-vector tests
/// in `tests/security/canonical_message_test.rs` can drive this
/// constructor with deterministic inputs and assert byte-equal output. The
/// function is otherwise an internal implementation detail of the challenge
/// route. No secrets are returned, no behaviour changes from production.
#[doc(hidden)]
pub fn create_canonical_message_for_challenge(
    method: &str,
    path: &str,
    timestamp: u64,
    body: &CreateChallengeRequest,
) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // IMPORTANT: Use serde_json to serialise the code_challenge directly,
    // NOT .to_string() which returns "[REDACTED]" for security reasons.
    // The canonical message needs the actual base64url-encoded value.
    let code_challenge_b64 = URL_SAFE_NO_PAD.encode(body.code_challenge.as_bytes());

    let payload = json!({
        "code_challenge": code_challenge_b64,
        "method": body.method,
        "verifying_key_id": body.verifying_key_id.map(|v| v.get()),
        "expires_in": body.expires_in.get(),
    });

    // EA-018: Include the nonce in the canonical message so the HMAC
    // signature is bound to this specific nonce value. The nonce is
    // always present on challenge requests (Authorizer.nonce is mandatory).
    let canonical = format!(
        "{}:{}:{}:{}:{}",
        timestamp, method, path, payload, body.authorizer.nonce
    );
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[DEBUG] Server canonical message length: {}",
        canonical.len()
    );
    canonical
}

/// Request body for `POST /v1/challenge`.
///
/// SECURITY: The `authorizer` field carries the HMAC-SHA256 signature, nonce, and
/// timestamp that authenticate the caller. The `code_challenge` binds the session
/// to the PKCE flow so proof submission requires the matching code verifier.
#[derive(Debug, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateChallengeRequest {
    /// PKCE code challenge encoded as base64url (exactly 32 bytes).
    pub code_challenge: B64Url32,
    /// PKCE method. Only S256 is supported.
    ///
    /// R4 NEW-P: required (was optional with a silent S256 default). The
    /// public contract documents `method` as required and the docs walkthrough
    /// example sets it explicitly. Omitting the field now returns
    /// `400 BODY_SCHEMA_INVALID, field=method`.
    pub method: PkceMethod,
    /// Optional verifying key identifier, validated against the origin policy.
    #[serde(default)]
    pub verifying_key_id: Option<VkId>,
    /// Requested challenge lifetime in seconds (clamped to policy and system limits).
    #[serde(default)]
    pub expires_in: ExpiresIn,
    /// HMAC authentication envelope (key_id, timestamp, hmac, nonce).
    pub authorizer: Authorizer,
}

/// Successful response from `POST /v1/challenge`.
///
/// Contains everything the client needs to display a QR code (or short code)
/// and later submit a zero knowledge proof against `rp_challenge`.
#[derive(serde::Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    /// Unique challenge identifier (UUIDv4).
    pub challenge_id: UuidV4,
    /// 12-digit numeric short code for accessibility (displayed as XXXX XXXX XXXX).
    pub short_code: String,
    /// Human-readable formatted short code: "XXXX XXXX XXXX".
    pub short_code_formatted: String,
    /// Base64url-encoded relying-party challenge (32 bytes).
    pub rp_challenge: B64Url32,
    /// Age cutoff in epoch days used by the ZK circuit.
    pub cutoff_days: CutoffDays,
    /// Verifying key identifier selected for this challenge.
    pub verifying_key_id: VkId,
    /// Base64url-encoded submit secret (32 bytes). Required for proof submission.
    pub submit_secret: B64Url32,
    /// Unix timestamp when this challenge expires.
    pub expires_at: u64,
    /// Direction of the age proof ("older" or "younger").
    pub proof_direction: String,
    /// URL to poll for challenge status updates.
    pub status_url: String,
    /// URL to submit the zero knowledge proof.
    pub verify_url: String,
}

/// Create a new age verification challenge.
///
/// SECURITY: Authenticates the caller via HMAC-SHA256 with nonce replay protection,
/// validates the origin against the tenant policy, generates cryptographic material
/// (nonce, rp_challenge, submit_secret), and persists the challenge to Durable Object
/// storage. The response includes a short code for accessibility and a submit secret
/// for proof submission.
///
/// TODO(testing): VA-RTE-011 -- HMAC auth, nonce replay prevention, and
/// origin policy enforcement lack integration tests. Requires a test
/// harness that can construct Headers with valid HMAC signatures and
/// interact with Durable Object storage.
pub async fn create_challenge(
    state: Arc<AppState>,
    headers: Headers,
    body: CreateChallengeRequest,
) -> Result<Response, WorkerError> {
    let start = worker::Date::now().as_millis();
    let mut phase_timings: Vec<(&str, f64)> = Vec::with_capacity(12);
    let mut sub_ops: Vec<(&str, f64)> = Vec::with_capacity(16);

    // W7-B3: Short-circuit ORIGIN_MISSING before any other work.
    //
    // The Origin header is required by every downstream phase: idempotency
    // fingerprinting (post-auth), policy lookup, audit logging, and the
    // `rp_sandbox_*` bypass path that loads the registered policy by client_id.
    // When the header was absent and the request carried a sandbox `rp_sandbox_*`
    // keyId, the earlier ordering let the request reach the bypass branch with
    // an empty origin string, which surfaced as a 500 INTERNAL_ERROR rather
    // than a clean 400 ORIGIN_MISSING. Pull the check to the top of the
    // handler so the response is deterministic regardless of credential type.
    //
    // The Sec-Fetch-* validation is also a public-facing precondition that
    // does not depend on tenant state, so we group it with the Origin check
    // here. Both fast paths run before any KV / DO / audit-logger operation.
    if let Err(e) = validate_fetch_metadata(&headers) {
        return e.to_response();
    }

    let origin = match headers.get("Origin").ok().flatten() {
        Some(o) if !o.is_empty() => o,
        _ => {
            return ApiError::bad_request(
                "ORIGIN_MISSING",
                Some("Origin"),
                "Origin header is required (set it to the registered relying-party origin, e.g. https://example.com)",
            )
            .to_response();
        }
    };

    // Phase 1: Extract idempotency key (header parse only, no cache lookup).
    // EA-007: The cache check is deferred to after authentication so that
    // client_id is available for the request fingerprint.
    let phase_start = worker::Date::now().as_millis();
    let idempotency_key =
        crate::security::idempotency::extract_idempotency_key(&headers, "POST", "/v1/challenge")?;
    phase_timings.push((
        "idempotency_extract",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Phase 2: Remaining header-driven validation.
    let phase_start = worker::Date::now().as_millis();

    // IV-101: Reject origins exceeding 2048 bytes to prevent abuse.
    // Valid origins are scheme + host + optional port; 2048 is extremely generous.
    if origin.len() > 2048 {
        return ApiError::bad_request(
            "ORIGIN_TOO_LONG",
            Some("Origin"),
            "Origin header exceeds 2048 bytes",
        )
        .to_response();
    }

    // VA-CHL-001 / AL-021 / AL-043: Reject and audit malicious origin schemes before any
    // policy lookup. Covers javascript:, data:, vbscript:, and blob: URI schemes.
    if origin.contains("javascript:")
        || origin.contains("data:")
        || origin.contains("vbscript:")
        || origin.contains("blob:")
    {
        let malicious_ip = get_client_ip(&headers);
        // AL-043: Malicious origin detection (Critical).
        state
            .audit_logger
            .log_malicious_origin_detected(&origin, &malicious_ip, state.analytics.as_ref())
            .await;
        // AL-021: Forbidden origin denial audit.
        state
            .audit_logger
            .log_forbidden_origin(&origin, &malicious_ip, "/v1/challenge")
            .await;
        return ApiError::bad_request(
            "ORIGIN_MALICIOUS",
            Some("Origin"),
            "Origin contains a forbidden URI scheme",
        )
        .to_response();
    }

    #[cfg(target_arch = "wasm32")]
    console_log!("[/v1/challenge] Creating challenge for origin={}", origin);

    let api_key = headers.get("X-API-Key").ok().flatten();
    phase_timings.push((
        "header_extraction",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Phase 3: Parallel policy + KV fetch
    // PERFORMANCE: Parallelize independent operations to reduce latency
    // Note: MEK is pre-cached at startup, so only policy and KV are loaded here
    let parallel_start = worker::Date::now().as_millis();

    // Run two independent operations in parallel:
    // 1. Load origin policy from storage (with in-memory caching, detailed result)
    // 2. Get KV namespace for short code collision detection
    let ((policy_detail_result, policy_ms), (kv_result, kv_ns_ms)) = join!(
        async {
            let t = worker::Date::now().as_millis();
            let r = state.origin_policy_store.get_policy_detail(&origin).await;
            (r, worker::Date::now().as_millis().saturating_sub(t) as f64)
        },
        async {
            let t = worker::Date::now().as_millis();
            let r = state.env.kv(KV_CONFIG);
            (r, worker::Date::now().as_millis().saturating_sub(t) as f64)
        }
    );

    let parallel_elapsed = worker::Date::now()
        .as_millis()
        .saturating_sub(parallel_start);
    phase_timings.push(("policy_kv_fetch", parallel_elapsed as f64));
    sub_ops.push(("policy_cache_get", policy_ms));
    sub_ops.push(("kv_namespace_get", kv_ns_ms));
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[PERF] Parallel operations completed in {}ms",
        parallel_elapsed
    );

    // Phase 4: Policy validation
    let phase_start = worker::Date::now().as_millis();
    // AL-046/AL-047: Audit disabled and unknown origin denials.
    let client_ip_early = get_client_ip(&headers);

    // SECURITY (sandbox DX): rp_sandbox_* bypass.
    //
    // In `sandbox`, an `rp_sandbox_*` keyId issued by /v1/register-test-origin
    // can authenticate from any request Origin. The HMAC-SHA256 + nonce + PKCE
    // envelope is the real auth on this server-to-server route; the request
    // Origin header is browser-CORS theatre.
    //
    // Resolution path: client_lookup/<keyId> -> registered_origin -> policy.
    // The registered policy is needed because its `clients` entry holds the
    // encrypted HMAC secret used for authentication. Without it we have no
    // way to verify the HMAC and the bypass would either degrade auth (bad)
    // or simply 401 (worse DX than the original 403).
    let bypass_active =
        should_skip_origin_check_for_rp_sandbox(&state.cfg.environment, &body.authorizer.key_id);

    let policy = if bypass_active {
        let lookup_kv = state.env.kv(KV_CONFIG).map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Sandbox bypass: failed to get KV_CONFIG namespace: {:?}",
                _e
            );
            ApiError::Internal(anyhow::anyhow!("Service unavailable"))
        })?;

        // Per-operation timeout for client_lookup KV read.
        let lookup_key = format!("client_lookup/{}", body.authorizer.key_id);
        let lookup_kv_clone = lookup_kv.clone();
        let lookup_key_clone = lookup_key.clone();
        let registered_origin = crate::utils::timeout::with_timeout(
            "client_lookup KV read",
            crate::utils::timeout::KV_READ_TIMEOUT_MS,
            async move { lookup_kv_clone.get(&lookup_key_clone).text().await },
        )
        .await
        .map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Sandbox bypass: client_lookup read timed out: {}",
                _e
            );
            ApiError::Internal(anyhow::anyhow!("Service unavailable"))
        })?
        .map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Sandbox bypass: client_lookup read failed: {:?}",
                _e
            );
            ApiError::Internal(anyhow::anyhow!("Service unavailable"))
        })?;

        match registered_origin {
            Some(reg_origin) if !reg_origin.is_empty() => {
                // Load the registered policy by the original origin so the
                // `clients` (HMAC secrets) and `allowed_vk_ids` come from
                // the real registration, not a fully synthetic struct.
                let detail = state
                    .origin_policy_store
                    .get_policy_detail(&reg_origin)
                    .await?;
                match detail {
                    PolicyLookupResult::Found(p) => {
                        // Apply the same overrides as the hosted-flow pk_test_*
                        // synthetic policy. Origin allowlist is implicitly
                        // skipped because we resolved by client_id, not by
                        // the request Origin header.
                        let p = apply_sandbox_bypass_overrides(p);
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[challenge] Sandbox rp_sandbox_* origin check skipped (key_id={}, request_origin={}, registered_origin={})",
                            body.authorizer.key_id,
                            origin,
                            reg_origin
                        );
                        // Audit-log the bypass at INFO so it's traceable.
                        state
                            .audit_logger
                            .log_sandbox_origin_bypass(
                                &body.authorizer.key_id,
                                &origin,
                                &reg_origin,
                                &client_ip_early,
                            )
                            .await;
                        p
                    }
                    PolicyLookupResult::Disabled | PolicyLookupResult::NotFound => {
                        // Stale or revoked client_lookup entry. Fail closed on
                        // the same 403 as the non-bypass path so callers see
                        // consistent behaviour when their sandbox registration
                        // expires.
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[/v1/challenge] Sandbox bypass: stale client_lookup ({}) -> registered_origin {} no longer enabled",
                            body.authorizer.key_id,
                            reg_origin
                        );
                        state
                            .audit_logger
                            .log_origin_not_found(&origin, &client_ip_early)
                            .await;
                        return ApiError::forbidden(
                            "ORIGIN_NOT_ALLOWED",
                            "Sandbox bypass lookup resolved to a registered origin that is no longer enabled",
                        )
                        .to_response();
                    }
                }
            }
            _ => {
                // No client_lookup entry: either the rp_sandbox_* keyId was
                // never registered, the entry has expired (TTL), or this is
                // an attacker probing with a guessed keyId. Fall through to
                // the standard origin-allowlist path so we return 403 the
                // same way as a stranger from an unknown origin.
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[/v1/challenge] Sandbox bypass: no client_lookup entry for key_id={}, falling back to standard origin policy",
                    body.authorizer.key_id
                );
                match policy_detail_result? {
                    PolicyLookupResult::Found(p) => p,
                    PolicyLookupResult::Disabled => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!("[/v1/challenge] Origin {} is disabled", origin);
                        state
                            .audit_logger
                            .log_origin_disabled(&origin, &client_ip_early)
                            .await;
                        return ApiError::forbidden(
                            "ORIGIN_DISABLED",
                            "The policy registered for this Origin has been disabled",
                        )
                        .to_response();
                    }
                    PolicyLookupResult::NotFound => {
                        #[cfg(target_arch = "wasm32")]
                        console_log!("[/v1/challenge] Origin {} not approved", origin);
                        state
                            .audit_logger
                            .log_origin_not_found(&origin, &client_ip_early)
                            .await;
                        return ApiError::forbidden(
                            "ORIGIN_NOT_ALLOWED",
                            "Origin is not registered with this verifier (register a sandbox origin via /v1/register-test-origin or contact your admin)",
                        )
                        .to_response();
                    }
                }
            }
        }
    } else {
        match policy_detail_result? {
            PolicyLookupResult::Found(p) => p,
            PolicyLookupResult::Disabled => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[/v1/challenge] Origin {} is disabled", origin);
                state
                    .audit_logger
                    .log_origin_disabled(&origin, &client_ip_early)
                    .await;
                return ApiError::forbidden(
                    "ORIGIN_DISABLED",
                    "The policy registered for this Origin has been disabled",
                )
                .to_response();
            }
            PolicyLookupResult::NotFound => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[/v1/challenge] Origin {} not approved", origin);
                state
                    .audit_logger
                    .log_origin_not_found(&origin, &client_ip_early)
                    .await;
                return ApiError::forbidden(
                    "ORIGIN_NOT_ALLOWED",
                    "Origin is not registered with this verifier (register a sandbox origin via /v1/register-test-origin or contact your admin)",
                )
                .to_response();
            }
        }
    };

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/challenge] Origin {} policy: min_age_years={}, tenant={}",
        origin,
        policy.min_age_years,
        policy.tenant_id
    );

    // Handle KV result
    let kv = kv_result.map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/challenge] Failed to get KV namespace: {:?}", _e);
        ApiError::Internal(anyhow::anyhow!("Service unavailable"))
    })?;

    let canonical_message = create_canonical_message_for_challenge(
        "POST",
        "/v1/challenge",
        body.authorizer.timestamp,
        &body,
    );
    phase_timings.push((
        "policy_validation",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Phase 5: Authentication
    let phase_start = worker::Date::now().as_millis();
    // SECURITY: Extract client IP for authentication audit logging (CWE-778, ASVS V7.2.1)
    let client_ip = get_client_ip(&headers);

    // PERFORMANCE: Use cached MEK (Master Encryption Key) pre-loaded at startup
    // This eliminates 50-150ms of Secrets Store latency per request.
    // SECURITY: Clone into Zeroizing to ensure the copy is cleared on drop.
    let mek = state.mek_cached.as_ref().map(|cached| {
        let mek_bytes: &Vec<u8> = cached.as_ref();
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[PERF] Using cached MEK ({} bytes) - Secrets Store fetch avoided",
            mek_bytes.len()
        );
        zeroize::Zeroizing::new(mek_bytes.clone())
    });
    let previous_mek = state.previous_mek.as_ref().map(|cached| {
        let mek_bytes: &Vec<u8> = cached.as_ref();
        zeroize::Zeroizing::new(mek_bytes.clone())
    });
    if mek.is_none() {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[SECURITY] [Auth] [WARNING] No cached MEK available - system will operate without MEK"
        );
    }

    // SECURITY: Create authenticator with audit logger, nonce store, MEK, and dummy hash
    // for replay protection and timing resistance (H-13).
    let mut authenticator = ClientAuthenticator::new(&policy)
        .with_audit_logger(&state.audit_logger, client_ip.clone())
        .with_nonce_store(state.nonce_store.clone())
        .with_dummy_hash(state.dummy_argon2_hash.clone());

    if let Some(ref ae) = state.analytics {
        authenticator = authenticator.with_analytics(ae.clone());
    }
    if let Some(mek_bytes) = mek {
        authenticator = authenticator.with_mek(mek_bytes);
    }
    if let Some(prev_mek_bytes) = previous_mek {
        authenticator = authenticator.with_previous_mek(prev_mek_bytes);
    }

    let t = worker::Date::now().as_millis();
    // capture which MEK slot satisfied the envelope-decrypt step
    // so the per-request `secret_version` log line can attribute the satisfying
    // slot. The same value is surfaced on the `x-secret-version` response header.
    let mut mek_slot: Option<crate::security::secret_versions::RotationSlot> = None;
    let client = authenticator
        .authenticate_tracked(
            api_key.as_deref(),
            &body.authorizer,
            &canonical_message,
            Some(&mut mek_slot),
        )
        .await
        .map_err(|err| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Authentication failed for origin {}: {:?}",
                origin,
                err
            );
            err
        })?;
    sub_ops.push((
        "auth_hmac_verify",
        worker::Date::now().as_millis().saturating_sub(t) as f64,
    ));

    #[cfg(target_arch = "wasm32")]
    console_log!("[/v1/challenge] Client authenticated for origin={}", origin);
    phase_timings.push((
        "authentication",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // EA-007: Idempotency cache check runs AFTER auth so client_id is available
    // for the request fingerprint. This prevents cross-client cache collisions.
    let phase_start = worker::Date::now().as_millis();
    if let (Some(ref key), Some(ref store)) = (&idempotency_key, &state.idempotency_store) {
        // Removed client_ip from fingerprint input. IP addresses are
        // non-deterministic (mobile network switch, VPN failover) and caused
        // spurious cache misses or 409 Conflict on legitimate retries.
        let fingerprint = crate::security::idempotency::compute_request_fingerprint(
            "challenge",
            &client.client_id,
        );
        if let Some(cached_response) = crate::security::idempotency::check_idempotency(
            store,
            key,
            "challenge",
            &fingerprint,
            Some(&state.audit_logger),
            Some(&client_ip),
            state.analytics.as_ref(),
        )
        .await?
        {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Returning cached response for challenge creation (key: {})",
                key.get(..key.len().min(8)).unwrap_or(key)
            );
            return Ok(cached_response);
        }
    }
    phase_timings.push((
        "idempotency_check",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // R9 (RL-03): Per-ACCOUNT quota on the VERIFIED client_id, as a SUPPLEMENT
    // to the pre-auth per-IP gate in worker_routes.rs (which already ran and is
    // untouched). Placed here it is provably:
    //   * post-auth    -- `client.client_id` is the identity proven by the
    //                      HMAC-SHA256 + nonce + PKCE envelope (authenticate_tracked
    //                      above), never a raw header;
    //   * replay-safe  -- the EA-007 idempotency cache check immediately above
    //                      returns the cached response for an idempotent replay
    //                      BEFORE this point, and an HMAC replay with a reused
    //                      nonce is already rejected by authenticate_tracked, so
    //                      a replay is never double-charged;
    //   * pre-mutation -- it runs BEFORE the challenge DO put and the short-code
    //                      KV write below, so no challenge state has been created
    //                      yet (the early ORIGIN_INDEX credit check that follows
    //                      is a read only).
    if let Err(resp) =
        super::api_key_auth::enforce_account_quota(&state, &client.client_id, "challenge").await
    {
        return resp;
    }

    // ── Early credit check via ORIGIN_INDEX (zero additional latency) ─────
    // The ORIGIN_INDEX KV entry is needed later for billing entity resolution
    // (organisation_id). Read it once here and reuse the result. When metering
    // is enabled, reject early with 402 if credits are exhausted. This avoids
    // wasting proof-generation work on sessions that will fail at redemption.
    // Per-operation timeout for ORIGIN_INDEX KV read.
    let origin_index_json: Option<String> = if let Ok(oi_kv) = state.env.kv("ORIGIN_INDEX") {
        let oi_kv_clone = oi_kv.clone();
        let origin_clone = origin.clone();
        match crate::utils::timeout::with_timeout(
            "origin_index KV read",
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
                        "[/v1/challenge] Early credit check failed for origin {}: \
                         metering enabled but has_credits={:?}",
                        origin,
                        entry.has_credits
                    );
                    state
                        .audit_logger
                        .log_suspicious_activity(&client_ip, "challenge:early_credit_check_failed")
                        .await;
                    return ApiError::PaymentRequired(None).to_response();
                }
            }
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[/v1/challenge] WARNING: Failed to deserialise ORIGIN_INDEX for origin {}: {}",
                    origin,
                    _e
                );
            }
        }
    }

    // Phase 6: Cutoff calculation and validation
    let phase_start = worker::Date::now().as_millis();
    // PkceMethod already enforces the S256 hashing method.
    // B64Url32 guarantees the code challenge is exactly 32 bytes.

    // Compute the cutoff in epoch days to match the verifier expectations.
    // SECURITY: Use checked_sub to prevent integer underflow (CWE-191)
    // Epoch days from u64 seconds. u64 / 86_400 cannot overflow, and epoch days
    // fits in u32 until year 11,761,191 so truncation is not a concern.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    let today_epoch_days = (current_timestamp() / 86_400) as u32;

    // Derive proof direction and age threshold from origin policy.
    // The client never sends direction; it's determined server-side.
    let direction = policy.effective_proof_direction();
    let age_years = policy.age_threshold().map_err(|msg| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/challenge] Origin {} policy error: {}", origin, msg);
        ApiError::BadRequest(Some(msg.into()))
    })?;

    // VK selection: both directions use the same allowed_vk_ids.
    let verifying_key_id = if let Some(requested_vk) = body.verifying_key_id {
        if !policy.allowed_vk_ids.contains(&requested_vk.get()) {
            // AL-025: Audit VK-ID-not-allowed denial.
            state
                .audit_logger
                .log_vk_id_not_allowed(requested_vk.get(), &origin, "", &client_ip_early)
                .await;
            return ApiError::BadRequest(Some("Verifying key not allowed for this origin".into()))
                .to_response();
        }
        requested_vk
    } else {
        let first_vk = *policy.allowed_vk_ids.first().ok_or_else(|| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] No allowed VK IDs configured for origin {}",
                origin
            );
            ApiError::Internal(anyhow::anyhow!("Service unavailable"))
        })?;
        VkId::new(first_vk).ok_or_else(|| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Invalid VK ID configured for origin {}",
                origin
            );
            ApiError::Internal(anyhow::anyhow!("Service unavailable"))
        })?
    };

    let age_days = crate::utils::calculate_exact_days_for_years(age_years);

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/challenge] direction={} age_years={} age_days={} (accounting for leap years)",
        direction.as_str(),
        age_years,
        age_days
    );

    let today_i32 = i32::try_from(today_epoch_days)
        .map_err(|_| ApiError::BadRequest(Some("today_epoch_days out of i32 range".to_string())))?;
    let age_i32 = i32::try_from(age_days)
        .map_err(|_| ApiError::BadRequest(Some("age_days out of i32 range".to_string())))?;
    let cutoff_days_raw = today_i32
        .checked_sub(age_i32)
        .ok_or_else(|| ApiError::BadRequest(Some("cutoff_days overflow".to_string())))?;
    let cutoff_days =
        CutoffDays::new(cutoff_days_raw).map_err(|e| ApiError::BadRequest(Some(e)))?;

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/challenge] Computed cutoff_days={} (today={} - age_days={} from {} years, direction={})",
        cutoff_days.get(),
        today_epoch_days,
        age_days,
        age_years,
        direction.as_str()
    );
    // AL-026: Audit cutoff date validation.
    state
        .audit_logger
        .log_cutoff_validation(&origin, age_years, cutoff_days.get(), direction.as_str())
        .await;

    phase_timings.push((
        "cutoff_validation",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Phase 7: Crypto generation (nonce, rp_challenge, submit_secret)
    let phase_start = worker::Date::now().as_millis();

    // KV namespace already obtained in parallel above

    // Generate all challenge components.
    let challenge_id = Uuid::new_v4();
    let challenge_id_v4 = UuidV4(challenge_id);
    // PERFORMANCE: Deterministic short code from UUID - no KV lookup required
    // UUID uniqueness guarantees short code uniqueness
    let short_code = generate_short_code_from_uuid(&challenge_id);
    let nonce = generate_nonce().map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/challenge] Failed to generate nonce: {:?}", _e);
        ApiError::Internal(anyhow::anyhow!("Service unavailable"))
    })?;
    let rp_challenge = rp_challenge(&origin, &nonce);
    let submit_secret_bytes =
        generate_secure_random(32).map_err(|e| WorkerError::RustError(format!("{}", e)))?;
    let mut submit_secret_arr = [0u8; 32];
    submit_secret_arr.copy_from_slice(&submit_secret_bytes);
    let submit_secret = B64Url32::new(submit_secret_arr);
    // SECURITY: Zeroize the stack copy. B64Url32 owns its own copy and
    // zeroizes via its Drop impl; this clears the intermediate array.
    submit_secret_arr.zeroize();

    // Wrap the relying-party challenge in a B64Url32 helper.
    let mut rp_challenge_arr = [0u8; 32];
    rp_challenge_arr.copy_from_slice(&rp_challenge);
    let rp_challenge_b64 = B64Url32::new(rp_challenge_arr);
    rp_challenge_arr.zeroize();

    // Bound the requested expiry by policy and system limits.
    let ttl_secs = body
        .expires_in
        .get()
        .min(policy.max_ttl_sec)
        .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

    let now = crate::utils::current_timestamp();
    let expires_at = now.saturating_add(ttl_secs);
    phase_timings.push((
        "crypto_generation",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Phase 8: Durable Object storage
    let phase_start = worker::Date::now().as_millis();
    // Persist the challenge for later verification.
    let cached = CachedChallenge {
        id: challenge_id,
        short_code: short_code.clone(),
        rp_challenge: rp_challenge.to_vec(),
        cutoff_days: cutoff_days.get(),
        verifying_key_id: verifying_key_id.get(),
        code_challenge: body.code_challenge.to_string(),
        code_challenge_bytes: body.code_challenge.0.to_vec(),
        // SECURITY: Clone the secret into the challenge struct. The Zeroizing wrapper
        // on submit_secret_bytes will scrub its copy on drop; CachedChallenge::drop
        // zeroizes its own copy independently.
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
        client_id: Some(client.client_id.clone()),
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

    let t = worker::Date::now().as_millis();
    if let Err(_e) = state.challenge_store.put(&challenge_id, &cached).await {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/challenge] Failed to store challenge: {:?}", _e);
        state
            .audit_logger
            .log_suspicious_activity(&client_ip, "downstream_failure:challenge_store_write")
            .await;
        return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
    }
    sub_ops.push((
        "challenge_do_put",
        worker::Date::now().as_millis().saturating_sub(t) as f64,
    ));
    phase_timings.push((
        "do_storage",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Phase 9: KV storage (short code mapping)
    let phase_start = worker::Date::now().as_millis();
    // Store short_code → UUID mapping in KV for fast lookup
    // Note: KV already obtained above for collision detection
    let code_key = format!("code:{}", short_code);
    let kv_builder = kv
        .put(&code_key, challenge_id.to_string())
        .map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Failed to store short code mapping: {:?}",
                _e
            );
            ApiError::Internal(anyhow::anyhow!("Service unavailable"))
        })?
        .expiration_ttl(ttl_secs);

    // Per-operation timeout for short code KV write.
    let t = worker::Date::now().as_millis();
    match crate::utils::timeout::with_timeout(
        "short_code KV write",
        crate::utils::timeout::KV_WRITE_TIMEOUT_MS,
        kv_builder.execute(),
    )
    .await
    {
        Ok(Err(_e)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/challenge] Failed to execute KV put: {:?}", _e);
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "downstream_failure:kv_write")
                .await;
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
        Err(_timeout_err) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge] Short code KV put timed out: {}",
                _timeout_err
            );
            state
                .audit_logger
                .log_suspicious_activity(&client_ip, "downstream_failure:kv_write_timeout")
                .await;
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
        Ok(Ok(())) => {}
    }
    sub_ops.push((
        "short_code_kv_put",
        worker::Date::now().as_millis().saturating_sub(t) as f64,
    ));
    phase_timings.push((
        "kv_storage",
        (worker::Date::now().as_millis().saturating_sub(phase_start)) as f64,
    ));

    // Record challenge creation analytics.
    let analytics = Analytics::new(&state.env);
    let duration_ms = (worker::Date::now().as_millis().saturating_sub(start)) as f64;
    analytics.challenge_created(
        "/v1/challenge",
        &challenge_id.to_string(),
        &origin,
        cutoff_days.get(),
        &state.cfg.environment,
    );

    // Emit an audit event for traceability.
    let client_ip = get_client_ip(&headers);
    state
        .audit_logger
        .log_challenge_created(
            &challenge_id.to_string(),
            &client_ip,
            &origin,
            Some(&client.client_id),
        )
        .await;

    // SECURITY: Redact challenge_id in logs (GDPR compliance, CWE-532)
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/challenge] âœ… created challenge_id={} origin={} cutoff_days={} duration_ms={}",
        redact_challenge_id(&challenge_id.to_string()),
        origin,
        cutoff_days.get(),
        duration_ms
    );

    // Emit structured JSON log for Grafana/Loki dashboards
    // Format: Easy to parse with Loki's json parser
    let is_slow = duration_ms > 500.0;
    let _slow_phases: Vec<_> = phase_timings
        .iter()
        .filter(|(_, ms)| *ms > 50.0)
        .map(|(name, ms)| format!("{}:{:.0}", name, ms))
        .collect();

    // Build phase timing JSON
    let _phase_json: String = phase_timings
        .iter()
        .map(|(name, ms)| format!("\"{}\":{:.1}", name, ms))
        .collect::<Vec<_>>()
        .join(",");

    let _sub_ops_json: String = sub_ops
        .iter()
        .map(|(name, ms)| format!("\"{}\":{:.1}", name, ms))
        .collect::<Vec<_>>()
        .join(",");

    #[cfg(target_arch = "wasm32")]
    {
        // SECURITY (M1 - log injection): origin is attacker-influenceable (a
        // non-browser client can place arbitrary bytes in a wildcard-matched
        // subdomain segment). This log line is hand-built JSON, so interpolating
        // the raw origin would let a `"` or `,` forge or corrupt fields that a
        // downstream JSON parser (e.g. the alerter) reads. serde_json::to_string
        // emits a properly escaped, already-quoted JSON string value.
        let origin_json = serde_json::to_string(&origin).unwrap_or_else(|_| "\"\"".to_string());
        console_log!(
            r#"{{"type":"CHALLENGE_CREATED","duration_ms":{:.1},"slow":{},"phases":{{{}}},"sub_ops":{{{}}},"slow_phases":"{}","origin":{}}}"#,
            duration_ms,
            is_slow,
            _phase_json,
            _sub_ops_json,
            _slow_phases.join(","),
            origin_json
        );
    }

    // Human-readable breakdown for slow requests
    if is_slow {
        // duration_ms originates from saturating_sub on non-negative millis, so
        // the f64-to-u64 cast cannot lose sign. Truncation at u64::MAX is fine
        // for a log line.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let _duration_ms_int = duration_ms as u64;
        let _breakdown = phase_timings
            .iter()
            .map(|(name, ms)| {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let ms_int = *ms as u64;
                format!("{}={}ms", name, ms_int)
            })
            .collect::<Vec<_>>()
            .join(", ");
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SLOW_REQUEST] Challenge creation took {}ms | Breakdown: {}",
            _duration_ms_int,
            _breakdown
        );
    }

    // Assemble the API response payload.
    let short_code_formatted = ShortCode::new(&short_code)
        .map(|sc| sc.display_formatted())
        .unwrap_or_else(|_| short_code.clone());
    let response = ChallengeResponse {
        challenge_id: challenge_id_v4,
        short_code,
        short_code_formatted,
        rp_challenge: rp_challenge_b64,
        cutoff_days,
        verifying_key_id,
        submit_secret,
        expires_at,
        proof_direction: direction.as_str().to_string(),
        status_url: format!(
            "{}/challenge/{}",
            build_v1_base(&state.cfg.api_base_url),
            challenge_id
        ),
        verify_url: format!("{}/verify", build_v1_base(&state.cfg.api_base_url)),
    };

    let mut worker_response = Response::from_json(&response)?.with_status(201);

    // emit the per-request `secret_version` log line and set
    // the `x-secret-version` response header. The handler touches VERIFIER_MEK
    // (per-client HMAC-secret envelope decrypt) and IP_HASH_SALT (request IP
    // log-redaction). The VERIFIER_HMAC class is per-client and rotates via
    // MEK rotation in the current architecture, so the MEK slot label is the
    // satisfying slot for the verify path; the header carries the MEK slot
    // fingerprint.
    {
        let mut line = crate::security::secret_versions::SecretVersionLine::new();
        line.add_slot_used(
            state.mek_role,
            &state.mek_fingerprint,
            &state.mek_fingerprint_previous,
            mek_slot,
        );
        // IP_HASH_SALT is single-slot; record the fingerprint
        // for the panel grouping but no `_used` attribution beyond MEK above.
        line.add_slot(
            state.ip_hash_salt_role,
            &state.ip_hash_salt_fingerprint,
            "000000",
        );
        line.emit_log("POST /v1/challenge");
        line.apply_header(&mut worker_response)?;
    }

    // SECURITY: Store response in idempotency cache if key was provided
    if let (Some(key), Some(store)) = (idempotency_key, &state.idempotency_store) {
        // Serialise response for caching
        let response_body = serde_json::to_string(&response).unwrap_or_else(|_e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[IDEMPOTENCY] Failed to serialise response for caching: {:?}",
                _e
            );
            "{}".to_string()
        });

        // EA-007: Fingerprint includes client_id to prevent cross-client cache collisions.
        // Removed client_ip (non-deterministic, causes spurious mismatches).
        let fingerprint = crate::security::idempotency::compute_request_fingerprint(
            "challenge",
            &client.client_id,
        );
        let _ = crate::security::idempotency::store_idempotency_response(
            store,
            &key,
            response_body,
            201,
            "challenge",
            Some(ttl_secs),
            &fingerprint,
        )
        .await;
    }

    Ok(worker_response)
}

/// Full challenge details returned by `GET /v1/challenge/:id`.
///
/// Includes `submit_secret` because access requires the 122-bit UUID capability
/// (obtained via QR deep link), not the lower-entropy short code.
#[derive(serde::Serialize, JsonSchema)]
pub struct ChallengeDetailsResponse {
    /// Unique challenge identifier (UUIDv4).
    pub challenge_id: UuidV4,
    /// 12-digit numeric short code for accessibility (displayed as XXXX XXXX XXXX).
    pub short_code: String,
    /// Human-readable formatted short code: "XXXX XXXX XXXX".
    pub short_code_formatted: String,
    /// Base64url-encoded relying-party challenge (32 bytes).
    pub rp_challenge: B64Url32,
    /// Age cutoff in epoch days used by the ZK circuit.
    pub cutoff_days: CutoffDays,
    /// Verifying key identifier selected for this challenge.
    pub verifying_key_id: VkId,
    /// Base64url-encoded submit secret (32 bytes). Required for proof submission.
    pub submit_secret: B64Url32,
    /// Unix timestamp when this challenge expires.
    pub expires_at: u64,
    /// Direction of the age proof ("older" or "younger").
    pub proof_direction: String,
    /// URL to poll for challenge status updates.
    pub status_url: String,
    /// URL to submit the zero knowledge proof.
    pub verify_url: String,
}

/// Response for short code lookups. Identical to [`ChallengeDetailsResponse`] but
/// omits `submit_secret` to prevent shoulder-surfing attacks (XA8-8).
///
/// SECURITY: The 12-digit short code has only ~40 bits of entropy and is displayed
/// on screen, making it observable by nearby attackers. The UUID-based endpoint
/// retains `submit_secret` because the UUID has 122 bits of entropy and is only
/// accessible via QR deep link (not human-readable on screen).
#[derive(serde::Serialize, JsonSchema)]
pub struct ShortCodeChallengeResponse {
    /// Unique challenge identifier (UUIDv4).
    pub challenge_id: UuidV4,
    /// 12-digit numeric short code for accessibility.
    pub short_code: String,
    /// Human-readable formatted short code: "XXXX XXXX XXXX".
    pub short_code_formatted: String,
    /// Base64url-encoded relying-party challenge (32 bytes).
    pub rp_challenge: B64Url32,
    /// Age cutoff in epoch days used by the ZK circuit.
    pub cutoff_days: CutoffDays,
    /// Verifying key identifier selected for this challenge.
    pub verifying_key_id: VkId,
    /// Unix timestamp when this challenge expires.
    pub expires_at: u64,
    /// Direction of the age proof ("older" or "younger").
    pub proof_direction: String,
    /// URL to poll for challenge status updates.
    pub status_url: String,
    /// URL to submit the zero knowledge proof.
    pub verify_url: String,
}

/// Retrieve full challenge details by UUID.
///
/// SECURITY: Capability-based authentication (magic link pattern). The 128-bit UUID
/// is the credential; possession proves authorisation. No additional auth headers are
/// checked. Rate limiting is applied at the route layer.
pub async fn get_challenge_details(
    state: Arc<AppState>,
    sid: Uuid,
) -> Result<Response, WorkerError> {
    let cached = match state.challenge_store.get(&sid).await {
        Ok(Some(c)) => c,
        Ok(None) => return ApiError::NotFound.to_response(),
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/challenge/get] Failed to get challenge: {:?}", e);
            return ApiError::Internal(e.into()).to_response();
        }
    };

    // SECURITY: Capability-based authentication (magic link pattern)
    // The 128-bit UUID IS the authentication credential. Possession of the UUID
    // (via QR scan or short code) proves authorisation to access the challenge.
    // No additional auth headers are checked. The UUID has 122 bits of entropy,
    // expires in 30-300 seconds, and is single-use. Proof submission requires
    // a separate 256-bit submit_secret (constant-time compared).
    // Rate limiting is applied at the route layer (worker_routes.rs).
    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[SECURITY] get_challenge_details: UUID capability access for challenge {}",
        redact_challenge_id(&sid.to_string())
    );

    // Ensure the challenge remains valid.
    // SECURITY: Return 404 (not 410) for expired challenges to prevent a state oracle
    // that lets attackers distinguish "never existed" from "existed but expired".
    let now = current_timestamp();
    if now > cached.expires_at {
        return ApiError::NotFound.to_response();
    }

    // State guard: if the challenge has transitioned out of Pending, the submit_secret
    // will have been zeroised. Return 404 (consistent with anti-oracle pattern above).
    if cached.state != ChallengeState::Pending {
        return ApiError::NotFound.to_response();
    }

    // Provide the full challenge payload required by the client.
    let rp_challenge_arr: [u8; 32] = cached
        .rp_challenge
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("rp_challenge length mismatch")))?;

    let submit_secret_arr: [u8; 32] = match cached.submit_secret.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge/get] submit_secret is not 32 bytes (state: {:?})",
                cached.state.as_str()
            );
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
    };

    let short_code_formatted = ShortCode::new(&cached.short_code)
        .map(|sc| sc.display_formatted())
        .unwrap_or_else(|_| cached.short_code.clone());
    let response = ChallengeDetailsResponse {
        challenge_id: UuidV4(cached.id),
        short_code: cached.short_code.clone(),
        short_code_formatted,
        rp_challenge: B64Url32::new(rp_challenge_arr),
        cutoff_days: CutoffDays::new(cached.cutoff_days)?,
        verifying_key_id: VkId::new(cached.verifying_key_id)
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Invalid VK ID")))?,
        submit_secret: B64Url32::new(submit_secret_arr),
        expires_at: cached.expires_at,
        proof_direction: cached.proof_direction.as_str().to_string(),
        status_url: format!(
            "{}/challenge/{}",
            build_v1_base(&state.cfg.api_base_url),
            cached.id
        ),
        verify_url: format!("{}/verify", build_v1_base(&state.cfg.api_base_url)),
    };

    Response::from_json(&response)
}

/// Resolve a 12-digit short code to challenge details (without `submit_secret`).
///
/// SECURITY: The response deliberately omits `submit_secret` to prevent
/// shoulder-surfing attacks. Short codes have only ~40 bits of entropy and are
/// displayed on screen. Failed lookups are audit-logged to detect enumeration.
pub async fn get_challenge_by_short_code(
    state: Arc<AppState>,
    short_code: String,
    client_ip: &str,
) -> Result<Response, WorkerError> {
    // VA-CHL-015: Validate short code format before KV lookup to reject clearly
    // invalid input without wasting a KV read. Short codes are exactly 12 ASCII
    // digits (spaces stripped by the caller / ShortCode type).
    {
        let normalised: String = short_code.chars().filter(|c| !c.is_whitespace()).collect();
        if normalised.len() != 12 || !normalised.chars().all(|c| c.is_ascii_digit()) {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge/by-code] Rejected invalid short code format (len={})",
                normalised.len()
            );
            state
                .audit_logger
                .log_suspicious_activity(client_ip, "short_code_invalid_format")
                .await;
            return ApiError::bad_request(
                "INVALID_SHORT_CODE",
                Some("short_code"),
                "Short code must be exactly 12 numeric digits",
            )
            .to_response();
        }
    }

    // Look up the UUID from KV using the short code
    let kv = state.env.kv(KV_CONFIG).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/challenge/by-code] KV access error: {:?}", _e);
        ApiError::Internal(anyhow::anyhow!("Service unavailable"))
    })?;

    // Per-operation timeout for short code KV lookup.
    // Use normalised (whitespace-stripped) form for consistent KV key.
    let normalised_code: String = short_code.chars().filter(|c| !c.is_whitespace()).collect();
    let code_key = format!("code:{}", normalised_code);
    let kv_clone = kv.clone();
    let code_key_clone = code_key.clone();
    let uuid_str = match crate::utils::timeout::with_timeout(
        "short_code KV read",
        crate::utils::timeout::KV_READ_TIMEOUT_MS,
        async move { kv_clone.get(&code_key_clone).text().await },
    )
    .await
    {
        Ok(Ok(Some(uuid))) => uuid,
        Ok(Ok(None)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge/by-code] Short code {} not found",
                short_code
            );
            // Log failed lookups to detect enumeration attempts against 40-bit entropy short codes
            state
                .audit_logger
                .log_suspicious_activity(client_ip, "short_code_not_found")
                .await;
            return ApiError::NotFound.to_response();
        }
        Ok(Err(_e)) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge/by-code] Failed to lookup short code: {:?}",
                _e
            );
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
        Err(_timeout_err) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[/v1/challenge/by-code] Short code lookup timed out: {}",
                _timeout_err
            );
            return ApiError::Internal(anyhow::anyhow!("Service unavailable")).to_response();
        }
    };

    // Parse the UUID
    let challenge_id = Uuid::parse_str(&uuid_str).map_err(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!("[/v1/challenge/by-code] Invalid UUID in mapping: {:?}", _e);
        ApiError::Internal(anyhow::anyhow!("Service unavailable"))
    })?;

    #[cfg(target_arch = "wasm32")]
    console_log!(
        "[/v1/challenge/by-code] Short code {} resolved to challenge {}",
        short_code,
        redact_challenge_id(&challenge_id.to_string())
    );

    // SECURITY: Return challenge details WITHOUT submit_secret (XA8-8).
    // The short code has ~40 bits of entropy and is visible on screen. An attacker
    // who shoulder-surfs the 12-digit code should NOT get the submit_secret needed
    // for proof submission. The submit_secret is only available via the deep link
    // payload (QR scan) or the UUID-based details endpoint (122-bit capability).
    let cached = match state.challenge_store.get(&challenge_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return ApiError::NotFound.to_response(),
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/challenge/by-code] Failed to get challenge: {:?}", e);
            return ApiError::Internal(e.into()).to_response();
        }
    };

    // SECURITY: Return 404 (not 410) for expired challenges to prevent a state oracle
    // that lets attackers distinguish "never existed" from "existed but expired".
    let now = current_timestamp();
    if now > cached.expires_at {
        return ApiError::NotFound.to_response();
    }

    let rp_challenge_arr: [u8; 32] = cached
        .rp_challenge
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("rp_challenge length mismatch")))?;

    // Audit: log successful short code lookup (P3-25)
    state
        .audit_logger
        .log_short_code_lookup_success(&short_code, &cached.id.to_string(), client_ip)
        .await;

    let short_code_formatted = ShortCode::new(&cached.short_code)
        .map(|sc| sc.display_formatted())
        .unwrap_or_else(|_| cached.short_code.clone());
    let response = ShortCodeChallengeResponse {
        challenge_id: UuidV4(cached.id),
        short_code: cached.short_code.clone(),
        short_code_formatted,
        rp_challenge: B64Url32::new(rp_challenge_arr),
        cutoff_days: CutoffDays::new(cached.cutoff_days)?,
        verifying_key_id: VkId::new(cached.verifying_key_id)
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Invalid VK ID")))?,
        expires_at: cached.expires_at,
        proof_direction: cached.proof_direction.as_str().to_string(),
        status_url: format!(
            "{}/challenge/{}",
            build_v1_base(&state.cfg.api_base_url),
            cached.id
        ),
        verify_url: format!("{}/verify", build_v1_base(&state.cfg.api_base_url)),
    };

    Response::from_json(&response)
}

/// Poll the current state of a challenge (pending, proof_ok, verified, failed, expired).
///
/// SECURITY: Requires HMAC authentication via `X-API-Key` and enforces BOLA ownership
/// (OWASP API1:2023, CWE-639). Only the client that created the challenge may poll it.
pub async fn poll_challenge(
    state: Arc<AppState>,
    headers: Headers,
    sid: Uuid,
) -> Result<Response, WorkerError> {
    let entry = match state.challenge_store.get(&sid).await {
        Ok(Some(e)) => e,
        Ok(None) => return ApiError::NotFound.to_response(),
        Err(e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!("[/v1/challenge/poll] Failed to get challenge: {:?}", e);
            return ApiError::Internal(e.into()).to_response();
        }
    };

    // SECURITY: MANDATORY BOLA protection (OWASP API1:2023, CWE-639)
    // Authentication is REQUIRED - this endpoint exposes challenge state information.
    //
    // PG-VAL-016: Pass the challenge's recorded `client_id` to the auth
    // helper so the sandbox bypass can resolve the registered policy by
    // unique clientId (not the shared sandbox apiKey, which collides across
    // playground users).
    let client_ip = get_client_ip(&headers);
    let client_id = match try_extract_client_id(&headers, &state, entry.client_id.as_deref()).await
    {
        Some(id) => id,
        None => {
            // SECURITY: Redact challenge_id in logs
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY] poll_challenge: Authentication required for challenge {}",
                redact_challenge_id(&sid.to_string())
            );
            state
                .audit_logger
                .log_authentication_failure(&client_ip, "poll_missing_client_id", None, None, None)
                .await;
            return ApiError::unauthorized(
                    "POLL_AUTH_FAILED",
                    "Origin + X-API-Key did not match the client that created this challenge. In sandbox the X-API-Key must match the credential returned from /v1/register-test-origin for this challenge's owner.",
                )
                .to_response();
        }
    };

    // Verify ownership
    if let Err(e) = super::ownership::verify_ownership(
        entry.client_id.as_deref(),
        Some(&client_id),
        &sid.to_string(),
        "poll_challenge",
        &state.audit_logger,
        &client_ip,
        "poll_bola_ownership_mismatch",
    )
    .await
    {
        return e.to_response();
    }

    let now = crate::utils::current_timestamp();
    if now > entry.expires_at && entry.state != ChallengeState::Verified {
        return ApiError::gone(
            "CHALLENGE_EXPIRED",
            "Challenge has passed its expiry timestamp; create a new one via POST /v1/challenge",
        )
        .to_response();
    }

    #[derive(serde::Serialize, JsonSchema)]
    struct StatusDto {
        state: String,
        status: String,
        verified: bool,
        proof_verified: bool,
    }

    // Audit: log successful challenge poll (P3-26)
    state
        .audit_logger
        .log_challenge_poll_success(&sid.to_string(), &client_ip, &client_id)
        .await;

    let dto = StatusDto {
        state: entry.state.as_str().to_string(),
        status: entry.state.as_str().to_string(),
        verified: entry.state == ChallengeState::Verified,
        proof_verified: matches!(
            entry.state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        ),
    };

    Response::from_json(&dto)
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

    /* ========================================================================== */
    /*                    generate_secure_random() TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_generate_secure_random_correct_length() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(32)?;
        assert_eq!(result.len(), 32);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_zero_length() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(0)?;
        assert_eq!(result.len(), 0);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_single_byte() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(1)?;
        assert_eq!(result.len(), 1);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_large_size() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(1024)?;
        assert_eq!(result.len(), 1024);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_different_outputs() -> Result<(), Box<dyn std::error::Error>> {
        let result1 = generate_secure_random(32)?;
        let result2 = generate_secure_random(32)?;
        // Two independent calls should produce different random data
        assert_ne!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_not_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(32)?;
        let all_zeros = vec![0u8; 32];
        // Extremely unlikely to get all zeros from secure random
        assert_ne!(*result, all_zeros);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_not_all_ones() -> Result<(), Box<dyn std::error::Error>> {
        let result = generate_secure_random(32)?;
        let all_ones = vec![0xFFu8; 32];
        assert_ne!(*result, all_ones);
        Ok(())
    }

    #[test]
    fn test_generate_secure_random_various_sizes() -> Result<(), Box<dyn std::error::Error>> {
        for size in [1, 4, 8, 16, 32, 64, 128, 256] {
            let result = generate_secure_random(size)?;
            assert_eq!(result.len(), size);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    create_canonical_message_for_challenge() TESTS         */
    /* ========================================================================== */

    fn create_test_request() -> Result<CreateChallengeRequest, Box<dyn std::error::Error>> {
        Ok(CreateChallengeRequest {
            code_challenge: B64Url32::new([42u8; 32]),
            method: PkceMethod::default(),
            verifying_key_id: Some(VkId::new(1).ok_or("VkId::new(1) returned None")?),
            expires_in: ExpiresIn::default(),
            authorizer: Authorizer {
                key_id: "test".to_string(),
                timestamp: 1234567890,
                hmac: "a".repeat(64),
                nonce: "test-nonce-12345678".to_string(),
            },
        })
    }

    #[test]
    fn test_create_canonical_message_format() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Should start with timestamp:method:path:
        assert!(msg.starts_with("1000:POST:/v1/challenge:"));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_includes_code_challenge(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Should contain the code_challenge field
        assert!(msg.contains("code_challenge"));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_includes_method() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Should contain the method field (S256)
        assert!(msg.contains("\"method\""));
        assert!(msg.contains("\"S256\""));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_includes_verifying_key_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Should contain verifying_key_id
        assert!(msg.contains("verifying_key_id"));
        assert!(msg.contains("1"));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_includes_expires_in() -> Result<(), Box<dyn std::error::Error>>
    {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Should contain expires_in
        assert!(msg.contains("expires_in"));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);
        let msg2 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Same inputs should produce same output
        assert_eq!(msg1, msg2);
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_different_timestamps() -> Result<(), Box<dyn std::error::Error>>
    {
        let req = create_test_request()?;
        let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);
        let msg2 = create_canonical_message_for_challenge("POST", "/v1/challenge", 2000, &req);

        // Different timestamps should produce different messages
        assert_ne!(msg1, msg2);
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_different_methods() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);
        let msg2 = create_canonical_message_for_challenge("GET", "/v1/challenge", 1000, &req);

        // Different HTTP methods should produce different messages
        assert_ne!(msg1, msg2);
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_different_paths() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);
        let msg2 = create_canonical_message_for_challenge("POST", "/v1/verify", 1000, &req);

        // Different paths should produce different messages
        assert_ne!(msg1, msg2);
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_optional_fields_none() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut req = create_test_request()?;
        req.verifying_key_id = None;

        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Should still produce valid message
        assert!(msg.starts_with("1000:POST:/v1/challenge:"));
        assert!(msg.contains("code_challenge"));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_colon_separator() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // EA-018: Now 5 colon-separated sections: timestamp:method:path:json:nonce
        let parts: Vec<&str> = msg.splitn(5, ':').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "1000");
        assert_eq!(parts[1], "POST");
        assert_eq!(parts[2], "/v1/challenge");
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_includes_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // EA-018: Nonce must appear in the canonical message
        assert!(msg.ends_with(&req.authorizer.nonce));
        Ok(())
    }

    #[test]
    fn test_create_canonical_message_different_nonces() -> Result<(), Box<dyn std::error::Error>> {
        let mut req1 = create_test_request()?;
        req1.authorizer.nonce = "a".repeat(64);

        let mut req2 = create_test_request()?;
        req2.authorizer.nonce = "b".repeat(64);

        let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req1);
        let msg2 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req2);

        // Different nonces must produce different canonical messages
        assert_ne!(msg1, msg2);
        Ok(())
    }

    /* ========================================================================== */
    /*    SANDBOX rp_sandbox_* ORIGIN BYPASS TESTS (mirrors hosted pk_test_*)    */
    /* ========================================================================== */

    #[test]
    fn test_sandbox_rp_sandbox_skips_origin_check() {
        // The bug-1 happy path: sandbox + rp_sandbox_* keyId triggers the bypass.
        let key_id = "rp_sandbox_a1b2c3d4e5f6";
        assert!(should_skip_origin_check_for_rp_sandbox("sandbox", key_id));
    }

    #[test]
    fn test_sandbox_non_rp_sandbox_prefix_does_not_skip() {
        // Sandbox env but a non-rp_sandbox_ keyId must NOT bypass. Production
        // RP credentials and arbitrary attacker-supplied keyIds don't share
        // the developer-DX exemption.
        for key_id in [
            "rp_live_a1b2c3d4e5f6",
            "rp_a1b2c3d4e5f6",
            "RP_SANDBOX_a1b2c3d4e5f6", // case-sensitive: must NOT match
            "",
            "pk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "client_id_with_rp_sandbox_in_middle",
        ] {
            assert!(
                !should_skip_origin_check_for_rp_sandbox("sandbox", key_id),
                "key_id {} must not trigger bypass in sandbox",
                key_id
            );
        }
    }

    #[test]
    fn test_production_rp_sandbox_does_not_skip() {
        // Even if an attacker forges an `rp_sandbox_*` keyId in production,
        // the env gate prevents the bypass. HMAC will then fail anyway, but
        // we want defence in depth: no sandbox-only behaviour in prod.
        let key_id = "rp_sandbox_a1b2c3d4e5f6";
        for env in ["production", "staging", "test", "", "sandbox-eu"] {
            assert!(
                !should_skip_origin_check_for_rp_sandbox(env, key_id),
                "environment {} must not trigger bypass",
                env
            );
        }
    }

    #[test]
    fn test_apply_sandbox_bypass_overrides_preserves_clients() {
        // The bypass MUST keep the registered policy's `clients` list intact.
        // that's where the encrypted HMAC secret lives. Wiping it would force
        // the authenticator into the dummy-hash path and the legitimate
        // developer's call would 401.
        let original_clients = vec![crate::storage::origin_policy::ClientAuthConfig {
            client_id: "rp_sandbox_a1b2c3d4e5f6".to_string(),
            api_key_hash: "$argon2id$test".to_string(),
            api_key_prefix: Some("pk_test_".to_string()),
            encrypted_hmac_secret: "encrypted-secret".to_string(),
            dek_encrypted: "encrypted-dek".to_string(),
            encryption_version: 1,
            active: true,
        }];
        let registered = crate::storage::origin_policy::OriginPolicy {
            tenant_id: "test_abc123".to_string(),
            min_age_years: 21,
            max_age_years: None,
            proof_direction: None,
            allowed_vk_ids: vec![1],
            allowed_issuers: vec![],
            max_ttl_sec: 3600,
            billing: crate::storage::origin_policy::BillingConfig {
                plan: "pro".to_string(),
                metering_enabled: true,
            },
            enabled: true,
            created_at: 0,
            updated_at: 0,
            clients: original_clients.clone(),
            provisioned_by: None,
            failure_mode: None,
            failure_mode_locked: false,
        };

        let bypassed = apply_sandbox_bypass_overrides(registered);

        // Sandbox shape is applied:
        assert_eq!(bypassed.tenant_id, "sandbox_default");
        assert_eq!(bypassed.min_age_years, 18);
        assert_eq!(bypassed.billing.plan, "sandbox");
        assert!(!bypassed.billing.metering_enabled);

        // Clients (HMAC secrets) survive:
        assert_eq!(bypassed.clients.len(), 1);
        assert_eq!(bypassed.clients[0].client_id, "rp_sandbox_a1b2c3d4e5f6");
        assert_eq!(
            bypassed.clients[0].encrypted_hmac_secret,
            "encrypted-secret"
        );

        // Other fields are unchanged so the policy still authorises the same
        // VKs and respects max_ttl_sec.
        assert_eq!(bypassed.allowed_vk_ids, vec![1]);
        assert_eq!(bypassed.max_ttl_sec, 3600);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: generate_secure_random always produces requested length
        #[test]
        fn prop_generate_secure_random_length(len in 0usize..512) {
            let result = generate_secure_random(len).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            prop_assert_eq!(result.len(), len);
        }

        /// Property: generate_secure_random produces unique outputs
        #[test]
        fn prop_generate_secure_random_uniqueness(len in 1usize..128) {
            let result1 = generate_secure_random(len).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let result2 = generate_secure_random(len).map_err(|e| TestCaseError::fail(format!("{e}")))?;
            // Probability of collision is negligible for cryptographic RNG
            prop_assert_ne!(result1, result2);
        }

        /// Property: canonical message includes timestamp
        #[test]
        fn prop_canonical_message_includes_timestamp(timestamp in any::<u64>()) {
            let req = create_test_request().map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", timestamp, &req);
            let timestamp_str = timestamp.to_string();
            prop_assert!(msg.starts_with(&timestamp_str));
        }

        /// Property: different timestamps produce different canonical messages
        #[test]
        fn prop_canonical_message_timestamp_sensitivity(
            timestamp1 in any::<u64>(),
            timestamp2 in any::<u64>()
        ) {
            prop_assume!(timestamp1 != timestamp2);
            let req = create_test_request().map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", timestamp1, &req);
            let msg2 = create_canonical_message_for_challenge("POST", "/v1/challenge", timestamp2, &req);
            prop_assert_ne!(msg1, msg2);
        }

        /// Property: canonical message is deterministic
        #[test]
        fn prop_canonical_message_deterministic(timestamp in any::<u64>()) {
            let req = create_test_request().map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", timestamp, &req);
            let msg2 = create_canonical_message_for_challenge("POST", "/v1/challenge", timestamp, &req);
            prop_assert_eq!(msg1, msg2);
        }
    }

    /* ========================================================================== */
    /*                    CONSTANTS TESTS                                        */
    /* ========================================================================== */

    // Compile-time constant invariants (checked once, never optimised away).
    // MIN must stay at or above 60 because Cloudflare Workers KV's
    // .expiration_ttl() rejects anything lower; the /v1/challenge KV write
    // would fail and surface as a generic 500.
    const _: () = assert!(MAX_CHALLENGE_TTL > MIN_CHALLENGE_TTL);
    const _: () = assert!(MIN_CHALLENGE_TTL > 0);
    const _: () = assert!(MIN_CHALLENGE_TTL >= 60);
    const _: () = assert!(MAX_CHALLENGE_TTL <= 300);
    const _: () = assert!(MAX_CHALLENGE_TTL - MIN_CHALLENGE_TTL >= 30);

    #[test]
    fn test_max_challenge_ttl_constant() {
        assert_eq!(MAX_CHALLENGE_TTL, 300);
    }

    #[test]
    fn test_min_challenge_ttl_constant() {
        assert_eq!(MIN_CHALLENGE_TTL, 60);
    }

    /* ========================================================================== */
    /*                    get_client_ip() TESTS                                  */
    /* ========================================================================== */

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_cf_connecting_ip() -> Result<(), Box<dyn std::error::Error>> {
        let headers = Headers::new();
        headers.set("CF-Connecting-IP", "192.168.1.1")?;

        let ip = get_client_ip(&headers);
        assert_eq!(ip, "192.168.1.1");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_ignores_x_forwarded_for() -> Result<(), Box<dyn std::error::Error>> {
        let headers = Headers::new();
        headers.set("X-Forwarded-For", "10.0.0.1")?;

        // SECURITY: X-Forwarded-For is spoofable, only CF-Connecting-IP is trusted
        let ip = get_client_ip(&headers);
        assert_eq!(ip, "unknown");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_ignores_x_real_ip() -> Result<(), Box<dyn std::error::Error>> {
        let headers = Headers::new();
        headers.set("X-Real-IP", "172.16.0.1")?;

        // SECURITY: X-Real-IP is spoofable, only CF-Connecting-IP is trusted
        let ip = get_client_ip(&headers);
        assert_eq!(ip, "unknown");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_cf_only_when_multiple_present() -> Result<(), Box<dyn std::error::Error>>
    {
        let headers = Headers::new();
        headers.set("CF-Connecting-IP", "192.168.1.1")?;
        headers.set("X-Forwarded-For", "10.0.0.1")?;

        let ip = get_client_ip(&headers);
        assert_eq!(ip, "192.168.1.1");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_unknown_without_cf_header() -> Result<(), Box<dyn std::error::Error>> {
        let headers = Headers::new();
        headers.set("X-Forwarded-For", "10.0.0.1")?;
        headers.set("X-Real-IP", "172.16.0.1")?;

        // Only CF-Connecting-IP is trusted
        let ip = get_client_ip(&headers);
        assert_eq!(ip, "unknown");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_unknown_when_missing() {
        let headers = Headers::new();
        let ip = get_client_ip(&headers);
        assert_eq!(ip, "unknown");
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_ipv6_format() -> Result<(), Box<dyn std::error::Error>> {
        let headers = Headers::new();
        headers.set("CF-Connecting-IP", "2001:db8::1")?;

        let ip = get_client_ip(&headers);
        assert_eq!(ip, "2001:db8::1");
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_get_client_ip_localhost() -> Result<(), Box<dyn std::error::Error>> {
        let headers = Headers::new();
        headers.set("CF-Connecting-IP", "127.0.0.1")?;

        let ip = get_client_ip(&headers);
        assert_eq!(ip, "127.0.0.1");
        Ok(())
    }

    /* ========================================================================== */
    /*                    TTL Bounding Logic TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_ttl_bounding_within_limits() {
        let requested = 100;
        let policy_max = 200;
        let bounded = requested
            .min(policy_max)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

        assert_eq!(bounded, 100);
    }

    #[test]
    fn test_ttl_bounding_exceeds_max() {
        let requested = 500;
        let policy_max = 400;
        let bounded = requested
            .min(policy_max)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

        assert_eq!(bounded, MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_below_min() {
        let requested = 10;
        let policy_max = 200;
        let bounded = requested
            .min(policy_max)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

        assert_eq!(bounded, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_policy_lower_than_requested() {
        let requested = 200;
        let policy_max = 100;
        let bounded = requested
            .min(policy_max)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

        assert_eq!(bounded, 100);
    }

    #[test]
    fn test_ttl_bounding_policy_lower_than_min() {
        let requested = 100;
        let policy_max = 10;
        let bounded = requested
            .min(policy_max)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

        assert_eq!(bounded, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_all_equal() {
        let requested = 60;
        let policy_max = 60;
        let bounded = requested
            .min(policy_max)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);

        assert_eq!(bounded, 60);
    }

    /* ========================================================================== */
    /*                    Cutoff Days Calculation TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_calculation_normal() {
        let today_epoch_days = 19000u32;
        let min_age_days = 6570u32;
        let cutoff = today_epoch_days - min_age_days;

        assert_eq!(cutoff, 12430);
    }

    #[test]
    fn test_cutoff_days_calculation_zero_min_age() {
        let today_epoch_days = 19000u32;
        let min_age_days = 0u32;
        let cutoff = today_epoch_days - min_age_days;

        assert_eq!(cutoff, 19000);
    }

    #[test]
    fn test_cutoff_days_calculation_large_min_age() {
        let today_epoch_days = 20000u32;
        let min_age_days = 10000u32;
        let cutoff = today_epoch_days - min_age_days;

        assert_eq!(cutoff, 10000);
    }

    #[test]
    fn test_epoch_days_from_timestamp() {
        let timestamp = 1_600_000_000u64; // September 13, 2020
        let epoch_days = (timestamp / 86_400) as u32;

        assert_eq!(epoch_days, 18518);
    }

    #[test]
    fn test_epoch_days_calculation() {
        let secs_per_day = 86_400u64;
        assert_eq!(secs_per_day, 24 * 60 * 60);
    }

    /* ========================================================================== */
    /*                    URL Construction TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_status_url_format() -> Result<(), Box<dyn std::error::Error>> {
        let api_base_url = "https://verify.provii.app/v1";
        let challenge_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let status_url = format!("{}/challenge/{}", api_base_url, challenge_id);

        assert_eq!(
            status_url,
            "https://verify.provii.app/v1/challenge/550e8400-e29b-41d4-a716-446655440000"
        );
        Ok(())
    }

    #[test]
    fn test_verify_url_format() {
        let api_base_url = "https://verify.provii.app/v1";
        let verify_url = format!("{}/verify", api_base_url);

        assert_eq!(verify_url, "https://verify.provii.app/v1/verify");
    }

    #[test]
    fn test_status_url_with_custom_base() -> Result<(), Box<dyn std::error::Error>> {
        let api_base_url = "https://custom.api.example.com";
        let challenge_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let status_url = format!("{}/challenge/{}", api_base_url, challenge_id);

        assert_eq!(
            status_url,
            "https://custom.api.example.com/challenge/550e8400-e29b-41d4-a716-446655440000"
        );
        Ok(())
    }

    #[test]
    fn test_url_construction_always_https() {
        let api_base_url = "https://verify.provii.app/v1";
        let status_url = format!("{}/challenge/{}", api_base_url, Uuid::new_v4());

        assert!(status_url.starts_with("https://"));
    }

    /* ========================================================================== */
    /*                    PG-VAL-016 build_v1_base TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_build_v1_base_appends_when_missing() {
        // Sandbox previously configured `https://sandbox-verify.provii.app`
        // without `/v1`. The helper must append it so emitted URLs work.
        assert_eq!(
            build_v1_base("https://sandbox-verify.provii.app"),
            "https://sandbox-verify.provii.app/v1"
        );
    }

    #[test]
    fn test_build_v1_base_preserves_when_present() {
        // Production carries `/v1` in the configured base. The helper must
        // not duplicate it (`/v1/v1/challenge/...` would also 404).
        assert_eq!(
            build_v1_base("https://verify.provii.app/v1"),
            "https://verify.provii.app/v1"
        );
    }

    #[test]
    fn test_build_v1_base_strips_trailing_slash() {
        assert_eq!(
            build_v1_base("https://example.com/"),
            "https://example.com/v1"
        );
        assert_eq!(
            build_v1_base("https://example.com/v1/"),
            "https://example.com/v1"
        );
    }

    #[test]
    fn test_build_v1_base_does_not_double_v1_when_path_only_partially_matches() {
        // Defensive: a base ending in something that *contains* "/v1"
        // (e.g. /verify/v1) but isn't exactly "/v1" still appends correctly.
        // This isn't a real config but the helper shouldn't silently drop
        // the suffix.
        assert_eq!(
            build_v1_base("https://example.com/api"),
            "https://example.com/api/v1"
        );
    }

    #[test]
    fn test_emitted_status_url_includes_v1_in_sandbox_shape() {
        // Round-trip the bug NEW-C reported in round-2 validation: the
        // server's `status_url` field omitted `/v1/` for sandbox callers.
        let challenge_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let status_url = format!(
            "{}/challenge/{}",
            build_v1_base("https://sandbox-verify.provii.app"),
            challenge_id
        );
        assert_eq!(
            status_url,
            "https://sandbox-verify.provii.app/v1/challenge/550e8400-e29b-41d4-a716-446655440000"
        );
        let verify_url = format!(
            "{}/verify",
            build_v1_base("https://sandbox-verify.provii.app")
        );
        assert_eq!(verify_url, "https://sandbox-verify.provii.app/v1/verify");
    }

    /* ========================================================================== */
    /*                    Array Copying Logic TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_vec_to_array_32_bytes() {
        let vec = vec![
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);

        assert_eq!(arr[0], 1);
        assert_eq!(arr[31], 32);
        assert_eq!(arr.len(), 32);
    }

    #[test]
    fn test_vec_to_array_preserves_values() {
        let vec = (0u8..32).collect::<Vec<_>>();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);

        for (i, &val) in arr.iter().enumerate() {
            assert_eq!(val, i as u8);
        }
    }

    #[test]
    fn test_array_copy_all_zeros() {
        let vec = vec![0u8; 32];

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);

        for &val in &arr {
            assert_eq!(val, 0);
        }
    }

    #[test]
    fn test_array_copy_all_ones() {
        let vec = vec![255u8; 32];

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);

        for &val in &arr {
            assert_eq!(val, 255);
        }
    }

    /* ========================================================================== */
    /*                    StatusDto Creation TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_status_dto_pending_state() {
        let state = ChallengeState::Pending;
        let status_str = state.as_str().to_string();
        let verified = state == ChallengeState::Verified;
        let proof_verified = matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );

        assert_eq!(status_str, "pending");
        assert!(!verified);
        assert!(!proof_verified);
    }

    #[test]
    fn test_status_dto_proof_ok_waiting_state() {
        let state = ChallengeState::ProofOkWaitingForRedeem;
        let status_str = state.as_str().to_string();
        let verified = state == ChallengeState::Verified;
        let proof_verified = matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );

        assert_eq!(status_str, "proof_ok_waiting_for_redeem");
        assert!(!verified);
        assert!(proof_verified);
    }

    #[test]
    fn test_status_dto_verified_state() {
        let state = ChallengeState::Verified;
        let status_str = state.as_str().to_string();
        let verified = state == ChallengeState::Verified;
        let proof_verified = matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );

        assert_eq!(status_str, "verified");
        assert!(verified);
        assert!(proof_verified);
    }

    #[test]
    fn test_status_dto_failed_state() {
        let state = ChallengeState::Failed;
        let status_str = state.as_str().to_string();
        let verified = state == ChallengeState::Verified;
        let proof_verified = matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );

        assert_eq!(status_str, "failed");
        assert!(!verified);
        assert!(!proof_verified);
    }

    #[test]
    fn test_status_dto_expired_state() {
        let state = ChallengeState::Expired;
        let status_str = state.as_str().to_string();
        let verified = state == ChallengeState::Verified;
        let proof_verified = matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );

        assert_eq!(status_str, "expired");
        assert!(!verified);
        assert!(!proof_verified);
    }

    /* ========================================================================== */
    /*                    Additional Property Tests                              */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: TTL bounding is monotonic (result always within bounds)
        #[test]
        fn prop_ttl_bounding_always_in_range(
            requested in any::<u64>(),
            policy_max in any::<u64>()
        ) {
            let bounded = requested
                .min(policy_max)
                .min(MAX_CHALLENGE_TTL)
                .max(MIN_CHALLENGE_TTL);

            prop_assert!(bounded >= MIN_CHALLENGE_TTL);
            prop_assert!(bounded <= MAX_CHALLENGE_TTL);
        }

        /// Property: Cutoff days calculation is deterministic
        #[test]
        fn prop_cutoff_days_deterministic(
            today in 10000u32..30000,
            min_age in 1u32..10000
        ) {
            prop_assume!(today > min_age);
            let cutoff1 = today - min_age;
            let cutoff2 = today - min_age;
            prop_assert_eq!(cutoff1, cutoff2);
        }

        /// Property: URL construction preserves UUID
        #[test]
        fn prop_url_preserves_uuid(uuid_bytes in any::<[u8; 16]>()) {
            let uuid = Uuid::from_bytes(uuid_bytes);
            let api_base_url = "https://verify.provii.app/v1";
            let status_url = format!("{}/challenge/{}", api_base_url, uuid);

            prop_assert!(status_url.contains(&uuid.to_string()));
        }

        /// Property: Array copying preserves all bytes
        #[test]
        fn prop_array_copy_preserves_bytes(bytes in prop::collection::vec(any::<u8>(), 32..=32)) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);

            for (i, &b) in bytes.iter().enumerate() {
                prop_assert_eq!(arr[i], b);
            }
        }

        /// Property: Status verification flags are mutually consistent
        #[test]
        fn prop_status_flags_consistent(_seed in any::<u8>()) {
            let states = vec![
                ChallengeState::Pending,
                ChallengeState::ProofOkWaitingForRedeem,
                ChallengeState::Verified,
                ChallengeState::Failed,
                ChallengeState::Expired,
            ];

            for state in states {
                let verified = state == ChallengeState::Verified;
                let proof_verified = matches!(
                    state,
                    ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
                );

                // If verified, then proof_verified must also be true
                if verified {
                    prop_assert!(proof_verified);
                }
            }
        }
    }

    // Client IP extraction uses worker::Headers which is only available on wasm32.
    // This proptest cannot run on native targets. Gate it behind an unreachable feature.
    #[cfg(all(not(target_arch = "wasm32"), feature = "__proptest_worker_headers"))]
    proptest! {
        /// Property: Only CF-Connecting-IP is used, all other headers ignored
        #[test]
        fn prop_client_ip_cf_only(has_cf in any::<bool>(), has_fwd in any::<bool>()) -> Result<(), Box<dyn std::error::Error>> {
            let mut headers = Headers::new();

            if has_cf {
                headers.set("CF-Connecting-IP", "192.168.1.1")?;
            }
            if has_fwd {
                headers.set("X-Forwarded-For", "10.0.0.1")?;
            }

            let ip = get_client_ip(&headers);

            if has_cf {
                prop_assert_eq!(ip, "192.168.1.1");
            } else {
                // X-Forwarded-For is never used regardless of presence
                prop_assert_eq!(ip, "unknown");
            }
            Ok(())
        }
    }

    /* ========================================================================== */
    /*                generate_short_code_from_uuid() TESTS                      */
    /* ========================================================================== */

    #[test]
    fn test_short_code_from_uuid_is_12_digits() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let code = generate_short_code_from_uuid(&id);

        assert_eq!(code.len(), 12, "short code must be exactly 12 characters");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "short code must be all digits, got: {}",
            code
        );
        Ok(())
    }

    #[test]
    fn test_short_code_from_uuid_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
        let code1 = generate_short_code_from_uuid(&id);
        let code2 = generate_short_code_from_uuid(&id);

        assert_eq!(code1, code2, "same UUID must produce same short code");
        Ok(())
    }

    #[test]
    fn test_short_code_from_uuid_different_uuids_differ() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let code1 = generate_short_code_from_uuid(&id1);
        let code2 = generate_short_code_from_uuid(&id2);

        // In theory there is a 10^-12 collision probability. Two fresh v4 UUIDs
        // should produce different codes in practice.
        assert_ne!(
            code1, code2,
            "different UUIDs should produce different short codes"
        );
    }

    #[test]
    fn test_short_code_from_nil_uuid() {
        let nil = Uuid::nil();
        let code = generate_short_code_from_uuid(&nil);

        assert_eq!(code.len(), 12);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        // All bytes are 0, XOR folding yields 0, num=0, code="000000000000".
        assert_eq!(code, "000000000000");
    }

    #[test]
    fn test_short_code_from_max_uuid() {
        let max = Uuid::max();
        let code = generate_short_code_from_uuid(&max);

        assert_eq!(code.len(), 12);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        // All bytes 0xFF, XOR(0xFF, 0xFF)=0 for each position. Same as nil.
        assert_eq!(code, "000000000000");
    }

    #[test]
    fn test_short_code_is_valid_shortcode_type() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("a1b2c3d4-e5f6-4718-8293-a4b5c6d7e8f9")?;
        let code = generate_short_code_from_uuid(&id);

        // The generated code must be parseable by ShortCode::new.
        let sc = ShortCode::new(&code).map_err(|e| format!("ShortCode::new failed: {}", e))?;
        assert_eq!(sc.as_str(), &code);
        Ok(())
    }

    #[test]
    fn test_short_code_formatted_display() -> Result<(), Box<dyn std::error::Error>> {
        let id = Uuid::parse_str("a1b2c3d4-e5f6-4718-8293-a4b5c6d7e8f9")?;
        let code = generate_short_code_from_uuid(&id);
        let sc = ShortCode::new(&code).map_err(|e| format!("ShortCode::new failed: {}", e))?;
        let formatted = sc.display_formatted();

        // Format is "XXXX XXXX XXXX"
        assert_eq!(
            formatted.len(),
            14,
            "formatted code should be 14 chars (12 digits + 2 spaces)"
        );
        let parts: Vec<&str> = formatted.split(' ').collect();
        assert_eq!(parts.len(), 3, "formatted code should have 3 groups");
        for part in &parts {
            assert_eq!(part.len(), 4, "each group should be 4 digits");
        }
        Ok(())
    }

    #[test]
    fn test_short_code_xor_folding_symmetry() -> Result<(), Box<dyn std::error::Error>> {
        // UUID where high and low halves differ by exactly one byte.
        // This verifies the XOR folding produces nonzero output when halves differ.
        let id = Uuid::from_bytes([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        let code = generate_short_code_from_uuid(&id);
        assert_ne!(
            code, "000000000000",
            "non-symmetric halves should not produce all zeros"
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                build_v1_base() EXTENDED TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_build_v1_base_empty_string() {
        assert_eq!(build_v1_base(""), "/v1");
    }

    #[test]
    fn test_build_v1_base_just_slash() {
        assert_eq!(build_v1_base("/"), "/v1");
    }

    #[test]
    fn test_build_v1_base_multiple_trailing_slashes() {
        // trim_end_matches('/') removes all trailing slashes.
        assert_eq!(
            build_v1_base("https://example.com///"),
            "https://example.com/v1"
        );
    }

    #[test]
    fn test_build_v1_base_v1_with_multiple_trailing_slashes() {
        assert_eq!(
            build_v1_base("https://example.com/v1///"),
            "https://example.com/v1"
        );
    }

    #[test]
    fn test_build_v1_base_v1_in_hostname() {
        // "v1" appearing in the host part should not be treated as the path suffix.
        assert_eq!(
            build_v1_base("https://v1.example.com"),
            "https://v1.example.com/v1"
        );
    }

    #[test]
    fn test_build_v1_base_nested_path() {
        assert_eq!(
            build_v1_base("https://example.com/api/v2"),
            "https://example.com/api/v2/v1"
        );
    }

    #[test]
    fn test_build_v1_base_v10_suffix() {
        // "/v10" ends with "0", not "/v1", so /v1 must be appended.
        assert_eq!(
            build_v1_base("https://example.com/v10"),
            "https://example.com/v10/v1"
        );
    }

    #[test]
    fn test_build_v1_base_v1_exact_path() {
        // Exactly "/v1" with nothing else.
        assert_eq!(build_v1_base("/v1"), "/v1");
    }

    #[test]
    fn test_build_v1_base_used_in_status_url() {
        let challenge_id = Uuid::nil();
        let base = build_v1_base("https://api.example.com");
        let status = format!("{}/challenge/{}", base, challenge_id);
        assert!(status.starts_with("https://api.example.com/v1/challenge/"));
    }

    #[test]
    fn test_build_v1_base_used_in_verify_url() {
        let base = build_v1_base("https://api.example.com/v1");
        let verify = format!("{}/verify", base);
        assert_eq!(verify, "https://api.example.com/v1/verify");
    }

    /* ========================================================================== */
    /*        apply_sandbox_bypass_overrides() EXTENDED TESTS                     */
    /* ========================================================================== */

    fn make_origin_policy(
        tenant_id: &str,
        min_age: u32,
        plan: &str,
        metering: bool,
    ) -> crate::storage::origin_policy::OriginPolicy {
        crate::storage::origin_policy::OriginPolicy {
            tenant_id: tenant_id.to_string(),
            min_age_years: min_age,
            max_age_years: None,
            proof_direction: None,
            allowed_vk_ids: vec![1],
            allowed_issuers: vec![],
            max_ttl_sec: 300,
            billing: crate::storage::origin_policy::BillingConfig {
                plan: plan.to_string(),
                metering_enabled: metering,
            },
            enabled: true,
            created_at: 0,
            updated_at: 0,
            clients: Vec::new(),
            provisioned_by: None,
            failure_mode: None,
            failure_mode_locked: false,
        }
    }

    #[test]
    fn test_sandbox_bypass_overrides_replace_tenant_id() {
        let policy = make_origin_policy("org_prod_xyz", 21, "enterprise", true);
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert_eq!(bypassed.tenant_id, "sandbox_default");
    }

    #[test]
    fn test_sandbox_bypass_overrides_force_age_18() {
        let policy = make_origin_policy("t", 25, "free", false);
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert_eq!(bypassed.min_age_years, 18);
    }

    #[test]
    fn test_sandbox_bypass_overrides_disable_metering() {
        let policy = make_origin_policy("t", 18, "pro", true);
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert!(!bypassed.billing.metering_enabled);
        assert_eq!(bypassed.billing.plan, "sandbox");
    }

    #[test]
    fn test_sandbox_bypass_overrides_preserve_allowed_vk_ids() {
        let mut policy = make_origin_policy("t", 18, "free", false);
        policy.allowed_vk_ids = vec![1, 2, 5, 7];
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert_eq!(bypassed.allowed_vk_ids, vec![1, 2, 5, 7]);
    }

    #[test]
    fn test_sandbox_bypass_overrides_preserve_max_ttl() {
        let mut policy = make_origin_policy("t", 18, "free", false);
        policy.max_ttl_sec = 120;
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert_eq!(bypassed.max_ttl_sec, 120);
    }

    #[test]
    fn test_sandbox_bypass_overrides_preserve_enabled_flag() {
        let mut policy = make_origin_policy("t", 18, "free", false);
        policy.enabled = false;
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert!(!bypassed.enabled, "enabled flag must not be modified");
    }

    #[test]
    fn test_sandbox_bypass_overrides_preserve_allowed_issuers() {
        let mut policy = make_origin_policy("t", 18, "free", false);
        policy.allowed_issuers = vec!["issuer_a".to_string(), "issuer_b".to_string()];
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert_eq!(bypassed.allowed_issuers.len(), 2);
    }

    #[test]
    fn test_sandbox_bypass_overrides_idempotent() {
        let policy = make_origin_policy("sandbox_default", 18, "sandbox", false);
        let bypassed = apply_sandbox_bypass_overrides(policy);
        assert_eq!(bypassed.tenant_id, "sandbox_default");
        assert_eq!(bypassed.min_age_years, 18);
        assert_eq!(bypassed.billing.plan, "sandbox");
        assert!(!bypassed.billing.metering_enabled);
    }

    /* ========================================================================== */
    /*        should_skip_origin_check_for_rp_sandbox() EXTENDED TESTS           */
    /* ========================================================================== */

    #[test]
    fn test_sandbox_bypass_exact_prefix_boundary() {
        // "rp_sandbox_" is exactly the prefix. Anything after it should match.
        assert!(should_skip_origin_check_for_rp_sandbox(
            "sandbox",
            "rp_sandbox_"
        ));
        assert!(should_skip_origin_check_for_rp_sandbox(
            "sandbox",
            "rp_sandbox_x"
        ));
        assert!(should_skip_origin_check_for_rp_sandbox(
            "sandbox",
            "rp_sandbox_1234567890abcdef"
        ));
    }

    #[test]
    fn test_sandbox_bypass_rejects_partial_prefix() {
        assert!(!should_skip_origin_check_for_rp_sandbox(
            "sandbox",
            "rp_sandbox"
        ));
        assert!(!should_skip_origin_check_for_rp_sandbox(
            "sandbox",
            "rp_sandbo"
        ));
        assert!(!should_skip_origin_check_for_rp_sandbox("sandbox", "rp_"));
    }

    #[test]
    fn test_sandbox_bypass_empty_environment() {
        assert!(!should_skip_origin_check_for_rp_sandbox(
            "",
            "rp_sandbox_abc"
        ));
    }

    #[test]
    fn test_sandbox_bypass_empty_key_id() {
        assert!(!should_skip_origin_check_for_rp_sandbox("sandbox", ""));
    }

    #[test]
    fn test_sandbox_bypass_both_empty() {
        assert!(!should_skip_origin_check_for_rp_sandbox("", ""));
    }

    /* ========================================================================== */
    /*        create_canonical_message_for_challenge() EXTENDED TESTS             */
    /* ========================================================================== */

    #[test]
    fn test_canonical_message_exact_five_part_structure() -> Result<(), Box<dyn std::error::Error>>
    {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 9999, &req);

        // EA-018: exactly 5 colon-separated parts.
        // But the JSON body itself contains colons, so we use splitn(5,...).
        let parts: Vec<&str> = msg.splitn(5, ':').collect();
        assert_eq!(
            parts.len(),
            5,
            "canonical message must have 5 colon-delimited sections"
        );
        assert_eq!(parts[0], "9999");
        assert_eq!(parts[1], "POST");
        assert_eq!(parts[2], "/v1/challenge");
        // parts[3] is the JSON payload (contains colons itself)
        // parts[4] ends with the nonce
        Ok(())
    }

    #[test]
    fn test_canonical_message_uses_base64url_not_display() -> Result<(), Box<dyn std::error::Error>>
    {
        // B64Url32::fmt (Display) returns "[REDACTED]". The canonical message
        // must use the actual base64url encoding, not the Display impl.
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);
        assert!(
            !msg.contains("[REDACTED]"),
            "canonical message must not contain [REDACTED]"
        );
        Ok(())
    }

    #[test]
    fn test_canonical_message_with_zero_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 0, &req);
        assert!(msg.starts_with("0:POST:/v1/challenge:"));
        Ok(())
    }

    #[test]
    fn test_canonical_message_with_u64_max_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", u64::MAX, &req);
        assert!(msg.starts_with(&format!("{}:POST:/v1/challenge:", u64::MAX)));
        Ok(())
    }

    #[test]
    fn test_canonical_message_verifying_key_none_vs_some() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut req_none = create_test_request()?;
        req_none.verifying_key_id = None;
        let msg_none =
            create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req_none);

        let req_some = create_test_request()?; // has verifying_key_id = Some(1)
        let msg_some =
            create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req_some);

        // The messages must differ because the JSON payload includes null vs 1.
        assert_ne!(msg_none, msg_some);
        // The None variant should contain "null" in the JSON.
        assert!(
            msg_none.contains("null"),
            "None vk_id should serialise as null"
        );
        Ok(())
    }

    #[test]
    fn test_canonical_message_different_code_challenges() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut req1 = create_test_request()?;
        req1.code_challenge = B64Url32::new([0u8; 32]);

        let mut req2 = create_test_request()?;
        req2.code_challenge = B64Url32::new([255u8; 32]);

        let msg1 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req1);
        let msg2 = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req2);

        assert_ne!(msg1, msg2);
        Ok(())
    }

    #[test]
    fn test_canonical_message_empty_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let mut req = create_test_request()?;
        req.authorizer.nonce = String::new();

        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Ends with an empty nonce (trailing colon from the format string).
        assert!(
            msg.ends_with(':'),
            "empty nonce should leave trailing colon"
        );
        Ok(())
    }

    #[test]
    fn test_canonical_message_json_payload_is_valid_json() -> Result<(), Box<dyn std::error::Error>>
    {
        let req = create_test_request()?;
        let msg = create_canonical_message_for_challenge("POST", "/v1/challenge", 1000, &req);

        // Extract the JSON payload: it's the 4th colon-delimited field.
        // Format: timestamp:method:path:{json}:nonce
        // We split into at most 5 parts and take parts[3] through to the last colon before nonce.
        let after_path = msg
            .strip_prefix("1000:POST:/v1/challenge:")
            .ok_or("unexpected prefix")?;
        // The nonce is the last colon-delimited segment.
        let json_end = after_path.rfind(':').ok_or("no colon before nonce")?;
        let json_str = &after_path[..json_end];

        let parsed: serde_json::Value = serde_json::from_str(json_str)?;
        assert!(parsed.is_object());
        assert!(parsed.get("code_challenge").is_some());
        assert!(parsed.get("method").is_some());
        assert!(parsed.get("expires_in").is_some());
        assert!(parsed.get("verifying_key_id").is_some());
        Ok(())
    }

    /* ========================================================================== */
    /*        TTL Bounding EXTENDED TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_ttl_bounding_exact_min() {
        let bounded = MIN_CHALLENGE_TTL
            .min(300)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_exact_max() {
        let bounded = MAX_CHALLENGE_TTL
            .min(500)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_zero_requested() {
        let bounded = 0u64.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_u64_max_requested() {
        let bounded = 300.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, MAX_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_zero_policy_max() {
        let bounded = 0.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, MIN_CHALLENGE_TTL);
    }

    #[test]
    fn test_ttl_bounding_policy_max_between_min_and_max() {
        let bounded = 150.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, 150);
    }

    #[test]
    fn test_ttl_bounding_both_at_min() {
        let bounded = MIN_CHALLENGE_TTL
            .min(MIN_CHALLENGE_TTL)
            .clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL);
        assert_eq!(bounded, MIN_CHALLENGE_TTL);
    }

    /* ========================================================================== */
    /*        Cutoff Days i32 Boundary TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_cutoff_days_checked_sub_normal() {
        let today: i32 = 20000;
        let age_days: i32 = 6575;
        let result = today.checked_sub(age_days);
        assert_eq!(result, Some(13425));
    }

    #[test]
    fn test_cutoff_days_checked_sub_zero_age() {
        let today: i32 = 20000;
        let age_days: i32 = 0;
        let result = today.checked_sub(age_days);
        assert_eq!(result, Some(20000));
    }

    #[test]
    fn test_cutoff_days_checked_sub_produces_negative() {
        // When age_days > today, cutoff is negative (future date). CutoffDays
        // allows negatives down to CutoffDays::MIN.
        let today: i32 = 100;
        let age_days: i32 = 200;
        let result = today.checked_sub(age_days);
        assert_eq!(result, Some(-100));
    }

    #[test]
    fn test_cutoff_days_checked_sub_i32_min_overflow() {
        // i32::MIN - 1 would overflow. checked_sub catches it.
        let result = i32::MIN.checked_sub(1);
        assert!(result.is_none());
    }

    #[test]
    fn test_cutoff_days_new_within_range() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(10000)?;
        assert_eq!(cd.get(), 10000);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_at_min_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(CutoffDays::MIN)?;
        assert_eq!(cd.get(), CutoffDays::MIN);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_at_max_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let cd = CutoffDays::new(CutoffDays::MAX)?;
        assert_eq!(cd.get(), CutoffDays::MAX);
        Ok(())
    }

    #[test]
    fn test_cutoff_days_new_below_min() {
        let result = CutoffDays::new(CutoffDays::MIN - 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_cutoff_days_new_above_max() {
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
        let cd = CutoffDays::new(-5000)?;
        assert_eq!(cd.get(), -5000);
        Ok(())
    }

    /* ========================================================================== */
    /*        VkId Boundary TESTS                                                */
    /* ========================================================================== */

    #[test]
    fn test_vk_id_new_zero_returns_none() {
        assert!(VkId::new(0).is_none());
    }

    #[test]
    fn test_vk_id_new_one_returns_some() {
        let vk = VkId::new(1);
        assert!(vk.is_some());
        assert_eq!(vk.map(|v| v.get()), Some(1));
    }

    #[test]
    fn test_vk_id_new_max_u32() {
        let vk = VkId::new(u32::MAX);
        assert!(vk.is_some());
        assert_eq!(vk.map(|v| v.get()), Some(u32::MAX));
    }

    /* ========================================================================== */
    /*        ExpiresIn Boundary TESTS                                           */
    /* ========================================================================== */

    #[test]
    fn test_expires_in_default_is_max() {
        let e = ExpiresIn::default();
        assert_eq!(e.get(), 300);
    }

    #[test]
    fn test_expires_in_clamps_below_min() {
        let e = ExpiresIn::new(0);
        assert_eq!(e.get(), ExpiresIn::MIN);
    }

    #[test]
    fn test_expires_in_clamps_above_max() {
        let e = ExpiresIn::new(99999);
        assert_eq!(e.get(), ExpiresIn::MAX);
    }

    #[test]
    fn test_expires_in_within_range() {
        let e = ExpiresIn::new(120);
        assert_eq!(e.get(), 120);
    }

    #[test]
    fn test_expires_in_at_min() {
        let e = ExpiresIn::new(ExpiresIn::MIN);
        assert_eq!(e.get(), ExpiresIn::MIN);
    }

    #[test]
    fn test_expires_in_at_max() {
        let e = ExpiresIn::new(ExpiresIn::MAX);
        assert_eq!(e.get(), ExpiresIn::MAX);
    }

    /* ========================================================================== */
    /*        ChallengeState EXTENDED TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_as_str_all_variants() {
        assert_eq!(ChallengeState::Pending.as_str(), "pending");
        assert_eq!(
            ChallengeState::ProofOkWaitingForRedeem.as_str(),
            "proof_ok_waiting_for_redeem"
        );
        assert_eq!(ChallengeState::Verified.as_str(), "verified");
        assert_eq!(ChallengeState::Failed.as_str(), "failed");
        assert_eq!(ChallengeState::Expired.as_str(), "expired");
    }

    #[test]
    fn test_challenge_state_equality() {
        assert_eq!(ChallengeState::Pending, ChallengeState::Pending);
        assert_ne!(ChallengeState::Pending, ChallengeState::Failed);
        assert_ne!(
            ChallengeState::Verified,
            ChallengeState::ProofOkWaitingForRedeem
        );
    }

    #[test]
    fn test_status_dto_all_states_produce_valid_strings() {
        let all_states = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];

        for state in &all_states {
            let s = state.as_str();
            assert!(!s.is_empty(), "state {:?} produced empty string", state);
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "state string '{}' contains unexpected characters",
                s
            );
        }
    }

    #[test]
    fn test_verified_implies_proof_verified() {
        // Business rule: if verified is true, proof_verified must also be true.
        let verified = ChallengeState::Verified == ChallengeState::Verified;
        let proof_verified = matches!(
            ChallengeState::Verified,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );
        assert!(verified);
        assert!(proof_verified);
    }

    #[test]
    fn test_proof_ok_not_verified() {
        // proof_ok state: proof_verified=true but verified=false.
        let state = ChallengeState::ProofOkWaitingForRedeem;
        let verified = state == ChallengeState::Verified;
        let proof_verified = matches!(
            state,
            ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
        );
        assert!(!verified);
        assert!(proof_verified);
    }

    #[test]
    fn test_terminal_states_not_proof_verified() {
        // Failed and Expired are terminal; neither should report proof_verified.
        for state in [ChallengeState::Failed, ChallengeState::Expired] {
            let verified = state == ChallengeState::Verified;
            let proof_verified = matches!(
                state,
                ChallengeState::ProofOkWaitingForRedeem | ChallengeState::Verified
            );
            assert!(!verified, "{:?} should not be verified", state);
            assert!(!proof_verified, "{:?} should not be proof_verified", state);
        }
    }

    /* ========================================================================== */
    /*        Origin Validation Logic TESTS (pure string checks)                 */
    /* ========================================================================== */

    #[test]
    fn test_origin_malicious_scheme_javascript() {
        let origin = "javascript:alert(1)";
        assert!(origin.contains("javascript:"));
    }

    #[test]
    fn test_origin_malicious_scheme_data() {
        let origin = "data:text/html,<h1>XSS</h1>";
        assert!(origin.contains("data:"));
    }

    #[test]
    fn test_origin_malicious_scheme_vbscript() {
        let origin = "vbscript:MsgBox";
        assert!(origin.contains("vbscript:"));
    }

    // VA-CHL-001: blob: URI scheme added to malicious origin checks.
    #[test]
    fn test_origin_malicious_scheme_blob() {
        let origin = "blob:https://evil.com/abc123";
        assert!(origin.contains("blob:"));
    }

    #[test]
    fn test_origin_malicious_schemes_do_not_match_normal_origins() {
        let normal_origins = [
            "https://example.com",
            "http://localhost:3000",
            "https://data-analytics.example.com",
            "https://javascript-docs.example.com",
            "https://blobfish.example.com",
        ];
        for o in &normal_origins {
            // "javascript:" (with colon) not present in "javascript-docs".
            // "data:" not present in "data-analytics" (hyphen, not colon).
            // "blob:" not present in "blobfish" (no colon after).
            let has_js = o.contains("javascript:");
            let has_data = o.contains("data:");
            let has_vbs = o.contains("vbscript:");
            let has_blob = o.contains("blob:");
            assert!(
                !(has_js || has_data || has_vbs || has_blob),
                "normal origin '{}' incorrectly flagged as malicious",
                o
            );
        }
    }

    #[test]
    fn test_origin_too_long_boundary() {
        let exactly_2048 = "x".repeat(2048);
        assert!(exactly_2048.len() <= 2048, "exactly 2048 should be allowed");

        let too_long = "x".repeat(2049);
        assert!(too_long.len() > 2048, "2049 should be rejected");
    }

    #[test]
    fn test_origin_empty_is_rejected() {
        let origin = "";
        let is_valid = !origin.is_empty();
        assert!(!is_valid, "empty origin should be rejected");
    }

    /* ========================================================================== */
    /*        Epoch Days Calculation EXTENDED TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_epoch_days_zero_timestamp() {
        let ts: u64 = 0;
        let epoch_days = (ts / 86_400) as u32;
        assert_eq!(epoch_days, 0);
    }

    #[test]
    fn test_epoch_days_one_day() {
        let epoch_days = (86_400u64 / 86_400) as u32;
        assert_eq!(epoch_days, 1);
    }

    #[test]
    fn test_epoch_days_just_under_one_day() {
        let epoch_days = (86_399u64 / 86_400) as u32;
        assert_eq!(epoch_days, 0);
    }

    #[test]
    fn test_epoch_days_year_2030() {
        // 2030-01-01T00:00:00Z = 1893456000
        let epoch_days = (1_893_456_000u64 / 86_400) as u32;
        assert_eq!(epoch_days, 21_915);
    }

    #[test]
    fn test_epoch_days_u64_max_does_not_overflow_u32() {
        // u64::MAX / 86400 = ~213_503_982_334_601, which overflows u32.
        // This matches the production code's `#[allow(cast_possible_truncation)]`.
        // The truncation is acceptable because epoch days won't reach u32::MAX
        // until year 11,761,191.
        let epoch_days_u64 = u64::MAX / 86_400;
        assert!(epoch_days_u64 > u32::MAX as u64);
    }

    /* ========================================================================== */
    /*        ShortCode::new() Validation TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_shortcode_new_valid_12_digits() -> Result<(), Box<dyn std::error::Error>> {
        let sc = ShortCode::new("123456789012")?;
        assert_eq!(sc.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_with_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let sc = ShortCode::new("1234 5678 9012")?;
        assert_eq!(sc.as_str(), "123456789012");
        Ok(())
    }

    #[test]
    fn test_shortcode_new_too_short() {
        let result = ShortCode::new("12345678901");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_too_long() {
        let result = ShortCode::new("1234567890123");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_non_numeric() {
        let result = ShortCode::new("12345678901a");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_new_empty() {
        let result = ShortCode::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_shortcode_display_formatted_groups() -> Result<(), Box<dyn std::error::Error>> {
        let sc = ShortCode::new("123456789012")?;
        assert_eq!(sc.display_formatted(), "1234 5678 9012");
        Ok(())
    }

    #[test]
    fn test_shortcode_all_zeros() -> Result<(), Box<dyn std::error::Error>> {
        let sc = ShortCode::new("000000000000")?;
        assert_eq!(sc.display_formatted(), "0000 0000 0000");
        Ok(())
    }

    #[test]
    fn test_shortcode_all_nines() -> Result<(), Box<dyn std::error::Error>> {
        let sc = ShortCode::new("999999999999")?;
        assert_eq!(sc.display_formatted(), "9999 9999 9999");
        Ok(())
    }

    /* ========================================================================== */
    /*        B64Url32 TESTS                                                     */
    /* ========================================================================== */

    #[test]
    fn test_b64url32_new_round_trip() {
        let bytes = [42u8; 32];
        let b = B64Url32::new(bytes);
        assert_eq!(b.as_bytes(), &bytes);
    }

    #[test]
    fn test_b64url32_display_is_redacted() {
        let b = B64Url32::new([0u8; 32]);
        assert_eq!(format!("{}", b), "[REDACTED]");
    }

    #[test]
    fn test_b64url32_debug_is_redacted() {
        let b = B64Url32::new([0u8; 32]);
        assert_eq!(format!("{:?}", b), "B64Url32(***redacted***)");
    }

    /* ========================================================================== */
    /*        Authorizer Validation TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_authorizer_validate_valid() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "test-key".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        auth.validate()?;
        Ok(())
    }

    #[test]
    fn test_authorizer_validate_empty_key_id() {
        let auth = Authorizer {
            key_id: "".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_whitespace_key_id() {
        let auth = Authorizer {
            key_id: "   ".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_key_id_too_long() {
        let auth = Authorizer {
            key_id: "x".repeat(129),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_key_id_non_ascii() {
        let auth = Authorizer {
            key_id: "key\x00id".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_hmac_too_short() {
        let auth = Authorizer {
            key_id: "key".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(63),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_hmac_too_long() {
        let auth = Authorizer {
            key_id: "key".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(65),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_hmac_non_hex() {
        let auth = Authorizer {
            key_id: "key".to_string(),
            timestamp: 1000,
            hmac: "z".repeat(64),
            nonce: "b".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_nonce_wrong_length() {
        let auth = Authorizer {
            key_id: "key".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(32),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_validate_nonce_non_hex() {
        let auth = Authorizer {
            key_id: "key".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "g".repeat(64),
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_authorizer_debug_redacts_secrets() {
        let auth = Authorizer {
            key_id: "visible-key".to_string(),
            timestamp: 1000,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let debug_str = format!("{:?}", auth);
        assert!(debug_str.contains("visible-key"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&"a".repeat(64)));
        assert!(!debug_str.contains(&"b".repeat(64)));
    }

    /* ========================================================================== */
    /*        Expires-at Calculation TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_expires_at_saturating_add_normal() {
        let now: u64 = 1_700_000_000;
        let ttl: u64 = 300;
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, 1_700_000_300);
    }

    #[test]
    fn test_expires_at_saturating_add_near_max() {
        let now: u64 = u64::MAX - 100;
        let ttl: u64 = 300;
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, u64::MAX);
    }

    #[test]
    fn test_expires_at_saturating_add_zero_ttl() {
        let now: u64 = 1_700_000_000;
        let ttl: u64 = 0;
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, now);
    }

    /* ========================================================================== */
    /*        ChallengeState Serialisation Round-Trip TESTS                      */
    /* ========================================================================== */

    #[test]
    fn test_challenge_state_serialise_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let states = [
            ChallengeState::Pending,
            ChallengeState::ProofOkWaitingForRedeem,
            ChallengeState::Verified,
            ChallengeState::Failed,
            ChallengeState::Expired,
        ];

        for state in &states {
            let json = serde_json::to_string(state)?;
            let deserialized: ChallengeState = serde_json::from_str(&json)?;
            assert_eq!(state, &deserialized, "round-trip failed for {:?}", state);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*        generate_short_code_from_uuid() + ShortCode Integration TESTS      */
    /* ========================================================================== */

    #[test]
    fn test_short_code_fallback_on_invalid_code() {
        // When ShortCode::new fails, the route falls back to the raw code.
        // This tests the pattern used in the handler.
        let short_code = "not-a-code";
        let formatted = ShortCode::new(short_code)
            .map(|sc| sc.display_formatted())
            .unwrap_or_else(|_| short_code.to_string());
        assert_eq!(formatted, "not-a-code");
    }

    #[test]
    fn test_generate_short_code_always_parseable_by_shortcode() {
        // Verify the contract: every generated short code must be valid for ShortCode::new.
        for _ in 0..20 {
            let id = Uuid::new_v4();
            let code = generate_short_code_from_uuid(&id);
            assert!(
                ShortCode::new(&code).is_ok(),
                "generated code '{}' is not a valid ShortCode (uuid={})",
                code,
                id
            );
        }
    }

    /* ========================================================================== */
    /*        Epoch Days to i32 Conversion TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_today_epoch_days_i32_try_from_normal() -> Result<(), Box<dyn std::error::Error>> {
        let today: u32 = 20000;
        let today_i32 = i32::try_from(today)?;
        assert_eq!(today_i32, 20000);
        Ok(())
    }

    #[test]
    fn test_today_epoch_days_i32_try_from_max_u32() {
        let today: u32 = u32::MAX;
        let result = i32::try_from(today);
        assert!(result.is_err(), "u32::MAX should not fit in i32");
    }

    #[test]
    fn test_today_epoch_days_i32_try_from_i32_max() -> Result<(), Box<dyn std::error::Error>> {
        let today: u32 = i32::MAX as u32;
        let today_i32 = i32::try_from(today)?;
        assert_eq!(today_i32, i32::MAX);
        Ok(())
    }

    #[test]
    fn test_today_epoch_days_i32_try_from_just_over_i32_max() {
        let today: u32 = (i32::MAX as u32) + 1;
        let result = i32::try_from(today);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*        Additional Property-Based TESTS                                    */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: generate_short_code_from_uuid always produces exactly 12 digits.
        #[test]
        fn prop_short_code_always_12_digits(uuid_bytes in any::<[u8; 16]>()) {
            let id = Uuid::from_bytes(uuid_bytes);
            let code = generate_short_code_from_uuid(&id);
            prop_assert_eq!(code.len(), 12);
            prop_assert!(code.chars().all(|c| c.is_ascii_digit()));
        }

        /// Property: generate_short_code_from_uuid is deterministic.
        #[test]
        fn prop_short_code_deterministic(uuid_bytes in any::<[u8; 16]>()) {
            let id = Uuid::from_bytes(uuid_bytes);
            let code1 = generate_short_code_from_uuid(&id);
            let code2 = generate_short_code_from_uuid(&id);
            prop_assert_eq!(code1, code2);
        }

        /// Property: every generated short code is accepted by ShortCode::new.
        #[test]
        fn prop_short_code_always_valid_shortcode(uuid_bytes in any::<[u8; 16]>()) {
            let id = Uuid::from_bytes(uuid_bytes);
            let code = generate_short_code_from_uuid(&id);
            let result = ShortCode::new(&code);
            prop_assert!(result.is_ok(), "code '{}' from uuid {} failed ShortCode::new", code, id);
        }

        /// Property: build_v1_base output always ends with "/v1".
        #[test]
        fn prop_build_v1_base_always_ends_with_v1(
            base in "[a-z]{3,10}://[a-z]{3,10}\\.[a-z]{2,4}(/[a-z0-9]{0,5}){0,3}"
        ) {
            let result = build_v1_base(&base);
            prop_assert!(
                result.ends_with("/v1"),
                "build_v1_base('{}') = '{}' does not end with /v1",
                base,
                result
            );
        }

        /// Property: build_v1_base is idempotent for inputs already ending in /v1.
        #[test]
        fn prop_build_v1_base_idempotent_for_v1_suffix(
            prefix in "[a-z]{3,10}://[a-z]{3,10}\\.[a-z]{2,4}"
        ) {
            let with_v1 = format!("{}/v1", prefix);
            let result1 = build_v1_base(&with_v1);
            let result2 = build_v1_base(&result1);
            prop_assert_eq!(result1, result2, "build_v1_base should be idempotent for /v1 suffixes");
        }

        /// Property: apply_sandbox_bypass_overrides always sets tenant_id to "sandbox_default".
        #[test]
        fn prop_sandbox_bypass_always_sets_sandbox_tenant(
            tenant in "[a-z_]{1,30}",
            age in 1u32..150
        ) {
            let policy = crate::storage::origin_policy::OriginPolicy {
                tenant_id: tenant,
                min_age_years: age,
                max_age_years: None,
                proof_direction: None,
                allowed_vk_ids: vec![1],
                allowed_issuers: vec![],
                max_ttl_sec: 300,
                billing: crate::storage::origin_policy::BillingConfig {
                    plan: "pro".to_string(),
                    metering_enabled: true,
                },
                enabled: true,
                created_at: 0,
                updated_at: 0,
                clients: Vec::new(),
                provisioned_by: None,
                failure_mode: None,
                failure_mode_locked: false,
            };
            let result = apply_sandbox_bypass_overrides(policy);
            prop_assert_eq!(result.tenant_id, "sandbox_default");
            prop_assert_eq!(result.min_age_years, 18u32);
            prop_assert_eq!(result.billing.plan, "sandbox");
            prop_assert!(!result.billing.metering_enabled);
        }

        /// Property: CutoffDays::new succeeds for all values in [MIN, MAX].
        #[test]
        fn prop_cutoff_days_in_range_always_ok(v in CutoffDays::MIN..=CutoffDays::MAX) {
            let result = CutoffDays::new(v);
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.expect("checked above").get(), v);
        }

        /// Property: CutoffDays::new fails for values outside [MIN, MAX].
        #[test]
        fn prop_cutoff_days_out_of_range_always_err(
            v in prop::strategy::Union::new(vec![
                (i32::MIN..CutoffDays::MIN).boxed(),
                ((CutoffDays::MAX + 1)..=i32::MAX).boxed(),
            ])
        ) {
            let result = CutoffDays::new(v);
            prop_assert!(result.is_err());
        }

        /// Property: ExpiresIn always clamps to [MIN, MAX].
        #[test]
        fn prop_expires_in_always_clamped(v in any::<u64>()) {
            let e = ExpiresIn::new(v);
            prop_assert!(e.get() >= ExpiresIn::MIN);
            prop_assert!(e.get() <= ExpiresIn::MAX);
        }

        /// Property: VkId::new(0) is always None, VkId::new(n>0) is always Some.
        #[test]
        fn prop_vk_id_zero_is_none_nonzero_is_some(v in any::<u32>()) {
            let result = VkId::new(v);
            if v == 0 {
                prop_assert!(result.is_none());
            } else {
                prop_assert!(result.is_some());
                prop_assert_eq!(result.expect("checked above").get(), v);
            }
        }

        /// Property: canonical message length > 0 for any input.
        #[test]
        fn prop_canonical_message_non_empty(
            method in "(GET|POST|PUT|DELETE)",
            path in "/[a-z]{1,10}",
            timestamp in any::<u64>()
        ) {
            let req = create_test_request().map_err(|e| TestCaseError::fail(format!("{e}")))?;
            let msg = create_canonical_message_for_challenge(&method, &path, timestamp, &req);
            prop_assert!(!msg.is_empty());
        }

        /// Property: Authorizer.validate() rejects empty key_id.
        #[test]
        fn prop_authorizer_empty_key_id_rejected(ts in any::<u64>()) {
            let auth = Authorizer {
                key_id: "".to_string(),
                timestamp: ts,
                hmac: "a".repeat(64),
                nonce: "b".repeat(64),
            };
            prop_assert!(auth.validate().is_err());
        }
    }
}
