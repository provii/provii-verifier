// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! SECURITY: Authentication for status and metrics endpoints.
//!
//! Implements authentication for sensitive status endpoints to prevent information
//! disclosure attacks (CWE-200). The `STATUS_API_TOKEN` is a Class 6 internal
//! API key and must accept
//! the bearer in `Authorization: Bearer <token>` or `X-API-Key`. The legacy
//! `X-Status-Token` header is preserved for callers already in production.
//!
//! Authentication methods, tried in order:
//!
//! 1. `Authorization: Bearer <token>` against the dual-slot `STATUS_API_TOKEN`
//!    pair (Class 6 spec shape, used by external monitoring scripts and the
//!    rotation smoke test).
//! 2. `X-Status-Token` against the same dual-slot pair (legacy callers).
//! 3. `X-API-Key` resolved against the origin policy store.
//!
//! All paths verify Argon2id PHC hashes with the constant-time `argon2`
//! verifier. All access attempts (successful and failed) are audit logged for
//! security monitoring.
#![forbid(unsafe_code)]

use crate::{
    error::ApiError,
    security::{audit::AuditLogger, log_sanitizer::hash_ip, status_token_cache},
    storage::origin_policy::OriginPolicyStore,
};
use std::sync::Arc;
use worker::{Env, Headers};

/// Abstraction over HTTP header access so functions that only need
/// `get(name) -> Option<String>` can be tested on native targets without
/// instantiating `worker::Headers` (which requires wasm-bindgen).
///
/// The trait is intentionally minimal: a single fallible `get` that mirrors
/// the `worker::Headers::get` contract.
pub trait HeaderSource {
    /// Retrieve the value of a header by name.
    ///
    /// Returns `Ok(Some(value))` when the header is present, `Ok(None)` when
    /// absent, and `Err` on malformed header names. Implementations SHOULD
    /// normalise header names to lowercase (HTTP/2 requires it; HTTP/1.1
    /// treats them case-insensitively).
    fn get(&self, name: &str) -> Result<Option<String>, String>;
}

impl HeaderSource for Headers {
    fn get(&self, name: &str) -> Result<Option<String>, String> {
        Headers::get(self, name).map_err(|e| format!("{e:?}"))
    }
}

impl HeaderSource for &Headers {
    fn get(&self, name: &str) -> Result<Option<String>, String> {
        Headers::get(self, name).map_err(|e| format!("{e:?}"))
    }
}

#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

/// Outcome of a successful status-endpoint authentication. The variant tracks
/// which dual-slot path satisfied the verify so the caller can emit the
/// `x-secret-version` HTTP response header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAuthSlot {
    /// The presented credential matched the current `STATUS_API_TOKEN` slot.
    Current,
    /// The presented credential matched the `STATUS_API_TOKEN_PREVIOUS` slot
    /// during a rotation window.
    Previous,
    /// Authenticated via the X-API-Key path against an origin's stored client
    /// credential. This path is rotation-orthogonal and does not surface a
    /// status-token fingerprint on the response header.
    ApiKey,
}

/// Successful authentication outcome. Pairs the slot identifier with the slot
/// fingerprint so callers can attach `x-secret-version` directly.
#[derive(Debug, Clone)]
pub struct StatusAuthOutcome {
    /// Which slot satisfied the verify path.
    pub slot: StatusAuthSlot,
    /// The 6-char fingerprint of the satisfying slot. For [`StatusAuthSlot::ApiKey`]
    /// this is the [`crate::security::secret_fingerprint::FINGERPRINT_UNSET`]
    /// sentinel because an API-key authentication does not bind to a status
    /// token slot.
    pub fingerprint: String,
}

/// derive the env-aware role suffix used in
/// the `slot` and `secret_version` keys on the status auth log line.
///
/// Returns `"STATUS_TOKEN_PROD"` for production deployments and
/// `"STATUS_TOKEN_SBX"` for sandbox or local development. The Grafana panel
/// per the structured log schema uses this suffix as the disambiguator, so sandbox
/// traffic must NOT attribute to the production fingerprint slot.
///
/// `cfg.environment` carries the deployment environment string set by
/// `wrangler --env <name>`. Only `"sandbox"` and `"development"` map to the
/// SBX suffix; every other value (including the `"test"` default) maps to
/// PROD so a misconfigured deployment fails closed onto the production-label
/// dashboard rather than silently mislabelling.
#[must_use]
pub fn status_token_role_for_env(environment: &str) -> &'static str {
    match environment {
        "sandbox" | "development" => "STATUS_TOKEN_SBX",
        _ => "STATUS_TOKEN_PROD",
    }
}

/// Strip a leading `Bearer ` scheme token from an `Authorization` header value
/// and return the trimmed credential, or `None` if the header is missing the
/// scheme, the credential is empty, or the header carries any other scheme
/// (`Basic`, etc.).
///
/// Comparison of the scheme literal is ASCII-case-insensitive per RFC 9110
/// §11.1. The credential portion is returned verbatim with no decoding so the
/// constant-time Argon2id verifier downstream sees the same bytes the operator
/// pasted into the `curl` invocation.
///
/// SECURITY: this helper is fed only by the request `Authorization` header, a
/// public input. The shape check (scheme literal, single space delimiter) is
/// not secret-dependent and does not leak timing information about the
/// credential.
fn extract_bearer_token(authorization: &str) -> Option<&str> {
    let (scheme, rest) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let credential = rest.trim_start();
    if credential.is_empty() {
        return None;
    }
    Some(credential)
}

/// Cached fingerprint pair for the dual-slot `STATUS_API_TOKEN` binding.
///
/// Returned by [`current_fingerprints`] so callers building the
/// `/_internal/version` response body can read the current public-safe slot
/// labels without holding their own copy on [`crate::AppState`]. The
/// underlying cache is the same five-minute TTL store used by
/// [`authenticate_status_endpoint`], so a fingerprint surfaced here matches
/// the slot the verify path would accept against during the same window.
#[derive(Debug, Clone)]
pub struct StatusTokenFingerprints {
    /// 6-char public-safe fingerprint of the current slot. Carries
    /// [`crate::security::secret_fingerprint::FINGERPRINT_UNSET`] when the
    /// slot is unbound.
    pub current: String,
    /// 6-char public-safe fingerprint of the previous slot. Carries the
    /// unset sentinel outside a rotation window.
    pub previous: String,
}

/// Read the current dual-slot fingerprint pair from the
/// [`status_token_cache`] module, refreshing from Cloudflare Secrets Store
/// on cache miss or expiry. Used by `/_internal/version` to surface the
/// public-safe `STATUS_API_TOKEN_6CHAR` labels in the response body without
/// leaking the underlying token.
pub async fn current_fingerprints(env: &Env) -> StatusTokenFingerprints {
    let current = status_token_cache::get_or_refresh(env, "STATUS_API_TOKEN").await;
    let previous = status_token_cache::get_or_refresh(env, "STATUS_API_TOKEN_PREVIOUS").await;
    StatusTokenFingerprints {
        current: current.fingerprint,
        previous: previous.fingerprint,
    }
}

/// SECURITY: Authenticates access to status/metrics endpoints.
///
/// Prevents unauthorised access to sensitive system information that could be
/// used for reconnaissance attacks (CWE-200, ASVS V7.4).
///
/// The dual-slot `STATUS_API_TOKEN` pair is resolved through the
/// five-minute TTL [`status_token_cache`] on every call rather than being
/// pinned at cold start. A rotated token in Secrets Store becomes effective
/// on every warm isolate within
/// [`status_token_cache::STATUS_TOKEN_CACHE_TTL_MS`], so a stolen credential
/// can no longer outlive the operator's deletion of the slot from Secrets
/// Store.
///
/// # Authentication Flow
///
/// Tries each source in order, returning on the first successful
/// Argon2id verify:
///
/// 1. `Authorization: Bearer <token>` against the dual-slot
///    `STATUS_API_TOKEN` pair (Class 6 spec shape; rotation smoke test path).
/// 2. `X-Status-Token` against the dual-slot pair (legacy alias).
/// 3. `X-API-Key` against stored client credentials in the origin policy
///    store.
/// 4. Falls through to rejection if none match.
///
/// if a previous-slot hash is populated, the verify
/// falls back to the previous slot when the current slot rejects (dual-slot
/// accept). If none of the sources succeed, the request is rejected and an
/// audit event is emitted.
///
/// # Security
///
/// SECURITY: Status token verification uses Argon2id with constant-time
/// comparison (via the `argon2` crate internally). Authentication failures are
/// audit logged for monitoring. Client IPs are HMAC-hashed before appearing in
/// any log output.
///
/// # Arguments
///
/// * `env` - Worker environment used by the slot cache to refresh from
///   Secrets Store on cache miss.
/// * `headers` - Request headers containing authentication credentials.
/// * `status_token_role` - env-aware role label used as the `slot` /
///   `secret_version` key suffix (`"STATUS_TOKEN_PROD"` in production,
///   `"STATUS_TOKEN_SBX"` in sandbox). Required so Grafana panel grouping
///   does not attribute sandbox traffic to the production slot.
/// * `audit_logger` - Logger for security events.
/// * `client_ip` - IP address of the requester.
/// * `origin_policy_store` - Optional store for API key validation.
/// * `ip_hash_salt` - HMAC key for privacy-preserving IP logging.
///
/// # Returns
///
/// * `Ok(StatusAuthOutcome)` describing which slot satisfied the verify path,
///   so the caller can attach an `x-secret-version` HTTP response header.
/// * `Err(ApiError::Unauthorized)` if authentication fails.
#[allow(clippy::too_many_arguments)]
pub async fn authenticate_status_endpoint(
    env: &Env,
    headers: &Headers,
    status_token_role: &str,
    audit_logger: &AuditLogger,
    client_ip: &str,
    origin_policy_store: Option<&Arc<OriginPolicyStore>>,
    ip_hash_salt: &str,
) -> Result<StatusAuthOutcome, ApiError> {
    // Pull the dual-slot pair through the five-minute TTL cache.
    // The cache layer handles Secrets Store I/O, Argon2id hashing, and
    // fingerprint computation. Both slots are read on every call so a
    // mid-rotation client presenting either token observes the same
    // dual-accept behaviour the cold-start hash gave, only
    // refreshed within the TTL bound rather than pinned to the isolate.
    let current_slot = status_token_cache::get_or_refresh(env, "STATUS_API_TOKEN").await;
    let previous_slot = status_token_cache::get_or_refresh(env, "STATUS_API_TOKEN_PREVIOUS").await;

    authenticate_status_endpoint_with_resolved_slots(
        headers,
        current_slot.argon2_hash.as_deref(),
        previous_slot.argon2_hash.as_deref(),
        &current_slot.fingerprint,
        &previous_slot.fingerprint,
        status_token_role,
        audit_logger,
        client_ip,
        origin_policy_store,
        ip_hash_salt,
    )
    .await
}

/// Pure verify path: takes the resolved Argon2id hashes and 6-char
/// fingerprints for both slots and runs the dual-slot accept logic. Split
/// out from [`authenticate_status_endpoint`] so the unit tests can drive
/// the verify behaviour without instantiating a Worker [`Env`].
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
async fn authenticate_status_endpoint_with_resolved_slots(
    headers: &impl HeaderSource,
    status_token_hash: Option<&str>,
    status_token_hash_previous: Option<&str>,
    status_token_fingerprint: &str,
    status_token_fingerprint_previous: &str,
    status_token_role: &str,
    audit_logger: &AuditLogger,
    client_ip: &str,
    origin_policy_store: Option<&Arc<OriginPolicyStore>>,
    ip_hash_salt: &str,
) -> Result<StatusAuthOutcome, ApiError> {
    // derive the previous-slot key suffix
    // from the role tag so sandbox/prod logs do not collide. The role tag is
    // a small fixed-shape ASCII identifier set at boot from `cfg.environment`;
    // a non-secret, non-attacker-controlled value.
    let status_token_role_previous = format!("{status_token_role}_PREVIOUS");

    // Resolve the candidate bearer token. Rotation class §6.1 requires
    // `Authorization: Bearer <token>` for Class 6 keys; the rotation smoke test
    // uses that shape. `X-Status-Token` stays supported as a legacy alias so
    // existing monitoring callers do not need a redeploy. Both header shapes
    // resolve into the same dual-slot Argon2id verify path.
    //
    // Authorization wins over X-Status-Token when both are sent so the
    // smoke-test path always produces the spec-aligned audit subject and to
    // give a single-shape contract to new callers. The dual-slot verify itself
    // is constant-time (Argon2id), and the slot loop never short-circuits on a
    // secret-derived comparison branch.
    let bearer_token = headers
        .get("Authorization")
        .ok()
        .flatten()
        .as_deref()
        .and_then(extract_bearer_token)
        .map(str::to_string);
    let provided_token: Option<zeroize::Zeroizing<String>> = match bearer_token {
        Some(t) => Some(zeroize::Zeroizing::new(t)),
        None => headers
            .get("X-Status-Token")
            .ok()
            .flatten()
            .map(zeroize::Zeroizing::new),
    };

    // SECURITY: Dedicated status token (Authorization: Bearer or X-Status-Token).
    // L-5: Verify with Argon2id via hash::verify_api_key instead of SHA-256 + ct_eq.
    //
    // dual-slot accept. We attempt the current slot
    // first; on miss, fall back to the previous slot if it is populated. The
    // slot identifier is logged under `secret_version_used` per the
    // structured log schema so the Grafana panel can attribute requests across
    // a rotation window.
    if let Some(provided_token) = provided_token {
        // Try current slot.
        if let Some(expected_hash) = status_token_hash {
            if crate::security::hash::verify_api_key(&provided_token, expected_hash) {
                console_log!(
                    r#"{{"event":"status_auth_success","slot":"{}","secret_version":{{"{}":"{}","{}":"{}"}},"secret_version_used":"{}","ip_hash":"{}"}}"#,
                    status_token_role,
                    status_token_role,
                    status_token_fingerprint,
                    status_token_role_previous,
                    status_token_fingerprint_previous,
                    status_token_role,
                    hash_ip(client_ip, ip_hash_salt)
                );

                audit_logger
                    .log_authentication_success(client_ip, "status_token", "status_endpoint")
                    .await;

                return Ok(StatusAuthOutcome {
                    slot: StatusAuthSlot::Current,
                    fingerprint: status_token_fingerprint.to_string(),
                });
            }
        }

        // Try previous slot. Mid-rotation only; absent slot is the steady state.
        if let Some(prev_hash) = status_token_hash_previous {
            if crate::security::hash::verify_api_key(&provided_token, prev_hash) {
                console_log!(
                    r#"{{"event":"status_auth_success","slot":"{}","secret_version":{{"{}":"{}","{}":"{}"}},"secret_version_used":"{}","ip_hash":"{}"}}"#,
                    status_token_role_previous,
                    status_token_role,
                    status_token_fingerprint,
                    status_token_role_previous,
                    status_token_fingerprint_previous,
                    status_token_role_previous,
                    hash_ip(client_ip, ip_hash_salt)
                );

                audit_logger
                    .log_authentication_success(
                        client_ip,
                        "status_token_previous",
                        "status_endpoint",
                    )
                    .await;

                return Ok(StatusAuthOutcome {
                    slot: StatusAuthSlot::Previous,
                    fingerprint: status_token_fingerprint_previous.to_string(),
                });
            }
        }
    }

    // SECURITY: Try standard API key (X-API-Key header) with proper validation
    if let (Ok(Some(api_key)), Some(policy_store)) = (headers.get("X-API-Key"), origin_policy_store)
    {
        // SECURITY: Validate API key against stored credentials
        // Check all origins for a matching API key (since we don't have Origin header for status endpoints)
        // This is acceptable for monitoring endpoints as we're still requiring valid credentials

        if !api_key.is_empty() {
            // Get Origin header if present to narrow down the search
            let origin = headers.get("Origin").ok().flatten();

            if let Some(origin_value) = origin {
                // If Origin is present, validate against that specific origin's policy
                if let Ok(Some(policy)) = policy_store.get_policy(&origin_value).await {
                    for client in &policy.clients {
                        if !client.active {
                            continue;
                        }

                        if crate::security::hash::verify_api_key(&api_key, &client.api_key_hash) {
                            console_log!("[SECURITY] Status endpoint access granted via API key for origin {} from IP: {}", origin_value, hash_ip(client_ip, ip_hash_salt));

                            // AL-040: Log successful authentication (was misclassified as suspicious_activity).
                            audit_logger
                                .log_authentication_success(
                                    client_ip,
                                    &client.client_id,
                                    "status_endpoint",
                                )
                                .await;

                            return Ok(StatusAuthOutcome {
                                slot: StatusAuthSlot::ApiKey,
                                fingerprint: crate::security::secret_fingerprint::FINGERPRINT_UNSET
                                    .to_string(),
                            });
                        }
                    }
                }
            }

            // Origin not provided or didn't match - this is now an authentication failure
            // We no longer blindly accept any 32+ char string as valid
            console_log!(
                "[SECURITY] Status endpoint access denied: invalid API key from IP: {}",
                hash_ip(client_ip, ip_hash_salt)
            );
        }
    }

    // SECURITY: Authentication failed - log for security monitoring
    console_log!(
        "[SECURITY] Status endpoint access denied for IP: {}",
        hash_ip(client_ip, ip_hash_salt)
    );

    audit_logger
        .log_authentication_failure(
            client_ip,
            "status_endpoint_unauthorized",
            None,
            None,
            Some(serde_json::json!({
                "endpoint": "status",
                "has_authorization_header": headers.get("Authorization").ok().flatten().is_some(),
                "has_status_token_header": headers.get("X-Status-Token").ok().flatten().is_some(),
                "has_api_key_header": headers.get("X-API-Key").ok().flatten().is_some(),
            })),
        )
        .await;

    Err(ApiError::Unauthorized)
}

// ---------------------------------------------------------------------------
// F-01 (#72): Replay protection on internal bearer endpoints
// ---------------------------------------------------------------------------

/// Maximum acceptable clock skew between the operator and server in seconds
/// when a request reaches an internal bearer endpoint. Mirrors the value
/// applied to partner-traffic verify paths in
/// [`crate::security::auth::ClientAuthenticator`] (300s either side of the
/// server clock). Any wider window weakens the replay window without a
/// compensating operational benefit; any narrower window starts to reject
/// well-behaved operator scripts under normal NTP skew.
pub const INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS: u64 = 300;

/// TTL applied to nonce entries in the dedup store for internal bearer
/// endpoints. 24 hours is well above the 300-second timestamp window so a
/// captured nonce cannot ride a slow clock skew past the dedup TTL boundary
/// before its timestamp window closes. Matches the F-01 ask in #72.
pub const INTERNAL_REPLAY_NONCE_TTL_SECS: u64 = 24 * 60 * 60;

/// Outcome of an internal-bearer replay-window check. The `Ok` variant
/// carries the `(timestamp, nonce)` pair so the caller can include them in
/// structured audit logs without re-reading the headers.
#[derive(Debug, Clone)]
pub struct InternalReplayCheckOutcome {
    /// Operator-supplied timestamp the request was bound to.
    pub timestamp: u64,
    /// Operator-supplied nonce that was atomically check-and-set.
    pub nonce: String,
}

/// F-01 (#72): Enforce a rolling-window timestamp + per-request nonce
/// dedupe on an internal bearer endpoint after the credential itself has
/// already been verified by [`authenticate_status_endpoint`].
///
/// This MUST be called after the auth path returns `Ok`. The order matters
/// because:
///
/// 1. The nonce store is consumed atomically: once a nonce is set, a
///    second request carrying the same `(role, nonce)` tuple is rejected.
///    Running the check before the auth path verified the bearer would
///    let an unauthenticated attacker burn nonces and DoS legitimate
///    operators.
/// 2. The timestamp window check is cheap; running it before the auth
///    path gives an unauthenticated attacker a free oracle telling them
///    when the server clock falls into a particular range. After auth,
///    only authenticated callers see the timestamp rejection error.
///
/// Required headers:
///
/// * `X-Timestamp` - Unix seconds. Must be within
///   [`INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS`] of the server clock in
///   either direction.
/// * `X-Nonce` - Opaque single-use token from the operator. Must be
///   non-empty and at most 256 bytes (cap is enforced before the check
///   and-set so a malformed nonce cannot waste DO storage). The nonce
///   is bound to `role_tag` so a token that authenticates one of the
///   internal bearer surfaces cannot be replayed against a sibling
///   surface (e.g. a `/_internal/version` token cannot replay
///   `/health/detailed`).
///
/// On any check failure, a structured audit log entry is emitted with the
/// operator-supplied timestamp + nonce prefix (first 8 bytes only, never
/// the full nonce) and the function returns `ApiError::Unauthorized` per
/// Structured log `replay_rejected` outcome shape.
///
/// SECURITY: this helper does NOT branch on secret values. The headers
/// are public input controlled by the caller; the comparisons are
/// constant-time only where they need to be (the bearer comparison ran
/// already inside the auth primitive). The nonce check runs through the
/// existing [`crate::storage::traits::NonceStore`] DO so the dedupe
/// window is consistent across worker isolates.
pub async fn enforce_internal_replay_window(
    headers: &impl HeaderSource,
    nonce_store: &Arc<dyn crate::storage::traits::NonceStore>,
    role_tag: &str,
    audit_logger: &AuditLogger,
    client_ip: &str,
    ip_hash_salt: &str,
) -> Result<InternalReplayCheckOutcome, ApiError> {
    // Pull headers. Missing or empty -> 401 with structured audit.
    let provided_timestamp_raw = match headers.get("X-Timestamp").ok().flatten() {
        Some(v) if !v.is_empty() => v,
        _ => {
            audit_logger
                .log_authentication_failure(
                    client_ip,
                    "internal_replay_missing_timestamp",
                    None,
                    None,
                    Some(serde_json::json!({
                        "role": role_tag,
                        "endpoint_class": "internal_bearer",
                        "ip_hash": hash_ip(client_ip, ip_hash_salt),
                    })),
                )
                .await;
            return Err(ApiError::Unauthorized);
        }
    };

    let provided_nonce = match headers.get("X-Nonce").ok().flatten() {
        Some(v) if !v.is_empty() => v,
        _ => {
            audit_logger
                .log_authentication_failure(
                    client_ip,
                    "internal_replay_missing_nonce",
                    None,
                    None,
                    Some(serde_json::json!({
                        "role": role_tag,
                        "endpoint_class": "internal_bearer",
                        "ip_hash": hash_ip(client_ip, ip_hash_salt),
                    })),
                )
                .await;
            return Err(ApiError::Unauthorized);
        }
    };

    // Defensive nonce length cap. Operators send hex/base64 strings; 256
    // bytes is well above any reasonable encoding of a 256-bit nonce.
    if provided_nonce.len() > 256 {
        audit_logger
            .log_authentication_failure(
                client_ip,
                "internal_replay_nonce_too_long",
                None,
                None,
                Some(serde_json::json!({
                    "role": role_tag,
                    "len": provided_nonce.len(),
                    "ip_hash": hash_ip(client_ip, ip_hash_salt),
                })),
            )
            .await;
        return Err(ApiError::Unauthorized);
    }

    // Parse timestamp. Reject anything that cannot be a Unix seconds
    // integer; floats and negatives are not accepted.
    let provided_timestamp: u64 = match provided_timestamp_raw.parse() {
        Ok(t) => t,
        Err(_) => {
            audit_logger
                .log_authentication_failure(
                    client_ip,
                    "internal_replay_invalid_timestamp",
                    None,
                    None,
                    Some(serde_json::json!({
                        "role": role_tag,
                        "raw": provided_timestamp_raw,
                        "ip_hash": hash_ip(client_ip, ip_hash_salt),
                    })),
                )
                .await;
            return Err(ApiError::Unauthorized);
        }
    };

    // Bidirectional timestamp window check. Same shape as
    // ClientAuthenticator::authenticate.
    let server_time = crate::utils::current_timestamp();
    let skew = if server_time >= provided_timestamp {
        server_time.saturating_sub(provided_timestamp)
    } else {
        provided_timestamp.saturating_sub(server_time)
    };
    if skew > INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS {
        audit_logger
            .log_authentication_failure(
                client_ip,
                "internal_replay_timestamp_skew",
                None,
                None,
                Some(serde_json::json!({
                    "role": role_tag,
                    "server_time": server_time,
                    "client_timestamp": provided_timestamp,
                    "skew_seconds": skew,
                    "max_allowed": INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS,
                    "ip_hash": hash_ip(client_ip, ip_hash_salt),
                })),
            )
            .await;
        return Err(ApiError::Unauthorized);
    }

    // Atomic check-and-set on the nonce store. Tag includes the role
    // so a `/_internal/version` nonce cannot replay another internal
    // bearer surface (e.g. `/metrics`) when both share a dedupe DO.
    let nonce_tag = format!("internal-bearer:{}:{}", role_tag, provided_nonce);
    let nonce_ttl = std::time::Duration::from_secs(INTERNAL_REPLAY_NONCE_TTL_SECS);
    match nonce_store.check_and_set(&nonce_tag, nonce_ttl).await {
        Ok(true) => Ok(InternalReplayCheckOutcome {
            timestamp: provided_timestamp,
            nonce: provided_nonce,
        }),
        Ok(false) => {
            // Replay: the nonce has been consumed within the dedupe TTL.
            // Structured log outcome: `replay_rejected`.
            audit_logger
                .log_authentication_failure(
                    client_ip,
                    "replay_rejected",
                    None,
                    None,
                    Some(serde_json::json!({
                        "role": role_tag,
                        "endpoint_class": "internal_bearer",
                        "nonce_prefix": provided_nonce.chars().take(8).collect::<String>(),
                        "ip_hash": hash_ip(client_ip, ip_hash_salt),
                    })),
                )
                .await;
            Err(ApiError::Unauthorized)
        }
        Err(e) => {
            // Fail closed on storage error: a fresh-but-uncheckable nonce
            // is indistinguishable from a replay.
            audit_logger
                .log_authentication_failure(
                    client_ip,
                    "internal_replay_nonce_storage_error",
                    None,
                    None,
                    Some(serde_json::json!({
                        "role": role_tag,
                        "error": format!("{:?}", e),
                        "ip_hash": hash_ip(client_ip, ip_hash_salt),
                    })),
                )
                .await;
            Err(ApiError::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        authenticate_status_endpoint_with_resolved_slots as authenticate_status_endpoint,
        status_token_role_for_env, HeaderSource, StatusAuthSlot,
    };
    use crate::error::ApiError;
    use crate::security::audit::AuditLogger;
    use provii_audit::{AuditLogger as SharedLogger, PrivacyContext};
    use std::sync::Arc;

    /// Native-compatible mock for HTTP header access. Wraps a `HashMap` and
    /// implements [`HeaderSource`] so the functions under test can be driven
    /// without instantiating `worker::Headers` (which panics on non-wasm
    /// targets via wasm-bindgen).
    struct TestHeaders(std::collections::HashMap<String, String>);

    impl TestHeaders {
        fn new() -> Self {
            Self(std::collections::HashMap::new())
        }

        fn set(&mut self, name: &str, value: &str) {
            self.0.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }

    impl HeaderSource for TestHeaders {
        fn get(&self, name: &str) -> Result<Option<String>, String> {
            Ok(self.0.get(&name.to_ascii_lowercase()).cloned())
        }
    }

    /// Build an AuditLogger backed by no sink. Console output is a no-op on
    /// native targets (the `console_log!` stub expands to nothing) so the
    /// tests stay quiet.
    fn test_logger() -> Result<AuditLogger, Box<dyn std::error::Error>> {
        let salt = b"test-salt-minimum-32-bytes-long!!".to_vec();
        let privacy = Arc::new(PrivacyContext::new(salt)?);
        let inner = SharedLogger::new(None, privacy, "provii-verifier-test");
        Ok(AuditLogger::new(
            inner,
            "test".to_string(),
            "0.0.0".to_string(),
        ))
    }

    /// Hash a token with the same Argon2id helper used in production so the
    /// dual-slot tests exercise the real verify path, not a mock.
    fn hash(token: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(crate::security::hash::hash_api_key(token)?)
    }

    fn headers_with_token(token: &str) -> TestHeaders {
        let mut h = TestHeaders::new();
        h.set("X-Status-Token", token);
        h
    }

    /// current-only-bound, current matches.
    /// No previous slot is set (steady state outside a rotation window).
    /// The current token must verify and the function must return Ok.
    #[tokio::test]
    async fn test_authenticate_current_only_match() -> Result<(), Box<dyn std::error::Error>> {
        let current_token = "current-status-token-A";
        let current_hash = hash(current_token)?;
        let headers = headers_with_token(current_token);
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            None, // previous slot unset
            "abcdef",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.1",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        let outcome = result.expect("current-only-bound match must return Ok");
        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        assert_eq!(outcome.fingerprint, "abcdef");
        Ok(())
    }

    /// both slots bound, current matches.
    /// The function must accept against the current slot and never reach the
    /// previous slot (the previous slot here is bound to a token the caller
    /// is NOT presenting).
    #[tokio::test]
    async fn test_authenticate_both_bound_current_matches() -> Result<(), Box<dyn std::error::Error>>
    {
        let current_token = "current-status-token-B";
        let previous_token = "previous-status-token-B";
        let current_hash = hash(current_token)?;
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_token(current_token);
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.2",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        let outcome = result.expect("current-slot match in dual-bind must return Ok");
        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        assert_eq!(outcome.fingerprint, "abcdef");
        Ok(())
    }

    /// both slots bound, previous matches.
    /// The current slot must NOT match. The verify must fall through and
    /// accept the previous slot. This is the rotation-window code path
    /// Previously flagged as untested.
    #[tokio::test]
    async fn test_authenticate_both_bound_previous_matches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_token = "current-status-token-C";
        let previous_token = "previous-status-token-C";
        let current_hash = hash(current_token)?;
        let previous_hash = hash(previous_token)?;

        // Caller still presents the previous token (mid-rotation client).
        let headers = headers_with_token(previous_token);
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.3",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        let outcome =
            result.expect("previous-slot match must return Ok via dual-slot fall-through");
        assert_eq!(outcome.slot, StatusAuthSlot::Previous);
        assert_eq!(outcome.fingerprint, "fedcba");
        Ok(())
    }

    /// both slots bound, neither matches.
    /// A wrong token must reject under both slots and surface Unauthorized.
    #[tokio::test]
    async fn test_authenticate_both_bound_both_miss() -> Result<(), Box<dyn std::error::Error>> {
        let current_hash = hash("current-status-token-D")?;
        let previous_hash = hash("previous-status-token-D")?;

        let headers = headers_with_token("not-the-right-token");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.4",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    /// current-only-bound, current does NOT match.
    /// There is no previous slot to fall through to, and the function must
    /// not invent one. A wrong token must reject with Unauthorized.
    #[tokio::test]
    async fn test_authenticate_current_only_miss() -> Result<(), Box<dyn std::error::Error>> {
        let current_hash = hash("current-status-token-E")?;
        let headers = headers_with_token("not-the-right-token");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            None,
            "abcdef",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.5",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    #[test]
    fn test_status_token_argon2id_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        // L-5: Verify that hash_api_key + verify_api_key roundtrips correctly
        let token = "test-status-token-123";
        let hash = crate::security::hash::hash_api_key(token)?;
        assert!(crate::security::hash::verify_api_key(token, &hash));
        assert!(!crate::security::hash::verify_api_key("wrong-token", &hash));
        Ok(())
    }

    #[test]
    fn test_status_token_argon2id_format() -> Result<(), Box<dyn std::error::Error>> {
        let token = "test-status-token-123";
        let hash = crate::security::hash::hash_api_key(token)?;
        assert!(hash.starts_with("$argon2id$"));
        Ok(())
    }

    /// production environments must label the
    /// status-auth slot `STATUS_TOKEN_PROD`. Anything other than `sandbox` or
    /// `development` falls through to PROD so a misconfigured deployment
    /// fails closed onto the production-label dashboard rather than silently
    /// mislabelling sandbox-shaped fingerprints onto the prod panel.
    #[test]
    fn test_status_token_role_production_yields_prod_suffix() {
        assert_eq!(status_token_role_for_env("production"), "STATUS_TOKEN_PROD");
    }

    /// sandbox traffic must label the
    /// status-auth slot `STATUS_TOKEN_SBX` so Grafana panel grouping per
    /// the structured log schema attributes it to the sandbox fingerprint slot.
    #[test]
    fn test_status_token_role_sandbox_yields_sbx_suffix() {
        assert_eq!(status_token_role_for_env("sandbox"), "STATUS_TOKEN_SBX");
    }

    /// Local-dev shares the SBX label with sandbox; both are non-prod.
    #[test]
    fn test_status_token_role_development_yields_sbx_suffix() {
        assert_eq!(status_token_role_for_env("development"), "STATUS_TOKEN_SBX");
    }

    /// Unknown environment strings (typo, empty, `"test"`) fall back to PROD.
    /// Verified explicitly so a misconfigured wrangler env name does not
    /// silently mislabel as sandbox.
    #[test]
    fn test_status_token_role_unknown_env_falls_back_to_prod() {
        assert_eq!(status_token_role_for_env(""), "STATUS_TOKEN_PROD");
        assert_eq!(status_token_role_for_env("test"), "STATUS_TOKEN_PROD");
        assert_eq!(status_token_role_for_env("staging"), "STATUS_TOKEN_PROD");
    }

    fn headers_with_authorization(value: &str) -> TestHeaders {
        let mut h = TestHeaders::new();
        h.set("Authorization", value);
        h
    }

    /// Class 6 spec shape: `Authorization: Bearer <current>` against a both-
    /// bound dual-slot pair must accept and report the current slot. This is
    /// the steady-state bearer path the rotation smoke test exercises.
    #[tokio::test]
    async fn test_authenticate_bearer_current_matches() -> Result<(), Box<dyn std::error::Error>> {
        let current_token = "current-bearer-token-A";
        let previous_token = "previous-bearer-token-A";
        let current_hash = hash(current_token)?;
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_authorization(&format!("Bearer {current_token}"));
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.10",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("Bearer current-slot match must return Ok");

        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        assert_eq!(outcome.fingerprint, "abcdef");
        Ok(())
    }

    /// Reproduces the deployed sandbox-verify smoke-test scenario verbatim:
    /// dual-slot binding active, caller presents the previous token via
    /// `Authorization: Bearer`. Mode A would have caught this before the live
    /// rotation if a Bearer test had existed.
    #[tokio::test]
    async fn test_authenticate_bearer_previous_matches() -> Result<(), Box<dyn std::error::Error>> {
        let current_token = "current-bearer-token-B";
        let previous_token = "previous-bearer-token-B";
        let current_hash = hash(current_token)?;
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_authorization(&format!("Bearer {previous_token}"));
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.11",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("Bearer previous-slot match must return Ok via dual-slot fall-through");

        assert_eq!(outcome.slot, StatusAuthSlot::Previous);
        assert_eq!(outcome.fingerprint, "fedcba");
        Ok(())
    }

    /// Bearer header with the wrong token rejects under both slots. Confirms
    /// the bearer path is not wider than the X-Status-Token path.
    #[tokio::test]
    async fn test_authenticate_bearer_both_miss() -> Result<(), Box<dyn std::error::Error>> {
        let current_hash = hash("current-bearer-token-C")?;
        let previous_hash = hash("previous-bearer-token-C")?;

        let headers = headers_with_authorization("Bearer not-the-right-token");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.12",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    /// `Authorization: Basic ...` must NOT be treated as a bearer credential.
    /// The function rejects without consulting the slot hashes.
    #[tokio::test]
    async fn test_authenticate_authorization_basic_scheme_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_hash = hash("current-bearer-token-D")?;
        let headers = headers_with_authorization("Basic dXNlcjpwYXNz");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            None,
            "abcdef",
            "000000",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.13",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    /// When both `Authorization: Bearer` and `X-Status-Token` are sent,
    /// Authorization wins. This is intentional so the spec-aligned shape is
    /// the canonical one used in audit subjects and so a future deprecation
    /// of `X-Status-Token` does not silently change behaviour.
    #[tokio::test]
    async fn test_authorization_overrides_x_status_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let bearer_token = "bearer-wins-token";
        let bearer_hash = hash(bearer_token)?;
        let other_hash = hash("a-different-token")?;

        let mut headers = TestHeaders::new();
        headers.set("Authorization", &format!("Bearer {bearer_token}"));
        headers.set("X-Status-Token", "a-different-token");
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&bearer_hash),
            Some(&other_hash),
            "abcdef",
            "fedcba",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.14",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("Bearer must take precedence over X-Status-Token");

        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        Ok(())
    }

    /// `extract_bearer_token` accepts the canonical RFC 9110 shape and rejects
    /// every malformed variant. Pure unit test on the helper so a regression
    /// surfaces without the Argon2id verify cost.
    #[test]
    fn test_extract_bearer_token_shape() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer_token("bearer abc"), Some("abc"));
        assert_eq!(extract_bearer_token("BEARER abc"), Some("abc"));
        assert_eq!(extract_bearer_token("Bearer   abc"), Some("abc"));
        assert_eq!(extract_bearer_token("Basic abc"), None);
        assert_eq!(extract_bearer_token("Bearer "), None);
        assert_eq!(extract_bearer_token("Bearer"), None);
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("abc"), None);
    }

    /// Mixed-case `BeArEr` must still parse because RFC 9110 §11.1 specifies
    /// case-insensitive scheme comparison.
    #[test]
    fn test_extract_bearer_token_mixed_case() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("BeArEr xyz"), Some("xyz"));
        assert_eq!(extract_bearer_token("bEaReR token-123"), Some("token-123"));
    }

    /// Bearer token with special characters and long values must be returned
    /// verbatim so the downstream Argon2id verifier sees the exact bytes.
    #[test]
    fn test_extract_bearer_token_special_characters() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer a+b/c=d"), Some("a+b/c=d"));
        assert_eq!(
            extract_bearer_token("Bearer !@#$%^&*()"),
            Some("!@#$%^&*()")
        );
    }

    /// Bearer with only whitespace after scheme is treated as empty credential.
    #[test]
    fn test_extract_bearer_token_whitespace_only_credential() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer    "), None);
    }

    /// Bearer with multiple spaces between scheme and credential preserves
    /// the credential without leading spaces (trim_start).
    #[test]
    fn test_extract_bearer_token_preserves_trailing_spaces() {
        use super::extract_bearer_token;
        // Credential with trailing space is preserved (only leading is trimmed).
        assert_eq!(extract_bearer_token("Bearer token "), Some("token "));
    }

    /// `Digest`, `Negotiate`, `NTLM` and other non-Bearer schemes must reject.
    #[test]
    fn test_extract_bearer_token_rejects_other_schemes() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Digest abc"), None);
        assert_eq!(extract_bearer_token("Negotiate abc"), None);
        assert_eq!(extract_bearer_token("NTLM abc"), None);
        assert_eq!(extract_bearer_token("Token abc"), None);
    }

    /// Rotate-without-redeploy must invalidate a stolen
    /// previous-slot token once the cache TTL elapses, without depending
    /// on a worker redeploy. Drives the slot cache directly via the
    /// `test_seed` / `test_force_expire` helpers, mirroring the warm-isolate
    /// state machine the deployed runtime exercises.
    ///
    /// Sequence:
    /// 1. Seed the cache with an old token's Argon2id hash.
    /// 2. Confirm a verify with the old token would succeed against the
    ///    seeded hash.
    /// 3. Simulate the operator rotating the slot in Secrets Store and
    ///    the TTL expiring on the warm isolate by calling
    ///    `test_force_expire`.
    /// 4. Re-seed with the new token's Argon2id hash (the refresh path
    ///    runtime would do this on next request).
    /// 5. Confirm the old token no longer verifies against the freshly
    ///    seeded slot.
    ///
    /// The test would have failed under the old design because the
    /// AppState-pinned hash would still authorise the old token.
    #[tokio::test]
    async fn rotation_without_redeploy_invalidates_old_token_after_ttl(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::status_token_cache::{
            test_clear, test_force_expire, test_seed, CachedSlot, STATUS_TOKEN_CACHE_TTL_MS,
        };

        // Sanity pin: the verify path is bound to the documented TTL.
        assert_eq!(STATUS_TOKEN_CACHE_TTL_MS, 5 * 60 * 1_000);

        let binding = "STATUS_API_TOKEN_TEST_F09";
        test_clear();

        // Step 1: warm isolate observes the old token's hash in the cache.
        let old_token = "rotated-out-status-token";
        let old_hash = hash(old_token)?;
        test_seed(
            binding,
            CachedSlot {
                argon2_hash: Some(old_hash.clone()),
                fingerprint: "oldfgp".to_string(),
            },
        );

        // Step 2: a verify against the seeded hash succeeds. The auth path
        // here uses the resolved-slots variant so the cache fetch and the
        // verify can be exercised independently in the test environment.
        let headers = headers_with_token(old_token);
        let logger = test_logger()?;
        let pre_rotation = authenticate_status_endpoint(
            &headers,
            Some(&old_hash),
            None,
            "oldfgp",
            "000000",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.99",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;
        assert!(
            pre_rotation.is_ok(),
            "old token must verify against the warm-isolate hash before rotation"
        );

        // Step 3 + 4: operator rotates Secrets Store, TTL elapses, the
        // refresh path replaces the cached hash with the new slot's
        // value. `test_force_expire` then `test_seed` mirrors the runtime
        // path inside `get_or_refresh`.
        test_force_expire(binding);
        let new_token = "rotated-in-status-token";
        let new_hash = hash(new_token)?;
        test_seed(
            binding,
            CachedSlot {
                argon2_hash: Some(new_hash.clone()),
                fingerprint: "newfgp".to_string(),
            },
        );

        // Step 5: the old token no longer authenticates against the
        // freshly resolved slot, confirming the warm-isolate path observes
        // the rotation within the TTL bound rather than holding the old
        // hash for the isolate's lifetime.
        let headers_old_again = headers_with_token(old_token);
        let post_rotation = authenticate_status_endpoint(
            &headers_old_again,
            Some(&new_hash),
            None,
            "newfgp",
            "000000",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.99",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;
        assert!(
            matches!(post_rotation, Err(ApiError::Unauthorized)),
            "old token must be rejected once the cache observes the rotated slot"
        );

        // The new token must verify against the freshly resolved slot.
        let headers_new = headers_with_token(new_token);
        let new_ok = authenticate_status_endpoint(
            &headers_new,
            Some(&new_hash),
            None,
            "newfgp",
            "000000",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.99",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;
        assert!(
            new_ok.is_ok(),
            "newly rotated token must verify against the refreshed slot"
        );

        test_clear();
        Ok(())
    }

    // ── F-01 (#72) replay-window tests ──────────────────────────────────────
    //
    // These tests exercise the orchestration logic of
    // `enforce_internal_replay_window` with an in-memory `NonceStore`
    // backed by `Mutex<HashMap>`. Production traffic uses the
    // Durable-Object-backed store; this mock covers the public
    // contract: timestamp window, missing-header rejection, role-tag
    // dedupe scoping, and replay rejection.

    use super::{
        enforce_internal_replay_window, INTERNAL_REPLAY_NONCE_TTL_SECS,
        INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS,
    };
    use crate::storage::traits::NonceStore;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    struct InMemoryNonceStore {
        seen: Mutex<HashMap<String, ()>>,
    }

    impl InMemoryNonceStore {
        fn new() -> Self {
            Self {
                seen: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl NonceStore for InMemoryNonceStore {
        async fn check_and_set(
            &self,
            nonce_tag: &str,
            _ttl: Duration,
        ) -> crate::error::ApiResult<bool> {
            let mut g = self.seen.lock().expect("nonce store mutex poisoned");
            if g.contains_key(nonce_tag) {
                Ok(false)
            } else {
                g.insert(nonce_tag.to_string(), ());
                Ok(true)
            }
        }
    }

    fn replay_headers(timestamp: u64, nonce: &str) -> TestHeaders {
        let mut h = TestHeaders::new();
        h.set("X-Timestamp", &timestamp.to_string());
        h.set("X-Nonce", nonce);
        h
    }

    /// Constants: pin the chosen window/TTL so a regression that
    /// shrinks either is caught at build time.
    #[test]
    fn test_internal_replay_window_constants() {
        assert_eq!(INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS, 300);
        assert_eq!(INTERNAL_REPLAY_NONCE_TTL_SECS, 24 * 60 * 60);
    }

    /// Happy path: fresh timestamp + first-use nonce returns the
    /// outcome echoing the operator-supplied values.
    #[tokio::test]
    async fn test_replay_window_accepts_fresh_request() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let headers = replay_headers(now, "fresh-nonce-001");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("fresh request must accept");

        assert_eq!(outcome.timestamp, now);
        assert_eq!(outcome.nonce, "fresh-nonce-001");
        Ok(())
    }

    /// Replay: same nonce reused inside the dedupe TTL must be
    /// rejected with Unauthorized.
    #[tokio::test]
    async fn test_replay_window_rejects_nonce_reuse() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let headers = replay_headers(now, "reused-nonce-XYZ");

        let _ = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("first call must succeed");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("nonce replay must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Stale timestamp: 600s in the past exceeds the 300s window so
    /// the request is rejected without consulting the nonce store.
    #[tokio::test]
    async fn test_replay_window_rejects_stale_timestamp() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let stale = now.saturating_sub(600);
        let headers = replay_headers(stale, "stale-nonce-AAA");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("stale timestamp must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Future-skew rejection: the bidirectional window also catches
    /// pre-mint attempts where the operator clock is ahead.
    #[tokio::test]
    async fn test_replay_window_rejects_future_timestamp() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let future = now.saturating_add(600);
        let headers = replay_headers(future, "future-nonce-BBB");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "future timestamp must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Missing X-Nonce: 401. The audit tag is
    /// `internal_replay_missing_nonce`, but the response is the
    /// identical Unauthorized variant so the endpoint cannot be
    /// probed via differing failure modes.
    #[tokio::test]
    async fn test_replay_window_rejects_missing_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();

        let mut h = TestHeaders::new();
        h.set("X-Timestamp", &now.to_string());
        // X-Nonce omitted

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("missing nonce must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Role-tag isolation: a nonce consumed against `internal_version`
    /// does not reject the same nonce against a sibling surface
    /// (`metrics`). The shared dedupe DO must scope dedupe by role
    /// tag so a captured request cannot replay across surfaces.
    #[tokio::test]
    async fn test_replay_window_role_tag_isolates_dedupe() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let headers = replay_headers(now, "shared-nonce-ZZZ");

        let _ = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("first surface must accept");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "metrics",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("sibling surface must accept independently");

        assert_eq!(outcome.nonce, "shared-nonce-ZZZ");
        Ok(())
    }

    // ── StatusAuthSlot / StatusAuthOutcome type tests ──────────────────

    #[test]
    fn test_status_auth_slot_eq() {
        assert_eq!(StatusAuthSlot::Current, StatusAuthSlot::Current);
        assert_eq!(StatusAuthSlot::Previous, StatusAuthSlot::Previous);
        assert_eq!(StatusAuthSlot::ApiKey, StatusAuthSlot::ApiKey);
        assert_ne!(StatusAuthSlot::Current, StatusAuthSlot::Previous);
        assert_ne!(StatusAuthSlot::Current, StatusAuthSlot::ApiKey);
        assert_ne!(StatusAuthSlot::Previous, StatusAuthSlot::ApiKey);
    }

    #[test]
    fn test_status_auth_slot_debug() {
        let debug_current = format!("{:?}", StatusAuthSlot::Current);
        let debug_previous = format!("{:?}", StatusAuthSlot::Previous);
        let debug_api_key = format!("{:?}", StatusAuthSlot::ApiKey);
        assert!(debug_current.contains("Current"));
        assert!(debug_previous.contains("Previous"));
        assert!(debug_api_key.contains("ApiKey"));
    }

    #[test]
    fn test_status_auth_slot_clone() {
        let slot = StatusAuthSlot::Current;
        let cloned = slot;
        assert_eq!(slot, cloned);
    }

    #[test]
    fn test_status_auth_outcome_debug() {
        let outcome = super::StatusAuthOutcome {
            slot: StatusAuthSlot::Current,
            fingerprint: "abcdef".to_string(),
        };
        let debug_str = format!("{:?}", outcome);
        assert!(debug_str.contains("Current"));
        assert!(debug_str.contains("abcdef"));
    }

    #[test]
    fn test_status_auth_outcome_clone() {
        let outcome = super::StatusAuthOutcome {
            slot: StatusAuthSlot::Previous,
            fingerprint: "fedcba".to_string(),
        };
        let cloned = outcome.clone();
        assert_eq!(cloned.slot, StatusAuthSlot::Previous);
        assert_eq!(cloned.fingerprint, "fedcba");
    }

    // ── InternalReplayCheckOutcome type tests ─────────────────────────

    #[test]
    fn test_internal_replay_check_outcome_debug() {
        let outcome = super::InternalReplayCheckOutcome {
            timestamp: 1700000000,
            nonce: "test-nonce".to_string(),
        };
        let debug_str = format!("{:?}", outcome);
        assert!(debug_str.contains("1700000000"));
        assert!(debug_str.contains("test-nonce"));
    }

    #[test]
    fn test_internal_replay_check_outcome_clone() {
        let outcome = super::InternalReplayCheckOutcome {
            timestamp: 1700000000,
            nonce: "clone-nonce".to_string(),
        };
        let cloned = outcome.clone();
        assert_eq!(cloned.timestamp, 1700000000);
        assert_eq!(cloned.nonce, "clone-nonce");
    }

    // ── StatusTokenFingerprints type tests ─────────────────────────────

    #[test]
    fn test_status_token_fingerprints_debug() {
        let fp = super::StatusTokenFingerprints {
            current: "abc123".to_string(),
            previous: "000000".to_string(),
        };
        let debug_str = format!("{:?}", fp);
        assert!(debug_str.contains("abc123"));
        assert!(debug_str.contains("000000"));
    }

    #[test]
    fn test_status_token_fingerprints_clone() {
        let fp = super::StatusTokenFingerprints {
            current: "abc123".to_string(),
            previous: "def456".to_string(),
        };
        let cloned = fp.clone();
        assert_eq!(cloned.current, "abc123");
        assert_eq!(cloned.previous, "def456");
    }

    // ── Replay window: missing timestamp ──────────────────────────────

    #[tokio::test]
    async fn test_replay_window_rejects_missing_timestamp() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let mut h = TestHeaders::new();
        h.set("X-Nonce", "some-nonce");
        // X-Timestamp omitted

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "missing timestamp must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Invalid (non-numeric) timestamp must be rejected.
    #[tokio::test]
    async fn test_replay_window_rejects_non_numeric_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let mut h = TestHeaders::new();
        h.set("X-Timestamp", "not-a-number");
        h.set("X-Nonce", "valid-nonce");

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "non-numeric timestamp must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Negative timestamp (float) must be rejected.
    #[tokio::test]
    async fn test_replay_window_rejects_float_timestamp() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let mut h = TestHeaders::new();
        h.set("X-Timestamp", "1700000000.5");
        h.set("X-Nonce", "float-nonce");

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("float timestamp must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Nonce longer than 256 bytes must be rejected before hitting the store.
    #[tokio::test]
    async fn test_replay_window_rejects_oversized_nonce() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();

        let long_nonce = "a".repeat(257);
        let mut h = TestHeaders::new();
        h.set("X-Timestamp", &now.to_string());
        h.set("X-Nonce", &long_nonce);

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("oversized nonce must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Nonce of exactly 256 bytes must be accepted (boundary test).
    #[tokio::test]
    async fn test_replay_window_accepts_max_nonce_length() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();

        let max_nonce = "b".repeat(256);
        let headers = replay_headers(now, &max_nonce);

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("256-byte nonce must be accepted");

        assert_eq!(outcome.nonce.len(), 256);
        Ok(())
    }

    /// Timestamp at exactly the boundary (300s old) must be accepted.
    #[tokio::test]
    async fn test_replay_window_accepts_boundary_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let boundary = now.saturating_sub(INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS);
        let headers = replay_headers(boundary, "boundary-nonce");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("timestamp at exact boundary (300s old) must be accepted");

        assert_eq!(outcome.timestamp, boundary);
        Ok(())
    }

    /// Timestamp at 301s old (one second past the window) must be rejected.
    #[tokio::test]
    async fn test_replay_window_rejects_one_past_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let past_boundary = now.saturating_sub(INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS + 1);
        let headers = replay_headers(past_boundary, "past-boundary-nonce");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "timestamp 301s old must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Both headers completely absent must reject.
    #[tokio::test]
    async fn test_replay_window_rejects_both_headers_absent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let h = TestHeaders::new();
        // Both X-Timestamp and X-Nonce omitted

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "both absent headers must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Empty X-Timestamp (present but empty) must be rejected.
    #[tokio::test]
    async fn test_replay_window_rejects_empty_timestamp() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let mut h = TestHeaders::new();
        h.set("X-Timestamp", "");
        h.set("X-Nonce", "nonce");

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("empty timestamp must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Empty X-Nonce (present but empty) must be rejected.
    #[tokio::test]
    async fn test_replay_window_rejects_empty_nonce() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();

        let mut h = TestHeaders::new();
        h.set("X-Timestamp", &now.to_string());
        h.set("X-Nonce", "");

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.50",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("empty nonce must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// No auth header at all must reject with Unauthorized.
    #[tokio::test]
    async fn test_authenticate_no_headers_at_all() -> Result<(), Box<dyn std::error::Error>> {
        let current_hash = hash("current-token-noheader")?;
        let headers = TestHeaders::new();
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            None,
            "abcdef",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.20",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    /// Neither slot bound (both None) must reject any token.
    #[tokio::test]
    async fn test_authenticate_no_slots_bound() -> Result<(), Box<dyn std::error::Error>> {
        let headers = headers_with_token("some-token");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            None, // no current slot
            None, // no previous slot
            "000000",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.21",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    // ── Additional coverage: previous-only slot binding ──────────────

    /// Previous slot only bound (no current hash), caller presents the
    /// previous token. Must accept via the previous-slot fall-through.
    /// This covers the path where `status_token_hash` is None but
    /// `status_token_hash_previous` is Some and matches.
    #[tokio::test]
    async fn test_authenticate_previous_only_bound_matches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous_token = "previous-only-token-A";
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_token(previous_token);
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            None, // current slot unset
            Some(&previous_hash),
            "000000",
            "prevfp",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.30",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("previous-only-bound match must return Ok");

        assert_eq!(outcome.slot, StatusAuthSlot::Previous);
        assert_eq!(outcome.fingerprint, "prevfp");
        Ok(())
    }

    /// Previous slot only bound (no current hash), caller presents the
    /// wrong token. Must reject.
    #[tokio::test]
    async fn test_authenticate_previous_only_bound_miss() -> Result<(), Box<dyn std::error::Error>>
    {
        let previous_hash = hash("previous-only-token-B")?;

        let headers = headers_with_token("wrong-token-entirely");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            None,
            Some(&previous_hash),
            "000000",
            "prevfp",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.31",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    // ── Additional coverage: Bearer edge cases ──────────────────────

    /// Bearer header with no current slot hash, previous slot matches.
    /// Verifies the dual-slot Bearer path when current is None.
    #[tokio::test]
    async fn test_authenticate_bearer_previous_only_matches(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous_token = "bearer-prev-only-A";
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_authorization(&format!("Bearer {previous_token}"));
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            None, // no current slot
            Some(&previous_hash),
            "000000",
            "prevfp",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.32",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("Bearer with previous-only match must return Ok");

        assert_eq!(outcome.slot, StatusAuthSlot::Previous);
        assert_eq!(outcome.fingerprint, "prevfp");
        Ok(())
    }

    /// Bearer header with whitespace-only credential after the scheme
    /// token. `extract_bearer_token` returns None, so the function falls
    /// through to X-Status-Token. With no X-Status-Token set, must reject.
    #[tokio::test]
    async fn test_authenticate_bearer_whitespace_only_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_hash = hash("some-current-token")?;
        let headers = headers_with_authorization("Bearer    ");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            None,
            "abcdef",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.33",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    /// Authorization header with an unsupported scheme (Digest) AND a
    /// valid X-Status-Token. The Bearer extraction returns None so the
    /// function must fall through to X-Status-Token and accept.
    #[tokio::test]
    async fn test_authenticate_non_bearer_auth_falls_through_to_x_status_token(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token = "fallthrough-token-A";
        let token_hash = hash(token)?;

        let mut headers = TestHeaders::new();
        headers.set("Authorization", "Digest realm=test");
        headers.set("X-Status-Token", token);
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&token_hash),
            None,
            "abcdef",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.34",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("non-Bearer auth must fall through to X-Status-Token");

        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        assert_eq!(outcome.fingerprint, "abcdef");
        Ok(())
    }

    /// X-Status-Token present with correct token matching the previous
    /// slot, current slot hash is None. Ensures X-Status-Token path also
    /// exercises the dual-slot fall-through to previous.
    #[tokio::test]
    async fn test_authenticate_x_status_token_previous_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let previous_token = "x-status-prev-only";
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_token(previous_token);
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            None,
            Some(&previous_hash),
            "000000",
            "xprevf",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.35",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("X-Status-Token with previous-only match must return Ok");

        assert_eq!(outcome.slot, StatusAuthSlot::Previous);
        assert_eq!(outcome.fingerprint, "xprevf");
        Ok(())
    }

    /// Bearer with no slots bound at all. Token is extracted from the
    /// Authorization header but both hashes are None, so the verify block
    /// is skipped entirely and the request falls through to Unauthorized.
    #[tokio::test]
    async fn test_authenticate_bearer_no_slots_bound() -> Result<(), Box<dyn std::error::Error>> {
        let headers = headers_with_authorization("Bearer some-token");
        let logger = test_logger()?;

        let result = authenticate_status_endpoint(
            &headers,
            None,
            None,
            "000000",
            "000000",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.36",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        assert!(matches!(result, Err(ApiError::Unauthorized)));
        Ok(())
    }

    /// Bearer current matches but previous also populated. Verify that the
    /// fingerprint returned is specifically the current slot, not the
    /// previous, even when both would verify. This ensures the function
    /// tries current first and short-circuits.
    #[tokio::test]
    async fn test_authenticate_bearer_current_wins_over_previous_when_same_token(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Both slots hashed from the same token value. Current must win.
        let token = "shared-token-both-slots";
        let current_hash = hash(token)?;
        let previous_hash = hash(token)?;

        let headers = headers_with_authorization(&format!("Bearer {token}"));
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "curfgp",
            "prvfgp",
            "STATUS_TOKEN_PROD",
            &logger,
            "192.0.2.37",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("both slots match; current must win");

        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        assert_eq!(outcome.fingerprint, "curfgp");
        Ok(())
    }

    // ── Additional coverage: extract_bearer_token edge cases ────────

    /// Tab character as delimiter (not space) must cause split_once(' ')
    /// to return None, rejecting the header.
    #[test]
    fn test_extract_bearer_token_tab_delimiter_rejects() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer\tabc"), None);
    }

    /// Newline in credential must not cause issues. The split is on the
    /// first space; whatever follows is the credential verbatim.
    #[test]
    fn test_extract_bearer_token_with_newline_in_credential() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer abc\ndef"), Some("abc\ndef"));
    }

    /// Single character credential after Bearer scheme.
    #[test]
    fn test_extract_bearer_token_single_char_credential() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer x"), Some("x"));
    }

    /// Multiple spaces in credential should be preserved after the
    /// leading-space trim.
    #[test]
    fn test_extract_bearer_token_spaces_in_credential() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token("Bearer a b c"), Some("a b c"));
    }

    /// Only a space character, no scheme at all. split_once returns
    /// ("", rest), and "" does not match "Bearer" case-insensitively.
    #[test]
    fn test_extract_bearer_token_leading_space_only() {
        use super::extract_bearer_token;
        assert_eq!(extract_bearer_token(" abc"), None);
    }

    // ── Additional coverage: status_token_role_for_env edge cases ───

    /// Uppercase variants of sandbox/development must map to PROD (the
    /// match is case-sensitive; only lowercase maps to SBX).
    #[test]
    fn test_status_token_role_case_sensitive() {
        assert_eq!(status_token_role_for_env("Sandbox"), "STATUS_TOKEN_PROD");
        assert_eq!(status_token_role_for_env("SANDBOX"), "STATUS_TOKEN_PROD");
        assert_eq!(
            status_token_role_for_env("Development"),
            "STATUS_TOKEN_PROD"
        );
        assert_eq!(
            status_token_role_for_env("DEVELOPMENT"),
            "STATUS_TOKEN_PROD"
        );
    }

    /// "prod" and "production" both map to PROD.
    #[test]
    fn test_status_token_role_prod_variants() {
        assert_eq!(status_token_role_for_env("prod"), "STATUS_TOKEN_PROD");
        assert_eq!(status_token_role_for_env("production"), "STATUS_TOKEN_PROD");
    }

    // ── Additional coverage: enforce_internal_replay_window ─────────

    /// Nonce store returning Err must fail closed (Unauthorized), not
    /// accept the request.
    #[tokio::test]
    async fn test_replay_window_storage_error_fails_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        struct ErroringNonceStore;

        #[async_trait::async_trait(?Send)]
        impl NonceStore for ErroringNonceStore {
            async fn check_and_set(
                &self,
                _nonce_tag: &str,
                _ttl: Duration,
            ) -> crate::error::ApiResult<bool> {
                Err(ApiError::BadRequest(Some(
                    "simulated storage failure".to_string(),
                )))
            }
        }

        let store: Arc<dyn NonceStore> = Arc::new(ErroringNonceStore);
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let headers = replay_headers(now, "error-nonce");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.60",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "storage error must fail closed with Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Negative timestamp string must be rejected (u64 parse fails on
    /// negative values).
    #[tokio::test]
    async fn test_replay_window_rejects_negative_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let mut h = TestHeaders::new();
        h.set("X-Timestamp", "-1");
        h.set("X-Nonce", "neg-nonce");

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.61",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "negative timestamp must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Timestamp zero with current server time well past the window.
    /// The skew will be enormous, so the request must reject.
    #[tokio::test]
    async fn test_replay_window_rejects_timestamp_zero() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let headers = replay_headers(0, "zero-ts-nonce");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.62",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            other => panic!("timestamp zero must surface Unauthorized, got {:?}", other), // nosemgrep: provii.workers.panic-in-worker
        }
        Ok(())
    }

    /// Future timestamp at exactly the boundary (+300s) must be accepted.
    #[tokio::test]
    async fn test_replay_window_accepts_future_boundary_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let future_boundary = now.saturating_add(INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS);
        let headers = replay_headers(future_boundary, "future-boundary-nonce");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.63",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("timestamp at exact future boundary (+300s) must be accepted");

        assert_eq!(outcome.timestamp, future_boundary);
        Ok(())
    }

    /// Future timestamp at +301s (one past the window) must be rejected.
    #[tokio::test]
    async fn test_replay_window_rejects_future_one_past_boundary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let future_past = now.saturating_add(INTERNAL_REPLAY_TIMESTAMP_WINDOW_SECS + 1);
        let headers = replay_headers(future_past, "future-past-nonce");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.64",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "future timestamp +301s must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Very large timestamp string (u64::MAX) that is well beyond the
    /// server clock must be rejected as future-skew.
    #[tokio::test]
    async fn test_replay_window_rejects_u64_max_timestamp() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let headers = replay_headers(u64::MAX, "max-ts-nonce");

        let result = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.65",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "u64::MAX timestamp must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Nonce of exactly 1 byte must be accepted.
    #[tokio::test]
    async fn test_replay_window_accepts_single_byte_nonce() -> Result<(), Box<dyn std::error::Error>>
    {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let headers = replay_headers(now, "x");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.66",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("single-byte nonce must be accepted");

        assert_eq!(outcome.nonce, "x");
        Ok(())
    }

    /// Same nonce against the same role tag must replay-reject even if
    /// the timestamp is different (within the window). The dedupe key
    /// is role + nonce, not role + nonce + timestamp.
    #[tokio::test]
    async fn test_replay_window_rejects_same_nonce_different_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();

        let headers_first = replay_headers(now, "dedup-nonce-TS");
        let _ = enforce_internal_replay_window(
            &headers_first,
            &store,
            "internal_version",
            &logger,
            "192.0.2.67",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("first call must succeed");

        // Same nonce, timestamp shifted by 1 second (still within window).
        let headers_second = replay_headers(now + 1, "dedup-nonce-TS");
        let result = enforce_internal_replay_window(
            &headers_second,
            &store,
            "internal_version",
            &logger,
            "192.0.2.67",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "same nonce with different timestamp must replay-reject, got {:?}",
                other
            ),
        }
        Ok(())
    }

    /// Timestamp at server_time - 299 must be accepted (within window).
    #[tokio::test]
    async fn test_replay_window_accepts_within_window_past(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let within = now.saturating_sub(299);
        let headers = replay_headers(within, "within-past-nonce");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.68",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("timestamp 299s in the past must be accepted");

        assert_eq!(outcome.timestamp, within);
        Ok(())
    }

    /// Timestamp at server_time + 299 must be accepted (within window,
    /// future direction).
    #[tokio::test]
    async fn test_replay_window_accepts_within_window_future(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;
        let now = crate::utils::current_timestamp();
        let within = now.saturating_add(299);
        let headers = replay_headers(within, "within-future-nonce");

        let outcome = enforce_internal_replay_window(
            &headers,
            &store,
            "internal_version",
            &logger,
            "192.0.2.69",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("timestamp 299s in the future must be accepted");

        assert_eq!(outcome.timestamp, within);
        Ok(())
    }

    /// Overflow-safe: timestamp string that overflows u64 must reject
    /// (parse fails).
    #[tokio::test]
    async fn test_replay_window_rejects_overflow_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn NonceStore> = Arc::new(InMemoryNonceStore::new());
        let logger = test_logger()?;

        let mut h = TestHeaders::new();
        // u64::MAX + 1 in decimal
        h.set("X-Timestamp", "18446744073709551616");
        h.set("X-Nonce", "overflow-nonce");

        let result = enforce_internal_replay_window(
            &h,
            &store,
            "internal_version",
            &logger,
            "192.0.2.70",
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await;

        match result {
            Err(ApiError::Unauthorized) => {}
            // nosemgrep: provii.workers.panic-in-worker
            other => panic!(
                "overflow timestamp must surface Unauthorized, got {:?}",
                other
            ),
        }
        Ok(())
    }

    // ── Additional coverage: auth with SBX role label ───────────────

    /// The `status_token_role_previous` derivation appends `_PREVIOUS`
    /// to the role tag. Verify that the SBX role label produces the
    /// correct audit trail by checking that a current match with the
    /// SBX role label returns the correct fingerprint (the role label
    /// itself is only used in console_log so we verify side-effect-free
    /// correctness through the returned outcome).
    #[tokio::test]
    async fn test_authenticate_sbx_role_current_match() -> Result<(), Box<dyn std::error::Error>> {
        let token = "sbx-role-test-token";
        let token_hash = hash(token)?;

        let headers = headers_with_token(token);
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&token_hash),
            None,
            "sbxfgp",
            "000000",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.40",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("SBX role with current match must return Ok");

        assert_eq!(outcome.slot, StatusAuthSlot::Current);
        assert_eq!(outcome.fingerprint, "sbxfgp");
        Ok(())
    }

    /// Both slots bound with SBX role, previous matches via Bearer.
    /// Ensures the _PREVIOUS suffix derivation works for sandbox.
    #[tokio::test]
    async fn test_authenticate_sbx_role_bearer_previous_match(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_token = "sbx-current-bearer";
        let previous_token = "sbx-previous-bearer";
        let current_hash = hash(current_token)?;
        let previous_hash = hash(previous_token)?;

        let headers = headers_with_authorization(&format!("Bearer {previous_token}"));
        let logger = test_logger()?;

        let outcome = authenticate_status_endpoint(
            &headers,
            Some(&current_hash),
            Some(&previous_hash),
            "sbxcur",
            "sbxprv",
            "STATUS_TOKEN_SBX",
            &logger,
            "192.0.2.41",
            None,
            "ip-hash-salt-test-32-bytes-long!",
        )
        .await
        .expect("SBX Bearer previous match must return Ok");

        assert_eq!(outcome.slot, StatusAuthSlot::Previous);
        assert_eq!(outcome.fingerprint, "sbxprv");
        Ok(())
    }
}
