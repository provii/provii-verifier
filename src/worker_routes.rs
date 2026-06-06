// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HTTP routing layer for the Cloudflare Worker V1 API.
//!
//! This module builds the [`Router`] that dispatches every inbound HTTP request to the
//! appropriate route handler. Each route closure follows the same pattern: validate
//! Sec-Fetch metadata, enforce rate limits, read and parse the request body within a
//! size cap, call into the domain handler, then wrap the response with security and
//! CORS headers.
//!
//! The catch-all handler at the bottom defends against web cache deception by
//! returning explicit 404s with anti-caching headers for every unmatched path.
//! It also provides elevated security logging when probes hit the former
//! `/v1/internal/*` paths (removed when provii-verifier was merged).

use crate::bindings::{KV_CONFIG, KV_RATE_LIMITS};
use crate::{
    config::Config,
    error::ApiError,
    routes::{
        challenge::{
            create_challenge, get_challenge_by_short_code, get_challenge_details, poll_challenge,
            CreateChallengeRequest,
        },
        csp_report::handle_csp_report,
        health::{health_check_basic, health_check_detailed},
        internal_admin::{
            admin_rate_limit_check, authenticate_admin_endpoint, handle_delete_test_fixtures,
            handle_mek_decrypt_probe, handle_replay_pre_rotation_token,
            handle_test_fixtures_manifest, record_admin_auth_failure,
        },
        internal_invalidate_jwks::handle_invalidate_jwks_authed,
        internal_version::handle_internal_version,
        redeem::{redeem_challenge, RedeemRequest},
        verify::{submit_verification, SubmitProofRequest},
    },
    security::{
        authenticate_status_endpoint, generate_swagger_ui_html, hash_ip,
        headers::{add_internal_security_headers, api_security_headers, docs_security_headers},
        validate_fetch_metadata, validate_fetch_metadata_csp,
        validation::VALIDATOR,
    },
    AppState,
};
use std::sync::Arc;
use worker::{console_log, Error as WorkerError, Headers, Response, Router};

/// ADV-VA-033: Read a u32 env var with a default, logging when the default is used.
///
/// This replaces bare `.unwrap_or(default)` so that missing or unparseable
/// configuration values produce a visible warning rather than silently falling
/// back.
fn env_var_u32(ctx_env: &worker::Env, name: &str, default: u32) -> u32 {
    match ctx_env.var(name) {
        Ok(v) => match v.to_string().parse::<u32>() {
            Ok(val) => val,
            Err(_) => {
                console_log!(
                    "[WARN] Env var {} has unparseable value '{}', using default {}",
                    name,
                    v.to_string(),
                    default
                );
                default
            }
        },
        Err(_) => {
            console_log!(
                "[WARN] Env var {} not configured, using default {}",
                name,
                default
            );
            default
        }
    }
}

/// Check whether the request Content-Type header indicates JSON.
fn is_json(headers: &Headers) -> bool {
    headers
        .get("Content-Type")
        .ok()
        .flatten()
        .map(|ct| ct.to_ascii_lowercase().starts_with("application/json"))
        .unwrap_or(false)
}

/// Read the request body, rejecting payloads that exceed `max` bytes.
///
/// ST-VA-024: Pre-checks Content-Length before buffering the body. If the
/// header is present and exceeds the limit, the request is rejected without
/// reading the stream. The Workers API does not expose a streaming body
/// reader, so the post-read length check remains as a defence in depth
/// against chunked-encoding or missing Content-Length scenarios.
async fn read_limited_body(req: &mut worker::Request, max: usize) -> Result<Vec<u8>, WorkerError> {
    // Fast reject: if Content-Length is declared and over the limit, bail
    // before buffering any bytes.
    if let Ok(Some(cl)) = req.headers().get("content-length") {
        if let Ok(size) = cl.parse::<usize>() {
            if size > max {
                return Err(worker::Error::RustError("Request entity too large".into()));
            }
        }
    }
    let bytes = req.bytes().await?;
    if bytes.len() > max {
        return Err(worker::Error::RustError("Request entity too large".into()));
    }
    Ok(bytes)
}

/// Generate a hosted-flow test key pair, encrypt it with the HOSTED_MEK, and
/// write both the `PublicKeyData` entry to HOSTED_PUBLIC_KEYS and an
/// `OriginIndexEntry` to ORIGIN_INDEX. Returns the `pk_test_*` identifier on
/// success so the caller can include it in the registration response.
///
/// # Errors
///
/// Returns a human-readable error string. Callers treat this as non-fatal:
/// the expert-flow (HMAC) credentials remain valid even if hosted key
/// provisioning fails.
async fn generate_hosted_test_key(
    env: &worker::Env,
    origin: &str,
    ttl_seconds: u64,
) -> Result<String, String> {
    use crate::hosted::encryption::{encrypt_with_mek, get_mek_from_secrets};
    use crate::hosted::keys::{KeyManager, KeyType, PUBLIC_KEY_DATA_AAD};

    // 1. Generate cryptographic key pair
    let key_pair = KeyManager::generate_key_pair(KeyType::Test)
        .map_err(|e| format!("key generation: {}", e))?;

    let now_sec = worker::Date::now().as_millis() / 1000;

    // 2. Build the PublicKeyData JSON manually because the Rust struct has
    //    #[serde(skip_serializing)] on secret_key (correct for API responses
    //    but the KV blob must include it for hosted-mode HMAC authentication).
    let key_data_json = serde_json::json!({
        "id": &key_pair.public_key,
        "secret_key": &key_pair.secret_key,
        "allowed_origins": [origin],
        "enabled": true,
        "created_at": now_sec,
        "updated_at": now_sec,
        "name": "Sandbox self-service key",
        "metadata": {
            "environment": "sandbox",
            "purpose": "self-service-test",
            "registered_via": "register-test-origin"
        }
    });

    // 3. Encrypt with HOSTED_MEK (AES-256-GCM, same AAD as provii-management)
    let mek = get_mek_from_secrets(env)
        .await
        .map_err(|e| format!("MEK retrieval: {}", e))?;

    let plaintext = key_data_json.to_string();

    let encrypted = encrypt_with_mek(&mek, &plaintext, PUBLIC_KEY_DATA_AAD)
        .map_err(|e| format!("encryption: {}", e))?;

    // 4. Write encrypted PublicKeyData to HOSTED_PUBLIC_KEYS
    let hosted_kv = env
        .kv("HOSTED_PUBLIC_KEYS")
        .map_err(|e| format!("HOSTED_PUBLIC_KEYS binding: {}", e))?;

    hosted_kv
        .put(&key_pair.public_key, &encrypted)
        .map_err(|e| format!("HOSTED_PUBLIC_KEYS put: {}", e))?
        .expiration_ttl(ttl_seconds)
        .execute()
        .await
        .map_err(|e| format!("HOSTED_PUBLIC_KEYS write: {}", e))?;

    // 5. Write OriginIndexEntry to ORIGIN_INDEX
    let origin_index_kv = env
        .kv("ORIGIN_INDEX")
        .map_err(|e| format!("ORIGIN_INDEX binding: {}", e))?;

    let origin_entry = serde_json::json!({
        "key_ids": [&key_pair.public_key],
        "metering_enabled": false,
        "updated_at": now_sec.saturating_mul(1000)  // provii-management uses Date.now() (milliseconds)
    });

    origin_index_kv
        .put(origin, origin_entry.to_string())
        .map_err(|e| format!("ORIGIN_INDEX put: {}", e))?
        .expiration_ttl(ttl_seconds)
        .execute()
        .await
        .map_err(|e| format!("ORIGIN_INDEX write: {}", e))?;

    // Clone the public_key before the KeyPair is dropped (ZeroizeOnDrop
    // prevents moving fields out). The public key is not secret material.
    let pk_id = key_pair.public_key.clone();
    Ok(pk_id)
}

/// Add security and CORS headers to the response.
///
/// SECURITY: Implements OWASP CORS best practices:
/// - Credentials are only allowed for exact origin matches
/// - Wildcard origins never receive credentials
/// - All CORS violations are logged for security monitoring
/// - Origin header is always reflected (never "*") when credentials are involved
fn add_security_and_cors_headers(
    mut response: Response,
    req_headers: &Headers,
    cfg: &Config,
) -> Result<Response, WorkerError> {
    let origin = req_headers.get("Origin")?.unwrap_or_default();

    // Apply security headers before handling CORS.
    let security_headers = api_security_headers();
    security_headers.apply(&mut response)?;

    let h = response.headers_mut();

    // SECURITY: Configure CORS response headers following OWASP guidelines.
    // In sandbox, reflect any origin so developers can test pk_test_* keys
    // from localhost, dev domains, and other unregistered origins. This is
    // safe because sandbox is a separate deployment with no production data.
    if !origin.is_empty() {
        let is_sandbox = cfg.environment == "sandbox";
        let origin_matches = is_sandbox || cfg.cors.matches(&origin);
        let allows_credentials = if is_sandbox {
            false // sandbox does not set credentials for arbitrary origins
        } else {
            cfg.cors.allows_credentials(&origin)
        };

        if origin_matches {
            // SECURITY: Always reflect the specific origin, never use "*"
            h.set("Access-Control-Allow-Origin", &origin)?;

            // SECURITY: Set credentials header when allows_credentials returns true.
            // Global wildcard blocks credentials; subdomain wildcards allow them
            // because the ACAO header reflects the specific origin (never "*").
            if allows_credentials {
                h.set("Access-Control-Allow-Credentials", "true")?;
                console_log!(
                    "[SECURITY][CORS] Allowed origin with credentials: {}",
                    origin
                );
            } else if is_sandbox {
                console_log!(
                    "[SECURITY][CORS] Sandbox: reflecting origin without credentials: {}",
                    origin
                );
            } else {
                // Origin matches but credentials not allowed (global wildcard in list)
                console_log!(
                    "[SECURITY][CORS] Allowed origin WITHOUT credentials (global wildcard): {}",
                    origin
                );
            }
        } else {
            // SECURITY: Silently omit Access-Control-Allow-Origin for disallowed origins.
            // The browser will enforce CORS rejection when this header is absent.
            console_log!(
                "[SECURITY][CORS] Blocked origin (not in allowlist): {}",
                origin
            );
        }
    } else {
        console_log!("[CORS] No Origin header present (same-origin or non-browser request)");
    }

    // Set the baseline CORS headers for every response.
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    // SECURITY: All these custom headers (X-API-Key, Idempotency-Key, etc.) trigger CORS preflight
    // as they are not CORS-safelisted headers. Preflight validation ensures proper access control.
    h.set(
        "Access-Control-Allow-Headers",
        "Content-Type, X-API-Version, X-API-Key, Idempotency-Key, X-CSRF-Token",
    )?;
    h.set("Access-Control-Max-Age", "86400")?;

    // SECURITY: Vary header ensures proper caching behaviour per-origin
    h.set("Vary", "Origin")?;

    // Attach a request identifier for traceability.
    let request_id = uuid::Uuid::new_v4().to_string();
    h.set("X-Request-Id", &request_id)?;

    Ok(response)
}

/// Return a permissive CORS preflight response for sandbox hosted endpoints.
///
/// In sandbox, hosted CORS preflights accept any origin so that pk_test_* keys
/// work from localhost, dev domains, and other unregistered origins. The actual
/// authentication and origin checks run on the POST handler. Only called when
/// `cfg.environment == "sandbox"` and an Origin header is present.
///
/// Returns `None` when the bypass does not apply (non-sandbox or missing origin),
/// signalling the caller to fall through to the standard preflight logic.
fn sandbox_hosted_cors_preflight(
    origin: &Option<String>,
    cfg: &Config,
) -> Option<Result<Response, WorkerError>> {
    if cfg.environment != "sandbox" {
        return None;
    }
    let o = origin.as_deref()?;
    if o.is_empty() {
        return None;
    }
    let build = || -> Result<Response, WorkerError> {
        let mut response = Response::empty()?.with_status(204);
        crate::hosted::cors::add_cors_headers_with_credentials(response.headers_mut(), o, false)
            .map_err(|e| worker::Error::RustError(format!("{}", e)))?;
        crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
            &mut response,
        );
        response
            .headers_mut()
            .set("Cache-Control", "private, max-age=86400")?;
        response.headers_mut().delete("Pragma")?;
        console_log!("[CORS] Sandbox: allowing hosted preflight from any origin");
        Ok(response)
    };
    Some(build())
}

/// Handle OPTIONS preflight requests with security headers.
///
/// SECURITY: Implements OWASP CORS preflight best practices:
/// - Credentials only allowed for exact origin matches
/// - All preflight violations are logged
/// - Proper security headers applied before CORS headers
fn handle_options(req_headers: &Headers, cfg: &Config) -> Result<Response, WorkerError> {
    // CH-006: Use 204 No Content for preflight (no body expected).
    let mut response = Response::empty()?.with_status(204);

    // Apply the baseline security headers.
    let security_headers = api_security_headers();
    security_headers.apply(&mut response)?;

    let origin = req_headers.get("Origin").ok().flatten().unwrap_or_default();

    let h = response.headers_mut();

    // SECURITY: Apply same credential rules as regular requests
    if !origin.is_empty() {
        let origin_matches = cfg.cors.matches(&origin);
        let allows_credentials = cfg.cors.allows_credentials(&origin);

        if origin_matches {
            h.set("Access-Control-Allow-Origin", &origin)?;

            // SECURITY: Allow credentials unless global wildcard is configured.
            // Subdomain wildcards allow credentials (ACAO reflects specific origin).
            if allows_credentials {
                h.set("Access-Control-Allow-Credentials", "true")?;
                console_log!(
                    "[SECURITY][CORS Preflight] ✅ Allowed origin with credentials: {}",
                    origin
                );
            } else {
                console_log!(
                    "[SECURITY][CORS Preflight] ⚠️ Allowed origin WITHOUT credentials: {}",
                    origin
                );
            }
        } else {
            // SECURITY: Silently omit Access-Control-Allow-Origin for disallowed origins.
            console_log!("[SECURITY][CORS Preflight] ❌ Blocked origin: {}", origin);
        }
    }

    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    h.set(
        "Access-Control-Allow-Headers",
        "Content-Type, X-API-Version, X-API-Key, Idempotency-Key, X-CSRF-Token",
    )?;
    h.set("Access-Control-Max-Age", "86400")?;
    h.set("Vary", "Origin")?;

    Ok(response)
}

/// Extract the client IP from request headers.
///
/// SECURITY: Uses ONLY CF-Connecting-IP which is set by the Cloudflare edge
/// and cannot be spoofed. Falls back to "unknown" when not present (e.g.
/// direct requests bypassing Cloudflare, which should not happen in prod).
///
/// NOTE: This function returns the RAW IP address. When logging IPs,
/// always use hash_ip() from security::log_sanitizer for GDPR compliance.
pub(crate) fn get_client_ip(headers: &Headers) -> String {
    headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string())
}

/// Defence in depth for `/_internal/*` routes.
///
/// Service-binding traffic from sibling Workers reaches the dispatcher
/// without `CF-Connecting-IP`. Public-internet traffic always carries the
/// header (the Cloudflare edge sets it). Rejecting any request that
/// presents the header blocks an external attacker who possesses a valid
/// internal bearer token from reaching the surface, even before the
/// existing dual-slot status-token auth runs.
///
/// Returns `Some(401_response)` when external traffic is detected; the
/// caller forwards the response unchanged. Returns `None` when the
/// request looks like service-binding traffic and the existing auth
/// path should run.
///
/// The check applies in both production and sandbox: the `/_internal/*`
/// surface is service-binding-only in every environment, so an external
/// connecting-IP is unauthorised regardless of `ENVIRONMENT`. Mirrors
/// the provii-audit-consumer `internal_version_unauthorised` rejection
/// log shape so the SIEM can pivot across Workers on one event name.
fn reject_external_internal_traffic(
    headers: &Headers,
    role_tag: &str,
) -> Option<worker::Result<Response>> {
    let connecting_ip = headers
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_default();
    if connecting_ip.is_empty() {
        return None;
    }
    console_log!(
        r#"{{"event":"internal_route_unauthorised","service":"provii-verifier","role_tag":"{}","reason":"external_traffic"}}"#,
        role_tag
    );
    Some(error_with_headers("Unauthorized", 401))
}

/// Extract client_id from request headers for dynamic rate limiting.
///
/// Resolution order:
/// 1. Origin header (primary identifier for browser requests)
/// 2. X-API-Key header (for server-to-server requests)
/// 3. X-Public-Key header (for hosted flow requests)
/// 4. Fallback to salted-hash of IP address
///
/// # Arguments
///
/// * `headers` - Request headers
/// * `ip_hash_salt` - Salt for hashing IP addresses (GDPR: raw IPs must not persist in KV)
///
/// # Returns
///
/// Client identifier suitable for rate limit lookups
fn get_client_id(headers: &Headers, ip_hash_salt: &str) -> String {
    // SECURITY: Always compute IP hash for use in rate limit keys to prevent
    // Origin spoofing from bypassing per-IP rate limits (H-26).
    let client_ip = get_client_ip(headers);
    let ip_hash = hash_ip(&client_ip, ip_hash_salt);

    // Prefer Origin header for browser requests, but always include IP hash
    // so rate limits are per-origin-per-IP (not spoofable via Origin alone).
    if let Ok(Some(origin)) = headers.get("Origin") {
        if !origin.is_empty() {
            return format!("origin:{}:{}", origin, ip_hash);
        }
    }

    // Fallback to X-API-Key for server-to-server requests
    // Note: This extracts the key for identification only, not authentication
    if let Ok(Some(api_key)) = headers.get("X-API-Key") {
        if !api_key.is_empty() {
            // SECURITY: Hash API key to prevent plaintext exposure in KV store (R-17).
            // Anyone with Cloudflare dashboard read access could see all customer API keys
            // if stored as plaintext KV keys. First 16 hex chars of SHA-256 is sufficient
            // for rate limit bucketing (64 bits of collision resistance).
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(api_key.as_bytes());
            let hash_hex = format!("{:x}", hash);
            let hash_prefix = hash_hex.get(..16).unwrap_or(&hash_hex);
            // SECURITY (ST-VA-004): Include IP hash in API key rate limit bucket.
            // Without the IP component, an attacker can rotate fake X-API-Key values
            // to mint fresh rate limit buckets. The IP hash binds the bucket to the
            // source address, matching the pattern used by the origin path above.
            return format!("apikey:{}:{}", hash_prefix, ip_hash);
        }
    }

    // SECURITY: Hash IP with domain-separated salt before storing as KV key (SH-008).
    // Raw IPs in KV storage are PII under GDPR and expose client identity to anyone
    // with Cloudflare dashboard read access. hash_ip() uses SHA-256 with a
    // "provii-ip-v0" domain separator, making the output deterministic (same IP +
    // salt = same key) but irreversible without the salt.
    format!("ip:{}", ip_hash)
}

/// Validate the request size against configured limits.
///
/// ST-VA-025: When Content-Length is missing or unparseable on a request that
/// carries a body (POST/PUT/PATCH), we fall through rather than silently
/// passing. The body-level enforcement in `read_limited_body` catches these
/// cases after buffering. Logging the gap here ensures visibility.
fn validate_request_size(headers: &Headers, endpoint: &str) -> Result<(), ApiError> {
    match headers.get("content-length") {
        Ok(Some(cl)) => {
            if let Ok(size) = cl.parse::<usize>() {
                VALIDATOR.validate_request_size(size, endpoint)?;
            } else {
                // Unparseable Content-Length: log and rely on body-level check.
                console_log!(
                    "[SECURITY] Unparseable Content-Length header on endpoint={}, relying on body-level enforcement",
                    endpoint
                );
            }
        }
        _ => {
            // Missing Content-Length: body-level enforcement in read_limited_body
            // will catch oversized payloads. Log for visibility.
            console_log!(
                "[SECURITY] Missing Content-Length on endpoint={}, relying on body-level enforcement",
                endpoint
            );
        }
    }
    Ok(())
}

/// Create an error response with proper security headers.
///
/// SECURITY: ASVS V3.4.1, V3.4.4, V3.4.5 - Ensures all error responses include
/// the full set of security headers (HSTS, X-Content-Type-Options, CSP, etc.)
/// to prevent security header bypass vulnerabilities.
///
/// This helper replaces direct Response::error() calls which bypass security headers.
///
/// # Arguments
///
/// * `message` - Error message to include in response
/// * `status` - HTTP status code
///
/// # Returns
///
/// Result containing a Response with security headers applied
// PG-VAL-016: Schema-inference helpers live in `routes::schema_inference` so
// they are covered by CI (this file is excluded by the `worker_routes` regex).
use crate::routes::schema_inference::{
    infer_create_challenge_schema_field, infer_redeem_schema_field,
};

// VA-ROOT-007: Produces the standard 5-key error envelope (error, message,
// request_id, field, detail) to match ApiError::to_response and avoid
// inconsistent response shapes.
fn error_with_headers(message: &str, status: u16) -> worker::Result<Response> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let error_code = match status {
        400 => "BAD_REQUEST",
        401 => "UNAUTHORIZED",
        402 => "PAYMENT_REQUIRED",
        403 => "FORBIDDEN",
        404 => "NOT_FOUND",
        405 => "METHOD_NOT_ALLOWED",
        409 => "CONFLICT",
        410 => "GONE",
        413 => "PAYLOAD_TOO_LARGE",
        415 => "UNSUPPORTED_MEDIA_TYPE",
        429 => "TOO_MANY_REQUESTS",
        503 => "SERVICE_UNAVAILABLE",
        _ => "INTERNAL_ERROR",
    };
    let body = serde_json::json!({
        "error": error_code,
        "message": message,
        "request_id": request_id,
        "field": null,
        "detail": null,
    });
    let mut response = Response::from_json(&body)?.with_status(status);

    // Apply all required security headers
    let security_headers = api_security_headers();
    security_headers.apply(&mut response)?;

    // Ensure proper content type
    response
        .headers_mut()
        .set("Content-Type", "application/json; charset=utf-8")?;

    // VA-ROOT-004: Add Clear-Site-Data on all 401/403 responses
    if status == 401 || status == 403 {
        response.headers_mut().set("Clear-Site-Data", r#""*""#)?;
    }

    Ok(response)
}

/// Recover the correct HTTP status from a `worker::Error` that bubbled up
/// through `?` from a route handler.
///
/// SECURITY: When an `ApiError` is propagated via `?`, the
/// `From<ApiError> for worker::Error` impl converts it to
/// `worker::Error::RustError(<display>)`. The Display string still encodes
/// the variant (`"forbidden"`, `"bad-request"`, etc.). This helper parses
/// that string and re-emits a Response with the original status code. Without
/// this every propagated error became a generic 500 INTERNAL_ERROR, the
/// 500-instead-of-403 bug the user reported.
///
/// Falls back to 500 for opaque worker errors (e.g. JS runtime failures, KV
/// internal errors) where 500 is the correct mapping anyway.
fn handler_error_to_response(
    endpoint: &str,
    err: &worker::Error,
    hdrs: &Headers,
    cfg: &Config,
) -> Result<Response, worker::Error> {
    let s = err.to_string();
    match crate::error::ApiError::status_for_display_str(&s) {
        Some((status, code)) => {
            console_log!(
                "[{}] Handler error mapped to HTTP {} ({}): {:?}",
                endpoint,
                status,
                code,
                err
            );
            // PG-VAL-001: Delegate to `response_from_worker_error` so any
            // structured detail (`code`, `field`, `detail`) carried via the
            // `<base>!!<payload>` envelope reaches the client. The legacy
            // path lost it, leaving every error as the same opaque
            // BAD_REQUEST/Internal-error body.
            let resp = crate::error::ApiError::response_from_worker_error(err)?;
            add_security_and_cors_headers(resp, hdrs, cfg)
        }
        None => {
            console_log!(
                "[{}] Handler error (opaque, mapped to 500): {:?}",
                endpoint,
                err
            );
            let resp = error_with_headers("Internal error", 500)?;
            add_security_and_cors_headers(resp, hdrs, cfg)
        }
    }
}

/// AC-001: Obtain the rate limit KV binding, failing closed with a 503 if the
/// binding is unavailable. Previously, each route used `if let Ok(rl_kv)` which
/// silently skipped rate limiting on binding errors (fail-open). This helper
/// centralises the fail-closed behaviour: if KV_RATE_LIMITS cannot be bound, the
/// request is rejected rather than processed without rate limit enforcement.
///
/// Use via the `require_rl_kv!` macro which handles the early return.
fn require_rate_limit_kv(ctx_env: &worker::Env) -> Result<worker::kv::KvStore, WorkerError> {
    ctx_env.kv(KV_RATE_LIMITS).map_err(|e| {
        console_log!(
            "{{\"audit\":true,\"event\":\"rate_limit_binding_failure\",\"severity\":\"error\",\"binding\":\"VERIFIER_KV_RATE_LIMITS\",\"outcome\":\"fail_closed\",\"error\":\"{}\"}}",
            e
        );
        e
    })
}

/// AC-001: Fail-closed rate limit KV binding. Returns the KV store or
/// immediately returns a 503 response to the caller.
macro_rules! require_rl_kv {
    ($ctx:expr) => {
        match require_rate_limit_kv(&$ctx.env) {
            Ok(kv) => kv,
            Err(_) => return error_with_headers("Service temporarily unavailable", 503),
        }
    };
}

/// R8 (RL-10): Offload a reject/validation-path audit emit so the 4xx/5xx
/// response returns to the client BEFORE the `AUDIT_QUEUE` send round-trip.
///
/// The enforcement/decision MUST already have run before this macro is invoked
/// (the macro only relocates the best-effort emit, never the admit/deny gate);
/// the emit is best-effort (errors swallowed inside `AuditLogger`) so it can
/// never become a 5xx.
///
/// `crate::take_worker_context()` is SINGLE-SHOT: only the first taker per
/// request receives the `Context`. The `else` arm is therefore MANDATORY and
/// falls back to the original inline `.await` so the audit is never silently
/// dropped. Reject branches `return` immediately after the emit, so at most one
/// site per request takes the context and the handler's own later takes are
/// unaffected.
///
/// Usage: bind the logger to `$logger` (an owned `Arc<AuditLogger>` in the
/// offload arm, a borrow in the inline arm) and write the emit ONCE:
/// ```ignore
/// offload_audit!(ctx, |logger| logger.log_suspicious_activity(&client_ip, "reason"));
/// return error_with_headers("Access denied", 403);
/// ```
/// Any captured locals (e.g. `client_ip`) are moved into the background future
/// in the offload arm and borrowed in the inline arm; both are valid because the
/// caller `return`s straight after. Sites whose emit borrows `ctx.data`
/// (e.g. passing `ctx.data.analytics.as_ref()`) must instead capture an owned
/// clone explicitly and not use this macro.
macro_rules! offload_audit {
    ($ctx:expr, |$logger:ident| $emit:expr) => {{
        if let Some(__wctx) = crate::take_worker_context() {
            let $logger = $ctx.data.audit_logger.clone();
            __wctx.wait_until(async move {
                $emit.await;
            });
        } else {
            let $logger = &$ctx.data.audit_logger;
            $emit.await;
        }
    }};
}

/// SEC-028: Enforce a session-bound CSRF token on a mutating hosted endpoint.
///
/// Extracts the `X-CSRF-Token` header, validates it against
/// `expected_session_id` using the cached `SESSION_TOKEN_SECRET`, audits
/// failures, and returns a 403 response on rejection. Pass `"anonymous"` as
/// `expected_session_id` for endpoints that have no session ID on the path
/// (logout, sandbox simulate-proof); the client must have obtained its token
/// from `GET /v1/hosted/csrf-token`.
///
/// On failure, returns `Err` with a fully built `worker::Result<Response>` so
/// the caller can forward it directly:
/// ```ignore
/// if let Err(resp) = enforce_hosted_csrf(&ctx, &hdrs, &sid, "hosted_redeem").await {
///     return resp;
/// }
/// ```
///
/// A 503 is returned if the signing key is not cached (startup race); this
/// mirrors the 503 path used on the CSRF generation endpoints.
async fn enforce_hosted_csrf(
    ctx: &worker::RouteContext<Arc<AppState>>,
    hdrs: &Headers,
    expected_session_id: &str,
    endpoint: &str,
) -> Result<(), worker::Result<Response>> {
    let client_ip = get_client_ip(hdrs);

    // Extract header. Missing / empty → 403 with audit.
    let token = match hdrs
        .get(crate::hosted::endpoints::csrf::CSRF_HEADER_NAME)
        .ok()
        .flatten()
    {
        Some(t) if !t.is_empty() => t,
        _ => {
            // R8: emit best-effort off the critical path; fall back to inline.
            if let Some(wctx) = crate::take_worker_context() {
                let logger = ctx.data.audit_logger.clone();
                let ip = client_ip.clone();
                let ep = endpoint.to_string();
                let sid = expected_session_id.to_string();
                wctx.wait_until(async move {
                    logger
                        .log_csrf_validation_failed(&ip, &ep, &sid, "missing_token")
                        .await;
                });
            } else {
                ctx.data
                    .audit_logger
                    .log_csrf_validation_failed(
                        &client_ip,
                        endpoint,
                        expected_session_id,
                        "missing_token",
                    )
                    .await;
            }
            return Err(csrf_forbidden_response(hdrs, &ctx.data.cfg));
        }
    };

    // Fetch the cached signing key. Without it we cannot validate; fail closed.
    let signing_key = match ctx.data.session_token_secret.as_ref() {
        Some(s) => (**s).clone(),
        None => {
            console_log!(
                "[CSRF] SESSION_TOKEN_SECRET unavailable; cannot validate on {}",
                endpoint
            );
            // R8: emit best-effort off the critical path; fall back to inline.
            if let Some(wctx) = crate::take_worker_context() {
                let logger = ctx.data.audit_logger.clone();
                let ip = client_ip.clone();
                let ep = endpoint.to_string();
                let sid = expected_session_id.to_string();
                wctx.wait_until(async move {
                    logger
                        .log_csrf_validation_failed(&ip, &ep, &sid, "signing_key_unavailable")
                        .await;
                });
            } else {
                ctx.data
                    .audit_logger
                    .log_csrf_validation_failed(
                        &client_ip,
                        endpoint,
                        expected_session_id,
                        "signing_key_unavailable",
                    )
                    .await;
            }
            let err = error_with_headers("Service temporarily unavailable", 503)
                .and_then(|r| add_security_and_cors_headers(r, hdrs, &ctx.data.cfg));
            return Err(err);
        }
    };

    // Decode the base64url signing key.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let key_bytes = match URL_SAFE_NO_PAD.decode(signing_key.as_bytes()) {
        Ok(k) => k,
        Err(_) => {
            // R8: emit best-effort off the critical path; fall back to inline.
            if let Some(wctx) = crate::take_worker_context() {
                let logger = ctx.data.audit_logger.clone();
                let ip = client_ip.clone();
                let ep = endpoint.to_string();
                let sid = expected_session_id.to_string();
                wctx.wait_until(async move {
                    logger
                        .log_csrf_validation_failed(&ip, &ep, &sid, "signing_key_unavailable")
                        .await;
                });
            } else {
                ctx.data
                    .audit_logger
                    .log_csrf_validation_failed(
                        &client_ip,
                        endpoint,
                        expected_session_id,
                        "signing_key_unavailable",
                    )
                    .await;
            }
            let err = error_with_headers("Service temporarily unavailable", 503)
                .and_then(|r| add_security_and_cors_headers(r, hdrs, &ctx.data.cfg));
            return Err(err);
        }
    };

    // SEC-028 (rotation, #31): single-slot read path per
    // Rotation class §10 + structured log schema. The CSRF
    // verifier intentionally consults only the current
    // `SESSION_TOKEN_SECRET`. The `_PREVIOUS` slot remains loaded
    // into `AppState::session_token_secret_previous` for the
    // separate session-cookie verify path (a dual-slot rolling
    // window class) but is NOT consulted here. CSRF tokens expire
    // inside the operator's rotation window (one CSRF TTL between
    // writing the new slot and dropping the old one), so a
    // single-slot read does not regress availability. See
    // `csrf::validate_csrf_token` doc comment for the full §10
    // rationale.
    let config = crate::hosted::endpoints::csrf::CsrfConfig::default();
    match crate::hosted::endpoints::csrf::validate_csrf_token(
        &token,
        expected_session_id,
        &key_bytes,
        config.token_expiration_seconds,
    ) {
        Ok(()) => Ok(()),
        Err(reason) => {
            // R8: emit best-effort off the critical path; fall back to inline.
            let failure_reason = reason.failure_reason();
            if let Some(wctx) = crate::take_worker_context() {
                let logger = ctx.data.audit_logger.clone();
                let ip = client_ip.clone();
                let ep = endpoint.to_string();
                let sid = expected_session_id.to_string();
                wctx.wait_until(async move {
                    logger
                        .log_csrf_validation_failed(&ip, &ep, &sid, failure_reason)
                        .await;
                });
            } else {
                ctx.data
                    .audit_logger
                    .log_csrf_validation_failed(
                        &client_ip,
                        endpoint,
                        expected_session_id,
                        failure_reason,
                    )
                    .await;
            }
            Err(csrf_forbidden_response(hdrs, &ctx.data.cfg))
        }
    }
}

/// Build a 403 response for CSRF rejection with a structured JSON body.
///
/// SECURITY: The response body is deliberately generic; specific failure
/// reasons (`expired`, `invalid_signature`, `session_mismatch`) never surface
/// to the client, only to the audit log. This prevents an attacker from
/// using the endpoint as an oracle to probe valid tokens or session IDs.
fn csrf_forbidden_response(hdrs: &Headers, cfg: &Config) -> worker::Result<Response> {
    // W7-P1: Route through ApiError::forbidden_with_field so the response carries
    // the canonical 5-key envelope `{error, code, field, detail, request_id}`
    // and the rejection is consistent with other 403 paths (origin policy, etc.).
    // The `detail` is a generic, non-oracle string: it does not reveal whether
    // the token was missing, expired, or session-mismatched.
    let mut resp = ApiError::forbidden_with_field(
        "CSRF_INVALID",
        "X-CSRF-Token",
        "Session-bound CSRF token required",
    )
    .to_response()?;
    // Apply baseline security headers so the 403 carries the same HSTS/CSP
    // posture as other rejections (CH-007 parity).
    let security_headers = api_security_headers();
    security_headers.apply(&mut resp)?;
    add_security_and_cors_headers(resp, hdrs, cfg)
}

/// Build the V1 HTTP router, registering every public route.
///
/// Each route closure validates headers, enforces rate limits, deserialises the
/// request body within a size cap, delegates to the domain handler, and applies
/// security and CORS headers to the response.
///
/// # SECURITY: Route categories
///
/// Public routes (`/v1/challenge`, `/v1/verify`, etc.) validate
/// Sec-Fetch metadata and enforce per-client KV-counter rate limits.
/// The sandbox-only route (`/v1/register-test-origin`) is gated on
/// `cfg.environment` and requires a sandbox API key compared with
/// `subtle::ConstantTimeEq`. The catch-all returns 404 with anti-caching
/// headers for web cache deception prevention (ASVS V14.2.5), and includes
/// elevated logging for `/v1/internal/*` probes (internal routes were removed
/// when provii-verifier was merged; the catch-all detection remains as a
/// security control).
pub fn build_router(state: Arc<AppState>) -> Router<'static, Arc<AppState>> {
    let mut router = Router::with_data(state.clone());

    // SECURITY: Basic health check endpoints (unauthenticated for load balancers)
    // These endpoints return minimal information suitable for liveness probes
    router = router
        .get_async("/health", |_req, ctx| async move {
            // L-2: Liveness probes do not need IP hashing. Removed hash_ip call.
            match health_check_basic(ctx.data.clone()).await {
                Ok(health_response) => {
                    // Return 503 when crypto init fails (Unhealthy),
                    // so load balancers stop routing traffic to this instance.
                    let http_status = health_response.status.http_status_code();
                    let mut response =
                        Response::from_json(&health_response)?.with_status(http_status);
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut response)?;
                    Ok(response)
                }
                Err(e) => {
                    console_log!("❌ Basic health check failed: {:?}", e);
                    error_with_headers("Health check failed", 500)
                }
            }
        })
        // rotation-framework version endpoint. Returns the
        // 8-char fingerprint of every active rotation-capable secret slot so
        // the drill workflow's `wait-for-propagation` step can confirm a
        // redeploy actually shifted bindings before continuing. Auth: CF
        // Access in sandbox, status-token in production. See
        // `routes/internal_version.rs` for the auth precedence rules.
        .get_async("/_internal/version", |req, ctx| async move {
            let hdrs = req.headers();
            // Defence in depth: reject any request carrying CF-Connecting-IP
            // before the existing status-token auth runs. /_internal/* is a
            // service-binding-only surface, so an external connecting-IP is
            // unauthorised regardless of token validity. See
            // `reject_external_internal_traffic` for the rationale.
            if let Some(resp) = reject_external_internal_traffic(hdrs, "internal_version") {
                let mut response = resp?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }
            let client_ip = get_client_ip(hdrs);
            let mut response = handle_internal_version(hdrs, &client_ip, &ctx.data).await?;
            let security_headers = api_security_headers();
            security_headers.apply(&mut response)?;
            Ok(response)
        })
        // Push-invalidation of the JWKS issuer registry cache.
        // Called by provii-management via service binding when an issuer is
        // revoked. Clears the in-memory cache and bumps the epoch counter.
        // Auth: reject_external_internal_traffic guard only (no bearer
        // token needed since service bindings are trust-boundary-internal).
        .post_async("/_internal/invalidate-jwks", |req, ctx| async move {
            let hdrs = req.headers();
            if let Some(resp) = reject_external_internal_traffic(hdrs, "invalidate_jwks") {
                let mut response = resp?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }
            // ADV-VA-11-002: Use authenticated handler (belt-and-suspenders
            // with reject_external_internal_traffic).
            let client_ip = get_client_ip(hdrs);
            let mut response = handle_invalidate_jwks_authed(
                &ctx.data.jwks_cache,
                hdrs,
                &ctx.data,
                &ctx.env,
                &client_ip,
            )
            .await?;
            let security_headers = api_security_headers();
            security_headers.apply(&mut response)?;
            Ok(response)
        })
        // Rotation drill: probe HOSTED_MEK by decrypting an envelope and
        // returning the slot that satisfied + a 6-char fingerprint of the
        // recovered plaintext. admin rate limiting: 10/hour cap + 5-attempt
        // lockout, dual-slot bearer + replay-window wrapper.
        .post_async("/_internal/mek-decrypt-probe", |mut req, ctx| async move {
            let hdrs = req.headers().clone();
            if let Some(resp) = reject_external_internal_traffic(&hdrs, "admin-mek-probe") {
                let mut response = resp?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }
            let client_ip = get_client_ip(&hdrs);
            let ip_hash = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let role_tag = "admin-mek-probe";

            let rl_kv = require_rl_kv!(ctx);
            if let Err(retry) = admin_rate_limit_check(&rl_kv, &ip_hash, role_tag).await {
                let mut resp =
                    Response::from_json(&serde_json::json!({ "error": "rate_limited" }))?
                        .with_status(429);
                resp.headers_mut().set("Retry-After", &retry.to_string())?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut resp)?;
                return Ok(resp);
            }

            if let Err(e) =
                authenticate_admin_endpoint(&hdrs, &client_ip, &ctx.data, role_tag).await
            {
                record_admin_auth_failure(&rl_kv, &ip_hash, role_tag).await;
                let mut response = e.to_response()?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }

            let body = match read_limited_body(&mut req, 64 * 1024).await {
                Ok(b) => b,
                Err(_) => return error_with_headers("Request entity too large", 413),
            };
            let mut response = handle_mek_decrypt_probe(&body, &ctx.data).await?;
            let security_headers = api_security_headers();
            security_headers.apply(&mut response)?;
            Ok(response)
        })
        // Rotation drill: replay a captured pre-rotation admin token
        // against the live dual-slot accept path. Returns rejected: true
        // when the previous slot has aged out.
        .post_async(
            "/_internal/replay-saved-pre-rotation-token",
            |mut req, ctx| async move {
                let hdrs = req.headers().clone();
                if let Some(resp) = reject_external_internal_traffic(&hdrs, "admin-replay-token") {
                    let mut response = resp?;
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut response)?;
                    return Ok(response);
                }
                let client_ip = get_client_ip(&hdrs);
                let ip_hash = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
                let role_tag = "admin-replay-token";

                let rl_kv = require_rl_kv!(ctx);
                if let Err(retry) = admin_rate_limit_check(&rl_kv, &ip_hash, role_tag).await {
                    let mut resp =
                        Response::from_json(&serde_json::json!({ "error": "rate_limited" }))?
                            .with_status(429);
                    resp.headers_mut().set("Retry-After", &retry.to_string())?;
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut resp)?;
                    return Ok(resp);
                }

                if let Err(e) =
                    authenticate_admin_endpoint(&hdrs, &client_ip, &ctx.data, role_tag).await
                {
                    record_admin_auth_failure(&rl_kv, &ip_hash, role_tag).await;
                    let mut response = e.to_response()?;
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut response)?;
                    return Ok(response);
                }

                let body = match read_limited_body(&mut req, 16 * 1024).await {
                    Ok(b) => b,
                    Err(_) => return error_with_headers("Request entity too large", 413),
                };
                let mut response =
                    handle_replay_pre_rotation_token(&body, &client_ip, &ctx.data).await?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                Ok(response)
            },
        )
        // Rotation drill: manifest of test-fixture classes this worker
        // can clear. The cleanup CLI calls this first to discover the
        // surface, then issues DELETE per class.
        .get_async("/_internal/test-fixtures", |req, ctx| async move {
            let hdrs = req.headers().clone();
            if let Some(resp) = reject_external_internal_traffic(&hdrs, "admin-fixture-manifest") {
                let mut response = resp?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }
            let client_ip = get_client_ip(&hdrs);
            let ip_hash = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let role_tag = "admin-fixture-manifest";

            let rl_kv = require_rl_kv!(ctx);
            if let Err(retry) = admin_rate_limit_check(&rl_kv, &ip_hash, role_tag).await {
                let mut resp =
                    Response::from_json(&serde_json::json!({ "error": "rate_limited" }))?
                        .with_status(429);
                resp.headers_mut().set("Retry-After", &retry.to_string())?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut resp)?;
                return Ok(resp);
            }

            if let Err(e) =
                authenticate_admin_endpoint(&hdrs, &client_ip, &ctx.data, role_tag).await
            {
                record_admin_auth_failure(&rl_kv, &ip_hash, role_tag).await;
                let mut response = e.to_response()?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }

            let mut response = handle_test_fixtures_manifest().await?;
            let security_headers = api_security_headers();
            security_headers.apply(&mut response)?;
            Ok(response)
        })
        // Rotation drill: clear test-only entries for a named fixture
        // class. The class is supplied as a path parameter; only `bans`
        // is currently supported.
        .delete_async("/_internal/test-fixtures/:class", |req, ctx| async move {
            let hdrs = req.headers().clone();
            if let Some(resp) = reject_external_internal_traffic(&hdrs, "admin-fixture-delete") {
                let mut response = resp?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }
            let client_ip = get_client_ip(&hdrs);
            let ip_hash = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let class = ctx
                .param("class")
                .map(|s| s.to_string())
                .unwrap_or_default();
            let role_tag = format!("admin-fixture:{}", class);

            let rl_kv = require_rl_kv!(ctx);
            if let Err(retry) = admin_rate_limit_check(&rl_kv, &ip_hash, &role_tag).await {
                let mut resp =
                    Response::from_json(&serde_json::json!({ "error": "rate_limited" }))?
                        .with_status(429);
                resp.headers_mut().set("Retry-After", &retry.to_string())?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut resp)?;
                return Ok(resp);
            }

            if let Err(e) =
                authenticate_admin_endpoint(&hdrs, &client_ip, &ctx.data, &role_tag).await
            {
                record_admin_auth_failure(&rl_kv, &ip_hash, &role_tag).await;
                let mut response = e.to_response()?;
                let security_headers = api_security_headers();
                security_headers.apply(&mut response)?;
                return Ok(response);
            }

            let mut response = handle_delete_test_fixtures(&class, &ctx.data).await?;
            let security_headers = api_security_headers();
            security_headers.apply(&mut response)?;
            Ok(response)
        })
        // SECURITY: Detailed health/metrics endpoint (requires authentication)
        // This endpoint returns detailed system information and requires API key
        .get_async("/health/detailed", |req, ctx| async move {
            let hdrs = req.headers();
            let client_ip = get_client_ip(hdrs);

            // M-F2: Per-IP rate limit (30/hour) before authentication to prevent brute force.
            let ip_hash = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result =
                    crate::rate_limiting::check_per_ip_limit(&rl_kv, "health_ip:", &ip_hash, 30)
                        .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] /health/detailed rate limit exceeded for hashed IP: {}",
                        ip_hash.get(..16).unwrap_or(&ip_hash)
                    );
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, hdrs, &ctx.data.cfg);
                }
            }

            // The dual-slot STATUS_API_TOKEN pair is resolved by
            // `authenticate_status_endpoint` through the five-minute TTL
            // `status_token_cache` on every request rather than pinned at
            // cold start. The fingerprints attached to the response are
            // pulled from the same cache so the response carries a value
            // consistent with the slot the verify path accepted against.
            match authenticate_status_endpoint(
                &ctx.data.env,
                hdrs,
                ctx.data.status_token_role,
                &ctx.data.audit_logger,
                &client_ip,
                Some(&ctx.data.origin_policy_store),
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(outcome) => {
                    // SECURITY: Hash IP for GDPR compliance
                    console_log!(
                        "[SECURITY] Detailed health check authorized for IP: {}",
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                    // AL-030: Audit status endpoint access (parity with /metrics).
                    ctx.data
                        .audit_logger
                        .log_status_endpoint_access(&client_ip, "health_detailed", true)
                        .await;

                    // F-01 (#72): rolling-window timestamp + per-request
                    // nonce dedupe on top of the bearer auth above. Auth
                    // before replay so an unauthenticated attacker
                    // cannot burn nonces or probe the server-clock
                    // window. Mirrors the `/_internal/version` wrapper.
                    if let Err(e) = crate::security::status_auth::enforce_internal_replay_window(
                        hdrs,
                        &ctx.data.nonce_store,
                        "health_detailed",
                        &ctx.data.audit_logger,
                        &client_ip,
                        &ctx.data.ip_hash_salt,
                    )
                    .await
                    {
                        console_log!(
                            "[/health/detailed] replay window rejection for ip_hash={}",
                            hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                        );
                        let mut response = e.to_response()?;
                        let security_headers = api_security_headers();
                        security_headers.apply(&mut response)?;
                        return Ok(response);
                    }

                    match health_check_detailed(ctx.data.clone()).await {
                        Ok(health_response) => {
                            // Return 503 when subsystems are unhealthy,
                            // so monitoring and load balancers detect degradation.
                            let http_status = health_response.status.http_status_code();
                            let mut response =
                                Response::from_json(&health_response)?.with_status(http_status);
                            let security_headers = api_security_headers();
                            security_headers.apply(&mut response)?;
                            // emit the per-request `secret_version`
                            // log line + apply the `x-secret-version` header
                            // carrying the STATUS_API_TOKEN slot that satisfied.
                            let used = match outcome.slot {
                                crate::security::StatusAuthSlot::Current => Some(
                                    crate::security::secret_versions::RotationSlot::Current,
                                ),
                                crate::security::StatusAuthSlot::Previous => Some(
                                    crate::security::secret_versions::RotationSlot::Previous,
                                ),
                                crate::security::StatusAuthSlot::ApiKey => None,
                            };
                            let fps = crate::security::status_auth::current_fingerprints(
                                &ctx.data.env,
                            )
                            .await;
                            let line = crate::security::secret_versions::SecretVersionLine::single_for_slot(
                                ctx.data.status_token_role,
                                &fps.current,
                                &fps.previous,
                                used,
                            );
                            line.emit_log("GET /health/detailed");
                            line.apply_header(&mut response)?;
                            Ok(response)
                        }
                        Err(e) => {
                            console_log!("❌ Detailed health check failed: {:?}", e);
                            error_with_headers("Health check failed", 500)
                        }
                    }
                }
                Err(e) => {
                    // SECURITY: Hash IP for GDPR compliance
                    console_log!(
                        "[SECURITY] Detailed health check denied for IP: {}",
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                    let mut response = e.to_response()?;
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut response)?;
                    Ok(response)
                }
            }
        })
        // SECURITY: Metrics endpoint (alias to /health/detailed, requires authentication)
        .get_async("/metrics", |req, ctx| async move {
            let hdrs = req.headers();
            let client_ip = get_client_ip(hdrs);

            // M-F2: Per-IP rate limit (30/hour) before authentication to prevent brute force.
            let ip_hash = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result =
                    crate::rate_limiting::check_per_ip_limit(&rl_kv, "metrics_ip:", &ip_hash, 30)
                        .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] /metrics rate limit exceeded for hashed IP: {}",
                        ip_hash.get(..16).unwrap_or(&ip_hash)
                    );
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, hdrs, &ctx.data.cfg);
                }
            }

            // Dual-slot pair resolved through the five-minute TTL
            // `status_token_cache`. See /health/detailed call site above.
            match authenticate_status_endpoint(
                &ctx.data.env,
                hdrs,
                ctx.data.status_token_role,
                &ctx.data.audit_logger,
                &client_ip,
                Some(&ctx.data.origin_policy_store),
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(outcome) => {
                    // SECURITY: Hash IP for GDPR compliance
                    console_log!(
                        "[SECURITY] Metrics endpoint authorized for IP: {}",
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                    // AL-031: Audit status endpoint access.
                    ctx.data
                        .audit_logger
                        .log_status_endpoint_access(&client_ip, "metrics", true)
                        .await;

                    // F-01 (#72): replay-window check after the bearer
                    // verified. Same ordering rationale as the sibling
                    // `/health/detailed` and `/_internal/version` wrappers.
                    if let Err(e) = crate::security::status_auth::enforce_internal_replay_window(
                        hdrs,
                        &ctx.data.nonce_store,
                        "metrics",
                        &ctx.data.audit_logger,
                        &client_ip,
                        &ctx.data.ip_hash_salt,
                    )
                    .await
                    {
                        console_log!(
                            "[/metrics] replay window rejection for ip_hash={}",
                            hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                        );
                        let mut response = e.to_response()?;
                        let security_headers = api_security_headers();
                        security_headers.apply(&mut response)?;
                        return Ok(response);
                    }

                    match health_check_detailed(ctx.data.clone()).await {
                        Ok(health_response) => {
                            // Return 503 when subsystems are unhealthy.
                            let http_status = health_response.status.http_status_code();
                            let mut response =
                                Response::from_json(&health_response)?.with_status(http_status);
                            let security_headers = api_security_headers();
                            security_headers.apply(&mut response)?;
                            // emit the per-request `secret_version`
                            // log line + apply the `x-secret-version` header
                            // carrying the STATUS_API_TOKEN slot that satisfied.
                            let used = match outcome.slot {
                                crate::security::StatusAuthSlot::Current => Some(
                                    crate::security::secret_versions::RotationSlot::Current,
                                ),
                                crate::security::StatusAuthSlot::Previous => Some(
                                    crate::security::secret_versions::RotationSlot::Previous,
                                ),
                                crate::security::StatusAuthSlot::ApiKey => None,
                            };
                            let fps = crate::security::status_auth::current_fingerprints(
                                &ctx.data.env,
                            )
                            .await;
                            let line = crate::security::secret_versions::SecretVersionLine::single_for_slot(
                                ctx.data.status_token_role,
                                &fps.current,
                                &fps.previous,
                                used,
                            );
                            line.emit_log("GET /metrics");
                            line.apply_header(&mut response)?;
                            Ok(response)
                        }
                        Err(e) => {
                            console_log!("❌ Metrics check failed: {:?}", e);
                            error_with_headers("Metrics unavailable", 500)
                        }
                    }
                }
                Err(e) => {
                    // SECURITY: Hash IP for GDPR compliance
                    console_log!(
                        "[SECURITY] Metrics endpoint denied for IP: {}",
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                    let mut response = e.to_response()?;
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut response)?;
                    Ok(response)
                }
            }
        })
        // CSP violation reporting endpoint (ASVS V3.4.7)
        .post_async("/v1/csp-report", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // SECURITY: ASVS V3.4.7 - Rate limit CSP reports to prevent DoS
            let client_ip = hdrs
                .get("CF-Connecting-IP")
                .ok()
                .flatten()
                .unwrap_or_else(|| "unknown".to_string());

            // SECURITY (EA-016): ASVS V3.5.8 - Validate Sec-Fetch metadata headers.
            // Uses CSP-specific validator that permits Sec-Fetch-Mode: no-cors, which
            // browsers use when sending CSP violation reports via the Reporting API.
            if let Err(e) = validate_fetch_metadata_csp(&hdrs) {
                console_log!(
                    "[SECURITY] CSP report blocked - failed Sec-Fetch validation: {:?}",
                    e
                );
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                return error_with_headers("Access denied", 403);
            }

            // Check rate limit: 10 CSP reports per minute per IP
            let rate_limit_key = format!(
                "csp_report:{}",
                crate::security::hash_ip(&client_ip, &ctx.data.ip_hash_salt)
            );
            let rate_limit_kv = match ctx.kv("VERIFIER_KV_RATE_LIMITS") {
                Ok(kv) => kv,
                Err(e) => {
                    console_log!("[CSP] KV binding VERIFIER_KV_RATE_LIMITS failed: {:?}", e);
                    return error_with_headers("Service temporarily unavailable", 503);
                }
            };

            let current_count: u32 = match rate_limit_kv
                .get(&rate_limit_key)
                .text()
                .await
            {
                Ok(val) => val.and_then(|s: String| s.parse::<u32>().ok()).unwrap_or(0),
                Err(e) => {
                    console_log!("[CSP] KV rate limit read failed for key {}: {:?}", rate_limit_key, e);
                    return error_with_headers("Service temporarily unavailable", 503);
                }
            };

            if current_count >= 10 {
                console_log!(
                    "[SECURITY] CSP report rate limit exceeded for IP: {}",
                    crate::security::hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                );
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "csp_report_rate_limit_exceeded"));
                return error_with_headers("Too Many Requests", 429);
            }

            // Increment rate limit counter (60 second TTL)
            let new_count = current_count.saturating_add(1);

            // Fail-open: CSP reports carry security signal; losing them on
            // transient KV write failure is worse than allowing an un-counted report.
            match rate_limit_kv.put(&rate_limit_key, new_count.to_string()) {
                Ok(builder) => {
                    if let Err(e) = builder.expiration_ttl(60).execute().await {
                        console_log!(
                            "[CSP] KV rate limit write execute failed for key {}: {:?}",
                            rate_limit_key, e
                        );
                    }
                }
                Err(e) => {
                    console_log!(
                        "[CSP] KV rate limit put builder failed for key {}: {:?}",
                        rate_limit_key, e
                    );
                }
            }

            console_log!("[SECURITY] CSP report received (count: {})", new_count);

            match handle_csp_report(req, ctx).await {
                // L-3: handle_csp_report() already applies security headers internally.
                // Only the error fallback needs them applied here.
                Ok(response) => Ok(response),
                Err(e) => {
                    console_log!("[CSP-REPORT] Error handling report: {:?}", e);
                    // CH-008: Apply security headers to error fallback response.
                    let mut fallback = Response::empty()?.with_status(204);
                    let security_headers = api_security_headers();
                    security_headers.apply(&mut fallback)?;
                    Ok(fallback)
                }
            }
        })
        // OPTIONS handlers for CORS preflight.
        .options("/v1/challenge", |req, ctx| {
            handle_options(req.headers(), &ctx.data.cfg)
        })
        .options("/v1/challenge/:sid", |req, ctx| {
            handle_options(req.headers(), &ctx.data.cfg)
        })
        .options("/v1/challenge/:sid/redeem", |req, ctx| {
            handle_options(req.headers(), &ctx.data.cfg)
        })
        .options("/v1/verify", |req, ctx| {
            handle_options(req.headers(), &ctx.data.cfg)
        })
        .options("/v1/challenge/:sid/details", |req, ctx| {
            handle_options(req.headers(), &ctx.data.cfg)
        })
        .options("/v1/challenge/by-code/:code", |req, ctx| {
            handle_options(req.headers(), &ctx.data.cfg)
        })
        // V1 API routes.
        // OpenAPI specification endpoint.
        .get_async("/v1/openapi.json", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // Read the advertised API version from the environment.
            let version = ctx
                .env
                .var("API_VERSION")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "1.0.0".to_string());

            let base_url = ctx.data.cfg.api_base_url.clone();

            // CH-009: Route openapi.json through the standard security + CORS header pipeline.
            let rsp = crate::routes::openapi::serve_openapi_json(&version, &base_url)?;
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // Documentation UI endpoint.
        .get("/v1/docs", |_req, _ctx| {
            // Generate cryptographic nonce for CSP (ASVS V2.2.3, V3.6.1)
            let nonce = crate::security::headers::generate_csp_nonce();

            // Generate Swagger UI HTML with SRI-protected CDN assets and nonce-based CSP
            let swagger_html = generate_swagger_ui_html("/v1/openapi.json", &nonce);
            let mut response = Response::from_html(&swagger_html)?;

            // Apply security headers with nonce-based CSP
            let docs_headers = docs_security_headers(&nonce);
            docs_headers.apply(&mut response)?;

            // Add request identifier for traceability
            let request_id = uuid::Uuid::new_v4().to_string();
            response.headers_mut().set("X-Request-Id", &request_id)?;

            Ok(response)
        })
        // Create challenge endpoint (browser-friendly JSON).
        .post_async("/v1/challenge", |mut req, ctx| async move {
            let hdrs = req.headers().clone();
            let _endpoint = "/v1/challenge";

            // SECURITY: ASVS V3.5.8 - Validate Sec-Fetch-* headers to prevent cross-site attacks
            if let Err(e) = validate_fetch_metadata(&hdrs) {
                console_log!("[SECURITY] Sec-Fetch validation failed for /v1/challenge");
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                let err_response = e.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SEC-011: Per-IP rate limit enforced BEFORE the per-client quota.
            // An attacker who rotates `X-Client-Id` (or forges origins) can mint
            // fresh per-customer buckets; the per-IP cap is additive defence that
            // binds the request to the source address.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let per_ip_limit: u32 = env_var_u32(&ctx.env, "PER_IP_LIMIT_PER_HOUR", 1000);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_expert_ip_limit(
                    &rl_kv,
                    &hashed_ip,
                    "challenge",
                    per_ip_limit,
                )
                .await;
                if !result.allowed {
                    console_log!("[RateLimit] Per-IP challenge limit exceeded");
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &hashed_ip,
                        "challenge_per_ip",
                        &client_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // KV-counter rate limiting: per-customer hourly quota
            let client_id = get_client_id(&hdrs, &ctx.data.ip_hash_salt);
            let default_quota: u32 = env_var_u32(&ctx.env, "DEFAULT_QUOTA_PER_HOUR", 500);

            let rl_quota: Option<crate::rate_limiting::RateLimitResult>;
            {
                let rl_kv = require_rl_kv!(ctx);
                let cfg_kv = ctx.kv(KV_RATE_LIMITS).unwrap_or_else(|_| rl_kv.clone());
                let result = crate::rate_limiting::check_quota(
                    &rl_kv,
                    &cfg_kv,
                    &client_id,
                    "challenge",
                    default_quota,
                )
                .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] Challenge rate limit exceeded for client '{}'",
                        client_id
                    );
                    // AL-024: Audit rate limit exceeded event.
                    let rl_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &client_id,
                        "challenge",
                        &rl_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                rl_quota = Some(result);
            }

            // Enforce the expected JSON content type.
            if !is_json(&hdrs) {
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "invalid_content_type:challenge"));
                let err_response = ApiError::UnsupportedMediaType.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // Read the body while enforcing the size limit.
            let body_bytes = match read_limited_body(&mut req, 1024).await {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/challenge] Request too large: {:?}", e);
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "oversized_body:challenge"));
                    let err_response = ApiError::PayloadTooLarge(Some("Request too large".into()))
                        .to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            // Deserialise using the strict API types.
            let body: CreateChallengeRequest = match serde_json::from_slice(&body_bytes) {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/challenge] Failed to parse JSON: {:?}", e);
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "json_parse_failure:challenge"));
                    // PG-VAL-016: When the failure points at a specific top-level
                    // field (e.g. `code_challenge` not 32 bytes, `expires_in` out
                    // of range), surface that as `field` so devs aren't told the
                    // whole body is malformed when only one value is wrong. When
                    // the parse failure is structural (missing top-level field,
                    // unknown extra field, syntax error), keep `field: body`.
                    let (field_name, detail_msg) =
                        infer_create_challenge_schema_field(&body_bytes, &e);
                    let err_response =
                        ApiError::bad_request("BODY_SCHEMA_INVALID", Some(&field_name), detail_msg)
                            .to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let mut rsp = match create_challenge(ctx.data.clone(), hdrs.clone(), body).await {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response("/v1/challenge", &e, &hdrs, &ctx.data.cfg);
                }
            };

            if let Some(ref rl) = rl_quota {
                let _ = crate::rate_limiting::apply_rate_limit_headers(&mut rsp, rl);
            }
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // Retrieve full challenge details for native clients (capability-based: UUID is the credential).
        .get_async("/v1/challenge/:sid/details", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // CH-016: Validate Sec-Fetch metadata on challenge details endpoint.
            if let Err(e) = validate_fetch_metadata(&hdrs) {
                console_log!(
                    "[SECURITY] Sec-Fetch validation failed for /v1/challenge/:sid/details"
                );
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                let err_response = e.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SEC-011: Per-IP rate limit enforced before the per-client quota.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let per_ip_limit: u32 = env_var_u32(&ctx.env, "PER_IP_LIMIT_PER_HOUR", 1000);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_expert_ip_limit(
                    &rl_kv,
                    &hashed_ip,
                    "challenge_details",
                    per_ip_limit,
                )
                .await;
                if !result.allowed {
                    console_log!("[RateLimit] Per-IP challenge_details limit exceeded");
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &hashed_ip,
                        "challenge_details_per_ip",
                        &client_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // KV-counter rate limiting: per-customer hourly quota
            let client_id = get_client_id(&hdrs, &ctx.data.ip_hash_salt);
            let default_quota: u32 = env_var_u32(&ctx.env, "DEFAULT_QUOTA_PER_HOUR", 500);

            let rl_quota: Option<crate::rate_limiting::RateLimitResult>;
            {
                let rl_kv = require_rl_kv!(ctx);
                let cfg_kv = ctx.kv(KV_RATE_LIMITS).unwrap_or_else(|_| rl_kv.clone());
                let result = crate::rate_limiting::check_quota(
                    &rl_kv,
                    &cfg_kv,
                    &client_id,
                    "challenge_details",
                    default_quota,
                )
                .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] Details rate limit exceeded for client '{}'",
                        client_id
                    );
                    // AL-024: Audit rate limit exceeded event.
                    let rl_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &client_id,
                        "challenge_details",
                        &rl_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                rl_quota = Some(result);
            }

            let sid_str = ctx
                .param("sid")
                .ok_or_else(|| WorkerError::RustError("Missing sid".into()))?;

            let sid = match VALIDATOR.validate_uuid(sid_str, "sid") {
                Ok(id) => id,
                Err(e) => {
                    let err_response = e.to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            // Audit log: this endpoint exposes submit_secret via UUID capability.
            let ip = get_client_ip(&hdrs);
            ctx.data
                .audit_logger
                .log_suspicious_activity(&ip, "challenge_details_accessed")
                .await;

            let mut rsp = match get_challenge_details(ctx.data.clone(), sid).await {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/challenge/:sid/details",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };
            if let Some(ref rl) = rl_quota {
                let _ = crate::rate_limiting::apply_rate_limit_headers(&mut rsp, rl);
            }
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // Look up challenge by short code (for accessibility/manual entry).
        .get_async("/v1/challenge/by-code/:code", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // CH-016: Validate Sec-Fetch metadata on by-code endpoint.
            if let Err(e) = validate_fetch_metadata(&hdrs) {
                console_log!(
                    "[SECURITY] Sec-Fetch validation failed for /v1/challenge/by-code/:code"
                );
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                let err_response = e.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // Per-IP rate limit for short code enumeration prevention.
            // Short codes have ~40 bits of entropy, so rate limiting per IP
            // is critical to prevent brute force enumeration.
            let ip = get_client_ip(&hdrs);
            // SECURITY: Hash IP before use as KV key (R-16, GDPR data minimisation).
            let ip_hashed = hash_ip(&ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let sc_limit: u32 = env_var_u32(&ctx.env, "SHORT_CODE_LIMIT_PER_HOUR", 60);
                let result = crate::rate_limiting::check_per_ip_limit(
                    &rl_kv,
                    "short_code:",
                    &ip_hashed,
                    sc_limit,
                )
                .await;
                if !result.allowed {
                    console_log!("[RateLimit] Short code enumeration limit exceeded for IP");
                    // AL-036: Audit short code enumeration rate limit (40-bit entropy makes brute force higher risk)
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &ip_hashed,
                        "short_code_enumeration",
                        &ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // KV-counter rate limiting: per-customer hourly quota
            let client_id = get_client_id(&hdrs, &ctx.data.ip_hash_salt);
            let default_quota: u32 = env_var_u32(&ctx.env, "DEFAULT_QUOTA_PER_HOUR", 500);

            let rl_quota: Option<crate::rate_limiting::RateLimitResult>;
            {
                let rl_kv = require_rl_kv!(ctx);
                let cfg_kv = ctx.kv(KV_RATE_LIMITS).unwrap_or_else(|_| rl_kv.clone());
                let result = crate::rate_limiting::check_quota(
                    &rl_kv,
                    &cfg_kv,
                    &client_id,
                    "by_code",
                    default_quota,
                )
                .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] Short code rate limit exceeded for client '{}'",
                        client_id
                    );
                    // AL-024: Audit rate limit exceeded event.
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &client_id,
                        "by_code",
                        &ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                rl_quota = Some(result);
            }

            let code = ctx
                .param("code")
                .ok_or_else(|| WorkerError::RustError("Missing code parameter".into()))?;

            // Validate short code format (12 digits)
            let short_code = match VALIDATOR.validate_string(code, "code", 12) {
                Ok(c) if c.len() == 12 && c.chars().all(|ch| ch.is_ascii_digit()) => c,
                _ => {
                    let err_response = ApiError::BadRequest(Some(
                        "Invalid short code format (must be 12 digits)".into(),
                    ))
                    .to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let client_ip = get_client_ip(&hdrs);
            let mut rsp =
                match get_challenge_by_short_code(ctx.data.clone(), short_code, &client_ip).await {
                    Ok(response) => response,
                    Err(e) => {
                        return handler_error_to_response(
                            "/v1/challenge/by-code/:code",
                            &e,
                            &hdrs,
                            &ctx.data.cfg,
                        );
                    }
                };
            if let Some(ref rl) = rl_quota {
                let _ = crate::rate_limiting::apply_rate_limit_headers(&mut rsp, rl);
            }
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // Poll the status of a challenge.
        .get_async("/v1/challenge/:sid", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // CH-017: Validate Sec-Fetch metadata on challenge poll endpoint.
            if let Err(e) = validate_fetch_metadata(&hdrs) {
                console_log!("[SECURITY] Sec-Fetch validation failed for /v1/challenge/:sid");
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                let err_response = e.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SEC-011: Per-IP rate limit enforced before the per-client quota.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let per_ip_limit: u32 = env_var_u32(&ctx.env, "PER_IP_LIMIT_PER_HOUR", 1000);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_expert_ip_limit(
                    &rl_kv,
                    &hashed_ip,
                    "status",
                    per_ip_limit,
                )
                .await;
                if !result.allowed {
                    console_log!("[RateLimit] Per-IP status poll limit exceeded");
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &hashed_ip,
                        "status_per_ip",
                        &client_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // KV-counter rate limiting: per-customer hourly quota for status polling
            let client_id = get_client_id(&hdrs, &ctx.data.ip_hash_salt);
            let default_quota: u32 = env_var_u32(&ctx.env, "DEFAULT_QUOTA_PER_HOUR", 500);

            let rl_quota: Option<crate::rate_limiting::RateLimitResult>;
            {
                let rl_kv = require_rl_kv!(ctx);
                let cfg_kv = ctx.kv(KV_RATE_LIMITS).unwrap_or_else(|_| rl_kv.clone());
                let result = crate::rate_limiting::check_quota(
                    &rl_kv,
                    &cfg_kv,
                    &client_id,
                    "status",
                    default_quota,
                )
                .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] Status poll rate limit exceeded for client '{}'",
                        client_id
                    );
                    // AL-024: Audit rate limit exceeded event.
                    let rl_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &client_id,
                        "status",
                        &rl_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                rl_quota = Some(result);
            }

            let sid_str = ctx
                .param("sid")
                .ok_or_else(|| WorkerError::RustError("Missing sid".into()))?;

            let sid = match VALIDATOR.validate_uuid(sid_str, "sid") {
                Ok(id) => id,
                Err(e) => {
                    let err_response = e.to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let mut rsp = match poll_challenge(ctx.data.clone(), hdrs.clone(), sid).await {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/challenge/:sid",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };
            if let Some(ref rl) = rl_quota {
                let _ = crate::rate_limiting::apply_rate_limit_headers(&mut rsp, rl);
            }
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // Redeem a challenge using the PKCE verifier.
        .post_async("/v1/challenge/:sid/redeem", |mut req, ctx| async move {
            let hdrs = req.headers().clone();
            let endpoint = "/v1/challenge/*/redeem";

            // IV-104/IV-154: Enforce Content-Type: application/json before parsing.
            if !is_json(&hdrs) {
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "invalid_content_type:redeem"));
                let err_response = ApiError::UnsupportedMediaType.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SECURITY: ASVS V3.5.8 - Validate Sec-Fetch-* headers to prevent cross-site attacks
            if let Err(e) = validate_fetch_metadata(&hdrs) {
                console_log!("[SECURITY] Sec-Fetch validation failed for /v1/challenge/redeem");
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                let err_response = e.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SEC-011: Per-IP rate limit enforced before the per-client quota.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let per_ip_limit: u32 = env_var_u32(&ctx.env, "PER_IP_LIMIT_PER_HOUR", 1000);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_expert_ip_limit(
                    &rl_kv,
                    &hashed_ip,
                    "redeem",
                    per_ip_limit,
                )
                .await;
                if !result.allowed {
                    console_log!("[RateLimit] Per-IP redeem limit exceeded");
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &hashed_ip,
                        "redeem_per_ip",
                        &client_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // KV-counter rate limiting: per-customer hourly quota
            let client_id = get_client_id(&hdrs, &ctx.data.ip_hash_salt);
            let default_quota: u32 = env_var_u32(&ctx.env, "DEFAULT_QUOTA_PER_HOUR", 500);

            let rl_quota: Option<crate::rate_limiting::RateLimitResult>;
            {
                let rl_kv = require_rl_kv!(ctx);
                let cfg_kv = ctx.kv(KV_RATE_LIMITS).unwrap_or_else(|_| rl_kv.clone());
                let result = crate::rate_limiting::check_quota(
                    &rl_kv,
                    &cfg_kv,
                    &client_id,
                    "redeem",
                    default_quota,
                )
                .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] Redeem rate limit exceeded for client '{}'",
                        client_id
                    );
                    // AL-024: Audit rate limit exceeded event.
                    let rl_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &client_id,
                        "redeem",
                        &rl_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                rl_quota = Some(result);
            }

            // Enforce the maximum request body size.
            if let Err(e) = validate_request_size(&hdrs, endpoint) {
                return add_security_and_cors_headers(e.to_response()?, &hdrs, &ctx.data.cfg);
            }

            let sid_str = ctx
                .param("sid")
                .ok_or_else(|| WorkerError::RustError("Missing sid".into()))?;

            let sid = match VALIDATOR.validate_uuid(sid_str, "sid") {
                Ok(id) => id,
                Err(e) => {
                    let err_response = e.to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            // IV-103/IV-151: Read body with enforced size limit before parsing JSON.
            // 8 KB is generous for a redeem request which only contains a PKCE verifier.
            let body_bytes = match read_limited_body(&mut req, 8 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/challenge/redeem] Request too large: {:?}", e);
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "oversized_body:redeem"));
                    let err_response = ApiError::PayloadTooLarge(Some("Request too large".into()))
                        .to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let body: RedeemRequest = match serde_json::from_slice(&body_bytes) {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/challenge/redeem] Failed to parse JSON: {:?}", e);
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "json_parse_failure:redeem"));
                    // PG-VAL-016: Localise the offending field when serde
                    // identifies it (`code_verifier` length, missing field,
                    // unknown extra field). Fall back to `body` for purely
                    // structural failures (syntax, EOF).
                    let (field_name, detail_msg) = infer_redeem_schema_field(&body_bytes, &e);
                    let err_response =
                        ApiError::bad_request("BODY_SCHEMA_INVALID", Some(&field_name), detail_msg)
                            .to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let mut rsp = match redeem_challenge(ctx.data.clone(), hdrs.clone(), sid, body).await {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/challenge/:sid/redeem",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };
            if let Some(ref rl) = rl_quota {
                let _ = crate::rate_limiting::apply_rate_limit_headers(&mut rsp, rl);
            }
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // Submit verification; PKCE enforcement happens in the core logic.
        .post_async("/v1/verify", |mut req, ctx| async move {
            let hdrs = req.headers().clone();
            let endpoint = "/v1/verify";

            // IV-102: Enforce Content-Type: application/json before parsing.
            if !is_json(&hdrs) {
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "invalid_content_type:verify"));
                let err_response = ApiError::UnsupportedMediaType.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SECURITY: ASVS V3.5.8 - Validate Sec-Fetch-* headers to prevent cross-site attacks
            if let Err(e) = validate_fetch_metadata(&hdrs) {
                console_log!("[SECURITY] Sec-Fetch validation failed for /v1/verify");
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                let err_response = e.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // SEC-011: Per-IP rate limit enforced before the per-client quota.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            let per_ip_limit: u32 = env_var_u32(&ctx.env, "PER_IP_LIMIT_PER_HOUR", 1000);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_expert_ip_limit(
                    &rl_kv,
                    &hashed_ip,
                    "verify",
                    per_ip_limit,
                )
                .await;
                if !result.allowed {
                    console_log!("[RateLimit] Per-IP verify limit exceeded");
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &hashed_ip,
                        "verify_per_ip",
                        &client_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // KV-counter rate limiting: per-customer hourly quota
            let client_id = get_client_id(&hdrs, &ctx.data.ip_hash_salt);
            let default_quota: u32 = env_var_u32(&ctx.env, "DEFAULT_QUOTA_PER_HOUR", 500);

            let rl_quota: Option<crate::rate_limiting::RateLimitResult>;
            {
                let rl_kv = require_rl_kv!(ctx);
                let cfg_kv = ctx.kv(KV_RATE_LIMITS).unwrap_or_else(|_| rl_kv.clone());
                let result = crate::rate_limiting::check_quota(
                    &rl_kv,
                    &cfg_kv,
                    &client_id,
                    "verify",
                    default_quota,
                )
                .await;
                if !result.allowed {
                    console_log!(
                        "[RateLimit] Verify rate limit exceeded for client '{}'",
                        client_id
                    );
                    // AL-024: Audit rate limit exceeded event.
                    let rl_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        &client_id,
                        "verify",
                        &rl_ip,
                        result.current_count,
                        result.limit,
                    ));
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                rl_quota = Some(result);
            }

            // Enforce the maximum request payload size via Content-Length header.
            if let Err(e) = validate_request_size(&hdrs, endpoint) {
                return add_security_and_cors_headers(e.to_response()?, &hdrs, &ctx.data.cfg);
            }

            // CIV-113: Read body with enforced size limit before parsing JSON.
            // The Content-Length check above can be bypassed (chunked encoding, missing
            // header). read_limited_body reads the actual bytes and rejects oversized
            // payloads. 128 KB matches the limit in VALIDATOR.validate_request_size.
            let body_bytes = match read_limited_body(&mut req, 128 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/verify] Request too large: {:?}", e);
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "oversized_body:verify"));
                    let err_response = ApiError::PayloadTooLarge(Some("Request too large".into()))
                        .to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let body: SubmitProofRequest = match serde_json::from_slice(&body_bytes) {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/verify] Failed to parse JSON: {:?}", e);
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "json_parse_failure:verify"));
                    let err_response = error_with_headers("Invalid JSON", 400)?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }
            };

            let mut rsp = match submit_verification(ctx.data.clone(), hdrs.clone(), body).await {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response("/v1/verify", &e, &hdrs, &ctx.data.cfg);
                }
            };
            if let Some(ref rl) = rl_quota {
                let _ = crate::rate_limiting::apply_rate_limit_headers(&mut rsp, rl);
            }
            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        });

    // SANDBOX ONLY: Add test origin registration endpoint
    // This allows external developers to register their origins for testing
    // Only available in sandbox environment, returns 404 in production
    if state.cfg.environment == "sandbox" {
        router = router
            .options("/v1/register-test-origin", |req, ctx| {
                handle_options(req.headers(), &ctx.data.cfg)
            })
            .post_async("/v1/register-test-origin", |mut req, ctx| async move {
                let hdrs = req.headers().clone();

                // Double-check we're in sandbox environment
                if ctx.data.cfg.environment != "sandbox" {
                    return error_with_headers("Not found", 404);
                }

                // SECURITY: ASVS V3.5.8 - Validate Sec-Fetch-* headers to prevent cross-site attacks
                if let Err(e) = validate_fetch_metadata(&hdrs) {
                    console_log!("[SECURITY] Sec-Fetch validation failed for /v1/register-test-origin");
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "sec_fetch_violation"));
                    let err_response = e.to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }

                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct RegisterRequest {
                    origin: String,
                    /// Minimum age in years (default 18). Used for over_age proofs.
                    #[serde(default = "default_min_age_years")]
                    min_age_years: u32,
                    /// Proof direction: "over_age" (default) or "under_age".
                    proof_direction: Option<String>,
                    /// Maximum age in years. Required when proof_direction is "under_age".
                    max_age_years: Option<u32>,
                    api_key: String,
                    contact_email: Option<String>,
                }

                fn default_min_age_years() -> u32 { 18 }

                // ST-VA-026: Maximum lengths for RegisterRequest string fields.
                // Prevents unbounded strings from inflating KV keys and values.
                const MAX_ORIGIN_LEN: usize = 2048;
                const MAX_API_KEY_LEN: usize = 256;
                const MAX_EMAIL_LEN: usize = 320;

                // Sandbox test origins expire after 72 hours for weekend testing.
                const TTL_SECONDS: u64 = 259200;

                // IV-153: Read body with enforced size limit before parsing JSON.
                // 4 KB is generous for a registration request.
                let body_bytes = match read_limited_body(&mut req, 4 * 1024).await {
                    Ok(b) => b,
                    Err(e) => {
                        console_log!("[register-test-origin] Request too large: {:?}", e);
                        return error_with_headers("Request too large", 413);
                    }
                };

                // W6-NT3 / W7-S1: Verify the docs-gateway HMAC over the raw
                // body before any JSON parse. The gateway signs every outbound
                // call to this endpoint with the same SANDBOX_API_KEY the
                // caller then presents in the body's `api_key` field. Checking
                // the HMAC first means a tampered body is rejected before the
                // JSON parser runs, and it binds the tag to the exact bytes
                // the gateway generated so modification in transit
                // invalidates the request.
                //
                // Fail-closed alignment with provii-issuer/src/routes.rs: if the
                // cached secret is unavailable (Secrets Store read failed at
                // startup), we must reject the call as `docs_hmac_invalid`
                // rather than silently skipping HMAC verification. An
                // attacker-controlled body must never reach `serde_json::
                // from_slice` on an unauthenticated code path.
                // LT-001: accept the X-Docs-Hmac signed with EITHER the shared
                // SANDBOX_API_KEY or the dedicated LOADTEST_API_KEY (both cached
                // at startup). Fail-closed: if NEITHER is cached, reject as the
                // stable `docs_hmac_invalid` 401 (no default-key path).
                // PG-VAL-016: Structured error envelope (matches the rest of the
                // worker); the `DOCS_HMAC_INVALID` code keeps the SCREAMING_SNAKE
                // convention the OpenAPI spec and round-trip dispatcher enforce.
                let docs_hmac_candidate_keys: [Option<&[u8]>; 2] = [
                    ctx.data.sandbox_api_key_cached.as_ref().map(|k| k.as_bytes()),
                    ctx.data.loadtest_api_key_cached.as_ref().map(|k| k.as_bytes()),
                ];
                if docs_hmac_candidate_keys.iter().all(|k| k.is_none()) {
                    console_log!(
                        "[register-test-origin] neither SANDBOX_API_KEY nor LOADTEST_API_KEY cached; failing closed on X-Docs-Hmac"
                    );
                    let resp = crate::error::ApiError::unauthorized(
                        "DOCS_HMAC_INVALID",
                        "X-Docs-Hmac signature is required for this endpoint and could not be verified (server-side key not provisioned)",
                    )
                    .to_response()?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                let header_value = hdrs
                    .get(crate::security::DOCS_HMAC_HEADER)
                    .ok()
                    .flatten();
                // Try each present key; accept on the first that verifies Ok,
                // keeping the last failure outcome for the rejection detail.
                let mut docs_hmac_ok = false;
                let mut docs_hmac_outcome = crate::security::DocsHmacCheck::MissingHeader;
                for key in docs_hmac_candidate_keys.into_iter().flatten() {
                    match crate::security::verify_docs_hmac(
                        header_value.as_deref(),
                        &body_bytes,
                        key,
                    ) {
                        crate::security::DocsHmacCheck::Ok => {
                            docs_hmac_ok = true;
                            break;
                        }
                        outcome => docs_hmac_outcome = outcome,
                    }
                }
                if !docs_hmac_ok {
                    console_log!(
                        "[register-test-origin] X-Docs-Hmac verification failed: {:?}",
                        docs_hmac_outcome
                    );
                    // Detail strings no longer leak the internal "docs gateway"
                    // implementation phrase; callers only need the header contract.
                    let detail = match docs_hmac_outcome {
                        crate::security::DocsHmacCheck::MissingHeader => {
                            "X-Docs-Hmac header is required for the docs sandbox proxy route"
                        }
                        crate::security::DocsHmacCheck::MalformedHeader => {
                            "X-Docs-Hmac header is not a valid hex-encoded HMAC-SHA256 tag"
                        }
                        crate::security::DocsHmacCheck::Mismatch => {
                            "X-Docs-Hmac signature did not verify against the request body"
                        }
                        crate::security::DocsHmacCheck::Ok => "ok",
                    };
                    let resp = crate::error::ApiError::unauthorized(
                        "DOCS_HMAC_INVALID",
                        detail,
                    )
                    .to_response()?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }

                let body: RegisterRequest = match serde_json::from_slice(&body_bytes) {
                    Ok(b) => b,
                    Err(e) => {
                        console_log!("[register-test-origin] Invalid JSON: {:?}", e);
                        let resp = crate::error::ApiError::bad_request(
                            "BODY_SCHEMA_INVALID",
                            Some("body"),
                            "Request body could not be parsed as JSON or has unknown fields",
                        )
                        .to_response()?;
                        return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                    }
                };

                // ST-VA-026: Enforce field length constraints after deserialisation.
                if body.origin.len() > MAX_ORIGIN_LEN {
                    let resp = crate::error::ApiError::bad_request(
                        "BODY_SCHEMA_INVALID",
                        Some("origin"),
                        "origin exceeds maximum length (2048 bytes)",
                    )
                    .to_response()?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                if body.api_key.len() > MAX_API_KEY_LEN {
                    let resp = crate::error::ApiError::bad_request(
                        "BODY_SCHEMA_INVALID",
                        Some("api_key"),
                        "api_key exceeds maximum length (256 bytes)",
                    )
                    .to_response()?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                if let Some(ref email) = body.contact_email {
                    if email.len() > MAX_EMAIL_LEN {
                        let resp = crate::error::ApiError::bad_request(
                            "BODY_SCHEMA_INVALID",
                            Some("contact_email"),
                            "contact_email exceeds maximum length (320 bytes)",
                        )
                        .to_response()?;
                        return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                    }
                }

                // Validate proof_direction if provided
                let proof_direction = match body.proof_direction.as_deref() {
                    Some("over_age") | None => "over_age",
                    Some("under_age") => "under_age",
                    Some(other) => {
                        console_log!("[register-test-origin] Invalid proof_direction: {}", other);
                        let resp = crate::error::ApiError::bad_request(
                            "BODY_SCHEMA_INVALID",
                            Some("proof_direction"),
                            "proof_direction must be \"over_age\" or \"under_age\"",
                        )
                        .to_response()?;
                        return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                    }
                };

                // Validate: under_age requires max_age_years
                if proof_direction == "under_age" && body.max_age_years.is_none() {
                    let resp = crate::error::ApiError::bad_request(
                        "BODY_SCHEMA_INVALID",
                        Some("max_age_years"),
                        "max_age_years is required when proof_direction is \"under_age\"",
                    )
                    .to_response()?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }

                // IV-172: Bounded age values to 0..=150
                if body.min_age_years > 150 {
                    let resp = crate::error::ApiError::bad_request(
                        "BODY_SCHEMA_INVALID",
                        Some("min_age_years"),
                        "min_age_years must not exceed 150",
                    )
                    .to_response()?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
                if let Some(max) = body.max_age_years {
                    if max > 150 {
                        let resp = crate::error::ApiError::bad_request(
                            "BODY_SCHEMA_INVALID",
                            Some("max_age_years"),
                            "max_age_years must not exceed 150",
                        )
                        .to_response()?;
                        return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                    }
                }

                // LT-001: accept the in-body api_key matching EITHER the shared
                // SANDBOX_API_KEY or the dedicated LOADTEST_API_KEY (both cached
                // at startup, M-27). At least one must be present.
                if ctx.data.sandbox_api_key_cached.is_none()
                    && ctx.data.loadtest_api_key_cached.is_none()
                {
                    console_log!("[register-test-origin] neither SANDBOX_API_KEY nor LOADTEST_API_KEY cached at startup");
                    return error_with_headers("Service configuration error", 500);
                }

                // ST-VA-027: hash both sides to a fixed 32-byte digest before the
                // constant-time compare so no length-dependent timing signal
                // leaks. The supplied key is accepted if it matches EITHER cached
                // key; both comparisons are evaluated (no short-circuit on which
                // key matched).
                use sha2::{Digest as _, Sha256 as Sha256Digest};
                let supplied_hash = Sha256Digest::digest(body.api_key.as_bytes());
                let sandbox_match = ctx.data.sandbox_api_key_cached.as_ref().map(|k| {
                    let expected_hash = Sha256Digest::digest(k.as_bytes());
                    bool::from(subtle::ConstantTimeEq::ct_eq(
                        supplied_hash.as_slice(),
                        expected_hash.as_slice(),
                    ))
                }).unwrap_or(false);
                let loadtest_match = ctx.data.loadtest_api_key_cached.as_ref().map(|k| {
                    let expected_hash = Sha256Digest::digest(k.as_bytes());
                    bool::from(subtle::ConstantTimeEq::ct_eq(
                        supplied_hash.as_slice(),
                        expected_hash.as_slice(),
                    ))
                }).unwrap_or(false);
                if !sandbox_match && !loadtest_match {
                    console_log!("[register-test-origin] Invalid API key from origin: {}", body.origin);
                    // AL-022: Audit sandbox API key authentication failure.
                    // R8: emit best-effort off the critical path; fall back to inline.
                    let fail_ip = get_client_ip(&hdrs);
                    if let Some(wctx) = crate::take_worker_context() {
                        let logger = ctx.data.audit_logger.clone();
                        let origin = body.origin.clone();
                        wctx.wait_until(async move {
                            logger.log_sandbox_api_key_failure(&fail_ip, &origin).await;
                        });
                    } else {
                        ctx.data
                            .audit_logger
                            .log_sandbox_api_key_failure(&fail_ip, &body.origin)
                            .await;
                    }
                    return error_with_headers("Access denied", 403);
                }

                // Rate limiting: 10 registrations per IP per hour
                let client_ip = get_client_ip(&hdrs);
                let rate_limit_kv = match ctx.kv(KV_RATE_LIMITS) {
                    Ok(kv) => kv,
                    Err(e) => {
                        console_log!("[register-test-origin] KV binding {} failed: {:?}", KV_RATE_LIMITS, e);
                        return error_with_headers("Service temporarily unavailable", 503);
                    }
                };
                let rate_key = format!("origin_reg:{}", hash_ip(&client_ip, &ctx.data.ip_hash_salt));

                let current_count: u32 = match rate_limit_kv
                    .get(&rate_key)
                    .text()
                    .await
                {
                    Ok(val) => val.and_then(|s| s.parse().ok()).unwrap_or(0),
                    Err(e) => {
                        console_log!("[register-test-origin] KV rate limit read failed for key {}: {:?}", rate_key, e);
                        return error_with_headers("Service temporarily unavailable", 503);
                    }
                };

                if current_count >= 10 {
                    // SECURITY: Hash IP for GDPR compliance
                    console_log!("[register-test-origin] Rate limit exceeded for IP: {}", hash_ip(&client_ip, &ctx.data.ip_hash_salt));
                    // AL-031: Audit rate limit hit on sandbox self-service registration.
                    offload_audit!(ctx, |logger| logger.log_rate_limit_exceeded(
                        "sandbox_self_service",
                        "/v1/register-test-origin",
                        &client_ip,
                        current_count,
                        10,
                    ));
                    let resp = error_with_headers("Rate limit exceeded. Try again in 1 hour.", 429)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }

                // Increment rate limit counter (expires in 1 hour)
                match rate_limit_kv.put(&rate_key, current_count.saturating_add(1).to_string()) {
                    Ok(builder) => {
                        if let Err(e) = builder.expiration_ttl(3600).execute().await {
                            console_log!("[register-test-origin] KV rate limit write execute failed for key {}: {:?}", rate_key, e);
                            return error_with_headers("Service temporarily unavailable", 503);
                        }
                    }
                    Err(e) => {
                        console_log!("[register-test-origin] KV rate limit put builder failed for key {}: {:?}", rate_key, e);
                        return error_with_headers("Service temporarily unavailable", 503);
                    }
                }

                // Validate origin format
                if !body.origin.starts_with("http://") && !body.origin.starts_with("https://") {
                    return error_with_headers("Origin must start with http:// or https://", 400);
                }

                let origin = body.origin.trim_end_matches('/').to_string();
                let config_kv = match ctx.kv(KV_CONFIG) {
                    Ok(kv) => kv,
                    Err(e) => {
                        console_log!("[register-test-origin] KV binding {} failed: {:?}", KV_CONFIG, e);
                        return error_with_headers("Service temporarily unavailable", 503);
                    }
                };
                // W2-Bug1: Use correct KV key prefix matching OriginPolicyStore
                let origin_key = format!("origins/{}", origin);

                // Idempotent: if origin already exists, return 200 with info
                // (not 409). Do NOT re-expose secrets.
                let existing_check = match config_kv.get(&origin_key).text().await {
                    Ok(val) => val,
                    Err(e) => {
                        console_log!("[register-test-origin] KV config read failed for key {}: {:?}", origin_key, e);
                        return error_with_headers("Service temporarily unavailable", 503);
                    }
                };
                if let Some(existing_json) = existing_check {
                    // Attempt to parse existing policy to return useful info
                    let info = if let Ok(existing) = serde_json::from_str::<serde_json::Value>(&existing_json) {
                        serde_json::json!({
                            "success": true,
                            "message": format!("Origin '{}' is already registered.", origin),
                            "already_existed": true,
                            "origin": origin,
                            "tenant_id": existing.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("unknown"),
                            "verifying_key_id": crate::VK_ID.to_string(),
                            "min_age_years": existing.get("min_age_years").and_then(|v| v.as_u64()),
                            "max_age_years": existing.get("max_age_years").and_then(|v| v.as_u64()),
                            "proof_direction": existing.get("proof_direction").and_then(|v| v.as_str()),
                            "note": "Secrets are not re-exposed. If you need new credentials, wait for the existing registration to expire."
                        })
                    } else {
                        serde_json::json!({
                            "success": true,
                            "message": format!("Origin '{}' is already registered.", origin),
                            "already_existed": true,
                            "origin": origin,
                            "verifying_key_id": crate::VK_ID.to_string(),
                            "note": "Secrets are not re-exposed. If you need new credentials, wait for the existing registration to expire."
                        })
                    };
                    // AL-031: Audit idempotent re-registration (no new secrets issued).
                    ctx.data
                        .audit_logger
                        .log_test_origin_reregistration(&client_ip, &origin)
                        .await;
                    let resp = Response::from_json(&info)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }

                // SECURITY: Generate unique HMAC secret per origin.
                //
                // Canonical form (matches provii-issuer + provii-management): the
                // stored plaintext is the 32 raw random bytes. The base64url
                // string returned to the caller is purely transport encoding;
                // clients MUST base64url-decode before using the result as
                // the HMAC key.
                //
                // Wrapped in Zeroizing so the raw bytes clear on drop. The
                // base64 string also Zeroizing because it carries the same
                // secret material in encoded form until the response is
                // built.
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                let mut raw_bytes = [0u8; 32];
                getrandom::getrandom(&mut raw_bytes).map_err(|e| {
                    worker::Error::RustError(format!("Failed to generate HMAC secret: {}", e))
                })?;
                let hmac_secret_raw = zeroize::Zeroizing::new(raw_bytes.to_vec());
                {
                    use zeroize::Zeroize;
                    raw_bytes.zeroize();
                }
                let hmac_secret_b64url =
                    zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(hmac_secret_raw.as_slice()));

                // Envelope encryption: encrypt HMAC secret with MEK
                let mek = match &ctx.data.mek_cached {
                    Some(m) => m.clone(),
                    None => {
                        console_log!("[register-test-origin] MEK not cached at startup");
                        return error_with_headers("Service configuration error", 500);
                    }
                };

                // SECURITY (HMAC harmonisation, task #50): encrypt the 32 RAW
                // bytes, not the 43-char base64url ASCII representation. This
                // matches the canonical form used by provii-issuer and the
                // provii-management verifier provisioning flow, so the same
                // base64url-decode-then-sign convention works against every
                // Provii HMAC endpoint. Pre-fix provii-verifier stored the 43
                // ASCII bytes, breaking cross-service reuse of `hmac_secret`.
                let encrypted = match crate::security::envelope_encryption::encrypt_hmac_secret(
                    hmac_secret_raw.as_slice(),
                    &mek,
                ).await {
                    Ok(enc) => enc,
                    Err(e) => {
                        console_log!("[register-test-origin] Envelope encryption failed: {:?}", e);
                        return error_with_headers("Internal encryption error", 500);
                    }
                };

                // Hash the sandbox API key with Argon2id for the api_key_hash field
                let api_key_hash = match crate::security::hash::hash_api_key(&body.api_key) {
                    Ok(h) => h,
                    Err(e) => {
                        console_log!("[register-test-origin] Failed to hash API key: {:?}", e);
                        return error_with_headers("Internal hashing error", 500);
                    }
                };

                // Derive unique client_id from tenant_id to prevent audit log
                // confusion and credential cross-contamination between test origins.
                let origin_hash = blake3::hash(origin.as_bytes());
                let tenant_id = format!("test_{}", origin_hash);
                // First 12 hex chars of the blake3 hash, used as a unique suffix.
                // blake3 outputs 32 bytes; we take the first 6 bytes (12 hex chars).
                let hash_bytes = origin_hash.as_bytes();
                let client_id = format!(
                    "rp_sandbox_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    hash_bytes[0], hash_bytes[1], hash_bytes[2],
                    hash_bytes[3], hash_bytes[4], hash_bytes[5],
                );

                // Compute timestamps in seconds (OriginPolicy uses seconds)
                let now_sec = worker::Date::now().as_millis() / 1000;
                let expires_at = now_sec.saturating_add(TTL_SECONDS);

                // Build OriginPolicy-compatible JSON (no extra fields that
                // would break deserialisation when deny_unknown_fields is off,
                // but more importantly: only fields OriginPolicy expects).
                let config = serde_json::json!({
                    "tenant_id": tenant_id,
                    "min_age_years": body.min_age_years,
                    "max_age_years": body.max_age_years,
                    "proof_direction": proof_direction,
                    "max_ttl_sec": 3600,
                    "allowed_vk_ids": [crate::VK_ID],
                    "allowed_issuers": [],
                    "billing": {
                        "plan": "sandbox",
                        "metering_enabled": false
                    },
                    "clients": [{
                        "client_id": client_id,
                        "api_key_hash": api_key_hash,
                        "api_key_prefix": body.api_key.chars().take(8).collect::<String>(),
                        "encrypted_hmac_secret": encrypted.encrypted_secret,
                        "dek_encrypted": encrypted.encrypted_dek,
                        "encryption_version": encrypted.version,
                        "active": true
                    }],
                    "enabled": true,
                    "created_at": now_sec,
                    "updated_at": now_sec
                });

                // Store in KV with 72h TTL for weekend testing (W2).
                match config_kv.put(&origin_key, config.to_string()) {
                    Ok(builder) => {
                        if let Err(e) = builder.expiration_ttl(TTL_SECONDS).execute().await {
                            console_log!("[register-test-origin] KV config write execute failed for key {}: {:?}", origin_key, e);
                            return error_with_headers("Service temporarily unavailable", 503);
                        }
                    }
                    Err(e) => {
                        console_log!("[register-test-origin] KV config put builder failed for key {}: {:?}", origin_key, e);
                        return error_with_headers("Service temporarily unavailable", 503);
                    }
                }

                // Reverse index: client_id -> registered origin.
                //
                // Used by the sandbox `rp_sandbox_*` origin bypass on
                // POST /v1/challenge so the expert flow can resolve the
                // policy (and its `clients` entry, needed for HMAC auth)
                // when the request arrives from a different Origin than
                // the registered sandbox origin (e.g. the playground).
                //
                // Same TTL as the policy entry so they expire together;
                // a stale lookup is never authoritative because the
                // dispatcher then loads the policy and re-checks `enabled`.
                //
                // Non-fatal write: HMAC + nonce remain the auth boundary.
                // Without the index the sandbox bypass simply does not
                // apply for this client_id; production-grade origin
                // allowlist behaviour still holds.
                let lookup_key = format!("client_lookup/{}", client_id);
                let lookup_put = config_kv
                    .put(&lookup_key, origin.clone())
                    .map(|b| b.expiration_ttl(TTL_SECONDS));
                match lookup_put {
                    Ok(builder) => {
                        if let Err(e) = builder.execute().await {
                            console_log!(
                                "[register-test-origin] client_lookup index write failed (non-fatal): {:?}",
                                e
                            );
                        }
                    }
                    Err(e) => {
                        console_log!(
                            "[register-test-origin] client_lookup index put builder failed (non-fatal): {:?}",
                            e
                        );
                    }
                }

                // ── Generate hosted-flow key pair (pk_test_* / sk_test_*) ────
                //
                // This gives developers both expert-flow (HMAC) and hosted-flow
                // (pk_test) credentials in a single self-service call.
                let hosted_public_key = match generate_hosted_test_key(&ctx.env, &origin, TTL_SECONDS).await {
                    Ok(pk) => Some(pk),
                    Err(e) => {
                        // Non-fatal: expert-flow credentials are still valid.
                        // Log the failure and continue without a hosted key.
                        console_log!(
                            "[register-test-origin] Hosted key generation failed (non-fatal): {}",
                            e
                        );
                        None
                    }
                };

                // Build response with DX improvements
                let origin_json_escaped = serde_json::to_string(&origin)
                    .unwrap_or_else(|_| format!("\"{}\"", origin));

                // SECURITY: Do NOT echo sandbox_api_key in response (O-8).
                // The caller already has the key (they sent it). Echoing shared
                // credentials in responses creates unnecessary exposure in logs,
                // proxies, and browser dev tools.
                let response = serde_json::json!({
                    "success": true,
                    "message": format!("Test origin '{}' registered successfully!", origin),
                    "origin": origin,
                    "client_id": client_id,
                    "hmac_secret": &*hmac_secret_b64url,
                    "public_key": hosted_public_key,
                    "verifying_key_id": crate::VK_ID.to_string(),
                    "min_age_years": body.min_age_years,
                    "max_age_years": body.max_age_years,
                    "proof_direction": proof_direction,
                    "ttl_seconds": TTL_SECONDS,
                    "expires_at": expires_at,
                    "security_note": "IMPORTANT: Store the HMAC secret securely. This is a unique secret generated for your origin. It will not be shown again.",
                    "test_instructions": {
                        "endpoint": "https://sandbox-verify.provii.app/v1/challenge",
                        "example_curl": format!(
                            "curl -X POST https://sandbox-verify.provii.app/v1/challenge \\\n  -H \"Content-Type: application/json\" \\\n  -H \"X-Client-Id: {}\" \\\n  -H \"X-Timestamp: $(date +%s)\" \\\n  -H \"X-Nonce: $(openssl rand -hex 16)\" \\\n  -H \"X-Signature: <HMAC-SHA256>\" \\\n  -d '{{\"origin\": {}}}'",
                            client_id, origin_json_escaped
                        ),
                        "example_agegate_js": format!(
                            "<script src=\"https://cdn.provii.app/agegate.js\"\n  data-public-key=\"{}\"\n  data-environment=\"sandbox\"\n  async>\n</script>",
                            hosted_public_key.as_deref().unwrap_or("YOUR_PK_TEST_KEY")
                        )
                    }
                });

                // AL-031: Audit successful test origin registration with the
                // semantically correct event type. Previously misused
                // log_suspicious_activity, which is reserved for hostile traffic.
                let reg_ip = get_client_ip(&hdrs);
                ctx.data
                    .audit_logger
                    .log_test_origin_registered(&reg_ip, &origin, &client_id, TTL_SECONDS)
                    .await;

                let resp = Response::from_json(&response)?;
                add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg)
            });
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // HOSTED FLOW ENDPOINTS (M-058, M-059)
    //
    // Browser-facing age verification endpoints ported from provii-verifier.
    // These use ORIGIN_INDEX KV for CORS validation (not the provii-verifier
    // Config-based CORS). SECURITY: Each handler performs its own origin
    // validation, rate limiting, and session binding checks.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    router = router
        // OPTIONS preflight handlers for hosted routes (use hosted CORS).
        .options_async("/v1/hosted/challenge", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        .options_async("/v1/hosted/status/:session_id", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        .options_async("/v1/hosted/redeem/:session_id", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        .options_async("/v1/hosted/user/logout", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        .options_async("/v1/hosted/session/check", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        // ADV-VA-05-010: OPTIONS preflight for CSRF token endpoints.
        // Browsers send preflights for credentialed cross-origin GETs when
        // custom headers or credentials are involved (provii-agegate sends cookies).
        .options_async("/v1/hosted/csrf-token", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        .options_async("/v1/hosted/csrf-token/:session_id", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        // ADV-VA-05-010: OPTIONS preflight for WebSocket upgrade endpoint.
        .options_async("/v1/hosted/ws/:session_id", |req, ctx| async move {
            let origin = req.headers().get("Origin").ok().flatten();
            if let Some(r) = sandbox_hosted_cors_preflight(&origin, &ctx.data.cfg) {
                return r;
            }
            match crate::hosted::cors::handle_cors_preflight(
                &ctx.env,
                origin,
                &ctx.data.ip_hash_salt,
            )
            .await
            {
                Ok(r) => Ok(r),
                Err(e) => {
                    let mut r = e.to_response()?;
                    crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                        &mut r,
                    );
                    Ok(r)
                }
            }
        })
        // POST /v1/hosted/challenge - Create a hosted verification session.
        .post_async("/v1/hosted/challenge", |mut req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-014: Enforce Content-Type: application/json before parsing.
            // application/x-www-form-urlencoded is CORS-safelisted (no preflight),
            // so rejecting non-JSON content types forces a preflight on cross-origin
            // requests, providing CSRF defence in depth.
            if !is_json(&hdrs) {
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "invalid_content_type:hosted_challenge"));
                let err_response = ApiError::UnsupportedMediaType.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // ADV-VA-013: Sec-Fetch validation (lenient mode for cross-origin hosted flow).
            // Hosted endpoints legitimately receive cross-site requests from customer
            // domains. Lenient mode logs violations without rejecting, providing audit
            // visibility into unexpected fetch metadata patterns.
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/challenge");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/challenge: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (500/hr) before any work.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "challenge", 500,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // ADV-VA-008: Enforce body size limit before parsing.
            let body_bytes = match read_limited_body(&mut req, 4 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/hosted/challenge] Request too large: {:?}", e);
                    return add_security_and_cors_headers(
                        error_with_headers("Request too large", 413)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let rsp = match crate::hosted::endpoints::challenge::handle_hosted_challenge(
                ctx.data.clone(),
                &ctx.env,
                body_bytes,
                &hdrs,
            )
            .await
            {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/hosted/challenge",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // GET /v1/hosted/status/:session_id - Poll session status.
        .get_async("/v1/hosted/status/:session_id", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/status");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/status: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (600/hr) before session lookup.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "status", 600,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            let session_id = ctx
                .param("session_id")
                .ok_or_else(|| WorkerError::RustError("Missing session_id".into()))?;

            // Validate UUID format.
            let sid = match VALIDATOR.validate_uuid(session_id, "session_id") {
                Ok(id) => id.to_string(),
                Err(_e) => {
                    return add_security_and_cors_headers(
                        error_with_headers("Not found", 404)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let rsp = match crate::hosted::endpoints::status::handle_hosted_status(
                ctx.data.clone(),
                hdrs.clone(),
                &sid,
            )
            .await
            {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/hosted/status",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // POST /v1/hosted/redeem/:session_id - Redeem with PKCE verifier.
        .post_async("/v1/hosted/redeem/:session_id", |mut req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-014: Enforce Content-Type: application/json before parsing.
            if !is_json(&hdrs) {
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "invalid_content_type:hosted_redeem"));
                let err_response = ApiError::UnsupportedMediaType.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/redeem");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/redeem: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (60/hr) before session lookup.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "redeem", 60,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            let session_id = ctx
                .param("session_id")
                .ok_or_else(|| WorkerError::RustError("Missing session_id".into()))?;

            // Validate UUID format.
            let sid = match VALIDATOR.validate_uuid(session_id, "session_id") {
                Ok(id) => id.to_string(),
                Err(_e) => {
                    return add_security_and_cors_headers(
                        error_with_headers("Not found", 404)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            // SEC-028: CSRF validation on the session-bound token from the
            // X-CSRF-Token header. Enforced BEFORE any body read or state
            // mutation. Uses the cached SESSION_TOKEN_SECRET (same key as
            // generation at /v1/hosted/csrf-token/:session_id).
            if let Err(reason) = enforce_hosted_csrf(&ctx, &hdrs, &sid, "hosted_redeem").await {
                return reason;
            }

            // Read and parse the JSON body (PKCE code_verifier).
            let body_bytes = match read_limited_body(&mut req, 4 * 1024).await {
                Ok(b) => b,
                Err(e) => {
                    console_log!("[/v1/hosted/redeem] Request too large: {:?}", e);
                    return add_security_and_cors_headers(
                        error_with_headers("Request too large", 413)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let body: crate::hosted::endpoints::redeem::HostedRedeemRequest =
                match serde_json::from_slice(&body_bytes) {
                    Ok(b) => b,
                    Err(e) => {
                        console_log!("[/v1/hosted/redeem] Invalid JSON: {:?}", e);
                        return add_security_and_cors_headers(
                            error_with_headers("Invalid request", 400)?,
                            &hdrs,
                            &ctx.data.cfg,
                        );
                    }
                };

            let rsp = match crate::hosted::endpoints::redeem::handle_hosted_redeem(
                ctx.data.clone(),
                hdrs.clone(),
                &sid,
                body,
            )
            .await
            {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/hosted/redeem",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // GET /v1/hosted/ws/:session_id - WebSocket upgrade for push notifications.
        .get_async("/v1/hosted/ws/:session_id", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/ws");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/ws: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (120/hr) before session lookup.
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "ws", 120,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            let session_id = ctx
                .param("session_id")
                .ok_or_else(|| WorkerError::RustError("Missing session_id".into()))?;

            // Validate UUID format.
            let sid = match VALIDATOR.validate_uuid(session_id, "session_id") {
                Ok(id) => id.to_string(),
                Err(_e) => {
                    return add_security_and_cors_headers(
                        error_with_headers("Not found", 404)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let rsp = match crate::hosted::endpoints::ws::handle_hosted_ws_upgrade(
                ctx.data.clone(),
                &req,
                hdrs.clone(),
                &sid,
            )
            .await
            {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/hosted/ws",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // GET /v1/hosted/session/check - Check for existing session cookie.
        .get_async("/v1/hosted/session/check", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/session/check");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/session/check: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (300/hr).
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "session_check", 300,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // Build session check config from env vars and secrets.
            let cookie_name = ctx
                .env
                .var("SESSION_COOKIE_NAME")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "__Host-session".to_string());

            // SC-001: Read from cached AppState (loaded at startup).
            let session_token_secret = match ctx.data.session_token_secret.as_ref() {
                Some(s) => (**s).clone(),
                None => {
                    console_log!("[/v1/hosted/session/check] SESSION_TOKEN_SECRET unavailable (not cached at startup)");
                    return add_security_and_cors_headers(
                        error_with_headers("Service unavailable", 503)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let session_token_secret_previous = ctx
                .data
                .session_token_secret_previous
                .as_ref()
                .map(|s| (**s).clone());

            let config = crate::hosted::endpoints::session_check::SessionCheckConfig {
                session_token_secret,
                session_token_secret_previous,
                cookie_name,
            };

            let origin = hdrs.get("Origin").ok().flatten().unwrap_or_default();

            let rsp = match crate::hosted::endpoints::session_check::handle_hosted_session_check(
                ctx.data.clone(),
                hdrs.clone(),
                &config,
                &origin,
            )
            .await
            {
                Ok(response) => response,
                Err(e) => {
                    return handler_error_to_response(
                        "/v1/hosted/session/check",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        })
        // GET /v1/hosted/csrf-token - Generate anonymous CSRF token.
        .get_async("/v1/hosted/csrf-token", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/csrf-token");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/csrf-token: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (300/hr).
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "csrf", 300,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // SC-001: Read from cached AppState (loaded at startup).
            let signing_key = match ctx.data.session_token_secret.as_ref() {
                Some(s) => (**s).clone(),
                None => {
                    console_log!("[/v1/hosted/csrf-token] SESSION_TOKEN_SECRET unavailable (not cached at startup)");
                    // AL-032: Audit token generation failure (signing key missing).
                    // R8: emit best-effort off the critical path; fall back to inline.
                    if let Some(wctx) = crate::take_worker_context() {
                        let logger = ctx.data.audit_logger.clone();
                        let ip = client_ip.clone();
                        let analytics = ctx.data.analytics.clone();
                        wctx.wait_until(async move {
                            logger
                                .log_csrf_token_generation_failed(
                                    &ip,
                                    "anonymous",
                                    "signing_key_unavailable",
                                    analytics.as_ref(),
                                )
                                .await;
                        });
                    } else {
                        ctx.data
                            .audit_logger
                            .log_csrf_token_generation_failed(
                                &client_ip,
                                "anonymous",
                                "signing_key_unavailable",
                                ctx.data.analytics.as_ref(),
                            )
                            .await;
                    }
                    return add_security_and_cors_headers(
                        error_with_headers("Service unavailable", 503)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let config = crate::hosted::endpoints::csrf::CsrfConfig::default();

            match crate::hosted::endpoints::csrf::handle_anonymous_csrf_token(signing_key, config)
                .await
            {
                Ok(response) => {
                    // AL-032: Audit successful anonymous CSRF token generation.
                    ctx.data
                        .audit_logger
                        .log_csrf_token_generated(&client_ip, "anonymous")
                        .await;
                    add_security_and_cors_headers(response, &hdrs, &ctx.data.cfg)
                }
                Err(e) => {
                    // AL-032: Audit handler-level token generation failure.
                    // R8: emit best-effort off the critical path; fall back to inline.
                    if let Some(wctx) = crate::take_worker_context() {
                        let logger = ctx.data.audit_logger.clone();
                        let ip = client_ip.clone();
                        let analytics = ctx.data.analytics.clone();
                        wctx.wait_until(async move {
                            logger
                                .log_csrf_token_generation_failed(
                                    &ip,
                                    "anonymous",
                                    "handler_error",
                                    analytics.as_ref(),
                                )
                                .await;
                        });
                    } else {
                        ctx.data
                            .audit_logger
                            .log_csrf_token_generation_failed(
                                &client_ip,
                                "anonymous",
                                "handler_error",
                                ctx.data.analytics.as_ref(),
                            )
                            .await;
                    }
                    handler_error_to_response(
                        "/v1/hosted/csrf-token",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    )
                }
            }
        })
        // GET /v1/hosted/csrf-token/:session_id - Generate session-bound CSRF token.
        .get_async("/v1/hosted/csrf-token/:session_id", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/csrf-token/:session_id");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/csrf-token/:sid: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (300/hr, shared with anonymous csrf).
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "csrf", 300,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            let session_id = ctx
                .param("session_id")
                .ok_or_else(|| WorkerError::RustError("Missing session_id".into()))?;

            // Validate UUID format.
            let sid = match VALIDATOR.validate_uuid(session_id, "session_id") {
                Ok(id) => id.to_string(),
                Err(_e) => {
                    return add_security_and_cors_headers(
                        error_with_headers("Not found", 404)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            // SC-001: Read from cached AppState (loaded at startup).
            let signing_key = match ctx.data.session_token_secret.as_ref() {
                Some(s) => (**s).clone(),
                None => {
                    console_log!(
                        "[/v1/hosted/csrf-token/:sid] SESSION_TOKEN_SECRET unavailable (not cached at startup)"
                    );
                    // AL-032: Audit token generation failure (signing key missing).
                    // R8: emit best-effort off the critical path; fall back to inline.
                    if let Some(wctx) = crate::take_worker_context() {
                        let logger = ctx.data.audit_logger.clone();
                        let ip = client_ip.clone();
                        let sid_owned = sid.clone();
                        let analytics = ctx.data.analytics.clone();
                        wctx.wait_until(async move {
                            logger
                                .log_csrf_token_generation_failed(
                                    &ip,
                                    &sid_owned,
                                    "signing_key_unavailable",
                                    analytics.as_ref(),
                                )
                                .await;
                        });
                    } else {
                        ctx.data
                            .audit_logger
                            .log_csrf_token_generation_failed(
                                &client_ip,
                                &sid,
                                "signing_key_unavailable",
                                ctx.data.analytics.as_ref(),
                            )
                            .await;
                    }
                    return add_security_and_cors_headers(
                        error_with_headers("Service unavailable", 503)?,
                        &hdrs,
                        &ctx.data.cfg,
                    );
                }
            };

            let config = crate::hosted::endpoints::csrf::CsrfConfig::default();

            match crate::hosted::endpoints::csrf::handle_csrf_token_generation(
                sid.clone(),
                signing_key,
                config,
            )
            .await
            {
                Ok(response) => {
                    // AL-032: Audit successful session-bound CSRF token generation.
                    ctx.data
                        .audit_logger
                        .log_csrf_token_generated(&client_ip, &sid)
                        .await;
                    add_security_and_cors_headers(response, &hdrs, &ctx.data.cfg)
                }
                Err(e) => {
                    // AL-032: Audit handler-level token generation failure.
                    // R8: emit best-effort off the critical path; fall back to inline.
                    if let Some(wctx) = crate::take_worker_context() {
                        let logger = ctx.data.audit_logger.clone();
                        let ip = client_ip.clone();
                        let sid_owned = sid.clone();
                        let analytics = ctx.data.analytics.clone();
                        wctx.wait_until(async move {
                            logger
                                .log_csrf_token_generation_failed(
                                    &ip,
                                    &sid_owned,
                                    "handler_error",
                                    analytics.as_ref(),
                                )
                                .await;
                        });
                    } else {
                        ctx.data
                            .audit_logger
                            .log_csrf_token_generation_failed(
                                &client_ip,
                                &sid,
                                "handler_error",
                                ctx.data.analytics.as_ref(),
                            )
                            .await;
                    }
                    handler_error_to_response(
                        "/v1/hosted/csrf-token/:sid",
                        &e,
                        &hdrs,
                        &ctx.data.cfg,
                    )
                }
            }
        })
        // POST /v1/hosted/user/logout - Clear session cookie.
        .post_async("/v1/hosted/user/logout", |req, ctx| async move {
            let hdrs = req.headers().clone();

            // ADV-VA-014: Enforce Content-Type: application/json for POST endpoints.
            // Even though logout has no body, requiring JSON content type forces a
            // CORS preflight on cross-origin requests, preventing form-based CSRF.
            if !is_json(&hdrs) {
                let client_ip = get_client_ip(&hdrs);
                offload_audit!(ctx, |logger| logger
                    .log_suspicious_activity(&client_ip, "invalid_content_type:hosted_logout"));
                let err_response = ApiError::UnsupportedMediaType.to_response()?;
                return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
            }

            // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
            {
                let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/user/logout");
                if !violations.is_empty() {
                    let client_ip = get_client_ip(&hdrs);
                    console_log!(
                        "[SECURITY] Sec-Fetch violations on /v1/hosted/user/logout: {:?} (IP: {})",
                        violations,
                        hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                    );
                }
            }

            // ADV-VA-003: Per-IP rate limit (60/hr).
            let client_ip = get_client_ip(&hdrs);
            let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
            {
                let rl_kv = require_rl_kv!(ctx);
                let result = crate::rate_limiting::check_hosted_ip_limit(
                    &rl_kv, &hashed_ip, "logout", 60,
                ).await;
                if !result.allowed {
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                }
            }

            // SEC-028: CSRF validation using an anonymous (pre-session) token.
            // Clients must have first called GET /v1/hosted/csrf-token before
            // invoking logout. Logout is idempotent, but forcing CSRF here
            // closes the drive-by-logout attack vector.
            if let Err(resp) = enforce_hosted_csrf(&ctx, &hdrs, "anonymous", "hosted_logout").await {
                return resp;
            }

            let cookie_name = ctx
                .env
                .var("SESSION_COOKIE_NAME")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "__Host-session".to_string());

            let rsp =
                match crate::hosted::endpoints::logout::handle_hosted_logout(&cookie_name).await {
                    Ok(response) => response,
                    Err(e) => {
                        return handler_error_to_response(
                            "/v1/hosted/user/logout",
                            &e,
                            &hdrs,
                            &ctx.data.cfg,
                        );
                    }
                };

            add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
        });

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // SANDBOX-ONLY: Proof simulator (W3)
    //
    // Allows developers to complete the hosted verification flow without a
    // physical wallet device. Only registered in sandbox environment.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if state.cfg.environment == "sandbox" {
        router = router
            // OPTIONS preflight for simulate-proof (uses hosted CORS).
            .options_async("/v1/hosted/sandbox/simulate-proof", |req, ctx| async move {
                let origin = req.headers().get("Origin").ok().flatten();
                match crate::hosted::cors::handle_cors_preflight(
                    &ctx.env,
                    origin,
                    &ctx.data.ip_hash_salt,
                )
                .await
                {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        let mut r = e.to_response()?;
                        crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                            &mut r,
                        );
                        Ok(r)
                    }
                }
            })
            // POST /v1/hosted/sandbox/simulate-proof - Simulate proof for sandbox testing.
            .post_async("/v1/hosted/sandbox/simulate-proof", |mut req, ctx| async move {
                let hdrs = req.headers().clone();

                // Double-check sandbox environment (defence in depth).
                if ctx.data.cfg.environment != "sandbox" {
                    return error_with_headers("Not found", 404);
                }

                // ADV-VA-014: Enforce Content-Type: application/json.
                if !is_json(&hdrs) {
                    let client_ip = get_client_ip(&hdrs);
                    offload_audit!(ctx, |logger| logger
                        .log_suspicious_activity(&client_ip, "invalid_content_type:hosted_simulate"));
                    let err_response = ApiError::UnsupportedMediaType.to_response()?;
                    return add_security_and_cors_headers(err_response, &hdrs, &ctx.data.cfg);
                }

                // ADV-VA-013: Sec-Fetch validation (lenient, audit-only).
                {
                    let violations = crate::hosted::middleware::sec_fetch::validate_sec_fetch_lenient(&req, "/v1/hosted/sandbox/simulate-proof");
                    if !violations.is_empty() {
                        let client_ip = get_client_ip(&hdrs);
                        console_log!(
                            "[SECURITY] Sec-Fetch violations on /v1/hosted/sandbox/simulate-proof: {:?} (IP: {})",
                            violations,
                            hash_ip(&client_ip, &ctx.data.ip_hash_salt)
                        );
                    }
                }

                // Per-IP rate limit (30/hr).
                let client_ip = get_client_ip(&hdrs);
                let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);
                {
                    let rl_kv = require_rl_kv!(ctx);
                    let result = crate::rate_limiting::check_hosted_ip_limit(
                        &rl_kv, &hashed_ip, "simulate", 30,
                    ).await;
                    if !result.allowed {
                        let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                        return add_security_and_cors_headers(resp, &hdrs, &ctx.data.cfg);
                    }
                }

                // PG-VAL-005: CSRF requirement removed for the sandbox
                // simulate-proof endpoint.
                //
                // The real auth on this endpoint is knowledge of
                // `submit_secret` and `challenge_id`, both delivered to the
                // browser only by a successful POST /v1/hosted/challenge call
                // (which is itself rate-limited and CSRF-protected). The CSRF
                // token added belt-and-braces protection but broke the
                // documented "demo without a wallet" flow from provii-agegate
                // (the SDK never minted an anonymous CSRF token before
                // calling simulate-proof, so every fresh-dev playground run
                // returned 403 CSRF_INVALID).
                //
                // Sandbox-only (gated by `cfg.environment == "sandbox"` at
                // route registration and the explicit re-check above), so
                // production is unaffected.

                // Body size limit (2KB).
                let body_bytes = match read_limited_body(&mut req, 2 * 1024).await {
                    Ok(b) => b,
                    Err(e) => {
                        console_log!("[/v1/hosted/sandbox/simulate-proof] Request too large: {:?}", e);
                        return add_security_and_cors_headers(
                            error_with_headers("Request too large", 413)?,
                            &hdrs,
                            &ctx.data.cfg,
                        );
                    }
                };

                let rsp = match crate::hosted::endpoints::simulate::handle_simulate_proof(
                    ctx.data.clone(),
                    body_bytes,
                )
                .await
                {
                    Ok(response) => response,
                    Err(e) => {
                        return handler_error_to_response(
                            "/v1/hosted/sandbox/simulate-proof",
                            &e,
                            &hdrs,
                            &ctx.data.cfg,
                        );
                    }
                };

                add_security_and_cors_headers(rsp, &hdrs, &ctx.data.cfg)
            });
    }

    // SECURITY: ASVS V14.2.5 - Catch-all 404 handler for web cache deception prevention
    // This ensures ALL unmatched routes return explicit 404 with anti-caching headers
    // Prevents cache deception attacks via fake path extensions (e.g., /api/secret.css)
    router = router.or_else_any_method_async("/*catchall", |req, ctx| async move {
        let hdrs = req.headers();
        let client_ip = get_client_ip(hdrs);
        let path = req.path();

        // L-1: Compute hashed IP once and reuse throughout the handler.
        let hashed_ip = hash_ip(&client_ip, &ctx.data.ip_hash_salt);

        // L-4: Per-IP rate limit (60/minute) to prevent abuse of HMAC hashing
        // and audit logging on the catchall. Fail-closed: returns 503 if KV
        // is unavailable, matching every other endpoint via require_rl_kv!.
        let rate_kv = require_rl_kv!(ctx);
        let rl = crate::rate_limiting::check_catchall_limit(&rate_kv, &hashed_ip, 60).await;
        if !rl.allowed {
            console_log!(
                "[SECURITY][429] Catchall rate limit exceeded for IP: {}",
                hashed_ip
            );
            let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&rl)?;
            return add_security_and_cors_headers(resp, hdrs, &ctx.data.cfg);
        }

        // SECURITY: Log 404 access attempts with hashed IP for monitoring
        console_log!(
            "[SECURITY][404] Unmatched route accessed: {} from IP: {}",
            path,
            hashed_ip
        );

        // SB-017/SB-018: Internal path probing detection.
        // If someone hits an unmatched /v1/internal/* path, that is suspicious:
        // only provii-verifier should call known internal endpoints via service binding.
        // Strip CORS headers (internal endpoints are not browser-facing) and log a
        // security warning for SOC monitoring.
        if path.starts_with("/v1/internal/") || path == "/v1/internal" {
            // SB-018: Elevated audit log for internal endpoint probing.
            console_log!(
                "{{\"audit\":true,\"event\":\"internal_endpoint_probe\",\"severity\":\"warning\",\"path\":\"{}\",\"ip_hash\":\"{}\"}}",
                path,
                hashed_ip
            );
            // R8: emit best-effort off the critical path; fall back to inline.
            let probe_reason = format!("internal_endpoint_probe:{}", path);
            if let Some(wctx) = crate::take_worker_context() {
                let logger = ctx.data.audit_logger.clone();
                let ip = client_ip.clone();
                wctx.wait_until(async move {
                    logger.log_suspicious_activity(&ip, &probe_reason).await;
                });
            } else {
                ctx.data
                    .audit_logger
                    .log_suspicious_activity(&client_ip, &probe_reason)
                    .await;
            }

            // CH-014 / SB-017: Return 404 with internal security headers (no CORS headers).
            let response = ApiError::NotFound.to_response()?;
            return add_internal_security_headers(response);
        }

        // SECURITY: Audit log suspicious 404 attempts with known malicious extensions
        let suspicious_extensions = [".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".ttf"];
        if suspicious_extensions.iter().any(|ext| path.ends_with(ext)) {
            console_log!(
                "[SECURITY][CACHE_DECEPTION] Potential cache deception attempt detected: {} from IP: {}",
                path,
                hashed_ip
            );

            // Log suspicious activity for cache deception attempts
            // R8: emit best-effort off the critical path; fall back to inline.
            let reason = format!("Path with suspicious extension accessed: {}", path);
            if let Some(wctx) = crate::take_worker_context() {
                let logger = ctx.data.audit_logger.clone();
                let ip = client_ip.clone();
                wctx.wait_until(async move {
                    logger.log_suspicious_activity(&ip, &reason).await;
                });
            } else {
                ctx.data
                    .audit_logger
                    .log_suspicious_activity(&client_ip, &reason)
                    .await;
            }
        }

        // Return explicit 404 with anti-caching headers
        let err_response = ApiError::NotFound.to_response()?;
        add_security_and_cors_headers(err_response, hdrs, &ctx.data.cfg)
    });

    router
}

// Tests for Worker-specific functions (is_json, get_client_ip, validate_request_size)
// require the Cloudflare Workers runtime and cannot be run on native targets.
// These functions are tested in integration tests with the actual Workers runtime.

// Tests for schema-inference functions live in `routes::schema_inference::tests`.
