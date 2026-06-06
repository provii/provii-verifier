// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! CORS (Cross-Origin Resource Sharing) Validation Module for the hosted
//! verification flow.
//!
//! Provides secure CORS handling with O(1) origin validation via ORIGIN_INDEX
//! KV lookup, credit availability checking, origin allowlist validation, and
//! audit logging for rejected origins.
//!
//! ## Security
//!
//! SECURITY: All origins must be explicitly registered in ORIGIN_INDEX KV
//! (managed by provii-management). There are no env-var fallbacks or legacy
//! allowlists. Origin reflection is never used; only the exact registered
//! origin string is echoed back in `Access-Control-Allow-Origin`.
//!
//! ## Origin Pattern Matching
//!
//! - Exact match: `https://example.com`
//! - Wildcard subdomains: `https://*.example.com` (matches sub.example.com, not example.com)

use crate::error::ApiError;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::RwLock;
use worker::{Env, Headers};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Privacy-preserving origin hashing
// ---------------------------------------------------------------------------

/// HMAC-SHA-256 hash of an origin string for privacy-preserving logging.
///
/// SECURITY: Uses domain tag `"provii-origin-v0"` to prevent cross-context
/// collisions with IP hashes or other HMAC-tagged values.
fn hash_origin(origin: &str, salt: &str) -> String {
    let Ok(mut mac) = HmacSha256::new_from_slice(salt.as_bytes()) else {
        return "0".repeat(64);
    };
    mac.update(b"provii-origin-v0");
    mac.update(origin.as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// M-31: In-memory origin validation cache
//
// Avoids repeated ORIGIN_INDEX KV reads for the same origin during heavy
// preflight traffic. Entries expire after ORIGIN_CACHE_TTL_SECS seconds.
// The cache is bounded to ORIGIN_CACHE_MAX_ENTRIES to prevent unbounded
// growth from enumeration attacks.
// ---------------------------------------------------------------------------

/// TTL for cached origin validation results (seconds).
const ORIGIN_CACHE_TTL_SECS: u64 = 60;

/// Maximum number of cached entries. At ~128 bytes per entry, 2048
/// entries = ~256KB, well within Worker memory budget.
const ORIGIN_CACHE_MAX_ENTRIES: usize = 2048;

struct OriginCacheEntry {
    result: OriginValidationResult,
    cached_at: u64,
}

static ORIGIN_CACHE: std::sync::OnceLock<RwLock<HashMap<String, OriginCacheEntry>>> =
    std::sync::OnceLock::new();

fn origin_cache() -> &'static RwLock<HashMap<String, OriginCacheEntry>> {
    ORIGIN_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Current Unix timestamp in seconds (delegates to crate utility).
fn cache_now() -> u64 {
    crate::utils::current_timestamp()
}

/// Result of origin validation, distinguishing between CORS rejection and
/// credit exhaustion so callers can return the correct HTTP status code.
///
/// SECURITY: Fail-closed. Origins not present in ORIGIN_INDEX are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginValidationResult {
    /// Origin is allowed and has credits (or metering is disabled).
    Allowed,
    /// Origin is not in any allowed list (CORS violation).
    Rejected,
    /// Origin is allowed but credit balance is exhausted (402).
    InsufficientCredits { organization_id: String },
}

/// Origin index entry from provii-management
#[derive(Debug, Deserialize)]
struct OriginIndexEntry {
    key_ids: Vec<String>,
    /// Organization ID that owns these keys
    #[serde(default)]
    organization_id: Option<String>,
    /// Whether the organization has credits available
    #[serde(default)]
    has_credits: Option<bool>,
    /// Whether metering/billing is enabled for this origin
    /// If false, credit checks are skipped (e.g., sandbox, demo, free tier)
    #[serde(default)]
    metering_enabled: Option<bool>,
}

/// Validate an origin against ORIGIN_INDEX KV and check credit status.
///
/// Returns `Ok(OriginValidationResult)` indicating whether the origin is
/// allowed, rejected, or allowed but out of credits. Callers use the
/// result to return the correct HTTP status (403 for CORS rejection, 402
/// for credit exhaustion).
///
/// `pii_hash_salt` is the HMAC key used for privacy-preserving origin
/// hashing in log output.
///
/// SECURITY: ORIGIN_INDEX is the sole authoritative source for allowed
/// origins. There are no env-var or per-key fallbacks. Unknown origins
/// are rejected (fail-closed).
pub async fn validate_origin(
    env: &Env,
    origin: &str,
    pii_hash_salt: &str,
) -> Result<OriginValidationResult, ApiError> {
    // M-31: Check in-memory cache before hitting KV.
    let now = cache_now();
    if let Ok(cache) = origin_cache().read() {
        if let Some(entry) = cache.get(origin) {
            if now.saturating_sub(entry.cached_at) < ORIGIN_CACHE_TTL_SECS {
                return Ok(entry.result.clone());
            }
        }
    }

    // O(1) lookup in ORIGIN_INDEX - check if origin is indexed and has credits
    let result = validate_origin_from_kv(env, origin, pii_hash_salt).await?;

    // M-31: Cache the result for future lookups within the TTL window.
    // InsufficientCredits is intentionally NOT cached because credit status
    // can change at any moment (top-up, sync). We only cache Allowed and
    // Rejected, which are stable within a 60-second window.
    if matches!(
        result,
        OriginValidationResult::Allowed | OriginValidationResult::Rejected
    ) {
        if let Ok(mut cache) = origin_cache().write() {
            // Selective eviction: remove entries older than half the TTL before
            // falling back to a full clear. This preserves hot entries when only
            // a handful of stale ones pushed the count over the limit.
            if cache.len() >= ORIGIN_CACHE_MAX_ENTRIES {
                let half_ttl = ORIGIN_CACHE_TTL_SECS / 2;
                cache.retain(|_, entry| now.saturating_sub(entry.cached_at) < half_ttl);
                if cache.len() >= ORIGIN_CACHE_MAX_ENTRIES {
                    cache.clear();
                }
            }
            cache.insert(
                origin.to_string(),
                OriginCacheEntry {
                    result: result.clone(),
                    cached_at: now,
                },
            );
        }
    }

    Ok(result)
}

/// Inner KV lookup for origin validation. Separated from `validate_origin`
/// so the caching wrapper remains readable.
async fn validate_origin_from_kv(
    env: &Env,
    origin: &str,
    pii_hash_salt: &str,
) -> Result<OriginValidationResult, ApiError> {
    if let Ok(kv) = env.kv("ORIGIN_INDEX") {
        if let Ok(Some(value)) = kv.get(origin).text().await {
            if let Ok(entry) = serde_json::from_str::<OriginIndexEntry>(&value) {
                if !entry.key_ids.is_empty() {
                    // Check credit status ONLY if metering is enabled
                    // metering_enabled == None or Some(false) means skip credit check (sandbox, demo, free tier)
                    // metering_enabled == Some(true) means enforce credit check
                    let metering_active = entry.metering_enabled == Some(true);
                    let org_id = entry
                        .organization_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string());

                    if metering_active {
                        // P4-001: Fail-CLOSED credit check.
                        // has_credits must be explicitly Some(true) to allow.
                        // Some(false) or None (not yet synced) both reject.
                        match entry.has_credits {
                            Some(true) => {
                                // Credits confirmed available - allow
                            }
                            _ => {
                                // Some(false) = exhausted, None = not synced (fail-closed)
                                let origin_hash = hash_origin(origin, pii_hash_salt);
                                let reason = if entry.has_credits == Some(false) {
                                    "credits exhausted"
                                } else {
                                    "credit status not synced (fail-closed)"
                                };
                                worker::console_warn!(
                                    "[CORS] Origin {} rejected - organization {} {} (metering enabled)",
                                    origin_hash,
                                    org_id,
                                    reason
                                );
                                return Ok(OriginValidationResult::InsufficientCredits {
                                    organization_id: org_id,
                                });
                            }
                        }
                    } else {
                        let _origin_hash = hash_origin(origin, pii_hash_salt);
                        #[cfg(target_arch = "wasm32")]
                        worker::console_log!(
                            "[CORS] Origin {} - metering disabled, skipping credit check",
                            _origin_hash
                        );
                    }

                    let _origin_hash = hash_origin(origin, pii_hash_salt);
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[CORS] Origin {} allowed via ORIGIN_INDEX (keys: {:?}, metering: {})",
                        _origin_hash,
                        entry.key_ids,
                        metering_active
                    );
                    return Ok(OriginValidationResult::Allowed);
                }
            }
        }
    }

    // Origin not found in ORIGIN_INDEX. Reject (fail-closed).
    log_rejected_origin(origin, pii_hash_salt).await;

    Ok(OriginValidationResult::Rejected)
}

/// Match origin against pattern (supports exact match and wildcard subdomains).
///
/// SECURITY: Delegates to shared `origin_matches_pattern` which
/// enforces dot-boundary checking. Prevents `evilexample.com` from matching
/// `*.example.com`.
pub fn match_origin(pattern: &str, origin: &str) -> bool {
    crate::utils::origin::origin_matches_pattern(pattern, origin)
}

/// Add CORS headers with explicit credential control.
///
/// SECURITY: `credentials` must be `true` only when the origin matched an
/// exact string in the allowed origins list. Setting credentials for
/// wildcard-matched origins would let any subdomain send credentialed
/// requests, which is a privilege escalation vector.
pub fn add_cors_headers_with_credentials(
    headers: &mut Headers,
    origin: &str,
    credentials: bool,
) -> Result<(), ApiError> {
    headers
        .set("Access-Control-Allow-Origin", origin)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORS header: {}", e)))?;

    // CH-035: Only allow methods this API actually uses
    headers
        .set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORS header: {}", e)))?;

    // CH-036: Removed Authorization (not used by this API; auth is via pk_ key headers and cookies)
    headers
        .set(
            "Access-Control-Allow-Headers",
            "Content-Type, X-API-Key, X-Public-Key, X-Request-ID, X-API-Version, Idempotency-Key, X-CSRF-Token",
        )
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORS header: {}", e)))?;

    // Only set credentials for exact origin matches, NEVER for wildcard matches.
    // Setting credentials for wildcard-matched origins would allow any subdomain
    // to send credentialed requests, which is a security vulnerability.
    if credentials {
        headers
            .set("Access-Control-Allow-Credentials", "true")
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORS header: {}", e)))?;
    }

    headers
        .set("Access-Control-Max-Age", "86400")
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORS header: {}", e)))?;

    // Expose non-simple response headers so JavaScript can read them
    headers
        .set(
            "Access-Control-Expose-Headers",
            "X-Idempotency-Replayed, X-Request-ID",
        )
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORS header: {}", e)))?;

    // Vary: Origin is required when Access-Control-Allow-Origin is not "*".
    // Without it, caches may serve a response with one origin's CORS headers
    // to a request from a different origin.
    headers
        .set("Vary", "Origin")
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set Vary header: {}", e)))?;

    // Override Cross-Origin-Resource-Policy for cross-origin API access
    // Security headers set this to "same-origin" by default, but CORS-enabled
    // endpoints need "cross-origin" to allow the browser to use the response
    headers
        .set("Cross-Origin-Resource-Policy", "cross-origin")
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set CORP header: {}", e)))?;

    Ok(())
}

/// Log rejected CORS request for security monitoring.
///
/// SECURITY: The origin is hashed before logging to avoid leaking
/// integrator URLs into plain-text logs. The tamper-proof audit event is
/// dispatched at the call site (`handle_cors_preflight_with_audit`)
/// where `Env` is accessible.
async fn log_rejected_origin(origin: &str, pii_hash_salt: &str) {
    let origin_hash = hash_origin(origin, pii_hash_salt);

    worker::console_warn!(
        "[AUDIT] CORS rejected: origin_hash={}, error=origin not in ORIGIN_INDEX",
        origin_hash
    );
}

/// Handle CORS preflight (OPTIONS) requests
///
/// Validates origin against ORIGIN_INDEX KV.
/// Returns 204 for allowed origins, 403 for rejected origins, and 402
/// (with a JSON body) when the origin is valid but credits are exhausted.
///
/// `pii_hash_salt` is the HMAC key used for privacy-preserving origin
/// hashing in log output.
pub async fn handle_cors_preflight(
    env: &Env,
    origin: Option<String>,
    pii_hash_salt: &str,
) -> Result<worker::Response, ApiError> {
    use worker::Response;

    // If no origin provided, reject
    let origin = origin.ok_or_else(|| {
        ApiError::BadRequest(Some("Missing Origin header for CORS preflight".to_string()))
    })?;

    // Validate origin against ORIGIN_INDEX KV
    let result = validate_origin(env, &origin, pii_hash_salt).await?;

    match result {
        OriginValidationResult::Rejected => {
            let origin_hash = hash_origin(&origin, pii_hash_salt);
            worker::console_warn!("[CORS Preflight] Rejected origin_hash: {}", origin_hash);
            // Return 403 for disallowed origins
            Ok(Response::empty()
                .map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!("Failed to create response: {}", e))
                })?
                .with_status(403))
        }
        OriginValidationResult::InsufficientCredits { organization_id } => {
            let origin_hash = hash_origin(&origin, pii_hash_salt);
            worker::console_warn!(
                "[CORS Preflight] Credits exhausted for origin {} (org: {})",
                origin_hash,
                organization_id
            );
            // P4-002: Return proper 402 with JSON body and CORS headers so
            // the browser can read the response (CORS headers are required
            // even for error responses on preflight).
            let body = serde_json::json!({
                "error": "insufficient_credits",
                "message": "Credit balance exhausted. Purchase more credits to continue verifying."
            });
            let mut response = Response::from_json(&body)
                .map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!("Failed to create response: {}", e))
                })?
                .with_status(402);
            add_cors_headers_with_credentials(response.headers_mut(), &origin, true)?;
            crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                &mut response,
            );
            Ok(response)
        }
        OriginValidationResult::Allowed => {
            let _origin_hash = hash_origin(&origin, pii_hash_salt);
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[CORS Preflight] Allowed origin: {}", _origin_hash);

            // Create response with CORS headers.
            // credentials=true is required because provii-agegate sends
            // credentials: 'include' for HttpOnly session cookies.
            let mut response = Response::empty()
                .map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!("Failed to create response: {}", e))
                })?
                .with_status(204);

            add_cors_headers_with_credentials(response.headers_mut(), &origin, true)?;

            // CH-052: Add security headers to CORS preflight responses
            crate::hosted::middleware::security_headers::apply_security_headers_best_effort(
                &mut response,
            );

            // Override cache-control for preflight responses. The default
            // security headers set no-store, which prevents browsers from
            // caching the preflight result despite Access-Control-Max-Age.
            // Preflight responses contain no sensitive data (just "origin
            // allowed"), so allowing the browser to cache them is safe and
            // eliminates a round-trip on every subsequent CORS request.
            response
                .headers_mut()
                .set("Cache-Control", "private, max-age=86400")?;
            response.headers_mut().delete("Pragma")?;

            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_origin_exact() {
        assert!(match_origin("https://example.com", "https://example.com"));
        assert!(!match_origin("https://example.com", "https://other.com"));
    }

    #[test]
    fn test_match_origin_wildcard() {
        // Should match subdomains
        assert!(match_origin(
            "https://*.example.com",
            "https://sub.example.com"
        ));
        assert!(match_origin(
            "https://*.example.com",
            "https://deep.sub.example.com"
        ));

        // Should NOT match base domain
        assert!(!match_origin(
            "https://*.example.com",
            "https://example.com"
        ));

        // Should NOT match different domains
        assert!(!match_origin("https://*.example.com", "https://evil.com"));
    }

    #[test]
    fn test_match_origin_scheme_sensitive() {
        assert!(!match_origin("https://example.com", "http://example.com"));
        assert!(!match_origin("http://example.com", "https://example.com"));
    }

    #[test]
    fn test_hash_origin_deterministic() {
        let salt = "test-salt";
        let h1 = hash_origin("https://example.com", salt);
        let h2 = hash_origin("https://example.com", salt);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_hash_origin_different_inputs() {
        let salt = "test-salt";
        let h1 = hash_origin("https://example.com", salt);
        let h2 = hash_origin("https://other.com", salt);
        assert_ne!(h1, h2);
    }

    // ── hash_origin: different salts ────────────────────────────────────

    #[test]
    fn test_hash_origin_different_salts() {
        let h1 = hash_origin("https://example.com", "salt-a");
        let h2 = hash_origin("https://example.com", "salt-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_origin_empty_origin() {
        let h = hash_origin("", "salt");
        assert_eq!(
            h.len(),
            64,
            "hash should be 64 hex chars even for empty input"
        );
    }

    #[test]
    fn test_hash_origin_empty_salt() {
        // HMAC accepts zero-length keys (will pad to block size)
        let h = hash_origin("https://example.com", "");
        assert_eq!(h.len(), 64);
    }

    // ── match_origin: additional edge cases ─────────────────────────────

    #[test]
    fn test_match_origin_empty_pattern() {
        assert!(!match_origin("", "https://example.com"));
    }

    #[test]
    fn test_match_origin_empty_origin() {
        assert!(!match_origin("https://example.com", ""));
    }

    #[test]
    fn test_match_origin_global_wildcard() {
        assert!(match_origin("*", "https://any.origin.com"));
        assert!(match_origin("*", "http://localhost:3000"));
    }

    #[test]
    fn test_match_origin_port_mismatch() {
        assert!(!match_origin(
            "https://example.com:443",
            "https://example.com:8443"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_port_match() {
        assert!(match_origin(
            "https://*.example.com:8443",
            "https://sub.example.com:8443"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_port_mismatch() {
        assert!(!match_origin(
            "https://*.example.com:8443",
            "https://sub.example.com:9443"
        ));
    }

    #[test]
    fn test_match_origin_case_insensitive() {
        assert!(match_origin("https://EXAMPLE.COM", "https://example.com"));
    }

    #[test]
    fn test_match_origin_wildcard_deep_subdomain() {
        assert!(match_origin(
            "https://*.example.com",
            "https://a.b.c.d.example.com"
        ));
    }

    // ── OriginValidationResult equality ─────────────────────────────────

    #[test]
    fn test_origin_validation_result_equality() {
        assert_eq!(
            OriginValidationResult::Allowed,
            OriginValidationResult::Allowed
        );
        assert_eq!(
            OriginValidationResult::Rejected,
            OriginValidationResult::Rejected
        );
        assert_ne!(
            OriginValidationResult::Allowed,
            OriginValidationResult::Rejected
        );
    }

    #[test]
    fn test_origin_validation_result_insufficient_credits() {
        let a = OriginValidationResult::InsufficientCredits {
            organization_id: "org-1".to_string(),
        };
        let b = OriginValidationResult::InsufficientCredits {
            organization_id: "org-1".to_string(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_origin_validation_result_different_orgs() {
        let a = OriginValidationResult::InsufficientCredits {
            organization_id: "org-1".to_string(),
        };
        let b = OriginValidationResult::InsufficientCredits {
            organization_id: "org-2".to_string(),
        };
        assert_ne!(a, b);
    }

    // ── OriginIndexEntry deserialisation ─────────────────────────────────

    #[test]
    fn test_origin_index_entry_deserialize_minimal() {
        let json = r#"{"key_ids":["pk_test_abc"]}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key_ids, vec!["pk_test_abc"]);
        assert_eq!(entry.organization_id, None);
        assert_eq!(entry.has_credits, None);
        assert_eq!(entry.metering_enabled, None);
    }

    #[test]
    fn test_origin_index_entry_deserialize_full() {
        let json = r#"{"key_ids":["pk_live_abc"],"organization_id":"org-123","has_credits":true,"metering_enabled":true}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key_ids, vec!["pk_live_abc"]);
        assert_eq!(entry.organization_id, Some("org-123".to_string()));
        assert_eq!(entry.has_credits, Some(true));
        assert_eq!(entry.metering_enabled, Some(true));
    }

    #[test]
    fn test_origin_index_entry_deserialize_no_credits() {
        let json = r#"{"key_ids":["k"],"has_credits":false,"metering_enabled":true}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.has_credits, Some(false));
        assert_eq!(entry.metering_enabled, Some(true));
    }

    // ── Cache constants ─────────────────────────────────────────────────

    #[test]
    fn test_origin_cache_ttl() {
        assert_eq!(ORIGIN_CACHE_TTL_SECS, 60);
    }

    #[test]
    fn test_origin_cache_max_entries() {
        assert_eq!(ORIGIN_CACHE_MAX_ENTRIES, 2048);
    }

    // ── add_cors_headers_with_credentials ────────────────────────────────

    // ADV-VA-06-007: These tests are legitimately wasm32-only because they
    // construct worker::Response objects which require the Cloudflare Workers
    // runtime. They run via wasm_bindgen_test in the wasm32 target.
    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_with_credentials_true() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://example.com", true)?;

        let h = resp.headers();
        assert_eq!(
            h.get("Access-Control-Allow-Origin")
                .ok()
                .flatten()
                .as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            h.get("Access-Control-Allow-Credentials")
                .ok()
                .flatten()
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            h.get("Access-Control-Allow-Methods")
                .ok()
                .flatten()
                .as_deref(),
            Some("GET, POST, OPTIONS")
        );
        assert_eq!(
            h.get("Access-Control-Max-Age").ok().flatten().as_deref(),
            Some("86400")
        );
        assert_eq!(h.get("Vary").ok().flatten().as_deref(), Some("Origin"));
        assert_eq!(
            h.get("Cross-Origin-Resource-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("cross-origin")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_without_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://other.com", false)?;

        let h = resp.headers();
        assert_eq!(
            h.get("Access-Control-Allow-Origin")
                .ok()
                .flatten()
                .as_deref(),
            Some("https://other.com")
        );
        // credentials=false should NOT set Access-Control-Allow-Credentials
        assert!(h
            .get("Access-Control-Allow-Credentials")
            .ok()
            .flatten()
            .is_none());
        Ok(())
    }

    // ── hash_origin: output format ─────────────────────────────────────

    #[test]
    fn test_hash_origin_output_is_lowercase_hex() {
        let h = hash_origin("https://example.com", "some-salt");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "hash must be lowercase hex only, got: {}",
            h
        );
    }

    #[test]
    fn test_hash_origin_unicode_origin() {
        let h = hash_origin("https://\u{00e9}xample.com", "salt");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_origin_long_origin() {
        let long_origin = "https://".to_string() + &"a".repeat(8000) + ".com";
        let h = hash_origin(&long_origin, "salt");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_hash_origin_domain_tag_isolation() {
        // hash_origin uses the domain tag "provii-origin-v0". Two different
        // origin strings that share a suffix must still produce different hashes.
        let h1 = hash_origin("https://a.example.com", "salt");
        let h2 = hash_origin("https://b.example.com", "salt");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_origin_both_empty() {
        let h = hash_origin("", "");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── match_origin: dot-boundary security ────────────────────

    #[test]
    fn test_match_origin_dot_boundary_attack() {
        // SECURITY: "evilexample.com" must not match "*.example.com"
        assert!(!match_origin(
            "https://*.example.com",
            "https://evilexample.com"
        ));
    }

    #[test]
    fn test_match_origin_dot_boundary_hyphen_attack() {
        assert!(!match_origin(
            "https://*.example.com",
            "https://evil-example.com"
        ));
    }

    #[test]
    fn test_match_origin_dot_boundary_prefix_attack() {
        assert!(!match_origin(
            "https://*.example.com",
            "https://notexample.com"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_no_scheme() {
        // Pattern lacking "://" should not match
        assert!(!match_origin("*.example.com", "https://sub.example.com"));
    }

    #[test]
    fn test_match_origin_both_empty() {
        assert!(!match_origin("", ""));
    }

    #[test]
    fn test_match_origin_exact_trailing_slash() {
        // Origins should not have paths, but URL normalisation adds trailing slash
        assert!(match_origin("https://example.com/", "https://example.com/"));
    }

    #[test]
    fn test_match_origin_wildcard_with_default_port() {
        // https default port (443) should match whether explicit or not
        assert!(match_origin(
            "https://*.example.com",
            "https://sub.example.com:443"
        ));
    }

    #[test]
    fn test_match_origin_exact_with_explicit_default_port() {
        assert!(match_origin(
            "https://example.com",
            "https://example.com:443"
        ));
    }

    #[test]
    fn test_match_origin_http_default_port_80() {
        assert!(match_origin("http://example.com", "http://example.com:80"));
    }

    #[test]
    fn test_match_origin_wildcard_http_port_match() {
        assert!(match_origin(
            "http://*.example.com:3000",
            "http://app.example.com:3000"
        ));
    }

    #[test]
    fn test_match_origin_malformed_origin() {
        assert!(!match_origin("https://*.example.com", "not-a-url"));
    }

    #[test]
    fn test_match_origin_malformed_pattern_with_valid_origin() {
        assert!(!match_origin("not-a-url", "https://example.com"));
    }

    #[test]
    fn test_match_origin_whitespace_only() {
        assert!(!match_origin("   ", "   "));
    }

    #[test]
    fn test_match_origin_localhost_exact() {
        assert!(match_origin(
            "http://localhost:3000",
            "http://localhost:3000"
        ));
    }

    #[test]
    fn test_match_origin_localhost_port_mismatch() {
        assert!(!match_origin(
            "http://localhost:3000",
            "http://localhost:4000"
        ));
    }

    // ── OriginValidationResult: cross-variant inequality ────────────────

    #[test]
    fn test_origin_validation_result_allowed_ne_insufficient_credits() {
        let credits = OriginValidationResult::InsufficientCredits {
            organization_id: "org-1".to_string(),
        };
        assert_ne!(OriginValidationResult::Allowed, credits);
    }

    #[test]
    fn test_origin_validation_result_rejected_ne_insufficient_credits() {
        let credits = OriginValidationResult::InsufficientCredits {
            organization_id: "org-1".to_string(),
        };
        assert_ne!(OriginValidationResult::Rejected, credits);
    }

    #[test]
    fn test_origin_validation_result_clone() {
        let original = OriginValidationResult::InsufficientCredits {
            organization_id: "org-clone".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_origin_validation_result_debug_allowed() {
        let dbg = format!("{:?}", OriginValidationResult::Allowed);
        assert_eq!(dbg, "Allowed");
    }

    #[test]
    fn test_origin_validation_result_debug_rejected() {
        let dbg = format!("{:?}", OriginValidationResult::Rejected);
        assert_eq!(dbg, "Rejected");
    }

    #[test]
    fn test_origin_validation_result_debug_insufficient_credits() {
        let result = OriginValidationResult::InsufficientCredits {
            organization_id: "org-42".to_string(),
        };
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("InsufficientCredits"));
        assert!(dbg.contains("org-42"));
    }

    // ── OriginIndexEntry: additional deserialisation paths ──────────────

    #[test]
    fn test_origin_index_entry_deserialize_empty_key_ids() {
        let json = r#"{"key_ids":[]}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).expect("valid json"); // nosemgrep: provii.workers.expect-on-external-input
        assert!(entry.key_ids.is_empty());
        assert_eq!(entry.organization_id, None);
    }

    #[test]
    fn test_origin_index_entry_deserialize_multiple_key_ids() {
        let json = r#"{"key_ids":["pk_a","pk_b","pk_c","pk_d"]}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).expect("valid json"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.key_ids.len(), 4);
        assert_eq!(entry.key_ids[0], "pk_a");
        assert_eq!(entry.key_ids[3], "pk_d");
    }

    #[test]
    fn test_origin_index_entry_deserialize_unknown_fields_ignored() {
        // Forward compatibility: unknown fields should be silently ignored
        let json = r#"{"key_ids":["k"],"future_field":"value","another":42}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).expect("valid json"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.key_ids, vec!["k"]);
    }

    #[test]
    fn test_origin_index_entry_deserialize_metering_disabled_with_credits() {
        let json = r#"{"key_ids":["k"],"has_credits":true,"metering_enabled":false}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).expect("valid json"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.has_credits, Some(true));
        assert_eq!(entry.metering_enabled, Some(false));
    }

    #[test]
    fn test_origin_index_entry_deserialize_metering_none() {
        let json = r#"{"key_ids":["k"],"has_credits":false}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).expect("valid json"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.has_credits, Some(false));
        assert_eq!(entry.metering_enabled, None);
    }

    #[test]
    fn test_origin_index_entry_deserialize_missing_key_ids_fails() {
        let json = r#"{"organization_id":"org-1"}"#;
        let result = serde_json::from_str::<OriginIndexEntry>(json);
        assert!(result.is_err(), "key_ids is required");
    }

    #[test]
    fn test_origin_index_entry_deserialize_null_optionals() {
        let json = r#"{"key_ids":["k"],"organization_id":null,"has_credits":null,"metering_enabled":null}"#;
        let entry: OriginIndexEntry = serde_json::from_str(json).expect("valid json"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(entry.organization_id, None);
        assert_eq!(entry.has_credits, None);
        assert_eq!(entry.metering_enabled, None);
    }

    // ── add_cors_headers_with_credentials: header values ────────────────

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_allow_headers_value() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://test.com", false)?;

        let h = resp.headers();
        let allow_headers = h.get("Access-Control-Allow-Headers").ok().flatten();
        let allow_headers = allow_headers.as_deref().expect("Allow-Headers must be set");
        // CH-036: Authorization is removed; these headers must be present
        assert!(allow_headers.contains("Content-Type"));
        assert!(allow_headers.contains("X-API-Key"));
        assert!(allow_headers.contains("X-Public-Key"));
        assert!(allow_headers.contains("X-Request-ID"));
        assert!(allow_headers.contains("X-API-Version"));
        assert!(allow_headers.contains("Idempotency-Key"));
        // CH-036: Authorization must NOT be in the allow list
        assert!(!allow_headers.contains("Authorization"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_expose_headers_value() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://test.com", true)?;

        let h = resp.headers();
        let expose = h.get("Access-Control-Expose-Headers").ok().flatten();
        let expose = expose.as_deref().expect("Expose-Headers must be set");
        assert!(expose.contains("X-Idempotency-Replayed"));
        assert!(expose.contains("X-Request-ID"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_origin_is_echoed_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let origin = "https://my-specific-origin.example.com:9999";
        let mut resp = worker::Response::empty()?.with_status(200);
        add_cors_headers_with_credentials(resp.headers_mut(), origin, false)?;

        let h = resp.headers();
        assert_eq!(
            h.get("Access-Control-Allow-Origin")
                .ok()
                .flatten()
                .as_deref(),
            Some(origin),
            "Origin must be echoed exactly, never reflected or wildcarded"
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_vary_always_set() -> Result<(), Box<dyn std::error::Error>> {
        // Vary: Origin is mandatory when Allow-Origin is not "*"
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://a.com", false)?;
        assert_eq!(
            resp.headers().get("Vary").ok().flatten().as_deref(),
            Some("Origin")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_corp_always_cross_origin() -> Result<(), Box<dyn std::error::Error>> {
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://a.com", true)?;
        assert_eq!(
            resp.headers()
                .get("Cross-Origin-Resource-Policy")
                .ok()
                .flatten()
                .as_deref(),
            Some("cross-origin")
        );
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_add_cors_headers_methods_restricted() -> Result<(), Box<dyn std::error::Error>> {
        // CH-035: Only GET, POST, OPTIONS should be allowed
        let mut resp = worker::Response::empty()?.with_status(204);
        add_cors_headers_with_credentials(resp.headers_mut(), "https://a.com", false)?;
        let methods = resp
            .headers()
            .get("Access-Control-Allow-Methods")
            .ok()
            .flatten()
            .expect("Methods header must be set");
        assert!(methods.contains("GET"));
        assert!(methods.contains("POST"));
        assert!(methods.contains("OPTIONS"));
        // Dangerous methods must not be allowed
        assert!(!methods.contains("PUT"));
        assert!(!methods.contains("DELETE"));
        assert!(!methods.contains("PATCH"));
        Ok(())
    }

    // ── origin_cache: initialisation and basic operations ───────────────

    #[test]
    fn test_origin_cache_returns_same_instance() {
        let cache_a = origin_cache();
        let cache_b = origin_cache();
        assert!(std::ptr::eq(cache_a, cache_b));
    }

    #[test]
    fn test_origin_cache_entry_fields() {
        let entry = OriginCacheEntry {
            result: OriginValidationResult::Allowed,
            cached_at: 1_700_000_000,
        };
        assert_eq!(entry.result, OriginValidationResult::Allowed);
        assert_eq!(entry.cached_at, 1_700_000_000);
    }

    #[test]
    fn test_origin_cache_entry_rejected() {
        let entry = OriginCacheEntry {
            result: OriginValidationResult::Rejected,
            cached_at: 0,
        };
        assert_eq!(entry.result, OriginValidationResult::Rejected);
    }

    #[test]
    fn test_origin_cache_entry_insufficient_credits() {
        let entry = OriginCacheEntry {
            result: OriginValidationResult::InsufficientCredits {
                organization_id: "org-test".to_string(),
            },
            cached_at: 999,
        };
        assert_eq!(
            entry.result,
            OriginValidationResult::InsufficientCredits {
                organization_id: "org-test".to_string(),
            }
        );
    }

    // ── match_origin: security-critical negative cases ──────────────────

    #[test]
    fn test_match_origin_wildcard_rejects_different_tld() {
        assert!(!match_origin(
            "https://*.example.com",
            "https://sub.example.org"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_case_insensitive() {
        assert!(match_origin(
            "https://*.EXAMPLE.COM",
            "https://sub.example.com"
        ));
        assert!(match_origin(
            "https://*.example.com",
            "https://SUB.EXAMPLE.COM"
        ));
    }

    #[test]
    fn test_match_origin_exact_different_host() {
        assert!(!match_origin("https://example.com", "https://example.org"));
    }

    #[test]
    fn test_match_origin_exact_different_subdomain() {
        assert!(!match_origin(
            "https://app.example.com",
            "https://api.example.com"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_single_char_subdomain() {
        assert!(match_origin(
            "https://*.example.com",
            "https://x.example.com"
        ));
    }

    #[test]
    fn test_match_origin_global_wildcard_with_port() {
        assert!(match_origin("*", "https://example.com:9999"));
    }

    #[test]
    fn test_match_origin_global_wildcard_with_http() {
        assert!(match_origin("*", "http://insecure.example.com"));
    }

    // ── hash_origin: collision resistance ───────────────────────────────

    #[test]
    fn test_hash_origin_no_collision_similar_origins() {
        let salt = "collision-test";
        let h1 = hash_origin("https://example.com", salt);
        let h2 = hash_origin("https://example.com/", salt);
        let h3 = hash_origin("https://example.com:443", salt);
        // All three are semantically similar but string-different, so hashes differ
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn test_hash_origin_special_characters() {
        let h = hash_origin("https://example.com?foo=bar&baz=qux", "salt");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── OriginIndexEntry: invalid JSON ─────────────────────────────────

    #[test]
    fn test_origin_index_entry_invalid_json() {
        let result = serde_json::from_str::<OriginIndexEntry>("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_index_entry_wrong_type_key_ids() {
        let json = r#"{"key_ids":"not-an-array"}"#;
        let result = serde_json::from_str::<OriginIndexEntry>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_index_entry_wrong_type_has_credits() {
        let json = r#"{"key_ids":["k"],"has_credits":"yes"}"#;
        let result = serde_json::from_str::<OriginIndexEntry>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_index_entry_wrong_type_metering_enabled() {
        let json = r#"{"key_ids":["k"],"metering_enabled":"yes"}"#;
        let result = serde_json::from_str::<OriginIndexEntry>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_index_entry_empty_json_object() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<OriginIndexEntry>(json);
        assert!(result.is_err(), "key_ids is required and has no default");
    }
}
