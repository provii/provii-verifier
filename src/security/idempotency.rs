// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Idempotency middleware for protecting critical API endpoints.
//!
//! SECURITY: Implements idempotency key support (ASVS V11, OWASP API4:2023).
//! Prevents duplicate operations: double-billing from duplicate charge requests,
//! duplicate verifications from retry storms, multiple redemptions of the same
//! challenge, and replay of stale responses.
//!
//! Keys are scoped per method+endpoint, validated as UUID v4, and stored in
//! Durable Objects with a configurable TTL (default 24 h). On store failure the
//! middleware fails closed, rejecting the request rather than risking a duplicate.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use crate::{
    error::ApiError, security::audit::AuditLogger,
    storage::idempotency_store::DurableObjectIdempotencyStore,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use worker::{Headers, Response};

/// Default TTL for idempotency keys (24 hours in seconds)
pub const DEFAULT_IDEMPOTENCY_TTL_SECS: u64 = 86_400;

/// SECURITY: Extract idempotency key from request headers, scoped to the endpoint.
/// Returns None if no Idempotency-Key header is present (optional idempotency).
///
/// RT-042: The returned key is prefixed with `method:endpoint:` so that the same
/// Idempotency-Key header value used on different endpoints cannot collide.
///
/// # Header Format
/// `Idempotency-Key: <UUID v4>`
///
/// # Validation
/// - Must be exactly 36 characters (UUID v4 format with hyphens)
/// - Must match UUID v4 pattern: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
/// - Case-insensitive (normalised to lowercase)
/// - Scoped per method+endpoint to prevent cross-endpoint collisions
///
/// # Arguments
/// * `headers` - Request headers
/// * `method` - HTTP method (e.g., "POST")
/// * `endpoint` - Endpoint path (e.g., "/v1/verify")
///
/// # Returns
/// - Some(scoped_key) if valid Idempotency-Key header present
/// - None if no header present (idempotency is optional)
///
/// # Errors
/// - ApiError::BadRequest if header present but invalid format
pub fn extract_idempotency_key(
    headers: &Headers,
    method: &str,
    endpoint: &str,
) -> Result<Option<String>, ApiError> {
    match headers.get("Idempotency-Key") {
        Ok(Some(key)) => {
            // SECURITY: Normalise to lowercase for consistent comparison
            let normalized_key = key.to_lowercase();

            // SECURITY: Validate UUID v4 format to prevent injection attacks
            if !is_valid_uuid_v4(&normalized_key) {
                // KV-054: Truncate key in log output
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][IDEMPOTENCY] Invalid Idempotency-Key format rejected: {}",
                    key.get(..key.len().min(8)).unwrap_or(&key)
                );
                return Err(ApiError::BadRequest(Some(
                    "Invalid Idempotency-Key format (must be UUID v4)".into(),
                )));
            }

            // RT-042 + KV-053: Scope the key to method+endpoint to prevent cross-endpoint collisions.
            let scoped_key = format!("{}:{}:{}", method, endpoint, normalized_key);

            // KV-054: Truncate key in log output
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Idempotency-Key extracted (scoped to {}:{}): {}",
                method,
                endpoint,
                normalized_key
                    .get(..normalized_key.len().min(8))
                    .unwrap_or(&normalized_key)
            );
            Ok(Some(scoped_key))
        }
        Ok(None) => {
            // No idempotency key provided - this is allowed (optional idempotency)
            Ok(None)
        }
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Error reading Idempotency-Key header: {:?}",
                _e
            );
            Err(ApiError::BadRequest(Some(
                "Error reading Idempotency-Key header".into(),
            )))
        }
    }
}

/// SECURITY: Validate UUID v4 format.
/// Prevents injection attacks by ensuring strict UUID v4 format compliance.
///
/// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
/// - Version nibble (13th char after hyphens removed) must be '4'
/// - Variant nibble (17th char after hyphens removed) must be in [8, 9, a, b]
fn is_valid_uuid_v4(key: &str) -> bool {
    // UUID v4 format: 8-4-4-4-12 (36 chars total)
    if key.len() != 36 {
        return false;
    }

    // Check UUID v4 pattern: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() != 5 {
        return false;
    }

    // Validate segment lengths. We verified parts.len() == 5 above, so
    // indexing with .get() and unwrapping is safe, but we use .get() to
    // satisfy the indexing_slicing lint.
    let (p0, p1, p2, p3, p4) = match (
        parts.first(),
        parts.get(1),
        parts.get(2),
        parts.get(3),
        parts.get(4),
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => (*a, *b, *c, *d, *e),
        _ => return false,
    };
    if p0.len() != 8 || p1.len() != 4 || p2.len() != 4 || p3.len() != 4 || p4.len() != 12 {
        return false;
    }

    // Validate all characters are hex
    for part in &parts {
        if !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }

    // Validate version (4) and variant bits
    // Version 4: p2 starts with '4'
    if !p2.starts_with('4') {
        return false;
    }

    // Variant: p3 starts with 8, 9, a, or b.
    let Some(first_char) = p3.chars().next() else {
        return false;
    };
    let Some(variant_char) = first_char.to_lowercase().next() else {
        return false;
    };
    if !['8', '9', 'a', 'b'].contains(&variant_char) {
        return false;
    }

    true
}

/// SECURITY: Check if an idempotency key has been used before.
/// If it has, return the cached response. If not, return None to proceed with request processing.
///
/// # Arguments
/// * `store` - The idempotency store (Durable Objects)
/// * `key` - The idempotency key (UUID v4)
/// * `endpoint` - The endpoint name for scoped key prefixing (KV-053)
/// * `request_fingerprint` - The request fingerprint for mismatch detection (KV-032)
/// * `audit_logger` - Optional audit logger for AL-044 fail-closed events
/// * `client_ip` - Optional client IP for audit correlation
///
/// # Returns
/// Returns `Ok(Some(response))` when a duplicate request is detected, allowing the
/// caller to return the cached response directly. Returns `Ok(None)` for new requests
/// that should proceed with normal processing. Returns `Err` if the backing store is
/// unavailable or if the request fingerprint does not match a previously stored key.
pub async fn check_idempotency(
    store: &Arc<DurableObjectIdempotencyStore>,
    key: &str,
    endpoint: &str,
    request_fingerprint: &str,
    audit_logger: Option<&AuditLogger>,
    client_ip: Option<&str>,
    analytics: Option<&worker::AnalyticsEngineDataset>,
) -> Result<Option<Response>, ApiError> {
    // KV-053: Prefix key with endpoint for scoped idempotency
    let scoped_key = format!("{}:{}", endpoint, key);
    // KV-054: Truncate key in logs
    let key_truncated = key.get(..key.len().min(8)).unwrap_or(key);

    match store.check(&scoped_key).await {
        Ok(Some(cached)) if !cached.expired => {
            // KV-032 + VA-HDR-015: Validate request fingerprint matches stored
            // fingerprint. An empty stored fingerprint is treated as a mismatch
            // rather than silently passing, because it indicates a storage
            // corruption or a race between writers. Letting it through would
            // allow any subsequent request body to replay the cached response.
            if cached.request_fingerprint.is_empty() {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][IDEMPOTENCY] Empty stored fingerprint for key {} - treating as mismatch (storage corruption)",
                    key_truncated
                );
                return Err(ApiError::Conflict(Some(
                    "Idempotency key has empty fingerprint (storage corruption)".into(),
                )));
            }
            if cached.request_fingerprint != request_fingerprint {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][IDEMPOTENCY] Fingerprint mismatch for key {} - idempotency key reused for different request",
                    key_truncated
                );
                return Err(ApiError::Conflict(Some(
                    "Idempotency key reused for different request".into(),
                )));
            }

            // SECURITY: Duplicate request detected - return cached response
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Duplicate request detected for key {} - returning cached response (HTTP {})",
                key_truncated,
                cached.status_code
            );

            // Reconstruct response from cached data with correct status code
            // Note: worker::Response doesn't have status_mut(), so we create with the status
            let response = Response::from_bytes(cached.response_body.as_bytes().to_vec())
                .map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!("Failed to create response: {}", e))
                })?
                .with_status(cached.status_code);

            // Add headers
            let mut response = response;
            response
                .headers_mut()
                .set("Content-Type", "application/json; charset=utf-8")
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set header: {}", e)))?;

            // Add idempotency header to indicate this is a cached response
            response
                .headers_mut()
                .set("X-Idempotency-Replayed", "true")
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("Failed to set header: {}", e)))?;

            Ok(Some(response))
        }
        Ok(Some(_expired)) => {
            // Key exists but expired - proceed as new request
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Key {} expired - processing as new request",
                key_truncated
            );
            Ok(None)
        }
        Ok(None) => {
            // New request - proceed with processing
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] New idempotency key {} - proceeding with request",
                key_truncated
            );
            Ok(None)
        }
        Err(e) => {
            // KV-006 / RT-045: On idempotency store failure, fail closed. The request
            // MUST be rejected to prevent duplicate operations without dedup protection.
            let err_msg = format!("{:?}", e);
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Idempotency check failed for key {} - rejecting request (fail-closed)",
                key_truncated
            );
            // AL-044: Audit fail-closed on DO store failure (severity: critical).
            if let Some(logger) = audit_logger {
                logger
                    .log_idempotency_store_fail_open(
                        key_truncated,
                        &err_msg,
                        client_ip.unwrap_or("unknown"),
                        analytics,
                    )
                    .await;
            }
            Err(ApiError::ServiceUnavailable(Some(
                "Idempotency check unavailable, please retry".into(),
            )))
        }
    }
}

/// KV-032: Compute a SHA-256 request fingerprint from endpoint and identity.
///
/// This fingerprint is stored alongside the idempotency response and checked
/// on subsequent requests to detect key reuse across different operations.
///
/// Only deterministic, request-scoped fields are included. Client IP
/// is intentionally excluded because it is non-deterministic (mobile network
/// switch, VPN failover, CDN routing changes) and caused spurious cache misses
/// or 409 Conflict responses on legitimate retries.
///
/// A length-prefixed encoding is used to prevent concatenation collisions
/// (e.g. endpoint="ab", identity="c" vs endpoint="a", identity="bc").
pub fn compute_request_fingerprint(endpoint: &str, identity: &str) -> String {
    let mut hasher = Sha256::new();
    // Length-prefix each field to domain-separate them and prevent
    // concatenation collisions.
    hasher.update(endpoint.len().to_le_bytes());
    hasher.update(endpoint.as_bytes());
    hasher.update(identity.len().to_le_bytes());
    hasher.update(identity.as_bytes());
    hex::encode(hasher.finalize())
}

/// SECURITY: Store a response in the idempotency cache after successful processing.
/// This allows duplicate requests to receive the same response without reprocessing.
///
/// # Arguments
/// * `store` - The idempotency store (Durable Objects)
/// * `key` - The idempotency key (UUID v4)
/// * `response_body` - The serialised response body
/// * `status_code` - HTTP status code
/// * `endpoint` - The endpoint identifier (for scoped key prefixing and monitoring)
/// * `ttl_secs` - Optional TTL in seconds (defaults to 24 hours)
/// * `request_fingerprint` - The request fingerprint for mismatch detection (KV-032)
///
/// # Returns
/// - Ok(()) if stored successfully (or on benign failure)
/// - Does not return errors to avoid breaking the response path
pub async fn store_idempotency_response(
    store: &Arc<DurableObjectIdempotencyStore>,
    key: &str,
    response_body: String,
    status_code: u16,
    endpoint: &str,
    ttl_secs: Option<u64>,
    request_fingerprint: &str,
) -> Result<(), ApiError> {
    // KV-053: Prefix key with endpoint for scoped idempotency
    let scoped_key = format!("{}:{}", endpoint, key);
    // KV-054: Truncate key in logs
    let _key_truncated = key.get(..key.len().min(8)).unwrap_or(key);

    match store
        .store(
            &scoped_key,
            response_body,
            status_code,
            endpoint,
            ttl_secs,
            request_fingerprint,
        )
        .await
    {
        Ok(true) => {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Stored idempotency key {} for endpoint {} (ttl: {}s)",
                _key_truncated,
                endpoint,
                ttl_secs.unwrap_or(DEFAULT_IDEMPOTENCY_TTL_SECS)
            );
            Ok(())
        }
        Ok(false) => {
            // SECURITY: Race condition detected - key was already stored by concurrent request
            // This is safe to ignore as both requests produce the same response
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Race condition detected for key {} - key already stored by concurrent request (this is safe)",
                _key_truncated
            );
            Ok(())
        }
        Err(e) => {
            // KV-055: Structured JSON audit on store failure. The primary operation
            // already completed, so we log but do not fail the request.
            let _err_msg = format!("{:?}", e);
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "{}",
                serde_json::json!({
                    "level": "error",
                    "component": "idempotency",
                    "event": "store_failure",
                    "idempotency_key": _key_truncated,
                    "error": _err_msg
                })
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    UUID v4 VALIDATION TESTS                               */
    /* ========================================================================== */

    #[test]
    fn test_valid_uuid_v4() {
        let key = "550e8400-e29b-41d4-a716-446655440000";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_valid_uuid_v4_uppercase() {
        let key = "550E8400-E29B-41D4-A716-446655440000";
        assert!(is_valid_uuid_v4(&key.to_lowercase()));
    }

    #[test]
    fn test_invalid_uuid_wrong_length() {
        let key = "550e8400-e29b-41d4-a716";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_no_hyphens() {
        let key = "550e8400e29b41d4a716446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_version() {
        // Version should be 4 (third segment first char)
        let key = "550e8400-e29b-31d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_variant() {
        // Variant should be 8, 9, a, or b (fourth segment first char)
        let key = "550e8400-e29b-41d4-c716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_non_hex_chars() {
        let key = "550e8400-e29b-41d4-a716-4466554400gg";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_sql_injection() {
        let key = "'; DROP TABLE idempotency; --";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_path_traversal() {
        let key = "../../../etc/passwd";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_empty() {
        assert!(!is_valid_uuid_v4(""));
    }

    #[test]
    fn test_valid_uuid_all_lowercase() {
        let key = "abcdef01-2345-4678-9abc-def012345678";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_valid_uuid_mixed_case_normalized() {
        let key = "AbCdEf01-2345-4678-9abc-def012345678";
        assert!(is_valid_uuid_v4(&key.to_lowercase()));
    }

    /* ========================================================================== */
    /*                    CONSTANTS TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_default_ttl_constant() {
        assert_eq!(DEFAULT_IDEMPOTENCY_TTL_SECS, 86_400);
    }

    #[test]
    fn test_default_ttl_is_24_hours() {
        assert_eq!(DEFAULT_IDEMPOTENCY_TTL_SECS, 24 * 60 * 60);
    }

    /* ========================================================================== */
    /*                    UUID v4 VARIANT BIT TESTS                             */
    /* ========================================================================== */

    #[test]
    fn test_valid_uuid_variant_8() {
        // Variant nibble = '8'
        let key = "550e8400-e29b-41d4-8716-446655440000";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_valid_uuid_variant_9() {
        // Variant nibble = '9'
        let key = "550e8400-e29b-41d4-9716-446655440000";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_valid_uuid_variant_b() {
        // Variant nibble = 'b'
        let key = "550e8400-e29b-41d4-b716-446655440000";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_variant_0() {
        let key = "550e8400-e29b-41d4-0716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_variant_7() {
        let key = "550e8400-e29b-41d4-7716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_variant_d() {
        let key = "550e8400-e29b-41d4-d716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_variant_e() {
        let key = "550e8400-e29b-41d4-e716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_variant_f() {
        let key = "550e8400-e29b-41d4-f716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    /* ========================================================================== */
    /*                    UUID v4 VERSION NIBBLE TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_invalid_uuid_version_0() {
        let key = "550e8400-e29b-01d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_1() {
        let key = "550e8400-e29b-11d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_2() {
        let key = "550e8400-e29b-21d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_5() {
        let key = "550e8400-e29b-51d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_6() {
        let key = "550e8400-e29b-61d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_7() {
        let key = "550e8400-e29b-71d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_a() {
        let key = "550e8400-e29b-a1d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_version_f() {
        let key = "550e8400-e29b-f1d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    /* ========================================================================== */
    /*                    UUID v4 SEGMENT LENGTH TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_invalid_uuid_wrong_segment_lengths_correct_total() {
        // 36 chars total but wrong segment structure (9-3-4-4-12)
        let key = "550e84001-e2b-41d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_segment_too_short_first() {
        // First segment 7 chars, last 13 to keep total 36
        let key = "550e840-e29b-41d4-a716-4466554400000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_segment_too_short_last() {
        // Last segment 11 chars, first 9 to keep total 36
        let key = "550e84001-e29b-41d4-a716-44665544000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_six_segments() {
        // Six hyphen-separated segments totalling 36 chars
        let key = "550e-8400-e29b-41d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_four_segments() {
        // Four hyphen-separated segments totalling 36 chars
        let key = "550e8400e29b-41d4-a716-446655440000aa";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_three_hyphens() {
        // Only three hyphens, four segments
        let key = "550e8400-e29b41d4-a716-446655440000a";
        assert!(!is_valid_uuid_v4(key));
    }

    /* ========================================================================== */
    /*                    UUID v4 SPECIAL INPUT TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_invalid_uuid_all_hyphens() {
        let key = "------------------------------------";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_all_zeros_wrong_version() {
        // All zeros fails because version nibble is '0' not '4'
        let key = "00000000-0000-0000-0000-000000000000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_valid_uuid_nil_like_with_correct_version_variant() {
        // All zeros except version=4 and variant=8
        let key = "00000000-0000-4000-8000-000000000000";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_valid_uuid_max_hex_with_correct_version_variant() {
        // All f's except version=4 and variant=a
        let key = "ffffffff-ffff-4fff-afff-ffffffffffff";
        assert!(is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_whitespace_padded() {
        let key = " 550e8400-e29b-41d4-a716-44665544000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_trailing_whitespace() {
        let key = "550e8400-e29b-41d4-a716-44665544000 ";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_newline_embedded() {
        let key = "550e8400-e29b-41d4-a716\n446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_null_byte() {
        let key = "550e8400-e29b-41d4-a716-44665544\x0000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_unicode_homoglyph() {
        // U+0430 Cyrillic 'a' looks like Latin 'a' but is multi-byte
        let key = "550e8400-e29b-41d4-\u{0430}716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_curly_braces() {
        // Some systems wrap UUIDs in braces
        let key = "{50e8400-e29b-41d4-a716-44665544000}";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_uppercase_hex_in_version() {
        // Version nibble 'A' is not '4' even though 'A' is valid hex
        let key = "550e8400-e29b-a1d4-a716-446655440000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_single_char() {
        assert!(!is_valid_uuid_v4("x"));
    }

    #[test]
    fn test_invalid_uuid_exactly_35_chars() {
        let key = "550e8400-e29b-41d4-a716-44665544000";
        assert!(!is_valid_uuid_v4(key));
    }

    #[test]
    fn test_invalid_uuid_exactly_37_chars() {
        let key = "550e8400-e29b-41d4-a716-4466554400000";
        assert!(!is_valid_uuid_v4(key));
    }

    /* ========================================================================== */
    /*                    COMPUTE REQUEST FINGERPRINT TESTS                      */
    /* ========================================================================== */

    #[test]
    fn test_fingerprint_deterministic() {
        let fp1 = compute_request_fingerprint("/v1/verify", "client-123");
        let fp2 = compute_request_fingerprint("/v1/verify", "client-123");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_endpoints_differ() {
        let fp1 = compute_request_fingerprint("/v1/verify", "client-123");
        let fp2 = compute_request_fingerprint("/v1/challenge", "client-123");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_identities_differ() {
        let fp1 = compute_request_fingerprint("/v1/verify", "client-123");
        let fp2 = compute_request_fingerprint("/v1/verify", "client-456");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_is_sha256_hex() {
        let fp = compute_request_fingerprint("/v1/verify", "client-123");
        // SHA-256 output is 32 bytes = 64 hex chars
        assert_eq!(fp.len(), 64);
        // All characters must be lowercase hex
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(fp.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn test_fingerprint_order_matters() {
        // endpoint and identity are concatenated in order, so swapping should differ
        let fp1 = compute_request_fingerprint("alpha", "beta");
        let fp2 = compute_request_fingerprint("beta", "alpha");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_empty_endpoint() {
        let fp = compute_request_fingerprint("", "client-123");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_empty_identity() {
        let fp = compute_request_fingerprint("/v1/verify", "");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_both_empty() {
        let fp = compute_request_fingerprint("", "");
        assert_eq!(fp.len(), 64);
        // With length-prefix encoding, the hash of two empty strings
        // includes the zero-length prefixes, so it differs from SHA-256("").
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_known_vector() {
        // Pre-computed with length-prefix encoding.
        let mut hasher = Sha256::new();
        hasher.update(10usize.to_le_bytes()); // len("/v1/verify") == 10
        hasher.update(b"/v1/verify");
        hasher.update(10usize.to_le_bytes()); // len("client-123") == 10
        hasher.update(b"client-123");
        let expected = hex::encode(hasher.finalize());

        let fp = compute_request_fingerprint("/v1/verify", "client-123");
        assert_eq!(fp, expected);
    }

    #[test]
    fn test_fingerprint_unicode_inputs() {
        let fp = compute_request_fingerprint("/v1/verify", "\u{00E9}\u{00F1}\u{00FC}");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_fingerprint_long_inputs() {
        let long_endpoint = "/v1/".to_string() + &"a".repeat(10_000);
        let long_identity = "id-".to_string() + &"b".repeat(10_000);
        let fp = compute_request_fingerprint(&long_endpoint, &long_identity);
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn test_fingerprint_boundary_concatenation_is_domain_separated() {
        // Length-prefixed encoding prevents concatenation collisions.
        // "ab" + "c" vs "a" + "bc" now produce different hashes because the
        // length prefix distinguishes them.
        let fp1 = compute_request_fingerprint("ab", "c");
        let fp2 = compute_request_fingerprint("a", "bc");
        assert_ne!(fp1, fp2);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Valid UUID v4 passes validation
        #[test]
        fn prop_valid_uuid_v4(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{3}",
            d in "[0-9a-f]{3}",
            e in "[0-9a-f]{12}"
        ) {
            // Construct valid UUID v4 with correct version and variant
            let key = format!("{}-{}-4{}-a{}-{}", a, b, c, d, e);
            prop_assert!(is_valid_uuid_v4(&key));
        }

        /// Property: Invalid length UUIDs fail validation
        #[test]
        fn prop_invalid_length(len in 1usize..100) {
            prop_assume!(len != 36);
            let key = "a".repeat(len);
            prop_assert!(!is_valid_uuid_v4(&key));
        }

        /// Property: Non-hex characters fail validation
        #[test]
        fn prop_non_hex_chars(s in "[^0-9a-fA-F-]{36}") {
            prop_assert!(!is_valid_uuid_v4(&s));
        }

        /// Property: All four valid variant nibbles produce valid UUIDs
        #[test]
        fn prop_valid_uuid_all_variants(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{3}",
            d in "[0-9a-f]{3}",
            e in "[0-9a-f]{12}",
            variant in proptest::sample::select(vec!['8', '9', 'a', 'b'])
        ) {
            let key = format!("{}-{}-4{}-{}{}-{}", a, b, c, variant, d, e);
            prop_assert!(is_valid_uuid_v4(&key));
        }

        /// Property: Non-4 version nibbles produce invalid UUIDs
        #[test]
        fn prop_invalid_uuid_wrong_version(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{3}",
            d in "[0-9a-f]{3}",
            e in "[0-9a-f]{12}",
            version in "[0-35-9a-f]"
        ) {
            let key = format!("{}-{}-{}{}-a{}-{}", a, b, version, c, d, e);
            prop_assert!(!is_valid_uuid_v4(&key));
        }

        /// Property: Invalid variant nibbles produce invalid UUIDs
        #[test]
        fn prop_invalid_uuid_wrong_variant(
            a in "[0-9a-f]{8}",
            b in "[0-9a-f]{4}",
            c in "[0-9a-f]{3}",
            d in "[0-9a-f]{3}",
            e in "[0-9a-f]{12}",
            variant in "[0-7c-f]"
        ) {
            let key = format!("{}-{}-4{}-{}{}-{}", a, b, c, variant, d, e);
            prop_assert!(!is_valid_uuid_v4(&key));
        }

        /// Property: Fingerprint output is always 64 hex chars
        #[test]
        fn prop_fingerprint_length(
            endpoint in "\\PC{0,200}",
            identity in "\\PC{0,200}"
        ) {
            let fp = compute_request_fingerprint(&endpoint, &identity);
            prop_assert_eq!(fp.len(), 64);
            prop_assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        }

        /// Property: Fingerprint is deterministic
        #[test]
        fn prop_fingerprint_deterministic(
            endpoint in "\\PC{0,100}",
            identity in "\\PC{0,100}"
        ) {
            let fp1 = compute_request_fingerprint(&endpoint, &identity);
            let fp2 = compute_request_fingerprint(&endpoint, &identity);
            prop_assert_eq!(fp1, fp2);
        }
    }
}
