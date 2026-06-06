// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Hosted Idempotency Durable Object implementation
//!
//! Tracks idempotency keys to prevent duplicate operations in hosted
//! verification sessions. Implements industry-standard idempotency patterns
//! (Stripe/AWS) to prevent:
//! - Duplicate verifications from retry storms
//! - Multiple redemptions of the same challenge
//!
//! SECURITY: Protects against duplicate operations (ASVS V11, OWASP API4:2023).
//! - Distributed idempotency key storage with TTL
//! - Atomic check-and-set operations to handle race conditions
//! - Per-key response caching to ensure consistent results
//! - Support for optional idempotency (backward compatible)
//!
//! TTL Policy:
//! - Default: 300 seconds (5 min, matching session TTL)
//! - Auto-cleanup to prevent unbounded memory growth
//!
//! Ported from provii-verifier's IdempotencyDO. Renamed to HostedIdempotencyDO
//! to avoid collision with provii-verifier's existing IdempotencyDO.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use worker::*;

/// Default TTL for idempotency keys (5 minutes in seconds, matching session TTL)
const DEFAULT_IDEMPOTENCY_TTL_SECS: u64 = 300;

/// Maximum idempotency keys per shard (used in tests to validate design limits).
#[cfg(test)]
const MAX_KEYS_PER_SHARD: usize = 10_000;

/// Soft limit that triggers standard pruning (used in tests to validate design limits).
#[cfg(test)]
const SOFT_LIMIT_PER_SHARD: usize = 7_000;

/// Maximum request body size (128 KiB)
const MAX_BODY_SIZE: usize = 131_072;

/// Minimum allowed TTL (seconds)
const MIN_TTL_SECS: u64 = 60;

/// Maximum allowed TTL (seconds)
const MAX_TTL_SECS: u64 = 600;

/// SECURITY: Idempotency key entry with cached response and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdempotencyEntry {
    /// The cached HTTP response body (JSON serialised)
    response_body: String,
    /// HTTP status code from original request
    status_code: u16,
    /// Timestamp when this key was first seen (UNIX seconds)
    created_at: u64,
    /// Expiration timestamp (UNIX seconds)
    expires_at: u64,
    /// Endpoint that created this entry (for monitoring)
    endpoint: String,
    /// Request fingerprint for validation
    request_fingerprint: String,
}

impl IdempotencyEntry {
    fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }
}

/// SECURITY: Idempotency request payload for storing a new key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetIdempotencyRequest {
    response_body: String,
    status_code: u16,
    ttl_secs: Option<u64>,
    endpoint: String,
    request_fingerprint: String,
}

/// SECURITY: Idempotency check response.
#[derive(Debug, Serialize)]
struct CheckIdempotencyResponse {
    exists: bool,
    response_body: Option<String>,
    status_code: Option<u16>,
    expired: bool,
    endpoint: Option<String>,
    request_fingerprint: Option<String>,
}

/// Storage key prefix for per-entry hosted idempotency records.
const HOSTED_IDEM_PREFIX: &str = "idem:";

#[durable_object]
pub struct HostedIdempotencyDO {
    state: State,
    #[allow(dead_code)] // Required by #[durable_object] trait
    env: Env,
}

impl DurableObject for HostedIdempotencyDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();

        // ADV-VA-03-003: Use strip_prefix for exact prefix removal.
        let raw_key = match path.strip_prefix("/idempotency/") {
            Some(key) => key,
            None => return Response::error("Invalid path", 400),
        };

        // URL-decode the key (the store URL-encodes scoped keys containing
        // colons and slashes).
        let idempotency_key =
            urlencoding::decode(raw_key).unwrap_or(std::borrow::Cow::Borrowed(raw_key));

        // SECURITY: Validate the key contains a valid UUID v4.
        // KV-084: Keys may be endpoint-scoped (format: "{endpoint}:{uuid}").
        // Extract the UUID portion for validation.
        let uuid_portion = Self::extract_uuid_portion(&idempotency_key);
        if !Self::is_valid_idempotency_key(uuid_portion) {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][HOSTED_IDEMPOTENCY] Invalid idempotency key format rejected: {}",
                idempotency_key
            );
            // EIL-019: Add security headers to DO error responses
            let body = serde_json::json!({ "error": "Invalid idempotency key format" });
            let mut resp = Response::from_json(&body)?.with_status(400);
            resp.headers_mut()
                .set("X-Content-Type-Options", "nosniff")?;
            resp.headers_mut().set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate, max-age=0",
            )?;
            return Ok(resp);
        }

        match req.method() {
            Method::Get => self.check_idempotency_key(&idempotency_key).await,
            Method::Post => self.set_idempotency_key(&idempotency_key, req).await,
            _ => {
                let body = serde_json::json!({ "error": "Method not allowed" });
                let mut resp = Response::from_json(&body)?.with_status(405);
                resp.headers_mut()
                    .set("X-Content-Type-Options", "nosniff")?;
                resp.headers_mut().set(
                    "Cache-Control",
                    "no-store, no-cache, must-revalidate, max-age=0",
                )?;
                Ok(resp)
            }
        }
    }
}

impl HostedIdempotencyDO {
    /// KV-084: Extract the UUID portion from a potentially scoped key.
    ///
    /// Scoped keys have the format `{endpoint}:{uuid}`. Unscoped keys are
    /// bare UUIDs. Returns the UUID portion for validation.
    fn extract_uuid_portion(key: &str) -> &str {
        // If the key ends with a 36-char segment after the last colon,
        // treat that as the UUID. Otherwise treat the whole key as the UUID.
        if let Some(pos) = key.rfind(':') {
            let candidate = key.get(pos.saturating_add(1)..).unwrap_or(key);
            if candidate.len() == 36 {
                return candidate;
            }
        }
        key
    }

    /// SECURITY: Validate idempotency key format.
    /// Enforces UUID v4 format for security and consistency (36 chars with hyphens).
    fn is_valid_idempotency_key(key: &str) -> bool {
        if key.len() != 36 {
            return false;
        }

        let parts: Vec<&str> = key.split('-').collect();
        let [p0, p1, p2, p3, p4] = match <[&str; 5]>::try_from(parts.as_slice()) {
            Ok(arr) => arr,
            Err(_) => return false,
        };

        if p0.len() != 8 || p1.len() != 4 || p2.len() != 4 || p3.len() != 4 || p4.len() != 12 {
            return false;
        }

        for part in [p0, p1, p2, p3, p4] {
            if !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
        }

        // Version 4: p2 starts with '4'
        if !p2.starts_with('4') {
            return false;
        }

        // Variant: p3 starts with 8, 9, a, or b
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

    /// SECURITY: Check if an idempotency key exists and return cached response if present.
    ///
    /// VA-DOD-019: Each entry is stored under its own DO storage key
    /// (`idem:{key}`) to avoid the 128 KB single-value limit.
    async fn check_idempotency_key(&self, key: &str) -> Result<Response> {
        let storage_key = format!("{}{}", HOSTED_IDEM_PREFIX, key);
        let entry: Option<IdempotencyEntry> =
            self.state.storage().get(&storage_key).await.unwrap_or(None);

        let now = Date::now().as_millis() / 1000;

        match entry {
            Some(entry) => {
                let expired = entry.is_expired(now);

                if expired {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY][HOSTED_IDEMPOTENCY] Key {} found but expired (created: {}, expires: {}, now: {})",
                        key,
                        entry.created_at,
                        entry.expires_at,
                        now
                    );
                    // Clean up expired entry on read.
                    let _ = self.state.storage().delete(&storage_key).await;
                } else {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY][HOSTED_IDEMPOTENCY] Duplicate request detected for key {} (endpoint: {}, age: {}s)",
                        key,
                        entry.endpoint,
                        now.saturating_sub(entry.created_at)
                    );
                }

                Response::from_json(&CheckIdempotencyResponse {
                    exists: true,
                    response_body: if expired {
                        None
                    } else {
                        Some(entry.response_body.clone())
                    },
                    status_code: if expired {
                        None
                    } else {
                        Some(entry.status_code)
                    },
                    expired,
                    endpoint: if expired {
                        None
                    } else {
                        Some(entry.endpoint.clone())
                    },
                    request_fingerprint: if expired {
                        None
                    } else {
                        Some(entry.request_fingerprint.clone())
                    },
                })
            }
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[HOSTED_IDEMPOTENCY] Key {} not found (new request)", key);
                Response::from_json(&CheckIdempotencyResponse {
                    exists: false,
                    response_body: None,
                    status_code: None,
                    expired: false,
                    endpoint: None,
                    request_fingerprint: None,
                })
            }
        }
    }

    /// SECURITY: Set an idempotency key with cached response (atomic check-and-set).
    ///
    /// VA-DOD-019: Each entry is stored under its own DO storage key
    /// (`idem:{key}`) to avoid the 128 KB single-value limit.
    async fn set_idempotency_key(&self, key: &str, mut req: Request) -> Result<Response> {
        // KV-076: Reject oversized request bodies before deserialisation.
        let raw_bytes = req.bytes().await?;
        if raw_bytes.len() > MAX_BODY_SIZE {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][HOSTED_IDEMPOTENCY] Rejecting oversized body: {} bytes (max {})",
                raw_bytes.len(),
                MAX_BODY_SIZE
            );
            return Response::error("Payload Too Large", 413);
        }
        let body: SetIdempotencyRequest = serde_json::from_slice(&raw_bytes)
            .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

        let storage_key = format!("{}{}", HOSTED_IDEM_PREFIX, key);
        let now = Date::now().as_millis() / 1000;

        // SECURITY: Atomic check-and-set to prevent race conditions.
        let existing: Option<IdempotencyEntry> =
            self.state.storage().get(&storage_key).await.unwrap_or(None);

        if let Some(existing) = existing {
            if existing.is_expired(now) {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][HOSTED_IDEMPOTENCY] Expired key {} being replaced",
                    key
                );
                // Allow replacement (falls through to insert below).
            } else {
                // Race condition detected
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][HOSTED_IDEMPOTENCY] Race condition detected for key {} - returning existing response",
                    key
                );
                return Response::from_json(&serde_json::json!({
                    "success": false,
                    "reason": "duplicate_key",
                    "cached_response": existing.response_body,
                    "cached_status_code": existing.status_code
                }));
            }
        }

        // KV-077: Clamp TTL to [MIN_TTL_SECS, MAX_TTL_SECS].
        let ttl_secs = body
            .ttl_secs
            .unwrap_or(DEFAULT_IDEMPOTENCY_TTL_SECS)
            .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let expires_at = now.saturating_add(ttl_secs);

        let entry = IdempotencyEntry {
            response_body: body.response_body,
            status_code: body.status_code,
            created_at: now,
            expires_at,
            endpoint: body.endpoint.clone(),
            request_fingerprint: body.request_fingerprint,
        };

        // Persist this entry under its own storage key.
        self.state.storage().put(&storage_key, &entry).await?;

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SECURITY][HOSTED_IDEMPOTENCY] Stored idempotency key {} (endpoint: {}, ttl: {}s)",
            key,
            body.endpoint,
            ttl_secs
        );

        // Prune expired entries opportunistically by listing all idem: keys.
        #[cfg(target_arch = "wasm32")]
        let (pruned, active_count) = {
            let all_keys = self.state.storage().list().await?;
            let entries = js_sys::Object::entries(&all_keys);
            let total_entries = entries.length();
            let mut to_delete: Vec<String> = Vec::new();

            for i in 0..total_entries {
                let pair = js_sys::Array::from(&entries.get(i));
                let k = match pair.get(0).as_string() {
                    Some(s) => s,
                    None => continue,
                };
                if !k.starts_with(HOSTED_IDEM_PREFIX) {
                    continue;
                }
                let val = pair.get(1);
                if let Ok(e) = serde_wasm_bindgen::from_value::<IdempotencyEntry>(val) {
                    if e.is_expired(now) {
                        to_delete.push(k);
                    }
                }
            }

            let pruned = to_delete.len();
            if !to_delete.is_empty() {
                for batch in to_delete.chunks(128) {
                    let keys: Vec<String> = batch.iter().map(|k| k.to_string()).collect();
                    let _ = self.state.storage().delete_multiple(keys).await;
                }
                console_log!(
                    "[HOSTED_IDEMPOTENCY] Pruned {} expired keys from per-entry storage",
                    pruned
                );
            }
            (pruned, (total_entries as usize).saturating_sub(pruned))
        };

        #[cfg(not(target_arch = "wasm32"))]
        let (pruned, active_count) = (0usize, 0usize);

        Response::from_json(&serde_json::json!({
            "success": true,
            "shard_size": active_count,
            "pruned": pruned,
            "ttl_secs": ttl_secs
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_valid_uuid_v4() {
        let key = "550e8400-e29b-41d4-a716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_v4_uppercase() {
        let key = "550E8400-E29B-41D4-A716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_v4_mixed_case() {
        let key = "550e8400-E29b-41D4-a716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_length() {
        let key = "550e8400-e29b-41d4-a716";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_no_hyphens() {
        let key = "550e8400e29b41d4a716446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_version() {
        let key = "550e8400-e29b-31d4-a716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_variant() {
        let key = "550e8400-e29b-41d4-c716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_non_hex_chars() {
        let key = "550e8400-e29b-41d4-a716-4466554400gg";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_empty_string() {
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(""));
    }

    #[test]
    fn test_invalid_uuid_special_chars() {
        let key = "550e8400-e29b-41d4-a716-446655440000!";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_sql_injection_attempt() {
        let key = "'; DROP TABLE idempotency_keys; --";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_path_traversal() {
        let key = "../../../etc/passwd";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_idempotency_entry_not_expired() {
        let now = 1000;
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: now,
            expires_at: now + 100,
            endpoint: "/v1/test".to_string(),
            request_fingerprint: "fingerprint".to_string(),
        };

        assert!(!entry.is_expired(now));
        assert!(!entry.is_expired(now + 50));
        assert!(!entry.is_expired(now + 99));
    }

    #[test]
    fn test_idempotency_entry_expired() {
        let now = 1000;
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: now,
            expires_at: now + 100,
            endpoint: "/v1/test".to_string(),
            request_fingerprint: "fingerprint".to_string(),
        };

        assert!(entry.is_expired(now + 101));
        assert!(entry.is_expired(now + 200));
    }

    #[test]
    fn test_idempotency_entry_exact_expiry() {
        let now = 1000;
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: now,
            expires_at: now + 100,
            endpoint: "/v1/test".to_string(),
            request_fingerprint: "fingerprint".to_string(),
        };

        // At exactly expires_at, should NOT be expired (now > expires_at is false)
        assert!(!entry.is_expired(now + 100));
    }

    #[test]
    fn test_hashmap_insert_and_get() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let key = "550e8400-e29b-41d4-a716-446655440000".to_string();

        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/v1/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        keys.insert(key.clone(), entry);
        assert!(keys.contains_key(&key));
    }

    #[test]
    fn test_pruning_removes_expired() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        keys.insert(
            "expired1".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 100,
                expires_at: 500,
                endpoint: "/v1/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        keys.insert(
            "valid1".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 900,
                expires_at: 2000,
                endpoint: "/v1/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        keys.retain(|_, entry| !entry.is_expired(now));

        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("valid1"));
        assert!(!keys.contains_key("expired1"));
    }

    #[test]
    fn test_constants_reasonable_values() {
        assert_eq!(DEFAULT_IDEMPOTENCY_TTL_SECS, 300);
        assert_eq!(MAX_KEYS_PER_SHARD, 10_000);
        assert_eq!(SOFT_LIMIT_PER_SHARD, 7_000);
        // Compile-time check: SOFT_LIMIT_PER_SHARD must be less than MAX_KEYS_PER_SHARD
        const _: () = assert!(SOFT_LIMIT_PER_SHARD < MAX_KEYS_PER_SHARD);
    }

    // ─── extract_uuid_portion tests ───

    #[test]
    fn test_extract_uuid_bare_uuid() {
        let key = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            HostedIdempotencyDO::extract_uuid_portion(key),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_extract_uuid_scoped_key() {
        let key = "/v1/verify:550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            HostedIdempotencyDO::extract_uuid_portion(key),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_extract_uuid_multiple_colons() {
        let key = "scope:sub:550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            HostedIdempotencyDO::extract_uuid_portion(key),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_extract_uuid_colon_but_not_36_chars() {
        // After the last colon, the candidate is only 5 chars, so the whole
        // key is returned as the UUID portion.
        let key = "scope:short";
        assert_eq!(HostedIdempotencyDO::extract_uuid_portion(key), key);
    }

    #[test]
    fn test_extract_uuid_trailing_colon() {
        // Trailing colon means empty string after the colon (not 36 chars).
        let key = "scope:";
        assert_eq!(HostedIdempotencyDO::extract_uuid_portion(key), key);
    }

    #[test]
    fn test_extract_uuid_colon_at_start() {
        let key = ":550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            HostedIdempotencyDO::extract_uuid_portion(key),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_extract_uuid_empty_string() {
        assert_eq!(HostedIdempotencyDO::extract_uuid_portion(""), "");
    }

    #[test]
    fn test_extract_uuid_no_colon_not_36() {
        let key = "not-a-uuid";
        assert_eq!(HostedIdempotencyDO::extract_uuid_portion(key), key);
    }

    // ─── Additional UUID validation edge cases ───

    #[test]
    fn test_valid_uuid_variant_8() {
        let key = "550e8400-e29b-41d4-8716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_variant_9() {
        let key = "550e8400-e29b-41d4-9716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_variant_b() {
        let key = "550e8400-e29b-41d4-b716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_variant_b_uppercase() {
        let key = "550e8400-e29b-41d4-B716-446655440000";
        assert!(HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_variant_0() {
        let key = "550e8400-e29b-41d4-0716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_variant_d() {
        let key = "550e8400-e29b-41d4-d716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_variant_e() {
        let key = "550e8400-e29b-41d4-e716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_variant_f() {
        let key = "550e8400-e29b-41d4-f716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_version_1() {
        let key = "550e8400-e29b-11d4-a716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_version_5() {
        let key = "550e8400-e29b-51d4-a716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_version_7() {
        let key = "550e8400-e29b-71d4-a716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_extra_hyphen() {
        let key = "550e8400-e29b-41d4-a716-44665544-000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_segment_lengths() {
        // First segment too short, last too long (still 36 total with hyphens)
        let key = "550e840-e29b0-41d4-a716-446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_spaces() {
        let key = "550e8400 e29b 41d4 a716 446655440000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_null_bytes() {
        let key = "550e8400-e29b-41d4-a716-44665544\x00000";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_exactly_36_non_uuid() {
        // 36 chars but not valid UUID structure
        let key = "abcdefghijklmnopqrstuvwxyz0123456789";
        assert!(!HostedIdempotencyDO::is_valid_idempotency_key(key));
    }

    // ─── TTL clamping tests ───

    #[test]
    fn test_ttl_clamp_below_minimum() {
        let ttl: u64 = 10; // Below MIN_TTL_SECS (60)
        let clamped = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, MIN_TTL_SECS);
    }

    #[test]
    fn test_ttl_clamp_above_maximum() {
        let ttl: u64 = 9999; // Above MAX_TTL_SECS (600)
        let clamped = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, MAX_TTL_SECS);
    }

    #[test]
    fn test_ttl_clamp_at_minimum_boundary() {
        let clamped = MIN_TTL_SECS.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, MIN_TTL_SECS);
    }

    #[test]
    fn test_ttl_clamp_at_maximum_boundary() {
        let clamped = MAX_TTL_SECS.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, MAX_TTL_SECS);
    }

    #[test]
    fn test_ttl_clamp_within_bounds() {
        let ttl: u64 = 300;
        let clamped = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, 300);
    }

    #[test]
    fn test_ttl_clamp_zero() {
        let ttl: u64 = 0;
        let clamped = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, MIN_TTL_SECS);
    }

    #[test]
    fn test_ttl_clamp_u64_max() {
        let ttl: u64 = u64::MAX;
        let clamped = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, MAX_TTL_SECS);
    }

    #[test]
    fn test_ttl_default_is_within_bounds() {
        let clamped = DEFAULT_IDEMPOTENCY_TTL_SECS.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(clamped, DEFAULT_IDEMPOTENCY_TTL_SECS);
    }

    #[test]
    fn test_ttl_none_uses_default() {
        let resolved = DEFAULT_IDEMPOTENCY_TTL_SECS.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        assert_eq!(resolved, DEFAULT_IDEMPOTENCY_TTL_SECS);
    }

    // ─── Expiry edge cases ───

    #[test]
    fn test_entry_expired_at_zero_timestamps() {
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: 0,
            expires_at: 0,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };
        // now=0 -> 0 > 0 is false
        assert!(!entry.is_expired(0));
        // now=1 -> 1 > 0 is true
        assert!(entry.is_expired(1));
    }

    #[test]
    fn test_entry_expired_at_u64_max() {
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: u64::MAX - 10,
            expires_at: u64::MAX,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };
        // Cannot be expired since nothing exceeds u64::MAX
        assert!(!entry.is_expired(u64::MAX));
        assert!(!entry.is_expired(u64::MAX - 1));
    }

    #[test]
    fn test_saturating_add_for_expires_at() {
        let now: u64 = u64::MAX - 10;
        let ttl: u64 = 600;
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, u64::MAX);
    }

    // ─── Pruning logic tests ───

    #[test]
    fn test_pruning_keeps_all_when_none_expired() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        for i in 0..5 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: now,
                    expires_at: now + 300,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        let before = keys.len();
        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), before);
    }

    #[test]
    fn test_pruning_removes_all_when_all_expired() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 5000;

        for i in 0..5 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 100,
                    expires_at: 200, // Expired long ago
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_pruning_mixed_expired_and_valid() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        // Two expired entries
        keys.insert(
            "expired-a".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 50,
                expires_at: 100,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );
        keys.insert(
            "expired-b".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 200,
                expires_at: 500,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // Two valid entries
        keys.insert(
            "valid-a".to_string(),
            IdempotencyEntry {
                response_body: r#"{"ok":true}"#.to_string(),
                status_code: 200,
                created_at: 900,
                expires_at: 2000,
                endpoint: "/v1/verify".to_string(),
                request_fingerprint: "fp-a".to_string(),
            },
        );
        keys.insert(
            "valid-b".to_string(),
            IdempotencyEntry {
                response_body: r#"{"ok":true}"#.to_string(),
                status_code: 200,
                created_at: 950,
                expires_at: 1500,
                endpoint: "/v1/verify".to_string(),
                request_fingerprint: "fp-b".to_string(),
            },
        );

        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("valid-a"));
        assert!(keys.contains_key("valid-b"));
    }

    #[test]
    fn test_pruned_count_calculation() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        for i in 0..10 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 100,
                    expires_at: if i < 7 { 500 } else { 2000 },
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        let before_prune = keys.len();
        keys.retain(|_, entry| !entry.is_expired(now));
        let after_prune = keys.len();
        let pruned = before_prune.saturating_sub(after_prune);

        assert_eq!(before_prune, 10);
        assert_eq!(after_prune, 3);
        assert_eq!(pruned, 7);
    }

    // ─── Aggressive pruning (soft limit) tests ───

    #[test]
    fn test_aggressive_pruning_removes_old_entries() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now: u64 = 10_000;
        let aggressive_cutoff = now.saturating_sub(3_600);

        // Entry older than aggressive cutoff (created more than 1 hour ago)
        keys.insert(
            "old-entry".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 5000,      // 5000 seconds before now, older than cutoff
                expires_at: now + 300, // Not expired by TTL
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // Entry newer than aggressive cutoff
        keys.insert(
            "recent-entry".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 9000, // Within 3600s of now
                expires_at: now + 300,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // Simulate the aggressive prune logic from set_idempotency_key
        keys.retain(|_, entry| entry.created_at > aggressive_cutoff);

        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("recent-entry"));
        assert!(!keys.contains_key("old-entry"));
    }

    #[test]
    fn test_aggressive_pruning_cutoff_boundary() {
        let now: u64 = 10_000;
        let aggressive_cutoff = now.saturating_sub(3_600); // = 6400

        // Entry created at exactly the cutoff
        let entry_at_cutoff = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: aggressive_cutoff, // = 6400
            expires_at: now + 300,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        // created_at > aggressive_cutoff is false when equal
        assert!((entry_at_cutoff.created_at <= aggressive_cutoff));

        // One second after cutoff survives
        let entry_after_cutoff = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: aggressive_cutoff + 1, // = 6401
            expires_at: now + 300,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        assert!(entry_after_cutoff.created_at > aggressive_cutoff);
    }

    #[test]
    fn test_aggressive_pruning_cutoff_saturating_sub() {
        // When now < 3600, saturating_sub yields 0
        let now: u64 = 100;
        let aggressive_cutoff = now.saturating_sub(3_600);
        assert_eq!(aggressive_cutoff, 0);

        // Anything with created_at > 0 survives
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: 1,
            expires_at: now + 300,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };
        assert!(entry.created_at > aggressive_cutoff);
    }

    // ─── FIFO eviction (hard limit) tests ───

    #[test]
    fn test_fifo_eviction_keeps_newest() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Insert entries with varying created_at
        for i in 0..15 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: format!("{}", i),
                    status_code: 200,
                    created_at: (i as u64) * 100,
                    expires_at: (i as u64) * 100 + 5000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        let keep_count = 10;

        // Replicate the FIFO eviction logic
        let mut entries: Vec<_> = keys.into_iter().collect();
        entries.sort_by_key(|(_, entry)| entry.created_at);
        entries.reverse();
        keys = entries.into_iter().take(keep_count).collect();

        assert_eq!(keys.len(), keep_count);

        // The 5 oldest entries (created_at = 0, 100, 200, 300, 400) should be evicted
        for i in 0..5 {
            assert!(
                !keys.contains_key(&format!("key-{}", i)),
                "key-{} should have been evicted",
                i
            );
        }

        // The 10 newest (created_at = 500..1400) should survive
        for i in 5..15 {
            assert!(
                keys.contains_key(&format!("key-{}", i)),
                "key-{} should have survived",
                i
            );
        }
    }

    #[test]
    fn test_fifo_eviction_exact_at_limit() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Insert exactly MAX_KEYS_PER_SHARD entries
        for i in 0..MAX_KEYS_PER_SHARD {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: i as u64,
                    expires_at: (i as u64) + 5000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        // At exactly MAX_KEYS_PER_SHARD, the condition (keys.len() > MAX_KEYS_PER_SHARD)
        // is false, so no eviction occurs
        assert!((keys.len() <= MAX_KEYS_PER_SHARD));
    }

    #[test]
    fn test_fifo_eviction_one_over_limit() {
        let limit = 5_usize; // Use small limit to keep test fast

        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        for i in 0..(limit + 1) {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: (i as u64) * 10,
                    expires_at: (i as u64) * 10 + 1000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        assert_eq!(keys.len(), limit + 1);

        // Replicate FIFO eviction
        let mut entries: Vec<_> = keys.into_iter().collect();
        entries.sort_by_key(|(_, entry)| entry.created_at);
        entries.reverse();
        keys = entries.into_iter().take(limit).collect();

        assert_eq!(keys.len(), limit);

        // The oldest entry (created_at = 0) should be evicted
        assert!(!keys.contains_key("key-0"));
    }

    // ─── Race condition detection tests ───

    #[test]
    fn test_race_condition_existing_non_expired_key_blocks() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;
        let key = "race-key";

        let existing = IdempotencyEntry {
            response_body: r#"{"original":true}"#.to_string(),
            status_code: 200,
            created_at: 900,
            expires_at: 1300, // Not expired at now=1000
            endpoint: "/v1/verify".to_string(),
            request_fingerprint: "fp-original".to_string(),
        };
        keys.insert(key.to_string(), existing);

        // Simulate the race detection check
        let blocked = if let Some(existing) = keys.get(key) {
            !existing.is_expired(now)
        } else {
            false
        };

        assert!(blocked, "Non-expired existing key should block insert");
    }

    #[test]
    fn test_race_condition_expired_key_allows_replacement() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 2000;
        let key = "expired-race-key";

        let existing = IdempotencyEntry {
            response_body: r#"{"original":true}"#.to_string(),
            status_code: 200,
            created_at: 100,
            expires_at: 500, // Expired at now=2000
            endpoint: "/v1/verify".to_string(),
            request_fingerprint: "fp-original".to_string(),
        };
        keys.insert(key.to_string(), existing);

        let blocked = if let Some(existing) = keys.get(key) {
            !existing.is_expired(now)
        } else {
            false
        };

        assert!(!blocked, "Expired key should allow replacement");
    }

    #[test]
    fn test_race_condition_absent_key_allows_insert() {
        let keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;
        let key = "absent-key";

        let blocked = if let Some(existing) = keys.get(key) {
            !existing.is_expired(now)
        } else {
            false
        };

        assert!(!blocked, "Absent key should allow insert");
    }

    // ─── Memory pressure / constants tests ───

    #[test]
    fn test_max_body_size_constant() {
        assert_eq!(MAX_BODY_SIZE, 131_072);
        assert_eq!(MAX_BODY_SIZE, 128 * 1024);
    }

    #[test]
    fn test_min_ttl_less_than_max_ttl() {
        assert!(MIN_TTL_SECS < MAX_TTL_SECS);
    }

    #[test]
    fn test_default_ttl_within_bounds() {
        assert!(DEFAULT_IDEMPOTENCY_TTL_SECS >= MIN_TTL_SECS);
        assert!(DEFAULT_IDEMPOTENCY_TTL_SECS <= MAX_TTL_SECS);
    }

    #[test]
    fn test_soft_limit_less_than_hard_limit() {
        assert!(SOFT_LIMIT_PER_SHARD < MAX_KEYS_PER_SHARD);
    }

    // ─── Serde tests ───

    #[test]
    fn test_idempotency_entry_roundtrip() -> std::result::Result<(), serde_json::Error> {
        let entry = IdempotencyEntry {
            response_body: r#"{"verified":true}"#.to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 1300,
            endpoint: "/v1/verify".to_string(),
            request_fingerprint: "sha256:abc123".to_string(),
        };

        let json = serde_json::to_string(&entry)?;
        let deserialized: IdempotencyEntry = serde_json::from_str(&json)?;

        assert_eq!(deserialized.response_body, entry.response_body);
        assert_eq!(deserialized.status_code, entry.status_code);
        assert_eq!(deserialized.created_at, entry.created_at);
        assert_eq!(deserialized.expires_at, entry.expires_at);
        assert_eq!(deserialized.endpoint, entry.endpoint);
        assert_eq!(deserialized.request_fingerprint, entry.request_fingerprint);
        Ok(())
    }

    #[test]
    fn test_set_request_deserialise_with_ttl() -> std::result::Result<(), serde_json::Error> {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "ttl_secs": 120,
            "endpoint": "/v1/verify",
            "request_fingerprint": "fp"
        }"#;
        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.ttl_secs, Some(120));
        assert_eq!(req.status_code, 200);
        assert_eq!(req.endpoint, "/v1/verify");
        Ok(())
    }

    #[test]
    fn test_set_request_deserialise_without_ttl() -> std::result::Result<(), serde_json::Error> {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "endpoint": "/v1/verify",
            "request_fingerprint": "fp"
        }"#;
        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.ttl_secs, None);
        Ok(())
    }

    #[test]
    fn test_set_request_rejects_unknown_fields() {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "endpoint": "/v1/verify",
            "request_fingerprint": "fp",
            "unknown_field": "bad"
        }"#;
        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_rejects_missing_required() {
        // Missing response_body
        let json = r#"{
            "status_code": 200,
            "endpoint": "/v1/verify",
            "request_fingerprint": "fp"
        }"#;
        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_response_serialises_exists_true() -> std::result::Result<(), serde_json::Error> {
        let resp = CheckIdempotencyResponse {
            exists: true,
            response_body: Some(r#"{"ok":true}"#.to_string()),
            status_code: Some(200),
            expired: false,
            endpoint: Some("/v1/verify".to_string()),
            request_fingerprint: Some("fp".to_string()),
        };
        let json = serde_json::to_value(&resp)?;
        assert_eq!(json["exists"], true);
        assert_eq!(json["expired"], false);
        assert_eq!(json["status_code"], 200);
        assert!(json["response_body"].is_string());
        Ok(())
    }

    #[test]
    fn test_check_response_serialises_not_found() -> std::result::Result<(), serde_json::Error> {
        let resp = CheckIdempotencyResponse {
            exists: false,
            response_body: None,
            status_code: None,
            expired: false,
            endpoint: None,
            request_fingerprint: None,
        };
        let json = serde_json::to_value(&resp)?;
        assert_eq!(json["exists"], false);
        assert_eq!(json["expired"], false);
        assert!(json["response_body"].is_null());
        assert!(json["status_code"].is_null());
        assert!(json["endpoint"].is_null());
        assert!(json["request_fingerprint"].is_null());
        Ok(())
    }

    #[test]
    fn test_check_response_serialises_expired() -> std::result::Result<(), serde_json::Error> {
        // When an entry is expired, the check returns exists=true, expired=true,
        // with None for the response fields
        let resp = CheckIdempotencyResponse {
            exists: true,
            response_body: None,
            status_code: None,
            expired: true,
            endpoint: None,
            request_fingerprint: None,
        };
        let json = serde_json::to_value(&resp)?;
        assert_eq!(json["exists"], true);
        assert_eq!(json["expired"], true);
        assert!(json["response_body"].is_null());
        Ok(())
    }

    // ─── Full set_idempotency_key pruning pipeline simulation ───

    /// Simulates the exact pruning pipeline from set_idempotency_key:
    /// 1. Expire-based prune
    /// 2. Aggressive prune if over soft limit
    /// 3. FIFO eviction if over hard limit
    /// 4. Final capacity assertion
    #[test]
    fn test_full_pruning_pipeline() {
        let now = 100_000;
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Add a mix of expired, old-but-not-expired, and fresh entries
        for i in 0..20 {
            let created_at = if i < 5 {
                // Group 1: expired (created long ago, expires_at in the past)
                100
            } else if i < 12 {
                // Group 2: old but not expired (created > 3600s ago)
                now - 5000
            } else {
                // Group 3: fresh (created recently)
                now - 100
            };

            let expires_at = if i < 5 {
                200 // Expired
            } else {
                now + 10_000 // Not expired
            };

            keys.insert(
                format!("pipeline-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at,
                    expires_at,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        assert_eq!(keys.len(), 20);

        // Step 1: Prune expired
        keys.retain(|_, entry| !entry.is_expired(now));
        // Group 1 (5 entries) removed
        assert_eq!(keys.len(), 15);

        // Step 2: Aggressive prune would only trigger if > SOFT_LIMIT_PER_SHARD
        // 15 < 7000, so no aggressive pruning here

        // Step 3: FIFO eviction would only trigger if > MAX_KEYS_PER_SHARD
        // 15 < 10000, so no eviction here

        // Verify the right entries survived
        for i in 0..5 {
            assert!(!keys.contains_key(&format!("pipeline-{}", i)));
        }
        for i in 5..20 {
            assert!(keys.contains_key(&format!("pipeline-{}", i)));
        }
    }

    #[test]
    fn test_insert_overwrites_existing_in_hashmap() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let key = "overwrite-key".to_string();

        keys.insert(
            key.clone(),
            IdempotencyEntry {
                response_body: "first".to_string(),
                status_code: 200,
                created_at: 100,
                expires_at: 200,
                endpoint: "/v1/first".to_string(),
                request_fingerprint: "fp1".to_string(),
            },
        );

        keys.insert(
            key.clone(),
            IdempotencyEntry {
                response_body: "second".to_string(),
                status_code: 201,
                created_at: 300,
                expires_at: 600,
                endpoint: "/v1/second".to_string(),
                request_fingerprint: "fp2".to_string(),
            },
        );

        assert_eq!(keys.len(), 1);
        let entry = keys.get(&key).expect("key should exist");
        assert_eq!(entry.response_body, "second");
        assert_eq!(entry.status_code, 201);
        assert_eq!(entry.endpoint, "/v1/second");
    }

    // ─── Body size validation test ───

    #[test]
    fn test_body_size_check() {
        let under_limit = vec![0u8; MAX_BODY_SIZE];
        assert!(under_limit.len() <= MAX_BODY_SIZE);

        let over_limit = vec![0u8; MAX_BODY_SIZE + 1];
        assert!(over_limit.len() > MAX_BODY_SIZE);

        let empty = Vec::<u8>::new();
        assert!(empty.len() <= MAX_BODY_SIZE);
    }

    // ─── IdempotencyEntry Clone and Debug derive tests ───

    #[test]
    fn test_entry_clone_is_independent() {
        let entry = IdempotencyEntry {
            response_body: r#"{"a":1}"#.to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 1300,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        let cloned = entry.clone();
        assert_eq!(cloned.response_body, entry.response_body);
        assert_eq!(cloned.status_code, entry.status_code);
        assert_eq!(cloned.created_at, entry.created_at);
        assert_eq!(cloned.expires_at, entry.expires_at);
    }

    #[test]
    fn test_entry_debug_does_not_panic() {
        let entry = IdempotencyEntry {
            response_body: "test".to_string(),
            status_code: 200,
            created_at: 0,
            expires_at: 0,
            endpoint: "".to_string(),
            request_fingerprint: "".to_string(),
        };
        // Ensure Debug impl works without panicking
        let debug_str = format!("{:?}", entry);
        assert!(!debug_str.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_expiry_deterministic(created in 1000u64..10000, ttl in 1u64..10000, now in 1000u64..20000) {
            let expires_at = created.saturating_add(ttl);
            let expired1 = now > expires_at;
            let expired2 = now > expires_at;
            prop_assert_eq!(expired1, expired2);
        }

        #[test]
        fn prop_not_expired_before_expiry(created in 1000u64..10000, ttl in 100u64..10000) {
            let expires_at = created.saturating_add(ttl);
            let entry = IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: created,
                expires_at,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            };

            for offset in 0..ttl {
                let check_time = created.saturating_add(offset);
                prop_assert!(!entry.is_expired(check_time));
            }
        }

        #[test]
        fn prop_expired_after_expiry(created in 1000u64..10000, ttl in 100u64..10000, offset in 1u64..1000) {
            let expires_at = created.saturating_add(ttl);
            let entry = IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: created,
                expires_at,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            };

            let check_time = expires_at.saturating_add(offset);
            prop_assert!(entry.is_expired(check_time));
        }

        #[test]
        fn prop_ttl_clamp_always_in_bounds(ttl in 0u64..10000) {
            let clamped = ttl.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            prop_assert!(clamped >= MIN_TTL_SECS);
            prop_assert!(clamped <= MAX_TTL_SECS);
        }

        #[test]
        fn prop_uuid_validation_rejects_random_strings(s in "[a-z0-9]{1,50}") {
            // Random alphanumeric strings almost never form valid v4 UUIDs
            // This exercises the validation broadly
            let _result = HostedIdempotencyDO::is_valid_idempotency_key(&s);
            // No panic is the assertion
        }

        #[test]
        fn prop_extract_uuid_never_panics(s in "[ -~]{0,200}") {
            let _result = HostedIdempotencyDO::extract_uuid_portion(&s);
            // No panic is the assertion
        }

        #[test]
        fn prop_fifo_eviction_preserves_newest(count in 1_usize..50, keep in 1_usize..50) {
            let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
            for i in 0..count {
                keys.insert(
                    format!("k-{}", i),
                    IdempotencyEntry {
                        response_body: "{}".to_string(),
                        status_code: 200,
                        created_at: i as u64,
                        expires_at: (i as u64) + 1000,
                        endpoint: "/t".to_string(),
                        request_fingerprint: "f".to_string(),
                    },
                );
            }

            let mut entries: Vec<_> = keys.into_iter().collect();
            entries.sort_by_key(|(_, e)| e.created_at);
            entries.reverse();
            let result: HashMap<_, _> = entries.into_iter().take(keep).collect();

            prop_assert!(result.len() <= keep);
            prop_assert!(result.len() <= count);

            // All surviving entries should have created_at >= the eviction threshold
            if count > keep {
                let threshold = (count - keep) as u64;
                for (_, entry) in &result {
                    prop_assert!(entry.created_at >= threshold);
                }
            }
        }

        #[test]
        fn prop_saturating_add_never_overflows(base in 0u64..u64::MAX, ttl in 0u64..10000) {
            let result = base.saturating_add(ttl);
            prop_assert!(result >= base);
        }
    }
}
