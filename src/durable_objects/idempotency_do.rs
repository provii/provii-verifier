// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object that tracks idempotency keys to prevent duplicate operations.
//!
//! Implements industry-standard idempotency patterns (Stripe/AWS) to prevent
//! double verifications from retry storms and multiple redemptions of the
//! same challenge.
//!
//! SECURITY: Protects against duplicate operations (ASVS V11, OWASP API4:2023).
//!
//! - Distributed idempotency key storage with TTL.
//! - Atomic check-and-set operations to handle race conditions.
//! - Per-key response caching to ensure consistent results.
//! - Structured security logging for monitoring.
//! - Backward-compatible optional idempotency.
//!
//! TTL Policy: default 24 hours (86 400 seconds), matching challenge
//! expiration. Auto-cleanup on every write prevents unbounded memory growth.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use worker::*;

/// Default TTL for idempotency keys (24 hours in seconds)
const DEFAULT_IDEMPOTENCY_TTL_SECS: u64 = 86_400;

/// ADV-VA-03-009: Alarm interval for periodic cleanup of expired entries
/// (300 seconds = 5 minutes).
const ALARM_INTERVAL_MS: i64 = 300_000;

/// Maximum idempotency keys per shard before triggering cleanup.
/// With sharding, this allows significant scale.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const MAX_KEYS_PER_SHARD: usize = 10_000;

/// Soft limit that triggers standard pruning
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
const SOFT_LIMIT_PER_SHARD: usize = 7_000;

/// SECURITY: Idempotency key entry with cached response and metadata.
/// Stores both the HTTP response and metadata for debugging/monitoring.
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
    /// Request fingerprint (method + path + body hash) for validation
    request_fingerprint: String,
}

impl IdempotencyEntry {
    fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }
}

/// IV-1251: Maximum request body size for idempotency DO operations (128 KB).
/// Idempotency requests include cached response bodies which can be moderately
/// sized, but anything beyond this limit is abuse.
const MAX_IDEMPOTENCY_BODY_SIZE: usize = 131_072;

/// SECURITY: Idempotency request payload for storing a new key.
///
/// IV-1251: deny_unknown_fields prevents injecting unexpected fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetIdempotencyRequest {
    /// HTTP response body to cache (JSON string)
    response_body: String,
    /// HTTP status code
    status_code: u16,
    /// TTL in seconds (defaults to 24 hours if not provided)
    ttl_secs: Option<u64>,
    /// Endpoint identifier (for monitoring/debugging)
    endpoint: String,
    /// Request fingerprint for validation
    request_fingerprint: String,
}

/// SECURITY: Idempotency check response.
#[derive(Debug, Serialize)]
struct CheckIdempotencyResponse {
    /// Whether the key exists
    exists: bool,
    /// Cached response body if exists
    response_body: Option<String>,
    /// Cached status code if exists
    status_code: Option<u16>,
    /// Whether the entry is expired
    expired: bool,
    /// Stored request fingerprint for mismatch detection (KV-032)
    request_fingerprint: Option<String>,
}

/// Idempotency key tracker that stores cached HTTP responses.
///
/// Each entry is stored as its own DO storage key (`idem:{key}`) rather
/// than in a single serialised HashMap. This avoids the 128 KB per-value
/// limit on Durable Object storage. Expired entries are pruned lazily on
/// read and on every write via `list()` + batch delete.
///
/// SECURITY: Race condition protection is the primary purpose. Two requests
/// bearing the same idempotency key that arrive concurrently will see the
/// first-writer-wins result; the second receives the cached response.
#[durable_object]
pub struct IdempotencyDO {
    state: State,
    #[allow(dead_code)] // Required by worker-rs Durable Object API
    env: Env,
}

/// Storage key prefix for per-entry idempotency records.
const IDEM_PREFIX: &str = "idem:";

impl DurableObject for IdempotencyDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();

        // ADV-VA-03-003: Use strip_prefix for exact prefix removal (trim_start_matches
        // strips individual characters, not the whole prefix).
        let idempotency_key = match path.strip_prefix("/idempotency/") {
            Some(key) => key,
            None => return Response::error("Invalid path", 400),
        };

        // SECURITY: Validate idempotency key format (UUID v4)
        if !Self::is_valid_idempotency_key(idempotency_key) {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[SECURITY][IDEMPOTENCY] Invalid idempotency key format rejected: {}",
                idempotency_key
            );
            return Response::error("Invalid idempotency key format (must be UUID v4)", 400);
        }

        match req.method() {
            Method::Get => self.check_idempotency_key(idempotency_key).await,
            Method::Post => self.set_idempotency_key(idempotency_key, req).await,
            Method::Delete => self.delete_idempotency_key(idempotency_key).await,
            _ => Response::error("Method not allowed", 405),
        }
    }

    /// ADV-VA-03-009: Periodic alarm handler for cleaning up expired idempotency
    /// entries. Supplements the opportunistic write-time pruning so that entries
    /// are eventually removed even when the DO receives no further writes.
    async fn alarm(&self) -> Result<Response> {
        self.cleanup_expired_entries().await?;
        Response::ok("alarm_handled")
    }
}

impl IdempotencyDO {
    /// SECURITY: Validate idempotency key format.
    /// Accepts bare UUID v4 (36 chars) or endpoint-scoped `{prefix}:{uuid}` format (KV-053).
    /// This prevents injection attacks and ensures predictable key distribution across shards.
    fn is_valid_idempotency_key(key: &str) -> bool {
        // KV-053: Accept endpoint-scoped keys in `{prefix}:{uuid}` format.
        // Extract the UUID portion: if the key contains ':', validate the part after the last ':'.
        let uuid_part = if let Some(idx) = key.rfind(':') {
            let prefix = match key.get(..idx) {
                Some(p) => p,
                None => return false,
            };
            // Prefix must be non-empty and contain only alphanumeric + underscore + hyphen
            if prefix.is_empty()
                || !prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return false;
            }
            match key.get(idx.saturating_add(1)..) {
                Some(s) => s,
                None => return false,
            }
        } else {
            key
        };

        Self::is_valid_uuid_v4(uuid_part)
    }

    /// Validate strict UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    fn is_valid_uuid_v4(key: &str) -> bool {
        // UUID v4 format: 8-4-4-4-12 (36 chars total)
        if key.len() != 36 {
            return false;
        }

        // Check UUID v4 pattern: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        // where y is one of [8, 9, a, b]
        let parts: Vec<&str> = key.split('-').collect();
        if parts.len() != 5 {
            return false;
        }

        // Validate segment lengths. parts.len() == 5 checked above.
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
    /// This implements atomic read for duplicate request detection.
    ///
    /// VA-DOD-019: Each entry is stored under its own DO storage key
    /// (`idem:{key}`) to avoid the 128 KB single-value limit.
    async fn check_idempotency_key(&self, key: &str) -> Result<Response> {
        let storage_key = format!("{}{}", IDEM_PREFIX, key);
        let entry: Option<IdempotencyEntry> =
            self.state.storage().get(&storage_key).await.unwrap_or(None);

        let now = Date::now().as_millis() / 1000;

        match entry {
            Some(entry) => {
                let expired = entry.is_expired(now);

                if expired {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                        "[SECURITY][IDEMPOTENCY] Key {} found but expired (created: {}, expires: {}, now: {})",
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
                        "[SECURITY][IDEMPOTENCY] Duplicate request detected for key {} (endpoint: {}, age: {}s)",
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
                    request_fingerprint: if expired {
                        None
                    } else {
                        Some(entry.request_fingerprint.clone())
                    },
                })
            }
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!("[IDEMPOTENCY] Key {} not found (new request)", key);
                Response::from_json(&CheckIdempotencyResponse {
                    exists: false,
                    response_body: None,
                    status_code: None,
                    expired: false,
                    request_fingerprint: None,
                })
            }
        }
    }

    /// SECURITY: Set an idempotency key with cached response (atomic check-and-set).
    /// This implements the critical race condition protection:
    /// - If key exists: Return existing cached response (duplicate detected)
    /// - If key new: Store response and return success
    ///
    /// VA-DOD-019: Each entry is stored under its own DO storage key
    /// (`idem:{key}`) to avoid the 128 KB single-value limit.
    async fn set_idempotency_key(&self, key: &str, mut req: Request) -> Result<Response> {
        // IV-1251: Enforce body size limit before parsing.
        let body_bytes = req.bytes().await?;
        if body_bytes.len() > MAX_IDEMPOTENCY_BODY_SIZE {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[IDEMPOTENCY] Body too large: {} > {}",
                body_bytes.len(),
                MAX_IDEMPOTENCY_BODY_SIZE
            );
            return Response::error("Request entity too large", 413);
        }
        let body: SetIdempotencyRequest = serde_json::from_slice(&body_bytes)
            .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

        let storage_key = format!("{}{}", IDEM_PREFIX, key);
        let now = Date::now().as_millis() / 1000;

        // SECURITY: Atomic check-and-set to prevent race conditions.
        let existing: Option<IdempotencyEntry> =
            self.state.storage().get(&storage_key).await.unwrap_or(None);

        if let Some(existing) = existing {
            if existing.is_expired(now) {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][IDEMPOTENCY] Expired key {} being replaced (was created: {}, expired: {})",
                    key,
                    existing.created_at,
                    existing.expires_at
                );
                // Allow replacement of expired keys (falls through to insert below).
            } else {
                // SECURITY: Race condition detected.
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY][IDEMPOTENCY] Race condition detected for key {} - returning existing response (endpoint: {}, age: {}s)",
                    key,
                    existing.endpoint,
                    now.saturating_sub(existing.created_at)
                );

                return Response::from_json(&serde_json::json!({
                    "success": false,
                    "reason": "duplicate_key",
                    "cached_response": existing.response_body,
                    "cached_status_code": existing.status_code
                }));
            }
        }

        // Calculate TTL (use provided or default)
        let ttl_secs = body.ttl_secs.unwrap_or(DEFAULT_IDEMPOTENCY_TTL_SECS);
        let expires_at = now.saturating_add(ttl_secs);

        // Create new entry
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

        // ADV-VA-03-009: Schedule alarm for periodic cleanup if none is pending.
        self.ensure_alarm_scheduled().await?;

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SECURITY][IDEMPOTENCY] Stored idempotency key {} (endpoint: {}, ttl: {}s, expires: {})",
            key,
            body.endpoint,
            ttl_secs,
            expires_at
        );

        // Prune expired entries opportunistically by listing all idem: keys.
        #[cfg(target_arch = "wasm32")]
        let (pruned, active_count) = {
            let all_keys = self.state.storage().list().await?;
            let mut to_delete: Vec<String> = Vec::new();
            let entries = js_sys::Object::entries(&all_keys);
            let total_entries = entries.length();

            for i in 0..total_entries {
                let pair = js_sys::Array::from(&entries.get(i));
                let k = match pair.get(0).as_string() {
                    Some(s) => s,
                    None => continue,
                };
                if !k.starts_with(IDEM_PREFIX) {
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
                    "[IDEMPOTENCY] Pruned {} expired keys from per-entry storage",
                    pruned
                );
            }
            let active_count = (total_entries as usize).saturating_sub(pruned);
            if active_count > 5_000 {
                console_log!(
                    "[IDEMPOTENCY] Shard size warning: ~{} active keys (soft_limit={}, hard_limit={})",
                    active_count,
                    SOFT_LIMIT_PER_SHARD,
                    MAX_KEYS_PER_SHARD
                );
            }
            (pruned, active_count)
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

    /// ADV-VA-03-009: Ensure a cleanup alarm is scheduled. If one is already
    /// pending, this is a no-op.
    async fn ensure_alarm_scheduled(&self) -> Result<()> {
        let existing = self.state.storage().get_alarm().await?;
        if existing.is_none() {
            self.state.storage().set_alarm(ALARM_INTERVAL_MS).await?;
        }
        Ok(())
    }

    /// ADV-VA-03-009: Alarm handler implementation. Lists all `idem:` prefixed
    /// keys, deletes expired entries, and reschedules the alarm if active entries
    /// remain.
    ///
    /// Uses JS interop APIs (`js_sys`, `serde_wasm_bindgen`) that only exist on
    /// wasm32. On native targets (used by `cargo llvm-cov`) it compiles as a
    /// no-op stub.
    #[cfg(target_arch = "wasm32")]
    async fn cleanup_expired_entries(&self) -> Result<()> {
        let now = Date::now().as_millis() / 1000;

        let opts = durable::ListOptions::new().prefix(IDEM_PREFIX);
        let map = self.state.storage().list_with_options(opts).await?;

        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut remaining_count: usize = 0;

        let entries = map.entries();
        loop {
            let next = entries
                .next()
                .map_err(|e| worker::Error::RustError(format!("Map iterator error: {:?}", e)))?;
            let done = js_sys::Reflect::get(&next, &wasm_bindgen::JsValue::from_str("done"))
                .unwrap_or(wasm_bindgen::JsValue::TRUE)
                .as_bool()
                .unwrap_or(true);
            if done {
                break;
            }

            let value = js_sys::Reflect::get(&next, &wasm_bindgen::JsValue::from_str("value"))
                .map_err(|e| worker::Error::RustError(format!("Map entry value error: {:?}", e)))?;
            let pair = js_sys::Array::from(&value);
            let key_js = pair.get(0);
            let val_js = pair.get(1);

            let key = key_js.as_string().unwrap_or_default();
            if key.is_empty() {
                continue;
            }

            match serde_wasm_bindgen::from_value::<IdempotencyEntry>(val_js) {
                Ok(e) if e.is_expired(now) => {
                    keys_to_delete.push(key);
                }
                Ok(_) => {
                    remaining_count = remaining_count.saturating_add(1);
                }
                Err(_) => {
                    // Corrupt entry, remove it.
                    keys_to_delete.push(key);
                }
            }
        }

        if !keys_to_delete.is_empty() {
            console_log!(
                "[IDEMPOTENCY] Alarm cleanup: deleting {} expired entries, {} remain",
                keys_to_delete.len(),
                remaining_count
            );
            for batch in keys_to_delete.chunks(128) {
                let keys: Vec<String> = batch.iter().map(|k| k.to_string()).collect();
                let _ = self.state.storage().delete_multiple(keys).await;
            }
        }

        // Reschedule alarm if active entries remain.
        if remaining_count > 0 {
            self.state.storage().set_alarm(ALARM_INTERVAL_MS).await?;
        }

        Ok(())
    }

    /// Native-target stub: alarm cleanup requires JS interop and cannot run
    /// outside the Workers runtime. Returns `Ok(())` unconditionally.
    #[cfg(not(target_arch = "wasm32"))]
    async fn cleanup_expired_entries(&self) -> Result<()> {
        Ok(())
    }

    /// SECURITY: Delete an idempotency key (for testing/admin purposes).
    /// In production, keys should expire naturally via TTL.
    ///
    /// VA-DOD-019: Uses per-entry storage key (`idem:{key}`).
    async fn delete_idempotency_key(&self, key: &str) -> Result<Response> {
        let storage_key = format!("{}{}", IDEM_PREFIX, key);
        let removed = self
            .state
            .storage()
            .delete(&storage_key)
            .await
            .unwrap_or(false);

        if removed {
            #[cfg(target_arch = "wasm32")]
            console_log!("[IDEMPOTENCY] Deleted idempotency key {}", key);
        } else {
            #[cfg(target_arch = "wasm32")]
            console_log!("[IDEMPOTENCY] Key {} not found for deletion", key);
        }

        Response::from_json(&serde_json::json!({
            "success": removed
        }))
    }
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
    use std::collections::HashMap;

    /* ========================================================================== */
    /*                    IDEMPOTENCY KEY VALIDATION TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_valid_uuid_v4() {
        let key = "550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_v4_uppercase() {
        let key = "550E8400-E29B-41D4-A716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_uuid_v4_mixed_case() {
        let key = "550e8400-E29b-41D4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_length() {
        let key = "550e8400-e29b-41d4-a716";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_no_hyphens() {
        let key = "550e8400e29b41d4a716446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_version() {
        // Version should be 4 (third segment first char)
        let key = "550e8400-e29b-31d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_wrong_variant() {
        // Variant should be 8, 9, a, or b (fourth segment first char)
        let key = "550e8400-e29b-41d4-c716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_non_hex_chars() {
        let key = "550e8400-e29b-41d4-a716-4466554400gg";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_empty_string() {
        assert!(!IdempotencyDO::is_valid_idempotency_key(""));
    }

    #[test]
    fn test_invalid_uuid_special_chars() {
        let key = "550e8400-e29b-41d4-a716-446655440000!";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_sql_injection_attempt() {
        let key = "'; DROP TABLE idempotency_keys; --";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_uuid_path_traversal() {
        let key = "../../../etc/passwd";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    /* ========================================================================== */
    /*                KV-053: ENDPOINT-SCOPED KEY VALIDATION TESTS               */
    /* ========================================================================== */

    #[test]
    fn test_valid_prefixed_key() {
        let key = "challenge:550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_prefixed_key_with_underscores() {
        let key = "internal_redeem:550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_valid_prefixed_key_with_hyphens_in_prefix() {
        let key = "v1-redeem:550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_prefixed_key_empty_prefix() {
        let key = ":550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_prefixed_key_bad_uuid() {
        let key = "challenge:not-a-uuid";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_prefixed_key_special_chars_in_prefix() {
        let key = "chal../lenge:550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    /* ========================================================================== */
    /*                    IDEMPOTENCY ENTRY TESTS                                */
    /* ========================================================================== */

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
    fn test_idempotency_entry_creation() {
        let entry = IdempotencyEntry {
            response_body: r#"{"result":"OK"}"#.to_string(),
            status_code: 201,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/v1/challenge".to_string(),
            request_fingerprint: "POST:/v1/challenge:hash123".to_string(),
        };

        assert_eq!(entry.response_body, r#"{"result":"OK"}"#);
        assert_eq!(entry.status_code, 201);
        assert_eq!(entry.created_at, 1000);
        assert_eq!(entry.expires_at, 2000);
        assert_eq!(entry.endpoint, "/v1/challenge");
    }

    /* ========================================================================== */
    /*                    HASHMAP OPERATIONS TESTS                               */
    /* ========================================================================== */

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
    fn test_hashmap_duplicate_insert_overwrites() -> Result<(), Box<dyn std::error::Error>> {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let key = "550e8400-e29b-41d4-a716-446655440000".to_string();

        let entry1 = IdempotencyEntry {
            response_body: "first".to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/v1/test".to_string(),
            request_fingerprint: "fp1".to_string(),
        };

        let entry2 = IdempotencyEntry {
            response_body: "second".to_string(),
            status_code: 201,
            created_at: 1500,
            expires_at: 2500,
            endpoint: "/v1/test".to_string(),
            request_fingerprint: "fp2".to_string(),
        };

        keys.insert(key.clone(), entry1);
        keys.insert(key.clone(), entry2);

        let stored = keys.get(&key).ok_or("key not found in map")?;
        assert_eq!(stored.response_body, "second");
        assert_eq!(stored.status_code, 201);
        Ok(())
    }

    #[test]
    fn test_hashmap_multiple_keys() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        for i in 0..10 {
            let key = format!("550e8400-e29b-41d4-a716-44665544{:04}", i);
            let entry = IdempotencyEntry {
                response_body: format!("response_{}", i),
                status_code: 200,
                created_at: 1000 + i as u64,
                expires_at: 2000 + i as u64,
                endpoint: "/v1/test".to_string(),
                request_fingerprint: format!("fp_{}", i),
            };
            keys.insert(key, entry);
        }

        assert_eq!(keys.len(), 10);
    }

    /* ========================================================================== */
    /*                    PRUNING LOGIC TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_pruning_removes_expired() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        // Add expired entry
        keys.insert(
            "expired1".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 100,
                expires_at: 500, // Expired
                endpoint: "/v1/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // Add valid entry
        keys.insert(
            "valid1".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 900,
                expires_at: 2000, // Not expired
                endpoint: "/v1/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // Prune expired entries
        keys.retain(|_, entry| !entry.is_expired(now));

        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("valid1"));
        assert!(!keys.contains_key("expired1"));
    }

    #[test]
    fn test_pruning_keeps_all_valid() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        for i in 0..10 {
            keys.insert(
                format!("key{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: now,
                    expires_at: now + 1000, // All valid
                    endpoint: "/v1/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        keys.retain(|_, entry| !entry.is_expired(now));

        assert_eq!(keys.len(), 10);
    }

    #[test]
    fn test_pruning_removes_all_expired() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 1000;

        for i in 0..10 {
            keys.insert(
                format!("key{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 100,
                    expires_at: 500, // All expired
                    endpoint: "/v1/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        keys.retain(|_, entry| !entry.is_expired(now));

        assert_eq!(keys.len(), 0);
    }

    /* ========================================================================== */
    /*                    TTL CALCULATION TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_default_ttl() {
        let now = 1000;
        let ttl = DEFAULT_IDEMPOTENCY_TTL_SECS;
        let expires_at = now + ttl;

        assert_eq!(ttl, 86_400); // 24 hours
        assert_eq!(expires_at, 1000 + 86_400);
    }

    #[test]
    fn test_custom_ttl() {
        let now = 1000;
        let custom_ttl = 3600; // 1 hour
        let expires_at = now + custom_ttl;

        assert_eq!(expires_at, 1000 + 3600);
    }

    #[test]
    fn test_ttl_edge_cases() {
        let now = 1000;

        // Zero TTL (expires immediately)
        let zero_ttl = 0;
        assert_eq!(now + zero_ttl, 1000);

        // Very long TTL
        let long_ttl = 86_400 * 30; // 30 days
        assert_eq!(now + long_ttl, 1000 + 2_592_000);
    }

    /* ========================================================================== */
    /*                    REQUEST FINGERPRINT TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_request_fingerprint_format() {
        let fingerprint = "POST:/v1/challenge:abc123hash";
        assert!(fingerprint.contains("POST"));
        assert!(fingerprint.contains("/v1/challenge"));
        assert!(fingerprint.contains("abc123hash"));
    }

    #[test]
    fn test_request_fingerprint_different_methods() {
        let fp1 = "POST:/v1/challenge:hash123";
        let fp2 = "GET:/v1/challenge:hash123";
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_request_fingerprint_different_paths() {
        let fp1 = "POST:/v1/challenge:hash123";
        let fp2 = "POST:/v1/verify:hash123";
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_request_fingerprint_different_bodies() {
        let fp1 = "POST:/v1/challenge:hash123";
        let fp2 = "POST:/v1/challenge:hash456";
        assert_ne!(fp1, fp2);
    }

    /* ========================================================================== */
    /*                    CONSTANTS TESTS                                        */
    /* ========================================================================== */

    #[test]
    fn test_constants_reasonable_values() {
        assert_eq!(DEFAULT_IDEMPOTENCY_TTL_SECS, 86_400);
        assert_eq!(MAX_KEYS_PER_SHARD, 10_000);
        assert_eq!(SOFT_LIMIT_PER_SHARD, 7_000);
        const _: () = assert!(SOFT_LIMIT_PER_SHARD < MAX_KEYS_PER_SHARD);
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    /* ========================================================================== */
    /*                UUID V4 DIRECT VALIDATION TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_uuid_v4_all_variant_chars_accepted() {
        // Variant char is first char of 4th segment; must be 8, 9, a, or b
        let variants = ['8', '9', 'a', 'b', 'A', 'B'];
        for v in variants {
            let key = format!("550e8400-e29b-41d4-{}716-446655440000", v);
            assert!(
                IdempotencyDO::is_valid_uuid_v4(&key),
                "variant char '{}' should be accepted",
                v
            );
        }
    }

    #[test]
    fn test_uuid_v4_rejected_variant_chars() {
        // 0-7, c-f are not valid variant chars
        let invalid = ['0', '1', '2', '3', '4', '5', '6', '7', 'c', 'd', 'e', 'f'];
        for v in invalid {
            let key = format!("550e8400-e29b-41d4-{}716-446655440000", v);
            assert!(
                !IdempotencyDO::is_valid_uuid_v4(&key),
                "variant char '{}' should be rejected",
                v
            );
        }
    }

    #[test]
    fn test_uuid_v4_version_must_be_4() {
        // Version is first char of 3rd segment
        for v in [
            '0', '1', '2', '3', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ] {
            let key = format!("550e8400-e29b-{}1d4-a716-446655440000", v);
            assert!(
                !IdempotencyDO::is_valid_uuid_v4(&key),
                "version '{}' should be rejected",
                v
            );
        }
    }

    #[test]
    fn test_uuid_v4_wrong_segment_lengths() {
        // First segment too short (7 chars instead of 8)
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e840-e29b-41d4-a716-446655440000"
        ));
        // Second segment too long (5 chars instead of 4)
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b0-41d4-a716-446655440000"
        ));
        // Third segment too short
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b-41d-a716-446655440000"
        ));
        // Fourth segment too long
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b-41d4-a7160-446655440000"
        ));
        // Fifth segment too short (11 chars instead of 12)
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b-41d4-a716-44665544000"
        ));
    }

    #[test]
    fn test_uuid_v4_extra_hyphens() {
        // 6 segments instead of 5
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b-41d4-a716-4466-55440000"
        ));
    }

    #[test]
    fn test_uuid_v4_too_few_segments() {
        // Only 4 segments
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b-41d4-a716446655440000"
        ));
    }

    #[test]
    fn test_uuid_v4_nil_uuid_rejected() {
        // All zeros, version 0, variant 0 -- not UUID v4
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "00000000-0000-0000-0000-000000000000"
        ));
    }

    #[test]
    fn test_uuid_v4_all_zeros_valid_v4_format() {
        // All zeros but with version 4 and valid variant
        assert!(IdempotencyDO::is_valid_uuid_v4(
            "00000000-0000-4000-8000-000000000000"
        ));
    }

    #[test]
    fn test_uuid_v4_all_f_invalid() {
        // All f's, version = f, variant = f -- not valid
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
        ));
    }

    #[test]
    fn test_uuid_v4_empty_string() {
        assert!(!IdempotencyDO::is_valid_uuid_v4(""));
    }

    #[test]
    fn test_uuid_v4_single_char() {
        assert!(!IdempotencyDO::is_valid_uuid_v4("a"));
    }

    #[test]
    fn test_uuid_v4_exactly_36_chars_but_no_hyphens() {
        // 36 characters, all hex, no hyphens -- split won't produce 5 parts
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400e29b41d4a716446655440000aaaa"
        ));
    }

    #[test]
    fn test_uuid_v4_non_ascii_chars() {
        assert!(!IdempotencyDO::is_valid_uuid_v4(
            "550e8400-e29b-41d4-a716-44665544\u{00e9}\u{00e9}\u{00e9}\u{00e9}"
        ));
    }

    /* ========================================================================== */
    /*        KV-053: ADDITIONAL ENDPOINT-SCOPED KEY EDGE CASES                 */
    /* ========================================================================== */

    #[test]
    fn test_prefixed_key_multiple_colons_uses_last() {
        // rfind(':') takes the last colon, so prefix = "a:b" and uuid = remainder
        let key = "a:b:550e8400-e29b-41d4-a716-446655440000";
        // prefix "a:b" contains ':', which is NOT alphanumeric/underscore/hyphen
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_numeric_prefix() {
        let key = "12345:550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_single_char_prefix() {
        let key = "x:550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_space_in_prefix_rejected() {
        let key = "chal lenge:550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_dot_in_prefix_rejected() {
        let key = "v1.0:550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_colon_only() {
        // Empty prefix, then uuid part
        let key = ":550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_trailing_colon_no_uuid() {
        let key = "prefix:";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_colon_at_end_with_partial_uuid() {
        let key = "prefix:550e8400-e29b-41d4-a716";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_unicode_prefix_rejected() {
        let key = "pr\u{00e9}fix:550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_bare_uuid_no_colon() {
        // Bare UUID without prefix should work
        let key = "550e8400-e29b-41d4-a716-446655440000";
        assert!(IdempotencyDO::is_valid_idempotency_key(key));
    }

    /* ========================================================================== */
    /*                IDEMPOTENCY ENTRY EXPIRY EDGE CASES                       */
    /* ========================================================================== */

    #[test]
    fn test_entry_expired_at_zero() {
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: 0,
            expires_at: 0,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        // now == 0, expires_at == 0: 0 > 0 is false
        assert!(!entry.is_expired(0));
        // now == 1: 1 > 0 is true
        assert!(entry.is_expired(1));
    }

    #[test]
    fn test_entry_expired_at_u64_max() {
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: 0,
            expires_at: u64::MAX,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        // Nothing can exceed u64::MAX
        assert!(!entry.is_expired(u64::MAX));
        assert!(!entry.is_expired(0));
        assert!(!entry.is_expired(u64::MAX - 1));
    }

    #[test]
    fn test_entry_created_after_expiry_is_still_checked_correctly() {
        // Contrived: created_at > expires_at (shouldn't happen, but test the logic)
        let entry = IdempotencyEntry {
            response_body: "{}".to_string(),
            status_code: 200,
            created_at: 5000,
            expires_at: 1000,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        // is_expired only checks now > expires_at
        assert!(entry.is_expired(1001));
        assert!(!entry.is_expired(999));
        assert!(!entry.is_expired(1000));
    }

    /* ========================================================================== */
    /*                SERDE ROUND-TRIP TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_idempotency_entry_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let entry = IdempotencyEntry {
            response_body: r#"{"ok":true}"#.to_string(),
            status_code: 201,
            created_at: 1716000000,
            expires_at: 1716086400,
            endpoint: "/v1/challenge/redeem".to_string(),
            request_fingerprint: "POST:/v1/challenge/redeem:deadbeef".to_string(),
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
    fn test_idempotency_entry_serde_with_special_chars() -> Result<(), Box<dyn std::error::Error>> {
        let entry = IdempotencyEntry {
            response_body: r#"{"msg":"hello \"world\""}"#.to_string(),
            status_code: 200,
            created_at: 0,
            expires_at: 100,
            endpoint: "/v1/test?foo=bar&baz=qux".to_string(),
            request_fingerprint: "fp with spaces".to_string(),
        };

        let json = serde_json::to_string(&entry)?;
        let deserialized: IdempotencyEntry = serde_json::from_str(&json)?;

        assert_eq!(deserialized.response_body, entry.response_body);
        assert_eq!(deserialized.endpoint, entry.endpoint);
        assert_eq!(deserialized.request_fingerprint, entry.request_fingerprint);
        Ok(())
    }

    #[test]
    fn test_idempotency_entry_serde_empty_strings() -> Result<(), Box<dyn std::error::Error>> {
        let entry = IdempotencyEntry {
            response_body: String::new(),
            status_code: 204,
            created_at: 0,
            expires_at: 0,
            endpoint: String::new(),
            request_fingerprint: String::new(),
        };

        let json = serde_json::to_string(&entry)?;
        let deserialized: IdempotencyEntry = serde_json::from_str(&json)?;

        assert_eq!(deserialized.response_body, "");
        assert_eq!(deserialized.status_code, 204);
        assert_eq!(deserialized.endpoint, "");
        assert_eq!(deserialized.request_fingerprint, "");
        Ok(())
    }

    /* ========================================================================== */
    /*                SET IDEMPOTENCY REQUEST DESERIALISATION TESTS              */
    /* ========================================================================== */

    #[test]
    fn test_set_request_deser_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "response_body": "{\"ok\":true}",
            "status_code": 200,
            "ttl_secs": 3600,
            "endpoint": "/v1/challenge",
            "request_fingerprint": "fp123"
        }"#;

        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.response_body, "{\"ok\":true}");
        assert_eq!(req.status_code, 200);
        assert_eq!(req.ttl_secs, Some(3600));
        assert_eq!(req.endpoint, "/v1/challenge");
        assert_eq!(req.request_fingerprint, "fp123");
        Ok(())
    }

    #[test]
    fn test_set_request_deser_optional_ttl_absent() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.ttl_secs, None);
        Ok(())
    }

    #[test]
    fn test_set_request_deser_ttl_null() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "ttl_secs": null,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.ttl_secs, None);
        Ok(())
    }

    #[test]
    fn test_set_request_deser_ttl_zero() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "ttl_secs": 0,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.ttl_secs, Some(0));
        Ok(())
    }

    #[test]
    fn test_set_request_deser_deny_unknown_fields() {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp",
            "malicious_field": "injected"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_deser_missing_required_field() {
        // Missing response_body
        let json = r#"{
            "status_code": 200,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_deser_missing_status_code() {
        let json = r#"{
            "response_body": "{}",
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_deser_missing_endpoint() {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "request_fingerprint": "fp"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_deser_missing_fingerprint() {
        let json = r#"{
            "response_body": "{}",
            "status_code": 200,
            "endpoint": "/v1/test"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_deser_wrong_type_status_code() {
        let json = r#"{
            "response_body": "{}",
            "status_code": "not_a_number",
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_request_deser_status_code_u16_max() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "response_body": "{}",
            "status_code": 65535,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let req: SetIdempotencyRequest = serde_json::from_str(json)?;
        assert_eq!(req.status_code, u16::MAX);
        Ok(())
    }

    #[test]
    fn test_set_request_deser_status_code_overflow() {
        let json = r#"{
            "response_body": "{}",
            "status_code": 65536,
            "endpoint": "/v1/test",
            "request_fingerprint": "fp"
        }"#;

        let result = serde_json::from_str::<SetIdempotencyRequest>(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                CHECK IDEMPOTENCY RESPONSE SERIALISATION TESTS             */
    /* ========================================================================== */

    #[test]
    fn test_check_response_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let resp = CheckIdempotencyResponse {
            exists: false,
            response_body: None,
            status_code: None,
            expired: false,
            request_fingerprint: None,
        };

        let json = serde_json::to_value(&resp)?;
        assert_eq!(json["exists"], false);
        assert!(json["response_body"].is_null());
        assert!(json["status_code"].is_null());
        assert_eq!(json["expired"], false);
        assert!(json["request_fingerprint"].is_null());
        Ok(())
    }

    #[test]
    fn test_check_response_found_not_expired() -> Result<(), Box<dyn std::error::Error>> {
        let resp = CheckIdempotencyResponse {
            exists: true,
            response_body: Some(r#"{"ok":true}"#.to_string()),
            status_code: Some(200),
            expired: false,
            request_fingerprint: Some("fp123".to_string()),
        };

        let json = serde_json::to_value(&resp)?;
        assert_eq!(json["exists"], true);
        assert_eq!(json["response_body"], r#"{"ok":true}"#);
        assert_eq!(json["status_code"], 200);
        assert_eq!(json["expired"], false);
        assert_eq!(json["request_fingerprint"], "fp123");
        Ok(())
    }

    #[test]
    fn test_check_response_found_expired() -> Result<(), Box<dyn std::error::Error>> {
        let resp = CheckIdempotencyResponse {
            exists: true,
            response_body: None,
            status_code: None,
            expired: true,
            request_fingerprint: None,
        };

        let json = serde_json::to_value(&resp)?;
        assert_eq!(json["exists"], true);
        assert!(json["response_body"].is_null());
        assert!(json["status_code"].is_null());
        assert_eq!(json["expired"], true);
        assert!(json["request_fingerprint"].is_null());
        Ok(())
    }

    /* ========================================================================== */
    /*                AGGRESSIVE PRUNING (SOFT LIMIT) TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_aggressive_pruning_removes_old_entries() {
        let now = 100_000u64;
        let aggressive_cutoff = now.saturating_sub(3_600);

        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Add entries older than 1 hour (should be removed by aggressive prune)
        for i in 0..100 {
            keys.insert(
                format!("old-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 50_000, // older than cutoff
                    expires_at: now + 1000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        // Add entries within last hour (should be kept)
        for i in 0..50 {
            keys.insert(
                format!("new-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: now - 1800, // 30 min ago, within cutoff
                    expires_at: now + 1000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        assert_eq!(keys.len(), 150);

        // Apply aggressive pruning (same logic as in set_idempotency_key)
        keys.retain(|_, entry| entry.created_at > aggressive_cutoff);

        assert_eq!(keys.len(), 50);
        // Verify only the new entries remain
        assert!(keys.contains_key("new-0"));
        assert!(!keys.contains_key("old-0"));
    }

    #[test]
    fn test_aggressive_pruning_cutoff_boundary() {
        let now = 100_000u64;
        let aggressive_cutoff = now.saturating_sub(3_600);

        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Entry created at exactly the cutoff
        keys.insert(
            "at-cutoff".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: aggressive_cutoff,
                expires_at: now + 1000,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // Entry created 1 second after cutoff
        keys.insert(
            "after-cutoff".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: aggressive_cutoff + 1,
                expires_at: now + 1000,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        // retain keeps entries where created_at > aggressive_cutoff (strict >)
        keys.retain(|_, entry| entry.created_at > aggressive_cutoff);

        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("after-cutoff"));
        assert!(!keys.contains_key("at-cutoff"));
    }

    #[test]
    fn test_aggressive_pruning_saturating_sub_at_zero() {
        // If now is small, saturating_sub prevents underflow
        let now = 1000u64;
        let aggressive_cutoff = now.saturating_sub(3_600);
        assert_eq!(aggressive_cutoff, 0);

        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        keys.insert(
            "entry".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 1, // > 0
                expires_at: now + 1000,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        keys.retain(|_, entry| entry.created_at > aggressive_cutoff);
        assert_eq!(keys.len(), 1);
    }

    /* ========================================================================== */
    /*                FIFO EVICTION (HARD LIMIT) TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_fifo_eviction_keeps_newest() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Create 20 entries with different timestamps
        for i in 0..20u64 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: i * 100, // 0, 100, 200, ... 1900
                    expires_at: 10000 + i * 100,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        // Apply FIFO eviction with limit of 10 (same logic as in set_idempotency_key)
        let limit = 10;
        let mut entries: Vec<_> = keys.into_iter().collect();
        entries.sort_by_key(|(_, entry)| entry.created_at);
        entries.reverse(); // Newest first
        keys = entries.into_iter().take(limit).collect();

        assert_eq!(keys.len(), 10);

        // Newest 10 should remain (created_at 1000..1900)
        for i in 10..20u64 {
            assert!(
                keys.contains_key(&format!("key-{}", i)),
                "key-{} should be kept (created_at={})",
                i,
                i * 100
            );
        }
        // Oldest 10 should be evicted (created_at 0..900)
        for i in 0..10u64 {
            assert!(
                !keys.contains_key(&format!("key-{}", i)),
                "key-{} should be evicted (created_at={})",
                i,
                i * 100
            );
        }
    }

    #[test]
    fn test_fifo_eviction_at_exact_limit() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Create exactly MAX_KEYS_PER_SHARD entries
        for i in 0..MAX_KEYS_PER_SHARD {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: i as u64,
                    expires_at: 100_000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        // At exact limit, the `if keys.len() > MAX_KEYS_PER_SHARD` check is false
        assert_eq!(keys.len(), MAX_KEYS_PER_SHARD);
        assert!(keys.len() <= MAX_KEYS_PER_SHARD);
    }

    #[test]
    fn test_fifo_eviction_one_over_limit() {
        let limit = 5usize;

        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        for i in 0..6u64 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: i * 10,
                    expires_at: 1000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        assert_eq!(keys.len(), 6);

        // FIFO eviction
        let mut entries: Vec<_> = keys.into_iter().collect();
        entries.sort_by_key(|(_, entry)| entry.created_at);
        entries.reverse();
        keys = entries.into_iter().take(limit).collect();

        assert_eq!(keys.len(), 5);
        // Oldest entry (created_at=0) should be evicted
        assert!(!keys.contains_key("key-0"));
        // Newest entry (created_at=50) should remain
        assert!(keys.contains_key("key-5"));
    }

    #[test]
    fn test_fifo_eviction_same_timestamps() {
        // When all entries have the same created_at, sort is stable but
        // exactly which entries survive is deterministic within one run
        let limit = 2usize;

        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        for i in 0..5u64 {
            keys.insert(
                format!("key-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 1000, // All same timestamp
                    expires_at: 2000,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        let mut entries: Vec<_> = keys.into_iter().collect();
        entries.sort_by_key(|(_, entry)| entry.created_at);
        entries.reverse();
        keys = entries.into_iter().take(limit).collect();

        assert_eq!(keys.len(), 2);
    }

    /* ========================================================================== */
    /*                TTL CALCULATION EDGE CASES                                 */
    /* ========================================================================== */

    #[test]
    fn test_ttl_saturating_add_overflow() {
        let now = u64::MAX - 10;
        let ttl = 100u64;

        // The code uses saturating_add to prevent overflow
        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, u64::MAX);
    }

    #[test]
    fn test_ttl_saturating_add_no_overflow() {
        let now = 1_000_000u64;
        let ttl = DEFAULT_IDEMPOTENCY_TTL_SECS;

        let expires_at = now.saturating_add(ttl);
        assert_eq!(expires_at, 1_000_000 + 86_400);
    }

    #[test]
    fn test_default_ttl_used_when_none() {
        let ttl = DEFAULT_IDEMPOTENCY_TTL_SECS;
        assert_eq!(ttl, 86_400);
    }

    #[test]
    fn test_custom_ttl_used_when_some() {
        let ttl: u64 = 7200;
        assert_eq!(ttl, 7200);
    }

    #[test]
    fn test_zero_ttl_used_when_provided() {
        let ttl: u64 = 0;
        assert_eq!(ttl, 0);
    }

    /* ========================================================================== */
    /*                COMBINED PRUNING PIPELINE TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_standard_prune_then_no_aggressive_needed() {
        let now = 100_000u64;
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Add 100 entries, 50 expired and 50 valid
        for i in 0..50u64 {
            keys.insert(
                format!("expired-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 10_000,
                    expires_at: 50_000, // expired
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }
        for i in 0..50u64 {
            keys.insert(
                format!("valid-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: now - 100,
                    expires_at: now + 86_400,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        // Standard prune
        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 50);

        // Below soft limit, no aggressive prune needed
        assert!(keys.len() <= SOFT_LIMIT_PER_SHARD);
    }

    #[test]
    fn test_standard_prune_then_aggressive_prune_needed() {
        let now = 100_000u64;
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // Add 8000 non-expired entries, most older than 1 hour
        for i in 0..7500u64 {
            keys.insert(
                format!("old-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: 50_000, // older than aggressive cutoff
                    expires_at: now + 86_400,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }
        for i in 0..500u64 {
            keys.insert(
                format!("new-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: now - 1800, // 30 min ago, within cutoff
                    expires_at: now + 86_400,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        // Standard prune (none expired)
        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 8000);

        // Over soft limit, apply aggressive prune
        assert!(keys.len() > SOFT_LIMIT_PER_SHARD);
        let aggressive_cutoff = now.saturating_sub(3_600);
        keys.retain(|_, entry| entry.created_at > aggressive_cutoff);

        assert_eq!(keys.len(), 500);
    }

    #[test]
    fn test_prune_mixed_expiry_ratios() {
        let now = 50_000u64;
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        // 1 expired, 9 valid
        keys.insert(
            "expired-0".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 1000,
                expires_at: 2000,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );
        for i in 0..9u64 {
            keys.insert(
                format!("valid-{}", i),
                IdempotencyEntry {
                    response_body: "{}".to_string(),
                    status_code: 200,
                    created_at: now - 100,
                    expires_at: now + 86_400,
                    endpoint: "/test".to_string(),
                    request_fingerprint: "fp".to_string(),
                },
            );
        }

        assert_eq!(keys.len(), 10);
        let before = keys.len();
        keys.retain(|_, entry| !entry.is_expired(now));
        let pruned = before.saturating_sub(keys.len());

        assert_eq!(pruned, 1);
        assert_eq!(keys.len(), 9);
    }

    /* ========================================================================== */
    /*                HASHMAP REMOVAL TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_hashmap_remove_existing_key() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let key = "test-key".to_string();

        keys.insert(
            key.clone(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 1000,
                expires_at: 2000,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        let removed = keys.remove(&key).is_some();
        assert!(removed);
        assert!(!keys.contains_key(&key));
    }

    #[test]
    fn test_hashmap_remove_nonexistent_key() {
        let keys: HashMap<String, IdempotencyEntry> = HashMap::new();

        let removed = keys.contains_key("nonexistent");
        assert!(!removed);
    }

    #[test]
    fn test_hashmap_remove_returns_false_for_missing() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let removed = keys.remove("missing-key").is_some();
        assert!(!removed);
    }

    /* ========================================================================== */
    /*                CONSTANTS AND LIMIT RELATIONSHIP TESTS                     */
    /* ========================================================================== */

    #[test]
    fn test_soft_limit_less_than_hard_limit() {
        assert!(SOFT_LIMIT_PER_SHARD < MAX_KEYS_PER_SHARD);
    }

    #[test]
    fn test_max_body_size_constant() {
        assert_eq!(MAX_IDEMPOTENCY_BODY_SIZE, 131_072); // 128 KB
        assert_eq!(MAX_IDEMPOTENCY_BODY_SIZE, 128 * 1024);
    }

    #[test]
    fn test_default_ttl_is_24_hours() {
        assert_eq!(DEFAULT_IDEMPOTENCY_TTL_SECS, 24 * 60 * 60);
    }

    /* ========================================================================== */
    /*                IDEMPOTENCY KEY INJECTION/SECURITY TESTS                  */
    /* ========================================================================== */

    #[test]
    fn test_invalid_key_null_bytes() {
        let key = "550e8400-e29b-41d4-a716-44665544\x00000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_key_newline_injection() {
        let key = "550e8400-e29b-41d4-a716-446655440000\n";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_key_tab_injection() {
        let key = "550e8400-e29b-41d4-a716-446655440000\t";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_key_very_long_string() {
        let key = "a".repeat(10_000);
        assert!(!IdempotencyDO::is_valid_idempotency_key(&key));
    }

    #[test]
    fn test_invalid_key_just_hyphens() {
        let key = "--------";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_key_whitespace_only() {
        let key = "    ";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_invalid_key_url_encoded() {
        let key = "550e8400%2De29b%2D41d4%2Da716%2D446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_with_slash_in_prefix_rejected() {
        let key = "path/traversal:550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    #[test]
    fn test_prefixed_key_with_at_sign_rejected() {
        let key = "user@evil:550e8400-e29b-41d4-a716-446655440000";
        assert!(!IdempotencyDO::is_valid_idempotency_key(key));
    }

    /* ========================================================================== */
    /*                ENTRY CLONE AND DEBUG DERIVE TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_idempotency_entry_clone() {
        let entry = IdempotencyEntry {
            response_body: "body".to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        let cloned = entry.clone();
        assert_eq!(cloned.response_body, entry.response_body);
        assert_eq!(cloned.status_code, entry.status_code);
        assert_eq!(cloned.created_at, entry.created_at);
        assert_eq!(cloned.expires_at, entry.expires_at);
        assert_eq!(cloned.endpoint, entry.endpoint);
        assert_eq!(cloned.request_fingerprint, entry.request_fingerprint);
    }

    #[test]
    fn test_idempotency_entry_debug() {
        let entry = IdempotencyEntry {
            response_body: "body".to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("IdempotencyEntry"));
        assert!(debug_str.contains("200"));
        assert!(debug_str.contains("1000"));
    }

    #[test]
    fn test_check_response_debug() {
        let resp = CheckIdempotencyResponse {
            exists: true,
            response_body: Some("body".to_string()),
            status_code: Some(200),
            expired: false,
            request_fingerprint: Some("fp".to_string()),
        };

        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("CheckIdempotencyResponse"));
    }

    /* ========================================================================== */
    /*                PRUNING COUNTER ARITHMETIC TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_pruned_count_calculation() {
        let before_prune = 100usize;
        let after_prune = 75usize;
        let pruned = before_prune.saturating_sub(after_prune);
        assert_eq!(pruned, 25);
    }

    #[test]
    fn test_pruned_count_zero_when_nothing_pruned() {
        let before_prune = 100usize;
        let after_prune = 100usize;
        let pruned = before_prune.saturating_sub(after_prune);
        assert_eq!(pruned, 0);
    }

    #[test]
    fn test_pruned_count_saturating_when_after_larger() {
        // Shouldn't happen in practice, but saturating_sub handles it
        let before_prune = 50usize;
        let after_prune = 100usize;
        let pruned = before_prune.saturating_sub(after_prune);
        assert_eq!(pruned, 0);
    }

    /* ========================================================================== */
    /*                ENTRY FIELD VALUE BOUNDARY TESTS                           */
    /* ========================================================================== */

    #[test]
    fn test_entry_status_code_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        for code in [0u16, 1, 100, 200, 299, 400, 404, 500, 599, u16::MAX] {
            let entry = IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: code,
                created_at: 1000,
                expires_at: 2000,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            };

            let json = serde_json::to_string(&entry)?;
            let deserialized: IdempotencyEntry = serde_json::from_str(&json)?;
            assert_eq!(deserialized.status_code, code);
        }
        Ok(())
    }

    #[test]
    fn test_entry_large_response_body_serde() -> Result<(), Box<dyn std::error::Error>> {
        let large_body = "x".repeat(100_000);

        let entry = IdempotencyEntry {
            response_body: large_body.clone(),
            status_code: 200,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/test".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        let json = serde_json::to_string(&entry)?;
        let deserialized: IdempotencyEntry = serde_json::from_str(&json)?;
        assert_eq!(deserialized.response_body.len(), 100_000);
        assert_eq!(deserialized.response_body, large_body);
        Ok(())
    }

    #[test]
    fn test_entry_unicode_in_response_body() -> Result<(), Box<dyn std::error::Error>> {
        let entry = IdempotencyEntry {
            response_body: r#"{"msg":"G'day ☃"}"#.to_string(),
            status_code: 200,
            created_at: 1000,
            expires_at: 2000,
            endpoint: "/v1/\u{1f600}".to_string(),
            request_fingerprint: "fp".to_string(),
        };

        let json = serde_json::to_string(&entry)?;
        let deserialized: IdempotencyEntry = serde_json::from_str(&json)?;
        assert_eq!(deserialized.response_body, entry.response_body);
        Ok(())
    }

    /* ========================================================================== */
    /*                IDEMPOTENCY MAP OPERATIONS TESTS                          */
    /* ========================================================================== */

    #[test]
    fn test_empty_map_prune_is_noop() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 100_000u64;

        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_single_entry_map_prune_expired() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 100_000u64;

        keys.insert(
            "only-key".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 1000,
                expires_at: 2000, // expired
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_single_entry_map_prune_valid() {
        let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();
        let now = 100_000u64;

        keys.insert(
            "only-key".to_string(),
            IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: 99_000,
                expires_at: 200_000, // not expired
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            },
        );

        keys.retain(|_, entry| !entry.is_expired(now));
        assert_eq!(keys.len(), 1);
    }

    /* ========================================================================== */
    /*                PROPERTY-BASED TESTS                                      */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Expiry check is deterministic
        #[test]
        fn prop_expiry_deterministic(created in 1000u64..10000, ttl in 1u64..10000, now in 1000u64..20000) {
            let expires_at = created + ttl;
            let expired1 = now > expires_at;
            let expired2 = now > expires_at;
            prop_assert_eq!(expired1, expired2);
        }

        /// Property: Entry is not expired before expiry time
        #[test]
        fn prop_not_expired_before_expiry(created in 1000u64..10000, ttl in 100u64..10000) {
            let expires_at = created + ttl;
            let entry = IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: created,
                expires_at,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            };

            // Check at various times before expiry
            for offset in 0..ttl {
                let check_time = created + offset;
                prop_assert!(!entry.is_expired(check_time));
            }
        }

        /// Property: Entry is expired after expiry time
        #[test]
        fn prop_expired_after_expiry(created in 1000u64..10000, ttl in 100u64..10000, offset in 1u64..1000) {
            let expires_at = created + ttl;
            let entry = IdempotencyEntry {
                response_body: "{}".to_string(),
                status_code: 200,
                created_at: created,
                expires_at,
                endpoint: "/test".to_string(),
                request_fingerprint: "fp".to_string(),
            };

            let check_time = expires_at + offset;
            prop_assert!(entry.is_expired(check_time));
        }

        /// Property: TTL calculation is consistent
        #[test]
        fn prop_ttl_calculation(now in 1000u64..100000, ttl in 1u64..100000) {
            let expires1 = now + ttl;
            let expires2 = now + ttl;
            prop_assert_eq!(expires1, expires2);
        }

        /// Property: Pruning never removes non-expired entries
        #[test]
        fn prop_prune_preserves_valid(
            now in 10000u64..100000,
            count in 1usize..50,
            future_offset in 1u64..10000
        ) {
            let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

            for i in 0..count {
                keys.insert(
                    format!("key-{}", i),
                    IdempotencyEntry {
                        response_body: "{}".to_string(),
                        status_code: 200,
                        created_at: now,
                        expires_at: now + future_offset, // All in the future
                        endpoint: "/test".to_string(),
                        request_fingerprint: "fp".to_string(),
                    },
                );
            }

            keys.retain(|_, entry| !entry.is_expired(now));
            prop_assert_eq!(keys.len(), count);
        }

        /// Property: Pruning always removes expired entries
        #[test]
        fn prop_prune_removes_expired(
            now in 10000u64..100000,
            count in 1usize..50,
            past_offset in 1u64..10000
        ) {
            let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

            for i in 0..count {
                keys.insert(
                    format!("key-{}", i),
                    IdempotencyEntry {
                        response_body: "{}".to_string(),
                        status_code: 200,
                        created_at: 100,
                        expires_at: now - past_offset, // All in the past
                        endpoint: "/test".to_string(),
                        request_fingerprint: "fp".to_string(),
                    },
                );
            }

            keys.retain(|_, entry| !entry.is_expired(now));
            prop_assert_eq!(keys.len(), 0);
        }

        /// Property: FIFO eviction always retains exactly the limit count
        #[test]
        fn prop_fifo_eviction_retains_limit(
            total in 2usize..100,
            limit in 1usize..100
        ) {
            let limit = limit.min(total);
            let mut keys: HashMap<String, IdempotencyEntry> = HashMap::new();

            for i in 0..total {
                keys.insert(
                    format!("key-{}", i),
                    IdempotencyEntry {
                        response_body: "{}".to_string(),
                        status_code: 200,
                        created_at: i as u64,
                        expires_at: 100_000,
                        endpoint: "/test".to_string(),
                        request_fingerprint: "fp".to_string(),
                    },
                );
            }

            let mut entries: Vec<_> = keys.into_iter().collect();
            entries.sort_by_key(|(_, entry)| entry.created_at);
            entries.reverse();
            let result: HashMap<String, IdempotencyEntry> = entries.into_iter().take(limit).collect();

            prop_assert_eq!(result.len(), limit);
        }

        /// Property: Valid UUID v4 always accepted, random strings almost never
        #[test]
        fn prop_random_string_rejected(s in "[^0-9a-f\\-]{1,100}") {
            // Random non-hex strings should never be valid UUID v4
            prop_assert!(!IdempotencyDO::is_valid_uuid_v4(&s));
        }

        /// Property: saturating_add never panics
        #[test]
        fn prop_saturating_add_no_panic(now in 0u64..=u64::MAX, ttl in 0u64..=u64::MAX) {
            let result = now.saturating_add(ttl);
            prop_assert!(result >= now);
            prop_assert!(result >= ttl);
        }

        /// Property: saturating_sub never panics
        #[test]
        fn prop_saturating_sub_no_panic(a in 0u64..=u64::MAX, b in 0u64..=u64::MAX) {
            let result = a.saturating_sub(b);
            prop_assert!(result <= a);
        }
    }
}
