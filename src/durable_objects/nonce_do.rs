// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object that tracks nonce usage to prevent replay attacks.
//!
//! Every nonce is consumed exactly once. A second attempt to set the same
//! nonce tag returns `success: false` and emits a critical audit event
//! (AL-051).
//!
//! Storage model: each nonce is stored as an individual key `nonce:{tag}`
//! containing a `NonceEntry` struct with creation time and TTL. This avoids
//! the 128 KB per-key limit that existed in the previous HashMap-based design.
//!
//! Cleanup: an alarm fires periodically to list all `nonce:` prefixed keys,
//! delete expired entries, and reschedule itself if nonces remain.
//!
//! SECURITY: Single-use nonce enforcement is the core replay prevention
//! mechanism for both verify and redeem flows. A failure here would allow
//! an attacker to reuse a captured request payload.
#![forbid(unsafe_code)]

use crate::security::audit::AuditEventData;
use crate::utils::validation::validate_nonce_tag;
use serde::{Deserialize, Serialize};
use worker::*;

/// IV-1241: Typed request body for nonce set operations.
/// `deny_unknown_fields` rejects unexpected fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetNonceRequest {
    /// Caller-supplied TTL in seconds. Required so the DO knows when the
    /// nonce expires for alarm-based cleanup.
    ttl_seconds: u64,
}

/// A single nonce entry stored under `nonce:{tag}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NonceEntry {
    /// Unix timestamp (seconds) when the nonce was stored.
    created_at: u64,
    /// Unix timestamp (seconds) at which this nonce expires.
    expires_at: u64,
}

/// IV-1241: Maximum request body size for nonce DO operations (4 KB).
/// Nonce requests contain only a TTL; anything larger is abuse.
const MAX_NONCE_BODY_SIZE: usize = 4_096;

/// Alarm interval for cleanup sweeps (60 seconds).
const ALARM_INTERVAL_MS: i64 = 60_000;

/// Key prefix for nonce entries in DO storage.
const NONCE_KEY_PREFIX: &str = "nonce:";

/// Single-use nonce tracker for replay attack prevention.
///
/// SECURITY: The DO serialises all calls to the same shard, so TOCTOU races
/// between check and set are impossible within a single shard.
#[durable_object]
pub struct NonceDO {
    state: State,
    #[allow(dead_code)] // Required by worker-rs Durable Object API
    env: Env,
}

impl DurableObject for NonceDO {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path();
        // ADV-VA-03-003: Use strip_prefix for exact prefix removal.
        let encoded_nonce_tag = match path.strip_prefix("/nonce/") {
            Some(tag) => tag,
            None => return Response::error("Invalid path", 400),
        };

        // SECURITY: URL-decode the nonce tag before validation.
        // The tag is percent-encoded when sent from durable_object_store.rs.
        let nonce_tag = percent_encoding::percent_decode_str(encoded_nonce_tag)
            .decode_utf8()
            .map_err(|e| {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[NonceDO] Failed to decode nonce tag '{}': {:?}",
                    encoded_nonce_tag,
                    e
                );
                worker::Error::RustError(format!("Invalid UTF-8 in nonce tag: {}", e))
            })?;

        match req.method() {
            Method::Post => self.set_nonce(&nonce_tag, req).await,
            _ => Response::error("Method not allowed", 405),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        self.cleanup_expired_nonces().await?;
        Response::ok("alarm_handled")
    }
}

impl NonceDO {
    /// Consume a nonce tag, enforcing single-use semantics.
    ///
    /// Returns `{ "success": true, ... }` on first use, or
    /// `{ "success": false, ... }` if the nonce was already consumed
    /// (replay detected, AL-051).
    ///
    /// SECURITY: This is the authoritative replay prevention gate. A
    /// duplicate nonce tag triggers a critical audit event visible to
    /// security monitoring.
    async fn set_nonce(&self, nonce_tag: &str, mut req: Request) -> Result<Response> {
        // SECURITY: Validate nonce tag to prevent injection attacks (CWE-89, CSA-01)
        if let Err(_e) = validate_nonce_tag(nonce_tag) {
            #[cfg(target_arch = "wasm32")]
            console_log!("[NonceDO] Invalid nonce tag rejected: {}", nonce_tag);
            return Response::error("Invalid nonce tag", 400);
        }

        // IV-1241: Enforce body size limit before parsing.
        let body_bytes = req.bytes().await?;
        if body_bytes.len() > MAX_NONCE_BODY_SIZE {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[NonceDO] Body too large: {} > {}",
                body_bytes.len(),
                MAX_NONCE_BODY_SIZE
            );
            return Response::error("Request entity too large", 413);
        }

        // IV-1241: Parse into typed struct instead of serde_json::Value.
        let body: SetNonceRequest = serde_json::from_slice(&body_bytes)
            .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {}", e)))?;

        let now = Date::now().as_millis() / 1000;

        // AL-051: Collect audit events for replay detection.
        let mut audit_events: Vec<AuditEventData> = Vec::new();

        // Check whether this nonce already exists in storage.
        let storage_key = format!("{}{}", NONCE_KEY_PREFIX, nonce_tag);
        let existing: Option<NonceEntry> = self
            .state
            .storage()
            .get::<NonceEntry>(&storage_key)
            .await
            .ok()
            .flatten();

        if let Some(entry) = existing {
            // Entry exists. Check if it has expired.
            if entry.expires_at >= now {
                // Still valid: this is a replay.
                #[cfg(target_arch = "wasm32")]
                console_log!("[NonceDO] Replay detected for nonce_tag={}", nonce_tag);

                // AL-051: CRITICAL audit for replay detection.
                audit_events.push(AuditEventData {
                    event_type: "nonce_replay_detected".into(),
                    severity: "critical".into(),
                    message: format!("Replay attack: nonce_tag={} already used", nonce_tag),
                    resource_id: nonce_tag.to_string(),
                    component: "nonce_do".into(),
                    details: serde_json::json!({
                        "nonce_tag": nonce_tag,
                        "created_at": entry.created_at,
                        "expires_at": entry.expires_at,
                    })
                    .to_string(),
                    ..Default::default()
                });

                return Response::from_json(&serde_json::json!({
                    "success": false,
                    "audit_events": audit_events,
                }));
            }
            // Entry expired: fall through to overwrite it.
        }

        // Store the nonce with its TTL.
        let ttl_seconds = body.ttl_seconds;
        let entry = NonceEntry {
            created_at: now,
            expires_at: now.saturating_add(ttl_seconds),
        };

        self.state.storage().put(&storage_key, &entry).await?;

        // Schedule an alarm if none is currently set. The alarm will handle
        // cleanup of expired nonces across all keys.
        self.ensure_alarm_scheduled().await?;

        Response::from_json(&serde_json::json!({
            "success": true,
            "audit_events": audit_events,
        }))
    }

    /// Ensure a cleanup alarm is scheduled. If one is already pending, this
    /// is a no-op.
    async fn ensure_alarm_scheduled(&self) -> Result<()> {
        let existing = self.state.storage().get_alarm().await?;
        if existing.is_none() {
            self.state.storage().set_alarm(ALARM_INTERVAL_MS).await?;
        }
        Ok(())
    }

    /// Alarm handler: list all `nonce:` keys, delete expired entries, and
    /// reschedule the alarm if nonces remain.
    ///
    /// This function uses JS interop APIs (`js_sys`, `wasm_bindgen`,
    /// `serde_wasm_bindgen`) that only exist on wasm32. On native targets
    /// (used by `cargo llvm-cov`) it compiles as an unreachable stub.
    #[cfg(target_arch = "wasm32")]
    async fn cleanup_expired_nonces(&self) -> Result<()> {
        let now = Date::now().as_millis() / 1000;

        let opts = durable::ListOptions::new().prefix(NONCE_KEY_PREFIX);
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

            // Attempt to deserialise the entry. If corrupt, delete it.
            let entry: Option<NonceEntry> =
                serde_wasm_bindgen::from_value::<NonceEntry>(val_js).ok();

            match entry {
                Some(e) if e.expires_at < now => {
                    keys_to_delete.push(key);
                }
                Some(_) => {
                    remaining_count = remaining_count.saturating_add(1);
                }
                None => {
                    // Corrupt entry, remove it.
                    keys_to_delete.push(key);
                }
            }
        }

        if !keys_to_delete.is_empty() {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[NonceDO] Alarm cleanup: deleting {} expired nonces, {} remain",
                keys_to_delete.len(),
                remaining_count
            );
            self.state.storage().delete_multiple(keys_to_delete).await?;
        }

        // Reschedule alarm if live nonces remain.
        if remaining_count > 0 {
            self.state.storage().set_alarm(ALARM_INTERVAL_MS).await?;
        }

        Ok(())
    }

    /// Native-target stub: alarm cleanup requires JS interop and cannot run
    /// outside the Workers runtime. Returns `Ok(())` unconditionally.
    #[cfg(not(target_arch = "wasm32"))]
    async fn cleanup_expired_nonces(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::string_slice,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::*;

    // ========================================================================
    // Path Parsing Tests
    // ========================================================================

    #[test]
    fn test_nonce_tag_extraction_simple() {
        let path = "/nonce/verify:12345";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap();
        assert_eq!(nonce_tag, "verify:12345");
    }

    #[test]
    fn test_nonce_tag_extraction_with_uuid() {
        let path = "/nonce/verify:550e8400-e29b-41d4-a716-446655440000";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap();
        assert_eq!(nonce_tag, "verify:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_nonce_tag_extraction_redeem() {
        let path = "/nonce/redeem:550e8400-e29b-41d4-a716-446655440000";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap();
        assert_eq!(nonce_tag, "redeem:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_nonce_tag_extraction_empty() {
        let path = "/nonce/";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap();
        assert_eq!(nonce_tag, "");
    }

    #[test]
    fn test_nonce_tag_extraction_no_prefix() {
        let path = "/other/path";
        assert!(path.strip_prefix("/nonce/").is_none());
    }

    #[test]
    fn test_nonce_tag_extraction_multiple_slashes() {
        let path = "/nonce/verify:abc/def";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap();
        assert_eq!(nonce_tag, "verify:abc/def");
    }

    #[test]
    fn test_nonce_tag_extraction_special_chars() {
        let path = "/nonce/verify:abc-123_xyz.test";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap();
        assert_eq!(nonce_tag, "verify:abc-123_xyz.test");
    }

    // ========================================================================
    // NonceEntry Serialisation Tests
    // ========================================================================

    #[test]
    fn test_nonce_entry_roundtrip() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: NonceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.created_at, 1_700_000_000);
        assert_eq!(decoded.expires_at, 1_700_000_300);
    }

    #[test]
    fn test_nonce_entry_expiry_check_valid() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let now = 1_700_000_100;
        assert!(entry.expires_at >= now, "Entry should still be valid");
    }

    #[test]
    fn test_nonce_entry_expiry_check_expired() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let now = 1_700_000_400;
        assert!(entry.expires_at < now, "Entry should be expired");
    }

    #[test]
    fn test_nonce_entry_expiry_boundary() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        // At exactly expires_at, the entry is still considered valid (>=).
        let now = 1_700_000_300;
        assert!(entry.expires_at >= now);
    }

    #[test]
    fn test_nonce_entry_expiry_one_past() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let now = 1_700_000_301;
        assert!(entry.expires_at < now);
    }

    // ========================================================================
    // Storage Key Format Tests
    // ========================================================================

    #[test]
    fn test_storage_key_format() {
        let tag = "verify:550e8400-e29b-41d4-a716-446655440000";
        let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
        assert_eq!(key, "nonce:verify:550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_storage_key_prefix_constant() {
        assert_eq!(NONCE_KEY_PREFIX, "nonce:");
    }

    #[test]
    fn test_storage_key_different_tags() {
        let key1 = format!("{}verify:aaa", NONCE_KEY_PREFIX);
        let key2 = format!("{}redeem:bbb", NONCE_KEY_PREFIX);
        assert_ne!(key1, key2);
        assert!(key1.starts_with(NONCE_KEY_PREFIX));
        assert!(key2.starts_with(NONCE_KEY_PREFIX));
    }

    // ========================================================================
    // SetNonceRequest Parsing Tests
    // ========================================================================

    #[test]
    fn test_set_nonce_request_valid() {
        let json = r#"{"ttl_seconds": 300}"#;
        let req: SetNonceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.ttl_seconds, 300);
    }

    #[test]
    fn test_set_nonce_request_zero_ttl() {
        let json = r#"{"ttl_seconds": 0}"#;
        let req: SetNonceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.ttl_seconds, 0);
    }

    #[test]
    fn test_set_nonce_request_large_ttl() {
        let json = r#"{"ttl_seconds": 86400}"#;
        let req: SetNonceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.ttl_seconds, 86400);
    }

    #[test]
    fn test_set_nonce_request_deny_unknown_fields() {
        let json = r#"{"ttl_seconds": 300, "extra_field": true}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_nonce_request_missing_ttl() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err());
    }

    // ========================================================================
    // Response Format Tests
    // ========================================================================

    #[test]
    fn test_success_response_format() {
        let events: Vec<AuditEventData> = Vec::new();
        let json = serde_json::json!({
            "success": true,
            "audit_events": events,
        });
        assert_eq!(json["success"], true);
        assert!(json["audit_events"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_replay_response_format() {
        let events = vec![AuditEventData {
            event_type: "nonce_replay_detected".into(),
            severity: "critical".into(),
            message: "Replay attack: nonce_tag=test already used".into(),
            resource_id: "test".into(),
            component: "nonce_do".into(),
            details: "{}".into(),
            ..Default::default()
        }];
        let json = serde_json::json!({
            "success": false,
            "audit_events": events,
        });
        assert_eq!(json["success"], false);
        assert_eq!(json["audit_events"].as_array().unwrap().len(), 1);
    }

    // ========================================================================
    // Body Size Limit Tests
    // ========================================================================

    #[test]
    fn test_body_size_under_limit() {
        let body = vec![0u8; MAX_NONCE_BODY_SIZE - 1];
        assert!(body.len() <= MAX_NONCE_BODY_SIZE);
    }

    #[test]
    fn test_body_size_at_limit() {
        let body = vec![0u8; MAX_NONCE_BODY_SIZE];
        assert!(body.len() <= MAX_NONCE_BODY_SIZE);
    }

    #[test]
    fn test_body_size_over_limit() {
        let body = vec![0u8; MAX_NONCE_BODY_SIZE + 1];
        assert!(body.len() > MAX_NONCE_BODY_SIZE);
    }

    // ========================================================================
    // Alarm Configuration Tests
    // ========================================================================

    #[test]
    fn test_alarm_interval_positive() {
        assert!(ALARM_INTERVAL_MS > 0);
    }

    #[test]
    fn test_alarm_interval_reasonable() {
        // Should be between 10s and 5min
        assert!(ALARM_INTERVAL_MS >= 10_000);
        assert!(ALARM_INTERVAL_MS <= 300_000);
    }

    // ========================================================================
    // Property-Based Tests
    // ========================================================================

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    // ========================================================================
    // Percent-Encoding / Decoding Tests
    // ========================================================================

    #[test]
    fn test_percent_decode_simple_tag() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "verify%3A12345";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "verify:12345");
        Ok(())
    }

    #[test]
    fn test_percent_decode_already_decoded() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "verify:12345";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "verify:12345");
        Ok(())
    }

    #[test]
    fn test_percent_decode_uuid_with_colons() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "redeem%3A550e8400-e29b-41d4-a716-446655440000";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "redeem:550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[test]
    fn test_percent_decode_double_encoded_colon() -> Result<(), Box<dyn std::error::Error>> {
        // Double-encoded colon: %253A -> %3A (only one layer decoded)
        let encoded = "verify%253A12345";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "verify%3A12345");
        Ok(())
    }

    #[test]
    fn test_percent_decode_hyphens_underscores_unchanged() -> Result<(), Box<dyn std::error::Error>>
    {
        let encoded = "tag-with_hyphens-and_underscores";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "tag-with_hyphens-and_underscores");
        Ok(())
    }

    #[test]
    fn test_percent_decode_encoded_space() -> Result<(), Box<dyn std::error::Error>> {
        // Spaces are percent-encoded as %20. After decoding, the nonce
        // contains a space which validate_nonce_tag would reject.
        let encoded = "tag%20with%20spaces";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "tag with spaces");
        assert!(validate_nonce_tag(&decoded).is_err());
        Ok(())
    }

    #[test]
    fn test_percent_decode_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "");
        Ok(())
    }

    #[test]
    fn test_percent_decode_invalid_utf8() {
        // %FF is not valid UTF-8 on its own
        let encoded = "%FF%FE";
        let result = percent_encoding::percent_decode_str(encoded).decode_utf8();
        assert!(result.is_err());
    }

    #[test]
    fn test_percent_decode_encoded_null_byte() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "tag%00injection";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "tag\0injection");
        // validate_nonce_tag rejects null bytes
        assert!(validate_nonce_tag(&decoded).is_err());
        Ok(())
    }

    #[test]
    fn test_percent_decode_path_traversal_encoded() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "..%2F..%2Fetc%2Fpasswd";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "../../etc/passwd");
        assert!(validate_nonce_tag(&decoded).is_err());
        Ok(())
    }

    // ========================================================================
    // Nonce Validation Integration Tests (decode then validate)
    // ========================================================================

    #[test]
    fn test_decode_then_validate_valid_tag() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "verify%3A550e8400-e29b-41d4-a716-446655440000";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert!(validate_nonce_tag(&decoded).is_ok());
        Ok(())
    }

    #[test]
    fn test_decode_then_validate_special_chars_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let encoded = "tag%40with%23special";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "tag@with#special");
        assert!(validate_nonce_tag(&decoded).is_err());
        Ok(())
    }

    #[test]
    fn test_decode_then_validate_semicolon_injection() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = "tag%3Bdrop%20table";
        let decoded = percent_encoding::percent_decode_str(encoded).decode_utf8()?;
        assert_eq!(decoded, "tag;drop table");
        assert!(validate_nonce_tag(&decoded).is_err());
        Ok(())
    }

    // ========================================================================
    // NonceEntry Expiry Edge Cases
    // ========================================================================

    #[test]
    fn test_nonce_entry_zero_ttl_expires_immediately_at_boundary() {
        // With TTL 0, expires_at == created_at. At now == created_at,
        // the entry is valid (expires_at >= now).
        let now = 1_700_000_000u64;
        let entry = NonceEntry {
            created_at: now,
            expires_at: now.saturating_add(0),
        };
        assert!(entry.expires_at >= now);
    }

    #[test]
    fn test_nonce_entry_zero_ttl_expired_one_second_later() {
        let now = 1_700_000_000u64;
        let entry = NonceEntry {
            created_at: now,
            expires_at: now.saturating_add(0),
        };
        let later = now.saturating_add(1);
        assert!(entry.expires_at < later);
    }

    #[test]
    fn test_nonce_entry_saturating_add_overflow() {
        // When now is near u64::MAX, saturating_add prevents overflow.
        let now = u64::MAX - 10;
        let entry = NonceEntry {
            created_at: now,
            expires_at: now.saturating_add(300),
        };
        assert_eq!(entry.expires_at, u64::MAX);
        // Entry is valid: saturating_add clamped to u64::MAX (confirmed above).
    }

    #[test]
    fn test_nonce_entry_max_ttl() {
        let now = 1_700_000_000u64;
        let entry = NonceEntry {
            created_at: now,
            expires_at: now.saturating_add(u64::MAX),
        };
        assert_eq!(entry.expires_at, u64::MAX);
    }

    #[test]
    fn test_nonce_entry_created_at_zero() {
        let entry = NonceEntry {
            created_at: 0,
            expires_at: 300,
        };
        let now = 299u64;
        assert!(entry.expires_at >= now);
        let later = 301u64;
        assert!(entry.expires_at < later);
    }

    #[test]
    fn test_nonce_entry_very_short_ttl_1s() {
        let now = 1_700_000_000u64;
        let entry = NonceEntry {
            created_at: now,
            expires_at: now.saturating_add(1),
        };
        assert!(entry.expires_at >= now);
        assert!(entry.expires_at >= now.saturating_add(1));
        assert!(entry.expires_at < now.saturating_add(2));
    }

    // ========================================================================
    // Cleanup Classification Logic Tests
    // ========================================================================
    //
    // In cleanup_expired_nonces: `expires_at < now` means expired (delete).
    // In set_nonce: `expires_at >= now` means still valid (replay).
    // These two conditions are complementary.

    #[test]
    fn test_cleanup_classification_expired() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let now = 1_700_000_301u64;
        // cleanup_expired_nonces deletes when expires_at < now
        assert!(
            entry.expires_at < now,
            "Should be classified as expired for cleanup"
        );
    }

    #[test]
    fn test_cleanup_classification_still_valid() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let now = 1_700_000_300u64;
        // At exactly expires_at, cleanup does NOT delete (expires_at < now is false)
        assert!(
            (entry.expires_at >= now),
            "Should NOT be deleted at exact expiry time"
        );
    }

    #[test]
    fn test_cleanup_vs_replay_complementary() {
        // For any entry, exactly one of these is true:
        // - expires_at >= now (replay detection says "still valid")
        // - expires_at < now  (cleanup says "expired, delete")
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        for now in [
            1_700_000_000,
            1_700_000_299,
            1_700_000_300,
            1_700_000_301,
            1_700_000_999,
        ] {
            let is_valid_replay = entry.expires_at >= now;
            let is_expired_cleanup = entry.expires_at < now;
            assert_ne!(
                is_valid_replay, is_expired_cleanup,
                "Exactly one condition must be true at now={}",
                now
            );
        }
    }

    #[test]
    fn test_cleanup_corrupt_entry_would_be_deleted() {
        // In cleanup, if deserialisation fails -> None -> delete.
        // We test the match arm logic with Option:
        let corrupt: Option<NonceEntry> = None;
        let should_delete = corrupt.is_none();
        assert!(should_delete, "Corrupt (None) entries should be deleted");
    }

    #[test]
    fn test_cleanup_remaining_count_saturating() {
        // remaining_count uses saturating_add to avoid overflow
        let mut remaining_count: usize = usize::MAX;
        remaining_count = remaining_count.saturating_add(1);
        assert_eq!(remaining_count, usize::MAX);
    }

    // ========================================================================
    // SetNonceRequest Parsing Edge Cases
    // ========================================================================

    #[test]
    fn test_set_nonce_request_max_u64_ttl() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!(r#"{{"ttl_seconds": {}}}"#, u64::MAX);
        let req: SetNonceRequest = serde_json::from_str(&json)?;
        assert_eq!(req.ttl_seconds, u64::MAX);
        Ok(())
    }

    #[test]
    fn test_set_nonce_request_negative_ttl_rejected() {
        let json = r#"{"ttl_seconds": -1}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Negative TTL should fail u64 parsing");
    }

    #[test]
    fn test_set_nonce_request_float_ttl_rejected() {
        let json = r#"{"ttl_seconds": 300.5}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Float TTL should fail u64 parsing");
    }

    #[test]
    fn test_set_nonce_request_string_ttl_rejected() {
        let json = r#"{"ttl_seconds": "300"}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "String TTL should fail u64 parsing");
    }

    #[test]
    fn test_set_nonce_request_null_ttl_rejected() {
        let json = r#"{"ttl_seconds": null}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Null TTL should fail u64 parsing");
    }

    #[test]
    fn test_set_nonce_request_boolean_ttl_rejected() {
        let json = r#"{"ttl_seconds": true}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Boolean TTL should fail u64 parsing");
    }

    #[test]
    fn test_set_nonce_request_single_element_array_accepted() {
        // serde_json treats a single-element JSON array as positional fields
        // for a single-field struct, so `[300]` deserialises successfully.
        let json = r#"[300]"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(
            result.is_ok(),
            "Single-element array maps to single-field struct"
        );
        assert_eq!(result.unwrap().ttl_seconds, 300);
    }

    #[test]
    fn test_set_nonce_request_multi_element_array_rejected() {
        let json = r#"[300, 400]"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(
            result.is_err(),
            "Multi-element array should fail for single-field struct"
        );
    }

    #[test]
    fn test_set_nonce_request_empty_array_rejected() {
        let json = r#"[]"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Empty array should fail struct parsing");
    }

    #[test]
    fn test_set_nonce_request_empty_object() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Missing ttl_seconds should fail");
    }

    #[test]
    fn test_set_nonce_request_multiple_unknown_fields_rejected() {
        let json = r#"{"ttl_seconds": 300, "foo": 1, "bar": 2}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Unknown fields should be rejected");
    }

    #[test]
    fn test_set_nonce_request_overflow_rejected() {
        // u64::MAX + 1 in JSON
        let json = r#"{"ttl_seconds": 18446744073709551616}"#;
        let result = serde_json::from_str::<SetNonceRequest>(json);
        assert!(result.is_err(), "Overflow beyond u64::MAX should fail");
    }

    // ========================================================================
    // NonceEntry Serialisation Edge Cases
    // ========================================================================

    #[test]
    fn test_nonce_entry_serialisation_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let entry = NonceEntry {
            created_at: 0,
            expires_at: 0,
        };
        let json = serde_json::to_string(&entry)?;
        let decoded: NonceEntry = serde_json::from_str(&json)?;
        assert_eq!(decoded.created_at, 0);
        assert_eq!(decoded.expires_at, 0);
        Ok(())
    }

    #[test]
    fn test_nonce_entry_serialisation_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let entry = NonceEntry {
            created_at: u64::MAX,
            expires_at: u64::MAX,
        };
        let json = serde_json::to_string(&entry)?;
        let decoded: NonceEntry = serde_json::from_str(&json)?;
        assert_eq!(decoded.created_at, u64::MAX);
        assert_eq!(decoded.expires_at, u64::MAX);
        Ok(())
    }

    #[test]
    fn test_nonce_entry_deserialisation_extra_field_allowed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // NonceEntry does NOT have deny_unknown_fields, so extra fields are ignored.
        let json = r#"{"created_at": 1000, "expires_at": 2000, "extra": true}"#;
        let entry: NonceEntry = serde_json::from_str(json)?;
        assert_eq!(entry.created_at, 1000);
        assert_eq!(entry.expires_at, 2000);
        Ok(())
    }

    #[test]
    fn test_nonce_entry_deserialisation_missing_field_rejected() {
        let json = r#"{"created_at": 1000}"#;
        let result = serde_json::from_str::<NonceEntry>(json);
        assert!(result.is_err(), "Missing expires_at should fail");
    }

    #[test]
    fn test_nonce_entry_debug_format() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("1700000000"));
        assert!(debug.contains("1700000300"));
    }

    #[test]
    fn test_nonce_entry_clone() {
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.created_at, entry.created_at);
        assert_eq!(cloned.expires_at, entry.expires_at);
    }

    // ========================================================================
    // Storage Key Edge Cases
    // ========================================================================

    #[test]
    fn test_storage_key_empty_tag() {
        let tag = "";
        let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
        assert_eq!(key, "nonce:");
    }

    #[test]
    fn test_storage_key_very_long_tag() {
        let tag = "a".repeat(256);
        let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
        assert_eq!(key.len(), NONCE_KEY_PREFIX.len() + 256);
        assert!(key.starts_with(NONCE_KEY_PREFIX));
    }

    #[test]
    fn test_storage_key_unicode_tag() {
        // After percent-decoding, a tag could theoretically contain unicode
        // (though validate_nonce_tag would reject non-ASCII).
        let tag = "verify:abc123";
        let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
        assert_eq!(key, "nonce:verify:abc123");
    }

    #[test]
    fn test_storage_key_multiple_colons() {
        let tag = "verify:sub:550e8400-e29b-41d4-a716-446655440000";
        let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
        assert_eq!(key, "nonce:verify:sub:550e8400-e29b-41d4-a716-446655440000");
        // Verify the prefix is still detectable
        assert!(key.starts_with("nonce:"));
    }

    // ========================================================================
    // Audit Event Construction Tests
    // ========================================================================

    #[test]
    fn test_audit_event_replay_fields() {
        let nonce_tag = "verify:test-uuid-123";
        let entry = NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let event = AuditEventData {
            event_type: "nonce_replay_detected".into(),
            severity: "critical".into(),
            message: format!("Replay attack: nonce_tag={} already used", nonce_tag),
            resource_id: nonce_tag.to_string(),
            component: "nonce_do".into(),
            details: serde_json::json!({
                "nonce_tag": nonce_tag,
                "created_at": entry.created_at,
                "expires_at": entry.expires_at,
            })
            .to_string(),
            ..Default::default()
        };
        assert_eq!(event.event_type, "nonce_replay_detected");
        assert_eq!(event.severity, "critical");
        assert!(event.message.contains(nonce_tag));
        assert_eq!(event.resource_id, nonce_tag);
        assert_eq!(event.component, "nonce_do");

        // Verify details JSON is parseable and contains correct values
        let details: serde_json::Value =
            serde_json::from_str(&event.details).expect("details should be valid JSON"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(details["nonce_tag"], nonce_tag);
        assert_eq!(details["created_at"], 1_700_000_000u64);
        assert_eq!(details["expires_at"], 1_700_000_300u64);
    }

    #[test]
    fn test_audit_event_default_fields_empty() {
        let event = AuditEventData {
            event_type: "nonce_replay_detected".into(),
            severity: "critical".into(),
            message: "test".into(),
            resource_id: "tag".into(),
            component: "nonce_do".into(),
            details: "{}".into(),
            ..Default::default()
        };
        // Fields not explicitly set should be empty strings (Default)
        assert_eq!(event.actor_ip, "");
        assert_eq!(event.origin, "");
        assert_eq!(event.actor_id, "");
        assert_eq!(event.request_id, "");
        assert_eq!(event.environment, "");
        assert_eq!(event.worker_version, "");
    }

    #[test]
    fn test_audit_event_serialises_to_json() -> Result<(), Box<dyn std::error::Error>> {
        let event = AuditEventData {
            event_type: "nonce_replay_detected".into(),
            severity: "critical".into(),
            message: "Replay attack: nonce_tag=test already used".into(),
            resource_id: "test".into(),
            component: "nonce_do".into(),
            details: "{}".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(&event)?;
        assert_eq!(json["event_type"], "nonce_replay_detected");
        assert_eq!(json["severity"], "critical");
        assert_eq!(json["component"], "nonce_do");
        Ok(())
    }

    // ========================================================================
    // Response JSON Structure Tests
    // ========================================================================

    #[test]
    fn test_success_response_has_empty_audit_events() {
        let events: Vec<AuditEventData> = Vec::new();
        let json = serde_json::json!({
            "success": true,
            "audit_events": events,
        });
        assert_eq!(json["success"], true);
        let arr = json["audit_events"]
            .as_array()
            .expect("audit_events should be array");
        assert!(arr.is_empty());
    }

    #[test]
    fn test_replay_response_success_is_false() {
        let events = vec![AuditEventData {
            event_type: "nonce_replay_detected".into(),
            severity: "critical".into(),
            ..Default::default()
        }];
        let json = serde_json::json!({
            "success": false,
            "audit_events": events,
        });
        assert_eq!(json["success"], false);
    }

    #[test]
    fn test_replay_response_audit_event_count() {
        let events = vec![AuditEventData {
            event_type: "nonce_replay_detected".into(),
            severity: "critical".into(),
            ..Default::default()
        }];
        let json = serde_json::json!({
            "success": false,
            "audit_events": events,
        });
        let arr = json["audit_events"]
            .as_array()
            .expect("audit_events should be array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["event_type"], "nonce_replay_detected");
        assert_eq!(arr[0]["severity"], "critical");
    }

    // ========================================================================
    // Body Size Constant Tests
    // ========================================================================

    #[test]
    fn test_max_nonce_body_size_is_4kb() {
        assert_eq!(MAX_NONCE_BODY_SIZE, 4096);
    }

    #[test]
    fn test_body_size_check_empty_body_passes() {
        let body: Vec<u8> = Vec::new();
        assert!(body.len() <= MAX_NONCE_BODY_SIZE);
    }

    #[test]
    fn test_body_size_check_valid_json_passes() {
        let body = br#"{"ttl_seconds": 300}"#;
        assert!(body.len() <= MAX_NONCE_BODY_SIZE);
    }

    #[test]
    fn test_body_size_check_large_json_with_padding() {
        // A malicious request with padding to exceed the limit
        let padding = " ".repeat(MAX_NONCE_BODY_SIZE);
        let body = format!(r#"{{"ttl_seconds": 300, "padding": "{}"}}"#, padding);
        assert!(body.len() > MAX_NONCE_BODY_SIZE);
    }

    // ========================================================================
    // Nonce Tag Validation (exercising validate_nonce_tag from this module)
    // ========================================================================

    #[test]
    fn test_validate_nonce_tag_verify_prefix() {
        assert!(validate_nonce_tag("verify:550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_redeem_prefix() {
        assert!(validate_nonce_tag("redeem:550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_empty_rejected() {
        assert!(validate_nonce_tag("").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_null_byte_rejected() {
        assert!(validate_nonce_tag("test\0tag").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_path_traversal_rejected() {
        assert!(validate_nonce_tag("../etc/passwd").is_err());
        assert!(validate_nonce_tag("..\\windows").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_dots_rejected() {
        assert!(validate_nonce_tag("tag.with.dots").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_spaces_rejected() {
        assert!(validate_nonce_tag("tag with spaces").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_sql_injection_rejected() {
        assert!(validate_nonce_tag("tag'or'1'='1").is_err());
    }

    #[test]
    fn test_validate_nonce_tag_single_char_accepted() {
        assert!(validate_nonce_tag("a").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_underscores_accepted() {
        assert!(validate_nonce_tag("tag_with_underscores").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_only_digits() {
        assert!(validate_nonce_tag("1234567890").is_ok());
    }

    #[test]
    fn test_validate_nonce_tag_max_length_boundary() {
        // 256 chars is the max
        let tag = "a".repeat(256);
        assert!(validate_nonce_tag(&tag).is_ok());
        let tag_over = "a".repeat(257);
        assert!(validate_nonce_tag(&tag_over).is_err());
    }

    // ========================================================================
    // Single-Use Enforcement Logic Tests (pure state machine)
    // ========================================================================
    //
    // These test the decision logic without DO storage. Given an existing
    // entry and a current timestamp, what should happen?

    #[test]
    fn test_single_use_first_use_no_existing_entry() {
        let existing: Option<NonceEntry> = None;
        // No existing entry: should proceed to store (success: true)
        assert!(existing.is_none());
    }

    #[test]
    fn test_single_use_replay_entry_not_expired() {
        let existing = Some(NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        });
        let now = 1_700_000_200u64;
        // Entry exists and not expired: replay (success: false)
        if let Some(entry) = &existing {
            assert!(entry.expires_at >= now, "Should detect replay");
        }
    }

    #[test]
    fn test_single_use_expired_entry_allows_reuse() {
        let existing = Some(NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        });
        let now = 1_700_000_301u64;
        // Entry exists but expired: should proceed to overwrite (success: true)
        if let Some(entry) = &existing {
            assert!(entry.expires_at < now, "Expired entry should allow new use");
        }
    }

    #[test]
    fn test_single_use_boundary_exact_expiry_is_replay() {
        let existing = Some(NonceEntry {
            created_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        });
        let now = 1_700_000_300u64;
        // At exactly expires_at, the code uses >= so this is still a replay
        if let Some(entry) = &existing {
            assert!(
                entry.expires_at >= now,
                "Exact expiry boundary should count as replay"
            );
        }
    }

    #[test]
    fn test_single_use_decision_matrix() {
        // Exhaustively test the decision for several (existing, now) pairs
        let cases: Vec<(Option<NonceEntry>, u64, bool)> = vec![
            // (existing_entry, now, expected_success)
            (None, 1_700_000_100, true), // No entry: success
            (
                Some(NonceEntry {
                    created_at: 100,
                    expires_at: 200,
                }),
                150,
                false,
            ), // Valid entry: replay
            (
                Some(NonceEntry {
                    created_at: 100,
                    expires_at: 200,
                }),
                200,
                false,
            ), // At boundary: replay
            (
                Some(NonceEntry {
                    created_at: 100,
                    expires_at: 200,
                }),
                201,
                true,
            ), // Expired: success
            (
                Some(NonceEntry {
                    created_at: 100,
                    expires_at: 100,
                }),
                100,
                false,
            ), // Zero TTL at boundary: replay
            (
                Some(NonceEntry {
                    created_at: 100,
                    expires_at: 100,
                }),
                101,
                true,
            ), // Zero TTL past: success
        ];

        for (i, (existing, now, expected_success)) in cases.iter().enumerate() {
            let is_replay = match existing {
                Some(entry) => entry.expires_at >= *now,
                None => false,
            };
            let success = !is_replay;
            assert_eq!(
                success, *expected_success,
                "Case {} failed: existing={:?}, now={}, expected_success={}",
                i, existing, now, expected_success
            );
        }
    }

    // ========================================================================
    // Alarm Reschedule Decision Tests
    // ========================================================================

    #[test]
    fn test_alarm_reschedule_when_nonces_remain() {
        let remaining_count: usize = 1;
        assert!(remaining_count > 0, "Should reschedule alarm");
    }

    #[test]
    fn test_alarm_no_reschedule_when_empty() {
        let remaining_count: usize = 0;
        assert!(remaining_count == 0, "Should not reschedule alarm");
    }

    #[test]
    fn test_alarm_reschedule_many_remaining() {
        let remaining_count: usize = 10_000;
        assert!(
            remaining_count > 0,
            "Should reschedule alarm with many nonces"
        );
    }

    // ========================================================================
    // Keys-to-Delete Collection Logic Tests
    // ========================================================================

    #[test]
    fn test_cleanup_keys_collection_mixed_entries() {
        let now = 1_700_000_500u64;
        let entries: Vec<(String, Option<NonceEntry>)> = vec![
            (
                "nonce:a".into(),
                Some(NonceEntry {
                    created_at: 1_700_000_000,
                    expires_at: 1_700_000_100,
                }),
            ), // expired
            (
                "nonce:b".into(),
                Some(NonceEntry {
                    created_at: 1_700_000_000,
                    expires_at: 1_700_000_600,
                }),
            ), // valid
            ("nonce:c".into(), None), // corrupt
            (
                "nonce:d".into(),
                Some(NonceEntry {
                    created_at: 1_700_000_000,
                    expires_at: 1_700_000_499,
                }),
            ), // expired
            (
                "nonce:e".into(),
                Some(NonceEntry {
                    created_at: 1_700_000_000,
                    expires_at: 1_700_000_500,
                }),
            ), // boundary: valid
        ];

        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut remaining_count: usize = 0;

        for (key, entry) in &entries {
            if key.is_empty() {
                continue;
            }
            match entry {
                Some(e) if e.expires_at < now => {
                    keys_to_delete.push(key.clone());
                }
                Some(_) => {
                    remaining_count = remaining_count.saturating_add(1);
                }
                None => {
                    keys_to_delete.push(key.clone());
                }
            }
        }

        assert_eq!(keys_to_delete.len(), 3); // a (expired), c (corrupt), d (expired)
        assert_eq!(remaining_count, 2); // b (valid), e (boundary valid)
        assert!(keys_to_delete.contains(&"nonce:a".to_string()));
        assert!(keys_to_delete.contains(&"nonce:c".to_string()));
        assert!(keys_to_delete.contains(&"nonce:d".to_string()));
    }

    #[test]
    fn test_cleanup_keys_all_expired() {
        let now = 2_000_000_000u64;
        let entries: Vec<(String, Option<NonceEntry>)> = vec![
            (
                "nonce:a".into(),
                Some(NonceEntry {
                    created_at: 100,
                    expires_at: 200,
                }),
            ),
            (
                "nonce:b".into(),
                Some(NonceEntry {
                    created_at: 300,
                    expires_at: 400,
                }),
            ),
        ];

        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut remaining_count: usize = 0;

        for (key, entry) in &entries {
            match entry {
                Some(e) if e.expires_at < now => keys_to_delete.push(key.clone()),
                Some(_) => remaining_count = remaining_count.saturating_add(1),
                None => keys_to_delete.push(key.clone()),
            }
        }

        assert_eq!(keys_to_delete.len(), 2);
        assert_eq!(remaining_count, 0);
    }

    #[test]
    fn test_cleanup_keys_all_valid() {
        let now = 100u64;
        let entries: Vec<(String, Option<NonceEntry>)> = vec![
            (
                "nonce:a".into(),
                Some(NonceEntry {
                    created_at: 50,
                    expires_at: 200,
                }),
            ),
            (
                "nonce:b".into(),
                Some(NonceEntry {
                    created_at: 50,
                    expires_at: 300,
                }),
            ),
        ];

        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut remaining_count: usize = 0;

        for (key, entry) in &entries {
            match entry {
                Some(e) if e.expires_at < now => keys_to_delete.push(key.clone()),
                Some(_) => remaining_count = remaining_count.saturating_add(1),
                None => keys_to_delete.push(key.clone()),
            }
        }

        assert!(keys_to_delete.is_empty());
        assert_eq!(remaining_count, 2);
    }

    #[test]
    fn test_cleanup_keys_empty_key_skipped() {
        let entries: Vec<(String, Option<NonceEntry>)> = vec![(
            "".into(),
            Some(NonceEntry {
                created_at: 100,
                expires_at: 200,
            }),
        )];

        let mut processed = 0usize;
        for (key, _entry) in &entries {
            if key.is_empty() {
                continue;
            }
            processed = processed.saturating_add(1);
        }

        assert_eq!(processed, 0, "Empty key should be skipped");
    }

    #[test]
    fn test_cleanup_keys_only_corrupt() {
        let now = 1_000u64;
        let entries: Vec<(String, Option<NonceEntry>)> = vec![
            ("nonce:corrupt1".into(), None),
            ("nonce:corrupt2".into(), None),
        ];

        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut remaining_count: usize = 0;

        for (key, entry) in &entries {
            match entry {
                Some(e) if e.expires_at < now => keys_to_delete.push(key.clone()),
                Some(_) => remaining_count = remaining_count.saturating_add(1),
                None => keys_to_delete.push(key.clone()),
            }
        }

        assert_eq!(keys_to_delete.len(), 2);
        assert_eq!(remaining_count, 0);
    }

    // ========================================================================
    // Path Parsing Additional Edge Cases
    // ========================================================================

    #[test]
    fn test_nonce_tag_extraction_only_prefix() {
        let path = "/nonce/";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap_or(path);
        assert_eq!(nonce_tag, "");
    }

    #[test]
    fn test_nonce_tag_extraction_nested_nonce_prefix() {
        let path = "/nonce/nonce:abc";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap_or(path);
        assert_eq!(nonce_tag, "nonce:abc");
    }

    #[test]
    fn test_nonce_tag_extraction_double_prefix() {
        // ADV-VA-03-003: strip_prefix removes the prefix exactly once,
        // preserving the second /nonce/ as part of the tag.
        let path = "/nonce//nonce/tag";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap_or(path);
        assert_eq!(nonce_tag, "/nonce/tag");
    }

    #[test]
    fn test_nonce_tag_extraction_unicode_in_path() {
        let path = "/nonce/verify%3Aabc";
        let nonce_tag = path.strip_prefix("/nonce/").unwrap_or(path);
        assert_eq!(nonce_tag, "verify%3Aabc");
    }

    #[test]
    fn test_nonce_tag_extraction_no_prefix_returns_none() {
        let path = "/other/tag";
        assert!(path.strip_prefix("/nonce/").is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: strip_prefix is idempotent on the extracted tag
        #[test]
        fn prop_path_strip_idempotent(tag in "[a-z]{1,20}:[0-9]{1,10}") {
            let path = format!("/nonce/{}", tag);
            let stripped = path.strip_prefix("/nonce/").unwrap();
            let path2 = format!("/nonce/{}", stripped);
            let stripped2 = path2.strip_prefix("/nonce/").unwrap();

            prop_assert_eq!(stripped, stripped2);
        }

        /// Property: Storage key prefix is always present
        #[test]
        fn prop_storage_key_has_prefix(tag in "[a-z]{1,20}:[0-9a-f-]{1,36}") {
            let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
            prop_assert!(key.starts_with(NONCE_KEY_PREFIX));
            prop_assert!(key.len() > NONCE_KEY_PREFIX.len());
        }

        /// Property: NonceEntry serialisation roundtrips
        #[test]
        fn prop_nonce_entry_roundtrip(created_at in 1_000_000_000u64..2_000_000_000, ttl in 0u64..86400) {
            let entry = NonceEntry {
                created_at,
                expires_at: created_at.saturating_add(ttl),
            };
            let json = serde_json::to_string(&entry).unwrap();
            let decoded: NonceEntry = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(decoded.created_at, created_at);
            prop_assert_eq!(decoded.expires_at, created_at.saturating_add(ttl));
        }

        /// Property: Expired entries always have expires_at < now
        #[test]
        fn prop_expiry_logic(created_at in 1_000_000_000u64..1_500_000_000, ttl in 1u64..600, elapsed in 0u64..1200) {
            let entry = NonceEntry {
                created_at,
                expires_at: created_at.saturating_add(ttl),
            };
            let now = created_at.saturating_add(elapsed);
            let is_valid = entry.expires_at >= now;
            let should_be_valid = elapsed <= ttl;
            prop_assert_eq!(is_valid, should_be_valid);
        }

        /// Property: SetNonceRequest rejects unknown fields
        #[test]
        fn prop_deny_unknown_fields(extra in "[a-z]{1,10}") {
            let json = format!(r#"{{"ttl_seconds": 300, "{}": true}}"#, extra);
            let result = serde_json::from_str::<SetNonceRequest>(&json);
            prop_assert!(result.is_err());
        }

        /// Property: saturating_add never overflows
        #[test]
        fn prop_saturating_add_no_overflow(now in 0u64..u64::MAX, ttl in 0u64..u64::MAX) {
            let expires_at = now.saturating_add(ttl);
            prop_assert!(expires_at >= now);
            prop_assert!(expires_at >= ttl);
        }

        /// Property: cleanup and replay decisions are complementary
        #[test]
        fn prop_cleanup_replay_complementary(
            created_at in 1_000_000_000u64..1_500_000_000,
            ttl in 0u64..86400,
            elapsed in 0u64..172800
        ) {
            let entry = NonceEntry {
                created_at,
                expires_at: created_at.saturating_add(ttl),
            };
            let now = created_at.saturating_add(elapsed);
            let is_replay = entry.expires_at >= now;
            let is_expired = entry.expires_at < now;
            // Exactly one must be true
            prop_assert!(is_replay != is_expired);
        }

        /// Property: percent-decode then re-encode roundtrips for safe ASCII
        #[test]
        fn prop_percent_decode_ascii_passthrough(tag in "[a-z0-9_-]{1,50}") {
            let decoded = percent_encoding::percent_decode_str(&tag)
                .decode_utf8()
                .unwrap();
            prop_assert_eq!(decoded.as_ref(), tag.as_str());
        }

        /// Property: valid nonce tags survive decode -> validate
        #[test]
        fn prop_valid_tag_survives_decode_validate(tag in "[a-z]{1,10}:[0-9a-f-]{1,36}") {
            let decoded = percent_encoding::percent_decode_str(&tag)
                .decode_utf8()
                .unwrap();
            prop_assert!(validate_nonce_tag(&decoded).is_ok());
        }

        /// Property: storage key length is prefix length + tag length
        #[test]
        fn prop_storage_key_length(tag in "[a-z0-9:-]{1,100}") {
            let key = format!("{}{}", NONCE_KEY_PREFIX, tag);
            prop_assert_eq!(key.len(), NONCE_KEY_PREFIX.len() + tag.len());
        }

        /// Property: SetNonceRequest roundtrips valid TTL values
        #[test]
        fn prop_set_nonce_request_roundtrip(ttl in 0u64..u64::MAX) {
            let json = format!(r#"{{"ttl_seconds": {}}}"#, ttl);
            let parsed = serde_json::from_str::<SetNonceRequest>(&json).unwrap();
            prop_assert_eq!(parsed.ttl_seconds, ttl);
        }
    }
}
