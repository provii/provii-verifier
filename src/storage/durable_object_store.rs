// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Durable Object-backed nonce store for atomic check-and-set semantics.
//!
//! The NonceDO serialises all operations per shard, eliminating the TOCTOU race
//! inherent in the KV-backed implementation (which required two sequential
//! round-trips: GET then PUT). A single POST to the DO performs an atomic
//! check-and-set in one round-trip, halving latency and closing the race window.
//!
//! Each nonce is stored as an individual key (`nonce:{tag}`) rather than in a
//! single serialised HashMap, avoiding the 128 KB per-key storage limit.
//!
//! Nonce tags are sharded across DO instances using a deterministic hash of the
//! tag string to distribute load evenly.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::error::{ApiError, ApiResult};
use crate::security::audit::AuditEventData;
use crate::storage::{traits::NonceStore, AuditLoggerSlot};

/// Calculate which shard a nonce tag should be routed to.
fn calculate_nonce_shard_id(tag: &str, shard_count: usize) -> String {
    let mut hasher = DefaultHasher::new();
    tag.hash(&mut hasher);
    let hash = hasher.finish();
    // shard_count is a small positive number (e.g. 25), so the cast and modulo are safe.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    let shard_num = (hash % shard_count as u64) as usize;
    format!("nonce-shard-{}", shard_num)
}

/// Durable Object-backed [`NonceStore`] with atomic check-and-set.
///
/// Each `check_and_set` call is a single POST to the NonceDO, which handles
/// deduplication and audit event generation internally. The DO returns
/// `{"success": true}` on first use and `{"success": false}` when the nonce
/// has already been consumed (replay detected). Expired nonce cleanup is
/// handled by the DO's alarm handler.
///
/// AL-008: Holds an [`AuditLoggerSlot`] so audit events emitted by the DO
/// (`nonce_replay_detected`) reach the worker-level audit logger and are
/// persisted to D1 via the audit queue.
pub struct DurableObjectNonceStore {
    namespace: worker::durable::ObjectNamespace,
    shard_count: usize,
    audit_logger: AuditLoggerSlot,
}

impl DurableObjectNonceStore {
    /// Create a new store with the given DO namespace and shard count.
    pub fn new(
        namespace: worker::durable::ObjectNamespace,
        shard_count: usize,
        audit_logger: AuditLoggerSlot,
    ) -> Self {
        Self {
            namespace,
            shard_count,
            audit_logger,
        }
    }

    /// AL-008: Best-effort dispatch of the `audit_events` array embedded in
    /// the NonceDO response body. Failure to parse is non-fatal; the nonce
    /// check itself has already completed.
    async fn dispatch_events_from_body(&self, body: &str) {
        let Some(logger) = self.audit_logger.get() else {
            return;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return;
        };
        let Some(array) = value.get("audit_events").and_then(|v| v.as_array()) else {
            return;
        };
        if array.is_empty() {
            return;
        }
        let events: Vec<AuditEventData> = array
            .iter()
            .filter_map(|v| serde_json::from_value::<AuditEventData>(v.clone()).ok())
            .collect();
        if events.is_empty() {
            return;
        }
        logger.dispatch_do_audit_events(&events, "", "", "").await;
    }
}

/// VA-STO-002: Maximum allowed length for a nonce tag. Nonce tags are
/// typically under 200 bytes; anything beyond this limit is suspect.
const MAX_NONCE_TAG_LENGTH: usize = 512;

#[async_trait(?Send)]
impl NonceStore for DurableObjectNonceStore {
    async fn check_and_set(&self, nonce_tag: &str, ttl: Duration) -> ApiResult<bool> {
        // VA-STO-002: Validate inputs before writing.
        if nonce_tag.is_empty() {
            return Err(ApiError::BadRequest(Some(
                "Nonce tag must not be empty".into(),
            )));
        }
        if nonce_tag.len() > MAX_NONCE_TAG_LENGTH {
            return Err(ApiError::BadRequest(Some(format!(
                "Nonce tag exceeds maximum length of {} bytes",
                MAX_NONCE_TAG_LENGTH
            ))));
        }
        if nonce_tag.contains('\0') {
            return Err(ApiError::BadRequest(Some(
                "Nonce tag must not contain null bytes".into(),
            )));
        }
        if ttl.is_zero() {
            return Err(ApiError::BadRequest(Some(
                "Nonce TTL must be greater than zero".into(),
            )));
        }
        let shard_id = calculate_nonce_shard_id(nonce_tag, self.shard_count);
        let stub = self.namespace.id_from_name(&shard_id)?.get_stub()?;

        // Percent-encode the nonce tag for safe URL transmission.
        let encoded_tag =
            percent_encoding::utf8_percent_encode(nonce_tag, percent_encoding::NON_ALPHANUMERIC)
                .to_string();

        let url = format!("https://do.internal/nonce/{}", encoded_tag);

        // Pass the TTL so the DO stores it with the nonce entry for
        // alarm-based expiry cleanup.
        let body = serde_json::json!({ "ttl_seconds": ttl.as_secs() });

        let headers = worker::Headers::new();
        let _ = headers.set("Content-Type", "application/json");

        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_headers(headers);
        init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(
            &body.to_string(),
        )));

        let req = worker::Request::new_with_init(&url, &init)?;

        // Per-operation timeout for NonceDO fetch.
        let mut resp = crate::utils::timeout::with_timeout(
            "NonceDO fetch",
            crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
            stub.fetch_with_request(req),
        )
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("{}", e)))?
        .map_err(|e: worker::Error| {
            ApiError::Internal(anyhow::anyhow!("NonceDO fetch failed: {}", e))
        })?;

        // Read the body once. The NonceDO embeds `audit_events` in the replay
        // path; a single body read avoids the pattern of consuming via
        // `resp.json::<NonceResponse>()` which silently dropped the events.
        let body = resp.text().await.map_err(|e| {
            ApiError::Internal(anyhow::anyhow!("NonceDO response read failed: {}", e))
        })?;

        // AL-008: Dispatch any embedded audit events before returning so
        // CRITICAL replay events reach the audit queue.
        self.dispatch_events_from_body(&body).await;

        #[derive(serde::Deserialize)]
        struct NonceResponse {
            success: bool,
        }

        let result: NonceResponse = serde_json::from_str(&body).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!("NonceDO response parse failed: {}", e))
        })?;

        Ok(result.success)
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

    #[test]
    fn test_shard_id_deterministic() {
        let id1 = calculate_nonce_shard_id("verify:abc-123", 25);
        let id2 = calculate_nonce_shard_id("verify:abc-123", 25);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_shard_id_format() {
        let id = calculate_nonce_shard_id("verify:abc-123", 25);
        assert!(id.starts_with("nonce-shard-"));
    }

    #[test]
    fn test_shard_id_bounded() -> Result<(), Box<dyn std::error::Error>> {
        for i in 0..1000 {
            let tag = format!("verify:{}", i);
            let id = calculate_nonce_shard_id(&tag, 25);
            let shard_num: usize = id
                .strip_prefix("nonce-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            assert!(shard_num < 25, "Shard {} out of range", shard_num);
        }
        Ok(())
    }

    #[test]
    fn test_shard_id_distribution() -> Result<(), Box<dyn std::error::Error>> {
        let mut counts = [0usize; 25];
        for i in 0..10000 {
            let tag = format!("verify:{}", i);
            let id = calculate_nonce_shard_id(&tag, 25);
            let shard_num: usize = id
                .strip_prefix("nonce-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            counts[shard_num] += 1;
        }
        // Every shard should get at least some traffic.
        for (i, &count) in counts.iter().enumerate() {
            assert!(count > 0, "Shard {} received zero items", i);
        }
        Ok(())
    }

    #[test]
    fn test_different_tags_can_differ() {
        let id1 = calculate_nonce_shard_id("verify:aaa", 25);
        let id2 = calculate_nonce_shard_id("verify:zzz", 25);
        // They CAN be the same (hash collision), but with 25 shards and distinct inputs,
        // statistically they should usually differ. We just verify both are valid.
        assert!(id1.starts_with("nonce-shard-"));
        assert!(id2.starts_with("nonce-shard-"));
    }

    #[test]
    fn test_single_shard() {
        let id = calculate_nonce_shard_id("any-tag", 1);
        assert_eq!(id, "nonce-shard-0");
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: shard index is always within bounds.
        #[test]
        fn prop_shard_bounded(tag in "verify:[a-z0-9-]{1,50}", count in 1usize..100) {
            let id = calculate_nonce_shard_id(&tag, count);
            let num: usize = id
                .strip_prefix("nonce-shard-")
                .expect("missing prefix")
                .parse()
                .expect("not a number");
            prop_assert!(num < count);
        }

        /// Property: shard assignment is deterministic.
        #[test]
        fn prop_shard_deterministic(tag in "verify:[a-z0-9-]{1,50}") {
            let id1 = calculate_nonce_shard_id(&tag, 25);
            let id2 = calculate_nonce_shard_id(&tag, 25);
            prop_assert_eq!(id1, id2);
        }
    }

    // ======================================================================
    // Shard boundary values
    // ======================================================================

    #[test]
    fn test_shard_two_shards_covers_both() -> Result<(), Box<dyn std::error::Error>> {
        // With 2 shards, we should hit both 0 and 1 given enough inputs
        let mut seen = [false; 2];
        for i in 0..100 {
            let tag = format!("verify:{}", i);
            let id = calculate_nonce_shard_id(&tag, 2);
            let shard_num: usize = id
                .strip_prefix("nonce-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            seen[shard_num] = true;
        }
        assert!(seen[0], "Shard 0 never hit with 2 shards");
        assert!(seen[1], "Shard 1 never hit with 2 shards");
        Ok(())
    }

    #[test]
    fn test_shard_large_count() -> Result<(), Box<dyn std::error::Error>> {
        // With a large shard count, shard_num should still be within bounds
        let shard_count = 1000;
        let id = calculate_nonce_shard_id("verify:test-tag", shard_count);
        let shard_num: usize = id
            .strip_prefix("nonce-shard-")
            .ok_or("missing prefix")?
            .parse()?;
        assert!(shard_num < shard_count);
        Ok(())
    }

    #[test]
    fn test_shard_empty_tag() {
        let id = calculate_nonce_shard_id("", 25);
        assert!(id.starts_with("nonce-shard-"));
    }

    #[test]
    fn test_shard_unicode_tag() {
        let id = calculate_nonce_shard_id("verify:\u{1F600}\u{1F601}", 10);
        assert!(id.starts_with("nonce-shard-"));
    }

    // ======================================================================
    // Percent-encoding for nonce tags
    // ======================================================================

    #[test]
    fn test_nonce_url_percent_encoding() {
        let nonce_tag = "verify:abc+def/ghi";
        let encoded =
            percent_encoding::utf8_percent_encode(nonce_tag, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let url = format!("https://do.internal/nonce/{}", encoded);
        assert!(url.starts_with("https://do.internal/nonce/"));
        // Special chars should be encoded
        assert!(!url.contains('+'));
    }

    #[test]
    fn test_nonce_url_format_simple() {
        let encoded_tag = "verify%3Aabc%2D123";
        let url = format!("https://do.internal/nonce/{}", encoded_tag);
        assert_eq!(url, "https://do.internal/nonce/verify%3Aabc%2D123");
    }

    // ======================================================================
    // TTL serialisation for DO body
    // ======================================================================

    #[test]
    fn test_ttl_body_json() -> Result<(), Box<dyn std::error::Error>> {
        let ttl = Duration::from_secs(300);
        let body = serde_json::json!({ "ttl_seconds": ttl.as_secs() });
        let parsed: serde_json::Value = serde_json::from_str(&body.to_string())?;
        assert_eq!(parsed["ttl_seconds"], 300);
        Ok(())
    }

    #[test]
    fn test_ttl_body_zero_duration() -> Result<(), Box<dyn std::error::Error>> {
        let ttl = Duration::from_secs(0);
        let body = serde_json::json!({ "ttl_seconds": ttl.as_secs() });
        let parsed: serde_json::Value = serde_json::from_str(&body.to_string())?;
        assert_eq!(parsed["ttl_seconds"], 0);
        Ok(())
    }

    // ======================================================================
    // Distribution statistical check
    // ======================================================================

    #[test]
    fn test_shard_distribution_chi_squared_loose() -> Result<(), Box<dyn std::error::Error>> {
        let shard_count = 25;
        let n = 10000usize;
        let mut counts = vec![0usize; shard_count];
        for i in 0..n {
            let tag = format!("verify:{}", i);
            let id = calculate_nonce_shard_id(&tag, shard_count);
            let shard_num: usize = id
                .strip_prefix("nonce-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            counts[shard_num] = counts[shard_num].saturating_add(1);
        }
        let expected = n as f64 / shard_count as f64;
        // No shard should hold more than 3x the expected average
        for (i, &count) in counts.iter().enumerate() {
            assert!(
                (count as f64) < expected * 3.0,
                "Shard {} has {} items, expected ~{:.0}",
                i,
                count,
                expected
            );
        }
        Ok(())
    }
}
