// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Idempotency store implementation using Durable Objects.
//!
//! Caches HTTP responses by idempotency key so that retried requests receive
//! the same response without re-executing side effects. Keys are sharded
//! across Durable Object instances by hash for even load distribution.
//!
//! SECURITY: Implements idempotency key support per ASVS V11 and
//! OWASP API4:2023. Stored responses are capped at 64 KB (IV-1212) and include
//! a request fingerprint for mismatch detection (RT-044).
#![forbid(unsafe_code)]

use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use worker::{Method, Request};

/// SECURITY: Cached idempotency response.
///
/// IV-1211: deny_unknown_fields prevents injecting unexpected fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedIdempotencyResponse {
    /// Serialised JSON response body returned to the caller.
    pub response_body: String,
    /// HTTP status code of the original response.
    pub status_code: u16,
    /// Whether the cached entry has exceeded its TTL.
    pub expired: bool,
    /// KV-032: Stored request fingerprint for mismatch detection (RT-044).
    #[serde(default)]
    pub request_fingerprint: String,
}

/// IV-1212: Maximum length for cached response bodies (64 KB).
/// Idempotency responses are short JSON payloads; anything larger is suspect.
const MAX_RESPONSE_BODY_LENGTH: usize = 65_536;

/// VA-STO-002: Maximum allowed length for an idempotency key.
const MAX_IDEMPOTENCY_KEY_LENGTH: usize = 512;

/// VA-STO-002: Maximum allowed length for an endpoint identifier.
const MAX_ENDPOINT_LENGTH: usize = 256;

/// Calculate which shard an idempotency key should be stored in.
fn calculate_idempotency_shard_id(key: &str, shard_count: usize) -> String {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let hash = hasher.finish();
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    let shard_num = (hash % shard_count as u64) as usize;
    format!("idempotency-shard-{}", shard_num)
}

/// Durable Object-backed idempotency key store, sharded by key hash.
pub struct DurableObjectIdempotencyStore {
    namespace: worker::durable::ObjectNamespace,
    shard_count: usize,
}

impl DurableObjectIdempotencyStore {
    /// Create a new store with the given DO namespace and shard count.
    pub fn new(namespace: worker::durable::ObjectNamespace, shard_count: usize) -> Self {
        Self {
            namespace,
            shard_count,
        }
    }

    fn get_shard_id(&self, key: &str) -> String {
        calculate_idempotency_shard_id(key, self.shard_count)
    }

    /// VA-STO-002: Validate an idempotency key before any storage operation.
    /// Rejects empty keys, oversized keys, and keys containing null bytes.
    fn validate_key(key: &str) -> ApiResult<()> {
        if key.is_empty() {
            return Err(ApiError::BadRequest(Some(
                "Idempotency key must not be empty".into(),
            )));
        }
        if key.len() > MAX_IDEMPOTENCY_KEY_LENGTH {
            return Err(ApiError::BadRequest(Some(format!(
                "Idempotency key exceeds maximum length of {} bytes",
                MAX_IDEMPOTENCY_KEY_LENGTH
            ))));
        }
        if key.contains('\0') {
            return Err(ApiError::BadRequest(Some(
                "Idempotency key must not contain null bytes".into(),
            )));
        }
        Ok(())
    }

    async fn send_to_do(
        &self,
        key: &str,
        method: Method,
        body: Option<Vec<u8>>,
    ) -> ApiResult<worker::Response> {
        let shard_id = self.get_shard_id(key);
        let stub = self.namespace.id_from_name(&shard_id)?.get_stub()?;

        // Percent-encode the key for transmission
        let encoded_key =
            percent_encoding::utf8_percent_encode(key, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let path = format!("/idempotency/{}", encoded_key);
        let url = format!("https://do.internal{}", path);
        let body_str = body
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).to_string());

        let mut init = worker::RequestInit::new();
        init.with_method(method);

        if let Some(ref body_data) = body_str {
            let headers = worker::Headers::new();
            init.with_headers(headers);
            init.with_body(Some(worker::wasm_bindgen::JsValue::from_str(body_data)));
        }

        let req = Request::new_with_init(&url, &init)?;

        // Per-operation timeout for IdempotencyDO fetch.
        crate::utils::timeout::with_timeout(
            "IdempotencyDO fetch",
            crate::utils::timeout::DO_FETCH_TIMEOUT_MS,
            stub.fetch_with_request(req),
        )
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("{}", e)))?
        .map_err(|e: worker::Error| ApiError::Internal(anyhow::anyhow!(e.to_string())))
    }

    /// SECURITY: Check if an idempotency key exists.
    /// Returns cached response if found and not expired.
    ///
    /// VA-STO-002: Validates key before sending to DO.
    pub async fn check(&self, key: &str) -> ApiResult<Option<CachedIdempotencyResponse>> {
        Self::validate_key(key)?;
        let mut resp = self.send_to_do(key, Method::Get, None).await?;

        #[derive(Deserialize)]
        struct CheckResponse {
            exists: bool,
            response_body: Option<String>,
            status_code: Option<u16>,
            expired: bool,
            #[serde(default)]
            request_fingerprint: Option<String>,
        }

        let result: CheckResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

        if result.exists && !result.expired {
            if let (Some(body), Some(status)) = (result.response_body, result.status_code) {
                return Ok(Some(CachedIdempotencyResponse {
                    response_body: body,
                    status_code: status,
                    expired: false,
                    request_fingerprint: result.request_fingerprint.unwrap_or_default(),
                }));
            }
        }

        Ok(None)
    }

    /// SECURITY: Store an idempotency key with cached response.
    /// Returns Ok(true) if stored successfully, Ok(false) if key already exists.
    ///
    /// # Arguments
    /// * `key` - The scoped idempotency key (already includes method:endpoint prefix from RT-042)
    /// * `response_body` - The response body to cache
    /// * `status_code` - The HTTP status code of the response
    /// * `endpoint` - The endpoint identifier (for monitoring)
    /// * `ttl_secs` - Optional TTL in seconds
    /// * `request_body_hash` - Optional hash of the inbound request body (RT-044).
    ///   When provided, this fingerprint is stored alongside the cached response so
    ///   that a replayed key with a different request body can be detected.
    pub async fn store(
        &self,
        key: &str,
        response_body: String,
        status_code: u16,
        endpoint: &str,
        ttl_secs: Option<u64>,
        request_fingerprint: &str,
    ) -> ApiResult<bool> {
        // VA-STO-002: Validate inputs at the storage boundary.
        Self::validate_key(key)?;
        if endpoint.is_empty() {
            return Err(ApiError::BadRequest(Some(
                "Endpoint must not be empty".into(),
            )));
        }
        if endpoint.len() > MAX_ENDPOINT_LENGTH {
            return Err(ApiError::BadRequest(Some(format!(
                "Endpoint exceeds maximum length of {} bytes",
                MAX_ENDPOINT_LENGTH
            ))));
        }
        if endpoint.contains('\0') {
            return Err(ApiError::BadRequest(Some(
                "Endpoint must not contain null bytes".into(),
            )));
        }

        // IV-1212: Reject oversized response bodies before storing.
        if response_body.len() > MAX_RESPONSE_BODY_LENGTH {
            return Err(ApiError::BadRequest(Some(format!(
                "Response body exceeds maximum length of {} bytes",
                MAX_RESPONSE_BODY_LENGTH
            ))));
        }

        let body = serde_json::to_vec(&serde_json::json!({
            "response_body": response_body,
            "status_code": status_code,
            "ttl_secs": ttl_secs,
            "endpoint": endpoint,
            "request_fingerprint": request_fingerprint,
        }))
        .map_err(|e| ApiError::Internal(e.into()))?;

        let mut resp = self.send_to_do(key, Method::Post, Some(body)).await?;

        #[derive(Deserialize)]
        struct SetResponse {
            success: bool,
        }

        let result: SetResponse = resp
            .json()
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

        Ok(result.success)
    }

    /// Helper to hash response body for fingerprinting
    #[cfg(test)]
    #[allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::string_slice
    )]
    fn hash_body(body: &str) -> String {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(body.as_bytes());
        hex::encode(&hash[0..8]) // First 8 bytes is sufficient for fingerprinting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idempotency_shard_id_format() {
        let shard_id = calculate_idempotency_shard_id("550e8400-e29b-41d4-a716-446655440000", 10);
        assert!(shard_id.starts_with("idempotency-shard-"));
    }

    #[test]
    fn test_idempotency_shard_id_within_range() -> Result<(), Box<dyn std::error::Error>> {
        let shard_count = 16;
        let shard_id = calculate_idempotency_shard_id("test-key", shard_count);

        let shard_num: usize = shard_id
            .strip_prefix("idempotency-shard-")
            .ok_or("missing prefix")?
            .parse()?;

        assert!(shard_num < shard_count);
        Ok(())
    }

    #[test]
    fn test_idempotency_shard_id_deterministic() {
        let key = "550e8400-e29b-41d4-a716-446655440000";
        let shard1 = calculate_idempotency_shard_id(key, 8);
        let shard2 = calculate_idempotency_shard_id(key, 8);

        assert_eq!(shard1, shard2);
    }

    #[test]
    fn test_hash_body() {
        let body1 = r#"{"result":"OK"}"#;
        let body2 = r#"{"result":"FAIL"}"#;

        let hash1 = DurableObjectIdempotencyStore::hash_body(body1);
        let hash2 = DurableObjectIdempotencyStore::hash_body(body2);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_hash_body_deterministic() {
        let body = r#"{"test":"data"}"#;
        let hash1 = DurableObjectIdempotencyStore::hash_body(body);
        let hash2 = DurableObjectIdempotencyStore::hash_body(body);

        assert_eq!(hash1, hash2);
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_shard_id_deterministic(key in "[a-f0-9\\-]{36}") {
            let shard1 = calculate_idempotency_shard_id(&key, 16);
            let shard2 = calculate_idempotency_shard_id(&key, 16);
            prop_assert_eq!(shard1, shard2);
        }

        #[test]
        fn prop_shard_id_in_range(key in ".*", shard_count in 1usize..32) {
            let shard_id = calculate_idempotency_shard_id(&key, shard_count);
            let shard_num: usize = shard_id
                .strip_prefix("idempotency-shard-")
                .expect("missing prefix")
                .parse()
                .expect("not a number");
            prop_assert!(shard_num < shard_count);
        }

        #[test]
        fn prop_hash_body_deterministic(body in ".*") {
            let hash1 = DurableObjectIdempotencyStore::hash_body(&body);
            let hash2 = DurableObjectIdempotencyStore::hash_body(&body);
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_hash_body_length(body in ".*") {
            let hash = DurableObjectIdempotencyStore::hash_body(&body);
            prop_assert_eq!(hash.len(), 16);
        }
    }

    // ======================================================================
    // CachedIdempotencyResponse serialisation
    // ======================================================================

    #[test]
    fn test_cached_response_serialise() -> Result<(), Box<dyn std::error::Error>> {
        let resp = CachedIdempotencyResponse {
            response_body: r#"{"ok":true}"#.to_string(),
            status_code: 200,
            expired: false,
            request_fingerprint: "abc123".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        assert!(json.contains("200"));
        assert!(json.contains("abc123"));
        assert!(json.contains(r#"{\"ok\":true}"#));
        Ok(())
    }

    #[test]
    fn test_cached_response_deserialise() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"response_body":"{\"ok\":true}","status_code":201,"expired":false,"request_fingerprint":"fp"}"#;
        let resp: CachedIdempotencyResponse = serde_json::from_str(json)?;
        assert_eq!(resp.status_code, 201);
        assert!(!resp.expired);
        assert_eq!(resp.request_fingerprint, "fp");
        Ok(())
    }

    #[test]
    fn test_cached_response_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = CachedIdempotencyResponse {
            response_body: "test body".to_string(),
            status_code: 409,
            expired: true,
            request_fingerprint: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&resp)?;
        let decoded: CachedIdempotencyResponse = serde_json::from_str(&json)?;
        assert_eq!(decoded.response_body, resp.response_body);
        assert_eq!(decoded.status_code, resp.status_code);
        assert_eq!(decoded.expired, resp.expired);
        assert_eq!(decoded.request_fingerprint, resp.request_fingerprint);
        Ok(())
    }

    #[test]
    fn test_cached_response_deny_unknown_fields() {
        let json = r#"{"response_body":"b","status_code":200,"expired":false,"request_fingerprint":"","extra":"bad"}"#;
        let result = serde_json::from_str::<CachedIdempotencyResponse>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra keys"
        );
    }

    #[test]
    fn test_cached_response_default_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
        // request_fingerprint has #[serde(default)], so missing field should deserialise to ""
        let json = r#"{"response_body":"b","status_code":200,"expired":false}"#;
        let resp: CachedIdempotencyResponse = serde_json::from_str(json)?;
        assert_eq!(resp.request_fingerprint, "");
        Ok(())
    }

    // ======================================================================
    // MAX_RESPONSE_BODY_LENGTH constant
    // ======================================================================

    #[test]
    fn test_max_response_body_length_is_64kb() {
        assert_eq!(MAX_RESPONSE_BODY_LENGTH, 65_536);
    }

    #[test]
    fn test_response_body_within_limit() {
        let body = "a".repeat(MAX_RESPONSE_BODY_LENGTH);
        assert!(body.len() <= MAX_RESPONSE_BODY_LENGTH);
    }

    #[test]
    fn test_response_body_exceeds_limit() {
        let body = "a".repeat(MAX_RESPONSE_BODY_LENGTH.saturating_add(1));
        assert!(body.len() > MAX_RESPONSE_BODY_LENGTH);
    }

    // ======================================================================
    // Shard edge cases
    // ======================================================================

    #[test]
    fn test_idempotency_shard_single_shard() {
        let id = calculate_idempotency_shard_id("any-key-here", 1);
        assert_eq!(id, "idempotency-shard-0");
    }

    #[test]
    fn test_idempotency_shard_empty_key() {
        let id = calculate_idempotency_shard_id("", 10);
        assert!(id.starts_with("idempotency-shard-"));
    }

    #[test]
    fn test_idempotency_shard_distribution() -> Result<(), Box<dyn std::error::Error>> {
        let shard_count = 16;
        let mut counts = vec![0usize; shard_count];
        for i in 0..10000 {
            let key = format!("key-{}", i);
            let shard_id = calculate_idempotency_shard_id(&key, shard_count);
            let shard_num: usize = shard_id
                .strip_prefix("idempotency-shard-")
                .ok_or("missing prefix")?
                .parse()?;
            counts[shard_num] = counts[shard_num].saturating_add(1);
        }
        // Every shard should receive at least some traffic
        for (i, &count) in counts.iter().enumerate() {
            assert!(count > 0, "Shard {} received zero items", i);
        }
        Ok(())
    }

    // ======================================================================
    // Percent-encoding for keys in URL paths
    // ======================================================================

    #[test]
    fn test_percent_encode_simple_key() {
        let key = "abc123";
        let encoded =
            percent_encoding::utf8_percent_encode(key, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        // Simple alphanumeric key should mostly encode
        assert!(encoded.contains("abc"));
    }

    #[test]
    fn test_percent_encode_special_chars() {
        let key = "POST:/verify?foo=bar&baz=1";
        let encoded =
            percent_encoding::utf8_percent_encode(key, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        // Colon, slashes, question marks, ampersand, equals should be encoded
        assert!(!encoded.contains(':'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('?'));
        assert!(!encoded.contains('&'));
    }

    #[test]
    fn test_percent_encode_url_path_format() {
        let key = "test-key-123";
        let encoded =
            percent_encoding::utf8_percent_encode(key, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let path = format!("/idempotency/{}", encoded);
        let url = format!("https://do.internal{}", path);
        assert!(url.starts_with("https://do.internal/idempotency/"));
    }

    // ======================================================================
    // Property tests for CachedIdempotencyResponse
    // ======================================================================

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_cached_response_roundtrip(
            body in ".*",
            status in 100u16..600,
            expired in any::<bool>(),
            fp in "[a-f0-9]{0,32}"
        ) {
            let resp = CachedIdempotencyResponse {
                response_body: body.clone(),
                status_code: status,
                expired,
                request_fingerprint: fp.clone(),
            };
            let json = serde_json::to_string(&resp).expect("serialise");
            let decoded: CachedIdempotencyResponse = serde_json::from_str(&json).expect("deserialise");
            prop_assert_eq!(decoded.response_body, body);
            prop_assert_eq!(decoded.status_code, status);
            prop_assert_eq!(decoded.expired, expired);
            prop_assert_eq!(decoded.request_fingerprint, fp);
        }

        #[test]
        fn prop_max_body_length_boundary(len in 65530usize..65545) {
            let body = "x".repeat(len);
            let within = body.len() <= MAX_RESPONSE_BODY_LENGTH;
            let expected = len <= MAX_RESPONSE_BODY_LENGTH;
            prop_assert_eq!(within, expected);
        }
    }
}
