// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Native-target rate limiting tests for provii-verifier.
//!
//! Extracts the portable rate limiting logic from `src/rate_limiting.rs` and
//! `src/hosted/rate_limiting.rs` and exercises it with a mock KV backend.
//! The main crate targets wasm32 exclusively, so these tests must live in a
//! separate native-target subcrate.
//!
//! Covers:
//! - `parse_tier_limits` edge cases (nested, flat, invalid, empty)
//! - KV counter allow/deny decisions and fail-closed behaviour
//! - Tier lookup with caching and expiry
//! - In-memory counter cache with sync intervals and eviction
//! - End-to-end quota and per-IP limit flows
//! - KV failure counter (circuit breaker) behaviour

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{OnceLock, RwLock};

use async_trait::async_trait;

// ===========================================================================
// RateLimitKv trait + MockKv
// ===========================================================================

/// Errors from the rate limit KV abstraction.
#[derive(Debug)]
pub struct RateLimitKvError(pub String);

impl std::fmt::Display for RateLimitKvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Minimal KV interface consumed by the rate limiting modules.
#[async_trait(?Send)]
pub trait RateLimitKv {
    async fn get_text(&self, key: &str) -> Result<Option<String>, RateLimitKvError>;
    async fn put_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), RateLimitKvError>;
}

/// Record of a `put_with_ttl` call.
#[derive(Debug, Clone)]
pub struct PutRecord {
    pub key: String,
    pub value: String,
    pub ttl_secs: u64,
}

/// In-memory KV mock with failure injection and put logging.
pub struct MockKv {
    inner: std::sync::Mutex<MockKvInner>,
}

struct MockKvInner {
    data: HashMap<String, String>,
    puts: Vec<PutRecord>,
    get_error: Option<String>,
    put_error: Option<String>,
    persistent_errors: bool,
}

impl Default for MockKv {
    fn default() -> Self {
        Self::new()
    }
}

impl MockKv {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(MockKvInner {
                data: HashMap::new(),
                puts: Vec::new(),
                get_error: None,
                put_error: None,
                persistent_errors: false,
            }),
        }
    }

    pub fn with_entry(self, key: &str, value: &str) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner.data.insert(key.to_string(), value.to_string());
        }
        self
    }

    pub fn with_get_error(self, msg: &str) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner.get_error = Some(msg.to_string());
        }
        self
    }

    pub fn with_put_error(self, msg: &str) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner.put_error = Some(msg.to_string());
        }
        self
    }

    pub fn with_persistent_errors(self) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner.persistent_errors = true;
        }
        self
    }

    pub fn puts(&self) -> Vec<PutRecord> {
        self.inner
            .lock()
            .map(|inner| inner.puts.clone())
            .unwrap_or_default()
    }
}

#[async_trait(?Send)]
impl RateLimitKv for MockKv {
    async fn get_text(&self, key: &str) -> Result<Option<String>, RateLimitKvError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| RateLimitKvError(e.to_string()))?;
        if let Some(ref err) = inner.get_error {
            let msg = err.clone();
            if !inner.persistent_errors {
                inner.get_error = None;
            }
            return Err(RateLimitKvError(msg));
        }
        Ok(inner.data.get(key).cloned())
    }

    async fn put_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl_secs: u64,
    ) -> Result<(), RateLimitKvError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| RateLimitKvError(e.to_string()))?;
        if let Some(ref err) = inner.put_error {
            let msg = err.clone();
            if !inner.persistent_errors {
                inner.put_error = None;
            }
            return Err(RateLimitKvError(msg));
        }
        inner.puts.push(PutRecord {
            key: key.to_string(),
            value: value.to_string(),
            ttl_secs,
        });
        inner.data.insert(key.to_string(), value.to_string());
        Ok(())
    }
}

// ===========================================================================
// Extracted rate limiting logic (expert module)
// ===========================================================================

/// Parse tier limit JSON into a map of endpoint name to hourly quota.
///
/// Extracted from `src/rate_limiting.rs` for native testing. Handles:
/// - Nested: `{ "limits": { "endpoint": limit }, ... }`
/// - Flat: `{ "endpoint": limit, ... }`
///
/// Returns an empty map on invalid JSON.
pub fn parse_tier_limits(json: &str) -> HashMap<String, u32> {
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(limits) = obj.get("limits") {
            if let Ok(map) = serde_json::from_value::<HashMap<String, u32>>(limits.clone()) {
                return map;
            }
        }
    }
    serde_json::from_str::<HashMap<String, u32>>(json).unwrap_or_default()
}

/// Increment a KV counter and return `(allowed, current_count, limit)`.
/// Fail-closed on KV read errors.
///
/// Extracted from `src/rate_limiting.rs::check_kv_counter`.
pub async fn check_kv_counter(
    kv: &dyn RateLimitKv,
    key: &str,
    limit: u32,
    ttl_secs: u64,
) -> (bool, u32, u32) {
    let count: u32 = match kv.get_text(key).await {
        Ok(Some(s)) => s.parse().unwrap_or(0),
        Ok(None) => 0,
        Err(_) => {
            // Fail closed.
            return (false, 0, limit);
        }
    };

    if count >= limit {
        return (false, count, limit);
    }

    if let Err(_e) = kv
        .put_with_ttl(key, &count.saturating_add(1).to_string(), ttl_secs)
        .await
    {
        // Write failure: still allow (bounded degradation).
    }

    (true, count.saturating_add(1), limit)
}

// ---------------------------------------------------------------------------
// Expert tier cache
// ---------------------------------------------------------------------------

struct ExpertTierCache {
    limits: HashMap<String, u32>,
    fetched_at: u64,
}

static EXPERT_TIER_CACHE: OnceLock<RwLock<HashMap<String, ExpertTierCache>>> = OnceLock::new();

fn expert_tier_cache() -> &'static RwLock<HashMap<String, ExpertTierCache>> {
    EXPERT_TIER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn clear_expert_tier_cache() {
    if let Ok(mut cache) = expert_tier_cache().write() {
        cache.clear();
    }
}

/// Look up the per-hour quota for `client_id` on `endpoint`.
/// Extracted from `src/rate_limiting.rs::get_customer_limit`.
pub async fn get_customer_limit(
    kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> u32 {
    if let Ok(cache) = expert_tier_cache().read() {
        if let Some(entry) = cache.get(client_id) {
            if now_secs.saturating_sub(entry.fetched_at) < 60 {
                return entry.limits.get(endpoint).copied().unwrap_or(default_limit);
            }
        }
    }

    let tier_id = match kv
        .get_text(&format!("rate_limits/clients/{}", client_id))
        .await
    {
        Ok(Some(t)) => t,
        _ => return default_limit,
    };

    let limits = match kv.get_text(&format!("rate_limits/tiers/{}", tier_id)).await {
        Ok(Some(json)) => parse_tier_limits(&json),
        _ => HashMap::new(),
    };

    let result = limits.get(endpoint).copied().unwrap_or(default_limit);

    if let Ok(mut cache) = expert_tier_cache().write() {
        cache.insert(
            client_id.to_string(),
            ExpertTierCache {
                limits,
                fetched_at: now_secs,
            },
        );
    }

    result
}

/// Rate limit check result.
pub struct RateLimitResult {
    pub allowed: bool,
    pub current_count: u32,
    pub limit: u32,
    pub retry_after_secs: u32,
}

/// Testable check_quota flow (expert module).
pub async fn check_quota(
    rate_limit_kv: &dyn RateLimitKv,
    config_kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    let hour_ts = (now_secs / 3600) * 3600;

    let limit = get_customer_limit(config_kv, client_id, endpoint, default_limit, now_secs).await;

    let key = format!("quota:{}:{}:{}", client_id, endpoint, hour_ts);
    let (allowed, current_count, limit) = check_kv_counter(rate_limit_kv, &key, limit, 7200).await;

    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX);

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
    }
}

/// Testable per-IP limit flow (expert module).
pub async fn check_per_ip_limit(
    rate_limit_kv: &dyn RateLimitKv,
    ip: &str,
    limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    let hour_ts = (now_secs / 3600) * 3600;

    let key = format!("short_code_enum:{}:{}", ip, hour_ts);
    let (allowed, current_count, limit) = check_kv_counter(rate_limit_kv, &key, limit, 7200).await;

    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX);

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
    }
}

// ===========================================================================
// Extracted rate limiting logic (hosted module)
// ===========================================================================

/// KV failure counter (extracted from hosted module statics).
static HOSTED_KV_FAILURE_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn hosted_record_kv_success() {
    HOSTED_KV_FAILURE_COUNT.store(0, Ordering::Relaxed);
}

pub fn hosted_record_kv_failure() -> u32 {
    HOSTED_KV_FAILURE_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1)
}

pub fn hosted_kv_unavailable_count() -> u32 {
    HOSTED_KV_FAILURE_COUNT.load(Ordering::Relaxed)
}

pub fn hosted_reset_kv_failure_count() {
    HOSTED_KV_FAILURE_COUNT.store(0, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Hosted tier cache
// ---------------------------------------------------------------------------

struct HostedTierCache {
    limits: HashMap<String, u32>,
    fetched_at: u64,
}

static HOSTED_TIER_CACHE: OnceLock<RwLock<HashMap<String, HostedTierCache>>> = OnceLock::new();

fn hosted_tier_cache() -> &'static RwLock<HashMap<String, HostedTierCache>> {
    HOSTED_TIER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn clear_hosted_tier_cache() {
    if let Ok(mut cache) = hosted_tier_cache().write() {
        cache.clear();
    }
}

/// Hosted tier lookup (extracted from `src/hosted/rate_limiting.rs`).
pub async fn hosted_get_customer_limit(
    kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> u32 {
    if let Ok(cache) = hosted_tier_cache().read() {
        if let Some(entry) = cache.get(client_id) {
            if now_secs.saturating_sub(entry.fetched_at) < 60 {
                return entry.limits.get(endpoint).copied().unwrap_or(default_limit);
            }
        }
    }

    let tier_id = match kv
        .get_text(&format!("rate_limits/clients/{}", client_id))
        .await
    {
        Ok(Some(t)) => t,
        _ => return default_limit,
    };

    let limits = match kv.get_text(&format!("rate_limits/tiers/{}", tier_id)).await {
        Ok(Some(json)) => parse_tier_limits(&json),
        _ => HashMap::new(),
    };

    let result = limits.get(endpoint).copied().unwrap_or(default_limit);

    if let Ok(mut cache) = hosted_tier_cache().write() {
        cache.insert(
            client_id.to_string(),
            HostedTierCache {
                limits,
                fetched_at: now_secs,
            },
        );
    }

    result
}

// ---------------------------------------------------------------------------
// Hosted in-memory counter cache
// ---------------------------------------------------------------------------

struct InMemoryCounter {
    count: u64,
    last_synced_at: f64,
    kv_count: u64,
}

const COUNTER_CACHE_MAX_ENTRIES: usize = 5000;
const COUNTER_SYNC_INTERVAL_SECS: f64 = 10.0;
const COUNTER_SYNC_INTERVAL_HITS: u64 = 10;

static HOSTED_COUNTER_CACHE: OnceLock<RwLock<HashMap<String, InMemoryCounter>>> = OnceLock::new();

fn hosted_counter_cache() -> &'static RwLock<HashMap<String, InMemoryCounter>> {
    HOSTED_COUNTER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn clear_hosted_counter_cache() {
    if let Ok(mut cache) = hosted_counter_cache().write() {
        cache.clear();
    }
}

/// Hosted KV counter with in-memory caching.
/// Extracted from `src/hosted/rate_limiting.rs::check_kv_counter`.
///
/// Returns `(allowed, count, limit, kv_unavailable)`.
pub async fn hosted_check_kv_counter(
    kv: &dyn RateLimitKv,
    key: &str,
    limit: u32,
    ttl_secs: u64,
    now_ms: f64,
) -> (bool, u32, u32, bool) {
    // Fast path: check in-memory cache
    let cache_result: Option<(u32, Option<u64>)> = {
        if let Ok(mut cache) = hosted_counter_cache().write() {
            if let Some(entry) = cache.get_mut(key) {
                let age_secs = (now_ms - entry.last_synced_at) / 1000.0;
                if age_secs < COUNTER_SYNC_INTERVAL_SECS {
                    entry.count = entry.count.saturating_add(1);
                    let count = u32::try_from(entry.count).unwrap_or(u32::MAX);
                    let increments_since_sync = entry.count.saturating_sub(entry.kv_count);
                    let sync_count = if increments_since_sync >= COUNTER_SYNC_INTERVAL_HITS {
                        let sc = entry.count;
                        entry.kv_count = sc;
                        entry.last_synced_at = now_ms;
                        Some(sc)
                    } else {
                        None
                    };
                    Some((count, sync_count))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some((count, sync_count)) = cache_result {
        if let Some(sc) = sync_count {
            let _ = kv.put_with_ttl(key, &sc.to_string(), ttl_secs).await;
        }
        if count >= limit {
            return (false, count, limit, false);
        }
        return (true, count, limit, false);
    }

    // Cache miss or stale: seed from KV
    let kv_count: u64 = match kv.get_text(key).await {
        Ok(Some(s)) => {
            hosted_record_kv_success();
            s.parse().unwrap_or(0)
        }
        Ok(None) => {
            hosted_record_kv_success();
            0
        }
        Err(_) => {
            let _failures = hosted_record_kv_failure();
            return (false, 0, limit, true);
        }
    };

    let new_count = kv_count.saturating_add(1);

    // Seed (or refresh) the in-memory cache
    if let Ok(mut cache) = hosted_counter_cache().write() {
        if cache.len() >= COUNTER_CACHE_MAX_ENTRIES {
            let stale_cutoff = now_ms - (ttl_secs as f64 * 1000.0);
            cache.retain(|_, entry| entry.last_synced_at > stale_cutoff);

            if cache.len() >= COUNTER_CACHE_MAX_ENTRIES {
                let mut entries: Vec<(String, f64)> = cache
                    .iter()
                    .map(|(k, v)| (k.clone(), v.last_synced_at))
                    .collect();
                entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                let evict_count = cache.len() / 2;
                for (k, _) in entries.into_iter().take(evict_count) {
                    cache.remove(&k);
                }
            }
        }
        cache.insert(
            key.to_string(),
            InMemoryCounter {
                count: new_count,
                last_synced_at: now_ms,
                kv_count: new_count,
            },
        );
    }

    if u32::try_from(new_count).unwrap_or(u32::MAX) >= limit {
        let _ = kv.put_with_ttl(key, &new_count.to_string(), ttl_secs).await;
        return (
            false,
            u32::try_from(new_count).unwrap_or(u32::MAX),
            limit,
            false,
        );
    }

    let _ = kv.put_with_ttl(key, &new_count.to_string(), ttl_secs).await;

    (
        true,
        u32::try_from(new_count).unwrap_or(u32::MAX),
        limit,
        false,
    )
}

/// Hosted check_quota result.
pub struct HostedRateLimitResult {
    pub allowed: bool,
    pub current_count: u32,
    pub limit: u32,
    pub retry_after_secs: u32,
    pub kv_unavailable: bool,
}

/// Testable check_quota flow (hosted module).
pub async fn hosted_check_quota(
    rate_limit_kv: &dyn RateLimitKv,
    config_kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
    now_ms: f64,
) -> HostedRateLimitResult {
    let hour_ts = (now_secs / 3600) * 3600;

    let limit =
        hosted_get_customer_limit(config_kv, client_id, endpoint, default_limit, hour_ts).await;

    let key = format!("quota:{}:{}:{}", client_id, endpoint, hour_ts);
    let (allowed, current_count, limit, kv_unavailable) =
        hosted_check_kv_counter(rate_limit_kv, &key, limit, 7200, now_ms).await;

    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX);

    HostedRateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        kv_unavailable,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // ======================================================================
    // Phase 1: parse_tier_limits (pure function, no mock needed)
    // ======================================================================

    // Test 1: nested StoredTier format
    #[test]
    fn parse_tier_limits_nested_format() {
        let json = r#"{"tier_id":"t1","limits":{"challenge":500,"verify":200}}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("challenge").copied(), Some(500));
        assert_eq!(map.get("verify").copied(), Some(200));
    }

    // Test 2: flat format
    #[test]
    fn parse_tier_limits_flat_format() {
        let json = r#"{"challenge":100,"verify":50}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("challenge").copied(), Some(100));
        assert_eq!(map.get("verify").copied(), Some(50));
    }

    // Test 3: invalid JSON returns empty
    #[test]
    fn parse_tier_limits_invalid_json() {
        let map = parse_tier_limits("not json at all");
        assert!(map.is_empty());
    }

    // Test 4: empty JSON object
    #[test]
    fn parse_tier_limits_empty_object() {
        let map = parse_tier_limits("{}");
        assert!(map.is_empty());
    }

    // Test 31: empty string
    #[test]
    fn parse_tier_limits_empty_string() {
        let map = parse_tier_limits("");
        assert!(map.is_empty());
    }

    // Test 32: nested with extra fields ignored
    #[test]
    fn parse_tier_limits_nested_extra_fields() {
        let json = r#"{"tier_id":"premium","name":"Premium","limits":{"challenge":1000},"created_at":"2026-01-01"}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("challenge").copied(), Some(1000));
    }

    // Extra: nested with non-u32 values falls back
    #[test]
    fn parse_tier_limits_nested_non_u32_falls_back() {
        let json = r#"{"limits":{"challenge":"not_a_number"}}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    // Extra: nested with empty limits object
    #[test]
    fn parse_tier_limits_nested_empty_limits() {
        let json = r#"{"limits":{}}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    // ======================================================================
    // Phase 2: Circuit breaker / KV failure counter (serial)
    // ======================================================================

    // Test 17: failure counter increments
    #[test]
    #[serial]
    fn kv_failure_counter_increments() {
        hosted_reset_kv_failure_count();
        assert_eq!(hosted_kv_unavailable_count(), 0);
        let c = hosted_record_kv_failure();
        assert_eq!(c, 1);
        let c = hosted_record_kv_failure();
        assert_eq!(c, 2);
        assert_eq!(hosted_kv_unavailable_count(), 2);
    }

    // Test 18: success resets counter
    #[test]
    #[serial]
    fn kv_success_resets_failure_counter() {
        hosted_reset_kv_failure_count();
        hosted_record_kv_failure();
        hosted_record_kv_failure();
        assert_eq!(hosted_kv_unavailable_count(), 2);
        hosted_record_kv_success();
        assert_eq!(hosted_kv_unavailable_count(), 0);
    }

    // Test 19: counter stays at zero when no failures
    #[test]
    #[serial]
    fn kv_failure_counter_stays_at_zero() {
        hosted_reset_kv_failure_count();
        hosted_record_kv_success();
        hosted_record_kv_success();
        assert_eq!(hosted_kv_unavailable_count(), 0);
    }

    // Test 20: interleaved success/failure
    #[test]
    #[serial]
    fn kv_failure_counter_interleaved() {
        hosted_reset_kv_failure_count();
        hosted_record_kv_failure();
        hosted_record_kv_success();
        assert_eq!(hosted_kv_unavailable_count(), 0);
        hosted_record_kv_failure();
        assert_eq!(hosted_kv_unavailable_count(), 1);
        hosted_record_kv_success();
        assert_eq!(hosted_kv_unavailable_count(), 0);
    }

    // ======================================================================
    // Phase 3: Expert KV counter logic (mock KV)
    // ======================================================================

    // Test 5: first request allowed, counter starts at 1
    #[tokio::test]
    async fn expert_kv_counter_first_request_allowed() {
        let kv = MockKv::new();
        let (allowed, count, limit) = check_kv_counter(&kv, "test:key:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].value, "1");
        assert_eq!(puts[0].ttl_secs, 7200);
    }

    // Test 6: request denied at limit
    #[tokio::test]
    async fn expert_kv_counter_denied_at_limit() {
        let kv = MockKv::new().with_entry("test:key:0", "100");
        let (allowed, count, limit) = check_kv_counter(&kv, "test:key:0", 100, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 100);
        assert_eq!(limit, 100);
    }

    // Test 7: request denied above limit
    #[tokio::test]
    async fn expert_kv_counter_denied_above_limit() {
        let kv = MockKv::new().with_entry("test:key:0", "150");
        let (allowed, count, limit) = check_kv_counter(&kv, "test:key:0", 100, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 150);
        assert_eq!(limit, 100);
    }

    // Test 8: KV read failure denies (fail-closed)
    #[tokio::test]
    async fn expert_kv_counter_read_failure_denies() {
        let kv = MockKv::new().with_get_error("KV unavailable");
        let (allowed, count, limit) = check_kv_counter(&kv, "test:key:0", 100, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 100);
    }

    // Test 9: KV write failure still allows
    #[tokio::test]
    async fn expert_kv_counter_write_failure_still_allows() {
        let kv = MockKv::new().with_put_error("KV write failed");
        let (allowed, count, limit) = check_kv_counter(&kv, "test:key:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
        assert!(kv.puts().is_empty());
    }

    // Test 10: unparseable counter treated as zero
    #[tokio::test]
    async fn expert_kv_counter_unparseable_treated_as_zero() {
        let kv = MockKv::new().with_entry("test:key:0", "not_a_number");
        let (allowed, count, limit) = check_kv_counter(&kv, "test:key:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
    }

    // Extra: counter increments correctly across successive calls
    #[tokio::test]
    async fn expert_kv_counter_increments_across_calls() {
        let kv = MockKv::new();
        let (allowed, count, _) = check_kv_counter(&kv, "test:inc:0", 5, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);

        let (allowed, count, _) = check_kv_counter(&kv, "test:inc:0", 5, 7200).await;
        assert!(allowed);
        assert_eq!(count, 2);

        let _ = check_kv_counter(&kv, "test:inc:0", 5, 7200).await; // 3
        let _ = check_kv_counter(&kv, "test:inc:0", 5, 7200).await; // 4
        let (allowed, count, _) = check_kv_counter(&kv, "test:inc:0", 5, 7200).await;
        assert!(allowed);
        assert_eq!(count, 5);

        let (allowed, count, _) = check_kv_counter(&kv, "test:inc:0", 5, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 5);
    }

    // Extra: limit of 0 denies everything
    #[tokio::test]
    async fn expert_kv_counter_zero_limit_denies_all() {
        let kv = MockKv::new();
        let (allowed, _, limit) = check_kv_counter(&kv, "test:zero:0", 0, 7200).await;
        assert!(!allowed);
        assert_eq!(limit, 0);
    }

    // Extra: limit of 1 allows exactly one request
    #[tokio::test]
    async fn expert_kv_counter_limit_one() {
        let kv = MockKv::new();
        let (allowed, count, _) = check_kv_counter(&kv, "test:one:0", 1, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        let (allowed, count, _) = check_kv_counter(&kv, "test:one:0", 1, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 1);
    }

    // Extra: TTL is correctly passed through
    #[tokio::test]
    async fn expert_kv_counter_ttl_propagated() {
        let kv = MockKv::new();
        let _ = check_kv_counter(&kv, "test:ttl:0", 100, 3600).await;
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].ttl_secs, 3600);
    }

    // ======================================================================
    // Phase 3b: Expert tier lookup (mock KV, serial for static cache)
    // ======================================================================

    // Test 21: tier lookup returns custom limit
    #[tokio::test]
    #[serial]
    async fn expert_tier_lookup_returns_custom_limit() {
        clear_expert_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_1", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":2000}}"#,
            );
        let limit = get_customer_limit(&kv, "client_1", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 2000);
    }

    // Test 22: missing client falls back to default
    #[tokio::test]
    #[serial]
    async fn expert_tier_lookup_missing_client_uses_default() {
        clear_expert_tier_cache();
        let kv = MockKv::new();
        let limit = get_customer_limit(&kv, "unknown", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    // Test 23: missing tier falls back to default
    #[tokio::test]
    #[serial]
    async fn expert_tier_lookup_missing_tier_uses_default() {
        clear_expert_tier_cache();
        let kv = MockKv::new().with_entry("rate_limits/clients/client_2", "nonexistent_tier");
        let limit = get_customer_limit(&kv, "client_2", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    // Test 24: endpoint not in tier limits falls back to default
    #[tokio::test]
    #[serial]
    async fn expert_tier_lookup_endpoint_not_in_tier() {
        clear_expert_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_3", "basic")
            .with_entry("rate_limits/tiers/basic", r#"{"limits":{"verify":300}}"#);
        let limit = get_customer_limit(&kv, "client_3", "challenge", 50, 1_700_000_000).await;
        assert_eq!(limit, 50);
    }

    // Test 25: KV failure for client lookup falls back to default
    #[tokio::test]
    #[serial]
    async fn expert_tier_lookup_kv_failure_uses_default() {
        clear_expert_tier_cache();
        let kv = MockKv::new()
            .with_get_error("KV down")
            .with_persistent_errors();
        let limit = get_customer_limit(&kv, "client_x", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    // Test 26: tier cache returns cached value within TTL
    #[tokio::test]
    #[serial]
    async fn expert_tier_cache_returns_cached_value() {
        clear_expert_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/cached_client", "gold")
            .with_entry("rate_limits/tiers/gold", r#"{"limits":{"challenge":5000}}"#);
        let limit = get_customer_limit(&kv, "cached_client", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 5000);

        // Second call 30s later: should use cache
        let kv2 = MockKv::new();
        let limit =
            get_customer_limit(&kv2, "cached_client", "challenge", 100, 1_700_000_030).await;
        assert_eq!(limit, 5000);
    }

    // Test 27: tier cache expires after 60s
    #[tokio::test]
    #[serial]
    async fn expert_tier_cache_expires_after_60s() {
        clear_expert_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/expiring", "silver")
            .with_entry(
                "rate_limits/tiers/silver",
                r#"{"limits":{"challenge":3000}}"#,
            );
        let limit = get_customer_limit(&kv, "expiring", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 3000);

        // 61s later: stale, KV empty -> default
        let kv2 = MockKv::new();
        let limit = get_customer_limit(&kv2, "expiring", "challenge", 100, 1_700_000_061).await;
        assert_eq!(limit, 100);
    }

    // Test 28: different endpoints from same tier
    #[tokio::test]
    #[serial]
    async fn expert_tier_lookup_different_endpoints() {
        clear_expert_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/multi_ep", "enterprise")
            .with_entry(
                "rate_limits/tiers/enterprise",
                r#"{"limits":{"challenge":10000,"verify":5000}}"#,
            );
        let challenge = get_customer_limit(&kv, "multi_ep", "challenge", 100, 1_700_000_000).await;
        assert_eq!(challenge, 10000);

        // Cache should serve different endpoint
        let kv2 = MockKv::new();
        let verify = get_customer_limit(&kv2, "multi_ep", "verify", 100, 1_700_000_010).await;
        assert_eq!(verify, 5000);
    }

    // ======================================================================
    // Phase 4: End-to-end flows (expert module)
    // ======================================================================

    // Test 11: check_quota allows first request with default limit
    #[tokio::test]
    #[serial]
    async fn expert_check_quota_allows_first_request() {
        clear_expert_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let result = check_quota(
            &rate_kv,
            &config_kv,
            "client_a",
            "challenge",
            100,
            1_700_000_000,
        )
        .await;
        assert!(result.allowed);
        assert_eq!(result.current_count, 1);
        assert_eq!(result.limit, 100);
        assert!(result.retry_after_secs <= 3600);
    }

    // Test 12: check_quota uses custom tier limit
    #[tokio::test]
    #[serial]
    async fn expert_check_quota_uses_tier_limit() {
        clear_expert_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/vip", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":9999}}"#,
            );
        let result =
            check_quota(&rate_kv, &config_kv, "vip", "challenge", 100, 1_700_000_000).await;
        assert!(result.allowed);
        assert_eq!(result.limit, 9999);
    }

    // Test 13: check_quota denied at limit
    #[tokio::test]
    #[serial]
    async fn expert_check_quota_denied_at_limit() {
        clear_expert_tier_cache();
        let hour_ts = (1_700_000_000u64 / 3600) * 3600;
        let key = format!("quota:client_b:challenge:{}", hour_ts);
        let rate_kv = MockKv::new().with_entry(&key, "50");
        let config_kv = MockKv::new();
        let result = check_quota(
            &rate_kv,
            &config_kv,
            "client_b",
            "challenge",
            50,
            1_700_000_000,
        )
        .await;
        assert!(!result.allowed);
        assert_eq!(result.current_count, 50);
    }

    // Test 14: check_per_ip_limit allows first request
    #[tokio::test]
    async fn expert_check_per_ip_limit_allows_first() {
        let kv = MockKv::new();
        let result = check_per_ip_limit(&kv, "192.168.1.1", 60, 1_700_000_000).await;
        assert!(result.allowed);
        assert_eq!(result.current_count, 1);
        assert_eq!(result.limit, 60);
    }

    // Test 15: check_per_ip_limit denied at limit
    #[tokio::test]
    async fn expert_check_per_ip_limit_denied_at_limit() {
        let hour_ts = (1_700_000_000u64 / 3600) * 3600;
        let key = format!("short_code_enum:10.0.0.1:{}", hour_ts);
        let kv = MockKv::new().with_entry(&key, "60");
        let result = check_per_ip_limit(&kv, "10.0.0.1", 60, 1_700_000_000).await;
        assert!(!result.allowed);
        assert_eq!(result.current_count, 60);
    }

    // Test 16: check_per_ip_limit KV failure fail-closed
    #[tokio::test]
    async fn expert_check_per_ip_limit_kv_failure_denies() {
        let kv = MockKv::new().with_get_error("boom");
        let result = check_per_ip_limit(&kv, "10.0.0.2", 60, 1_700_000_000).await;
        assert!(!result.allowed);
        assert_eq!(result.current_count, 0);
    }

    // Test 29: check_quota constructs correct KV key
    #[tokio::test]
    #[serial]
    async fn expert_check_quota_correct_kv_key() {
        clear_expert_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let _ = check_quota(&rate_kv, &config_kv, "c1", "verify", 100, now).await;
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, format!("quota:c1:verify:{}", hour_ts));
    }

    // Test 30: check_per_ip_limit constructs correct KV key
    #[tokio::test]
    async fn expert_check_per_ip_limit_correct_kv_key() {
        let kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let _ = check_per_ip_limit(&kv, "1.2.3.4", 100, now).await;
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, format!("short_code_enum:1.2.3.4:{}", hour_ts));
    }

    // Extra: retry_after correctly computed
    #[tokio::test]
    #[serial]
    async fn expert_check_quota_retry_after_computation() {
        clear_expert_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let expected_retry = hour_ts + 3600 - now;
        let result = check_quota(&rate_kv, &config_kv, "c1", "challenge", 100, now).await;
        assert_eq!(result.retry_after_secs, expected_retry as u32);
    }

    // Extra: different clients use different keys
    #[tokio::test]
    #[serial]
    async fn expert_check_quota_isolates_clients() {
        clear_expert_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let r1 = check_quota(&rate_kv, &config_kv, "alice", "challenge", 100, now).await;
        let r2 = check_quota(&rate_kv, &config_kv, "bob", "challenge", 100, now).await;
        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 2);
        assert_ne!(puts[0].key, puts[1].key);
    }

    // ======================================================================
    // Phase 3c: Hosted KV counter with in-memory cache (serial)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_first_request_allowed() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let now_ms = 1_700_000_000_000.0;
        let (allowed, count, limit, kv_unavail) =
            hosted_check_kv_counter(&kv, "hosted:test:key:0", 100, 7200, now_ms).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
        assert!(!kv_unavail);
        assert_eq!(kv.puts().len(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_denied_at_limit() {
        clear_hosted_counter_cache();
        let kv = MockKv::new().with_entry("hosted:test:key:0", "100");
        let now_ms = 1_700_000_000_000.0;
        let (allowed, count, limit, _) =
            hosted_check_kv_counter(&kv, "hosted:test:key:0", 100, 7200, now_ms).await;
        assert!(!allowed);
        assert_eq!(count, 101); // read 100, incremented to 101, which >= limit
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_read_failure_fail_closed() {
        clear_hosted_counter_cache();
        hosted_reset_kv_failure_count();
        let kv = MockKv::new().with_get_error("KV unavailable");
        let now_ms = 1_700_000_000_000.0;
        let (allowed, count, limit, kv_unavail) =
            hosted_check_kv_counter(&kv, "hosted:test:key:0", 100, 7200, now_ms).await;
        assert!(!allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 100);
        assert!(kv_unavail);
        assert_eq!(hosted_kv_unavailable_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_in_memory_cache_avoids_kv_read() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let now_ms = 1_700_000_000_000.0;

        // First call: seeds from KV
        let (allowed, count, _, _) =
            hosted_check_kv_counter(&kv, "hosted:cached:key:0", 100, 7200, now_ms).await;
        assert!(allowed);
        assert_eq!(count, 1);
        let puts_after_first = kv.puts().len();

        // Second call 5s later: in-memory cache hit, no KV read
        let now_ms_2 = now_ms + 5000.0;
        let (allowed, count, _, _) =
            hosted_check_kv_counter(&kv, "hosted:cached:key:0", 100, 7200, now_ms_2).await;
        assert!(allowed);
        assert_eq!(count, 2);

        // No additional KV puts (not at sync threshold)
        assert_eq!(kv.puts().len(), puts_after_first);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_cache_expires_after_sync_interval() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed cache
        let _ = hosted_check_kv_counter(&kv, "hosted:stale:key:0", 100, 7200, now_ms).await;

        // 11s later: stale
        let stale_ms = now_ms + 11_000.0;
        let (allowed, count, _, _) =
            hosted_check_kv_counter(&kv, "hosted:stale:key:0", 100, 7200, stale_ms).await;
        assert!(allowed);
        // Re-seeded from KV (which has "1"), so new_count = 2
        assert_eq!(count, 2);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_syncs_every_n_hits() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed
        let _ = hosted_check_kv_counter(&kv, "hosted:sync:key:0", 1000, 7200, now_ms).await;
        let initial_puts = kv.puts().len();

        // 9 in-memory increments (count goes 2..10)
        for i in 1..10 {
            let t = now_ms + (i as f64 * 100.0);
            let _ = hosted_check_kv_counter(&kv, "hosted:sync:key:0", 1000, 7200, t).await;
        }

        // 10th in-memory increment (count=11, kv_count=1, delta=10 >= COUNTER_SYNC_INTERVAL_HITS)
        let t = now_ms + 1000.0;
        let _ = hosted_check_kv_counter(&kv, "hosted:sync:key:0", 1000, 7200, t).await;

        let final_puts = kv.puts().len();
        assert!(
            final_puts > initial_puts,
            "Should have synced to KV after {} in-memory increments (initial puts: {}, final: {})",
            COUNTER_SYNC_INTERVAL_HITS,
            initial_puts,
            final_puts,
        );
    }

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_zero_limit_denies() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let now_ms = 1_700_000_000_000.0;
        let (allowed, _, limit, _) =
            hosted_check_kv_counter(&kv, "hosted:zero:key:0", 0, 7200, now_ms).await;
        assert!(!allowed);
        assert_eq!(limit, 0);
    }

    // ======================================================================
    // Phase 3d: Hosted tier lookup (serial for static cache)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_tier_lookup_returns_custom_limit() {
        clear_hosted_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_client_1", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":2000}}"#,
            );
        let limit =
            hosted_get_customer_limit(&kv, "h_client_1", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 2000);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_tier_lookup_missing_client_uses_default() {
        clear_hosted_tier_cache();
        let kv = MockKv::new();
        let limit =
            hosted_get_customer_limit(&kv, "h_unknown", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_tier_cache_returns_cached_value() {
        clear_hosted_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_cached", "gold")
            .with_entry("rate_limits/tiers/gold", r#"{"limits":{"challenge":5000}}"#);
        let limit =
            hosted_get_customer_limit(&kv, "h_cached", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 5000);

        let kv2 = MockKv::new();
        let limit =
            hosted_get_customer_limit(&kv2, "h_cached", "challenge", 100, 1_700_000_030).await;
        assert_eq!(limit, 5000);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_tier_cache_expires_after_60s() {
        clear_hosted_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_expiring", "silver")
            .with_entry(
                "rate_limits/tiers/silver",
                r#"{"limits":{"challenge":3000}}"#,
            );
        let _ = hosted_get_customer_limit(&kv, "h_expiring", "challenge", 100, 1_700_000_000).await;

        let kv2 = MockKv::new();
        let limit =
            hosted_get_customer_limit(&kv2, "h_expiring", "challenge", 100, 1_700_000_061).await;
        assert_eq!(limit, 100);
    }

    // ======================================================================
    // Phase 4: End-to-end hosted flows
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_check_quota_allows_first_request() {
        clear_hosted_tier_cache();
        clear_hosted_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let result = hosted_check_quota(
            &rate_kv,
            &config_kv,
            "h_client_a",
            "challenge",
            100,
            1_700_000_000,
            1_700_000_000_000.0,
        )
        .await;
        assert!(result.allowed);
        assert_eq!(result.current_count, 1);
        assert_eq!(result.limit, 100);
        assert!(!result.kv_unavailable);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_check_quota_uses_tier_limit() {
        clear_hosted_tier_cache();
        clear_hosted_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/h_vip", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":9999}}"#,
            );
        let result = hosted_check_quota(
            &rate_kv,
            &config_kv,
            "h_vip",
            "challenge",
            100,
            1_700_000_000,
            1_700_000_000_000.0,
        )
        .await;
        assert!(result.allowed);
        assert_eq!(result.limit, 9999);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_check_quota_kv_failure_signals_unavailable() {
        clear_hosted_tier_cache();
        clear_hosted_counter_cache();
        hosted_reset_kv_failure_count();
        let rate_kv = MockKv::new()
            .with_get_error("KV is down")
            .with_persistent_errors();
        let config_kv = MockKv::new();
        let result = hosted_check_quota(
            &rate_kv,
            &config_kv,
            "h_client_c",
            "challenge",
            100,
            1_700_000_000,
            1_700_000_000_000.0,
        )
        .await;
        assert!(!result.allowed);
        assert!(result.kv_unavailable);
    }

    #[tokio::test]
    #[serial]
    async fn hosted_check_quota_correct_kv_key() {
        clear_hosted_tier_cache();
        clear_hosted_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let _ = hosted_check_quota(
            &rate_kv,
            &config_kv,
            "hc1",
            "verify",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, format!("quota:hc1:verify:{}", hour_ts));
    }

    // ======================================================================
    // RateLimitKvError Display coverage
    // ======================================================================

    #[test]
    fn rate_limit_kv_error_display() {
        let err = RateLimitKvError("something broke".to_string());
        let msg = format!("{err}");
        assert_eq!(msg, "something broke");
    }

    #[test]
    fn rate_limit_kv_error_debug() {
        let err = RateLimitKvError("oops".to_string());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("oops"));
    }

    // ======================================================================
    // MockKv Default trait coverage
    // ======================================================================

    #[tokio::test]
    async fn mock_kv_default_trait() {
        let kv: MockKv = Default::default();
        // Default-constructed mock has no data, no errors
        let result = kv.get_text("nonexistent").await;
        assert!(result.is_ok());
        assert!(result.ok().flatten().is_none());
    }

    // ======================================================================
    // Hosted in-memory cache: denial via in-memory path (line 512-513)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_in_memory_cache_denies_at_limit() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed with count near limit (limit=5)
        // First call from KV: count becomes 1
        let (allowed, count, _, _) =
            hosted_check_kv_counter(&kv, "hosted:deny:inmem:0", 5, 7200, now_ms).await;
        assert!(allowed);
        assert_eq!(count, 1);

        // Rapidly increment in-memory to hit limit (counts 2, 3, 4, 5)
        for i in 1..=4 {
            let t = now_ms + (i as f64 * 100.0);
            let _ = hosted_check_kv_counter(&kv, "hosted:deny:inmem:0", 5, 7200, t).await;
        }

        // Next in-memory hit: count=6 >= limit=5, should be denied
        let t = now_ms + 500.0;
        let (allowed, count, limit, _) =
            hosted_check_kv_counter(&kv, "hosted:deny:inmem:0", 5, 7200, t).await;
        assert!(!allowed, "should deny when in-memory count reaches limit");
        assert!(count >= 5, "count should be at or above limit, got {count}");
        assert_eq!(limit, 5);
    }

    // ======================================================================
    // Hosted tier cache: missing tier JSON returns default (line 424)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_tier_lookup_missing_tier_json_uses_default() {
        clear_hosted_tier_cache();
        // Client maps to a tier, but the tier JSON is missing
        let kv =
            MockKv::new().with_entry("rate_limits/clients/h_client_missing_tier", "ghost_tier");
        let limit = hosted_get_customer_limit(
            &kv,
            "h_client_missing_tier",
            "challenge",
            200,
            1_700_000_000,
        )
        .await;
        assert_eq!(limit, 200);
    }

    // ======================================================================
    // Hosted tier cache: KV failure on client lookup (line 412)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_tier_lookup_kv_failure_uses_default() {
        clear_hosted_tier_cache();
        let kv = MockKv::new()
            .with_get_error("KV down")
            .with_persistent_errors();
        let limit =
            hosted_get_customer_limit(&kv, "h_client_broken", "challenge", 150, 1_700_000_000)
                .await;
        assert_eq!(limit, 150);
    }

    // ======================================================================
    // Hosted tier cache: endpoint not in tier (line 424 variant)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_tier_lookup_endpoint_not_in_tier() {
        clear_hosted_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_client_partial", "basic")
            .with_entry("rate_limits/tiers/basic", r#"{"limits":{"verify":300}}"#);
        let limit =
            hosted_get_customer_limit(&kv, "h_client_partial", "challenge", 50, 1_700_000_000)
                .await;
        assert_eq!(limit, 50);
    }

    // ======================================================================
    // Hosted cache eviction under pressure
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn hosted_kv_counter_cache_eviction_under_pressure() {
        clear_hosted_counter_cache();
        let kv = MockKv::new();
        let base_ms = 1_700_000_000_000.0;

        // Fill the cache to COUNTER_CACHE_MAX_ENTRIES by calling with
        // unique keys. Each call seeds one entry.
        for i in 0..COUNTER_CACHE_MAX_ENTRIES {
            let key = format!("hosted:evict:key:{i}");
            // Stagger timestamps so older entries are evictable
            let t = base_ms + (i as f64 * 100.0);
            let (allowed, _, _, _) = hosted_check_kv_counter(&kv, &key, 10000, 7200, t).await;
            assert!(allowed);
        }

        // Cache is now full. The next call with a new key (cache miss,
        // stale enough to bypass in-memory path) should trigger eviction.
        let overflow_key = "hosted:evict:overflow";
        let late_ms = base_ms + (COUNTER_CACHE_MAX_ENTRIES as f64 * 100.0) + 15_000.0;
        let (allowed, count, _, _) =
            hosted_check_kv_counter(&kv, overflow_key, 10000, 7200, late_ms).await;
        assert!(allowed);
        assert_eq!(count, 1);

        // Verify cache did not grow unbounded. It should have evicted.
        let cache_size = hosted_counter_cache().read().map(|c| c.len()).unwrap_or(0);
        assert!(
            cache_size <= COUNTER_CACHE_MAX_ENTRIES,
            "cache should not exceed max entries after eviction, got {cache_size}"
        );
    }
}
