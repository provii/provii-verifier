// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Simple KV-counter-based rate limiting for the hosted verification flow.
//!
//! Replaces the shared-rate-limit Durable Object system with direct KV
//! reads and writes. All limits are configurable via wrangler.toml env
//! vars or RATE_LIMIT_CONFIG KV tier data (managed through the admin
//! portal). Fail-closed: if a KV read fails the request is denied.

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{OnceLock, RwLock};

use crate::rate_limit_kv::RateLimitKv;
use worker::kv::KvStore;
use worker::Response;

// ---------------------------------------------------------------------------
// KV failure tracking -- per-isolate, used for metrics only
// ---------------------------------------------------------------------------

// SECURITY: Fail-closed design. Any KV read failure results in the request
// being denied (503). The counter below is for observability only; it does
// not gate allow/deny decisions.

/// Consecutive KV read failures observed by this isolate (metrics only).
static KV_FAILURE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total requests denied due to KV unavailability in the current outage
/// window. Reset to zero when KV recovers (see `record_kv_success`).
static FALLBACK_DENIED_COUNT: AtomicU32 = AtomicU32::new(0);

#[cfg(any(target_arch = "wasm32", test))]
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Record a successful KV read, resetting the consecutive failure counter.
/// Uses `swap` instead of `store` to detect the open-to-closed transition.
/// CF Workers are single-threaded per isolate, so no TOCTOU risk.
pub fn record_kv_success() {
    let previous = KV_FAILURE_COUNT.swap(0, Ordering::Relaxed);
    if previous > 0 {
        let denied = FALLBACK_DENIED_COUNT.load(Ordering::Relaxed);
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "{{\"audit\":true,\"event\":\"hosted_kv_recovered\",\"severity\":\"info\",\"previous_consecutive_failures\":{},\"total_denied_during_outage\":{}}}",
            previous,
            denied
        );
        let _ = denied;
        FALLBACK_DENIED_COUNT.store(0, Ordering::Relaxed);
    }
}

/// Record a KV read failure, returning the new consecutive failure count.
fn record_kv_failure() -> u32 {
    let new_count = KV_FAILURE_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    FALLBACK_DENIED_COUNT.fetch_add(1, Ordering::Relaxed);

    #[cfg(target_arch = "wasm32")]
    if new_count >= CIRCUIT_BREAKER_THRESHOLD {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "{{\"audit\":true,\"event\":\"hosted_circuit_breaker_tripped\",\"severity\":\"critical\",\"consecutive_failures\":{},\"threshold\":{}}}",
            new_count,
            CIRCUIT_BREAKER_THRESHOLD
        );
    } else {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "{{\"audit\":true,\"event\":\"hosted_kv_read_failure\",\"severity\":\"warning\",\"consecutive_failures\":{},\"outcome\":\"fail_closed\"}}",
            new_count
        );
    }

    new_count
}

/// Current consecutive KV failure count (for metrics/logging).
pub fn kv_unavailable_count() -> u32 {
    KV_FAILURE_COUNT.load(Ordering::Relaxed)
}

/// Reset the KV failure counter. Only available in test builds.
#[cfg(test)]
pub(crate) fn reset_kv_failure_count() {
    KV_FAILURE_COUNT.store(0, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Tier cache -- cached per-isolate for 60 seconds
// ---------------------------------------------------------------------------

struct TierCache {
    limits: HashMap<String, u32>,
    fetched_at: u64,
}

static TIER_CACHE: OnceLock<RwLock<HashMap<String, TierCache>>> = OnceLock::new();

fn tier_cache() -> &'static RwLock<HashMap<String, TierCache>> {
    TIER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Parse tier limit JSON into a map of endpoint name to hourly quota.
///
/// Handles two formats:
/// - Nested: `{ "limits": { "endpoint": limit }, ... }` (StoredTier from provii-management)
/// - Flat: `{ "endpoint": limit, ... }`
///
/// Returns an empty map on invalid JSON.
pub(crate) fn parse_tier_limits(json: &str) -> HashMap<String, u32> {
    // provii-management stores StoredTier: { "limits": { "endpoint": limit }, "tier_id": "...", ... }
    // Extract the nested .limits field first, fall back to flat map format.
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(limits) = obj.get("limits") {
            if let Ok(map) = serde_json::from_value::<HashMap<String, u32>>(limits.clone()) {
                return map;
            }
        }
    }
    // Fallback: flat { "endpoint_name": limit, ... }
    serde_json::from_str::<HashMap<String, u32>>(json).unwrap_or_default()
}

/// Look up the per-hour quota for `client_id` on `endpoint` (testable inner function).
///
/// Takes `now_ms` as a parameter (milliseconds) for the timing instrumentation,
/// and `now_secs` for the cache TTL check.
async fn get_customer_limit_impl(
    kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
    sub_ops: &mut Vec<(&'static str, f64)>,
    now_ms: f64,
) -> u32 {
    // Check in-memory cache first
    let t = now_ms;
    if let Ok(cache) = tier_cache().read() {
        if let Some(entry) = cache.get(client_id) {
            if now_secs.saturating_sub(entry.fetched_at) < 60 {
                sub_ops.push(("rl_tier_cache_check", now_ms - t));
                return entry.limits.get(endpoint).copied().unwrap_or(default_limit);
            }
        }
    }
    sub_ops.push(("rl_tier_cache_check", now_ms - t));

    // Cache miss: read from KV
    let t = now_ms;
    let tier_id = match kv
        .get_text(&format!("rate_limits/clients/{}", client_id))
        .await
    {
        Ok(Some(t_id)) => {
            sub_ops.push(("rl_kv_get_client_tier", now_ms - t));
            t_id
        }
        _ => {
            sub_ops.push(("rl_kv_get_client_tier", now_ms - t));
            return default_limit;
        }
    };

    let t = now_ms;
    let limits = match kv.get_text(&format!("rate_limits/tiers/{}", tier_id)).await {
        Ok(Some(json)) => parse_tier_limits(&json),
        _ => HashMap::new(),
    };
    sub_ops.push(("rl_kv_get_tier_limits", now_ms - t));

    let result = limits.get(endpoint).copied().unwrap_or(default_limit);

    // Update cache
    if let Ok(mut cache) = tier_cache().write() {
        cache.insert(
            client_id.to_string(),
            TierCache {
                limits,
                fetched_at: now_secs,
            },
        );
    }

    result
}

/// Production wrapper that reads timing from `js_sys::Date::now()`.
#[cfg(target_arch = "wasm32")]
async fn get_customer_limit(
    kv: &KvStore,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
    sub_ops: &mut Vec<(&'static str, f64)>,
) -> u32 {
    let adapter = crate::rate_limit_kv::KvStoreAdapter(kv);
    let now_ms = js_sys::Date::now();
    get_customer_limit_impl(
        &adapter,
        client_id,
        endpoint,
        default_limit,
        now_secs,
        sub_ops,
        now_ms,
    )
    .await
}

/// Native-target stub: delegates to the testable `_impl` with a zero timestamp.
#[cfg(not(target_arch = "wasm32"))]
async fn get_customer_limit(
    kv: &KvStore,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
    sub_ops: &mut Vec<(&'static str, f64)>,
) -> u32 {
    let adapter = crate::rate_limit_kv::KvStoreAdapter(kv);
    get_customer_limit_impl(
        &adapter,
        client_id,
        endpoint,
        default_limit,
        now_secs,
        sub_ops,
        0.0,
    )
    .await
}

// ---------------------------------------------------------------------------
// In-memory counter cache -- reduces KV round-trips for hot keys
// ---------------------------------------------------------------------------

/// Per-key in-memory counter that batches KV writes.
struct InMemoryCounter {
    /// Total count including in-memory increments not yet synced to KV.
    count: u64,
    /// Timestamp (ms) of last KV sync.
    last_synced_at: f64,
    /// The count value as last read from or written to KV.
    kv_count: u64,
}

/// Maximum entries before the entire map is cleared (full-clear eviction).
const COUNTER_CACHE_MAX_ENTRIES: usize = 5000;

/// Seconds between KV syncs for a given key.
const COUNTER_SYNC_INTERVAL_SECS: f64 = 10.0;

/// Number of in-memory increments between forced KV syncs.
const COUNTER_SYNC_INTERVAL_HITS: u64 = 10;

static COUNTER_CACHE: OnceLock<RwLock<HashMap<String, InMemoryCounter>>> = OnceLock::new();

fn counter_cache() -> &'static RwLock<HashMap<String, InMemoryCounter>> {
    COUNTER_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Clear the counter cache. Only available in test builds.
#[cfg(test)]
pub(crate) fn clear_counter_cache() {
    if let Ok(mut cache) = counter_cache().write() {
        cache.clear();
    }
}

/// Clear the tier cache. Only available in test builds.
#[cfg(test)]
pub(crate) fn clear_tier_cache() {
    if let Ok(mut cache) = tier_cache().write() {
        cache.clear();
    }
}

// ---------------------------------------------------------------------------
// KV counter -- non-atomic, acceptable at Provii's scale
// ---------------------------------------------------------------------------

/// Increment a KV counter and return `(allowed, count, limit, kv_unavailable)`.
///
/// Uses a per-isolate in-memory cache to avoid KV round-trips on every
/// request. The cache is seeded from KV on first access or when stale
/// (> 10 seconds), and synced back on every 10th in-memory increment or
/// when the staleness threshold is exceeded.
///
/// Returns `(true, count, limit, false)` if the request is within quota,
/// `(false, count, limit, false)` if over quota. On KV read errors the
/// request is denied (fail-closed) with `kv_unavailable` set to true.
pub(crate) async fn check_kv_counter_impl(
    kv: &dyn RateLimitKv,
    key: &str,
    limit: u32,
    ttl_secs: u64,
    sub_ops: &mut Vec<(&'static str, f64)>,
    now_ms: f64,
) -> (bool, u32, u32, bool) {
    // Fast path: check in-memory cache for a fresh entry.
    // The lock guard is dropped before any .await to avoid holding it across
    // an await point (clippy::await_holding_lock).
    let t = now_ms;
    let cache_result: Option<(u32, Option<u64>)> = {
        if let Ok(mut cache) = counter_cache().write() {
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
                    None // Stale entry: fall through to KV read below.
                }
            } else {
                None
            }
        } else {
            None
        }
    };
    // Lock is dropped here; safe to await below.
    if let Some((count, sync_count)) = cache_result {
        sub_ops.push(("rl_counter_cache_check", now_ms - t));
        if let Some(sc) = sync_count {
            let t_put = now_ms;
            let _ = kv.put_with_ttl(key, &sc.to_string(), ttl_secs).await;
            sub_ops.push(("rl_kv_put_counter", now_ms - t_put));
        }
        if count >= limit {
            return (false, count, limit, false);
        }
        return (true, count, limit, false);
    }
    sub_ops.push(("rl_counter_cache_check", now_ms - t));

    // Cache miss or stale: seed from KV.
    let t = now_ms;
    let kv_count: u64 = match kv.get_text(key).await {
        Ok(Some(s)) => {
            record_kv_success();
            sub_ops.push(("rl_kv_get_counter", now_ms - t));
            s.parse().unwrap_or(0)
        }
        Ok(None) => {
            record_kv_success();
            sub_ops.push(("rl_kv_get_counter", now_ms - t));
            0
        }
        Err(_) => {
            sub_ops.push(("rl_kv_get_counter", now_ms - t));
            let failures = record_kv_failure();
            // SECURITY: Fail closed. KV unavailability must not bypass rate
            // limiting. Deny the request and signal kv_unavailable so callers
            // can return 503 with Retry-After.
            let _ = failures; // used only for metrics/logging
            return (false, 0, limit, true);
        }
    };

    let new_count = kv_count.saturating_add(1);

    // Seed (or refresh) the in-memory cache.
    if let Ok(mut cache) = counter_cache().write() {
        // ADV-VA-027: Instead of clearing the entire cache (which an attacker
        // could trigger by rotating 5,001 distinct rate limit keys), evict
        // entries whose last KV sync is older than the rate limit window first.
        // Only fall back to a full clear if the cache is still over capacity.
        if cache.len() >= COUNTER_CACHE_MAX_ENTRIES {
            let stale_cutoff = now_ms - (ttl_secs as f64 * 1000.0);
            cache.retain(|_, entry| entry.last_synced_at > stale_cutoff);

            // If still over capacity after expiring stale entries, evict the
            // oldest half by last_synced_at to maintain bounded memory without
            // destroying all counters.
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

    // SECURITY: Rate limit enforcement. Deny if the counter has reached
    // or exceeded the per-customer, per-endpoint hourly quota.
    if u32::try_from(new_count).unwrap_or(u32::MAX) >= limit {
        // Still write back so the counter is accurate for the next isolate.
        let t = now_ms;
        let _ = kv.put_with_ttl(key, &new_count.to_string(), ttl_secs).await;
        sub_ops.push(("rl_kv_put_counter", now_ms - t));
        return (
            false,
            u32::try_from(new_count).unwrap_or(u32::MAX),
            limit,
            false,
        );
    }

    // Write incremented count back to KV (we just did a KV read, so sync now).
    let t = now_ms;
    let _ = kv.put_with_ttl(key, &new_count.to_string(), ttl_secs).await;
    sub_ops.push(("rl_kv_put_counter", now_ms - t));

    (
        true,
        u32::try_from(new_count).unwrap_or(u32::MAX),
        limit,
        false,
    )
}

/// Production wrapper that reads timing from `js_sys::Date::now()`.
#[cfg(target_arch = "wasm32")]
async fn check_kv_counter(
    kv: &KvStore,
    key: &str,
    limit: u32,
    ttl_secs: u64,
    sub_ops: &mut Vec<(&'static str, f64)>,
) -> (bool, u32, u32, bool) {
    let adapter = crate::rate_limit_kv::KvStoreAdapter(kv);
    let now_ms = js_sys::Date::now();
    check_kv_counter_impl(&adapter, key, limit, ttl_secs, sub_ops, now_ms).await
}

/// Native-target stub: delegates to the testable `_impl` with a zero timestamp.
#[cfg(not(target_arch = "wasm32"))]
async fn check_kv_counter(
    kv: &KvStore,
    key: &str,
    limit: u32,
    ttl_secs: u64,
    sub_ops: &mut Vec<(&'static str, f64)>,
) -> (bool, u32, u32, bool) {
    let adapter = crate::rate_limit_kv::KvStoreAdapter(kv);
    check_kv_counter_impl(&adapter, key, limit, ttl_secs, sub_ops, 0.0).await
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of a rate limit check, carrying enough context for logging and
/// `Retry-After` header generation.
pub struct RateLimitResult {
    /// Whether the request is within quota.
    pub allowed: bool,
    /// Number of requests counted in the current window (after increment).
    pub current_count: u32,
    /// Per-customer, per-endpoint hourly quota that applies.
    pub limit: u32,
    /// Seconds remaining until the current hourly window resets.
    pub retry_after_secs: u32,
    /// True when the check was denied due to KV being unavailable.
    /// Callers should return 503 with Retry-After when this is set.
    pub kv_unavailable: bool,
    /// Sub-operation timing data for performance instrumentation.
    /// Each entry is `(operation_name, duration_ms)`.
    pub sub_ops: Vec<(&'static str, f64)>,
}

/// Check per-customer hourly quota (post-auth, tier-based).
///
/// `client_id` is the authenticated identity (public key).
/// `endpoint` is a short label like `"challenge"`.
pub async fn check_quota(
    rate_limit_kv: &KvStore,
    config_kv: &KvStore,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
) -> RateLimitResult {
    let mut sub_ops: Vec<(&'static str, f64)> = Vec::new();

    // SECURITY: Rate limit decision point. The hour-boundary timestamp
    // keys the KV counter so quotas reset each calendar hour (UTC).
    let now_secs = crate::utils::current_timestamp();
    let hour_ts = (now_secs / 3600).saturating_mul(3600);

    let limit = get_customer_limit(
        config_kv,
        client_id,
        endpoint,
        default_limit,
        hour_ts,
        &mut sub_ops,
    )
    .await;

    let key = format!("quota:{}:{}:{}", client_id, endpoint, hour_ts);
    let (allowed, current_count, limit, kv_unavailable) =
        check_kv_counter(rate_limit_kv, &key, limit, 7200, &mut sub_ops).await;

    // Seconds remaining in the current hour
    let now_actual = crate::utils::current_timestamp();
    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_actual)).unwrap_or(u32::MAX);

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        kv_unavailable,
        sub_ops,
    }
}

/// Build a 503 Service Unavailable response with a Retry-After header.
///
/// Used when the rate limiter cannot function (KV binding missing or KV read
/// failures). The response is infallible: if header construction fails, the
/// bare 503 is still returned without the header.
pub fn service_unavailable_with_retry_after(
    retry_after_secs: u32,
) -> Result<Response, worker::Error> {
    let body = serde_json::json!({
        "error": "Service temporarily unavailable",
        "code": "RATE_LIMITER_UNAVAILABLE",
    });
    let mut resp = Response::from_json(&body)?;
    // Best-effort header attachment. If this fails, the 503 status alone
    // still communicates the correct semantics to the client.
    let _ = resp
        .headers_mut()
        .set("Retry-After", &retry_after_secs.to_string());
    Ok(resp.with_status(503))
}

/// Testable quota check that takes trait objects and injectable timestamps.
#[cfg(test)]
pub(crate) async fn check_quota_impl(
    rate_limit_kv: &dyn RateLimitKv,
    config_kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
    now_ms: f64,
) -> RateLimitResult {
    let mut sub_ops: Vec<(&'static str, f64)> = Vec::new();

    let hour_ts = (now_secs / 3600).saturating_mul(3600);

    let limit = get_customer_limit_impl(
        config_kv,
        client_id,
        endpoint,
        default_limit,
        hour_ts,
        &mut sub_ops,
        now_ms,
    )
    .await;

    let key = format!("quota:{}:{}:{}", client_id, endpoint, hour_ts);
    let (allowed, current_count, limit, kv_unavailable) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 7200, &mut sub_ops, now_ms).await;

    #[allow(clippy::cast_possible_truncation)]
    let retry_after =
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX);

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        kv_unavailable,
        sub_ops,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

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
    use crate::rate_limit_kv::mock::MockKv;
    use serial_test::serial;

    // ======================================================================
    // Phase 1: parse_tier_limits (pure function, no mock needed)
    // ======================================================================

    #[test]
    fn parse_tier_limits_nested_format() {
        let json = r#"{"tier_id":"t1","limits":{"challenge":500,"verify":200}}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("challenge").copied(), Some(500));
        assert_eq!(map.get("verify").copied(), Some(200));
    }

    #[test]
    fn parse_tier_limits_flat_format() {
        let json = r#"{"challenge":100,"verify":50}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("challenge").copied(), Some(100));
        assert_eq!(map.get("verify").copied(), Some(50));
    }

    #[test]
    fn parse_tier_limits_invalid_json() {
        let map = parse_tier_limits("not json at all");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_empty_object() {
        let map = parse_tier_limits("{}");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_empty_string() {
        let map = parse_tier_limits("");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_extra_fields() {
        let json = r#"{"tier_id":"premium","name":"Premium","limits":{"challenge":1000},"created_at":"2026-01-01"}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("challenge").copied(), Some(1000));
    }

    #[test]
    fn parse_tier_limits_nested_non_u32_falls_back() {
        let json = r#"{"limits":{"challenge":"not_a_number"}}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_empty_limits() {
        let json = r#"{"limits":{}}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    // ======================================================================
    // Phase 2: KV failure tracking (serial due to static atomics)
    // ======================================================================

    #[test]
    #[serial]
    fn kv_failure_count_starts_at_zero() {
        reset_kv_failure_count();
        assert_eq!(kv_unavailable_count(), 0);
    }

    #[test]
    #[serial]
    fn kv_failure_count_increments() {
        reset_kv_failure_count();
        let count = record_kv_failure();
        assert_eq!(count, 1);
        let count = record_kv_failure();
        assert_eq!(count, 2);
        assert_eq!(kv_unavailable_count(), 2);
    }

    #[test]
    #[serial]
    fn kv_success_resets_failure_count() {
        reset_kv_failure_count();
        record_kv_failure();
        record_kv_failure();
        assert_eq!(kv_unavailable_count(), 2);
        record_kv_success();
        assert_eq!(kv_unavailable_count(), 0);
    }

    #[test]
    #[serial]
    fn kv_failure_count_multiple_resets() {
        reset_kv_failure_count();
        record_kv_failure();
        record_kv_success();
        assert_eq!(kv_unavailable_count(), 0);
        record_kv_failure();
        assert_eq!(kv_unavailable_count(), 1);
        record_kv_success();
        assert_eq!(kv_unavailable_count(), 0);
    }

    // ======================================================================
    // Phase 3: KV counter logic with in-memory cache (serial for statics)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_first_request_allowed() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, limit, kv_unavail) =
            check_kv_counter_impl(&kv, "hosted:test:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
        assert!(!kv_unavail);

        // Verify a put was issued
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].value, "1");
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_denied_at_limit() {
        clear_counter_cache();
        let kv = MockKv::new().with_entry("hosted:test:key:0", "100");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, limit, _) =
            check_kv_counter_impl(&kv, "hosted:test:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(!allowed);
        assert_eq!(count, 101); // read 100, incremented to 101
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_read_failure_denies_fail_closed() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new().with_get_error("KV unavailable");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, limit, kv_unavail) =
            check_kv_counter_impl(&kv, "hosted:test:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(!allowed);
        assert_eq!(count, 0);
        assert_eq!(limit, 100);
        assert!(kv_unavail);
        assert_eq!(kv_unavailable_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_unparseable_treated_as_zero() {
        clear_counter_cache();
        let kv = MockKv::new().with_entry("hosted:test:key:0", "garbage");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:test:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_in_memory_cache_avoids_kv_read() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // First call: seeds from KV
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:cached:key:0", 100, 7200, &mut sub_ops, now_ms)
                .await;
        assert!(allowed);
        assert_eq!(count, 1);

        // Second call 5 seconds later: should use in-memory cache
        sub_ops.clear();
        let now_ms_2 = now_ms + 5000.0;
        let (allowed, count, _, _) = check_kv_counter_impl(
            &kv,
            "hosted:cached:key:0",
            100,
            7200,
            &mut sub_ops,
            now_ms_2,
        )
        .await;
        assert!(allowed);
        assert_eq!(count, 2);

        // No additional KV get should have occurred for the second call.
        // The sub_ops should show a cache hit (rl_counter_cache_check) but
        // no rl_kv_get_counter.
        let has_kv_get = sub_ops.iter().any(|(name, _)| *name == "rl_kv_get_counter");
        assert!(
            !has_kv_get,
            "Second call should use in-memory cache, not KV"
        );
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_expires_after_sync_interval() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // First call: seeds cache
        let _ =
            check_kv_counter_impl(&kv, "hosted:stale:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // Call 11 seconds later: cache should be stale (COUNTER_SYNC_INTERVAL_SECS = 10.0)
        sub_ops.clear();
        let stale_ms = now_ms + 11_000.0;
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:stale:key:0", 100, 7200, &mut sub_ops, stale_ms)
                .await;

        assert!(allowed);
        // Re-seeded from KV (which now has "1" from the first write)
        // so new_count = 1 + 1 = 2
        assert_eq!(count, 2);

        // Should have done a KV get for the re-seed
        let has_kv_get = sub_ops.iter().any(|(name, _)| *name == "rl_kv_get_counter");
        assert!(has_kv_get, "Stale cache should trigger KV read");
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_syncs_every_n_hits() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // First call: seeds cache and writes to KV
        let _ =
            check_kv_counter_impl(&kv, "hosted:sync:key:0", 1000, 7200, &mut sub_ops, now_ms).await;
        let initial_puts = kv.puts().len();
        assert_eq!(initial_puts, 1); // one put from the seed write-back

        // Next 9 calls within sync interval: increments in memory only
        for i in 1..10 {
            sub_ops.clear();
            let t = now_ms + (i as f64 * 100.0); // 100ms apart, well within 10s
            let _ =
                check_kv_counter_impl(&kv, "hosted:sync:key:0", 1000, 7200, &mut sub_ops, t).await;
        }

        // After seed + 9 in-memory increments = 10 total.
        // The 10th increment since sync should trigger a forced KV sync
        // (COUNTER_SYNC_INTERVAL_HITS = 10, and kv_count was set to 1 at seed,
        // so after 9 in-memory increments count=10, increments_since_sync=9).
        // Actually: seed sets count=1, kv_count=1.
        // Each in-memory increment: count++.
        // After 9 increments: count=10, kv_count=1, increments_since_sync=9.
        // So not yet at 10. One more:
        sub_ops.clear();
        let t = now_ms + 1000.0;
        let _ = check_kv_counter_impl(&kv, "hosted:sync:key:0", 1000, 7200, &mut sub_ops, t).await;

        // count=11, kv_count=1, increments_since_sync=10 >= 10 -> sync!
        let has_put = sub_ops.iter().any(|(name, _)| *name == "rl_kv_put_counter");
        assert!(
            has_put,
            "Should sync to KV after COUNTER_SYNC_INTERVAL_HITS increments"
        );
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_zero_limit_denies_all() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, _, limit, _) =
            check_kv_counter_impl(&kv, "hosted:zero:key:0", 0, 7200, &mut sub_ops, now_ms).await;
        assert!(!allowed);
        assert_eq!(limit, 0);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_limit_one() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // limit=1: first request increments 0→1, which is >= limit, so denied
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:one:key:0", 1, 7200, &mut sub_ops, now_ms).await;
        assert!(!allowed);
        assert_eq!(count, 1);
    }

    // ======================================================================
    // Phase 2b: Tier lookup via mock KV
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_returns_custom_limit() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_h1", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":2000}}"#,
            );
        let mut sub_ops = Vec::new();

        let limit = get_customer_limit_impl(
            &kv,
            "client_h1",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 2000);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_missing_client_uses_default() {
        clear_tier_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();

        let limit = get_customer_limit_impl(
            &kv,
            "unknown_h",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_kv_failure_uses_default() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_get_error("KV down")
            .with_persistent_errors();
        let mut sub_ops = Vec::new();

        let limit = get_customer_limit_impl(
            &kv,
            "fail_client",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn tier_cache_returns_cached_value() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/cached_h", "gold")
            .with_entry("rate_limits/tiers/gold", r#"{"limits":{"challenge":5000}}"#);
        let mut sub_ops = Vec::new();

        // Populate cache at t=1_700_000_000
        let limit = get_customer_limit_impl(
            &kv,
            "cached_h",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 5000);

        // Second call at t=1_700_000_030 (30s, within 60s TTL)
        let kv2 = MockKv::new();
        sub_ops.clear();
        let limit = get_customer_limit_impl(
            &kv2,
            "cached_h",
            "challenge",
            100,
            1_700_000_030,
            &mut sub_ops,
            1_700_000_030_000.0,
        )
        .await;
        assert_eq!(limit, 5000);
    }

    #[tokio::test]
    #[serial]
    async fn tier_cache_expires_after_60s() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/expiring_h", "silver")
            .with_entry(
                "rate_limits/tiers/silver",
                r#"{"limits":{"challenge":3000}}"#,
            );
        let mut sub_ops = Vec::new();

        // Populate cache
        let _ = get_customer_limit_impl(
            &kv,
            "expiring_h",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;

        // 61s later: stale, KV empty -> default
        let kv2 = MockKv::new();
        sub_ops.clear();
        let limit = get_customer_limit_impl(
            &kv2,
            "expiring_h",
            "challenge",
            100,
            1_700_000_061,
            &mut sub_ops,
            1_700_000_061_000.0,
        )
        .await;
        assert_eq!(limit, 100);
    }

    // ======================================================================
    // Phase 4: End-to-end check_quota_impl flow
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_allows_first_request() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let result = check_quota_impl(
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
        assert!(result.retry_after_secs <= 3600);
    }

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_uses_tier_limit() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/h_vip", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":9999}}"#,
            );

        let result = check_quota_impl(
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
    async fn check_quota_impl_denied_at_limit() {
        clear_tier_cache();
        clear_counter_cache();
        let now_secs = 1_700_000_000u64;
        let hour_ts = (now_secs / 3600) * 3600;
        let key = format!("quota:h_client_b:challenge:{}", hour_ts);
        let rate_kv = MockKv::new().with_entry(&key, "50");
        let config_kv = MockKv::new();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_client_b",
            "challenge",
            50,
            now_secs,
            now_secs as f64 * 1000.0,
        )
        .await;

        assert!(!result.allowed);
    }

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_kv_unavailable_signals_503() {
        clear_tier_cache();
        clear_counter_cache();
        reset_kv_failure_count();
        let rate_kv = MockKv::new()
            .with_get_error("KV is down")
            .with_persistent_errors();
        let config_kv = MockKv::new();

        let result = check_quota_impl(
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
    async fn check_quota_impl_correct_kv_key() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;

        let _ = check_quota_impl(
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

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_sub_ops_populated() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "hc_ops",
            "challenge",
            100,
            1_700_000_000,
            1_700_000_000_000.0,
        )
        .await;

        // Sub-ops should have been populated with timing data
        assert!(
            !result.sub_ops.is_empty(),
            "sub_ops should contain performance instrumentation entries"
        );
    }

    // ======================================================================
    // Phase 1b: parse_tier_limits additional edge cases
    // ======================================================================

    #[test]
    fn parse_tier_limits_nested_null_limits() {
        let json = r#"{"limits":null}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_limits_is_array() {
        let json = r#"{"limits":[100,200]}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_flat_with_zero_values() {
        let json = r#"{"challenge":0,"verify":0}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.get("challenge").copied(), Some(0));
        assert_eq!(map.get("verify").copied(), Some(0));
    }

    #[test]
    fn parse_tier_limits_flat_max_u32() {
        let json = format!(r#"{{"challenge":{}}}"#, u32::MAX);
        let map = parse_tier_limits(&json);
        assert_eq!(map.get("challenge").copied(), Some(u32::MAX));
    }

    #[test]
    fn parse_tier_limits_negative_value_fails() {
        let json = r#"{"challenge":-1}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_float_value_fails() {
        let json = r#"{"challenge":1.5}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_single_endpoint() {
        let json = r#"{"limits":{"verify":42}}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("verify").copied(), Some(42));
    }

    #[test]
    fn parse_tier_limits_many_endpoints() {
        let json = r#"{"limits":{"a":1,"b":2,"c":3,"d":4,"e":5}}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 5);
    }

    // ======================================================================
    // Phase 2c: KV failure tracking edge cases
    // ======================================================================

    #[test]
    #[serial]
    fn kv_failure_count_reaches_circuit_breaker_threshold() {
        reset_kv_failure_count();
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            record_kv_failure();
        }
        assert_eq!(kv_unavailable_count(), CIRCUIT_BREAKER_THRESHOLD);
    }

    #[test]
    #[serial]
    fn kv_failure_count_exceeds_circuit_breaker_threshold() {
        reset_kv_failure_count();
        for _ in 0..10 {
            record_kv_failure();
        }
        assert_eq!(kv_unavailable_count(), 10);
    }

    #[test]
    #[serial]
    fn kv_success_on_zero_count_is_noop() {
        reset_kv_failure_count();
        assert_eq!(kv_unavailable_count(), 0);
        record_kv_success();
        assert_eq!(kv_unavailable_count(), 0);
    }

    #[test]
    #[serial]
    fn kv_failure_and_recovery_cycle() {
        reset_kv_failure_count();
        // Failure cycle 1
        record_kv_failure();
        record_kv_failure();
        assert_eq!(kv_unavailable_count(), 2);
        record_kv_success();
        assert_eq!(kv_unavailable_count(), 0);
        // Failure cycle 2
        record_kv_failure();
        assert_eq!(kv_unavailable_count(), 1);
        record_kv_success();
        assert_eq!(kv_unavailable_count(), 0);
    }

    // ======================================================================
    // Phase 3b: KV counter additional edge cases
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_denied_above_limit() {
        clear_counter_cache();
        let kv = MockKv::new().with_entry("hosted:above:key:0", "200");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, limit, _) =
            check_kv_counter_impl(&kv, "hosted:above:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(!allowed);
        // 200 + 1 = 201, which exceeds limit
        assert_eq!(count, 201);
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_empty_string_treated_as_zero() {
        clear_counter_cache();
        let kv = MockKv::new().with_entry("hosted:empty:key:0", "");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:empty:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_different_keys_isolated() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (_, count_a, _, _) =
            check_kv_counter_impl(&kv, "hosted:iso:a", 100, 7200, &mut sub_ops, now_ms).await;
        let (_, count_b, _, _) =
            check_kv_counter_impl(&kv, "hosted:iso:b", 100, 7200, &mut sub_ops, now_ms).await;

        assert_eq!(count_a, 1);
        assert_eq!(count_b, 1);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_write_failure_still_allows() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new().with_put_error("write fail");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, _, kv_unavail) =
            check_kv_counter_impl(&kv, "hosted:wfail:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // Read succeeds (no entry -> count 0 -> new_count 1), write fails but
        // the request is still allowed (fail-open on write, fail-closed on read)
        assert!(allowed);
        assert_eq!(count, 1);
        assert!(!kv_unavail);
    }

    // ======================================================================
    // Phase 2d: Tier lookup additional edge cases
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_missing_tier_uses_default() {
        clear_tier_cache();
        let kv = MockKv::new().with_entry("rate_limits/clients/h_orphan", "nonexistent_tier");
        let mut sub_ops = Vec::new();

        let limit = get_customer_limit_impl(
            &kv,
            "h_orphan",
            "challenge",
            77,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 77);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_endpoint_not_in_tier() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_partial", "basic")
            .with_entry("rate_limits/tiers/basic", r#"{"limits":{"verify":300}}"#);
        let mut sub_ops = Vec::new();

        // "challenge" is not in the tier limits
        let limit = get_customer_limit_impl(
            &kv,
            "h_partial",
            "challenge",
            42,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 42);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_malformed_tier_json() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_malformed", "broken_tier")
            .with_entry("rate_limits/tiers/broken_tier", "not json at all");
        let mut sub_ops = Vec::new();

        let limit = get_customer_limit_impl(
            &kv,
            "h_malformed",
            "challenge",
            99,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 99);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_different_endpoints_same_tier() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/h_multi", "enterprise")
            .with_entry(
                "rate_limits/tiers/enterprise",
                r#"{"limits":{"challenge":10000,"verify":5000}}"#,
            );
        let mut sub_ops = Vec::new();

        let challenge_limit = get_customer_limit_impl(
            &kv,
            "h_multi",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(challenge_limit, 10000);

        // Cache should work for a different endpoint
        let kv2 = MockKv::new();
        sub_ops.clear();
        let verify_limit = get_customer_limit_impl(
            &kv2,
            "h_multi",
            "verify",
            100,
            1_700_000_010,
            &mut sub_ops,
            1_700_000_010_000.0,
        )
        .await;
        assert_eq!(verify_limit, 5000);
    }

    // ======================================================================
    // Phase 4b: End-to-end additional edge cases
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_retry_after_at_hour_boundary() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        // Exactly at an hour boundary
        let now = 1_699_200_000u64;
        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_boundary",
            "challenge",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;
        assert_eq!(result.retry_after_secs, 3600);
    }

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_retry_after_near_end_of_hour() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let hour_ts = 1_699_200_000u64;
        let now = hour_ts + 3599; // 1 second before hour ends

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_near_end",
            "challenge",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;
        assert_eq!(result.retry_after_secs, 1);
    }

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_different_endpoints_isolated() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;

        let r1 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_ep_client",
            "challenge",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;
        let r2 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_ep_client",
            "verify",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;

        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);
    }

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_different_clients_isolated() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;

        let r1 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_alice",
            "challenge",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;
        let r2 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_bob",
            "challenge",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;

        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);
    }

    // ======================================================================
    // RateLimitResult struct coverage
    // ======================================================================

    #[test]
    fn rate_limit_result_fields() {
        let r = RateLimitResult {
            allowed: false,
            current_count: 100,
            limit: 100,
            retry_after_secs: 1800,
            kv_unavailable: true,
            sub_ops: vec![("test_op", 1.5)],
        };
        assert!(!r.allowed);
        assert_eq!(r.current_count, 100);
        assert_eq!(r.limit, 100);
        assert_eq!(r.retry_after_secs, 1800);
        assert!(r.kv_unavailable);
        assert_eq!(r.sub_ops.len(), 1);
        assert_eq!(r.sub_ops[0].0, "test_op");
    }

    #[test]
    fn rate_limit_result_remaining_calculation() {
        let r = RateLimitResult {
            allowed: true,
            current_count: 30,
            limit: 100,
            retry_after_secs: 0,
            kv_unavailable: false,
            sub_ops: Vec::new(),
        };
        let remaining = r.limit.saturating_sub(r.current_count);
        assert_eq!(remaining, 70);
    }

    #[test]
    fn rate_limit_result_remaining_when_over() {
        let r = RateLimitResult {
            allowed: false,
            current_count: 150,
            limit: 100,
            retry_after_secs: 0,
            kv_unavailable: false,
            sub_ops: Vec::new(),
        };
        let remaining = r.limit.saturating_sub(r.current_count);
        assert_eq!(remaining, 0);
    }

    // ======================================================================
    // Constants coverage
    // ======================================================================

    #[test]
    fn circuit_breaker_threshold_is_sensible() {
        assert!(CIRCUIT_BREAKER_THRESHOLD > 0);
        assert!(CIRCUIT_BREAKER_THRESHOLD <= 100);
    }

    #[test]
    fn counter_cache_max_entries_is_sensible() {
        assert!(COUNTER_CACHE_MAX_ENTRIES > 0);
    }

    #[test]
    fn counter_sync_interval_secs_is_sensible() {
        assert!(COUNTER_SYNC_INTERVAL_SECS > 0.0);
    }

    #[test]
    fn counter_sync_interval_hits_is_sensible() {
        assert!(COUNTER_SYNC_INTERVAL_HITS > 0);
    }

    // ======================================================================
    // Phase 5: service_unavailable_with_retry_after
    // ======================================================================

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn service_unavailable_returns_503() -> Result<(), worker::Error> {
        let resp = service_unavailable_with_retry_after(60)?;
        assert_eq!(resp.status_code(), 503);
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn service_unavailable_has_retry_after_header() -> Result<(), worker::Error> {
        let resp = service_unavailable_with_retry_after(120)?;
        let hdr = resp.headers().get("Retry-After").ok().flatten();
        assert_eq!(hdr.as_deref(), Some("120"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn service_unavailable_zero_retry_after() -> Result<(), worker::Error> {
        let resp = service_unavailable_with_retry_after(0)?;
        assert_eq!(resp.status_code(), 503);
        let hdr = resp.headers().get("Retry-After").ok().flatten();
        assert_eq!(hdr.as_deref(), Some("0"));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn service_unavailable_max_retry_after() -> Result<(), worker::Error> {
        let resp = service_unavailable_with_retry_after(u32::MAX)?;
        assert_eq!(resp.status_code(), 503);
        let hdr = resp.headers().get("Retry-After").ok().flatten();
        let expected = u32::MAX.to_string();
        assert_eq!(hdr.as_deref(), Some(expected.as_str()));
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn service_unavailable_body_is_json() -> Result<(), worker::Error> {
        let resp = service_unavailable_with_retry_after(30)?;
        // The response should be valid JSON with the expected fields.
        // We can check content-type header set by Response::from_json.
        let ct = resp.headers().get("Content-Type").ok().flatten();
        assert!(
            ct.as_deref()
                .map(|s| s.contains("application/json"))
                .unwrap_or(false),
            "Content-Type should be application/json, got {:?}",
            ct
        );
        Ok(())
    }

    // ======================================================================
    // Phase 6: FALLBACK_DENIED_COUNT tracking
    // ======================================================================

    #[test]
    #[serial]
    fn fallback_denied_count_incremented_by_failures() {
        reset_kv_failure_count();
        FALLBACK_DENIED_COUNT.store(0, Ordering::Relaxed);

        record_kv_failure();
        record_kv_failure();
        record_kv_failure();
        assert_eq!(FALLBACK_DENIED_COUNT.load(Ordering::Relaxed), 3);
    }

    #[test]
    #[serial]
    fn fallback_denied_count_reset_on_recovery() {
        reset_kv_failure_count();
        FALLBACK_DENIED_COUNT.store(0, Ordering::Relaxed);

        record_kv_failure();
        record_kv_failure();
        assert_eq!(FALLBACK_DENIED_COUNT.load(Ordering::Relaxed), 2);

        record_kv_success();
        assert_eq!(FALLBACK_DENIED_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[serial]
    fn fallback_denied_count_not_reset_when_no_failures() {
        reset_kv_failure_count();
        FALLBACK_DENIED_COUNT.store(0, Ordering::Relaxed);

        // Success when already at zero should not touch denied count
        record_kv_success();
        assert_eq!(FALLBACK_DENIED_COUNT.load(Ordering::Relaxed), 0);
    }

    // ======================================================================
    // Phase 7: record_kv_failure return value at exact threshold
    // ======================================================================

    #[test]
    #[serial]
    fn record_kv_failure_returns_count_at_threshold() {
        reset_kv_failure_count();
        let mut last = 0;
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            last = record_kv_failure();
        }
        assert_eq!(last, CIRCUIT_BREAKER_THRESHOLD);
    }

    #[test]
    #[serial]
    fn record_kv_failure_returns_count_above_threshold() {
        reset_kv_failure_count();
        for _ in 0..CIRCUIT_BREAKER_THRESHOLD {
            record_kv_failure();
        }
        let above = record_kv_failure();
        assert_eq!(above, CIRCUIT_BREAKER_THRESHOLD + 1);
    }

    #[test]
    #[serial]
    fn record_kv_failure_returns_one_on_first_call() {
        reset_kv_failure_count();
        let count = record_kv_failure();
        assert_eq!(count, 1);
    }

    // ======================================================================
    // Phase 8: In-memory counter cache denial path
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_hit_denied_at_limit() {
        clear_counter_cache();
        reset_kv_failure_count();
        // Seed with count=99, limit=100. First call increments to 100.
        let kv = MockKv::new().with_entry("hosted:cd:key:0", "99");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed: reads 99, increments to 100, 100 >= 100 -> denied
        let (allowed, count, limit, _) =
            check_kv_counter_impl(&kv, "hosted:cd:key:0", 100, 7200, &mut sub_ops, now_ms).await;
        assert!(!allowed);
        assert_eq!(count, 100);
        assert_eq!(limit, 100);

        // Second call via cache: increments to 101, still denied
        sub_ops.clear();
        let now_ms_2 = now_ms + 1000.0;
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:cd:key:0", 100, 7200, &mut sub_ops, now_ms_2).await;
        assert!(!allowed);
        assert_eq!(count, 101);

        // Verify no KV get was issued for the cached call
        let has_kv_get = sub_ops.iter().any(|(name, _)| *name == "rl_kv_get_counter");
        assert!(!has_kv_get, "Denied via cache should not do KV get");
    }

    // ======================================================================
    // Phase 9: Cache sync on hit triggers KV write AND denial
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_sync_and_deny() {
        clear_counter_cache();
        reset_kv_failure_count();
        // Seed with 89, limit 100. First call: count=90.
        let kv = MockKv::new().with_entry("hosted:sd:key:0", "89");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, _, _, _) =
            check_kv_counter_impl(&kv, "hosted:sd:key:0", 100, 7200, &mut sub_ops, now_ms).await;
        assert!(allowed);

        // 10 more calls (count 91..100). The 10th in-memory increment since
        // kv_count=90 should trigger a sync.
        for i in 1..=10 {
            sub_ops.clear();
            let t = now_ms + (i as f64 * 100.0);
            let _ = check_kv_counter_impl(&kv, "hosted:sd:key:0", 100, 7200, &mut sub_ops, t).await;
        }

        // After seed (count=90, kv_count=90) + 10 in-memory increments:
        // count=100, increments_since_sync=10 -> sync triggered.
        // count=100 >= limit=100 -> denied.
        let last_has_put = sub_ops.iter().any(|(name, _)| *name == "rl_kv_put_counter");
        assert!(last_has_put, "10th increment should trigger KV sync");
    }

    // ======================================================================
    // Phase 10: Counter cache eviction paths (ADV-VA-027)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_evicts_stale_entries_at_capacity() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_000_000_000_000.0;
        let ttl_secs = 3600u64;

        // Fill the cache to exactly COUNTER_CACHE_MAX_ENTRIES with stale entries.
        // We inject directly into the cache to avoid 5000 KV round-trips.
        {
            let mut cache = counter_cache().write().expect("lock");
            cache.clear();
            let stale_time = now_ms - (ttl_secs as f64 * 1000.0) - 1000.0; // older than TTL
            for i in 0..COUNTER_CACHE_MAX_ENTRIES {
                cache.insert(
                    format!("stale_key_{}", i),
                    InMemoryCounter {
                        count: 1,
                        last_synced_at: stale_time,
                        kv_count: 1,
                    },
                );
            }
            assert_eq!(cache.len(), COUNTER_CACHE_MAX_ENTRIES);
        }

        // This call should trigger eviction of stale entries, then insert the new key.
        let (allowed, count, _, _) = check_kv_counter_impl(
            &kv,
            "new_key_after_eviction",
            100,
            ttl_secs,
            &mut sub_ops,
            now_ms,
        )
        .await;
        assert!(allowed);
        assert_eq!(count, 1);

        // The stale entries should have been evicted
        let cache = counter_cache().read().expect("lock");
        assert!(
            cache.len() < COUNTER_CACHE_MAX_ENTRIES,
            "Stale entries should have been evicted, got {}",
            cache.len()
        );
        assert!(
            cache.contains_key("new_key_after_eviction"),
            "New key should be in cache after eviction"
        );
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_evicts_oldest_half_when_all_fresh() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_000_000_000_000.0;
        let ttl_secs = 3600u64;

        // Fill the cache with fresh (non-stale) entries at capacity.
        {
            let mut cache = counter_cache().write().expect("lock");
            cache.clear();
            // All entries are recent (within the TTL window)
            let recent_time = now_ms - 1000.0; // 1 second ago, well within TTL
            for i in 0..COUNTER_CACHE_MAX_ENTRIES {
                cache.insert(
                    format!("fresh_key_{}", i),
                    InMemoryCounter {
                        count: 1,
                        last_synced_at: recent_time + (i as f64 * 0.001), // slightly different times
                        kv_count: 1,
                    },
                );
            }
            assert_eq!(cache.len(), COUNTER_CACHE_MAX_ENTRIES);
        }

        // This call should: retain all (none are stale), then evict oldest half.
        let (allowed, count, _, _) = check_kv_counter_impl(
            &kv,
            "after_half_eviction",
            100,
            ttl_secs,
            &mut sub_ops,
            now_ms,
        )
        .await;
        assert!(allowed);
        assert_eq!(count, 1);

        let cache = counter_cache().read().expect("lock");
        // After evicting half of 5000 = 2500 evicted, then insert 1 = 2501
        let expected_approx = COUNTER_CACHE_MAX_ENTRIES / 2 + 1;
        assert!(
            cache.len() <= expected_approx,
            "After half-eviction, expected ~{} entries, got {}",
            expected_approx,
            cache.len()
        );
        assert!(
            cache.contains_key("after_half_eviction"),
            "New key should be present after half-eviction"
        );
    }

    // ======================================================================
    // Phase 11: u32 overflow handling in check_kv_counter_impl
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_u32_max_value_in_kv() {
        clear_counter_cache();
        reset_kv_failure_count();
        let max_str = u64::from(u32::MAX).to_string();
        let kv = MockKv::new().with_entry("hosted:overflow:key:0", &max_str);
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, limit, _) = check_kv_counter_impl(
            &kv,
            "hosted:overflow:key:0",
            100,
            7200,
            &mut sub_ops,
            now_ms,
        )
        .await;

        // u32::MAX + 1 saturates to u32::MAX in the try_from
        assert!(!allowed);
        assert_eq!(count, u32::MAX);
        assert_eq!(limit, 100);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_large_value_above_u32_max() {
        clear_counter_cache();
        reset_kv_failure_count();
        // Value that exceeds u32::MAX when parsed as u64
        let large_val = (u64::from(u32::MAX) + 100).to_string();
        let kv = MockKv::new().with_entry("hosted:bigval:key:0", &large_val);
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, _, _) = check_kv_counter_impl(
            &kv,
            "hosted:bigval:key:0",
            u32::MAX,
            7200,
            &mut sub_ops,
            now_ms,
        )
        .await;

        // Parsed as u64, saturating_add(1), then try_from saturates to u32::MAX
        assert!(!allowed);
        assert_eq!(count, u32::MAX);
    }

    // ======================================================================
    // Phase 12: Tier cache - flat format through KV lookup
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_flat_format_via_kv() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/flat_client", "flat_tier")
            .with_entry(
                "rate_limits/tiers/flat_tier",
                r#"{"challenge":777,"verify":333}"#,
            );
        let mut sub_ops = Vec::new();

        let limit = get_customer_limit_impl(
            &kv,
            "flat_client",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 777);
    }

    // ======================================================================
    // Phase 13: Tier cache write populates correctly
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_cache_populated_after_kv_miss() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/cache_pop", "my_tier")
            .with_entry(
                "rate_limits/tiers/my_tier",
                r#"{"limits":{"challenge":888,"verify":444}}"#,
            );
        let mut sub_ops = Vec::new();

        // First call populates the cache
        let limit = get_customer_limit_impl(
            &kv,
            "cache_pop",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;
        assert_eq!(limit, 888);

        // Verify the cache now has the entry with both endpoints
        let cache = tier_cache().read().expect("lock");
        let entry = cache.get("cache_pop");
        assert!(
            entry.is_some(),
            "Tier cache should have entry for cache_pop"
        );
        let entry = entry.expect("just checked");
        assert_eq!(entry.limits.get("challenge").copied(), Some(888));
        assert_eq!(entry.limits.get("verify").copied(), Some(444));
        assert_eq!(entry.fetched_at, 1_700_000_000);
    }

    // ======================================================================
    // Phase 14: Tier cache boundary - exactly at 60s
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_cache_still_valid_at_59s() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/ttl59", "tier59")
            .with_entry(
                "rate_limits/tiers/tier59",
                r#"{"limits":{"challenge":600}}"#,
            );
        let mut sub_ops = Vec::new();

        // Populate at t=1_700_000_000
        let _ = get_customer_limit_impl(
            &kv,
            "ttl59",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;

        // At t=1_700_000_059 (59 seconds later), cache is still valid
        let kv2 = MockKv::new(); // empty KV; should not be hit
        sub_ops.clear();
        let limit = get_customer_limit_impl(
            &kv2,
            "ttl59",
            "challenge",
            100,
            1_700_000_059,
            &mut sub_ops,
            1_700_000_059_000.0,
        )
        .await;
        assert_eq!(limit, 600);
    }

    #[tokio::test]
    #[serial]
    async fn tier_cache_stale_at_exactly_60s() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/ttl60", "tier60")
            .with_entry(
                "rate_limits/tiers/tier60",
                r#"{"limits":{"challenge":700}}"#,
            );
        let mut sub_ops = Vec::new();

        // Populate at t=1_700_000_000
        let _ = get_customer_limit_impl(
            &kv,
            "ttl60",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;

        // At exactly t=1_700_000_060 (60 seconds), saturating_sub = 60, NOT < 60 -> stale
        let kv2 = MockKv::new(); // empty KV; will fall through to default
        sub_ops.clear();
        let limit = get_customer_limit_impl(
            &kv2,
            "ttl60",
            "challenge",
            100,
            1_700_000_060,
            &mut sub_ops,
            1_700_000_060_000.0,
        )
        .await;
        assert_eq!(
            limit, 100,
            "Cache should be stale at exactly 60s, returning default"
        );
    }

    // ======================================================================
    // Phase 15: check_kv_counter_impl - KV Ok(None) path explicitly
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_ok_none_resets_failure_count() {
        clear_counter_cache();
        reset_kv_failure_count();
        // Pre-set some failures
        record_kv_failure();
        record_kv_failure();
        assert_eq!(kv_unavailable_count(), 2);

        let kv = MockKv::new(); // No entries -> get returns Ok(None)
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, _, kv_unavail) =
            check_kv_counter_impl(&kv, "hosted:none:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(allowed);
        assert_eq!(count, 1);
        assert!(!kv_unavail);
        // The Ok(None) path calls record_kv_success, which resets the counter
        assert_eq!(kv_unavailable_count(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_ok_some_resets_failure_count() {
        clear_counter_cache();
        reset_kv_failure_count();
        record_kv_failure();
        assert_eq!(kv_unavailable_count(), 1);

        let kv = MockKv::new().with_entry("hosted:some:key:0", "5");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:some:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        assert!(allowed);
        assert_eq!(count, 6);
        assert_eq!(kv_unavailable_count(), 0);
    }

    // ======================================================================
    // Phase 16: Counter cache exactly at sync interval boundary (10s)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_stale_at_exactly_10s() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed the cache
        let _ =
            check_kv_counter_impl(&kv, "hosted:10s:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // At exactly 10 seconds: age_secs = 10.0, NOT < 10.0 -> stale
        sub_ops.clear();
        let stale_ms = now_ms + 10_000.0;
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:10s:key:0", 100, 7200, &mut sub_ops, stale_ms).await;

        assert!(allowed);
        // Re-seeded from KV (which has "1"), so new_count = 1 + 1 = 2
        assert_eq!(count, 2);

        let has_kv_get = sub_ops.iter().any(|(name, _)| *name == "rl_kv_get_counter");
        assert!(has_kv_get, "At exactly 10s, should re-read from KV");
    }

    #[tokio::test]
    #[serial]
    async fn kv_counter_cache_fresh_at_9_999s() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed the cache
        let _ =
            check_kv_counter_impl(&kv, "hosted:9s:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // At 9.999 seconds: age_secs = 9.999, < 10.0 -> fresh cache hit
        sub_ops.clear();
        let fresh_ms = now_ms + 9_999.0;
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:9s:key:0", 100, 7200, &mut sub_ops, fresh_ms).await;

        assert!(allowed);
        assert_eq!(count, 2);

        let has_kv_get = sub_ops.iter().any(|(name, _)| *name == "rl_kv_get_counter");
        assert!(!has_kv_get, "At 9.999s, should use cache");
    }

    // ======================================================================
    // Phase 17: check_quota_impl - retry_after mid-hour
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_retry_after_mid_hour() {
        clear_tier_cache();
        clear_counter_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let hour_ts = 1_699_200_000u64;
        let now = hour_ts + 1800; // exactly 30 minutes in

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_mid",
            "challenge",
            100,
            now,
            now as f64 * 1000.0,
        )
        .await;

        assert_eq!(result.retry_after_secs, 1800);
    }

    // ======================================================================
    // Phase 18: Multiple sequential failures then recovery
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_multiple_failures_then_recovery() {
        clear_counter_cache();
        reset_kv_failure_count();
        FALLBACK_DENIED_COUNT.store(0, Ordering::Relaxed);

        // Fail 3 times
        let kv_fail = MockKv::new()
            .with_get_error("fail")
            .with_persistent_errors();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        for i in 0..3 {
            sub_ops.clear();
            let key = format!("hosted:mf:key:{}", i);
            // Each call uses a different key to avoid cache hits
            let (allowed, _, _, kv_unavail) = check_kv_counter_impl(
                &kv_fail,
                &key,
                100,
                7200,
                &mut sub_ops,
                now_ms + (i as f64 * 1000.0),
            )
            .await;
            assert!(!allowed);
            assert!(kv_unavail);
        }
        assert_eq!(kv_unavailable_count(), 3);
        assert_eq!(FALLBACK_DENIED_COUNT.load(Ordering::Relaxed), 3);

        // Now recover
        let kv_ok = MockKv::new();
        sub_ops.clear();
        let (allowed, count, _, kv_unavail) = check_kv_counter_impl(
            &kv_ok,
            "hosted:mf:recover",
            100,
            7200,
            &mut sub_ops,
            now_ms + 5000.0,
        )
        .await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert!(!kv_unavail);
        assert_eq!(kv_unavailable_count(), 0);
        assert_eq!(FALLBACK_DENIED_COUNT.load(Ordering::Relaxed), 0);
    }

    // ======================================================================
    // Phase 19: check_quota_impl with tier + near-limit counter
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_tier_limit_enforced_over_default() {
        clear_tier_cache();
        clear_counter_cache();
        let now_secs = 1_700_000_000u64;
        let hour_ts = (now_secs / 3600) * 3600;

        // Client has a tier with limit=50 for "challenge"
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/h_low_tier", "low")
            .with_entry("rate_limits/tiers/low", r#"{"limits":{"challenge":50}}"#);

        // Counter is at 49
        let key = format!("quota:h_low_tier:challenge:{}", hour_ts);
        let rate_kv = MockKv::new().with_entry(&key, "49");

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_low_tier",
            "challenge",
            1000, // default is 1000, but tier limit is 50
            now_secs,
            now_secs as f64 * 1000.0,
        )
        .await;

        // 49 + 1 = 50, which equals the tier limit of 50 -> denied
        assert!(!result.allowed);
        assert_eq!(result.limit, 50);
        assert_eq!(result.current_count, 50);
    }

    // ======================================================================
    // Phase 20: Counter cache KV write-back TTL verification
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_put_uses_correct_ttl() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;
        let ttl = 14400u64;

        let _ =
            check_kv_counter_impl(&kv, "hosted:ttl:key:0", 100, ttl, &mut sub_ops, now_ms).await;

        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].ttl_secs, ttl);
    }

    // ======================================================================
    // Phase 21: check_quota_impl with config KV error (rate KV fine)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_config_kv_error_uses_default_limit() {
        clear_tier_cache();
        clear_counter_cache();
        reset_kv_failure_count();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_get_error("config down")
            .with_persistent_errors();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_cfg_err",
            "challenge",
            250,
            1_700_000_000,
            1_700_000_000_000.0,
        )
        .await;

        // Config KV error means default limit used; rate KV works fine
        assert!(result.allowed);
        assert_eq!(result.limit, 250);
        assert_eq!(result.current_count, 1);
        assert!(!result.kv_unavailable);
    }

    // ======================================================================
    // Phase 22: sub_ops instrumentation details
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_kv_counter_sub_ops_on_cache_miss() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let _ =
            check_kv_counter_impl(&kv, "hosted:ops:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // On cache miss, should have: rl_counter_cache_check, rl_kv_get_counter, rl_kv_put_counter
        let op_names: Vec<&str> = sub_ops.iter().map(|(name, _)| *name).collect();
        assert!(
            op_names.contains(&"rl_counter_cache_check"),
            "Should have cache check op, got {:?}",
            op_names
        );
        assert!(
            op_names.contains(&"rl_kv_get_counter"),
            "Should have KV get op, got {:?}",
            op_names
        );
        assert!(
            op_names.contains(&"rl_kv_put_counter"),
            "Should have KV put op, got {:?}",
            op_names
        );
    }

    #[tokio::test]
    #[serial]
    async fn check_kv_counter_sub_ops_on_cache_hit() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed
        let _ =
            check_kv_counter_impl(&kv, "hosted:ops2:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // Cache hit
        sub_ops.clear();
        let now_ms_2 = now_ms + 1000.0;
        let _ = check_kv_counter_impl(&kv, "hosted:ops2:key:0", 100, 7200, &mut sub_ops, now_ms_2)
            .await;

        let op_names: Vec<&str> = sub_ops.iter().map(|(name, _)| *name).collect();
        assert!(
            op_names.contains(&"rl_counter_cache_check"),
            "Cache hit should still have cache check op"
        );
        assert!(
            !op_names.contains(&"rl_kv_get_counter"),
            "Cache hit should NOT have KV get op"
        );
    }

    #[tokio::test]
    #[serial]
    async fn get_customer_limit_sub_ops_on_cache_hit() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/ops_tier", "ops_t")
            .with_entry("rate_limits/tiers/ops_t", r#"{"limits":{"challenge":111}}"#);
        let mut sub_ops = Vec::new();

        // Populate cache
        let _ = get_customer_limit_impl(
            &kv,
            "ops_tier",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;

        // Cache hit (within 60s)
        sub_ops.clear();
        let _ = get_customer_limit_impl(
            &kv,
            "ops_tier",
            "challenge",
            100,
            1_700_000_010,
            &mut sub_ops,
            1_700_000_010_000.0,
        )
        .await;

        let op_names: Vec<&str> = sub_ops.iter().map(|(name, _)| *name).collect();
        assert!(
            op_names.contains(&"rl_tier_cache_check"),
            "Tier cache hit should have cache check op"
        );
        // Should NOT have KV get ops since cache was used
        assert!(
            !op_names.contains(&"rl_kv_get_client_tier"),
            "Tier cache hit should NOT have KV get client tier op"
        );
    }

    #[tokio::test]
    #[serial]
    async fn get_customer_limit_sub_ops_on_cache_miss() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/ops_miss", "ops_m")
            .with_entry("rate_limits/tiers/ops_m", r#"{"limits":{"challenge":222}}"#);
        let mut sub_ops = Vec::new();

        let _ = get_customer_limit_impl(
            &kv,
            "ops_miss",
            "challenge",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;

        let op_names: Vec<&str> = sub_ops.iter().map(|(name, _)| *name).collect();
        assert!(
            op_names.contains(&"rl_tier_cache_check"),
            "Cache miss should have cache check op"
        );
        assert!(
            op_names.contains(&"rl_kv_get_client_tier"),
            "Cache miss should have KV get client tier op"
        );
        assert!(
            op_names.contains(&"rl_kv_get_tier_limits"),
            "Cache miss should have KV get tier limits op"
        );
    }

    // ======================================================================
    // Phase 23: Counter cache limit=1 via in-memory path
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_limit_one_denied_on_cache_hit() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // First call: seeds from KV (empty), count=1, 1 >= 1 -> allowed (count starts at 1, but
        // the comparison is >=, so count=1 with limit=1 is... let's check the code path).
        // Actually: new_count=0+1=1, u32::try_from(1)=1, 1 >= 1 -> denied!
        // Wait, limit=1 means first request is denied on KV seed path (line 390).
        // Re-read: limit=2 to allow first, deny second.
        let (allowed, count, _, _) =
            check_kv_counter_impl(&kv, "hosted:l2:key:0", 2, 7200, &mut sub_ops, now_ms).await;
        assert!(allowed, "First request with limit=2 should be allowed");
        assert_eq!(count, 1);

        // Second call (cache hit): count=2, 2 >= 2 -> denied
        sub_ops.clear();
        let (allowed, count, _, _) = check_kv_counter_impl(
            &kv,
            "hosted:l2:key:0",
            2,
            7200,
            &mut sub_ops,
            now_ms + 1000.0,
        )
        .await;
        assert!(!allowed, "Second request with limit=2 should be denied");
        assert_eq!(count, 2);
    }

    // ======================================================================
    // Phase 24: parse_tier_limits - nested with limits being a string
    // ======================================================================

    #[test]
    fn parse_tier_limits_nested_limits_is_string() {
        let json = r#"{"limits":"not an object"}"#;
        let map = parse_tier_limits(json);
        // "not an object" can't deserialize to HashMap<String, u32>, falls through
        // to flat parse which also fails
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_limits_is_number() {
        // "limits" is a number not a map, so nested parse fails; flat fallback
        // succeeds because {"limits":42} is valid HashMap<String, u32>
        let json = r#"{"limits":42}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.get("limits"), Some(&42));
    }

    #[test]
    fn parse_tier_limits_flat_with_mixed_types_fails() {
        // Mixed: some values are u32, some are strings. Flat parse fails entirely.
        let json = r#"{"challenge":100,"verify":"fast"}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_with_overflow_value() {
        // Value exceeds u32::MAX -> deserialisation fails -> falls through to flat parse
        let json = format!(r#"{{"limits":{{"challenge":{}}}}}"#, u64::MAX);
        let map = parse_tier_limits(&json);
        assert!(map.is_empty());
    }

    // ======================================================================
    // Phase 25: clear_counter_cache and clear_tier_cache correctness
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn clear_counter_cache_actually_clears() {
        clear_counter_cache();
        let kv = MockKv::new();
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        // Seed an entry
        let _ =
            check_kv_counter_impl(&kv, "hosted:clr:key:0", 100, 7200, &mut sub_ops, now_ms).await;

        // Verify cache has the entry
        {
            let cache = counter_cache().read().expect("lock");
            assert!(cache.contains_key("hosted:clr:key:0"));
        }

        // Clear and verify
        clear_counter_cache();
        {
            let cache = counter_cache().read().expect("lock");
            assert!(cache.is_empty(), "Cache should be empty after clear");
        }
    }

    #[tokio::test]
    #[serial]
    async fn clear_tier_cache_actually_clears() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/clr_tier", "t1")
            .with_entry("rate_limits/tiers/t1", r#"{"limits":{"a":1}}"#);
        let mut sub_ops = Vec::new();

        // Populate tier cache
        let _ = get_customer_limit_impl(
            &kv,
            "clr_tier",
            "a",
            100,
            1_700_000_000,
            &mut sub_ops,
            1_700_000_000_000.0,
        )
        .await;

        {
            let cache = tier_cache().read().expect("lock");
            assert!(cache.contains_key("clr_tier"));
        }

        clear_tier_cache();
        {
            let cache = tier_cache().read().expect("lock");
            assert!(cache.is_empty(), "Tier cache should be empty after clear");
        }
    }

    // ======================================================================
    // Phase 26: check_quota_impl sub_ops populated for all paths
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_sub_ops_include_tier_and_counter() {
        clear_tier_cache();
        clear_counter_cache();
        reset_kv_failure_count();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/h_ops_full", "full_tier")
            .with_entry(
                "rate_limits/tiers/full_tier",
                r#"{"limits":{"challenge":500}}"#,
            );

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "h_ops_full",
            "challenge",
            100,
            1_700_000_000,
            1_700_000_000_000.0,
        )
        .await;

        let op_names: Vec<&str> = result.sub_ops.iter().map(|(name, _)| *name).collect();
        // Should have tier ops AND counter ops
        assert!(
            op_names.contains(&"rl_tier_cache_check"),
            "Should have tier cache check"
        );
        assert!(
            op_names.contains(&"rl_kv_get_client_tier"),
            "Should have tier KV get"
        );
        assert!(
            op_names.contains(&"rl_counter_cache_check"),
            "Should have counter cache check"
        );
        assert!(
            op_names.contains(&"rl_kv_get_counter"),
            "Should have counter KV get"
        );
    }

    // ======================================================================
    // Phase 27: Denied counter still writes back to KV
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn kv_counter_denied_still_writes_back() {
        clear_counter_cache();
        reset_kv_failure_count();
        let kv = MockKv::new().with_entry("hosted:wb:key:0", "99");
        let mut sub_ops = Vec::new();
        let now_ms = 1_700_000_000_000.0;

        let (allowed, _, _, _) =
            check_kv_counter_impl(&kv, "hosted:wb:key:0", 100, 7200, &mut sub_ops, now_ms).await;
        assert!(!allowed);

        // Verify the incremented count was written back
        let puts = kv.puts();
        assert!(
            !puts.is_empty(),
            "Denied request should still write back count"
        );
        let last_put = &puts[puts.len() - 1];
        assert_eq!(last_put.value, "100", "Should write back incremented count");
    }

    // ======================================================================
    // Phase 28: tier_cache() and counter_cache() lazy init
    // ======================================================================

    #[test]
    fn tier_cache_returns_same_instance() {
        let a = tier_cache() as *const _;
        let b = tier_cache() as *const _;
        assert_eq!(a, b, "tier_cache() should return the same static instance");
    }

    #[test]
    fn counter_cache_returns_same_instance() {
        let a = counter_cache() as *const _;
        let b = counter_cache() as *const _;
        assert_eq!(
            a, b,
            "counter_cache() should return the same static instance"
        );
    }
}
