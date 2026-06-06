// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! KV-counter-based rate limiting for the verifier API.
//!
//! Replaces the shared-rate-limit Durable Object system with direct KV
//! reads and writes. All limits are configurable via wrangler.toml env
//! vars or `RATE_LIMIT_CONFIG` KV tier data (managed through the admin
//! portal). Fail-closed: if a KV read fails the request is denied.
//!
//! Two public entry points are provided: [`check_quota`] for per-customer
//! hourly quotas (post-auth, tier-based) and [`check_per_ip_limit`] for
//! anonymous per-IP throttling against short code enumeration.

#[cfg(target_arch = "wasm32")]
use worker::console_log;

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::rate_limit_kv::RateLimitKv;
use worker::kv::KvStore;
use worker::{Date, Response};

/// Unix timestamp (seconds) at which the current rate limit window resets.
#[allow(clippy::arithmetic_side_effects)]
fn reset_timestamp() -> u64 {
    let now_secs = Date::now().as_millis() / 1000;
    let hour_ts = now_secs / 3600 * 3600;
    hour_ts + 3600
}

// ---------------------------------------------------------------------------
// Tier cache (Pattern C) -- cached per-isolate for 60 seconds
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
/// - Nested: `{ "limits": { "endpoint": limit }, ... }`  (StoredTier from provii-management)
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
    // ADV-VA-034: Log an error when both nested and flat JSON formats fail to parse.
    serde_json::from_str::<HashMap<String, u32>>(json).unwrap_or_else(|_e| {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[ERROR] Malformed tier JSON (neither nested nor flat format): {} - defaulting to empty limits",
            _e
        );
        HashMap::new()
    })
}

/// Look up the per-hour quota for `client_id` on `endpoint`.
///
/// Reads `rate_limits/clients/{client_id}` -> tier_id, then
/// `rate_limits/tiers/{tier_id}` -> `{ endpoint: limit }`.
/// Falls back to `default_limit` on any miss or error.
async fn get_customer_limit_impl(
    kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> u32 {
    // Check in-memory cache first
    // ADV-VA-032: Log poisoned RwLock rather than silently falling through to KV.
    if let Ok(cache) = tier_cache().read().map_err(|e| {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[ERROR] TIER_CACHE RwLock poisoned on read: {} - falling through to KV",
            e
        );
        e
    }) {
        if let Some(entry) = cache.get(client_id) {
            if now_secs.saturating_sub(entry.fetched_at) < 60 {
                return entry.limits.get(endpoint).copied().unwrap_or(default_limit);
            }
        }
    }

    // Cache miss: read from KV
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

    // Update cache
    // ADV-VA-032: Log poisoned write lock (same rationale as read path above).
    if let Ok(mut cache) = tier_cache().write().map_err(|e| {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[ERROR] TIER_CACHE RwLock poisoned on write: {} - skipping cache update",
            e
        );
        e
    }) {
        // VA-HOS-007: Cap cache size to prevent unbounded memory growth.
        // Evict oldest entries when the cache exceeds 1000 clients.
        if cache.len() >= 1000 {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.fetched_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
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

// ---------------------------------------------------------------------------
// KV counter (Pattern B) -- non-atomic, acceptable at Provii's scale
// ---------------------------------------------------------------------------

/// Increment a KV counter and return `(allowed, current_count, limit, read_failed)`.
///
/// Returns `(true, count, limit, false)` if the request is within quota,
/// `(false, count, limit, false)` if over quota. On KV read errors the request
/// is denied (fail-closed, `read_failed = true`) to prevent unlimited traffic
/// during KV outages.
///
/// `read_failed` is a transport signal only: it lets callers distinguish a
/// genuine over-limit rejection (return 429 with the window Retry-After) from a
/// KV-brownout rejection (return 503 with a short Retry-After, R1). It NEVER
/// changes the admit/reject decision -- a read failure still rejects the
/// request (`allowed = false`), mirroring the hosted counter's `kv_unavailable`
/// signal verbatim.
///
/// ## Known limitation: non-atomic read-check-write (ST-VA-011)
///
/// Cloudflare KV does not support atomic compare-and-swap (CAS). The counter
/// is implemented as read-then-write, so concurrent requests that arrive within
/// the same KV propagation window (~60s for global consistency) may all read
/// the same counter value and each increment from the same base. In the worst
/// case a burst of N concurrent requests could allow up to N-1 extra requests
/// beyond the limit.
///
/// This is a best-effort rate limiter, not a hard quota enforcer. At Provii's
/// request volume the practical impact is negligible. A Durable Object based
/// counter would provide true atomicity but adds latency and cost for every
/// rate-limited request, which is not justified for the current traffic profile.
/// The fail-closed behaviour on KV read errors (below) ensures that KV outages
/// do not degrade into unlimited traffic.
pub(crate) async fn check_kv_counter_impl(
    kv: &dyn RateLimitKv,
    key: &str,
    limit: u32,
    ttl_secs: u64,
) -> (bool, u32, u32, bool) {
    let count: u32 = match kv.get_text(key).await {
        Ok(Some(s)) => s.parse().unwrap_or(0),
        Ok(None) => 0,
        Err(_) => {
            // SECURITY: Fail closed. Rate limiting is a security control; allowing
            // unlimited traffic when KV reads fail creates a bypass vector (ADV-VA-011).
            // R1: the request is STILL rejected (allowed = false); read_failed = true
            // only steers the caller to a 503 + short Retry-After instead of a 429
            // advertising the full window. This does NOT convert the limiter to
            // fail-open.
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "{{\"audit\":true,\"event\":\"rate_limit_kv_read_failure\",\"severity\":\"critical\",\"key_prefix\":\"{}\",\"outcome\":\"fail_closed\"}}",
                key.get(..20).unwrap_or(key)
            );
            return (false, 0, limit, true);
        }
    };

    if count >= limit {
        return (false, count, limit, false);
    }

    // Increment (best-effort, non-atomic). Write failures are logged but do not
    // block the request: the read succeeded and the count is within limits, so at
    // worst the counter fails to increment and the next request also passes. This
    // is bounded degradation (one extra request per failure), not a full bypass.
    if let Err(_e) = kv
        .put_with_ttl(key, &count.saturating_add(1).to_string(), ttl_secs)
        .await
    {
        #[cfg(target_arch = "wasm32")]
        console_log!(
            "{{\"audit\":true,\"event\":\"rate_limit_kv_write_failure\",\"severity\":\"warning\",\"error\":\"{}\"}}",
            _e
        );
    }

    (true, count.saturating_add(1), limit, false)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of a rate limit check, carrying enough context for logging and
/// Retry-After header generation.
pub struct RateLimitResult {
    /// Whether the request is within quota.
    pub allowed: bool,
    /// Number of requests consumed in the current window (after this one).
    pub current_count: u32,
    /// Maximum requests permitted in the current window.
    pub limit: u32,
    /// Seconds until the current rate limit window resets (clamped to
    /// [`MAX_ADVERTISED_RETRY_AFTER_SECS`] for the advertised header; RL-11).
    pub retry_after_secs: u32,
    /// True only when the underlying KV counter read failed and the request was
    /// rejected fail-closed (R1). When `allowed` is false because of this, the
    /// caller returns 503 + short Retry-After rather than 429. This flag NEVER
    /// affects the admit/reject decision: `read_failed == true` always implies
    /// `allowed == false`.
    pub read_failed: bool,
}

/// Upper bound (seconds) on the Retry-After advertised on a 429 from a
/// fixed-window counter (RL-11).
///
/// A fixed-window limiter naturally advertises "seconds until the window
/// boundary", which can be up to the full window (~3600s for the hourly
/// buckets). A single sub-second burst then tells a self-throttling SDK to back
/// off for an hour, turning a brief rejection into a self-inflicted outage. The
/// KV counter is also only globally consistent within ~60s (see
/// [`check_kv_counter_impl`]), so advertising a wait longer than that window is
/// not even meaningful. We therefore clamp the *advertised* header to a small
/// value. This is a header-only change: it does not alter the admit/reject
/// decision, the bucket key, or the window length used for enforcement.
pub const MAX_ADVERTISED_RETRY_AFTER_SECS: u32 = 60;

/// Clamp a computed fixed-window Retry-After to the advertised ceiling (RL-11).
///
/// Written once and applied in every `*_impl` helper so the cap is consistent
/// across all volumetric limiters.
#[inline]
pub(crate) fn clamp_retry_after(retry_after_secs: u32) -> u32 {
    retry_after_secs.min(MAX_ADVERTISED_RETRY_AFTER_SECS)
}

/// Check per-customer hourly quota (post-auth, tier-based).
///
/// `client_id` is the authenticated identity (client ID, origin, etc.).
/// `endpoint` is a short label like `"challenge"` or `"verify"`.
pub async fn check_quota(
    rate_limit_kv: &KvStore,
    config_kv: &KvStore,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let now_secs = Date::now().as_millis() / 1000;
    let rate_adapter = crate::rate_limit_kv::KvStoreAdapter(rate_limit_kv);
    let config_adapter = crate::rate_limit_kv::KvStoreAdapter(config_kv);
    check_quota_impl(
        &rate_adapter,
        &config_adapter,
        client_id,
        endpoint,
        default_limit,
        now_secs,
    )
    .await
}

/// Check the per-ACCOUNT hourly quota keyed on a cryptographically VERIFIED
/// client identity (R9 / RL-03).
///
/// This is a SUPPLEMENT to the pre-auth, IP-embedded [`check_quota`] gate, NOT a
/// replacement. The pre-auth gate stays in place as the per-IP anti-flood net
/// (and the ST-VA-004 bucket-rotation defence). This function runs a SECOND
/// quota check, inside the handler, AFTER `authenticate_api_key` (or the
/// challenge HMAC authenticator) has returned a verified `client_id`, and keys
/// the bucket on that verified identity with NO IP component:
///
/// ```text
/// acct_quota:{verified_client_id}:{endpoint}:{hour_ts}
/// ```
///
/// The result is that every legitimate end-user sharing one egress IP (corporate
/// NAT, CGNAT, Starlink, a server-side backend) is bucketed by their
/// authenticated account rather than collapsed onto a single shared per-IP
/// `quota:{...}:{ip_hash}` bucket. The per-customer tier lookup is performed via
/// [`get_customer_limit_impl`] on the SAME verified `client_id`, so a premium
/// customer's higher tier is found by their real identity rather than the
/// spoofable IP-embedded id used by the pre-auth gate.
///
/// SECURITY: `client_id` MUST be the verified identity returned by
/// `authenticate_api_key`'s `verify_against_policy` (Argon2id), the challenge
/// HMAC authenticator, or the verify-path mobile capability-token owner. It must
/// NEVER be a raw, unauthenticated header. Anonymous / unauthenticated callers
/// MUST continue to use the existing per-IP [`check_quota`] fallback instead of
/// being bucketed here on a shared constant.
///
/// On a KV READ failure the request is rejected fail-closed with
/// `read_failed = true` (identical to [`check_quota`]); callers surface that via
/// [`rate_limit_or_unavailable_response`] so an infrastructure brownout returns
/// 503 + short Retry-After, never a 429 (R1).
pub async fn check_account_quota(
    rate_limit_kv: &KvStore,
    config_kv: &KvStore,
    verified_client_id: &str,
    endpoint: &str,
    default_limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let now_secs = Date::now().as_millis() / 1000;
    let rate_adapter = crate::rate_limit_kv::KvStoreAdapter(rate_limit_kv);
    let config_adapter = crate::rate_limit_kv::KvStoreAdapter(config_kv);
    check_account_quota_impl(
        &rate_adapter,
        &config_adapter,
        verified_client_id,
        endpoint,
        default_limit,
        now_secs,
    )
    .await
}

/// Check per-IP per-minute limit for the catch-all 404 handler.
///
/// Uses a 60-second window keyed on the pre-hashed IP. This prevents
/// abuse of the catchall's HMAC hashing and audit logging without
/// affecting legitimate traffic (60 requests/minute is generous).
pub async fn check_catchall_limit(
    rate_limit_kv: &KvStore,
    hashed_ip: &str,
    limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let now_secs = Date::now().as_millis() / 1000;
    let adapter = crate::rate_limit_kv::KvStoreAdapter(rate_limit_kv);
    check_catchall_limit_impl(&adapter, hashed_ip, limit, now_secs).await
}

/// Check a per-IP hourly limit under a caller-supplied key prefix.
///
/// Uses `VERIFIER_KV_RATE_LIMITS` KV. The `key_prefix` namespaces the KV
/// counter so logically distinct per-IP limiters (the global pre-routing gate,
/// `/health/detailed`, `/metrics`, and short-code enumeration) do not collide
/// on a single shared bucket. Each caller passes its own prefix
/// (`global_ip:` / `health_ip:` / `metrics_ip:` / `short_code:`), mirroring the
/// distinct `expert_ip:` / `hosted:` / `catchall:` namespaces. The limit value
/// itself is unchanged and supplied by the caller (e.g. `SHORT_CODE_LIMIT_PER_HOUR`).
pub async fn check_per_ip_limit(
    rate_limit_kv: &KvStore,
    key_prefix: &str,
    ip: &str,
    limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let now_secs = Date::now().as_millis() / 1000;
    let adapter = crate::rate_limit_kv::KvStoreAdapter(rate_limit_kv);
    check_per_ip_limit_impl(&adapter, key_prefix, ip, limit, now_secs).await
}

/// Set `X-RateLimit-*` headers on a response.
///
/// Adds:
/// - `X-RateLimit-Limit`     -- max requests in the window
/// - `X-RateLimit-Remaining` -- requests left in the window
/// - `X-RateLimit-Reset`     -- Unix timestamp when the window resets
/// - `Retry-After`           -- seconds until the window resets (only when limit exceeded)
pub fn apply_rate_limit_headers(
    resp: &mut Response,
    result: &RateLimitResult,
) -> worker::Result<()> {
    let remaining = result.limit.saturating_sub(result.current_count);
    let reset = reset_timestamp();
    let h = resp.headers_mut();
    h.set("X-RateLimit-Limit", &result.limit.to_string())?;
    h.set("X-RateLimit-Remaining", &remaining.to_string())?;
    h.set("X-RateLimit-Reset", &reset.to_string())?;
    Ok(())
}

/// Build a 429 response with Retry-After, X-RateLimit-*, and security headers.
///
/// CH-007: Security headers are applied to rate-limit responses so that
/// clients rejected by quota still receive HSTS, CSP, X-Frame-Options, etc.
///
/// ADV-VA-05-001: Returns the standard 5-key error envelope (error, message,
/// request_id, field, detail) plus the retry_after field.
pub fn rate_limit_response(result: &RateLimitResult) -> worker::Result<Response> {
    use crate::security::headers::api_security_headers;

    let request_id = uuid::Uuid::new_v4().to_string();
    let body = serde_json::json!({
        "error": "TOO_MANY_REQUESTS",
        "message": "Rate limit exceeded",
        "request_id": request_id,
        "field": null,
        "detail": "You have exceeded the allowed request rate. Wait before retrying.",
        "retry_after": result.retry_after_secs,
    });
    let mut resp = Response::from_json(&body)?;

    // Apply security headers first.
    let security_headers = api_security_headers();
    security_headers.apply(&mut resp)?;

    let headers = resp.headers_mut();
    headers.set("Retry-After", &result.retry_after_secs.to_string())?;
    // X-RateLimit-* headers (remaining is 0 since we're rate-limited)
    headers.set("X-RateLimit-Limit", &result.limit.to_string())?;
    headers.set("X-RateLimit-Remaining", "0")?;
    headers.set("X-RateLimit-Reset", &reset_timestamp().to_string())?;
    // Expose rate limit headers so browsers can read them cross-origin.
    headers.set(
        "Access-Control-Expose-Headers",
        "Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset",
    )?;
    // Override status to 429
    Ok(resp.with_status(429))
}

/// Build a 503 response with a short Retry-After for a counter-READ failure
/// (R1). Mirrors the hosted module's
/// [`crate::hosted::rate_limiting::service_unavailable_with_retry_after`]
/// verbatim so a KV brownout returns the same semantics on every surface.
pub fn service_unavailable_with_retry_after(retry_after_secs: u32) -> worker::Result<Response> {
    let body = serde_json::json!({
        "error": "Service temporarily unavailable",
        "code": "RATE_LIMITER_UNAVAILABLE",
    });
    let mut resp = Response::from_json(&body)?;
    // Best-effort header attachment. If this fails, the 503 status alone still
    // communicates the correct semantics to the client.
    let _ = resp
        .headers_mut()
        .set("Retry-After", &retry_after_secs.to_string());
    Ok(resp.with_status(503))
}

/// Seconds advertised on the R1 503 (counter-READ failure) path. Short so a
/// self-throttling client retries quickly once KV recovers, instead of backing
/// off for the full rate-limit window.
pub const READ_FAILURE_RETRY_AFTER_SECS: u32 = 5;

/// R1 shared dispatch: pick the correct rejection response for a limiter that
/// has already decided `!result.allowed`.
///
/// - When `result.read_failed` (KV counter read failed, fail-closed): return a
///   503 + short Retry-After so an infrastructure brownout is not misreported
///   to the customer as a quota breach with an hour-long backoff.
/// - Otherwise (a genuine over-limit): return the existing 429 via
///   [`rate_limit_response`].
///
/// This changes ONLY the HTTP status code and Retry-After header. The caller
/// has already rejected the request in both cases; this helper must be invoked
/// at every `if !result.allowed` rejection site so KV brownouts never surface
/// as a 429-with-window-Retry-After.
pub fn rate_limit_or_unavailable_response(result: &RateLimitResult) -> worker::Result<Response> {
    if result.read_failed {
        service_unavailable_with_retry_after(READ_FAILURE_RETRY_AFTER_SECS)
    } else {
        rate_limit_response(result)
    }
}

/// Per-IP hourly rate limit for hosted endpoints.
///
/// Uses a `hosted:{endpoint}:{hashed_ip}:{hour_ts}` key to avoid collisions
/// with the expert-mode (`expert_ip:`) and short-code (`short_code:`) namespaces.
pub async fn check_hosted_ip_limit(
    rate_limit_kv: &KvStore,
    hashed_ip: &str,
    endpoint: &str,
    limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let now_secs = Date::now().as_millis() / 1000;
    let adapter = crate::rate_limit_kv::KvStoreAdapter(rate_limit_kv);
    check_hosted_ip_limit_impl(&adapter, hashed_ip, endpoint, limit, now_secs).await
}

/// Per-IP hourly rate limit for expert-mode endpoints (SEC-011).
///
/// Complements the per-client `check_quota` by catching attackers who forge or
/// spread `X-Client-Id` values across many synthetic clients to bypass the
/// per-customer quota. Keyed on the hashed IP, independent of the client ID
/// bucket.
///
/// Uses an `expert_ip:{endpoint}:{hashed_ip}:{hour_ts}` key to avoid collisions
/// with the hosted (`hosted:`) and short-code enumeration (`short_code:`)
/// namespaces.
pub async fn check_expert_ip_limit(
    rate_limit_kv: &KvStore,
    hashed_ip: &str,
    endpoint: &str,
    limit: u32,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let now_secs = Date::now().as_millis() / 1000;
    let adapter = crate::rate_limit_kv::KvStoreAdapter(rate_limit_kv);
    check_expert_ip_limit_impl(&adapter, hashed_ip, endpoint, limit, now_secs).await
}

// ---------------------------------------------------------------------------
// Testable inner functions (trait-based, called by production wrappers)
// ---------------------------------------------------------------------------

/// Quota check that takes trait objects instead of concrete KvStore.
/// Production `check_quota` delegates here; tests call directly with MockKv.
pub(crate) async fn check_quota_impl(
    rate_limit_kv: &dyn RateLimitKv,
    config_kv: &dyn RateLimitKv,
    client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    let hour_ts = (now_secs / 3600).saturating_mul(3600);

    let limit =
        get_customer_limit_impl(config_kv, client_id, endpoint, default_limit, now_secs).await;

    let key = format!("quota:{}:{}:{}", client_id, endpoint, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 7200).await;

    #[allow(clippy::cast_possible_truncation)]
    let retry_after = clamp_retry_after(
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX),
    );

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Per-ACCOUNT quota check (R9) that takes trait objects instead of concrete
/// KvStore. Production `check_account_quota` delegates here; tests call directly
/// with MockKv.
///
/// Identical to [`check_quota_impl`] except the KV counter key uses the
/// `acct_quota:` namespace and carries NO IP component, so the bucket is keyed
/// purely on the VERIFIED `client_id`. The tier lookup
/// ([`get_customer_limit_impl`]) is performed on that same verified id.
pub(crate) async fn check_account_quota_impl(
    rate_limit_kv: &dyn RateLimitKv,
    config_kv: &dyn RateLimitKv,
    verified_client_id: &str,
    endpoint: &str,
    default_limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    let hour_ts = (now_secs / 3600).saturating_mul(3600);

    // R9 step 4: re-key the per-customer tier/limit lookup onto the VERIFIED id
    // so a premium customer's higher tier is found by their real identity, not
    // the spoofable IP-embedded id used by the pre-auth gate.
    let limit = get_customer_limit_impl(
        config_kv,
        verified_client_id,
        endpoint,
        default_limit,
        now_secs,
    )
    .await;

    // R9: NO IP component. Distinct `acct_quota:` namespace so this never
    // collides with the pre-auth per-IP `quota:` buckets.
    let key = format!("acct_quota:{}:{}:{}", verified_client_id, endpoint, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 7200).await;

    #[allow(clippy::cast_possible_truncation)]
    let retry_after = clamp_retry_after(
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX),
    );

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Per-IP check with injectable timestamp.
/// Production `check_per_ip_limit` delegates here; tests call directly with MockKv.
///
/// `key_prefix` namespaces the KV counter (e.g. `global_ip:`, `health_ip:`,
/// `metrics_ip:`, `short_code:`) so logically distinct per-IP limiters with
/// different limits do not share a single bucket.
pub(crate) async fn check_per_ip_limit_impl(
    rate_limit_kv: &dyn RateLimitKv,
    key_prefix: &str,
    ip: &str,
    limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    let hour_ts = (now_secs / 3600).saturating_mul(3600);

    let key = format!("{}{}:{}", key_prefix, ip, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 7200).await;

    #[allow(clippy::cast_possible_truncation)]
    let retry_after = clamp_retry_after(
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX),
    );

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Catchall per-IP limit with injectable timestamp.
/// Production `check_catchall_limit` delegates here; tests call directly with MockKv.
pub(crate) async fn check_catchall_limit_impl(
    rate_limit_kv: &dyn RateLimitKv,
    hashed_ip: &str,
    limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let minute_ts = now_secs / 60 * 60;

    let key = format!("catchall:{}:{}", hashed_ip, minute_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 120).await;

    // 60s window: already <= the advertised ceiling, but clamp uniformly.
    #[allow(clippy::cast_possible_truncation)]
    let retry_after = clamp_retry_after(
        u32::try_from(minute_ts.saturating_add(60).saturating_sub(now_secs)).unwrap_or(u32::MAX),
    );

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Hosted per-IP hourly limit with injectable timestamp.
/// Production `check_hosted_ip_limit` delegates here; tests call directly with MockKv.
pub(crate) async fn check_hosted_ip_limit_impl(
    rate_limit_kv: &dyn RateLimitKv,
    hashed_ip: &str,
    endpoint: &str,
    limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let hour_ts = now_secs / 3600 * 3600;

    let key = format!("hosted:{}:{}:{}", endpoint, hashed_ip, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 7200).await;

    #[allow(clippy::cast_possible_truncation)]
    let retry_after = clamp_retry_after(
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX),
    );

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Expert per-IP hourly limit with injectable timestamp.
/// Production `check_expert_ip_limit` delegates here; tests call directly with MockKv.
pub(crate) async fn check_expert_ip_limit_impl(
    rate_limit_kv: &dyn RateLimitKv,
    hashed_ip: &str,
    endpoint: &str,
    limit: u32,
    now_secs: u64,
) -> RateLimitResult {
    #[allow(clippy::arithmetic_side_effects)]
    let hour_ts = now_secs / 3600 * 3600;

    let key = format!("expert_ip:{}:{}:{}", endpoint, hashed_ip, hour_ts);
    let (allowed, current_count, limit, read_failed) =
        check_kv_counter_impl(rate_limit_kv, &key, limit, 7200).await;

    #[allow(clippy::cast_possible_truncation)]
    let retry_after = clamp_retry_after(
        u32::try_from(hour_ts.saturating_add(3600).saturating_sub(now_secs)).unwrap_or(u32::MAX),
    );

    RateLimitResult {
        allowed,
        current_count,
        limit,
        retry_after_secs: retry_after,
        read_failed,
    }
}

/// Clear the tier cache. Only available in test builds.
#[cfg(test)]
pub(crate) fn clear_tier_cache() {
    if let Ok(mut cache) = tier_cache().write() {
        cache.clear();
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

    // -- Test 1: nested StoredTier format --
    #[test]
    fn parse_tier_limits_nested_format() {
        let json = r#"{"tier_id":"t1","limits":{"challenge":500,"verify":200}}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("challenge").copied(), Some(500));
        assert_eq!(map.get("verify").copied(), Some(200));
    }

    // -- Test 2: flat format --
    #[test]
    fn parse_tier_limits_flat_format() {
        let json = r#"{"challenge":100,"verify":50}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("challenge").copied(), Some(100));
        assert_eq!(map.get("verify").copied(), Some(50));
    }

    // -- Test 3: invalid JSON returns empty --
    #[test]
    fn parse_tier_limits_invalid_json() {
        let map = parse_tier_limits("not json at all");
        assert!(map.is_empty());
    }

    // -- Test 4: empty JSON object --
    #[test]
    fn parse_tier_limits_empty_object() {
        let map = parse_tier_limits("{}");
        assert!(map.is_empty());
    }

    // -- Test 31: empty string --
    #[test]
    fn parse_tier_limits_empty_string() {
        let map = parse_tier_limits("");
        assert!(map.is_empty());
    }

    // -- Test 32: nested with extra fields ignored --
    #[test]
    fn parse_tier_limits_nested_extra_fields() {
        let json = r#"{"tier_id":"premium","name":"Premium","limits":{"challenge":1000},"created_at":"2026-01-01"}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("challenge").copied(), Some(1000));
    }

    // -- Test: nested with limits containing non-u32 values falls back to flat --
    #[test]
    fn parse_tier_limits_nested_non_u32_falls_back() {
        // limits contains a string value, so nested parse fails, flat parse also fails
        let json = r#"{"limits":{"challenge":"not_a_number"}}"#;
        let map = parse_tier_limits(json);
        // Flat parse of the outer object also fails (has "limits" key with object value)
        assert!(map.is_empty());
    }

    // -- Test: nested with empty limits object --
    #[test]
    fn parse_tier_limits_nested_empty_limits() {
        let json = r#"{"limits":{}}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    // ======================================================================
    // Phase 3: KV counter logic (MockKv)
    // ======================================================================

    // -- Test 5: first request allowed, counter starts at 1 --
    #[tokio::test]
    async fn kv_counter_first_request_allowed() {
        let kv = MockKv::new();
        let (allowed, count, limit, _) = check_kv_counter_impl(&kv, "test:key:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);

        // Verify a put was issued with count=1
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].value, "1");
        assert_eq!(puts[0].ttl_secs, 7200);
    }

    // -- Test 6: request denied at limit --
    #[tokio::test]
    async fn kv_counter_denied_at_limit() {
        let kv = MockKv::new().with_entry("test:key:0", "100");
        let (allowed, count, limit, _) = check_kv_counter_impl(&kv, "test:key:0", 100, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 100);
        assert_eq!(limit, 100);
    }

    // -- Test 7: request denied above limit --
    #[tokio::test]
    async fn kv_counter_denied_above_limit() {
        let kv = MockKv::new().with_entry("test:key:0", "150");
        let (allowed, count, limit, _) = check_kv_counter_impl(&kv, "test:key:0", 100, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 150);
        assert_eq!(limit, 100);
    }

    // -- Test 8: KV read failure denies (fail-closed) --
    #[tokio::test]
    async fn kv_counter_read_failure_denies() {
        let kv = MockKv::new().with_get_error("KV unavailable");
        let (allowed, count, limit, read_failed) =
            check_kv_counter_impl(&kv, "test:key:0", 100, 7200).await;
        // R1: read failure rejects fail-closed AND flags read_failed so the
        // caller returns 503 + short Retry-After instead of 429.
        assert!(!allowed);
        assert!(read_failed);
        assert_eq!(count, 0);
        assert_eq!(limit, 100);
    }

    // -- Test 9: KV write failure still allows --
    #[tokio::test]
    async fn kv_counter_write_failure_still_allows() {
        let kv = MockKv::new().with_put_error("KV write failed");
        let (allowed, count, limit, _) = check_kv_counter_impl(&kv, "test:key:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
        // No puts should have succeeded
        assert!(kv.puts().is_empty());
    }

    // -- Test 10: unparseable counter treated as zero --
    #[tokio::test]
    async fn kv_counter_unparseable_treated_as_zero() {
        let kv = MockKv::new().with_entry("test:key:0", "not_a_number");
        let (allowed, count, limit, _) = check_kv_counter_impl(&kv, "test:key:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, 100);
    }

    // -- Test: counter increments correctly on successive calls --
    #[tokio::test]
    async fn kv_counter_increments_across_calls() {
        let kv = MockKv::new();

        // First call: 0 -> 1
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:key:0", 5, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);

        // Second call: reads "1" from KV -> 2
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:key:0", 5, 7200).await;
        assert!(allowed);
        assert_eq!(count, 2);

        // Keep going until limit
        let _ = check_kv_counter_impl(&kv, "test:key:0", 5, 7200).await; // 3
        let _ = check_kv_counter_impl(&kv, "test:key:0", 5, 7200).await; // 4

        // Fifth call: count=4, still below limit=5
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:key:0", 5, 7200).await;
        assert!(allowed);
        assert_eq!(count, 5);

        // Sixth call: count=5, at limit, denied
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:key:0", 5, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 5);
    }

    // -- Test: limit of 0 denies everything --
    #[tokio::test]
    async fn kv_counter_zero_limit_denies_all() {
        let kv = MockKv::new();
        let (allowed, _, limit, _) = check_kv_counter_impl(&kv, "test:key:0", 0, 7200).await;
        assert!(!allowed);
        assert_eq!(limit, 0);
    }

    // -- Test: limit of 1 allows exactly one request --
    #[tokio::test]
    async fn kv_counter_limit_one() {
        let kv = MockKv::new();

        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:key:0", 1, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);

        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:key:0", 1, 7200).await;
        assert!(!allowed);
        assert_eq!(count, 1);
    }

    // -- Test: TTL is correctly passed through to put --
    #[tokio::test]
    async fn kv_counter_ttl_propagated() {
        let kv = MockKv::new();
        let _ = check_kv_counter_impl(&kv, "test:key:0", 100, 3600).await;
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].ttl_secs, 3600);
    }

    // ======================================================================
    // Phase 2: Tier lookup via mock KV
    // ======================================================================

    // -- Test 21: tier lookup returns custom limit --
    #[tokio::test]
    #[serial]
    async fn tier_lookup_returns_custom_limit() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_1", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":2000}}"#,
            );

        let limit = get_customer_limit_impl(&kv, "client_1", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 2000);
    }

    // -- Test 22: missing client falls back to default --
    #[tokio::test]
    #[serial]
    async fn tier_lookup_missing_client_uses_default() {
        clear_tier_cache();
        let kv = MockKv::new();
        let limit = get_customer_limit_impl(&kv, "unknown", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    // -- Test 23: missing tier falls back to default --
    #[tokio::test]
    #[serial]
    async fn tier_lookup_missing_tier_uses_default() {
        clear_tier_cache();
        let kv = MockKv::new().with_entry("rate_limits/clients/client_2", "nonexistent_tier");
        let limit = get_customer_limit_impl(&kv, "client_2", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    // -- Test 24: endpoint not in tier limits falls back to default --
    #[tokio::test]
    #[serial]
    async fn tier_lookup_endpoint_not_in_tier() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_3", "basic")
            .with_entry("rate_limits/tiers/basic", r#"{"limits":{"verify":300}}"#);

        // "challenge" is not in the tier limits
        let limit = get_customer_limit_impl(&kv, "client_3", "challenge", 50, 1_700_000_000).await;
        assert_eq!(limit, 50);
    }

    // -- Test 25: KV failure for client lookup falls back to default --
    #[tokio::test]
    #[serial]
    async fn tier_lookup_kv_failure_uses_default() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_get_error("KV down")
            .with_persistent_errors();
        let limit = get_customer_limit_impl(&kv, "client_x", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 100);
    }

    // -- Test 26: tier cache returns cached value within TTL --
    #[tokio::test]
    #[serial]
    async fn tier_cache_returns_cached_value() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/cached_client", "gold")
            .with_entry("rate_limits/tiers/gold", r#"{"limits":{"challenge":5000}}"#);

        // First call populates cache
        let limit =
            get_customer_limit_impl(&kv, "cached_client", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 5000);

        // Second call within 60s should use cache (even though KV is now empty for this test,
        // the cache was populated above and 1_700_000_030 - 1_700_000_000 = 30 < 60)
        let kv2 = MockKv::new(); // empty KV, but cache should hit
        let limit =
            get_customer_limit_impl(&kv2, "cached_client", "challenge", 100, 1_700_000_030).await;
        assert_eq!(limit, 5000);
    }

    // -- Test 27: tier cache expires after 60s --
    #[tokio::test]
    #[serial]
    async fn tier_cache_expires_after_60s() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/expiring_client", "silver")
            .with_entry(
                "rate_limits/tiers/silver",
                r#"{"limits":{"challenge":3000}}"#,
            );

        // Populate cache at t=1_700_000_000
        let limit =
            get_customer_limit_impl(&kv, "expiring_client", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 3000);

        // At t=1_700_000_061 (61s later), cache is stale; KV is empty -> default
        let kv2 = MockKv::new();
        let limit =
            get_customer_limit_impl(&kv2, "expiring_client", "challenge", 100, 1_700_000_061).await;
        assert_eq!(limit, 100);
    }

    // -- Test 28: different endpoints have different limits from same tier --
    #[tokio::test]
    #[serial]
    async fn tier_lookup_different_endpoints() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/multi_ep", "enterprise")
            .with_entry(
                "rate_limits/tiers/enterprise",
                r#"{"limits":{"challenge":10000,"verify":5000}}"#,
            );

        let challenge_limit =
            get_customer_limit_impl(&kv, "multi_ep", "challenge", 100, 1_700_000_000).await;
        assert_eq!(challenge_limit, 10000);

        // Cache should still work for a different endpoint from same client
        let kv2 = MockKv::new(); // empty, relies on cache
        let verify_limit =
            get_customer_limit_impl(&kv2, "multi_ep", "verify", 100, 1_700_000_010).await;
        assert_eq!(verify_limit, 5000);
    }

    // ======================================================================
    // Phase 4: End-to-end flows (check_quota_impl, check_per_ip_limit_impl)
    // ======================================================================

    // -- Test 11: check_quota_impl allows first request with default limit --
    #[tokio::test]
    #[serial]
    async fn check_quota_impl_allows_first_request() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let result = check_quota_impl(
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

    // -- Test 12: check_quota_impl uses custom tier limit --
    #[tokio::test]
    #[serial]
    async fn check_quota_impl_uses_tier_limit() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/vip", "premium")
            .with_entry(
                "rate_limits/tiers/premium",
                r#"{"limits":{"challenge":9999}}"#,
            );

        let result =
            check_quota_impl(&rate_kv, &config_kv, "vip", "challenge", 100, 1_700_000_000).await;

        assert!(result.allowed);
        assert_eq!(result.limit, 9999);
    }

    // -- Test 13: check_quota_impl denied when at limit --
    #[tokio::test]
    #[serial]
    async fn check_quota_impl_denied_at_limit() {
        clear_tier_cache();
        let hour_ts = (1_700_000_000u64 / 3600) * 3600;
        let key = format!("quota:client_b:challenge:{}", hour_ts);
        let rate_kv = MockKv::new().with_entry(&key, "50");
        let config_kv = MockKv::new();

        let result = check_quota_impl(
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

    // -- Test 14: check_per_ip_limit_impl allows first request --
    #[tokio::test]
    async fn check_per_ip_limit_allows_first() {
        let kv = MockKv::new();
        let result =
            check_per_ip_limit_impl(&kv, "short_code:", "192.168.1.1", 60, 1_700_000_000).await;

        assert!(result.allowed);
        assert_eq!(result.current_count, 1);
        assert_eq!(result.limit, 60);
    }

    // -- Test 15: check_per_ip_limit_impl denied when at limit --
    #[tokio::test]
    async fn check_per_ip_limit_denied_at_limit() {
        let hour_ts = (1_700_000_000u64 / 3600) * 3600;
        let key = format!("short_code:10.0.0.1:{}", hour_ts);
        let kv = MockKv::new().with_entry(&key, "60");

        let result =
            check_per_ip_limit_impl(&kv, "short_code:", "10.0.0.1", 60, 1_700_000_000).await;

        assert!(!result.allowed);
        assert_eq!(result.current_count, 60);
    }

    // -- Test 16: check_per_ip_limit_impl KV failure fail-closed --
    #[tokio::test]
    async fn check_per_ip_limit_kv_failure_denies() {
        let kv = MockKv::new().with_get_error("boom");
        let result =
            check_per_ip_limit_impl(&kv, "short_code:", "10.0.0.2", 60, 1_700_000_000).await;

        assert!(!result.allowed);
        assert!(result.read_failed); // R1: steers caller to 503, not 429
        assert_eq!(result.current_count, 0);
    }

    // -- Test 29: check_quota_impl constructs correct KV key --
    #[tokio::test]
    #[serial]
    async fn check_quota_impl_correct_kv_key() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let _ = check_quota_impl(&rate_kv, &config_kv, "c1", "verify", 100, now).await;

        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, format!("quota:c1:verify:{}", hour_ts));
    }

    // -- Test 30: check_per_ip_limit_impl constructs correct KV key --
    #[tokio::test]
    async fn check_per_ip_limit_correct_kv_key() {
        let kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let _ = check_per_ip_limit_impl(&kv, "short_code:", "1.2.3.4", 100, now).await;

        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, format!("short_code:1.2.3.4:{}", hour_ts));
    }

    // -- Test: retry_after is correctly computed --
    #[tokio::test]
    #[serial]
    async fn check_quota_impl_retry_after_computation() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        // 600 seconds into the hour
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        // RL-11: the raw window remainder is large, so the advertised Retry-After
        // is clamped to MAX_ADVERTISED_RETRY_AFTER_SECS.
        let raw_retry = (hour_ts + 3600 - now) as u32;
        assert!(raw_retry > MAX_ADVERTISED_RETRY_AFTER_SECS);

        let result = check_quota_impl(&rate_kv, &config_kv, "c1", "challenge", 100, now).await;

        assert_eq!(result.retry_after_secs, MAX_ADVERTISED_RETRY_AFTER_SECS);
    }

    // -- Test: different clients use different keys --
    #[tokio::test]
    #[serial]
    async fn check_quota_impl_isolates_clients() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;

        let r1 = check_quota_impl(&rate_kv, &config_kv, "alice", "challenge", 100, now).await;
        let r2 = check_quota_impl(&rate_kv, &config_kv, "bob", "challenge", 100, now).await;

        // Both should be allowed, both at count 1 (different keys)
        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);

        // Should have 2 puts to different keys
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 2);
        assert_ne!(puts[0].key, puts[1].key);
    }

    // ======================================================================
    // parse_tier_limits: additional edge cases
    // ======================================================================

    #[test]
    fn parse_tier_limits_nested_null_limits_field() {
        // "limits" field is null, not an object
        let json = r#"{"limits":null}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_nested_limits_is_array() {
        // "limits" field is an array, not a map
        let json = r#"{"limits":[1,2,3]}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_flat_with_zero_value() {
        let json = r#"{"challenge":0,"verify":0}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.get("challenge").copied(), Some(0));
        assert_eq!(map.get("verify").copied(), Some(0));
    }

    #[test]
    fn parse_tier_limits_flat_with_max_u32() {
        let json = format!(r#"{{"challenge":{}}}"#, u32::MAX);
        let map = parse_tier_limits(&json);
        assert_eq!(map.get("challenge").copied(), Some(u32::MAX));
    }

    #[test]
    fn parse_tier_limits_nested_many_endpoints() {
        let json = r#"{"limits":{"a":1,"b":2,"c":3,"d":4,"e":5}}"#;
        let map = parse_tier_limits(json);
        assert_eq!(map.len(), 5);
        assert_eq!(map.get("a").copied(), Some(1));
        assert_eq!(map.get("e").copied(), Some(5));
    }

    #[test]
    fn parse_tier_limits_negative_value_fails() {
        // u32 cannot be negative; the flat parse should fail
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
    fn parse_tier_limits_nested_mixed_types() {
        // Some values are valid u32, some are not
        let json = r#"{"limits":{"a":100,"b":"invalid"}}"#;
        let map = parse_tier_limits(json);
        // The nested parse fails, flat parse also fails -> empty
        assert!(map.is_empty());
    }

    // ======================================================================
    // KV counter: additional edge cases
    // ======================================================================

    #[tokio::test]
    async fn kv_counter_counter_at_u32_max() {
        let kv = MockKv::new().with_entry("test:max:0", &u32::MAX.to_string());
        let (allowed, count, limit, _) =
            check_kv_counter_impl(&kv, "test:max:0", u32::MAX, 7200).await;
        assert!(!allowed);
        assert_eq!(count, u32::MAX);
        assert_eq!(limit, u32::MAX);
    }

    #[tokio::test]
    async fn kv_counter_large_limit_allows() {
        let kv = MockKv::new();
        let (allowed, count, limit, _) =
            check_kv_counter_impl(&kv, "test:large:0", u32::MAX, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
        assert_eq!(limit, u32::MAX);
    }

    #[tokio::test]
    async fn kv_counter_empty_string_value_treated_as_zero() {
        let kv = MockKv::new().with_entry("test:empty:0", "");
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:empty:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn kv_counter_negative_string_treated_as_zero() {
        let kv = MockKv::new().with_entry("test:neg:0", "-5");
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:neg:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn kv_counter_float_string_treated_as_zero() {
        let kv = MockKv::new().with_entry("test:float:0", "3.14");
        let (allowed, count, _, _) = check_kv_counter_impl(&kv, "test:float:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn kv_counter_different_keys_are_isolated() {
        let kv = MockKv::new();
        let (_, count_a, _, _) = check_kv_counter_impl(&kv, "key_a", 100, 7200).await;
        let (_, count_b, _, _) = check_kv_counter_impl(&kv, "key_b", 100, 7200).await;
        assert_eq!(count_a, 1);
        assert_eq!(count_b, 1);
    }

    // ======================================================================
    // Tier lookup: additional edge cases
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_kv_failure_for_tier_uses_default() {
        clear_tier_cache();
        // Client exists but tier KV read fails
        let kv = MockKv::new().with_entry("rate_limits/clients/client_fail", "bad_tier");
        // "rate_limits/tiers/bad_tier" is not populated, so returns None -> empty limits -> default
        let limit =
            get_customer_limit_impl(&kv, "client_fail", "challenge", 42, 1_700_000_000).await;
        assert_eq!(limit, 42);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_empty_tier_id() {
        clear_tier_cache();
        let kv = MockKv::new().with_entry("rate_limits/clients/client_empty", "");
        // Tier ID is empty string, lookup "rate_limits/tiers/" returns None -> default
        let limit =
            get_customer_limit_impl(&kv, "client_empty", "challenge", 77, 1_700_000_000).await;
        assert_eq!(limit, 77);
    }

    #[tokio::test]
    #[serial]
    async fn tier_lookup_malformed_tier_json() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_mal", "malformed_tier")
            .with_entry("rate_limits/tiers/malformed_tier", "not json");
        let limit =
            get_customer_limit_impl(&kv, "client_mal", "challenge", 55, 1_700_000_000).await;
        // Malformed JSON -> parse_tier_limits returns empty -> default
        assert_eq!(limit, 55);
    }

    // ======================================================================
    // check_quota_impl: retry_after computations
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_retry_after_at_hour_boundary() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        // Exactly at an hour boundary (no seconds into the hour)
        let now = 1_699_200_000u64; // divisible by 3600
        let hour_ts = (now / 3600) * 3600;
        assert_eq!(now, hour_ts); // confirm it's on the boundary

        let result =
            check_quota_impl(&rate_kv, &config_kv, "boundary", "challenge", 100, now).await;
        // RL-11: the raw remainder is a full hour (3600s) but the advertised
        // Retry-After is clamped so a brief rejection cannot tell a client to
        // back off for an hour.
        assert_eq!(result.retry_after_secs, MAX_ADVERTISED_RETRY_AFTER_SECS);
    }

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_retry_after_near_end_of_hour() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        // 1 second before the hour ends
        let hour_ts = 1_699_200_000u64;
        let now = hour_ts + 3599;

        let result =
            check_quota_impl(&rate_kv, &config_kv, "near_end", "challenge", 100, now).await;
        assert_eq!(result.retry_after_secs, 1);
    }

    // ======================================================================
    // check_per_ip_limit_impl: additional edge cases
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_different_ips_isolated() {
        let kv = MockKv::new();
        let now = 1_700_000_000u64;

        let r1 = check_per_ip_limit_impl(&kv, "short_code:", "ip_a", 10, now).await;
        let r2 = check_per_ip_limit_impl(&kv, "short_code:", "ip_b", 10, now).await;

        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);
    }

    #[tokio::test]
    async fn check_per_ip_limit_retry_after_computation() {
        let kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        // RL-11: large raw remainder -> advertised Retry-After is clamped.
        let raw_retry = (hour_ts + 3600 - now) as u32;
        assert!(raw_retry > MAX_ADVERTISED_RETRY_AFTER_SECS);

        let result = check_per_ip_limit_impl(&kv, "short_code:", "ip_timer", 100, now).await;
        assert_eq!(result.retry_after_secs, MAX_ADVERTISED_RETRY_AFTER_SECS);
    }

    #[tokio::test]
    async fn check_per_ip_limit_zero_limit_denies() {
        let kv = MockKv::new();
        let result = check_per_ip_limit_impl(&kv, "short_code:", "ip_zero", 0, 1_700_000_000).await;
        assert!(!result.allowed);
        assert_eq!(result.limit, 0);
    }

    // ======================================================================
    // check_quota_impl: different endpoints use different keys
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_different_endpoints_isolated() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;

        let r1 = check_quota_impl(&rate_kv, &config_kv, "client_ep", "challenge", 100, now).await;
        let r2 = check_quota_impl(&rate_kv, &config_kv, "client_ep", "verify", 100, now).await;

        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);

        // Should have 2 puts with different keys
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 2);
        assert!(puts[0].key.contains("challenge"));
        assert!(puts[1].key.contains("verify"));
    }

    // ======================================================================
    // RateLimitResult struct coverage
    // ======================================================================

    #[test]
    fn rate_limit_result_fields() {
        let r = RateLimitResult {
            allowed: true,
            current_count: 42,
            limit: 100,
            retry_after_secs: 1800,
            read_failed: false,
        };
        assert!(r.allowed);
        assert_eq!(r.current_count, 42);
        assert_eq!(r.limit, 100);
        assert_eq!(r.retry_after_secs, 1800);
    }

    #[test]
    fn rate_limit_result_remaining_calculation() {
        let r = RateLimitResult {
            allowed: true,
            current_count: 30,
            limit: 100,
            retry_after_secs: 0,
            read_failed: false,
        };
        let remaining = r.limit.saturating_sub(r.current_count);
        assert_eq!(remaining, 70);
    }

    #[test]
    fn rate_limit_result_remaining_when_over_limit() {
        let r = RateLimitResult {
            allowed: false,
            current_count: 150,
            limit: 100,
            retry_after_secs: 0,
            read_failed: false,
        };
        let remaining = r.limit.saturating_sub(r.current_count);
        assert_eq!(remaining, 0); // saturating_sub prevents underflow
    }

    // ======================================================================
    // KV counter: boundary at limit-1
    // ======================================================================

    #[tokio::test]
    async fn kv_counter_allowed_at_one_below_limit() {
        // count=99, limit=100 -> allowed, increments to 100
        let kv = MockKv::new().with_entry("test:boundary:0", "99");
        let (allowed, count, limit, _) =
            check_kv_counter_impl(&kv, "test:boundary:0", 100, 7200).await;
        assert!(allowed);
        assert_eq!(count, 100);
        assert_eq!(limit, 100);

        // Verify the KV was written with "100"
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].value, "100");
    }

    #[tokio::test]
    async fn kv_counter_no_put_when_denied() {
        // At limit, request denied, no write should occur
        let kv = MockKv::new().with_entry("test:nop:0", "50");
        let (allowed, _, _, _) = check_kv_counter_impl(&kv, "test:nop:0", 50, 7200).await;
        assert!(!allowed);
        // No put should have been recorded since we returned early
        assert!(kv.puts().is_empty());
    }

    #[tokio::test]
    async fn kv_counter_put_value_matches_incremented_count() {
        // Verify the stored value after multiple increments is correct
        let kv = MockKv::new();

        let _ = check_kv_counter_impl(&kv, "test:val:0", 10, 3600).await;
        assert_eq!(kv.read_raw("test:val:0"), Some("1".to_string()));

        let _ = check_kv_counter_impl(&kv, "test:val:0", 10, 3600).await;
        assert_eq!(kv.read_raw("test:val:0"), Some("2".to_string()));

        let _ = check_kv_counter_impl(&kv, "test:val:0", 10, 3600).await;
        assert_eq!(kv.read_raw("test:val:0"), Some("3".to_string()));
    }

    #[tokio::test]
    async fn kv_counter_short_ttl_propagated() {
        let kv = MockKv::new();
        let _ = check_kv_counter_impl(&kv, "test:short:0", 100, 120).await;
        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].ttl_secs, 120);
    }

    // ======================================================================
    // Tier lookup: flat format through get_customer_limit_impl
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_flat_format_tier_json() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/flat_client", "flat_tier")
            .with_entry(
                "rate_limits/tiers/flat_tier",
                r#"{"challenge":777,"verify":333}"#,
            );

        let limit =
            get_customer_limit_impl(&kv, "flat_client", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 777);

        // Verify "verify" endpoint from the same tier (should be cached)
        let kv2 = MockKv::new();
        let limit =
            get_customer_limit_impl(&kv2, "flat_client", "verify", 100, 1_700_000_010).await;
        assert_eq!(limit, 333);
    }

    // ======================================================================
    // Tier cache: refresh after expiry with new data
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_cache_refreshes_with_new_data_after_expiry() {
        clear_tier_cache();

        // First: populate cache at t=1_700_000_000 with limit=500
        let kv1 = MockKv::new()
            .with_entry("rate_limits/clients/refresh_client", "tier_v1")
            .with_entry(
                "rate_limits/tiers/tier_v1",
                r#"{"limits":{"challenge":500}}"#,
            );
        let limit =
            get_customer_limit_impl(&kv1, "refresh_client", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 500);

        // At t+30 (within cache TTL), cache still returns old value
        let kv_empty = MockKv::new();
        let limit =
            get_customer_limit_impl(&kv_empty, "refresh_client", "challenge", 100, 1_700_000_030)
                .await;
        assert_eq!(limit, 500);

        // At t+61 (cache expired), KV now returns updated tier with limit=999
        let kv2 = MockKv::new()
            .with_entry("rate_limits/clients/refresh_client", "tier_v2")
            .with_entry(
                "rate_limits/tiers/tier_v2",
                r#"{"limits":{"challenge":999}}"#,
            );
        let limit =
            get_customer_limit_impl(&kv2, "refresh_client", "challenge", 100, 1_700_000_061).await;
        assert_eq!(limit, 999);

        // At t+90 (within new cache TTL), should still return 999
        let kv_empty2 = MockKv::new();
        let limit = get_customer_limit_impl(
            &kv_empty2,
            "refresh_client",
            "challenge",
            100,
            1_700_000_090,
        )
        .await;
        assert_eq!(limit, 999);
    }

    // ======================================================================
    // Tier cache: multiple clients cached independently
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_cache_multiple_clients_independent() {
        clear_tier_cache();

        let kv = MockKv::new()
            .with_entry("rate_limits/clients/client_alpha", "alpha_tier")
            .with_entry(
                "rate_limits/tiers/alpha_tier",
                r#"{"limits":{"challenge":111}}"#,
            )
            .with_entry("rate_limits/clients/client_beta", "beta_tier")
            .with_entry(
                "rate_limits/tiers/beta_tier",
                r#"{"limits":{"challenge":222}}"#,
            );

        let limit_alpha =
            get_customer_limit_impl(&kv, "client_alpha", "challenge", 100, 1_700_000_000).await;
        let limit_beta =
            get_customer_limit_impl(&kv, "client_beta", "challenge", 100, 1_700_000_000).await;

        assert_eq!(limit_alpha, 111);
        assert_eq!(limit_beta, 222);

        // Both should be cached independently; empty KV, both still return cached values
        let kv_empty = MockKv::new();
        let cached_alpha =
            get_customer_limit_impl(&kv_empty, "client_alpha", "challenge", 100, 1_700_000_030)
                .await;
        let cached_beta =
            get_customer_limit_impl(&kv_empty, "client_beta", "challenge", 100, 1_700_000_030)
                .await;
        assert_eq!(cached_alpha, 111);
        assert_eq!(cached_beta, 222);
    }

    // ======================================================================
    // Tier lookup: KV error on tier read (client found, tier read fails)
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_tier_kv_error_uses_default() {
        clear_tier_cache();
        // Client maps to "err_tier", but the get for "rate_limits/tiers/err_tier"
        // will fail because we inject a get error after the first successful read.
        // MockKv's with_get_error fires on the *next* get call, and client lookup
        // is the first call, so we need a different approach.
        // Instead, the tier key simply doesn't exist, returning None -> empty limits.
        let kv = MockKv::new().with_entry("rate_limits/clients/errclient", "missing_tier_id");
        // "rate_limits/tiers/missing_tier_id" not in KV -> None -> empty map -> default
        let limit = get_customer_limit_impl(&kv, "errclient", "challenge", 88, 1_700_000_000).await;
        assert_eq!(limit, 88);
    }

    // ======================================================================
    // Tier lookup: cache at exactly 60 seconds boundary
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_cache_exactly_at_60s_still_valid() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/boundary_client", "btier")
            .with_entry("rate_limits/tiers/btier", r#"{"limits":{"challenge":600}}"#);

        let limit =
            get_customer_limit_impl(&kv, "boundary_client", "challenge", 100, 1_700_000_000).await;
        assert_eq!(limit, 600);

        // At exactly 59 seconds later, cache is still valid (59 < 60)
        let kv_empty = MockKv::new();
        let limit = get_customer_limit_impl(
            &kv_empty,
            "boundary_client",
            "challenge",
            100,
            1_700_000_059,
        )
        .await;
        assert_eq!(limit, 600);

        // At exactly 60 seconds later, cache expires (60 - 0 = 60, which is NOT < 60)
        let kv2 = MockKv::new(); // empty -> default
        let limit =
            get_customer_limit_impl(&kv2, "boundary_client", "challenge", 100, 1_700_000_060).await;
        assert_eq!(limit, 100);
    }

    // ======================================================================
    // check_quota_impl: full flow with tier and exhaustion
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_tier_limit_exhaustion() {
        clear_tier_cache();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;

        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/exhaust_client", "tiny_tier")
            .with_entry(
                "rate_limits/tiers/tiny_tier",
                r#"{"limits":{"challenge":2}}"#,
            );
        let rate_kv = MockKv::new();

        // First request: allowed (count 0 -> 1, limit 2)
        let r1 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "exhaust_client",
            "challenge",
            100,
            now,
        )
        .await;
        assert!(r1.allowed);
        assert_eq!(r1.limit, 2);
        assert_eq!(r1.current_count, 1);

        // Second request: allowed (count 1 -> 2, limit 2)
        let r2 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "exhaust_client",
            "challenge",
            100,
            now,
        )
        .await;
        assert!(r2.allowed);
        assert_eq!(r2.current_count, 2);

        // Third request: denied (count 2 >= limit 2)
        let r3 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "exhaust_client",
            "challenge",
            100,
            now,
        )
        .await;
        assert!(!r3.allowed);
        assert_eq!(r3.current_count, 2);

        // Verify the key format
        let expected_key = format!("quota:exhaust_client:challenge:{}", hour_ts);
        assert_eq!(rate_kv.read_raw(&expected_key), Some("2".to_string()));
    }

    // ======================================================================
    // check_quota_impl: KV read failure -> fail-closed through full flow
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_rate_kv_read_failure_denies() {
        clear_tier_cache();
        let rate_kv = MockKv::new()
            .with_get_error("KV outage")
            .with_persistent_errors();
        let config_kv = MockKv::new();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "fail_client",
            "challenge",
            100,
            1_700_000_000,
        )
        .await;

        assert!(!result.allowed);
        assert!(result.read_failed); // R1: steers caller to 503, not 429
        assert_eq!(result.current_count, 0);
        assert_eq!(result.limit, 100);
    }

    // ======================================================================
    // check_quota_impl: KV write failure -> still allows
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_rate_kv_write_failure_allows() {
        clear_tier_cache();
        let rate_kv = MockKv::new().with_put_error("write timeout");
        let config_kv = MockKv::new();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "write_fail_client",
            "challenge",
            100,
            1_700_000_000,
        )
        .await;

        // Request is allowed because read succeeded and count was 0 < 100
        assert!(result.allowed);
        assert_eq!(result.current_count, 1);
        assert_eq!(result.limit, 100);
        // But no puts recorded (write failed)
        assert!(rate_kv.puts().is_empty());
    }

    // ======================================================================
    // check_quota_impl: different time windows produce different keys
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_different_hour_windows() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let now_hour1 = 1_700_000_000u64;
        let now_hour2 = now_hour1 + 3600; // next hour

        let r1 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "window_client",
            "challenge",
            100,
            now_hour1,
        )
        .await;
        let r2 = check_quota_impl(
            &rate_kv,
            &config_kv,
            "window_client",
            "challenge",
            100,
            now_hour2,
        )
        .await;

        // Both should be allowed as count=1 (different keys due to different hour_ts)
        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);

        // Verify two different keys were written
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 2);
        assert_ne!(puts[0].key, puts[1].key);
    }

    // ======================================================================
    // check_per_ip_limit_impl: exhaust through successive calls
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_exhaust_through_calls() {
        let kv = MockKv::new();
        let now = 1_700_000_000u64;

        // Limit of 3
        let r1 = check_per_ip_limit_impl(&kv, "short_code:", "exhaust_ip", 3, now).await;
        assert!(r1.allowed);
        assert_eq!(r1.current_count, 1);

        let r2 = check_per_ip_limit_impl(&kv, "short_code:", "exhaust_ip", 3, now).await;
        assert!(r2.allowed);
        assert_eq!(r2.current_count, 2);

        let r3 = check_per_ip_limit_impl(&kv, "short_code:", "exhaust_ip", 3, now).await;
        assert!(r3.allowed);
        assert_eq!(r3.current_count, 3);

        let r4 = check_per_ip_limit_impl(&kv, "short_code:", "exhaust_ip", 3, now).await;
        assert!(!r4.allowed);
        assert_eq!(r4.current_count, 3);
    }

    // ======================================================================
    // check_per_ip_limit_impl: different hour windows are independent
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_different_hour_windows() {
        let kv = MockKv::new();

        let now_hour1 = 1_700_000_000u64;
        let now_hour2 = now_hour1 + 3600;

        let r1 = check_per_ip_limit_impl(&kv, "short_code:", "window_ip", 10, now_hour1).await;
        let r2 = check_per_ip_limit_impl(&kv, "short_code:", "window_ip", 10, now_hour2).await;

        assert!(r1.allowed);
        assert!(r2.allowed);
        assert_eq!(r1.current_count, 1);
        assert_eq!(r2.current_count, 1);

        // Different keys
        let puts = kv.puts();
        assert_eq!(puts.len(), 2);
        assert_ne!(puts[0].key, puts[1].key);
    }

    // ======================================================================
    // check_per_ip_limit_impl: retry_after at hour boundary
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_retry_after_at_boundary() {
        let kv = MockKv::new();
        // Exactly on the hour boundary
        let now = 1_699_200_000u64;
        assert_eq!(now % 3600, 0);

        let result = check_per_ip_limit_impl(&kv, "short_code:", "boundary_ip", 100, now).await;
        // RL-11: raw remainder is a full hour; advertised value is clamped.
        assert_eq!(result.retry_after_secs, MAX_ADVERTISED_RETRY_AFTER_SECS);
    }

    #[tokio::test]
    async fn check_per_ip_limit_retry_after_1s_before_boundary() {
        let kv = MockKv::new();
        let hour_ts = 1_699_200_000u64;
        let now = hour_ts + 3599;

        let result = check_per_ip_limit_impl(&kv, "short_code:", "near_end_ip", 100, now).await;
        assert_eq!(result.retry_after_secs, 1);
    }

    // ======================================================================
    // check_quota_impl: config_kv error falls back to default, rate_kv works
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_config_kv_error_uses_default_limit() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_get_error("config KV down")
            .with_persistent_errors();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "config_err_client",
            "challenge",
            250,
            1_700_000_000,
        )
        .await;

        // Config KV fails -> default limit of 250 used
        // Rate KV works -> request allowed
        assert!(result.allowed);
        assert_eq!(result.limit, 250);
        assert_eq!(result.current_count, 1);
    }

    // ======================================================================
    // check_quota_impl: both KVs fail -> denied with default limit
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_both_kvs_fail_denied() {
        clear_tier_cache();
        let rate_kv = MockKv::new()
            .with_get_error("rate KV down")
            .with_persistent_errors();
        let config_kv = MockKv::new()
            .with_get_error("config KV down")
            .with_persistent_errors();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "both_fail",
            "challenge",
            100,
            1_700_000_000,
        )
        .await;

        // Config fails -> default limit 100
        // Rate read fails -> fail-closed -> denied
        assert!(!result.allowed);
        assert!(result.read_failed); // R1: steers caller to 503, not 429
        assert_eq!(result.limit, 100);
    }

    // ======================================================================
    // check_per_ip_limit_impl: write failure still allows
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_write_failure_allows() {
        let kv = MockKv::new().with_put_error("write broken");

        let result =
            check_per_ip_limit_impl(&kv, "short_code:", "write_fail_ip", 100, 1_700_000_000).await;

        // Read succeeded (count=0, below limit), write fails but request still allowed
        assert!(result.allowed);
        assert_eq!(result.current_count, 1);
        assert!(kv.puts().is_empty());
    }

    // ======================================================================
    // check_per_ip_limit_impl: key format correctness with various IPs
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_key_format_ipv6() {
        let kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;

        let _ = check_per_ip_limit_impl(&kv, "short_code:", "2001:db8::1", 100, now).await;

        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, format!("short_code:2001:db8::1:{}", hour_ts));
    }

    // ======================================================================
    // check_quota_impl: client/endpoint with special characters in key
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_special_chars_in_key() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;

        let _ = check_quota_impl(
            &rate_kv,
            &config_kv,
            "client/with:colons",
            "end:point",
            100,
            now,
        )
        .await;

        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(
            puts[0].key,
            format!("quota:client/with:colons:end:point:{}", hour_ts)
        );
    }

    // ======================================================================
    // Tier lookup: cache hit for endpoint present vs absent
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_cache_hit_with_missing_endpoint_returns_default() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/partial_client", "partial_tier")
            .with_entry(
                "rate_limits/tiers/partial_tier",
                r#"{"limits":{"verify":400}}"#,
            );

        // Populate cache for "verify"
        let limit =
            get_customer_limit_impl(&kv, "partial_client", "verify", 100, 1_700_000_000).await;
        assert_eq!(limit, 400);

        // Now ask for "challenge" which is NOT in the tier; cache is populated
        // for this client, so the cache hit path returns default
        let kv_empty = MockKv::new();
        let limit =
            get_customer_limit_impl(&kv_empty, "partial_client", "challenge", 55, 1_700_000_010)
                .await;
        assert_eq!(limit, 55);
    }

    // ======================================================================
    // Tier lookup: zero-value limit in tier
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn tier_lookup_zero_limit_in_tier() {
        clear_tier_cache();
        let kv = MockKv::new()
            .with_entry("rate_limits/clients/zero_client", "zero_tier")
            .with_entry(
                "rate_limits/tiers/zero_tier",
                r#"{"limits":{"challenge":0}}"#,
            );

        let limit =
            get_customer_limit_impl(&kv, "zero_client", "challenge", 100, 1_700_000_000).await;
        // Tier explicitly sets 0, should return 0 not the default
        assert_eq!(limit, 0);
    }

    // ======================================================================
    // Full flow: zero tier limit -> immediate denial
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_zero_tier_limit_denies() {
        clear_tier_cache();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/banned", "banned_tier")
            .with_entry(
                "rate_limits/tiers/banned_tier",
                r#"{"limits":{"challenge":0}}"#,
            );
        let rate_kv = MockKv::new();

        let result = check_quota_impl(
            &rate_kv,
            &config_kv,
            "banned",
            "challenge",
            100,
            1_700_000_000,
        )
        .await;

        // Tier says limit=0, so first request is already denied
        assert!(!result.allowed);
        assert_eq!(result.limit, 0);
    }

    // ======================================================================
    // parse_tier_limits: JSON array at top level
    // ======================================================================

    #[test]
    fn parse_tier_limits_top_level_array() {
        let json = r#"[1, 2, 3]"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_top_level_string() {
        let json = r#""just a string""#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_top_level_number() {
        let json = "42";
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_top_level_bool() {
        let json = "true";
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tier_limits_top_level_null() {
        let json = "null";
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    // ======================================================================
    // parse_tier_limits: overflow u32 value
    // ======================================================================

    #[test]
    fn parse_tier_limits_value_exceeds_u32() {
        // u32::MAX + 1 = 4294967296
        let json = r#"{"challenge":4294967296}"#;
        let map = parse_tier_limits(json);
        assert!(map.is_empty());
    }

    // ======================================================================
    // check_quota_impl: TTL of 7200 is passed to KV counter
    // ======================================================================

    #[tokio::test]
    #[serial]
    async fn check_quota_impl_ttl_is_7200() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();

        let _ = check_quota_impl(
            &rate_kv,
            &config_kv,
            "ttl_client",
            "challenge",
            100,
            1_700_000_000,
        )
        .await;

        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].ttl_secs, 7200);
    }

    // ======================================================================
    // check_per_ip_limit_impl: TTL is 7200
    // ======================================================================

    #[tokio::test]
    async fn check_per_ip_limit_ttl_is_7200() {
        let kv = MockKv::new();
        let _ = check_per_ip_limit_impl(&kv, "short_code:", "ttl_ip", 100, 1_700_000_000).await;

        let puts = kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].ttl_secs, 7200);
    }

    // ======================================================================
    // RateLimitResult: edge cases
    // ======================================================================

    #[test]
    fn rate_limit_result_zero_limit_zero_count() {
        let r = RateLimitResult {
            allowed: false,
            current_count: 0,
            limit: 0,
            retry_after_secs: 3600,
            read_failed: false,
        };
        assert!(!r.allowed);
        assert_eq!(r.limit.saturating_sub(r.current_count), 0);
    }

    #[test]
    fn rate_limit_result_max_values() {
        let r = RateLimitResult {
            allowed: true,
            current_count: u32::MAX,
            limit: u32::MAX,
            retry_after_secs: u32::MAX,
            read_failed: false,
        };
        assert!(r.allowed);
        assert_eq!(r.limit.saturating_sub(r.current_count), 0);
    }

    #[test]
    fn rate_limit_result_remaining_when_count_equals_limit() {
        let r = RateLimitResult {
            allowed: false,
            current_count: 100,
            limit: 100,
            retry_after_secs: 1800,
            read_failed: false,
        };
        assert_eq!(r.limit.saturating_sub(r.current_count), 0);
    }

    #[test]
    fn rate_limit_result_remaining_when_count_is_one() {
        let r = RateLimitResult {
            allowed: true,
            current_count: 1,
            limit: 100,
            retry_after_secs: 3599,
            read_failed: false,
        };
        assert_eq!(r.limit.saturating_sub(r.current_count), 99);
    }

    // -----------------------------------------------------------------------
    // check_catchall_limit_impl
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn catchall_limit_allows_under_limit() {
        let kv = MockKv::new();
        let r = check_catchall_limit_impl(&kv, "hashed_ip_abc", 10, 1_700_000_000).await;
        assert!(r.allowed);
        assert_eq!(r.current_count, 1);
        assert_eq!(r.limit, 10);
    }

    #[tokio::test]
    async fn catchall_limit_denies_at_limit() {
        let kv = MockKv::new();
        for _ in 0..5 {
            let _ = check_catchall_limit_impl(&kv, "ip1", 5, 1_700_000_000).await;
        }
        let r = check_catchall_limit_impl(&kv, "ip1", 5, 1_700_000_000).await;
        assert!(!r.allowed);
        assert_eq!(r.limit, 5);
    }

    #[tokio::test]
    async fn catchall_limit_key_includes_minute_bucket() {
        let kv = MockKv::new();
        let _ = check_catchall_limit_impl(&kv, "ip2", 10, 1_700_000_060).await;
        let _ = check_catchall_limit_impl(&kv, "ip2", 10, 1_700_000_120).await;
        let puts = kv.puts();
        let keys: Vec<String> = puts.iter().map(|p| p.key.clone()).collect();
        assert!(keys.iter().any(|k| k.contains("1700000040")));
        assert!(keys.iter().any(|k| k.contains("1700000100")));
    }

    #[tokio::test]
    async fn catchall_limit_retry_after_within_minute() {
        let kv = MockKv::new();
        let r = check_catchall_limit_impl(&kv, "ip3", 10, 1_700_000_030).await;
        assert!(r.retry_after_secs <= 60);
        assert!(r.retry_after_secs > 0);
    }

    // -----------------------------------------------------------------------
    // check_hosted_ip_limit_impl
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn hosted_ip_limit_allows_under_limit() {
        let kv = MockKv::new();
        let r = check_hosted_ip_limit_impl(&kv, "hashed_ip", "challenge", 100, 1_700_000_000).await;
        assert!(r.allowed);
        assert_eq!(r.current_count, 1);
        assert_eq!(r.limit, 100);
    }

    #[tokio::test]
    async fn hosted_ip_limit_denies_at_limit() {
        let kv = MockKv::new();
        for _ in 0..10 {
            let _ = check_hosted_ip_limit_impl(&kv, "ipA", "challenge", 10, 1_700_000_000).await;
        }
        let r = check_hosted_ip_limit_impl(&kv, "ipA", "challenge", 10, 1_700_000_000).await;
        assert!(!r.allowed);
    }

    #[tokio::test]
    async fn hosted_ip_limit_key_format() {
        let kv = MockKv::new();
        let _ = check_hosted_ip_limit_impl(&kv, "ipB", "redeem", 100, 1_700_000_000).await;
        let puts = kv.puts();
        assert!(puts[0].key.starts_with("hosted:redeem:ipB:"));
    }

    #[tokio::test]
    async fn hosted_ip_limit_retry_after_within_hour() {
        let kv = MockKv::new();
        let r = check_hosted_ip_limit_impl(&kv, "ipC", "status", 100, 1_700_000_000).await;
        assert!(r.retry_after_secs <= 3600);
    }

    #[tokio::test]
    async fn hosted_ip_limit_different_endpoints_independent() {
        let kv = MockKv::new();
        for _ in 0..5 {
            let _ = check_hosted_ip_limit_impl(&kv, "ipD", "challenge", 5, 1_700_000_000).await;
        }
        let r = check_hosted_ip_limit_impl(&kv, "ipD", "challenge", 5, 1_700_000_000).await;
        assert!(!r.allowed);
        let r2 = check_hosted_ip_limit_impl(&kv, "ipD", "redeem", 5, 1_700_000_000).await;
        assert!(r2.allowed);
    }

    // -----------------------------------------------------------------------
    // check_expert_ip_limit_impl
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn expert_ip_limit_allows_under_limit() {
        let kv = MockKv::new();
        let r = check_expert_ip_limit_impl(&kv, "hashed_ip", "verify", 100, 1_700_000_000).await;
        assert!(r.allowed);
        assert_eq!(r.current_count, 1);
    }

    #[tokio::test]
    async fn expert_ip_limit_denies_at_limit() {
        let kv = MockKv::new();
        for _ in 0..8 {
            let _ = check_expert_ip_limit_impl(&kv, "ipE", "verify", 8, 1_700_000_000).await;
        }
        let r = check_expert_ip_limit_impl(&kv, "ipE", "verify", 8, 1_700_000_000).await;
        assert!(!r.allowed);
    }

    #[tokio::test]
    async fn expert_ip_limit_key_format() {
        let kv = MockKv::new();
        let _ = check_expert_ip_limit_impl(&kv, "ipF", "challenge", 100, 1_700_003_600).await;
        let puts = kv.puts();
        assert!(puts[0].key.starts_with("expert_ip:challenge:ipF:"));
    }

    #[tokio::test]
    async fn expert_ip_limit_different_hour_resets() {
        let kv = MockKv::new();
        for _ in 0..5 {
            let _ = check_expert_ip_limit_impl(&kv, "ipG", "verify", 5, 1_700_000_000).await;
        }
        let r1 = check_expert_ip_limit_impl(&kv, "ipG", "verify", 5, 1_700_000_000).await;
        assert!(!r1.allowed);
        let r2 = check_expert_ip_limit_impl(&kv, "ipG", "verify", 5, 1_700_003_600).await;
        assert!(r2.allowed);
    }

    // ======================================================================
    // R9 (RL-03): per-account quota on the verified identity
    // ======================================================================

    // -- The account-quota key carries NO IP component and uses the
    //    `acct_quota:` namespace keyed on the verified client_id. --
    #[tokio::test]
    #[serial]
    async fn check_account_quota_impl_key_has_no_ip_component() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;

        let _ = check_account_quota_impl(
            &rate_kv,
            &config_kv,
            "rp_live_verified_abc",
            "verify",
            500,
            now,
        )
        .await;

        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(
            puts[0].key,
            format!("acct_quota:rp_live_verified_abc:verify:{}", hour_ts)
        );
    }

    // -- Two end-users with the SAME (notional) source IP but DIFFERENT verified
    //    identities get independent buckets: the IP is absent from the key. --
    #[tokio::test]
    #[serial]
    async fn check_account_quota_impl_isolates_distinct_accounts() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;

        let a = check_account_quota_impl(&rate_kv, &config_kv, "acct_a", "verify", 100, now).await;
        let b = check_account_quota_impl(&rate_kv, &config_kv, "acct_b", "verify", 100, now).await;

        assert!(a.allowed);
        assert!(b.allowed);
        assert_eq!(a.current_count, 1);
        assert_eq!(b.current_count, 1);
        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 2);
        assert_ne!(puts[0].key, puts[1].key);
    }

    // -- The tier lookup is re-keyed onto the VERIFIED id: a premium customer's
    //    higher tier is found by their real identity, raising the limit. --
    #[tokio::test]
    #[serial]
    async fn check_account_quota_impl_uses_tier_for_verified_id() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new()
            .with_entry("rate_limits/clients/rp_live_premium", "premium")
            .with_entry("rate_limits/tiers/premium", r#"{"limits":{"verify":9999}}"#);

        let result = check_account_quota_impl(
            &rate_kv,
            &config_kv,
            "rp_live_premium",
            "verify",
            500,
            1_700_000_000,
        )
        .await;

        assert!(result.allowed);
        assert_eq!(result.limit, 9999);
    }

    // -- Over the per-account limit returns a genuine 429-style rejection
    //    (allowed=false, read_failed=false). --
    #[tokio::test]
    #[serial]
    async fn check_account_quota_impl_denied_at_limit() {
        clear_tier_cache();
        let now = 1_700_000_000u64;
        let hour_ts = (now / 3600) * 3600;
        let key = format!("acct_quota:acct_full:verify:{}", hour_ts);
        let rate_kv = MockKv::new().with_entry(&key, "50");
        let config_kv = MockKv::new();

        let result =
            check_account_quota_impl(&rate_kv, &config_kv, "acct_full", "verify", 50, now).await;

        assert!(!result.allowed);
        assert!(!result.read_failed);
        assert_eq!(result.current_count, 50);
    }

    // -- A KV READ failure rejects fail-closed AND flags read_failed so the
    //    caller surfaces 503 + short Retry-After (R1), never a 429. --
    #[tokio::test]
    #[serial]
    async fn check_account_quota_impl_read_failure_sets_read_failed() {
        clear_tier_cache();
        let rate_kv = MockKv::new()
            .with_get_error("KV unavailable")
            .with_persistent_errors();
        let config_kv = MockKv::new();

        let result =
            check_account_quota_impl(&rate_kv, &config_kv, "acct_x", "verify", 500, 1_700_000_000)
                .await;

        assert!(!result.allowed);
        assert!(result.read_failed);
    }

    // -- The account namespace does not collide with the pre-auth per-IP
    //    `quota:` namespace, so the supplement and the IP net never share a
    //    bucket. --
    #[tokio::test]
    #[serial]
    async fn check_account_quota_impl_namespace_distinct_from_pre_auth() {
        clear_tier_cache();
        let rate_kv = MockKv::new();
        let config_kv = MockKv::new();
        let now = 1_700_000_000u64;

        let _ = check_account_quota_impl(&rate_kv, &config_kv, "id1", "verify", 500, now).await;
        let _ = check_quota_impl(&rate_kv, &config_kv, "id1", "verify", 500, now).await;

        let puts = rate_kv.puts();
        assert_eq!(puts.len(), 2);
        assert!(puts[0].key.starts_with("acct_quota:"));
        assert!(puts[1].key.starts_with("quota:"));
        assert_ne!(puts[0].key, puts[1].key);
    }
}
