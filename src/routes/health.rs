// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Health check endpoints providing system status and diagnostics.
//!
//! Two tiers are exposed: a basic unauthenticated liveness probe for load
//! balancers, and an authenticated detailed check that reports subsystem
//! health for challenge store, nonce store, JWKS cache, rate limiter, ban
//! store, and the hosted subsystems (sessions KV, session DO, MEK cache).

use crate::{error::ApiResult, AppState};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use worker::Date;

/// Overall health status of the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational.
    Healthy,
    /// Service operational but some subsystems degraded.
    Degraded,
    /// Critical failures detected.
    Unhealthy,
}

impl HealthStatus {
    /// Return the HTTP status code appropriate for this health status.
    ///
    /// - `Healthy` / `Degraded`: 200 (service can still handle requests)
    /// - `Unhealthy`: 503 (load balancers should stop routing traffic here)
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::Healthy | Self::Degraded => 200,
            Self::Unhealthy => 503,
        }
    }
}

/// SECURITY: Basic health check response (unauthenticated).
/// Contains only essential liveness information without sensitive system details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicHealthResponse {
    /// Overall service health status.
    pub status: HealthStatus,

    /// Current timestamp in seconds since epoch.
    pub timestamp: u64,

    /// API version.
    pub version: String,
}

/// Health check response structure (authenticated).
/// Contains detailed subsystem health checks and metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Overall service health status.
    pub status: HealthStatus,

    /// Current timestamp in seconds since epoch.
    pub timestamp: u64,

    /// API version.
    pub version: String,

    /// Detailed subsystem health checks.
    pub checks: HealthChecks,
}

/// Individual subsystem health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthChecks {
    /// Challenge store availability.
    pub challenge_store: SubsystemHealth,

    /// Nonce store availability.
    pub nonce_store: SubsystemHealth,

    /// JWKS cache status.
    pub jwks_cache: SubsystemHealth,

    /// Rate limiter status.
    pub rate_limiter: SubsystemHealth,

    /// Ban store status.
    pub ban_store: SubsystemHealth,

    /// Hosted sessions KV namespace availability.
    pub hosted_sessions_kv: SubsystemHealth,

    /// Hosted Master Encryption Key cache status.
    pub hosted_mek: SubsystemHealth,
}

/// Health status of an individual subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemHealth {
    /// Whether the subsystem is operational.
    pub operational: bool,

    /// Optional message providing additional context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Optional metrics for this subsystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<serde_json::Value>,
}

impl SubsystemHealth {
    /// Create a healthy subsystem status.
    pub fn healthy() -> Self {
        Self {
            operational: true,
            message: None,
            metrics: None,
        }
    }

    /// Create a healthy subsystem with a message.
    pub fn healthy_with_message(message: impl Into<String>) -> Self {
        Self {
            operational: true,
            message: Some(message.into()),
            metrics: None,
        }
    }

    /// Create a healthy subsystem with metrics.
    pub fn healthy_with_metrics(metrics: serde_json::Value) -> Self {
        Self {
            operational: true,
            message: None,
            metrics: Some(metrics),
        }
    }

    /// Create a degraded subsystem status.
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            operational: true,
            message: Some(format!("DEGRADED: {}", message.into())),
            metrics: None,
        }
    }

    /// Create an unhealthy subsystem status.
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            operational: false,
            message: Some(message.into()),
            metrics: None,
        }
    }
}

/// SECURITY: Basic liveness probe for load balancers (unauthenticated).
/// Returns minimal health information without sensitive system details.
/// This endpoint is intentionally unauthenticated to allow load balancers
/// and monitoring systems to perform health checks without credentials.
pub async fn health_check_basic(_state: Arc<AppState>) -> ApiResult<BasicHealthResponse> {
    let now = Date::now().as_millis() / 1000;

    // Verify that the one-shot crypto initialisation succeeded. init_crypto_once()
    // is idempotent (backed by OnceLock), so calling it here is effectively free
    // after the first cold-start invocation. If crypto init failed, the worker
    // cannot verify proofs and must report unhealthy.
    let status = match crate::init_crypto_once() {
        Ok(()) => HealthStatus::Healthy,
        Err(_) => HealthStatus::Unhealthy,
    };

    // SECURITY: Minimal response for unauthenticated access
    // No sensitive system information is exposed
    Ok(BasicHealthResponse {
        status,
        timestamp: now,
        version: "v1".to_string(),
        // http_status transported alongside the response body so the
        // caller (worker_routes) can set the correct HTTP status code.
    })
}

/// SECURITY: Detailed health check with full metrics (requires authentication).
/// Returns full system status including subsystem health and metrics.
/// This endpoint requires API key authentication to prevent information disclosure.
pub async fn health_check_detailed(state: Arc<AppState>) -> ApiResult<HealthCheckResponse> {
    let now = Date::now().as_millis() / 1000;

    // SECURITY: Authenticated endpoint - perform full health checks
    // These checks may reveal sensitive system architecture information
    let challenge_store = check_challenge_store(&state).await;
    let nonce_store = check_nonce_store(&state).await;
    let jwks_cache = check_jwks_cache(&state);
    let rate_limiter = check_rate_limiter(&state).await;
    let ban_store = check_ban_store(&state).await;
    let hosted_sessions_kv = check_hosted_sessions_kv(&state).await;
    let hosted_mek = check_hosted_mek();

    let checks = HealthChecks {
        challenge_store: challenge_store.clone(),
        nonce_store: nonce_store.clone(),
        jwks_cache: jwks_cache.clone(),
        rate_limiter: rate_limiter.clone(),
        ban_store: ban_store.clone(),
        hosted_sessions_kv: hosted_sessions_kv.clone(),
        hosted_mek: hosted_mek.clone(),
    };

    let overall_status = determine_overall_status(&[
        &checks.challenge_store,
        &checks.nonce_store,
        &checks.jwks_cache,
        &checks.rate_limiter,
        &checks.ban_store,
        &checks.hosted_sessions_kv,
        &checks.hosted_mek,
    ]);

    Ok(HealthCheckResponse {
        status: overall_status,
        timestamp: now,
        version: "v1".to_string(),
        checks,
    })
}

/// Check challenge store health by testing DO connectivity.
async fn check_challenge_store(state: &AppState) -> SubsystemHealth {
    // Generate a test UUID that won't collide with real challenges.
    let test_uuid = uuid::Uuid::new_v4();

    match state.challenge_store.get(&test_uuid).await {
        // Not found (None) is expected and indicates the store is working.
        Ok(None) => SubsystemHealth::healthy_with_message("DO connectivity OK"),

        // Any error indicates a problem.
        // SECURITY: Use Display format, not Debug, to avoid leaking internal details
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[Health] Challenge store error: {:?}", _e);
            SubsystemHealth::unhealthy("Challenge store unavailable".to_string())
        }

        // Finding a challenge with our random UUID would be extremely unlikely.
        Ok(Some(_)) => SubsystemHealth::healthy_with_message("Unexpected challenge found (OK)"),
    }
}

/// Check nonce store health by testing DO connectivity.
async fn check_nonce_store(state: &AppState) -> SubsystemHealth {
    // Use a test nonce tag that won't collide with real usage.
    let test_tag = format!("health_check_{}", uuid::Uuid::new_v4());
    let ttl = std::time::Duration::from_secs(60); // 1 minute TTL for health check

    match state.nonce_store.check_and_set(&test_tag, ttl).await {
        // Success means the store is working (we just set a nonce).
        Ok(true) => SubsystemHealth::healthy_with_message("DO connectivity OK"),

        // False would mean the nonce already existed (extremely unlikely).
        Ok(false) => SubsystemHealth::healthy_with_message("Nonce collision (unlikely but OK)"),

        // Any error indicates a problem.
        // SECURITY: Use Display format, not Debug, to avoid leaking internal details
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[Health] Nonce store error: {:?}", _e);
            SubsystemHealth::unhealthy("Nonce store unavailable".to_string())
        }
    }
}

/// Check JWKS cache status.
fn check_jwks_cache(state: &AppState) -> SubsystemHealth {
    match state.jwks_cache.get_cache_stats() {
        Ok(stats) => {
            let metrics = serde_json::json!({
                "cache_size": stats.cache_size,
                "last_refresh_age_secs": stats.last_refresh_age_secs,
                "refresh_in_progress": stats.refresh_in_progress,
            });

            // Warn if cache is very stale (>1 hour).
            if stats.last_refresh_age_secs > 3600 {
                SubsystemHealth::degraded(format!(
                    "Cache stale: {} seconds old",
                    stats.last_refresh_age_secs
                ))
            } else {
                SubsystemHealth::healthy_with_metrics(metrics)
            }
        }
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[Health] JWKS cache error: {:?}", _e);
            SubsystemHealth::unhealthy("JWKS cache unavailable".to_string())
        }
    }
}

/// Check rate-limiter KV health by reading a sentinel key.
///
/// Rate limiting uses KV counters in `VERIFIER_KV_RATE_LIMITS` with per-hour
/// TTL. The limiter FAILS CLOSED: when a KV read errors, the request is
/// rejected (503), not allowed (see `rate_limiting::check_kv_counter_impl`).
/// A KV outage therefore blocks live traffic, so this check must actually
/// probe the binding. Previously it returned a hard-coded "operational" with
/// a comment claiming the limiter fails open, which was both a no-op and
/// factually wrong: the status page could show green while every request was
/// being rejected with 503.
async fn check_rate_limiter(state: &AppState) -> SubsystemHealth {
    match state.env.kv("VERIFIER_KV_RATE_LIMITS") {
        Ok(kv) => match kv.get("__health__").text().await {
            Ok(_) => SubsystemHealth::healthy_with_metrics(serde_json::json!({
                "status": "operational",
                "implementation": "kv-counter",
                "fail_mode": "closed",
                "note": "Counters in VERIFIER_KV_RATE_LIMITS; a KV read error rejects the request (503)"
            })),
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("[Health] Rate limiter KV read error: {:?}", _e);
                // Fail-closed means a KV outage blocks live traffic, so report
                // it as unhealthy rather than hiding it behind a green status.
                SubsystemHealth::unhealthy("Rate limiter KV unavailable".to_string())
            }
        },
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[Health] Rate limiter KV binding error: {:?}", _e);
            SubsystemHealth::unhealthy("Rate limiter KV binding unavailable".to_string())
        }
    }
}

/// Check ban store health.
async fn check_ban_store(state: &AppState) -> SubsystemHealth {
    // Test with a placeholder nullifier hash to verify store connectivity.
    // Using zero bytes as it's extremely unlikely to be an actual banned nullifier.
    let test_nullifier = [0u8; 32];

    match state.ban_store.is_banned(&test_nullifier).await {
        Ok(_) => SubsystemHealth::healthy_with_message("KV connectivity OK"),
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[Health] Ban store error: {:?}", _e);
            SubsystemHealth::unhealthy("Ban store unavailable".to_string())
        }
    }
}

/// Check hosted sessions KV namespace health via sentinel read.
///
/// Reads a key that should never exist (`__health__`). A successful read
/// (returning `None`) confirms the KV binding is reachable and functional.
async fn check_hosted_sessions_kv(state: &AppState) -> SubsystemHealth {
    match state.env.kv("HOSTED_SESSIONS") {
        Ok(kv) => match kv.get("__health__").text().await {
            Ok(_) => SubsystemHealth::healthy_with_message("KV connectivity OK"),
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("[Health] Hosted sessions KV read error: {:?}", _e);
                SubsystemHealth::unhealthy("Hosted sessions KV unavailable")
            }
        },
        Err(_e) => {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[Health] Hosted sessions KV binding error: {:?}", _e);
            SubsystemHealth::unhealthy("HOSTED_SESSIONS binding not configured")
        }
    }
}

/// Check whether the hosted Master Encryption Key is cached.
///
/// The MEK is fetched from the Secrets Store on the first request that
/// requires encryption. On a cold start the cache will be empty, which is
/// normal and reported as degraded rather than unhealthy.
fn check_hosted_mek() -> SubsystemHealth {
    if crate::hosted::encryption::mek_cache_populated() {
        SubsystemHealth::healthy_with_message("MEK cached")
    } else {
        SubsystemHealth::degraded("MEK not yet cached (cold start, will populate on first use)")
    }
}

/// Determine overall health status from subsystem health checks.
fn determine_overall_status(checks: &[&SubsystemHealth]) -> HealthStatus {
    let mut has_unhealthy = false;
    let mut has_degraded = false;

    for check in checks {
        if !check.operational {
            has_unhealthy = true;
        } else if let Some(msg) = &check.message {
            if msg.starts_with("DEGRADED:") {
                has_degraded = true;
            }
        }
    }

    if has_unhealthy {
        HealthStatus::Unhealthy
    } else if has_degraded {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;

    // ── SubsystemHealth constructors ────────────────────────────────

    #[test]
    fn healthy_is_operational_no_message_no_metrics() {
        let h = SubsystemHealth::healthy();
        assert!(h.operational);
        assert!(h.message.is_none());
        assert!(h.metrics.is_none());
    }

    #[test]
    fn healthy_with_message_stores_message() {
        let h = SubsystemHealth::healthy_with_message("all good");
        assert!(h.operational);
        assert_eq!(h.message.as_deref(), Some("all good"));
        assert!(h.metrics.is_none());
    }

    #[test]
    fn healthy_with_message_accepts_string_owned() {
        let owned = String::from("DO connectivity OK");
        let h = SubsystemHealth::healthy_with_message(owned);
        assert!(h.operational);
        assert_eq!(h.message.as_deref(), Some("DO connectivity OK"));
    }

    #[test]
    fn healthy_with_metrics_stores_json() {
        let metrics = serde_json::json!({"cache_size": 42});
        let h = SubsystemHealth::healthy_with_metrics(metrics.clone());
        assert!(h.operational);
        assert!(h.message.is_none());
        assert_eq!(h.metrics, Some(metrics));
    }

    #[test]
    fn degraded_is_operational_with_prefix() {
        let h = SubsystemHealth::degraded("Cache stale");
        assert!(h.operational);
        let msg = h.message.as_deref().expect("message present");
        assert!(msg.starts_with("DEGRADED: "));
        assert!(msg.contains("Cache stale"));
        assert!(h.metrics.is_none());
    }

    #[test]
    fn unhealthy_is_not_operational() {
        let h = SubsystemHealth::unhealthy("store down");
        assert!(!h.operational);
        assert_eq!(h.message.as_deref(), Some("store down"));
        assert!(h.metrics.is_none());
    }

    // ── HealthStatus HTTP status code mapping ────────────────────────

    #[test]
    fn healthy_returns_200() {
        assert_eq!(HealthStatus::Healthy.http_status_code(), 200);
    }

    #[test]
    fn degraded_returns_200() {
        assert_eq!(HealthStatus::Degraded.http_status_code(), 200);
    }

    #[test]
    fn unhealthy_returns_503() {
        assert_eq!(HealthStatus::Unhealthy.http_status_code(), 503);
    }

    // ── HealthStatus serde round-trip ───────────────────────────────

    #[test]
    fn health_status_serialises_lowercase() {
        let healthy_json = serde_json::to_string(&HealthStatus::Healthy).unwrap();
        assert_eq!(healthy_json, "\"healthy\"");

        let degraded_json = serde_json::to_string(&HealthStatus::Degraded).unwrap();
        assert_eq!(degraded_json, "\"degraded\"");

        let unhealthy_json = serde_json::to_string(&HealthStatus::Unhealthy).unwrap();
        assert_eq!(unhealthy_json, "\"unhealthy\"");
    }

    #[test]
    fn health_status_deserialises_from_lowercase() {
        let h: HealthStatus = serde_json::from_str("\"healthy\"").unwrap();
        assert!(matches!(h, HealthStatus::Healthy));

        let d: HealthStatus = serde_json::from_str("\"degraded\"").unwrap();
        assert!(matches!(d, HealthStatus::Degraded));

        let u: HealthStatus = serde_json::from_str("\"unhealthy\"").unwrap();
        assert!(matches!(u, HealthStatus::Unhealthy));
    }

    #[test]
    fn health_status_rejects_uppercase() {
        let result = serde_json::from_str::<HealthStatus>("\"Healthy\"");
        assert!(result.is_err());
    }

    // ── BasicHealthResponse serde ───────────────────────────────────

    #[test]
    fn basic_health_response_round_trips() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Healthy,
            timestamp: 1700000000,
            version: "v1".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: BasicHealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timestamp, 1700000000);
        assert_eq!(parsed.version, "v1");
        assert!(matches!(parsed.status, HealthStatus::Healthy));
    }

    // ── HealthCheckResponse serde ───────────────────────────────────

    #[test]
    fn health_check_response_serialises_all_fields() {
        let resp = HealthCheckResponse {
            status: HealthStatus::Degraded,
            timestamp: 1700000001,
            version: "v1".to_string(),
            checks: HealthChecks {
                challenge_store: SubsystemHealth::healthy(),
                nonce_store: SubsystemHealth::healthy(),
                jwks_cache: SubsystemHealth::degraded("stale"),
                rate_limiter: SubsystemHealth::healthy(),
                ban_store: SubsystemHealth::healthy(),
                hosted_sessions_kv: SubsystemHealth::healthy(),
                hosted_mek: SubsystemHealth::healthy(),
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"challenge_store\""));
        assert!(json.contains("\"nonce_store\""));
        assert!(json.contains("\"jwks_cache\""));
        assert!(json.contains("\"rate_limiter\""));
        assert!(json.contains("\"ban_store\""));
        assert!(json.contains("\"hosted_sessions_kv\""));
        assert!(json.contains("\"hosted_mek\""));
    }

    // ── SubsystemHealth serde ───────────────────────────────────────

    #[test]
    fn subsystem_health_skips_none_message() {
        let h = SubsystemHealth::healthy();
        let json = serde_json::to_string(&h).unwrap();
        assert!(!json.contains("\"message\""));
    }

    #[test]
    fn subsystem_health_skips_none_metrics() {
        let h = SubsystemHealth::healthy_with_message("ok");
        let json = serde_json::to_string(&h).unwrap();
        assert!(!json.contains("\"metrics\""));
    }

    #[test]
    fn subsystem_health_includes_present_fields() {
        let h = SubsystemHealth::healthy_with_metrics(serde_json::json!({"x": 1}));
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"metrics\""));
        assert!(json.contains("\"operational\":true"));
    }

    // ── determine_overall_status ────────────────────────────────────

    #[test]
    fn all_healthy_yields_healthy() {
        let a = SubsystemHealth::healthy();
        let b = SubsystemHealth::healthy_with_message("ok");
        let status = determine_overall_status(&[&a, &b]);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn single_degraded_yields_degraded() {
        let a = SubsystemHealth::healthy();
        let b = SubsystemHealth::degraded("slow");
        let status = determine_overall_status(&[&a, &b]);
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn single_unhealthy_yields_unhealthy() {
        let a = SubsystemHealth::healthy();
        let b = SubsystemHealth::unhealthy("down");
        let status = determine_overall_status(&[&a, &b]);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }

    #[test]
    fn unhealthy_takes_precedence_over_degraded() {
        let a = SubsystemHealth::degraded("slow");
        let b = SubsystemHealth::unhealthy("down");
        let status = determine_overall_status(&[&a, &b]);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }

    #[test]
    fn empty_checks_yields_healthy() {
        let status = determine_overall_status(&[]);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn multiple_degraded_still_degraded() {
        let a = SubsystemHealth::degraded("slow cache");
        let b = SubsystemHealth::degraded("old data");
        let status = determine_overall_status(&[&a, &b]);
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn operational_with_non_degraded_message_is_healthy() {
        // A message that does NOT start with "DEGRADED:" should not trigger degraded.
        let h = SubsystemHealth::healthy_with_message("DO connectivity OK");
        let status = determine_overall_status(&[&h]);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn degraded_prefix_must_include_colon() {
        // A message starting with "DEGRADED" but missing the colon should NOT count.
        let h = SubsystemHealth {
            operational: true,
            message: Some("DEGRADED but no colon".to_string()),
            metrics: None,
        };
        let status = determine_overall_status(&[&h]);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn seven_subsystem_all_healthy() {
        // Mirrors the real usage: exactly 7 subsystems.
        let checks: Vec<SubsystemHealth> = (0..7).map(|_| SubsystemHealth::healthy()).collect();
        let refs: Vec<&SubsystemHealth> = checks.iter().collect();
        let status = determine_overall_status(&refs);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn seven_subsystem_one_unhealthy_in_middle() {
        let mut checks: Vec<SubsystemHealth> = (0..7).map(|_| SubsystemHealth::healthy()).collect();
        checks[3] = SubsystemHealth::unhealthy("ban store down");
        let refs: Vec<&SubsystemHealth> = checks.iter().collect();
        let status = determine_overall_status(&refs);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }

    // ── HealthCheckResponse deserialisation ─────────────────────────

    #[test]
    fn health_check_response_deserialises_from_json() {
        let json = r#"{
            "status": "healthy",
            "timestamp": 1700000000,
            "version": "v1",
            "checks": {
                "challenge_store": { "operational": true },
                "nonce_store": { "operational": true },
                "jwks_cache": { "operational": true },
                "rate_limiter": { "operational": true },
                "ban_store": { "operational": true },
                "hosted_sessions_kv": { "operational": true },
                "hosted_mek": { "operational": true }
            }
        }"#;
        let parsed: HealthCheckResponse = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed.status, HealthStatus::Healthy));
        assert!(parsed.checks.challenge_store.operational);
        assert!(parsed.checks.hosted_mek.operational);
    }

    // ── Clone + Debug impls ─────────────────────────────────────────

    #[test]
    fn health_status_clone() {
        let h = HealthStatus::Healthy;
        let h2 = h.clone();
        let s1 = serde_json::to_string(&h).unwrap();
        let s2 = serde_json::to_string(&h2).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn subsystem_health_clone() {
        let h = SubsystemHealth::degraded("test");
        let h2 = h.clone();
        assert_eq!(h.operational, h2.operational);
        assert_eq!(h.message, h2.message);
    }

    #[test]
    fn health_status_debug() {
        let debug = format!("{:?}", HealthStatus::Unhealthy);
        assert!(debug.contains("Unhealthy"));
    }

    #[test]
    fn subsystem_health_debug() {
        let h = SubsystemHealth::unhealthy("broken");
        let debug = format!("{:?}", h);
        assert!(debug.contains("broken"));
        assert!(debug.contains("false"));
    }

    // ── determine_overall_status additional combinations ───────────

    #[test]
    fn all_unhealthy_yields_unhealthy() {
        let a = SubsystemHealth::unhealthy("store 1 down");
        let b = SubsystemHealth::unhealthy("store 2 down");
        let status = determine_overall_status(&[&a, &b]);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }

    #[test]
    fn mixed_degraded_and_healthy_yields_degraded() {
        let a = SubsystemHealth::healthy();
        let b = SubsystemHealth::degraded("cache stale");
        let c = SubsystemHealth::healthy_with_message("ok");
        let d = SubsystemHealth::healthy_with_metrics(serde_json::json!({}));
        let status = determine_overall_status(&[&a, &b, &c, &d]);
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn single_element_healthy() {
        let a = SubsystemHealth::healthy();
        let status = determine_overall_status(&[&a]);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn single_element_unhealthy() {
        let a = SubsystemHealth::unhealthy("down");
        let status = determine_overall_status(&[&a]);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }

    #[test]
    fn single_element_degraded() {
        let a = SubsystemHealth::degraded("slow");
        let status = determine_overall_status(&[&a]);
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn degraded_prefix_is_exact_match() {
        // "DEGRADED:" (with colon-space) is what degraded() produces.
        // A message with just "DEGRADED:" (no space after) should still match
        // starts_with("DEGRADED:").
        let h = SubsystemHealth {
            operational: true,
            message: Some("DEGRADED:no space".to_string()),
            metrics: None,
        };
        let status = determine_overall_status(&[&h]);
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn message_not_starting_with_degraded_is_healthy() {
        let h = SubsystemHealth {
            operational: true,
            message: Some("Everything is DEGRADED: but prefix is wrong".to_string()),
            metrics: None,
        };
        let status = determine_overall_status(&[&h]);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn unhealthy_without_message_still_unhealthy() {
        let h = SubsystemHealth {
            operational: false,
            message: None,
            metrics: None,
        };
        let status = determine_overall_status(&[&h]);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }

    // ── SubsystemHealth constructor additional tests ────────────────

    #[test]
    fn degraded_message_format() {
        let h = SubsystemHealth::degraded("MEK not cached");
        let msg = h.message.as_deref().expect("has message");
        assert_eq!(msg, "DEGRADED: MEK not cached");
    }

    #[test]
    fn degraded_accepts_owned_string() {
        let owned = String::from("stale data");
        let h = SubsystemHealth::degraded(owned);
        assert!(h.operational);
        assert!(h.message.as_deref().expect("msg").starts_with("DEGRADED: "));
    }

    #[test]
    fn unhealthy_accepts_owned_string() {
        let owned = String::from("total failure");
        let h = SubsystemHealth::unhealthy(owned);
        assert!(!h.operational);
        assert_eq!(h.message.as_deref(), Some("total failure"));
    }

    #[test]
    fn healthy_with_metrics_null_json() {
        let h = SubsystemHealth::healthy_with_metrics(serde_json::json!(null));
        assert!(h.operational);
        assert!(h.metrics.is_some());
    }

    #[test]
    fn healthy_with_metrics_nested_json() {
        let metrics = serde_json::json!({
            "cache": { "size": 42, "hits": 100 },
            "uptime_secs": 3600
        });
        let h = SubsystemHealth::healthy_with_metrics(metrics.clone());
        let m = h.metrics.expect("metrics present");
        assert_eq!(m["cache"]["size"], 42);
        assert_eq!(m["uptime_secs"], 3600);
    }

    // ── HealthStatus serde edge cases ──────────────────────────────

    #[test]
    fn health_status_rejects_mixed_case() {
        assert!(serde_json::from_str::<HealthStatus>("\"Degraded\"").is_err());
        assert!(serde_json::from_str::<HealthStatus>("\"UNHEALTHY\"").is_err());
    }

    #[test]
    fn health_status_rejects_numeric() {
        assert!(serde_json::from_str::<HealthStatus>("0").is_err());
    }

    #[test]
    fn health_status_rejects_empty_string() {
        assert!(serde_json::from_str::<HealthStatus>("\"\"").is_err());
    }

    #[test]
    fn health_status_rejects_null() {
        assert!(serde_json::from_str::<HealthStatus>("null").is_err());
    }

    // ── BasicHealthResponse edge cases ─────────────────────────────

    #[test]
    fn basic_health_response_zero_timestamp() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Healthy,
            timestamp: 0,
            version: "v1".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"timestamp\":0"));
    }

    #[test]
    fn basic_health_response_max_timestamp() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Healthy,
            timestamp: u64::MAX,
            version: "v1".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        let parsed: BasicHealthResponse = serde_json::from_str(&json).expect("parse"); // nosemgrep: provii.workers.expect-on-external-input
        assert_eq!(parsed.timestamp, u64::MAX);
    }

    #[test]
    fn basic_health_response_unhealthy_status() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Unhealthy,
            timestamp: 1700000000,
            version: "v1".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"unhealthy\""));
    }

    #[test]
    fn basic_health_response_degraded_status() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Degraded,
            timestamp: 1700000000,
            version: "v1".to_string(),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"degraded\""));
    }

    // ── HealthCheckResponse field coverage ──────────────────────────

    #[test]
    fn health_check_response_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let resp = HealthCheckResponse {
            status: HealthStatus::Healthy,
            timestamp: 1700000000,
            version: "v1".to_string(),
            checks: HealthChecks {
                challenge_store: SubsystemHealth::healthy(),
                nonce_store: SubsystemHealth::healthy_with_message("ok"),
                jwks_cache: SubsystemHealth::healthy_with_metrics(serde_json::json!({"size": 1})),
                rate_limiter: SubsystemHealth::healthy(),
                ban_store: SubsystemHealth::healthy(),
                hosted_sessions_kv: SubsystemHealth::healthy(),
                hosted_mek: SubsystemHealth::degraded("cold start"),
            },
        };
        let json = serde_json::to_string(&resp)?;
        let parsed: HealthCheckResponse = serde_json::from_str(&json)?;
        assert!(matches!(parsed.status, HealthStatus::Healthy));
        assert!(parsed.checks.nonce_store.operational);
        assert!(parsed.checks.hosted_mek.operational); // degraded is still operational
        assert_eq!(
            parsed.checks.jwks_cache.metrics.as_ref().expect("metrics")["size"],
            1
        );
        Ok(())
    }

    #[test]
    fn health_check_response_all_unhealthy() {
        let resp = HealthCheckResponse {
            status: HealthStatus::Unhealthy,
            timestamp: 0,
            version: "v1".to_string(),
            checks: HealthChecks {
                challenge_store: SubsystemHealth::unhealthy("down"),
                nonce_store: SubsystemHealth::unhealthy("down"),
                jwks_cache: SubsystemHealth::unhealthy("down"),
                rate_limiter: SubsystemHealth::unhealthy("down"),
                ban_store: SubsystemHealth::unhealthy("down"),
                hosted_sessions_kv: SubsystemHealth::unhealthy("down"),
                hosted_mek: SubsystemHealth::unhealthy("down"),
            },
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("\"unhealthy\""));
        assert!(!resp.checks.challenge_store.operational);
        assert!(!resp.checks.hosted_mek.operational);
    }

    // ── SubsystemHealth serde skip_serializing_if ──────────────────

    #[test]
    fn subsystem_health_both_message_and_metrics_present() {
        let h = SubsystemHealth {
            operational: true,
            message: Some("info".to_string()),
            metrics: Some(serde_json::json!({"key": "val"})),
        };
        let json = serde_json::to_string(&h).expect("serialise");
        assert!(json.contains("\"message\""));
        assert!(json.contains("\"metrics\""));
    }

    #[test]
    fn subsystem_health_deserialise_minimal() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"operational": false}"#;
        let h: SubsystemHealth = serde_json::from_str(json)?;
        assert!(!h.operational);
        assert!(h.message.is_none());
        assert!(h.metrics.is_none());
        Ok(())
    }

    // ── HealthChecks Debug ─────────────────────────────────────────

    #[test]
    fn health_checks_debug_contains_all_subsystems() {
        let checks = HealthChecks {
            challenge_store: SubsystemHealth::healthy(),
            nonce_store: SubsystemHealth::healthy(),
            jwks_cache: SubsystemHealth::healthy(),
            rate_limiter: SubsystemHealth::healthy(),
            ban_store: SubsystemHealth::healthy(),
            hosted_sessions_kv: SubsystemHealth::healthy(),
            hosted_mek: SubsystemHealth::healthy(),
        };
        let debug = format!("{:?}", checks);
        assert!(debug.contains("challenge_store"));
        assert!(debug.contains("nonce_store"));
        assert!(debug.contains("jwks_cache"));
        assert!(debug.contains("rate_limiter"));
        assert!(debug.contains("ban_store"));
        assert!(debug.contains("hosted_sessions_kv"));
        assert!(debug.contains("hosted_mek"));
    }

    // ── HealthChecks Clone ─────────────────────────────────────────

    #[test]
    fn health_checks_clone_preserves_state() {
        let checks = HealthChecks {
            challenge_store: SubsystemHealth::healthy_with_message("msg1"),
            nonce_store: SubsystemHealth::degraded("slow"),
            jwks_cache: SubsystemHealth::unhealthy("broken"),
            rate_limiter: SubsystemHealth::healthy(),
            ban_store: SubsystemHealth::healthy(),
            hosted_sessions_kv: SubsystemHealth::healthy(),
            hosted_mek: SubsystemHealth::healthy(),
        };
        let cloned = checks.clone();
        assert_eq!(
            checks.challenge_store.message,
            cloned.challenge_store.message
        );
        assert_eq!(
            checks.nonce_store.operational,
            cloned.nonce_store.operational
        );
        assert_eq!(checks.jwks_cache.operational, cloned.jwks_cache.operational);
    }

    // ── BasicHealthResponse Clone + Debug ──────────────────────────

    #[test]
    fn basic_health_response_clone() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Healthy,
            timestamp: 42,
            version: "v1".to_string(),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.timestamp, 42);
        assert_eq!(cloned.version, "v1");
    }

    #[test]
    fn basic_health_response_debug() {
        let resp = BasicHealthResponse {
            status: HealthStatus::Healthy,
            timestamp: 42,
            version: "v1".to_string(),
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("BasicHealthResponse"));
        assert!(debug.contains("42"));
    }

    // ── HealthCheckResponse Clone + Debug ──────────────────────────

    #[test]
    fn health_check_response_clone() {
        let resp = HealthCheckResponse {
            status: HealthStatus::Degraded,
            timestamp: 99,
            version: "v1".to_string(),
            checks: HealthChecks {
                challenge_store: SubsystemHealth::healthy(),
                nonce_store: SubsystemHealth::healthy(),
                jwks_cache: SubsystemHealth::healthy(),
                rate_limiter: SubsystemHealth::healthy(),
                ban_store: SubsystemHealth::healthy(),
                hosted_sessions_kv: SubsystemHealth::healthy(),
                hosted_mek: SubsystemHealth::healthy(),
            },
        };
        let cloned = resp.clone();
        assert_eq!(cloned.timestamp, 99);
        assert!(matches!(cloned.status, HealthStatus::Degraded));
    }

    #[test]
    fn health_check_response_debug() {
        let resp = HealthCheckResponse {
            status: HealthStatus::Unhealthy,
            timestamp: 0,
            version: "v1".to_string(),
            checks: HealthChecks {
                challenge_store: SubsystemHealth::healthy(),
                nonce_store: SubsystemHealth::healthy(),
                jwks_cache: SubsystemHealth::healthy(),
                rate_limiter: SubsystemHealth::healthy(),
                ban_store: SubsystemHealth::healthy(),
                hosted_sessions_kv: SubsystemHealth::healthy(),
                hosted_mek: SubsystemHealth::healthy(),
            },
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("HealthCheckResponse"));
        assert!(debug.contains("Unhealthy"));
    }

    // ── Seven subsystems: additional boundary ──────────────────────

    #[test]
    fn seven_subsystem_one_degraded_rest_healthy() {
        let mut checks: Vec<SubsystemHealth> = (0..7).map(|_| SubsystemHealth::healthy()).collect();
        checks[6] = SubsystemHealth::degraded("mek cold start");
        let refs: Vec<&SubsystemHealth> = checks.iter().collect();
        let status = determine_overall_status(&refs);
        assert!(matches!(status, HealthStatus::Degraded));
    }

    #[test]
    fn seven_subsystem_mixed_degraded_and_unhealthy() {
        let mut checks: Vec<SubsystemHealth> = (0..7).map(|_| SubsystemHealth::healthy()).collect();
        checks[1] = SubsystemHealth::degraded("stale cache");
        checks[4] = SubsystemHealth::unhealthy("ban store down");
        let refs: Vec<&SubsystemHealth> = checks.iter().collect();
        let status = determine_overall_status(&refs);
        assert!(matches!(status, HealthStatus::Unhealthy));
    }
}
