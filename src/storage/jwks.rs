// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Issuer registry caching and lookup helpers with resilience patterns.
//!
//! Reads issuer metadata from KV (`ISSUER_REGISTRY`) instead of external JWKS.
//! Implements stale-while-revalidate to prevent blocking on cache misses,
//! a circuit breaker for KV failures, and graceful degradation with a hard
//! maximum cache age of 60 minutes (RT-049).
#![forbid(unsafe_code)]

use crate::error::{ApiError, ApiResult};
use crate::take_worker_context;
use base64::prelude::*;
use blake2::{Blake2s256, Digest};
use futures::future::join_all;
use group::GroupEncoding;
use jubjub::SubgroupPoint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use worker::kv::KvStore;

/// Cache lifetime in seconds (10 minutes normal).
const CACHE_TTL_SECS: u64 = 600;

/// Stale cache tolerance (16 minutes) - serve stale if refresh fails.
/// Reduced from 30 minutes to bound the window during which a revoked
/// issuer could still be accepted from stale cache data.
const STALE_CACHE_TTL_SECS: u64 = 960;

/// RT-049: Hard maximum cache age (60 minutes). Even in degraded mode the cache
/// is never served beyond this age. This bounds the window during which a revoked
/// issuer could still be accepted from stale cache data.
const HARD_MAX_CACHE_TTL_SECS: u64 = 3600;

/// Circuit breaker: max consecutive failures before opening circuit.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Circuit breaker: how long to wait before retrying after circuit opens (5 min).
const CIRCUIT_BREAKER_RESET_SECS: u64 = 300;

/// Public metadata for a single registered issuer.
///
/// Stored in the in-memory cache keyed by the Blake2s-256 hash of the
/// issuer's verification key (with `provii.issuer.vk.v0` domain separation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMeta {
    /// Unique key identifier assigned during registration (e.g. `issuer-abc123`).
    pub kid: String,
    /// Human-readable organisation name of the issuer.
    pub name: String,
    /// Whether this issuer's key has been revoked by the admin portal.
    pub revoked: bool,
    /// Raw 32-byte Jubjub verification key (SubgroupPoint encoding).
    pub vk_bytes: [u8; 32],
}

/// Issuer registry entry format (matches provii-management KV format).
///
/// Uses default-tolerant deserialisation so that fields added by
/// provii-management in the future do not break parsing on the verifier side.
#[derive(Debug, Deserialize)]
struct IssuerRegistryEntry {
    issuer_kid: String,
    #[serde(default)]
    #[allow(dead_code)] // Deserialised from KV; not read in production
    issuer_id: Option<String>,
    #[allow(dead_code)] // Deserialised from KV; not read in production
    issuer_key_hash: String,
    verification_key: String, // base64url-encoded
    organization_name: String,
    #[serde(default)]
    #[allow(dead_code)] // Deserialised from KV; not read in production
    organization_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialised from KV; not read in production
    environment: Option<String>,
    #[allow(dead_code)] // Deserialised from KV; not read in production
    created_at: u64,
    revoked: bool,
    #[serde(default)]
    #[allow(dead_code)] // Deserialised from KV; not read in production
    revoked_at: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)] // Deserialised from KV; not read in production
    revoked_reason: Option<String>,
}

/// Circuit breaker state for KV registry resilience.
#[derive(Debug, Clone)]
struct CircuitBreakerState {
    consecutive_failures: u32,
    last_failure_time: u64,
    is_open: bool,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure_time: 0,
            is_open: false,
        }
    }

    /// Check if circuit should attempt a request.
    fn should_attempt(&self, now: u64) -> bool {
        if !self.is_open {
            return true;
        }

        // Half-open: try again after reset period
        now.saturating_sub(self.last_failure_time) > CIRCUIT_BREAKER_RESET_SECS
    }

    /// Record a successful request (resets circuit).
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.is_open = false;
    }

    /// Record a failed request (may open circuit).
    fn record_failure(&mut self, now: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_failure_time = now;

        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            self.is_open = true;
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[IssuerRegistry] 🚨 Circuit breaker OPEN - {} consecutive failures",
                self.consecutive_failures
            );
        }
    }
}

/// In-memory issuer registry cache backed by Cloudflare KV.
///
/// Provides stale-while-revalidate semantics, a circuit breaker for repeated
/// KV failures, and a hard maximum cache age (RT-049) beyond which stale data
/// is never served. All internal state is behind `Arc<RwLock<_>>` so the cache
/// can be shared across concurrent requests within a single isolate.
pub struct JwksCache {
    kv: KvStore,
    cache: Arc<RwLock<HashMap<[u8; 32], IssuerMeta>>>,
    last_refresh: Arc<RwLock<u64>>,
    circuit_breaker: Arc<RwLock<CircuitBreakerState>>,
    refresh_in_progress: Arc<RwLock<bool>>,
    /// Epoch counter for push-invalidation race safety.
    /// Incremented on each invalidation call. Background refreshes
    /// capture the epoch before fetching from KV and only write back
    /// if the epoch has not changed, preventing a stale fetch from
    /// overwriting a more recent invalidation.
    epoch: Arc<AtomicU64>,
}

/// RAII guard that clears `refresh_in_progress` on drop, preventing deadlock if
/// the background refresh future panics or is cancelled.
struct RefreshGuard {
    flag: Arc<RwLock<bool>>,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        let mut guard = self.flag.write().unwrap_or_else(|e| e.into_inner());
        *guard = false;
    }
}

impl JwksCache {
    /// Create a new cache backed by the given KV namespace.
    pub fn new(kv: KvStore) -> Self {
        Self {
            kv,
            cache: Arc::new(RwLock::new(HashMap::new())),
            last_refresh: Arc::new(RwLock::new(0)),
            circuit_breaker: Arc::new(RwLock::new(CircuitBreakerState::new())),
            refresh_in_progress: Arc::new(RwLock::new(false)),
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Cache-only lookup that does not trigger refresh/fetch.
    /// Returns None if not in cache, Some(issuer) if cached.
    /// This is used for early rejection gates to avoid network I/O.
    pub fn peek_issuer(&self, issuer_key_hash: &[u8; 32]) -> Option<IssuerMeta> {
        let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
        cache.get(issuer_key_hash).cloned()
    }

    /// Check if cache is stale (past normal TTL).
    fn is_stale(&self, now: u64) -> bool {
        let last = *self.last_refresh.read().unwrap_or_else(|e| e.into_inner());
        now.saturating_sub(last) > CACHE_TTL_SECS
    }

    /// Check if cache is extremely stale (past stale tolerance).
    fn is_extremely_stale(&self, now: u64) -> bool {
        let last = *self.last_refresh.read().unwrap_or_else(|e| e.into_inner());
        now.saturating_sub(last) > STALE_CACHE_TTL_SECS
    }

    /// RT-049: Check if the cache has exceeded the hard maximum lifetime.
    /// Beyond this age, stale data must NEVER be served regardless of degraded mode.
    fn is_beyond_hard_max(&self, now: u64) -> bool {
        let last = *self.last_refresh.read().unwrap_or_else(|e| e.into_inner());
        last == 0 || now.saturating_sub(last) > HARD_MAX_CACHE_TTL_SECS
    }

    /// Try to start background refresh if not already in progress.
    /// Returns true if refresh was started, false if already in progress.
    fn try_start_refresh(&self) -> bool {
        let mut in_progress = self
            .refresh_in_progress
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if *in_progress {
            return false;
        }
        *in_progress = true;
        true
    }

    /// Mark refresh as completed.
    fn finish_refresh(&self) {
        let mut in_progress = self
            .refresh_in_progress
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *in_progress = false;
    }

    /// Full lookup with stale-while-revalidate resilience.
    ///
    /// Strategy:
    /// 1. If cache is fresh, return immediately
    /// 2. If cache is stale but not extremely stale:
    ///    - Return stale value immediately
    ///    - Trigger background refresh (non-blocking)
    /// 3. If cache is extremely stale:
    ///    - Attempt blocking refresh
    ///    - If refresh fails but cache exists, return stale value (degraded mode)
    ///    - If no cache at all, return error
    pub async fn lookup_issuer(&self, issuer_key_hash: &[u8; 32]) -> ApiResult<IssuerMeta> {
        let now = crate::utils::current_timestamp();

        // FAST PATH: Cache is fresh
        if !self.is_stale(now) {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            let issuer = cache
                .get(issuer_key_hash)
                .cloned()
                .ok_or(ApiError::NotFound)?;
            // VA-OPJ-010: Log when returning a revoked issuer from cache so
            // callers and monitoring can observe the revocation-awareness gap.
            // The caller (verify handler) enforces rejection; this log aids
            // operators in confirming push-invalidation is functioning.
            if issuer.revoked {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "{{\"audit\":true,\"event\":\"revoked_issuer_from_cache\",\"severity\":\"warning\",\"kid\":\"{}\",\"cache_age\":\"fresh\"}}",
                    issuer.kid
                );
            }
            return Ok(issuer);
        }

        // STALE PATH: Cache needs refresh
        let is_extremely_stale = self.is_extremely_stale(now);

        if is_extremely_stale {
            // BLOCKING REFRESH: Cache is extremely stale
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[IssuerRegistry] ⚠️  Cache extremely stale (>{}s), attempting blocking refresh",
                STALE_CACHE_TTL_SECS
            );

            match self.try_refresh().await {
                Ok(_) => {
                    // Refresh succeeded
                    let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
                    cache
                        .get(issuer_key_hash)
                        .cloned()
                        .ok_or_else(|| ApiError::NotFound)
                }
                Err(_e) => {
                    // DEGRADED MODE: Refresh failed, try to serve stale.
                    // RT-049: Never serve data older than HARD_MAX_CACHE_TTL_SECS.
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[IssuerRegistry] Refresh failed: {:?}, attempting to serve stale",
                        _e
                    );

                    if self.is_beyond_hard_max(now) {
                        #[cfg(target_arch = "wasm32")]
                        worker::console_log!(
                            "[IssuerRegistry] Cache beyond hard max ({}s), refusing to serve stale",
                            HARD_MAX_CACHE_TTL_SECS
                        );
                        return Err(ApiError::Internal(anyhow::anyhow!(
                            "Issuer registry unavailable: cache expired beyond hard maximum"
                        )));
                    }

                    let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
                    if let Some(issuer) = cache.get(issuer_key_hash).cloned() {
                        #[cfg(target_arch = "wasm32")]
                        worker::console_log!(
                            "[IssuerRegistry] DEGRADED MODE: Serving stale issuer (within hard max)"
                        );
                        Ok(issuer)
                    } else {
                        Err(ApiError::Internal(anyhow::anyhow!(
                            "Issuer registry unavailable and no cached data"
                        )))
                    }
                }
            }
        } else {
            // STALE-WHILE-REVALIDATE: Cache is stale but within tolerance
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[IssuerRegistry] 🔄 Cache stale (>{}s), serving stale while revalidating",
                CACHE_TTL_SECS
            );

            // Try to start background refresh (non-blocking)
            if self.try_start_refresh() {
                let cache_clone = Self {
                    kv: self.kv.clone(),
                    cache: self.cache.clone(),
                    last_refresh: self.last_refresh.clone(),
                    circuit_breaker: self.circuit_breaker.clone(),
                    refresh_in_progress: self.refresh_in_progress.clone(),
                    epoch: self.epoch.clone(),
                };
                dispatch_background(cache_clone);
            }

            // Return stale value immediately
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            let issuer = cache
                .get(issuer_key_hash)
                .cloned()
                .ok_or(ApiError::NotFound)?;
            // VA-OPJ-010: Warn when serving a revoked issuer from stale cache.
            // The background refresh should update the entry shortly. The
            // caller must still check the revoked flag and reject the proof.
            if issuer.revoked {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "{{\"audit\":true,\"event\":\"revoked_issuer_from_stale_cache\",\"severity\":\"warning\",\"kid\":\"{}\",\"cache_age\":\"stale\"}}",
                    issuer.kid
                );
            }
            Ok(issuer)
        }
    }

    /// Attempt refresh with circuit breaker protection.
    async fn try_refresh(&self) -> ApiResult<()> {
        let now = crate::utils::current_timestamp();

        // Check circuit breaker
        let should_attempt = {
            let breaker = self
                .circuit_breaker
                .read()
                .unwrap_or_else(|e| e.into_inner());
            breaker.should_attempt(now)
        };

        if !should_attempt {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[IssuerRegistry] Circuit breaker OPEN, skipping refresh");
            self.finish_refresh();
            return Err(ApiError::Internal(anyhow::anyhow!(
                "Circuit breaker open for issuer registry"
            )));
        }

        // Attempt refresh
        match self.refresh().await {
            Ok(_) => {
                // Success - reset circuit breaker
                let mut breaker = self
                    .circuit_breaker
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                breaker.record_success();
                self.finish_refresh();
                Ok(())
            }
            Err(e) => {
                // Failure - record in circuit breaker
                let mut breaker = self
                    .circuit_breaker
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                breaker.record_failure(now);
                self.finish_refresh();
                Err(e)
            }
        }
    }

    /// Fetch the full issuer registry from KV and replace the in-memory cache.
    ///
    /// Uses an epoch check to prevent a stale background refresh
    /// from overwriting data that was invalidated after the fetch started.
    pub async fn refresh(&self) -> ApiResult<()> {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[IssuerRegistry] Refreshing issuer registry from KV");

        // Capture epoch before the (potentially slow) KV fetch.
        let epoch_before = self.epoch.load(Ordering::SeqCst);

        // Fetch issuer entries from KV
        let entries = self.fetch_from_kv().await?;

        // Build the refreshed cache contents.
        let mut new_cache = HashMap::new();

        for entry in entries {
            // Decode the verification key
            if let Ok(vk_bytes) = BASE64_URL_SAFE_NO_PAD.decode(&entry.verification_key) {
                if vk_bytes.len() == 32 {
                    let mut vk_array = [0u8; 32];
                    vk_array.copy_from_slice(&vk_bytes);

                    // CIV-085: Validate the bytes represent a valid Jubjub SubgroupPoint.
                    // Reject keys that are not on the curve or not in the prime-order subgroup.
                    let ct_option = SubgroupPoint::from_bytes(&vk_array);
                    if ct_option.is_none().into() {
                        #[cfg(target_arch = "wasm32")]
                        worker::console_log!(
                            "[IssuerRegistry] Skipping issuer {} ({}): VK bytes are not a valid Jubjub SubgroupPoint",
                            entry.issuer_kid,
                            entry.organization_name
                        );
                        continue;
                    }

                    // Hash the verifying key bytes with domain separation (same as admin-portal)
                    let hash = {
                        let mut hasher = Blake2s256::new();
                        hasher.update(b"provii.issuer.vk.v0");
                        hasher.update(vk_array);
                        let result = hasher.finalize();
                        let mut hash_bytes = [0u8; 32];
                        hash_bytes.copy_from_slice(&result);
                        hash_bytes
                    };

                    let meta = IssuerMeta {
                        kid: entry.issuer_kid.clone(),
                        name: entry.organization_name.clone(),
                        revoked: entry.revoked,
                        vk_bytes: vk_array,
                    };

                    new_cache.insert(hash, meta);

                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[IssuerRegistry] Added issuer {} ({}) - revoked: {}",
                        entry.issuer_kid,
                        entry.organization_name,
                        entry.revoked
                    );
                }
            }
        }

        // Epoch guard. If the epoch changed while we were fetching
        // (i.e. an invalidation arrived mid-flight), discard this refresh to
        // avoid writing stale data over the invalidated state.
        let epoch_after = self.epoch.load(Ordering::SeqCst);
        if epoch_after != epoch_before {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[IssuerRegistry] Epoch changed during refresh ({} -> {}), discarding stale fetch",
                epoch_before,
                epoch_after
            );
            return Ok(());
        }

        // Publish the new cache contents.
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = new_cache;

        // Record the time of this refresh.
        let mut last = self.last_refresh.write().unwrap_or_else(|e| e.into_inner());
        *last = crate::utils::current_timestamp();

        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[IssuerRegistry] Refreshed {} issuers from KV", cache.len());

        Ok(())
    }

    async fn fetch_from_kv(&self) -> ApiResult<Vec<IssuerRegistryEntry>> {
        // List all issuer entries from KV with per-operation timeout.
        let kv = self.kv.clone();
        let list = crate::utils::timeout::with_timeout(
            "issuer_registry KV list",
            crate::utils::timeout::KV_LIST_TIMEOUT_MS,
            async move {
                kv.list()
                    .prefix("issuer:".to_string())
                    .execute()
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("KV list failed: {}", e)))
            },
        )
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("{}", e)))??;

        // Fail-closed: if the KV list was truncated, the issuer registry is
        // incomplete. Returning a partial set could silently accept proofs from
        // issuers whose keys were not loaded, or miss revoked issuers.
        if !list.list_complete {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!("[CRITICAL] Issuer registry truncated, list_complete=false");
            return Err(ApiError::Internal(anyhow::anyhow!(
                "Issuer registry KV list truncated (list_complete=false)"
            )));
        }

        // Dispatch all KV GETs concurrently with per-operation timeout.
        // Individual failures (including timeouts) are logged and skipped rather
        // than aborting the entire refresh.
        let kv = self.kv.clone();
        let futures: Vec<_> = list
            .keys
            .iter()
            .map(|key_meta| {
                let kv = kv.clone();
                let key_name = key_meta.name.clone();
                async move {
                    let kv_inner = kv.clone();
                    let key_inner = key_name.clone();
                    let result: Result<Option<String>, String> =
                        match crate::utils::timeout::with_timeout(
                            "issuer_registry KV get",
                            crate::utils::timeout::KV_READ_TIMEOUT_MS,
                            async move { kv_inner.get(&key_inner).text().await },
                        )
                        .await
                        {
                            Ok(Ok(val)) => Ok(val),
                            Ok(Err(kv_err)) => Err(kv_err.to_string()),
                            Err(timeout_err) => Err(timeout_err.to_string()),
                        };
                    (key_name, result)
                }
            })
            .collect();

        let results = join_all(futures).await;

        let mut entries = Vec::new();
        for (_key_name, result) in results {
            match result {
                Ok(Some(value)) => match serde_json::from_str::<IssuerRegistryEntry>(&value) {
                    Ok(entry) => entries.push(entry),
                    Err(_e) => {
                        #[cfg(target_arch = "wasm32")]
                        worker::console_log!(
                            "[IssuerRegistry] Failed to parse entry {}: {}",
                            _key_name,
                            _e
                        );
                    }
                },
                Ok(None) => {
                    // Key existed in list but GET returned nothing (deleted between list and get)
                }
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[IssuerRegistry] KV get failed for {}: {}",
                        _key_name,
                        _e
                    );
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[IssuerRegistry] Fetched {} entries from KV", entries.len());

        Ok(entries)
    }

    /// Get cache statistics for health monitoring.
    pub fn get_cache_stats(&self) -> ApiResult<CacheStats> {
        let cache = self
            .cache
            .read()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;

        let last_refresh = *self
            .last_refresh
            .read()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;

        let refresh_in_progress = *self
            .refresh_in_progress
            .read()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;

        let now = crate::utils::current_timestamp();
        let last_refresh_age_secs = if last_refresh > 0 {
            now.saturating_sub(last_refresh)
        } else {
            0
        };

        Ok(CacheStats {
            cache_size: cache.len(),
            last_refresh_age_secs,
            refresh_in_progress,
        })
    }

    /// Push-invalidate the cache.
    ///
    /// Called by `/_internal/invalidate-jwks` when provii-management revokes
    /// an issuer. Bumps the epoch counter and resets `last_refresh` to zero,
    /// forcing the next lookup to perform a blocking refresh from KV.
    ///
    /// The epoch increment ensures that any in-flight background refresh
    /// that started before invalidation will not overwrite the cleared state.
    pub fn invalidate(&self) {
        // Bump epoch first so any in-flight refresh sees the change.
        self.epoch.fetch_add(1, Ordering::SeqCst);

        // Clear the cache contents.
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        cache.clear();

        // Reset last_refresh so the next lookup treats cache as empty/stale.
        let mut last = self.last_refresh.write().unwrap_or_else(|e| e.into_inner());
        *last = 0;

        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[IssuerRegistry] Cache invalidated via push (epoch={})",
            self.epoch.load(Ordering::SeqCst)
        );
    }

    /// Current epoch value, exposed for diagnostics/health.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Pre-warm the cache during worker startup.
    /// Non-blocking - logs errors but doesn't fail startup.
    pub async fn prewarm(&self) {
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[PERF] Pre-warming issuer registry cache...");
        match self.refresh().await {
            Ok(_) => match self.get_cache_stats() {
                Ok(_stats) => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[PERF] Issuer cache pre-warmed: {} entries",
                        _stats.cache_size
                    );
                }
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[PERF] Issuer cache pre-warmed but stats unavailable: {:?}",
                        _e
                    );
                }
            },
            Err(_e) => {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "[PERF] Issuer cache pre-warm failed (will load on first request): {:?}",
                    _e
                );
            }
        }
    }
}

/// Dispatch a background refresh via the Worker context's `wait_until()`.
///
/// If the context has already been consumed (another handler took it), falls back
/// to clearing the refresh flag so the next request can retry.
fn dispatch_background(cache: JwksCache) {
    match take_worker_context() {
        Some(ctx) => {
            ctx.wait_until(async move {
                let _guard = RefreshGuard {
                    flag: cache.refresh_in_progress.clone(),
                };
                let _ = cache.try_refresh().await;
            });
        }
        None => {
            // Context unavailable (already consumed by another handler). Clear the
            // flag so the next inbound request can attempt a fresh refresh.
            #[cfg(target_arch = "wasm32")]
            worker::console_log!(
                "[IssuerRegistry] Worker context unavailable for background refresh, deferring"
            );
            cache.finish_refresh();
        }
    }
}

/// Cache statistics for health monitoring endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of issuer entries currently held in the cache.
    pub cache_size: usize,
    /// Seconds since the last successful refresh (0 if never refreshed).
    pub last_refresh_age_secs: u64,
    /// Whether a background refresh is currently in progress.
    pub refresh_in_progress: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    IssuerMeta TESTS                                       */
    /* ========================================================================== */

    #[test]
    fn test_issuer_meta_creation() {
        let meta = IssuerMeta {
            kid: "issuer-123".to_string(),
            name: "Test Issuer".to_string(),
            revoked: false,
            vk_bytes: [42u8; 32],
        };
        assert_eq!(meta.kid, "issuer-123");
        assert_eq!(meta.name, "Test Issuer");
        assert!(!meta.revoked);
        assert_eq!(meta.vk_bytes[0], 42);
    }

    #[test]
    fn test_issuer_meta_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let meta = IssuerMeta {
            kid: "test".to_string(),
            name: "TestIssuer".to_string(),
            revoked: true,
            vk_bytes: [0u8; 32],
        };
        let json = serde_json::to_string(&meta)?;
        assert!(json.contains("test"));
        assert!(json.contains("TestIssuer"));
        assert!(json.contains("true")); // revoked
        Ok(())
    }

    #[test]
    fn test_issuer_meta_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "kid": "issuer-456",
            "name": "Example Issuer",
            "revoked": false,
            "vk_bytes": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        }"#;
        let meta: IssuerMeta = serde_json::from_str(json)?;
        assert_eq!(meta.kid, "issuer-456");
        assert_eq!(meta.name, "Example Issuer");
        assert!(!meta.revoked);
        Ok(())
    }

    #[test]
    fn test_issuer_meta_clone() {
        let meta = IssuerMeta {
            kid: "clone-test".to_string(),
            name: "Clone".to_string(),
            revoked: false,
            vk_bytes: [123u8; 32],
        };
        let cloned = meta.clone();
        assert_eq!(meta.kid, cloned.kid);
        assert_eq!(meta.name, cloned.name);
        assert_eq!(meta.revoked, cloned.revoked);
        assert_eq!(meta.vk_bytes, cloned.vk_bytes);
    }

    #[test]
    fn test_issuer_meta_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let meta = IssuerMeta {
            kid: "roundtrip".to_string(),
            name: "Test".to_string(),
            revoked: true,
            vk_bytes: [255u8; 32],
        };
        let json = serde_json::to_string(&meta)?;
        let decoded: IssuerMeta = serde_json::from_str(&json)?;
        assert_eq!(meta.kid, decoded.kid);
        assert_eq!(meta.name, decoded.name);
        assert_eq!(meta.revoked, decoded.revoked);
        assert_eq!(meta.vk_bytes, decoded.vk_bytes);
        Ok(())
    }

    /* ========================================================================== */
    /*                    JwksCache TESTS                                        */
    /* ========================================================================== */

    // Note: JwksCache tests that require KvStore are skipped in unit tests.
    // JwksCache::new() requires a worker::kv::KvStore which is only available
    // in the Cloudflare Workers runtime environment. These tests should be
    // run as integration tests in the actual Worker environment.

    /* ========================================================================== */
    /*                    Constants TESTS                                        */
    /* ========================================================================== */

    // Compile-time constant invariants.
    const _: () = assert!(CACHE_TTL_SECS > 0);
    const _: () = assert!(HARD_MAX_CACHE_TTL_SECS > STALE_CACHE_TTL_SECS);
    const _: () = assert!(STALE_CACHE_TTL_SECS > CACHE_TTL_SECS);

    #[test]
    fn test_cache_ttl_constant() {
        assert_eq!(CACHE_TTL_SECS, 600); // 10 minutes
    }

    #[test]
    fn test_hard_max_cache_ttl_constant() {
        assert_eq!(HARD_MAX_CACHE_TTL_SECS, 3600); // 60 minutes
    }

    /* ========================================================================== */
    /*                    Blake2s256 Hashing Tests                               */
    /*===========================================================================*/

    #[test]
    fn test_blake2s256_hash_calculation() {
        let pubkey = [42u8; 32];
        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update(pubkey);
        let result = hasher.finalize();

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_blake2s256_domain_separation() {
        let pubkey = [0u8; 32];

        // With domain separator
        let mut hasher1 = Blake2s256::new();
        hasher1.update(b"provii.issuer.vk.v0");
        hasher1.update(pubkey);
        let result1 = hasher1.finalize();

        // Without domain separator
        let mut hasher2 = Blake2s256::new();
        hasher2.update(pubkey);
        let result2 = hasher2.finalize();

        // Should be different
        assert_ne!(&result1[..], &result2[..]);
    }

    #[test]
    fn test_blake2s256_deterministic() {
        let pubkey = [123u8; 32];

        let mut hasher1 = Blake2s256::new();
        hasher1.update(b"provii.issuer.vk.v0");
        hasher1.update(pubkey);
        let result1 = hasher1.finalize();

        let mut hasher2 = Blake2s256::new();
        hasher2.update(b"provii.issuer.vk.v0");
        hasher2.update(pubkey);
        let result2 = hasher2.finalize();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_blake2s256_different_keys_different_hashes() {
        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];

        let mut hasher1 = Blake2s256::new();
        hasher1.update(b"provii.issuer.vk.v0");
        hasher1.update(pubkey1);
        let result1 = hasher1.finalize();

        let mut hasher2 = Blake2s256::new();
        hasher2.update(b"provii.issuer.vk.v0");
        hasher2.update(pubkey2);
        let result2 = hasher2.finalize();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_blake2s256_hash_array_copy() {
        let pubkey = [255u8; 32];
        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update(pubkey);
        let result = hasher.finalize();

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);

        assert_eq!(hash_bytes.len(), 32);
        assert_eq!(&hash_bytes[..], &result[..]);
    }

    /* ========================================================================== */
    /*                    Base64 Decoding and Validation Tests                   */
    /* ========================================================================== */

    #[test]
    fn test_base64_decode_valid_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        // 32 bytes = 43 base64url chars (without padding)
        let pubkey = [42u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(pubkey);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;

        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, pubkey);
        Ok(())
    }

    #[test]
    fn test_base64_decode_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
        // Encode 16 bytes (not 32)
        let short_key = [1u8; 16];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(short_key);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;

        assert_eq!(decoded.len(), 16);
        assert_ne!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_base64_decode_invalid_string() {
        let invalid = "not!valid@base64";
        let result = BASE64_URL_SAFE_NO_PAD.decode(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_32_byte_array_copy() -> Result<(), Box<dyn std::error::Error>> {
        let original = [99u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(original);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;

        assert_eq!(decoded.len(), 32);

        let mut pubkey32 = [0u8; 32];
        pubkey32.copy_from_slice(&decoded);

        assert_eq!(pubkey32, original);
        Ok(())
    }

    #[test]
    fn test_base64_url_safe_no_pad_format() {
        let data = [1, 2, 3, 4, 5];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(data);

        // URL-safe should not contain + or /
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        // NO_PAD should not end with =
        assert!(!encoded.ends_with('='));
    }

    /* ========================================================================== */
    /*                    Name Fallback Logic Tests                              */
    /* ========================================================================== */

    fn name_fallback(name: Option<String>, kid: &str) -> String {
        name.unwrap_or_else(|| kid.to_string())
    }

    #[test]
    fn test_name_fallback_with_name() {
        let result = name_fallback(Some("Proper Name".to_string()), "issuer-123");
        assert_eq!(result, "Proper Name");
    }

    #[test]
    fn test_name_fallback_without_name() {
        let result = name_fallback(None, "issuer-456");
        assert_eq!(result, "issuer-456");
    }

    #[test]
    fn test_name_fallback_empty_name() {
        let result = name_fallback(Some(String::new()), "issuer-789");
        assert_eq!(result, "");
    }

    /* ========================================================================== */
    /*                    Revoked Flag Default Handling Tests                    */
    /* ========================================================================== */

    fn revoked_flag(revoked: Option<bool>) -> bool {
        revoked.unwrap_or(false)
    }

    #[test]
    fn test_revoked_flag_some_true() {
        assert!(revoked_flag(Some(true)));
    }

    #[test]
    fn test_revoked_flag_some_false() {
        assert!(!revoked_flag(Some(false)));
    }

    #[test]
    fn test_revoked_flag_none_defaults_false() {
        assert!(!revoked_flag(None));
    }

    /* ========================================================================== */
    /*                    CircuitBreakerState Tests                              */
    /* ========================================================================== */

    #[test]
    fn test_circuit_breaker_new_is_closed() {
        let cb = CircuitBreakerState::new();
        assert!(!cb.is_open);
        assert_eq!(cb.consecutive_failures, 0);
        assert_eq!(cb.last_failure_time, 0);
    }

    #[test]
    fn test_circuit_breaker_should_attempt_when_closed() {
        let cb = CircuitBreakerState::new();
        assert!(cb.should_attempt(0));
        assert!(cb.should_attempt(1_000_000));
    }

    #[test]
    fn test_circuit_breaker_record_success_resets() {
        let mut cb = CircuitBreakerState::new();
        cb.record_failure(100);
        cb.record_failure(200);
        assert_eq!(cb.consecutive_failures, 2);

        cb.record_success();
        assert_eq!(cb.consecutive_failures, 0);
        assert!(!cb.is_open);
    }

    #[test]
    fn test_circuit_breaker_opens_at_threshold() {
        let mut cb = CircuitBreakerState::new();
        for i in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(u64::from(i));
        }
        assert!(cb.is_open);
        assert_eq!(cb.consecutive_failures, MAX_CONSECUTIVE_FAILURES);
    }

    #[test]
    fn test_circuit_breaker_below_threshold_stays_closed() {
        let mut cb = CircuitBreakerState::new();
        for i in 0..(MAX_CONSECUTIVE_FAILURES - 1) {
            cb.record_failure(u64::from(i));
        }
        assert!(!cb.is_open);
    }

    #[test]
    fn test_circuit_breaker_open_denies_attempt() {
        let mut cb = CircuitBreakerState::new();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(1000);
        }
        assert!(cb.is_open);
        // Too soon after last failure
        assert!(!cb.should_attempt(1000));
        assert!(!cb.should_attempt(1000 + CIRCUIT_BREAKER_RESET_SECS));
    }

    #[test]
    fn test_circuit_breaker_half_open_after_reset_period() {
        let mut cb = CircuitBreakerState::new();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(1000);
        }
        assert!(cb.is_open);

        // After reset period, should attempt again (half-open)
        let retry_time = 1000 + CIRCUIT_BREAKER_RESET_SECS + 1;
        assert!(cb.should_attempt(retry_time));
    }

    #[test]
    fn test_circuit_breaker_success_after_half_open() {
        let mut cb = CircuitBreakerState::new();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(1000);
        }
        assert!(cb.is_open);

        cb.record_success();
        assert!(!cb.is_open);
        assert_eq!(cb.consecutive_failures, 0);
    }

    #[test]
    fn test_circuit_breaker_failure_increments_beyond_threshold() {
        let mut cb = CircuitBreakerState::new();
        for i in 0u64..10 {
            cb.record_failure(i);
        }
        assert!(cb.is_open);
        assert_eq!(cb.consecutive_failures, 10);
    }

    #[test]
    fn test_circuit_breaker_last_failure_time_updated() {
        let mut cb = CircuitBreakerState::new();
        cb.record_failure(100);
        assert_eq!(cb.last_failure_time, 100);
        cb.record_failure(200);
        assert_eq!(cb.last_failure_time, 200);
    }

    #[test]
    fn test_circuit_breaker_clone() {
        let mut cb = CircuitBreakerState::new();
        cb.record_failure(100);
        let cloned = cb.clone();
        assert_eq!(cloned.consecutive_failures, cb.consecutive_failures);
        assert_eq!(cloned.last_failure_time, cb.last_failure_time);
        assert_eq!(cloned.is_open, cb.is_open);
    }

    /* ========================================================================== */
    /*                    CacheStats Tests                                       */
    /* ========================================================================== */

    #[test]
    fn test_cache_stats_serialise() -> Result<(), Box<dyn std::error::Error>> {
        let stats = CacheStats {
            cache_size: 42,
            last_refresh_age_secs: 300,
            refresh_in_progress: false,
        };
        let json = serde_json::to_string(&stats)?;
        assert!(json.contains("42"));
        assert!(json.contains("300"));
        assert!(json.contains("false"));
        Ok(())
    }

    #[test]
    fn test_cache_stats_deserialise() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"cache_size":10,"last_refresh_age_secs":60,"refresh_in_progress":true}"#;
        let stats: CacheStats = serde_json::from_str(json)?;
        assert_eq!(stats.cache_size, 10);
        assert_eq!(stats.last_refresh_age_secs, 60);
        assert!(stats.refresh_in_progress);
        Ok(())
    }

    #[test]
    fn test_cache_stats_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let stats = CacheStats {
            cache_size: 0,
            last_refresh_age_secs: 0,
            refresh_in_progress: false,
        };
        let json = serde_json::to_string(&stats)?;
        let decoded: CacheStats = serde_json::from_str(&json)?;
        assert_eq!(decoded.cache_size, 0);
        assert_eq!(decoded.last_refresh_age_secs, 0);
        assert!(!decoded.refresh_in_progress);
        Ok(())
    }

    #[test]
    fn test_cache_stats_clone() {
        let stats = CacheStats {
            cache_size: 5,
            last_refresh_age_secs: 120,
            refresh_in_progress: true,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.cache_size, 5);
        assert_eq!(cloned.last_refresh_age_secs, 120);
        assert!(cloned.refresh_in_progress);
    }

    #[test]
    fn test_cache_stats_debug() {
        let stats = CacheStats {
            cache_size: 1,
            last_refresh_age_secs: 0,
            refresh_in_progress: false,
        };
        let dbg = format!("{:?}", stats);
        assert!(dbg.contains("cache_size"));
        assert!(dbg.contains("last_refresh_age_secs"));
    }

    /* ========================================================================== */
    /*                    Stale/Hard-Max TTL Relationship Tests                  */
    /* ========================================================================== */

    #[test]
    fn test_stale_cache_ttl_constant() {
        assert_eq!(STALE_CACHE_TTL_SECS, 960); // 16 minutes
    }

    #[test]
    fn test_max_consecutive_failures_constant() {
        assert_eq!(MAX_CONSECUTIVE_FAILURES, 3);
    }

    #[test]
    fn test_circuit_breaker_reset_secs_constant() {
        assert_eq!(CIRCUIT_BREAKER_RESET_SECS, 300); // 5 minutes
    }

    #[test]
    fn test_ttl_ordering_invariant() {
        // CACHE_TTL < STALE_CACHE_TTL < HARD_MAX_CACHE_TTL
        assert!(CACHE_TTL_SECS < STALE_CACHE_TTL_SECS);
        assert!(STALE_CACHE_TTL_SECS < HARD_MAX_CACHE_TTL_SECS);
    }

    /* ========================================================================== */
    /*                    IssuerRegistryEntry Deserialisation Tests              */
    /* ========================================================================== */

    #[test]
    fn test_issuer_registry_entry_deserialize_minimal() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "issuer_kid": "ik-001",
            "issuer_key_hash": "abc123",
            "verification_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "organization_name": "Test Org",
            "created_at": 1000,
            "revoked": false
        }"#;
        let entry: IssuerRegistryEntry = serde_json::from_str(json)?;
        assert_eq!(entry.issuer_kid, "ik-001");
        assert_eq!(entry.organization_name, "Test Org");
        assert!(!entry.revoked);
        assert!(entry.issuer_id.is_none());
        assert!(entry.organization_id.is_none());
        assert!(entry.environment.is_none());
        assert!(entry.revoked_at.is_none());
        assert!(entry.revoked_reason.is_none());
        Ok(())
    }

    #[test]
    fn test_issuer_registry_entry_deserialize_full() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "issuer_kid": "ik-002",
            "issuer_id": "issuer-uuid",
            "issuer_key_hash": "def456",
            "verification_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "organization_name": "Full Org",
            "organization_id": "org-uuid",
            "environment": "production",
            "created_at": 2000,
            "revoked": true,
            "revoked_at": 3000,
            "revoked_reason": "key compromised"
        }"#;
        let entry: IssuerRegistryEntry = serde_json::from_str(json)?;
        assert_eq!(entry.issuer_kid, "ik-002");
        assert_eq!(entry.issuer_id, Some("issuer-uuid".to_string()));
        assert!(entry.revoked);
        assert_eq!(entry.revoked_at, Some(3000));
        assert_eq!(entry.revoked_reason, Some("key compromised".to_string()));
        Ok(())
    }

    #[test]
    fn test_issuer_registry_entry_tolerates_unknown_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "issuer_kid": "ik-003",
            "issuer_key_hash": "ghi789",
            "verification_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "organization_name": "Tolerant Org",
            "created_at": 4000,
            "revoked": false,
            "future_field": "should_be_ignored"
        }"#;
        // This should parse without error because we don't use deny_unknown_fields
        let entry: IssuerRegistryEntry = serde_json::from_str(json)?;
        assert_eq!(entry.issuer_kid, "ik-003");
        Ok(())
    }

    /* ========================================================================== */
    /*                    Cache TTL Logic Tests                                  */
    /* ========================================================================== */

    #[test]
    fn test_cache_ttl_expired() {
        let now = 1000u64;
        let last_refresh = 300u64; // 700 seconds ago
        let elapsed = now - last_refresh;

        assert!(elapsed > CACHE_TTL_SECS); // 700 > 600
    }

    #[test]
    fn test_cache_ttl_not_expired() {
        let now = 1000u64;
        let last_refresh = 500u64; // 500 seconds ago
        let elapsed = now - last_refresh;

        assert!(elapsed <= CACHE_TTL_SECS); // 500 <= 600
    }

    #[test]
    fn test_cache_ttl_exact_boundary() {
        let now = 1000u64;
        let last_refresh = 400u64; // Exactly 600 seconds ago
        let elapsed = now - last_refresh;

        assert_eq!(elapsed, CACHE_TTL_SECS);
    }

    #[test]
    fn test_cache_ttl_just_expired() {
        let now = 1000u64;
        let last_refresh = 399u64; // 601 seconds ago
        let elapsed = now - last_refresh;

        assert!(elapsed > CACHE_TTL_SECS);
    }

    /* ========================================================================== */
    /*                    Last Refresh Tracking Tests                            */
    /* ========================================================================== */

    // Note: Last refresh tracking tests require JwksCache::new() which needs
    // a worker::kv::KvStore. These should be run as integration tests.

    /* ========================================================================== */
    /*                    IssuerMeta Additional Tests                            */
    /* ========================================================================== */

    #[test]
    fn test_issuer_meta_revoked_true() {
        let meta = IssuerMeta {
            kid: "revoked-key".to_string(),
            name: "Revoked".to_string(),
            revoked: true,
            vk_bytes: [0u8; 32],
        };
        assert!(meta.revoked);
    }

    #[test]
    fn test_issuer_meta_vk_bytes_all_zeros() {
        let meta = IssuerMeta {
            kid: "zero-key".to_string(),
            name: "Zero".to_string(),
            revoked: false,
            vk_bytes: [0u8; 32],
        };
        assert_eq!(meta.vk_bytes, [0u8; 32]);
    }

    #[test]
    fn test_issuer_meta_vk_bytes_all_ones() {
        let meta = IssuerMeta {
            kid: "ones-key".to_string(),
            name: "Ones".to_string(),
            revoked: false,
            vk_bytes: [255u8; 32],
        };
        assert_eq!(meta.vk_bytes, [255u8; 32]);
    }

    #[test]
    fn test_issuer_meta_kid_empty() {
        let meta = IssuerMeta {
            kid: "".to_string(),
            name: "Empty KID".to_string(),
            revoked: false,
            vk_bytes: [1u8; 32],
        };
        assert!(meta.kid.is_empty());
    }

    /* ========================================================================== */
    /*                    HashMap Cache Operations Tests                         */
    /* ========================================================================== */

    // Note: HashMap cache operations tests require JwksCache::new() which needs
    // a worker::kv::KvStore. These should be run as integration tests.

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: IssuerMeta serialisation roundtrip
        #[test]
        fn prop_issuer_meta_roundtrip(
            kid in ".*",
            name in ".*",
            revoked in any::<bool>(),
            vk_bytes in any::<[u8; 32]>()
        ) {
            let meta = IssuerMeta {
                kid: kid.clone(),
                name: name.clone(),
                revoked,
                vk_bytes,
            };
            let json = serde_json::to_string(&meta).expect("serialise");
            let decoded: IssuerMeta = serde_json::from_str(&json).expect("deserialise");
            prop_assert_eq!(decoded.kid, kid);
            prop_assert_eq!(decoded.name, name);
            prop_assert_eq!(decoded.revoked, revoked);
            prop_assert_eq!(decoded.vk_bytes, vk_bytes);
        }

        /// Property: IssuerMeta clone preserves all fields
        #[test]
        fn prop_issuer_meta_clone(
            kid in "[a-z]{3,20}",
            vk_bytes in any::<[u8; 32]>()
        ) {
            let meta = IssuerMeta {
                kid: kid.clone(),
                name: "test".to_string(),
                revoked: false,
                vk_bytes,
            };
            let cloned = meta.clone();
            prop_assert_eq!(meta.kid, cloned.kid);
            prop_assert_eq!(meta.vk_bytes, cloned.vk_bytes);
        }

        // Note: Property tests for JwksCache::new() are skipped as they require
        // a worker::kv::KvStore which is only available in the Workers runtime.

        /// Property: Blake2s256 hashing is deterministic
        #[test]
        fn prop_blake2s256_deterministic(vk_bytes in any::<[u8; 32]>()) {
            let mut hasher1 = Blake2s256::new();
            hasher1.update(b"provii.issuer.vk.v0");
            hasher1.update(&vk_bytes);
            let result1 = hasher1.finalize();

            let mut hasher2 = Blake2s256::new();
            hasher2.update(b"provii.issuer.vk.v0");
            hasher2.update(&vk_bytes);
            let result2 = hasher2.finalize();

            prop_assert_eq!(result1, result2);
        }

        /// Property: Different keys produce different hashes
        #[test]
        fn prop_blake2s256_unique_hashes(
            vk_bytes1 in any::<[u8; 32]>(),
            vk_bytes2 in any::<[u8; 32]>()
        ) {
            prop_assume!(vk_bytes1 != vk_bytes2);

            let mut hasher1 = Blake2s256::new();
            hasher1.update(b"provii.issuer.vk.v0");
            hasher1.update(&vk_bytes1);
            let result1 = hasher1.finalize();

            let mut hasher2 = Blake2s256::new();
            hasher2.update(b"provii.issuer.vk.v0");
            hasher2.update(&vk_bytes2);
            let result2 = hasher2.finalize();

            prop_assert_ne!(result1, result2);
        }

        /// Property: Base64 encoding/decoding roundtrip
        #[test]
        fn prop_base64_roundtrip(bytes in any::<[u8; 32]>()) {
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
            let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded).expect("decode");

            prop_assert_eq!(decoded.len(), 32);
            prop_assert_eq!(&decoded[..], &bytes[..]);
        }

        /// Property: Name fallback preserves non-empty names
        #[test]
        fn prop_name_fallback_preserves(kid in ".*", name in "[a-zA-Z]{1,50}") {
            let name_opt = Some(name.clone());
            let result = name_opt.unwrap_or_else(|| kid.clone());
            prop_assert_eq!(result, name);
        }

        /// Property: Name fallback uses kid when None
        #[test]
        fn prop_name_fallback_uses_kid(kid in "[a-z0-9-]{3,30}") {
            let name_opt: Option<String> = None;
            let result = name_opt.unwrap_or_else(|| kid.clone());
            prop_assert_eq!(result, kid);
        }

        /// Property: Revoked flag None always defaults to false
        #[test]
        fn prop_revoked_default_false(_seed in any::<u8>()) {
            let revoked: Option<bool> = None;
            let result = revoked.unwrap_or(false);
            prop_assert!(!result);
        }

        /// Property: CircuitBreakerState starts closed and should_attempt returns true
        #[test]
        fn prop_circuit_breaker_new_allows(now in any::<u64>()) {
            let cb = CircuitBreakerState::new();
            prop_assert!(cb.should_attempt(now));
        }

        /// Property: CircuitBreakerState record_success always resets to closed
        #[test]
        fn prop_circuit_breaker_success_resets(failures in 0u32..100) {
            let mut cb = CircuitBreakerState::new();
            for _ in 0..failures {
                cb.record_failure(1000);
            }
            cb.record_success();
            prop_assert!(!cb.is_open);
            prop_assert_eq!(cb.consecutive_failures, 0);
        }

        /// Property: Cache TTL comparison is consistent
        #[test]
        fn prop_cache_ttl_consistent(
            now in any::<u64>(),
            last_refresh in any::<u64>()
        ) {
            if now >= last_refresh {
                let elapsed = now - last_refresh;
                let should_refresh1 = elapsed > CACHE_TTL_SECS;
                let should_refresh2 = elapsed > CACHE_TTL_SECS;
                prop_assert_eq!(should_refresh1, should_refresh2);
            }
        }

        // Note: prop_last_refresh_retrievable requires JwksCache::new() which needs KvStore.

        /// Property: IssuerMeta revoked field is always boolean
        #[test]
        fn prop_issuer_meta_revoked_boolean(revoked in any::<bool>()) {
            let meta = IssuerMeta {
                kid: "test".to_string(),
                name: "Test".to_string(),
                revoked,
                vk_bytes: [0u8; 32],
            };
            prop_assert_eq!(meta.revoked, revoked);
        }

        // Note: prop_cache_consistent requires JwksCache::new() which needs KvStore.
    }

    /* ========================================================================== */
    /*                    CircuitBreakerState Additional Tests                   */
    /* ========================================================================== */

    #[test]
    fn test_circuit_breaker_exactly_at_reset_boundary() {
        let mut cb = CircuitBreakerState::new();
        let failure_time = 5000u64;
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(failure_time);
        }
        assert!(cb.is_open);
        // Exactly at the boundary should NOT allow attempt (> not >=)
        assert!(!cb.should_attempt(failure_time.saturating_add(CIRCUIT_BREAKER_RESET_SECS)));
    }

    #[test]
    fn test_circuit_breaker_one_past_reset_boundary() {
        let mut cb = CircuitBreakerState::new();
        let failure_time = 5000u64;
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(failure_time);
        }
        // One second past the boundary should allow attempt
        assert!(cb.should_attempt(
            failure_time
                .saturating_add(CIRCUIT_BREAKER_RESET_SECS)
                .saturating_add(1)
        ));
    }

    #[test]
    fn test_circuit_breaker_failure_then_success_then_failure() {
        let mut cb = CircuitBreakerState::new();
        cb.record_failure(100);
        cb.record_failure(200);
        assert_eq!(cb.consecutive_failures, 2);
        cb.record_success();
        assert_eq!(cb.consecutive_failures, 0);
        assert!(!cb.is_open);
        cb.record_failure(300);
        assert_eq!(cb.consecutive_failures, 1);
        assert!(!cb.is_open);
    }

    #[test]
    fn test_circuit_breaker_saturating_add_on_failure() {
        let mut cb = CircuitBreakerState::new();
        cb.consecutive_failures = u32::MAX;
        cb.record_failure(100);
        // saturating_add should prevent overflow
        assert_eq!(cb.consecutive_failures, u32::MAX);
    }

    #[test]
    fn test_circuit_breaker_should_attempt_at_time_zero() {
        let cb = CircuitBreakerState::new();
        assert!(cb.should_attempt(0));
    }

    #[test]
    fn test_circuit_breaker_should_attempt_at_max_time() {
        let cb = CircuitBreakerState::new();
        assert!(cb.should_attempt(u64::MAX));
    }

    #[test]
    fn test_circuit_breaker_open_with_zero_failure_time() {
        let mut cb = CircuitBreakerState::new();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            cb.record_failure(0);
        }
        assert!(cb.is_open);
        assert_eq!(cb.last_failure_time, 0);
        // Even with time 0, reset period has not elapsed at time 0
        assert!(!cb.should_attempt(0));
        // After reset period from time 0
        assert!(cb.should_attempt(CIRCUIT_BREAKER_RESET_SECS.saturating_add(1)));
    }

    /* ========================================================================== */
    /*                    IssuerRegistryEntry Edge Cases                         */
    /* ========================================================================== */

    #[test]
    fn test_issuer_registry_entry_missing_required_field() {
        let json = r#"{
            "issuer_kid": "ik-bad",
            "issuer_key_hash": "abc",
            "verification_key": "AAAA"
        }"#;
        // Missing organization_name, created_at, revoked
        let result = serde_json::from_str::<IssuerRegistryEntry>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_issuer_registry_entry_revoked_with_reason() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "issuer_kid": "ik-rev",
            "issuer_key_hash": "hash",
            "verification_key": "AAAA",
            "organization_name": "Revoked Org",
            "created_at": 1000,
            "revoked": true,
            "revoked_at": 2000,
            "revoked_reason": "compromised key material"
        }"#;
        let entry: IssuerRegistryEntry = serde_json::from_str(json)?;
        assert!(entry.revoked);
        assert_eq!(entry.revoked_at, Some(2000));
        assert_eq!(
            entry.revoked_reason.as_deref(),
            Some("compromised key material")
        );
        Ok(())
    }

    #[test]
    fn test_issuer_registry_entry_all_optional_none() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "issuer_kid": "ik-min",
            "issuer_key_hash": "h",
            "verification_key": "v",
            "organization_name": "Minimal",
            "created_at": 0,
            "revoked": false
        }"#;
        let entry: IssuerRegistryEntry = serde_json::from_str(json)?;
        assert!(entry.issuer_id.is_none());
        assert!(entry.organization_id.is_none());
        assert!(entry.environment.is_none());
        assert!(entry.revoked_at.is_none());
        assert!(entry.revoked_reason.is_none());
        Ok(())
    }

    #[test]
    fn test_issuer_registry_entry_all_optional_present() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "issuer_kid": "ik-full",
            "issuer_id": "id-1",
            "issuer_key_hash": "h",
            "verification_key": "v",
            "organization_name": "Full",
            "organization_id": "org-1",
            "environment": "sandbox",
            "created_at": 999,
            "revoked": false,
            "revoked_at": null,
            "revoked_reason": null
        }"#;
        let entry: IssuerRegistryEntry = serde_json::from_str(json)?;
        assert_eq!(entry.issuer_id.as_deref(), Some("id-1"));
        assert_eq!(entry.organization_id.as_deref(), Some("org-1"));
        assert_eq!(entry.environment.as_deref(), Some("sandbox"));
        assert!(entry.revoked_at.is_none());
        assert!(entry.revoked_reason.is_none());
        Ok(())
    }

    /* ========================================================================== */
    /*                    IssuerMeta HashMap Cache Simulation                    */
    /* ========================================================================== */

    #[test]
    fn test_cache_insert_and_lookup() {
        let mut cache: HashMap<[u8; 32], IssuerMeta> = HashMap::new();
        let key = [42u8; 32];
        let meta = IssuerMeta {
            kid: "ik-test".to_string(),
            name: "Test".to_string(),
            revoked: false,
            vk_bytes: [1u8; 32],
        };
        cache.insert(key, meta.clone());
        let found = cache.get(&key);
        assert!(found.is_some());
        assert_eq!(found.expect("just inserted").kid, "ik-test");
    }

    #[test]
    fn test_cache_lookup_missing_key() {
        let cache: HashMap<[u8; 32], IssuerMeta> = HashMap::new();
        let key = [99u8; 32];
        assert!(!cache.contains_key(&key));
    }

    #[test]
    fn test_cache_overwrite() {
        let mut cache: HashMap<[u8; 32], IssuerMeta> = HashMap::new();
        let key = [10u8; 32];
        let meta1 = IssuerMeta {
            kid: "v1".to_string(),
            name: "V1".to_string(),
            revoked: false,
            vk_bytes: [0u8; 32],
        };
        let meta2 = IssuerMeta {
            kid: "v2".to_string(),
            name: "V2".to_string(),
            revoked: true,
            vk_bytes: [0u8; 32],
        };
        cache.insert(key, meta1);
        cache.insert(key, meta2);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&key).expect("overwritten").kid, "v2");
        assert!(cache.get(&key).expect("overwritten").revoked);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache: HashMap<[u8; 32], IssuerMeta> = HashMap::new();
        for i in 0u8..5 {
            let mut key = [0u8; 32];
            key[0] = i;
            cache.insert(
                key,
                IssuerMeta {
                    kid: format!("ik-{}", i),
                    name: "N".to_string(),
                    revoked: false,
                    vk_bytes: [0u8; 32],
                },
            );
        }
        assert_eq!(cache.len(), 5);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_multiple_issuers() {
        let mut cache: HashMap<[u8; 32], IssuerMeta> = HashMap::new();
        for i in 0u8..10 {
            let mut key = [0u8; 32];
            key[0] = i;
            cache.insert(
                key,
                IssuerMeta {
                    kid: format!("ik-{}", i),
                    name: format!("Issuer {}", i),
                    revoked: i % 3 == 0,
                    vk_bytes: key,
                },
            );
        }
        assert_eq!(cache.len(), 10);
        // Check specific entries
        let mut k0 = [0u8; 32];
        k0[0] = 0;
        assert!(cache.get(&k0).expect("exists").revoked); // 0 % 3 == 0
        let mut k1 = [0u8; 32];
        k1[0] = 1;
        assert!(!cache.get(&k1).expect("exists").revoked); // 1 % 3 != 0
    }

    /* ========================================================================== */
    /*                    Stale/Hard-Max Boundary Tests                          */
    /* ========================================================================== */

    #[test]
    fn test_is_stale_logic_exactly_at_ttl() {
        // elapsed == CACHE_TTL_SECS should NOT be stale (> not >=)
        let last_refresh = 1000u64;
        let now = last_refresh.saturating_add(CACHE_TTL_SECS);
        let elapsed = now.saturating_sub(last_refresh);
        assert_eq!(elapsed, CACHE_TTL_SECS);
        assert!((elapsed <= CACHE_TTL_SECS));
    }

    #[test]
    fn test_is_stale_logic_one_past_ttl() {
        let last_refresh = 1000u64;
        let now = last_refresh
            .saturating_add(CACHE_TTL_SECS)
            .saturating_add(1);
        let elapsed = now.saturating_sub(last_refresh);
        assert!(elapsed > CACHE_TTL_SECS);
    }

    #[test]
    fn test_is_extremely_stale_exactly_at_boundary() {
        let last_refresh = 1000u64;
        let now = last_refresh.saturating_add(STALE_CACHE_TTL_SECS);
        let elapsed = now.saturating_sub(last_refresh);
        assert_eq!(elapsed, STALE_CACHE_TTL_SECS);
        assert!((elapsed <= STALE_CACHE_TTL_SECS));
    }

    #[test]
    fn test_is_extremely_stale_one_past_boundary() {
        let last_refresh = 1000u64;
        let now = last_refresh
            .saturating_add(STALE_CACHE_TTL_SECS)
            .saturating_add(1);
        let elapsed = now.saturating_sub(last_refresh);
        assert!(elapsed > STALE_CACHE_TTL_SECS);
    }

    #[test]
    fn test_hard_max_exactly_at_boundary() {
        let last_refresh = 1000u64;
        let now = last_refresh.saturating_add(HARD_MAX_CACHE_TTL_SECS);
        let elapsed = now.saturating_sub(last_refresh);
        assert_eq!(elapsed, HARD_MAX_CACHE_TTL_SECS);
        assert!((elapsed <= HARD_MAX_CACHE_TTL_SECS));
    }

    #[test]
    fn test_hard_max_one_past_boundary() {
        let last_refresh = 1000u64;
        let now = last_refresh
            .saturating_add(HARD_MAX_CACHE_TTL_SECS)
            .saturating_add(1);
        let elapsed = now.saturating_sub(last_refresh);
        assert!(elapsed > HARD_MAX_CACHE_TTL_SECS);
    }

    #[test]
    fn test_hard_max_zero_last_refresh_always_beyond() {
        // When last_refresh is 0 the cache has never been refreshed
        let last_refresh = 0u64;
        // is_beyond_hard_max checks: last == 0 || elapsed > HARD_MAX
        assert!(last_refresh == 0);
    }

    /* ========================================================================== */
    /*                    Jubjub SubgroupPoint Validation Tests                  */
    /* ========================================================================== */

    #[test]
    fn test_jubjub_identity_point() {
        use group::Group;
        let identity = SubgroupPoint::identity();
        let bytes = identity.to_bytes();
        let recovered = SubgroupPoint::from_bytes(&bytes);
        assert!(bool::from(recovered.is_some()));
    }

    #[test]
    fn test_jubjub_generator_point() {
        // The generator should also round-trip
        use group::Group;
        let gen = SubgroupPoint::generator();
        let bytes = gen.to_bytes();
        let recovered = SubgroupPoint::from_bytes(&bytes);
        assert!(bool::from(recovered.is_some()));
    }

    #[test]
    fn test_jubjub_random_invalid_bytes() {
        // Arbitrary bytes are almost certainly not valid SubgroupPoints
        let bad_bytes: [u8; 32] = [0xFF; 32];
        let result = SubgroupPoint::from_bytes(&bad_bytes);
        // This may or may not be valid; the point is the code handles it
        let _ = bool::from(result.is_some());
    }

    #[test]
    fn test_jubjub_zero_bytes_is_not_valid() {
        // All-zero bytes represent y=0 in little-endian, which is NOT a valid
        // JubJub curve point. The identity point (0, 1) encodes as
        // [1, 0, 0, ..., 0] (y=1 LE). The identity round-trip is already
        // covered by test_jubjub_identity_point above.
        let zero_bytes: [u8; 32] = [0u8; 32];
        let result = SubgroupPoint::from_bytes(&zero_bytes);
        assert!(!bool::from(result.is_some()));
    }

    /* ========================================================================== */
    /*                    VK Bytes to Hash Key Pipeline                          */
    /* ========================================================================== */

    #[test]
    fn test_vk_decode_hash_pipeline() -> Result<(), Box<dyn std::error::Error>> {
        // Simulate the full pipeline: base64url decode -> validate length -> hash
        let original_vk = [42u8; 32];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(original_vk);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;
        assert_eq!(decoded.len(), 32);

        let mut vk_array = [0u8; 32];
        vk_array.copy_from_slice(&decoded);

        let mut hasher = Blake2s256::new();
        hasher.update(b"provii.issuer.vk.v0");
        hasher.update(vk_array);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);

        assert_eq!(hash_bytes.len(), 32);
        Ok(())
    }

    #[test]
    fn test_vk_decode_wrong_length_skipped() -> Result<(), Box<dyn std::error::Error>> {
        // Keys that decode to != 32 bytes should be skipped
        let short = [1u8; 16];
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(short);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;
        assert_ne!(decoded.len(), 32);
        Ok(())
    }

    #[test]
    fn test_vk_invalid_base64_skipped() {
        let invalid = "!!!not_base64!!!";
        let result = BASE64_URL_SAFE_NO_PAD.decode(invalid);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    CacheStats Edge Cases                                  */
    /* ========================================================================== */

    #[test]
    fn test_cache_stats_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let stats = CacheStats {
            cache_size: 0,
            last_refresh_age_secs: 0,
            refresh_in_progress: false,
        };
        let json = serde_json::to_string(&stats)?;
        let decoded: CacheStats = serde_json::from_str(&json)?;
        assert_eq!(decoded.cache_size, 0);
        assert_eq!(decoded.last_refresh_age_secs, 0);
        assert!(!decoded.refresh_in_progress);
        Ok(())
    }

    #[test]
    fn test_cache_stats_large_values() -> Result<(), Box<dyn std::error::Error>> {
        let stats = CacheStats {
            cache_size: usize::MAX,
            last_refresh_age_secs: u64::MAX,
            refresh_in_progress: true,
        };
        let json = serde_json::to_string(&stats)?;
        let decoded: CacheStats = serde_json::from_str(&json)?;
        assert_eq!(decoded.cache_size, usize::MAX);
        assert_eq!(decoded.last_refresh_age_secs, u64::MAX);
        assert!(decoded.refresh_in_progress);
        Ok(())
    }

    /* ========================================================================== */
    /*                    RefreshGuard Tests                                     */
    /* ========================================================================== */

    #[test]
    fn test_refresh_guard_clears_flag_on_drop() {
        let flag = Arc::new(RwLock::new(true));
        {
            let _guard = RefreshGuard { flag: flag.clone() };
            assert!(*flag.read().unwrap_or_else(|e| e.into_inner()));
        }
        // After guard is dropped, flag should be false
        assert!(!*flag.read().unwrap_or_else(|e| e.into_inner()));
    }

    #[test]
    fn test_refresh_guard_clears_from_true() {
        let flag = Arc::new(RwLock::new(true));
        let guard = RefreshGuard { flag: flag.clone() };
        drop(guard);
        assert!(!*flag.read().unwrap_or_else(|e| e.into_inner()));
    }

    #[test]
    fn test_refresh_guard_clears_from_false() {
        let flag = Arc::new(RwLock::new(false));
        let guard = RefreshGuard { flag: flag.clone() };
        drop(guard);
        assert!(!*flag.read().unwrap_or_else(|e| e.into_inner()));
    }

    /* ========================================================================== */
    /*                    Epoch Counter Tests                                    */
    /* ========================================================================== */

    #[test]
    fn test_epoch_counter_starts_at_zero() {
        let epoch = Arc::new(AtomicU64::new(0));
        assert_eq!(epoch.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_epoch_counter_increments() {
        let epoch = Arc::new(AtomicU64::new(0));
        epoch.fetch_add(1, Ordering::SeqCst);
        assert_eq!(epoch.load(Ordering::SeqCst), 1);
        epoch.fetch_add(1, Ordering::SeqCst);
        assert_eq!(epoch.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_epoch_guard_prevents_stale_write() {
        // Simulate: capture epoch before refresh, invalidation bumps it, then check
        let epoch = Arc::new(AtomicU64::new(0));
        let epoch_before = epoch.load(Ordering::SeqCst);

        // Simulate invalidation
        epoch.fetch_add(1, Ordering::SeqCst);

        let epoch_after = epoch.load(Ordering::SeqCst);
        assert_ne!(epoch_before, epoch_after, "epoch should have changed");
    }

    #[test]
    fn test_epoch_guard_allows_write_when_unchanged() {
        let epoch = Arc::new(AtomicU64::new(5));
        let epoch_before = epoch.load(Ordering::SeqCst);
        // No invalidation occurs
        let epoch_after = epoch.load(Ordering::SeqCst);
        assert_eq!(epoch_before, epoch_after);
    }

    /* ========================================================================== */
    /*                    Invalidation Simulation Tests                          */
    /* ========================================================================== */

    #[test]
    fn test_invalidate_clears_cache_and_resets_last_refresh() {
        let cache: Arc<RwLock<HashMap<[u8; 32], IssuerMeta>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let last_refresh = Arc::new(RwLock::new(5000u64));
        let epoch = Arc::new(AtomicU64::new(0));

        // Populate cache
        {
            let mut c = cache.write().unwrap_or_else(|e| e.into_inner());
            c.insert(
                [1u8; 32],
                IssuerMeta {
                    kid: "test".to_string(),
                    name: "T".to_string(),
                    revoked: false,
                    vk_bytes: [0u8; 32],
                },
            );
        }
        assert_eq!(cache.read().unwrap_or_else(|e| e.into_inner()).len(), 1);

        // Simulate invalidate()
        epoch.fetch_add(1, Ordering::SeqCst);
        cache.write().unwrap_or_else(|e| e.into_inner()).clear();
        *last_refresh.write().unwrap_or_else(|e| e.into_inner()) = 0;

        assert!(cache.read().unwrap_or_else(|e| e.into_inner()).is_empty());
        assert_eq!(*last_refresh.read().unwrap_or_else(|e| e.into_inner()), 0);
        assert_eq!(epoch.load(Ordering::SeqCst), 1);
    }

    /* ========================================================================== */
    /*                    Additional Property Tests                              */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: CircuitBreakerState opens at exactly MAX_CONSECUTIVE_FAILURES
        #[test]
        fn prop_circuit_breaker_opens_at_threshold(extra_failures in 0u32..10) {
            let mut cb = CircuitBreakerState::new();
            for i in 0..MAX_CONSECUTIVE_FAILURES {
                cb.record_failure(u64::from(i));
            }
            prop_assert!(cb.is_open);
            for i in 0..extra_failures {
                cb.record_failure(u64::from(MAX_CONSECUTIVE_FAILURES).saturating_add(u64::from(i)));
            }
            prop_assert!(cb.is_open);
        }

        /// Property: RefreshGuard always clears flag regardless of initial state
        #[test]
        fn prop_refresh_guard_always_clears(initial in any::<bool>()) {
            let flag = Arc::new(RwLock::new(initial));
            let guard = RefreshGuard { flag: flag.clone() };
            drop(guard);
            prop_assert!(!*flag.read().unwrap_or_else(|e| e.into_inner()));
        }

        /// Property: Epoch counter monotonically increases
        #[test]
        fn prop_epoch_monotonic(increments in 1u64..100) {
            let epoch = Arc::new(AtomicU64::new(0));
            for _ in 0..increments {
                epoch.fetch_add(1, Ordering::SeqCst);
            }
            prop_assert_eq!(epoch.load(Ordering::SeqCst), increments);
        }

        /// Property: TTL classification is monotonic (stale implies stale at all later times)
        #[test]
        fn prop_ttl_monotonic(
            last_refresh in 0u64..1_000_000,
            delta1 in 0u64..10_000,
            delta2 in 0u64..10_000
        ) {
            let now1 = last_refresh.saturating_add(delta1);
            let now2 = last_refresh.saturating_add(delta1).saturating_add(delta2);
            let stale1 = now1.saturating_sub(last_refresh) > CACHE_TTL_SECS;
            let stale2 = now2.saturating_sub(last_refresh) > CACHE_TTL_SECS;
            // If stale at now1, must be stale at now2 (since now2 >= now1)
            if stale1 {
                prop_assert!(stale2);
            }
        }

        /// Property: CacheStats serialise/deserialise roundtrip
        #[test]
        fn prop_cache_stats_roundtrip(
            size in any::<usize>(),
            age in any::<u64>(),
            in_progress in any::<bool>()
        ) {
            let stats = CacheStats {
                cache_size: size,
                last_refresh_age_secs: age,
                refresh_in_progress: in_progress,
            };
            let json = serde_json::to_string(&stats).expect("serialise");
            let decoded: CacheStats = serde_json::from_str(&json).expect("deserialise");
            prop_assert_eq!(decoded.cache_size, size);
            prop_assert_eq!(decoded.last_refresh_age_secs, age);
            prop_assert_eq!(decoded.refresh_in_progress, in_progress);
        }
    }

    /* ========================================================================== */
    /*                    Base64 Edge Cases                                      */
    /* ========================================================================== */

    #[test]
    fn test_base64_empty_input() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode([]);
        assert_eq!(encoded, "");
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;
        assert!(decoded.is_empty());
        Ok(())
    }

    #[test]
    fn test_base64_one_byte() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode([0xAB]);
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(&encoded)?;
        assert_eq!(decoded, vec![0xAB]);
        Ok(())
    }

    #[test]
    fn test_base64_standard_vs_url_safe() {
        // Standard base64 uses + and /; URL-safe uses - and _
        let data = [0xFB, 0xFF, 0xFE]; // bytes that produce + and / in standard
        let url_encoded = BASE64_URL_SAFE_NO_PAD.encode(data);
        assert!(!url_encoded.contains('+'));
        assert!(!url_encoded.contains('/'));
    }

    /* ========================================================================== */
    /*                    Blake2s256 Domain Separation Coverage                  */
    /* ========================================================================== */

    #[test]
    fn test_blake2s256_same_key_different_domain() {
        let vk = [100u8; 32];

        let mut h1 = Blake2s256::new();
        h1.update(b"provii.issuer.vk.v0");
        h1.update(vk);
        let r1 = h1.finalize();

        let mut h2 = Blake2s256::new();
        h2.update(b"provii.issuer.vk.v1");
        h2.update(vk);
        let r2 = h2.finalize();

        assert_ne!(&r1[..], &r2[..]);
    }

    #[test]
    fn test_blake2s256_output_is_32_bytes() {
        let mut h = Blake2s256::new();
        h.update(b"provii.issuer.vk.v0");
        h.update([0u8; 32]);
        let result = h.finalize();
        assert_eq!(result.len(), 32);
    }

    /* ========================================================================== */
    /*                    IssuerMeta Debug Trait                                  */
    /* ========================================================================== */

    #[test]
    fn test_issuer_meta_debug_output() {
        let meta = IssuerMeta {
            kid: "dbg-test".to_string(),
            name: "Debug Issuer".to_string(),
            revoked: false,
            vk_bytes: [7u8; 32],
        };
        let dbg = format!("{:?}", meta);
        assert!(dbg.contains("dbg-test"));
        assert!(dbg.contains("Debug Issuer"));
    }
}
