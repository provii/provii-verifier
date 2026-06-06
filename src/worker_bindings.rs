// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Cloudflare Worker entry point for the verifier API.
//!
//! This module owns the `#[event(fetch)]` and `#[event(scheduled)]` handlers and
//! is responsible for initialising [`AppState`] from Cloudflare environment
//! bindings (KV namespaces, Durable Objects, Secrets Store, Analytics Engine).
//! The constructed state is cached in a process-global [`RwLock`] so that
//! subsequent warm requests skip the initialisation path entirely.
//!
//! Key responsibilities:
//!
//! - Parse worker environment variables and KV/DO bindings into [`WorkerEnv`].
//! - Load secret key material (MEK, IP hash salt, status token) in parallel.
//! - Enforce secret expiry at startup (fail-fast on expired secrets).
//! - Attach CORS and security headers to every response.
//! - Run cron-triggered Durable Object keep-alive warmups.
//! - Provide Cache API read-through caching.

#![forbid(unsafe_code)]

use crate::bindings::{DO_IDEMPOTENCY, KV_BANLIST, KV_CONFIG, KV_ISSUER_REGISTRY};
use crate::storage::origin_policy::OriginPolicyStore;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};
use worker::console_log;
use worker::{event, Context, Env, Error as WorkerError, Response};
use zeroize::Zeroize;

use crate::worker_routes::build_router;
use crate::{
    error::{ApiError, ApiResult},
    security::{headers::add_security_headers, AuditLogger},
    storage::{
        ban_store::KvBanStore,
        durable_object_store::DurableObjectNonceStore,
        idempotency_store::DurableObjectIdempotencyStore,
        jwks::JwksCache,
        traits::{BanStore, ChallengeStore, NonceStore},
    },
    AppState,
};

// Cache the app state to avoid reinitialising it on every request.
// Uses the standard library RwLock because Workers does not provide Tokio primitives.
static APP_STATE_CACHE: Lazy<RwLock<Option<Arc<AppState>>>> = Lazy::new(|| RwLock::new(None));

// Cache key used to invalidate state when environment configuration changes.
static ENV_CACHE_KEY: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

/// Environment-derived bindings supplied to the Cloudflare Worker.
///
/// Constructed once per worker instance via [`WorkerEnv::from_env`] and fed
/// into [`AppState`] during initialisation.
pub struct WorkerEnv {
    /// KV namespace backing challenge storage.
    pub challenges_kv: worker::kv::KvStore,
    /// KV namespace backing nonce storage.
    pub nonces_kv: worker::kv::KvStore,
    /// KV namespace for general configuration lookups.
    pub config_kv: worker::kv::KvStore,
    /// Optional KV namespace for the ban list. Falls back to `config_kv` when absent.
    pub banlist_kv: Option<worker::kv::KvStore>,
    /// KV namespace for the issuer public key registry.
    pub issuer_registry_kv: worker::kv::KvStore,

    /// Comma-separated origins permitted to call the API.
    pub allowed_origins: String,
    /// Comma-separated origins for CORS `Access-Control-Allow-Origin`.
    pub cors_origins: String,
    /// Base URL of the public API (e.g. `https://verify.provii.app/v1`).
    pub api_base_url: String,
    /// Base URL of the hosted backend (e.g. `https://hosted.provii.app`).
    /// Used for WebSocket URLs, status URLs, and other hosted-flow responses.
    pub hosted_base_url: String,
    /// Deployment environment (`production`, `sandbox`, or `development`).
    pub environment: Option<String>,

    /// Maximum age of a challenge before it expires, in milliseconds.
    pub max_challenge_age_ms: u64,
    /// Time-to-live for nonces, in seconds.
    pub nonce_ttl_sec: u64,
}

impl WorkerEnv {
    /// Construct a [`WorkerEnv`] by reading bindings and variables from the
    /// Cloudflare [`Env`]. Returns a [`WorkerError`] if any required binding
    /// is missing.
    pub fn from_env(env: &Env) -> Result<Self, WorkerError> {
        Ok(Self {
            // Bind KV namespaces required by the worker.
            challenges_kv: env.kv(KV_CONFIG)?,
            nonces_kv: env.kv(KV_CONFIG)?,
            config_kv: env.kv(KV_CONFIG)?,
            banlist_kv: env.kv(KV_BANLIST).ok(),
            issuer_registry_kv: env.kv(KV_ISSUER_REGISTRY).map_err(|e| {
                WorkerError::from(format!(
                    "VERIFIER_KV_ISSUER_REGISTRY binding missing: {}",
                    e
                ))
            })?,

            // SECURITY: Require explicit origin configuration. Defaulting to "*"
            // would silently disable CORS protection on misconfigured deployments.
            allowed_origins: env
                .var("ALLOWED_ORIGINS")
                .map(|v| v.to_string())
                .map_err(|_| {
                    WorkerError::from("ALLOWED_ORIGINS environment variable is required")
                })?,

            cors_origins: env
                .var("PROVII_CORS_ORIGINS")
                .map(|v| v.to_string())
                .map_err(|_| {
                    WorkerError::from("PROVII_CORS_ORIGINS environment variable is required")
                })?,

            api_base_url: env
                .var("API_BASE_URL")
                .map(|v| v.to_string())
                .unwrap_or("https://verify.provii.app/v1".to_string()),

            hosted_base_url: env
                .var("HOSTED_BASE_URL")
                .map(|v| v.to_string())
                .unwrap_or("https://hosted.provii.app".to_string()),

            environment: env.var("ENVIRONMENT").map(|v| v.to_string()).ok(),

            max_challenge_age_ms: env
                .var("MAX_CHAL_AGE_MS")
                .ok()
                .and_then(|v| v.to_string().parse().ok())
                .unwrap_or(60_000),

            nonce_ttl_sec: env
                .var("NONCE_TTL_SEC")
                .ok()
                .and_then(|v| v.to_string().parse().ok())
                .unwrap_or(300),
        })
    }
}

/// Return the cached [`AppState`], or initialise it from the [`Env`] on first call.
///
/// Uses a double-checked locking pattern: a read lock is tried first, and only
/// if the cache is empty is a write lock acquired to run `init_app_state_internal`.
pub async fn get_or_init_app_state(env: &Env) -> ApiResult<Arc<AppState>> {
    // Compute a cache key from relevant environment variables so configuration changes
    // invalidate the cached state.
    let current_cache_key = format!(
        "{}:{}:{}",
        env.var("PROVII_CORS_ORIGINS")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        env.var("API_BASE_URL")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        env.var("CHALLENGE_SHARD_COUNT")
            .map(|v| v.to_string())
            .unwrap_or_default()
    );

    // Invalidate the cached state if the configuration changed.
    {
        let stored_key = ENV_CACHE_KEY
            .read()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;
        if !stored_key.is_empty() && *stored_key != current_cache_key {
            console_log!("Environment changed, invalidating app state cache");
            let mut cache = APP_STATE_CACHE
                .write()
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;
            *cache = None;
        }
    }

    // Attempt a read-only lookup before taking the write lock.
    {
        let cache = APP_STATE_CACHE
            .read()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;
        if let Some(state) = cache.as_ref() {
            return Ok(Arc::clone(state));
        }
    }

    // Check under the write lock whether another request already initialised state.
    {
        let cache = APP_STATE_CACHE
            .write()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;
        if let Some(state) = cache.as_ref() {
            return Ok(Arc::clone(state));
        }
        // Guard dropped here before the await.
    }

    // Initialisation path (no lock held across the await point).
    console_log!("Initialising app state (first request or after invalidation)");
    let state = Arc::new(init_app_state_internal(env).await?);

    // Re-acquire the write lock to store the newly initialised state.
    let mut cache = APP_STATE_CACHE
        .write()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;

    // Double-check: another request may have raced us and already populated the cache.
    if let Some(existing) = cache.as_ref() {
        return Ok(Arc::clone(existing));
    }

    *cache = Some(Arc::clone(&state));

    // Record the cache key we used for this state instance.
    let mut key_store = ENV_CACHE_KEY
        .write()
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("Lock poisoned: {}", e)))?;
    *key_store = current_cache_key;

    Ok(state)
}

/// Validates that KV namespace IDs match the expected environment to prevent
/// accidental data contamination between dev, sandbox, and production.
fn validate_kv_namespace_ids(env: &Env) -> ApiResult<()> {
    // SECURITY (ADV-VA-015): Default to "production" (fail strict/safe) so that a
    // missing ENVIRONMENT variable triggers the stricter production-mode KV namespace
    // validation. Previously defaulted to "sandbox" which silently disabled checks.
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "production".to_string());

    console_log!(
        "🔒 Validating KV namespaces for environment: {}",
        environment
    );

    // Get the KV namespace bindings
    let config_kv = env.kv(KV_CONFIG).ok();

    // In production, we perform additional validation to ensure we're not accidentally
    // using sandbox or dev namespaces
    if environment == "production" {
        // Validate that we have all required production KV bindings
        if config_kv.is_none() {
            return Err(ApiError::Internal(anyhow::anyhow!(
                "Production environment missing KV_CONFIG binding"
            )));
        }

        // Namespace ID cross-contamination is prevented by wrangler.toml binding
        // the correct IDs per environment. We validate that the ENVIRONMENT variable
        // is set correctly and log it for auditing.
        console_log!("✅ Production environment validation passed");
        console_log!("   Using production-specific KV namespaces");
    } else if environment == "sandbox" {
        console_log!("✅ Sandbox environment validation passed");
        console_log!("   Using sandbox-specific KV namespaces");
    } else if environment == "development" {
        console_log!("✅ Development environment validation passed");
        console_log!("   Using development-specific KV namespaces");
    } else {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Unknown ENVIRONMENT value: {}. Must be one of: development, sandbox, production",
            environment
        )));
    }

    Ok(())
}

/// Internal initialisation routine invoked once per worker instance.
async fn init_app_state_internal(env: &Env) -> ApiResult<AppState> {
    // Validate environment configuration before proceeding
    validate_kv_namespace_ids(env)?;

    let worker_env =
        WorkerEnv::from_env(env).map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    let banlist_kv = worker_env.banlist_kv.clone();

    // Resolve KV_CONFIG once and reuse the handle for all consumers that share
    // this namespace (origin policies, challenges, nonces, ban store fallback).
    let config_kv = env.kv(KV_CONFIG)?;

    let origin_policy_store: Arc<OriginPolicyStore> =
        Arc::new(OriginPolicyStore::new(config_kv.clone()));

    // AL-008: Late-bound audit logger slot. Storage backends are constructed
    // here, before the audit logger (which depends on `ip_hash_salt` loaded
    // asynchronously from Secrets Store). The slot is set exactly once near
    // the bottom of this function and observed by every store at request
    // time so DO-emitted audit events reach D1 via the audit queue.
    let audit_logger_slot: crate::storage::AuditLoggerSlot = Arc::new(std::sync::OnceLock::new());

    // Challenges use the Durable Object backend for per-challenge single-writer
    // serialisation. Each challenge UUID maps to its own DO instance, eliminating
    // the need for a separate distributed lock.
    let challenge_store: Arc<dyn ChallengeStore> = {
        let challenge_namespace =
            env.durable_object(crate::bindings::DO_CHALLENGE)
                .map_err(|e| {
                    ApiError::Internal(anyhow::anyhow!(
                        "VERIFIER_DO_CHALLENGE binding missing or misconfigured: {}",
                        e
                    ))
                })?;
        console_log!("Challenge store: Durable Object backend (per-challenge addressing)");
        Arc::new(crate::storage::DurableObjectChallengeStore::new(
            challenge_namespace,
            Arc::clone(&audit_logger_slot),
        ))
    };

    let nonce_shard_count: usize = env
        .var("NONCE_SHARD_COUNT")
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "25".to_string())
        .parse()
        .unwrap_or(25)
        .clamp(1, 100);

    let nonce_store: Arc<dyn NonceStore> = match env.durable_object(crate::bindings::DO_NONCE) {
        Ok(nonce_namespace) => {
            console_log!(
                "✅ Using DO-backed nonce store ({} shards) for atomic check-and-set",
                nonce_shard_count
            );
            Arc::new(DurableObjectNonceStore::new(
                nonce_namespace,
                nonce_shard_count,
                Arc::clone(&audit_logger_slot),
            ))
        }
        Err(e) => {
            // SECURITY: Fail closed. The nonce store provides replay protection
            // (CWE-287, ASVS V6.1.3). KV fallback has a TOCTOU race that allows
            // nonce reuse. Refuse to start without atomic DO-backed nonce storage.
            console_log!(
                "{{\"audit\":true,\"event\":\"startup_blocked\",\"reason\":\"nonce_store_unavailable\",\"severity\":\"critical\",\"error\":\"{}\"}}",
                e
            );
            return Err(ApiError::Internal(anyhow::anyhow!(
                "Startup blocked: VERIFIER_DO_NONCE binding unavailable ({}). \
                 Nonce replay protection requires Durable Object storage.",
                e
            )));
        }
    };

    // Instantiate the ban store.
    let ban_store: Arc<dyn BanStore> = if let Some(ban_kv) = banlist_kv {
        Arc::new(KvBanStore::new(ban_kv))
    } else {
        // Fall back to the CONFIG namespace when a dedicated ban list is missing.
        Arc::new(KvBanStore::new(config_kv))
    };

    // Instantiate the issuer registry cache shared across requests (reads from KV).
    let jwks_cache = Arc::new(JwksCache::new(worker_env.issuer_registry_kv.clone()));

    // PERFORMANCE: Pre-warm cache during startup
    jwks_cache.prewarm().await;

    let cfg = Arc::new(
        crate::config::Config::from_worker_env(worker_env)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?,
    );

    // NOTE: AuditLogger is constructed after secret loading below (needs ip_hash_salt).

    // KV-counter rate limiting (replaces Durable Object system)
    console_log!("✅ KV-counter rate limiting ready (VERIFIER_KV_RATE_LIMITS)");

    // SECURITY: Initialise idempotency store (ASVS V11, OWASP API4:2023).
    // INVARIANT: Always `Some` after successful startup. The startup guard below logs
    // CRITICAL and blocks initialisation if the DO binding is missing. Handlers
    // continue to use `if let Some(ref store)` for type safety, but the binding is
    // guaranteed present in any correctly configured deployment.
    let idempotency_store = match env.durable_object(DO_IDEMPOTENCY) {
        Ok(idempotency_namespace) => {
            let idempotency_shard_count: usize = env
                .var("IDEMPOTENCY_SHARD_COUNT")
                .map(|s| s.to_string())
                .unwrap_or_else(|_| "16".to_string())
                .parse()
                .unwrap_or(16)
                .clamp(1, 100);

            console_log!(
                "✅ Idempotency protection enabled ({} shards)",
                idempotency_shard_count
            );
            Some(Arc::new(DurableObjectIdempotencyStore::new(
                idempotency_namespace,
                idempotency_shard_count,
            )))
        }
        Err(e) => {
            // SECURITY: Fail closed. Idempotency protection prevents replay and
            // double-spend attacks on credit consumption. Refuse to start without it.
            console_log!(
                "{{\"audit\":true,\"event\":\"startup_blocked\",\"reason\":\"idempotency_store_unavailable\",\"severity\":\"critical\",\"error\":\"{}\"}}",
                e
            );
            return Err(ApiError::Internal(anyhow::anyhow!(
                "Startup blocked: {} binding unavailable ({}). \
                 Idempotency protection is required.",
                DO_IDEMPOTENCY,
                e
            )));
        }
    };

    // Attempt to attach the Analytics Engine dataset for billing metrics.
    let analytics = env.analytics_engine("VERIFIER_ANALYTICS").ok();

    if analytics.is_some() {
        console_log!("✅ Analytics Engine connected");
    } else if cfg.environment == "production" {
        // H5: Analytics Engine is the primary billing event sink. In production
        // a missing binding means verification events are silently dropped and
        // credit consumption cannot be reconciled (revenue loss). Fail closed at
        // startup with a clear message rather than serving traffic that cannot
        // be metered. Sandbox/dev are exempt below (metering is best-effort
        // there). This mirrors the existing fail-closed posture for the
        // idempotency store and rate-limit binding.
        console_log!(
            "{{\"audit\":true,\"event\":\"startup_blocked\",\"reason\":\"analytics_engine_unavailable\",\"severity\":\"critical\",\"service\":\"provii-verifier\",\
             \"message\":\"VERIFIER_ANALYTICS binding unavailable in production. Refusing to start: billing events would be silently dropped.\"}}"
        );
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Startup blocked: VERIFIER_ANALYTICS (Analytics Engine) binding unavailable in \
             production. Billing events would be silently dropped. Provision the binding or \
             correct wrangler.toml before deploying."
        )));
    } else {
        // ADV-VA-017: Outside production, the binding is allowed to be absent so
        // sandbox/dev can run without an Analytics Engine dataset. Log at error
        // severity for alerting (events are not metered while it is missing).
        console_log!(
            "{{\"audit\":true,\"event\":\"analytics_engine_unavailable\",\"severity\":\"error\",\"service\":\"provii-verifier\",\
             \"message\":\"VERIFIER_ANALYTICS binding unavailable. Billing events will be silently dropped.\"}}"
        );
    }

    console_log!("✅ Security features initialised:");
    console_log!("  - Audit logging: enabled");
    console_log!("  - Ban store: enabled");
    console_log!("  - Rate limiting: enabled");
    console_log!("  - Security headers: enabled");
    console_log!("  - Idempotency protection: enabled");

    // Initialise the Groth16 verifier (idempotent). Failure is fatal: the
    // worker cannot verify proofs without a valid VK and crypto state.
    crate::init_crypto_once()?;

    // PERFORMANCE: Run secret expiry check, MEK pre-load, service token pre-load, and IP hash salt
    // pre-load in parallel. These are independent I/O operations (KV read + Secrets Store reads)
    // that each take ~100-200ms. Running them concurrently saves ~300-600ms on cold start.
    console_log!("🔐 Checking secret expiry + pre-loading secrets (parallel)...");

    let expiry_fut = crate::security::check_secret_expiry(env);

    let mek_fut = async {
        match env.secret_store("VERIFIER_MEK") {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, "VERIFIER_MEK").await {
                Ok(Some(mek_b64)) => {
                    // SECURITY: Wrap the base64 string so it is zeroized after decode
                    let mek_b64 = zeroize::Zeroizing::new(mek_b64);
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                    match URL_SAFE_NO_PAD.decode(mek_b64.as_bytes()) {
                        Ok(bytes) => {
                            console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK\",\"outcome\":\"success\",\"bytes\":{}}}",bytes.len());
                            Some(Arc::new(zeroize::Zeroizing::new(bytes)))
                        }
                        Err(_e) => {
                            console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK\",\"outcome\":\"decode_failure\"}}");
                            None
                        }
                    }
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK\",\"outcome\":\"not_found\"}}");
                    None
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK\",\"outcome\":\"fetch_error\"}}");
                    None
                }
            },
            Err(_e) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK\",\"outcome\":\"binding_unavailable\"}}");
                None
            }
        }
    };

    let previous_mek_fut = async {
        let binding = "VERIFIER_MEK_PREVIOUS";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(mek_b64)) => {
                    let mek_b64 = zeroize::Zeroizing::new(mek_b64);
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                    match URL_SAFE_NO_PAD.decode(mek_b64.as_bytes()) {
                        Ok(bytes) => {
                            console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK_PREVIOUS\",\"outcome\":\"success\",\"bytes\":{}}}",bytes.len());
                            Some(Arc::new(zeroize::Zeroizing::new(bytes)))
                        }
                        Err(_e) => {
                            console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK_PREVIOUS\",\"outcome\":\"decode_failure\"}}");
                            None
                        }
                    }
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK_PREVIOUS\",\"outcome\":\"not_found\"}}");
                    None
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK_PREVIOUS\",\"outcome\":\"fetch_error\"}}");
                    None
                }
            },
            Err(_) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_MEK_PREVIOUS\",\"outcome\":\"binding_unavailable\"}}");
                None
            }
        }
    };

    let ip_hash_salt_fut = async {
        let binding = "VERIFIER_IP_HASH_SALT";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(salt)) => {
                    if salt.is_empty() {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_IP_HASH_SALT\",\"outcome\":\"empty\",\"severity\":\"critical\"}}");
                        None
                    } else {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_IP_HASH_SALT\",\"outcome\":\"success\"}}");
                        Some(salt)
                    }
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_IP_HASH_SALT\",\"outcome\":\"not_found\",\"severity\":\"critical\"}}");
                    None
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_IP_HASH_SALT\",\"outcome\":\"fetch_error\",\"severity\":\"critical\"}}");
                    None
                }
            },
            Err(_e) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"VERIFIER_IP_HASH_SALT\",\"outcome\":\"binding_unavailable\",\"severity\":\"critical\"}}");
                None
            }
        }
    };

    // M-27: Read SANDBOX_API_KEY from Secrets Store at startup so the
    // /v1/register-test-origin handler avoids a per-request Secrets Store read.
    let sandbox_key_fut = async {
        let binding = "SANDBOX_API_KEY";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(key)) => {
                    if key.is_empty() {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SANDBOX_API_KEY\",\"outcome\":\"empty\"}}");
                        None
                    } else {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SANDBOX_API_KEY\",\"outcome\":\"success\"}}");
                        Some(zeroize::Zeroizing::new(key))
                    }
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SANDBOX_API_KEY\",\"outcome\":\"not_found\"}}");
                    None
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SANDBOX_API_KEY\",\"outcome\":\"fetch_error\"}}");
                    None
                }
            },
            Err(_e) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SANDBOX_API_KEY\",\"outcome\":\"binding_unavailable\"}}");
                None
            }
        }
    };

    // LT-001: Read LOADTEST_API_KEY from Secrets Store at startup (additive to
    // SANDBOX_API_KEY) so /v1/register-test-origin accepts the dedicated
    // load-test harness key without a per-request Secrets Store read.
    let loadtest_key_fut = async {
        let binding = "LOADTEST_API_KEY";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(key)) => {
                    if key.is_empty() {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"LOADTEST_API_KEY\",\"outcome\":\"empty\"}}");
                        None
                    } else {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"LOADTEST_API_KEY\",\"outcome\":\"success\"}}");
                        Some(zeroize::Zeroizing::new(key))
                    }
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"LOADTEST_API_KEY\",\"outcome\":\"not_found\"}}");
                    None
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"LOADTEST_API_KEY\",\"outcome\":\"fetch_error\"}}");
                    None
                }
            },
            Err(_e) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"LOADTEST_API_KEY\",\"outcome\":\"binding_unavailable\"}}");
                None
            }
        }
    };

    // STATUS_API_TOKEN slots are no longer hashed at cold start.
    // The Argon2id PHC + 6-char fingerprint pair is resolved on demand
    // through the five-minute TTL `status_token_cache` so a rotated token
    // in Secrets Store becomes effective on every warm isolate without a
    // redeploy. The cold-start helper retained below performs a binding
    // probe only: it reads the slot, emits the same `secrets_store_read`
    // audit line every other secret produces, and computes the public-safe
    // fingerprint for a one-shot startup log so an absent or empty slot
    // surfaces in cold-start logs without paying the ~60 ms Argon2id cost
    // twice (once at boot, once on the first request anyway).
    //
    // The fingerprint is not retained on AppState. The runtime fetches
    // both fingerprints from the cache on every status-endpoint request
    // via `current_fingerprints` so the response carries a value
    // consistent with the slot the verify path would accept against
    // during the same TTL window.
    async fn probe_status_token_slot(env: &Env, binding: &'static str) -> String {
        let unset = crate::security::secret_fingerprint::FINGERPRINT_UNSET.to_string();
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(token)) => {
                    if token.is_empty() {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"{}\",\"outcome\":\"empty\"}}", binding);
                        unset
                    } else {
                        console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"{}\",\"outcome\":\"success\"}}", binding);
                        let token = zeroize::Zeroizing::new(token);
                        crate::security::secret_fingerprint::fingerprint6_str(Some(&token))
                    }
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"{}\",\"outcome\":\"not_found\"}}", binding);
                    unset
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"{}\",\"outcome\":\"fetch_error\"}}", binding);
                    unset
                }
            },
            Err(_e) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"{}\",\"outcome\":\"binding_unavailable\"}}", binding);
                unset
            }
        }
    }

    let status_token_fut = probe_status_token_slot(env, "STATUS_API_TOKEN");

    // previous-slot probe. Absent slot is normal
    // outside a rotation window; absence does not warn or fail.
    let status_token_prev_fut = probe_status_token_slot(env, "STATUS_API_TOKEN_PREVIOUS");

    // SC-001 / M-049: Pre-load SESSION_TOKEN_SECRET at startup to eliminate
    // 7 per-request Secrets Store reads across session/check, csrf-token,
    // ws upgrade, challenge creation, and redemption handlers.
    let session_secret_fut = async {
        let binding = "SESSION_TOKEN_SECRET";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(s)) if !s.is_empty() => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SESSION_TOKEN_SECRET\",\"outcome\":\"success\"}}");
                    Some(Arc::new(zeroize::Zeroizing::new(s)))
                }
                Ok(Some(_)) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SESSION_TOKEN_SECRET\",\"outcome\":\"empty\"}}");
                    None
                }
                Ok(None) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SESSION_TOKEN_SECRET\",\"outcome\":\"not_found\"}}");
                    None
                }
                Err(_e) => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SESSION_TOKEN_SECRET\",\"outcome\":\"fetch_error\"}}");
                    None
                }
            },
            Err(_e) => {
                console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SESSION_TOKEN_SECRET\",\"outcome\":\"binding_unavailable\"}}");
                None
            }
        }
    };

    // SC-001 / M-049: Pre-load SESSION_TOKEN_SECRET_PREVIOUS for key rotation
    // fallback during session token verification.
    let session_secret_prev_fut = async {
        let binding = "SESSION_TOKEN_SECRET_PREVIOUS";
        match env.secret_store(binding) {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, binding).await {
                Ok(Some(s)) if !s.is_empty() => {
                    console_log!("{{\"audit\":true,\"event\":\"secrets_store_read\",\"secret\":\"SESSION_TOKEN_SECRET_PREVIOUS\",\"outcome\":\"success\"}}");
                    Some(Arc::new(zeroize::Zeroizing::new(s)))
                }
                _ => None,
            },
            Err(_) => None,
        }
    };

    let secrets_start = worker::Date::now().as_millis();
    let (
        expiry_result,
        mek_cached,
        ip_hash_salt_opt,
        previous_mek,
        status_token_fingerprint_probe,
        status_token_fingerprint_previous_probe,
        sandbox_api_key_cached,
        loadtest_api_key_cached,
        session_token_secret,
        session_token_secret_previous,
    ) = futures::join!(
        expiry_fut,
        mek_fut,
        ip_hash_salt_fut,
        previous_mek_fut,
        status_token_fut,
        status_token_prev_fut,
        sandbox_key_fut,
        loadtest_key_fut,
        session_secret_fut,
        session_secret_prev_fut
    );
    let secrets_ms = (worker::Date::now()
        .as_millis()
        .saturating_sub(secrets_start)) as f64;

    // SECURITY: MEK is required for envelope encryption of HMAC secrets.
    // Without it, no authenticated endpoint can function. Fail fast at startup
    // rather than returning 500 errors on every authenticated request.
    if mek_cached.is_none() {
        console_log!(
            "{{\"audit\":true,\"event\":\"startup_blocked\",\"reason\":\"mek_unavailable\",\"severity\":\"critical\"}}"
        );
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Startup blocked: VERIFIER_MEK unavailable from Secrets Store. \
             Envelope encryption requires the master encryption key."
        )));
    }

    // SECURITY: IP hash salt for GDPR-compliant salted IP hashing.
    // If the secret is missing from Secrets Store, generate a random ephemeral salt
    // so the worker can still start (degraded mode). IP hashes produced with the
    // ephemeral salt will not correlate across worker restarts, but the alternative
    // (crashing the worker entirely) is worse in production.
    let ip_hash_salt = zeroize::Zeroizing::new(match ip_hash_salt_opt {
        Some(salt) => salt,
        None => {
            console_log!(
                "{{\"alert\":\"IP_HASH_SALT_MISSING\",\"severity\":\"critical\",\"service\":\"provii-verifier\",\
                 \"message\":\"VERIFIER_IP_HASH_SALT not configured. Using ephemeral random salt. \
                 IP hashes will NOT correlate across worker restarts. Provision the secret immediately.\"}}"
            );
            let mut random_bytes = [0u8; 32];
            getrandom::getrandom(&mut random_bytes).map_err(|e| {
                ApiError::Internal(anyhow::anyhow!(
                    "Startup blocked: VERIFIER_IP_HASH_SALT missing AND CSPRNG failed: {}",
                    e
                ))
            })?;
            let ephemeral = hex::encode(random_bytes);
            // Zeroize the stack buffer; the hex string is owned by Zeroizing<String> above.
            random_bytes.zeroize();
            ephemeral
        }
    });

    // ASVS V13.3.4 [L3]: ENFORCE secret expiry - fail-fast on expired secrets
    match expiry_result {
        Ok(expiry_result) => {
            // CRITICAL: Block startup if ANY secrets are expired
            if !expiry_result.expired.is_empty() {
                console_log!(
                    "[SecretExpiry] ❌ STARTUP BLOCKED: {} expired secret(s) detected",
                    expiry_result.expired.len()
                );
                for secret_name in &expiry_result.expired {
                    console_log!("[SecretExpiry] ❌ EXPIRED: {}", secret_name);
                }
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "Startup blocked: {} expired secret(s). Immediate rotation required: {:?}",
                    expiry_result.expired.len(),
                    expiry_result.expired
                )));
            }

            // Log warnings for secrets expiring soon
            crate::security::log_expiry_warnings(&expiry_result);
        }
        Err(e) => {
            // ADV-VA-016: Secret expiry check failed (KV unreachable, binding
            // misconfigured, etc.). This is an availability-over-security trade-off:
            // blocking startup on a transient KV failure would cause a total outage
            // for all endpoints, including the health check that would surface the
            // problem. We continue with potentially expired secrets and rely on:
            //
            //   1. Structured error log below (picked up by Loki alerting rules)
            //   2. The cron health check which re-runs expiry validation
            //
            // If this warning fires persistently, the KV binding or Secrets Store
            // metadata is broken and must be investigated immediately.
            console_log!(
                "{{\"audit\":true,\"event\":\"secret_expiry_check_failed\",\"severity\":\"error\",\"service\":\"provii-verifier\",\
                 \"message\":\"Secret expiry check failed. Worker starting with potentially expired secrets. \
                 Investigate KV binding and Secrets Store metadata immediately.\",\"error\":\"{}\"}}",
                e
            );
        }
    }

    // Set up the audit logger with IP hash salt for GDPR-compliant salted hashing.
    // Must happen after ip_hash_salt is loaded from Secrets Store above.
    //
    // Uses the shared provii-audit crate:
    //   - PrivacyContext: domain-separated IP/UA hashing
    //   - QueueAuditSink: sends events to Cloudflare Queue for async D1 persistence
    let audit_logger = {
        use provii_audit::sinks::AuditSink;
        use provii_audit::PrivacyContext;

        let privacy = Arc::new(
            PrivacyContext::new(ip_hash_salt.as_bytes().to_vec()).map_err(|e| {
                console_log!("❌ Failed to create PrivacyContext: {:?}", e);
                ApiError::Internal(anyhow::anyhow!("PrivacyContext creation failed: {}", e))
            })?,
        );

        // QueueAuditSink::new requires the wasm32 Workers runtime. On native
        // targets the sink is unconstructable (struct contains Infallible), so
        // the queue path is compiled out entirely.
        #[cfg(target_arch = "wasm32")]
        let sink: Option<Arc<dyn AuditSink>> = {
            use provii_audit::sinks::queue::QueueAuditSink;
            match env.queue("AUDIT_QUEUE") {
                Ok(queue) => {
                    console_log!("✅ Queue audit sink connected (AUDIT_QUEUE)");
                    Some(Arc::new(QueueAuditSink::new(queue)))
                }
                Err(e) => {
                    // ADV-VA-018: Audit queue unavailability degrades to console-only logging.
                    // Security events (authentication failures, BOLA violations, ban list hits)
                    // will only appear in Cloudflare console logs which have limited retention
                    // and no structured query capability. D1 persistence is lost entirely.
                    console_log!(
                        "{{\"audit\":true,\"event\":\"audit_queue_unavailable\",\"severity\":\"error\",\"service\":\"provii-verifier\",\
                         \"message\":\"AUDIT_QUEUE binding unavailable. Security audit events will NOT be persisted to D1. \
                         Console-only logging active. Investigate binding configuration immediately.\",\"error\":\"{:?}\"}}", e
                    );
                    None
                }
            }
        };
        #[cfg(not(target_arch = "wasm32"))]
        let sink: Option<Arc<dyn AuditSink>> = None;

        let environment = env
            .var("ENVIRONMENT")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let worker_version = env
            .var("API_VERSION")
            .map(|v| v.to_string())
            .unwrap_or_default();
        let shared_logger = provii_audit::AuditLogger::new(sink, privacy, "provii-verifier");
        Arc::new(AuditLogger::new(shared_logger, environment, worker_version))
    };

    // AL-008: Wire the freshly-built audit logger into the storage layer slot
    // so the DO-backed challenge and nonce stores can dispatch audit events
    // emitted by their Durable Objects. `set` returns `Err` only if the slot
    // was somehow populated earlier; ignore it because there is exactly one
    // construction path.
    if audit_logger_slot.set(Arc::clone(&audit_logger)).is_err() {
        console_log!("[AL-008] audit_logger_slot already initialised; ignoring re-init");
    }

    // BILLING: Initialise credit management client if configured
    let credit_hmac_start = worker::Date::now().as_millis();
    let credit_management_client = {
        let base_url = env.var("CREDIT_MGMT_URL").map(|v| v.to_string()).ok();
        // SECURITY: Read HMAC key from Secrets Store (not env.var) to match wrangler.toml declaration
        let hmac_key = match env.secret_store("CREDIT_MGMT_HMAC_KEY") {
            Ok(store) => match crate::utils::retry::get_with_retry(&store, "CREDIT_MGMT_HMAC_KEY")
                .await
            {
                Ok(Some(key)) => {
                    console_log!("[CreditMgmt] ✅ CREDIT_MGMT_HMAC_KEY loaded from Secrets Store");
                    Some(key)
                }
                Ok(None) => {
                    console_log!("[CreditMgmt] ℹ️ CREDIT_MGMT_HMAC_KEY not found in Secrets Store");
                    None
                }
                Err(e) => {
                    console_log!("[CreditMgmt] ⚠️ CREDIT_MGMT_HMAC_KEY fetch error: {:?}", e);
                    None
                }
            },
            Err(e) => {
                console_log!(
                    "[CreditMgmt] ⚠️ CREDIT_MGMT_HMAC_KEY binding not available: {:?}",
                    e
                );
                None
            }
        };

        let credit_mgmt_key_id = env
            .var("CREDIT_MGMT_KEY_ID")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "provii-verifier".to_string());

        match (base_url, hmac_key) {
            (Some(url), Some(key)) => {
                console_log!(
                    "[CreditMgmt] Initialising credit management client with URL: {} key_id: {}",
                    url,
                    credit_mgmt_key_id
                );
                match crate::clients::CreditManagementClient::new(
                    url,
                    key,
                    credit_mgmt_key_id,
                    env.clone(),
                ) {
                    Ok(client) => {
                        console_log!(
                            "[CreditMgmt] ✅ Credit management client initialised successfully"
                        );
                        Some(Arc::new(client))
                    }
                    Err(e) => {
                        console_log!(
                            "[CreditMgmt] ❌ Failed to initialise credit management client: {:?}",
                            e
                        );
                        console_log!("[CreditMgmt] ⚠️ Continuing without credit management - billing will be logged only");
                        None
                    }
                }
            }
            (None, _) => {
                console_log!(
                    "[CreditMgmt] ℹ️ CREDIT_MGMT_URL not configured - billing will be logged only"
                );
                None
            }
            (_, None) => {
                console_log!("[CreditMgmt] ℹ️ CREDIT_MGMT_HMAC_KEY not configured - billing will be logged only");
                None
            }
        }
    };
    let credit_hmac_ms = (worker::Date::now()
        .as_millis()
        .saturating_sub(credit_hmac_start)) as f64;

    // ADV-VA-017: When both billing control surfaces are absent, verification events
    // are completely unmetered. This is a business-critical failure mode.
    if analytics.is_none() && credit_management_client.is_none() {
        console_log!(
            "{{\"audit\":true,\"event\":\"billing_controls_disabled\",\"severity\":\"error\",\"service\":\"provii-verifier\",\
             \"message\":\"Both Analytics Engine and Credit Management are unavailable. ALL billing controls are disabled. \
             Verification events will not be metered or billed.\"}}"
        );
    }

    // H-13: Pre-compute a dummy Argon2id hash with production parameters so that
    // the reject path for unknown client_ids takes the same time as a real
    // verification. This closes the timing oracle (CWE-208).
    //
    // Argon2id with m=65536 (64 MiB), t=3, p=4 is intentionally expensive; the
    // allocation happens once at startup and the resulting PHC string is reused
    // for every unknown-client reject path. The 64 MiB memory cost is required
    // to match production Argon2id parameters so that the constant-time
    // comparison between known and unknown client_ids is indistinguishable.
    let dummy_argon2_start = worker::Date::now().as_millis();
    let dummy_argon2_hash = crate::security::hash::hash_api_key("dummy_key_for_timing_resistance")
        .map_err(|e| {
            ApiError::Internal(anyhow::anyhow!(
                "Failed to generate dummy Argon2 hash: {}",
                e
            ))
        })?;
    let dummy_argon2_ms = (worker::Date::now()
        .as_millis()
        .saturating_sub(dummy_argon2_start)) as f64;

    // RT-052: Warn when previous rotation keys are active. These keys must be removed
    // from the Secrets Store within 72 hours of rotation completing to limit the
    // window in which the old key material remains valid.
    if previous_mek.is_some() {
        console_log!(
            "[SECURITY][ROTATION] Previous MEK is active. Remove VERIFIER_MEK_PREVIOUS from Secrets Store within 72 hours of completing rotation."
        );
    }
    // Cold-start sanity log for the status-token slot probes.
    // Both probes return the public-safe 6-char fingerprint or the unset
    // sentinel; the runtime verify path resolves the actual Argon2id hash
    // through the five-minute TTL `status_token_cache` on every request.
    // The sentinel comparison runs against the static literal exposed by
    // `secret_fingerprint::FINGERPRINT_UNSET`, so the branch is not
    // secret-dependent.
    let unset_sentinel = crate::security::secret_fingerprint::FINGERPRINT_UNSET;
    console_log!(
        r#"{{"audit":true,"event":"cold_start_status_token_probe","current_fingerprint":"{}","previous_fingerprint":"{}"}}"#,
        status_token_fingerprint_probe,
        status_token_fingerprint_previous_probe
    );
    // warn while the previous STATUS_API_TOKEN slot is
    // populated. The HMAC class runbook caps the dual-accept window per
    // Rotation class §3.2.
    if status_token_fingerprint_previous_probe != unset_sentinel {
        console_log!(
            "[SECURITY][ROTATION] Previous STATUS_API_TOKEN slot is active. Remove STATUS_API_TOKEN_PREVIOUS from Secrets Store once all callers have rotated."
        );
    }
    // Emit structured cold start sub-timing for Grafana Loki
    console_log!(
        r#"{{"type":"COLD_START_PHASES","service":"provii-verifier","secrets_ms":{:.1},"credit_hmac_ms":{:.1},"dummy_argon2_ms":{:.1}}}"#,
        secrets_ms,
        credit_hmac_ms,
        dummy_argon2_ms
    );

    // derive the status-token role suffix
    // from `cfg.environment` so sandbox traffic is grouped under its own
    // fingerprint slot in Grafana per the structured log schema.
    let status_token_role =
        crate::security::status_auth::status_token_role_for_env(&cfg.environment);

    // pre-compute 6-char fingerprints for every
    // rotation-capable secret in AppState. The fingerprints are public-safe
    // (24 bits, one-way hash) and surface on every protected response via the
    // `x-secret-version` header. Computing once at startup keeps
    // the per-request cost zero.
    use crate::security::secret_fingerprint::{fingerprint6_bytes, fingerprint6_str};
    use crate::security::secret_versions::{
        hosted_mek_role_for_env, ip_hash_salt_role_for_env, mek_role_for_env,
        session_token_role_for_env, verifier_hmac_role_for_env,
    };
    let unset_fp = crate::security::secret_fingerprint::FINGERPRINT_UNSET.to_string();

    let mek_fingerprint = mek_cached
        .as_ref()
        .map(|m| fingerprint6_bytes(m.as_slice()))
        .unwrap_or_else(|| unset_fp.clone());
    let mek_fingerprint_previous = previous_mek
        .as_ref()
        .map(|m| fingerprint6_bytes(m.as_slice()))
        .unwrap_or_else(|| unset_fp.clone());
    let session_token_fingerprint = session_token_secret
        .as_ref()
        .map(|s| fingerprint6_str(Some(s.as_str())))
        .unwrap_or_else(|| unset_fp.clone());
    let session_token_fingerprint_previous = session_token_secret_previous
        .as_ref()
        .map(|s| fingerprint6_str(Some(s.as_str())))
        .unwrap_or_else(|| unset_fp.clone());
    let ip_hash_salt_fingerprint = fingerprint6_str(Some(ip_hash_salt.as_str()));

    // M1: Pre-load the hosted MEK (and previous slot) into the process-wide
    // cache at startup, in parallel, rather than fetching it lazily on the
    // first hosted-flow request. This eliminates per-request Secrets Store
    // latency on a cold isolate and makes a missing/transient HOSTED_MEK visible
    // in cold-start logs immediately. The pre-load is best-effort and never
    // blocks startup: when the primary key is absent, hosted handlers return a
    // fast 503 on first use while non-hosted endpoints stay available. The
    // returned fingerprints (derived from the raw base64 string, identical to
    // the previous behaviour) feed the `x-secret-version` header and the
    // `/_internal/version` endpoint.
    let hosted_mek_preload = crate::hosted::encryption::preload_hosted_mek(env).await;
    let hosted_mek_fingerprint = hosted_mek_preload.primary_fingerprint;
    let hosted_mek_fingerprint_previous = hosted_mek_preload.previous_fingerprint;

    let mek_role = mek_role_for_env(&cfg.environment);
    let hosted_mek_role = hosted_mek_role_for_env(&cfg.environment);
    let verifier_hmac_role = verifier_hmac_role_for_env(&cfg.environment);
    let session_token_role_label = session_token_role_for_env(&cfg.environment);
    let ip_hash_salt_role = ip_hash_salt_role_for_env(&cfg.environment);

    Ok(AppState {
        cfg,
        challenge_store,
        nonce_store,
        ban_store,
        jwks_cache,
        audit_logger,
        origin_policy_store,
        idempotency_store,
        credit_management_client,
        mek_cached,
        previous_mek,
        ip_hash_salt,
        status_token_role,
        mek_fingerprint,
        mek_fingerprint_previous,
        hosted_mek_fingerprint,
        hosted_mek_fingerprint_previous,
        session_token_fingerprint,
        session_token_fingerprint_previous,
        ip_hash_salt_fingerprint,
        mek_role,
        hosted_mek_role,
        verifier_hmac_role,
        session_token_role_label,
        ip_hash_salt_role,
        sandbox_api_key_cached,
        loadtest_api_key_cached,
        session_token_secret,
        session_token_secret_previous,
        dummy_argon2_hash,
        env: env.clone(),
        analytics,
    })
}

/// Fetch event handler. Receives every inbound HTTP request, initialises (or
/// retrieves) the cached [`AppState`], instruments cold start metrics, and
/// dispatches to the router built by [`build_router`].
#[event(fetch)]
pub async fn handle_request(
    req: worker::Request,
    env: Env,
    ctx: Context,
) -> Result<Response, WorkerError> {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    // Store the worker context so route handlers can schedule fire-and-forget
    // background work via `wait_until()` without threading Context through the
    // router. Workers are single-threaded, so this is safe.
    crate::set_worker_context(ctx);

    // ══════════════════════════════════════════════════════════════════════════════
    // COLD START DETECTION & PERFORMANCE INSTRUMENTATION
    // ══════════════════════════════════════════════════════════════════════════════
    let request_start_ms = crate::utils::perf::now_millis();
    let is_cold = crate::is_cold_start();
    let request_num = crate::increment_request_count();
    let route = req.path();

    if is_cold {
        // Record the initialisation timestamp for this worker instance
        crate::record_worker_init_time();
        console_log!(
            "[COLD_START] ❄️ Cold start detected! Route: {} | Request #{}",
            route,
            request_num
        );
    } else {
        let worker_init_ts = crate::get_worker_init_timestamp();
        let worker_age_ms = if worker_init_ts > 0 {
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let start_u64 = request_start_ms as u64;
                start_u64.saturating_sub(worker_init_ts)
            }
        } else {
            0
        };
        console_log!(
            "[WARM] 🔥 Warm request #{} | Route: {} | Worker age: {}ms",
            request_num,
            route,
            worker_age_ms
        );
    }

    console_log!("[V1 API] Incoming request: {} {}", req.method(), req.path());

    // Capture values needed for error responses before the request/environment are moved.
    let origin = req
        .headers()
        .get("Origin")
        .ok()
        .flatten()
        .unwrap_or_default();
    // SECURITY: Default to empty (deny all cross-origin) rather than wildcard.
    // If the env var is missing, WorkerEnv::from_env will catch it and fail
    // startup. This fallback only affects error response CORS headers before
    // AppState is initialised.
    let cors_origins = env
        .var("PROVII_CORS_ORIGINS")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let environment = env
        .var("ENVIRONMENT")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Helper closure that attaches security and CORS headers to responses.
    let add_headers = |mut response: Response,
                       origin: &str,
                       cors_origins: &str|
     -> Result<Response, WorkerError> {
        // Apply baseline security headers.
        response = add_security_headers(response)?;

        let headers = response.headers_mut();

        // Determine whether the request origin is permitted.
        // Use shared origin matcher with dot-boundary enforcement.
        let is_global_wildcard = cors_origins.trim() == "*";
        let allowed = if is_global_wildcard {
            true
        } else {
            cors_origins.split(',').any(|pattern| {
                let pattern = pattern.trim();
                crate::utils::origin::origin_matches_pattern(pattern, origin)
            })
        };

        if allowed && !origin.is_empty() {
            headers.set("Access-Control-Allow-Origin", origin)?;
            // Only send credentials header when origins are explicitly
            // listed. A global wildcard ("*") with credentials is a browser
            // security violation and an over-permissive posture.
            if !is_global_wildcard {
                headers.set("Access-Control-Allow-Credentials", "true")?;
            }
        }
        // SECURITY: For rejected origins, silently omit Access-Control-Allow-Origin.
        // The browser enforces CORS rejection when this header is absent.

        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
        // ADV-VA-09-002: Aligned with hosted/cors.rs to include the full
        // set of allowed headers across all code paths.
        headers.set(
            "Access-Control-Allow-Headers",
            "Content-Type, X-API-Key, X-Public-Key, X-Request-ID, X-API-Version, Idempotency-Key, X-CSRF-Token",
        )?;
        headers.set("Access-Control-Max-Age", "86400")?;
        headers.set("Vary", "Origin")?;

        Ok(response)
    };

    // Liveness fast-path: /health must not pay the cold-start AppState build. It
    // is the most-hit endpoint (uptime monitors + the status page, every ~60s,
    // so isolates are frequently cold), and the basic check only verifies crypto
    // init (a cheap idempotent OnceLock). Answer it BEFORE building AppState so a
    // cold isolate still responds fast. /health/detailed remains the full
    // readiness probe that exercises AppState + subsystems. This response is
    // byte-identical to the router's /health (same BasicHealthResponse + status).
    if matches!(req.method(), worker::Method::Get) && route.as_str() == "/health" {
        let status = match crate::init_crypto_once() {
            Ok(()) => crate::routes::health::HealthStatus::Healthy,
            Err(_) => crate::routes::health::HealthStatus::Unhealthy,
        };
        let http_status = status.http_status_code();
        let resp = Response::from_json(&crate::routes::health::BasicHealthResponse {
            status,
            timestamp: worker::Date::now().as_millis() / 1000,
            version: "v1".to_string(),
        })?
        .with_status(http_status);
        return add_headers(resp, &origin, &cors_origins);
    }

    // Use the cached app state if available.
    let state_init_start = crate::utils::perf::now_millis();
    let state = match get_or_init_app_state(&env).await {
        Ok(state) => state,
        Err(e) => {
            console_log!("❌ get_or_init_app_state error: {:?}", e);
            let error_response = Response::error("Service initialisation failed", 500)?;
            return add_headers(error_response, &origin, &cors_origins);
        }
    };
    let state_init_ms = crate::utils::perf::now_millis() - state_init_start;

    // ══════════════════════════════════════════════════════════════════════════════
    // COLD START ANALYTICS
    // ══════════════════════════════════════════════════════════════════════════════
    // Record cold start metrics to Analytics Engine for performance monitoring
    if is_cold {
        let total_init_ms = crate::utils::perf::now_millis() - request_start_ms;
        console_log!(
            "[COLD_START] ⏱️ Initialisation complete | Total: {}ms | State: {}ms | Route: {}",
            total_init_ms,
            state_init_ms,
            route
        );

        // Emit analytics event for cold start tracking
        let analytics = crate::analytics::Analytics::new(&env);
        analytics.cold_start(
            &route,
            total_init_ms,
            None, // crypto_init_ms - measured separately in init_crypto_once
            Some(state_init_ms),
            None, // mek_fetch_ms - captured in init_app_state_internal
            &environment,
        );
    } else {
        // For warm requests, emit periodic analytics (every 100th request)
        if request_num.is_multiple_of(100) {
            let worker_init_ts = crate::get_worker_init_timestamp();
            let worker_age_ms = if worker_init_ts > 0 {
                {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let start_u64 = request_start_ms as u64;
                    start_u64.saturating_sub(worker_init_ts)
                }
            } else {
                0
            };
            let analytics = crate::analytics::Analytics::new(&env);
            analytics.warm_request(&route, request_num, worker_age_ms, &environment);
        }
    }

    // Reject sandbox-prefixed identifiers on production.
    // Runs BEFORE rate-limiting so that probing with sandbox credentials
    // does not chew through the per-IP budget. In the sandbox deployment
    // this check is a no-op (ENVIRONMENT=="sandbox").
    match crate::security::check_prefix_rejection(&req, &env) {
        Ok(Some(resp)) => {
            return add_headers(resp, &origin, &cors_origins);
        }
        Ok(None) => {}
        Err(e) => {
            console_log!(
                "[SECURITY] prefix rejection check failed to construct response: {:?}",
                e
            );
            // Fall through; the router will emit its own 500 if anything
            // genuinely malformed surfaces later.
        }
    }

    // H-8: Global per-IP rate limit before routing. Defends against volumetric
    // abuse from a single IP regardless of endpoint. Fail-closed: if the KV
    // binding is unavailable, return 503 rather than allowing unthrottled traffic.
    {
        let client_ip = crate::worker_routes::get_client_ip(req.headers());
        let ip_hash = crate::security::hash_ip(&client_ip, &state.ip_hash_salt);
        match env.kv(crate::bindings::KV_RATE_LIMITS) {
            Ok(rl_kv) => {
                let result =
                    crate::rate_limiting::check_per_ip_limit(&rl_kv, "global_ip:", &ip_hash, 1000)
                        .await;
                if !result.allowed {
                    console_log!(
                        "[SECURITY] Global IP rate limit exceeded for hashed IP: {}",
                        ip_hash.get(..16).unwrap_or(&ip_hash)
                    );
                    let resp = crate::rate_limiting::rate_limit_or_unavailable_response(&result)?;
                    return add_headers(resp, &origin, &cors_origins);
                }
            }
            Err(e) => {
                // SECURITY: Fail closed. Rate limiting is a security control;
                // allowing unlimited traffic when KV is down creates a DDoS vector.
                console_log!(
                    "[SECURITY] VERIFIER_KV_RATE_LIMITS binding failed, rejecting request: {:?}",
                    e
                );
                console_log!(
                    "{{\"audit\":true,\"event\":\"rate_limit_binding_failure\",\"severity\":\"critical\",\"binding\":\"VERIFIER_KV_RATE_LIMITS\",\"outcome\":\"fail_closed\"}}"
                );
                let resp = Response::error("Service Unavailable", 503)?;
                return add_headers(resp, &origin, &cors_origins);
            }
        }
    }

    let router = build_router(state);

    match router.run(req, env).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            console_log!("❌ Route error: {:?}", e);
            // M2: Preserve the structured ApiError that was propagated through
            // `?` into a `worker::Error`. The previous `Response::error(...)`
            // collapsed every routed handler error into an opaque 500, hiding
            // the real status (e.g. 400/401/402/403/429/503) and the
            // machine-readable code/field/detail. `response_from_worker_error`
            // decodes the `<base>!!<payload>` envelope and falls back to a 500
            // INTERNAL_ERROR only when the error does not match a known
            // ApiError. Mirrors the dispatcher path in worker_routes.rs.
            let error_response = ApiError::response_from_worker_error(&e)?;
            add_headers(error_response, &origin, &cors_origins)
        }
    }
}

/// Warm up critical Durable Object shards to reduce cold start latency.
/// Sends lightweight HEAD requests to keep shards warm and reduce P99 latency.
async fn warmup_durable_objects(env: &Env) {
    console_log!("[CRON] Starting DO keep-alive warmup...");
    let start = worker::Date::now().as_millis();

    // Get shard counts from environment
    let challenge_shard_count: usize = env
        .var("CHALLENGE_SHARD_COUNT")
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "25".to_string())
        .parse()
        .unwrap_or(25)
        .clamp(1, 100);

    let nonce_shard_count: usize = env
        .var("NONCE_SHARD_COUNT")
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "25".to_string())
        .parse()
        .unwrap_or(25)
        .clamp(1, 100);

    let mut warmed: u32 = 0;
    let mut failed: u32 = 0;

    // Warm challenge DOs (highest priority - used on every verification)
    if let Ok(namespace) = env.durable_object("VERIFIER_DO_CHALLENGE") {
        for i in 0..challenge_shard_count {
            let shard_name = format!("challenge-shard-{}", i);
            match namespace.id_from_name(&shard_name) {
                Ok(id) => {
                    match id.get_stub() {
                        Ok(stub) => {
                            // Send lightweight HEAD ping
                            match worker::Request::new(
                                "https://do.internal/ping",
                                worker::Method::Head,
                            ) {
                                Ok(req) => {
                                    let _ = stub.fetch_with_request(req).await;
                                    warmed = warmed.saturating_add(1);
                                }
                                Err(_) => failed = failed.saturating_add(1),
                            }
                        }
                        Err(_) => failed = failed.saturating_add(1),
                    }
                }
                Err(_) => failed = failed.saturating_add(1),
            }
        }
    } else {
        console_log!("[CRON] ⚠️ Challenge DO not available for warmup");
    }

    // Warm nonce DOs (high priority - used on every verification)
    if let Ok(namespace) = env.durable_object("VERIFIER_DO_NONCE") {
        for i in 0..nonce_shard_count {
            let shard_name = format!("nonce-shard-{}", i);
            match namespace.id_from_name(&shard_name) {
                Ok(id) => match id.get_stub() {
                    Ok(stub) => {
                        match worker::Request::new("https://do.internal/ping", worker::Method::Head)
                        {
                            Ok(req) => {
                                let _ = stub.fetch_with_request(req).await;
                                warmed = warmed.saturating_add(1);
                            }
                            Err(_) => failed = failed.saturating_add(1),
                        }
                    }
                    Err(_) => failed = failed.saturating_add(1),
                },
                Err(_) => failed = failed.saturating_add(1),
            }
        }
    } else {
        console_log!("[CRON] ⚠️ Nonce DO not available for warmup");
    }

    let elapsed = worker::Date::now().as_millis().saturating_sub(start);
    console_log!(
        "[CRON] DO keep-alive complete: {} warmed, {} failed, {}ms",
        warmed,
        failed,
        elapsed
    );
}

/// Pre-warm KV caches by reading sentinel keys. This primes the Cloudflare
/// edge cache for the KV namespaces most frequently hit during verification.
async fn warmup_kv_caches(env: &Env) {
    let start = worker::Date::now().as_millis();

    // Prime the origin policy cache for the playground origin (the most common
    // source of cron-adjacent cold requests).
    if let Ok(config_kv) = env.kv(KV_CONFIG) {
        let _ = config_kv
            .get("origin:https://playground.provii.app")
            .text()
            .await;
        let _ = config_kv.get("origin:https://demo.provii.app").text().await;
        console_log!("[CRON] KV pre-warm: origin policy cache primed (VERIFIER_KV_CONFIG)");
    } else {
        console_log!("[CRON] KV pre-warm: VERIFIER_KV_CONFIG binding unavailable, skipping");
    }

    // Prime the ban list KV cache with a known-absent sentinel read. The
    // actual value does not matter; the read warms the edge connection.
    if let Ok(ban_kv) = env.kv(KV_BANLIST) {
        let _ = ban_kv.get("ban:__warmup__").text().await;
        console_log!("[CRON] KV pre-warm: ban list cache primed (VERIFIER_KV_BANLIST)");
    } else {
        console_log!("[CRON] KV pre-warm: VERIFIER_KV_BANLIST binding unavailable, skipping");
    }

    let elapsed = worker::Date::now().as_millis().saturating_sub(start);
    console_log!("[CRON] KV pre-warm complete: {}ms", elapsed);
}

/// Warm hosted subsystem Durable Objects, KV, and MEK cache.
async fn warmup_hosted_subsystems(env: &Env) {
    let start = worker::Date::now().as_millis();
    let mut warmed: u32 = 0;
    let mut failed: u32 = 0;

    // -- Hosted DOs --

    // HOSTED_NONCE_DO: 25 shards (mirrors NONCE_SHARD_COUNT in hosted storage)
    const HOSTED_NONCE_SHARD_COUNT: usize = 25;
    if let Ok(namespace) = env.durable_object("HOSTED_NONCE_DO") {
        for i in 0..HOSTED_NONCE_SHARD_COUNT {
            let shard_name = format!("nonce-shard-{}", i);
            match namespace.id_from_name(&shard_name) {
                Ok(id) => match id.get_stub() {
                    Ok(stub) => {
                        match worker::Request::new("https://do.internal/ping", worker::Method::Head)
                        {
                            Ok(req) => {
                                let _ = stub.fetch_with_request(req).await;
                                warmed = warmed.saturating_add(1);
                            }
                            Err(_) => failed = failed.saturating_add(1),
                        }
                    }
                    Err(_) => failed = failed.saturating_add(1),
                },
                Err(_) => failed = failed.saturating_add(1),
            }
        }
    } else {
        console_log!("[CRON] HOSTED_NONCE_DO binding unavailable, skipping warmup");
    }

    // HOSTED_IDEMPOTENCY_DO: single shard
    if let Ok(namespace) = env.durable_object("HOSTED_IDEMPOTENCY_DO") {
        match namespace.id_from_name("idempotency-warmup") {
            Ok(id) => match id.get_stub() {
                Ok(stub) => {
                    match worker::Request::new("https://do.internal/ping", worker::Method::Head) {
                        Ok(req) => {
                            let _ = stub.fetch_with_request(req).await;
                            warmed = warmed.saturating_add(1);
                        }
                        Err(_) => failed = failed.saturating_add(1),
                    }
                }
                Err(_) => failed = failed.saturating_add(1),
            },
            Err(_) => failed = failed.saturating_add(1),
        }
    } else {
        console_log!("[CRON] HOSTED_IDEMPOTENCY_DO binding unavailable, skipping warmup");
    }

    // HOSTED_CHALLENGE_NOTIFY_DO: single shard
    if let Ok(namespace) = env.durable_object("HOSTED_CHALLENGE_NOTIFY_DO") {
        match namespace.id_from_name("notify-warmup") {
            Ok(id) => match id.get_stub() {
                Ok(stub) => {
                    match worker::Request::new("https://do.internal/ping", worker::Method::Head) {
                        Ok(req) => {
                            let _ = stub.fetch_with_request(req).await;
                            warmed = warmed.saturating_add(1);
                        }
                        Err(_) => failed = failed.saturating_add(1),
                    }
                }
                Err(_) => failed = failed.saturating_add(1),
            },
            Err(_) => failed = failed.saturating_add(1),
        }
    } else {
        console_log!("[CRON] HOSTED_CHALLENGE_NOTIFY_DO binding unavailable, skipping warmup");
    }

    // -- Hosted KV sentinel read --
    if let Ok(kv) = env.kv("HOSTED_SESSIONS") {
        let _ = kv.get("__warmup__").text().await;
        console_log!("[CRON] Hosted KV pre-warm: HOSTED_SESSIONS edge cache primed");
    } else {
        console_log!("[CRON] HOSTED_SESSIONS KV binding unavailable, skipping warmup");
    }

    // -- MEK pre-warm (primes the OnceLock cache so first real request is fast) --
    match crate::hosted::encryption::get_mek_from_secrets(env).await {
        Ok(_) => {
            console_log!("[CRON] Hosted MEK cache primed from Secrets Store");
        }
        Err(e) => {
            console_log!("[CRON] Hosted MEK pre-warm failed: {:?}", e);
            failed = failed.saturating_add(1);
        }
    }

    let elapsed = worker::Date::now().as_millis().saturating_sub(start);
    console_log!(
        "[CRON] Hosted subsystem warmup complete: {} DO shards warmed, {} failures, {}ms",
        warmed,
        failed,
        elapsed
    );
}

/// Scheduled event handler. Warms critical Durable Object shards and KV caches
/// every minute to eliminate cold starts (sandbox workers go cold within ~60s
/// of inactivity).
#[event(scheduled)]
pub async fn handle_cron(_event: worker::ScheduledEvent, env: Env, _ctx: worker::ScheduleContext) {
    console_log!("[CRON] Keep-alive warmup triggered");
    // Run verifier warmup, KV warmup, and hosted subsystem warmup in parallel
    // since they are fully independent.
    futures::join!(
        warmup_durable_objects(&env),
        warmup_kv_caches(&env),
        warmup_hosted_subsystems(&env),
    );
}

// VA-RL-013: This module (1570+ lines) has zero unit tests. All functions
// require a live `worker::Env` (KV namespaces, Durable Object bindings,
// Secrets Store) which is only available in the Cloudflare Workers wasm32
// runtime. Pure-logic extraction into testable helpers is tracked under
// VA-RL-013. Until then, coverage relies on the wasm_bindgen_test suite
// in `tests/security/internal_traffic_guard_test.rs` and end-to-end tests
// against the deployed worker.
#[cfg(test)]
mod tests {
    #[test]
    fn worker_bindings_module_compiles() {
        // Structural test: the module compiles and exports are accessible.
        // Full unit tests require the Workers runtime (Env, KvStore, DO).
    }
}
