// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Origin policy definitions and KV-backed store.
//!
//! An origin policy controls per-origin behaviour: minimum/maximum age
//! thresholds, proof direction, allowed issuers and verifying keys, TTL caps,
//! billing plan, and per-client HMAC authentication credentials. Policies are
//! written by `provii-management` and read from KV by this module with a 1-minute
//! in-memory cache (KV-016).
#![forbid(unsafe_code)]

use crate::{
    error::{ApiError, ApiResult},
    utils::current_timestamp,
};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use worker::kv::KvStore;
use zeroize::Zeroizing;

/// Direction of age proof: whether we're proving over-age or under-age.
///
/// Derived from origin policy at challenge creation time. The client never
/// chooses the direction; the server determines it from the policy's
/// `proof_direction` field (or infers it from `max_age_years`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofDirection {
    #[default]
    OverAge,
    UnderAge,
}

impl ProofDirection {
    /// Returns the wire-format string ("over_age" or "under_age").
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OverAge => "over_age",
            Self::UnderAge => "under_age",
        }
    }
}

impl fmt::Display for ProofDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// IV-171: deny_unknown_fields is intentionally NOT applied here.
/// OriginPolicy is written by provii-management and read by provii-verifier from KV.
/// Adding deny_unknown_fields would break deserialisation when provii-management
/// adds new fields before provii-verifier is updated, or when existing KV entries
/// contain legacy fields (e.g. the removed "rate_limits" object). The same
/// reasoning applies to nested BillingConfig and ClientAuthConfig.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OriginPolicy {
    pub tenant_id: String,
    /// Minimum allowed age expressed in years (e.g., 13, 16, 18, 21).
    /// This is converted to exact days at challenge creation time, accounting for leap years.
    ///
    /// IV-172: Bounded to 0..=150 to reject nonsensical policy values.
    pub min_age_years: u32,
    /// Maximum age for under-age verification (e.g., 13 means "under 13").
    /// Only required for origins that support under-age challenges.
    ///
    /// IV-172: Bounded to 0..=150 to reject nonsensical policy values.
    #[serde(default)]
    pub max_age_years: Option<u32>,
    /// Explicit proof direction set via provii-management. If absent, inferred
    /// from `max_age_years` (present → UnderAge, absent → OverAge).
    #[serde(default)]
    pub proof_direction: Option<ProofDirection>,
    /// Whitelisted verifying-key identifiers for over-age proofs.
    pub allowed_vk_ids: Vec<u32>,
    /// Allowed issuer key hashes encoded as base64url strings.
    pub allowed_issuers: Vec<String>,
    /// Maximum challenge TTL permitted for the origin.
    pub max_ttl_sec: u64,
    pub billing: BillingConfig,
    pub enabled: bool,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub clients: Vec<ClientAuthConfig>,
    /// Partner identifier when this policy was provisioned by a partner
    /// (e.g. "partner_cloudflare"). `None` for admin-provisioned policies.
    /// Existing KV entries without this field deserialise as `None`
    /// (IV-171: deny_unknown_fields is not used).
    #[serde(default)]
    pub provisioned_by: Option<String>,
    /// Outage failure mode for this origin: how the SDK should behave when
    /// Provii cannot return a verdict ("block" | "allow" | "defer"). `None` =
    /// force-explicit (the SDK falls back to the integrator's
    /// data-on-unavailable, else block). Delivered in the challenge response
    /// and cached by the SDK so it survives an outage. Existing KV entries
    /// without this field deserialise as `None`.
    #[serde(default)]
    pub failure_mode: Option<String>,
    /// When true, the integrator's data-on-unavailable choice is ignored
    /// (governance lock for high-risk customers).
    #[serde(default)]
    pub failure_mode_locked: bool,
}

/// Per-client authentication credentials stored within an [`OriginPolicy`].
///
/// Each client has an Argon2id-hashed API key and an AES-256-GCM encrypted
/// HMAC secret. The `api_key_prefix` field enables O(1) prefix-based lookup
/// instead of scanning all clients during authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    pub client_id: String,

    /// API key hash in Argon2id PHC format ($argon2id$ prefix).
    /// Non-Argon2id formats are rejected.
    pub api_key_hash: String,

    /// PERFORMANCE: First 8 characters of the API key for prefix-based indexing.
    /// This enables O(1) lookups by allowing us to narrow down which clients to verify.
    /// Format: "pk_live_" or "pk_test_" (8 chars)
    /// This is safe to store as it doesn't reveal the full key.
    #[serde(default)]
    pub api_key_prefix: Option<String>,

    /// SECURITY: AES-256-GCM encrypted HMAC secret (base64url-encoded).
    /// Format: IV (12 bytes) + ciphertext + authentication tag (16 bytes)
    /// Encrypted using the per-client DEK.
    pub encrypted_hmac_secret: String,

    /// SECURITY: Encrypted Data Encryption Key (base64url-encoded).
    /// Format: IV (12 bytes) + ciphertext + authentication tag (16 bytes)
    /// Encrypted using the Master Encryption Key (MEK) from Workers Secrets.
    pub dek_encrypted: String,

    /// Encryption version for key rotation and schema evolution.
    /// Incremented when re-encrypting with a new MEK version.
    #[serde(default = "default_encryption_version")]
    pub encryption_version: u8,

    #[serde(default = "default_true")]
    pub active: bool,
}

impl fmt::Debug for ClientAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SECURITY: Redact api_key_hash (defence-in-depth; it is a hash, not the raw key).
        f.debug_struct("ClientAuthConfig")
            .field("client_id", &self.client_id)
            .field("api_key_hash", &"[REDACTED]")
            .field("api_key_prefix", &self.api_key_prefix)
            .field("encrypted_hmac_secret", &"[ENCRYPTED]")
            .field("dek_encrypted", &"[ENCRYPTED]")
            .field("encryption_version", &self.encryption_version)
            .field("active", &self.active)
            .finish()
    }
}

// NOTE: Encrypted fields don't need zeroization as they're already protected
// by encryption. The decrypted secrets are zeroized using Zeroizing<Vec<u8>>
// in the verify_hmac function.
//
// ACCEPT: Clone on ClientAuthConfig scatters api_key_hash across memory.
// This is defence-in-depth only: api_key_hash is already a one-way Argon2id
// hash, not the raw secret. Serde intermediates during JSON deserialisation
// also produce transient String copies; Argon2 hashes are not secret material.

const fn default_true() -> bool {
    true
}

const fn default_encryption_version() -> u8 {
    1 // Default to version 1 for all new clients
}

/// Billing plan and metering toggle associated with an origin policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BillingConfig {
    /// Plan identifier (e.g. `free`, `pro`, `enterprise`).
    pub plan: String,
    /// Whether per-verification metering events are emitted.
    pub metering_enabled: bool,
}

impl Default for OriginPolicy {
    fn default() -> Self {
        Self {
            tenant_id: String::new(),
            min_age_years: 18,
            max_age_years: None,
            proof_direction: None,
            allowed_vk_ids: vec![1, 2, 3],
            allowed_issuers: vec![],
            max_ttl_sec: 300,
            billing: BillingConfig {
                plan: "free".to_string(),
                metering_enabled: false,
            },
            enabled: false,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            clients: Vec::new(),
            provisioned_by: None,
            failure_mode: None,
            failure_mode_locked: false,
        }
    }
}

impl OriginPolicy {
    /// Returns the effective proof direction for this origin.
    ///
    /// If the policy has an explicit `proof_direction`, that value is used.
    /// Otherwise, the direction is inferred: if `max_age_years` is set, the
    /// origin wants under-age verification; otherwise over-age.
    pub fn effective_proof_direction(&self) -> ProofDirection {
        if let Some(dir) = self.proof_direction {
            return dir;
        }
        if self.max_age_years.is_some() {
            ProofDirection::UnderAge
        } else {
            ProofDirection::OverAge
        }
    }

    /// Returns the age threshold (in years) for this origin's proof direction.
    ///
    /// - `OverAge` → uses `min_age_years`
    /// - `UnderAge` → uses `max_age_years` (returns error if not configured)
    ///
    /// IV-172: Rejects values above 150 years (no human lives longer).
    pub fn age_threshold(&self) -> Result<u32, &'static str> {
        const MAX_AGE_YEARS: u32 = 150;
        match self.effective_proof_direction() {
            ProofDirection::OverAge => {
                if self.min_age_years > MAX_AGE_YEARS {
                    return Err("min_age_years exceeds maximum of 150");
                }
                Ok(self.min_age_years)
            }
            ProofDirection::UnderAge => {
                let age = self
                    .max_age_years
                    .ok_or("Origin policy does not allow under-age verification")?;
                if age > MAX_AGE_YEARS {
                    return Err("max_age_years exceeds maximum of 150");
                }
                Ok(age)
            }
        }
    }
}

/// Result of a detailed origin policy lookup, distinguishing disabled from not-found.
///
/// Used by route handlers that need to audit the specific denial reason
/// (AL-046: disabled origin, AL-047: unknown origin).
#[derive(Debug)]
pub enum PolicyLookupResult {
    /// Policy found and enabled.
    Found(OriginPolicy),
    /// Policy exists in KV but is disabled.
    Disabled,
    /// No policy found for this origin.
    NotFound,
}

/// In-memory cached policy entry paired with a timestamp and an API key
/// prefix index for O(1) client lookups.
pub struct CachedPolicy {
    /// The full origin policy.
    pub policy: OriginPolicy,
    /// Timestamp in milliseconds since UNIX epoch when this entry was cached.
    pub cached_at: u64,
    /// Maps the first 8 characters of an API key (e.g. `pk_live_`) to the
    /// indices within `policy.clients` that share that prefix. Clients
    /// without a stored prefix fall into the `PREFIX_UNKNOWN` bucket.
    pub api_key_prefix_index: HashMap<String, Vec<usize>>,
}

/// Maximum number of cached origin policy entries. Beyond this, selective
/// TTL-based eviction removes entries older than half the cache TTL. If that
/// is insufficient, a full clear is performed as fallback.
const MAX_CACHE_ENTRIES: usize = 1024;

/// KV-backed origin policy store with a 1-minute in-memory cache (KV-016).
pub struct OriginPolicyStore {
    kv: KvStore,
    cache: RwLock<HashMap<String, CachedPolicy>>,
    /// Cache TTL in milliseconds (1 minute = 60,000 ms).
    /// KV-016: Reduced from 5 minutes to limit stale-policy window.
    cache_ttl_ms: u64,
}

impl OriginPolicyStore {
    /// Create a new store backed by the given KV namespace.
    pub fn new(kv: KvStore) -> Self {
        Self {
            kv,
            cache: RwLock::new(HashMap::new()),
            cache_ttl_ms: 60_000, // 1 minute (KV-016)
        }
    }

    fn policy_key(origin: &str) -> String {
        format!("origins/{}", origin)
    }

    /// Builds an API key prefix index for O(1) lookups.
    /// Maps the first 8 characters of API keys to client indices.
    /// This converts O(n) linear scan to O(1) hash map lookup + O(k) verification
    /// where k is the number of clients sharing the same prefix (typically very small).
    fn build_api_key_index(policy: &OriginPolicy) -> HashMap<String, Vec<usize>> {
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        let mut clients_without_prefix: usize = 0;

        for (idx, client) in policy.clients.iter().enumerate() {
            if !client.active {
                continue; // Skip inactive clients
            }

            // Use the api_key_prefix if available, otherwise fall back to ALL clients
            if let Some(ref prefix) = client.api_key_prefix {
                let prefix_key = prefix.get(..8).unwrap_or(prefix).to_string();
                index.entry(prefix_key).or_default().push(idx);
            } else {
                // PREFIX_UNKNOWN bucket: holds clients whose API key prefix was not
                // recorded at creation time. provii-management is being updated to
                // populate this field for new clients. Existing clients remain in
                // this bucket permanently because the raw API key is not stored
                // after initial creation.
                clients_without_prefix = clients_without_prefix.saturating_add(1);
                index
                    .entry("PREFIX_UNKNOWN".to_string())
                    .or_default()
                    .push(idx);
            }
        }

        let _active_count = policy.clients.iter().filter(|c| c.active).count();
        #[cfg(target_arch = "wasm32")]
        worker::console_log!(
            "[PERF] Built API key prefix index: {} unique prefixes for {} active clients ({} without prefix)",
            index.len(),
            _active_count,
            clients_without_prefix
        );

        index
    }

    pub async fn get_policy(&self, origin: &str) -> ApiResult<Option<OriginPolicy>> {
        // Check cache first
        let now = worker::Date::now().as_millis();
        {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(origin) {
                let age_ms = now.saturating_sub(cached.cached_at);
                if age_ms < self.cache_ttl_ms {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[PERF] Origin policy cache HIT for {} (age: {:.1}s)",
                        origin,
                        age_ms as f64 / 1000.0
                    );
                    return Ok(Some(cached.policy.clone()));
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[PERF] Origin policy cache MISS for {}", origin);

        // Fetch from KV with per-operation timeout.
        let key = Self::policy_key(origin);
        #[cfg(target_arch = "wasm32")]
        worker::console_log!("[OriginPolicy] Looking up policy for key: {}", key);

        let kv = self.kv.clone();
        let key_clone = key.clone();
        let value = crate::utils::timeout::with_timeout(
            "origin_policy KV read",
            crate::utils::timeout::KV_READ_TIMEOUT_MS,
            async move {
                kv.get(&key_clone).text().await.map_err(|e| {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!("[OriginPolicy] KV get error: {}", e);
                    ApiError::Internal(anyhow::anyhow!("KV get failed: {}", e))
                })
            },
        )
        .await
        .map_err(|e| {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[OriginPolicy] KV get timed out: {}", e);
            ApiError::Internal(anyhow::anyhow!("{}", e))
        })??;

        if let Some(json) = value {
            let json = Zeroizing::new(json);
            let policy: OriginPolicy = serde_json::from_str(&json).map_err(|e| {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("[OriginPolicy] Failed to parse JSON: {}", e);
                // AL-062: Structured audit log for corrupt policy JSON.
                // AuditLogger is unavailable in storage layer; use structured console JSON.
                #[cfg(target_arch = "wasm32")]
                worker::console_log!(
                    "{{\"audit\":true,\"event\":\"corrupt_policy_json\",\"severity\":\"critical\",\"origin\":\"{}\",\"parse_error\":\"{}\"}}",
                    origin,
                    e
                );
                ApiError::Internal(anyhow::anyhow!("Failed to parse policy: {}", e))
            })?;

            if !policy.enabled {
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("[OriginPolicy] Origin {} is disabled", origin);
                return Ok(None);
            }

            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[OriginPolicy] Policy loaded successfully for {}", origin);

            // Build API key prefix index for O(1) lookups
            let api_key_prefix_index = Self::build_api_key_index(&policy);

            // Store in cache with bounded eviction
            {
                let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
                if cache.len() >= MAX_CACHE_ENTRIES {
                    // Selective eviction: remove entries older than half the TTL
                    // (30 seconds). More targeted than a full clear.
                    let half_ttl = self.cache_ttl_ms / 2;
                    cache.retain(|_, entry| now.saturating_sub(entry.cached_at) < half_ttl);
                    if cache.len() >= MAX_CACHE_ENTRIES {
                        // Still over limit after selective eviction; full clear.
                        cache.clear();
                        #[cfg(target_arch = "wasm32")]
                        worker::console_log!(
                            "[PERF] Origin policy cache full-cleared (selective eviction insufficient)"
                        );
                    }
                }
                cache.insert(
                    origin.to_string(),
                    CachedPolicy {
                        policy: policy.clone(),
                        cached_at: now,
                        api_key_prefix_index,
                    },
                );
            }

            Ok(Some(policy))
        } else {
            #[cfg(target_arch = "wasm32")]
            worker::console_log!("[OriginPolicy] No policy found for key: {}", key);
            Ok(None)
        }
    }

    /// Detailed policy lookup that distinguishes disabled from not-found.
    ///
    /// Route handlers use this to emit distinct audit events for AL-046
    /// (disabled origin) vs AL-047 (unknown origin).
    pub async fn get_policy_detail(&self, origin: &str) -> ApiResult<PolicyLookupResult> {
        // Check cache first (same as get_policy)
        let now = worker::Date::now().as_millis();
        {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(origin) {
                let age_ms = now.saturating_sub(cached.cached_at);
                if age_ms < self.cache_ttl_ms {
                    if cached.policy.enabled {
                        return Ok(PolicyLookupResult::Found(cached.policy.clone()));
                    } else {
                        return Ok(PolicyLookupResult::Disabled);
                    }
                }
            }
        }

        // Fetch from KV with per-operation timeout.
        let key = Self::policy_key(origin);
        let kv = self.kv.clone();
        let key_clone = key.clone();
        let value = crate::utils::timeout::with_timeout(
            "origin_policy_detail KV read",
            crate::utils::timeout::KV_READ_TIMEOUT_MS,
            async move {
                kv.get(&key_clone)
                    .text()
                    .await
                    .map_err(|e| ApiError::Internal(anyhow::anyhow!("KV get failed: {}", e)))
            },
        )
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("{}", e)))??;

        match value {
            Some(json) => {
                let json = Zeroizing::new(json);
                let policy: OriginPolicy = serde_json::from_str(&json).map_err(|e| {
                    // AL-062: Structured audit log for corrupt policy JSON.
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "{{\"audit\":true,\"event\":\"corrupt_policy_json\",\"severity\":\"critical\",\"origin\":\"{}\",\"parse_error\":\"{}\"}}",
                        origin,
                        e
                    );
                    ApiError::Internal(anyhow::anyhow!("Failed to parse policy: {}", e))
                })?;

                let enabled = policy.enabled;

                // Cache regardless of enabled status (matches get_policy behaviour
                // for enabled policies; disabled ones are short-lived in cache).
                if enabled {
                    let api_key_prefix_index = Self::build_api_key_index(&policy);
                    let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
                    if cache.len() >= MAX_CACHE_ENTRIES {
                        let half_ttl = self.cache_ttl_ms / 2;
                        cache.retain(|_, entry| now.saturating_sub(entry.cached_at) < half_ttl);
                        if cache.len() >= MAX_CACHE_ENTRIES {
                            cache.clear();
                        }
                    }
                    cache.insert(
                        origin.to_string(),
                        CachedPolicy {
                            policy: policy.clone(),
                            cached_at: now,
                            api_key_prefix_index,
                        },
                    );
                    Ok(PolicyLookupResult::Found(policy))
                } else {
                    // RT-054: Evict any cached entry for a disabled origin so that
                    // re-enabling it in KV takes effect without waiting for the
                    // 5-minute cache TTL to expire.
                    self.invalidate_cache(Some(origin));
                    Ok(PolicyLookupResult::Disabled)
                }
            }
            None => Ok(PolicyLookupResult::NotFound),
        }
    }

    /// Invalidate cache for a specific origin or clear the entire cache.
    ///
    /// Currently called internally when a disabled origin is encountered during
    /// lookup (RT-054). No dedicated HTTP endpoint exists for external cache
    /// invalidation; policy changes propagate via the 5-minute cache TTL or
    /// by redeploying the worker.
    pub fn invalidate_cache(&self, origin: Option<&str>) {
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        match origin {
            Some(o) => {
                cache.remove(o);
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("[PERF] Origin policy cache invalidated for {}", o);
            }
            None => {
                cache.clear();
                #[cfg(target_arch = "wasm32")]
                worker::console_log!("[PERF] Origin policy cache cleared (all entries)");
            }
        }
    }

    /// Get cached policy with API key index for fast lookups.
    /// Returns None if policy not found or disabled.
    pub async fn get_cached_policy(&self, origin: &str) -> ApiResult<Option<CachedPolicy>> {
        // Check cache first
        let now = worker::Date::now().as_millis();
        {
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(origin) {
                let age_ms = now.saturating_sub(cached.cached_at);
                if age_ms < self.cache_ttl_ms {
                    #[cfg(target_arch = "wasm32")]
                    worker::console_log!(
                        "[PERF] Origin policy cache HIT for {} (age: {:.1}s)",
                        origin,
                        age_ms as f64 / 1000.0
                    );
                    return Ok(Some(CachedPolicy {
                        policy: cached.policy.clone(),
                        cached_at: cached.cached_at,
                        api_key_prefix_index: cached.api_key_prefix_index.clone(),
                    }));
                }
            }
        }

        // Cache miss - load from KV and build index
        let policy_opt = self.get_policy(origin).await?;

        if let Some(_policy) = policy_opt {
            // Policy was loaded and cached by get_policy, retrieve from cache
            let cache = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = cache.get(origin) {
                return Ok(Some(CachedPolicy {
                    policy: cached.policy.clone(),
                    cached_at: cached.cached_at,
                    api_key_prefix_index: cached.api_key_prefix_index.clone(),
                }));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* ========================================================================== */
    /*                    OriginPolicy TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_default() {
        let policy = OriginPolicy::default();
        assert_eq!(policy.tenant_id, "");
        assert_eq!(policy.min_age_years, 18);
        assert!(policy.max_age_years.is_none());
        assert!(policy.proof_direction.is_none());
        assert_eq!(policy.allowed_vk_ids, vec![1, 2, 3]);
        assert!(policy.allowed_issuers.is_empty());
        assert_eq!(policy.max_ttl_sec, 300);
        assert_eq!(policy.billing.plan, "free");
        assert!(!policy.billing.metering_enabled);
        assert!(!policy.enabled);
        assert!(policy.created_at > 0);
        assert!(policy.updated_at > 0);
        assert!(policy.clients.is_empty());
        assert!(policy.provisioned_by.is_none());
    }

    #[test]
    fn test_origin_policy_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy::default();
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains("tenant_id"));
        assert!(json.contains("\"min_age_years\":18"));
        assert!(json.contains("free"));
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        // Test standard deserialisation of an OriginPolicy
        let json = r#"{
            "tenant_id": "tenant123",
            "min_age_years": 18,
            "allowed_vk_ids": [1,2],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {
                "plan": "pro",
                "metering_enabled": true
            },
            "enabled": true,
            "created_at": 123,
            "updated_at": 456,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.tenant_id, "tenant123");
        assert_eq!(policy.min_age_years, 18);
        assert_eq!(policy.billing.plan, "pro");
        assert!(policy.billing.metering_enabled);
        assert!(policy.enabled);
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize_with_under_age_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "tenant_ua",
            "min_age_years": 18,
            "max_age_years": 13,
            "allowed_vk_ids": [1,2],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {
                "plan": "pro",
                "metering_enabled": true
            },
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.max_age_years, Some(13));
        assert_eq!(policy.min_age_years, 18);
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize_without_under_age_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Existing policies without under-age fields should still parse
        let json = r#"{
            "tenant_id": "tenant_oa",
            "min_age_years": 21,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {
                "plan": "free",
                "metering_enabled": false
            },
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert!(policy.max_age_years.is_none());
        assert_eq!(policy.min_age_years, 21);
        Ok(())
    }

    #[test]
    fn test_origin_policy_serialize_with_under_age_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = OriginPolicy {
            max_age_years: Some(13),
            ..OriginPolicy::default()
        };
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains("\"max_age_years\":13"));
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize_ignores_unknown_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Existing KV entries may still contain a legacy "rate_limits" field.
        // serde should silently ignore unknown fields (deny_unknown_fields is not set).
        let json = r#"{
            "tenant_id": "tenant123",
            "min_age_years": 18,
            "allowed_vk_ids": [1,2],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "rate_limits": {
                "create_per_min": 60,
                "verify_per_min": 120,
                "max_active_challenges": 100
            },
            "billing": {
                "plan": "pro",
                "metering_enabled": true
            },
            "enabled": true,
            "created_at": 123,
            "updated_at": 456,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.tenant_id, "tenant123");
        assert_eq!(policy.billing.plan, "pro");
        Ok(())
    }

    #[test]
    fn test_origin_policy_clone() {
        let policy = OriginPolicy::default();
        let cloned = policy.clone();
        assert_eq!(policy.min_age_years, cloned.min_age_years);
        assert_eq!(policy.enabled, cloned.enabled);
    }

    #[test]
    fn test_origin_policy_with_clients() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = OriginPolicy::default();
        policy.clients.push(ClientAuthConfig {
            client_id: "client1".to_string(),
            api_key_hash: "hash123".to_string(),
            api_key_prefix: None,
            encrypted_hmac_secret: "encrypted_secret".to_string(),
            dek_encrypted: "encrypted_dek".to_string(),
            encryption_version: 1,
            active: true,
        });
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains("client1"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    ProofDirection TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_proof_direction_default_is_over_age() {
        assert_eq!(ProofDirection::default(), ProofDirection::OverAge);
    }

    #[test]
    fn test_proof_direction_as_str() {
        assert_eq!(ProofDirection::OverAge.as_str(), "over_age");
        assert_eq!(ProofDirection::UnderAge.as_str(), "under_age");
    }

    #[test]
    fn test_proof_direction_display() {
        assert_eq!(format!("{}", ProofDirection::OverAge), "over_age");
        assert_eq!(format!("{}", ProofDirection::UnderAge), "under_age");
    }

    #[test]
    fn test_proof_direction_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let over = serde_json::to_string(&ProofDirection::OverAge)?;
        assert_eq!(over, "\"over_age\"");
        let under = serde_json::to_string(&ProofDirection::UnderAge)?;
        assert_eq!(under, "\"under_age\"");
        Ok(())
    }

    #[test]
    fn test_proof_direction_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let over: ProofDirection = serde_json::from_str("\"over_age\"")?;
        assert_eq!(over, ProofDirection::OverAge);
        let under: ProofDirection = serde_json::from_str("\"under_age\"")?;
        assert_eq!(under, ProofDirection::UnderAge);
        Ok(())
    }

    #[test]
    fn test_proof_direction_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        for dir in [ProofDirection::OverAge, ProofDirection::UnderAge] {
            let json = serde_json::to_string(&dir)?;
            let decoded: ProofDirection = serde_json::from_str(&json)?;
            assert_eq!(decoded, dir);
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    effective_proof_direction / age_threshold TESTS         */
    /* ========================================================================== */

    #[test]
    fn test_effective_direction_explicit_over_age() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::OverAge),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.effective_proof_direction(), ProofDirection::OverAge);
    }

    #[test]
    fn test_effective_direction_explicit_under_age() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(13),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.effective_proof_direction(), ProofDirection::UnderAge);
    }

    #[test]
    fn test_effective_direction_inferred_from_max_age() {
        let policy = OriginPolicy {
            max_age_years: Some(13),
            ..OriginPolicy::default()
        };
        // No explicit proof_direction, but max_age_years is set -> UnderAge
        assert_eq!(policy.effective_proof_direction(), ProofDirection::UnderAge);
    }

    #[test]
    fn test_effective_direction_inferred_default() {
        let policy = OriginPolicy::default();
        // No explicit proof_direction, no max_age_years → OverAge
        assert_eq!(policy.effective_proof_direction(), ProofDirection::OverAge);
    }

    #[test]
    fn test_age_threshold_over_age() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            min_age_years: 21,
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold()?, 21);
        Ok(())
    }

    #[test]
    fn test_age_threshold_under_age() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(13),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold()?, 13);
        Ok(())
    }

    #[test]
    fn test_age_threshold_under_age_missing_max() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            ..OriginPolicy::default()
        };
        // max_age_years not set -> error
        assert!(policy.age_threshold().is_err());
    }

    #[test]
    fn test_deserialize_existing_policy_without_proof_direction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Existing policies in KV lack proof_direction; should deserialise as None
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert!(policy.proof_direction.is_none());
        assert_eq!(policy.effective_proof_direction(), ProofDirection::OverAge);
        assert_eq!(policy.age_threshold()?, 18);
        Ok(())
    }

    #[test]
    fn test_deserialize_policy_with_explicit_proof_direction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t2",
            "min_age_years": 18,
            "max_age_years": 13,
            "proof_direction": "under_age",
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "pro", "metering_enabled": true},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.proof_direction, Some(ProofDirection::UnderAge));
        assert_eq!(policy.effective_proof_direction(), ProofDirection::UnderAge);
        assert_eq!(policy.age_threshold()?, 13);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ClientAuthConfig TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_client_auth_config_creation() {
        let config = ClientAuthConfig {
            client_id: "test".to_string(),
            api_key_hash: "hash".to_string(),
            api_key_prefix: None,
            encrypted_hmac_secret: "encrypted_secret".to_string(),
            dek_encrypted: "encrypted_dek".to_string(),
            encryption_version: 1,
            active: true,
        };
        assert_eq!(config.client_id, "test");
        assert!(config.active);
    }

    #[test]
    fn test_client_auth_config_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let config = ClientAuthConfig {
            client_id: "client1".to_string(),
            api_key_hash: "abc123".to_string(),
            api_key_prefix: None,
            encrypted_hmac_secret: "encrypted_xyz789".to_string(),
            dek_encrypted: "encrypted_dek".to_string(),
            encryption_version: 1,
            active: false,
        };
        let json = serde_json::to_string(&config)?;
        assert!(json.contains("client1"));
        assert!(json.contains("abc123"));
        assert!(json.contains("false"));
        Ok(())
    }

    #[test]
    fn test_client_auth_config_default_active() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "encrypted_secret",
            "dek_encrypted": "encrypted_dek"
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert!(config.active); // Should default to true
        assert_eq!(config.encryption_version, 1); // Default encryption version
        Ok(())
    }

    #[test]
    fn test_client_auth_config_explicit_inactive() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "encrypted_secret",
            "dek_encrypted": "encrypted_dek",
            "encryption_version": 1,
            "active": false
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert!(!config.active);
        Ok(())
    }

    /* ========================================================================== */
    /*                    BillingConfig TESTS                                    */
    /* ========================================================================== */

    #[test]
    fn test_billing_config_creation() {
        let config = BillingConfig {
            plan: "enterprise".to_string(),
            metering_enabled: true,
        };
        assert_eq!(config.plan, "enterprise");
        assert!(config.metering_enabled);
    }

    #[test]
    fn test_billing_config_serialize() -> Result<(), Box<dyn std::error::Error>> {
        let config = BillingConfig {
            plan: "starter".to_string(),
            metering_enabled: false,
        };
        let json = serde_json::to_string(&config)?;
        assert!(json.contains("starter"));
        assert!(json.contains("false"));
        Ok(())
    }

    #[test]
    fn test_billing_config_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "plan": "business",
            "metering_enabled": true
        }"#;
        let config: BillingConfig = serde_json::from_str(json)?;
        assert_eq!(config.plan, "business");
        assert!(config.metering_enabled);
        Ok(())
    }

    /* ========================================================================== */
    /*                    OriginPolicyStore::policy_key() TESTS                  */
    /* ========================================================================== */

    #[test]
    fn test_policy_key_format() {
        let key = OriginPolicyStore::policy_key("https://example.com");
        assert_eq!(key, "origins/https://example.com");
    }

    #[test]
    fn test_policy_key_simple_domain() {
        let key = OriginPolicyStore::policy_key("example.com");
        assert_eq!(key, "origins/example.com");
    }

    #[test]
    fn test_policy_key_with_port() {
        let key = OriginPolicyStore::policy_key("https://localhost:3000");
        assert_eq!(key, "origins/https://localhost:3000");
    }

    #[test]
    fn test_policy_key_empty_origin() {
        let key = OriginPolicyStore::policy_key("");
        assert_eq!(key, "origins/");
    }

    #[test]
    fn test_policy_key_special_chars() {
        let key = OriginPolicyStore::policy_key("https://test.example.com/path?query=value");
        assert_eq!(key, "origins/https://test.example.com/path?query=value");
    }

    /* ========================================================================== */
    /*                    provisioned_by BACKWARD COMPAT TESTS                   */
    /* ========================================================================== */

    #[test]
    fn test_deserialize_existing_policy_without_provisioned_by(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Existing KV entries lack provisioned_by; must deserialise as None.
        let json = r#"{
            "tenant_id": "t_old",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert!(policy.provisioned_by.is_none());
        Ok(())
    }

    #[test]
    fn test_deserialize_policy_with_provisioned_by() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t_cf",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "pro", "metering_enabled": true},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": [],
            "provisioned_by": "partner_cloudflare"
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(
            policy.provisioned_by,
            Some("partner_cloudflare".to_string())
        );
        Ok(())
    }

    #[test]
    fn test_serialize_policy_with_provisioned_by() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            provisioned_by: Some("partner_cloudflare".to_string()),
            ..OriginPolicy::default()
        };
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains("\"provisioned_by\":\"partner_cloudflare\""));
        Ok(())
    }

    /* ========================================================================== */
    /*                    default_true() TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_default_true_returns_true() {
        assert!(default_true());
    }

    #[test]
    fn test_default_encryption_version() {
        assert_eq!(default_encryption_version(), 1);
    }

    // ======================================================================
    // age_threshold: boundary and edge case tests
    // ======================================================================

    #[test]
    fn test_age_threshold_over_age_zero() {
        let policy = OriginPolicy {
            min_age_years: 0,
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().unwrap(), 0);
    }

    #[test]
    fn test_age_threshold_over_age_150() {
        let policy = OriginPolicy {
            min_age_years: 150,
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().unwrap(), 150);
    }

    #[test]
    fn test_age_threshold_over_age_151_rejected() {
        let policy = OriginPolicy {
            min_age_years: 151,
            ..OriginPolicy::default()
        };
        assert!(policy.age_threshold().is_err());
    }

    #[test]
    fn test_age_threshold_over_age_u32_max_rejected() {
        let policy = OriginPolicy {
            min_age_years: u32::MAX,
            ..OriginPolicy::default()
        };
        assert!(policy.age_threshold().is_err());
    }

    #[test]
    fn test_age_threshold_under_age_zero() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(0),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().unwrap(), 0);
    }

    #[test]
    fn test_age_threshold_under_age_150() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(150),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().unwrap(), 150);
    }

    #[test]
    fn test_age_threshold_under_age_151_rejected() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(151),
            ..OriginPolicy::default()
        };
        assert!(policy.age_threshold().is_err());
    }

    #[test]
    fn test_age_threshold_under_age_u32_max_rejected() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(u32::MAX),
            ..OriginPolicy::default()
        };
        assert!(policy.age_threshold().is_err());
    }

    // ======================================================================
    // effective_proof_direction: completeness
    // ======================================================================

    #[test]
    fn test_effective_direction_explicit_over_age_ignores_max_age() {
        // Explicit OverAge with max_age_years set: explicit wins
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::OverAge),
            max_age_years: Some(13),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.effective_proof_direction(), ProofDirection::OverAge);
    }

    #[test]
    fn test_effective_direction_explicit_under_age_without_max_age() {
        // Explicit UnderAge without max_age_years: age_threshold will fail
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: None,
            ..OriginPolicy::default()
        };
        assert_eq!(policy.effective_proof_direction(), ProofDirection::UnderAge);
        assert!(policy.age_threshold().is_err());
    }

    // ======================================================================
    // ClientAuthConfig: Debug redaction
    // ======================================================================

    #[test]
    fn test_client_auth_config_debug_redacts_sensitive_fields() {
        let config = ClientAuthConfig {
            client_id: "client1".to_string(),
            api_key_hash: "super_secret_hash".to_string(),
            api_key_prefix: Some("pk_live_".to_string()),
            encrypted_hmac_secret: "encrypted_secret_value".to_string(),
            dek_encrypted: "encrypted_dek_value".to_string(),
            encryption_version: 1,
            active: true,
        };
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("[ENCRYPTED]"));
        assert!(!dbg.contains("super_secret_hash"));
        assert!(!dbg.contains("encrypted_secret_value"));
        assert!(!dbg.contains("encrypted_dek_value"));
        assert!(dbg.contains("client1"));
        assert!(dbg.contains("pk_live_"));
    }

    // ======================================================================
    // ClientAuthConfig: api_key_prefix field
    // ======================================================================

    #[test]
    fn test_client_auth_config_with_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "api_key_prefix": "pk_live_",
            "encrypted_hmac_secret": "encrypted_secret",
            "dek_encrypted": "encrypted_dek"
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert_eq!(config.api_key_prefix, Some("pk_live_".to_string()));
        Ok(())
    }

    #[test]
    fn test_client_auth_config_missing_prefix_defaults_none(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "encrypted_secret",
            "dek_encrypted": "encrypted_dek"
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert!(config.api_key_prefix.is_none());
        Ok(())
    }

    // ======================================================================
    // OriginPolicy: additional deserialisation edge cases
    // ======================================================================

    #[test]
    fn test_origin_policy_deserialize_with_clients_and_prefix(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": [
                {
                    "client_id": "c1",
                    "api_key_hash": "hash1",
                    "api_key_prefix": "pk_test_",
                    "encrypted_hmac_secret": "enc1",
                    "dek_encrypted": "dek1",
                    "active": true
                }
            ]
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.clients.len(), 1);
        assert_eq!(policy.clients[0].client_id, "c1");
        assert_eq!(
            policy.clients[0].api_key_prefix,
            Some("pk_test_".to_string())
        );
        Ok(())
    }

    #[test]
    fn test_origin_policy_max_ttl_sec_zero() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [],
            "allowed_issuers": [],
            "max_ttl_sec": 0,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.max_ttl_sec, 0);
        Ok(())
    }

    // ======================================================================
    // PolicyLookupResult enum
    // ======================================================================

    #[test]
    fn test_policy_lookup_result_debug() {
        let r = PolicyLookupResult::NotFound;
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("NotFound"));

        let r2 = PolicyLookupResult::Disabled;
        let dbg2 = format!("{:?}", r2);
        assert!(dbg2.contains("Disabled"));
    }

    // ======================================================================
    // MAX_CACHE_ENTRIES constant
    // ======================================================================

    #[test]
    fn test_max_cache_entries_is_sensible() {
        assert!(MAX_CACHE_ENTRIES > 0);
        assert!(MAX_CACHE_ENTRIES <= 10_000);
    }

    /* ========================================================================== */
    /*                    ProofDirection: additional coverage                     */
    /* ========================================================================== */

    #[test]
    fn test_proof_direction_deserialize_invalid_string() {
        let result: Result<ProofDirection, _> = serde_json::from_str("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_direction_deserialize_empty_string() {
        let result: Result<ProofDirection, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_direction_deserialize_camel_case_rejected() {
        // snake_case is required by serde rename_all
        let result: Result<ProofDirection, _> = serde_json::from_str("\"overAge\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_direction_copy_semantics() {
        let a = ProofDirection::OverAge;
        let b = a; // Copy
        assert_eq!(a, b); // a still usable after copy
    }

    #[test]
    fn test_proof_direction_clone_eq() {
        let a = ProofDirection::UnderAge;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_proof_direction_ne() {
        assert_ne!(ProofDirection::OverAge, ProofDirection::UnderAge);
    }

    #[test]
    fn test_proof_direction_debug() {
        let dbg = format!("{:?}", ProofDirection::OverAge);
        assert_eq!(dbg, "OverAge");
        let dbg2 = format!("{:?}", ProofDirection::UnderAge);
        assert_eq!(dbg2, "UnderAge");
    }

    /* ========================================================================== */
    /*                    age_threshold: error message checks                     */
    /* ========================================================================== */

    #[test]
    fn test_age_threshold_over_age_151_error_message() {
        let policy = OriginPolicy {
            min_age_years: 151,
            ..OriginPolicy::default()
        };
        let err = policy.age_threshold().unwrap_err();
        assert_eq!(err, "min_age_years exceeds maximum of 150");
    }

    #[test]
    fn test_age_threshold_under_age_151_error_message() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(151),
            ..OriginPolicy::default()
        };
        let err = policy.age_threshold().unwrap_err();
        assert_eq!(err, "max_age_years exceeds maximum of 150");
    }

    #[test]
    fn test_age_threshold_under_age_missing_max_error_message() {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: None,
            ..OriginPolicy::default()
        };
        let err = policy.age_threshold().unwrap_err();
        assert_eq!(err, "Origin policy does not allow under-age verification");
    }

    /* ========================================================================== */
    /*                    OriginPolicy: deserialise error paths                   */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_deserialize_missing_tenant_id() {
        let json = r#"{
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_policy_deserialize_missing_billing() {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_policy_deserialize_missing_enabled() {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_policy_deserialize_wrong_type_min_age() {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": "not_a_number",
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_policy_deserialize_invalid_json() {
        let json = "not json at all";
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_policy_deserialize_empty_object() {
        let json = "{}";
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_policy_deserialize_negative_min_age() {
        // JSON has no unsigned integers; serde should reject negative for u32
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": -1,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    OriginPolicy: full roundtrip coverage                   */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_full_roundtrip_all_fields() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            tenant_id: "t_roundtrip".to_string(),
            min_age_years: 21,
            max_age_years: Some(65),
            proof_direction: Some(ProofDirection::UnderAge),
            allowed_vk_ids: vec![1, 2, 3, 4],
            allowed_issuers: vec!["issuer_a".to_string(), "issuer_b".to_string()],
            max_ttl_sec: 600,
            billing: BillingConfig {
                plan: "enterprise".to_string(),
                metering_enabled: true,
            },
            enabled: true,
            created_at: 1000,
            updated_at: 2000,
            clients: vec![
                ClientAuthConfig {
                    client_id: "c1".to_string(),
                    api_key_hash: "hash1".to_string(),
                    api_key_prefix: Some("pk_live_".to_string()),
                    encrypted_hmac_secret: "enc1".to_string(),
                    dek_encrypted: "dek1".to_string(),
                    encryption_version: 2,
                    active: true,
                },
                ClientAuthConfig {
                    client_id: "c2".to_string(),
                    api_key_hash: "hash2".to_string(),
                    api_key_prefix: None,
                    encrypted_hmac_secret: "enc2".to_string(),
                    dek_encrypted: "dek2".to_string(),
                    encryption_version: 1,
                    active: false,
                },
            ],
            provisioned_by: Some("partner_test".to_string()),
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&policy)?;
        let decoded: OriginPolicy = serde_json::from_str(&json)?;

        assert_eq!(decoded.tenant_id, "t_roundtrip");
        assert_eq!(decoded.min_age_years, 21);
        assert_eq!(decoded.max_age_years, Some(65));
        assert_eq!(decoded.proof_direction, Some(ProofDirection::UnderAge));
        assert_eq!(decoded.allowed_vk_ids, vec![1, 2, 3, 4]);
        assert_eq!(decoded.allowed_issuers.len(), 2);
        assert_eq!(decoded.allowed_issuers[0], "issuer_a");
        assert_eq!(decoded.allowed_issuers[1], "issuer_b");
        assert_eq!(decoded.max_ttl_sec, 600);
        assert_eq!(decoded.billing.plan, "enterprise");
        assert!(decoded.billing.metering_enabled);
        assert!(decoded.enabled);
        assert_eq!(decoded.created_at, 1000);
        assert_eq!(decoded.updated_at, 2000);
        assert_eq!(decoded.clients.len(), 2);
        assert_eq!(decoded.clients[0].client_id, "c1");
        assert!(decoded.clients[0].active);
        assert_eq!(decoded.clients[1].client_id, "c2");
        assert!(!decoded.clients[1].active);
        assert_eq!(decoded.provisioned_by, Some("partner_test".to_string()));
        Ok(())
    }

    #[test]
    fn test_origin_policy_roundtrip_none_optional_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = OriginPolicy {
            tenant_id: "t_none".to_string(),
            min_age_years: 18,
            max_age_years: None,
            proof_direction: None,
            allowed_vk_ids: vec![],
            allowed_issuers: vec![],
            max_ttl_sec: 300,
            billing: BillingConfig {
                plan: "free".to_string(),
                metering_enabled: false,
            },
            enabled: false,
            created_at: 0,
            updated_at: 0,
            clients: vec![],
            provisioned_by: None,
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&policy)?;
        let decoded: OriginPolicy = serde_json::from_str(&json)?;

        assert!(decoded.max_age_years.is_none());
        assert!(decoded.proof_direction.is_none());
        assert!(decoded.allowed_vk_ids.is_empty());
        assert!(decoded.allowed_issuers.is_empty());
        assert!(decoded.clients.is_empty());
        assert!(decoded.provisioned_by.is_none());
        assert_eq!(decoded.created_at, 0);
        assert_eq!(decoded.updated_at, 0);
        assert!(!decoded.enabled);
        Ok(())
    }

    /* ========================================================================== */
    /*                    OriginPolicy: clone deep equality                       */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_clone_preserves_all_fields() {
        let policy = OriginPolicy {
            tenant_id: "clone_test".to_string(),
            min_age_years: 25,
            max_age_years: Some(30),
            proof_direction: Some(ProofDirection::UnderAge),
            allowed_vk_ids: vec![1, 5, 9],
            allowed_issuers: vec!["iss1".to_string()],
            max_ttl_sec: 999,
            billing: BillingConfig {
                plan: "pro".to_string(),
                metering_enabled: true,
            },
            enabled: true,
            created_at: 500,
            updated_at: 600,
            clients: vec![ClientAuthConfig {
                client_id: "cc".to_string(),
                api_key_hash: "h".to_string(),
                api_key_prefix: Some("pk_test_".to_string()),
                encrypted_hmac_secret: "es".to_string(),
                dek_encrypted: "ed".to_string(),
                encryption_version: 3,
                active: true,
            }],
            provisioned_by: Some("partner_x".to_string()),
            failure_mode: None,
            failure_mode_locked: false,
        };
        let cloned = policy.clone();

        assert_eq!(cloned.tenant_id, policy.tenant_id);
        assert_eq!(cloned.min_age_years, policy.min_age_years);
        assert_eq!(cloned.max_age_years, policy.max_age_years);
        assert_eq!(cloned.proof_direction, policy.proof_direction);
        assert_eq!(cloned.allowed_vk_ids, policy.allowed_vk_ids);
        assert_eq!(cloned.allowed_issuers, policy.allowed_issuers);
        assert_eq!(cloned.max_ttl_sec, policy.max_ttl_sec);
        assert_eq!(cloned.billing.plan, policy.billing.plan);
        assert_eq!(
            cloned.billing.metering_enabled,
            policy.billing.metering_enabled
        );
        assert_eq!(cloned.enabled, policy.enabled);
        assert_eq!(cloned.created_at, policy.created_at);
        assert_eq!(cloned.updated_at, policy.updated_at);
        assert_eq!(cloned.clients.len(), policy.clients.len());
        assert_eq!(cloned.clients[0].client_id, policy.clients[0].client_id);
        assert_eq!(
            cloned.clients[0].encryption_version,
            policy.clients[0].encryption_version
        );
        assert_eq!(cloned.provisioned_by, policy.provisioned_by);
    }

    /* ========================================================================== */
    /*                    OriginPolicy: edge case values                          */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_max_ttl_sec_u64_max() -> Result<(), Box<dyn std::error::Error>> {
        let json = format!(
            r#"{{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [],
            "allowed_issuers": [],
            "max_ttl_sec": {},
            "billing": {{"plan": "free", "metering_enabled": false}},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }}"#,
            u64::MAX
        );
        let policy: OriginPolicy = serde_json::from_str(&json)?;
        assert_eq!(policy.max_ttl_sec, u64::MAX);
        Ok(())
    }

    #[test]
    fn test_origin_policy_empty_vk_ids_and_issuers() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert!(policy.allowed_vk_ids.is_empty());
        assert!(policy.allowed_issuers.is_empty());
        Ok(())
    }

    #[test]
    fn test_origin_policy_many_vk_ids() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "allowed_issuers": ["a", "b", "c", "d"],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.allowed_vk_ids.len(), 10);
        assert_eq!(policy.allowed_issuers.len(), 4);
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize_multiple_unknown_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Multiple unknown fields should all be silently ignored
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": [],
            "rate_limits": {"x": 1},
            "deprecated_field": "value",
            "another_unknown": 42,
            "nested_unknown": {"a": {"b": "c"}}
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.tenant_id, "t1");
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize_with_over_age_proof_direction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 21,
            "proof_direction": "over_age",
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.proof_direction, Some(ProofDirection::OverAge));
        assert_eq!(policy.effective_proof_direction(), ProofDirection::OverAge);
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 21);
        Ok(())
    }

    #[test]
    fn test_origin_policy_deserialize_invalid_proof_direction() {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "proof_direction": "sideways",
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": []
        }"#;
        let result: Result<OriginPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    /* ========================================================================== */
    /*                    OriginPolicy: age boundary interactions                 */
    /* ========================================================================== */

    #[test]
    fn test_age_threshold_over_age_exactly_1() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            min_age_years: 1,
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 1);
        Ok(())
    }

    #[test]
    fn test_age_threshold_under_age_exactly_1() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(1),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 1);
        Ok(())
    }

    #[test]
    fn test_age_threshold_over_age_149() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            min_age_years: 149,
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 149);
        Ok(())
    }

    #[test]
    fn test_age_threshold_under_age_149() -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::UnderAge),
            max_age_years: Some(149),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 149);
        Ok(())
    }

    #[test]
    fn test_age_threshold_inferred_under_age_returns_max_age(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // No explicit proof_direction, max_age_years set -> inferred UnderAge
        let policy = OriginPolicy {
            min_age_years: 18,
            max_age_years: Some(13),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.effective_proof_direction(), ProofDirection::UnderAge);
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 13);
        Ok(())
    }

    #[test]
    fn test_age_threshold_explicit_over_with_max_age_uses_min_age(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Explicit OverAge with max_age_years present: should use min_age_years
        let policy = OriginPolicy {
            proof_direction: Some(ProofDirection::OverAge),
            min_age_years: 21,
            max_age_years: Some(65),
            ..OriginPolicy::default()
        };
        assert_eq!(policy.age_threshold().map_err(|e| e.to_string())?, 21);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ClientAuthConfig: additional coverage                   */
    /* ========================================================================== */

    #[test]
    fn test_client_auth_config_full_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let config = ClientAuthConfig {
            client_id: "roundtrip_client".to_string(),
            api_key_hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash".to_string(),
            api_key_prefix: Some("pk_test_".to_string()),
            encrypted_hmac_secret: "base64url_encrypted_secret".to_string(),
            dek_encrypted: "base64url_encrypted_dek".to_string(),
            encryption_version: 5,
            active: false,
        };
        let json = serde_json::to_string(&config)?;
        let decoded: ClientAuthConfig = serde_json::from_str(&json)?;

        assert_eq!(decoded.client_id, "roundtrip_client");
        assert_eq!(
            decoded.api_key_hash,
            "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"
        );
        assert_eq!(decoded.api_key_prefix, Some("pk_test_".to_string()));
        assert_eq!(decoded.encrypted_hmac_secret, "base64url_encrypted_secret");
        assert_eq!(decoded.dek_encrypted, "base64url_encrypted_dek");
        assert_eq!(decoded.encryption_version, 5);
        assert!(!decoded.active);
        Ok(())
    }

    #[test]
    fn test_client_auth_config_explicit_null_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "api_key_prefix": null,
            "encrypted_hmac_secret": "encrypted_secret",
            "dek_encrypted": "encrypted_dek"
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert!(config.api_key_prefix.is_none());
        Ok(())
    }

    #[test]
    fn test_client_auth_config_encryption_version_zero() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "enc",
            "dek_encrypted": "dek",
            "encryption_version": 0
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert_eq!(config.encryption_version, 0);
        Ok(())
    }

    #[test]
    fn test_client_auth_config_encryption_version_255() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "enc",
            "dek_encrypted": "dek",
            "encryption_version": 255
        }"#;
        let config: ClientAuthConfig = serde_json::from_str(json)?;
        assert_eq!(config.encryption_version, 255);
        Ok(())
    }

    #[test]
    fn test_client_auth_config_encryption_version_overflow() {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "enc",
            "dek_encrypted": "dek",
            "encryption_version": 256
        }"#;
        let result: Result<ClientAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_auth_config_debug_includes_metadata() {
        let config = ClientAuthConfig {
            client_id: "debug_test".to_string(),
            api_key_hash: "irrelevant".to_string(),
            api_key_prefix: None,
            encrypted_hmac_secret: "irrelevant".to_string(),
            dek_encrypted: "irrelevant".to_string(),
            encryption_version: 7,
            active: false,
        };
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("debug_test"));
        assert!(dbg.contains("7")); // encryption_version
        assert!(dbg.contains("false")); // active
        assert!(!dbg.contains("irrelevant")); // secrets redacted
    }

    #[test]
    fn test_client_auth_config_debug_prefix_none_shown() {
        let config = ClientAuthConfig {
            client_id: "c".to_string(),
            api_key_hash: "h".to_string(),
            api_key_prefix: None,
            encrypted_hmac_secret: "e".to_string(),
            dek_encrypted: "d".to_string(),
            encryption_version: 1,
            active: true,
        };
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("None")); // api_key_prefix: None
    }

    #[test]
    fn test_client_auth_config_missing_required_field() {
        // client_id is required
        let json = r#"{
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "enc",
            "dek_encrypted": "dek"
        }"#;
        let result: Result<ClientAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_auth_config_missing_api_key_hash() {
        let json = r#"{
            "client_id": "test",
            "encrypted_hmac_secret": "enc",
            "dek_encrypted": "dek"
        }"#;
        let result: Result<ClientAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_auth_config_missing_encrypted_hmac_secret() {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "dek_encrypted": "dek"
        }"#;
        let result: Result<ClientAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_auth_config_missing_dek_encrypted() {
        let json = r#"{
            "client_id": "test",
            "api_key_hash": "hash",
            "encrypted_hmac_secret": "enc"
        }"#;
        let result: Result<ClientAuthConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_auth_config_clone() {
        let config = ClientAuthConfig {
            client_id: "clone_me".to_string(),
            api_key_hash: "h".to_string(),
            api_key_prefix: Some("pk_live_".to_string()),
            encrypted_hmac_secret: "e".to_string(),
            dek_encrypted: "d".to_string(),
            encryption_version: 2,
            active: true,
        };
        let cloned = config.clone();
        assert_eq!(cloned.client_id, "clone_me");
        assert_eq!(cloned.api_key_hash, "h");
        assert_eq!(cloned.api_key_prefix, Some("pk_live_".to_string()));
        assert_eq!(cloned.encrypted_hmac_secret, "e");
        assert_eq!(cloned.dek_encrypted, "d");
        assert_eq!(cloned.encryption_version, 2);
        assert!(cloned.active);
    }

    /* ========================================================================== */
    /*                    BillingConfig: additional coverage                      */
    /* ========================================================================== */

    #[test]
    fn test_billing_config_full_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let config = BillingConfig {
            plan: "enterprise".to_string(),
            metering_enabled: true,
        };
        let json = serde_json::to_string(&config)?;
        let decoded: BillingConfig = serde_json::from_str(&json)?;
        assert_eq!(decoded.plan, "enterprise");
        assert!(decoded.metering_enabled);
        Ok(())
    }

    #[test]
    fn test_billing_config_clone() {
        let config = BillingConfig {
            plan: "pro".to_string(),
            metering_enabled: true,
        };
        let cloned = config.clone();
        assert_eq!(cloned.plan, "pro");
        assert!(cloned.metering_enabled);
    }

    #[test]
    fn test_billing_config_debug() {
        let config = BillingConfig {
            plan: "free".to_string(),
            metering_enabled: false,
        };
        let dbg = format!("{:?}", config);
        assert!(dbg.contains("free"));
        assert!(dbg.contains("false"));
    }

    #[test]
    fn test_billing_config_missing_plan() {
        let json = r#"{"metering_enabled": true}"#;
        let result: Result<BillingConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_billing_config_missing_metering() {
        let json = r#"{"plan": "free"}"#;
        let result: Result<BillingConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_billing_config_empty_plan() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"plan": "", "metering_enabled": false}"#;
        let config: BillingConfig = serde_json::from_str(json)?;
        assert_eq!(config.plan, "");
        Ok(())
    }

    #[test]
    fn test_billing_config_ignores_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "plan": "pro",
            "metering_enabled": true,
            "some_future_field": "value"
        }"#;
        let config: BillingConfig = serde_json::from_str(json)?;
        assert_eq!(config.plan, "pro");
        assert!(config.metering_enabled);
        Ok(())
    }

    /* ========================================================================== */
    /*                    PolicyLookupResult: additional coverage                 */
    /* ========================================================================== */

    #[test]
    fn test_policy_lookup_result_found_debug() {
        let policy = OriginPolicy::default();
        let r = PolicyLookupResult::Found(policy);
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("Found"));
        assert!(dbg.contains("min_age_years"));
    }

    #[test]
    fn test_policy_lookup_result_all_variants_debug() {
        let variants: Vec<String> = vec![
            format!("{:?}", PolicyLookupResult::Disabled),
            format!("{:?}", PolicyLookupResult::NotFound),
        ];
        assert!(variants[0].contains("Disabled"));
        assert!(variants[1].contains("NotFound"));
    }

    /* ========================================================================== */
    /*                    OriginPolicy: multiple clients coverage                 */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_multiple_clients_mixed_active() -> Result<(), Box<dyn std::error::Error>>
    {
        let json = r#"{
            "tenant_id": "t1",
            "min_age_years": 18,
            "allowed_vk_ids": [1],
            "allowed_issuers": [],
            "max_ttl_sec": 300,
            "billing": {"plan": "free", "metering_enabled": false},
            "enabled": true,
            "created_at": 100,
            "updated_at": 200,
            "clients": [
                {
                    "client_id": "c1",
                    "api_key_hash": "h1",
                    "api_key_prefix": "pk_live_",
                    "encrypted_hmac_secret": "e1",
                    "dek_encrypted": "d1",
                    "active": true
                },
                {
                    "client_id": "c2",
                    "api_key_hash": "h2",
                    "encrypted_hmac_secret": "e2",
                    "dek_encrypted": "d2",
                    "active": false
                },
                {
                    "client_id": "c3",
                    "api_key_hash": "h3",
                    "api_key_prefix": "pk_test_",
                    "encrypted_hmac_secret": "e3",
                    "dek_encrypted": "d3",
                    "active": true
                },
                {
                    "client_id": "c4",
                    "api_key_hash": "h4",
                    "encrypted_hmac_secret": "e4",
                    "dek_encrypted": "d4"
                }
            ]
        }"#;
        let policy: OriginPolicy = serde_json::from_str(json)?;
        assert_eq!(policy.clients.len(), 4);
        assert!(policy.clients[0].active);
        assert!(!policy.clients[1].active);
        assert!(policy.clients[2].active);
        assert!(policy.clients[3].active); // defaults to true
        assert!(policy.clients[1].api_key_prefix.is_none());
        assert_eq!(
            policy.clients[0].api_key_prefix,
            Some("pk_live_".to_string())
        );
        assert_eq!(
            policy.clients[2].api_key_prefix,
            Some("pk_test_".to_string())
        );
        assert!(policy.clients[3].api_key_prefix.is_none());
        Ok(())
    }

    /* ========================================================================== */
    /*                    OriginPolicy: Debug output                              */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_debug_output() {
        let policy = OriginPolicy {
            tenant_id: "debug_tenant".to_string(),
            clients: vec![ClientAuthConfig {
                client_id: "c_dbg".to_string(),
                api_key_hash: "secret_hash_value".to_string(),
                api_key_prefix: None,
                encrypted_hmac_secret: "secret_enc".to_string(),
                dek_encrypted: "secret_dek".to_string(),
                encryption_version: 1,
                active: true,
            }],
            ..OriginPolicy::default()
        };
        let dbg = format!("{:?}", policy);
        // OriginPolicy itself derives Debug, so tenant_id is visible
        assert!(dbg.contains("debug_tenant"));
        // ClientAuthConfig's custom Debug should redact secrets
        assert!(dbg.contains("[REDACTED]"));
        assert!(dbg.contains("[ENCRYPTED]"));
        assert!(!dbg.contains("secret_hash_value"));
        assert!(!dbg.contains("secret_enc"));
        assert!(!dbg.contains("secret_dek"));
    }

    /* ========================================================================== */
    /*                    OriginPolicy: serialise field presence                  */
    /* ========================================================================== */

    #[test]
    fn test_origin_policy_serialize_contains_all_expected_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let policy = OriginPolicy {
            tenant_id: "field_check".to_string(),
            min_age_years: 16,
            max_age_years: Some(21),
            proof_direction: Some(ProofDirection::OverAge),
            allowed_vk_ids: vec![1],
            allowed_issuers: vec!["iss".to_string()],
            max_ttl_sec: 120,
            billing: BillingConfig {
                plan: "pro".to_string(),
                metering_enabled: true,
            },
            enabled: true,
            created_at: 1,
            updated_at: 2,
            clients: vec![],
            provisioned_by: Some("test".to_string()),
            failure_mode: None,
            failure_mode_locked: false,
        };
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains("\"tenant_id\""));
        assert!(json.contains("\"min_age_years\""));
        assert!(json.contains("\"max_age_years\""));
        assert!(json.contains("\"proof_direction\""));
        assert!(json.contains("\"allowed_vk_ids\""));
        assert!(json.contains("\"allowed_issuers\""));
        assert!(json.contains("\"max_ttl_sec\""));
        assert!(json.contains("\"billing\""));
        assert!(json.contains("\"enabled\""));
        assert!(json.contains("\"created_at\""));
        assert!(json.contains("\"updated_at\""));
        assert!(json.contains("\"clients\""));
        assert!(json.contains("\"provisioned_by\""));
        Ok(())
    }

    #[test]
    fn test_origin_policy_serialize_none_optional_fields_present(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // When max_age_years is None, serde still serialises it as null
        let policy = OriginPolicy::default();
        let json = serde_json::to_string(&policy)?;
        assert!(json.contains("\"max_age_years\":null"));
        assert!(json.contains("\"proof_direction\":null"));
        assert!(json.contains("\"provisioned_by\":null"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    policy_key: additional patterns                         */
    /* ========================================================================== */

    #[test]
    fn test_policy_key_unicode_origin() {
        let key = OriginPolicyStore::policy_key("https://\u{00E9}xample.com");
        assert_eq!(key, "origins/https://\u{00E9}xample.com");
    }

    #[test]
    fn test_policy_key_very_long_origin() {
        let long_origin = "a".repeat(2048);
        let key = OriginPolicyStore::policy_key(&long_origin);
        assert!(key.starts_with("origins/"));
        assert_eq!(key.len(), 8 + 2048); // "origins/" = 8 chars
    }

    #[test]
    fn test_policy_key_with_subdomain() {
        let key = OriginPolicyStore::policy_key("https://sub.domain.example.com");
        assert_eq!(key, "origins/https://sub.domain.example.com");
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: OriginPolicy serialisation roundtrip
        #[test]
        fn prop_origin_policy_roundtrip(
            tenant_id in ".*",
            min_age_years in 1u32..150,
            enabled in any::<bool>()
        ) {
            let mut policy = OriginPolicy::default();
            policy.tenant_id = tenant_id.clone();
            policy.min_age_years = min_age_years;
            policy.enabled = enabled;

            let json = serde_json::to_string(&policy)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded: OriginPolicy = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            prop_assert_eq!(decoded.tenant_id, tenant_id);
            prop_assert_eq!(decoded.min_age_years, min_age_years);
            prop_assert_eq!(decoded.enabled, enabled);
        }

        /// Property: policy_key() always starts with "origins/"
        #[test]
        fn prop_policy_key_prefix(origin in ".*") {
            let key = OriginPolicyStore::policy_key(&origin);
            prop_assert!(key.starts_with("origins/"));
        }

        /// Property: policy_key() preserves origin exactly
        #[test]
        fn prop_policy_key_preserves_origin(origin in "[a-z]{3,10}\\.com") {
            let key = OriginPolicyStore::policy_key(&origin);
            prop_assert_eq!(key, format!("origins/{}", origin));
        }

        /// Property: BillingConfig roundtrip
        #[test]
        fn prop_billing_roundtrip(
            plan in ".*",
            metering in any::<bool>()
        ) {
            let config = BillingConfig {
                plan: plan.clone(),
                metering_enabled: metering,
            };
            let json = serde_json::to_string(&config)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded: BillingConfig = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(decoded.plan, plan);
            prop_assert_eq!(decoded.metering_enabled, metering);
        }

        /// Property: ClientAuthConfig with default active=true
        #[test]
        fn prop_client_auth_default_active(
            client_id in "[a-z0-9]{3,20}",
            hash in "[a-f0-9]{64}",
            secret in "[a-zA-Z0-9]{20,50}"
        ) {
            let config = ClientAuthConfig {
                client_id,
                api_key_hash: hash,
                api_key_prefix: None,
                encrypted_hmac_secret: secret,
                dek_encrypted: "test_encrypted_dek".to_string(),
                encryption_version: 1,
                active: true, // Explicitly true
            };
            let json = serde_json::to_string(&config)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded: ClientAuthConfig = serde_json::from_str(&json)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(decoded.active);
        }
    }
}
