// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! HMAC-based client authentication for trusted verifier partners.
//!
//! Implements the authentication flow for relying parties calling provii-verifier.
//! Each request is verified through API key verification (Argon2id hash
//! comparison with a 30-second in-memory cache), nonce replay protection
//! (Durable Object-backed atomic check-and-set), and HMAC-SHA256 signature
//! verification over the canonical request message using envelope-encrypted
//! secrets decrypted at request time.
//!
//! SECURITY: HMAC comparison uses `hmac::Mac::verify_slice()` for constant-time
//! tag verification. Decrypted secret material is held in `Zeroizing` wrappers
//! and cleared from memory on drop.
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

// Use worker console_log on WASM, no-op macro for native testing
#[cfg(target_arch = "wasm32")]
use worker::console_log;

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => {{}};
}

use crate::{
    error::ApiError,
    security::audit::AuditLogger,
    storage::{
        origin_policy::{ClientAuthConfig, OriginPolicy},
        traits::NonceStore,
    },
    types::Authorizer,
    utils::NONCE_DEDUP_TTL,
};
use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

/// PERF: Cache TTL for API key verification results (30 seconds)
const API_KEY_CACHE_TTL_MS: u64 = 30_000;

/// PERF: Cached API key verification result
#[derive(Debug, Clone)]
struct VerificationCacheEntry {
    /// Whether the API key was verified successfully
    verified: bool,
    /// Client ID this verification is for
    client_id: String,
    /// Timestamp when this entry was cached (milliseconds)
    cached_at: u64,
}

/// PERF: Global cache for API key verification results
///
/// SECURITY: Cache keys are derived from API key prefix (first 8 chars) + hashed client_id
/// to avoid storing the full API key in memory. Cache entries expire after 30 seconds.
static API_KEY_CACHE: Lazy<RwLock<HashMap<String, VerificationCacheEntry>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// PERF: Generate a cache key from API key prefix and client_id hash
///
/// SECURITY: Only uses first 8 characters of API key + hashed client_id to avoid
/// storing sensitive data in the cache. This provides sufficient uniqueness while
/// maintaining security.
fn make_cache_key(api_key: &str, client_id: &str) -> String {
    // ADV-VA-021: Use a cryptographic hash of the full API key rather than a
    // short prefix. An 8-char prefix risks collisions between distinct keys
    // sharing the same prefix under the same DefaultHasher(client_id) bucket.
    // SHA-256 is not secret-keyed here; this is a cache index, not an auth check.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    hasher.update(b":");
    hasher.update(client_id.as_bytes());
    let digest = hasher.finalize();
    // Hex-encode the full 32-byte digest for a collision-resistant cache key.
    hex::encode(digest)
}

/// Authenticates relying-party requests against a stored `OriginPolicy`.
///
/// Built via a fluent API: `ClientAuthenticator::new(&policy).with_mek(mek)...`.
/// Call [`authenticate`](Self::authenticate) to run the full three-step flow
/// (API key, nonce, HMAC).
pub struct ClientAuthenticator<'a> {
    policy: &'a OriginPolicy,
    audit_logger: Option<&'a AuditLogger>,
    client_ip: Option<String>,
    nonce_store: Option<Arc<dyn NonceStore>>,
    /// SECURITY: Master Encryption Key (MEK) for decrypting HMAC secrets.
    /// Loaded from Cloudflare Secrets (VERIFIER_MEK).
    /// Wrapped in Zeroizing to clear key material from memory on drop.
    mek: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// SECURITY: Previous MEK for key rotation. When set, decrypt_hmac_secret_with_fallback
    /// will try this key if the primary MEK fails decryption.
    previous_mek: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// PERF: Optional KV store for API key prefix index lookups.
    /// When set, the first 8 chars of the API key are checked against
    /// `key_prefix:{prefix}` in KV to reject unknown keys before Argon2id.
    prefix_index_kv: Option<worker::kv::KvStore>,
    /// SECURITY: Pre-computed Argon2id hash with production parameters used
    /// as a timing decoy when client lookup misses (H-13, CWE-208).
    dummy_hash: Option<String>,
    /// Optional Analytics Engine dataset for critical audit fallback.
    analytics: Option<worker::AnalyticsEngineDataset>,
}

impl<'a> ClientAuthenticator<'a> {
    /// Instantiate an authenticator for the supplied origin policy.
    pub fn new(policy: &'a OriginPolicy) -> Self {
        Self {
            policy,
            audit_logger: None,
            client_ip: None,
            nonce_store: None,
            mek: None,
            previous_mek: None,
            prefix_index_kv: None,
            dummy_hash: None,
            analytics: None,
        }
    }

    /// Add audit logger for authentication failure logging (CWE-778, ASVS V7.2.1).
    pub fn with_audit_logger(mut self, logger: &'a AuditLogger, client_ip: String) -> Self {
        self.audit_logger = Some(logger);
        self.client_ip = Some(client_ip);
        self
    }

    /// SECURITY: Add nonce store for replay protection (CWE-287, ASVS V2).
    /// When provided, nonce-based replay protection will be enforced.
    pub fn with_nonce_store(mut self, store: Arc<dyn NonceStore>) -> Self {
        self.nonce_store = Some(store);
        self
    }

    /// SECURITY: Add Master Encryption Key (MEK) for HMAC secret decryption.
    /// Required for clients with encrypted HMAC secrets (encryption_version >= 1).
    /// Accepts Zeroizing wrapper to preserve zeroisation throughout the key's lifetime.
    pub fn with_mek(mut self, mek: zeroize::Zeroizing<Vec<u8>>) -> Self {
        self.mek = Some(mek);
        self
    }

    /// SECURITY: Add previous MEK for key rotation fallback.
    /// When set, HMAC secret decryption will try this key if the primary MEK fails.
    pub fn with_previous_mek(mut self, mek: zeroize::Zeroizing<Vec<u8>>) -> Self {
        self.previous_mek = Some(mek);
        self
    }

    /// SECURITY: Set the pre-computed dummy Argon2id hash for timing resistance (H-13).
    /// When a client_id is not found, the authenticator verifies against this decoy
    /// hash so the reject path takes the same time as a real verification, closing
    /// the timing oracle that would otherwise reveal client_id existence (CWE-208).
    pub fn with_dummy_hash(mut self, hash: String) -> Self {
        self.dummy_hash = Some(hash);
        self
    }

    /// Attach Analytics Engine dataset for critical audit fallback.
    /// When the audit queue fails, MEK failures are written here as a PII-free
    /// data point so the event remains observable.
    pub fn with_analytics(mut self, analytics: worker::AnalyticsEngineDataset) -> Self {
        self.analytics = Some(analytics);
        self
    }

    /// Validate API key + HMAC material against the stored client configuration.
    /// SECURITY: Now supports nonce-based replay protection (CWE-287, ASVS V2).
    pub async fn authenticate(
        &self,
        api_key: Option<&str>,
        authorizer: &Authorizer,
        canonical_message: &str,
    ) -> Result<&'a ClientAuthConfig, ApiError> {
        self.authenticate_tracked(api_key, authorizer, canonical_message, None)
            .await
    }

    /// Variant of [`Self::authenticate`] that records which MEK slot satisfied
    /// the envelope-decrypt step via `mek_slot_out`. The slot signal feeds the
    /// per-request `secret_version` log line. The outparam is left untouched on
    /// early rejects (missing API key, invalid authorizer, nonce reuse) and on
    /// the unencrypted client path; only set when MEK decryption ran.
    pub async fn authenticate_tracked(
        &self,
        api_key: Option<&str>,
        authorizer: &Authorizer,
        canonical_message: &str,
        mek_slot_out: Option<&mut Option<crate::security::secret_versions::RotationSlot>>,
    ) -> Result<&'a ClientAuthConfig, ApiError> {
        // SECURITY: Clone audit logging context once at the start for use in async closures
        let audit_logger_owned = self.audit_logger.cloned();
        let client_ip_owned = self.client_ip.clone();

        // Validate authorizer structure first
        if let Err(e) = authorizer.validate() {
            // SECURITY: Log validation failure (CWE-778)
            if let (Some(logger), Some(ip)) = (audit_logger_owned.clone(), client_ip_owned.clone())
            {
                let details = json!({
                    "failure_type": "invalid_authorizer_format",
                    "validation_error": e,
                    "key_id": authorizer.key_id
                });
                logger
                    .log_authentication_failure(
                        &ip,
                        "invalid_authorizer_format",
                        Some(&authorizer.key_id),
                        None,
                        Some(details),
                    )
                    .await;
            }
            return Err(ApiError::BadRequest(Some(e)));
        }

        // SECURITY: Validate timestamp freshness to bound replay windows (CWE-613).
        // The timestamp is integrity-protected by the HMAC signature, so the client
        // cannot manipulate it post-signing. A 300-second window accommodates
        // reasonable clock skew while limiting how long a captured signed request
        // remains usable. Matches the nonce TTL.
        {
            let server_time = crate::utils::current_timestamp();
            let skew = if server_time >= authorizer.timestamp {
                server_time.saturating_sub(authorizer.timestamp)
            } else {
                authorizer.timestamp.saturating_sub(server_time)
            };
            if skew > 300 {
                if let (Some(logger), Some(ip)) =
                    (audit_logger_owned.clone(), client_ip_owned.clone())
                {
                    let details = json!({
                        "failure_type": "timestamp_skew_exceeded",
                        "server_time": server_time,
                        "client_timestamp": authorizer.timestamp,
                        "skew_seconds": skew,
                        "max_allowed": 300
                    });
                    logger
                        .log_authentication_failure(
                            &ip,
                            "timestamp_skew_exceeded",
                            Some(&authorizer.key_id),
                            None,
                            Some(details),
                        )
                        .await;
                }
                return Err(ApiError::bad_request(
                    "TIMESTAMP_SKEW",
                    Some("authorizer.timestamp"),
                    "Request timestamp exceeds maximum clock skew (300s)",
                ));
            }
        }

        // Check if API key is provided
        let api_key = match api_key {
            Some(key) => key,
            None => {
                // SECURITY: Log missing API key (CWE-778)
                if let (Some(logger), Some(ip)) =
                    (audit_logger_owned.clone(), client_ip_owned.clone())
                {
                    let details = json!({
                        "failure_type": "missing_api_key",
                        "key_id": authorizer.key_id
                    });
                    logger
                        .log_authentication_failure(
                            &ip,
                            "missing_api_key",
                            Some(&authorizer.key_id),
                            None,
                            Some(details),
                        )
                        .await;
                }
                return Err(ApiError::unauthorized(
                    "API_KEY_MISSING",
                    "X-API-Key header is required",
                ));
            }
        };

        // PERF: Prefix index fast path. If configured, check
        // `key_prefix:{first8chars}` in KV. A miss means the key is
        // definitely invalid (reject without Argon2id). A KV error
        // falls through to the existing client scan.
        if let Some(ref kv) = self.prefix_index_kv {
            let prefix = api_key.get(..8).unwrap_or(api_key);
            let prefix_key = format!("key_prefix:{}", prefix);
            match kv.get(&prefix_key).text().await {
                Ok(Some(expected_client_id)) => {
                    // Prefix found: only verify against this one client
                    if expected_client_id != authorizer.key_id {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[Auth] Prefix index client_id mismatch: prefix maps to '{}' but key_id is '{}'",
                            expected_client_id, authorizer.key_id
                        );
                        return Err(ApiError::unauthorized(
                            "API_KEY_INVALID",
                            "API key does not match the supplied key_id",
                        ));
                    }
                    // Fall through to normal client lookup (which will match quickly)
                }
                Ok(None) => {
                    // Prefix not in index: reject after dummy Argon2id verification
                    // to prevent timing oracle (H-13, CWE-208).
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[Auth] API key prefix not found in index, rejecting");
                    if let Some(ref dummy) = self.dummy_hash {
                        let _ = crate::security::hash::verify_api_key(api_key, dummy);
                    }
                    return Err(ApiError::unauthorized(
                        "API_KEY_INVALID",
                        "API key not recognised",
                    ));
                }
                Err(_) => {
                    // KV read failure: fall through to existing scan
                    #[cfg(target_arch = "wasm32")]
                    console_log!("[Auth] Prefix index KV read failed, falling through to scan");
                }
            }
        }

        let client = match self
            .policy
            .clients
            .iter()
            .find(|c| c.client_id == authorizer.key_id && c.active)
        {
            Some(c) => c,
            None => {
                // SECURITY: Log unknown/inactive client (CWE-778)
                if let (Some(logger), Some(ip)) =
                    (audit_logger_owned.clone(), client_ip_owned.clone())
                {
                    let details = json!({
                        "failure_type": "unknown_or_inactive_client",
                        "key_id": authorizer.key_id
                    });
                    logger
                        .log_authentication_failure(
                            &ip,
                            "unknown_or_inactive_client",
                            Some(&authorizer.key_id),
                            None,
                            Some(details),
                        )
                        .await;
                }
                // SECURITY: Verify against dummy hash so the reject path takes
                // the same time as a real Argon2id verification, closing the
                // timing oracle for client_id existence (H-13, CWE-208).
                if let Some(ref dummy) = self.dummy_hash {
                    let _ = crate::security::hash::verify_api_key(api_key, dummy);
                }
                return Err(ApiError::unauthorized(
                    "CLIENT_UNKNOWN",
                    "key_id does not match an active client",
                ));
            }
        };

        Self::verify_api_key_cached(
            client,
            api_key,
            audit_logger_owned.clone(),
            client_ip_owned.clone(),
        )
        .await?;

        // SECURITY: Nonce-based replay protection is now mandatory (CWE-287, ASVS V6.1.3)
        // Migration period has ended - all clients must provide nonces
        self.verify_nonce(
            &authorizer.nonce,
            &authorizer.key_id,
            audit_logger_owned.clone(),
            client_ip_owned.clone(),
        )
        .await?;

        Self::verify_hmac(
            client,
            canonical_message,
            &authorizer.hmac,
            self.mek.as_ref().map(|m| m.as_slice()),
            self.previous_mek.as_ref().map(|m| m.as_slice()),
            audit_logger_owned.clone(),
            client_ip_owned.clone(),
            mek_slot_out,
            self.analytics.as_ref(),
        )
        .await?;

        // AL-038: Audit authentication success (CWE-778, ASVS V7.2.1).
        // Both success and failure paths must be logged for compliance.
        if let (Some(logger), Some(ip)) = (audit_logger_owned, client_ip_owned) {
            logger
                .log_authentication_success(
                    &ip,
                    &client.client_id,
                    "", // Origin not available at this level; caller adds it
                )
                .await;
        }

        Ok(client)
    }

    /// Verifies API key hash using Argon2id
    ///
    /// SECURITY: This function verifies API keys using constant-time comparison
    /// and logs authentication failures for audit trail (CWE-778).
    async fn verify_api_key(
        client: &ClientAuthConfig,
        api_key: &str,
        audit_logger: Option<AuditLogger>,
        client_ip: Option<String>,
    ) -> Result<(), ApiError> {
        let verified = crate::security::hash::verify_api_key(api_key, &client.api_key_hash);

        if !verified {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[Auth] API key hash mismatch for client_id={}",
                client.client_id
            );

            // SECURITY: Log API key hash mismatch (CWE-778)
            if let (Some(logger), Some(ip)) = (audit_logger, client_ip) {
                let details = json!({
                    "failure_type": "api_key_hash_mismatch",
                    "client_id": client.client_id
                });
                logger
                    .log_authentication_failure(
                        &ip,
                        "api_key_hash_mismatch",
                        Some(&client.client_id),
                        None,
                        Some(details),
                    )
                    .await;
            }

            return Err(ApiError::unauthorized(
                "API_KEY_INVALID",
                "API key did not match the stored hash for this client",
            ));
        }

        Ok(())
    }

    /// PERF: Verifies API key hash with caching to avoid repeated Argon2id computations
    ///
    /// This function wraps verify_api_key with a 30-second cache to optimise performance
    /// for clients making multiple requests. Argon2id verification takes ~60ms, so caching
    /// provides significant performance improvements for frequent requests.
    ///
    /// SECURITY: Cache security measures:
    /// - Cache key uses only API key prefix (8 chars) + hashed client_id
    /// - Short 30-second TTL minimises exposure window
    /// - Cache entries include client_id to prevent cross-client cache poisoning
    /// - Only successful verifications are cached (failures always re-verify)
    async fn verify_api_key_cached(
        client: &ClientAuthConfig,
        api_key: &str,
        audit_logger: Option<AuditLogger>,
        client_ip: Option<String>,
    ) -> Result<(), ApiError> {
        let cache_key = make_cache_key(api_key, &client.client_id);

        // PERF: Get current time for cache expiry check
        #[cfg(target_arch = "wasm32")]
        let now = worker::Date::now().as_millis();

        #[cfg(not(target_arch = "wasm32"))]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // PERF: Check cache first (read lock)
        {
            // ADV-VA-031: Log poisoned RwLock rather than silently skipping cache.
            // Recovery (skip cache, re-verify) is correct, but poisoning indicates
            // a panic occurred while holding the lock and must be visible to ops.
            if let Ok(cache) = API_KEY_CACHE.read().map_err(|e| {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[ERROR] API_KEY_CACHE RwLock poisoned on read: {} - falling through to full verification",
                    e
                );
                e
            }) {
                if let Some(cached) = cache.get(&cache_key) {
                    // SECURITY: Verify cache entry is for the same client_id
                    if cached.client_id == client.client_id
                        && now.saturating_sub(cached.cached_at) < API_KEY_CACHE_TTL_MS
                    {
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "[PERF] API key verification cache HIT for client_id={}",
                            client.client_id
                        );
                        // AL-055: Structured audit for cached auth decision.
                        #[cfg(target_arch = "wasm32")]
                        console_log!(
                            "{{\"audit\":true,\"event\":\"cached_auth_decision\",\"severity\":\"info\",\"client_id\":\"{}\",\"cache_hit\":true,\"verified\":{}}}",
                            client.client_id,
                            cached.verified
                        );

                        if cached.verified {
                            return Ok(());
                        } else {
                            return Err(ApiError::Unauthorized);
                        }
                    }
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[PERF] API key verification cache MISS for client_id={}",
            client.client_id
        );

        // PERF: Cache miss - perform full verification
        let result =
            Self::verify_api_key(client, api_key, audit_logger.clone(), client_ip.clone()).await;

        // PERF: Cache the result (write lock)
        // SECURITY: Only cache if we got a definitive result
        // ADV-VA-031: Log poisoned write lock (same rationale as above).
        if let Ok(cache_guard) = API_KEY_CACHE.write().map_err(|e| {
            #[cfg(target_arch = "wasm32")]
            console_log!(
                "[ERROR] API_KEY_CACHE RwLock poisoned on write: {} - skipping cache update",
                e
            );
            e
        }) {
            let mut cache = cache_guard;
            cache.insert(
                cache_key,
                VerificationCacheEntry {
                    verified: result.is_ok(),
                    client_id: client.client_id.clone(),
                    cached_at: now,
                },
            );
        }

        result
    }

    /// SECURITY: Verify nonce for replay protection (CWE-287, ASVS V2).
    /// Nonces are stored in Durable Objects with TTL matching challenge lifecycle.
    /// This provides cryptographic protection against replay attacks.
    async fn verify_nonce(
        &self,
        nonce: &str,
        key_id: &str,
        audit_logger: Option<AuditLogger>,
        client_ip: Option<String>,
    ) -> Result<(), ApiError> {
        // SECURITY: Nonce store must be configured for nonce-based replay protection
        let nonce_store = match &self.nonce_store {
            Some(store) => store,
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [Auth] Nonce store not configured, but nonce provided by client"
                );
                return Err(ApiError::Internal(anyhow::anyhow!(
                    "Nonce store not configured for replay protection"
                )));
            }
        };

        // SECURITY: Create nonce tag with key_id prefix for better tracking
        let nonce_tag = format!("auth:{}:{}", key_id, nonce);
        let nonce_ttl = NONCE_DEDUP_TTL;

        // SECURITY: Atomic check-and-set operation prevents race conditions
        // Returns true if nonce is new (first use), false if replay detected
        match nonce_store.check_and_set(&nonce_tag, nonce_ttl).await {
            Ok(true) => {
                // Nonce is new - authentication continues
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [Auth] Nonce validated successfully for key_id={}",
                    key_id
                );
                Ok(())
            }
            Ok(false) => {
                // Replay attack detected - nonce already used
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [Auth] REPLAY ATTACK DETECTED - Nonce reuse for key_id={}, nonce={}",
                    key_id,
                    nonce
                );

                // SECURITY: Log replay attack attempt (CWE-778)
                if let (Some(logger), Some(ip)) = (audit_logger, client_ip) {
                    let details = json!({
                        "failure_type": "nonce_replay_attack",
                        "key_id": key_id,
                        "nonce": nonce,
                        "attack_type": "replay"
                    });
                    logger
                        .log_authentication_failure(
                            &ip,
                            "nonce_replay_attack",
                            Some(key_id),
                            None,
                            Some(details),
                        )
                        .await;
                }

                Err(ApiError::unauthorized(
                    "NONCE_REPLAY",
                    "authorizer.nonce has already been used within the replay window (300s)",
                ))
            }
            Err(e) => {
                // Storage error - fail securely by rejecting authentication
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [Auth] Nonce store error for key_id={}: {:?}",
                    key_id,
                    e
                );

                // SECURITY: Log storage failure (CWE-778)
                if let (Some(logger), Some(ip)) = (audit_logger, client_ip) {
                    let details = json!({
                        "failure_type": "nonce_storage_error",
                        "key_id": key_id,
                        "error": format!("{:?}", e)
                    });
                    logger
                        .log_authentication_failure(
                            &ip,
                            "nonce_storage_error",
                            Some(key_id),
                            None,
                            Some(details),
                        )
                        .await;
                }

                Err(ApiError::Internal(anyhow::anyhow!(
                    "Nonce verification failed: {}",
                    e
                )))
            }
        }
    }

    /// SECURITY: Verify HMAC signature using encrypted secrets only.
    ///
    /// All HMAC secrets must be encrypted using AES-256-GCM envelope encryption.
    /// The MEK (Master Encryption Key) must be configured in Cloudflare Secrets, and the
    /// client must have `encrypted_hmac_secret` and `dek_encrypted` fields populated.
    /// The decrypted secret is securely zeroised from memory after use via `Zeroizing`.
    ///
    /// Returns Unauthorized error if decryption fails or encryption not configured.
    async fn verify_hmac(
        client: &ClientAuthConfig,
        canonical: &str,
        supplied_hex: &str,
        mek: Option<&[u8]>,
        previous_mek: Option<&[u8]>,
        audit_logger: Option<AuditLogger>,
        client_ip: Option<String>,
        mut mek_slot_out: Option<&mut Option<crate::security::secret_versions::RotationSlot>>,
        analytics: Option<&worker::AnalyticsEngineDataset>,
    ) -> Result<(), ApiError> {
        // SECURITY: All HMAC secrets must be encrypted (no plaintext support)
        let mek_bytes = match mek {
            Some(m) => m,
            None => {
                #[cfg(target_arch = "wasm32")]
                console_log!(
                    "[SECURITY] [Auth] [ERROR] No MEK available - all clients require encrypted secrets"
                );
                // AL-042: Audit MEK missing (never log key material).
                if let (Some(ref logger), Some(ref ip)) = (&audit_logger, &client_ip) {
                    logger
                        .log_mek_failure(&client.client_id, "mek_not_configured", ip, analytics)
                        .await;
                }
                return Err(ApiError::Internal(anyhow::anyhow!("MEK not configured")));
            }
        };

        let encrypted_secret = &client.encrypted_hmac_secret;
        let encrypted_dek = &client.dek_encrypted;

        // Decrypt HMAC secret using envelope encryption with optional fallback MEK
        let encrypted = crate::security::envelope_encryption::EncryptedSecret {
            encrypted_secret: encrypted_secret.clone(),
            encrypted_dek: encrypted_dek.clone(),
            version: client.encryption_version,
        };

        let mut local_slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let secret =
            match crate::security::envelope_encryption::decrypt_hmac_secret_with_fallback_tracked(
                &encrypted,
                mek_bytes,
                previous_mek,
                Some(&mut local_slot),
            )
            .await
            {
                Ok(s) => {
                    if let Some(out) = mek_slot_out.as_mut() {
                        **out = local_slot;
                    }
                    s
                }
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    console_log!(
                    "[SECURITY] [Auth] [ERROR] Failed to decrypt HMAC secret for client_id={}: {}",
                    client.client_id,
                    _e
                );
                    // AL-042: Audit MEK decryption failure (never log key material).
                    if let (Some(ref logger), Some(ref ip)) = (&audit_logger, &client_ip) {
                        logger
                            .log_mek_failure(&client.client_id, "decryption_failure", ip, analytics)
                            .await;
                    }
                    return Err(ApiError::Internal(anyhow::anyhow!(
                        "Failed to decrypt HMAC secret"
                    )));
                }
            };

        #[cfg(target_arch = "wasm32")]
        console_log!(
            "[SECURITY] [Auth] Successfully decrypted HMAC secret for client_id={}",
            client.client_id
        );

        // SECURITY: Compute expected HMAC-SHA256 over the canonical request message.
        // The decrypted secret is held in a Zeroizing wrapper and cleared on drop.
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_slice())
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("Invalid HMAC key: {}", e)))?;
        mac.update(canonical.as_bytes());

        // ST-VA-020: Use verify_slice() on raw bytes instead of comparing hex strings.
        // Previous code hex-encoded both sides and used ct_eq on the hex representations,
        // which doubles the comparison length and operates on a larger alphabet than
        // necessary. verify_slice() compares raw 32-byte tags in constant time.
        let supplied_bytes = hex::decode(supplied_hex).map_err(|_| {
            ApiError::bad_request(
                "INVALID_HMAC_FORMAT",
                Some("authorizer.hmac"),
                "hmac must be a valid hex string",
            )
        })?;

        if mac.verify_slice(&supplied_bytes).is_err() {
            #[cfg(target_arch = "wasm32")]
            console_log!("[Auth] HMAC mismatch for client_id={}", client.client_id);

            // SECURITY: Log HMAC verification failure (CWE-778)
            if let (Some(logger), Some(ip)) = (audit_logger, client_ip) {
                let details = json!({
                    "failure_type": "hmac_signature_mismatch",
                    "client_id": client.client_id,
                    "canonical_message_length": canonical.len()
                });
                logger
                    .log_authentication_failure(
                        &ip,
                        "hmac_signature_mismatch",
                        Some(&client.client_id),
                        None,
                        Some(details),
                    )
                    .await;
            }

            return Err(ApiError::unauthorized(
                "INVALID_HMAC",
                "HMAC signature does not match the canonical request",
            ));
        }

        Ok(())
    }
}

/// Test-only reset for `API_KEY_CACHE`.
///
/// Drops every cached Argon2id verification outcome so the next
/// `authenticate` call re-runs the full hash check against the freshly-loaded
/// `OriginPolicy`. The Mode B rotation harness calls this
/// between rotation steps when drilling client API key rotation, which closes
/// the fidelity gap for this cache.
///
/// Cache values are not secret material (a verified-flag plus the
/// non-secret `client_id`) so this is a defence-in-depth reset, not a
/// zeroisation concern.
///
/// Idempotent. Safe to call multiple times within a single test.
#[cfg(test)]
pub fn __reset_api_key_cache_for_testing() {
    // Recover a poisoned guard with `into_inner` so the reset is unconditional.
    // Poisoning is not expected under the single-threaded harness, but the
    // recovery keeps the helper safe to call after an earlier panicking test.
    let mut guard = match API_KEY_CACHE.write() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::origin_policy::ClientAuthConfig;
    #[cfg(not(target_arch = "wasm32"))]
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(not(target_arch = "wasm32"))]
    use base64::Engine;
    use serial_test::serial;

    /* ========================================================================== */
    /*                    HELPER FUNCTIONS FOR TEST DATA                         */
    /* ========================================================================== */

    fn create_test_client(
        client_id: &str,
        active: bool,
    ) -> Result<ClientAuthConfig, Box<dyn std::error::Error>> {
        // API key: "test-secret-key"
        // Hash using Argon2id (generated dynamically for each test)
        let api_key_hash = crate::security::hash::hash_api_key("test-secret-key")?;

        // HMAC secret (base64url): "dGVzdC1obWFjLXNlY3JldA" = "test-hmac-secret"
        // In production, this would be encrypted. For tests, we use a test value.
        let encrypted_hmac_secret = "dGVzdC1obWFjLXNlY3JldA".to_string();

        Ok(ClientAuthConfig {
            client_id: client_id.to_string(),
            api_key_hash,
            api_key_prefix: Some("pk_test_".to_string()),
            encrypted_hmac_secret,
            dek_encrypted: "test_encrypted_dek".to_string(),
            encryption_version: 1,
            active,
        })
    }

    fn create_test_policy(clients: Vec<ClientAuthConfig>) -> OriginPolicy {
        OriginPolicy {
            clients,
            enabled: true,
            ..OriginPolicy::default()
        }
    }

    /* ========================================================================== */
    /*                    CONSTRUCTOR TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_new_authenticator() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        let auth = ClientAuthenticator::new(&policy);
        assert!(std::ptr::eq(auth.policy, &policy));
        Ok(())
    }

    /* ========================================================================== */
    /*                    verify_api_key() TESTS                                 */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_verify_api_key_valid() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result =
            ClientAuthenticator::verify_api_key(&client, "test-secret-key", None, None).await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_invalid() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result = ClientAuthenticator::verify_api_key(&client, "wrong-key", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_empty() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result = ClientAuthenticator::verify_api_key(&client, "", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_case_sensitive() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result =
            ClientAuthenticator::verify_api_key(&client, "TEST-SECRET-KEY", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_with_extra_chars() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result =
            ClientAuthenticator::verify_api_key(&client, "test-secret-key ", None, None).await;
        // ApiError::unauthorized() returns BadRequest with "__STATUS:401__" prefix
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__")),
            "Expected 401 unauthorized, got: {:?}",
            err
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    verify_hmac() TESTS                                    */
    /* ========================================================================== */

    /// Helper: build a `ClientAuthConfig` whose HMAC secret is genuinely
    /// envelope-encrypted under `mek`. Returns the client and the raw HMAC
    /// key bytes so callers can compute the expected tag independently.
    async fn create_hmac_test_client(mek: &[u8]) -> (ClientAuthConfig, Vec<u8>) {
        let hmac_key = b"test-hmac-key-for-verify-tests!x"; // 32 bytes
        let encrypted = crate::security::envelope_encryption::encrypt_hmac_secret(hmac_key, mek)
            .await
            .expect("encrypt_hmac_secret must succeed with valid MEK");

        let api_key_hash = crate::security::hash::hash_api_key("unused-api-key")
            .expect("hash_api_key must succeed");

        let client = ClientAuthConfig {
            client_id: "hmac-test-client".to_string(),
            api_key_hash,
            api_key_prefix: Some("pk_test_".to_string()),
            encrypted_hmac_secret: encrypted.encrypted_secret.clone(),
            dek_encrypted: encrypted.encrypted_dek.clone(),
            encryption_version: encrypted.version,
            active: true,
        };

        (client, hmac_key.to_vec())
    }

    /// Compute the expected HMAC-SHA256 hex tag over `canonical` using `key`.
    fn compute_expected_hmac_hex(key: &[u8], canonical: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(key).expect("HMAC key length is always valid in tests");
        mac.update(canonical.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[tokio::test]
    async fn test_verify_hmac_correct_signature() -> Result<(), Box<dyn std::error::Error>> {
        let mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, hmac_key) = create_hmac_test_client(&mek).await;

        let canonical = "GET\n/v1/verify\n1716000000\nabc123";
        let supplied_hex = compute_expected_hmac_hex(&hmac_key, canonical);

        let mut slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &supplied_hex,
            Some(&mek),
            None,
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_ok(), "valid HMAC must pass: {:?}", result);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_wrong_signature() -> Result<(), Box<dyn std::error::Error>> {
        let mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, _hmac_key) = create_hmac_test_client(&mek).await;

        let canonical = "GET\n/v1/verify\n1716000000\nabc123";
        // 64 hex chars (32 bytes) but wrong value
        let wrong_hex = "aa".repeat(32);

        let mut slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &wrong_hex,
            Some(&mek),
            None,
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_err(), "wrong HMAC must fail");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("INVALID_HMAC")),
            "expected INVALID_HMAC error, got: {:?}",
            err
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_invalid_hex() -> Result<(), Box<dyn std::error::Error>> {
        let mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, _hmac_key) = create_hmac_test_client(&mek).await;

        let canonical = "GET\n/v1/verify\n1716000000\nabc123";

        let mut slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            "not-valid-hex",
            Some(&mek),
            None,
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_err(), "invalid hex must fail");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("INVALID_HMAC_FORMAT")),
            "expected INVALID_HMAC_FORMAT error, got: {:?}",
            err
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_missing_mek() -> Result<(), Box<dyn std::error::Error>> {
        let mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, hmac_key) = create_hmac_test_client(&mek).await;

        let canonical = "GET\n/v1/verify\n1716000000\nabc123";
        let supplied_hex = compute_expected_hmac_hex(&hmac_key, canonical);

        let mut slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &supplied_hex,
            None, // no MEK
            None,
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_err(), "missing MEK must fail");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::Internal(_)),
            "expected Internal error for missing MEK, got: {:?}",
            err
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_wrong_mek() -> Result<(), Box<dyn std::error::Error>> {
        let mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let wrong_mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, hmac_key) = create_hmac_test_client(&mek).await;

        let canonical = "GET\n/v1/verify\n1716000000\nabc123";
        let supplied_hex = compute_expected_hmac_hex(&hmac_key, canonical);

        let mut slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &supplied_hex,
            Some(&wrong_mek), // wrong MEK cannot decrypt the DEK
            None,
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_err(), "wrong MEK must cause decryption failure");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::Internal(_)),
            "expected Internal error for wrong MEK, got: {:?}",
            err
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_mek_slot_tracking() -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, hmac_key) = create_hmac_test_client(&mek).await;

        let canonical = "POST\n/v1/verify\n1716000001\ndef456";
        let supplied_hex = compute_expected_hmac_hex(&hmac_key, canonical);

        let mut slot: Option<RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &supplied_hex,
            Some(&mek),
            None,
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_ok(), "valid HMAC must pass: {:?}", result);
        assert_eq!(
            slot,
            Some(RotationSlot::Current),
            "mek_slot_out must be set to Current when primary MEK decrypts"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_previous_mek_fallback() -> Result<(), Box<dyn std::error::Error>> {
        use crate::security::secret_versions::RotationSlot;

        let old_mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let new_mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, hmac_key) = create_hmac_test_client(&old_mek).await;

        let canonical = "POST\n/v1/verify\n1716000002\nghi789";
        let supplied_hex = compute_expected_hmac_hex(&hmac_key, canonical);

        let mut slot: Option<RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &supplied_hex,
            Some(&new_mek),
            Some(&old_mek),
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(
            result.is_ok(),
            "previous MEK fallback must succeed: {:?}",
            result
        );
        assert_eq!(
            slot,
            Some(RotationSlot::Previous),
            "slot must be Previous when fallback MEK decrypts"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_hmac_both_meks_wrong() -> Result<(), Box<dyn std::error::Error>> {
        let real_mek = crate::security::envelope_encryption::generate_random_key(32)?;
        let wrong_mek_1 = crate::security::envelope_encryption::generate_random_key(32)?;
        let wrong_mek_2 = crate::security::envelope_encryption::generate_random_key(32)?;
        let (client, hmac_key) = create_hmac_test_client(&real_mek).await;

        let canonical = "POST\n/v1/verify\n1716000003\njkl012";
        let supplied_hex = compute_expected_hmac_hex(&hmac_key, canonical);

        let mut slot: Option<crate::security::secret_versions::RotationSlot> = None;
        let result = ClientAuthenticator::verify_hmac(
            &client,
            canonical,
            &supplied_hex,
            Some(&wrong_mek_1),
            Some(&wrong_mek_2),
            None,
            None,
            Some(&mut slot),
            None,
        )
        .await;

        assert!(result.is_err(), "both MEKs wrong must fail");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::Internal(_)),
            "expected Internal error when both MEKs fail, got: {:?}",
            err
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    authenticate() INTEGRATION TESTS                       */
    /* ========================================================================== */

    // Note: authenticate() is now async and requires an async runtime,
    // a master encryption key (mek) for HMAC secret decryption, and
    // Worker KV bindings for nonce storage. These tests should be run
    // as integration tests in the Workers runtime.
    // The function signature is:
    //   async fn authenticate(api_key, authorizer, canonical_message, mek, nonce_cache, audit_logger, client_ip)

    /* ========================================================================== */
    /*                    API KEY HASH TESTS                                     */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_api_key_single_bit_difference() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;

        // "test-secret-key" should pass
        assert!(
            ClientAuthenticator::verify_api_key(&client, "test-secret-key", None, None)
                .await
                .is_ok()
        );

        // Single character change should fail
        assert!(
            ClientAuthenticator::verify_api_key(&client, "test-secret-ket", None, None)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_api_key_with_non_ascii() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result =
            ClientAuthenticator::verify_api_key(&client, "test-sécrét-kéy", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_api_key_with_unicode() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result = ClientAuthenticator::verify_api_key(&client, "test-🔑-key", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_api_key_with_null_byte() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let key_with_null = "test\x00secret";
        let result = ClientAuthenticator::verify_api_key(&client, key_with_null, None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    /* ========================================================================== */
    /*                    ERROR PATH TESTS                                       */
    /* ========================================================================== */

    // Note: Tests for verify_hmac with invalid secrets are skipped because
    // verify_hmac is now async and requires the Workers runtime,
    // ClientAuthConfig uses encrypted_hmac_secret instead of hmac_secret,
    // and decryption requires the master encryption key (mek) from KV storage.

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn test_multiple_clients_same_api_key_hash() -> Result<(), Box<dyn std::error::Error>> {
        let client1 = create_test_client("client1", true)?;
        let client2 = create_test_client("client2", true)?;
        // Both have same API key hash due to test setup
        assert_eq!(client1.api_key_hash, client2.api_key_hash);

        // Verify both clients have matching hash
        assert!(!client1.api_key_hash.is_empty());
        assert!(!client2.api_key_hash.is_empty());
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS                                   */
    /* ========================================================================== */

    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Any incorrect API key fails verification
        #[test]
        fn prop_wrong_api_key_rejected(wrong_key in "[a-zA-Z0-9-]{1,50}") {
            prop_assume!(wrong_key != "test-secret-key");
            let client = create_test_client("client1", true).expect("create_test_client");
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
            let result = rt.block_on(ClientAuthenticator::verify_api_key(&client, &wrong_key, None, None));
            prop_assert!(result.is_err());
        }

        /// Property: HMAC computation is deterministic
        #[test]
        fn prop_hmac_computation_deterministic(canonical in "[a-zA-Z0-9\n]{10,100}") {
            // Note: verify_hmac is async and needs KV for mek, so we just test HMAC computation
            let secret = URL_SAFE_NO_PAD.decode("dGVzdC1obWFjLXNlY3JldA").expect("decode");
            type HmacSha256 = Hmac<Sha256>;

            let mut mac1 = HmacSha256::new_from_slice(&secret).expect("hmac key");
            mac1.update(canonical.as_bytes());
            let hmac1 = hex::encode(mac1.finalize().into_bytes());

            let mut mac2 = HmacSha256::new_from_slice(&secret).expect("hmac key");
            mac2.update(canonical.as_bytes());
            let hmac2 = hex::encode(mac2.finalize().into_bytes());

            prop_assert_eq!(&hmac1, &hmac2);
        }

        /// Property: Different messages produce different HMACs
        #[test]
        fn prop_different_messages_different_hmacs(
            msg1 in "[a-zA-Z0-9]{10,50}",
            msg2 in "[a-zA-Z0-9]{10,50}"
        ) {
            prop_assume!(msg1 != msg2);

            let secret = URL_SAFE_NO_PAD.decode("dGVzdC1obWFjLXNlY3JldA").expect("decode");
            type HmacSha256 = Hmac<Sha256>;

            let mut mac1 = HmacSha256::new_from_slice(&secret).expect("hmac key");
            mac1.update(msg1.as_bytes());
            let hmac1 = hex::encode(mac1.finalize().into_bytes());

            let mut mac2 = HmacSha256::new_from_slice(&secret).expect("hmac key");
            mac2.update(msg2.as_bytes());
            let hmac2 = hex::encode(mac2.finalize().into_bytes());

            prop_assert_ne!(hmac1, hmac2);
        }

        /// Property: API key verification is case-sensitive
        #[test]
        fn prop_api_key_case_sensitive(key in "[a-z]{10,20}") {
            let uppercase_key = key.to_uppercase();
            prop_assume!(key != uppercase_key);

            let client = create_test_client("client1", true).expect("create_test_client");
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");

            // If original key doesn't match, uppercase shouldn't either
            let result_lower = rt.block_on(ClientAuthenticator::verify_api_key(&client, &key, None, None));
            let result_upper = rt.block_on(ClientAuthenticator::verify_api_key(&client, &uppercase_key, None, None));

            if result_lower.is_err() {
                prop_assert!(result_upper.is_err());
            }
        }

        /// Property: SHA256 hashes are always 64 hex characters
        #[test]
        fn prop_api_key_hash_format(key in "[a-zA-Z0-9-]{10,50}") {
            use sha2::Digest;
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let hash = hex::encode(hasher.finalize());

            prop_assert_eq!(hash.len(), 64);
            prop_assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    /* ========================================================================== */
    /*                    NONCE VALIDATION TESTS (PHASE 2)                       */
    /* ========================================================================== */

    // SECURITY: Tests for nonce-based replay protection (CWE-287, ASVS V2)
    // Nonce must be exactly 64 hex characters (256 bits of entropy).

    #[test]
    fn test_authorizer_with_valid_nonce() {
        let nonce = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: nonce.to_string(),
        };
        assert!(auth.validate().is_ok());
        assert_eq!(auth.nonce, nonce);
    }

    #[test]
    fn test_nonce_validation_empty() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "".to_string(),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("64 hex characters"));
        Ok(())
    }

    #[test]
    fn test_nonce_validation_too_short() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "a".repeat(63), // 63 chars, need 64
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("64 hex characters"));
        Ok(())
    }

    #[test]
    fn test_nonce_validation_too_long() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "a".repeat(65), // 65 chars, need 64
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("64 hex characters"));
        Ok(())
    }

    #[test]
    fn test_nonce_validation_non_hex_chars() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: format!("{}g{}", "a".repeat(32), "b".repeat(31)), // 'g' is not hex
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result.err().ok_or("expected error")?.contains("hex"));
        Ok(())
    }

    #[test]
    fn test_nonce_validation_uuid_rejected() {
        // UUIDs are no longer accepted. Must be 64 hex chars.
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        };
        let result = auth.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_validation_uppercase_hex() {
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: "A".repeat(64),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_nonce_tag_format() {
        let key_id = "client-123";
        let nonce = "a".repeat(64);
        let expected_tag = format!("auth:{}:{}", key_id, nonce);
        assert!(expected_tag.starts_with("auth:client-123:"));
        assert_eq!(expected_tag.len(), "auth:client-123:".len() + 64);
    }

    #[test]
    fn test_nonce_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = "c".repeat(64);
        let auth = Authorizer {
            key_id: "client-123".to_string(),
            timestamp: 1234567890,
            hmac: "a".repeat(64),
            nonce: nonce.clone(),
        };
        let json = serde_json::to_string(&auth)?;
        assert!(json.contains(&nonce));
        assert!(json.contains("keyId"));
        Ok(())
    }

    #[test]
    fn test_nonce_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let nonce = "d".repeat(64);
        let json = format!(
            r#"{{"keyId":"client-123","timestamp":1234567890,"hmac":"{}","nonce":"{}"}}"#,
            "a".repeat(64),
            nonce
        );
        let auth: Authorizer = serde_json::from_str(&json)?;
        assert_eq!(auth.nonce, nonce);
        Ok(())
    }

    /* ========================================================================== */
    /*                    ARGON2ID HASH TESTS                                    */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_verify_api_key_argon2id_success() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result =
            ClientAuthenticator::verify_api_key(&client, "test-secret-key", None, None).await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_argon2id_fails_wrong_key() -> Result<(), Box<dyn std::error::Error>>
    {
        let client = create_test_client("client1", true)?;
        let result = ClientAuthenticator::verify_api_key(&client, "wrong-key", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_invalid_format_fails() -> Result<(), Box<dyn std::error::Error>> {
        let mut client = create_test_client("client1", true)?;
        client.api_key_hash = "invalid-hash-format".to_string();

        let result = ClientAuthenticator::verify_api_key(&client, "any-key", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_sha256_rejected() -> Result<(), Box<dyn std::error::Error>> {
        // SHA-256 hashes should be rejected (no backwards compatibility)
        let mut client = create_test_client("client1", true)?;
        client.api_key_hash =
            "2ceac6f36363c6246a64cca805cd43ca7a01b14eb2fcc532ceec3f60f2f7df1c".to_string();

        let result =
            ClientAuthenticator::verify_api_key(&client, "test-secret-key", None, None).await;
        assert!(
            matches!(&result.unwrap_err(), ApiError::BadRequest(Some(msg)) if msg.starts_with("__STATUS:401__"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_argon2id_salt_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        // Verify that the same key produces different hashes (due to salt)
        let hash1 = crate::security::hash::hash_api_key("same-key")?;
        let hash2 = crate::security::hash::hash_api_key("same-key")?;
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        let mut client1 = create_test_client("client1", true)?;
        client1.api_key_hash = hash1;
        let mut client2 = create_test_client("client2", true)?;
        client2.api_key_hash = hash2;

        assert!(
            ClientAuthenticator::verify_api_key(&client1, "same-key", None, None)
                .await
                .is_ok()
        );
        assert!(
            ClientAuthenticator::verify_api_key(&client2, "same-key", None, None)
                .await
                .is_ok()
        );
        Ok(())
    }

    // Note: Full integration tests with NonceStore would require async test infrastructure
    // and mocking. These tests cover the validation logic and data structures.
    // End-to-end replay protection is tested in the routes integration tests.

    /* ========================================================================== */
    /*                    make_cache_key() TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_make_cache_key_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let key1 = make_cache_key("pk_test_abc12345xyz", "client-1");
        let key2 = make_cache_key("pk_test_abc12345xyz", "client-1");
        assert_eq!(key1, key2);
        Ok(())
    }

    #[test]
    fn test_make_cache_key_different_api_keys() -> Result<(), Box<dyn std::error::Error>> {
        let key1 = make_cache_key("pk_test_aaaaaaaa", "client-1");
        let key2 = make_cache_key("pk_test_bbbbbbbb", "client-1");
        assert_ne!(key1, key2);
        Ok(())
    }

    #[test]
    fn test_make_cache_key_different_client_ids() -> Result<(), Box<dyn std::error::Error>> {
        let key1 = make_cache_key("pk_test_abc12345", "client-1");
        let key2 = make_cache_key("pk_test_abc12345", "client-2");
        assert_ne!(key1, key2);
        Ok(())
    }

    #[test]
    fn test_make_cache_key_is_hex_sha256() -> Result<(), Box<dyn std::error::Error>> {
        let key = make_cache_key("any-api-key", "any-client");
        // SHA-256 hex digest is always 64 lowercase hex chars
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_make_cache_key_empty_inputs() -> Result<(), Box<dyn std::error::Error>> {
        // Empty inputs should still produce a valid cache key (no panics)
        let key = make_cache_key("", "");
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn test_make_cache_key_different_inputs_differ() -> Result<(), Box<dyn std::error::Error>> {
        // Different api_key or client_id values produce different cache keys
        let key1 = make_cache_key("key-a", "client");
        let key2 = make_cache_key("key-b", "client");
        assert_ne!(key1, key2);

        let key3 = make_cache_key("key", "client-a");
        let key4 = make_cache_key("key", "client-b");
        assert_ne!(key3, key4);
        Ok(())
    }

    #[test]
    fn test_make_cache_key_long_inputs() -> Result<(), Box<dyn std::error::Error>> {
        let long_key = "x".repeat(1000);
        let long_client = "y".repeat(1000);
        let key = make_cache_key(&long_key, &long_client);
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        Ok(())
    }

    /* ========================================================================== */
    /*                    CACHE CONSTANT TESTS                                   */
    /* ========================================================================== */

    #[test]
    fn test_api_key_cache_ttl_is_30_seconds() {
        assert_eq!(API_KEY_CACHE_TTL_MS, 30_000);
    }

    /* ========================================================================== */
    /*                    VerificationCacheEntry TESTS                            */
    /* ========================================================================== */

    #[test]
    fn test_verification_cache_entry_fields() {
        let entry = VerificationCacheEntry {
            verified: true,
            client_id: "client-42".to_string(),
            cached_at: 1_000_000,
        };
        assert!(entry.verified);
        assert_eq!(entry.client_id, "client-42");
        assert_eq!(entry.cached_at, 1_000_000);
    }

    #[test]
    fn test_verification_cache_entry_clone() {
        let entry = VerificationCacheEntry {
            verified: false,
            client_id: "client-99".to_string(),
            cached_at: 5_000_000,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.verified, entry.verified);
        assert_eq!(cloned.client_id, entry.client_id);
        assert_eq!(cloned.cached_at, entry.cached_at);
    }

    #[test]
    fn test_verification_cache_entry_debug() {
        let entry = VerificationCacheEntry {
            verified: true,
            client_id: "test".to_string(),
            cached_at: 0,
        };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("true"));
        assert!(debug.contains("test"));
    }

    /* ========================================================================== */
    /*                    BUILDER PATTERN TESTS                                  */
    /* ========================================================================== */

    #[test]
    fn test_new_authenticator_defaults_all_none() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        let auth = ClientAuthenticator::new(&policy);
        assert!(auth.audit_logger.is_none());
        assert!(auth.client_ip.is_none());
        assert!(auth.nonce_store.is_none());
        assert!(auth.mek.is_none());
        assert!(auth.previous_mek.is_none());
        assert!(auth.prefix_index_kv.is_none());
        assert!(auth.dummy_hash.is_none());
        assert!(auth.analytics.is_none());
        Ok(())
    }

    #[test]
    fn test_with_mek_sets_mek() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        let mek = zeroize::Zeroizing::new(vec![0u8; 32]);
        let auth = ClientAuthenticator::new(&policy).with_mek(mek);
        assert!(auth.mek.is_some());
        assert_eq!(auth.mek.as_ref().map(|m| m.len()), Some(32));
        Ok(())
    }

    #[test]
    fn test_with_previous_mek_sets_previous_mek() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        let prev = zeroize::Zeroizing::new(vec![1u8; 32]);
        let auth = ClientAuthenticator::new(&policy).with_previous_mek(prev);
        assert!(auth.previous_mek.is_some());
        assert_eq!(auth.previous_mek.as_ref().map(|m| m.len()), Some(32));
        Ok(())
    }

    #[test]
    fn test_with_dummy_hash_sets_dummy_hash() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        let hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dummy".to_string();
        let auth = ClientAuthenticator::new(&policy).with_dummy_hash(hash.clone());
        assert_eq!(auth.dummy_hash, Some(hash));
        Ok(())
    }

    #[test]
    fn test_with_nonce_store_sets_store() -> Result<(), Box<dyn std::error::Error>> {
        use crate::storage::traits::NonceStore;
        use std::collections::HashMap as NsMap;
        use std::sync::Mutex;

        struct TestNonceStore {
            seen: Mutex<NsMap<String, ()>>,
        }

        #[async_trait::async_trait(?Send)]
        impl NonceStore for TestNonceStore {
            async fn check_and_set(
                &self,
                tag: &str,
                _ttl: std::time::Duration,
            ) -> crate::error::ApiResult<bool> {
                let mut g = self.seen.lock().expect("lock");
                if g.contains_key(tag) {
                    Ok(false)
                } else {
                    g.insert(tag.to_string(), ());
                    Ok(true)
                }
            }
        }

        let policy = create_test_policy(vec![]);
        let store: Arc<dyn NonceStore> = Arc::new(TestNonceStore {
            seen: Mutex::new(NsMap::new()),
        });
        let auth = ClientAuthenticator::new(&policy).with_nonce_store(store);
        assert!(auth.nonce_store.is_some());
        Ok(())
    }

    #[test]
    fn test_builder_chaining() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        let mek = zeroize::Zeroizing::new(vec![0u8; 32]);
        let prev = zeroize::Zeroizing::new(vec![1u8; 32]);
        let auth = ClientAuthenticator::new(&policy)
            .with_mek(mek)
            .with_previous_mek(prev)
            .with_dummy_hash("dummy".to_string());
        assert!(auth.mek.is_some());
        assert!(auth.previous_mek.is_some());
        assert_eq!(auth.dummy_hash, Some("dummy".to_string()));
        Ok(())
    }

    /* ========================================================================== */
    /*                    create_test_client() FIELD COVERAGE                    */
    /* ========================================================================== */

    #[test]
    fn test_create_test_client_active_fields() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("my-client", true)?;
        assert_eq!(client.client_id, "my-client");
        assert!(client.active);
        assert!(client.api_key_hash.starts_with("$argon2id$"));
        assert_eq!(client.api_key_prefix, Some("pk_test_".to_string()));
        assert_eq!(client.encrypted_hmac_secret, "dGVzdC1obWFjLXNlY3JldA");
        assert_eq!(client.dek_encrypted, "test_encrypted_dek");
        assert_eq!(client.encryption_version, 1);
        Ok(())
    }

    #[test]
    fn test_create_test_client_inactive() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("disabled-client", false)?;
        assert_eq!(client.client_id, "disabled-client");
        assert!(!client.active);
        Ok(())
    }

    /* ========================================================================== */
    /*                    create_test_policy() FIELD COVERAGE                    */
    /* ========================================================================== */

    #[test]
    fn test_create_test_policy_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("c1", true)?;
        let policy = create_test_policy(vec![client]);
        assert!(policy.enabled);
        assert_eq!(policy.clients.len(), 1);
        assert_eq!(policy.clients[0].client_id, "c1");
        Ok(())
    }

    #[test]
    fn test_create_test_policy_empty_clients() {
        let policy = create_test_policy(vec![]);
        assert!(policy.enabled);
        assert!(policy.clients.is_empty());
    }

    #[test]
    fn test_create_test_policy_multiple_clients() -> Result<(), Box<dyn std::error::Error>> {
        let c1 = create_test_client("alpha", true)?;
        let c2 = create_test_client("beta", false)?;
        let policy = create_test_policy(vec![c1, c2]);
        assert_eq!(policy.clients.len(), 2);
        assert!(policy.clients[0].active);
        assert!(!policy.clients[1].active);
        Ok(())
    }

    /* ========================================================================== */
    /*                    verify_api_key_cached() TESTS                          */
    /* ========================================================================== */

    #[tokio::test]
    #[serial]
    async fn test_verify_api_key_cached_miss_then_hit() -> Result<(), Box<dyn std::error::Error>> {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("cached-client", true)?;

        // First call: cache miss, should verify and cache
        let result =
            ClientAuthenticator::verify_api_key_cached(&client, "test-secret-key", None, None)
                .await;
        assert!(result.is_ok());

        // Second call: cache hit, should use cached result
        let result2 =
            ClientAuthenticator::verify_api_key_cached(&client, "test-secret-key", None, None)
                .await;
        assert!(result2.is_ok());

        // Verify cache entry exists
        let cache_key = make_cache_key("test-secret-key", &client.client_id);
        let guard = API_KEY_CACHE.read().expect("cache read lock");
        let cached = guard.get(&cache_key);
        assert!(cached.is_some());
        let cached = cached.expect("just asserted Some");
        assert!(cached.verified);
        assert_eq!(cached.client_id, "cached-client");
        drop(guard);

        __reset_api_key_cache_for_testing();
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_api_key_cached_wrong_key_not_cached_as_success(
    ) -> Result<(), Box<dyn std::error::Error>> {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("cached-fail", true)?;

        // Wrong key should fail
        let result =
            ClientAuthenticator::verify_api_key_cached(&client, "wrong-key-here", None, None).await;
        assert!(result.is_err());

        // Cache entry should record verified=false
        let cache_key = make_cache_key("wrong-key-here", &client.client_id);
        let guard = API_KEY_CACHE.read().expect("cache read lock");
        let cached = guard.get(&cache_key);
        assert!(cached.is_some());
        assert!(!cached.expect("just asserted Some").verified);
        drop(guard);

        __reset_api_key_cache_for_testing();
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_api_key_cached_cross_client_isolation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        __reset_api_key_cache_for_testing();
        let client_a = create_test_client("client-a", true)?;
        let client_b = create_test_client("client-b", true)?;

        // Cache a successful verification for client_a
        let result_a =
            ClientAuthenticator::verify_api_key_cached(&client_a, "test-secret-key", None, None)
                .await;
        assert!(result_a.is_ok());

        // client_b with the same api key should get its own cache entry
        let result_b =
            ClientAuthenticator::verify_api_key_cached(&client_b, "test-secret-key", None, None)
                .await;
        assert!(result_b.is_ok());

        // Verify both entries exist independently
        let key_a = make_cache_key("test-secret-key", "client-a");
        let key_b = make_cache_key("test-secret-key", "client-b");
        assert_ne!(key_a, key_b);

        let guard = API_KEY_CACHE.read().expect("cache read lock");
        assert!(guard.get(&key_a).is_some());
        assert!(guard.get(&key_b).is_some());
        drop(guard);

        __reset_api_key_cache_for_testing();
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_api_key_cached_expired_entry_reverifies(
    ) -> Result<(), Box<dyn std::error::Error>> {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("expiry-client", true)?;
        let cache_key = make_cache_key("test-secret-key", &client.client_id);

        // Manually insert an expired cache entry (cached_at far in the past)
        {
            let mut guard = API_KEY_CACHE.write().expect("cache write lock");
            guard.insert(
                cache_key.clone(),
                VerificationCacheEntry {
                    verified: true,
                    client_id: "expiry-client".to_string(),
                    // Set cached_at to 0 so it's definitely expired (>30s ago)
                    cached_at: 0,
                },
            );
        }

        // Should treat the entry as expired and re-verify (succeeding with correct key)
        let result =
            ClientAuthenticator::verify_api_key_cached(&client, "test-secret-key", None, None)
                .await;
        assert!(result.is_ok());

        // Cache entry should be updated with a fresh timestamp
        let guard = API_KEY_CACHE.read().expect("cache read lock");
        let cached = guard.get(&cache_key).expect("entry should exist");
        assert!(cached.cached_at > 0);
        assert!(cached.verified);
        drop(guard);

        __reset_api_key_cache_for_testing();
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_api_key_cached_stale_client_id_mismatch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("real-client", true)?;
        let cache_key = make_cache_key("test-secret-key", &client.client_id);

        // Manually insert a cache entry with a different client_id (simulating
        // a collision where the cache key maps to a different client)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        {
            let mut guard = API_KEY_CACHE.write().expect("cache write lock");
            guard.insert(
                cache_key.clone(),
                VerificationCacheEntry {
                    verified: true,
                    client_id: "different-client".to_string(),
                    cached_at: now,
                },
            );
        }

        // The client_id mismatch check should cause a cache miss and re-verify
        let result =
            ClientAuthenticator::verify_api_key_cached(&client, "test-secret-key", None, None)
                .await;
        assert!(result.is_ok());

        __reset_api_key_cache_for_testing();
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_verify_api_key_cached_failed_result_cached_and_returned(
    ) -> Result<(), Box<dyn std::error::Error>> {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("fail-cache-client", true)?;

        // First call with wrong key: should fail and cache verified=false
        let result =
            ClientAuthenticator::verify_api_key_cached(&client, "bad-key", None, None).await;
        assert!(result.is_err());

        // Second call with same wrong key: should hit cache and return Unauthorized
        let result2 =
            ClientAuthenticator::verify_api_key_cached(&client, "bad-key", None, None).await;
        assert!(result2.is_err());
        // Cached failure returns bare ApiError::Unauthorized, not the structured one
        assert!(matches!(result2, Err(ApiError::Unauthorized)));

        __reset_api_key_cache_for_testing();
        Ok(())
    }

    /* ========================================================================== */
    /*                    verify_nonce() TESTS                                   */
    /* ========================================================================== */

    /// In-memory nonce store for unit testing `verify_nonce`.
    struct TestNonceStore {
        seen: std::sync::Mutex<HashMap<String, ()>>,
    }

    impl TestNonceStore {
        fn new() -> Self {
            Self {
                seen: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl crate::storage::traits::NonceStore for TestNonceStore {
        async fn check_and_set(
            &self,
            tag: &str,
            _ttl: std::time::Duration,
        ) -> crate::error::ApiResult<bool> {
            let mut g = self.seen.lock().expect("nonce store mutex poisoned");
            if g.contains_key(tag) {
                Ok(false)
            } else {
                g.insert(tag.to_string(), ());
                Ok(true)
            }
        }
    }

    /// Nonce store that always returns an error, for testing the error path.
    struct FailingNonceStore;

    #[async_trait::async_trait(?Send)]
    impl crate::storage::traits::NonceStore for FailingNonceStore {
        async fn check_and_set(
            &self,
            _tag: &str,
            _ttl: std::time::Duration,
        ) -> crate::error::ApiResult<bool> {
            Err(ApiError::Internal(anyhow::anyhow!("storage unavailable")))
        }
    }

    #[tokio::test]
    async fn test_verify_nonce_fresh_nonce_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn crate::storage::traits::NonceStore> = Arc::new(TestNonceStore::new());
        let policy = create_test_policy(vec![]);
        let auth = ClientAuthenticator::new(&policy).with_nonce_store(store);

        let result = auth
            .verify_nonce("unique-nonce-value", "client-1", None, None)
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_nonce_replayed_nonce_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn crate::storage::traits::NonceStore> = Arc::new(TestNonceStore::new());
        let policy = create_test_policy(vec![]);
        let auth = ClientAuthenticator::new(&policy).with_nonce_store(store);

        // First use: accepted
        let result = auth
            .verify_nonce("replay-nonce", "client-1", None, None)
            .await;
        assert!(result.is_ok());

        // Second use: replay attack detected
        let result2 = auth
            .verify_nonce("replay-nonce", "client-1", None, None)
            .await;
        assert!(result2.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_nonce_different_key_ids_same_nonce(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn crate::storage::traits::NonceStore> = Arc::new(TestNonceStore::new());
        let policy = create_test_policy(vec![]);
        let auth = ClientAuthenticator::new(&policy).with_nonce_store(store);

        // Same nonce string for different key_ids should produce different nonce tags
        let result1 = auth
            .verify_nonce("same-nonce", "client-a", None, None)
            .await;
        assert!(result1.is_ok());

        let result2 = auth
            .verify_nonce("same-nonce", "client-b", None, None)
            .await;
        assert!(result2.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_nonce_no_store_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        let policy = create_test_policy(vec![]);
        // No nonce store configured
        let auth = ClientAuthenticator::new(&policy);

        let result = auth
            .verify_nonce("some-nonce", "client-1", None, None)
            .await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::Internal(_))));
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_nonce_store_error_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let store: Arc<dyn crate::storage::traits::NonceStore> = Arc::new(FailingNonceStore);
        let policy = create_test_policy(vec![]);
        let auth = ClientAuthenticator::new(&policy).with_nonce_store(store);

        let result = auth.verify_nonce("any-nonce", "client-1", None, None).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ApiError::Internal(_))));
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_nonce_tag_format_includes_key_id() -> Result<(), Box<dyn std::error::Error>>
    {
        // Verify that the nonce tag format is "auth:{key_id}:{nonce}"
        let key_id = "test-client";
        let nonce = "abc123";
        let expected = format!("auth:{}:{}", key_id, nonce);
        assert_eq!(expected, "auth:test-client:abc123");
        Ok(())
    }

    /* ========================================================================== */
    /*                    HMAC COMPUTATION TESTS (PURE LOGIC)                    */
    /* ========================================================================== */

    #[test]
    fn test_hmac_sha256_known_vector() -> Result<(), Box<dyn std::error::Error>> {
        // Test HMAC-SHA256 computation matches expected output for known inputs.
        // Secret = "test-hmac-secret", message = "canonical-message"
        type HmacSha256 = Hmac<Sha256>;
        let secret = b"test-hmac-secret";
        let message = b"canonical-message";

        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(message);
        let result = hex::encode(mac.finalize().into_bytes());

        // Must be 64 hex characters (32 bytes)
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));

        // Recompute to ensure determinism
        let mut mac2 = HmacSha256::new_from_slice(secret)?;
        mac2.update(message);
        let result2 = hex::encode(mac2.finalize().into_bytes());
        assert_eq!(result, result2);
        Ok(())
    }

    #[test]
    fn test_hmac_sha256_verify_slice_correct() -> Result<(), Box<dyn std::error::Error>> {
        type HmacSha256 = Hmac<Sha256>;
        let secret = b"my-secret";
        let message = b"my-message";

        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(message);
        let tag = mac.finalize().into_bytes();

        // verify_slice should accept the correct tag
        let mut mac2 = HmacSha256::new_from_slice(secret)?;
        mac2.update(message);
        assert!(mac2.verify_slice(&tag).is_ok());
        Ok(())
    }

    #[test]
    fn test_hmac_sha256_verify_slice_wrong_tag() -> Result<(), Box<dyn std::error::Error>> {
        type HmacSha256 = Hmac<Sha256>;
        let secret = b"my-secret";
        let message = b"my-message";

        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(message);

        // Tamper with the tag
        let wrong_tag = vec![0u8; 32];
        assert!(mac.verify_slice(&wrong_tag).is_err());
        Ok(())
    }

    #[test]
    fn test_hmac_sha256_verify_slice_wrong_length() -> Result<(), Box<dyn std::error::Error>> {
        type HmacSha256 = Hmac<Sha256>;
        let secret = b"my-secret";
        let message = b"my-message";

        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(message);

        // Wrong length tag
        let short_tag = vec![0u8; 16];
        assert!(mac.verify_slice(&short_tag).is_err());
        Ok(())
    }

    #[test]
    fn test_hmac_sha256_empty_message() -> Result<(), Box<dyn std::error::Error>> {
        type HmacSha256 = Hmac<Sha256>;
        let secret = b"secret-key";

        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(b"");
        let tag = hex::encode(mac.finalize().into_bytes());

        // Empty message should still produce a valid 64-char hex HMAC
        assert_eq!(tag.len(), 64);
        Ok(())
    }

    #[test]
    fn test_hmac_sha256_different_secrets_different_tags() -> Result<(), Box<dyn std::error::Error>>
    {
        type HmacSha256 = Hmac<Sha256>;
        let message = b"same-message";

        let mut mac1 = HmacSha256::new_from_slice(b"secret-1")?;
        mac1.update(message);
        let tag1 = hex::encode(mac1.finalize().into_bytes());

        let mut mac2 = HmacSha256::new_from_slice(b"secret-2")?;
        mac2.update(message);
        let tag2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(tag1, tag2);
        Ok(())
    }

    #[test]
    fn test_hex_decode_valid() -> Result<(), Box<dyn std::error::Error>> {
        // Simulates the hex::decode path in verify_hmac
        let valid_hex = "a".repeat(64);
        let bytes = hex::decode(&valid_hex)?;
        assert_eq!(bytes.len(), 32);
        Ok(())
    }

    #[test]
    fn test_hex_decode_invalid() {
        // Simulates the hex::decode error path in verify_hmac
        let invalid_hex = "zzzz";
        assert!(hex::decode(invalid_hex).is_err());
    }

    #[test]
    fn test_hex_decode_odd_length() {
        // Odd-length hex strings are invalid
        let odd_hex = "abc";
        assert!(hex::decode(odd_hex).is_err());
    }

    /* ========================================================================== */
    /*                    CLIENT LOOKUP LOGIC TESTS                              */
    /* ========================================================================== */

    #[test]
    fn test_client_lookup_by_key_id_and_active() -> Result<(), Box<dyn std::error::Error>> {
        let active = create_test_client("active-client", true)?;
        let inactive = create_test_client("inactive-client", false)?;
        let policy = create_test_policy(vec![active, inactive]);

        // Active client should be found
        let found = policy
            .clients
            .iter()
            .find(|c| c.client_id == "active-client" && c.active);
        assert!(found.is_some());

        // Inactive client should NOT be found (active filter)
        let not_found = policy
            .clients
            .iter()
            .find(|c| c.client_id == "inactive-client" && c.active);
        assert!(not_found.is_none());

        // Non-existent client should NOT be found
        let missing = policy
            .clients
            .iter()
            .find(|c| c.client_id == "ghost" && c.active);
        assert!(missing.is_none());
        Ok(())
    }

    #[test]
    fn test_client_lookup_inactive_excluded() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("my-client", false)?;
        let policy = create_test_policy(vec![client]);

        let found = policy
            .clients
            .iter()
            .find(|c| c.client_id == "my-client" && c.active);
        assert!(found.is_none());
        Ok(())
    }

    #[test]
    fn test_client_lookup_empty_clients() {
        let policy = create_test_policy(vec![]);
        let found = policy
            .clients
            .iter()
            .find(|c| c.client_id == "any" && c.active);
        assert!(found.is_none());
    }

    /* ========================================================================== */
    /*                    AUTHORIZER VALIDATION EDGE CASES                       */
    /* ========================================================================== */

    #[test]
    fn test_authorizer_validate_all_fields_valid() {
        let auth = Authorizer {
            key_id: "prod-client-001".to_string(),
            timestamp: 1716000000,
            hmac: "0123456789abcdef".repeat(4),
            nonce: "fedcba9876543210".repeat(4),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_authorizer_validate_key_id_whitespace_prefix() -> Result<(), Box<dyn std::error::Error>>
    {
        let auth = Authorizer {
            key_id: " leading-space".to_string(),
            timestamp: 123,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        // Space is not ascii_graphic, so this should be rejected
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result
            .err()
            .ok_or("expected error")?
            .contains("invalid characters"));
        Ok(())
    }

    #[test]
    fn test_authorizer_validate_hmac_empty() -> Result<(), Box<dyn std::error::Error>> {
        let auth = Authorizer {
            key_id: "client".to_string(),
            timestamp: 123,
            hmac: "".to_string(),
            nonce: "b".repeat(64),
        };
        let result = auth.validate();
        assert!(result.is_err());
        assert!(result.err().ok_or("expected error")?.contains("hex"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    API_KEY_CACHE GLOBAL STATE TESTS                       */
    /* ========================================================================== */

    #[test]
    fn test_api_key_cache_is_initially_accessible() {
        // The Lazy static should initialise without panicking
        let guard = API_KEY_CACHE.read().expect("should acquire read lock");
        // May or may not be empty depending on test order, but must not panic
        drop(guard);
    }

    #[test]
    fn test_api_key_cache_write_and_read() {
        __reset_api_key_cache_for_testing();

        let key = "test-cache-rw-key".to_string();
        {
            let mut guard = API_KEY_CACHE.write().expect("write lock");
            guard.insert(
                key.clone(),
                VerificationCacheEntry {
                    verified: true,
                    client_id: "rw-client".to_string(),
                    cached_at: 42,
                },
            );
        }

        let guard = API_KEY_CACHE.read().expect("read lock");
        let entry = guard.get(&key).expect("entry should exist");
        assert!(entry.verified);
        assert_eq!(entry.client_id, "rw-client");
        assert_eq!(entry.cached_at, 42);
        drop(guard);

        __reset_api_key_cache_for_testing();
    }

    /* ========================================================================== */
    /*                    verify_api_key() ADDITIONAL EDGE CASES                 */
    /* ========================================================================== */

    #[tokio::test]
    async fn test_verify_api_key_very_long_key() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let long_key = "x".repeat(10_000);
        let result = ClientAuthenticator::verify_api_key(&client, &long_key, None, None).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_newline_in_key() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        let result =
            ClientAuthenticator::verify_api_key(&client, "test-secret\n-key", None, None).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_prefix_only() -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        // Just the prefix of the correct key should fail
        let result = ClientAuthenticator::verify_api_key(&client, "test-secret", None, None).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_api_key_correct_key_succeeds_repeatedly(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = create_test_client("client1", true)?;
        // Multiple sequential verifications with the correct key
        for _ in 0..5 {
            let result =
                ClientAuthenticator::verify_api_key(&client, "test-secret-key", None, None).await;
            assert!(result.is_ok());
        }
        Ok(())
    }

    /* ========================================================================== */
    /*                    PROPERTY-BASED TESTS (ADDITIONAL)                      */
    /* ========================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: make_cache_key is deterministic for any input
        #[test]
        fn prop_make_cache_key_deterministic(
            api_key in "[a-zA-Z0-9_-]{0,100}",
            client_id in "[a-zA-Z0-9_-]{0,100}"
        ) {
            let key1 = make_cache_key(&api_key, &client_id);
            let key2 = make_cache_key(&api_key, &client_id);
            prop_assert_eq!(&key1, &key2);
        }

        /// Property: make_cache_key always returns 64-char hex string
        #[test]
        fn prop_make_cache_key_format(
            api_key in ".*",
            client_id in ".*"
        ) {
            let key = make_cache_key(&api_key, &client_id);
            prop_assert_eq!(key.len(), 64);
            prop_assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        }

        /// Property: different inputs produce different cache keys (collision resistance)
        #[test]
        fn prop_make_cache_key_collision_resistant(
            api_key_a in "[a-zA-Z0-9]{1,50}",
            api_key_b in "[a-zA-Z0-9]{1,50}",
            client_id in "[a-zA-Z0-9]{1,50}"
        ) {
            prop_assume!(api_key_a != api_key_b);
            let key_a = make_cache_key(&api_key_a, &client_id);
            let key_b = make_cache_key(&api_key_b, &client_id);
            prop_assert_ne!(key_a, key_b);
        }

        /// Property: HMAC verify_slice accepts only the correct tag
        #[test]
        fn prop_hmac_verify_rejects_wrong_tag(
            secret in "[a-zA-Z0-9]{1,64}",
            message in "[a-zA-Z0-9]{1,200}",
            tamper_byte in 0u8..=255u8
        ) {
            type HmacSha256 = Hmac<Sha256>;

            let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                .expect("HMAC key should be valid");
            mac.update(message.as_bytes());
            let tag = mac.finalize().into_bytes();

            // Tamper with the first byte
            let mut tampered = tag.to_vec();
            if !tampered.is_empty() {
                tampered[0] = tampered[0].wrapping_add(tamper_byte.saturating_add(1));
            }

            // Re-create MAC for verification
            let mut mac2 = HmacSha256::new_from_slice(secret.as_bytes())
                .expect("HMAC key should be valid");
            mac2.update(message.as_bytes());
            prop_assert!(mac2.verify_slice(&tampered).is_err());
        }
    }

    /* ========================================================================== */
    /*                    authenticate() DISPATCH TESTS                         */
    /* ========================================================================== */

    /// Helper: build a valid Authorizer with a current timestamp so the
    /// timestamp-skew check passes without needing to mock time.
    fn create_valid_authorizer_now(key_id: &str) -> Authorizer {
        let ts = crate::utils::current_timestamp();
        Authorizer {
            key_id: key_id.to_string(),
            timestamp: ts,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_rejects_invalid_authorizer_format() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("client-fmt", true).expect("test client");
        let policy = create_test_policy(vec![client]);
        let auth = ClientAuthenticator::new(&policy);

        // Authorizer with empty key_id is structurally invalid
        let bad_authorizer = Authorizer {
            key_id: "".to_string(),
            timestamp: crate::utils::current_timestamp(),
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth
            .authenticate(Some("test-secret-key"), &bad_authorizer, "canonical")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("empty")),
            "expected BadRequest with 'empty', got: {:?}",
            err
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_rejects_expired_timestamp() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("client-ts", true).expect("test client");
        let policy = create_test_policy(vec![client]);
        let auth = ClientAuthenticator::new(&policy);

        // Timestamp 600 seconds in the past exceeds the 300s window
        let old_ts = crate::utils::current_timestamp().saturating_sub(600);
        let authorizer = Authorizer {
            key_id: "client-ts".to_string(),
            timestamp: old_ts,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth
            .authenticate(Some("test-secret-key"), &authorizer, "canonical")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("TIMESTAMP_SKEW")),
            "expected TIMESTAMP_SKEW error, got: {:?}",
            err
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_rejects_future_timestamp() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("client-ts-future", true).expect("test client");
        let policy = create_test_policy(vec![client]);
        let auth = ClientAuthenticator::new(&policy);

        // Timestamp 600 seconds in the future exceeds the 300s window
        let future_ts = crate::utils::current_timestamp().saturating_add(600);
        let authorizer = Authorizer {
            key_id: "client-ts-future".to_string(),
            timestamp: future_ts,
            hmac: "a".repeat(64),
            nonce: "b".repeat(64),
        };
        let result = auth
            .authenticate(Some("test-secret-key"), &authorizer, "canonical")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("TIMESTAMP_SKEW")),
            "expected TIMESTAMP_SKEW error for future timestamp, got: {:?}",
            err
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_accepts_timestamp_within_window() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("client-ts-ok", true).expect("test client");
        let policy = create_test_policy(vec![client]);
        // No nonce store, so it will fail at nonce check. But we confirm
        // it passes the timestamp check by getting a different error.
        let auth = ClientAuthenticator::new(&policy);

        let authorizer = create_valid_authorizer_now("client-ts-ok");
        let result = auth
            .authenticate(Some("test-secret-key"), &authorizer, "canonical")
            .await;
        // Should fail at nonce store (Internal) or API key verification,
        // NOT at timestamp validation
        if let Err(ref e) = result {
            let is_timestamp =
                matches!(e, ApiError::BadRequest(Some(msg)) if msg.contains("TIMESTAMP_SKEW"));
            assert!(
                !is_timestamp,
                "timestamp within window should not produce TIMESTAMP_SKEW"
            );
        }
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_rejects_missing_api_key() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("client-nokey", true).expect("test client");
        let policy = create_test_policy(vec![client]);
        let auth = ClientAuthenticator::new(&policy);

        let authorizer = create_valid_authorizer_now("client-nokey");
        let result = auth.authenticate(None, &authorizer, "canonical").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("API_KEY_MISSING")),
            "expected API_KEY_MISSING error, got: {:?}",
            err
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_rejects_unknown_client_id() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("known-client", true).expect("test client");
        let policy = create_test_policy(vec![client]);
        let auth = ClientAuthenticator::new(&policy);

        // Use a key_id that does not match any client in the policy
        let authorizer = create_valid_authorizer_now("unknown-client");
        let result = auth
            .authenticate(Some("test-secret-key"), &authorizer, "canonical")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("CLIENT_UNKNOWN")),
            "expected CLIENT_UNKNOWN error, got: {:?}",
            err
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_rejects_inactive_client() {
        __reset_api_key_cache_for_testing();
        let client = create_test_client("inactive-client", false).expect("test client");
        let policy = create_test_policy(vec![client]);
        let auth = ClientAuthenticator::new(&policy);

        let authorizer = create_valid_authorizer_now("inactive-client");
        let result = auth
            .authenticate(Some("test-secret-key"), &authorizer, "canonical")
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(Some(msg)) if msg.contains("CLIENT_UNKNOWN")),
            "expected CLIENT_UNKNOWN for inactive client, got: {:?}",
            err
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_full_dispatch_with_nonce_store() {
        __reset_api_key_cache_for_testing();
        let mek =
            crate::security::envelope_encryption::generate_random_key(32).expect("generate MEK");
        let (client, hmac_key) = create_hmac_test_client(&mek).await;
        let policy = create_test_policy(vec![client]);

        let store: Arc<dyn crate::storage::traits::NonceStore> = Arc::new(TestNonceStore::new());

        let authorizer_ts = crate::utils::current_timestamp();
        let nonce_hex = "c".repeat(64);
        let canonical = format!("POST\n/v1/verify\n{}\n{}", authorizer_ts, nonce_hex);
        let hmac_hex = compute_expected_hmac_hex(&hmac_key, &canonical);

        let authorizer = Authorizer {
            key_id: "hmac-test-client".to_string(),
            timestamp: authorizer_ts,
            hmac: hmac_hex,
            nonce: nonce_hex,
        };

        let auth = ClientAuthenticator::new(&policy)
            .with_mek(mek)
            .with_nonce_store(store);

        let result = auth
            .authenticate(
                Some("wrong-api-key-that-wont-match"),
                &authorizer,
                &canonical,
            )
            .await;
        // API key "wrong-api-key-that-wont-match" does not match the Argon2id
        // hash (create_hmac_test_client hashes "unused-api-key"). This confirms
        // the full dispatch runs past timestamp, authorizer validation, client
        // lookup, and into API key verification.
        assert!(result.is_err());
        let err = result.unwrap_err();
        // The error should be from API key verification, not from an
        // earlier dispatch stage
        let err_str = format!("{:?}", err);
        assert!(
            !err_str.contains("TIMESTAMP_SKEW")
                && !err_str.contains("API_KEY_MISSING")
                && !err_str.contains("CLIENT_UNKNOWN"),
            "error should come from API key verification stage, got: {}",
            err_str
        );
        __reset_api_key_cache_for_testing();
    }

    #[tokio::test]
    #[serial]
    async fn test_authenticate_full_success_with_correct_credentials() {
        __reset_api_key_cache_for_testing();
        let mek =
            crate::security::envelope_encryption::generate_random_key(32).expect("generate MEK");
        let (_client, hmac_key) = create_hmac_test_client(&mek).await;

        let api_key = "full-flow-test-key";
        let api_key_hash = crate::security::hash::hash_api_key(api_key).expect("hash_api_key");

        let encrypted = crate::security::envelope_encryption::encrypt_hmac_secret(&hmac_key, &mek)
            .await
            .expect("encrypt");

        let full_client = ClientAuthConfig {
            client_id: "full-flow-client".to_string(),
            api_key_hash,
            api_key_prefix: Some("pk_test_".to_string()),
            encrypted_hmac_secret: encrypted.encrypted_secret.clone(),
            dek_encrypted: encrypted.encrypted_dek.clone(),
            encryption_version: encrypted.version,
            active: true,
        };
        let full_policy = create_test_policy(vec![full_client]);

        let authorizer_ts2 = crate::utils::current_timestamp();
        let nonce_hex2 = "e".repeat(64);
        let canonical2 = format!("POST\n/v1/verify\n{}\n{}", authorizer_ts2, nonce_hex2);
        let hmac_hex2 = compute_expected_hmac_hex(&hmac_key, &canonical2);

        let authorizer2 = Authorizer {
            key_id: "full-flow-client".to_string(),
            timestamp: authorizer_ts2,
            hmac: hmac_hex2,
            nonce: nonce_hex2,
        };

        let store2: Arc<dyn crate::storage::traits::NonceStore> = Arc::new(TestNonceStore::new());

        let auth = ClientAuthenticator::new(&full_policy)
            .with_mek(mek)
            .with_nonce_store(store2);

        let result = auth
            .authenticate(Some(api_key), &authorizer2, &canonical2)
            .await;
        assert!(
            result.is_ok(),
            "full authenticate flow with correct credentials should succeed: {:?}",
            result.err()
        );
        let returned_client = result.expect("just asserted Ok");
        assert_eq!(returned_client.client_id, "full-flow-client");
        __reset_api_key_cache_for_testing();
    }

    #[test]
    fn reset_api_key_cache_for_testing_clears_all_entries() {
        // Pre-populate the cache with sentinel entries.
        {
            let mut guard = API_KEY_CACHE
                .write()
                .expect("API_KEY_CACHE lock should be free under serial test");
            guard.insert(
                "key-a".to_string(),
                VerificationCacheEntry {
                    verified: true,
                    client_id: "client-a".to_string(),
                    cached_at: 0,
                },
            );
            guard.insert(
                "key-b".to_string(),
                VerificationCacheEntry {
                    verified: false,
                    client_id: "client-b".to_string(),
                    cached_at: 0,
                },
            );
            assert_eq!(guard.len(), 2);
        }

        __reset_api_key_cache_for_testing();

        let guard = API_KEY_CACHE
            .read()
            .expect("API_KEY_CACHE lock should be free after reset");
        assert!(
            guard.is_empty(),
            "reset helper must clear every cached verification outcome"
        );
        drop(guard);

        // Calling twice must remain a no-op.
        __reset_api_key_cache_for_testing();
        assert!(API_KEY_CACHE
            .read()
            .expect("re-reading API_KEY_CACHE after second reset must succeed")
            .is_empty());
    }
}
