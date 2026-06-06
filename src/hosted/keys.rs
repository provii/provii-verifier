// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Public Key Management Module
//!
//! This module provides secure management of API public/secret key pairs with:
//! - Cryptographically secure key generation
//! - KV-backed storage with AES-256-GCM encryption (HOSTED_MEK)
//! - Origin whitelist validation (exact match and wildcard subdomains)
//! - Key lifecycle management (creation, retrieval, update, soft deletion)
//!
//! ## Key Format
//!
//! - Public keys: `pk_live_{32_hex_chars}` or `pk_test_{32_hex_chars}`
//! - Secret keys: `sk_live_{32_hex_chars}` or `sk_test_{32_hex_chars}`
//!
//! ## KV Storage Schema
//!
//! Public key entries are stored as AES-256-GCM encrypted JSON blobs,
//! encrypted with the `HOSTED_MEK` and bound to the AAD string
//! `provii-verifier:public_key_data:v1`. The KV value is a base64url-encoded
//! wire format: `IV (12 bytes) || Ciphertext || Auth Tag (16 bytes)`.
//!
//! The plaintext JSON structure before encryption:
//! ```json
//! {
//!   "id": "pk_live_...",
//!   "secret_key": "sk_live_...",
//!   "allowed_origins": ["https://example.com", "https://*.example.org"],
//!   "rate_limit_override": null,
//!   "enabled": true,
//!   "created_at": 1234567890,
//!   "updated_at": 1234567890,
//!   "last_used_at": null,
//!   "metadata": {}
//! }
//! ```
#![forbid(unsafe_code)]

use crate::hosted::encryption::{decrypt_with_mek, get_mek_from_secrets};
use crate::hosted::types::config::PublicKeyInfo;
use crate::hosted::types::errors::HostedApiError as ApiError;
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use worker::{kv::KvStore, Env};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Key pair type (live or test)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// Production keys (start with pk_live_ / sk_live_)
    Live,
    /// Test keys (start with pk_test_ / sk_test_)
    #[default]
    Test,
}

/// Public/secret key pair.
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// Implements `ZeroizeOnDrop` to ensure `secret_key` is securely cleared from memory
/// when the `KeyPair` is dropped. Debug output redacts `secret_key` to prevent
/// accidental logging.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    /// Public key identifier (not sensitive, skip zeroization)
    #[zeroize(skip)]
    pub public_key: String,
    /// Secret key (never logged or exposed after creation)
    /// This field will be zeroized when the KeyPair is dropped
    pub secret_key: String,
    /// Key type (live or test)
    #[zeroize(skip)]
    pub key_type: KeyType,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .field("key_type", &self.key_type)
            .finish()
    }
}

/// Public key data stored in KV.
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// Implements `ZeroizeOnDrop` to ensure `secret_key` is securely cleared from memory
/// when the `PublicKeyData` is dropped. Debug output redacts `secret_key` to prevent
/// accidental logging.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PublicKeyData {
    /// Public key ID
    #[zeroize(skip)]
    pub id: String,

    /// Secret key (stored securely, never returned in API responses)
    /// This field will be zeroized when the PublicKeyData is dropped
    #[serde(skip_serializing)]
    pub secret_key: String,

    /// Organisation ID that owns this key (links to verifier organisation)
    /// This ties the key to a customer in the admin portal
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub organization_id: Option<String>,

    /// Human-readable name for this key (e.g., "Production API Key")
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub name: Option<String>,

    /// Allowed origins (supports wildcards like https://*.example.com)
    #[zeroize(skip)]
    pub allowed_origins: Vec<String>,

    /// Optional rate limit override (per-key custom limits)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub rate_limit_override: Option<RateLimitOverride>,

    /// Whether this key is enabled
    #[zeroize(skip)]
    pub enabled: bool,

    /// When this key was created (Unix timestamp)
    #[zeroize(skip)]
    pub created_at: u64,

    /// When this key was last updated (Unix timestamp)
    #[zeroize(skip)]
    pub updated_at: u64,

    /// When this key was last used (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub last_used_at: Option<u64>,

    /// Custom metadata (for customer tracking, billing, etc.)
    #[serde(default)]
    #[zeroize(skip)]
    pub metadata: serde_json::Value,
}

impl std::fmt::Debug for PublicKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyData")
            .field("id", &self.id)
            .field("secret_key", &"[REDACTED]")
            .field("organization_id", &self.organization_id)
            .field("name", &self.name)
            .field("allowed_origins", &self.allowed_origins)
            .field("rate_limit_override", &self.rate_limit_override)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_used_at", &self.last_used_at)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Per-key rate limit override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitOverride {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration in seconds
    pub window_seconds: u32,
}

/// Associated Authenticated Data for public key data encryption.
///
/// SECURITY: Binds ciphertext to the public_key_data context so that an encrypted
/// value from one field (e.g. a session blob) cannot be spliced into the key store.
/// This constant MUST match the AAD used by provii-management when writing encrypted
/// key data to the same KV namespace.
pub const PUBLIC_KEY_DATA_AAD: &[u8] = b"provii-verifier:public_key_data:v1";

/// Key management operations
pub struct KeyManager<'a> {
    kv: KvStore,
    env: &'a Env,
}

impl<'a> KeyManager<'a> {
    /// Create a new key manager with KV store
    pub fn new(env: &'a Env) -> Result<Self, ApiError> {
        let kv = env
            .kv("HOSTED_PUBLIC_KEYS")
            .map_err(|e| ApiError::internal(format!("Failed to access KV store: {}", e)))?;

        Ok(Self { kv, env })
    }

    /// SECURITY: Generate a new cryptographically secure key pair.
    ///
    /// Uses `getrandom` for 32 bytes of entropy per key (public + secret).
    /// Raw byte arrays are wrapped in `Zeroizing` so they are cleared from
    /// memory once hex encoding is complete (VA-HKE-002).
    pub fn generate_key_pair(key_type: KeyType) -> Result<KeyPair, ApiError> {
        // Generate 32 random bytes for each key.
        // VA-HKE-002: Wrap in Zeroizing so raw bytes are cleared after hex encoding.
        let mut public_bytes = zeroize::Zeroizing::new([0u8; 32]);
        let mut secret_bytes = zeroize::Zeroizing::new([0u8; 32]);

        getrandom(&mut *public_bytes)
            .map_err(|e| ApiError::internal(format!("Failed to generate random bytes: {}", e)))?;

        getrandom(&mut *secret_bytes)
            .map_err(|e| ApiError::internal(format!("Failed to generate random bytes: {}", e)))?;

        // Convert to hex. The hex strings for the secret key are also wrapped
        // in Zeroizing so the intermediate representation is cleared on drop.
        let public_hex = hex::encode(*public_bytes);
        let secret_hex = zeroize::Zeroizing::new(hex::encode(*secret_bytes));

        // Format with appropriate prefix
        let prefix = match key_type {
            KeyType::Live => ("pk_live_", "sk_live_"),
            KeyType::Test => ("pk_test_", "sk_test_"),
        };

        Ok(KeyPair {
            public_key: format!("{}{}", prefix.0, public_hex),
            secret_key: format!("{}{}", prefix.1, &*secret_hex),
            key_type,
        })
    }

    /// Get public key data from KV, decrypting with the MEK.
    ///
    /// # Security
    ///
    /// The KV value is AES-256-GCM encrypted with the HOSTED_MEK and bound to
    /// [`PUBLIC_KEY_DATA_AAD`]. If the MEK is unavailable the operation fails
    /// with 503 Service Unavailable. If decryption fails the operation fails
    /// with 500 Internal Server Error. There is no plaintext fallback.
    pub async fn get_key(&self, public_key: &str) -> Result<PublicKeyData, ApiError> {
        // Validate key format
        validate_key_format(public_key)?;

        // Fetch from KV
        let encrypted_value = self
            .kv
            .get(public_key)
            .text()
            .await
            .map_err(|e| ApiError::internal(format!("Failed to fetch key from KV: {}", e)))?;

        let encrypted_value = encrypted_value
            .ok_or_else(|| ApiError::unauthorized("Invalid or unknown public key"))?;

        // Retrieve the MEK. Without it, encryption at rest cannot be enforced.
        let mek = get_mek_from_secrets(self.env).await.map_err(|_e| {
            #[cfg(target_arch = "wasm32")]
            worker::console_error!(
                "[KeyManager] HOSTED_MEK unavailable, cannot decrypt key {}",
                public_key,
            );
            ApiError::service_unavailable("Encryption key unavailable")
        })?;

        // Decrypt the KV value. Failure means the entry is corrupt or was
        // written with a different key.
        let decrypted_json = decrypt_with_mek(&mek, &encrypted_value, PUBLIC_KEY_DATA_AAD)
            .map_err(|_e| {
                #[cfg(target_arch = "wasm32")]
                worker::console_error!(
                    "[KeyManager] Decryption failed for key {}: re-provision via provii-management",
                    public_key,
                );
                ApiError::internal("Failed to decrypt key data")
            })?;

        let key_data: PublicKeyData = serde_json::from_str(&decrypted_json).map_err(|e| {
            ApiError::internal(format!("Failed to parse decrypted key data: {}", e))
        })?;

        Ok(key_data)
    }

    /// Validate origin against allowed origins list
    pub fn validate_origin(&self, key_data: &PublicKeyData, origin: &str) -> Result<(), ApiError> {
        for allowed in &key_data.allowed_origins {
            if match_origin(allowed, origin) {
                return Ok(());
            }
        }

        Err(ApiError::forbidden(format!(
            "Origin '{}' is not allowed for this key",
            origin
        )))
    }
}

/// Validate that a public key has the correct format
pub fn validate_key_format(key: &str) -> Result<(), ApiError> {
    // Must start with pk_live_ or pk_test_
    if !key.starts_with("pk_live_") && !key.starts_with("pk_test_") {
        return Err(ApiError::unauthorized(
            "Invalid key format: must start with pk_live_ or pk_test_",
        ));
    }

    // Both pk_live_ and pk_test_ are 8 chars; extract the hex suffix.
    let hex_part = key.get(8..).unwrap_or("");

    // Must be exactly 64 hex characters (32 bytes)
    if hex_part.len() != 64 {
        return Err(ApiError::unauthorized(
            "Invalid key format: must be 32 bytes (64 hex characters)",
        ));
    }

    // Must be valid hex
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::unauthorized(
            "Invalid key format: must contain only hexadecimal characters",
        ));
    }

    Ok(())
}

/// Validate origin pattern is acceptable
pub fn validate_origin_pattern(pattern: &str) -> Result<(), ApiError> {
    // Reject dangerous patterns
    if pattern == "*" || pattern == "http://*" || pattern == "https://*" {
        return Err(ApiError::invalid_request(
            "Invalid origin pattern: wildcard-only patterns not allowed",
        ));
    }

    // Must start with http:// or https://
    if !pattern.starts_with("http://") && !pattern.starts_with("https://") {
        return Err(ApiError::invalid_request(
            "Invalid origin pattern: must start with http:// or https://",
        ));
    }

    // If contains wildcard, validate it's in subdomain position
    if pattern.contains('*') {
        // Must be in format https://*.example.com
        let suffix = match pattern.split_once("*.") {
            Some((_prefix, s)) => s,
            None => {
                return Err(ApiError::invalid_request(
                    "Invalid wildcard pattern: must be in format https://*.domain.com",
                ));
            }
        };

        // Must have a dot separator after wildcard
        if !suffix.contains('.') {
            return Err(ApiError::invalid_request(
                "Invalid wildcard pattern: must have domain suffix after wildcard",
            ));
        }
    }

    Ok(())
}

/// Match an origin against a pattern (exact match or wildcard subdomain).
///
/// Delegates to the shared `origin_matches_pattern` which
/// enforces dot-boundary checking to prevent suffix attacks.
pub fn match_origin(pattern: &str, origin: &str) -> bool {
    crate::utils::origin::origin_matches_pattern(pattern, origin)
}

/// Convert PublicKeyData to PublicKeyInfo (for compatibility)
impl From<PublicKeyData> for PublicKeyInfo {
    fn from(data: PublicKeyData) -> Self {
        Self {
            public_key: data.id.clone(),
            secret_key: data.secret_key.clone(),
            allowed_origins: data.allowed_origins.clone(),
            active: data.enabled,
            created_at: data.created_at,
            last_used_at: data.last_used_at,
            metadata: Some(data.metadata.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_key_format_valid() {
        assert!(validate_key_format(
            "pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());

        assert!(validate_key_format(
            "pk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_ok());
    }

    #[test]
    fn test_validate_key_format_invalid() {
        // Wrong prefix
        assert!(validate_key_format("sk_live_123").is_err());

        // Too short
        assert!(validate_key_format("pk_live_123").is_err());

        // Invalid hex
        assert!(validate_key_format(
            "pk_live_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        )
        .is_err());
    }

    #[test]
    fn test_validate_origin_pattern() {
        // Valid patterns
        assert!(validate_origin_pattern("https://example.com").is_ok());
        assert!(validate_origin_pattern("https://*.example.com").is_ok());
        assert!(validate_origin_pattern("http://localhost:3000").is_ok());

        // Invalid patterns
        assert!(validate_origin_pattern("*").is_err());
        assert!(validate_origin_pattern("https://*").is_err());
        assert!(validate_origin_pattern("example.com").is_err());
        assert!(validate_origin_pattern("https://*").is_err());
    }

    #[test]
    fn test_match_origin() {
        // Exact match
        assert!(match_origin("https://example.com", "https://example.com"));

        // Wildcard match
        assert!(match_origin(
            "https://*.example.com",
            "https://sub.example.com"
        ));
        assert!(match_origin(
            "https://*.example.com",
            "https://deep.sub.example.com"
        ));

        // No match
        assert!(!match_origin("https://example.com", "https://evil.com"));
        assert!(!match_origin(
            "https://*.example.com",
            "https://example.com"
        ));
        assert!(!match_origin("https://example.com", "http://example.com"));
    }

    #[test]
    fn test_constant_time_compare() {
        use subtle::ConstantTimeEq;
        assert!(bool::from(b"secret".ct_eq(b"secret")));
        assert!(!bool::from(b"secret".ct_eq(b"Secret")));
        assert!(!bool::from(b"secret".as_slice().ct_eq(b"secre".as_slice())));
        assert!(!bool::from(
            b"secret".as_slice().ct_eq(b"secrets".as_slice())
        ));
    }

    #[test]
    fn test_generate_key_pair() -> Result<(), Box<dyn std::error::Error>> {
        let pair1 = KeyManager::generate_key_pair(KeyType::Live)?;
        let pair2 = KeyManager::generate_key_pair(KeyType::Live)?;

        // Should be different
        assert_ne!(pair1.public_key, pair2.public_key);
        assert_ne!(pair1.secret_key, pair2.secret_key);

        // Should have correct format
        assert!(pair1.public_key.starts_with("pk_live_"));
        assert!(pair1.secret_key.starts_with("sk_live_"));

        // Should be correct length
        assert_eq!(pair1.public_key.len(), 8 + 64); // prefix + 64 hex chars
        assert_eq!(pair1.secret_key.len(), 8 + 64);
        Ok(())
    }

    #[test]
    fn test_generate_key_pair_test_mode() -> Result<(), Box<dyn std::error::Error>> {
        let pair = KeyManager::generate_key_pair(KeyType::Test)?;

        assert!(pair.public_key.starts_with("pk_test_"));
        assert!(pair.secret_key.starts_with("sk_test_"));
        Ok(())
    }

    /* ========================================================================== */
    /*      SANDBOX ORIGIN BYPASS TESTS (pk_test_* skip origin validation)       */
    /* ========================================================================== */

    /// Helper: returns true when the origin check should be skipped.
    /// Mirrors the condition in `hosted/endpoints/challenge.rs`.
    fn should_skip_origin_check(environment: &str, public_key: &str) -> bool {
        environment == "sandbox" && public_key.starts_with("pk_test_")
    }

    #[test]
    fn test_sandbox_pk_test_skips_origin_check() {
        let pk = "pk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(should_skip_origin_check("sandbox", pk));
    }

    #[test]
    fn test_production_pk_live_enforces_origin_check() {
        let pk = "pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!should_skip_origin_check("production", pk));
    }

    #[test]
    fn test_production_pk_test_still_enforces_origin_check() {
        // pk_test_* in production must NOT skip the origin check.
        let pk = "pk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!should_skip_origin_check("production", pk));
    }

    #[test]
    fn test_sandbox_pk_live_still_enforces_origin_check() {
        // pk_live_* in sandbox must NOT skip the origin check.
        let pk = "pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!should_skip_origin_check("sandbox", pk));
    }

    #[test]
    fn test_sandbox_bypass_with_mismatched_origin() {
        // A pk_test_* key in sandbox should allow any origin, even one not
        // in the key's allowed_origins list.
        let pk = "pk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let environment = "sandbox";
        let allowed_origins = ["https://registered.example.com".to_string()];
        let request_origin = "http://localhost:3000";

        let skip = should_skip_origin_check(environment, pk);
        assert!(skip, "sandbox pk_test_* must skip origin check");

        // The origin does NOT match the allowed list
        let origin_in_list = allowed_origins.iter().any(|o| o == request_origin);
        assert!(
            !origin_in_list,
            "http://localhost:3000 is not in allowed_origins"
        );

        // But because skip is true, the request would proceed.
        // This is the sandbox DX improvement.
    }

    #[test]
    fn test_production_pk_live_rejects_mismatched_origin() {
        // A pk_live_* key in production must reject unregistered origins.
        let pk = "pk_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let environment = "production";

        let skip = should_skip_origin_check(environment, pk);
        assert!(!skip, "production pk_live_* must NOT skip origin check");

        // The caller would proceed to validate_origin and get rejected.
    }

    #[test]
    fn test_sandbox_bypass_development_environment() {
        // Only "sandbox" triggers the bypass, not "development" or "test".
        let pk = "pk_test_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!should_skip_origin_check("development", pk));
        assert!(!should_skip_origin_check("test", pk));
        assert!(!should_skip_origin_check("", pk));
    }

    #[test]
    fn test_validate_origin_rejects_mismatched_for_live_keys() {
        // Verify that validate_origin itself rejects when the origin is not
        // in allowed_origins. This is the enforcement path for pk_live_*.
        let key_data = PublicKeyData {
            id: "pk_live_aabbccdd".to_string(),
            secret_key: "sk_live_aabbccdd".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec!["https://registered.example.com".to_string()],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({}),
        };

        // match_origin is the core matching function used by validate_origin
        let unregistered = "http://localhost:3000";
        let matches = key_data
            .allowed_origins
            .iter()
            .any(|allowed| match_origin(allowed, unregistered));
        assert!(!matches, "unregistered origin must not match allowed list");

        let registered = "https://registered.example.com";
        let matches = key_data
            .allowed_origins
            .iter()
            .any(|allowed| match_origin(allowed, registered));
        assert!(matches, "registered origin must match allowed list");
    }

    // ======================================================================
    // validate_key_format: additional edge cases
    // ======================================================================

    #[test]
    fn test_validate_key_format_empty_string() {
        assert!(validate_key_format("").is_err());
    }

    #[test]
    fn test_validate_key_format_just_prefix() {
        assert!(validate_key_format("pk_live_").is_err());
    }

    #[test]
    fn test_validate_key_format_short_hex() {
        assert!(validate_key_format("pk_live_0123456789abcdef").is_err());
    }

    #[test]
    fn test_validate_key_format_too_long_hex() {
        let hex = "a".repeat(65);
        let key = format!("pk_live_{}", hex);
        assert!(validate_key_format(&key).is_err());
    }

    #[test]
    fn test_validate_key_format_uppercase_hex_is_valid() {
        let key = format!("pk_live_{}", "A".repeat(64));
        assert!(validate_key_format(&key).is_ok());
    }

    #[test]
    fn test_validate_key_format_mixed_case_hex() {
        let key = format!(
            "pk_test_{}",
            "aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123456789aAbBcCdDeEfF01234567"
        );
        assert!(validate_key_format(&key).is_ok());
    }

    #[test]
    fn test_validate_key_format_sk_prefix_rejected() {
        let key = format!("sk_live_{}", "a".repeat(64));
        assert!(validate_key_format(&key).is_err());
    }

    #[test]
    fn test_validate_key_format_non_hex_chars() {
        let key = format!("pk_live_{}", "g".repeat(64)); // 'g' is not hex
        assert!(validate_key_format(&key).is_err());
    }

    #[test]
    fn test_validate_key_format_special_chars_in_hex() {
        let key = "pk_live_012345678!abcdef0123456789abcdef0123456789abcdef0123456789ab";
        assert!(validate_key_format(key).is_err());
    }

    // ======================================================================
    // validate_origin_pattern: additional edge cases
    // ======================================================================

    #[test]
    fn test_validate_origin_pattern_http_wildcard_rejected() {
        assert!(validate_origin_pattern("http://*").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_bare_wildcard_rejected() {
        assert!(validate_origin_pattern("*").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_no_scheme() {
        assert!(validate_origin_pattern("example.com").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_ftp_scheme_rejected() {
        assert!(validate_origin_pattern("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_wildcard_without_dot() {
        // https://*example.com is not a valid wildcard pattern
        assert!(validate_origin_pattern("https://*example.com").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_wildcard_tld_only() {
        // https://*.com has no dot in suffix after wildcard removal
        assert!(validate_origin_pattern("https://*.com").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_valid_wildcard_subdomain() {
        assert!(validate_origin_pattern("https://*.example.com").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_valid_wildcard_deep_subdomain() {
        assert!(validate_origin_pattern("https://*.deep.example.com").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_http_localhost_valid() {
        assert!(validate_origin_pattern("http://localhost").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_https_with_path() {
        // Patterns with paths are technically accepted (no path validation)
        assert!(validate_origin_pattern("https://example.com/path").is_ok());
    }

    // ======================================================================
    // match_origin: additional edge cases
    // ======================================================================

    #[test]
    fn test_match_origin_empty_origin() {
        assert!(!match_origin("https://example.com", ""));
    }

    #[test]
    fn test_match_origin_empty_pattern() {
        assert!(!match_origin("", "https://example.com"));
    }

    #[test]
    fn test_match_origin_both_empty() {
        // Both empty returns false (empty pattern/origin always rejected)
        assert!(!match_origin("", ""));
    }

    #[test]
    fn test_match_origin_case_insensitive() {
        // Hostname comparison is case-insensitive via to_ascii_lowercase
        assert!(match_origin("https://Example.com", "https://example.com"));
    }

    #[test]
    fn test_match_origin_trailing_slash_matches() {
        // URL parser normalises both to path "/", so they match
        assert!(match_origin("https://example.com", "https://example.com/"));
    }

    #[test]
    fn test_match_origin_default_port_normalised() {
        // Url::parse normalises :443 as the default https port, so port() returns None for both
        assert!(match_origin(
            "https://example.com:443",
            "https://example.com"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_suffix_attack_prevention() {
        // https://evilexample.com should NOT match https://*.example.com
        assert!(!match_origin(
            "https://*.example.com",
            "https://evilexample.com"
        ));
    }

    // ======================================================================
    // KeyPair: generation, Debug, ZeroizeOnDrop
    // ======================================================================

    #[test]
    fn test_generate_key_pair_live_format() -> Result<(), Box<dyn std::error::Error>> {
        let pair = KeyManager::generate_key_pair(KeyType::Live)?;
        assert!(pair.public_key.starts_with("pk_live_"));
        assert!(pair.secret_key.starts_with("sk_live_"));
        assert_eq!(pair.public_key.len(), 72); // 8 prefix + 64 hex
        assert_eq!(pair.secret_key.len(), 72);
        assert_eq!(pair.key_type, KeyType::Live);
        Ok(())
    }

    #[test]
    fn test_generate_key_pair_test_format() -> Result<(), Box<dyn std::error::Error>> {
        let pair = KeyManager::generate_key_pair(KeyType::Test)?;
        assert!(pair.public_key.starts_with("pk_test_"));
        assert!(pair.secret_key.starts_with("sk_test_"));
        assert_eq!(pair.key_type, KeyType::Test);
        Ok(())
    }

    #[test]
    fn test_generate_key_pair_uniqueness() -> Result<(), Box<dyn std::error::Error>> {
        let pairs: Vec<_> = (0..5)
            .map(|_| KeyManager::generate_key_pair(KeyType::Live).unwrap())
            .collect();
        // All public keys should be unique
        for i in 0..pairs.len() {
            for j in (i + 1)..pairs.len() {
                assert_ne!(pairs[i].public_key, pairs[j].public_key);
                assert_ne!(pairs[i].secret_key, pairs[j].secret_key);
            }
        }
        Ok(())
    }

    #[test]
    fn test_key_pair_debug_redacts_secret() {
        let pair = KeyManager::generate_key_pair(KeyType::Live).unwrap();
        let dbg = format!("{:?}", pair);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("sk_live_"));
        assert!(dbg.contains("pk_live_"));
    }

    #[test]
    fn test_key_pair_clone() {
        let pair = KeyManager::generate_key_pair(KeyType::Test).unwrap();
        let cloned = pair.clone();
        assert_eq!(pair.public_key, cloned.public_key);
        assert_eq!(pair.secret_key, cloned.secret_key);
        assert_eq!(pair.key_type, cloned.key_type);
    }

    // ======================================================================
    // KeyType serialisation
    // ======================================================================

    #[test]
    fn test_key_type_default_is_test() {
        assert_eq!(KeyType::default(), KeyType::Test);
    }

    #[test]
    fn test_key_type_serialize() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(serde_json::to_string(&KeyType::Live)?, r#""live""#);
        assert_eq!(serde_json::to_string(&KeyType::Test)?, r#""test""#);
        Ok(())
    }

    #[test]
    fn test_key_type_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let live: KeyType = serde_json::from_str(r#""live""#)?;
        assert_eq!(live, KeyType::Live);
        let test: KeyType = serde_json::from_str(r#""test""#)?;
        assert_eq!(test, KeyType::Test);
        Ok(())
    }

    #[test]
    fn test_key_type_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        for kt in [KeyType::Live, KeyType::Test] {
            let json = serde_json::to_string(&kt)?;
            let decoded: KeyType = serde_json::from_str(&json)?;
            assert_eq!(decoded, kt);
        }
        Ok(())
    }

    // ======================================================================
    // PublicKeyData: serialisation and Debug
    // ======================================================================

    #[test]
    fn test_public_key_data_debug_redacts_secret_key() {
        let data = PublicKeyData {
            id: "pk_test_abc".to_string(),
            secret_key: "sk_test_secret_value".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec![],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({}),
        };
        let dbg = format!("{:?}", data);
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("sk_test_secret_value"));
    }

    #[test]
    fn test_public_key_data_serialise_skips_secret_key() -> Result<(), Box<dyn std::error::Error>> {
        let data = PublicKeyData {
            id: "pk_test_abc".to_string(),
            secret_key: "sk_test_secret_value".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec![],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({}),
        };
        let json = serde_json::to_string(&data)?;
        // #[serde(skip_serializing)] on secret_key
        assert!(!json.contains("sk_test_secret_value"));
        assert!(!json.contains("secret_key"));
        Ok(())
    }

    #[test]
    fn test_public_key_data_from_into_public_key_info() {
        let data = PublicKeyData {
            id: "pk_test_123".to_string(),
            secret_key: "sk_test_123".to_string(),
            organization_id: Some("org1".to_string()),
            name: Some("Test Key".to_string()),
            allowed_origins: vec!["https://example.com".to_string()],
            rate_limit_override: None,
            enabled: true,
            created_at: 1000,
            updated_at: 2000,
            last_used_at: Some(3000),
            metadata: serde_json::json!({"env": "test"}),
        };
        let info: PublicKeyInfo = data.into();
        assert_eq!(info.public_key, "pk_test_123");
        assert_eq!(info.secret_key, "sk_test_123");
        assert_eq!(
            info.allowed_origins,
            vec!["https://example.com".to_string()]
        );
        assert!(info.active);
        assert_eq!(info.created_at, 1000);
        assert_eq!(info.last_used_at, Some(3000));
    }

    // ======================================================================
    // RateLimitOverride
    // ======================================================================

    #[test]
    fn test_rate_limit_override_serialise() -> Result<(), Box<dyn std::error::Error>> {
        let r = RateLimitOverride {
            max_requests: 1000,
            window_seconds: 3600,
        };
        let json = serde_json::to_string(&r)?;
        assert!(json.contains("1000"));
        assert!(json.contains("3600"));
        Ok(())
    }

    #[test]
    fn test_rate_limit_override_deserialise() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"max_requests":500,"window_seconds":60}"#;
        let r: RateLimitOverride = serde_json::from_str(json)?;
        assert_eq!(r.max_requests, 500);
        assert_eq!(r.window_seconds, 60);
        Ok(())
    }

    // ======================================================================
    // PUBLIC_KEY_DATA_AAD constant
    // ======================================================================

    #[test]
    fn test_public_key_data_aad_is_set() {
        assert!(PUBLIC_KEY_DATA_AAD.starts_with(b"provii-verifier"));
    }

    #[test]
    fn test_public_key_data_aad_has_version_suffix() {
        let aad_str = std::str::from_utf8(PUBLIC_KEY_DATA_AAD).unwrap();
        assert!(aad_str.ends_with(":v1"));
    }

    // ======================================================================
    // validate_key_format: boundary and unicode edge cases
    // ======================================================================

    #[test]
    fn test_validate_key_format_exactly_64_hex_chars() {
        // Exactly 64 hex chars after prefix: valid
        let key = format!("pk_live_{}", "0".repeat(64));
        assert!(validate_key_format(&key).is_ok());
    }

    #[test]
    fn test_validate_key_format_63_hex_chars() {
        let key = format!("pk_live_{}", "0".repeat(63));
        assert!(validate_key_format(&key).is_err());
    }

    #[test]
    fn test_validate_key_format_whitespace_in_hex() {
        let key = format!("pk_live_{} {}", "a".repeat(32), "b".repeat(31));
        assert!(validate_key_format(&key).is_err());
    }

    #[test]
    fn test_validate_key_format_unicode_in_hex() {
        // Multi-byte unicode chars that happen to be 64 chars in display
        let key = "pk_live_\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}";
        assert!(validate_key_format(key).is_err());
    }

    #[test]
    fn test_validate_key_format_null_bytes_in_hex() {
        let key = format!("pk_live_{}", "a".repeat(64));
        // Replace one char with null byte
        let bytes = key.as_bytes().to_vec();
        let mut modified = bytes;
        modified[10] = 0;
        let key_str = String::from_utf8(modified);
        // If the null byte makes it non-hex, it should fail
        if let Ok(k) = key_str {
            assert!(validate_key_format(&k).is_err());
        }
    }

    #[test]
    fn test_validate_key_format_pk_test_exactly_valid() {
        let key = format!("pk_test_{}", "deadbeef".repeat(8));
        assert!(validate_key_format(&key).is_ok());
    }

    #[test]
    fn test_validate_key_format_sk_test_prefix_rejected() {
        let key = format!("sk_test_{}", "a".repeat(64));
        assert!(validate_key_format(&key).is_err());
    }

    #[test]
    fn test_validate_key_format_pk_live_with_trailing_newline() {
        let key = format!("pk_live_{}\n", "a".repeat(64));
        assert!(validate_key_format(&key).is_err());
    }

    // ======================================================================
    // validate_origin_pattern: additional edge cases
    // ======================================================================

    #[test]
    fn test_validate_origin_pattern_multiple_wildcards_accepted() {
        // split_once("*.") splits at the first "*.", leaving "*.example.com" as
        // the suffix. The suffix contains a dot, so validation passes.
        assert!(validate_origin_pattern("https://*.*.example.com").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_wildcard_in_path_position() {
        // "https://example.com/*" contains '*' but split_once("*.") finds no
        // "*." sequence, so the wildcard branch returns Err (invalid format).
        assert!(validate_origin_pattern("https://example.com/*").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_https_ip_literal() {
        // IP address is technically valid (no wildcard concerns)
        assert!(validate_origin_pattern("https://192.168.1.1").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_https_ip_with_port() {
        assert!(validate_origin_pattern("https://192.168.1.1:8443").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_empty_string() {
        assert!(validate_origin_pattern("").is_err());
    }

    #[test]
    fn test_validate_origin_pattern_just_scheme() {
        // No wildcard and starts with https://, so validation passes
        assert!(validate_origin_pattern("https://").is_ok());
    }

    #[test]
    fn test_validate_origin_pattern_ws_scheme_rejected() {
        assert!(validate_origin_pattern("ws://example.com").is_err());
    }

    // ======================================================================
    // match_origin: protocol and path edge cases
    // ======================================================================

    #[test]
    fn test_match_origin_wildcard_with_explicit_port() {
        assert!(match_origin(
            "https://*.example.com:8443",
            "https://app.example.com:8443"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_port_mismatch() {
        assert!(!match_origin(
            "https://*.example.com:8443",
            "https://app.example.com:9443"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_deep_sub_with_port() {
        assert!(match_origin(
            "https://*.example.com:8443",
            "https://a.b.c.example.com:8443"
        ));
    }

    #[test]
    fn test_match_origin_exact_with_default_port() {
        // https default port is 443: explicit :443 should match bare https
        assert!(match_origin(
            "https://example.com",
            "https://example.com:443"
        ));
    }

    #[test]
    fn test_match_origin_exact_case_insensitive_hostname() {
        assert!(match_origin("https://EXAMPLE.COM", "https://example.com"));
    }

    #[test]
    fn test_match_origin_wildcard_case_insensitive() {
        assert!(match_origin(
            "https://*.EXAMPLE.COM",
            "https://sub.example.com"
        ));
    }

    #[test]
    fn test_match_origin_wildcard_no_match_scheme_difference() {
        assert!(!match_origin(
            "https://*.example.com",
            "http://sub.example.com"
        ));
    }

    #[test]
    fn test_match_origin_exact_http_localhost_port() {
        assert!(match_origin(
            "http://localhost:3000",
            "http://localhost:3000"
        ));
    }

    #[test]
    fn test_match_origin_exact_http_localhost_different_port() {
        assert!(!match_origin(
            "http://localhost:3000",
            "http://localhost:4000"
        ));
    }

    // ======================================================================
    // KeyType: additional trait coverage
    // ======================================================================

    #[test]
    fn test_key_type_copy() {
        let kt = KeyType::Live;
        let kt2 = kt; // Copy
        assert_eq!(kt, kt2);
    }

    #[test]
    fn test_key_type_debug() {
        let dbg = format!("{:?}", KeyType::Live);
        assert_eq!(dbg, "Live");
        let dbg2 = format!("{:?}", KeyType::Test);
        assert_eq!(dbg2, "Test");
    }

    #[test]
    fn test_key_type_clone() {
        let kt = KeyType::Live;
        let cloned = kt;
        assert_eq!(kt, cloned);
    }

    #[test]
    fn test_key_type_deserialize_invalid() {
        let result: Result<KeyType, _> = serde_json::from_str(r#""sandbox""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_type_deserialize_case_sensitive() {
        // serde(rename_all = "lowercase") means "Live" (PascalCase) should fail
        let result: Result<KeyType, _> = serde_json::from_str(r#""Live""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_type_inequality() {
        assert_ne!(KeyType::Live, KeyType::Test);
    }

    // ======================================================================
    // PublicKeyData: deserialisation roundtrip with secret_key
    // ======================================================================

    #[test]
    fn test_public_key_data_deserialize_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        // Manually construct JSON that includes secret_key
        let json = r#"{
            "id": "pk_test_abc",
            "secret_key": "sk_test_secret",
            "allowed_origins": ["https://example.com"],
            "enabled": true,
            "created_at": 1000,
            "updated_at": 2000,
            "metadata": {}
        }"#;
        let data: PublicKeyData = serde_json::from_str(json)?;
        assert_eq!(data.id, "pk_test_abc");
        assert_eq!(data.secret_key, "sk_test_secret");
        assert_eq!(data.allowed_origins.len(), 1);
        assert!(data.enabled);
        assert_eq!(data.created_at, 1000);
        assert_eq!(data.updated_at, 2000);
        Ok(())
    }

    #[test]
    fn test_public_key_data_deserialize_with_all_optional_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "id": "pk_live_xyz",
            "secret_key": "sk_live_xyz",
            "organization_id": "org-42",
            "name": "Production Key",
            "allowed_origins": ["https://a.com", "https://b.com"],
            "rate_limit_override": {"max_requests": 500, "window_seconds": 60},
            "enabled": false,
            "created_at": 111,
            "updated_at": 222,
            "last_used_at": 333,
            "metadata": {"plan": "enterprise"}
        }"#;
        let data: PublicKeyData = serde_json::from_str(json)?;
        assert_eq!(data.organization_id, Some("org-42".to_string()));
        assert_eq!(data.name, Some("Production Key".to_string()));
        assert_eq!(data.allowed_origins.len(), 2);
        assert!(data.rate_limit_override.is_some());
        let rlo = data.rate_limit_override.as_ref().ok_or("missing rlo")?;
        assert_eq!(rlo.max_requests, 500);
        assert_eq!(rlo.window_seconds, 60);
        assert!(!data.enabled);
        assert_eq!(data.last_used_at, Some(333));
        Ok(())
    }

    #[test]
    fn test_public_key_data_serialise_skips_none_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let data = PublicKeyData {
            id: "pk_test_000".to_string(),
            secret_key: "sk_test_000".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec![],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({}),
        };
        let json = serde_json::to_string(&data)?;
        // skip_serializing_if = "Option::is_none" should exclude these
        assert!(!json.contains("organization_id"));
        assert!(!json.contains("rate_limit_override"));
        assert!(!json.contains("last_used_at"));
        assert!(!json.contains("name"));
        Ok(())
    }

    #[test]
    fn test_public_key_data_serialise_includes_some_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let data = PublicKeyData {
            id: "pk_test_001".to_string(),
            secret_key: "sk_test_001".to_string(),
            organization_id: Some("org-1".to_string()),
            name: Some("My Key".to_string()),
            allowed_origins: vec!["https://example.com".to_string()],
            rate_limit_override: Some(RateLimitOverride {
                max_requests: 10,
                window_seconds: 5,
            }),
            enabled: true,
            created_at: 100,
            updated_at: 200,
            last_used_at: Some(300),
            metadata: serde_json::json!({"tier": 2}),
        };
        let json = serde_json::to_string(&data)?;
        assert!(json.contains("organization_id"));
        assert!(json.contains("org-1"));
        assert!(json.contains("rate_limit_override"));
        assert!(json.contains("last_used_at"));
        assert!(json.contains("name"));
        assert!(json.contains("My Key"));
        // secret_key is still skipped
        assert!(!json.contains("secret_key"));
        Ok(())
    }

    // ======================================================================
    // PublicKeyData: clone preserves all fields
    // ======================================================================

    #[test]
    fn test_public_key_data_clone_preserves_all() {
        let data = PublicKeyData {
            id: "pk_test_clone".to_string(),
            secret_key: "sk_test_clone".to_string(),
            organization_id: Some("org-clone".to_string()),
            name: Some("Clone Test".to_string()),
            allowed_origins: vec!["https://a.com".to_string(), "https://b.com".to_string()],
            rate_limit_override: Some(RateLimitOverride {
                max_requests: 42,
                window_seconds: 10,
            }),
            enabled: false,
            created_at: 1111,
            updated_at: 2222,
            last_used_at: Some(3333),
            metadata: serde_json::json!({"x": 1}),
        };
        let cloned = data.clone();
        assert_eq!(data.id, cloned.id);
        assert_eq!(data.secret_key, cloned.secret_key);
        assert_eq!(data.organization_id, cloned.organization_id);
        assert_eq!(data.name, cloned.name);
        assert_eq!(data.allowed_origins, cloned.allowed_origins);
        assert_eq!(data.enabled, cloned.enabled);
        assert_eq!(data.created_at, cloned.created_at);
        assert_eq!(data.updated_at, cloned.updated_at);
        assert_eq!(data.last_used_at, cloned.last_used_at);
        assert_eq!(data.metadata, cloned.metadata);
    }

    // ======================================================================
    // From<PublicKeyData> for PublicKeyInfo: additional paths
    // ======================================================================

    #[test]
    fn test_public_key_data_into_info_disabled_key() {
        let data = PublicKeyData {
            id: "pk_test_disabled".to_string(),
            secret_key: "sk_test_disabled".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec![],
            rate_limit_override: None,
            enabled: false,
            created_at: 500,
            updated_at: 600,
            last_used_at: None,
            metadata: serde_json::json!(null),
        };
        let info: PublicKeyInfo = data.into();
        assert!(!info.active);
        assert_eq!(info.last_used_at, None);
        assert_eq!(info.created_at, 500);
    }

    #[test]
    fn test_public_key_data_into_info_preserves_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let data = PublicKeyData {
            id: "pk_test_meta".to_string(),
            secret_key: "sk_test_meta".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec!["https://x.com".to_string()],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({"billing": "enterprise", "region": "au"}),
        };
        let info: PublicKeyInfo = data.into();
        let meta = info.metadata.as_ref().ok_or("metadata should be Some")?;
        assert_eq!(meta["billing"], "enterprise");
        assert_eq!(meta["region"], "au");
        Ok(())
    }

    #[test]
    fn test_public_key_data_into_info_multiple_origins() {
        let data = PublicKeyData {
            id: "pk_test_multi".to_string(),
            secret_key: "sk_test_multi".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec![
                "https://a.com".to_string(),
                "https://b.com".to_string(),
                "https://*.c.com".to_string(),
                "http://localhost:3000".to_string(),
            ],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({}),
        };
        let info: PublicKeyInfo = data.into();
        assert_eq!(info.allowed_origins.len(), 4);
    }

    // ======================================================================
    // RateLimitOverride: additional coverage
    // ======================================================================

    #[test]
    fn test_rate_limit_override_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = RateLimitOverride {
            max_requests: 999,
            window_seconds: 120,
        };
        let json = serde_json::to_string(&original)?;
        let decoded: RateLimitOverride = serde_json::from_str(&json)?;
        assert_eq!(decoded.max_requests, 999);
        assert_eq!(decoded.window_seconds, 120);
        Ok(())
    }

    #[test]
    fn test_rate_limit_override_zero_values() -> Result<(), Box<dyn std::error::Error>> {
        let r = RateLimitOverride {
            max_requests: 0,
            window_seconds: 0,
        };
        let json = serde_json::to_string(&r)?;
        let decoded: RateLimitOverride = serde_json::from_str(&json)?;
        assert_eq!(decoded.max_requests, 0);
        assert_eq!(decoded.window_seconds, 0);
        Ok(())
    }

    #[test]
    fn test_rate_limit_override_max_values() -> Result<(), Box<dyn std::error::Error>> {
        let r = RateLimitOverride {
            max_requests: u32::MAX,
            window_seconds: u32::MAX,
        };
        let json = serde_json::to_string(&r)?;
        let decoded: RateLimitOverride = serde_json::from_str(&json)?;
        assert_eq!(decoded.max_requests, u32::MAX);
        assert_eq!(decoded.window_seconds, u32::MAX);
        Ok(())
    }

    #[test]
    fn test_rate_limit_override_clone() {
        let r = RateLimitOverride {
            max_requests: 100,
            window_seconds: 60,
        };
        let cloned = r.clone();
        assert_eq!(r.max_requests, cloned.max_requests);
        assert_eq!(r.window_seconds, cloned.window_seconds);
    }

    #[test]
    fn test_rate_limit_override_debug() {
        let r = RateLimitOverride {
            max_requests: 50,
            window_seconds: 30,
        };
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("50"));
        assert!(dbg.contains("30"));
        assert!(dbg.contains("RateLimitOverride"));
    }

    // ======================================================================
    // PublicKeyData Debug: additional field coverage
    // ======================================================================

    #[test]
    fn test_public_key_data_debug_shows_all_non_secret_fields() {
        let data = PublicKeyData {
            id: "pk_test_dbg".to_string(),
            secret_key: "sk_test_dbg".to_string(),
            organization_id: Some("org-dbg".to_string()),
            name: Some("Debug Key".to_string()),
            allowed_origins: vec!["https://debug.example.com".to_string()],
            rate_limit_override: Some(RateLimitOverride {
                max_requests: 10,
                window_seconds: 5,
            }),
            enabled: true,
            created_at: 777,
            updated_at: 888,
            last_used_at: Some(999),
            metadata: serde_json::json!({"env": "debug"}),
        };
        let dbg = format!("{:?}", data);
        assert!(dbg.contains("pk_test_dbg"));
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("sk_test_dbg"));
        assert!(dbg.contains("org-dbg"));
        assert!(dbg.contains("Debug Key"));
        assert!(dbg.contains("debug.example.com"));
        assert!(dbg.contains("777"));
        assert!(dbg.contains("888"));
        assert!(dbg.contains("999"));
    }

    // ======================================================================
    // PUBLIC_KEY_DATA_AAD: exact value check
    // ======================================================================

    #[test]
    fn test_public_key_data_aad_exact_value() {
        assert_eq!(PUBLIC_KEY_DATA_AAD, b"provii-verifier:public_key_data:v1");
    }

    #[test]
    fn test_public_key_data_aad_is_valid_utf8() -> Result<(), Box<dyn std::error::Error>> {
        let s = std::str::from_utf8(PUBLIC_KEY_DATA_AAD)?;
        assert!(!s.is_empty());
        Ok(())
    }

    // ======================================================================
    // KeyPair: generated key hex is valid
    // ======================================================================

    #[test]
    fn test_generated_key_pair_hex_is_valid() -> Result<(), Box<dyn std::error::Error>> {
        let pair = KeyManager::generate_key_pair(KeyType::Live)?;
        let pk_hex = pair.public_key.get(8..).ok_or("missing pk hex")?;
        let sk_hex = pair.secret_key.get(8..).ok_or("missing sk hex")?;
        // Both should decode as valid hex
        let pk_bytes = hex::decode(pk_hex)?;
        let sk_bytes = hex::decode(sk_hex)?;
        assert_eq!(pk_bytes.len(), 32);
        assert_eq!(sk_bytes.len(), 32);
        Ok(())
    }

    #[test]
    fn test_generated_key_pair_passes_validate_key_format() -> Result<(), Box<dyn std::error::Error>>
    {
        let pair_live = KeyManager::generate_key_pair(KeyType::Live)?;
        let pair_test = KeyManager::generate_key_pair(KeyType::Test)?;
        validate_key_format(&pair_live.public_key).map_err(|e| format!("{:?}", e))?;
        validate_key_format(&pair_test.public_key).map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    // ======================================================================
    // validate_key_format: error message content
    // ======================================================================

    #[test]
    fn test_validate_key_format_wrong_prefix_error_message() {
        let err = validate_key_format("xx_live_aabbccdd").err();
        assert!(err.is_some());
    }

    #[test]
    fn test_validate_key_format_short_hex_error_message() {
        let key = format!("pk_live_{}", "a".repeat(10));
        let err = validate_key_format(&key).err();
        assert!(err.is_some());
    }

    #[test]
    fn test_validate_key_format_non_hex_error_message() {
        let key = format!("pk_live_{}", "z".repeat(64));
        let err = validate_key_format(&key).err();
        assert!(err.is_some());
    }

    // ======================================================================
    // Zeroize implementation: KeyPair drop clears secret_key
    // ======================================================================

    #[test]
    fn test_key_pair_zeroize() -> Result<(), Box<dyn std::error::Error>> {
        let mut pair =
            KeyManager::generate_key_pair(KeyType::Live).map_err(|e| format!("{:?}", e))?;
        // Manually zeroize and verify
        pair.zeroize();
        assert!(pair.secret_key.is_empty());
        // public_key is skipped from zeroize
        assert!(!pair.public_key.is_empty());
        Ok(())
    }

    #[test]
    fn test_public_key_data_zeroize() {
        let mut data = PublicKeyData {
            id: "pk_test_z".to_string(),
            secret_key: "sk_test_z_secret_material".to_string(),
            organization_id: None,
            name: None,
            allowed_origins: vec![],
            rate_limit_override: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_used_at: None,
            metadata: serde_json::json!({}),
        };
        data.zeroize();
        assert!(data.secret_key.is_empty());
        // id is skipped
        assert!(!data.id.is_empty());
    }
}
