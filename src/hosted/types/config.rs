// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Configuration types for hosted verification flows.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public key configuration stored in KV.
///
/// Each relying party has a public key registered with allowed origins
/// and rate limit configuration.
///
/// # SECURITY: Memory Zeroisation (ASVS 11.7.1 L3)
///
/// Implements `ZeroizeOnDrop` to ensure `secret_key` is cleared from memory on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyInfo {
    /// Public key identifier (unique, not sensitive)
    #[zeroize(skip)]
    pub public_key: String,

    /// Secret key for HMAC authentication (encrypted at rest).
    /// This field will be zeroized when PublicKeyInfo is dropped.
    #[serde(skip_serializing)]
    pub secret_key: String,

    /// Allowed origins (scheme + host + port)
    #[zeroize(skip)]
    pub allowed_origins: Vec<String>,

    /// Whether this key is currently active
    #[zeroize(skip)]
    pub active: bool,

    /// When this key was created (Unix timestamp seconds)
    #[zeroize(skip)]
    pub created_at: u64,

    /// When this key was last used (Unix timestamp seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub last_used_at: Option<u64>,

    /// Custom metadata (for analytics, billing, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub metadata: Option<serde_json::Value>,
}

impl std::fmt::Debug for PublicKeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyInfo")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .field("allowed_origins", &self.allowed_origins)
            .field("active", &self.active)
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl PublicKeyInfo {
    /// Check if an origin is allowed for this key.
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins
            .iter()
            .any(|allowed| Self::origin_matches(allowed, origin))
    }

    /// Match origin patterns (supports wildcards).
    ///
    /// Delegates to shared `origin_matches_pattern` with dot-boundary enforcement.
    fn origin_matches(pattern: &str, origin: &str) -> bool {
        crate::utils::origin::origin_matches_pattern(pattern, origin)
    }
}

/// Durable Object sharding configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardingConfig {
    /// Number of session DO shards
    #[serde(default = "default_session_shards")]
    pub session_shards: u32,

    /// Number of nonce DO shards
    #[serde(default = "default_nonce_shards")]
    pub nonce_shards: u32,

    /// Number of audit log DO shards
    #[serde(default = "default_audit_shards")]
    pub audit_shards: u32,

    /// Number of idempotency DO shards
    #[serde(default = "default_idempotency_shards")]
    pub idempotency_shards: u32,
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            session_shards: 25,
            nonce_shards: 25,
            audit_shards: 25,
            idempotency_shards: 25,
        }
    }
}

// Default value functions for serde

fn default_true() -> bool {
    true
}

fn default_session_shards() -> u32 {
    25
}

fn default_nonce_shards() -> u32 {
    25
}

fn default_audit_shards() -> u32 {
    25
}

fn default_idempotency_shards() -> u32 {
    25
}

/// SECURITY: CSRF protection configuration.
///
/// Controls token expiration, origin matching, and rate limits for CSRF
/// token generation. Exempt paths bypass CSRF validation entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrfProtectionConfig {
    /// CSRF token expiration in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_csrf_expiration")]
    pub token_expiration_seconds: u64,

    /// Whether to require Origin header match (default: true)
    #[serde(default = "default_true")]
    pub require_origin_match: bool,

    /// List of paths exempt from CSRF protection
    #[serde(default = "default_csrf_exempt_paths")]
    pub exempt_paths: Vec<String>,

    /// Maximum tokens to generate per session per minute (rate limiting)
    #[serde(default = "default_csrf_rate_limit")]
    pub max_tokens_per_session_per_minute: u32,

    /// Whether CSRF protection is enabled (can be disabled for testing)
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for CsrfProtectionConfig {
    fn default() -> Self {
        Self {
            token_expiration_seconds: 3600,
            require_origin_match: true,
            exempt_paths: default_csrf_exempt_paths(),
            max_tokens_per_session_per_minute: 10,
            enabled: true,
        }
    }
}

fn default_csrf_expiration() -> u64 {
    3600 // 1 hour
}

fn default_csrf_exempt_paths() -> Vec<String> {
    vec![
        "/health".to_string(),
        "/health/ready".to_string(),
        "/health/live".to_string(),
        "/health/detailed".to_string(),
        "/metrics".to_string(),
        "/v1/hosted/status/".to_string(), // GET only
        "/v1/csrf-token".to_string(),     // Token generation endpoint
    ]
}

fn default_csrf_rate_limit() -> u32 {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_key_info() -> PublicKeyInfo {
        PublicKeyInfo {
            public_key: "pk-test".to_string(),
            secret_key: "sk-secret".to_string(),
            allowed_origins: vec![
                "https://example.com".to_string(),
                "https://*.example.org".to_string(),
            ],
            active: true,
            created_at: 1234567890,
            last_used_at: None,
            metadata: None,
        }
    }

    #[test]
    fn test_origin_exact_match() {
        let key = create_test_key_info();
        assert!(key.is_origin_allowed("https://example.com"));
    }

    #[test]
    fn test_origin_wildcard_match() {
        let key = create_test_key_info();
        assert!(key.is_origin_allowed("https://sub.example.org"));
        assert!(key.is_origin_allowed("https://deep.sub.example.org"));
    }

    #[test]
    fn test_origin_no_match() {
        let key = create_test_key_info();
        assert!(!key.is_origin_allowed("https://evil.com"));
        assert!(!key.is_origin_allowed("http://example.com")); // Wrong scheme
    }

    #[test]
    fn test_sharding_config_default() {
        let config = ShardingConfig::default();
        assert_eq!(config.session_shards, 25);
        assert_eq!(config.nonce_shards, 25);
        assert_eq!(config.audit_shards, 25);
        assert_eq!(config.idempotency_shards, 25);
    }

    #[test]
    fn test_public_key_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let key = create_test_key_info();
        let json = serde_json::to_string(&key)?;
        assert!(json.contains("pk-test"));
        assert!(json.contains("https://example.com"));
        assert!(!json.contains("sk-secret")); // Secret should not serialize
        Ok(())
    }

    #[test]
    fn test_origin_pattern_matching() {
        assert!(PublicKeyInfo::origin_matches(
            "https://example.com",
            "https://example.com"
        ));
        assert!(PublicKeyInfo::origin_matches(
            "https://*.example.com",
            "https://sub.example.com"
        ));
        assert!(PublicKeyInfo::origin_matches(
            "https://*.example.com",
            "https://deep.sub.example.com"
        ));
        assert!(!PublicKeyInfo::origin_matches(
            "https://*.example.com",
            "https://example.com"
        ));
    }

    // ── PublicKeyInfo Debug redaction ────────────────────────────────────

    #[test]
    fn test_public_key_info_debug_redacts_secret() {
        let key = create_test_key_info();
        let debug = format!("{:?}", key);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("sk-secret"));
    }

    // ── PublicKeyInfo deserialisation ────────────────────────────────────

    #[test]
    fn test_public_key_info_deserialization() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"public_key":"pk-1","secret_key":"sk-1","allowed_origins":["https://a.com"],"active":true,"created_at":1000}"#;
        let info: PublicKeyInfo = serde_json::from_str(json)?;
        assert_eq!(info.public_key, "pk-1");
        assert_eq!(info.secret_key, "sk-1");
        assert_eq!(info.allowed_origins, vec!["https://a.com"]);
        assert!(info.active);
        assert_eq!(info.created_at, 1000);
        assert_eq!(info.last_used_at, None);
        assert_eq!(info.metadata, None);
        Ok(())
    }

    #[test]
    fn test_public_key_info_rejects_unknown_fields() {
        let json = r#"{"public_key":"pk","secret_key":"sk","allowed_origins":[],"active":true,"created_at":0,"extra":"bad"}"#;
        let result = serde_json::from_str::<PublicKeyInfo>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    // ── PublicKeyInfo::is_origin_allowed edge cases ─────────────────────

    #[test]
    fn test_is_origin_allowed_empty_list() {
        let key = PublicKeyInfo {
            public_key: "pk".to_string(),
            secret_key: "sk".to_string(),
            allowed_origins: vec![],
            active: true,
            created_at: 0,
            last_used_at: None,
            metadata: None,
        };
        assert!(!key.is_origin_allowed("https://example.com"));
    }

    #[test]
    fn test_is_origin_allowed_multiple_patterns() {
        let key = PublicKeyInfo {
            public_key: "pk".to_string(),
            secret_key: "sk".to_string(),
            allowed_origins: vec![
                "https://a.com".to_string(),
                "https://b.com".to_string(),
                "https://*.c.com".to_string(),
            ],
            active: true,
            created_at: 0,
            last_used_at: None,
            metadata: None,
        };
        assert!(key.is_origin_allowed("https://a.com"));
        assert!(key.is_origin_allowed("https://b.com"));
        assert!(key.is_origin_allowed("https://sub.c.com"));
        assert!(!key.is_origin_allowed("https://c.com"));
        assert!(!key.is_origin_allowed("https://d.com"));
    }

    // ── PublicKeyInfo::origin_matches suffix attack prevention ───────────

    #[test]
    fn test_origin_matches_suffix_attack() {
        assert!(!PublicKeyInfo::origin_matches(
            "https://*.example.com",
            "https://evilexample.com"
        ));
    }

    // ── ShardingConfig serialisation roundtrip ──────────────────────────

    #[test]
    fn test_sharding_config_serialization_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let config = ShardingConfig {
            session_shards: 50,
            nonce_shards: 30,
            audit_shards: 10,
            idempotency_shards: 5,
        };
        let json = serde_json::to_string(&config)?;
        let deserialized: ShardingConfig = serde_json::from_str(&json)?;
        assert_eq!(deserialized.session_shards, 50);
        assert_eq!(deserialized.nonce_shards, 30);
        assert_eq!(deserialized.audit_shards, 10);
        assert_eq!(deserialized.idempotency_shards, 5);
        Ok(())
    }

    #[test]
    fn test_sharding_config_rejects_unknown_fields() {
        let json = r#"{"session_shards":1,"nonce_shards":1,"audit_shards":1,"idempotency_shards":1,"extra":"bad"}"#;
        let result = serde_json::from_str::<ShardingConfig>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    #[test]
    fn test_sharding_config_defaults_in_deserialization() -> Result<(), Box<dyn std::error::Error>>
    {
        // All fields have defaults via serde; empty object should work
        let json = r#"{}"#;
        let config: ShardingConfig = serde_json::from_str(json)?;
        assert_eq!(config.session_shards, 25);
        assert_eq!(config.nonce_shards, 25);
        assert_eq!(config.audit_shards, 25);
        assert_eq!(config.idempotency_shards, 25);
        Ok(())
    }

    // ── CsrfProtectionConfig ────────────────────────────────────────────

    #[test]
    fn test_csrf_protection_config_default() {
        let config = CsrfProtectionConfig::default();
        assert_eq!(config.token_expiration_seconds, 3600);
        assert!(config.require_origin_match);
        assert_eq!(config.max_tokens_per_session_per_minute, 10);
        assert!(config.enabled);
        // Exempt paths should not have exactly 3 items
        assert!(config.exempt_paths.len() != 3);
    }

    #[test]
    fn test_csrf_protection_config_exempt_paths() {
        let config = CsrfProtectionConfig::default();
        assert!(config.exempt_paths.contains(&"/health".to_string()));
        assert!(config.exempt_paths.contains(&"/v1/csrf-token".to_string()));
        assert!(config
            .exempt_paths
            .contains(&"/v1/hosted/status/".to_string()));
    }

    #[test]
    fn test_csrf_protection_config_serialization_roundtrip(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = CsrfProtectionConfig {
            token_expiration_seconds: 1800,
            require_origin_match: false,
            exempt_paths: vec!["/health".to_string(), "/test".to_string()],
            max_tokens_per_session_per_minute: 5,
            enabled: false,
        };
        let json = serde_json::to_string(&config)?;
        let deserialized: CsrfProtectionConfig = serde_json::from_str(&json)?;
        assert_eq!(deserialized.token_expiration_seconds, 1800);
        assert!(!deserialized.require_origin_match);
        assert_eq!(deserialized.exempt_paths.len(), 2);
        assert_eq!(deserialized.max_tokens_per_session_per_minute, 5);
        assert!(!deserialized.enabled);
        Ok(())
    }

    #[test]
    fn test_csrf_protection_config_rejects_unknown_fields() {
        let json = r#"{"token_expiration_seconds":3600,"require_origin_match":true,"exempt_paths":[],"max_tokens_per_session_per_minute":10,"enabled":true,"extra":"bad"}"#;
        let result = serde_json::from_str::<CsrfProtectionConfig>(json);
        assert!(
            result.is_err(),
            "deny_unknown_fields should reject extra fields"
        );
    }

    #[test]
    fn test_csrf_protection_config_defaults_in_deserialization(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{}"#;
        let config: CsrfProtectionConfig = serde_json::from_str(json)?;
        assert_eq!(config.token_expiration_seconds, 3600);
        assert!(config.require_origin_match);
        assert!(config.enabled);
        Ok(())
    }

    // ── PublicKeyInfo serialisation: secret_key skip_serializing ────────

    #[test]
    fn test_public_key_info_secret_key_not_serialized() -> Result<(), Box<dyn std::error::Error>> {
        let key = PublicKeyInfo {
            public_key: "pk-no-leak".to_string(),
            secret_key: "this-must-not-appear".to_string(),
            allowed_origins: vec!["https://a.com".to_string()],
            active: true,
            created_at: 0,
            last_used_at: None,
            metadata: None,
        };
        let json = serde_json::to_string(&key)?;
        assert!(
            !json.contains("this-must-not-appear"),
            "secret_key must not be serialised"
        );
        assert!(
            !json.contains("secret_key"),
            "secret_key field name must not appear"
        );
        Ok(())
    }

    // ── PublicKeyInfo with metadata ─────────────────────────────────────

    #[test]
    fn test_public_key_info_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"public_key":"pk","secret_key":"sk","allowed_origins":[],"active":true,"created_at":0,"metadata":{"tier":"premium","count":42}}"#;
        let info: PublicKeyInfo = serde_json::from_str(json)?;
        let meta = info.metadata.as_ref().ok_or("missing metadata")?;
        assert_eq!(meta["tier"], "premium");
        assert_eq!(meta["count"], 42);
        Ok(())
    }

    #[test]
    fn test_public_key_info_with_last_used_at() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"public_key":"pk","secret_key":"sk","allowed_origins":[],"active":false,"created_at":100,"last_used_at":200}"#;
        let info: PublicKeyInfo = serde_json::from_str(json)?;
        assert!(!info.active);
        assert_eq!(info.last_used_at, Some(200));
        assert_eq!(info.created_at, 100);
        Ok(())
    }

    // ── PublicKeyInfo serialisation roundtrip ────────────────────────────

    #[test]
    fn test_public_key_info_serialization_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let original = PublicKeyInfo {
            public_key: "pk-rt".to_string(),
            secret_key: "sk-rt".to_string(),
            allowed_origins: vec!["https://a.com".to_string(), "https://b.com".to_string()],
            active: true,
            created_at: 999,
            last_used_at: Some(1000),
            metadata: Some(serde_json::json!({"key": "val"})),
        };
        let json = serde_json::to_string(&original)?;
        // secret_key is skip_serializing, so deserialization needs it in the source
        // Instead test that the non-secret fields survive serialisation
        let value: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(value["public_key"], "pk-rt");
        assert_eq!(value["active"], true);
        assert_eq!(value["created_at"], 999);
        assert_eq!(value["last_used_at"], 1000);
        Ok(())
    }

    // ── PublicKeyInfo::is_origin_allowed with scheme mismatch ──────────

    #[test]
    fn test_origin_allowed_http_vs_https() {
        let key = PublicKeyInfo {
            public_key: "pk".to_string(),
            secret_key: "sk".to_string(),
            allowed_origins: vec!["https://example.com".to_string()],
            active: true,
            created_at: 0,
            last_used_at: None,
            metadata: None,
        };
        assert!(
            !key.is_origin_allowed("http://example.com"),
            "http should not match https"
        );
    }

    #[test]
    fn test_origin_allowed_with_port() {
        let key = PublicKeyInfo {
            public_key: "pk".to_string(),
            secret_key: "sk".to_string(),
            allowed_origins: vec!["http://localhost:3000".to_string()],
            active: true,
            created_at: 0,
            last_used_at: None,
            metadata: None,
        };
        assert!(key.is_origin_allowed("http://localhost:3000"));
        assert!(
            !key.is_origin_allowed("http://localhost:3001"),
            "wrong port should not match"
        );
    }

    // ── ShardingConfig custom values ────────────────────────────────────

    #[test]
    fn test_sharding_config_custom_values() {
        let config = ShardingConfig {
            session_shards: 100,
            nonce_shards: 50,
            audit_shards: 10,
            idempotency_shards: 5,
        };
        assert_eq!(config.session_shards, 100);
        assert_eq!(config.nonce_shards, 50);
        assert_eq!(config.audit_shards, 10);
        assert_eq!(config.idempotency_shards, 5);
    }

    #[test]
    fn test_sharding_config_partial_defaults() -> Result<(), Box<dyn std::error::Error>> {
        // Only set some fields; others should use defaults
        let json = r#"{"session_shards":50}"#;
        let config: ShardingConfig = serde_json::from_str(json)?;
        assert_eq!(config.session_shards, 50);
        assert_eq!(config.nonce_shards, 25); // default
        assert_eq!(config.audit_shards, 25); // default
        assert_eq!(config.idempotency_shards, 25); // default
        Ok(())
    }

    // ── CsrfProtectionConfig partial overrides ──────────────────────────

    #[test]
    fn test_csrf_config_partial_override() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"enabled":false}"#;
        let config: CsrfProtectionConfig = serde_json::from_str(json)?;
        assert!(!config.enabled);
        // Other fields should have defaults
        assert_eq!(config.token_expiration_seconds, 3600);
        assert!(config.require_origin_match);
        assert_eq!(config.max_tokens_per_session_per_minute, 10);
        Ok(())
    }

    #[test]
    fn test_csrf_config_all_exempt_paths_present() {
        let config = CsrfProtectionConfig::default();
        let expected_paths = vec![
            "/health",
            "/health/ready",
            "/health/live",
            "/health/detailed",
            "/metrics",
            "/v1/hosted/status/",
            "/v1/csrf-token",
        ];
        for path in expected_paths {
            assert!(
                config.exempt_paths.contains(&path.to_string()),
                "Missing exempt path: {}",
                path
            );
        }
    }

    #[test]
    fn test_csrf_config_custom_exempt_paths() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"exempt_paths":["/custom"]}"#;
        let config: CsrfProtectionConfig = serde_json::from_str(json)?;
        assert_eq!(config.exempt_paths, vec!["/custom".to_string()]);
        Ok(())
    }

    // ── PublicKeyInfo Debug output format ────────────────────────────────

    #[test]
    fn test_public_key_info_debug_includes_non_secret_fields() {
        let key = PublicKeyInfo {
            public_key: "pk-debug-test".to_string(),
            secret_key: "sk-should-not-show".to_string(),
            allowed_origins: vec!["https://debug.example.com".to_string()],
            active: true,
            created_at: 12345,
            last_used_at: Some(67890),
            metadata: None,
        };
        let debug = format!("{:?}", key);
        assert!(debug.contains("pk-debug-test"));
        assert!(debug.contains("debug.example.com"));
        assert!(debug.contains("12345"));
        assert!(debug.contains("67890"));
        assert!(!debug.contains("sk-should-not-show"));
    }

    // ── ShardingConfig clone ────────────────────────────────────────────

    #[test]
    fn test_sharding_config_clone() {
        let config = ShardingConfig {
            session_shards: 10,
            nonce_shards: 20,
            audit_shards: 30,
            idempotency_shards: 40,
        };
        let cloned = config.clone();
        assert_eq!(cloned.session_shards, 10);
        assert_eq!(cloned.nonce_shards, 20);
        assert_eq!(cloned.audit_shards, 30);
        assert_eq!(cloned.idempotency_shards, 40);
    }

    // ── CsrfProtectionConfig clone ──────────────────────────────────────

    #[test]
    fn test_csrf_config_clone() {
        let config = CsrfProtectionConfig {
            token_expiration_seconds: 7200,
            require_origin_match: false,
            exempt_paths: vec!["/a".to_string(), "/b".to_string()],
            max_tokens_per_session_per_minute: 20,
            enabled: false,
        };
        let cloned = config.clone();
        assert_eq!(cloned.token_expiration_seconds, 7200);
        assert!(!cloned.require_origin_match);
        assert_eq!(cloned.exempt_paths.len(), 2);
        assert_eq!(cloned.max_tokens_per_session_per_minute, 20);
        assert!(!cloned.enabled);
    }

    // ── PublicKeyInfo::is_origin_allowed with trailing slash ────────────

    #[test]
    fn test_origin_allowed_trailing_slash_normalised() {
        let key = PublicKeyInfo {
            public_key: "pk".to_string(),
            secret_key: "sk".to_string(),
            allowed_origins: vec!["https://example.com".to_string()],
            active: true,
            created_at: 0,
            last_used_at: None,
            metadata: None,
        };
        // URL parsing normalises both to path "/", so trailing slash matches
        assert!(key.is_origin_allowed("https://example.com/"));
    }

    // ── PublicKeyInfo inactive key ──────────────────────────────────────

    #[test]
    fn test_public_key_info_inactive() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{"public_key":"pk-inactive","secret_key":"sk","allowed_origins":["https://a.com"],"active":false,"created_at":0}"#;
        let info: PublicKeyInfo = serde_json::from_str(json)?;
        assert!(!info.active);
        // is_origin_allowed still works even for inactive keys (caller checks active)
        assert!(info.is_origin_allowed("https://a.com"));
        Ok(())
    }

    // ── ShardingConfig debug ────────────────────────────────────────────

    #[test]
    fn test_sharding_config_debug() {
        let config = ShardingConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("session_shards"));
        assert!(debug.contains("25"));
    }

    // ── CsrfProtectionConfig debug ──────────────────────────────────────

    #[test]
    fn test_csrf_config_debug() {
        let config = CsrfProtectionConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("token_expiration_seconds"));
        assert!(debug.contains("3600"));
        assert!(debug.contains("enabled"));
    }
}
