// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Load and validate runtime configuration sourced from the Worker environment.
//!
//! Parses comma-separated origin lists into [`AllowedOrigins`] with support for
//! exact matches, subdomain wildcards, and a global wildcard. Production release
//! builds reject wildcard CORS origins to prevent credential leakage.
#![forbid(unsafe_code)]

use std::time::Duration;
use thiserror::Error;
use url::Url;

use crate::utils::current_timestamp;

/// Wrapper around a list of origin patterns with helper matching logic.
///
/// SECURITY: Implements OWASP CORS best practices:
/// - Wildcard patterns are restricted in production
/// - Credentials are never allowed with wildcard origins
/// - Subdomain wildcards are validated carefully
/// - All origin matching is case-insensitive
#[derive(Debug, Clone)]
pub struct AllowedOrigins {
    patterns: Vec<String>,
    // SECURITY: Track if this list contains the global wildcard to prevent
    // accidentally allowing credentials with wildcard origins
    contains_global_wildcard: bool,
}

impl AllowedOrigins {
    /// Parse a comma-separated string of origin patterns into an [`AllowedOrigins`].
    ///
    /// Returns [`ConfigError::InvalidOrigins`] when the input is empty or
    /// contains only whitespace.
    /// Returns a wildcard `AllowedOrigins` that matches any origin.
    ///
    /// This is infallible and used where `Default` needs a known-good value.
    pub fn wildcard() -> Self {
        Self {
            patterns: vec!["*".to_string()],
            contains_global_wildcard: true,
        }
    }

    /// Parse a comma-separated string of origin patterns into an [`AllowedOrigins`].
    ///
    /// Returns [`ConfigError::InvalidOrigins`] when the input is empty or
    /// contains only whitespace.
    pub fn new(raw: String) -> Result<Self, ConfigError> {
        let list: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if list.is_empty() {
            return Err(ConfigError::InvalidOrigins);
        }

        // SECURITY: Check for global wildcard
        let contains_global_wildcard = list.iter().any(|p| p == "*");

        Ok(Self {
            patterns: list,
            contains_global_wildcard,
        })
    }

    /// SECURITY: Returns true if the origin matches any allowed pattern.
    /// Does NOT indicate whether credentials should be allowed.
    pub fn matches(&self, origin: &str) -> bool {
        let origin_url = match Url::parse(origin) {
            Ok(u) => u,
            Err(_) => return false,
        };

        self.patterns.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }

            if pattern.contains("://*.") {
                return self.matches_subdomain_wildcard(pattern, &origin_url);
            }

            if let Ok(pattern_url) = Url::parse(pattern) {
                return pattern_url.scheme() == origin_url.scheme()
                    && pattern_url.host() == origin_url.host()
                    && pattern_url.port_or_known_default() == origin_url.port_or_known_default();
            }

            false
        })
    }

    /// SECURITY: Returns true only if credentials should be allowed for this origin.
    ///
    /// The global wildcard (`"*"`) always blocks credentials because the OWASP
    /// prohibition is against `Access-Control-Allow-Credentials: true` paired
    /// with `Access-Control-Allow-Origin: *`. Subdomain wildcard patterns (e.g.
    /// `https://*.provii.app`) DO allow credentials because the response
    /// reflects the specific matched origin in the ACAO header (never `"*"`).
    /// This is required for session cookies across subdomains in the hosted flow.
    pub fn allows_credentials(&self, origin: &str) -> bool {
        // SECURITY: Never allow credentials with global wildcard
        if self.contains_global_wildcard {
            return false;
        }

        // Allow credentials for both exact and subdomain wildcard matches.
        // This is safe because we always reflect the specific origin in
        // Access-Control-Allow-Origin (never "*"). The OWASP prohibition is
        // against credentials + wildcard ACAO header, not against internal
        // wildcard matching patterns. The hosted flow requires credentials
        // for session cookies across *.provii.app subdomains.
        self.matches(origin)
    }

    fn matches_subdomain_wildcard(&self, pattern: &str, origin_url: &Url) -> bool {
        let pattern_url = match Url::parse(&pattern.replace("*.", "wildcard.")) {
            Ok(u) => u,
            Err(_) => return false,
        };

        if pattern_url.scheme() != origin_url.scheme() {
            return false;
        }
        if pattern_url.port_or_known_default() != origin_url.port_or_known_default() {
            return false;
        }

        match (pattern_url.host_str(), origin_url.host_str()) {
            (Some(pattern_host), Some(origin_host)) => {
                let suffix = pattern_host
                    .strip_prefix("wildcard.")
                    .unwrap_or(pattern_host);
                let suffix_lower = suffix.to_ascii_lowercase();
                let origin_lower = origin_host.to_ascii_lowercase();
                origin_lower.ends_with(&format!(".{}", suffix_lower))
            }
            _ => false,
        }
    }
}

/// Validated runtime configuration for the verifier Worker.
///
/// Built once from environment variables during cold start via
/// [`Config::from_worker_env`]. A [`Default`] impl exists for tests only.
#[derive(Debug)]
pub struct Config {
    /// Origins permitted to submit verification requests.
    pub allowed_origins: AllowedOrigins,
    /// Maximum challenge age in milliseconds before expiry.
    pub max_challenge_age_ms: u64,
    /// Pre-computed [`Duration`] form of `max_challenge_age_ms`.
    pub challenge_ttl: Duration,
    /// Origins permitted in CORS preflight responses.
    pub cors: AllowedOrigins,
    /// Public base URL of this verifier API (used in deep links).
    pub api_base_url: String,
    /// Base URL of the hosted backend (used in hosted-flow responses).
    pub hosted_base_url: String,
    /// Unix timestamp (seconds) recorded at Worker cold start.
    pub started_at_timestamp: u64,
    /// Time-to-live for nonce deduplication entries.
    pub nonce_cache_ttl: Duration,
    /// Deployment environment name (`"production"` or `"sandbox"`).
    pub environment: String,
}

impl Config {
    /// Build a [`Config`] from the Cloudflare Worker environment bindings.
    ///
    /// In release builds running outside sandbox, wildcard CORS origins are
    /// rejected to enforce the production security policy.
    pub fn from_worker_env(
        worker_env: crate::worker_bindings::WorkerEnv,
    ) -> Result<Self, ConfigError> {
        let allowed_origins = AllowedOrigins::new(worker_env.allowed_origins)?;

        // SECURITY: In production, reject wildcard patterns to prevent CORS bypass
        // attacks and credential leakage. Runtime check on ENVIRONMENT variable
        // (not compile-time debug_assertions) so the guard works regardless of
        // build profile. Local dev users must set ENVIRONMENT=development in
        // .dev.vars if they need wildcard origins.
        let is_sandbox = worker_env
            .environment
            .as_ref()
            .map(|v| v == "sandbox" || v == "development")
            .unwrap_or(false);

        if !is_sandbox && allowed_origins.contains_global_wildcard {
            return Err(ConfigError::WildcardInProduction);
        }

        let cors = AllowedOrigins::new(worker_env.cors_origins)?;

        if !is_sandbox && cors.contains_global_wildcard {
            return Err(ConfigError::WildcardInProduction);
        }

        let environment = worker_env
            .environment
            .unwrap_or_else(|| "production".to_string());

        Ok(Self {
            allowed_origins,
            max_challenge_age_ms: worker_env.max_challenge_age_ms,
            challenge_ttl: Duration::from_millis(worker_env.max_challenge_age_ms),
            cors,
            api_base_url: worker_env.api_base_url,
            hosted_base_url: worker_env.hosted_base_url,
            started_at_timestamp: current_timestamp(),
            nonce_cache_ttl: Duration::from_secs(worker_env.nonce_ttl_sec),
            environment,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        // CH-013: Default environment is "test" so the WildcardInProduction
        // guard catches any accidental use of Default in a production path.
        Self {
            allowed_origins: AllowedOrigins::wildcard(),
            cors: AllowedOrigins::wildcard(),
            max_challenge_age_ms: 60_000,
            challenge_ttl: Duration::from_millis(60_000),
            api_base_url: "https://verify.provii.app/v1".to_string(),
            hosted_base_url: "https://hosted.provii.app".to_string(),
            nonce_cache_ttl: Duration::from_secs(300),
            started_at_timestamp: current_timestamp(),
            environment: "test".to_string(),
        }
    }
}

/// Errors returned when building a [`Config`] from environment variables.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The origin list was empty, whitespace-only, or unparseable.
    #[error("ALLOWED_ORIGINS or PROVII_CORS_ORIGINS is empty or malformed")]
    InvalidOrigins,
    /// A wildcard origin was supplied in a production release build.
    #[error("wildcard CORS origins are not allowed in production (security policy violation)")]
    WildcardInProduction,
}

// Integration tests for AllowedOrigins CORS behaviour also live in
// `bins/cors-tests/`. The inline tests below cover the pure Rust
// path for native-target coverage.

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

    /// Helper: parse origins or return test failure.
    fn parse(raw: &str) -> Result<AllowedOrigins, Box<dyn std::error::Error>> {
        AllowedOrigins::new(raw.to_string()).map_err(|e| e.into())
    }

    /* ====================================================================== */
    /*                    AllowedOrigins::new() TESTS                        */
    /* ====================================================================== */

    #[test]
    fn test_new_single_origin() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert_eq!(ao.patterns.len(), 1);
        assert!(!ao.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_new_multiple_origins() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://a.com, https://b.com, https://c.com")?;
        assert_eq!(ao.patterns.len(), 3);
        assert!(!ao.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_new_with_global_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("*")?;
        assert!(ao.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_new_wildcard_among_others() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com, *")?;
        assert!(ao.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_new_empty_string_err() {
        assert!(AllowedOrigins::new("".to_string()).is_err());
    }

    #[test]
    fn test_new_whitespace_only_err() {
        assert!(AllowedOrigins::new("   ,  ,  ".to_string()).is_err());
    }

    #[test]
    fn test_new_commas_only_err() {
        assert!(AllowedOrigins::new(",,,".to_string()).is_err());
    }

    #[test]
    fn test_new_trims_whitespace() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("  https://a.com  , https://b.com  ")?;
        assert_eq!(ao.patterns[0], "https://a.com");
        assert_eq!(ao.patterns[1], "https://b.com");
        Ok(())
    }

    /* ====================================================================== */
    /*                    AllowedOrigins::wildcard() TESTS                   */
    /* ====================================================================== */

    #[test]
    fn test_wildcard_constructor() {
        let ao = AllowedOrigins::wildcard();
        assert!(ao.contains_global_wildcard);
        assert_eq!(ao.patterns.len(), 1);
        assert_eq!(ao.patterns[0], "*");
    }

    #[test]
    fn test_wildcard_matches_anything() {
        let ao = AllowedOrigins::wildcard();
        assert!(ao.matches("https://example.com"));
        assert!(ao.matches("http://localhost:3000"));
        assert!(ao.matches("https://any.domain.ever"));
    }

    /* ====================================================================== */
    /*                    AllowedOrigins::matches() TESTS                    */
    /* ====================================================================== */

    #[test]
    fn test_matches_exact_https() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(ao.matches("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_exact_http() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://example.com")?;
        assert!(ao.matches("http://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_scheme_mismatch_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.matches("http://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_port_mismatch_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.matches("https://example.com:8443"));
        Ok(())
    }

    #[test]
    fn test_matches_port_match() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com:8443")?;
        assert!(ao.matches("https://example.com:8443"));
        Ok(())
    }

    #[test]
    fn test_matches_different_host_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.matches("https://other.com"));
        Ok(())
    }

    #[test]
    fn test_matches_malformed_origin_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.matches("not-a-url"));
        Ok(())
    }

    #[test]
    fn test_matches_empty_origin_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.matches(""));
        Ok(())
    }

    #[test]
    fn test_matches_global_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("*")?;
        assert!(ao.matches("https://anything.com"));
        assert!(ao.matches("http://localhost:9999"));
        Ok(())
    }

    #[test]
    fn test_matches_multiple_patterns() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://a.com, https://b.com")?;
        assert!(ao.matches("https://a.com"));
        assert!(ao.matches("https://b.com"));
        assert!(!ao.matches("https://c.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    Subdomain wildcard matching                        */
    /* ====================================================================== */

    #[test]
    fn test_matches_subdomain_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.provii.app")?;
        assert!(ao.matches("https://hosted.provii.app"));
        assert!(ao.matches("https://verify.provii.app"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_deep() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.provii.app")?;
        assert!(ao.matches("https://a.b.c.provii.app"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_base_domain_rejects(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.provii.app")?;
        assert!(!ao.matches("https://provii.app"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_scheme_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.example.com")?;
        assert!(!ao.matches("http://sub.example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_port_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.example.com")?;
        assert!(!ao.matches("https://sub.example.com:8443"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_with_port() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.example.com:8443")?;
        assert!(ao.matches("https://sub.example.com:8443"));
        assert!(!ao.matches("https://sub.example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_case_insensitive() -> Result<(), Box<dyn std::error::Error>>
    {
        let ao = parse("https://*.EXAMPLE.COM")?;
        assert!(ao.matches("https://sub.example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_suffix_attack_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.example.com")?;
        assert!(!ao.matches("https://evilexample.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    AllowedOrigins::allows_credentials() TESTS         */
    /* ====================================================================== */

    #[test]
    fn test_allows_credentials_exact_match() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(ao.allows_credentials("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_no_match() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.allows_credentials("https://other.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_global_wildcard_blocks() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("*")?;
        assert!(!ao.allows_credentials("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_wildcard_constructor_blocks() {
        let ao = AllowedOrigins::wildcard();
        assert!(!ao.allows_credentials("https://example.com"));
    }

    #[test]
    fn test_allows_credentials_subdomain_wildcard_allows() -> Result<(), Box<dyn std::error::Error>>
    {
        let ao = parse("https://*.provii.app")?;
        assert!(ao.allows_credentials("https://hosted.provii.app"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_subdomain_wildcard_no_match(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.provii.app")?;
        assert!(!ao.allows_credentials("https://other.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    Config::default() TESTS                            */
    /* ====================================================================== */

    #[test]
    fn test_config_default_values() {
        let config = Config::default();
        assert_eq!(config.max_challenge_age_ms, 60_000);
        assert_eq!(config.challenge_ttl, Duration::from_millis(60_000));
        assert_eq!(config.api_base_url, "https://verify.provii.app/v1");
        assert_eq!(config.hosted_base_url, "https://hosted.provii.app");
        assert_eq!(config.nonce_cache_ttl, Duration::from_secs(300));
        assert_eq!(config.environment, "test");
    }

    #[test]
    fn test_config_default_has_wildcard_origins() {
        let config = Config::default();
        assert!(config.allowed_origins.contains_global_wildcard);
        assert!(config.cors.contains_global_wildcard);
    }

    #[test]
    fn test_config_default_timestamp_nonzero() {
        let config = Config::default();
        assert!(config.started_at_timestamp > 0);
    }

    /* ====================================================================== */
    /*                    ConfigError Display TESTS                          */
    /* ====================================================================== */

    #[test]
    fn test_config_error_invalid_origins_display() {
        assert!(ConfigError::InvalidOrigins
            .to_string()
            .contains("empty or malformed"));
    }

    #[test]
    fn test_config_error_wildcard_in_production_display() {
        assert!(ConfigError::WildcardInProduction
            .to_string()
            .contains("not allowed in production"));
    }

    #[test]
    fn test_config_error_debug() {
        let debug = format!("{:?}", ConfigError::InvalidOrigins);
        assert!(debug.contains("InvalidOrigins"));
    }

    /* ====================================================================== */
    /*                    AllowedOrigins Clone/Debug TESTS                   */
    /* ====================================================================== */

    #[test]
    fn test_allowed_origins_clone() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        let cloned = ao.clone();
        assert!(cloned.matches("https://example.com"));
        assert!(!cloned.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_allowed_origins_debug() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        let debug = format!("{:?}", ao);
        assert!(debug.contains("AllowedOrigins"));
        assert!(debug.contains("example.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    PROPERTY-BASED TESTS                               */
    /* ====================================================================== */

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Any non-empty comma-separated string produces Ok
        #[test]
        fn prop_nonempty_origin_parses(host in "[a-z]{3,10}\\.(com|org|net)") {
            let input = format!("https://{}", host);
            prop_assert!(AllowedOrigins::new(input).is_ok());
        }

        /// Property: Global wildcard always matches any valid URL
        #[test]
        fn prop_wildcard_matches_all(host in "[a-z]{3,10}\\.com") {
            let url = format!("https://{}", host);
            prop_assert!(AllowedOrigins::wildcard().matches(&url));
        }

        /// Property: Global wildcard never allows credentials
        #[test]
        fn prop_wildcard_blocks_credentials(host in "[a-z]{3,10}\\.com") {
            let url = format!("https://{}", host);
            prop_assert!(!AllowedOrigins::wildcard().allows_credentials(&url));
        }

        /// Property: Exact origin match is reflexive
        #[test]
        fn prop_exact_match_reflexive(host in "[a-z]{3,10}\\.com") {
            let url = format!("https://{}", host);
            let ao = AllowedOrigins::new(url.clone())
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            prop_assert!(ao.matches(&url));
        }

        /// Property: Scheme mismatch always rejects (non-wildcard)
        #[test]
        fn prop_scheme_mismatch_rejects(host in "[a-z]{3,10}\\.com") {
            let ao = AllowedOrigins::new(format!("https://{}", host))
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            let url = format!("http://{}", host);
            prop_assert!(!ao.matches(&url));
        }

        /// Property: Subdomain wildcard never matches the bare domain
        #[test]
        fn prop_subdomain_wildcard_rejects_bare(host in "[a-z]{3,10}\\.com") {
            let pattern = format!("https://*.{}", host);
            let ao = AllowedOrigins::new(pattern)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            let url = format!("https://{}", host);
            prop_assert!(!ao.matches(&url));
        }

        /// Property: Subdomain wildcard matches any sub.host
        #[test]
        fn prop_subdomain_wildcard_matches_sub(
            host in "[a-z]{3,10}\\.com",
            sub in "[a-z]{2,8}"
        ) {
            let pattern = format!("https://*.{}", host);
            let ao = AllowedOrigins::new(pattern)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            let url = format!("https://{}.{}", sub, host);
            prop_assert!(ao.matches(&url));
        }

        /// Property: Non-wildcard exact match never allows unrelated origins
        #[test]
        fn prop_exact_no_cross_match(
            host_a in "[a-z]{3,6}\\.com",
            host_b in "[a-z]{7,10}\\.org"
        ) {
            let ao = AllowedOrigins::new(format!("https://{}", host_a))
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            let url = format!("https://{}", host_b);
            prop_assert!(!ao.matches(&url));
        }
    }

    /* ====================================================================== */
    /*                    matches() – UNPARSEABLE PATTERN TESTS              */
    /* ====================================================================== */

    #[test]
    fn test_matches_unparseable_pattern_returns_false() -> Result<(), Box<dyn std::error::Error>> {
        // A pattern that is not "*", not a subdomain wildcard, and not a valid URL.
        // AllowedOrigins::new accepts any non-empty string; matching should silently
        // fail for patterns that cannot be parsed as a URL.
        let ao = AllowedOrigins {
            patterns: vec!["not a url at all".to_string()],
            contains_global_wildcard: false,
        };
        assert!(!ao.matches("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_pattern_just_scheme_no_host() -> Result<(), Box<dyn std::error::Error>> {
        let ao = AllowedOrigins {
            patterns: vec!["https://".to_string()],
            contains_global_wildcard: false,
        };
        assert!(!ao.matches("https://example.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    matches_subdomain_wildcard – EDGE CASES            */
    /* ====================================================================== */

    #[test]
    fn test_subdomain_wildcard_case_insensitive_origin() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.example.com")?;
        assert!(ao.matches("https://SUB.EXAMPLE.COM"));
        Ok(())
    }

    #[test]
    fn test_subdomain_wildcard_mixed_with_exact() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://exact.com, https://*.wild.com")?;
        assert!(ao.matches("https://exact.com"));
        assert!(ao.matches("https://sub.wild.com"));
        assert!(!ao.matches("https://exact.com:8080"));
        assert!(!ao.matches("https://wild.com"));
        Ok(())
    }

    #[test]
    fn test_subdomain_wildcard_http_scheme() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://*.localhost")?;
        assert!(ao.matches("http://app.localhost"));
        assert!(!ao.matches("https://app.localhost"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    matches() – PORT EDGE CASES                        */
    /* ====================================================================== */

    #[test]
    fn test_matches_explicit_default_port_vs_implicit() -> Result<(), Box<dyn std::error::Error>> {
        // https default port is 443; explicit :443 should match implicit
        let ao = parse("https://example.com")?;
        assert!(ao.matches("https://example.com:443"));
        Ok(())
    }

    #[test]
    fn test_matches_explicit_default_port_pattern() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com:443")?;
        assert!(ao.matches("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_http_default_port_80() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://example.com")?;
        assert!(ao.matches("http://example.com:80"));
        Ok(())
    }

    #[test]
    fn test_matches_http_explicit_port_80_matches_implicit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://example.com:80")?;
        assert!(ao.matches("http://example.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    matches() – MULTIPLE PATTERN TESTS                 */
    /* ====================================================================== */

    #[test]
    fn test_matches_last_pattern_matches() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://a.com, https://b.com, https://c.com, https://d.com")?;
        assert!(ao.matches("https://d.com"));
        Ok(())
    }

    #[test]
    fn test_matches_first_pattern_matches() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://a.com, https://b.com, https://c.com, https://d.com")?;
        assert!(ao.matches("https://a.com"));
        Ok(())
    }

    #[test]
    fn test_matches_none_of_multiple_patterns() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://a.com, https://b.com")?;
        assert!(!ao.matches("https://z.com"));
        Ok(())
    }

    #[test]
    fn test_matches_wildcard_with_exact_patterns() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://specific.com, *")?;
        // Wildcard should match anything
        assert!(ao.matches("https://anything.com"));
        assert!(ao.matches("https://specific.com"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    allows_credentials() – ADDITIONAL TESTS            */
    /* ====================================================================== */

    #[test]
    fn test_allows_credentials_global_wildcard_among_others_blocks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com, *")?;
        // Even though example.com is a specific origin, the presence of global
        // wildcard in the list blocks credentials for all origins.
        assert!(!ao.allows_credentials("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_malformed_origin_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let ao = parse("https://example.com")?;
        assert!(!ao.allows_credentials("not-a-url"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_empty_origin_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(!ao.allows_credentials(""));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_subdomain_wildcard_deep_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.provii.app")?;
        assert!(ao.allows_credentials("https://a.b.provii.app"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_subdomain_wildcard_base_domain_blocks(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://*.provii.app")?;
        assert!(!ao.allows_credentials("https://provii.app"));
        Ok(())
    }

    /* ====================================================================== */
    /*                    AllowedOrigins::new() – ADDITIONAL EDGE CASES      */
    /* ====================================================================== */

    #[test]
    fn test_new_single_comma_empty() {
        assert!(AllowedOrigins::new(",".to_string()).is_err());
    }

    #[test]
    fn test_new_filters_empty_segments() -> Result<(), Box<dyn std::error::Error>> {
        // Leading, trailing, and consecutive commas leave empty segments that
        // are filtered out.
        let ao = parse(",https://a.com,,https://b.com,")?;
        assert_eq!(ao.patterns.len(), 2);
        Ok(())
    }

    #[test]
    fn test_new_preserves_pattern_order() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://first.com, https://second.com")?;
        assert_eq!(ao.patterns[0], "https://first.com");
        assert_eq!(ao.patterns[1], "https://second.com");
        Ok(())
    }

    #[test]
    fn test_new_wildcard_not_star() -> Result<(), Box<dyn std::error::Error>> {
        // "**" is not the global wildcard
        let ao = parse("**")?;
        assert!(!ao.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_new_single_space_err() {
        assert!(AllowedOrigins::new(" ".to_string()).is_err());
    }

    /* ====================================================================== */
    /*                    Config::default() – ADDITIONAL TESTS               */
    /* ====================================================================== */

    #[test]
    fn test_config_default_wildcard_matches_any() {
        let config = Config::default();
        assert!(config.allowed_origins.matches("https://anything.com"));
        assert!(config.cors.matches("http://localhost:3000"));
    }

    #[test]
    fn test_config_default_wildcard_blocks_credentials() {
        let config = Config::default();
        assert!(!config
            .allowed_origins
            .allows_credentials("https://example.com"));
        assert!(!config.cors.allows_credentials("https://example.com"));
    }

    /* ====================================================================== */
    /*                    ConfigError as std::error::Error                   */
    /* ====================================================================== */

    #[test]
    fn test_config_error_is_std_error() {
        // ConfigError must implement std::error::Error
        let err: Box<dyn std::error::Error> = Box::new(ConfigError::InvalidOrigins);
        assert!(err.to_string().contains("empty or malformed"));
    }

    #[test]
    fn test_config_error_wildcard_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ConfigError::WildcardInProduction);
        assert!(err.to_string().contains("not allowed in production"));
    }

    #[test]
    fn test_config_error_debug_wildcard() {
        let debug = format!("{:?}", ConfigError::WildcardInProduction);
        assert!(debug.contains("WildcardInProduction"));
    }

    /* ====================================================================== */
    /*                    matches() – URL EDGE CASES                         */
    /* ====================================================================== */

    #[test]
    fn test_matches_trailing_slash_origin() -> Result<(), Box<dyn std::error::Error>> {
        // URLs with trailing slashes should still match (Url::parse normalises)
        let ao = parse("https://example.com")?;
        assert!(ao.matches("https://example.com/"));
        Ok(())
    }

    #[test]
    fn test_matches_path_in_origin_still_matches_host() -> Result<(), Box<dyn std::error::Error>> {
        // Origin with path component; host/scheme/port still match
        let ao = parse("https://example.com")?;
        assert!(ao.matches("https://example.com/some/path"));
        Ok(())
    }

    #[test]
    fn test_matches_origin_with_query_string() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("https://example.com")?;
        assert!(ao.matches("https://example.com?foo=bar"));
        Ok(())
    }

    #[test]
    fn test_matches_ip_address_exact() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://127.0.0.1:3000")?;
        assert!(ao.matches("http://127.0.0.1:3000"));
        assert!(!ao.matches("http://127.0.0.1:3001"));
        Ok(())
    }

    #[test]
    fn test_matches_ip_address_different_ip() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://192.168.1.1:8080")?;
        assert!(!ao.matches("http://192.168.1.2:8080"));
        Ok(())
    }

    #[test]
    fn test_matches_localhost_with_port() -> Result<(), Box<dyn std::error::Error>> {
        let ao = parse("http://localhost:3000")?;
        assert!(ao.matches("http://localhost:3000"));
        assert!(!ao.matches("http://localhost:3001"));
        assert!(!ao.matches("https://localhost:3000"));
        Ok(())
    }
}
