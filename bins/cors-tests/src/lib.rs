// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Native-target CORS tests for provii-verifier.
//!
//! SOURCE OF TRUTH: The canonical `AllowedOrigins` implementation lives in
//! `provii-verifier/src/config.rs` (lines 24-141). This file is a copy that MUST
//! stay in sync with the source. If CORS matching behaviour changes in
//! config.rs, update this file accordingly.
//!
//! The root provii-verifier package targets wasm32-unknown-unknown (via
//! `.cargo/config.toml`), making all `#[test]` blocks dead code on native
//! targets. This subcrate exercises the same CORS logic on the native target
//! so tests actually execute in CI.
//!
//! Additionally includes tests for `match_origin` / `origin_matches_pattern`
//! from `src/hosted/cors.rs` and `src/utils/origin.rs`.

#![forbid(unsafe_code)]

use url::Url;

// =============================================================================
// AllowedOrigins, copied from provii-verifier/src/config.rs:24-141
// KEEP IN SYNC with the source file. Any drift is a bug.
// =============================================================================

/// Wrapper around a list of origin patterns with helper matching logic.
///
/// SECURITY: Implements OWASP CORS best practices:
/// - Wildcard patterns are restricted in production
/// - Credentials are never allowed with global wildcard origins
/// - Subdomain wildcards allow credentials because the response reflects
///   the specific matched origin (never "*" in the ACAO header)
/// - All origin matching is case-insensitive
#[derive(Debug, Clone)]
pub struct AllowedOrigins {
    patterns: Vec<String>,
    // SECURITY: Track if this list contains the global wildcard to prevent
    // accidentally allowing credentials with wildcard origins
    contains_global_wildcard: bool,
}

/// Errors returned when building an `AllowedOrigins` from a raw string.
#[derive(Debug)]
pub enum ConfigError {
    /// The origin list was empty, whitespace-only, or unparseable.
    InvalidOrigins,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOrigins => {
                write!(
                    f,
                    "ALLOWED_ORIGINS or PROVII_CORS_ORIGINS is empty or malformed"
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl AllowedOrigins {
    /// Returns a wildcard `AllowedOrigins` that matches any origin.
    pub fn wildcard() -> Self {
        Self {
            patterns: vec!["*".to_string()],
            contains_global_wildcard: true,
        }
    }

    /// Parse a comma-separated string of origin patterns into an `AllowedOrigins`.
    ///
    /// Returns `ConfigError::InvalidOrigins` when the input is empty or
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

        let contains_global_wildcard = list.iter().any(|p| p == "*");

        Ok(Self {
            patterns: list,
            contains_global_wildcard,
        })
    }

    /// Returns true if the origin matches any allowed pattern.
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

    /// Returns true only if credentials should be allowed for this origin.
    ///
    /// The global wildcard ("*") always blocks credentials because the OWASP
    /// prohibition is against `Access-Control-Allow-Credentials: true` when
    /// `Access-Control-Allow-Origin: *`. Subdomain wildcard patterns (e.g.
    /// `https://*.provii.app`) DO allow credentials because the response
    /// reflects the specific matched origin in the ACAO header (never "*").
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

// =============================================================================
// origin_matches_pattern, copied from provii-verifier/src/utils/origin.rs
// Used by the hosted/cors.rs match_origin function.
// KEEP IN SYNC with the source file.
// =============================================================================

/// Match an origin string against a pattern (shared origin matching logic).
///
/// Supports:
/// - Global wildcard: `"*"` matches any origin
/// - Exact match: `"https://example.com"` matches only itself (case-insensitive hostname)
/// - Subdomain wildcard: `"https://*.example.com"` matches `https://sub.example.com`
///   but NOT `https://example.com` and NOT `https://evilexample.com`
pub fn origin_matches_pattern(pattern: &str, origin: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pattern = pattern.trim();
    let origin = origin.trim();

    if pattern.is_empty() || origin.is_empty() {
        return false;
    }

    // Wildcard subdomain matching
    if let Some((scheme_prefix, wildcard_suffix)) = pattern.split_once("*.") {
        if scheme_prefix.is_empty() || wildcard_suffix.is_empty() {
            return false;
        }

        let pattern_url_str = format!("{}placeholder.{}", scheme_prefix, wildcard_suffix);
        let parsed_pattern = match Url::parse(&pattern_url_str) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let pattern_host_suffix = match parsed_pattern.host_str() {
            Some(h) => h
                .strip_prefix("placeholder.")
                .unwrap_or(h)
                .to_ascii_lowercase(),
            None => return false,
        };
        let pattern_port = parsed_pattern.port();

        let parsed_origin = match Url::parse(origin) {
            Ok(u) => u,
            Err(_) => return false,
        };

        let origin_host = match parsed_origin.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };

        if parsed_origin.scheme() != parsed_pattern.scheme() {
            return false;
        }

        if parsed_origin.port() != pattern_port {
            return false;
        }

        // DOT-BOUNDARY ENFORCEMENT
        let dot_suffix = format!(".{}", pattern_host_suffix);
        if origin_host.ends_with(&dot_suffix) {
            let subdomain_len = origin_host.len().saturating_sub(dot_suffix.len());
            return subdomain_len > 0;
        }

        return false;
    }

    // Exact match
    let parsed_pattern = match Url::parse(pattern) {
        Ok(u) => u,
        Err(_) => return pattern.eq_ignore_ascii_case(origin),
    };

    let parsed_origin = match Url::parse(origin) {
        Ok(u) => u,
        Err(_) => return false,
    };

    if parsed_pattern.scheme() != parsed_origin.scheme() {
        return false;
    }

    let pattern_host = parsed_pattern
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let origin_host = parsed_origin
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if pattern_host != origin_host {
        return false;
    }

    if parsed_pattern.port() != parsed_origin.port() {
        return false;
    }

    parsed_pattern.path() == parsed_origin.path()
}

/// Convenience wrapper matching hosted/cors.rs `match_origin` signature
/// (pattern first, origin second).
pub fn match_origin(pattern: &str, origin: &str) -> bool {
    origin_matches_pattern(pattern, origin)
}

// =============================================================================
// Tests
// =============================================================================

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

    // =========================================================================
    // AllowedOrigins::new() tests (from config.rs)
    // =========================================================================

    #[test]
    fn test_allowed_origins_new_single() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert_eq!(origins.patterns.len(), 1);
        assert_eq!(origins.patterns[0], "https://example.com");
        assert!(!origins.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_allowed_origins_new_multiple() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,https://b.com,https://c.com".to_string())?;
        assert_eq!(origins.patterns.len(), 3);
        assert_eq!(origins.patterns[0], "https://a.com");
        assert_eq!(origins.patterns[1], "https://b.com");
        assert_eq!(origins.patterns[2], "https://c.com");
        assert!(!origins.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_allowed_origins_new_with_spaces() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new(" https://a.com , https://b.com ".to_string())?;
        assert_eq!(origins.patterns.len(), 2);
        assert_eq!(origins.patterns[0], "https://a.com");
        assert_eq!(origins.patterns[1], "https://b.com");
        assert!(!origins.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_allowed_origins_new_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("*".to_string())?;
        assert_eq!(origins.patterns.len(), 1);
        assert_eq!(origins.patterns[0], "*");
        assert!(origins.contains_global_wildcard);
        Ok(())
    }

    #[test]
    fn test_allowed_origins_new_empty_string() -> Result<(), Box<dyn std::error::Error>> {
        let result = AllowedOrigins::new("".to_string());
        assert!(result.is_err());
        let err = result.err().ok_or("expected error, got Ok")?;
        assert!(matches!(err, ConfigError::InvalidOrigins));
        Ok(())
    }

    #[test]
    fn test_allowed_origins_new_whitespace_only() {
        let result = AllowedOrigins::new("   ".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_allowed_origins_new_multiple_commas() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,,https://b.com".to_string())?;
        assert_eq!(origins.patterns.len(), 2); // Empty string filtered out
        assert!(!origins.contains_global_wildcard);
        Ok(())
    }

    // =========================================================================
    // AllowedOrigins::matches() tests (from config.rs)
    // =========================================================================

    #[test]
    fn test_matches_exact_origin() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(origins.matches("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_exact_origin_no_match() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(!origins.matches("https://other.com"));
        Ok(())
    }

    #[test]
    fn test_matches_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("*".to_string())?;
        assert!(origins.matches("https://example.com"));
        assert!(origins.matches("http://localhost:3000"));
        assert!(origins.matches("https://anything.org"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.matches("https://sub.example.com"));
        assert!(origins.matches("https://deep.sub.example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_no_match_root() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(!origins.matches("https://example.com")); // Root domain doesn't match
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_no_match_different_domain(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(!origins.matches("https://sub.other.com"));
        Ok(())
    }

    #[test]
    fn test_matches_scheme_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(!origins.matches("http://example.com")); // http vs https
        Ok(())
    }

    #[test]
    fn test_matches_port_exact() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("http://localhost:3000".to_string())?;
        assert!(origins.matches("http://localhost:3000"));
        assert!(!origins.matches("http://localhost:3001"));
        Ok(())
    }

    #[test]
    fn test_matches_invalid_url() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(!origins.matches("not-a-valid-url"));
        assert!(!origins.matches(""));
        Ok(())
    }

    #[test]
    fn test_matches_multiple_patterns() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,https://b.com".to_string())?;
        assert!(origins.matches("https://a.com"));
        assert!(origins.matches("https://b.com"));
        assert!(!origins.matches("https://c.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_case_insensitive() -> Result<(), Box<dyn std::error::Error>>
    {
        let origins = AllowedOrigins::new("https://*.Example.COM".to_string())?;
        assert!(origins.matches("https://sub.example.com"));
        assert!(origins.matches("https://SUB.EXAMPLE.COM"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_scheme_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(!origins.matches("http://sub.example.com")); // http vs https
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_port_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com:443".to_string())?;
        assert!(!origins.matches("https://sub.example.com:8443"));
        Ok(())
    }

    #[test]
    fn test_matches_default_https_port() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(origins.matches("https://example.com:443"));
        assert!(origins.matches("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_default_http_port() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("http://example.com".to_string())?;
        assert!(origins.matches("http://example.com:80"));
        assert!(origins.matches("http://example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_mixed_case_host() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://Example.COM".to_string())?;
        assert!(origins.matches("https://example.com"));
        assert!(origins.matches("https://EXAMPLE.COM"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_multi_level() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.matches("https://api.staging.example.com"));
        assert!(origins.matches("https://very.deep.sub.example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_single_level() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.matches("https://sub.example.com"));
        assert!(origins.matches("https://api.example.com"));
        Ok(())
    }

    #[test]
    fn test_matches_multiple_patterns_first_match() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,https://b.com,https://c.com".to_string())?;
        assert!(origins.matches("https://a.com"));
        Ok(())
    }

    #[test]
    fn test_matches_multiple_patterns_middle_match() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,https://b.com,https://c.com".to_string())?;
        assert!(origins.matches("https://b.com"));
        Ok(())
    }

    #[test]
    fn test_matches_multiple_patterns_last_match() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,https://b.com,https://c.com".to_string())?;
        assert!(origins.matches("https://c.com"));
        Ok(())
    }

    #[test]
    fn test_matches_wildcard_with_exact_origins() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://specific.com,*".to_string())?;
        assert!(origins.matches("https://specific.com"));
        assert!(origins.matches("https://anything-else.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_with_path() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.matches("https://sub.example.com/path/to/resource"));
        assert!(origins.matches("https://api.example.com/v1/endpoint"));
        Ok(())
    }

    #[test]
    fn test_matches_exact_origin_with_path() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(origins.matches("https://example.com/some/path"));
        assert!(origins.matches("https://example.com/"));
        Ok(())
    }

    #[test]
    fn test_matches_localhost_various_ports() -> Result<(), Box<dyn std::error::Error>> {
        let origins =
            AllowedOrigins::new("http://localhost:3000,http://localhost:8080".to_string())?;
        assert!(origins.matches("http://localhost:3000"));
        assert!(origins.matches("http://localhost:8080"));
        assert!(!origins.matches("http://localhost:9000"));
        Ok(())
    }

    #[test]
    fn test_matches_ip_address() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("http://127.0.0.1".to_string())?;
        assert!(origins.matches("http://127.0.0.1"));
        assert!(!origins.matches("http://192.168.1.1"));
        Ok(())
    }

    #[test]
    fn test_matches_ip_address_with_port() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("http://127.0.0.1:8080".to_string())?;
        assert!(origins.matches("http://127.0.0.1:8080"));
        assert!(!origins.matches("http://127.0.0.1:3000"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_empty_subdomain() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(!origins.matches("https://example.com"));
        assert!(!origins.matches("https://example.com/"));
        Ok(())
    }

    #[test]
    fn test_matches_invalid_pattern_url() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("invalid-pattern".to_string())?;
        assert!(!origins.matches("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_new_with_commas_and_spaces_complex() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("  https://a.com  ,  ,  https://b.com  ,  ".to_string())?;
        assert_eq!(origins.patterns.len(), 2);
        assert!(origins.matches("https://a.com"));
        assert!(origins.matches("https://b.com"));
        Ok(())
    }

    #[test]
    fn test_matches_subdomain_wildcard_trailing_dot() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.matches("https://sub.example.com"));
        Ok(())
    }

    // =========================================================================
    // AllowedOrigins::allows_credentials() tests (from config.rs)
    // =========================================================================

    #[test]
    fn test_allows_credentials_exact_match() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(origins.allows_credentials("https://example.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_wildcard_denied() -> Result<(), Box<dyn std::error::Error>> {
        // SECURITY: Global wildcard MUST NOT allow credentials (OWASP CORS)
        let origins = AllowedOrigins::new("*".to_string())?;
        assert!(!origins.allows_credentials("https://example.com"));
        assert!(!origins.allows_credentials("https://anything.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_subdomain_wildcard_allowed() -> Result<(), Box<dyn std::error::Error>>
    {
        // Subdomain wildcards ALLOW credentials because the response
        // reflects the specific matched origin in Access-Control-Allow-Origin
        // (never "*"). The OWASP prohibition is against credentials + wildcard
        // ACAO header value. The hosted flow requires credentials for session
        // cookies across *.provii.app subdomains.
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.allows_credentials("https://sub.example.com"));
        assert!(origins.allows_credentials("https://api.example.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_mixed_wildcard_and_exact() -> Result<(), Box<dyn std::error::Error>>
    {
        // SECURITY: If list contains global wildcard "*", NO credentials allowed
        let origins = AllowedOrigins::new("https://specific.com,*".to_string())?;
        assert!(!origins.allows_credentials("https://specific.com"));
        assert!(!origins.allows_credentials("https://other.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_multiple_exact_origins() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://a.com,https://b.com".to_string())?;
        assert!(origins.allows_credentials("https://a.com"));
        assert!(origins.allows_credentials("https://b.com"));
        assert!(!origins.allows_credentials("https://c.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_scheme_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(!origins.allows_credentials("http://example.com"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_port_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com:443".to_string())?;
        assert!(!origins.allows_credentials("https://example.com:8443"));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_invalid_origin() -> Result<(), Box<dyn std::error::Error>> {
        let origins = AllowedOrigins::new("https://example.com".to_string())?;
        assert!(!origins.allows_credentials("not-a-url"));
        assert!(!origins.allows_credentials(""));
        Ok(())
    }

    #[test]
    fn test_allows_credentials_subdomain_matches_and_allows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Subdomain wildcard matches AND allows credentials (response
        // reflects specific origin, not "*").
        let origins = AllowedOrigins::new("https://*.example.com".to_string())?;
        assert!(origins.matches("https://sub.example.com"));
        assert!(origins.allows_credentials("https://sub.example.com"));
        Ok(())
    }

    // =========================================================================
    // New tests: global wildcard blocks credentials, production scenario
    // =========================================================================

    #[test]
    fn test_global_wildcard_blocks_credentials_for_any_origin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Even if the origin matches (which it always does with "*"), credentials
        // must be blocked because we cannot set ACAO to "*" with credentials.
        let origins = AllowedOrigins::new("*".to_string())?;
        assert!(origins.matches("https://app.provii.app"));
        assert!(!origins.allows_credentials("https://app.provii.app"));
        assert!(origins.matches("http://localhost:3000"));
        assert!(!origins.allows_credentials("http://localhost:3000"));
        Ok(())
    }

    #[test]
    fn test_provii_production_scenario() -> Result<(), Box<dyn std::error::Error>> {
        // Production uses *.provii.app for the hosted flow. Subdomains
        // must match and allow credentials for session cookies.
        let origins = AllowedOrigins::new("https://*.provii.app".to_string())?;

        // Valid subdomains match and allow credentials
        assert!(origins.matches("https://verify.provii.app"));
        assert!(origins.allows_credentials("https://verify.provii.app"));

        assert!(origins.matches("https://hosted.provii.app"));
        assert!(origins.allows_credentials("https://hosted.provii.app"));

        assert!(origins.matches("https://demo.provii.app"));
        assert!(origins.allows_credentials("https://demo.provii.app"));

        // Root domain does NOT match
        assert!(!origins.matches("https://provii.app"));
        assert!(!origins.allows_credentials("https://provii.app"));

        // Different domain does NOT match
        assert!(!origins.matches("https://evilprovii.app"));
        assert!(!origins.allows_credentials("https://evilprovii.app"));

        // HTTP scheme mismatch
        assert!(!origins.matches("http://verify.provii.app"));
        assert!(!origins.allows_credentials("http://verify.provii.app"));

        Ok(())
    }

    // =========================================================================
    // hosted/cors.rs tests (match_origin / origin_matches_pattern)
    // =========================================================================

    #[test]
    fn test_match_origin_exact() {
        assert!(match_origin("https://example.com", "https://example.com"));
        assert!(!match_origin("https://example.com", "https://other.com"));
    }

    #[test]
    fn test_match_origin_wildcard() {
        // Should match subdomains
        assert!(match_origin(
            "https://*.example.com",
            "https://sub.example.com"
        ));
        assert!(match_origin(
            "https://*.example.com",
            "https://deep.sub.example.com"
        ));

        // Should NOT match base domain
        assert!(!match_origin(
            "https://*.example.com",
            "https://example.com"
        ));

        // Should NOT match different domains
        assert!(!match_origin("https://*.example.com", "https://evil.com"));
    }

    #[test]
    fn test_match_origin_scheme_sensitive() {
        assert!(!match_origin("https://example.com", "http://example.com"));
        assert!(!match_origin("http://example.com", "https://example.com"));
    }

    #[test]
    fn test_match_origin_global_wildcard() {
        assert!(match_origin("*", "https://example.com"));
        assert!(match_origin("*", "http://localhost:3000"));
        assert!(match_origin("*", "https://sub.deep.example.org"));
    }

    #[test]
    fn test_match_origin_dot_boundary_enforcement() {
        // evilexample.com must NOT match *.example.com
        assert!(!match_origin(
            "https://*.example.com",
            "https://evilexample.com"
        ));
    }

    // =========================================================================
    // ConfigError Display + Error trait coverage
    // =========================================================================

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::InvalidOrigins;
        let msg = format!("{err}");
        assert!(
            msg.contains("ALLOWED_ORIGINS"),
            "display should mention env var: {msg}"
        );
        assert!(
            msg.contains("PROVII_CORS_ORIGINS"),
            "display should mention alt env var: {msg}"
        );
    }

    #[test]
    fn test_config_error_is_std_error() {
        let err = ConfigError::InvalidOrigins;
        // Verify it implements std::error::Error by calling source()
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn test_config_error_debug() {
        let err = ConfigError::InvalidOrigins;
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("InvalidOrigins"));
    }

    // =========================================================================
    // AllowedOrigins::wildcard() coverage
    // =========================================================================

    #[test]
    fn test_allowed_origins_wildcard_constructor() {
        let origins = AllowedOrigins::wildcard();
        assert!(origins.contains_global_wildcard);
        assert_eq!(origins.patterns.len(), 1);
        assert_eq!(origins.patterns[0], "*");
        assert!(origins.matches("https://any.domain.com"));
        assert!(!origins.allows_credentials("https://any.domain.com"));
    }

    // =========================================================================
    // origin_matches_pattern edge cases (empty, whitespace, malformed)
    // =========================================================================

    #[test]
    fn test_origin_matches_pattern_empty_pattern() {
        assert!(!origin_matches_pattern("", "https://example.com"));
    }

    #[test]
    fn test_origin_matches_pattern_empty_origin() {
        assert!(!origin_matches_pattern("https://example.com", ""));
    }

    #[test]
    fn test_origin_matches_pattern_both_empty() {
        assert!(!origin_matches_pattern("", ""));
    }

    #[test]
    fn test_origin_matches_pattern_whitespace_only_pattern() {
        assert!(!origin_matches_pattern("   ", "https://example.com"));
    }

    #[test]
    fn test_origin_matches_pattern_whitespace_only_origin() {
        assert!(!origin_matches_pattern("https://example.com", "   "));
    }

    #[test]
    fn test_origin_matches_pattern_bare_wildcard_prefix_no_suffix() {
        // Pattern "*.": split_once gives ("", "") which should fail
        assert!(!origin_matches_pattern("*.", "https://example.com"));
    }

    #[test]
    fn test_origin_matches_pattern_wildcard_with_empty_suffix() {
        // Pattern "https://*.": split_once("*.") -> ("https://", "") -> empty suffix -> false
        assert!(!origin_matches_pattern("https://*.", "https://example.com"));
    }

    #[test]
    fn test_origin_matches_pattern_wildcard_invalid_pattern_url() {
        // A wildcard pattern that cannot be parsed as a URL after placeholder substitution
        assert!(!origin_matches_pattern(
            "not-a-scheme://*.example.com",
            "https://sub.example.com"
        ));
    }

    #[test]
    fn test_origin_matches_pattern_wildcard_invalid_origin_url() {
        // Valid wildcard pattern, but origin is not a valid URL
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "not-a-url"
        ));
    }

    #[test]
    fn test_origin_matches_pattern_wildcard_port_mismatch() {
        assert!(!origin_matches_pattern(
            "https://*.example.com:8080",
            "https://sub.example.com:9090"
        ));
    }

    #[test]
    fn test_origin_matches_pattern_wildcard_scheme_mismatch() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "http://sub.example.com"
        ));
    }

    #[test]
    fn test_origin_matches_pattern_exact_unparseable_pattern_case_insensitive() {
        // When pattern is not a valid URL, falls back to case-insensitive string comparison
        assert!(origin_matches_pattern("not-a-url", "NOT-A-URL"));
        assert!(origin_matches_pattern("NOT-A-URL", "not-a-url"));
    }

    #[test]
    fn test_origin_matches_pattern_exact_unparseable_pattern_no_match() {
        assert!(!origin_matches_pattern("not-a-url", "different"));
    }

    #[test]
    fn test_origin_matches_pattern_exact_unparseable_origin() {
        // Pattern is valid URL, origin is not
        assert!(!origin_matches_pattern("https://example.com", "not-a-url"));
    }

    #[test]
    fn test_origin_matches_pattern_exact_port_mismatch() {
        assert!(!origin_matches_pattern(
            "https://example.com:443",
            "https://example.com:8443"
        ));
    }

    #[test]
    fn test_origin_matches_pattern_exact_path_mismatch() {
        assert!(!origin_matches_pattern(
            "https://example.com/foo",
            "https://example.com/bar"
        ));
    }

    #[test]
    fn test_origin_matches_pattern_exact_path_match() {
        assert!(origin_matches_pattern(
            "https://example.com/foo",
            "https://example.com/foo"
        ));
    }

    // =========================================================================
    // Property-based tests (from config.rs)
    // =========================================================================

    use proptest::prelude::*;

    proptest! {
        /// Property: Wildcard always matches valid URLs
        #[test]
        fn prop_wildcard_matches_all(scheme in "(https?)", host in "[a-z]{3,10}\\.(com|org|net)") {
            let origins = AllowedOrigins::new("*".to_string())
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let url = format!("{}://{}", scheme, host);
            prop_assert!(origins.matches(&url));
        }

        /// Property: Exact origin match is deterministic
        #[test]
        fn prop_exact_match_deterministic(host in "[a-z]{3,10}\\.com") {
            let url = format!("https://{}", host);
            let origins = AllowedOrigins::new(url.clone())
                .map_err(|e| TestCaseError::fail(e.to_string()))?;

            let result1 = origins.matches(&url);
            let result2 = origins.matches(&url);
            prop_assert_eq!(result1, result2);
        }

        /// Property: Non-matching scheme always fails
        #[test]
        fn prop_scheme_mismatch_fails(host in "[a-z]{3,10}\\.com") {
            let origins = AllowedOrigins::new(format!("https://{}", host))
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let http_url = format!("http://{}", host);
            prop_assert!(!origins.matches(&http_url));
        }

        /// Property: Subdomain wildcard matches any subdomain
        #[test]
        fn prop_subdomain_wildcard(
            subdomain in "[a-z]{3,10}",
            domain in "[a-z]{3,10}\\.com"
        ) {
            let pattern = format!("https://*.{}", domain);
            let origins = AllowedOrigins::new(pattern)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let url = format!("https://{}.{}", subdomain, domain);
            prop_assert!(origins.matches(&url));
        }

        /// Property: Empty origin list always fails
        #[test]
        fn prop_empty_fails(_seed in any::<u8>()) {
            let result = AllowedOrigins::new("".to_string());
            prop_assert!(result.is_err());
        }

        /// Property: AllowedOrigins parsing is deterministic
        #[test]
        fn prop_parsing_deterministic(origins_str in "[a-z]{3,10}\\.(com|org)") {
            let url = format!("https://{}", origins_str);
            let result1 = AllowedOrigins::new(url.clone());
            let result2 = AllowedOrigins::new(url);
            prop_assert_eq!(result1.is_ok(), result2.is_ok());
        }

        /// Property: Whitespace trimming works correctly
        #[test]
        fn prop_whitespace_trimming(
            spaces_before in 0usize..5,
            spaces_after in 0usize..5
        ) {
            let origin = "https://example.com";
            let padded = format!("{}{}{}",
                " ".repeat(spaces_before),
                origin,
                " ".repeat(spaces_after)
            );

            let origins = AllowedOrigins::new(padded)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&origins.patterns[0], origin);
        }

        /// Property: Global wildcard always blocks credentials
        #[test]
        fn prop_global_wildcard_blocks_credentials(host in "[a-z]{3,10}\\.com") {
            let origins = AllowedOrigins::new("*".to_string())
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let url = format!("https://{}", host);
            prop_assert!(origins.matches(&url));
            prop_assert!(!origins.allows_credentials(&url));
        }

        /// Property: Subdomain wildcard allows credentials (reflects specific origin)
        #[test]
        fn prop_subdomain_wildcard_allows_credentials(
            subdomain in "[a-z]{3,10}",
            domain in "[a-z]{3,10}\\.com"
        ) {
            let pattern = format!("https://*.{}", domain);
            let origins = AllowedOrigins::new(pattern)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let url = format!("https://{}.{}", subdomain, domain);
            prop_assert!(origins.allows_credentials(&url));
        }
    }
}
