// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared origin pattern matching with dot-boundary enforcement (pure logic).
//!
//! Single source of truth for origin matching. Prevents suffix attacks
//! (e.g. `evilexample.com` matching `*.example.com`) by enforcing a
//! leading dot boundary.
#![forbid(unsafe_code)]

use url::Url;

/// Match an origin string against a pattern.
///
/// Supports:
/// - Global wildcard: `"*"` matches any origin
/// - Exact match: `"https://example.com"` matches only itself (case-insensitive hostname)
/// - Subdomain wildcard: `"https://*.example.com"` matches `https://sub.example.com`
///   but NOT `https://example.com` and NOT `https://evilexample.com`
/// - Multiple wildcards in a single pattern are rejected
///
/// Scheme and port must match exactly. Hostname comparison is case-insensitive.
/// Returns `false` for any malformed input rather than panicking.
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
        // VA-HOS-005: Reject patterns with multiple wildcards.
        if wildcard_suffix.contains('*') {
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
        Err(_) => {
            if pattern.contains("://") || origin.contains("://") {
                return false;
            }
            return pattern.eq_ignore_ascii_case(origin);
        }
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

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn global_wildcard_matches_anything() {
        assert!(origin_matches_pattern("*", "https://example.com"));
        assert!(origin_matches_pattern("*", "http://localhost:3000"));
    }

    #[test]
    fn exact_match_same_origin() {
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://example.com"
        ));
    }

    #[test]
    fn exact_match_case_insensitive() {
        assert!(origin_matches_pattern(
            "https://Example.COM",
            "https://example.com"
        ));
    }

    #[test]
    fn exact_match_scheme_mismatch() {
        assert!(!origin_matches_pattern(
            "https://example.com",
            "http://example.com"
        ));
    }

    #[test]
    fn exact_match_port_mismatch() {
        assert!(!origin_matches_pattern(
            "https://example.com:8443",
            "https://example.com"
        ));
    }

    #[test]
    fn wildcard_matches_valid_subdomain() {
        assert!(origin_matches_pattern(
            "https://*.example.com",
            "https://app.example.com"
        ));
        assert!(origin_matches_pattern(
            "https://*.example.com",
            "https://sub.deep.example.com"
        ));
    }

    #[test]
    fn wildcard_rejects_base_domain() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://example.com"
        ));
    }

    // CRITICAL: Suffix attack / dot-boundary enforcement
    #[test]
    fn wildcard_rejects_suffix_attack_evilexample() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://evilexample.com"
        ));
    }

    #[test]
    fn wildcard_rejects_suffix_attack_provii() {
        assert!(!origin_matches_pattern(
            "https://*.provii.app",
            "https://evilprovii.app"
        ));
    }

    #[test]
    fn wildcard_rejects_double_wildcard() {
        assert!(!origin_matches_pattern(
            "https://*.*.example.com",
            "https://a.b.example.com"
        ));
    }

    #[test]
    fn wildcard_scheme_mismatch() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "http://sub.example.com"
        ));
    }

    #[test]
    fn wildcard_port_match() {
        assert!(origin_matches_pattern(
            "https://*.example.com:8443",
            "https://sub.example.com:8443"
        ));
    }

    #[test]
    fn wildcard_port_mismatch() {
        assert!(!origin_matches_pattern(
            "https://*.example.com:8443",
            "https://sub.example.com"
        ));
    }

    #[test]
    fn empty_pattern_rejects() {
        assert!(!origin_matches_pattern("", "https://example.com"));
    }

    #[test]
    fn empty_origin_rejects() {
        assert!(!origin_matches_pattern("https://example.com", ""));
    }

    #[test]
    fn malformed_origin_rejects() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "not-a-url"
        ));
    }

    #[test]
    fn whitespace_trimmed() {
        assert!(origin_matches_pattern(
            " https://example.com ",
            " https://example.com "
        ));
    }

    #[test]
    fn wildcard_case_insensitive() {
        assert!(origin_matches_pattern(
            "https://*.EXAMPLE.COM",
            "https://sub.example.com"
        ));
    }

    #[test]
    fn exact_match_with_port() {
        assert!(origin_matches_pattern(
            "http://localhost:3000",
            "http://localhost:3000"
        ));
    }

    #[test]
    fn exact_match_default_port_443() {
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://example.com:443"
        ));
    }

    #[test]
    fn malformed_pattern_fallback_case_insensitive() {
        assert!(origin_matches_pattern("not-a-url", "not-a-url"));
        assert!(origin_matches_pattern("NOT-A-URL", "not-a-url"));
    }

    #[test]
    fn bare_star_dot_domain_rejects() {
        assert!(!origin_matches_pattern(
            "*.example.com",
            "https://sub.example.com"
        ));
    }

    #[test]
    fn wildcard_single_char_subdomain() {
        assert!(origin_matches_pattern(
            "https://*.example.com",
            "https://x.example.com"
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        #[test]
        fn prop_wildcard_matches_all(host in "[a-z]{3,15}\\.com") {
            let origin = format!("https://{}", host);
            prop_assert!(origin_matches_pattern("*", &origin));
        }

        #[test]
        fn prop_exact_match_reflexive(host in "[a-z]{3,15}\\.com") {
            let url = format!("https://{}", host);
            prop_assert!(origin_matches_pattern(&url, &url));
        }

        #[test]
        fn prop_wildcard_rejects_base(host in "[a-z]{3,15}\\.com") {
            let pattern = format!("https://*.{}", host);
            let origin = format!("https://{}", host);
            prop_assert!(!origin_matches_pattern(&pattern, &origin));
        }

        #[test]
        fn prop_suffix_attack_rejected(
            prefix in "[a-z]{2,6}",
            host in "[a-z]{3,10}\\.com"
        ) {
            let pattern = format!("https://*.{}", host);
            let evil_origin = format!("https://{}{}", prefix, host);
            prop_assert!(!origin_matches_pattern(&pattern, &evil_origin));
        }
    }
}
