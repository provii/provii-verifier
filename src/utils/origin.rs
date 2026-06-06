// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Shared origin pattern matching with dot-boundary enforcement.
//!
//! Previous implementations used `ends_with(suffix)` without
//! enforcing a leading dot, allowing `https://evilexample.com` to match
//! a pattern of `https://*.example.com`. This module is the single source
//! of truth for origin matching across the entire codebase.

// Delegate to the pure-logic crate. The function signature and behaviour
// are byte-identical; this is a re-export, not a wrapper.
pub use provii_verifier_logic::origin::origin_matches_pattern;

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    // =========================================================================
    // Global wildcard
    // =========================================================================

    #[test]
    fn global_wildcard_matches_anything() {
        assert!(origin_matches_pattern("*", "https://example.com"));
        assert!(origin_matches_pattern("*", "http://localhost:3000"));
        assert!(origin_matches_pattern("*", "https://sub.deep.example.org"));
    }

    // =========================================================================
    // Exact match
    // =========================================================================

    #[test]
    fn exact_match_same_origin() {
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://example.com"
        ));
    }

    #[test]
    fn exact_match_case_insensitive_hostname() {
        assert!(origin_matches_pattern(
            "https://Example.COM",
            "https://example.com"
        ));
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://EXAMPLE.COM"
        ));
    }

    #[test]
    fn exact_match_scheme_mismatch_rejects() {
        assert!(!origin_matches_pattern(
            "https://example.com",
            "http://example.com"
        ));
    }

    #[test]
    fn exact_match_port_mismatch_rejects() {
        assert!(!origin_matches_pattern(
            "https://example.com:8443",
            "https://example.com"
        ));
        assert!(!origin_matches_pattern(
            "https://example.com",
            "https://example.com:8443"
        ));
    }

    #[test]
    fn exact_match_with_port() {
        assert!(origin_matches_pattern(
            "http://localhost:3000",
            "http://localhost:3000"
        ));
    }

    // =========================================================================
    // Wildcard subdomain matching
    // =========================================================================

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
        // "*.example.com" must NOT match "example.com" itself
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://example.com"
        ));
    }

    // =========================================================================
    // CRITICAL: Suffix attack / dot-boundary enforcement
    // =========================================================================

    #[test]
    fn wildcard_rejects_suffix_attack_evilexample() {
        // This is the primary vulnerability being fixed.
        // "evilexample.com" ends with "example.com" but lacks the dot boundary.
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
    fn wildcard_rejects_suffix_attack_with_prefix() {
        // "notexample.com" must not match "*.example.com"
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://notexample.com"
        ));
    }

    #[test]
    fn wildcard_rejects_suffix_attack_with_hyphen() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://evil-example.com"
        ));
    }

    // =========================================================================
    // VA-HOS-005: Multiple wildcards rejected
    // =========================================================================

    #[test]
    fn wildcard_rejects_double_wildcard_pattern() {
        assert!(!origin_matches_pattern(
            "https://*.*.example.com",
            "https://a.b.example.com"
        ));
    }

    #[test]
    fn wildcard_rejects_trailing_wildcard() {
        assert!(!origin_matches_pattern(
            "https://*.example.*",
            "https://sub.example.com"
        ));
    }

    // =========================================================================
    // Scheme and port matching for wildcards
    // =========================================================================

    #[test]
    fn wildcard_scheme_mismatch_rejects() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "http://sub.example.com"
        ));
    }

    #[test]
    fn wildcard_port_mismatch_rejects() {
        assert!(!origin_matches_pattern(
            "https://*.example.com:8443",
            "https://sub.example.com"
        ));
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://sub.example.com:8443"
        ));
    }

    #[test]
    fn wildcard_port_match_succeeds() {
        assert!(origin_matches_pattern(
            "https://*.example.com:8443",
            "https://sub.example.com:8443"
        ));
    }

    // =========================================================================
    // Case insensitivity for wildcards
    // =========================================================================

    #[test]
    fn wildcard_case_insensitive() {
        assert!(origin_matches_pattern(
            "https://*.EXAMPLE.COM",
            "https://sub.example.com"
        ));
        assert!(origin_matches_pattern(
            "https://*.example.com",
            "https://SUB.EXAMPLE.COM"
        ));
    }

    // =========================================================================
    // Invalid / edge-case inputs
    // =========================================================================

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
    fn wildcard_with_deep_subdomain() {
        assert!(origin_matches_pattern(
            "https://*.example.com",
            "https://a.b.c.example.com"
        ));
    }

    // =========================================================================
    // Additional edge cases
    // =========================================================================

    #[test]
    fn both_empty_rejects() {
        assert!(!origin_matches_pattern("", ""));
    }

    #[test]
    fn whitespace_only_pattern_rejects() {
        assert!(!origin_matches_pattern("   ", "https://example.com"));
    }

    #[test]
    fn whitespace_only_origin_rejects() {
        assert!(!origin_matches_pattern("https://example.com", "   "));
    }

    #[test]
    fn exact_match_with_trailing_slash() {
        // URL parsing normalises trailing slash as root path
        assert!(origin_matches_pattern(
            "https://example.com/",
            "https://example.com/"
        ));
    }

    #[test]
    fn exact_match_different_paths() {
        assert!(!origin_matches_pattern(
            "https://example.com/a",
            "https://example.com/b"
        ));
    }

    #[test]
    fn exact_match_default_port_443() {
        // https default port is 443; explicit :443 should match
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://example.com:443"
        ));
    }

    #[test]
    fn exact_match_different_explicit_ports() {
        assert!(!origin_matches_pattern(
            "https://example.com:8443",
            "https://example.com:9443"
        ));
    }

    #[test]
    fn wildcard_pattern_missing_scheme_rejects() {
        // Pattern without :// is not a valid wildcard
        assert!(!origin_matches_pattern(
            "*.example.com",
            "https://sub.example.com"
        ));
    }

    #[test]
    fn malformed_pattern_falls_back_to_case_insensitive_eq() {
        // When both pattern and origin are unparseable but equal
        assert!(origin_matches_pattern("not-a-url", "not-a-url"));
    }

    #[test]
    fn malformed_pattern_case_insensitive() {
        assert!(origin_matches_pattern("NOT-A-URL", "not-a-url"));
    }

    #[test]
    fn malformed_pattern_vs_valid_origin() {
        assert!(!origin_matches_pattern("not-a-url", "https://example.com"));
    }

    #[test]
    fn wildcard_localhost_with_port() {
        assert!(origin_matches_pattern(
            "http://*.localhost:3000",
            "http://app.localhost:3000"
        ));
    }

    #[test]
    fn wildcard_ipv4_is_not_supported() {
        // Wildcard with IP address pattern: parsed URL might not have a host suffix
        assert!(!origin_matches_pattern(
            "https://*.192.168.1.1",
            "https://sub.192.168.1.1"
        ));
    }

    // =========================================================================
    // Property-based tests
    // =========================================================================

    #[cfg(not(target_arch = "wasm32"))]
    use proptest::prelude::*;

    // =========================================================================
    // Wildcard edge cases: malformed patterns
    // =========================================================================

    #[test]
    fn wildcard_empty_suffix_after_star_dot_rejects() {
        // Pattern "https://*." has empty wildcard_suffix
        assert!(!origin_matches_pattern("https://*.", "https://example.com"));
    }

    #[test]
    fn wildcard_star_only_no_dot_not_wildcard_pattern() {
        // "https://*" does not contain "*." so it falls to exact match
        assert!(!origin_matches_pattern("https://*", "https://example.com"));
    }

    #[test]
    fn wildcard_double_star_rejects() {
        assert!(!origin_matches_pattern(
            "https://*.*.example.com",
            "https://a.b.example.com"
        ));
    }

    // =========================================================================
    // Exact match: path normalisation
    // =========================================================================

    #[test]
    fn exact_match_root_path_vs_no_slash() {
        // URL parser normalises "https://example.com" to path "/"
        // and "https://example.com/" also to path "/"
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://example.com/"
        ));
    }

    #[test]
    fn exact_match_with_query_string_differs() {
        // Different paths (query strings are not part of path comparison
        // but the origin should not have query strings anyway)
        assert!(origin_matches_pattern(
            "https://example.com",
            "https://example.com"
        ));
    }

    #[test]
    fn exact_match_different_subdomains() {
        assert!(!origin_matches_pattern(
            "https://app.example.com",
            "https://api.example.com"
        ));
    }

    // =========================================================================
    // Wildcard: single-char subdomain
    // =========================================================================

    #[test]
    fn wildcard_single_char_subdomain_matches() {
        assert!(origin_matches_pattern(
            "https://*.example.com",
            "https://x.example.com"
        ));
    }

    // =========================================================================
    // Port edge cases
    // =========================================================================

    #[test]
    fn exact_match_http_default_port_80() {
        // http default port is 80; explicit :80 should match no-port
        assert!(origin_matches_pattern(
            "http://example.com",
            "http://example.com:80"
        ));
    }

    #[test]
    fn wildcard_http_port_80_matches_default() {
        assert!(origin_matches_pattern(
            "http://*.example.com",
            "http://sub.example.com:80"
        ));
    }

    #[test]
    fn wildcard_different_ports_reject() {
        assert!(!origin_matches_pattern(
            "https://*.example.com:9000",
            "https://sub.example.com:9001"
        ));
    }

    // =========================================================================
    // Scheme edge cases
    // =========================================================================

    #[test]
    fn exact_match_wss_scheme() {
        assert!(origin_matches_pattern(
            "wss://example.com",
            "wss://example.com"
        ));
    }

    #[test]
    fn exact_match_wss_vs_ws_rejects() {
        assert!(!origin_matches_pattern(
            "wss://example.com",
            "ws://example.com"
        ));
    }

    // =========================================================================
    // Wildcard with IP addresses (not supported)
    // =========================================================================

    #[test]
    fn wildcard_ipv6_not_supported() {
        assert!(!origin_matches_pattern("https://*.::1", "https://sub.::1"));
    }

    // =========================================================================
    // Malformed inputs
    // =========================================================================

    #[test]
    fn origin_with_null_byte_rejects() {
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "https://sub\0.example.com"
        ));
    }

    #[test]
    fn pattern_with_spaces_in_hostname() {
        // Spaces in URL should fail to parse
        assert!(!origin_matches_pattern(
            "https://example .com",
            "https://example .com"
        ));
    }

    #[test]
    fn global_wildcard_matches_empty_string() {
        // "*" matches anything, including empty
        assert!(origin_matches_pattern("*", ""));
    }

    #[test]
    fn global_wildcard_matches_garbage() {
        assert!(origin_matches_pattern("*", "not a url at all"));
    }

    // =========================================================================
    // Hostname no host after parsing
    // =========================================================================

    #[test]
    fn wildcard_origin_with_no_host_rejects() {
        // data: URIs have no host
        assert!(!origin_matches_pattern(
            "https://*.example.com",
            "data:text/html,<h1>hi</h1>"
        ));
    }

    #[test]
    fn exact_match_data_uri_rejects() {
        assert!(!origin_matches_pattern(
            "https://example.com",
            "data:text/html,<h1>hi</h1>"
        ));
    }

    // =========================================================================
    // Wildcard: scheme prefix empty
    // =========================================================================

    #[test]
    fn bare_star_dot_domain_rejects() {
        // "*.example.com" without a scheme; scheme_prefix is ""
        assert!(!origin_matches_pattern(
            "*.example.com",
            "https://sub.example.com"
        ));
    }

    // =========================================================================
    // Additional property-based tests
    // =========================================================================

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(target_arch = "wasm32")]
    use proptest::prelude::*;

    #[cfg(not(target_arch = "wasm32"))]
    proptest! {
        /// Property: Global wildcard matches any valid HTTPS origin
        #[test]
        fn prop_wildcard_matches_all(host in "[a-z]{3,15}\\.com") {
            let origin = format!("https://{}", host);
            prop_assert!(origin_matches_pattern("*", &origin));
        }

        /// Property: Exact match is reflexive for valid origins
        #[test]
        fn prop_exact_match_reflexive(host in "[a-z]{3,15}\\.com") {
            let url = format!("https://{}", host);
            prop_assert!(origin_matches_pattern(&url, &url));
        }

        /// Property: Subdomain wildcard with dot boundary rejects base domain
        #[test]
        fn prop_wildcard_rejects_base(host in "[a-z]{3,15}\\.com") {
            let pattern = format!("https://*.{}", host);
            let origin = format!("https://{}", host);
            prop_assert!(!origin_matches_pattern(&pattern, &origin));
        }

        /// Property: Subdomain wildcard accepts sub.domain
        #[test]
        fn prop_wildcard_accepts_subdomain(
            sub in "[a-z]{2,8}",
            host in "[a-z]{3,15}\\.com"
        ) {
            let pattern = format!("https://*.{}", host);
            let origin = format!("https://{}.{}", sub, host);
            prop_assert!(origin_matches_pattern(&pattern, &origin));
        }

        /// Property: Scheme mismatch always rejects for exact patterns
        #[test]
        fn prop_scheme_mismatch(host in "[a-z]{3,15}\\.com") {
            let pattern = format!("https://{}", host);
            let origin = format!("http://{}", host);
            prop_assert!(!origin_matches_pattern(&pattern, &origin));
        }

        /// Property: Empty pattern always rejects non-empty origins
        #[test]
        fn prop_empty_pattern_rejects(host in "[a-z]{3,15}\\.com") {
            let origin = format!("https://{}", host);
            prop_assert!(!origin_matches_pattern("", &origin));
        }

        /// Property: Suffix attack always fails for wildcard patterns
        #[test]
        fn prop_suffix_attack_rejected(
            prefix in "[a-z]{2,6}",
            host in "[a-z]{3,10}\\.com"
        ) {
            let pattern = format!("https://*.{}", host);
            // Attacker concatenates prefix directly onto host (no dot)
            let evil_origin = format!("https://{}{}", prefix, host);
            prop_assert!(!origin_matches_pattern(&pattern, &evil_origin));
        }
    }
}
